//! An implementation of the eth gas price oracle, used for providing gas price estimates based on
//! previous blocks.

use super::{EthApiError, EthResult, EthStateCache, RpcInvalidTransactionError};
use alloy_consensus::{constants::GWEI_TO_WEI, BlockHeader, Transaction, TxReceipt};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{map::FbBuildHasher, Address, B256, U256};
use alloy_rpc_types_eth::BlockId;
use derive_more::{Deref, DerefMut, From, Into};
use itertools::Itertools;
use reth_lru::LruMap;
use reth_rpc_server_types::{
    constants,
    constants::gas_oracle::{
        DEFAULT_GAS_PRICE_BLOCKS, DEFAULT_GAS_PRICE_PERCENTILE, DEFAULT_IGNORE_GAS_PRICE,
        DEFAULT_MAX_GAS_PRICE, MAX_HEADER_HISTORY, MAX_REWARD_PERCENTILE_COUNT, SAMPLE_NUMBER,
    },
};
use reth_storage_api::{BlockReaderIdExt, NodePrimitivesProvider};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Formatter},
    str::FromStr,
};
use tokio::sync::Mutex;
use tracing::warn;

/// The default gas limit for `eth_call` and adjacent calls. See
/// [`RPC_DEFAULT_GAS_CAP`](constants::gas_oracle::RPC_DEFAULT_GAS_CAP).
pub const RPC_DEFAULT_GAS_CAP: GasCap = GasCap(constants::gas_oracle::RPC_DEFAULT_GAS_CAP);

/// Settings for the [`GasPriceOracle`]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GasPriceOracleConfig {
    /// The number of populated blocks to produce the gas price estimate
    pub blocks: u32,

    /// The percentile of gas prices to use for the estimate
    pub percentile: u32,

    /// The maximum number of headers to keep in the cache
    pub max_header_history: u64,

    /// The maximum number of blocks for estimating gas price
    pub max_block_history: u64,

    /// The maximum number for reward percentiles.
    ///
    /// This effectively limits how many transactions and receipts are fetched to compute the
    /// reward percentile.
    pub max_reward_percentile_count: u64,

    /// The default gas price to use if there are no blocks to use
    pub default_suggested_fee: Option<U256>,

    /// The maximum gas price to use for the estimate
    pub max_price: Option<U256>,

    /// The minimum gas price, under which the sample will be ignored
    pub ignore_price: Option<U256>,

    /// valve-tech fork: the lowest tip the oracle suggests, when the chain has a minimum tip
    /// that transactions must pay to be mined. `None` leaves the suggestion unbounded below.
    #[serde(default)]
    pub min_price: Option<U256>,

    /// valve-tech fork: how the oracle samples recent blocks. See [`GasPriceSampleMode`].
    #[serde(default)]
    pub sample_mode: GasPriceSampleMode,
}

impl Default for GasPriceOracleConfig {
    fn default() -> Self {
        Self {
            blocks: DEFAULT_GAS_PRICE_BLOCKS,
            percentile: DEFAULT_GAS_PRICE_PERCENTILE,
            max_header_history: MAX_HEADER_HISTORY,
            max_block_history: MAX_HEADER_HISTORY,
            max_reward_percentile_count: MAX_REWARD_PERCENTILE_COUNT,
            default_suggested_fee: None,
            max_price: Some(DEFAULT_MAX_GAS_PRICE),
            ignore_price: Some(DEFAULT_IGNORE_GAS_PRICE),
            min_price: None,
            sample_mode: GasPriceSampleMode::Reth,
        }
    }
}

impl GasPriceOracleConfig {
    /// valve-tech fork: the settings rpc.pulsechain.com runs, erigon-pulse's `FullNodeGPO`: the
    /// [`GasPriceSampleMode::Pulsechain`] sampling over 20 blocks at the 60th percentile, tips
    /// under 1,000 gwei ignored, and a cap of 1 PLS.
    pub fn pulsechain() -> Self {
        Self {
            blocks: DEFAULT_GAS_PRICE_BLOCKS,
            percentile: DEFAULT_GAS_PRICE_PERCENTILE,
            max_price: Some(PULSECHAIN_MAX_PRICE),
            ignore_price: Some(PULSECHAIN_IGNORE_PRICE),
            sample_mode: GasPriceSampleMode::Pulsechain,
            ..Default::default()
        }
    }
}

/// valve-tech fork: erigon-pulse ignores tips under 1,000 gwei (`DefaultIgnorePrice`).
pub const PULSECHAIN_IGNORE_PRICE: U256 = U256::from_limbs([1_000 * GWEI_TO_WEI, 0, 0, 0]);

/// valve-tech fork: erigon-pulse caps its suggestion at 1 PLS, 1e18 wei (`DefaultMaxPrice`).
pub const PULSECHAIN_MAX_PRICE: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);

/// erigon-pulse samples the lowest 40 percent of each block's filtered tips...
const PULSECHAIN_SAMPLE_PERCENT: usize = 40;
/// ...and at least 3 of them, where the block has 3...
const PULSECHAIN_MIN_SAMPLES: usize = 3;
/// ...and at most 1,000 (the `limit` that `SuggestTipCap` passes to `getBlockPrices`).
const PULSECHAIN_MAX_SAMPLES: usize = 1_000;

/// valve-tech fork: how [`GasPriceOracle::suggest_tip_cap`] samples recent blocks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GasPriceSampleMode {
    /// reth's sampling: the 3 lowest tips of each block, over the newest `blocks` blocks that
    /// give a sample. Empty blocks do not count.
    #[default]
    Reth,
    /// erigon-pulse's sampling, as rpc.pulsechain.com answers: exactly `blocks` blocks back from
    /// the head, empty ones included. Each block gives the lowest 40 percent of its tips (at
    /// least 3, at most 1,000), after it drops tips under `ignore_price`, transactions from the
    /// block's coinbase and self-transfers. With no sample, the oracle keeps its last answer.
    /// `eth_feeHistory` rewards follow erigon-pulse too, see
    /// [`calculate_pulsechain_reward_percentiles`](crate::fee_history::calculate_pulsechain_reward_percentiles).
    Pulsechain,
}

impl GasPriceSampleMode {
    /// The mode's name, as the `--gpo.sample-mode` flag takes it.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Reth => "reth",
            Self::Pulsechain => "pulsechain",
        }
    }
}

impl fmt::Display for GasPriceSampleMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GasPriceSampleMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "reth" => Ok(Self::Reth),
            "pulsechain" => Ok(Self::Pulsechain),
            _ => Err(format!("unknown gas price sample mode {s:?}, expected reth or pulsechain")),
        }
    }
}

/// Calculates a gas price depending on recent blocks.
#[derive(Debug)]
pub struct GasPriceOracle<Provider>
where
    Provider: NodePrimitivesProvider,
{
    /// The type used to subscribe to block events and get block info
    provider: Provider,
    /// The cache for blocks
    cache: EthStateCache<Provider::Primitives>,
    /// The config for the oracle
    oracle_config: GasPriceOracleConfig,
    /// The price under which the sample will be ignored.
    ignore_price: Option<u128>,
    /// Stores the latest calculated price and its block hash and Cache stores the lowest effective
    /// tip values of recent blocks
    inner: Mutex<GasPriceOracleInner>,
}

impl<Provider> GasPriceOracle<Provider>
where
    Provider: BlockReaderIdExt + NodePrimitivesProvider,
{
    /// Creates and returns the [`GasPriceOracle`].
    pub fn new(
        provider: Provider,
        mut oracle_config: GasPriceOracleConfig,
        cache: EthStateCache<Provider::Primitives>,
    ) -> Self {
        // sanitize the percentile to be less than 100
        if oracle_config.percentile > 100 {
            warn!(prev_percentile = ?oracle_config.percentile, "Invalid configured gas price percentile, assuming 100.");
            oracle_config.percentile = 100;
        }
        let ignore_price = oracle_config.ignore_price.map(|price| price.saturating_to());

        // this is the number of blocks that we will cache the values for
        let cached_values = (oracle_config.blocks * 5).max(oracle_config.max_block_history as u32);
        let inner = Mutex::new(GasPriceOracleInner {
            last_price: GasPriceOracleResult {
                block_hash: B256::ZERO,
                price: oracle_config
                    .default_suggested_fee
                    .or(oracle_config.min_price)
                    .unwrap_or_else(|| match oracle_config.sample_mode {
                        GasPriceSampleMode::Reth => GasPriceOracleResult::default().price,
                        // erigon's price cache starts at 0
                        GasPriceSampleMode::Pulsechain => U256::ZERO,
                    }),
            },
            lowest_effective_tip_cache: EffectiveTipLruCache(LruMap::with_hasher(
                cached_values,
                Default::default(),
            )),
        });

        Self { provider, oracle_config, cache, ignore_price, inner }
    }

    /// Returns the configuration of the gas price oracle.
    pub const fn config(&self) -> &GasPriceOracleConfig {
        &self.oracle_config
    }

    /// Suggests a gas price estimate based on recent blocks, using the configured percentile.
    pub async fn suggest_tip_cap(&self) -> EthResult<U256> {
        let header = self
            .provider
            .sealed_header_by_number_or_tag(BlockNumberOrTag::Latest)?
            .ok_or(EthApiError::HeaderNotFound(BlockId::latest()))?;

        let mut inner = self.inner.lock().await;

        // if we have stored a last price, then we check whether or not it was for the same head
        if inner.last_price.block_hash == header.hash() {
            return Ok(inner.last_price.price)
        }

        if self.oracle_config.sample_mode == GasPriceSampleMode::Pulsechain {
            let samples =
                self.pulsechain_samples(&mut inner, header.hash(), header.number()).await?;
            let price =
                percentile_sample(samples, self.oracle_config.percentile, inner.last_price.price);
            return Ok(self.store_price(&mut inner, header.hash(), price))
        }

        // if all responses are empty, then we can return a maximum of 2*check_block blocks' worth
        // of prices
        //
        // we only return more than check_block blocks' worth of prices if one or more return empty
        // transactions
        let mut current_hash = header.hash();
        let mut window = TipWindow::default();

        // we only check a maximum of 2 * max_block_history, or the number of blocks in the chain
        let max_blocks = header.number().min(self.oracle_config.max_block_history * 2);

        for _ in 0..max_blocks {
            // Check if current hash is in cache
            let (parent_hash, block_values) =
                if let Some(vals) = inner.lowest_effective_tip_cache.get(&current_hash) {
                    vals.to_owned()
                } else {
                    // Otherwise we fetch it using get_block_values
                    let (parent_hash, block_values) = self
                        .get_block_values(current_hash, SAMPLE_NUMBER)
                        .await?
                        .ok_or(EthApiError::HeaderNotFound(current_hash.into()))?;
                    inner
                        .lowest_effective_tip_cache
                        .insert(current_hash, (parent_hash, block_values.clone()));
                    (parent_hash, block_values)
                };

            window.push_block(block_values);

            // break when we have enough populated blocks
            if window.populated_blocks >= self.oracle_config.blocks {
                break
            }

            current_hash = parent_hash;
        }

        // Take the configured percentile of the populated blocks. With no populated block in
        // range, keep the last price: it is the last real observed tip, or the configured
        // default suggested fee when the oracle has no history yet.
        let price = window.price(self.oracle_config.percentile, inner.last_price.price);

        Ok(self.store_price(&mut inner, header.hash(), price))
    }

    /// Caps `price` at the max price, floors it at the min price, and stores it as the answer for
    /// the head `block_hash`.
    fn store_price(
        &self,
        inner: &mut GasPriceOracleInner,
        block_hash: B256,
        mut price: U256,
    ) -> U256 {
        // constrain to the max price
        if let Some(max_price) = self.oracle_config.max_price &&
            price > max_price
        {
            price = max_price;
        }

        // never suggest less than the chain's minimum tip
        if let Some(min_price) = self.oracle_config.min_price {
            price = price.max(min_price);
        }

        inner.last_price = GasPriceOracleResult { block_hash, price };

        price
    }

    /// Get the `limit` lowest effective tip values for the given block. If the oracle has a
    /// configured `ignore_price` threshold, then tip values under that threshold will be ignored
    /// before returning a result.
    ///
    /// If the block cannot be found, then this will return `None`.
    ///
    /// This method also returns the parent hash for the given block.
    async fn get_block_values(
        &self,
        block_hash: B256,
        limit: usize,
    ) -> EthResult<Option<(B256, Vec<U256>)>> {
        // check the cache (this will hit the disk if the block is not cached)
        let Some(block) = self.cache.get_recovered_block(block_hash).await? else {
            return Ok(None)
        };

        let base_fee_per_gas = block.base_fee_per_gas();
        let parent_hash = block.parent_hash();

        // sort the functions by ascending effective tip first
        let sorted_transactions = block.transactions_recovered().sorted_by_cached_key(|tx| {
            if let Some(base_fee) = base_fee_per_gas {
                (*tx).effective_tip_per_gas(base_fee)
            } else {
                Some((*tx).priority_fee_or_price())
            }
        });

        let mut prices = Vec::with_capacity(limit);

        for tx in sorted_transactions {
            let effective_tip = if let Some(base_fee) = base_fee_per_gas {
                tx.effective_tip_per_gas(base_fee)
            } else {
                Some(tx.priority_fee_or_price())
            };

            // ignore transactions with a tip under the configured threshold
            if let Some(ignore_under) = self.ignore_price &&
                effective_tip < Some(ignore_under)
            {
                continue
            }

            // check if the sender was the coinbase, if so, ignore
            if tx.signer() == block.beneficiary() {
                continue
            }

            // a `None` effective_gas_tip represents a transaction where the max_fee_per_gas is
            // less than the base fee which would be invalid
            prices.push(U256::from(effective_tip.ok_or(RpcInvalidTransactionError::FeeCapTooLow)?));

            // we have enough entries
            if prices.len() >= limit {
                break
            }
        }

        Ok(Some((parent_hash, prices)))
    }

    /// valve-tech fork: the tip samples of [`GasPriceSampleMode::Pulsechain`], as erigon-pulse's
    /// `SuggestTipCap` collects them. It walks exactly `blocks` blocks back from the head (at
    /// least 1), and stops before the genesis block. Empty blocks count toward `blocks`.
    async fn pulsechain_samples(
        &self,
        inner: &mut GasPriceOracleInner,
        head_hash: B256,
        head_number: u64,
    ) -> EthResult<Vec<U256>> {
        let blocks = u64::from(self.oracle_config.blocks.max(1));
        let mut samples = Vec::new();
        let mut current_hash = head_hash;
        for _ in 0..head_number.min(blocks) {
            let (parent_hash, block_values) =
                if let Some(vals) = inner.lowest_effective_tip_cache.get(&current_hash) {
                    vals.to_owned()
                } else {
                    let (parent_hash, block_values) = self
                        .pulsechain_block_values(current_hash)
                        .await?
                        .ok_or(EthApiError::HeaderNotFound(current_hash.into()))?;
                    inner
                        .lowest_effective_tip_cache
                        .insert(current_hash, (parent_hash, block_values.clone()));
                    (parent_hash, block_values)
                };
            samples.extend(block_values);
            current_hash = parent_hash;
        }
        Ok(samples)
    }

    /// valve-tech fork: one block's samples for [`GasPriceSampleMode::Pulsechain`], with the
    /// block's parent hash. `None` if the block is not found.
    async fn pulsechain_block_values(
        &self,
        block_hash: B256,
    ) -> EthResult<Option<(B256, Vec<U256>)>> {
        let Some(block) = self.cache.get_recovered_block(block_hash).await? else {
            return Ok(None)
        };
        let base_fee = block.base_fee_per_gas();
        let txs = block.transactions_recovered().map(|tx| PulsechainTx {
            tip: pulsechain_effective_tip(*tx, base_fee),
            sender: tx.signer(),
            to: tx.to(),
        });
        let values = pulsechain_block_samples(txs, block.beneficiary(), self.ignore_price);
        let parent_hash = block.parent_hash();
        Ok(Some((parent_hash, values)))
    }

    /// Suggests a max priority fee value using a simplified and more predictable algorithm
    /// appropriate for chains like Optimism with a single known block builder.
    ///
    /// It returns either:
    /// - The minimum suggested priority fee when blocks have capacity
    /// - 10% above the median effective priority fee from the last block when at capacity
    ///
    /// A block is considered at capacity if its total gas used plus the maximum single transaction
    /// gas would exceed the block's gas limit.
    pub async fn op_suggest_tip_cap(&self, min_suggested_priority_fee: U256) -> EthResult<U256> {
        let header = self
            .provider
            .sealed_header_by_number_or_tag(BlockNumberOrTag::Latest)?
            .ok_or(EthApiError::HeaderNotFound(BlockId::latest()))?;

        let mut inner = self.inner.lock().await;

        // if we have stored a last price, then we check whether or not it was for the same head
        if inner.last_price.block_hash == header.hash() {
            return Ok(inner.last_price.price);
        }

        let mut suggestion = min_suggested_priority_fee;

        // find the maximum gas used by any of the transactions in the block to use as the
        // capacity margin for the block, if no receipts are found return the
        // suggested_min_priority_fee
        let receipts = self
            .cache
            .get_receipts(header.hash())
            .await?
            .ok_or(EthApiError::ReceiptsNotFound(BlockId::latest()))?;

        let mut max_tx_gas_used = 0u64;
        let mut last_cumulative_gas = 0;
        for receipt in receipts.as_ref() {
            let cumulative_gas = receipt.cumulative_gas_used();
            // get the gas used by each transaction in the block, by subtracting the
            // cumulative gas used of the previous transaction from the cumulative gas used of
            // the current transaction. This is because there is no gas_used()
            // method on the Receipt trait.
            let gas_used = cumulative_gas - last_cumulative_gas;
            max_tx_gas_used = max_tx_gas_used.max(gas_used);
            last_cumulative_gas = cumulative_gas;
        }

        // if the block is at capacity, the suggestion must be increased
        if header.gas_used() + max_tx_gas_used > header.gas_limit() {
            let Some(median_tip) = self.get_block_median_tip(header.hash()).await? else {
                return Ok(suggestion);
            };

            let new_suggestion = median_tip + median_tip / U256::from(10);

            if new_suggestion > suggestion {
                suggestion = new_suggestion;
            }
        }

        // constrain to the max price
        if let Some(max_price) = self.oracle_config.max_price &&
            suggestion > max_price
        {
            suggestion = max_price;
        }

        inner.last_price = GasPriceOracleResult { block_hash: header.hash(), price: suggestion };

        Ok(suggestion)
    }

    /// Get the median tip value for the given block. This is useful for determining
    /// tips when a block is at capacity.
    ///
    /// If the block cannot be found or has no transactions, this will return `None`.
    pub async fn get_block_median_tip(&self, block_hash: B256) -> EthResult<Option<U256>> {
        // check the cache (this will hit the disk if the block is not cached)
        let Some(block) = self.cache.get_recovered_block(block_hash).await? else {
            return Ok(None)
        };

        let base_fee_per_gas = block.base_fee_per_gas();

        // Filter, sort and collect the prices
        let prices = block
            .transactions_recovered()
            .filter_map(|tx| {
                if let Some(base_fee) = base_fee_per_gas {
                    (*tx).effective_tip_per_gas(base_fee)
                } else {
                    Some((*tx).priority_fee_or_price())
                }
            })
            .sorted()
            .collect::<Vec<_>>();

        let median = if prices.is_empty() {
            // if there are no prices, return `None`
            None
        } else if prices.len() % 2 == 1 {
            Some(U256::from(prices[prices.len() / 2]))
        } else {
            Some(U256::from((prices[prices.len() / 2 - 1] + prices[prices.len() / 2]) / 2))
        };

        Ok(median)
    }
}

/// valve-tech fork: one transaction as erigon-pulse's oracle reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PulsechainTx {
    /// The effective tip, see [`pulsechain_effective_tip`].
    pub tip: u128,
    /// The sender.
    pub sender: Address,
    /// The recipient, `None` for a contract creation.
    pub to: Option<Address>,
}

/// valve-tech fork: erigon's `GetEffectiveGasTip`: the tip a transaction pays over `base_fee`,
/// and 0 where its fee cap is under the base fee. Before London it is the priority fee or gas
/// price.
pub fn pulsechain_effective_tip<T: Transaction>(tx: &T, base_fee: Option<u64>) -> u128 {
    match base_fee {
        Some(base_fee) => tx.effective_tip_per_gas(base_fee).unwrap_or_default(),
        None => tx.priority_fee_or_price(),
    }
}

/// valve-tech fork: one block's samples, as erigon-pulse's `getBlockPrices` takes them. It drops
/// a tip under `ignore_price`, a transaction from `coinbase`, and a self-transfer (a recipient
/// equal to the sender). It sorts the rest ascending and keeps the lowest 40 percent: at least 3,
/// at most all of them, and at most 1,000. erigon also drops a transaction whose sender it does
/// not know; a recovered block knows every sender.
pub fn pulsechain_block_samples(
    txs: impl IntoIterator<Item = PulsechainTx>,
    coinbase: Address,
    ignore_price: Option<u128>,
) -> Vec<U256> {
    let mut tips: Vec<u128> = txs
        .into_iter()
        .filter(|tx| {
            ignore_price.is_none_or(|ignore| tx.tip >= ignore) &&
                tx.sender != coinbase &&
                tx.to != Some(tx.sender)
        })
        .map(|tx| tx.tip)
        .collect();
    tips.sort_unstable();
    let keep = (tips.len() * PULSECHAIN_SAMPLE_PERCENT / 100)
        .max(PULSECHAIN_MIN_SAMPLES)
        .min(tips.len())
        .min(PULSECHAIN_MAX_SAMPLES);
    tips.truncate(keep);
    tips.into_iter().map(U256::from).collect()
}

/// The sample at `percentile` of `samples`, or `fallback` when there is none.
fn percentile_sample(mut samples: Vec<U256>, percentile: u32, fallback: U256) -> U256 {
    if samples.is_empty() {
        return fallback
    }
    samples.sort_unstable();
    samples[(samples.len() - 1) * percentile as usize / 100]
}

/// The tip samples that [`GasPriceOracle::suggest_tip_cap`] collects over its block window.
///
/// valve-tech fork: a block with no usable sample is skipped. A block has no usable sample when
/// it is empty, or when every transaction in it pays a tip under `ignore_price` or comes from the
/// block's coinbase. Upstream (#23094) pushes a zero for such a block instead. On a quiet chain
/// the zeros then fill the window, the percentile lands on zero, and `eth_maxPriorityFeePerGas`
/// answers 0 while transactions with that tip mine slowly or not at all. Geth keeps its last
/// price for these blocks; skipping them keeps the estimate on the last real observed tip.
#[derive(Debug, Default)]
struct TipWindow {
    /// The tip samples of the populated blocks.
    samples: Vec<U256>,
    /// The number of blocks that gave at least one sample.
    populated_blocks: u32,
}

impl TipWindow {
    /// Adds one block's samples. A block with no sample adds nothing.
    fn push_block(&mut self, block_values: Vec<U256>) {
        if block_values.is_empty() {
            return
        }
        self.samples.extend(block_values);
        self.populated_blocks += 1;
    }

    /// Returns the `percentile` sample, or `fallback` when no block gave a sample.
    fn price(mut self, percentile: u32, fallback: U256) -> U256 {
        if self.samples.is_empty() {
            return fallback
        }
        self.samples.sort_unstable();
        self.samples[(self.samples.len() - 1) * percentile as usize / 100]
    }
}

/// Container type for mutable inner state of the [`GasPriceOracle`]
#[derive(Debug)]
struct GasPriceOracleInner {
    last_price: GasPriceOracleResult,
    lowest_effective_tip_cache: EffectiveTipLruCache,
}

/// Wrapper struct for `LruMap`
#[derive(Deref, DerefMut)]
pub struct EffectiveTipLruCache(LruMap<B256, (B256, Vec<U256>), FbBuildHasher<32>>);

impl Debug for EffectiveTipLruCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EffectiveTipLruCache")
            .field("cache_length", &self.len())
            .field("cache_memory_usage", &self.memory_usage())
            .finish()
    }
}

/// Stores the last result that the oracle returned
#[derive(Debug, Clone)]
pub struct GasPriceOracleResult {
    /// The block hash that the oracle used to calculate the price
    pub block_hash: B256,
    /// The price that the oracle calculated
    pub price: U256,
}

impl Default for GasPriceOracleResult {
    fn default() -> Self {
        Self { block_hash: B256::ZERO, price: U256::from(GWEI_TO_WEI) }
    }
}

/// The wrapper type for gas limit
#[derive(Debug, Clone, Copy, From, Into)]
pub struct GasCap(pub u64);

impl Default for GasCap {
    fn default() -> Self {
        RPC_DEFAULT_GAS_CAP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERCENTILE: u32 = DEFAULT_GAS_PRICE_PERCENTILE;
    const BLOCKS: u32 = DEFAULT_GAS_PRICE_BLOCKS;

    fn tips(values: &[u64]) -> Vec<U256> {
        values.iter().copied().map(U256::from).collect()
    }

    /// Runs the window the way `suggest_tip_cap` does: blocks newest first, stop once `BLOCKS`
    /// blocks gave a sample, and never scan more than `max_blocks` blocks.
    fn suggest(blocks: &[Vec<U256>], max_blocks: usize, last_price: U256) -> U256 {
        let mut window = TipWindow::default();
        for values in blocks.iter().take(max_blocks) {
            window.push_block(values.clone());
            if window.populated_blocks >= BLOCKS {
                break
            }
        }
        window.price(PERCENTILE, last_price)
    }

    /// The upstream algorithm before this fix: an empty block pushes a zero.
    fn suggest_upstream(blocks: &[Vec<U256>], max_blocks: usize, last_price: U256) -> U256 {
        let mut results = Vec::new();
        let mut populated = 0;
        for values in blocks.iter().take(max_blocks) {
            if values.is_empty() {
                results.push(U256::ZERO);
            } else {
                results.extend(values.iter().copied());
                populated += 1;
            }
            if populated >= BLOCKS {
                break
            }
        }
        if results.is_empty() {
            return last_price
        }
        results.sort_unstable();
        results[(results.len() - 1) * PERCENTILE as usize / 100]
    }

    #[test]
    fn all_empty_window_returns_last_good_price() {
        let last_good = U256::from(1_008_789u64);
        let blocks = vec![Vec::new(); 40];

        assert_eq!(suggest(&blocks, 40, last_good), last_good);
        // The fault this fixes: upstream answers zero for the same window.
        assert_eq!(suggest_upstream(&blocks, 40, last_good), U256::ZERO);
    }

    #[test]
    fn all_empty_window_without_history_returns_default_fee() {
        let default_fee = GasPriceOracleResult::default().price;
        let blocks = vec![Vec::new(); 40];

        assert_eq!(suggest(&blocks, 40, default_fee), U256::from(GWEI_TO_WEI));

        let configured = U256::from(7_000_000u64);
        assert_eq!(suggest(&blocks, 40, configured), configured);
    }

    #[test]
    fn mixed_window_ignores_empty_blocks() {
        // 38 empty blocks and 2 populated ones, as on chain 943 after a quiet stretch.
        let mut blocks = vec![Vec::new(); 40];
        blocks[3] = tips(&[1_008_789, 2_000_000, 3_000_000]);
        blocks[17] = tips(&[1_500_000]);

        let price = suggest(&blocks, 40, U256::from(GWEI_TO_WEI));

        // Same answer as a window that holds only the populated blocks.
        let populated_only = vec![blocks[3].clone(), blocks[17].clone()];
        assert_eq!(price, suggest(&populated_only, 40, U256::ZERO));
        // samples sorted: 1_008_789, 1_500_000, 2_000_000, 3_000_000; index 3 * 60 / 100 = 1
        assert_eq!(price, U256::from(1_500_000u64));
        assert_eq!(suggest_upstream(&blocks, 40, U256::from(GWEI_TO_WEI)), U256::ZERO);
    }

    #[test]
    fn mixed_window_scans_past_empty_blocks_for_enough_samples() {
        // Upstream stops at max_blocks too; empty blocks never count toward BLOCKS.
        let mut blocks: Vec<Vec<U256>> = Vec::new();
        for i in 0..60u64 {
            blocks.push(if i % 3 == 0 { tips(&[1_000_000 + i]) } else { Vec::new() });
        }
        let price = suggest(&blocks, 60, U256::ZERO);
        // 20 populated blocks: tips 1_000_000 + {0, 3, ..., 57}; index 19 * 60 / 100 = 11
        assert_eq!(price, U256::from(1_000_033u64));
    }

    #[test]
    fn full_blocks_control_is_unchanged() {
        let blocks: Vec<Vec<U256>> = (0..40u64)
            .map(|i| tips(&[1_000_000 + i, 2_000_000 + i * 7, 5_000_000 + i * 13]))
            .collect();
        let last = U256::from(GWEI_TO_WEI);

        assert_eq!(suggest(&blocks, 40, last), suggest_upstream(&blocks, 40, last));
        assert_ne!(suggest(&blocks, 40, last), U256::ZERO);
    }

    // --- valve-tech fork: the `pulsechain` sample mode ---

    const COINBASE: Address = Address::repeat_byte(0xc0);
    const GWEI: u128 = GWEI_TO_WEI as u128;
    const IGNORE: Option<u128> = Some(1_000 * GWEI);

    fn ptx(tip: u128, sender: u8, to: Option<u8>) -> PulsechainTx {
        PulsechainTx { tip, sender: Address::repeat_byte(sender), to: to.map(Address::repeat_byte) }
    }

    fn samples(txs: Vec<PulsechainTx>) -> Vec<u128> {
        pulsechain_block_samples(txs, COINBASE, IGNORE).into_iter().map(|v| v.to()).collect()
    }

    #[test]
    fn pulsechain_drops_the_coinbase() {
        let mut txs = vec![ptx(2_000 * GWEI, 1, Some(2)), ptx(3_000 * GWEI, 3, Some(4))];
        txs.push(PulsechainTx { tip: 1_500 * GWEI, sender: COINBASE, to: None });
        assert_eq!(samples(txs), [2_000 * GWEI, 3_000 * GWEI]);
    }

    #[test]
    fn pulsechain_drops_self_transfers() {
        let txs = vec![
            ptx(1_500 * GWEI, 1, Some(1)),
            ptx(2_000 * GWEI, 2, Some(3)),
            // a contract creation has no recipient and is no self-transfer
            ptx(3_000 * GWEI, 4, None),
        ];
        assert_eq!(samples(txs), [2_000 * GWEI, 3_000 * GWEI]);
    }

    #[test]
    fn pulsechain_drops_tips_under_the_ignore_price() {
        let txs = vec![
            ptx(1_000 * GWEI - 1, 1, Some(2)),
            ptx(1_000 * GWEI, 3, Some(4)),
            ptx(4_000 * GWEI, 5, Some(6)),
        ];
        assert_eq!(samples(txs), [1_000 * GWEI, 4_000 * GWEI]);
    }

    #[test]
    fn pulsechain_keeps_the_lowest_40_percent_and_at_least_3() {
        let block = |n: u8| -> Vec<PulsechainTx> {
            (0..n).rev().map(|i| ptx(1_000 * GWEI + u128::from(i), i, Some(i + 1))).collect()
        };
        let lowest = |n: u128| (0..n).map(|i| 1_000 * GWEI + i).collect::<Vec<_>>();
        // 20 * 40% = 8, sorted ascending
        assert_eq!(samples(block(20)), lowest(8));
        // 5 * 40% = 2, raised to 3
        assert_eq!(samples(block(5)), lowest(3));
        // fewer than 3: all of them
        assert_eq!(samples(block(2)), lowest(2));
        assert!(samples(Vec::new()).is_empty());
    }

    #[test]
    fn pulsechain_keeps_at_most_1000_per_block() {
        let txs: Vec<_> = (0..3_000u32)
            .map(|i| PulsechainTx {
                tip: 1_000 * GWEI + u128::from(i),
                sender: Address::with_last_byte(1),
                to: None,
            })
            .collect();
        assert_eq!(pulsechain_block_samples(txs, COINBASE, IGNORE).len(), 1_000);
    }

    #[test]
    fn pulsechain_effective_tip_saturates_at_zero() {
        let tx = alloy_consensus::TxEip1559 {
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 30,
            ..Default::default()
        };
        assert_eq!(pulsechain_effective_tip(&tx, Some(80)), 20);
        assert_eq!(pulsechain_effective_tip(&tx, Some(50)), 30);
        // reth's own sampling refuses this transaction with `FeeCapTooLow`; erigon counts 0
        assert_eq!(pulsechain_effective_tip(&tx, Some(101)), 0);
        assert_eq!(pulsechain_effective_tip(&tx, None), 30);
        let legacy = alloy_consensus::TxLegacy { gas_price: 100, ..Default::default() };
        assert_eq!(pulsechain_effective_tip(&legacy, Some(60)), 40);
    }

    #[test]
    fn percentile_sample_keeps_the_fallback_without_samples() {
        assert_eq!(percentile_sample(Vec::new(), 60, U256::from(7)), U256::from(7));
        assert_eq!(percentile_sample(tips(&[5, 1, 4, 2, 3]), 60, U256::from(7)), U256::from(3));
    }

    #[test]
    fn pulsechain_sample_mode_names() {
        for mode in [GasPriceSampleMode::Reth, GasPriceSampleMode::Pulsechain] {
            assert_eq!(mode.as_str().parse::<GasPriceSampleMode>(), Ok(mode));
            assert_eq!(serde_json::to_value(mode).unwrap(), mode.as_str());
        }
        assert!("erigon".parse::<GasPriceSampleMode>().is_err());
    }

    #[test]
    fn config_without_sample_mode_deserializes_as_reth() {
        let mut value = serde_json::to_value(GasPriceOracleConfig::default()).unwrap();
        value.as_object_mut().unwrap().remove("sampleMode").expect("the field is serialized");
        let config: GasPriceOracleConfig = serde_json::from_value(value).unwrap();
        assert_eq!(config, GasPriceOracleConfig::default());
    }

    /// One capture from rpc.pulsechain.com, made by `testdata/gpo-pulsechain/capture.py`.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Capture {
        head: u64,
        max_priority_fee_per_gas: U256,
        gas_price: U256,
        blocks: Vec<CaptureBlock>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CaptureBlock {
        number: u64,
        coinbase: Address,
        base_fee: Option<alloy_primitives::U64>,
        txs: Vec<CaptureTx>,
    }

    /// One captured transaction: `[type, gasPrice or maxFeePerGas, maxPriorityFeePerGas, from,
    /// to]`.
    type CaptureTx = (u8, U256, Option<U256>, Address, Option<Address>);

    impl CaptureBlock {
        fn base_fee(&self) -> Option<u64> {
            self.base_fee.map(|b| b.to())
        }

        fn pulsechain_txs(&self) -> Vec<PulsechainTx> {
            let base_fee = self.base_fee();
            self.txs
                .iter()
                .map(|&(kind, fee, priority, sender, to)| {
                    let fee: u128 = fee.to();
                    let tip = match (kind, priority) {
                        (0 | 1, None) => pulsechain_effective_tip(
                            &alloy_consensus::TxLegacy { gas_price: fee, ..Default::default() },
                            base_fee,
                        ),
                        (2 | 4, Some(priority)) => pulsechain_effective_tip(
                            &alloy_consensus::TxEip1559 {
                                max_fee_per_gas: fee,
                                max_priority_fee_per_gas: priority.to(),
                                ..Default::default()
                            },
                            base_fee,
                        ),
                        other => panic!("unexpected transaction shape {other:?}"),
                    };
                    PulsechainTx { tip, sender, to }
                })
                .collect()
        }
    }

    fn captures() -> Vec<(String, Capture)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/gpo-pulsechain");
        let mut out: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .map(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                (name, serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap())
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The `pulsechain` mode over each capture, as `suggest_tip_cap` computes it with erigon's
    /// defaults.
    fn pulsechain_answer(capture: &Capture) -> U256 {
        let config = GasPriceOracleConfig::pulsechain();
        let ignore = config.ignore_price.map(|p| p.saturating_to());
        let samples = capture
            .blocks
            .iter()
            .take(config.blocks as usize)
            .flat_map(|b| pulsechain_block_samples(b.pulsechain_txs(), b.coinbase, ignore))
            .collect();
        percentile_sample(samples, config.percentile, U256::ZERO).min(config.max_price.unwrap())
    }

    /// The differential test: each capture's `eth_maxPriorityFeePerGas` from rpc.pulsechain.com
    /// equals the `pulsechain` mode's answer over the same 20 blocks.
    #[test]
    fn pulsechain_mode_matches_rpc_pulsechain_com() {
        let captures = captures();
        assert!(captures.len() >= 5, "expected at least 5 captures, found {}", captures.len());
        for (name, capture) in &captures {
            assert_eq!(capture.blocks.len(), 20, "{name}");
            for (i, b) in capture.blocks.iter().enumerate() {
                assert_eq!(b.number, capture.head - i as u64, "{name}: blocks run newest first");
            }
            assert_eq!(
                pulsechain_answer(capture),
                capture.max_priority_fee_per_gas,
                "{name}: the pulsechain mode disagrees with erigon"
            );
            // eth_gasPrice is the tip plus the head's base fee, on both nodes
            let head_base_fee = U256::from(capture.blocks[0].base_fee().unwrap());
            assert_eq!(
                capture.gas_price,
                capture.max_priority_fee_per_gas + head_base_fee,
                "{name}"
            );
        }
    }

    /// The negative control: without the self-transfer rule, or with reth's 2 wei ignore price,
    /// the captures do not all give erigon's answer, so the differential test can fail. A capture
    /// may still agree by chance: many transactions can pay the same tip.
    #[test]
    fn pulsechain_captures_need_each_erigon_rule() {
        let captures = captures();
        let answer = |capture: &Capture, keep_to: bool, ignore: u128| {
            let samples = capture
                .blocks
                .iter()
                .flat_map(|b| {
                    let txs = b
                        .pulsechain_txs()
                        .into_iter()
                        .map(|tx| PulsechainTx { to: if keep_to { tx.to } else { None }, ..tx });
                    pulsechain_block_samples(txs, b.coinbase, Some(ignore))
                })
                .collect();
            percentile_sample(samples, 60, U256::ZERO)
        };
        let differ = |keep_to: bool, ignore: u128| {
            captures
                .iter()
                .filter(|(_, c)| answer(c, keep_to, ignore) != c.max_priority_fee_per_gas)
                .count()
        };
        assert_eq!(differ(true, 1_000 * GWEI), 0, "the control agrees on every capture");
        assert!(differ(false, 1_000 * GWEI) > captures.len() / 2, "self-transfers");
        assert!(differ(true, 2) > captures.len() / 2, "the ignore price");
    }
}
