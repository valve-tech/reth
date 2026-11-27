//! Consist of types adjacent to the fee history cache and its configs

use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    sync::{atomic::Ordering::SeqCst, Arc},
};

use alloy_consensus::{BlockHeader, Header, Transaction, TxReceipt};
use alloy_eips::eip7840::BlobParams;
use alloy_primitives::Address;
use alloy_rpc_types_eth::TxGasAndReward;
use futures::{
    future::{Fuse, FusedFuture},
    FutureExt, Stream, StreamExt,
};
use metrics::atomics::AtomicU64;
use reth_chain_state::CanonStateNotification;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_primitives_traits::{Block, BlockBody, NodePrimitives, RecoveredBlock, SealedBlock};
use reth_rpc_server_types::constants::gas_oracle::MAX_HEADER_HISTORY;
use reth_storage_api::BlockReaderIdExt;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{gas_oracle::GasPriceSampleMode, utils::checked_blob_gas_used_ratio};

use super::{EthApiError, EthStateCache};

/// Contains cached fee history entries for blocks.
///
/// Purpose for this is to provide cached data for `eth_feeHistory`.
#[derive(Debug, Clone)]
pub struct FeeHistoryCache<H> {
    inner: Arc<FeeHistoryCacheInner<H>>,
}

impl<H> FeeHistoryCache<H>
where
    H: BlockHeader + Clone,
{
    /// Creates new `FeeHistoryCache` instance, initialize it with the more recent data, set bounds
    pub fn new(config: FeeHistoryCacheConfig) -> Self {
        let inner = FeeHistoryCacheInner {
            lower_bound: Default::default(),
            upper_bound: Default::default(),
            config,
            entries: Default::default(),
        };
        Self { inner: Arc::new(inner) }
    }

    /// How the cache is configured.
    #[inline]
    pub fn config(&self) -> &FeeHistoryCacheConfig {
        &self.inner.config
    }

    /// Returns the configured resolution for percentile approximation.
    #[inline]
    pub fn resolution(&self) -> u64 {
        self.config().resolution
    }

    /// Returns all blocks that are missing in the cache in the [`lower_bound`, `upper_bound`]
    /// range.
    ///
    /// This function is used to populate the cache with missing blocks, which can happen if the
    /// node switched to stage sync node.
    async fn missing_consecutive_blocks(&self) -> VecDeque<u64> {
        let entries = self.inner.entries.read().await;
        (self.lower_bound()..self.upper_bound())
            .rev()
            .filter(|&block_number| !entries.contains_key(&block_number))
            .collect()
    }

    /// Insert block data into the cache.
    async fn insert_blocks<'a, I, B, R, C>(&self, blocks: I, chain_spec: &C)
    where
        B: Block<Header = H> + 'a,
        R: TxReceipt + 'a,
        I: IntoIterator<Item = (&'a RecoveredBlock<B>, &'a [R])>,
        C: EthChainSpec,
    {
        let mut entries = self.inner.entries.write().await;

        let percentiles = self.predefined_percentiles();
        // Insert all new blocks and calculate approximated rewards
        for (block, receipts) in blocks {
            let mut fee_history_entry = FeeHistoryEntry::<H>::new(
                block.sealed_block(),
                chain_spec.blob_params_at_timestamp(block.header().timestamp()),
            );
            fee_history_entry.rewards = reward_percentiles_for_block(
                self.inner.config.sample_mode,
                &percentiles,
                block,
                receipts,
            );
            entries.insert(block.number(), Arc::new(fee_history_entry));
        }

        // enforce bounds by popping the oldest entries
        while entries.len() > self.inner.config.max_blocks as usize {
            entries.pop_first();
        }

        if entries.is_empty() {
            self.inner.upper_bound.store(0, SeqCst);
            self.inner.lower_bound.store(0, SeqCst);
            return
        }

        let upper_bound = *entries.last_entry().expect("Contains at least one entry").key();

        // also enforce proper lower bound in case we have gaps
        let target_lower = upper_bound.saturating_sub(self.inner.config.max_blocks);
        while entries.len() > 1 && *entries.first_key_value().unwrap().0 < target_lower {
            entries.pop_first();
        }

        let lower_bound = *entries.first_entry().expect("Contains at least one entry").key();
        self.inner.upper_bound.store(upper_bound, SeqCst);
        self.inner.lower_bound.store(lower_bound, SeqCst);
    }

    /// Get `UpperBound` value for `FeeHistoryCache`
    pub fn upper_bound(&self) -> u64 {
        self.inner.upper_bound.load(SeqCst)
    }

    /// Get `LowerBound` value for `FeeHistoryCache`
    pub fn lower_bound(&self) -> u64 {
        self.inner.lower_bound.load(SeqCst)
    }

    /// Collect fee history for the given range (inclusive `start_block..=end_block`).
    ///
    /// This function retrieves fee history entries from the cache for the specified range.
    /// If the requested range (`start_block` to `end_block`) is within the cache bounds,
    /// it returns the corresponding entries.
    /// Otherwise it returns None.
    pub async fn get_history(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Option<Vec<Arc<FeeHistoryEntry<H>>>> {
        if end_block < start_block {
            // invalid range, return None
            return None
        }
        let lower_bound = self.lower_bound();
        let upper_bound = self.upper_bound();
        if start_block >= lower_bound && end_block <= upper_bound {
            let entries = self.inner.entries.read().await;
            let result = entries
                .range(start_block..=end_block)
                .map(|(_, fee_entry)| fee_entry.clone())
                .collect::<Vec<_>>();

            if result.is_empty() {
                return None
            }

            Some(result)
        } else {
            None
        }
    }

    /// Generates predefined set of percentiles
    ///
    /// This returns 100 * resolution points
    pub fn predefined_percentiles(&self) -> Vec<f64> {
        let res = self.resolution() as f64;
        (0..=100 * self.resolution()).map(|p| p as f64 / res).collect()
    }
}

/// Settings for the [`FeeHistoryCache`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistoryCacheConfig {
    /// Max number of blocks in cache.
    ///
    /// Default is [`MAX_HEADER_HISTORY`] plus some change to also serve slightly older blocks from
    /// cache, since `fee_history` supports the entire range
    pub max_blocks: u64,
    /// Percentile approximation resolution
    ///
    /// Default is 4 which means 0.25
    pub resolution: u64,
    /// valve-tech fork: how the cached rewards are computed, see
    /// [`reward_percentiles_for_block`]. The eth API builder sets it from the gas price oracle.
    #[serde(default)]
    pub sample_mode: GasPriceSampleMode,
}

impl Default for FeeHistoryCacheConfig {
    fn default() -> Self {
        Self {
            max_blocks: MAX_HEADER_HISTORY + 100,
            resolution: 4,
            sample_mode: GasPriceSampleMode::Reth,
        }
    }
}

/// Container type for shared state in [`FeeHistoryCache`]
#[derive(Debug)]
struct FeeHistoryCacheInner<H> {
    /// Stores the lower bound of the cache
    lower_bound: AtomicU64,
    /// Stores the upper bound of the cache
    upper_bound: AtomicU64,
    /// Config for `FeeHistoryCache`, consists of resolution for percentile approximation
    /// and max number of blocks
    config: FeeHistoryCacheConfig,
    /// Stores the entries of the cache
    entries: tokio::sync::RwLock<BTreeMap<u64, Arc<FeeHistoryEntry<H>>>>,
}

/// Awaits for new chain events and directly inserts them into the cache so they're available
/// immediately before they need to be fetched from disk.
pub async fn fee_history_cache_new_blocks_task<St, Provider, N>(
    fee_history_cache: FeeHistoryCache<N::BlockHeader>,
    mut events: St,
    provider: Provider,
    cache: EthStateCache<N>,
) where
    St: Stream<Item = CanonStateNotification<N>> + Unpin + 'static,
    Provider:
        BlockReaderIdExt<Block = N::Block, Receipt = N::Receipt> + ChainSpecProvider + 'static,
    N: NodePrimitives,
    N::BlockHeader: BlockHeader + Clone,
{
    // We're listening for new blocks emitted when the node is in live sync.
    // If the node transitions to stage sync, we need to fetch the missing blocks
    let mut missing_blocks = VecDeque::new();
    let mut fetch_missing_block = Fuse::terminated();

    loop {
        if fetch_missing_block.is_terminated() &&
            let Some(block_number) = missing_blocks.pop_front()
        {
            trace!(target: "rpc::fee", ?block_number, "Fetching missing block for fee history cache");
            if let Ok(Some(hash)) = provider.block_hash(block_number) {
                // fetch missing block
                fetch_missing_block = cache.get_block_and_receipts(hash).boxed().fuse();
            }
        }

        let chain_spec = provider.chain_spec();

        tokio::select! {
            res = &mut fetch_missing_block =>  {
                if let Ok(res) = res {
                    let res = res.as_ref()
                        .map(|(b, r)| (&**b, r.as_slice()));
                    fee_history_cache.insert_blocks(res, &chain_spec).await;
                }
            }
            event = events.next() =>  {
                let Some(event) = event else {
                     // the stream ended, we are done
                    break
                };

                let committed = event.committed();
                let blocks_and_receipts = committed
                    .blocks_and_receipts()
                    .map(|(block, receipts)| (&**block, receipts.as_slice()));
                fee_history_cache.insert_blocks(blocks_and_receipts, &chain_spec).await;

                // keep track of missing blocks
                missing_blocks = fee_history_cache.missing_consecutive_blocks().await;
            }
        }
    }
}

/// Calculates reward percentiles for transactions in a block.
///
/// The results are returned as a vector of `u128` values.
pub fn calculate_reward_percentiles_for_block<T, R>(
    percentiles: &[f64],
    base_fee_per_gas: u64,
    transactions: &[T],
    receipts: &[R],
) -> Result<Vec<u128>, EthApiError>
where
    T: Transaction,
    R: TxReceipt,
{
    let mut transactions = transactions
        .iter()
        .zip(receipts)
        .scan(0, |previous_gas, (tx, receipt)| {
            // Convert the cumulative gas used in the receipts
            // to the gas usage by the transaction
            //
            // While we will sum up the gas again later, it is worth
            // noting that the order of the transactions will be different,
            // so the sum will also be different for each receipt.
            let gas_used = receipt.cumulative_gas_used() - *previous_gas;
            *previous_gas = receipt.cumulative_gas_used();

            Some(TxGasAndReward {
                gas_used,
                reward: tx.effective_tip_per_gas(base_fee_per_gas).unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();

    // EIP-8037 can make header gas used exceed the sum of per-transaction receipt gas.
    let total_receipt_gas_used =
        receipts.last().map(|receipt| receipt.cumulative_gas_used()).unwrap_or_default();

    // Sort the transactions by their rewards in ascending order
    transactions.sort_unstable_by_key(|tx| tx.reward);

    // Find the transaction that corresponds to the given percentile
    //
    // We use a `tx_index` here that is shared across all percentiles, since we know
    // the percentiles are monotonically increasing.
    let mut tx_index = 0;
    let mut cumulative_gas_used = transactions.first().map(|tx| tx.gas_used).unwrap_or_default();
    let mut rewards_in_block = Vec::with_capacity(percentiles.len());
    for percentile in percentiles {
        // Empty blocks should return in a zero row
        if transactions.is_empty() {
            rewards_in_block.push(0);
            continue
        }

        let threshold = (total_receipt_gas_used as f64 * percentile / 100.) as u64;
        while cumulative_gas_used < threshold && tx_index < transactions.len() - 1 {
            tx_index += 1;
            cumulative_gas_used += transactions[tx_index].gas_used;
        }
        rewards_in_block.push(transactions[tx_index].reward);
    }

    Ok(rewards_in_block)
}

/// valve-tech fork: the reward percentiles of `block` under `mode`. [`GasPriceSampleMode::Reth`]
/// is [`calculate_reward_percentiles_for_block`]. [`GasPriceSampleMode::Pulsechain`] is
/// [`calculate_pulsechain_reward_percentiles`], as erigon-pulse's `processBlock` computes them.
pub fn reward_percentiles_for_block<B, R>(
    mode: GasPriceSampleMode,
    percentiles: &[f64],
    block: &RecoveredBlock<B>,
    receipts: &[R],
) -> Vec<u128>
where
    B: Block,
    R: TxReceipt,
{
    let base_fee = block.header().base_fee_per_gas().unwrap_or_default();
    match mode {
        GasPriceSampleMode::Reth => calculate_reward_percentiles_for_block(
            percentiles,
            base_fee,
            block.body().transactions(),
            receipts,
        )
        .unwrap_or_default(),
        GasPriceSampleMode::Pulsechain => {
            let gas_used = receipts.iter().scan(0, |previous_gas, receipt| {
                let gas_used = receipt.cumulative_gas_used() - *previous_gas;
                *previous_gas = receipt.cumulative_gas_used();
                Some(gas_used)
            });
            let txs =
                block.transactions_with_sender().zip(gas_used).map(|((sender, tx), gas_used)| {
                    PulsechainReward {
                        sender: *sender,
                        to: tx.to(),
                        reward: tx.effective_tip_per_gas(base_fee).unwrap_or_default(),
                        gas_used,
                    }
                });
            calculate_pulsechain_reward_percentiles(percentiles, txs, block.header().beneficiary())
        }
    }
}

/// valve-tech fork: whether each of `percentiles` is on the grid of the fee history cache with
/// `resolution`, so the cache holds its exact reward.
pub fn on_resolution_grid(percentiles: &[f64], resolution: u64) -> bool {
    percentiles.iter().all(|p| (p * resolution as f64).fract() == 0.0)
}

/// valve-tech fork: one transaction as erigon-pulse's `processBlock` reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PulsechainReward {
    /// The sender.
    pub sender: Address,
    /// The recipient, `None` for a contract creation.
    pub to: Option<Address>,
    /// The effective tip over the block's base fee, 0 where the fee cap is under it.
    pub reward: u128,
    /// The gas the transaction used.
    pub gas_used: u64,
}

/// valve-tech fork: erigon-pulse's reward percentiles. It drops the transactions from `coinbase`
/// and the self-transfers (a recipient equal to the sender), with no ignore price. It reads each
/// percentile of the gas the remaining transactions used, not of the block's gas used. With no
/// transaction left, every reward is 0. erigon also drops a transaction whose sender it does not
/// know; a recovered block knows every sender.
pub fn calculate_pulsechain_reward_percentiles(
    percentiles: &[f64],
    txs: impl IntoIterator<Item = PulsechainReward>,
    coinbase: Address,
) -> Vec<u128> {
    let mut txs: Vec<_> = txs
        .into_iter()
        .filter(|tx| tx.sender != coinbase && tx.to != Some(tx.sender))
        .map(|tx| TxGasAndReward { gas_used: tx.gas_used, reward: tx.reward })
        .collect();
    if txs.is_empty() {
        return vec![0; percentiles.len()]
    }
    txs.sort_unstable_by_key(|tx| tx.reward);
    let total_filtered_gas: u64 = txs.iter().map(|tx| tx.gas_used).sum();

    let mut tx_index = 0;
    let mut cumulative_gas_used = txs[0].gas_used;
    let mut rewards = Vec::with_capacity(percentiles.len());
    for percentile in percentiles {
        let threshold = (total_filtered_gas as f64 * percentile / 100.) as u64;
        while cumulative_gas_used < threshold && tx_index < txs.len() - 1 {
            tx_index += 1;
            cumulative_gas_used += txs[tx_index].gas_used;
        }
        rewards.push(txs[tx_index].reward);
    }
    rewards
}

/// A cached entry for a block's fee history.
#[derive(Debug, Clone)]
pub struct FeeHistoryEntry<H = Header> {
    /// The full block header.
    pub header: H,
    /// Gas used ratio this block.
    pub gas_used_ratio: f64,
    /// The base per blob gas for EIP-4844.
    /// For pre EIP-4844 equals to zero.
    pub base_fee_per_blob_gas: Option<u128>,
    /// Blob gas used ratio for this block.
    ///
    /// Calculated as the ratio of blob gas used and the available blob data gas per block.
    /// Will be zero if no blob gas was used or pre EIP-4844.
    pub blob_gas_used_ratio: f64,
    /// Approximated rewards for the configured percentiles.
    pub rewards: Vec<u128>,
    /// Blob parameters for this block.
    pub blob_params: Option<BlobParams>,
}

impl<H> FeeHistoryEntry<H>
where
    H: BlockHeader + Clone,
{
    /// Creates a new entry from a sealed block.
    ///
    /// Note: This does not calculate the rewards for the block.
    pub fn new<B>(block: &SealedBlock<B>, blob_params: Option<BlobParams>) -> Self
    where
        B: Block<Header = H>,
    {
        let header = block.header();
        Self {
            header: block.header().clone(),
            gas_used_ratio: header.gas_used() as f64 / header.gas_limit() as f64,
            base_fee_per_blob_gas: header
                .excess_blob_gas()
                .and_then(|excess_blob_gas| Some(blob_params?.calc_blob_fee(excess_blob_gas))),
            blob_gas_used_ratio: checked_blob_gas_used_ratio(
                block.body().blob_gas_used(),
                blob_params
                    .as_ref()
                    .map(|params| params.max_blob_gas_per_block())
                    .unwrap_or(alloy_eips::eip4844::MAX_DATA_GAS_PER_BLOCK_DENCUN),
            ),
            rewards: Vec::new(),
            blob_params,
        }
    }

    /// Returns the blob fee for the next block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None.
    ///
    /// See also [`Self::next_block_excess_blob_gas`]
    pub fn next_block_blob_fee(&self) -> Option<u128> {
        self.header.maybe_next_block_blob_fee(self.blob_params)
    }

    /// Calculate excess blob gas for the next block according to the EIP-4844 spec.
    ///
    /// Returns a `None` if no excess blob gas is set, no EIP-4844 support
    pub fn next_block_excess_blob_gas(&self) -> Option<u64> {
        self.header.maybe_next_block_excess_blob_gas(self.blob_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{TxEip1559, TxType};
    use alloy_primitives::Signature;
    use reth_ethereum_primitives::{Receipt, Transaction as EthTransaction, TransactionSigned};

    #[test]
    fn reward_percentiles_use_receipt_gas_weight_for_eip8037() {
        const BASE_FEE: u64 = 1;
        const LOW_GAS: u64 = 100_000;
        const HIGH_GAS: u64 = 21_000;

        let low_tip = 1;
        let high_tip = 100_000_000_000;
        let transactions =
            [eip1559_transaction(low_tip, BASE_FEE), eip1559_transaction(high_tip, BASE_FEE)];
        let receipts = [receipt(LOW_GAS), receipt(LOW_GAS + HIGH_GAS)];

        let rewards =
            calculate_reward_percentiles_for_block(&[50.0], BASE_FEE, &transactions, &receipts)
                .unwrap();

        assert_eq!(rewards, vec![low_tip]);
    }

    fn eip1559_transaction(tip: u128, base_fee: u64) -> TransactionSigned {
        TransactionSigned::new_unhashed(
            EthTransaction::Eip1559(TxEip1559 {
                max_priority_fee_per_gas: tip,
                max_fee_per_gas: tip + base_fee as u128,
                ..Default::default()
            }),
            Signature::test_signature(),
        )
    }

    fn receipt(cumulative_gas_used: u64) -> Receipt {
        Receipt { tx_type: TxType::Eip1559, success: true, cumulative_gas_used, logs: Vec::new() }
    }
    // --- valve-tech fork: the `pulsechain` rewards ---

    const COINBASE: Address = Address::repeat_byte(0xc0);

    fn rtx(reward: u128, gas_used: u64, sender: u8, to: Option<u8>) -> PulsechainReward {
        PulsechainReward {
            sender: Address::repeat_byte(sender),
            to: to.map(Address::repeat_byte),
            reward,
            gas_used,
        }
    }

    fn pulsechain(percentiles: &[f64], txs: Vec<PulsechainReward>) -> Vec<u128> {
        calculate_pulsechain_reward_percentiles(percentiles, txs, COINBASE)
    }

    #[test]
    fn pulsechain_rewards_drop_the_coinbase() {
        let mut txs = vec![rtx(5, 21_000, 1, Some(2))];
        txs.push(PulsechainReward { sender: COINBASE, to: None, reward: 1, gas_used: 21_000 });
        assert_eq!(pulsechain(&[0.0, 100.0], txs), [5, 5]);
    }

    #[test]
    fn pulsechain_rewards_drop_self_transfers() {
        let txs =
            vec![rtx(1, 21_000, 1, Some(1)), rtx(5, 21_000, 2, Some(3)), rtx(7, 21_000, 4, None)];
        // a contract creation has no recipient and stays
        assert_eq!(pulsechain(&[0.0, 100.0], txs), [5, 7]);
    }

    #[test]
    fn pulsechain_rewards_apply_no_ignore_price() {
        let txs = vec![rtx(0, 21_000, 1, Some(2)), rtx(2, 21_000, 3, Some(4))];
        assert_eq!(pulsechain(&[0.0, 100.0], txs), [0, 2]);
    }

    /// The percentiles read the gas of the kept transactions. A dropped self-transfer that used
    /// most of the block's gas moves the 50th percentile; over the block's gas it would not.
    #[test]
    fn pulsechain_rewards_read_the_gas_of_the_kept_transactions() {
        let txs = vec![
            rtx(1, 21_000, 1, Some(2)),
            rtx(2, 21_000, 3, Some(4)),
            rtx(3, 21_000, 5, Some(6)),
            rtx(9, 1_000_000, 7, Some(7)),
        ];
        // kept gas 63,000: the 50th percentile threshold is 31,500, reached by the second. Over
        // the block's 1,063,000 gas it would be 531,500, never reached, and the answer 3.
        assert_eq!(pulsechain(&[50.0], txs), [2]);
    }

    #[test]
    fn pulsechain_rewards_are_zero_when_every_transaction_is_dropped() {
        let txs = vec![
            rtx(5, 21_000, 1, Some(1)),
            PulsechainReward { sender: COINBASE, to: None, reward: 6, gas_used: 21_000 },
        ];
        assert_eq!(pulsechain(&[10.0, 90.0], txs), [0, 0]);
        assert_eq!(pulsechain(&[10.0, 90.0], Vec::new()), [0, 0]);
    }

    /// One capture of `eth_feeHistory` from rpc.pulsechain.com, made by
    /// `testdata/gpo-pulsechain-fee-history/capture.py`.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Capture {
        histories: Vec<CaptureHistory>,
        blocks: Vec<CaptureBlock>,
    }

    #[derive(serde::Deserialize)]
    struct CaptureHistory {
        percentiles: Vec<f64>,
        reward: Vec<Vec<alloy_primitives::U128>>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CaptureBlock {
        number: u64,
        coinbase: Address,
        base_fee: Option<alloy_primitives::U64>,
        gas_used: u64,
        txs: Vec<CaptureTx>,
    }

    /// `[type, gasPrice or maxFeePerGas, maxPriorityFeePerGas, from, to, gasUsed]`
    type CaptureTx = (u8, U256, Option<U256>, Address, Option<Address>, u64);

    use alloy_primitives::U256;

    /// The captured block, with the captured senders, and its receipts.
    fn recovered(
        b: &CaptureBlock,
    ) -> (RecoveredBlock<reth_ethereum_primitives::Block>, Vec<Receipt>) {
        let mut senders = Vec::new();
        let mut transactions = Vec::new();
        let mut receipts = Vec::new();
        let mut cumulative_gas_used = 0;
        for &(kind, fee, priority, from, to, gas_used) in &b.txs {
            let fee: u128 = fee.to();
            let kind_to =
                to.map_or(alloy_primitives::TxKind::Create, alloy_primitives::TxKind::Call);
            let tx = match (kind, priority) {
                (0 | 1, None) => EthTransaction::Legacy(alloy_consensus::TxLegacy {
                    gas_price: fee,
                    to: kind_to,
                    ..Default::default()
                }),
                (2 | 4, Some(priority)) => EthTransaction::Eip1559(TxEip1559 {
                    max_fee_per_gas: fee,
                    max_priority_fee_per_gas: priority.to(),
                    to: kind_to,
                    ..Default::default()
                }),
                other => panic!("unexpected transaction shape {other:?}"),
            };
            transactions.push(TransactionSigned::new_unhashed(tx, Signature::test_signature()));
            senders.push(from);
            cumulative_gas_used += gas_used;
            receipts.push(receipt(cumulative_gas_used));
        }
        let block = reth_ethereum_primitives::Block {
            header: Header {
                number: b.number,
                beneficiary: b.coinbase,
                base_fee_per_gas: b.base_fee.map(|f| f.to()),
                gas_used: b.gas_used,
                gas_limit: 90_000_000,
                ..Default::default()
            },
            body: reth_ethereum_primitives::BlockBody { transactions, ..Default::default() },
        };
        (RecoveredBlock::new_unhashed(block, senders), receipts)
    }

    fn captures() -> Vec<(String, Capture)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/gpo-pulsechain-fee-history");
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

    fn want(history: &CaptureHistory, i: usize) -> Vec<u128> {
        history.reward[i].iter().map(|r| r.to()).collect()
    }

    /// The differential test: for each capture, each percentile set and each block, the
    /// pulsechain rewards equal rpc.pulsechain.com's `eth_feeHistory` rewards. reth's own rule
    /// misses some of them, so the test can fail.
    #[test]
    fn pulsechain_rewards_match_rpc_pulsechain_com() {
        let captures = captures();
        assert!(captures.len() >= 3, "expected at least 3 captures, found {}", captures.len());
        let (mut rows, mut reth_rows) = (0, 0);
        for (name, capture) in &captures {
            let blocks: Vec<_> = capture.blocks.iter().map(recovered).collect();
            for history in &capture.histories {
                for (i, (block, receipts)) in blocks.iter().enumerate() {
                    let ps = &history.percentiles;
                    let got = reward_percentiles_for_block(
                        GasPriceSampleMode::Pulsechain,
                        ps,
                        block,
                        receipts,
                    );
                    assert_eq!(got, want(history, i), "{name}: block {}, {ps:?}", block.number());
                    let reth =
                        reward_percentiles_for_block(GasPriceSampleMode::Reth, ps, block, receipts);
                    rows += 1;
                    reth_rows += usize::from(reth == want(history, i));
                }
            }
        }
        assert!(reth_rows < rows * 9 / 10, "reth's rule matched {reth_rows} of {rows} rows");
    }

    /// The fee history cache keeps pulsechain rewards for the percentiles on its grid.
    #[tokio::test]
    async fn the_cache_keeps_pulsechain_rewards() {
        let spec = reth_chainspec::ChainSpecBuilder::mainnet().build();
        for (name, capture) in &captures() {
            let blocks: Vec<_> = capture.blocks.iter().map(recovered).collect();
            let config = FeeHistoryCacheConfig {
                sample_mode: GasPriceSampleMode::Pulsechain,
                ..Default::default()
            };
            let cache = FeeHistoryCache::<Header>::new(config);
            cache.insert_blocks(blocks.iter().map(|(b, r)| (b, r.as_slice())), &spec).await;
            let first = capture.blocks[0].number;
            let last = capture.blocks.last().unwrap().number;
            let entries = cache.get_history(first, last).await.expect("cached");
            let resolution = cache.resolution() as f64;
            for history in &capture.histories {
                if !on_resolution_grid(&history.percentiles, cache.resolution()) {
                    continue
                }
                for (i, entry) in entries.iter().enumerate() {
                    let got: Vec<u128> = history
                        .percentiles
                        .iter()
                        .map(|p| entry.rewards[(p * resolution) as usize])
                        .collect();
                    assert_eq!(got, want(history, i), "{name}: entry {i}");
                }
            }
        }
    }

    #[test]
    fn the_resolution_grid() {
        assert!(on_resolution_grid(&[0.0, 12.5, 99.75, 100.0], 4));
        assert!(!on_resolution_grid(&[33.3], 4));
        assert!(!on_resolution_grid(&[12.5], 1));
    }
}
