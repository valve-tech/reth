//! The tip that `eth_maxPriorityFeePerGas` answers on 369: erigon-pulse's gas price oracle, as
//! rpc.pulsechain.com runs it, over the blocks this node holds. pulse-reth runs the same
//! algorithm under `--gpo.sample-mode pulsechain`.
//!
//! erigon walks exactly 20 blocks back from the head; an empty block counts toward the 20. Per
//! block it drops tips under 1,000 gwei, transactions whose sender it does not know or that come
//! from the block's coinbase, and self-transfers. It keeps the lowest 40 percent of the rest (at
//! least 3, at most 1,000). It answers the 60th percentile of all samples, capped at 1 PLS. With
//! no sample it keeps its last answer.
//!
//! The same module keeps which transactions erigon's `eth_feeHistory` rewards read on 369: those
//! with a known sender that is not the coinbase and that are no self-transfer, with no ignore
//! price ([`BlockTips::kept`]).

use crate::chain::{HeaderChain, HeldBlock};
use alloy_consensus::{transaction::SignerRecoverable, Transaction as _, TxEnvelope};
use alloy_primitives::{map::B256Map, Address, B256};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const GWEI: u128 = 1_000_000_000;
/// The blocks erigon walks back from the head.
const CHECK_BLOCKS: u64 = 20;
/// The percentile of the samples that erigon answers.
const PERCENTILE: usize = 60;
/// erigon ignores tips under 1,000 gwei.
const IGNORE_PRICE: u128 = 1_000 * GWEI;
/// erigon caps its answer at 1 PLS.
pub(super) const MAX_PRICE: u128 = 1_000_000_000_000_000_000;
/// erigon samples the lowest 40 percent of each block's filtered tips...
const SAMPLE_PERCENT: usize = 40;
/// ...and at least 3 of them, where the block has 3...
const MIN_SAMPLES: usize = 3;
/// ...and at most 1,000.
const MAX_SAMPLES: usize = 1_000;
/// The answer before the oracle has a sample. erigon starts at 0, but rpc.pulsechain.com never
/// shows it: its cache is warm, and 369 is never quiet for 20 blocks. A node that starts on a
/// quiet stretch should not tell wallets that a zero tip is enough. 50,000 gwei is what reth-lite
/// answered on 369 before it ran the oracle.
pub(super) const INITIAL_TIP: u128 = 50_000 * GWEI;
/// The blocks whose samples are kept: the window, and room for a reorganisation.
pub(super) const CACHED_BLOCKS: usize = 64;
/// The blocks outside the window whose tips a fee history keeps: one fee history's worth.
pub(super) const OTHER_BLOCKS: usize = 32;

/// One transaction as erigon's oracle reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TxTip {
    /// The effective tip, see [`effective_tip`].
    pub(super) tip: u128,
    /// The sender, `None` where it does not recover.
    pub(super) sender: Option<Address>,
    /// The recipient, `None` for a contract creation.
    pub(super) to: Option<Address>,
}

/// erigon's `GetEffectiveGasTip`: the tip `tx` pays over `base_fee`, and 0 where its fee cap is
/// under the base fee. Before London it is the priority fee or gas price.
pub(super) fn effective_tip(tx: &TxEnvelope, base_fee: Option<u64>) -> u128 {
    match base_fee {
        Some(base_fee) => tx.effective_tip_per_gas(base_fee).unwrap_or_default(),
        None => tx.priority_fee_or_price(),
    }
}

/// Whether erigon reads `tx` of a block with `coinbase`: its sender is known, is not the
/// coinbase, and is not its recipient.
pub(super) fn keeps(tx: &TxTip, coinbase: Address) -> bool {
    tx.sender.is_some_and(|sender| sender != coinbase && tx.to != Some(sender))
}

/// One block's samples, as erigon's `getBlockPrices` takes them, sorted ascending.
pub(super) fn block_samples(txs: impl IntoIterator<Item = TxTip>, coinbase: Address) -> Vec<u128> {
    let mut tips: Vec<u128> = txs
        .into_iter()
        .filter(|tx| tx.tip >= IGNORE_PRICE && keeps(tx, coinbase))
        .map(|tx| tx.tip)
        .collect();
    tips.sort_unstable();
    let keep =
        (tips.len() * SAMPLE_PERCENT / 100).max(MIN_SAMPLES).min(tips.len()).min(MAX_SAMPLES);
    tips.truncate(keep);
    tips
}

/// The answer over `samples`, or `last` when there is none.
pub(super) fn answer(mut samples: Vec<u128>, last: u128) -> u128 {
    if samples.is_empty() {
        return last.min(MAX_PRICE)
    }
    samples.sort_unstable();
    samples[(samples.len() - 1) * PERCENTILE / 100].min(MAX_PRICE)
}

/// erigon's `eth_feeHistory` rewards at `percentiles`, from each transaction's tip, gas used and
/// whether erigon keeps it ([`keeps`]). It reads each percentile of the gas the kept
/// transactions used, and answers zeros when none is kept.
pub(super) fn rewards(
    txs: impl IntoIterator<Item = (u128, u64, bool)>,
    percentiles: &[f64],
) -> Vec<u128> {
    let mut txs: Vec<(u128, u64)> =
        txs.into_iter().filter(|(.., kept)| *kept).map(|(tip, gas, _)| (tip, gas)).collect();
    if txs.is_empty() {
        return vec![0; percentiles.len()]
    }
    txs.sort_by_key(|(tip, _)| *tip);
    let total: u64 = txs.iter().map(|(_, gas)| gas).sum();
    let (mut at, mut sum) = (0, txs[0].1);
    let mut out = Vec::with_capacity(percentiles.len());
    for p in percentiles {
        // As erigon: the float threshold truncated to whole gas.
        let threshold = (total as f64 * p / 100.0) as u64;
        while sum < threshold && at < txs.len() - 1 {
            at += 1;
            sum = sum.saturating_add(txs[at].1);
        }
        out.push(txs[at].0);
    }
    out
}

/// What the oracle keeps of one block: its samples, and which transactions erigon's rewards
/// read. [`block_tips`] computes it.
#[derive(Debug)]
pub(super) struct BlockTips {
    /// The block's tip samples ([`block_samples`]).
    samples: Box<[u128]>,
    /// Which of the block's transactions erigon's rewards read ([`keeps`]), in block order.
    pub(super) kept: Box<[bool]>,
}

/// What the oracle keeps of `b`. It recovers each sender of `b`: the caller runs it off the
/// async workers, and with no lock held.
pub(super) fn block_tips(b: &HeldBlock) -> BlockTips {
    let base_fee = b.header.base_fee_per_gas;
    let txs: Vec<TxTip> = b
        .body
        .transactions
        .iter()
        .map(|tx| TxTip {
            tip: effective_tip(tx, base_fee),
            sender: tx.recover_signer().ok(),
            to: tx.to(),
        })
        .collect();
    let coinbase = b.header.beneficiary;
    BlockTips {
        kept: txs.iter().map(|tx| keeps(tx, coinbase)).collect(),
        samples: block_samples(txs, coinbase).into(),
    }
}

/// The blocks the tip at `head` reads: `head` and its parents, 20 at most, as far back as `chain`
/// holds them with their bodies, and never the genesis block.
pub(super) fn window(chain: &HeaderChain, head: &HeldBlock) -> Vec<HeldBlock> {
    let mut out = Vec::new();
    let mut block = Some(head.clone());
    for _ in 0..head.header.number.min(CHECK_BLOCKS) {
        let Some(b) = block else { break };
        block = chain.by_hash(&b.header.parent_hash);
        out.push(b);
    }
    out
}

/// [`BlockTips`] by block hash, at most `max`, the oldest pushed out first.
#[derive(Debug)]
struct BlockCache {
    blocks: B256Map<Arc<BlockTips>>,
    order: VecDeque<B256>,
    max: usize,
}

impl BlockCache {
    fn new(max: usize) -> Self {
        Self { blocks: B256Map::default(), order: VecDeque::new(), max }
    }

    fn get(&self, hash: &B256) -> Option<Arc<BlockTips>> {
        self.blocks.get(hash).cloned()
    }

    fn insert(&mut self, hash: B256, tips: Arc<BlockTips>) {
        if self.blocks.contains_key(&hash) {
            return
        }
        if self.order.len() >= self.max &&
            let Some(old) = self.order.pop_front()
        {
            self.blocks.remove(&old);
        }
        self.order.push_back(hash);
        self.blocks.insert(hash, tips);
    }
}

/// The oracle's state. Every lock is held only for a lookup or an insert: senders are recovered
/// by [`block_tips`] with no lock held.
#[derive(Debug)]
pub(super) struct TipOracle {
    /// The blocks of the tip window. Only the tip's walk ([`window`]) inserts here, so a fee
    /// history over older blocks never pushes the window out.
    window: Mutex<BlockCache>,
    /// The blocks an `eth_feeHistory` read that the window cache did not hold.
    others: Mutex<BlockCache>,
    /// The head of the last answer, and the answer.
    last: Mutex<(B256, u128)>,
    /// One tip computation at a time, so that calls at a new head recover its senders once.
    /// Held across the recovery, but it guards no state: a call at an answered head never
    /// takes it.
    computing: tokio::sync::Mutex<()>,
    /// The senders recovered so far.
    pub(super) recovered: AtomicU64,
}

impl Default for TipOracle {
    fn default() -> Self {
        Self {
            window: Mutex::new(BlockCache::new(CACHED_BLOCKS)),
            others: Mutex::new(BlockCache::new(OTHER_BLOCKS)),
            last: Mutex::new((B256::ZERO, INITIAL_TIP)),
            computing: tokio::sync::Mutex::new(()),
            recovered: AtomicU64::new(0),
        }
    }
}

impl TipOracle {
    /// The answer at `head`, if the oracle has it.
    pub(super) fn answered(&self, head: &B256) -> Option<u128> {
        let last = self.last.lock();
        (last.0 == *head).then_some(last.1)
    }

    /// The computation guard: see [`Self::computing`].
    pub(super) async fn computing(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.computing.lock().await
    }

    /// The blocks of `blocks` whose tips the window cache does not hold.
    pub(super) fn missing(&self, blocks: &[HeldBlock]) -> Vec<HeldBlock> {
        let window = self.window.lock();
        blocks.iter().filter(|b| window.get(&b.hash).is_none()).cloned().collect()
    }

    /// Caches the tips of window blocks that [`block_tips`] computed.
    pub(super) fn insert_window(&self, computed: Vec<(B256, usize, BlockTips)>) {
        let mut window = self.window.lock();
        for (hash, txs, tips) in computed {
            self.recovered.fetch_add(txs as u64, Ordering::Relaxed);
            window.insert(hash, Arc::new(tips));
        }
    }

    /// The tip at `head` over `blocks`, its [`window`], whose tips are cached: computes and
    /// stores the answer. A block that is no longer cached gives no sample.
    pub(super) fn answer_over(&self, head: &B256, blocks: &[HeldBlock]) -> u128 {
        let samples: Vec<u128> = {
            let window = self.window.lock();
            blocks
                .iter()
                .filter_map(|b| window.get(&b.hash))
                .flat_map(|t| t.samples.to_vec())
                .collect()
        };
        let mut last = self.last.lock();
        let price = answer(samples, last.1);
        *last = (*head, price);
        price
    }

    /// The tips of `hash` for a fee history, from either cache.
    pub(super) fn cached(&self, hash: &B256) -> Option<Arc<BlockTips>> {
        self.window.lock().get(hash).or_else(|| self.others.lock().get(hash))
    }

    /// Caches the tips of a block a fee history read, apart from the window.
    pub(super) fn insert_other(&self, hash: B256, txs: usize, tips: Arc<BlockTips>) {
        self.recovered.fetch_add(txs as u64, Ordering::Relaxed);
        self.others.lock().insert(hash, tips);
    }

    /// Whether the window cache holds `hash`.
    #[cfg(test)]
    pub(super) fn in_window(&self, hash: &B256) -> bool {
        self.window.lock().get(hash).is_some()
    }

    /// The number of blocks each cache holds: the window, the others.
    #[cfg(test)]
    pub(super) fn cached_blocks(&self) -> (usize, usize) {
        (self.window.lock().blocks.len(), self.others.lock().blocks.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    const COINBASE: Address = Address::repeat_byte(0xc0);

    fn tx(tip: u128, sender: u8, to: Option<u8>) -> TxTip {
        TxTip { tip, sender: Some(Address::repeat_byte(sender)), to: to.map(Address::repeat_byte) }
    }

    #[test]
    fn each_erigon_filter_drops_its_transactions() {
        let txs = vec![
            tx(2_000 * GWEI, 1, Some(2)),
            // under the ignore price
            tx(IGNORE_PRICE - 1, 3, Some(4)),
            // from the coinbase
            TxTip { tip: 1_500 * GWEI, sender: Some(COINBASE), to: None },
            // a self-transfer
            tx(1_200 * GWEI, 5, Some(5)),
            // an unknown sender
            TxTip { tip: 1_100 * GWEI, sender: None, to: None },
            // a creation is no self-transfer
            tx(3_000 * GWEI, 6, None),
        ];
        assert_eq!(block_samples(txs, COINBASE), [2_000 * GWEI, 3_000 * GWEI]);
    }

    #[test]
    fn a_block_gives_its_lowest_40_percent_and_at_least_3() {
        let block = |n: u8| (0..n).rev().map(|i| tx(IGNORE_PRICE + u128::from(i), i, Some(i + 1)));
        let lowest = |n: u128| (0..n).map(|i| IGNORE_PRICE + i).collect::<Vec<_>>();
        assert_eq!(block_samples(block(20), COINBASE), lowest(8));
        assert_eq!(block_samples(block(5), COINBASE), lowest(3));
        assert_eq!(block_samples(block(2), COINBASE), lowest(2));
        let many = (0..3_000).map(|i| tx(IGNORE_PRICE + i, 1, None));
        assert_eq!(block_samples(many, COINBASE).len(), MAX_SAMPLES);
    }

    #[test]
    fn the_answer_is_the_60th_percentile_capped_at_1_pls() {
        assert_eq!(answer(vec![5, 1, 4, 2, 3], 9), 3);
        assert_eq!(answer(Vec::new(), 9), 9);
        assert_eq!(answer(vec![3 * MAX_PRICE], 9), MAX_PRICE);
    }

    /// One capture from rpc.pulsechain.com, shared with pulse-reth's oracle tests.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Capture {
        max_priority_fee_per_gas: U256,
        blocks: Vec<CaptureBlock>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CaptureBlock {
        coinbase: Address,
        base_fee: Option<alloy_primitives::U64>,
        txs: Vec<CaptureTx>,
    }

    /// One captured transaction: `[type, gasPrice or maxFeePerGas, maxPriorityFeePerGas, from,
    /// to]`.
    type CaptureTx = (u8, U256, Option<U256>, Address, Option<Address>);

    /// A transaction with the capture's fee fields. Its signature is a placeholder: the capture
    /// names the sender.
    fn envelope(kind: u8, fee: u128, priority: Option<U256>) -> TxEnvelope {
        use alloy_consensus::Signed;
        let sig = alloy_primitives::Signature::test_signature();
        match (kind, priority) {
            (0 | 1, None) => TxEnvelope::Legacy(Signed::new_unhashed(
                alloy_consensus::TxLegacy { gas_price: fee, ..Default::default() },
                sig,
            )),
            (2 | 4, Some(priority)) => TxEnvelope::Eip1559(Signed::new_unhashed(
                alloy_consensus::TxEip1559 {
                    max_fee_per_gas: fee,
                    max_priority_fee_per_gas: priority.to(),
                    ..Default::default()
                },
                sig,
            )),
            other => panic!("unexpected transaction shape {other:?}"),
        }
    }

    /// The differential test: over each capture's 20 blocks, the oracle gives the answer that
    /// rpc.pulsechain.com gave.
    #[test]
    fn the_oracle_matches_rpc_pulsechain_com_on_each_capture() {
        let dir =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../rpc/rpc-eth-types/testdata/gpo-pulsechain");
        let mut n = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "json") {
                continue
            }
            let capture: Capture = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let samples = capture
                .blocks
                .iter()
                .flat_map(|b| {
                    let base_fee = b.base_fee.map(|f| f.to());
                    let txs = b.txs.iter().map(move |&(kind, fee, priority, from, to)| TxTip {
                        tip: effective_tip(&envelope(kind, fee.to(), priority), base_fee),
                        sender: Some(from),
                        to,
                    });
                    block_samples(txs, b.coinbase)
                })
                .collect();
            assert_eq!(
                U256::from(answer(samples, 0)),
                capture.max_priority_fee_per_gas,
                "{}",
                path.display()
            );
            n += 1;
        }
        assert!(n >= 5, "expected at least 5 captures, found {n}");
    }
    #[test]
    fn erigons_rewards_keep_what_keeps_keeps() {
        // the coinbase, a self-transfer and an unknown sender are not read; a low tip is
        let cases = [
            (TxTip { tip: 1, sender: Some(COINBASE), to: None }, false),
            (tx(1, 5, Some(5)), false),
            (TxTip { tip: 1, sender: None, to: None }, false),
            (tx(0, 1, Some(2)), true),
            (tx(1, 6, None), true),
        ];
        for (t, want) in cases {
            assert_eq!(keeps(&t, COINBASE), want, "{t:?}");
        }
    }

    #[test]
    fn erigons_rewards_read_the_gas_of_the_kept_transactions() {
        // the dropped transaction used most of the gas: over all gas the 50th percentile would
        // be the 3; over the kept 40k it is the 1
        let txs = [(3, 60_000, false), (1, 20_000, true), (2, 20_000, true)];
        assert_eq!(rewards(txs, &[0.0, 50.0, 100.0]), [1, 1, 2]);
        assert_eq!(rewards(txs.map(|(t, g, _)| (t, g, true)), &[50.0]), [3]);
    }

    #[test]
    fn erigons_rewards_are_zero_when_nothing_is_kept() {
        assert_eq!(rewards([(3, 21_000, false)], &[10.0, 90.0]), [0, 0]);
        assert_eq!(rewards([], &[10.0, 90.0]), [0, 0]);
    }

    /// One capture of `eth_feeHistory`, shared with pulse-reth's fee history tests.
    #[derive(serde::Deserialize)]
    struct FeeCapture {
        histories: Vec<FeeHistory>,
        blocks: Vec<FeeBlock>,
    }

    #[derive(serde::Deserialize)]
    struct FeeHistory {
        percentiles: Vec<f64>,
        reward: Vec<Vec<alloy_primitives::U128>>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FeeBlock {
        coinbase: Address,
        base_fee: Option<alloy_primitives::U64>,
        txs: Vec<FeeTx>,
    }

    /// `[type, gasPrice or maxFeePerGas, maxPriorityFeePerGas, from, to, gasUsed]`
    type FeeTx = (u8, U256, Option<U256>, Address, Option<Address>, u64);

    /// The differential test of the rewards: each block of each capture, at each percentile
    /// set, gets rpc.pulsechain.com's `eth_feeHistory` rewards.
    #[test]
    fn the_rewards_match_rpc_pulsechain_com_on_each_capture() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rpc/rpc-eth-types/testdata/gpo-pulsechain-fee-history"
        );
        let mut rows = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "json") {
                continue
            }
            let capture: FeeCapture =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            for history in &capture.histories {
                for (b, want) in capture.blocks.iter().zip(&history.reward) {
                    let base_fee = b.base_fee.map(|f| f.to());
                    let txs = b.txs.iter().map(|&(kind, fee, priority, from, to, gas)| {
                        let tip = effective_tip(&envelope(kind, fee.to(), priority), base_fee);
                        (tip, gas, keeps(&TxTip { tip, sender: Some(from), to }, b.coinbase))
                    });
                    let want: Vec<u128> = want.iter().map(|r| r.to()).collect();
                    assert_eq!(rewards(txs, &history.percentiles), want, "{}", path.display());
                    rows += 1;
                }
            }
        }
        assert!(rows >= 3 * 8 * 4, "expected 3 captures of 8 blocks and 4 sets, found {rows} rows");
    }
}
