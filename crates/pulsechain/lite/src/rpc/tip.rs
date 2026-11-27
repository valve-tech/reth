//! The tip that `eth_maxPriorityFeePerGas` answers on 369: erigon-pulse's gas price oracle, as
//! rpc.pulsechain.com runs it, over the blocks this node holds. pulse-reth runs the same
//! algorithm under `--gpo.sample-mode pulsechain`.
//!
//! erigon walks exactly 20 blocks back from the head; an empty block counts toward the 20. Per
//! block it drops tips under 1,000 gwei, transactions whose sender it does not know or that come
//! from the block's coinbase, and self-transfers. It keeps the lowest 40 percent of the rest (at
//! least 3, at most 1,000). It answers the 60th percentile of all samples, capped at 1 PLS. With
//! no sample it keeps its last answer.

use crate::chain::{HeaderChain, HeldBlock};
use alloy_consensus::{transaction::SignerRecoverable, Transaction as _, TxEnvelope};
use alloy_primitives::{map::B256Map, Address, B256};
use std::{collections::VecDeque, sync::Arc};

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

/// One block's samples, as erigon's `getBlockPrices` takes them, sorted ascending.
pub(super) fn block_samples(txs: impl IntoIterator<Item = TxTip>, coinbase: Address) -> Vec<u128> {
    let mut tips: Vec<u128> = txs
        .into_iter()
        .filter(|tx| {
            tx.tip >= IGNORE_PRICE &&
                tx.sender.is_some_and(|sender| sender != coinbase && tx.to != Some(sender))
        })
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

/// The oracle's state: each block's samples, computed once, and the answer for the last head.
#[derive(Debug)]
pub(super) struct TipOracle {
    /// The samples of recent blocks, by block hash. At most [`CACHED_BLOCKS`].
    samples: B256Map<Arc<[u128]>>,
    /// The keys of `samples`, oldest first.
    order: VecDeque<B256>,
    /// The head of the last answer, and the answer.
    last: (B256, u128),
    /// The senders recovered so far.
    pub(super) recovered: u64,
}

impl Default for TipOracle {
    fn default() -> Self {
        Self {
            samples: B256Map::default(),
            order: VecDeque::new(),
            last: (B256::ZERO, INITIAL_TIP),
            recovered: 0,
        }
    }
}

impl TipOracle {
    /// The tip at `head`. It walks 20 blocks back from `head`, or to the oldest block that
    /// `chain` holds with its body. An answer is computed once per head, and a block's samples
    /// once per block.
    pub(super) fn suggest(&mut self, chain: &HeaderChain, head: &HeldBlock) -> u128 {
        if self.last.0 == head.hash {
            return self.last.1
        }
        let mut samples = Vec::new();
        let mut block = Some(head.clone());
        for _ in 0..head.header.number.min(CHECK_BLOCKS) {
            let Some(b) = block else { break };
            samples.extend_from_slice(&self.block_samples(&b));
            block = chain.by_hash(&b.header.parent_hash);
        }
        let price = answer(samples, self.last.1);
        self.last = (head.hash, price);
        price
    }

    /// The samples of `b`, from the cache or computed and cached.
    fn block_samples(&mut self, b: &HeldBlock) -> Arc<[u128]> {
        if let Some(s) = self.samples.get(&b.hash) {
            return s.clone()
        }
        let base_fee = b.header.base_fee_per_gas;
        let txs = b.body.transactions.iter().map(|tx| TxTip {
            tip: effective_tip(tx, base_fee),
            sender: tx.recover_signer().ok(),
            to: tx.to(),
        });
        let s: Arc<[u128]> = block_samples(txs, b.header.beneficiary).into();
        self.recovered += b.body.transactions.len() as u64;
        if self.order.len() >= CACHED_BLOCKS &&
            let Some(old) = self.order.pop_front()
        {
            self.samples.remove(&old);
        }
        self.order.push_back(b.hash);
        self.samples.insert(b.hash, s.clone());
        s
    }

    /// The number of blocks whose samples are cached.
    #[cfg(test)]
    pub(super) fn cached_blocks(&self) -> usize {
        self.samples.len()
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
}
