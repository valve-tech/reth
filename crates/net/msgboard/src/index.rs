//! Ordered in-memory index of live msgboard messages.
//!
//! Messages are kept sorted so the lowest-precedence entries land at the
//! front of the vec and `evict_oldest` always pops `msgs[0]`. The insertion
//! comparator mirrors `MsgIndex.Insert` in erigon-pulse's
//! `msgboard/message_index.go`:
//!
//! ```text
//! if new sorts at or after the tail -> append
//! else pos = first i where (newMsg.block_number < msgs[i].block_number
//!                           || (newMsg.block_number == msgs[i].block_number
//!                               && newMsg.ratio < msgs[i].ratio))
//! ```
//!
//! The ratio term is guarded by block equality, so the comparator is a strict
//! `(block, ratio)` lexicographic order. Reth matches it exactly, so
//! `evict_oldest` removes the **same** message under the **same** input
//! sequence as erigon, preserving wire-observable parity when the board sits
//! at its count limit.
//!
//! Erigon added that guard in `pulse-v3.4.4` (`78fbcffb8b`). Before it the
//! ratio term stood alone in the `OR` and the comparator was non-monotonic,
//! which made the resulting order depend on insertion sequence. See
//! [`erigon_insert_pos`] for what adopting the guard moves.
//!
//! Because the predicate is non-monotonic, the resulting order depends on
//! *how* the position is found, not just on the comparator: any binary search
//! probes a subset of indices and can stop at a later position than the first
//! one that satisfies the predicate. erigon does not binary-search at all — it
//! scans linearly from index 0, behind a fast path that appends when the new
//! message already sorts at or after the tail. [`erigon_insert_pos`] ports
//! that, so no binary search may be substituted for it.

use std::{cmp::Ordering, collections::HashMap, sync::Arc};

use alloy_primitives::B256;
use reth_msgboard_types::CheckedPoWMsg;

/// In-memory index of live messages with O(1) hash lookups and ordered eviction.
#[derive(Debug, Default)]
pub struct MsgIndex {
    /// Sorted `(block_number ASC, difficulty_ratio ASC)`. Eviction removes `msgs[0]`.
    msgs: Vec<Arc<CheckedPoWMsg>>,
    /// Fast lookup by `PoW` hash.
    by_hash: HashMap<B256, Arc<CheckedPoWMsg>>,
    /// Category hash → { message hash → message }.
    categories: HashMap<B256, HashMap<B256, Arc<CheckedPoWMsg>>>,
    /// Sum of all message `data` field lengths in bytes.
    total_size: u64,
}

impl MsgIndex {
    /// Insert a message. Returns `false` if the message is already present.
    pub fn insert(&mut self, msg: Arc<CheckedPoWMsg>) -> bool {
        if self.by_hash.contains_key(&msg.hash) {
            return false;
        }

        let pos = erigon_insert_pos(
            &self.msgs,
            msg.block_number,
            msg.msg.work_multiplier,
            msg.msg.work_divisor,
        );
        self.total_size += msg.msg.data.len() as u64;
        self.msgs.insert(pos, Arc::clone(&msg));
        self.by_hash.insert(msg.hash, Arc::clone(&msg));
        self.categories.entry(msg.msg.category).or_default().insert(msg.hash, Arc::clone(&msg));
        true
    }

    /// Remove a message by hash. Returns the removed message, if present.
    pub fn remove(&mut self, hash: &B256) -> Option<Arc<CheckedPoWMsg>> {
        let msg = self.by_hash.remove(hash)?;
        self.total_size = self.total_size.saturating_sub(msg.msg.data.len() as u64);

        // O(1) fast path: evicting the oldest message (front of sorted vec).
        if self.msgs.first().map(|m| &m.hash) == Some(hash) {
            self.msgs.remove(0);
        } else {
            self.msgs.retain(|m| &m.hash != hash);
        }

        if let Some(cat_map) = self.categories.get_mut(&msg.msg.category) {
            cat_map.remove(hash);
            if cat_map.is_empty() {
                self.categories.remove(&msg.msg.category);
            }
        }
        Some(msg)
    }

    /// Remove and return the oldest message (smallest `block_number` / `difficulty_ratio`).
    pub fn evict_oldest(&mut self) -> Option<Arc<CheckedPoWMsg>> {
        let hash = self.msgs.first()?.hash;
        self.remove(&hash)
    }

    /// Returns `true` if a message with this hash is already indexed.
    pub fn has(&self, hash: &B256) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Look up a message by its `PoW` hash.
    pub fn get(&self, hash: &B256) -> Option<Arc<CheckedPoWMsg>> {
        self.by_hash.get(hash).cloned()
    }

    /// All messages in sorted order.
    pub fn all_msgs(&self) -> &[Arc<CheckedPoWMsg>] {
        &self.msgs
    }

    /// All known category hashes.
    pub fn categories(&self) -> impl Iterator<Item = &B256> {
        self.categories.keys()
    }

    /// All messages belonging to `category`, in board precedence order.
    ///
    /// Walks the ordered `msgs` vec rather than the `categories` map. Iterating
    /// a `HashMap`'s values yields an arbitrary order that varies between runs
    /// and between nodes, which would make `msgboard_content` non-reproducible
    /// and inconsistent with [`all_msgs_filtered`](Self::all_msgs_filtered)
    /// (which returns precedence order). Precedence order is not recoverable by
    /// sorting the collected values afterwards: it is defined by erigon's
    /// non-total OR-comparator and the insertion history, not by any key.
    ///
    /// **Deliberate divergence from erigon.** Erigon's `CategoryMsgs` ranges
    /// over `m.categories[cat]`, a Go map, so its category-filtered
    /// `msgboard_content` is randomised *per call* — Go deliberately seeds map
    /// iteration order. There is no erigon order to match: any fixed order
    /// differs from it on nearly every call, and reth returns a deterministic
    /// one rather than reproducing the randomisation.
    ///
    /// The cost is `O(len)` rather than `O(category size)`. The board is capped
    /// at `count_limit` (default 10,000) and this is an RPC-only path, never
    /// the P2P hot path.
    pub fn category_msgs(&self, category: &B256) -> impl Iterator<Item = &Arc<CheckedPoWMsg>> {
        self.msgs.iter().filter(move |m| &m.msg.category == category)
    }

    /// All messages belonging to `category` filtered by block range, in board
    /// precedence order. See [`category_msgs`](Self::category_msgs) for why
    /// this walks the ordered vec.
    pub fn category_msgs_filtered(
        &self,
        category: &B256,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<Arc<CheckedPoWMsg>> {
        self.category_msgs(category)
            .filter(|m| {
                from_block.map_or(true, |f| m.block_number >= f) &&
                    to_block.map_or(true, |t| m.block_number <= t)
            })
            .cloned()
            .collect()
    }

    /// All messages across all categories filtered by block range.
    ///
    /// **Accepted divergence from erigon — see `docs/msgboard-parity-gaps.md`
    /// §13.4.** Erigon's `MsgIndex.Msgs` does not filter per message. It seeks
    /// a lower and an upper index and returns the contiguous slice between
    /// them, commenting "assuming msgs are sorted by block number".
    ///
    /// Since `pulse-v3.4.4` guarded the insert comparator that assumption
    /// holds, so the seeked slice and a per-message filter now agree on any
    /// range that matches something. One divergence survives: when *no*
    /// message satisfies a bound, erigon's seek never fires, the index keeps
    /// its initial value, and the filter fails open — a query whose range
    /// matches nothing returns the whole board.
    ///
    /// Reth filters per message, deliberately. Reproducing erigon here would
    /// mean handing an operator the entire board when they asked for a range
    /// containing none of it, and the parity argument that governs
    /// [`erigon_insert_pos`] does not reach this far: nothing about the filter
    /// is wire-observable, so a peer cannot tell the two apart and no eviction,
    /// gossip, or `PoW` decision depends on it. `msgboard_content` clients that
    /// pass a block range see a narrower, correct result.
    ///
    /// [`category_msgs_filtered`](Self::category_msgs_filtered) is **not**
    /// divergent — erigon's `CategoryMsgs` skips per message, like reth.
    /// `all_msgs_filtered_diverges_only_when_erigons_seek_fails_open` pins both.
    pub fn all_msgs_filtered(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<Arc<CheckedPoWMsg>> {
        self.msgs
            .iter()
            .filter(|m| {
                from_block.map_or(true, |f| m.block_number >= f) &&
                    to_block.map_or(true, |t| m.block_number <= t)
            })
            .cloned()
            .collect()
    }

    /// Number of messages in the index.
    pub const fn len(&self) -> usize {
        self.msgs.len()
    }

    /// Returns `true` if the index is empty.
    pub const fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    /// Total size in bytes of all message `data` fields.
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }
}

/// Insert position for a message, matching erigon-pulse's `MsgIndex.Insert`
/// (`msgboard/message_index.go:149` at `pulse-v3.4.4`).
///
/// Erigon does two things, in order: a fast path that appends when the new
/// message already sorts at or after the tail, then a **linear scan** from
/// index 0 for the first entry the comparator says the new message sorts
/// below. Keep the scan. Erigon still scans, so a binary search is a
/// divergence to justify rather than a free win, and the board is bounded by
/// `count_limit` anyway.
///
/// The comparator orders by block number first and compares the work ratio
/// only within one block. `pulse-v3.4.4` added that block-equality guard; the
/// release before it left the ratio term standing alone in the `OR`, which
/// made the comparator non-monotonic — the order then depended on the
/// insertion sequence, not just on the set of messages. Adopting the guard
/// moves 74.6% of board orders and 39.4% of `msgs[0]` values (the entry
/// `evict_oldest` drops) across the corpus in
/// `insert_order_matches_erigon_insert_over_200k_sequences`.
///
/// The fast path is not merely an optimisation. It appends on a ratio equal to
/// the tail's, where the scan's strict `<` would have found an earlier
/// position, so removing it changes the result.
fn erigon_insert_pos(
    msgs: &[Arc<CheckedPoWMsg>],
    new_block: u64,
    new_mult: u64,
    new_div: u64,
) -> usize {
    let Some(last) = msgs.last() else { return 0 };

    if new_block > last.block_number ||
        (new_block == last.block_number &&
            cmp_ratio(new_mult, new_div, last.msg.work_multiplier, last.msg.work_divisor)
                .is_ge())
    {
        return msgs.len();
    }

    // Reaching here means the new message sorts below the tail under the
    // comparator, so the tail itself always satisfies the predicate and the
    // scan cannot come up empty. Erigon relies on this too: its loop `break`s
    // with no fallback, and would leave the message in the category map but
    // absent from the ordered list if the position were ever missed. Appending
    // is the safe reading of that unreachable branch — reth must not silently
    // drop a message it reported as accepted.
    msgs.iter()
        .position(|m| {
            new_block < m.block_number ||
                (new_block == m.block_number &&
                    cmp_ratio(new_mult, new_div, m.msg.work_multiplier, m.msg.work_divisor)
                        .is_lt())
        })
        .unwrap_or(msgs.len())
}

/// Compare the work ratios `a/b` and `c/d` exactly, as erigon's `cmpRatio`
/// (`msgboard/pow_message.go:234`) does.
///
/// Cross-multiplication in `u128` cannot overflow for `u64` inputs, so this
/// agrees with erigon's `bits.Mul64` pair on every input.
/// [`PoWMsg::difficulty_ratio`](reth_msgboard_types::PoWMsg::difficulty_ratio)
/// returns `f64` and stops separating ratios above 2^53, which is why board
/// ordering does not use it.
const fn cmp_ratio(a: u64, b: u64, c: u64, d: u64) -> Ordering {
    let left = (a as u128) * (d as u128);
    let right = (b as u128) * (c as u128);
    if left < right {
        Ordering::Less
    } else if left > right {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::B256;
    use reth_msgboard_types::{CheckedPoWMsg, PoWMsg, VERSION_V1};

    use super::*;

    // ── test helpers ─────────────────────────────────────────────────────────

    fn block_hash_one() -> B256 {
        let mut b = [0u8; 32];
        b[0] = 0x01;
        B256::from(b)
    }

    fn category(byte: u8) -> B256 {
        let mut b = [0u8; 32];
        b[0] = byte;
        B256::from(b)
    }

    fn make_pow_msg(nonce: u64, data: &[u8]) -> PoWMsg {
        PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: category(0xCA),
            data: alloy_primitives::Bytes::copy_from_slice(data),
        }
    }

    /// Brute-force search for a valid nonce (up to 1M iterations).
    fn find_nonce(data: &[u8]) -> u64 {
        for n in 1u64..=1_000_000 {
            if make_pow_msg(n, data).to_checked(0, 0).is_ok() {
                return n;
            }
        }
        panic!("no valid nonce found within 1M iterations for data={data:?}");
    }

    fn make_checked(block_number: u64, data_byte: u8) -> Arc<CheckedPoWMsg> {
        let nonce = find_nonce(&[data_byte]);
        let pow = make_pow_msg(nonce, &[data_byte]);
        Arc::new(pow.to_checked(block_number, 0).expect("valid pow"))
    }

    fn make_checked_with_category(
        block_number: u64,
        data_byte: u8,
        cat: B256,
    ) -> Arc<CheckedPoWMsg> {
        let mut pow = PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce: 1,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: cat,
            data: alloy_primitives::Bytes::copy_from_slice(&[data_byte]),
        };
        for n in 1u64..=1_000_000 {
            pow.nonce = n;
            if pow.clone().to_checked(block_number, 0).is_ok() {
                return Arc::new(pow.to_checked(block_number, 0).expect("valid"));
            }
        }
        panic!("no valid nonce found for category test");
    }

    /// Build a `CheckedPoWMsg` with an arbitrary `(block, ratio)` pair without
    /// mining valid `PoW`. Ordering only reads `block_number` and
    /// `difficulty_ratio`, so the unverified hash is irrelevant here and this
    /// keeps the comparator tests off the nonce-search hot path.
    fn fake_checked(block: u64, mult: u64, div: u64, hash_byte: u8) -> Arc<CheckedPoWMsg> {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = hash_byte;
        Arc::new(CheckedPoWMsg {
            msg: PoWMsg {
                version: VERSION_V1,
                block_hash: block_hash_one(),
                nonce: 1,
                work_multiplier: mult,
                work_divisor: div,
                category: category(0xCA),
                data: alloy_primitives::Bytes::copy_from_slice(&[hash_byte]),
            },
            block_number: block,
            timestamp: 0,
            hash: B256::from(hash_bytes),
        })
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn insert_returns_true_for_new_message() {
        let mut idx = MsgIndex::default();
        let msg = make_checked(1, 0);
        assert!(idx.insert(msg));
    }

    #[test]
    fn insert_returns_false_for_duplicate() {
        let mut idx = MsgIndex::default();
        let msg = make_checked(1, 0);
        assert!(idx.insert(Arc::clone(&msg)));
        assert!(!idx.insert(msg));
    }

    #[test]
    fn evict_oldest_removes_message_with_lowest_block_number() {
        let mut idx = MsgIndex::default();
        let m1 = make_checked(10, 0);
        let m2 = make_checked(20, 1);
        let m3 = make_checked(5, 2);

        idx.insert(Arc::clone(&m1));
        idx.insert(Arc::clone(&m2));
        idx.insert(Arc::clone(&m3));

        // m3 has block_number 5, should be evicted first
        let evicted = idx.evict_oldest().expect("some message evicted");
        assert_eq!(evicted.hash, m3.hash);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn evict_oldest_on_empty_index_returns_none() {
        let mut idx = MsgIndex::default();
        assert!(idx.evict_oldest().is_none());
    }

    #[test]
    fn messages_sorted_by_block_number_asc_then_difficulty_ratio_asc() {
        let mut idx = MsgIndex::default();

        let m_block10 = make_checked(10, 0);
        let m_block5 = make_checked(5, 1);
        let m_block1 = make_checked(1, 2);

        idx.insert(Arc::clone(&m_block10));
        idx.insert(Arc::clone(&m_block5));
        idx.insert(Arc::clone(&m_block1));

        let all = idx.all_msgs();
        assert_eq!(all[0].block_number, 1);
        assert_eq!(all[1].block_number, 5);
        assert_eq!(all[2].block_number, 10);
    }

    #[test]
    fn remove_by_hash_works_and_updates_total_size() {
        let mut idx = MsgIndex::default();
        let msg = make_checked(1, 42);
        let data_len = msg.msg.data.len() as u64;
        let hash = msg.hash;

        idx.insert(Arc::clone(&msg));
        assert_eq!(idx.total_size(), data_len);

        let removed = idx.remove(&hash);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().hash, hash);
        assert_eq!(idx.total_size(), 0);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn remove_unknown_hash_returns_none() {
        let mut idx = MsgIndex::default();
        let unknown = B256::repeat_byte(0xAB);
        assert!(idx.remove(&unknown).is_none());
    }

    #[test]
    fn category_tracking_insert_adds_remove_cleans_up_empty_categories() {
        let cat = category(0xBE);
        let mut idx = MsgIndex::default();
        let msg = make_checked_with_category(1, 0, cat);
        let hash = msg.hash;

        idx.insert(Arc::clone(&msg));

        // Category should exist
        let cats: Vec<_> = idx.categories().collect();
        assert!(cats.contains(&&cat));

        // Remove the only message in this category
        idx.remove(&hash);

        // Category should be cleaned up
        let cats_after: Vec<_> = idx.categories().collect();
        assert!(!cats_after.contains(&&cat));
    }

    #[test]
    fn category_msgs_filtered_works_with_from_block_to_block() {
        let cat = category(0xCC);
        let mut idx = MsgIndex::default();

        // Insert messages at blocks 5, 10, 15
        let m5 = make_checked_with_category(5, 0, cat);
        let m10 = make_checked_with_category(10, 1, cat);
        let m15 = make_checked_with_category(15, 2, cat);

        idx.insert(Arc::clone(&m5));
        idx.insert(Arc::clone(&m10));
        idx.insert(Arc::clone(&m15));

        // Filter [7, 12]: only m10
        let filtered = idx.category_msgs_filtered(&cat, Some(7), Some(12));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].hash, m10.hash);

        // Filter from_block only: m10, m15
        let filtered = idx.category_msgs_filtered(&cat, Some(10), None);
        assert_eq!(filtered.len(), 2);

        // Filter to_block only: m5, m10
        let filtered = idx.category_msgs_filtered(&cat, None, Some(10));
        assert_eq!(filtered.len(), 2);

        // No filter: all three
        let filtered = idx.category_msgs_filtered(&cat, None, None);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn len_and_total_size_track_correctly() {
        let mut idx = MsgIndex::default();
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.total_size(), 0);
        assert!(idx.is_empty());

        let m1 = make_checked(1, 0);
        let m2 = make_checked(2, 1);
        let size1 = m1.msg.data.len() as u64;
        let size2 = m2.msg.data.len() as u64;

        idx.insert(Arc::clone(&m1));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.total_size(), size1);
        assert!(!idx.is_empty());

        idx.insert(Arc::clone(&m2));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.total_size(), size1 + size2);

        idx.remove(&m1.hash);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.total_size(), size2);
    }

    #[test]
    fn has_returns_correct_values() {
        let mut idx = MsgIndex::default();
        let msg = make_checked(1, 0);

        assert!(!idx.has(&msg.hash));
        idx.insert(Arc::clone(&msg));
        assert!(idx.has(&msg.hash));
        idx.remove(&msg.hash);
        assert!(!idx.has(&msg.hash));
    }

    #[test]
    fn get_returns_correct_message() {
        let mut idx = MsgIndex::default();
        let msg = make_checked(1, 7);

        assert!(idx.get(&msg.hash).is_none());
        idx.insert(Arc::clone(&msg));
        let got = idx.get(&msg.hash).expect("should be present");
        assert_eq!(got.hash, msg.hash);
    }

    /// Locks the block-equality guard in the insert comparator.
    ///
    /// This is the case the guard changes. Erigon's pre-`pulse-v3.4.4` scan
    /// tested `new_ratio < msgs[i].ratio` on its own, so a lower-ratio message
    /// from a *later* block sorted ahead of an earlier block and landed at
    /// index 0. The guarded predicate compares ratios only inside one block,
    /// so the message sorts after every earlier block instead.
    ///
    /// Hand-built `CheckedPoWMsg`s pin arbitrary `(block, ratio)` pairs
    /// without mining valid `PoW` for each combination. The expected order
    /// comes from running erigon's `MsgIndex.Insert` at `78fbcffb8b` over this
    /// sequence in Go.
    #[test]
    fn insert_position_respects_the_block_equality_guard() {
        // Pre-seed: [(5, 0.10), (10, 0.10)] — same ratio, increasing block.
        let mut idx = MsgIndex::default();
        idx.insert(fake_checked(5, 100_000, 1_000_000, 0xA0));
        idx.insert(fake_checked(10, 100_000, 1_000_000, 0xA1));

        // Insert (10, 0.05). The scan skips i=0: block 10 is not below block 5,
        // and the ratios are not compared across different blocks. At i=1 the
        // blocks match and 0.05 < 0.10, so the message lands at index 1.
        let new_msg = fake_checked(10, 50_000, 1_000_000, 0xB0);
        idx.insert(Arc::clone(&new_msg));

        let order: Vec<u8> = idx.all_msgs().iter().map(|m| m.hash[0]).collect();
        assert_eq!(order, vec![0xA0, 0xB0, 0xA1], "must match erigon's guarded comparator");

        // The eviction target stays the block-5 message. Under the unguarded
        // comparator it was the message just inserted, which sent erigon down
        // its self-displacement `BoardOverflow` branch at `count_limit` = 1.
        assert_eq!(idx.all_msgs()[0].hash[0], 0xA0, "eviction target must match erigon's");
    }

    /// Differential test against erigon's real `MsgIndex.Insert`, run in Go.
    ///
    /// Replays `200_000` pseudo-random insert sequences (~1.7M inserts) through
    /// [`MsgIndex::insert`] and FNV-1a hashes every resulting board order into
    /// a single digest. [`ERIGON_INSERT_DIGEST`] is the value produced by
    /// erigon's own insert routine, so a match means reth's ordering is
    /// identical to erigon's across the whole corpus — not just on the
    /// hand-picked cases above.
    ///
    /// The digest tracks `pulse-v3.4.4` (`78fbcffb8b`), whose comparator guards
    /// the ratio term with block equality. The unguarded comparator that came
    /// before it yields `14248539691690691664` over this same corpus; the two
    /// disagree on 74.6% of board orders and on 39.4% of `msgs[0]` values —
    /// the entry `evict_oldest` drops. Any change to the insert position, the
    /// comparator, or the ratio comparison moves the digest.
    ///
    /// The guarded comparator is monotonic, so a binary search over the same
    /// predicate now reproduces the scan exactly: Go's `sort.Search` yields
    /// this digest, not a different one. That was **not** true of the
    /// unguarded comparator, under which a search reordered most boards. The
    /// scan stays because erigon scans, not because a search is unsafe.
    ///
    /// The Go body below is `msgboard/message_index.go`'s `Insert` verbatim,
    /// with only the duplicate/`addToMap` handling elided — the corpus never
    /// repeats an id. To regenerate the constant (requires a Go toolchain):
    ///
    /// ```text
    /// package main
    ///
    /// import (
    ///     "fmt"
    ///     "math/bits"
    /// )
    ///
    /// type M struct { block, mult, div uint64; id uint8 }
    /// type R struct{ s uint64 }
    /// func (r *R) next() uint64 { x:=r.s; x^=x<<13; x^=x>>7; x^=x<<17; r.s=x; return x }
    ///
    /// func cmpRatio(a, b, c, d uint64) int {
    ///     hi1, lo1 := bits.Mul64(a, d)
    ///     hi2, lo2 := bits.Mul64(b, c)
    ///     switch {
    ///     case hi1 < hi2 || (hi1 == hi2 && lo1 < lo2): return -1
    ///     case hi1 > hi2 || (hi1 == hi2 && lo1 > lo2): return 1
    ///     default: return 0
    ///     }
    /// }
    ///
    /// func erigonInsert(msgs []M, newMsg M) []M {
    ///     if len(msgs) == 0 { return append(msgs, newMsg) }
    ///     last := msgs[len(msgs)-1]
    ///     if newMsg.block > last.block ||
    ///         (newMsg.block == last.block &&
    ///          cmpRatio(newMsg.mult, newMsg.div, last.mult, last.div) >= 0) {
    ///         return append(msgs, newMsg)
    ///     }
    ///     for i, msg := range msgs {
    ///         if newMsg.block < msg.block ||
    ///             (newMsg.block == msg.block &&
    ///              cmpRatio(newMsg.mult, newMsg.div, msg.mult, msg.div) < 0) {
    ///             out := make([]M, 0, len(msgs)+1)
    ///             out = append(out, msgs[:i]...)
    ///             out = append(out, newMsg)
    ///             out = append(out, msgs[i:]...)
    ///             return out
    ///         }
    ///     }
    ///     panic("erigon: no insert position found")
    /// }
    ///
    /// func main() {
    ///     blocks := []uint64{1,2,3,5,8,10,15,20}
    ///     mults := []uint64{10_000,50_000,100_000,200_000,500_000}
    ///     const div = uint64(1_000_000)
    ///     rng := &R{0xDEADBEEF}
    ///     var h uint64 = 14695981039346656037
    ///     mix := func(b byte) { h ^= uint64(b); h *= 1099511628211 }
    ///     for t := 0; t < 200000; t++ {
    ///         n := int(3 + rng.next()%12)
    ///         seq := make([]M, 0, n)
    ///         for id := 0; id < n; id++ {
    ///             b := blocks[rng.next()%uint64(len(blocks))]
    ///             m := mults[rng.next()%uint64(len(mults))]
    ///             seq = append(seq, M{b, m, div, uint8(id)})
    ///         }
    ///         board := make([]M, 0, n)
    ///         for _, m := range seq { board = erigonInsert(board, m) }
    ///         for _, m := range board { mix(m.id) }
    ///         mix(255)
    ///     }
    ///     fmt.Printf("%d\n", h)
    /// }
    /// ```
    ///
    /// The generator never panicked over the corpus, which is the empirical
    /// half of [`erigon_insert_pos`]'s claim that the scan cannot come up
    /// empty.
    ///
    /// The Rust side below must mirror that generator exactly: same xorshift
    /// seed and update, and the same draw order — `n`, then `block` then
    /// `mult` per message.
    #[test]
    fn insert_order_matches_erigon_insert_over_200k_sequences() {
        /// Digest produced by erigon's `MsgIndex.Insert` at `pulse-v3.4.4`, run in Go 1.23.
        const ERIGON_INSERT_DIGEST: u64 = 7673666368459825830;

        /// xorshift64 — must match the Go generator bit for bit.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
        }

        const BLOCKS: [u64; 8] = [1, 2, 3, 5, 8, 10, 15, 20];
        // Ratios 0.01, 0.05, 0.10, 0.20, 0.50 as `mult / 1_000_000`.
        const MULTS: [u64; 5] = [10_000, 50_000, 100_000, 200_000, 500_000];
        const DIV: u64 = 1_000_000;

        let mut rng = Rng(0xDEAD_BEEF);
        let mut digest: u64 = 14695981039346656037; // FNV-1a offset basis
        let mix = |byte: u8, d: &mut u64| {
            *d ^= u64::from(byte);
            *d = d.wrapping_mul(1099511628211); // FNV-1a prime
        };

        for _ in 0..200_000 {
            let n = 3 + (rng.next() % 12) as usize;
            let mut seq = Vec::with_capacity(n);
            for id in 0..n {
                let block = BLOCKS[(rng.next() % BLOCKS.len() as u64) as usize];
                let mult = MULTS[(rng.next() % MULTS.len() as u64) as usize];
                seq.push((block, mult, id as u8));
            }

            let mut idx = MsgIndex::default();
            for (block, mult, id) in seq {
                idx.insert(fake_checked(block, mult, DIV, id));
            }

            // Hash the resulting order; the hash byte carries the message id.
            for msg in idx.all_msgs() {
                mix(msg.hash[0], &mut digest);
            }
            mix(255, &mut digest); // sequence separator
        }

        assert_eq!(
            digest, ERIGON_INSERT_DIGEST,
            "board ordering diverged from erigon's MsgIndex.Insert at pulse-v3.4.4; \
             the pre-guard comparator produces 14248539691690691664",
        );
    }

    /// Regression test for substituting any binary search for erigon's scan.
    ///
    /// The expected order below is what erigon's `MsgIndex.Insert` at
    /// `78fbcffb8b` produces, computed by running erigon's Go source over this
    /// sequence. A deep board is used because short ones cannot separate
    /// candidate insert positions.
    ///
    /// The guarded comparator sorts the board by block number, so this order
    /// is also what a plain `(block, ratio)` lexicographic sort gives. That
    /// agreement is the point: it is the evidence the comparator became a
    /// total order, and it is what makes the digest test's `sort.Search`
    /// equivalence hold.
    #[test]
    fn insert_position_matches_erigon_on_deep_board() {
        const R50: u64 = 500_000; // ratio 0.50
        const R20: u64 = 200_000; // ratio 0.20
        const R05: u64 = 50_000; // ratio 0.05
        const R01: u64 = 10_000; // ratio 0.01
        const DIV: u64 = 1_000_000;

        // (block, ratio, id) in insertion order; hash byte is 0xA0 + id.
        let seq = [
            (2u64, R50, 0u8),
            (20, R20, 1),
            (5, R50, 2),
            (8, R05, 3),
            (2, R50, 4),
            (3, R20, 5),
            (15, R01, 6),
            (8, R05, 7),
            (8, R20, 8),
        ];

        let mut idx = MsgIndex::default();
        for (block, mult, id) in seq {
            idx.insert(fake_checked(block, mult, DIV, 0xA0 + id));
        }

        let order: Vec<u8> = idx.all_msgs().iter().map(|m| m.hash[0] - 0xA0).collect();
        assert_eq!(
            order,
            vec![0, 4, 5, 2, 3, 7, 8, 6, 1],
            "insert order must match erigon's fast-path-then-linear-scan Insert",
        );
        assert_eq!(
            idx.all_msgs()[0].hash[0] - 0xA0,
            0,
            "eviction target (msgs[0]) must match erigon's",
        );
    }

    /// Pins the surviving half of the divergence from erigon's `MsgIndex.Msgs`
    /// documented on [`MsgIndex::all_msgs_filtered`] and in
    /// `docs/msgboard-parity-gaps.md` §13.4.
    ///
    /// The guarded comparator sorts the board by block number, so erigon's
    /// "assuming msgs are sorted by block number" is now true and its seeked
    /// slice agrees with reth's per-message filter on any range that matches
    /// something. What survives is the fail-open: when no message satisfies
    /// `from`, erigon's forward seek never fires, `leftIdx` stays 0, and it
    /// returns the whole board where reth returns nothing.
    ///
    /// Erigon's answers below come from running its `Msgs` (`78fbcffb8b`,
    /// `msgboard/message_index.go:65`) over this board in Go.
    #[test]
    fn all_msgs_filtered_diverges_only_when_erigons_seek_fails_open() {
        const R10: u64 = 100_000; // ratio 0.10
        const R50: u64 = 500_000; // ratio 0.50
        const DIV: u64 = 1_000_000;

        let mut idx = MsgIndex::default();
        for (block, mult, id) in [(2u64, R10, 0u8), (2, R50, 1), (5, R50, 2), (5, R10, 3)] {
            idx.insert(fake_checked(block, mult, DIV, 0xA0 + id));
        }
        let blocks = |msgs: &[Arc<CheckedPoWMsg>]| -> Vec<u64> {
            msgs.iter().map(|m| m.block_number).collect()
        };
        assert_eq!(blocks(idx.all_msgs()), vec![2, 2, 5, 5], "the guard sorts the board by block");

        // Erigon seeks leftIdx=2, rightIdx=4 and returns blocks [5, 5]. Reth
        // agrees. Before the guard the board was [2, 5, 2, 5] and erigon
        // returned [5, 2, 5] — the block-2 message rode along between bounds.
        assert_eq!(blocks(&idx.all_msgs_filtered(Some(5), Some(8))), vec![5, 5]);

        // A range that matches nothing at the lower end still agrees, because
        // the backward seek for `to` does fire.
        assert!(idx.all_msgs_filtered(Some(3), Some(4)).is_empty());

        // The divergence that survives: no message satisfies `from`, erigon's
        // forward seek never fires, and it returns the whole board — blocks
        // [2, 2, 5, 5] — where reth returns nothing.
        assert!(idx.all_msgs_filtered(Some(10), Some(20)).is_empty());

        // The category-filtered path is *not* divergent: erigon's
        // `CategoryMsgs` skips per message, like reth.
        assert_eq!(
            blocks(&idx.category_msgs_filtered(&category(0xCA), Some(5), Some(8))),
            vec![5, 5]
        );
    }

    /// Erigon's own `TestInsertion` (`msgboard/message_index_test.go`),
    /// replayed against reth.
    ///
    /// Every message in erigon's suite carries the same work multiplier and
    /// divisor, so every `DifficultyRatio()` is equal and the comparator
    /// collapses to `newMsg.block < msgs[i].block`. That makes it monotonic,
    /// which is why this vector passes under a binary search too — it pins
    /// the comparator and the tie-breaking rule (equal block and ratio ⇒ the
    /// later insert sorts after), not the search. Its value is provenance:
    /// the expected orders are erigon's assertions, copied, not derived.
    #[test]
    fn insert_matches_erigon_test_insertion_vector() {
        const DIV: u64 = 1_000_000;

        // msg_<block>_<data>; the hash byte carries the data value.
        let msg = |block: u64, data: u8| fake_checked(block, 1, DIV, data);
        let order =
            |idx: &MsgIndex| -> Vec<u8> { idx.all_msgs().iter().map(|m| m.hash[0]).collect() };

        let mut idx = MsgIndex::default();
        for (block, data) in [(2, 2), (4, 4), (1, 1), (3, 3), (0, 0)] {
            idx.insert(msg(block, data));
        }
        assert_eq!(order(&idx), vec![0, 1, 2, 3, 4]);

        for (block, data) in [(2, 7), (4, 9)] {
            idx.insert(msg(block, data));
        }
        assert_eq!(order(&idx), vec![0, 1, 2, 7, 3, 4, 9]);

        for (block, data) in [(1, 6), (3, 8), (0, 5)] {
            idx.insert(msg(block, data));
        }
        assert_eq!(order(&idx), vec![0, 5, 1, 6, 2, 7, 3, 8, 4, 9]);
    }
}
