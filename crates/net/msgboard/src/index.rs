//! Ordered in-memory index of live msgboard messages.
//!
//! Messages are kept sorted so the lowest-precedence entries land at the
//! front of the vec and `evict_oldest` always pops `msgs[0]`. The insertion
//! comparator mirrors `MsgIndex.Insert` in erigon-pulse's
//! `msgboard/message_index.go` byte-for-byte:
//!
//! ```text
//! pos = first i where (newMsg.block_number < msgs[i].block_number
//!                      || newMsg.difficulty_ratio < msgs[i].difficulty_ratio)
//! ```
//!
//! That OR-comparator is not a true total order — under mixed
//! `(block, ratio)` distributions it can place a new message at an earlier
//! index than a strict `(block, ratio)` lexicographic sort would. Reth
//! matches this exactly so `evict_oldest` removes the **same** message under
//! the **same** input sequence as erigon, preserving wire-observable parity
//! when the board is at its count limit.

use std::{collections::HashMap, sync::Arc};

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

        // Erigon's `sort.Search` predicate is `f(i) = newMsg < msgs[i]` under
        // the OR-comparator (block_number_lt OR ratio_lt). `partition_point`
        // returns the first index where its predicate is `false`, so we
        // negate to `!(newMsg < m)`:
        //
        //     newMsg.block >= m.block && newMsg.ratio >= m.ratio
        //
        // This produces the same insert position as erigon for every input
        // sequence — including the cases where the OR-comparator is not a
        // proper total order — so subsequent `evict_oldest` (which pops
        // `msgs[0]`) removes the same message on both implementations.
        let new_block = msg.block_number;
        let new_ratio = msg.msg.difficulty_ratio();
        let pos = self.msgs.partition_point(|m| {
            new_block >= m.block_number && new_ratio >= m.msg.difficulty_ratio()
        });
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

    /// All messages belonging to `category`.
    pub fn category_msgs(&self, category: &B256) -> impl Iterator<Item = &Arc<CheckedPoWMsg>> {
        self.categories.get(category).into_iter().flat_map(|m| m.values())
    }

    /// All messages belonging to `category` filtered by block range.
    pub fn category_msgs_filtered(
        &self,
        category: &B256,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<Arc<CheckedPoWMsg>> {
        self.categories
            .get(category)
            .into_iter()
            .flat_map(|m| m.values())
            .filter(|m| {
                from_block.map_or(true, |f| m.block_number >= f) &&
                    to_block.map_or(true, |t| m.block_number <= t)
            })
            .cloned()
            .collect()
    }

    /// All messages across all categories filtered by block range.
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

    /// Locks the erigon-matching insert comparator against mixed
    /// `(block, ratio)` distributions where reth's previous strict-lex
    /// comparator placed the new message **after** the OR-comparator's
    /// position. Hand-built `CheckedPoWMsg`s are used so the test can pin
    /// arbitrary `(block, ratio)` pairs without burning CPU mining valid
    /// PoW for each combination.
    #[test]
    fn insert_position_matches_erigon_or_comparator() {
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

        // Pre-seed: [(5, 0.10), (10, 0.10)] — same ratio, increasing block.
        let mut idx = MsgIndex::default();
        idx.insert(fake_checked(5, 100_000, 1_000_000, 0xA0));
        idx.insert(fake_checked(10, 100_000, 1_000_000, 0xA1));

        // Insert (10, 0.05). erigon's sort.Search predicate on i=0:
        //   10 < 5 (F) || 0.05 < 0.10 (T) → returns 0.
        // So the new message lands at index 0 and `msgs[0]` after insert is the
        // freshly-inserted one. Eviction would remove the just-inserted msg
        // → reth must hit the BoardOverflow self-displacement path here for
        // count_limit=1, matching erigon.
        let new_msg = fake_checked(10, 50_000, 1_000_000, 0xB0);
        idx.insert(Arc::clone(&new_msg));

        // After insert: msgs[0] is the lowest-precedence entry.
        assert_eq!(
            idx.all_msgs()[0].hash,
            new_msg.hash,
            "erigon's OR-comparator places the new lower-ratio same-block msg at index 0",
        );
    }
}
