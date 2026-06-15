//! Sliding-window block tracker for msgboard message expiry.
//!
//! Mirrors erigon-pulse's `msgboard/block_filter.go`. Each call to
//! [`BlockFilter::set_head`] advances the window and prunes stale entries,
//! so block-hash → block-number lookups only cover the live window.

use std::collections::HashMap;

use alloy_primitives::B256;

/// Hard upper bound on the window size regardless of the configured `block_range`.
///
/// Matches `msgboardcfg.MaxBlockRange` in erigon-pulse v3.0.0-RC8. A peer that
/// advertises a message anchored to a block within `[head - 1080 + 1, head]`
/// is in our live window; outside that, the message is treated as expired.
pub const MAX_BLOCK_RANGE: u64 = 1080;

/// Tracks the sliding window of block hashes within which messages remain live.
///
/// A message anchored to block hash `H` at height `N` is considered live while
/// `lower <= N <= head`, where `lower = max(1, head - block_range + 1)`.
///
/// The `max(1, ...)` floor mirrors `calcLower` in erigon-pulse's
/// `block_filter.go`: erigon never lets `lower` reach `0`, so block 0 is never
/// inside the live window. Reth applies the same floor here for byte-identical
/// expiry semantics during the very-early-chain window.
#[derive(Debug)]
pub struct BlockFilter {
    limit: u64,
    head: u64,
    lower: u64,
    hash_to_num: HashMap<B256, u64>,
}

impl BlockFilter {
    /// Create a new filter with the given block range limit.
    pub fn new(limit: u64) -> Self {
        let limit = limit.clamp(1, MAX_BLOCK_RANGE);
        Self { limit, head: 0, lower: 0, hash_to_num: HashMap::new() }
    }

    /// Advance the chain head to `(height, hash)` and prune entries outside the new window.
    pub fn set_head(&mut self, height: u64, hash: B256) {
        self.head = height;
        // Mirror erigon's `calcLower`: floor `lower` at 1 so block 0 never sits
        // inside the live window once the chain has advanced past genesis.
        self.lower = height.saturating_sub(self.limit.saturating_sub(1)).max(1);
        self.hash_to_num.insert(hash, height);
        self.hash_to_num.retain(|_, &mut num| num >= self.lower);
    }

    /// Look up the block number for a given block hash, if it is within the live window.
    pub fn block_number(&self, hash: &B256) -> Option<u64> {
        self.hash_to_num.get(hash).copied()
    }

    /// Returns `true` if `block_number` falls within `[lower, head]`.
    pub const fn within_bounds(&self, block_number: u64) -> bool {
        block_number >= self.lower && block_number <= self.head
    }

    /// Current chain head height.
    pub const fn head(&self) -> u64 {
        self.head
    }

    /// Lower bound of the live window.
    pub const fn lower(&self) -> u64 {
        self.lower
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;

    fn hash(byte: u8) -> B256 {
        let mut b = [0u8; 32];
        b[0] = byte;
        B256::from(b)
    }

    #[test]
    fn new_filter_starts_zeroed() {
        let f = BlockFilter::new(10);
        assert_eq!(f.head(), 0);
        assert_eq!(f.lower(), 0);
    }

    #[test]
    fn set_head_advances_window() {
        let mut f = BlockFilter::new(10);
        f.set_head(100, hash(1));
        assert_eq!(f.head(), 100);
        // lower = 100 - (10 - 1) = 91
        assert_eq!(f.lower(), 91);
    }

    #[test]
    fn set_head_prunes_old_entries_outside_window() {
        let mut f = BlockFilter::new(3);
        // Insert blocks 1, 2, 3
        f.set_head(1, hash(1));
        f.set_head(2, hash(2));
        f.set_head(3, hash(3));

        // All three should be known
        assert!(f.block_number(&hash(1)).is_some());
        assert!(f.block_number(&hash(2)).is_some());
        assert!(f.block_number(&hash(3)).is_some());

        // Advance to 4: window becomes [4 - (3-1), 4] = [2, 4]
        // hash(1) at block 1 should be pruned
        f.set_head(4, hash(4));
        assert!(f.block_number(&hash(1)).is_none(), "block 1 should be pruned");
        assert!(f.block_number(&hash(2)).is_some());
        assert!(f.block_number(&hash(3)).is_some());
        assert!(f.block_number(&hash(4)).is_some());
    }

    #[test]
    fn block_number_returns_none_for_unknown_hash() {
        let f = BlockFilter::new(10);
        assert_eq!(f.block_number(&hash(42)), None);
    }

    #[test]
    fn block_number_returns_some_for_known_hash() {
        let mut f = BlockFilter::new(10);
        f.set_head(50, hash(5));
        assert_eq!(f.block_number(&hash(5)), Some(50));
    }

    #[test]
    fn within_bounds_checks_at_boundaries() {
        let mut f = BlockFilter::new(5);
        f.set_head(10, hash(1));
        // lower = 10 - (5 - 1) = 6, head = 10

        assert!(f.within_bounds(6), "lower bound should be in bounds");
        assert!(f.within_bounds(10), "head should be in bounds");
        assert!(f.within_bounds(8), "middle should be in bounds");
        assert!(!f.within_bounds(5), "below lower should be out of bounds");
        assert!(!f.within_bounds(11), "above head should be out of bounds");
    }

    #[test]
    fn limit_is_clamped_to_max_block_range() {
        // Request a limit larger than MAX_BLOCK_RANGE
        let mut f = BlockFilter::new(MAX_BLOCK_RANGE + 100);
        f.set_head(MAX_BLOCK_RANGE + 200, hash(1));
        // lower should be calculated using MAX_BLOCK_RANGE, not the requested value
        let expected_lower = (MAX_BLOCK_RANGE + 200).saturating_sub(MAX_BLOCK_RANGE - 1);
        assert_eq!(f.lower(), expected_lower);
    }

    #[test]
    fn limit_of_zero_is_clamped_to_one() {
        let mut f = BlockFilter::new(0);
        f.set_head(10, hash(1));
        // limit = 1, so lower = 10 - (1 - 1) = 10
        assert_eq!(f.lower(), 10);
        assert_eq!(f.head(), 10);
    }

    /// Mirrors erigon `calcLower`: `lower` is floored at 1 so block 0 never
    /// sits inside the live window once the chain has advanced past genesis.
    #[test]
    fn lower_is_clamped_to_one_during_early_chain() {
        let mut f = BlockFilter::new(120);
        // head=1: without clamp lower=0; with clamp lower=1.
        f.set_head(1, hash(1));
        assert_eq!(f.lower(), 1, "lower should never fall below 1");
        assert!(!f.within_bounds(0), "block 0 should never be in the live window");
        assert!(f.within_bounds(1));

        // head=50, limit=120: head-119 = -69 → saturating to 0 → clamped to 1.
        f.set_head(50, hash(50));
        assert_eq!(f.lower(), 1);
        assert!(!f.within_bounds(0));
        assert!(f.within_bounds(50));
    }
}
