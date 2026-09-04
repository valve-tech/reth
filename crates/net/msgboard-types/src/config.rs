//! Runtime configuration for the msgboard sub-protocol.
//!
//! [`MsgboardConfig`] mirrors the `Config` struct in erigon-pulse's
//! `msgboard/msgboardcfg/config.go`. All fields can be tuned via CLI flags;
//! the defaults match the reference implementation's production values.

/// Configures msgboard protocol limits and `PoW` parameters.
///
/// Most values are checked before accepting or relaying any
/// [`PoWMsg`](crate::PoWMsg) and are local policy, not wire format — each node
/// enforces its own. [`pulse_v344`](Self::pulse_v344) is the exception: it
/// selects which erigon-pulse behaviour set the node matches, and that is
/// visible to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MsgboardConfig {
    /// Minimum accepted `work_multiplier` in incoming messages.
    ///
    /// Messages with a lower multiplier are rejected as under-priced.
    /// Default: `10_000` (erigon-pulse default).
    pub work_multiplier: u64,

    /// Minimum accepted `work_divisor` denominator cap.
    ///
    /// Along with `work_multiplier`, determines the minimum difficulty ratio
    /// `multiplier / divisor` a message must satisfy.
    /// Default: `1_000_000` (erigon-pulse default).
    pub work_divisor: u64,

    /// Maximum allowed byte length of a single message's `data` field.
    ///
    /// Messages exceeding this size are rejected before `PoW` verification.
    /// Default: `8 KiB` (erigon-pulse default).
    pub size_limit: usize,

    /// Maximum number of messages retained in the in-memory store.
    ///
    /// When the store is full, the oldest messages (by block number) are evicted.
    /// Default: `10_000` (erigon-pulse default).
    pub count_limit: usize,

    /// Number of blocks a message remains live before expiry.
    ///
    /// A message anchored to `block_hash` at height `N` is dropped once the
    /// chain head reaches `N + block_range`. Default: `120` (erigon-pulse default).
    pub block_range: u64,

    /// Number of blocks to buffer from the lower bound of the live window when
    /// filtering peer-announced [`MsgID`]s.
    ///
    /// A message whose block number falls within `stale_block_buffer` blocks of
    /// the lower window bound is treated as "about to expire" and skipped in
    /// `filter_wanted`. Default: `3` (erigon-pulse default).
    pub stale_block_buffer: u64,

    /// Disable msgboard P2P participation (read-only observer mode).
    ///
    /// Mirrors `cfg.NoGossip` in erigon-pulse's `msgboardcfg/config.go`:
    /// when `true`, the board:
    ///  - drops all incoming peer messages without validating or persisting,
    ///  - skips the bulk-announce on every peer connection,
    ///  - does not forward newly accepted messages to peers,
    ///  - skips inbound `BoardMessageIDs` requests.
    ///
    /// Locally-submitted messages via JSON-RPC continue to work.
    /// Default: `false`.
    pub gossip_disabled: bool,

    /// Match the erigon-pulse `pulse-v3.4.4` behaviour set instead of the one
    /// before it.
    ///
    /// Erigon changed observable behaviour at `78fbcffb8b` without bumping
    /// `ProtocolVersion`, which is still `1` at both commits
    /// (`msgboard/protocol.go`). An old node and a new node therefore negotiate
    /// `msg/1` and then reject each other's frames. This flag is how an
    /// operator picks a side, so the binary can ship before the flag day and
    /// flip on it.
    ///
    /// It currently selects the wire format of two opcodes:
    ///
    ///  - `GetBoardMessages` carries 32-byte message hashes, not 121-byte [`MsgID`](crate::MsgID)
    ///    records.
    ///  - `BoardMessages` carries [`WirePoWMsg`](crate::WirePoWMsg) elements, each a message
    ///    paired with the hash its sender claims for it.
    ///
    /// The same release changed the board's eviction order, which is equally
    /// peer-visible: two nodes fed the same messages must drop the same one or
    /// they gossip different boards. The flag is named for the release rather
    /// than for the wire so it can cover that too.
    ///
    /// Default: `false` — byte-identical to the behaviour before `78fbcffb8b`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub pulse_v344: bool,
}

impl Default for MsgboardConfig {
    fn default() -> Self {
        Self {
            work_multiplier: 10_000,
            work_divisor: 1_000_000,
            size_limit: 8 * 1024, // 8 KiB
            count_limit: 10_000,
            block_range: 120,
            stale_block_buffer: 3,
            gossip_disabled: false,
            pulse_v344: false,
        }
    }
}

impl MsgboardConfig {
    /// Returns `true` if the message size does not exceed [`Self::size_limit`].
    pub const fn is_size_acceptable(&self, size: usize) -> bool {
        size <= self.size_limit
    }

    /// Returns `true` if the work ratio `mult/div` meets the minimum threshold.
    pub const fn is_work_acceptable(&self, multiplier: u64, divisor: u64) -> bool {
        // Compare mult/div ≥ cfg.mult/cfg.div  ⟺  mult × cfg.div ≥ cfg.mult × div
        // Use u128 to avoid overflow for reasonable field values.
        (multiplier as u128) * (self.work_divisor as u128) >=
            (self.work_multiplier as u128) * (divisor as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let cfg = MsgboardConfig::default();
        assert_eq!(cfg.work_multiplier, 10_000);
        assert_eq!(cfg.work_divisor, 1_000_000);
        assert_eq!(cfg.size_limit, 8192);
        assert_eq!(cfg.count_limit, 10_000);
        assert_eq!(cfg.block_range, 120);
        assert_eq!(cfg.stale_block_buffer, 3);
        assert!(!cfg.pulse_v344, "the pre-78fbcffb8b behaviour set is the default");
    }

    #[test]
    fn test_size_acceptable() {
        let cfg = MsgboardConfig::default();
        assert!(cfg.is_size_acceptable(8192));
        assert!(!cfg.is_size_acceptable(8193));
    }

    #[test]
    fn test_work_acceptable() {
        let cfg = MsgboardConfig::default();
        // Exactly the minimum ratio: mult/div == cfg.mult/cfg.div
        assert!(cfg.is_work_acceptable(10_000, 1_000_000));
        // Higher ratio (better work): 20_000 / 1_000_000 > 10_000 / 1_000_000
        assert!(cfg.is_work_acceptable(20_000, 1_000_000));
        // Lower ratio: 9_999 / 1_000_000 < 10_000 / 1_000_000
        assert!(!cfg.is_work_acceptable(9_999, 1_000_000));
    }
}
