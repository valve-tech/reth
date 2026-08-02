//! Prometheus metrics for the msgboard sub-protocol.
//!
//! Mirrors the prometheus metric set documented in `specs/02-msgboard.md` §16
//! and emitted by erigon-pulse `v3.0.0-RC8`.

use metrics::{Counter, Gauge, Histogram};
use reth_metrics::Metrics;

/// Prometheus metrics for the msgboard sub-protocol.
///
/// The gauges and histograms mirror erigon-pulse `v3.0.0-RC8`. The counters
/// below it do not exist in erigon — they exist because two reth-only wire
/// behaviours (rejecting the difficulty overflow, capping inbound requests)
/// were otherwise invisible in production, observable only by reading debug
/// logs. See `docs/msgboard-parity-gaps.md` §14.
#[derive(Metrics, Clone)]
#[metrics(scope = "msgboard")]
pub struct MsgboardMetrics {
    /// Duration of `add_remote_msgs` calls.
    pub add_remote_msgs_duration_seconds: Histogram,
    /// Duration of chain head update (`set_head`) calls.
    pub change_block_duration_seconds: Histogram,
    /// Duration of P2P message sends to peers.
    pub sent_to_peer_duration_seconds: Histogram,
    /// Duration of DB flush writes.
    pub write_to_db_duration_seconds: Histogram,

    /// Number of live messages currently held in the in-memory board.
    pub msg_count: Gauge,
    /// Sum of `data` bytes across all live messages (an approximation of board RAM use).
    pub msg_size: Gauge,
    /// Bytes written by the most recent `flush_to_db` call.
    pub write_to_db_bytes: Gauge,

    // ── acceptance ───────────────────────────────────────────────────────────
    /// Messages accepted from peers via `add_remote_msgs`.
    pub accepted_remote: Counter,
    /// Messages accepted from the local `msgboard_addMessage` RPC.
    pub accepted_local: Counter,

    // ── rejections that penalise the sending peer ────────────────────────────
    /// `data` field exceeded the configured size limit.
    pub rejected_oversized: Counter,
    /// Declared work ratio was below the configured minimum.
    pub rejected_insufficient_work: Counter,
    /// Difficulty was unrepresentable — the overflow closed in §14.1.
    ///
    /// **This is the counter to watch after deploying that fix.** Erigon
    /// accepts these messages (its `uint64` arithmetic wraps the threshold
    /// down, often to something trivially cheap); reth rejects them and
    /// penalises the sender. A non-zero value here means reth and erigon
    /// genuinely disagreed about a message on the wire.
    pub rejected_invalid_difficulty: Counter,
    /// `PoW` hash did not satisfy the required difficulty.
    pub rejected_invalid_pow: Counter,
    /// Rejected for a reason not covered above; should stay at zero, since
    /// field validation happens at the decode boundary.
    pub rejected_other: Counter,

    // ── circumstantial skips (peer is not penalised) ─────────────────────────
    /// Anchor block hash was not in our live window — the peer may simply be
    /// ahead of us or on a different fork.
    pub skipped_unknown_block: Counter,
    /// We already held the message.
    pub skipped_duplicate: Counter,
    /// The message was the lowest-precedence entry on a full board, so it
    /// displaced itself.
    pub skipped_board_overflow: Counter,
    /// The anchor block aged out between lookup and insertion.
    pub skipped_block_too_old: Counter,

    // ── lifecycle ────────────────────────────────────────────────────────────
    /// Messages displaced by a higher-precedence insert at `count_limit`.
    pub evicted: Counter,
    /// Messages dropped because their anchor block left the live window.
    pub expired: Counter,

    // ── protocol ─────────────────────────────────────────────────────────────
    /// Wire-malformed payloads (unparseable RLP, bad `MsgID` list length).
    pub bad_protocol: Counter,
    /// Payloads that parsed but carried messages failing validation.
    pub bad_message: Counter,
    /// Inbound `GetBoardMessages` frames whose ID list was deduplicated or
    /// capped — see §14.3. Non-zero means a peer asked for more than one
    /// frame's worth, which a conforming peer cannot do.
    pub requests_truncated: Counter,
    /// `BoardMessageIDs` frames announced to peers.
    pub announcements_sent: Counter,
    /// `BoardMessageIDs` frames received from peers.
    pub announcements_received: Counter,
    /// `GetBoardMessages` frames sent to peers.
    pub requests_sent: Counter,
    /// `GetBoardMessages` frames received from peers.
    pub requests_received: Counter,
    /// Individual messages served in `BoardMessages` responses.
    pub bodies_served: Counter,
    /// Individual messages received in `BoardMessages` payloads.
    pub bodies_received: Counter,
}
