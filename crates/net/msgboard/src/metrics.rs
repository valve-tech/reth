//! Prometheus metrics for the msgboard sub-protocol.
//!
//! Mirrors the prometheus metric set documented in `specs/02-msgboard.md` §16
//! and emitted by erigon-pulse `v3.0.0-RC8`.

use metrics::{Gauge, Histogram};
use reth_metrics::Metrics;

/// Prometheus metrics for the msgboard sub-protocol.
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
}
