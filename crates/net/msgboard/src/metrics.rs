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
    /// Message IDs requested from a peer whose reply has not yet arrived.
    ///
    /// Sits near zero in steady state. A value pinned at
    /// `MAX_PENDING_REQUESTS` means the tracker is failing open and duplicate
    /// requests are no longer suppressed.
    pub pending_requests: Gauge,
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

    // ── peer sessions ────────────────────────────────────────────────────────
    /// Peers with a live `msg/1` session right now.
    ///
    /// **Read this first when no gossip is arriving.** Every other counter on
    /// the receive path reads zero both when nobody is talking to us and when
    /// nobody *can*, and the two have completely different fixes. Zero here
    /// means no connected peer negotiated the capability, so the receive path
    /// was never reached and the message-level counters are silent by
    /// construction rather than by rejection.
    pub peer_sessions: Gauge,
    /// `msg/1` sessions opened since start.
    ///
    /// Read against [`peer_sessions`](Self::peer_sessions): a high count with a
    /// gauge near zero means peers negotiate the capability and then drop it,
    /// which is a different fault from never negotiating it at all.
    pub peer_sessions_opened: Counter,
    /// `msg/1` sessions closed since start.
    pub peer_sessions_closed: Counter,
    /// Live `msgboard_subscribe` subscriptions across every RPC connection.
    ///
    /// jsonrpsee already bounds these per connection, so this is not a cap —
    /// it is the reading that was missing. A subscription task that outlives
    /// its sink raises this and never lowers it, and without the gauge that
    /// leak is invisible until the per-connection cap starts refusing clients
    /// for no reason an operator can see.
    pub rpc_subscriptions: Gauge,
    /// Subscriptions accepted since start.
    ///
    /// Read against [`rpc_subscriptions`](Self::rpc_subscriptions): a high
    /// count with a gauge near zero means clients subscribe and leave, which
    /// is a different fault from clients that subscribe and hang.
    pub rpc_subscriptions_opened: Counter,
    /// Subscriptions ended since start.
    pub rpc_subscriptions_closed: Counter,
    /// Peers that connected but do not speak `msg/1`.
    ///
    /// Expected to be large: the capability is opt-in and most of the network
    /// does not run it. It is here to separate "we have no msgboard peers" from
    /// "we have no peers", which the eth peer count alone cannot do.
    pub peer_unsupported: Counter,

    // ── protocol ─────────────────────────────────────────────────────────────
    /// Wire-malformed payloads (unparseable RLP, bad `MsgID` list length).
    pub bad_protocol: Counter,
    /// Inbound frames dropped for exceeding `MAX_INBOUND_FRAME_SIZE`.
    ///
    /// The frame is discarded before it is decoded, so nothing else records it.
    /// A conforming peer chunks at the packet limit and never reaches this, so
    /// a non-zero value names a peer that is malfunctioning or probing. Watch it
    /// after deploy: the only inbound cap before this counter existed was
    /// eth-wire's 16 MiB `MAX_PAYLOAD_SIZE`, 160x the msg/1 limit.
    pub rejected_oversized_frame: Counter,
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
    /// Announced IDs not requested because a request was already in flight.
    ///
    /// This is the work the in-flight tracker saves. Each suppressed ID would
    /// otherwise have cost one request, one reply, and one secp256k1 scalar
    /// multiplication to discover we already had the message. Read it against
    /// `skipped_duplicate`, which counts the ones that still get through.
    pub requests_suppressed: Counter,
    /// `GetBoardMessages` frames received from peers.
    pub requests_received: Counter,
    /// Frames discarded because a peer left its outbound queue full for
    /// `OUTBOUND_SEND_TIMEOUT` — see §15.1. Non-zero means a peer stopped
    /// reading while we still had gossip for it, which is the signature of the
    /// memory-exhaustion attack that fix closed.
    pub outbound_dropped: Counter,
    /// Individual messages served in `BoardMessages` responses.
    pub bodies_served: Counter,
    /// Individual messages received in `BoardMessages` payloads.
    pub bodies_received: Counter,
    /// Delivered messages dropped before `PoW` verification because the peer
    /// held no reservation for them.
    ///
    /// A peer racing another peer's answer, or answering a request we withdrew,
    /// shows up here in ones and twos. A peer flooding bodies nobody asked for
    /// shows up in thousands: each one used to cost a secp256k1 scalar
    /// multiplication on the connection task.
    pub rejected_unsolicited: Counter,
    /// Announced IDs we wanted but did not request, because this peer already
    /// owes us `MAX_WANT_PER_PEER` messages.
    ///
    /// Stays at zero against a conforming peer, which cannot announce more than
    /// one frame's worth at a time.
    pub wants_refused: Counter,
}
