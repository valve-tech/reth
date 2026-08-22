//! `msg/1` `RLPx` sub-protocol handler.
//!
//! Registers the `PulseChain` msgboard capability with reth's network layer.
//! Each established peer connection gets a [`MsgboardConnectionHandler`] that
//! spawns a dedicated tokio task driving the three-opcode gossip exchange:
//!
//! | Opcode | Name               | Direction        |
//! |--------|--------------------|------------------|
//! | 0x00   | `BoardMessageIDs`  | both ways        |
//! | 0x01   | `GetBoardMessages` | both ways        |
//! | 0x02   | `BoardMessages`    | both ways        |
//!
//! On connection — once the board reports `is_ready()` — the handler announces
//! all locally-held message IDs to the peer. Thereafter it relays new-message
//! announcements via a `broadcast` subscription on [`MsgBoard`].

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use alloy_rlp::{length_of_length, Encodable};
use bytes::BufMut;
use futures::StreamExt;
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol, Capability,
};
use reth_msgboard_types::{
    decode_pow_msg_list, encode_pow_msg_list, MsgID, BOARD_MESSAGES, BOARD_MESSAGE_IDS,
    GET_BOARD_MESSAGES, MSG_ID_SIZE, PROTOCOL_LENGTH, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use reth_network::protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler};
use reth_network_api::{Direction, PeerId, ReputationChangeKind};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use alloy_primitives::bytes::BytesMut;

use crate::{board::MsgBoard, metrics::MsgboardMetrics};

/// Approximate per-packet size limit for chunked P2P responses, matching erigon-pulse behavior.
const P2P_MSG_PACKET_LIMIT: usize = 100 * 1024;

/// `MsgID`s that fit in one `P2P_MSG_PACKET_LIMIT` frame: `102_400 / 121` = 846.
///
/// Used for two coupled purposes: the chunk size when announcing our own IDs,
/// and the cap on how many IDs we will honour from a single inbound
/// `GetBoardMessages`. They must stay the same value — the cap is safe against
/// conforming peers precisely because no conforming peer can announce, and so
/// none can request, more than one frame's worth at a time.
const MAX_IDS_PER_FRAME: usize = P2P_MSG_PACKET_LIMIT / MSG_ID_SIZE;

/// Bytes a frame carries on top of the payload the packers measure: the opcode
/// byte, plus an RLP list header that is at most four bytes at this size.
///
/// Eight is the figure `get_board_messages_chunks_large_responses` already
/// asserts our own frames stay within, so the two bounds agree by construction.
const FRAME_OVERHEAD_ALLOWANCE: usize = 8;

/// Largest inbound frame we accept, opcode byte included. Anything larger is
/// dropped undecoded and the peer is reported — see [`handle_incoming`].
///
/// The spec caps a `msg/1` packet at [`P2P_MSG_PACKET_LIMIT`], but that limit
/// measures the payload, not the bytes on the wire. Our `BOARD_MESSAGES` packer
/// flushes only once the *next* message would cross it, and the frame it then
/// emits adds the RLP list header and the opcode on top. So reth legitimately
/// sends frames a few bytes past 102_400, and a bare 102_400 inbound bound
/// would have two reth nodes ban each other over their own largest legal
/// frames.
///
/// The alternative — reserve the header in the packer so our frames fit 102_400
/// exactly — reads cleaner against a strict peer, but it changes the frames we
/// put on the wire to buy nothing: erigon-pulse applies no inbound size check at
/// all, so no peer in the network is strict today. The allowance is 8 bytes on a
/// 100 KiB bound, which does not weaken it.
pub(crate) const MAX_INBOUND_FRAME_SIZE: usize = P2P_MSG_PACKET_LIMIT + FRAME_OVERHEAD_ALLOWANCE;

/// Widest RLP encoding of a [`PoWMsg`](reth_msgboard_types::PoWMsg)'s
/// fixed-width fields, `data` excluded.
///
/// `version` is one byte — [`VERSION_V1`] is 1, which RLP encodes as itself.
/// `block_hash` and `category` are 32-byte strings, 33 bytes each. `nonce`,
/// `work_multiplier` and `work_divisor` are `u64`s, 9 bytes each once the top
/// byte is set. Taking every integer at its widest makes the derived ceiling
/// hold for any message an operator's limit admits, not just a typical one.
const MSG_FIXED_FIELDS_RLP_LEN: usize = 1 + 33 + 9 + 9 + 9 + 33;

/// Bytes on the wire for a `BoardMessages` frame carrying exactly one message
/// whose `data` field is `data_len` long: the opcode, the outer list header,
/// the message's own list header, and the payload.
///
/// One message per frame is the case that matters. The packer flushes only
/// once the *next* message would cross [`P2P_MSG_PACKET_LIMIT`], so a message
/// larger than that target is never packed with anything else — it gets a
/// frame to itself, and that frame is as large as the message.
const fn lone_message_frame_len(data_len: usize) -> usize {
    let data_rlp = length_of_length(data_len) + data_len;
    let msg_payload = MSG_FIXED_FIELDS_RLP_LEN + data_rlp;
    let msg_rlp = length_of_length(msg_payload) + msg_payload;
    1 + length_of_length(msg_rlp) + msg_rlp
}

/// Largest `--msgboard.size-limit` that cannot make us emit a frame our own
/// inbound bound rejects.
///
/// `size_limit` bounds the `data` field of every message we accept, and any
/// message we accept we may later have to serve. Raise it past this figure and
/// one `GetBoardMessages` for a single large message produces a frame over
/// [`MAX_INBOUND_FRAME_SIZE`], which every reth peer drops undecoded while
/// reporting us for a protocol violation — `BadProtocol` weighs `i32::MIN`, so
/// that is a 12-hour ban from each of them. Erigon-pulse would neither request
/// the message (`FilterMessageIDs` skips `id.Size() > cfg.MsgSizeLimit`,
/// `msgboard/board.go:233`) nor object to the frame (its own inbound cap is
/// `ProtocolMaxMsgSize` = 10 MiB), so the split is reth-against-reth and
/// entirely self-inflicted. `msgboard.size-limit` is guarded at parse time in
/// [`MsgboardArgs`](crate::MsgboardArgs) so it cannot be reached.
///
/// Solved rather than written down: the RLP header widths depend on the very
/// length being solved for, and the answer moves the moment either
/// [`P2P_MSG_PACKET_LIMIT`] or [`FRAME_OVERHEAD_ALLOWANCE`] does.
/// `the_size_limit_ceiling_is_the_largest_body_that_fits_one_frame` checks the
/// arithmetic against a real encoded message.
pub(crate) const MAX_SAFE_SIZE_LIMIT: usize = {
    let mut data_len = MAX_INBOUND_FRAME_SIZE;
    while lone_message_frame_len(data_len) > MAX_INBOUND_FRAME_SIZE {
        data_len -= 1;
    }
    data_len
};

/// Frames that may sit in a peer's outbound queue before the connection task
/// stops producing and waits for the multiplexer to drain it.
///
/// Every frame we emit is at most one `P2P_MSG_PACKET_LIMIT` packet, so this
/// bounds msgboard's per-peer outbound memory at roughly 800 KiB — about
/// 24 MiB across `DEFAULT_MAX_COUNT_PEERS_INBOUND` = 30 peers. The queue was
/// unbounded until §15.1, which made it the target of a memory-exhaustion
/// attack: a peer that requests continuously and never reads gets ~66 bytes
/// queued per byte it sends.
///
/// Honest bursts do exceed this — a bulk announce is `count_limit / 846` frames
/// (12 at the default) and one full response can be ~69 — and that is the point:
/// the producer waits rather than buffering. A peer that is reading drains the
/// queue as fast as we fill it, so the wait is not observable.
const MAX_QUEUED_OUTGOING_FRAMES: usize = 8;

/// How long to wait for the multiplexer before giving up on a peer and
/// dropping what it will not take.
///
/// Waiting on a full queue is the backpressure that bounds our own memory, but
/// it also stops us draining [`ProtocolConnection`], and the multiplexer's
/// inbound queue to a satellite protocol is an *unbounded* channel it keeps
/// filling from the socket regardless
/// (`reth_eth_wire::multiplex`, `install_protocol` / the `poll_next` read loop).
/// Waiting indefinitely would therefore relocate unbounded growth upstream
/// instead of removing it.
///
/// Two scopings of this budget were wrong before the current one, so the
/// scoping matters more than the value:
///
///  - Per *send* let one request hold the read loop for `chunks x` this value. Fixed by
///    [`frame_deadline`], one deadline for everything emitted in response to a single inbound
///    frame.
///  - Per *inbound frame* was worse: a flooding peer sends many, each getting a fresh budget
///    against a queue that never drains, so the read loop advanced one frame per 30 s while the
///    multiplexer filled its unbounded inbound queue at line rate. Fixed by [`OutboundQueue`]'s
///    stalled flag, which pays this cost once per episode rather than once per frame.
///
/// 30 s is far longer than any healthy peer needs — the multiplexer accepts a
/// frame as soon as it is polled with room in its own 32 MiB out-buffer — so
/// reaching it means the peer's receive window has been shut for half a minute.
/// Note there is no *backpressure* lever short of ending the stream, which
/// disconnects the whole session including eth; §15.5 records why we don't.
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Msgboard capability: `msg/1`.
pub const MSG_CAPABILITY: Capability =
    Capability::new_static(PROTOCOL_NAME, PROTOCOL_VERSION as usize);

/// Msgboard protocol descriptor (capability + message count).
pub const MSG_PROTOCOL: Protocol = Protocol::new(MSG_CAPABILITY, PROTOCOL_LENGTH);

/// Penalises peers that send malformed or invalid msgboard payloads.
///
/// The msgboard crate cannot depend on a concrete `NetworkHandle` (it is
/// generic over `NetworkPrimitives` and exposes RPITIT methods that are not
/// object-safe), so the protocol handler keeps an `Arc<dyn PeerReporter>` and
/// `bin/reth` provides a small wrapper.
///
/// Implementations should map `report_bad_message` to a `BadMessage`
/// reputation hit and `report_bad_protocol` to a `BadProtocol` hit, mirroring
/// erigon-pulse's `PenalizePeer(PenaltyKind_Kick)` for the wire-malformed and
/// validation-rejected cases respectively.
pub trait PeerReporter: std::fmt::Debug + Send + Sync {
    /// Peer delivered a payload whose individual messages failed validation
    /// (bad PoW, missing fields, oversized data, …).
    fn report_bad_message(&self, peer_id: PeerId);

    /// Peer delivered a wire-level malformed payload (unparseable RLP,
    /// `MsgID` list whose length is not a multiple of `MSG_ID_SIZE`, …).
    fn report_bad_protocol(&self, peer_id: PeerId);
}

/// `RLPx` sub-protocol handler for `msg/1`.
///
/// Register this with the network via
/// `network_handle.add_rlpx_sub_protocol(handler.into())`.
#[derive(Debug, Clone)]
pub struct MsgboardProtocolHandler {
    pub(crate) board: Arc<MsgBoard>,
    /// Optional reputation-change sink. When `None` the handler still works
    /// but does not penalise misbehaving peers (useful for tests and for the
    /// short window between protocol registration and network handle
    /// availability).
    reporter: Option<Arc<dyn PeerReporter>>,
}

impl MsgboardProtocolHandler {
    /// Create a new handler backed by the given shared board, with no peer
    /// reporter wired. Outbound gossip is gated by
    /// [`reth_msgboard_types::MsgboardConfig::gossip_disabled`].
    pub const fn new(board: Arc<MsgBoard>) -> Self {
        Self { board, reporter: None }
    }

    /// Attach a peer reputation reporter so the connection task can penalise
    /// peers that send malformed or invalid payloads.
    pub fn with_reporter(mut self, reporter: Arc<dyn PeerReporter>) -> Self {
        self.reporter = Some(reporter);
        self
    }
}

impl ProtocolHandler for MsgboardProtocolHandler {
    type ConnectionHandler = MsgboardConnectionHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(MsgboardConnectionHandler {
            board: Arc::clone(&self.board),
            reporter: self.reporter.clone(),
        })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(MsgboardConnectionHandler {
            board: Arc::clone(&self.board),
            reporter: self.reporter.clone(),
        })
    }
}

/// Per-connection handler created by [`MsgboardProtocolHandler`].
#[derive(Debug)]
pub struct MsgboardConnectionHandler {
    board: Arc<MsgBoard>,
    reporter: Option<Arc<dyn PeerReporter>>,
}

impl ConnectionHandler for MsgboardConnectionHandler {
    /// Outbound stream: a bounded mpsc channel drained by the multiplexer. The
    /// bound is what stops a peer that never reads from growing our queue
    /// without limit — see [`MAX_QUEUED_OUTGOING_FRAMES`].
    type Connection = ReceiverStream<BytesMut>;

    fn protocol(&self) -> Protocol {
        MSG_PROTOCOL
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        // Msgboard is optional; stay connected even if the peer doesn't support it.
        //
        // Counted so that "no msgboard peers" is distinguishable from "no
        // peers". The capability is opt-in, so this is expected to dwarf
        // `peer_sessions_opened` on a network where few nodes run a board.
        self.board.metrics().peer_unsupported.increment(1);
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        _direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let board = self.board;
        let reporter = self.reporter;
        let (tx, rx) = outbound_channel();

        tokio::spawn(async move {
            run_connection(board, reporter, peer_id, conn, tx).await;
        });

        ReceiverStream::new(rx)
    }
}

/// Raises the live-session gauge for as long as one `msg/1` session runs.
///
/// A gauge that is incremented and decremented by hand drifts upward the first
/// time a path returns early, and a drifting "peers connected" reading is worse
/// than none — it is the number an operator trusts when nothing else is moving.
#[derive(Debug)]
struct SessionGuard {
    metrics: MsgboardMetrics,
}

impl SessionGuard {
    fn new(metrics: MsgboardMetrics) -> Self {
        metrics.peer_sessions.increment(1.0);
        metrics.peer_sessions_opened.increment(1);
        Self { metrics }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.metrics.peer_sessions.decrement(1.0);
        self.metrics.peer_sessions_closed.increment(1);
    }
}

/// The per-connection outbound queue handed to the multiplexer.
///
/// Split out from [`MsgboardConnectionHandler::into_connection`] so the bound
/// is reachable from tests: an unbounded queue here is the defect §15.1 closed,
/// and nothing else would fail if it came back.
fn outbound_channel() -> (OutboundQueue, mpsc::Receiver<BytesMut>) {
    let (tx, rx) = mpsc::channel(MAX_QUEUED_OUTGOING_FRAMES);
    (OutboundQueue::new(tx), rx)
}

/// The sending half of a peer's outbound queue, plus whether that peer has
/// stopped draining it.
///
/// The flag is what keeps the deadline in [`OUTBOUND_SEND_TIMEOUT`] from being
/// paid once per inbound frame. Waiting is only useful against a peer that is
/// *slow*; against one that has stopped reading it is pure cost, and the cost
/// is paid in the one place we cannot afford it — the read loop, which is what
/// keeps the multiplexer's unbounded inbound queue drained. So the wait happens
/// once, and until the peer takes another frame we drop without waiting.
#[derive(Debug)]
struct OutboundQueue {
    tx: mpsc::Sender<BytesMut>,
    /// Set when a frame is dropped on the deadline, cleared as soon as the peer
    /// accepts anything again. Only ever touched from the connection task;
    /// atomic rather than [`std::cell::Cell`] so the task's future stays `Send`.
    stalled: AtomicBool,
}

impl OutboundQueue {
    const fn new(tx: mpsc::Sender<BytesMut>) -> Self {
        Self { tx, stalled: AtomicBool::new(false) }
    }

    /// Queue one frame for the peer, waiting for room until `deadline`.
    ///
    /// Waiting is deliberate: the caller runs in the same task as the read
    /// loop, so a full queue stops us pulling further frames off
    /// [`ProtocolConnection`] and the backlog stops growing. See
    /// [`MAX_QUEUED_OUTGOING_FRAMES`] and [`OUTBOUND_SEND_TIMEOUT`].
    ///
    /// `deadline` is shared across every frame emitted for one inbound frame —
    /// see [`frame_deadline`] — so once it passes, the remainder of that
    /// response is dropped without waiting again.
    async fn send(
        &self,
        metrics: &MsgboardMetrics,
        peer_id: PeerId,
        deadline: tokio::time::Instant,
        buf: BytesMut,
    ) -> Sent {
        if self.stalled.load(Ordering::Relaxed) {
            return match self.tx.try_send(buf) {
                Ok(()) => {
                    // It is reading again; go back to waiting for it.
                    self.stalled.store(false, Ordering::Relaxed);
                    Sent::Ok
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    metrics.outbound_dropped.increment(1);
                    Sent::Dropped
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Sent::Closed,
            };
        }

        match tokio::time::timeout_at(deadline, self.tx.send(buf)).await {
            Ok(Ok(())) => Sent::Ok,
            Ok(Err(_)) => Sent::Closed,
            Err(_) => {
                self.stalled.store(true, Ordering::Relaxed);
                metrics.outbound_dropped.increment(1);
                tracing::debug!(
                    target: "msgboard",
                    ?peer_id,
                    timeout_secs = OUTBOUND_SEND_TIMEOUT.as_secs(),
                    "peer is not draining its msgboard queue; dropping frames until it resumes",
                );
                Sent::Dropped
            }
        }
    }

    /// Queue depth the multiplexer has yet to take, for tests.
    #[cfg(test)]
    fn max_capacity(&self) -> usize {
        self.tx.max_capacity()
    }

    /// Free slots remaining, for tests.
    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

/// The instant by which everything emitted in response to one inbound frame
/// must be queued, after which the remainder is dropped.
fn frame_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + OUTBOUND_SEND_TIMEOUT
}

/// Outcome of handing one frame to the multiplexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    /// Queued for the multiplexer.
    Ok,
    /// The queue stayed full for [`OUTBOUND_SEND_TIMEOUT`]; the frame was
    /// discarded and the connection continues.
    Dropped,
    /// The multiplexer dropped the receiver — the connection is gone.
    Closed,
}

/// Drives a single msgboard peer connection.
///
/// Once the board reports `is_ready()`, announces current message IDs and then
/// loops over incoming frames and broadcast notifications until the connection
/// closes. While the board is not ready, the handler stays subscribed to the
/// broadcast channel (so it doesn't accumulate `Lagged` errors) but does not
/// announce, request, or serve anything — mirroring erigon-pulse's
/// `handleInboundMessage` early-exit on `!Started()` and the
/// `MainLoop`-only `syncNewPeers` schedule.
async fn run_connection(
    board: Arc<MsgBoard>,
    reporter: Option<Arc<dyn PeerReporter>>,
    peer_id: PeerId,
    mut conn: ProtocolConnection,
    tx: OutboundQueue,
) {
    let metrics = board.metrics();
    // Held for the life of the session so the gauge falls on every exit path,
    // not just the one that returns normally.
    let _session = SessionGuard::new(metrics.clone());
    let mut new_msg_rx: broadcast::Receiver<_> = board.subscribe();
    let gossip_disabled = board.config().gossip_disabled;

    // Track whether we've already done the on-connect bulk announce so the
    // first ready→announce transition fires exactly once per connection.
    let mut announced = false;
    if !gossip_disabled && board.is_ready() {
        if send_board_message_ids(&board, &tx, peer_id).await == Sent::Closed {
            return;
        }
        announced = true;
    }

    loop {
        // If we became ready after connect (i.e. the node finished initial
        // sync mid-connection), do the bulk announce now — same effect as
        // erigon's `syncNewPeers` re-syncing once `Started()` flips.
        if !announced && !gossip_disabled && board.is_ready() {
            if send_board_message_ids(&board, &tx, peer_id).await == Sent::Closed {
                break;
            }
            announced = true;
        }

        tokio::select! {
            biased;

            // Incoming frame from the remote peer.
            maybe_raw = conn.next() => {
                let Some(raw) = maybe_raw else {
                    tracing::trace!(target: "msgboard", ?peer_id, "connection closed");
                    break;
                };
                let sent = handle_incoming(
                    &board, reporter_as_deref(reporter.as_ref()), &tx, raw, peer_id,
                ).await;
                if sent == Sent::Closed {
                    break;
                }
            }

            // New message accepted into the board — announce its ID to this peer
            // unless outbound gossip is disabled or we're not ready yet. We
            // still drain the channel so it doesn't accumulate `Lagged`.
            result = new_msg_rx.recv() => {
                match result {
                    Ok(new_msg) => {
                        if gossip_disabled || !board.is_ready() {
                            continue;
                        }
                        let start = Instant::now();
                        let ids = [new_msg.msg_id()];
                        let mut buf = BytesMut::with_capacity(1 + MSG_ID_SIZE);
                        buf.put_u8(BOARD_MESSAGE_IDS);
                        buf.put_slice(&MsgID::encode_list(&ids));
                        match tx.send(&metrics, peer_id, frame_deadline(), buf).await {
                            Sent::Closed => break,
                            Sent::Dropped => continue,
                            Sent::Ok => {}
                        }
                        metrics.announcements_sent.increment(1);
                        metrics.sent_to_peer_duration_seconds
                            .record(start.elapsed().as_secs_f64());
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Fell too far behind — re-announce everything (when allowed).
                        if !gossip_disabled &&
                            board.is_ready() &&
                            send_board_message_ids(&board, &tx, peer_id).await == Sent::Closed
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }
}

/// Borrow the trait object out of an `Option<Arc<dyn PeerReporter>>` without
/// cloning the `Arc`. The standard library doesn't ship an `as_deref` for
/// this exact shape because of object-safety quirks around DST coercion.
fn reporter_as_deref(opt: Option<&Arc<dyn PeerReporter>>) -> Option<&dyn PeerReporter> {
    opt.map(|arc| &**arc as &dyn PeerReporter)
}

/// Handle a single incoming raw frame from a peer.
///
/// A frame over [`MAX_INBOUND_FRAME_SIZE`] is dropped undecoded and the sender
/// is reported, whatever its opcode.
///
/// While the board is not ready (initial sync still in progress) all opcodes
/// short-circuit — mirroring erigon-pulse `handleInboundMessage`'s `Started()`
/// guard. Same behaviour when `cfg.gossip_disabled` is set: a read-only
/// observer must not request bodies, serve `GetBoardMessages` from a
/// potentially-stale DB, or accept new messages. `BoardMessages` payloads
/// continue to be drained off the wire so peers don't stall, but their
/// contents are dropped.
///
/// Returns [`Sent::Closed`] once the outbound queue has lost its receiver, so
/// the caller can stop driving a connection the multiplexer has torn down. Any
/// frame this emits may be dropped under sustained backpressure — see
/// [`send_frame`].
async fn handle_incoming(
    board: &Arc<MsgBoard>,
    reporter: Option<&dyn PeerReporter>,
    tx: &OutboundQueue,
    mut raw: BytesMut,
    peer_id: PeerId,
) -> Sent {
    if raw.is_empty() {
        return Sent::Ok;
    }

    // Before the opcode is even read, so it covers every opcode and costs no
    // allocation. Order matters: `MsgID::decode_list` sizes its `Vec` from the
    // payload, so a 16 MiB frame becomes ~138_000 decoded IDs if this runs
    // after it. 16 MiB is not hypothetical — eth-wire's `MAX_PAYLOAD_SIZE` is
    // the only other inbound cap, and it is 160x the msg/1 limit.
    if raw.len() > MAX_INBOUND_FRAME_SIZE {
        tracing::debug!(
            target: "msgboard",
            ?peer_id,
            bytes = raw.len(),
            limit = MAX_INBOUND_FRAME_SIZE,
            "oversized msgboard frame",
        );
        board.metrics().rejected_oversized_frame.increment(1);
        if let Some(r) = reporter {
            // The spec says disconnect. A satellite protocol has no disconnect
            // lever short of ending the stream, which tears down the whole
            // `RLPx` session including eth — `docs/msgboard-parity-gaps.md`
            // §15.5 records why we don't. `report_bad_protocol` is the closest
            // equivalent we have: `BadProtocol` weighs `i32::MIN`, so the peer
            // is banned on the first offence.
            r.report_bad_protocol(peer_id);
        }
        return Sent::Ok;
    }

    let opcode = raw[0];
    let payload = raw.split_off(1);

    let gossip_disabled = board.config().gossip_disabled;
    let ready = board.is_ready();
    let metrics = board.metrics();
    let deadline = frame_deadline();

    match opcode {
        BOARD_MESSAGE_IDS => {
            metrics.announcements_received.increment(1);
            // Peer announced IDs it holds; request the ones we want.
            let ids = match MsgID::decode_list(&payload) {
                Ok(ids) => ids,
                Err(err) => {
                    tracing::debug!(target: "msgboard", ?peer_id, %err, "malformed BoardMessageIDs");
                    metrics.bad_protocol.increment(1);
                    if let Some(r) = reporter {
                        r.report_bad_protocol(peer_id);
                    }
                    return Sent::Ok;
                }
            };
            if !ready || gossip_disabled {
                return Sent::Ok;
            }
            let wanted = board.filter_wanted(&ids);
            if wanted.is_empty() {
                return Sent::Ok;
            }
            // Chunked at `MAX_IDS_PER_FRAME`, unlike erigon-pulse, whose
            // `MessageId_BOARD_MESSAGE_IDS` arm sends `FlattenMsgIDs(mIDs)` in
            // one `SendMessageById` with no size bound. §13.2 accepted that
            // divergence-free behaviour when nothing capped the responder; §14.3
            // then capped ours at `MAX_IDS_PER_FRAME` distinct IDs per request,
            // which makes an unchunked request *lossy* against another reth
            // node — everything past 846 is silently dropped by the responder.
            // Chunking restores that: each frame is within what any responder
            // will honour, and erigon serves each frame independently, so the
            // exchange is unchanged against either client. It also makes this
            // the last outbound frame whose size the peer controls — see
            // `docs/msgboard-parity-gaps.md` §15.3.
            //
            // `MAX_INBOUND_FRAME_SIZE` now caps an announcement at
            // `MAX_IDS_PER_FRAME` IDs, so `wanted` never spans two chunks and
            // this loop runs once. It stays as the inner guard: the bound and
            // the chunk size are separate constants, and only this keeps them
            // from drifting apart silently.
            for (i, chunk) in wanted.chunks(MAX_IDS_PER_FRAME).enumerate() {
                let mut buf = BytesMut::with_capacity(1 + chunk.len() * MSG_ID_SIZE);
                buf.put_u8(GET_BOARD_MESSAGES);
                buf.put_slice(&MsgID::encode_list(chunk));
                metrics.requests_sent.increment(1);
                match tx.send(&metrics, peer_id, deadline, buf).await {
                    Sent::Ok => {}
                    // `filter_wanted` claimed every ID in `wanted`. A frame that
                    // never reached the peer must give its claims back, or the
                    // peers still announcing those messages stay suppressed for
                    // the full claim TTL and we fetch nothing. On `Closed` that
                    // also covers the chunks this loop will now never send.
                    Sent::Dropped => board.release_pending(chunk),
                    Sent::Closed => {
                        board.release_pending(&wanted[i * MAX_IDS_PER_FRAME..]);
                        return Sent::Closed;
                    }
                }
            }
        }

        GET_BOARD_MESSAGES => {
            metrics.requests_received.increment(1);
            // Peer wants the full messages for these IDs.
            let ids = match MsgID::decode_list(&payload) {
                Ok(ids) => ids,
                Err(err) => {
                    tracing::debug!(target: "msgboard", ?peer_id, %err, "malformed GetBoardMessages");
                    metrics.bad_protocol.increment(1);
                    if let Some(r) = reporter {
                        r.report_bad_protocol(peer_id);
                    }
                    return Sent::Ok;
                }
            };
            if !ready {
                return Sent::Ok;
            }

            // Deduplicate and cap before serving — see
            // `docs/msgboard-parity-gaps.md` §14.3.
            //
            // Erigon maps each requested ID to a message independently, with no
            // cap and no dedup, so one ID repeated N times is served N times and
            // an attacker needs to know only a single message on the board.
            // Reth bounds both: at most one frame's worth of *distinct* IDs is
            // honoured per request.
            //
            // Invisible to a conforming peer. Requests are built from a single
            // inbound announcement, both clients announce in `MAX_IDS_PER_FRAME`
            // chunks, and `filter_wanted` returns a subset — so no honest peer
            // reaches either limit. A peer that does is either malfunctioning or
            // probing, and gets a truncated response rather than a penalty,
            // since neither client documents a bound it could have respected.
            //
            // The spec now documents one, and `MAX_INBOUND_FRAME_SIZE` enforces
            // it before this arm runs: a request naming more than
            // `MAX_IDS_PER_FRAME` distinct IDs is a frame over the packet
            // limit, so the cap below is no longer reachable from the wire and
            // the dedup is what still fires. Both stay — see §18.
            let mut seen = HashSet::with_capacity(ids.len().min(MAX_IDS_PER_FRAME));
            let mut requested = Vec::with_capacity(ids.len().min(MAX_IDS_PER_FRAME));
            for id in &ids {
                if requested.len() == MAX_IDS_PER_FRAME {
                    break;
                }
                if seen.insert(*id) {
                    requested.push(*id);
                }
            }
            if requested.len() < ids.len() {
                metrics.requests_truncated.increment(1);
                tracing::debug!(
                    target: "msgboard",
                    ?peer_id,
                    announced = ids.len(),
                    served = requested.len(),
                    "GetBoardMessages truncated to distinct IDs within one frame",
                );
            }

            let msgs = board.get_messages_for_ids(&requested);
            if msgs.is_empty() {
                return Sent::Ok;
            }
            metrics.bodies_served.increment(msgs.len() as u64);
            // Chunk messages into ~100KB packets to match erigon-pulse behavior.
            let mut chunk = Vec::new();
            let mut chunk_size = 0usize;
            for msg in &msgs {
                let msg_size = msg.length();
                if !chunk.is_empty() && chunk_size + msg_size > P2P_MSG_PACKET_LIMIT {
                    let encoded_chunk = encode_pow_msg_list(&chunk);
                    let mut buf = BytesMut::with_capacity(1 + encoded_chunk.len());
                    buf.put_u8(BOARD_MESSAGES);
                    buf.put_slice(&encoded_chunk);
                    match tx.send(&metrics, peer_id, deadline, buf).await {
                        Sent::Closed => return Sent::Closed,
                        Sent::Ok | Sent::Dropped => {}
                    }
                    chunk.clear();
                    chunk_size = 0;
                }
                chunk.push(msg.clone());
                chunk_size += msg_size;
            }
            if !chunk.is_empty() {
                let encoded_chunk = encode_pow_msg_list(&chunk);
                let mut buf = BytesMut::with_capacity(1 + encoded_chunk.len());
                buf.put_u8(BOARD_MESSAGES);
                buf.put_slice(&encoded_chunk);
                match tx.send(&metrics, peer_id, deadline, buf).await {
                    Sent::Closed => return Sent::Closed,
                    Sent::Ok | Sent::Dropped => {}
                }
            }
        }

        BOARD_MESSAGES => {
            // Peer delivered the messages we requested.
            let msgs = match decode_pow_msg_list(&payload) {
                Ok(msgs) => msgs,
                Err(err) => {
                    tracing::debug!(target: "msgboard", ?peer_id, %err, "malformed BoardMessages");
                    metrics.bad_protocol.increment(1);
                    if let Some(r) = reporter {
                        r.report_bad_protocol(peer_id);
                    }
                    return Sent::Ok;
                }
            };
            // `add_remote_msgs` itself early-exits when `gossip_disabled` or
            // `!is_ready`; the explicit check here keeps the kickable count
            // honest (an observer node must not penalise peers).
            if !ready || gossip_disabled {
                return Sent::Ok;
            }
            metrics.bodies_received.increment(msgs.len() as u64);
            let (added, kickable) = board.add_remote_msgs(msgs);
            if added > 0 {
                tracing::debug!(target: "msgboard", ?peer_id, added, "accepted msgboard messages");
            }
            if kickable > 0 {
                tracing::debug!(target: "msgboard", ?peer_id, kickable, "rejected non-circumstantial messages");
                metrics.bad_message.increment(kickable as u64);
                if let Some(r) = reporter {
                    // One reputation hit per malformed/invalid message in the
                    // batch — matches erigon's `PenalizePeer` per-call cost.
                    for _ in 0..kickable {
                        r.report_bad_message(peer_id);
                    }
                }
            }
        }

        other => {
            tracing::debug!(target: "msgboard", ?peer_id, opcode = other, "unknown msgboard opcode");
            if let Some(r) = reporter {
                r.report_bad_protocol(peer_id);
            }
        }
    }

    Sent::Ok
}

/// Announce all currently-held message IDs to a peer.
///
/// IDs are chunked into ~100KB packets to match erigon-pulse behavior.
/// Each [`MsgID`] is [`MSG_ID_SIZE`] (121) bytes, so `102_400 / 121` = 846 IDs per chunk.
///
/// At the default `count_limit` a full board is 12 chunks, more than the
/// outbound queue holds, so this waits on a peer that is slow to drain and
/// skips chunks for one that has stopped entirely. Returns [`Sent::Closed`]
/// once the queue has no receiver.
async fn send_board_message_ids(
    board: &Arc<MsgBoard>,
    tx: &OutboundQueue,
    peer_id: PeerId,
) -> Sent {
    let ids = board.all_message_ids();
    if ids.is_empty() {
        return Sent::Ok;
    }
    let metrics = board.metrics();
    let deadline = frame_deadline();
    for chunk in ids.chunks(MAX_IDS_PER_FRAME) {
        let mut buf = BytesMut::with_capacity(1 + chunk.len() * MSG_ID_SIZE);
        buf.put_u8(BOARD_MESSAGE_IDS);
        buf.put_slice(&MsgID::encode_list(chunk));
        metrics.announcements_sent.increment(1);
        match tx.send(&metrics, peer_id, deadline, buf).await {
            Sent::Closed => return Sent::Closed,
            Sent::Ok | Sent::Dropped => {}
        }
    }
    Sent::Ok
}

/// Adapter: implement [`PeerReporter`] over any type that exposes the reth
/// `Peers` API. Lives outside `bin/reth` so it can be unit-tested.
///
/// `T` must be `Clone + Send + Sync + 'static` because the protocol handler
/// holds the reporter inside an `Arc<dyn PeerReporter>` and may share it
/// across many connection tasks.
#[derive(Debug, Clone)]
pub struct NetworkPeerReporter<T> {
    network: T,
}

impl<T> NetworkPeerReporter<T> {
    /// Wrap a `Peers`-implementing handle into a [`PeerReporter`].
    pub const fn new(network: T) -> Self {
        Self { network }
    }
}

impl<T> PeerReporter for NetworkPeerReporter<T>
where
    T: reth_network_api::Peers + std::fmt::Debug + Send + Sync + 'static,
{
    fn report_bad_message(&self, peer_id: PeerId) {
        self.network.reputation_change(peer_id, ReputationChangeKind::BadMessage);
    }

    fn report_bad_protocol(&self, peer_id: PeerId) {
        self.network.reputation_change(peer_id, ReputationChangeKind::BadProtocol);
    }
}

#[cfg(test)]
mod session_gauge {
    use super::*;
    use crate::metrics::MsgboardMetrics;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    /// The live-session gauge must return to zero on every exit path, including
    /// the ones that never reach the end of `run_connection`.
    ///
    /// A hand-incremented gauge drifts upward the first time a path returns
    /// early, and this is the number an operator reads when nothing else is
    /// moving — a stuck non-zero "peers connected" would report a healthy
    /// network while no peer is attached at all. The guard is what makes the
    /// decrement unconditional; this asserts it stays that way.
    ///
    /// Three sessions are opened and closed three different ways, then read
    /// once. `snapshot()` drains, so a read per assertion would report deltas
    /// rather than the running value — the paired counters carry the real
    /// weight here: `closed` short of `opened` means a `Drop` did not run.
    ///
    /// Installs its own recorder, so it must be the only test in this binary
    /// that does. The integration suite in `tests/metrics.rs` runs in a
    /// separate process and installs its own.
    #[test]
    fn the_gauge_returns_to_zero_on_every_exit_path() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        recorder.install().expect("no other recorder installed in this test binary");

        let metrics = MsgboardMetrics::default();

        // 1. Falls off the end.
        {
            let _session = SessionGuard::new(metrics.clone());
        }

        // 2. Returns early.
        fn bails(metrics: MsgboardMetrics) -> bool {
            let _session = SessionGuard::new(metrics);
            return false;
            #[allow(unreachable_code)]
            true
        }
        assert!(!bails(metrics.clone()));

        // 3. Panics. The connection task is spawned, so a panic there is contained and would
        //    otherwise leak a count for the life of the process.
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _session = SessionGuard::new(metrics);
            panic!("session died mid-frame");
        }));
        assert!(caught.is_err(), "the panic must actually have happened");

        let snap = snapshotter.snapshot().into_vec();
        let read = |name: &str| {
            snap.iter().find_map(|(key, _, _, value)| {
                (key.key().name() == name).then(|| match value {
                    DebugValue::Gauge(g) => g.into_inner(),
                    DebugValue::Counter(c) => *c as f64,
                    other => panic!("{name} is {other:?}"),
                })
            })
        };

        assert_eq!(read("msgboard.peer_sessions_opened"), Some(3.0));
        assert_eq!(
            read("msgboard.peer_sessions_closed"),
            Some(3.0),
            "every session must close, including the early return and the panic",
        );
        assert_eq!(
            read("msgboard.peer_sessions"),
            Some(0.0),
            "three sessions opened and three closed must leave the gauge where it started",
        );
    }
}

#[cfg(test)]
mod tests {
    //! Exercises the frame-handling core (`handle_incoming`,
    //! `send_board_message_ids`) directly against a real [`MsgBoard`] and an
    //! mpsc sender standing in for the multiplexer, so no network stack is
    //! needed. What's asserted is the wire response: opcode byte, payload
    //! bytes, frame count, and the reputation calls a peer earns.

    use std::sync::Mutex;

    use alloy_primitives::{Bytes, B256};
    use futures::poll;
    use reth_msgboard_types::{
        encode_pow_msg_list, CheckedPoWMsg, MsgboardConfig, PoWMsg, VERSION_V1,
    };
    use tokio::sync::mpsc::Receiver;

    use super::*;

    // ── harness ──────────────────────────────────────────────────────────────

    /// Records reputation calls so tests can assert on peer penalties.
    #[derive(Debug, Default)]
    struct RecordingReporter {
        bad_message: Mutex<usize>,
        bad_protocol: Mutex<usize>,
    }

    impl RecordingReporter {
        fn bad_message(&self) -> usize {
            *self.bad_message.lock().unwrap()
        }
        fn bad_protocol(&self) -> usize {
            *self.bad_protocol.lock().unwrap()
        }
    }

    impl PeerReporter for RecordingReporter {
        fn report_bad_message(&self, _peer_id: PeerId) {
            *self.bad_message.lock().unwrap() += 1;
        }
        fn report_bad_protocol(&self, _peer_id: PeerId) {
            *self.bad_protocol.lock().unwrap() += 1;
        }
    }

    fn peer() -> PeerId {
        PeerId::repeat_byte(0x7E)
    }

    fn block_hash_one() -> B256 {
        B256::repeat_byte(0x01)
    }

    fn category_hash() -> B256 {
        B256::repeat_byte(0xCA)
    }

    fn easy_cfg() -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: 1,
            work_divisor: 1_000_000,
            size_limit: 8 * 1024,
            count_limit: 10_000,
            block_range: 120,
            stale_block_buffer: 3,
            gossip_disabled: false,
        }
    }

    fn pow_msg(nonce: u64, data: &[u8]) -> PoWMsg {
        PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: category_hash(),
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Mine a valid message for `data` at `block`.
    fn mined(data: &[u8], block: u64) -> PoWMsg {
        for n in 1u64..=1_000_000 {
            if pow_msg(n, data).to_checked(block, 0).is_ok() {
                return pow_msg(n, data);
            }
        }
        panic!("no valid nonce for data={data:?}");
    }

    fn checked(data: &[u8], block: u64) -> CheckedPoWMsg {
        mined(data, block).to_checked(block, 0).expect("valid pow")
    }

    fn board_at(height: u64) -> Arc<MsgBoard> {
        let board = Arc::new(MsgBoard::new(easy_cfg()));
        board.set_ready();
        board.set_head(height, block_hash_one());
        board
    }

    fn board_with_cfg(cfg: MsgboardConfig, height: u64) -> Arc<MsgBoard> {
        let board = Arc::new(MsgBoard::new(cfg));
        board.set_ready();
        board.set_head(height, block_hash_one());
        board
    }

    /// A stand-in for the multiplexer's end of the outbound queue. Capacity is
    /// generous so tests that are not about backpressure never hit it; the
    /// production bound is `MAX_QUEUED_OUTGOING_FRAMES` and is asserted by
    /// `the_outbound_queue_is_bounded`.
    fn channel() -> (OutboundQueue, Receiver<BytesMut>) {
        let (tx, rx) = mpsc::channel(4096);
        (OutboundQueue::new(tx), rx)
    }

    /// Drain every frame currently queued on the receiver.
    fn drain(rx: &mut Receiver<BytesMut>) -> Vec<BytesMut> {
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            out.push(frame);
        }
        out
    }

    /// Regression test for the reflection amplification closed in §14.3.
    ///
    /// Erigon maps each requested ID to a message independently, so one ID
    /// repeated N times is served N times — an attacker needed to know only a
    /// single message on the board. Measured before the fix: a 60,501 B request
    /// of 500 repeats drew 4,135,710 B of response, 68x amplification.
    #[tokio::test]
    async fn get_board_messages_deduplicates_repeated_ids() {
        let board = board_at(10);
        // A message at the default 8 KiB `size_limit`, so the served bytes
        // reflect what an attacker would actually target.
        let big = vec![0x9u8; 8 * 1024];
        let id = board.add_local_msg(mined(&big, 10)).unwrap().msg_id();

        const REPEATS: usize = 500;
        let payload: Vec<u8> =
            std::iter::repeat_n(id, REPEATS).flat_map(|i| i.as_bytes().to_vec()).collect();
        let request_bytes = 1 + payload.len();

        let (tx, mut rx) = channel();
        handle_incoming(&board, None, &tx, frame(GET_BOARD_MESSAGES, &payload), peer()).await;

        let frames = drain(&mut rx);
        let response_bytes: usize = frames.iter().map(|f| f.len()).sum();
        let served: usize = frames
            .iter()
            .map(|f| decode_pow_msg_list(&f[1..]).expect("valid response").len())
            .sum();

        assert_eq!(served, 1, "the message is served once, not once per duplicate");
        assert!(
            response_bytes < request_bytes,
            "a duplicate flood must no longer amplify: response {response_bytes} B \
             vs request {request_bytes} B",
        );
    }

    /// A request for more than one frame's worth of distinct IDs is rejected,
    /// not truncated.
    ///
    /// §14.3 capped the responder at `MAX_IDS_PER_FRAME` and deliberately did
    /// not penalise, because no client documented a bound the sender could have
    /// respected. The spec now documents one, and `MAX_INBOUND_FRAME_SIZE`
    /// enforces it: 847 IDs is a 102,488-byte frame, so the request never
    /// reaches the cap. The board is seeded past the cap so the old truncating
    /// path would visibly serve 846 messages here.
    #[tokio::test]
    async fn get_board_messages_over_one_frame_of_ids_is_rejected_not_truncated() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());

        // Seed more distinct messages than one frame can name.
        let over = MAX_IDS_PER_FRAME + 50;
        let ids: Vec<MsgID> = (0..over)
            .map(|i| {
                let data = format!("msg-{i}").into_bytes();
                board.add_local_msg(mined(&data, 10)).unwrap().msg_id()
            })
            .collect();
        assert_eq!(ids.len(), over);

        let payload: Vec<u8> = ids.iter().flat_map(|i| i.as_bytes().to_vec()).collect();
        let raw = frame(GET_BOARD_MESSAGES, &payload);
        assert!(raw.len() > MAX_INBOUND_FRAME_SIZE, "the request must be over the packet limit");

        let (tx, mut rx) = channel();
        handle_incoming(&board, Some(rep.as_ref()), &tx, raw, peer()).await;

        assert!(drain(&mut rx).is_empty(), "nothing may be served from an oversized request");
        assert_eq!(rep.bad_protocol(), 1, "the spec disconnects the sender");
        assert_eq!(rep.bad_message(), 0);
    }

    /// The cap and dedup must not touch an ordinary exchange: a peer asking for
    /// the handful of IDs it actually lacks still gets all of them.
    #[tokio::test]
    async fn an_honest_request_is_served_in_full() {
        let board = board_at(10);
        let ids: Vec<MsgID> =
            (0..5u8).map(|i| board.add_local_msg(mined(&[i], 10)).unwrap().msg_id()).collect();

        let payload: Vec<u8> = ids.iter().flat_map(|i| i.as_bytes().to_vec()).collect();
        let (tx, mut rx) = channel();
        handle_incoming(&board, None, &tx, frame(GET_BOARD_MESSAGES, &payload), peer()).await;

        let served: usize = drain(&mut rx)
            .iter()
            .map(|f| decode_pow_msg_list(&f[1..]).expect("valid response").len())
            .sum();
        assert_eq!(served, 5, "every distinct requested message is returned");
    }

    // ── outbound queue bound (§15.1) ─────────────────────────────────────────
    //
    // The queue was `mpsc::unbounded_channel` until §15.1. reth's multiplexer
    // stops draining a protocol once its own out-buffer reaches 32 MiB, but it
    // keeps reading the socket regardless, so a peer that requested
    // continuously and never read simply relocated the backlog into this queue
    // and grew it without limit — ~66 bytes queued per byte sent.

    /// Seed enough 4 KiB messages that serving them all spans several
    /// `P2P_MSG_PACKET_LIMIT` frames, and return their IDs.
    fn seed_multi_frame_response(board: &Arc<MsgBoard>) -> Vec<MsgID> {
        (0..64u8)
            .map(|i| {
                let mut data = vec![0u8; 4096];
                data[0] = i;
                let msg = (1u64..=1_000_000)
                    .find_map(|n| {
                        let m = PoWMsg { nonce: n, ..pow_msg(1, &data) };
                        m.clone().to_checked(10, 0).is_ok().then_some(m)
                    })
                    .expect("nonce");
                board.add_local_msg(msg).unwrap().msg_id()
            })
            .collect()
    }

    #[test]
    fn the_outbound_queue_is_bounded() {
        let (tx, _rx) = outbound_channel();
        assert_eq!(
            tx.max_capacity(),
            MAX_QUEUED_OUTGOING_FRAMES,
            "an unbounded outbound queue is the §15.1 defect",
        );
        // `a_peer_that_stops_reading_gets_frames_dropped_not_queued_forever`
        // passes for *any* finite timeout, so the magnitude is pinned here:
        // the wait blocks our read loop, and the multiplexer's inbound queue
        // is unbounded and filled from the socket meanwhile.
        assert!(
            OUTBOUND_SEND_TIMEOUT <= Duration::from_secs(60),
            "a peer that has stopped reading must be given up on in seconds, not minutes",
        );
    }

    /// The property the bound buys: once the queue is full the handler stops
    /// producing and waits, rather than buffering the rest of the response.
    ///
    /// Because the handler shares its task with the read loop, waiting here is
    /// also what stops us pulling the next request off the wire.
    #[tokio::test]
    async fn a_full_outbound_queue_makes_the_handler_wait_instead_of_buffering() {
        let board = board_at(10);
        let ids = seed_multi_frame_response(&board);

        // Capacity 1 so the second frame has nowhere to go.
        let (tx, mut rx) = mpsc::channel::<BytesMut>(1);
        let tx = OutboundQueue::new(tx);
        let mut serving = Box::pin(handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids)),
            peer(),
        ));

        assert!(
            poll!(serving.as_mut()).is_pending(),
            "handler ran to completion with a full queue — it buffered the response",
        );
        assert_eq!(tx.capacity(), 0, "the one slot must be occupied");

        // It resumes only as the multiplexer drains, one frame at a time.
        let mut delivered = 0usize;
        loop {
            assert!(rx.recv().await.is_some(), "handler stopped producing early");
            delivered += 1;
            if poll!(serving.as_mut()).is_ready() {
                break;
            }
        }
        assert!(delivered > 1, "test is vacuous unless the response spans several frames");
    }

    /// Waiting bounds our own memory, but it also stops us draining
    /// [`ProtocolConnection`] — and the multiplexer's inbound queue to a
    /// satellite protocol is unbounded and filled from the socket regardless.
    /// Waiting forever would move the growth upstream, so the wait expires.
    ///
    /// Negative control: with a plain `tx.send(buf).await` in `send_frame` this
    /// test never returns.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_stops_reading_gets_frames_dropped_not_queued_forever() {
        let board = board_at(10);
        let ids = seed_multi_frame_response(&board);

        // A live receiver that is never polled: the peer is connected but has
        // stopped reading.
        let (tx, rx) = mpsc::channel::<BytesMut>(1);
        let tx = OutboundQueue::new(tx);
        let sent = handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids)),
            peer(),
        )
        .await;

        assert_eq!(sent, Sent::Ok, "a stalled peer is not a closed connection");
        assert_eq!(rx.len(), 1, "nothing beyond the queue's capacity may accumulate");
    }

    /// The timeout has to bound the *frame*, not each send inside it. Serving
    /// one request emits dozens of chunks, and the whole time we are waiting on
    /// them we are not draining [`ProtocolConnection`] — which is the queue we
    /// cannot bound. A per-send timeout would let a single request stall the
    /// read loop for `chunks x OUTBOUND_SEND_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn one_inbound_frame_stalls_the_read_loop_for_at_most_the_timeout() {
        let board = board_at(10);
        let ids = seed_multi_frame_response(&board);

        let (tx, _rx) = mpsc::channel::<BytesMut>(1);
        let tx = OutboundQueue::new(tx);
        let start = tokio::time::Instant::now();
        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids)),
            peer(),
        )
        .await;

        assert!(
            start.elapsed() <= OUTBOUND_SEND_TIMEOUT,
            "serving one request held the read loop for {:?}, over the {OUTBOUND_SEND_TIMEOUT:?} \
             budget for a single inbound frame",
            start.elapsed(),
        );
    }

    /// The deadline bounds one inbound frame, but a peer that has stopped
    /// reading sends many. If each frame gets a fresh budget, the read loop
    /// drains one frame per `OUTBOUND_SEND_TIMEOUT` — ~3 KiB/s — while the
    /// multiplexer keeps filling its *unbounded* inbound queue at the peer's
    /// line rate. Bounding our own queue would then buy nothing: the growth
    /// just moves upstream, which is the whole thing the deadline exists to
    /// prevent.
    ///
    /// So the wait is not repeated once a peer is known not to be draining.
    #[tokio::test(start_paused = true)]
    async fn a_flooding_peer_cannot_throttle_our_read_loop_frame_by_frame() {
        let board = board_at(10);
        let ids = seed_multi_frame_response(&board);
        let request = frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids));

        let (tx, _rx) = mpsc::channel::<BytesMut>(1);
        let tx = OutboundQueue::new(tx);
        let start = tokio::time::Instant::now();

        const FRAMES: usize = 10;
        for _ in 0..FRAMES {
            handle_incoming(&board, None, &tx, request.clone(), peer()).await;
        }

        assert!(
            start.elapsed() <= OUTBOUND_SEND_TIMEOUT * 2,
            "{FRAMES} frames from a peer that never reads cost {:?}; the read loop is being \
             throttled to one frame per timeout while the mux's unbounded inbound queue fills",
            start.elapsed(),
        );
    }

    /// The converse: giving up on a stalled peer must not be permanent. Once it
    /// takes a frame again it goes back to being waited on, so it is served in
    /// full rather than being dropped for the rest of the connection.
    ///
    /// Asserted as "the handler waits again", because that is what distinguishes
    /// a cleared flag from a stuck one — a stuck flag still delivers whatever
    /// happens to fit, so counting delivered frames proves nothing.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_resumes_reading_is_waited_on_again() {
        let board = board_at(10);
        let ids = seed_multi_frame_response(&board);
        let request = frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids));

        let (raw_tx, mut rx) = mpsc::channel::<BytesMut>(1);
        let tx = OutboundQueue::new(raw_tx);

        // Stall it: the one slot fills and the rest of the response is dropped.
        handle_incoming(&board, None, &tx, request.clone(), peer()).await;
        assert!(
            tx.stalled.load(Ordering::Relaxed),
            "a peer that never read must be marked stalled"
        );

        // The peer drains what it was given.
        while rx.try_recv().is_ok() {}

        // Serving it again: the first frame is taken, which clears the flag, so
        // the handler must go back to waiting once the queue refills.
        let mut serving = Box::pin(handle_incoming(&board, None, &tx, request, peer()));
        assert!(
            poll!(serving.as_mut()).is_pending(),
            "a recovered peer must be waited on again, not dropped for the rest of the connection",
        );
        assert!(!tx.stalled.load(Ordering::Relaxed), "the stall must clear once the peer reads");
    }

    /// Once the multiplexer drops the receiver the connection is gone, and the
    /// handler must say so rather than working through the rest of a response.
    #[tokio::test]
    async fn a_closed_outbound_queue_reports_the_connection_gone() {
        let board = board_at(10);
        let id = board.add_local_msg(mined(&[1], 10)).unwrap().msg_id();
        let (tx, rx) = channel();
        drop(rx);

        let sent = handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&[id])),
            peer(),
        )
        .await;

        assert_eq!(sent, Sent::Closed);
    }

    /// Build a raw frame: opcode byte followed by payload.
    fn frame(opcode: u8, payload: &[u8]) -> BytesMut {
        let mut b = BytesMut::with_capacity(1 + payload.len());
        b.put_u8(opcode);
        b.put_slice(payload);
        b
    }

    // ── framing basics ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_frame_is_ignored_and_not_penalised() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        handle_incoming(&board, Some(rep.as_ref()), &tx, BytesMut::new(), peer()).await;

        assert!(drain(&mut rx).is_empty());
        assert_eq!(rep.bad_protocol(), 0, "an empty frame is not a protocol violation");
        assert_eq!(rep.bad_message(), 0);
    }

    #[tokio::test]
    async fn unknown_opcode_earns_a_bad_protocol_hit() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(0x7F, &[]), peer()).await;

        assert!(drain(&mut rx).is_empty());
        assert_eq!(rep.bad_protocol(), 1);
    }

    #[tokio::test]
    async fn a_missing_reporter_does_not_panic() {
        let board = board_at(10);
        let (tx, _rx) = channel();
        // Every penalising path, with no reporter wired.
        handle_incoming(&board, None, &tx, frame(0x7F, &[]), peer()).await;
        handle_incoming(&board, None, &tx, frame(BOARD_MESSAGE_IDS, &[0u8; 5]), peer()).await;
        handle_incoming(&board, None, &tx, frame(GET_BOARD_MESSAGES, &[0u8; 5]), peer()).await;
        handle_incoming(&board, None, &tx, frame(BOARD_MESSAGES, &[0xFF, 0xFF]), peer()).await;
    }

    // ── inbound frame size ───────────────────────────────────────────────────
    //
    // The spec caps a msg/1 packet at 100 KiB and disconnects a peer that sends
    // a larger one. Msgboard checked nothing: the only inbound cap was
    // eth-wire's 16 MiB `MAX_PAYLOAD_SIZE`, 160x the limit, and a 16 MiB frame
    // decodes to ~138_000 MsgIDs before anything else rejects it.

    /// A config whose difficulty threshold is 1 for a ~100 KiB body, so a
    /// message that size clears the `PoW` on the first nonce. `size_limit` is
    /// raised to match: these tests are about the frame bound, not the body
    /// bound.
    fn frame_size_cfg() -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: 1,
            work_divisor: 1_000_000_000,
            size_limit: 256 * 1024,
            ..easy_cfg()
        }
    }

    /// Build a valid `BoardMessages` frame of exactly `target` bytes.
    ///
    /// The body length is solved for rather than guessed: one data byte moves
    /// the encoded frame by one byte in this range, so the correction lands in
    /// a couple of rounds.
    fn board_messages_frame_of(target: usize) -> BytesMut {
        let build = |len: usize| PoWMsg {
            work_divisor: 1_000_000_000,
            data: Bytes::from(vec![0x5A; len]),
            ..pow_msg(1, &[])
        };
        let mut data_len = target - 200;
        for _ in 0..8 {
            let msg = build(data_len);
            let encoded = encode_pow_msg_list(std::slice::from_ref(&msg));
            let frame_len = 1 + encoded.len();
            if frame_len == target {
                assert!(
                    msg.to_checked(10, 0).is_ok(),
                    "the first nonce must clear a difficulty of 1",
                );
                return frame(BOARD_MESSAGES, &encoded);
            }
            data_len = (data_len as isize + target as isize - frame_len as isize) as usize;
        }
        panic!("no body length gives a {target}-byte frame");
    }

    /// A config that admits ~40 KiB bodies and keeps their difficulty in the
    /// tens, so the packing tests spend their time on framing rather than on
    /// mining. The ratio equals the board's own minimum, so nothing is
    /// rejected as under-priced.
    fn packing_cfg() -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: 100,
            work_divisor: 1_000_000_000,
            size_limit: 64 * 1024,
            ..easy_cfg()
        }
    }

    /// Mine a message under [`packing_cfg`] whose RLP length is exactly
    /// `target` bytes.
    ///
    /// Solved rather than guessed: one data byte moves the encoded length by
    /// one byte in this range, so the correction lands in a couple of rounds.
    /// `fill` keeps sibling messages distinct, so the board does not collapse
    /// two of them into one entry.
    fn mined_with_rlp_len(target: usize, fill: u8, block: u64) -> PoWMsg {
        let build = |data_len: usize, nonce: u64| PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce,
            work_multiplier: packing_cfg().work_multiplier,
            work_divisor: packing_cfg().work_divisor,
            category: category_hash(),
            data: Bytes::from(vec![fill; data_len]),
        };
        let mut data_len = target - 110;
        for _ in 0..8 {
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let m = build(data_len, n);
                    m.clone().to_checked(block, 0).is_ok().then_some(m)
                })
                .expect("no nonce clears the difficulty within 1M tries");
            let len = msg.length();
            if len == target {
                return msg;
            }
            data_len = (data_len as isize + target as isize - len as isize) as usize;
        }
        panic!("no body length gives a {target}-byte message");
    }

    /// The bound has to admit our own largest legal frame.
    ///
    /// The `BoardMessages` packer flushes only once the *next* message would
    /// cross `P2P_MSG_PACKET_LIMIT`, so a chunk's payload reaches that figure
    /// exactly, and the frame then adds the RLP list header and the opcode.
    /// Enforcing a bare `P2P_MSG_PACKET_LIMIT` inbound would have two reth
    /// nodes ban each other over frames they both emit by design.
    ///
    /// Erigon-pulse packs to the same rule (`MaxSizeMsgChunks`,
    /// `msgboard/send.go:53-88`): it flushes when `groupSize+msgSize` would
    /// cross `p2pMsgPacketLimit`, then prepends the list header to a payload
    /// that has already reached the limit.
    ///
    /// This drives the real packer with real messages. The previous version
    /// asserted `MAX_INBOUND_FRAME_SIZE >= P2P_MSG_PACKET_LIMIT + 8`, which
    /// restates the definition two lines above the constant and could not
    /// fail whatever the packer did.
    #[tokio::test]
    async fn the_inbound_bound_admits_our_own_largest_frame() {
        let board = board_with_cfg(packing_cfg(), 10);

        // Three messages whose RLP lengths sum to exactly one packet — the
        // largest payload the packer can put in a single chunk.
        let lens = [40_000usize, 30_000, 32_400];
        assert_eq!(lens.iter().sum::<usize>(), P2P_MSG_PACKET_LIMIT, "the sum must be worst case");
        let mut ids: Vec<MsgID> = lens
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                board.add_local_msg(mined_with_rlp_len(len, 0xA0 + i as u8, 10)).unwrap().msg_id()
            })
            .collect();

        let (tx, mut rx) = channel();
        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids)),
            peer(),
        )
        .await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1, "a payload of exactly one packet is one chunk, not two");
        let sole = &frames[0];
        assert_eq!(
            sole.len(),
            1 + length_of_length(P2P_MSG_PACKET_LIMIT) + P2P_MSG_PACKET_LIMIT,
            "opcode + list header + a full packet of payload",
        );
        assert!(
            sole.len() <= MAX_INBOUND_FRAME_SIZE,
            "our own largest chunk is {} B, over the {MAX_INBOUND_FRAME_SIZE} B we admit inbound: \
             two reth nodes would ban each other",
            sole.len(),
        );
        assert_eq!(
            decode_pow_msg_list(&sole[1..]).expect("the chunk decodes").len(),
            3,
            "nothing may be dropped to keep the frame small",
        );

        // One more message, and the packer must split rather than overshoot.
        ids.push(board.add_local_msg(mined_with_rlp_len(9_000, 0xB0, 10)).unwrap().msg_id());
        let (tx, mut rx) = channel();
        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids)),
            peer(),
        )
        .await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 2, "past one packet the response must span two chunks");
        let mut served = 0;
        for f in &frames {
            assert!(
                f.len() <= MAX_INBOUND_FRAME_SIZE,
                "chunk of {} B is over the {MAX_INBOUND_FRAME_SIZE} B inbound bound",
                f.len(),
            );
            served += decode_pow_msg_list(&f[1..]).expect("each chunk decodes").len();
        }
        assert_eq!(served, 4, "every requested message is delivered exactly once");
    }

    /// [`MAX_SAFE_SIZE_LIMIT`] is solved from RLP header widths that depend on
    /// the very length being solved for, so the arithmetic is checked against a
    /// real encoded message rather than trusted.
    ///
    /// Both halves matter. Too high and the guard admits a `size_limit` that
    /// gets us banned; too low and it refuses a configuration that is fine.
    #[test]
    fn the_size_limit_ceiling_is_the_largest_body_that_fits_one_frame() {
        // Every integer at its widest, which is what `MSG_FIXED_FIELDS_RLP_LEN`
        // assumes. A narrower message only makes the frame smaller.
        let build = |data_len: usize| PoWMsg {
            version: VERSION_V1,
            block_hash: B256::repeat_byte(0xAB),
            nonce: u64::MAX,
            work_multiplier: u64::MAX,
            work_divisor: u64::MAX,
            category: B256::repeat_byte(0xCD),
            data: Bytes::from(vec![0x5A; data_len]),
        };
        let frame_len =
            |data_len: usize| 1 + encode_pow_msg_list(std::slice::from_ref(&build(data_len))).len();

        assert_eq!(
            frame_len(MAX_SAFE_SIZE_LIMIT),
            MAX_INBOUND_FRAME_SIZE,
            "a message at the ceiling must fill the inbound bound exactly",
        );
        assert!(
            frame_len(MAX_SAFE_SIZE_LIMIT + 1) > MAX_INBOUND_FRAME_SIZE,
            "one byte past the ceiling must not still fit — the guard would be too strict",
        );
    }

    #[tokio::test]
    async fn a_frame_at_the_inbound_limit_is_accepted() {
        let board = board_with_cfg(frame_size_cfg(), 10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        let raw = board_messages_frame_of(MAX_INBOUND_FRAME_SIZE);
        assert_eq!(raw.len(), MAX_INBOUND_FRAME_SIZE);
        handle_incoming(&board, Some(rep.as_ref()), &tx, raw, peer()).await;

        assert_eq!(board.all_message_ids().len(), 1, "a frame at the limit is handled normally");
        assert!(drain(&mut rx).is_empty(), "BoardMessages draws no reply");
        assert_eq!(rep.bad_protocol(), 0, "the limit is inclusive");
        assert_eq!(rep.bad_message(), 0);
    }

    /// One byte over, and otherwise perfectly valid: without the size check the
    /// board accepts the message, so this pins the bound rather than the
    /// payload.
    #[tokio::test]
    async fn a_frame_one_byte_over_the_limit_is_rejected_and_reported() {
        let board = board_with_cfg(frame_size_cfg(), 10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        let raw = board_messages_frame_of(MAX_INBOUND_FRAME_SIZE + 1);
        handle_incoming(&board, Some(rep.as_ref()), &tx, raw, peer()).await;

        assert!(board.all_message_ids().is_empty(), "the payload must never be decoded");
        assert!(drain(&mut rx).is_empty(), "an oversized frame draws no response");
        assert_eq!(rep.bad_protocol(), 1, "the sender must be reported");
        assert_eq!(rep.bad_message(), 0, "the frame is a protocol violation, not a bad message");
    }

    /// Size is judged before the payload is read, so well-formedness cannot
    /// change the verdict.
    ///
    /// Two oversized frames: one whose ID list decodes and would otherwise draw
    /// a response, one whose length is not a whole number of IDs and would
    /// otherwise fail to decode. Both must take the same path.
    #[tokio::test]
    async fn oversize_is_decided_before_the_payload_is_decoded() {
        let ids_over = MAX_INBOUND_FRAME_SIZE / MSG_ID_SIZE + 1;

        for garbage in [false, true] {
            let board = board_at(10);
            let id = board.add_local_msg(mined(&[1], 10)).unwrap().msg_id();
            let mut payload: Vec<u8> =
                std::iter::repeat_n(id, ids_over).flat_map(|i| i.as_bytes().to_vec()).collect();
            if garbage {
                payload.push(0xFF);
            }
            let raw = frame(GET_BOARD_MESSAGES, &payload);
            assert!(raw.len() > MAX_INBOUND_FRAME_SIZE, "the frame must be oversized");

            let rep = Arc::new(RecordingReporter::default());
            let (tx, mut rx) = channel();
            handle_incoming(&board, Some(rep.as_ref()), &tx, raw, peer()).await;

            assert!(drain(&mut rx).is_empty(), "garbage={garbage}: nothing may be served");
            assert_eq!(rep.bad_protocol(), 1, "garbage={garbage}");
            assert_eq!(rep.bad_message(), 0, "garbage={garbage}");
        }
    }

    // ── BoardMessageIDs (inbound announcements) ──────────────────────────────

    /// A list whose length is not a multiple of `MSG_ID_SIZE` is a wire-level
    /// violation, distinct from a semantically-invalid message.
    #[tokio::test]
    async fn malformed_id_list_earns_bad_protocol_not_bad_message() {
        for opcode in [BOARD_MESSAGE_IDS, GET_BOARD_MESSAGES] {
            let board = board_at(10);
            let rep = Arc::new(RecordingReporter::default());
            let (tx, mut rx) = channel();

            // MSG_ID_SIZE + 1 bytes: not a whole number of IDs.
            handle_incoming(
                &board,
                Some(rep.as_ref()),
                &tx,
                frame(opcode, &[0u8; MSG_ID_SIZE + 1]),
                peer(),
            )
            .await;

            assert!(drain(&mut rx).is_empty(), "opcode {opcode:#x} must not reply");
            assert_eq!(rep.bad_protocol(), 1, "opcode {opcode:#x}");
            assert_eq!(rep.bad_message(), 0, "opcode {opcode:#x}");
        }
    }

    #[tokio::test]
    async fn announced_ids_we_want_produce_a_get_board_messages_request() {
        let board = board_at(10);
        let (tx, mut rx) = channel();
        // An ID for a message the board does not hold, anchored to a live block.
        let want = checked(&[1, 2, 3], 10).msg_id();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&[want])),
            peer(),
        )
        .await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], GET_BOARD_MESSAGES, "must request the bodies");
        assert_eq!(&frames[0][1..], want.as_bytes(), "payload is the requested ID");
    }

    #[tokio::test]
    async fn announced_ids_we_already_hold_produce_no_request() {
        let board = board_at(10);
        let msg = mined(&[4, 5], 10);
        let id = board.add_local_msg(msg).unwrap().msg_id();
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&[id])),
            peer(),
        )
        .await;

        assert!(drain(&mut rx).is_empty(), "already-held IDs must not be re-requested");
    }

    /// `filter_wanted` drops non-V1 announcements before spending a round trip.
    #[tokio::test]
    async fn announced_ids_with_an_unknown_version_produce_no_request() {
        let board = board_at(10);
        let (tx, mut rx) = channel();
        let real = checked(&[9], 10);
        // Version 1 is the only construction, so anything else is dropped.
        let bogus = MsgID::from_checked(
            VERSION_V1 + 1,
            &real.msg.block_hash,
            real.msg.data.len() as u64,
            real.msg.work_multiplier,
            real.msg.work_divisor,
            &real.msg.category,
            &real.hash,
        );

        handle_incoming(
            &board,
            None,
            &tx,
            frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&[bogus])),
            peer(),
        )
        .await;

        assert!(drain(&mut rx).is_empty());
    }

    #[tokio::test]
    async fn announced_ids_anchored_to_an_unknown_block_produce_no_request() {
        let board = board_at(10);
        let (tx, mut rx) = channel();
        let real = checked(&[9], 10);
        let unknown_block = MsgID::from_checked(
            VERSION_V1,
            &B256::repeat_byte(0xEE), // never registered via set_head
            real.msg.data.len() as u64,
            real.msg.work_multiplier,
            real.msg.work_divisor,
            &real.msg.category,
            &real.hash,
        );

        handle_incoming(
            &board,
            None,
            &tx,
            frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&[unknown_block])),
            peer(),
        )
        .await;

        assert!(drain(&mut rx).is_empty());
    }

    #[tokio::test]
    async fn empty_id_list_is_valid_and_produces_no_request() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGE_IDS, &[]), peer())
            .await;

        assert!(drain(&mut rx).is_empty());
        assert_eq!(rep.bad_protocol(), 0, "an empty list is well-formed");
    }

    // ── readiness / gossip gating ────────────────────────────────────────────

    /// Mirrors erigon `handleInboundMessage`'s `Started()` short-circuit: a
    /// still-syncing node must not request bodies or serve them.
    #[tokio::test]
    async fn a_not_ready_board_does_not_reply_to_any_opcode() {
        let make = || {
            let board = Arc::new(MsgBoard::new(easy_cfg()));
            board.set_head(10, block_hash_one()); // head known, but never set_ready
            board
        };
        let want = checked(&[1], 10).msg_id();

        for (opcode, payload) in [
            (BOARD_MESSAGE_IDS, MsgID::encode_list(&[want])),
            (GET_BOARD_MESSAGES, MsgID::encode_list(&[want])),
        ] {
            let board = make();
            let (tx, mut rx) = channel();
            handle_incoming(&board, None, &tx, frame(opcode, &payload), peer()).await;
            assert!(drain(&mut rx).is_empty(), "opcode {opcode:#x} replied while not ready");
        }
    }

    #[tokio::test]
    async fn a_not_ready_board_drops_delivered_messages_without_penalising() {
        let board = Arc::new(MsgBoard::new(easy_cfg()));
        board.set_head(10, block_hash_one());
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();

        let payload = encode_pow_msg_list(&[mined(&[1], 10)]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer())
            .await;

        assert_eq!(board.status().2, 0, "nothing should be accepted while not ready");
        assert_eq!(rep.bad_message(), 0, "a syncing node must not penalise peers");
    }

    /// `gossip_disabled` is bidirectional: an observer neither requests bodies
    /// nor ingests delivered ones, and never penalises peers for gossiping.
    #[tokio::test]
    async fn gossip_disabled_suppresses_requests_and_ingest() {
        let cfg = MsgboardConfig { gossip_disabled: true, ..easy_cfg() };
        let want = checked(&[1], 10).msg_id();

        let board = board_with_cfg(cfg.clone(), 10);
        let (tx, mut rx) = channel();
        handle_incoming(
            &board,
            None,
            &tx,
            frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&[want])),
            peer(),
        )
        .await;
        assert!(drain(&mut rx).is_empty(), "observer must not request bodies");

        let board = board_with_cfg(cfg, 10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();
        let payload = encode_pow_msg_list(&[mined(&[1], 10)]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer())
            .await;
        assert_eq!(board.status().2, 0, "observer must not ingest");
        assert_eq!(rep.bad_message(), 0, "observer must not penalise");
    }

    /// `GetBoardMessages` is deliberately still served when gossip is disabled
    /// — the flag suppresses *outbound announcement and ingest*, not serving
    /// bodies a peer explicitly asked for.
    #[tokio::test]
    async fn gossip_disabled_still_serves_explicit_body_requests() {
        let cfg = MsgboardConfig { gossip_disabled: true, ..easy_cfg() };
        let board = board_with_cfg(cfg, 10);
        // `add_remote_msgs` is gossip-gated, so seed via the local path.
        let id = board.add_local_msg(mined(&[3], 10)).unwrap().msg_id();
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&[id])),
            peer(),
        )
        .await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], BOARD_MESSAGES);
    }

    // ── GetBoardMessages (serving bodies) ────────────────────────────────────

    #[tokio::test]
    async fn get_board_messages_returns_the_requested_bodies() {
        let board = board_at(10);
        let checked_msg = board.add_local_msg(mined(&[1, 2], 10)).unwrap();
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&[checked_msg.msg_id()])),
            peer(),
        )
        .await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], BOARD_MESSAGES);
        // Payload must decode back to the message we hold.
        let decoded = decode_pow_msg_list(&frames[0][1..]).expect("valid list");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], checked_msg.msg);
    }

    #[tokio::test]
    async fn get_board_messages_for_unknown_ids_sends_nothing() {
        let board = board_at(10);
        let unknown = checked(&[8, 8, 8], 10).msg_id();
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&[unknown])),
            peer(),
        )
        .await;

        assert!(drain(&mut rx).is_empty(), "unknown IDs must not produce an empty frame");
    }

    /// Responses are split into ~100 KiB packets. Each message here carries a
    /// 4 KiB payload, so 64 of them exceed the limit and must span >1 frame,
    /// with every frame independently decodable.
    #[tokio::test]
    async fn get_board_messages_chunks_large_responses() {
        let board = board_at(10);
        let mut ids = Vec::new();
        for i in 0..64u8 {
            let mut data = vec![0u8; 4096];
            data[0] = i; // make each message distinct
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let mut m = pow_msg(n, &data);
                    m.nonce = n;
                    m.clone().to_checked(10, 0).is_ok().then_some(m)
                })
                .expect("nonce");
            ids.push(board.add_local_msg(msg).unwrap().msg_id());
        }
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&ids)),
            peer(),
        )
        .await;

        let frames = drain(&mut rx);
        assert!(frames.len() > 1, "64 x 4KiB should exceed the 100KiB packet limit");

        let mut total = 0;
        for f in &frames {
            assert_eq!(f[0], BOARD_MESSAGES);
            // Tight, because MAX_QUEUED_OUTGOING_FRAMES x this is the per-peer
            // memory bound in §15.1. The chunker flushes *before* pushing a
            // message that would exceed the limit, so a frame is one packet
            // plus the RLP list header and the opcode byte — it does not
            // overshoot by a whole message.
            assert!(
                f.len() <= P2P_MSG_PACKET_LIMIT + 8,
                "frame of {} B exceeds one packet; the per-peer memory bound assumes it does not",
                f.len(),
            );
            total += decode_pow_msg_list(&f[1..]).expect("each chunk decodes independently").len();
        }
        assert_eq!(total, 64, "every requested message must be delivered exactly once");
    }

    // ── BoardMessages (ingesting bodies) ─────────────────────────────────────

    #[tokio::test]
    async fn delivered_messages_are_accepted_onto_the_board() {
        let board = board_at(10);
        let (tx, _rx) = channel();
        let payload = encode_pow_msg_list(&[mined(&[1], 10), mined(&[2], 10)]);

        handle_incoming(&board, None, &tx, frame(BOARD_MESSAGES, &payload), peer()).await;

        assert_eq!(board.status().2, 2, "both messages should be on the board");
    }

    #[tokio::test]
    async fn undecodable_message_payload_earns_a_bad_protocol_hit() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();

        handle_incoming(
            &board,
            Some(rep.as_ref()),
            &tx,
            frame(BOARD_MESSAGES, &[0xFF, 0xFF, 0xFF]),
            peer(),
        )
        .await;

        assert_eq!(rep.bad_protocol(), 1);
        assert_eq!(rep.bad_message(), 0, "a decode failure is a protocol fault, not a bad message");
    }

    /// One `BadMessage` hit per non-circumstantial rejection, matching erigon's
    /// per-call `PenalizePeer` cost.
    #[tokio::test]
    async fn invalid_messages_earn_one_bad_message_hit_each() {
        // size_limit 10 makes the 100-byte payloads oversized => kickable.
        let cfg = MsgboardConfig { size_limit: 10, ..easy_cfg() };
        let board = board_with_cfg(cfg, 10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();

        let big = vec![0u8; 100];
        let payload = encode_pow_msg_list(&[mined(&big, 10), mined(&big, 10)]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer())
            .await;

        assert_eq!(board.status().2, 0);
        assert!(rep.bad_message() >= 1, "oversized payloads must be kickable");
        assert_eq!(rep.bad_protocol(), 0, "the payload itself decoded fine");
    }

    /// A duplicate is circumstantial — erigon does not kick for it, so neither
    /// should reth.
    #[tokio::test]
    async fn duplicate_messages_do_not_earn_a_penalty() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();
        let msg = mined(&[6], 10);
        board.add_local_msg(msg.clone()).unwrap();

        let payload = encode_pow_msg_list(&[msg]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer())
            .await;

        assert_eq!(rep.bad_message(), 0, "duplicates are circumstantial, not kickable");
        assert_eq!(board.status().2, 1);
    }

    // ── outbound announcements ───────────────────────────────────────────────

    #[tokio::test]
    async fn announcing_an_empty_board_sends_nothing() {
        let board = board_at(10);
        let (tx, mut rx) = channel();

        send_board_message_ids(&board, &tx, peer()).await;

        assert!(drain(&mut rx).is_empty(), "an empty board must not send an empty frame");
    }

    #[tokio::test]
    async fn announcing_sends_one_frame_carrying_every_held_id() {
        let board = board_at(10);
        let mut expected = Vec::new();
        for i in 0..5u8 {
            expected.push(board.add_local_msg(mined(&[i], 10)).unwrap().msg_id());
        }
        let (tx, mut rx) = channel();

        send_board_message_ids(&board, &tx, peer()).await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], BOARD_MESSAGE_IDS);
        let decoded = MsgID::decode_list(&frames[0][1..]).expect("valid list");
        assert_eq!(decoded.len(), 5);
        // Order follows board precedence order.
        assert_eq!(decoded, board.all_message_ids());
        for id in &expected {
            assert!(decoded.contains(id));
        }
    }

    /// IDs are chunked at `P2P_MSG_PACKET_LIMIT / MSG_ID_SIZE` = 846 per frame
    /// (`102_400 / 121`). The doc comment on `send_board_message_ids` said 826
    /// before this test pinned the arithmetic.
    #[tokio::test]
    async fn announcing_chunks_at_846_ids_per_frame() {
        let ids_per_chunk = P2P_MSG_PACKET_LIMIT / MSG_ID_SIZE;
        assert_eq!(ids_per_chunk, 846, "chunk size drives the assertions below");

        let board = board_at(10);
        // 900 IDs => two frames (846 + 54).
        for i in 0..900u32 {
            let mut data = i.to_be_bytes().to_vec();
            data.push(0xAB);
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let m = PoWMsg { nonce: n, ..pow_msg(1, &data) };
                    m.clone().to_checked(10, 0).is_ok().then_some(m)
                })
                .expect("nonce");
            board.add_local_msg(msg).unwrap();
        }
        assert_eq!(board.all_message_ids().len(), 900);

        let (tx, mut rx) = channel();
        send_board_message_ids(&board, &tx, peer()).await;
        let frames = drain(&mut rx);

        assert_eq!(frames.len(), 2, "900 IDs must split into 846 + 54");
        assert_eq!(MsgID::decode_list(&frames[0][1..]).unwrap().len(), 846);
        assert_eq!(MsgID::decode_list(&frames[1][1..]).unwrap().len(), 54);
        for f in &frames {
            assert_eq!(f[0], BOARD_MESSAGE_IDS);
            assert!(f.len() - 1 <= P2P_MSG_PACKET_LIMIT, "chunk exceeded the packet limit");
        }
    }

    #[tokio::test]
    async fn announcing_to_a_closed_channel_does_not_panic() {
        let board = board_at(10);
        board.add_local_msg(mined(&[1], 10)).unwrap();
        let (tx, rx) = channel();
        drop(rx);

        send_board_message_ids(&board, &tx, peer()).await;
    }

    // ── protocol descriptor ──────────────────────────────────────────────────

    #[tokio::test]
    async fn capability_matches_the_msg_1_wire_identifier() {
        assert_eq!(MSG_CAPABILITY.name.as_ref(), "msg");
        assert_eq!(MSG_CAPABILITY.version, 1);
        assert_eq!(MSG_PROTOCOL.cap, MSG_CAPABILITY);
        // Three opcodes: 0x00, 0x01, 0x02.
        assert_eq!(MSG_PROTOCOL.messages(), 3);
        assert_eq!(PROTOCOL_LENGTH, 3);
    }

    #[tokio::test]
    async fn opcodes_have_their_wire_values() {
        assert_eq!(BOARD_MESSAGE_IDS, 0x00);
        assert_eq!(GET_BOARD_MESSAGES, 0x01);
        assert_eq!(BOARD_MESSAGES, 0x02);
    }

    // ── two-board convergence ────────────────────────────────────────────────
    //
    // Every test above drives one half of the exchange against hand-built
    // frames: the emitters are checked against what we believe the parser
    // expects, and the parser against what we believe the emitters produce.
    // Nothing checks the two halves against *each other*, so a consistent
    // misunderstanding on both sides passes the whole suite. These tests close
    // the loop — announce → request → deliver, board to board, with no frame
    // authored by the test.

    /// One side of a link: a board plus the channel the handler writes into.
    struct Node {
        board: Arc<MsgBoard>,
        rep: Arc<RecordingReporter>,
        tx: OutboundQueue,
        rx: Receiver<BytesMut>,
    }

    impl Node {
        fn at(height: u64) -> Self {
            let (tx, rx) = channel();
            Self { board: board_at(height), rep: Arc::new(RecordingReporter::default()), tx, rx }
        }

        fn hashes(&self) -> Vec<B256> {
            let mut h: Vec<B256> = self.board.all_messages().iter().map(|m| m.hash).collect();
            h.sort();
            h
        }
    }

    /// Deliver every frame `from` has queued into `to`'s handler, returning the
    /// opcodes that crossed the link. Replies land on `to`'s own channel, so
    /// alternating calls walk the protocol forward one hop at a time.
    async fn deliver(from: &mut Node, to: &Node) -> Vec<u8> {
        let mut opcodes = Vec::new();
        for frame in drain(&mut from.rx) {
            opcodes.push(frame[0]);
            handle_incoming(&to.board, Some(to.rep.as_ref()), &to.tx, frame, peer()).await;
        }
        opcodes
    }

    /// The full cycle, with every byte produced by the implementation itself.
    #[tokio::test]
    async fn two_boards_converge_through_the_announce_request_deliver_cycle() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);

        for data in [&[1u8][..], &[2u8][..], &[3u8][..]] {
            a.board.add_local_msg(mined(data, 10)).expect("accepted");
        }
        assert_eq!(a.board.status().2, 3, "A starts with three messages");
        assert_eq!(b.board.status().2, 0, "B starts empty");

        // A announces what it holds.
        send_board_message_ids(&a.board, &a.tx, peer()).await;
        assert_eq!(deliver(&mut a, &b).await, vec![BOARD_MESSAGE_IDS]);

        // B asks for the bodies it is missing.
        assert_eq!(deliver(&mut b, &a).await, vec![GET_BOARD_MESSAGES]);

        // A serves them; B ingests.
        assert_eq!(deliver(&mut a, &b).await, vec![BOARD_MESSAGES]);

        assert_eq!(b.hashes(), a.hashes(), "B should now hold exactly what A holds");
        assert_eq!(b.board.status().2, 3);

        // A clean exchange must not cost either side reputation.
        assert_eq!(a.rep.bad_message(), 0);
        assert_eq!(a.rep.bad_protocol(), 0);
        assert_eq!(b.rep.bad_message(), 0);
        assert_eq!(b.rep.bad_protocol(), 0);

        // And it must settle: B has nothing left to say.
        assert!(deliver(&mut b, &a).await.is_empty(), "converged link should fall silent");
    }

    /// Re-announcing to an already-synced peer must not restart the cycle —
    /// otherwise every reconnect and every broadcast re-fetches the whole board.
    #[tokio::test]
    async fn a_second_announcement_to_a_synced_peer_requests_nothing() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);
        a.board.add_local_msg(mined(&[1], 10)).expect("accepted");

        send_board_message_ids(&a.board, &a.tx, peer()).await;
        deliver(&mut a, &b).await;
        deliver(&mut b, &a).await;
        deliver(&mut a, &b).await;
        assert_eq!(b.hashes(), a.hashes(), "first cycle should converge");

        // Announce the same IDs again.
        send_board_message_ids(&a.board, &a.tx, peer()).await;
        assert_eq!(deliver(&mut a, &b).await, vec![BOARD_MESSAGE_IDS]);
        assert!(
            deliver(&mut b, &a).await.is_empty(),
            "a synced peer should request nothing on re-announcement",
        );
    }

    /// A partially-synced peer must request only what it lacks — `filter_wanted`
    /// and the announcement encoding have to agree on identity for this to hold.
    #[tokio::test]
    async fn a_partially_synced_peer_requests_only_the_missing_bodies() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);

        let shared = mined(&[1], 10);
        a.board.add_local_msg(shared.clone()).expect("accepted");
        b.board.add_local_msg(shared).expect("accepted");
        a.board.add_local_msg(mined(&[2], 10)).expect("accepted");
        a.board.add_local_msg(mined(&[3], 10)).expect("accepted");

        send_board_message_ids(&a.board, &a.tx, peer()).await;
        deliver(&mut a, &b).await;

        // Inspect B's request before it crosses the link.
        let request = drain(&mut b.rx);
        assert_eq!(request.len(), 1);
        assert_eq!(request[0][0], GET_BOARD_MESSAGES);
        let requested = MsgID::decode_list(&request[0][1..]).expect("well-formed id list");
        assert_eq!(requested.len(), 2, "only the two unheld messages should be requested");

        // Complete the exchange by hand from here, since the frame was consumed.
        handle_incoming(&a.board, Some(a.rep.as_ref()), &a.tx, request[0].clone(), peer()).await;
        assert_eq!(deliver(&mut a, &b).await, vec![BOARD_MESSAGES]);
        assert_eq!(b.hashes(), a.hashes());
    }

    /// Gossip flows both ways over one link: each side ends up with the union,
    /// and neither penalises the other.
    #[tokio::test]
    async fn two_boards_exchange_disjoint_messages_in_both_directions() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);
        a.board.add_local_msg(mined(&[1], 10)).expect("accepted");
        b.board.add_local_msg(mined(&[2], 10)).expect("accepted");

        // A → B
        send_board_message_ids(&a.board, &a.tx, peer()).await;
        deliver(&mut a, &b).await;
        deliver(&mut b, &a).await;
        deliver(&mut a, &b).await;

        // B → A
        send_board_message_ids(&b.board, &b.tx, peer()).await;
        deliver(&mut b, &a).await;
        deliver(&mut a, &b).await;
        deliver(&mut b, &a).await;

        assert_eq!(a.board.status().2, 2, "A should hold the union");
        assert_eq!(b.board.status().2, 2, "B should hold the union");
        assert_eq!(a.hashes(), b.hashes());
        assert_eq!(a.rep.bad_message() + a.rep.bad_protocol(), 0);
        assert_eq!(b.rep.bad_message() + b.rep.bad_protocol(), 0);
    }

    /// Synthesise `n` distinct `MsgID`s that `filter_wanted` will accept: live
    /// anchor block, `VERSION_V1`, and size/work inside `easy_cfg`. No `PoW` is
    /// mined because `filter_wanted` never verifies it — only the ID fields.
    fn wantable_ids(n: usize) -> Vec<MsgID> {
        (0..n)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&(i as u64).to_be_bytes());
                h[31] = 0xA5;
                MsgID::from_checked(
                    VERSION_V1,
                    &block_hash_one(),
                    100,
                    1,
                    1_000_000,
                    &category_hash(),
                    &B256::from(h),
                )
            })
            .collect()
    }

    /// The largest announcement a peer may legally send is one frame's worth of
    /// IDs, and the request we build from it must itself be a legal frame.
    ///
    /// §15.3 added the chunk loop because a peer could announce more than
    /// `MAX_IDS_PER_FRAME` in a single frame, and a reth responder then
    /// truncated the request and lost the overflow. `MAX_INBOUND_FRAME_SIZE`
    /// now rejects that announcement before it is decoded — 847 IDs is 102,488
    /// bytes — so the loop can no longer emit a second chunk. It stays as the
    /// inner guard; what the wire can still reach is this case.
    #[tokio::test]
    async fn a_full_frame_of_announced_ids_is_requested_in_one_legal_frame() {
        let board = board_at(10);
        let announced = wantable_ids(MAX_IDS_PER_FRAME);
        let raw = frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&announced));
        assert!(raw.len() <= MAX_INBOUND_FRAME_SIZE, "one frame's worth must be admissible");

        let wanted = board.filter_wanted(&announced);
        assert_eq!(wanted.len(), MAX_IDS_PER_FRAME, "all must be wanted");
        // `filter_wanted` claims every ID it returns, so this precondition
        // check would otherwise suppress the request the handler makes below.
        // Hand the claims back to leave the board as a first-time peer finds it.
        board.release_pending(&wanted);

        let (tx, mut rx) = channel();
        handle_incoming(&board, None, &tx, raw, peer()).await;

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1, "a legal announcement never needs a second request frame");
        assert_eq!(frames[0][0], GET_BOARD_MESSAGES);
        assert!(
            frames[0].len() <= MAX_INBOUND_FRAME_SIZE,
            "a legal announcement must not provoke a request a strict peer would ban",
        );
        let requested = MsgID::decode_list(&frames[0][1..]).expect("valid id list");
        assert_eq!(requested, announced, "no wanted ID may be dropped or reordered");
    }

    /// Gossip means every peer announces every message. Only the first
    /// announcement should cost a request: the rest arrive while that request
    /// is still in flight, and each one the board acted on would buy a second
    /// copy of a message it is already fetching — paid for with a secp256k1
    /// scalar multiplication to discover the duplicate.
    ///
    /// Measured at 90–98% of all requests on the production fleet before the
    /// in-flight tracker existed. See `crates/net/msgboard/src/pending.rs`.
    #[tokio::test]
    async fn only_the_first_peer_to_announce_a_message_is_asked_for_it() {
        let board = board_at(10);
        let announced = wantable_ids(3);
        let frame_in = frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&announced));

        let (tx_first, mut rx_first) = channel();
        handle_incoming(&board, None, &tx_first, frame_in.clone(), peer()).await;
        let first = drain(&mut rx_first);
        assert_eq!(first.len(), 1, "the first peer to announce should be asked");
        assert_eq!(
            MsgID::decode_list(&first[0][1..]).expect("valid id list"),
            announced,
            "and asked for every announced id",
        );

        // A second peer announcing the same messages, before any reply lands.
        let (tx_second, mut rx_second) = channel();
        handle_incoming(&board, None, &tx_second, frame_in, peer()).await;
        assert!(
            drain(&mut rx_second).is_empty(),
            "a second peer announcing an in-flight message must not be asked again",
        );
    }

    /// A claim is taken on the assumption the request reaches its peer. When
    /// the frame is dropped instead, holding the claim would stall the message
    /// for the full TTL while every other peer announcing it stays suppressed.
    #[tokio::test]
    async fn a_request_that_never_reaches_its_peer_releases_its_claim() {
        let board = board_at(10);
        let announced = wantable_ids(3);

        let wanted = board.filter_wanted(&announced);
        assert_eq!(wanted.len(), 3, "all must be wanted");
        assert!(board.filter_wanted(&announced).is_empty(), "and now claimed");

        board.release_pending(&wanted);

        let (tx, mut rx) = channel();
        handle_incoming(
            &board,
            None,
            &tx,
            frame(BOARD_MESSAGE_IDS, &MsgID::encode_list(&announced)),
            peer(),
        )
        .await;
        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1, "a released id must be requestable again");
        assert_eq!(MsgID::decode_list(&frames[0][1..]).expect("valid id list"), announced,);
    }

    /// A board too large to announce in one frame still transfers in full.
    ///
    /// This case used to be driven by a single over-cap announcement frame,
    /// because §12.9 held that a peer is not obliged to chunk. Since
    /// `MAX_INBOUND_FRAME_SIZE` such a frame is rejected, so the exchange runs
    /// the way the spec assumes every implementation runs it: chunked
    /// announcements, one request per announcement, nothing lost across the
    /// seam.
    #[tokio::test]
    async fn every_message_transfers_when_the_board_spans_several_announcement_frames() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);

        let total = MAX_IDS_PER_FRAME + 54;
        for i in 0..total as u32 {
            let mut data = i.to_be_bytes().to_vec();
            data.push(0xE1);
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let m = PoWMsg { nonce: n, ..pow_msg(1, &data) };
                    m.clone().to_checked(10, 0).is_ok().then_some(m)
                })
                .expect("nonce");
            a.board.add_local_msg(msg).unwrap();
        }
        assert_eq!(a.board.status().2, total as u64);

        send_board_message_ids(&a.board, &a.tx, peer()).await;
        assert_eq!(deliver(&mut a, &b).await.len(), 2, "A must announce in two frames");
        assert_eq!(deliver(&mut b, &a).await.len(), 2, "B must ask in two frames");
        deliver(&mut a, &b).await;

        assert_eq!(b.board.status().2, total as u64, "every announced message must transfer");
        assert_eq!(b.hashes(), a.hashes());
        assert_eq!(b.rep.bad_protocol(), 0, "a chunked exchange costs no reputation");
        assert_eq!(a.rep.bad_protocol(), 0);
    }

    /// Announcements chunk at 846 IDs, and so does the `GetBoardMessages`
    /// request built in response — see
    /// `a_full_frame_of_announced_ids_is_requested_in_one_legal_frame`. This
    /// test keeps the weaker end-to-end property pinned: a request provoked by
    /// our own chunked announcements stays inside the packet limit.
    #[tokio::test]
    async fn requests_provoked_by_our_own_announcements_stay_within_the_packet_limit() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);

        // 900 messages => two announcement chunks (846 + 54).
        for i in 0..900u32 {
            let mut data = i.to_be_bytes().to_vec();
            data.push(0xCD);
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let m = PoWMsg { nonce: n, ..pow_msg(1, &data) };
                    m.clone().to_checked(10, 0).is_ok().then_some(m)
                })
                .expect("nonce");
            a.board.add_local_msg(msg).unwrap();
        }

        send_board_message_ids(&a.board, &a.tx, peer()).await;
        let announcements = deliver(&mut a, &b).await;
        assert_eq!(announcements.len(), 2, "900 IDs must announce as two chunks");

        let requests = drain(&mut b.rx);
        assert!(!requests.is_empty(), "B wants everything A announced");
        for r in &requests {
            assert!(
                r.len() <= P2P_MSG_PACKET_LIMIT,
                "request frame of {} bytes exceeded the {P2P_MSG_PACKET_LIMIT}-byte packet limit",
                r.len(),
            );
        }
    }

    /// A message anchored outside the receiver's live window must not transfer,
    /// and must not be treated as peer misbehaviour — the peer is simply ahead.
    #[tokio::test]
    async fn a_peer_behind_the_live_window_does_not_ingest_expired_messages() {
        let mut a = Node::at(10);
        let b = Node::at(10);
        a.board.add_local_msg(mined(&[1], 10)).expect("accepted");

        // B advances far past the message's anchor block, expiring it.
        b.board.set_head(10 + easy_cfg().block_range + 5, B256::repeat_byte(0x02));

        send_board_message_ids(&a.board, &a.tx, peer()).await;
        deliver(&mut a, &b).await;

        assert_eq!(b.board.status().2, 0, "expired announcements are not requested");
        assert_eq!(b.rep.bad_message(), 0, "being out of window is not misbehaviour");
        assert_eq!(b.rep.bad_protocol(), 0);
    }
}
