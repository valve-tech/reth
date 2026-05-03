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

use std::{net::SocketAddr, sync::Arc, time::Instant};

use alloy_rlp::Encodable;
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
use tokio_stream::wrappers::UnboundedReceiverStream;

use alloy_primitives::bytes::BytesMut;

use crate::board::MsgBoard;

/// Approximate per-packet size limit for chunked P2P responses, matching erigon-pulse behavior.
const P2P_MSG_PACKET_LIMIT: usize = 100 * 1024;

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
    /// Outbound stream: an unbounded mpsc channel drained by the multiplexer.
    type Connection = UnboundedReceiverStream<BytesMut>;

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
        let (tx, rx) = mpsc::unbounded_channel::<BytesMut>();

        tokio::spawn(async move {
            run_connection(board, reporter, peer_id, conn, tx).await;
        });

        UnboundedReceiverStream::new(rx)
    }
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
    tx: mpsc::UnboundedSender<BytesMut>,
) {
    let metrics = board.metrics();
    let mut new_msg_rx: broadcast::Receiver<_> = board.subscribe();
    let gossip_disabled = board.config().gossip_disabled;

    // Track whether we've already done the on-connect bulk announce so the
    // first ready→announce transition fires exactly once per connection.
    let mut announced = false;
    if !gossip_disabled && board.is_ready() {
        send_board_message_ids(&board, &tx);
        announced = true;
    }

    loop {
        // If we became ready after connect (i.e. the node finished initial
        // sync mid-connection), do the bulk announce now — same effect as
        // erigon's `syncNewPeers` re-syncing once `Started()` flips.
        if !announced && !gossip_disabled && board.is_ready() {
            send_board_message_ids(&board, &tx);
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
                handle_incoming(&board, reporter_as_deref(reporter.as_ref()), &tx, raw, peer_id);
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
                        if tx.send(buf).is_err() {
                            break;
                        }
                        metrics.sent_to_peer_duration_seconds
                            .record(start.elapsed().as_secs_f64());
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Fell too far behind — re-announce everything (when allowed).
                        if !gossip_disabled && board.is_ready() {
                            send_board_message_ids(&board, &tx);
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
/// While the board is not ready (initial sync still in progress) all opcodes
/// short-circuit — mirroring erigon-pulse `handleInboundMessage`'s `Started()`
/// guard. Same behaviour when `cfg.gossip_disabled` is set: a read-only
/// observer must not request bodies, serve `GetBoardMessages` from a
/// potentially-stale DB, or accept new messages. `BoardMessages` payloads
/// continue to be drained off the wire so peers don't stall, but their
/// contents are dropped.
fn handle_incoming(
    board: &Arc<MsgBoard>,
    reporter: Option<&dyn PeerReporter>,
    tx: &mpsc::UnboundedSender<BytesMut>,
    mut raw: BytesMut,
    peer_id: PeerId,
) {
    if raw.is_empty() {
        return;
    }

    let opcode = raw[0];
    let payload = raw.split_off(1);

    let gossip_disabled = board.config().gossip_disabled;
    let ready = board.is_ready();

    match opcode {
        BOARD_MESSAGE_IDS => {
            // Peer announced IDs it holds; request the ones we want.
            let ids = match MsgID::decode_list(&payload) {
                Ok(ids) => ids,
                Err(err) => {
                    tracing::debug!(target: "msgboard", ?peer_id, %err, "malformed BoardMessageIDs");
                    if let Some(r) = reporter {
                        r.report_bad_protocol(peer_id);
                    }
                    return;
                }
            };
            if !ready || gossip_disabled {
                return;
            }
            let wanted = board.filter_wanted(&ids);
            if wanted.is_empty() {
                return;
            }
            let mut buf = BytesMut::with_capacity(1 + wanted.len() * MSG_ID_SIZE);
            buf.put_u8(GET_BOARD_MESSAGES);
            buf.put_slice(&MsgID::encode_list(&wanted));
            let _ = tx.send(buf);
        }

        GET_BOARD_MESSAGES => {
            // Peer wants the full messages for these IDs.
            let ids = match MsgID::decode_list(&payload) {
                Ok(ids) => ids,
                Err(err) => {
                    tracing::debug!(target: "msgboard", ?peer_id, %err, "malformed GetBoardMessages");
                    if let Some(r) = reporter {
                        r.report_bad_protocol(peer_id);
                    }
                    return;
                }
            };
            if !ready {
                return;
            }
            let msgs = board.get_messages_for_ids(&ids);
            if msgs.is_empty() {
                return;
            }
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
                    let _ = tx.send(buf);
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
                let _ = tx.send(buf);
            }
        }

        BOARD_MESSAGES => {
            // Peer delivered the messages we requested.
            let msgs = match decode_pow_msg_list(&payload) {
                Ok(msgs) => msgs,
                Err(err) => {
                    tracing::debug!(target: "msgboard", ?peer_id, %err, "malformed BoardMessages");
                    if let Some(r) = reporter {
                        r.report_bad_protocol(peer_id);
                    }
                    return;
                }
            };
            // `add_remote_msgs` itself early-exits when `gossip_disabled` or
            // `!is_ready`; the explicit check here keeps the kickable count
            // honest (an observer node must not penalise peers).
            if !ready || gossip_disabled {
                return;
            }
            let (added, kickable) = board.add_remote_msgs(msgs);
            if added > 0 {
                tracing::debug!(target: "msgboard", ?peer_id, added, "accepted msgboard messages");
            }
            if kickable > 0 {
                tracing::debug!(target: "msgboard", ?peer_id, kickable, "rejected non-circumstantial messages");
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
}

/// Announce all currently-held message IDs to a peer.
///
/// IDs are chunked into ~100KB packets to match erigon-pulse behavior.
/// Each [`MsgID`] is [`MSG_ID_SIZE`] (121) bytes, so approximately 826 IDs per chunk.
fn send_board_message_ids(board: &Arc<MsgBoard>, tx: &mpsc::UnboundedSender<BytesMut>) {
    let ids = board.all_message_ids();
    if ids.is_empty() {
        return;
    }
    let ids_per_chunk = P2P_MSG_PACKET_LIMIT / MSG_ID_SIZE;
    for chunk in ids.chunks(ids_per_chunk) {
        let mut buf = BytesMut::with_capacity(1 + chunk.len() * MSG_ID_SIZE);
        buf.put_u8(BOARD_MESSAGE_IDS);
        buf.put_slice(&MsgID::encode_list(chunk));
        let _ = tx.send(buf);
    }
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
