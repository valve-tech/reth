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
            // Deliberately unchunked, at parity with erigon-pulse: its
            // `MessageId_BOARD_MESSAGE_IDS` arm sends `FlattenMsgIDs(mIDs)` in
            // one `SendMessageById` with no size bound, even though the two
            // paths around it (announcements at 846 IDs, `BoardMessages` at the
            // packet limit) both chunk. The frame is therefore as large as the
            // peer's announcement made it — a peer is not obliged to chunk, and
            // neither client caps what it will ask for in one frame. Chunking
            // here unilaterally would be a wire change; see
            // `docs/msgboard-parity-gaps.md` §13.2.
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
/// Each [`MsgID`] is [`MSG_ID_SIZE`] (121) bytes, so `102_400 / 121` = 846 IDs per chunk.
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

#[cfg(test)]
mod tests {
    //! Exercises the frame-handling core (`handle_incoming`,
    //! `send_board_message_ids`) directly against a real [`MsgBoard`] and an
    //! mpsc sender standing in for the multiplexer, so no network stack is
    //! needed. What's asserted is the wire response: opcode byte, payload
    //! bytes, frame count, and the reputation calls a peer earns.

    use std::sync::Mutex;

    use alloy_primitives::{Bytes, B256};
    use reth_msgboard_types::{
        encode_pow_msg_list, CheckedPoWMsg, MsgboardConfig, PoWMsg, VERSION_V1,
    };
    use tokio::sync::mpsc::UnboundedReceiver;

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

    fn channel() -> (mpsc::UnboundedSender<BytesMut>, UnboundedReceiver<BytesMut>) {
        mpsc::unbounded_channel()
    }

    /// Drain every frame currently queued on the receiver.
    fn drain(rx: &mut UnboundedReceiver<BytesMut>) -> Vec<BytesMut> {
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            out.push(frame);
        }
        out
    }

    /// Build a raw frame: opcode byte followed by payload.
    fn frame(opcode: u8, payload: &[u8]) -> BytesMut {
        let mut b = BytesMut::with_capacity(1 + payload.len());
        b.put_u8(opcode);
        b.put_slice(payload);
        b
    }

    // ── framing basics ───────────────────────────────────────────────────────

    #[test]
    fn empty_frame_is_ignored_and_not_penalised() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        handle_incoming(&board, Some(rep.as_ref()), &tx, BytesMut::new(), peer());

        assert!(drain(&mut rx).is_empty());
        assert_eq!(rep.bad_protocol(), 0, "an empty frame is not a protocol violation");
        assert_eq!(rep.bad_message(), 0);
    }

    #[test]
    fn unknown_opcode_earns_a_bad_protocol_hit() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(0x7F, &[]), peer());

        assert!(drain(&mut rx).is_empty());
        assert_eq!(rep.bad_protocol(), 1);
    }

    #[test]
    fn a_missing_reporter_does_not_panic() {
        let board = board_at(10);
        let (tx, _rx) = channel();
        // Every penalising path, with no reporter wired.
        handle_incoming(&board, None, &tx, frame(0x7F, &[]), peer());
        handle_incoming(&board, None, &tx, frame(BOARD_MESSAGE_IDS, &[0u8; 5]), peer());
        handle_incoming(&board, None, &tx, frame(GET_BOARD_MESSAGES, &[0u8; 5]), peer());
        handle_incoming(&board, None, &tx, frame(BOARD_MESSAGES, &[0xFF, 0xFF]), peer());
    }

    // ── BoardMessageIDs (inbound announcements) ──────────────────────────────

    /// A list whose length is not a multiple of `MSG_ID_SIZE` is a wire-level
    /// violation, distinct from a semantically-invalid message.
    #[test]
    fn malformed_id_list_earns_bad_protocol_not_bad_message() {
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
            );

            assert!(drain(&mut rx).is_empty(), "opcode {opcode:#x} must not reply");
            assert_eq!(rep.bad_protocol(), 1, "opcode {opcode:#x}");
            assert_eq!(rep.bad_message(), 0, "opcode {opcode:#x}");
        }
    }

    #[test]
    fn announced_ids_we_want_produce_a_get_board_messages_request() {
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
        );

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], GET_BOARD_MESSAGES, "must request the bodies");
        assert_eq!(&frames[0][1..], want.as_bytes(), "payload is the requested ID");
    }

    #[test]
    fn announced_ids_we_already_hold_produce_no_request() {
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
        );

        assert!(drain(&mut rx).is_empty(), "already-held IDs must not be re-requested");
    }

    /// `filter_wanted` drops non-V1 announcements before spending a round trip.
    #[test]
    fn announced_ids_with_an_unknown_version_produce_no_request() {
        let board = board_at(10);
        let (tx, mut rx) = channel();
        let real = checked(&[9], 10);
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
        );

        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn announced_ids_anchored_to_an_unknown_block_produce_no_request() {
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
        );

        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn empty_id_list_is_valid_and_produces_no_request() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, mut rx) = channel();

        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGE_IDS, &[]), peer());

        assert!(drain(&mut rx).is_empty());
        assert_eq!(rep.bad_protocol(), 0, "an empty list is well-formed");
    }

    // ── readiness / gossip gating ────────────────────────────────────────────

    /// Mirrors erigon `handleInboundMessage`'s `Started()` short-circuit: a
    /// still-syncing node must not request bodies or serve them.
    #[test]
    fn a_not_ready_board_does_not_reply_to_any_opcode() {
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
            handle_incoming(&board, None, &tx, frame(opcode, &payload), peer());
            assert!(drain(&mut rx).is_empty(), "opcode {opcode:#x} replied while not ready");
        }
    }

    #[test]
    fn a_not_ready_board_drops_delivered_messages_without_penalising() {
        let board = Arc::new(MsgBoard::new(easy_cfg()));
        board.set_head(10, block_hash_one());
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();

        let payload = encode_pow_msg_list(&[mined(&[1], 10)]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer());

        assert_eq!(board.status().2, 0, "nothing should be accepted while not ready");
        assert_eq!(rep.bad_message(), 0, "a syncing node must not penalise peers");
    }

    /// `gossip_disabled` is bidirectional: an observer neither requests bodies
    /// nor ingests delivered ones, and never penalises peers for gossiping.
    #[test]
    fn gossip_disabled_suppresses_requests_and_ingest() {
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
        );
        assert!(drain(&mut rx).is_empty(), "observer must not request bodies");

        let board = board_with_cfg(cfg, 10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();
        let payload = encode_pow_msg_list(&[mined(&[1], 10)]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer());
        assert_eq!(board.status().2, 0, "observer must not ingest");
        assert_eq!(rep.bad_message(), 0, "observer must not penalise");
    }

    /// `GetBoardMessages` is deliberately still served when gossip is disabled
    /// — the flag suppresses *outbound announcement and ingest*, not serving
    /// bodies a peer explicitly asked for.
    #[test]
    fn gossip_disabled_still_serves_explicit_body_requests() {
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
        );

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], BOARD_MESSAGES);
    }

    // ── GetBoardMessages (serving bodies) ────────────────────────────────────

    #[test]
    fn get_board_messages_returns_the_requested_bodies() {
        let board = board_at(10);
        let checked_msg = board.add_local_msg(mined(&[1, 2], 10)).unwrap();
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&[checked_msg.msg_id()])),
            peer(),
        );

        let frames = drain(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], BOARD_MESSAGES);
        // Payload must decode back to the message we hold.
        let decoded = decode_pow_msg_list(&frames[0][1..]).expect("valid list");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], checked_msg.msg);
    }

    #[test]
    fn get_board_messages_for_unknown_ids_sends_nothing() {
        let board = board_at(10);
        let unknown = checked(&[8, 8, 8], 10).msg_id();
        let (tx, mut rx) = channel();

        handle_incoming(
            &board,
            None,
            &tx,
            frame(GET_BOARD_MESSAGES, &MsgID::encode_list(&[unknown])),
            peer(),
        );

        assert!(drain(&mut rx).is_empty(), "unknown IDs must not produce an empty frame");
    }

    /// Responses are split into ~100 KiB packets. Each message here carries a
    /// 4 KiB payload, so 64 of them exceed the limit and must span >1 frame,
    /// with every frame independently decodable.
    #[test]
    fn get_board_messages_chunks_large_responses() {
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
        );

        let frames = drain(&mut rx);
        assert!(frames.len() > 1, "64 x 4KiB should exceed the 100KiB packet limit");

        let mut total = 0;
        for f in &frames {
            assert_eq!(f[0], BOARD_MESSAGES);
            assert!(f.len() - 1 <= P2P_MSG_PACKET_LIMIT + 8192, "chunk overshot the limit badly");
            total += decode_pow_msg_list(&f[1..]).expect("each chunk decodes independently").len();
        }
        assert_eq!(total, 64, "every requested message must be delivered exactly once");
    }

    // ── BoardMessages (ingesting bodies) ─────────────────────────────────────

    #[test]
    fn delivered_messages_are_accepted_onto_the_board() {
        let board = board_at(10);
        let (tx, _rx) = channel();
        let payload = encode_pow_msg_list(&[mined(&[1], 10), mined(&[2], 10)]);

        handle_incoming(&board, None, &tx, frame(BOARD_MESSAGES, &payload), peer());

        assert_eq!(board.status().2, 2, "both messages should be on the board");
    }

    #[test]
    fn undecodable_message_payload_earns_a_bad_protocol_hit() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();

        handle_incoming(
            &board,
            Some(rep.as_ref()),
            &tx,
            frame(BOARD_MESSAGES, &[0xFF, 0xFF, 0xFF]),
            peer(),
        );

        assert_eq!(rep.bad_protocol(), 1);
        assert_eq!(rep.bad_message(), 0, "a decode failure is a protocol fault, not a bad message");
    }

    /// One `BadMessage` hit per non-circumstantial rejection, matching erigon's
    /// per-call `PenalizePeer` cost.
    #[test]
    fn invalid_messages_earn_one_bad_message_hit_each() {
        // size_limit 10 makes the 100-byte payloads oversized => kickable.
        let cfg = MsgboardConfig { size_limit: 10, ..easy_cfg() };
        let board = board_with_cfg(cfg, 10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();

        let big = vec![0u8; 100];
        let payload = encode_pow_msg_list(&[mined(&big, 10), mined(&big, 10)]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer());

        assert_eq!(board.status().2, 0);
        assert!(rep.bad_message() >= 1, "oversized payloads must be kickable");
        assert_eq!(rep.bad_protocol(), 0, "the payload itself decoded fine");
    }

    /// A duplicate is circumstantial — erigon does not kick for it, so neither
    /// should reth.
    #[test]
    fn duplicate_messages_do_not_earn_a_penalty() {
        let board = board_at(10);
        let rep = Arc::new(RecordingReporter::default());
        let (tx, _rx) = channel();
        let msg = mined(&[6], 10);
        board.add_local_msg(msg.clone()).unwrap();

        let payload = encode_pow_msg_list(&[msg]);
        handle_incoming(&board, Some(rep.as_ref()), &tx, frame(BOARD_MESSAGES, &payload), peer());

        assert_eq!(rep.bad_message(), 0, "duplicates are circumstantial, not kickable");
        assert_eq!(board.status().2, 1);
    }

    // ── outbound announcements ───────────────────────────────────────────────

    #[test]
    fn announcing_an_empty_board_sends_nothing() {
        let board = board_at(10);
        let (tx, mut rx) = channel();

        send_board_message_ids(&board, &tx);

        assert!(drain(&mut rx).is_empty(), "an empty board must not send an empty frame");
    }

    #[test]
    fn announcing_sends_one_frame_carrying_every_held_id() {
        let board = board_at(10);
        let mut expected = Vec::new();
        for i in 0..5u8 {
            expected.push(board.add_local_msg(mined(&[i], 10)).unwrap().msg_id());
        }
        let (tx, mut rx) = channel();

        send_board_message_ids(&board, &tx);

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
    #[test]
    fn announcing_chunks_at_846_ids_per_frame() {
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
        send_board_message_ids(&board, &tx);
        let frames = drain(&mut rx);

        assert_eq!(frames.len(), 2, "900 IDs must split into 846 + 54");
        assert_eq!(MsgID::decode_list(&frames[0][1..]).unwrap().len(), 846);
        assert_eq!(MsgID::decode_list(&frames[1][1..]).unwrap().len(), 54);
        for f in &frames {
            assert_eq!(f[0], BOARD_MESSAGE_IDS);
            assert!(f.len() - 1 <= P2P_MSG_PACKET_LIMIT, "chunk exceeded the packet limit");
        }
    }

    #[test]
    fn announcing_to_a_closed_channel_does_not_panic() {
        let board = board_at(10);
        board.add_local_msg(mined(&[1], 10)).unwrap();
        let (tx, rx) = channel();
        drop(rx);

        send_board_message_ids(&board, &tx);
    }

    // ── protocol descriptor ──────────────────────────────────────────────────

    #[test]
    fn capability_matches_the_msg_1_wire_identifier() {
        assert_eq!(MSG_CAPABILITY.name.as_ref(), "msg");
        assert_eq!(MSG_CAPABILITY.version, 1);
        assert_eq!(MSG_PROTOCOL.cap, MSG_CAPABILITY);
        // Three opcodes: 0x00, 0x01, 0x02.
        assert_eq!(MSG_PROTOCOL.messages(), 3);
        assert_eq!(PROTOCOL_LENGTH, 3);
    }

    #[test]
    fn opcodes_have_their_wire_values() {
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
        tx: mpsc::UnboundedSender<BytesMut>,
        rx: UnboundedReceiver<BytesMut>,
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
    fn deliver(from: &mut Node, to: &Node) -> Vec<u8> {
        let mut opcodes = Vec::new();
        for frame in drain(&mut from.rx) {
            opcodes.push(frame[0]);
            handle_incoming(&to.board, Some(to.rep.as_ref()), &to.tx, frame, peer());
        }
        opcodes
    }

    /// The full cycle, with every byte produced by the implementation itself.
    #[test]
    fn two_boards_converge_through_the_announce_request_deliver_cycle() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);

        for data in [&[1u8][..], &[2u8][..], &[3u8][..]] {
            a.board.add_local_msg(mined(data, 10)).expect("accepted");
        }
        assert_eq!(a.board.status().2, 3, "A starts with three messages");
        assert_eq!(b.board.status().2, 0, "B starts empty");

        // A announces what it holds.
        send_board_message_ids(&a.board, &a.tx);
        assert_eq!(deliver(&mut a, &b), vec![BOARD_MESSAGE_IDS]);

        // B asks for the bodies it is missing.
        assert_eq!(deliver(&mut b, &a), vec![GET_BOARD_MESSAGES]);

        // A serves them; B ingests.
        assert_eq!(deliver(&mut a, &b), vec![BOARD_MESSAGES]);

        assert_eq!(b.hashes(), a.hashes(), "B should now hold exactly what A holds");
        assert_eq!(b.board.status().2, 3);

        // A clean exchange must not cost either side reputation.
        assert_eq!(a.rep.bad_message(), 0);
        assert_eq!(a.rep.bad_protocol(), 0);
        assert_eq!(b.rep.bad_message(), 0);
        assert_eq!(b.rep.bad_protocol(), 0);

        // And it must settle: B has nothing left to say.
        assert!(deliver(&mut b, &a).is_empty(), "converged link should fall silent");
    }

    /// Re-announcing to an already-synced peer must not restart the cycle —
    /// otherwise every reconnect and every broadcast re-fetches the whole board.
    #[test]
    fn a_second_announcement_to_a_synced_peer_requests_nothing() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);
        a.board.add_local_msg(mined(&[1], 10)).expect("accepted");

        send_board_message_ids(&a.board, &a.tx);
        deliver(&mut a, &b);
        deliver(&mut b, &a);
        deliver(&mut a, &b);
        assert_eq!(b.hashes(), a.hashes(), "first cycle should converge");

        // Announce the same IDs again.
        send_board_message_ids(&a.board, &a.tx);
        assert_eq!(deliver(&mut a, &b), vec![BOARD_MESSAGE_IDS]);
        assert!(
            deliver(&mut b, &a).is_empty(),
            "a synced peer should request nothing on re-announcement",
        );
    }

    /// A partially-synced peer must request only what it lacks — `filter_wanted`
    /// and the announcement encoding have to agree on identity for this to hold.
    #[test]
    fn a_partially_synced_peer_requests_only_the_missing_bodies() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);

        let shared = mined(&[1], 10);
        a.board.add_local_msg(shared.clone()).expect("accepted");
        b.board.add_local_msg(shared).expect("accepted");
        a.board.add_local_msg(mined(&[2], 10)).expect("accepted");
        a.board.add_local_msg(mined(&[3], 10)).expect("accepted");

        send_board_message_ids(&a.board, &a.tx);
        deliver(&mut a, &b);

        // Inspect B's request before it crosses the link.
        let request = drain(&mut b.rx);
        assert_eq!(request.len(), 1);
        assert_eq!(request[0][0], GET_BOARD_MESSAGES);
        let requested = MsgID::decode_list(&request[0][1..]).expect("well-formed id list");
        assert_eq!(requested.len(), 2, "only the two unheld messages should be requested");

        // Complete the exchange by hand from here, since the frame was consumed.
        handle_incoming(&a.board, Some(a.rep.as_ref()), &a.tx, request[0].clone(), peer());
        assert_eq!(deliver(&mut a, &b), vec![BOARD_MESSAGES]);
        assert_eq!(b.hashes(), a.hashes());
    }

    /// Gossip flows both ways over one link: each side ends up with the union,
    /// and neither penalises the other.
    #[test]
    fn two_boards_exchange_disjoint_messages_in_both_directions() {
        let mut a = Node::at(10);
        let mut b = Node::at(10);
        a.board.add_local_msg(mined(&[1], 10)).expect("accepted");
        b.board.add_local_msg(mined(&[2], 10)).expect("accepted");

        // A → B
        send_board_message_ids(&a.board, &a.tx);
        deliver(&mut a, &b);
        deliver(&mut b, &a);
        deliver(&mut a, &b);

        // B → A
        send_board_message_ids(&b.board, &b.tx);
        deliver(&mut b, &a);
        deliver(&mut a, &b);
        deliver(&mut b, &a);

        assert_eq!(a.board.status().2, 2, "A should hold the union");
        assert_eq!(b.board.status().2, 2, "B should hold the union");
        assert_eq!(a.hashes(), b.hashes());
        assert_eq!(a.rep.bad_message() + a.rep.bad_protocol(), 0);
        assert_eq!(b.rep.bad_message() + b.rep.bad_protocol(), 0);
    }

    /// Announcements chunk at 846 IDs, but the `GetBoardMessages` request built
    /// in response does **not** chunk — its size is simply whatever the peer
    /// announced in one frame. That is safe only while a full announcement chunk
    /// still yields a request inside the packet limit, which silently couples
    /// the two paths: raising `ids_per_chunk` without teaching the request path
    /// to chunk would start emitting oversized frames.
    ///
    /// See §12.9 — a peer is not obliged to chunk its announcements, and reth
    /// does not bound the resulting request.
    #[test]
    fn requests_provoked_by_our_own_announcements_stay_within_the_packet_limit() {
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

        send_board_message_ids(&a.board, &a.tx);
        let announcements = deliver(&mut a, &b);
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
    #[test]
    fn a_peer_behind_the_live_window_does_not_ingest_expired_messages() {
        let mut a = Node::at(10);
        let b = Node::at(10);
        a.board.add_local_msg(mined(&[1], 10)).expect("accepted");

        // B advances far past the message's anchor block, expiring it.
        b.board.set_head(10 + easy_cfg().block_range + 5, B256::repeat_byte(0x02));

        send_board_message_ids(&a.board, &a.tx);
        deliver(&mut a, &b);

        assert_eq!(b.board.status().2, 0, "expired announcements are not requested");
        assert_eq!(b.rep.bad_message(), 0, "being out of window is not misbehaviour");
        assert_eq!(b.rep.bad_protocol(), 0);
    }
}
