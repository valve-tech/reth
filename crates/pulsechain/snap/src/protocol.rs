//! The `snap/1` `RLPx` sub-protocol: a [`ProtocolHandler`] that announces `snap/1` and serves it
//! from a shared [`Snap1Server`].
//!
//! Each connection decodes inbound frames and hands requests to the server, which applies the
//! admission limits. Replies go out as they finish; `snap/1` clients match them by request id. A
//! connection runs at most [`MAX_PENDING_REQUESTS`] requests, which reserve at most
//! [`MAX_PENDING_REPLY_BYTES`]. A request that does not fit waits in a queue of at most
//! [`MAX_BUFFERED_MESSAGES`] requests and [`MAX_BUFFERED_BYTES`] of decoded requests, and starts
//! once it fits as running ones finish; a small request does not wait behind a large one. A
//! request past the queue, or one that waits longer than the server's queue timeout, is answered
//! empty. So the connection keeps draining the multiplexer's queue for this protocol: a full queue
//! would end the whole session, `eth` included.
//!
//! A frame over [`MAX_FRAME_BYTES`], a frame that does not decode, an id outside `snap/1`, or a
//! response-shaped message ends the stream, which disconnects the peer. Limits never disconnect:
//! the server answers empty.

use crate::{
    backend::Snap1Backend,
    message::{Snap1Message, TrieNodePathSet, SNAP1_MESSAGE_COUNT, SNAP1_VERSION},
    server::{reply_budget, PeerId, Snap1Server},
};
use alloy_primitives::{bytes::BytesMut, Bytes};
use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, Stream, StreamExt},
};
use reth_eth_wire::{
    capability::SharedCapabilities,
    multiplex::ProtocolConnection,
    protocol::{Protocol, ProtocolIngressLimits},
    Capability,
};
use reth_network::protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler};
use reth_network_api::Direction;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// The largest inbound frame, including the message id byte: 128 KiB.
///
/// Every `snap/1` request is small. The largest one a client needs is a `GetTrieNodes` with
/// [`MAX_TRIE_NODE_LOOKUPS`](crate::MAX_TRIE_NODE_LOOKUPS) storage sets of one full-length path
/// each: 1024 x (33 owner + 34 path + 2 list header) is about 70 KiB with the request fields. A
/// full `GetByteCodes` is 1024 x 33, about 34 KiB, and a full `GetStorageRanges` is about the
/// same. 128 KiB holds the largest with almost 2x margin. A larger frame ends the connection.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

/// The most inbound bytes waiting for this connection: 1 MiB, eight full frames. The decoded
/// requests in the connection's queue are held to the same bound.
pub const MAX_BUFFERED_BYTES: usize = 1024 * 1024;

/// The most inbound messages waiting for this connection: two request windows. The connection's
/// queue holds at most this many requests.
pub const MAX_BUFFERED_MESSAGES: usize = 2 * MAX_PENDING_REQUESTS;

/// Requests one connection runs at once. Requests beyond this wait in the connection's queue.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// The most reply bytes the requests of one connection may reserve: 16 MiB. A request whose
/// reservation does not fit waits in the connection's queue, unless the connection runs nothing.
///
/// A request reserves its reply budget, capped at
/// [`SOFT_RESPONSE_LIMIT`](crate::SOFT_RESPONSE_LIMIT), plus [`REPLY_SLACK`] and the memory of
/// the decoded request. A reply leaves the reservation when the connection yields it. The
/// multiplexer then holds it in its outbound buffer until the peer reads it. That buffer is shared
/// with `eth`, caps at 32 MiB plus one message per connection, and stops the multiplexer from
/// taking replies while full. So one slow reader holds at most this reservation, that buffer and
/// the two messages the p2p sink admits: about 48 MiB of replies.
pub const MAX_PENDING_REPLY_BYTES: usize = 16 * 1024 * 1024;

/// The reply bytes a request reserves past its budget: the item that crosses the budget, and its
/// proof.
pub const REPLY_SLACK: usize = 64 * 1024;

/// Announces and serves `snap/1`.
pub struct Snap1Handler<F> {
    server: Arc<Snap1Server<F>>,
}

impl<F> Snap1Handler<F> {
    /// Creates a handler that serves through `server`.
    pub const fn new(server: Arc<Snap1Server<F>>) -> Self {
        Self { server }
    }
}

impl<F> Clone for Snap1Handler<F> {
    fn clone(&self) -> Self {
        Self { server: self.server.clone() }
    }
}

impl<F> std::fmt::Debug for Snap1Handler<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snap1Handler").finish_non_exhaustive()
    }
}

/// The `snap/1` capability this handler announces.
pub const fn snap1_protocol() -> Protocol {
    Protocol::new(Capability::new_static("snap", SNAP1_VERSION), SNAP1_MESSAGE_COUNT)
}

impl<F: Snap1Backend> ProtocolHandler for Snap1Handler<F> {
    type ConnectionHandler = Self;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(self.clone())
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(self.clone())
    }
}

impl<F: Snap1Backend> ConnectionHandler for Snap1Handler<F> {
    type Connection = Snap1Connection<ProtocolConnection, F>;

    fn protocol(&self) -> Protocol {
        snap1_protocol()
    }

    fn inbound_limits(&self) -> ProtocolIngressLimits {
        ProtocolIngressLimits::new(MAX_FRAME_BYTES)
            .with_max_buffered_bytes(MAX_BUFFERED_BYTES)
            .with_max_buffered_messages(MAX_BUFFERED_MESSAGES)
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        _direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        Snap1Connection::new(self.server, peer_id, conn)
    }
}

/// One peer's `snap/1` connection: a stream of encoded replies, in the order they finish.
///
/// The stream ends when the peer must be disconnected.
pub struct Snap1Connection<S, F> {
    inbound: S,
    server: Arc<Snap1Server<F>>,
    peer: PeerId,
    /// Running requests, each with the reply bytes it reserved.
    pending: FuturesUnordered<BoxFuture<'static, (usize, Option<Snap1Message>)>>,
    /// The reply bytes the running requests reserved.
    reserved: usize,
    /// Requests that wait for room, oldest first, each with when it stops waiting and the memory
    /// it holds.
    queue: VecDeque<(tokio::time::Instant, Snap1Message, usize)>,
    /// The memory the queued requests hold.
    queued_bytes: usize,
    /// Fires when the oldest queued request stops waiting. Made on first use, as it needs the
    /// runtime.
    queue_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Empty answers to requests past the queue or that waited too long. Reading pauses at
    /// [`MAX_BUFFERED_MESSAGES`] of them, which only happens while the multiplexer is not taking
    /// replies, and then it reads nothing either. Queued requests that stop waiting can add up to
    /// as many again.
    busy: VecDeque<Snap1Message>,
    inbound_done: bool,
}

impl<S, F> std::fmt::Debug for Snap1Connection<S, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snap1Connection")
            .field("peer", &self.peer)
            .field("pending", &self.pending.len())
            .field("reserved", &self.reserved)
            .field("queued", &self.queue.len())
            .finish_non_exhaustive()
    }
}

impl<S, F: Snap1Backend> Snap1Connection<S, F> {
    /// Creates the connection over the peer's inbound frames.
    pub fn new(server: Arc<Snap1Server<F>>, peer: PeerId, inbound: S) -> Self {
        server.peer_connected(peer);
        Self {
            inbound,
            server,
            peer,
            pending: FuturesUnordered::new(),
            reserved: 0,
            queue: VecDeque::new(),
            queued_bytes: 0,
            queue_timer: None,
            busy: VecDeque::new(),
            inbound_done: false,
        }
    }

    /// Whether a request that reserves `reserve` bytes may run now: when its reservation fits
    /// under the byte cap, or the connection runs nothing.
    fn has_room(&self, reserve: usize) -> bool {
        self.pending.is_empty() ||
            (self.pending.len() < MAX_PENDING_REQUESTS &&
                self.reserved.saturating_add(reserve) <= MAX_PENDING_REPLY_BYTES)
    }

    /// Runs `msg`, which reserves `reserve` reply bytes.
    fn start(&mut self, msg: Snap1Message, reserve: usize) {
        self.reserved += reserve;
        let (server, peer) = (self.server.clone(), self.peer);
        self.pending.push(Box::pin(async move { (reserve, server.handle(peer, msg).await) }));
    }

    /// Starts every queued request that has room, oldest first. A small request does not wait
    /// behind a large one that does not fit yet.
    fn start_queued(&mut self) {
        let mut i = 0;
        while i < self.queue.len() {
            if self.pending.len() >= MAX_PENDING_REQUESTS {
                return
            }
            let reserve = reserve(&self.queue[i].1, self.queue[i].2);
            if !self.has_room(reserve) {
                i += 1;
                continue
            }
            let Some((_, msg, held)) = self.queue.remove(i) else { return };
            self.queued_bytes -= held;
            self.start(msg, reserve);
        }
    }

    /// Answers `msg` empty because the connection is full. Returns `false` for a message that is
    /// not a request.
    fn answer_busy(&mut self, msg: Snap1Message) -> bool {
        let Some(empty) = self.server.answer_busy(msg) else { return false };
        self.busy.push_back(empty);
        true
    }
}

impl<S, F> Drop for Snap1Connection<S, F> {
    fn drop(&mut self) {
        self.server.peer_disconnected(self.peer);
    }
}

impl<S, F> Stream for Snap1Connection<S, F>
where
    S: Stream<Item = BytesMut> + Unpin,
    F: Snap1Backend,
{
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<BytesMut>> {
        let this = self.get_mut();

        // Take in every request the peer sent; past the queue they are answered empty.
        while !this.inbound_done && this.busy.len() < MAX_BUFFERED_MESSAGES {
            match this.inbound.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => this.inbound_done = true,
                Poll::Ready(Some(frame)) => {
                    // The multiplexer enforces the same limit; this keeps it for any other source.
                    if frame.len() > MAX_FRAME_BYTES {
                        return Poll::Ready(None)
                    }
                    let Ok(msg) = Snap1Message::decode(&frame) else { return Poll::Ready(None) };
                    if !is_request(&msg) {
                        return Poll::Ready(None)
                    }
                    let held = held_bytes(&msg, frame.len());
                    let reserve = reserve(&msg, held);
                    if this.has_room(reserve) {
                        this.start(msg, reserve);
                    } else if this.queue.len() < MAX_BUFFERED_MESSAGES &&
                        this.queued_bytes + held <= MAX_BUFFERED_BYTES
                    {
                        let until =
                            tokio::time::Instant::now() + this.server.connection_queue_timeout();
                        this.queued_bytes += held;
                        this.queue.push_back((until, msg, held));
                    } else if !this.answer_busy(msg) {
                        return Poll::Ready(None)
                    }
                }
            }
        }

        // Answer the queued requests that waited too long. All wait the same time, so the oldest
        // is the first to stop.
        while let Some(until) = this.queue.front().map(|(until, ..)| *until) {
            let timer =
                this.queue_timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(until)));
            if timer.deadline() != until {
                timer.as_mut().reset(until);
            }
            if timer.as_mut().poll(cx).is_pending() {
                break
            }
            let Some((_, msg, held)) = this.queue.pop_front() else { break };
            this.queued_bytes -= held;
            if !this.answer_busy(msg) {
                return Poll::Ready(None)
            }
        }

        let response = match this.busy.pop_front() {
            Some(empty) => Some(empty),
            None => match this.pending.poll_next_unpin(cx) {
                Poll::Ready(Some((reserve, response))) => {
                    this.reserved -= reserve;
                    this.start_queued();
                    // `None` is a message the server refused as not a request.
                    let Some(response) = response else { return Poll::Ready(None) };
                    Some(response)
                }
                Poll::Ready(None) if this.inbound_done => return Poll::Ready(None),
                Poll::Ready(None) | Poll::Pending => None,
            },
        };
        match response.map(|response| response.encode()) {
            Some(Ok(bytes)) => Poll::Ready(Some(BytesMut::from(bytes.as_ref()))),
            Some(Err(_)) => Poll::Ready(None),
            None => Poll::Pending,
        }
    }
}

/// The reply bytes a request that holds `held` bytes of memory reserves.
fn reserve(msg: &Snap1Message, held: usize) -> usize {
    reply_budget(msg) + REPLY_SLACK + held
}

/// About the memory a request decoded from a frame of `frame_len` bytes holds. A `GetTrieNodes`
/// of tiny path sets holds many times its frame; the other requests hold about their frame.
fn held_bytes(msg: &Snap1Message, frame_len: usize) -> usize {
    let Snap1Message::GetTrieNodes(m) = msg else { return frame_len };
    // The decoder keeps at most `MAX_TRIE_NODE_LOOKUPS` sets of a frame, so this cannot overflow.
    let sets = m.paths.capacity() * size_of::<TrieNodePathSet>();
    let held = m.paths.iter().fold(sets, |held, set| {
        held + set.capacity() * size_of::<Bytes>() +
            set.iter().map(|path| path.len()).sum::<usize>()
    });
    held.max(frame_len)
}

/// Returns `true` for the four messages a client sends.
const fn is_request(msg: &Snap1Message) -> bool {
    use reth_eth_wire_types::snap::SnapProtocolMessage as M;
    matches!(
        msg,
        Snap1Message::GetTrieNodes(_) |
            Snap1Message::Shared(
                M::GetAccountRange(_) | M::GetStorageRanges(_) | M::GetByteCodes(_)
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message::{GetTrieNodesMessage, TrieNodesMessage},
        server::{Lane, Snap1Config},
        test_utils::{FakeFactory, FakeState},
        RootLanes,
    };
    use alloy_primitives::{keccak256, Address, B256};
    use futures::channel::mpsc;
    use reth_eth_wire_types::snap::{
        AccountRangeMessage, ByteCodesMessage, GetAccountRangeMessage, GetByteCodesMessage,
        SnapProtocolMessage,
    };
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::{
        errors::provider::ProviderResult, StateRangeProviderFactory, StateRangeView,
    };

    const CODE: [u8; 2] = [0x60, 0x01];

    struct Backend {
        ranges: FakeFactory,
        codes: MockEthProvider,
        /// How long resolving a state view takes, except at [`Backend::fast_root`].
        view_delay: std::time::Duration,
        /// A root whose view resolves at once.
        fast_root: B256,
    }

    impl StateRangeProviderFactory for Backend {
        fn state_range_provider(&self, root: B256) -> ProviderResult<Option<StateRangeView>> {
            if root != self.fast_root {
                std::thread::sleep(self.view_delay);
            }
            self.ranges.state_range_provider(root)
        }
    }

    impl RootLanes for Backend {
        fn lane(&self, _root: B256) -> Option<Lane> {
            Some(Lane::Hot)
        }
    }

    impl Snap1Backend for Backend {
        fn byte_codes(&self, req: &GetByteCodesMessage) -> ProviderResult<ByteCodesMessage> {
            crate::serve_byte_codes(&self.codes, req)
        }
    }

    type Conn = Snap1Connection<mpsc::UnboundedReceiver<BytesMut>, Backend>;

    fn server() -> (Arc<Snap1Server<Backend>>, B256) {
        slow_server(std::time::Duration::ZERO)
    }

    fn slow_server(view_delay: std::time::Duration) -> (Arc<Snap1Server<Backend>>, B256) {
        server_with(view_delay, Snap1Config::default())
    }

    fn server_with(
        view_delay: std::time::Duration,
        cfg: Snap1Config,
    ) -> (Arc<Snap1Server<Backend>>, B256) {
        let mut ranges = FakeFactory::default();
        let root = ranges.add(FakeState::generated(20, 0));
        let fast_root = ranges.add(FakeState::generated(20, 1));
        let codes = MockEthProvider::default();
        codes.add_account(
            Address::with_last_byte(1),
            ExtendedAccount::new(0, Default::default()).with_bytecode(Bytes::from_static(&CODE)),
        );
        let backend = Backend { ranges, codes, view_delay, fast_root };
        let server = Arc::new(Snap1Server::new(Arc::new(backend), cfg));
        (server, root)
    }

    fn connection() -> (mpsc::UnboundedSender<BytesMut>, Conn, B256) {
        let (server, root) = server();
        let (tx, rx) = mpsc::unbounded();
        (tx, Snap1Connection::new(server, PeerId::repeat_byte(1), rx), root)
    }

    fn frame(msg: Snap1Message) -> BytesMut {
        BytesMut::from(msg.encode().unwrap().as_ref())
    }

    fn get_codes(id: u64) -> Snap1Message {
        Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
            request_id: id,
            hashes: vec![keccak256(CODE)],
            response_bytes: 1 << 20,
        }))
    }

    fn range_request(id: u64, root: B256) -> GetAccountRangeMessage {
        GetAccountRangeMessage {
            request_id: id,
            root_hash: root,
            starting_hash: B256::ZERO,
            limit_hash: B256::repeat_byte(0xff),
            response_bytes: 1 << 20,
        }
    }

    fn get_range(id: u64, root: B256) -> Snap1Message {
        Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(range_request(id, root)))
    }

    /// A `GetByteCodes` whose reply budget is the most the server grants.
    fn full_budget(id: u64) -> Snap1Message {
        Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
            request_id: id,
            hashes: vec![keccak256(CODE)],
            response_bytes: u64::MAX,
        }))
    }

    /// The reply bytes a [`full_budget`] request reserves.
    fn full_reserve() -> usize {
        crate::SOFT_RESPONSE_LIMIT + REPLY_SLACK + frame(full_budget(0)).len()
    }

    /// A `GetByteCodes` that reserves an eighth of a connection's reply bytes, so eight of them
    /// leave no room.
    fn eighth(id: u64) -> Snap1Message {
        let msg = |response_bytes| {
            Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
                request_id: id,
                hashes: vec![keccak256(CODE)],
                response_bytes,
            }))
        };
        let budget = MAX_PENDING_REPLY_BYTES / 8 - REPLY_SLACK;
        // The budget's encoding keeps its length when the frame size comes off it.
        let msg = msg((budget - frame(msg(budget as u64)).len()) as u64);
        assert_eq!(reserve(&msg, frame(msg.clone()).len()), MAX_PENDING_REPLY_BYTES / 8);
        msg
    }

    /// Polls the connection once.
    async fn poll_once<S: Stream<Item = BytesMut> + Unpin>(
        conn: &mut Snap1Connection<S, Backend>,
    ) -> Poll<Option<BytesMut>> {
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *conn).poll_next(cx))).await
    }

    async fn next_message<S: Stream<Item = BytesMut> + Unpin>(
        conn: &mut Snap1Connection<S, Backend>,
    ) -> Option<Snap1Message> {
        conn.next().await.map(|bytes| Snap1Message::decode(&bytes).unwrap())
    }

    #[tokio::test]
    async fn get_byte_codes_round_trips_through_the_framed_stream() {
        let (tx, mut conn, _) = connection();
        tx.unbounded_send(frame(get_codes(11))).unwrap();
        match next_message(&mut conn).await {
            Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) => {
                assert_eq!(m.request_id, 11);
                assert_eq!(m.codes, vec![Bytes::from_static(&CODE)]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_request_does_not_hold_back_later_replies() {
        let (server, root) = slow_server(std::time::Duration::from_millis(300));
        let (tx, rx) = mpsc::unbounded();
        let mut conn = Snap1Connection::new(server, PeerId::repeat_byte(1), rx);
        tx.unbounded_send(frame(get_range(1, root))).unwrap();
        tx.unbounded_send(frame(get_codes(2))).unwrap();
        assert!(matches!(
            next_message(&mut conn).await,
            Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) if m.request_id == 2
        ));
        assert!(matches!(
            next_message(&mut conn).await,
            Some(Snap1Message::Shared(SnapProtocolMessage::AccountRange(m))) if m.request_id == 1
        ));
    }

    // On this single-threaded runtime no request finishes while the test polls the connection.
    #[tokio::test]
    async fn reply_budgets_bound_what_a_connection_runs_and_the_rest_wait() {
        let (tx, mut conn, _) = connection();
        for id in 0..MAX_PENDING_REQUESTS as u64 {
            tx.unbounded_send(frame(full_budget(id))).unwrap();
        }
        drop(tx);
        // The first poll reads every frame, and runs requests until their reserved reply bytes
        // reach the cap. The rest wait.
        assert!(poll_once(&mut conn).await.is_pending());
        let ran = MAX_PENDING_REPLY_BYTES / full_reserve();
        assert_eq!(
            (conn.pending.len(), conn.reserved, conn.queue.len()),
            (ran, ran * full_reserve(), MAX_PENDING_REQUESTS - ran)
        );
        // The waiting ones start as running ones finish, and every request is served.
        let mut replies = Vec::new();
        while let Some(reply) = next_message(&mut conn).await {
            assert!(conn.reserved <= MAX_PENDING_REPLY_BYTES);
            replies.push(match reply {
                Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m)) => (m.request_id, m.codes),
                other => panic!("unexpected {other:?}"),
            });
        }
        replies.sort_unstable();
        let expected: Vec<_> = (0..MAX_PENDING_REQUESTS as u64)
            .map(|id| (id, vec![Bytes::from_static(&CODE)]))
            .collect();
        assert_eq!(replies, expected);
    }

    // The reservation covers replies in progress only. A yielded reply waits in the
    // multiplexer's outbound buffer, which bounds it.
    #[tokio::test]
    async fn a_yielded_reply_leaves_the_reservation() {
        let (tx, mut conn, _) = connection();
        tx.unbounded_send(frame(full_budget(1))).unwrap();
        assert!(poll_once(&mut conn).await.is_pending());
        assert_eq!(conn.reserved, full_reserve());
        let reply = next_message(&mut conn).await;
        assert!(matches!(
            reply,
            Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) if m.request_id == 1
        ));
        assert_eq!(conn.reserved, 0);
    }

    #[tokio::test]
    async fn requests_past_the_queue_are_answered_empty_at_once() {
        let (_, root) = server();
        // 1024 storage sets of one full-length path each.
        let big = |id| {
            frame(Snap1Message::GetTrieNodes(GetTrieNodesMessage {
                request_id: id,
                root_hash: root,
                paths: (0..1024u32)
                    .map(|i| {
                        vec![
                            Bytes::from(keccak256(i.to_be_bytes()).to_vec()),
                            Bytes::from(vec![0; 33]),
                        ]
                    })
                    .collect(),
                response_bytes: 1,
            }))
        };
        let big_frame = big(0);
        let big_held = held_bytes(&Snap1Message::decode(&big_frame).unwrap(), big_frame.len());
        let by_bytes = MAX_BUFFERED_BYTES / big_held;
        assert!(by_bytes < MAX_BUFFERED_MESSAGES);
        // The queue holds at most MAX_BUFFERED_MESSAGES requests and MAX_BUFFERED_BYTES of
        // decoded requests.
        let cases: [(&dyn Fn(u64) -> BytesMut, usize); 2] =
            [(&|id| frame(get_codes(id)), MAX_BUFFERED_MESSAGES), (&big, by_bytes)];
        for (request, queued) in cases {
            let (tx, mut conn, _) = connection();
            let ran = 8;
            for id in 0..ran {
                tx.unbounded_send(frame(eighth(id))).unwrap();
            }
            let last = ran + queued as u64;
            for id in ran..=last {
                tx.unbounded_send(request(id)).unwrap();
            }
            let Poll::Ready(Some(reply)) = poll_once(&mut conn).await else {
                panic!("the request past the queue must be answered at once")
            };
            let (id, empty) = match Snap1Message::decode(&reply).unwrap() {
                Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m)) => {
                    (m.request_id, m.codes.is_empty())
                }
                Snap1Message::TrieNodes(m) => (m.request_id, m.nodes.is_empty()),
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!((id, empty), (last, true));
            assert_eq!(conn.queue.len(), queued);
            assert!(conn.queued_bytes <= MAX_BUFFERED_BYTES);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn decoded_trie_node_requests_are_counted_at_their_decoded_size() {
        let (tx, mut conn, root) = connection();
        // 1024 account sets of a one-byte path: two bytes each on the wire.
        let tiny = |id| {
            Snap1Message::GetTrieNodes(GetTrieNodesMessage {
                request_id: id,
                root_hash: root,
                paths: vec![vec![Bytes::from_static(&[5])]; 1024],
                response_bytes: 0,
            })
        };
        let frame_len = frame(tiny(0)).len();
        // Decoded, each set takes at least its vector and one `Bytes`.
        let decoded = 1024 * (size_of::<TrieNodePathSet>() + size_of::<Bytes>());
        assert!(decoded > 20 * frame_len, "{decoded} vs {frame_len}");
        // One more than the request counts allow, so the first poll answers one empty.
        for id in 0..=(MAX_PENDING_REQUESTS + MAX_BUFFERED_MESSAGES) as u64 {
            tx.unbounded_send(frame(tiny(id))).unwrap();
        }
        assert!(matches!(poll_once(&mut conn).await, Poll::Ready(Some(_))));
        assert!(conn.reserved >= conn.pending.len() * (REPLY_SLACK + decoded));
        assert!(conn.reserved <= MAX_PENDING_REPLY_BYTES);
        assert!(conn.queued_bytes >= conn.queue.len() * decoded);
        assert!(conn.queued_bytes <= MAX_BUFFERED_BYTES);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_queued_request_is_answered_empty_after_the_queue_timeout() {
        // Every full-budget request gets a hot slot at once and holds it for the view delay.
        let cfg = Snap1Config {
            hot_workers: 16,
            hot_per_peer: 8,
            hot_queue_timeout: std::time::Duration::from_millis(100),
            ..Default::default()
        };
        let (server, root) = server_with(std::time::Duration::from_millis(400), cfg);
        let (tx, rx) = mpsc::unbounded();
        let mut conn = Snap1Connection::new(server, PeerId::repeat_byte(1), rx);
        let ran = (MAX_PENDING_REPLY_BYTES / full_reserve()) as u64;
        for id in 0..ran {
            let msg = Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(
                GetAccountRangeMessage { response_bytes: u64::MAX, ..range_request(id, root) },
            ));
            tx.unbounded_send(frame(msg)).unwrap();
        }
        // It does not fit beside the running ones.
        tx.unbounded_send(frame(full_budget(ran))).unwrap();
        drop(tx);
        let asked = std::time::Instant::now();
        match next_message(&mut conn).await {
            Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) => {
                assert_eq!((m.request_id, m.codes.len()), (ran, 0));
            }
            other => panic!("unexpected {other:?}"),
        }
        let waited = asked.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(100) &&
                waited < std::time::Duration::from_millis(400),
            "{waited:?}"
        );
        let mut served = 0;
        while let Some(reply) = next_message(&mut conn).await {
            match reply {
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => {
                    assert!(!m.accounts.is_empty(), "request {} answered empty", m.request_id);
                    served += 1;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(served, ran);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lite_client_request_profile_gets_no_empty_answer() {
        let (tx, mut conn, root) = connection();
        // A Go lite client sends 16 GetTrieNodes chunks with a 2 MiB budget at once, beside its
        // window of 64 one-key account requests.
        for id in 0..16u64 {
            tx.unbounded_send(frame(Snap1Message::GetTrieNodes(GetTrieNodesMessage {
                request_id: id,
                root_hash: root,
                paths: vec![vec![Bytes::from_static(&[0x00])]],
                response_bytes: 2 << 20,
            })))
            .unwrap();
        }
        for id in 16..80u64 {
            let key = keccak256((id % 20).to_be_bytes());
            let msg = Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(
                GetAccountRangeMessage {
                    request_id: id,
                    root_hash: root,
                    starting_hash: key,
                    limit_hash: key,
                    response_bytes: 1,
                },
            ));
            tx.unbounded_send(frame(msg)).unwrap();
        }
        drop(tx);
        let mut ids = Vec::new();
        while let Some(reply) = next_message(&mut conn).await {
            let (id, empty) = match reply {
                Snap1Message::TrieNodes(m) => (m.request_id, m.nodes.is_empty()),
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => {
                    (m.request_id, m.accounts.is_empty())
                }
                other => panic!("unexpected {other:?}"),
            };
            assert!(!empty, "request {id} was answered empty");
            ids.push(id);
        }
        ids.sort_unstable();
        assert_eq!(ids, (0..80).collect::<Vec<_>>());
    }

    /// The same profile under the default limits, with trie chunks that take 0.7 s each as on
    /// a busy node. The chunks fill the reply reservations and the peer's hot slots. The last
    /// chunk can wait past the queue timeout and be answered empty, but every one-key request is
    /// served beside them.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lite_client_profile_beside_slow_chunks_gets_every_one_key_answer() {
        let (server, slow_root) = slow_server(std::time::Duration::from_millis(700));
        let fast = FakeState::generated(20, 1);
        let fast_root = fast.root();
        let (tx, rx) = mpsc::unbounded();
        let mut conn = Snap1Connection::new(server, PeerId::repeat_byte(1), rx);
        for id in 0..16u64 {
            tx.unbounded_send(frame(Snap1Message::GetTrieNodes(GetTrieNodesMessage {
                request_id: id,
                root_hash: slow_root,
                paths: vec![vec![Bytes::from_static(&[0x00])]],
                response_bytes: 2 << 20,
            })))
            .unwrap();
        }
        let keys: Vec<B256> = fast.accounts.keys().copied().collect();
        for id in 16..80u64 {
            let key = keys[id as usize % keys.len()];
            let msg = Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(
                GetAccountRangeMessage {
                    request_id: id,
                    root_hash: fast_root,
                    starting_hash: key,
                    limit_hash: key,
                    response_bytes: 1,
                },
            ));
            tx.unbounded_send(frame(msg)).unwrap();
        }
        drop(tx);
        let (mut ids, mut empty) = (Vec::new(), Vec::new());
        while let Some(reply) = next_message(&mut conn).await {
            match reply {
                Snap1Message::TrieNodes(m) => ids.push(m.request_id),
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => {
                    ids.push(m.request_id);
                    if m.accounts.is_empty() {
                        empty.push(m.request_id);
                    }
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(empty, Vec::<u64>::new(), "one-key requests answered empty");
        ids.sort_unstable();
        assert_eq!(ids, (0..80).collect::<Vec<_>>());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_key_requests_do_not_wait_behind_queued_large_budgets() {
        // Enough slots that only the connection's reply reservations hold requests back.
        let cfg = Snap1Config {
            hot_workers: 32,
            hot_per_peer: 16,
            hot_queue_timeout: std::time::Duration::from_millis(300),
            ..Default::default()
        };
        let (server, slow_root) = server_with(std::time::Duration::from_millis(600), cfg);
        let fast = FakeState::generated(20, 1);
        let fast_root = fast.root();
        let (tx, rx) = mpsc::unbounded();
        let mut conn = Snap1Connection::new(server, PeerId::repeat_byte(1), rx);
        // A Go lite client's large trie chunks fill the reply reservations; its one-key
        // account requests come after them.
        for id in 0..16u64 {
            let msg = Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(
                GetAccountRangeMessage { response_bytes: 2 << 20, ..range_request(id, slow_root) },
            ));
            tx.unbounded_send(frame(msg)).unwrap();
        }
        let keys: Vec<B256> = fast.accounts.keys().copied().collect();
        for id in 16..80u64 {
            let key = keys[id as usize % keys.len()];
            let msg = Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(
                GetAccountRangeMessage {
                    request_id: id,
                    root_hash: fast_root,
                    starting_hash: key,
                    limit_hash: key,
                    response_bytes: 1,
                },
            ));
            tx.unbounded_send(frame(msg)).unwrap();
        }
        drop(tx);
        let mut empty = Vec::new();
        while let Some(reply) = next_message(&mut conn).await {
            match reply {
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => {
                    if m.request_id >= 16 && m.accounts.is_empty() {
                        empty.push(m.request_id);
                    }
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(empty, Vec::<u64>::new());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pipelining_peer_never_fills_the_multiplexer_queue() {
        let (server, root) = slow_server(std::time::Duration::from_millis(300));
        // Like the multiplexer's queue for this protocol: a full queue ends the session.
        let (mut tx, rx) = mpsc::channel(MAX_BUFFERED_MESSAGES - 1);
        let mut conn = Snap1Connection::new(server, PeerId::repeat_byte(1), rx);
        let mut ids = Vec::new();
        let mut take = |bytes: BytesMut| {
            ids.push(match Snap1Message::decode(&bytes).unwrap() {
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => m.request_id,
                other => panic!("unexpected {other:?}"),
            })
        };
        let total = 250u64;
        for id in 0..total {
            // The multiplexer polls the connection until it is pending, then reads one frame.
            while let Poll::Ready(reply) =
                std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut conn).poll_next(cx))).await
            {
                take(reply.expect("the stream must not end"));
            }
            tx.try_send(frame(get_range(id, root))).unwrap_or_else(|err| {
                panic!("request {id} found the queue full: {err}");
            });
        }
        drop(tx);
        while let Some(reply) = conn.next().await {
            take(reply);
        }
        ids.sort_unstable();
        assert_eq!(ids, (0..total).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn every_request_gets_one_reply_with_its_id() {
        let (tx, mut conn, root) = connection();
        for id in 1..=6u64 {
            let msg = match id % 3 {
                0 => get_codes(id),
                1 => get_range(id, root),
                _ => Snap1Message::GetTrieNodes(GetTrieNodesMessage {
                    request_id: id,
                    root_hash: root,
                    paths: vec![vec![Bytes::from_static(&[0x00])]],
                    response_bytes: 1 << 20,
                }),
            };
            tx.unbounded_send(frame(msg)).unwrap();
        }
        let mut ids = Vec::new();
        for _ in 0..6 {
            ids.push(match next_message(&mut conn).await.unwrap() {
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => m.request_id,
                Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m)) => m.request_id,
                Snap1Message::TrieNodes(m) => m.request_id,
                other => panic!("unexpected {other:?}"),
            });
        }
        ids.sort_unstable();
        assert_eq!(ids, [1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn garbage_frames_end_the_stream() {
        for garbage in [vec![0x42u8, 0xc0], vec![], vec![0x04, 0xff, 0xff], vec![0x08, 0xc0]] {
            let (tx, mut conn, _) = connection();
            tx.unbounded_send(BytesMut::from(garbage.as_slice())).unwrap();
            tx.unbounded_send(frame(get_codes(1))).unwrap();
            assert!(next_message(&mut conn).await.is_none(), "frame {garbage:?}");
        }
    }

    #[tokio::test]
    async fn response_shaped_messages_end_the_stream() {
        let responses = [
            Snap1Message::Shared(SnapProtocolMessage::AccountRange(AccountRangeMessage {
                request_id: 1,
                accounts: vec![],
                proof: vec![],
            })),
            Snap1Message::Shared(SnapProtocolMessage::ByteCodes(ByteCodesMessage {
                request_id: 1,
                codes: vec![],
            })),
            Snap1Message::TrieNodes(TrieNodesMessage { request_id: 1, nodes: vec![] }),
        ];
        for msg in responses {
            let (tx, mut conn, _) = connection();
            tx.unbounded_send(frame(msg)).unwrap();
            assert!(next_message(&mut conn).await.is_none());
        }
    }

    #[tokio::test]
    async fn stream_ends_when_the_peer_closes_after_the_last_reply() {
        let (tx, mut conn, _) = connection();
        tx.unbounded_send(frame(get_codes(2))).unwrap();
        drop(tx);
        assert!(next_message(&mut conn).await.is_some());
        assert!(next_message(&mut conn).await.is_none());
    }

    #[tokio::test]
    async fn a_flood_is_answered_in_full_with_bounded_buffering() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (server, _) = server();
        let (tx, rx) = mpsc::unbounded();
        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = pulled.clone();
        let inbound = rx.inspect(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let mut conn = Snap1Connection::new(server, PeerId::repeat_byte(1), inbound);
        let total = MAX_PENDING_REQUESTS * 4;
        for id in 0..total as u64 {
            tx.unbounded_send(frame(get_codes(id))).unwrap();
        }
        let mut ids = Vec::new();
        for id in 0..total {
            match conn.next().await.map(|bytes| Snap1Message::decode(&bytes).unwrap()) {
                Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) => {
                    ids.push(m.request_id)
                }
                other => panic!("unexpected {other:?}"),
            }
            // The connection reads at most a window, a queue, and a queue of empty answers ahead.
            let read = pulled.load(Ordering::SeqCst);
            let ahead = MAX_PENDING_REQUESTS + 2 * MAX_BUFFERED_MESSAGES;
            assert!(read <= id + 1 + ahead, "read {read} after {} replies", id + 1);
        }
        assert_eq!(pulled.load(Ordering::SeqCst), total);
        ids.sort_unstable();
        assert_eq!(ids, (0..total as u64).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn an_oversized_frame_ends_the_stream() {
        let (tx, mut conn, _) = connection();
        // A well-formed request, one hash over the frame limit.
        let hashes = vec![keccak256(CODE); MAX_FRAME_BYTES / 33 + 1];
        let msg = Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
            request_id: 1,
            hashes,
            response_bytes: 1 << 20,
        }));
        let bytes = frame(msg);
        assert!(bytes.len() > MAX_FRAME_BYTES);
        tx.unbounded_send(bytes).unwrap();
        assert!(next_message(&mut conn).await.is_none());
    }

    #[tokio::test]
    async fn the_largest_legitimate_requests_fit_a_frame() {
        let (tx, mut conn, root) = connection();
        // 1024 storage sets of one full-length path each: the costliest encoding of 1024 lookups.
        let paths = (0..1024u32)
            .map(|i| {
                vec![Bytes::from(keccak256(i.to_be_bytes()).to_vec()), Bytes::from(vec![0u8; 33])]
            })
            .collect();
        let trie = Snap1Message::GetTrieNodes(GetTrieNodesMessage {
            request_id: 1,
            root_hash: root,
            paths,
            response_bytes: u64::MAX,
        });
        let codes = Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
            request_id: 2,
            hashes: vec![keccak256(CODE); 1024],
            response_bytes: u64::MAX,
        }));
        for msg in [trie, codes] {
            let bytes = frame(msg);
            assert!(bytes.len() <= MAX_FRAME_BYTES, "{} bytes", bytes.len());
            tx.unbounded_send(bytes).unwrap();
        }
        let mut ids = Vec::new();
        for _ in 0..2 {
            ids.push(match next_message(&mut conn).await {
                Some(Snap1Message::TrieNodes(m)) => m.request_id,
                Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) => m.request_id,
                other => panic!("unexpected {other:?}"),
            });
        }
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
    }

    #[test]
    fn handler_announces_snap1_with_eight_messages_and_keeps_peers_without_it() {
        let (_tx, conn, _) = connection();
        let handler = Snap1Handler::new(conn.server.clone());
        let protocol = ConnectionHandler::protocol(&handler);
        assert_eq!(protocol.cap, Capability::new_static("snap", 1));
        assert_eq!(protocol.messages(), 8);
        let limits = handler.inbound_limits();
        assert_eq!(limits.max_frame_bytes(), Some(128 * 1024));
        assert_eq!(limits.max_buffered_bytes(), 1024 * 1024);
        assert_eq!(limits.max_buffered_messages(), 128);
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        assert!(ProtocolHandler::on_incoming(&handler, addr).is_some());
        assert!(ProtocolHandler::on_outgoing(&handler, addr, PeerId::ZERO).is_some());
        assert_eq!(
            handler.on_unsupported_by_peer(
                &SharedCapabilities::try_new(vec![Protocol::eth_68()], vec![Capability::eth_68()])
                    .unwrap(),
                Direction::Incoming,
                PeerId::ZERO
            ),
            OnNotSupported::KeepAlive
        );
    }
}
