#![allow(unreachable_pub)]
//! Testing gossiping of transactions.

use std::{
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
    time::Duration,
};

use alloy_primitives::bytes::BytesMut;
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
};
use reth_network::{
    protocol::{ConnectionHandler, IntoRlpxSubProtocol, OnNotSupported, ProtocolHandler},
    test_utils::{NetworkEventStream, Testnet},
    NetworkConfigBuilder, NetworkEventListenerProvider, NetworkManager, NetworkProtocols,
};
use reth_network_api::{Direction, NetworkInfo, PeerId, Peers};
use reth_provider::{noop::NoopProvider, test_utils::MockEthProvider};
use reth_tasks::Runtime;
use secp256k1::SecretKey;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::multiplex::proto::{PingPongProtoMessage, PingPongProtoMessageKind};

/// A simple Rlpx subprotocol that sends pings and pongs
mod proto {
    use super::*;
    use alloy_primitives::bytes::{Buf, BufMut};
    use reth_eth_wire::Capability;

    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PingPongProtoMessageId {
        Ping = 0x00,
        Pong = 0x01,
        PingMessage = 0x02,
        PongMessage = 0x03,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PingPongProtoMessageKind {
        Ping,
        Pong,
        PingMessage(String),
        PongMessage(String),
    }

    /// A protocol message, containing a message ID and payload.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PingPongProtoMessage {
        pub message_type: PingPongProtoMessageId,
        pub message: PingPongProtoMessageKind,
    }

    impl PingPongProtoMessage {
        /// Returns the capability for the `ping` protocol.
        pub const fn capability() -> Capability {
            Capability::new_static("ping", 1)
        }

        /// Returns the protocol for the `test` protocol.
        pub const fn protocol() -> Protocol {
            Protocol::new(Self::capability(), 4)
        }

        /// Creates a ping message
        pub const fn ping() -> Self {
            Self {
                message_type: PingPongProtoMessageId::Ping,
                message: PingPongProtoMessageKind::Ping,
            }
        }

        /// Creates a pong message
        pub const fn pong() -> Self {
            Self {
                message_type: PingPongProtoMessageId::Pong,
                message: PingPongProtoMessageKind::Pong,
            }
        }

        /// Creates a ping message
        pub fn ping_message(msg: impl Into<String>) -> Self {
            Self {
                message_type: PingPongProtoMessageId::PingMessage,
                message: PingPongProtoMessageKind::PingMessage(msg.into()),
            }
        }
        /// Creates a ping message
        pub fn pong_message(msg: impl Into<String>) -> Self {
            Self {
                message_type: PingPongProtoMessageId::PongMessage,
                message: PingPongProtoMessageKind::PongMessage(msg.into()),
            }
        }

        /// Creates a new `TestProtoMessage` with the given message ID and payload.
        pub fn encoded(&self) -> BytesMut {
            let mut buf = BytesMut::new();
            buf.put_u8(self.message_type as u8);
            match &self.message {
                PingPongProtoMessageKind::Ping | PingPongProtoMessageKind::Pong => {}
                PingPongProtoMessageKind::PingMessage(msg) |
                PingPongProtoMessageKind::PongMessage(msg) => {
                    buf.put(msg.as_bytes());
                }
            }
            buf
        }

        /// Decodes a `TestProtoMessage` from the given message buffer.
        pub fn decode_message(buf: &mut &[u8]) -> Option<Self> {
            if buf.is_empty() {
                return None
            }
            let id = buf[0];
            buf.advance(1);
            let message_type = match id {
                0x00 => PingPongProtoMessageId::Ping,
                0x01 => PingPongProtoMessageId::Pong,
                0x02 => PingPongProtoMessageId::PingMessage,
                0x03 => PingPongProtoMessageId::PongMessage,
                _ => return None,
            };
            let message = match message_type {
                PingPongProtoMessageId::Ping => PingPongProtoMessageKind::Ping,
                PingPongProtoMessageId::Pong => PingPongProtoMessageKind::Pong,
                PingPongProtoMessageId::PingMessage => PingPongProtoMessageKind::PingMessage(
                    String::from_utf8_lossy(&buf[..]).into_owned(),
                ),
                PingPongProtoMessageId::PongMessage => PingPongProtoMessageKind::PongMessage(
                    String::from_utf8_lossy(&buf[..]).into_owned(),
                ),
            };
            Some(Self { message_type, message })
        }
    }
}

#[derive(Debug)]
struct PingPongProtoHandler {
    state: ProtocolState,
    /// What the handler does when the remote does not speak the protocol.
    ///
    /// Both answers are in use. `Disconnect` drops the peer, which is what a required
    /// protocol wants. `KeepAlive` holds the session open without the protocol, which is
    /// what an optional one wants — and it is the case worth testing, because such a
    /// session looks healthy from every angle except the negotiated capability list.
    on_unsupported: OnNotSupported,
}

impl PingPongProtoHandler {
    /// Drops any peer that does not speak the protocol.
    const fn disconnecting(state: ProtocolState) -> Self {
        Self { state, on_unsupported: OnNotSupported::Disconnect }
    }

    /// Stays connected to a peer that does not speak the protocol.
    const fn optional(state: ProtocolState) -> Self {
        Self { state, on_unsupported: OnNotSupported::KeepAlive }
    }

    fn connection_handler(&self) -> PingPongConnectionHandler {
        PingPongConnectionHandler { state: self.state.clone(), on_unsupported: self.on_unsupported }
    }
}

impl ProtocolHandler for PingPongProtoHandler {
    type ConnectionHandler = PingPongConnectionHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(self.connection_handler())
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(self.connection_handler())
    }
}

#[derive(Clone, Debug)]
struct ProtocolState {
    events: mpsc::UnboundedSender<ProtocolEvent>,
}

#[derive(Debug)]
enum ProtocolEvent {
    Established {
        #[expect(dead_code)]
        direction: Direction,
        peer_id: PeerId,
        to_connection: mpsc::UnboundedSender<Command>,
    },
}

enum Command {
    /// Send a ping message to the peer.
    PingMessage {
        msg: String,
        /// The response will be sent to this channel.
        response: oneshot::Sender<String>,
    },
}

struct PingPongConnectionHandler {
    state: ProtocolState,
    on_unsupported: OnNotSupported,
}

impl ConnectionHandler for PingPongConnectionHandler {
    type Connection = PingPongProtoConnection;

    fn protocol(&self) -> Protocol {
        PingPongProtoMessage::protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        self.on_unsupported
    }

    fn into_connection(
        self,
        direction: Direction,
        _peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let (tx, rx) = mpsc::unbounded_channel();
        self.state
            .events
            .send(ProtocolEvent::Established { direction, peer_id: _peer_id, to_connection: tx })
            .ok();
        PingPongProtoConnection {
            conn,
            initial_ping: direction.is_outgoing().then(PingPongProtoMessage::ping),
            commands: UnboundedReceiverStream::new(rx),
            pending_pong: None,
        }
    }
}

struct PingPongProtoConnection {
    conn: ProtocolConnection,
    initial_ping: Option<PingPongProtoMessage>,
    commands: UnboundedReceiverStream<Command>,
    pending_pong: Option<oneshot::Sender<String>>,
}

impl Stream for PingPongProtoConnection {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(initial_ping) = this.initial_ping.take() {
            return Poll::Ready(Some(initial_ping.encoded()))
        }

        loop {
            if let Poll::Ready(Some(cmd)) = this.commands.poll_next_unpin(cx) {
                return match cmd {
                    Command::PingMessage { msg, response } => {
                        this.pending_pong = Some(response);
                        Poll::Ready(Some(PingPongProtoMessage::ping_message(msg).encoded()))
                    }
                }
            }
            let Some(msg) = ready!(this.conn.poll_next_unpin(cx)) else { return Poll::Ready(None) };

            let Some(msg) = PingPongProtoMessage::decode_message(&mut &msg[..]) else {
                return Poll::Ready(None)
            };

            match msg.message {
                PingPongProtoMessageKind::Ping => {
                    return Poll::Ready(Some(PingPongProtoMessage::pong().encoded()))
                }
                PingPongProtoMessageKind::Pong => {}
                PingPongProtoMessageKind::PingMessage(msg) => {
                    return Poll::Ready(Some(PingPongProtoMessage::pong_message(msg).encoded()))
                }
                PingPongProtoMessageKind::PongMessage(msg) => {
                    if let Some(sender) = this.pending_pong.take() {
                        sender.send(msg).ok();
                    }
                    continue
                }
            }

            return Poll::Pending
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_non_multiplex_peer() {
    reth_tracing::init_test_tracing();

    let net = Testnet::create(1).await;

    let secret_key = SecretKey::new(&mut rand_08::thread_rng());

    let config = NetworkConfigBuilder::eth(secret_key, Runtime::test())
        .listener_port(0)
        .disable_discovery()
        .build(NoopProvider::default());

    let mut network = NetworkManager::new(config).await.unwrap();

    let (tx, _) = mpsc::unbounded_channel();
    network
        .add_rlpx_sub_protocol(PingPongProtoHandler::disconnecting(ProtocolState { events: tx }));

    let handle = network.handle().clone();
    tokio::task::spawn(network);

    // create networkeventstream to get the next session event easily.
    let events = handle.event_listener();
    let mut event_stream = NetworkEventStream::new(events);

    let mut handles = net.handles();
    let handle0 = handles.next().unwrap();
    drop(handles);

    let _handle = net.spawn();

    handle.add_peer(*handle0.peer_id(), handle0.local_addr());

    let added_peer_id = event_stream.peer_added().await.unwrap();
    assert_eq!(added_peer_id, *handle0.peer_id());

    // peer with mismatched capability version should fail to connect and be removed.
    let removed_peer_id = event_stream.peer_removed().await.unwrap();
    assert_eq!(removed_peer_id, *handle0.peer_id());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proto_multiplex() {
    reth_tracing::init_test_tracing();
    let provider = MockEthProvider::default();
    let mut net = Testnet::create_with(2, provider.clone()).await;

    let (tx, mut from_peer0) = mpsc::unbounded_channel();
    net.peers_mut()[0]
        .add_rlpx_sub_protocol(PingPongProtoHandler::disconnecting(ProtocolState { events: tx }));

    let (tx, mut from_peer1) = mpsc::unbounded_channel();
    net.peers_mut()[1]
        .add_rlpx_sub_protocol(PingPongProtoHandler::disconnecting(ProtocolState { events: tx }));

    let handle = net.spawn();
    // connect all the peers
    handle.connect_peers().await;

    let peer0_to_peer1 = from_peer0.recv().await.unwrap();
    let peer0_conn = match peer0_to_peer1 {
        ProtocolEvent::Established { direction: _, peer_id, to_connection } => {
            assert_eq!(peer_id, *handle.peers()[1].peer_id());
            to_connection
        }
    };

    let peer1_to_peer0 = from_peer1.recv().await.unwrap();
    let peer1_conn = match peer1_to_peer0 {
        ProtocolEvent::Established { direction: _, peer_id, to_connection } => {
            assert_eq!(peer_id, *handle.peers()[0].peer_id());
            to_connection
        }
    };

    let (tx, rx) = oneshot::channel();
    // send a ping message from peer0 to peer1
    peer0_conn.send(Command::PingMessage { msg: "hello!".to_string(), response: tx }).unwrap();

    let response = rx.await.unwrap();
    assert_eq!(response, "hello!");

    let (tx, rx) = oneshot::channel();
    // send a ping message from peer1 to peer0
    peer1_conn
        .send(Command::PingMessage { msg: "hello from peer1!".to_string(), response: tx })
        .unwrap();

    let response = rx.await.unwrap();
    assert_eq!(response, "hello from peer1!");
}

/// A sub-protocol registered before the network spawns reaches a peer the node dials.
#[tokio::test(flavor = "multi_thread")]
async fn test_sub_protocol_registered_before_spawn_reaches_a_dialled_peer() {
    reth_tracing::init_test_tracing();

    assert!(
        dialler_establishes_sub_protocol(Registration::BeforeSpawn).await,
        "a protocol registered before the network spawns must reach a dialled peer"
    );
}

/// A sub-protocol registered after a session exists never appears on that session.
///
/// devp2p fixes the capability set during the `Hello` exchange, and `SessionManager` reads
/// the registered protocol list once per connection. Nothing renegotiates afterwards, so the
/// protocol stays absent for the life of the session. A node dials its trusted peers as it
/// starts and then holds those links open, which makes late registration permanent for
/// exactly the peers it most wants to talk to.
#[tokio::test(flavor = "multi_thread")]
async fn test_sub_protocol_registered_after_spawn_misses_an_existing_session() {
    reth_tracing::init_test_tracing();

    assert!(
        !dialler_establishes_sub_protocol(Registration::AfterSession).await,
        "a protocol registered after the session was negotiated must not appear on it"
    );
}

/// When the dialling node registers the sub-protocol, relative to its own startup.
#[derive(Clone, Copy)]
enum Registration {
    /// Before the network spawns, which is the only ordering that works.
    BeforeSpawn,
    /// Once the session with the peer is already established.
    AfterSession,
}

/// Dials a peer that speaks the ping-pong protocol, and reports whether the protocol
/// established on the dialling side.
async fn dialler_establishes_sub_protocol(registration: Registration) -> bool {
    // The peer being dialled always registers before it spawns, so it is never the reason
    // the protocol is missing.
    let mut listener = Testnet::create_with(1, MockEthProvider::default()).await;
    let (listener_tx, _listener_events) = mpsc::unbounded_channel();
    listener.peers_mut()[0].add_rlpx_sub_protocol(PingPongProtoHandler::optional(ProtocolState {
        events: listener_tx,
    }));

    let mut handles = listener.handles();
    let listener_handle = handles.next().unwrap();
    let listener_id = *listener_handle.peer_id();
    let listener_addr = listener_handle.local_addr();
    drop(handles);
    let _listener = listener.spawn();

    let secret_key = SecretKey::new(&mut rand_08::thread_rng());
    let config = NetworkConfigBuilder::eth(secret_key, Runtime::test())
        .listener_port(0)
        .disable_discovery()
        .build(NoopProvider::default());
    let mut network = NetworkManager::new(config).await.unwrap();

    let (tx, mut protocol_events) = mpsc::unbounded_channel();
    let state = ProtocolState { events: tx };

    if matches!(registration, Registration::BeforeSpawn) {
        network.add_rlpx_sub_protocol(PingPongProtoHandler::optional(state.clone()));
    }

    let handle = network.handle().clone();
    let mut sessions = NetworkEventStream::new(handle.event_listener());
    tokio::task::spawn(network);

    handle.add_peer(listener_id, listener_addr);

    if matches!(registration, Registration::AfterSession) {
        // Register only once the session has negotiated, so the outcome is the ordering
        // under test rather than a race against the dial.
        sessions.next_session_established().await;
        handle
            .add_rlpx_sub_protocol(PingPongProtoHandler::optional(state).into_rlpx_sub_protocol());
    }

    matches!(
        tokio::time::timeout(Duration::from_secs(5), protocol_events.recv()).await,
        Ok(Some(ProtocolEvent::Established { .. }))
    )
}
