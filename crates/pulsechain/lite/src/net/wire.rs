//! The wire: an outbound `snap/1` client sub-protocol on `reth-network`, and the `LiteNetwork`
//! that runs the network manager over a no-op provider.
//!
//! [`Snap1Client`] announces `snap/1` and, for every connected peer, keeps a channel on which
//! requests go out and responses are matched back by request id. This node never serves: a
//! frame with a request id from a peer is dropped unread, any other frame that does not decode
//! ends the connection, and so does a response with more list items than any answer it asks for. It
//! holds no blocks, so it answers each eth request for headers, bodies or receipts with an empty
//! list.
//!
//! Many peers advertise `snap/1` and never answer a `snap/1` request. So the first request to a
//! new peer is a probe: `GetByteCodes` for a hash no account has, which an honest server answers
//! at once with an empty list. A discovered peer that gives no answer to the probe or to any
//! other request within [`PROBE_TIMEOUT`] loses its session, so its slot goes back to discovery.
//! A static peer is kept, with a warning.

use super::{
    admit::{admit_peer, Expect},
    client::{Transport, TransportError, WireReceipt, CODE_BYTES},
    peers::BAN_FOR,
};
use crate::beacon::{HeadConfirm, PeerHeader};
use alloy_consensus::Header;
use alloy_eips::{eip2124::Head, BlockHashOrNumber};
use alloy_primitives::{bytes::BytesMut, B256};
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use parking_lot::Mutex;
use reth_eth_wire::{
    capability::SharedCapabilities,
    multiplex::ProtocolConnection,
    protocol::{Protocol, ProtocolIngressLimits},
};
use reth_eth_wire_types::{
    snap::{GetByteCodesMessage, SnapProtocolMessage as M},
    GetBlockHeaders, GetReceipts, HeadersDirection,
};
use reth_network::{
    protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler},
    EthNetworkPrimitives, NetworkHandle,
};
use reth_network_api::{Direction, PeerKind, PeerRequest, Peers, PeersInfo, ReputationChangeKind};
use reth_network_peers::{NodeRecord, PeerId};
use reth_pulsechain_snap::{snap1_protocol, Snap1Message};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

/// The most data one peer connection may have waiting for a response.
const MAX_PENDING: usize = 64;

/// How long a new peer has to answer the probe before a discovered one loses its session.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// The id of the probe request. Fetch ids count up from 1, so they never reach it.
const PROBE_ID: u64 = u64::MAX;
/// The hash whose code the probe asks for: the code of no account hashes to zero.
const PROBE_HASH: B256 = B256::ZERO;

/// The probe: `GetByteCodes` for [`PROBE_HASH`].
fn probe_request() -> Snap1Message {
    Snap1Message::Shared(M::GetByteCodes(GetByteCodesMessage {
        request_id: PROBE_ID,
        hashes: vec![PROBE_HASH],
        response_bytes: CODE_BYTES,
    }))
}

/// Where a connection's probe is.
#[derive(Debug)]
enum Probe {
    /// Not sent yet: the peer has `timeout` from the send.
    Due {
        timeout: Duration,
        /// A static peer: kept without an answer.
        keep: bool,
    },
    /// Sent, with no answer yet.
    Out { deadline: Pin<Box<tokio::time::Sleep>>, keep: bool },
}

/// The largest inbound `snap/1` frame: a full code reply, which may pass its [`CODE_BYTES`]
/// budget by its last contract (24 KiB at most) and the list headers. A larger frame ends the
/// connection before it is decompressed.
pub const MAX_FRAME_BYTES: usize = CODE_BYTES as usize + 64 * 1024;

/// The most RLP items a response may hold, counted over its lists. An answer this client accepts
/// holds a few hundred at most (64 codes, or 16 entries and 128 proof nodes), while a frame of
/// one-byte items would decode to millions of 32-byte entries.
const MAX_RESPONSE_ITEMS: usize = 4096;

/// The id of a response, or `None` for any other message.
pub const fn response_id(msg: &Snap1Message) -> Option<u64> {
    match msg {
        Snap1Message::Shared(M::AccountRange(r)) => Some(r.request_id),
        Snap1Message::Shared(M::StorageRanges(r)) => Some(r.request_id),
        Snap1Message::Shared(M::ByteCodes(r)) => Some(r.request_id),
        Snap1Message::TrieNodes(r) => Some(r.request_id),
        _ => None,
    }
}

/// `GetTrieNodes`, a `snap/1` id the shared set does not have.
const GET_TRIE_NODES: u8 = 0x06;
/// `TrieNodes`, a `snap/1` id the shared set does not have.
const TRIE_NODES: u8 = 0x07;

/// Whether `frame` carries a `snap/1` request id. This node serves nothing, so such a frame is
/// dropped before the decode, which would build every list it holds.
fn is_request_frame(frame: &[u8]) -> bool {
    use reth_eth_wire_types::snap::SnapMessageId as Id;
    let requests = [Id::GetAccountRange as u8, Id::GetStorageRanges as u8, Id::GetByteCodes as u8];
    frame.first().is_some_and(|id| requests.contains(id) || *id == GET_TRIE_NODES)
}

/// Whether `frame` is a response whose lists hold at most [`MAX_RESPONSE_ITEMS`] items, or not
/// a response. Runs before the decode, which would build every list it holds.
fn fits_item_budget(frame: &[u8]) -> bool {
    use reth_eth_wire_types::snap::SnapMessageId as Id;
    /// Responses nest their lists four deep: the message, its slot lists, one account's slots,
    /// one slot.
    const LIST_DEPTH: usize = 4;
    let Some((&id, body)) = frame.split_first() else { return true };
    let responses = [Id::AccountRange as u8, Id::StorageRanges as u8, Id::ByteCodes as u8];
    if !responses.contains(&id) && id != TRIE_NODES {
        return true;
    }
    let mut budget = MAX_RESPONSE_ITEMS;
    count_items(body, LIST_DEPTH, &mut budget).is_some()
}

/// Takes one from `budget` for every item in `buf` and, `depth` lists down, in the lists it
/// holds. `None` when the budget runs out or a header does not parse.
fn count_items(mut buf: &[u8], depth: usize, budget: &mut usize) -> Option<()> {
    while !buf.is_empty() {
        let header = alloy_rlp::Header::decode(&mut buf).ok()?;
        let payload = buf.get(..header.payload_length)?;
        buf = &buf[header.payload_length..];
        *budget = budget.checked_sub(1)?;
        if header.list && depth > 0 {
            count_items(payload, depth - 1, budget)?;
        }
    }
    Some(())
}

/// The id of a request, or `None` for any other message.
pub const fn request_id(msg: &Snap1Message) -> Option<u64> {
    match msg {
        Snap1Message::Shared(M::GetAccountRange(r)) => Some(r.request_id),
        Snap1Message::Shared(M::GetStorageRanges(r)) => Some(r.request_id),
        Snap1Message::Shared(M::GetByteCodes(r)) => Some(r.request_id),
        Snap1Message::GetTrieNodes(r) => Some(r.request_id),
        _ => None,
    }
}

#[derive(Debug)]
struct Outbound {
    id: u64,
    msg: Snap1Message,
    reply: oneshot::Sender<Snap1Message>,
}

#[derive(Debug, Default)]
struct Shared {
    peers: Mutex<HashMap<PeerId, mpsc::UnboundedSender<Outbound>>>,
}

/// The client half of `snap/1`: announces the protocol and exposes per-peer request channels.
#[derive(Clone, Default)]
pub struct Snap1Client {
    shared: Arc<Shared>,
    /// The static `--peer` nodes.
    statics: Arc<HashSet<PeerId>>,
    /// How long a new peer has to answer the probe; `None` sends no probe.
    probe: Option<Duration>,
}

impl std::fmt::Debug for Snap1Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snap1Client").field("peers", &self.shared.peers.lock().len()).finish()
    }
}

impl Snap1Client {
    /// A client for a node whose static `--peer` nodes are `statics`. With `probe`, each new
    /// peer is sent the probe and has that long to answer it.
    pub fn new(statics: HashSet<PeerId>, probe: Option<Duration>) -> Self {
        Self { shared: Arc::default(), statics: Arc::new(statics), probe }
    }

    /// A connection to `peer` over `inbound`, probed as this client's options say.
    fn connection<S>(&self, peer: PeerId, inbound: S) -> ClientConnection<S> {
        let conn = ClientConnection::new(self.shared.clone(), peer, inbound);
        match self.probe {
            Some(timeout) => conn.with_probe(timeout, self.statics.contains(&peer)),
            None => conn,
        }
    }

    /// Peers that have a live `snap/1` channel.
    pub fn peers(&self) -> Vec<PeerId> {
        self.shared.peers.lock().keys().copied().collect()
    }

    /// Sends `msg` to `peer` and waits for its response.
    pub async fn request(
        &self,
        peer: PeerId,
        msg: Snap1Message,
    ) -> Result<Snap1Message, TransportError> {
        let id = request_id(&msg).ok_or(TransportError::Unexpected)?;
        let tx =
            self.shared.peers.lock().get(&peer).cloned().ok_or(TransportError::Disconnected)?;
        let (reply, rx) = oneshot::channel();
        tx.send(Outbound { id, msg, reply }).map_err(|_| TransportError::Disconnected)?;
        rx.await.map_err(|_| TransportError::Disconnected)
    }
}

impl ProtocolHandler for Snap1Client {
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

impl ConnectionHandler for Snap1Client {
    type Connection = ClientConnection<ProtocolConnection>;

    fn protocol(&self) -> Protocol {
        snap1_protocol()
    }

    fn inbound_limits(&self) -> ProtocolIngressLimits {
        ProtocolIngressLimits::new(MAX_FRAME_BYTES)
            .with_max_buffered_bytes(2 * MAX_FRAME_BYTES)
            .with_max_buffered_messages(2 * MAX_PENDING)
    }

    /// Keeps the eth session, which still serves heads. A discovered peer without `snap/1` fails
    /// the keep rule and the audit drops it; a static one is kept and can serve no state.
    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        peer_id: PeerId,
    ) -> OnNotSupported {
        if self.statics.contains(&peer_id) {
            tracing::warn!(
                peer = %peer_id,
                "static peer does not offer snap/1, so it serves no state; a pulse-reth peer needs --pulsechain.snap1"
            );
        }
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        _direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        self.connection(peer_id, conn)
    }
}

/// One peer's connection: yields the frames to send, reads and matches the responses.
#[derive(Debug)]
pub struct ClientConnection<S> {
    inbound: S,
    shared: Arc<Shared>,
    peer: PeerId,
    /// This connection's entry in `shared`, weak so it does not keep `rx` open.
    tx: mpsc::WeakUnboundedSender<Outbound>,
    rx: mpsc::UnboundedReceiver<Outbound>,
    pending: HashMap<u64, oneshot::Sender<Snap1Message>>,
    /// The probe until the peer answers it or any other request; `None` after that, or with no
    /// probe.
    probe: Option<Probe>,
}

impl<S> ClientConnection<S> {
    fn new(shared: Arc<Shared>, peer: PeerId, inbound: S) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let weak = tx.downgrade();
        shared.peers.lock().insert(peer, tx);
        Self { inbound, shared, peer, tx: weak, rx, pending: HashMap::new(), probe: None }
    }

    /// Sends the probe first. Without an answer within `timeout` of the send the connection
    /// ends, unless `keep` (a static peer).
    fn with_probe(mut self, timeout: Duration, keep: bool) -> Self {
        self.probe = Some(Probe::Due { timeout, keep });
        self
    }
}

impl<S> Drop for ClientConnection<S> {
    fn drop(&mut self) {
        // A newer connection of the same peer may own the entry already; leave it in place.
        let mut peers = self.shared.peers.lock();
        if peers
            .get(&self.peer)
            .is_some_and(|tx| self.tx.upgrade().is_some_and(|own| own.same_channel(tx)))
        {
            peers.remove(&self.peer);
        }
    }
}

impl<S: Stream<Item = BytesMut> + Unpin> Stream for ClientConnection<S> {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<BytesMut>> {
        let this = self.get_mut();
        // Read what the peer sent first, so a response is matched before the next request.
        loop {
            match this.inbound.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(frame)) => {
                    if is_request_frame(&frame) {
                        continue;
                    }
                    // No answer this client asks for holds that many items: it is not a peer to
                    // keep, whether or not the response was asked for.
                    if !fits_item_budget(&frame) {
                        return Poll::Ready(None);
                    }
                    let Ok(msg) = Snap1Message::decode(&frame) else { return Poll::Ready(None) };
                    if let Some(id) = response_id(&msg) {
                        // An answer of any content to the probe, or to a request, passes it.
                        if id == PROBE_ID {
                            this.probe = None;
                        }
                        // An unsolicited or late response is dropped, not an offence.
                        if let Some(reply) = this.pending.remove(&id) {
                            this.probe = None;
                            let _ = reply.send(msg);
                        }
                    }
                }
            }
        }
        if let Some(Probe::Out { deadline, keep }) = &mut this.probe &&
            deadline.as_mut().poll(cx).is_ready()
        {
            if !*keep {
                tracing::debug!(peer = %this.peer, "dropping a peer that did not answer the snap/1 probe");
                return Poll::Ready(None);
            }
            tracing::warn!(
                peer = %this.peer,
                "static peer did not answer the snap/1 probe; kept, but it may serve no state"
            );
            this.probe = None;
        }
        if let Some(Probe::Due { timeout, keep }) = this.probe {
            this.probe = None;
            if let Ok(bytes) = probe_request().encode() {
                let deadline = Box::pin(tokio::time::sleep(timeout));
                this.probe = Some(Probe::Out { deadline, keep });
                return Poll::Ready(Some(BytesMut::from(bytes.as_ref())));
            }
        }
        // Forget requests whose waiter gave up. `poll_closed` also wakes this task when a live
        // waiter gives up later, which is what frees a slot while `rx` is not polled.
        this.pending.retain(|_, r| r.poll_closed(cx).is_pending());
        while this.pending.len() < MAX_PENDING {
            let Poll::Ready(Some(out)) = this.rx.poll_recv(cx) else { break };
            // A request that timed out or lost its hedge while queued is not sent.
            if out.reply.is_closed() {
                continue;
            }
            // A request that does not encode is dropped, which fails its waiter.
            if let Ok(bytes) = out.msg.encode() {
                this.pending.insert(out.id, out.reply);
                return Poll::Ready(Some(BytesMut::from(bytes.as_ref())));
            }
        }
        Poll::Pending
    }
}

/// Loads the node key from `path`, or creates and saves one when no file is there. A file that
/// cannot be read or does not parse is an error and is left alone; the error never shows the
/// file's contents.
pub fn load_or_create_node_key(
    path: &std::path::Path,
) -> std::io::Result<reth_network::config::SecretKey> {
    use reth_network::config::{rng_secret_key, SecretKey};
    use std::io::{Error, ErrorKind};
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let key = rng_secret_key();
            write_private(path, alloy_primitives::hex::encode(key.to_secret_bytes()).as_bytes())?;
            return Ok(key);
        }
        Err(e) => {
            return Err(Error::new(
                e.kind(),
                format!("cannot read node key file {}: {e}", path.display()),
            ))
        }
    };
    let key = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| alloy_primitives::hex::decode(text.trim()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| SecretKey::from_secret_bytes(b).ok())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!(
                    "node key file {} does not hold a hex secret key; move it aside to create a new key",
                    path.display()
                ),
            )
        })?;
    tighten_key_file(path);
    Ok(key)
}

/// Creates `dir` (and parents) readable by the owner only where the platform has modes.
pub(crate) fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes `contents` to `path` owner-only: a temp file in the same directory, created with
/// `create_new` and mode 0600, renamed over the target.
pub(crate) fn write_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        create_private_dir(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let _ = std::fs::remove_file(&tmp);
    let mut f = opts.open(&tmp)?;
    let res = f.write_all(contents).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = res.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Tightens a key file that is group- or world-accessible to 0600. Never logs the key.
#[cfg(unix)]
fn tighten_key_file(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else { return };
    if meta.permissions().mode() & 0o077 != 0 {
        tracing::warn!(path = %path.display(), "node key file was group- or world-accessible; setting mode 0600");
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(not(unix))]
fn tighten_key_file(_path: &std::path::Path) {}

/// Incoming eth requests that may wait for their empty answer; past that the network drops
/// them. reth's own node uses the same bound.
const ETH_REQUEST_QUEUE: usize = 256;

/// How often connected peers are checked against the keep rule.
const AUDIT_EVERY: Duration = Duration::from_secs(1);

/// What the network is started with.
#[derive(Debug, Clone)]
pub struct NetOptions {
    /// Chain id: 369 or 943 (anything else is the testnet).
    pub chain_id: u64,
    /// The node key.
    pub key: reth_network::config::SecretKey,
    /// Static `--peer` nodes: always kept, tried first.
    pub statics: Vec<NodeRecord>,
    /// Whether discv4 and DNS discovery run and non-static peers are accepted.
    pub discovery: bool,
    /// Most discovered peers kept connected, plus one per static peer that is not connected.
    pub max_peers: usize,
    /// Boot nodes; `None` is the chain's own list from the `PulseChain` chain spec.
    pub bootnodes: Option<Vec<NodeRecord>>,
    /// Most inbound connections: 0 in a real run, since this node serves nothing.
    pub max_inbound: usize,
    /// Discovery lookup and ping interval; `None` keeps reth's defaults. Tests shorten it.
    pub discovery_interval: Option<Duration>,
    /// Whether the chain's `enrtree://` DNS list is used (needs network access).
    pub dns: bool,
    /// How long the network refuses a banned discovered peer: [`BAN_FOR`] in a real run.
    pub ban_for: Duration,
    /// How long a new peer has to answer the `snap/1` probe: [`PROBE_TIMEOUT`] in a real run;
    /// `None` sends no probe.
    pub snap_probe: Option<Duration>,
}

impl NetOptions {
    /// The options a `reth-lite` run has for `cfg`, with the node `key`.
    pub fn from_config(
        cfg: &crate::config::LiteConfig,
        key: reth_network::config::SecretKey,
    ) -> Self {
        Self {
            chain_id: cfg.chain_id,
            key,
            statics: cfg.peers.clone(),
            discovery: cfg.discovery,
            max_peers: cfg.max_peers,
            bootnodes: None,
            max_inbound: 0,
            discovery_interval: None,
            dns: true,
            ban_for: BAN_FOR,
            snap_probe: Some(PROBE_TIMEOUT),
        }
    }
}

/// The running network: the manager task's handle plus the `snap/1` client.
#[derive(Clone)]
pub struct LiteNetwork {
    handle: NetworkHandle<EthNetworkPrimitives>,
    snap: Snap1Client,
    statics: Arc<HashSet<PeerId>>,
    /// Discovered peers that passed the keep rule.
    admitted: Arc<Mutex<HashSet<PeerId>>>,
}

impl std::fmt::Debug for LiteNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteNetwork").field("snap", &self.snap).finish_non_exhaustive()
    }
}

impl LiteNetwork {
    /// Wraps a started network.
    pub fn new(
        handle: NetworkHandle<EthNetworkPrimitives>,
        snap: Snap1Client,
        statics: HashSet<PeerId>,
    ) -> Self {
        Self {
            handle,
            snap,
            statics: Arc::new(statics),
            admitted: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Usable peers by kind: `(static, discovered)`, the `lite_peers{kind}` gauges.
    pub fn peer_counts(&self) -> (usize, usize) {
        let usable = self.peers();
        let statics = usable.iter().filter(|p| self.statics.contains(*p)).count();
        (statics, usable.len() - statics)
    }

    /// The node's own record (ports are the bound ones).
    pub fn local_record(&self) -> NodeRecord {
        self.handle.local_node_record()
    }

    /// Dials `node` as a normal (non-static) peer.
    pub fn connect(&self, node: NodeRecord) {
        // `add_peer` would add it as a reth static peer, which reth bans more leniently.
        self.handle.add_peer_kind(node.id, Some(PeerKind::Basic), node.tcp_addr(), None);
    }

    /// Checks every connected non-static peer once: keeps the ones that pass, drops and bans the
    /// rest, and returns how many are kept.
    pub async fn audit(&self, expect: &Expect) -> usize {
        let Ok(all) = self.handle.get_all_peers().await else { return 0 };
        let mut keep = HashSet::new();
        for info in &all {
            if self.statics.contains(&info.remote_id) {
                continue;
            }
            match admit_peer(expect, info) {
                Ok(()) => {
                    keep.insert(info.remote_id);
                }
                Err(why) => {
                    tracing::debug!(peer = %info.remote_id, %why, "dropping a peer that does not fit");
                    self.ban_discovered(info.remote_id);
                }
            }
        }
        let n = keep.len();
        *self.admitted.lock() = keep;
        n
    }

    /// Drops `peer` and refuses it for the configured ban time. `ban_peer` would be the admin
    /// ban, which never ends; the bad-protocol reputation ban carries the configured deadline.
    /// The session is also dropped directly: reth ignores a reputation change for a peer it does
    /// not track. The peer book's own ban keeps the peer from being asked again either way.
    fn ban_discovered(&self, peer: PeerId) {
        self.handle.reputation_change(peer, ReputationChangeKind::BadProtocol);
        self.handle.disconnect_peer(peer);
    }

    /// Starts the network for `cfg`, loading or creating the node key under its data directory.
    pub async fn start(
        cfg: &crate::config::LiteConfig,
        runtime: reth_tasks::Runtime,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key = load_or_create_node_key(&cfg.datadir.join("nodekey"))?;
        Self::start_with(NetOptions::from_config(cfg, key), runtime).await
    }

    /// Starts the network manager for `opts` over a no-op provider and spawns it.
    ///
    /// With discovery off the node talks to the static `--peer`s only. With discovery on it also
    /// finds peers through discv4 (and DNS) from the `PulseChain` boot nodes; only peers that pass
    /// [`admit`] are used, at most `max_peers` of them. discv5 is not used: the `PulseChain` boot
    /// node lists are discv4 only.
    pub async fn start_with(
        opts: NetOptions,
        runtime: reth_tasks::Runtime,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use reth_chainspec::{EthChainSpec, Hardforks};
        use reth_eth_wire::HelloMessageWithProtocols;
        use reth_eth_wire_types::EthVersion;
        use reth_network::{NetworkConfig, NetworkManager, PeersConfig};
        use reth_pulsechain_forks::chainspec as spec;

        let mainnet = opts.chain_id == spec::PULSECHAIN_MAINNET_CHAIN_ID;
        let chain =
            if mainnet { spec::PULSECHAIN.clone() } else { spec::PULSECHAIN_TESTNET_V4.clone() };
        // Present the chain's current fork id: a stale head would advertise the genesis one.
        let head = Head {
            number: u64::MAX,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            ..Default::default()
        };
        let expect = Expect { genesis: chain.genesis_hash(), fork_filter: chain.fork_filter(head) };

        let statics: HashSet<PeerId> = opts.statics.iter().map(|n| n.id).collect();
        let trusted: Vec<reth_network_peers::TrustedPeer> =
            opts.statics.iter().map(|n| (*n).into()).collect();
        let snap = Snap1Client::new(statics.clone(), opts.snap_probe);
        let builder = NetworkConfig::<(), EthNetworkPrimitives>::builder(opts.key, runtime.clone());
        // Only eth/68 is offered, so a peer that negotiates anything else never connects.
        let hello = HelloMessageWithProtocols::builder(builder.get_peer_id())
            .protocol(EthVersion::Eth68)
            .build();
        // reth counts a session with a trusted (static) peer as outbound, so the static peers get
        // their own slots on top of the discovered ones. reth fills any free slot, so while a
        // static peer is down a discovered one can take its slot. The audit does not cap that:
        // it would end the session each second and reth would dial another peer for the slot.
        let max_outbound = opts.max_peers + opts.statics.len();
        let peers_config = PeersConfig::default()
            .with_trusted_nodes(trusted)
            .with_trusted_nodes_only(!opts.discovery)
            .with_max_outbound(max_outbound)
            // This node serves nothing and is not meant to be dialed.
            .with_max_inbound(opts.max_inbound)
            .with_ban_duration(opts.ban_for)
            .with_max_concurrent_dials(max_outbound.max(1));
        let mut builder = builder
            .hello_message(hello)
            .set_head(head)
            .disable_nat()
            .listener_port(0)
            .peer_config(peers_config)
            .add_rlpx_sub_protocol(snap.clone());
        if opts.discovery {
            let boot = opts.bootnodes.unwrap_or_else(|| {
                if mainnet {
                    spec::pulsechain_nodes()
                } else {
                    spec::pulsechain_testnet_v4_nodes()
                }
            });
            builder = builder.discovery_port(0).boot_nodes(boot);
            if let Some(every) = opts.discovery_interval {
                let mut d = reth_discv4::Discv4ConfigBuilder::default();
                d.lookup_interval(every).ping_interval(every);
                builder = builder.discovery(d);
            }
            if !opts.dns {
                builder = builder.disable_dns_discovery();
            }
        } else {
            builder = builder.disable_discovery();
        }
        let mut net_cfg = builder.build_with_noop_provider(chain);
        if opts.discovery && opts.dns {
            let link = if mainnet {
                spec::PULSECHAIN_DNS_NETWORK
            } else {
                spec::PULSECHAIN_TESTNET_V4_DNS_NETWORK
            };
            if let Some(dns) = net_cfg.dns_discovery_config.as_mut() {
                dns.bootstrap_dns_networks
                    .get_or_insert_with(Default::default)
                    .insert(link.parse().map_err(|_| "bad DNS link entry")?);
            }
        }
        // Peers ask any node for headers, bodies and receipts. reth's handler over the no-op
        // provider answers each at once with an empty list, as reth does for blocks it does not
        // hold; a request with no answer at all gets this node banned for a protocol breach.
        let (eth_tx, eth_rx) = mpsc::channel(ETH_REQUEST_QUEUE);
        let eth_requests =
            reth_network::eth_requests::EthRequestHandler::new(net_cfg.client.clone(), eth_rx);
        let mut manager = NetworkManager::new(net_cfg).await?;
        manager.set_eth_request_handler(eth_tx);
        let handle = manager.handle().clone();
        runtime.spawn_task(manager);
        runtime.spawn_task(eth_requests);
        let net = Self::new(handle, snap, statics);
        if opts.discovery {
            let audit = net.clone();
            runtime.spawn_task(async move {
                loop {
                    audit.audit(&expect).await;
                    tokio::time::sleep(AUDIT_EVERY).await;
                }
            });
        }
        Ok(net)
    }
}

impl LiteNetwork {
    /// One header from `peer`, by hash or number.
    async fn header(&self, peer: PeerId, start: BlockHashOrNumber) -> Option<Header> {
        let (tx, rx) = oneshot::channel();
        self.handle.send_request(
            peer,
            PeerRequest::GetBlockHeaders {
                request: GetBlockHeaders {
                    start_block: start,
                    limit: 1,
                    skip: 0,
                    direction: HeadersDirection::Rising,
                },
                response: tx,
            },
        );
        let reply = tokio::time::timeout(Duration::from_secs(4), rx).await.ok()?.ok()?.ok()?;
        reply.0.into_iter().next()
    }
}

#[async_trait]
impl HeadConfirm for LiteNetwork {
    /// Each static peer's canonical header at `number`, by number origin, in a fixed order. The
    /// peers are asked at once.
    async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>> {
        let peers = self.sorted_statics();
        futures::future::join_all(peers.into_iter().map(|peer| async move {
            let h = self.header(peer, number.into()).await.filter(|h| h.number == number);
            h.map(|h| PeerHeader { hash: h.hash_slow(), parent_hash: h.parent_hash })
        }))
        .await
    }

    fn peer_name(&self, index: usize) -> String {
        self.sorted_statics().get(index).map_or_else(|| format!("#{index}"), |p| format!("{p}"))
    }
}

impl LiteNetwork {
    fn sorted_statics(&self) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = self.statics.iter().copied().collect();
        peers.sort_unstable();
        peers
    }
}

#[async_trait]
impl Transport for LiteNetwork {
    fn peers(&self) -> Vec<PeerId> {
        let admitted = self.admitted.lock();
        self.snap
            .peers()
            .into_iter()
            .filter(|p| self.statics.contains(p) || admitted.contains(p))
            .collect()
    }

    fn is_static(&self, peer: &PeerId) -> bool {
        self.statics.contains(peer)
    }

    fn ban(&self, peer: PeerId) {
        if self.statics.contains(&peer) {
            // The operator's node: drop the session; the peer book ignores it for a while.
            self.handle.disconnect_peer(peer);
        } else {
            self.ban_discovered(peer);
        }
    }

    fn drop_peer(&self, peer: PeerId) {
        // A local disconnect backs the peer off briefly, and reth fills the slot meanwhile.
        self.handle.disconnect_peer(peer);
    }

    async fn snap(&self, peer: PeerId, msg: Snap1Message) -> Result<Snap1Message, TransportError> {
        self.snap.request(peer, msg).await
    }

    async fn receipts(
        &self,
        peer: PeerId,
        block_hash: B256,
    ) -> Result<Option<Vec<WireReceipt>>, TransportError> {
        let (tx, rx) = oneshot::channel();
        self.handle.send_request(
            peer,
            PeerRequest::GetReceipts { request: GetReceipts(vec![block_hash]), response: tx },
        );
        let reply = tokio::time::timeout(Duration::from_secs(4), rx)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Disconnected)?
            .map_err(|_| TransportError::Disconnected)?;
        Ok(reply.0.into_iter().next())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{serve_snap, world, Acct};
    use alloy_primitives::{address, keccak256};
    use futures::channel::mpsc as fmpsc;
    use reth_eth_wire_types::snap::{GetAccountRangeMessage, SnapProtocolMessage as M};
    use reth_pulsechain_snap::Snap1Message as S;

    const A: alloy_primitives::Address = address!("00000000000000000000000000000000000a0001");

    fn req(id: u64, root: B256) -> S {
        let h = keccak256(A);
        S::Shared(M::GetAccountRange(GetAccountRangeMessage {
            request_id: id,
            root_hash: root,
            starting_hash: h,
            limit_hash: h,
            response_bytes: 1,
        }))
    }

    /// Drives a [`ClientConnection`] in the background: frames it yields are answered by `serve`.
    fn run(
        client: &Snap1Client,
        peer: PeerId,
        serve: impl Fn(S) -> Option<S> + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
        let mut conn = ClientConnection::new(client.shared.clone(), peer, inbound);
        tokio::spawn(async move {
            while let Some(frame) = conn.next().await {
                let msg = S::decode(&frame).unwrap();
                if let Some(resp) = serve(msg) {
                    to_conn
                        .unbounded_send(BytesMut::from(resp.encode().unwrap().as_ref()))
                        .unwrap();
                }
            }
        })
    }

    #[test]
    fn an_old_connection_closing_leaves_the_new_one_in_place() {
        let client = Snap1Client::default();
        let peer = PeerId::repeat_byte(1);
        let inbound = || futures::stream::pending::<BytesMut>();
        let old = ClientConnection::new(client.shared.clone(), peer, inbound());
        let new = ClientConnection::new(client.shared.clone(), peer, inbound());
        drop(old);
        assert_eq!(client.peers(), vec![peer]);
        drop(new);
        assert!(client.peers().is_empty());
    }

    #[tokio::test]
    async fn requests_are_matched_to_responses_by_id() {
        let w = std::sync::Arc::new(world(&[(A, Acct { balance: 9, ..Default::default() })]));
        let client = Snap1Client::default();
        let peer = PeerId::repeat_byte(1);
        let ww = w.clone();
        let _task = run(&client, peer, move |m| Some(serve_snap(&ww, m)));
        assert_eq!(client.peers(), vec![peer]);
        // Two concurrent requests get their own answers.
        let (a, b) = tokio::join!(
            client.request(peer, req(7, w.root)),
            client.request(peer, req(8, w.root))
        );
        assert_eq!(response_id(&a.unwrap()), Some(7));
        assert_eq!(response_id(&b.unwrap()), Some(8));
    }

    #[tokio::test]
    async fn a_garbage_frame_ends_the_connection_and_removes_the_peer() {
        let client = Snap1Client::default();
        let peer = PeerId::repeat_byte(2);
        let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
        let mut conn = ClientConnection::new(client.shared.clone(), peer, inbound);
        to_conn.unbounded_send(BytesMut::from(&[0xff, 0x01][..])).unwrap();
        assert!(conn.next().await.is_none());
        drop(conn);
        assert!(client.peers().is_empty());
        assert_eq!(
            client.request(peer, req(1, B256::ZERO)).await.unwrap_err(),
            TransportError::Disconnected
        );
    }

    #[tokio::test]
    async fn an_unanswered_request_ends_when_the_peer_goes() {
        let client = Snap1Client::default();
        let peer = PeerId::repeat_byte(3);
        let task = run(&client, peer, |_| None);
        let c = client.clone();
        let pending = tokio::spawn(async move { c.request(peer, req(1, B256::ZERO)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let _ = task.await;
        assert_eq!(pending.await.unwrap().unwrap_err(), TransportError::Disconnected);
    }

    #[tokio::test]
    async fn responses_and_requests_from_a_peer_without_a_waiter_are_ignored() {
        let client = Snap1Client::default();
        let peer = PeerId::repeat_byte(4);
        let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
        let mut conn = ClientConnection::new(client.shared.clone(), peer, inbound);
        // A late response with no waiter, and a request (we serve nothing).
        let stray =
            S::TrieNodes(reth_pulsechain_snap::TrieNodesMessage { request_id: 99, nodes: vec![] });
        to_conn.unbounded_send(BytesMut::from(stray.encode().unwrap().as_ref())).unwrap();
        to_conn
            .unbounded_send(BytesMut::from(req(5, B256::ZERO).encode().unwrap().as_ref()))
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), conn.next()).await.is_err());
        assert_eq!(client.peers(), vec![peer]);
    }

    type Waiter = oneshot::Receiver<Snap1Message>;

    /// A connection whose `pending` map is full, with the waiters' receivers, and one request
    /// queued behind them with its receiver.
    fn full_connection(
        client: &Snap1Client,
        peer: PeerId,
    ) -> (
        ClientConnection<fmpsc::UnboundedReceiver<BytesMut>>,
        fmpsc::UnboundedSender<BytesMut>,
        Vec<Waiter>,
        Waiter,
    ) {
        let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
        let mut conn = ClientConnection::new(client.shared.clone(), peer, inbound);
        let mut waiters = Vec::new();
        for id in 0..MAX_PENDING as u64 {
            let (reply, rx) = oneshot::channel();
            conn.pending.insert(id, reply);
            waiters.push(rx);
        }
        let (reply, queued) = oneshot::channel();
        let tx = client.shared.peers.lock()[&peer].clone();
        tx.send(Outbound { id: 1000, msg: req(1000, B256::ZERO), reply }).unwrap();
        (conn, to_conn, waiters, queued)
    }

    /// A waker that counts its wakes.
    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);

    impl futures::task::ArcWake for Wakes {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Wakes {
        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn poll_once<S: Stream<Item = BytesMut> + Unpin>(
        conn: &mut ClientConnection<S>,
        wakes: &Arc<Wakes>,
    ) -> Poll<Option<BytesMut>> {
        let waker = futures::task::waker(wakes.clone());
        conn.poll_next_unpin(&mut Context::from_waker(&waker))
    }

    fn sent_id(frame: Poll<Option<BytesMut>>) -> Option<u64> {
        let Poll::Ready(Some(frame)) = frame else { panic!("nothing sent: {frame:?}") };
        request_id(&S::decode(&frame).unwrap())
    }

    /// A connection with a waiter for request `id`, and the waiter's receiver.
    fn waiting_connection(
        id: u64,
    ) -> (
        ClientConnection<fmpsc::UnboundedReceiver<BytesMut>>,
        fmpsc::UnboundedSender<BytesMut>,
        Waiter,
    ) {
        let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
        let mut conn =
            ClientConnection::new(Snap1Client::default().shared, PeerId::repeat_byte(8), inbound);
        let (reply, rx) = oneshot::channel();
        conn.pending.insert(id, reply);
        (conn, to_conn, rx)
    }

    fn codes_reply(id: u64, codes: usize) -> BytesMut {
        let msg = S::Shared(M::ByteCodes(reth_eth_wire_types::snap::ByteCodesMessage {
            request_id: id,
            codes: vec![alloy_primitives::Bytes::new(); codes],
        }));
        BytesMut::from(msg.encode().unwrap().as_ref())
    }

    #[test]
    fn a_reply_with_more_items_than_any_answer_ends_the_connection_before_it_is_decoded() {
        // One byte on the wire per empty code, 32 bytes each once decoded.
        let frame = codes_reply(1, 1 << 20);
        assert!(frame.len() <= MAX_FRAME_BYTES, "{}", frame.len());
        for pending in [true, false] {
            let (mut conn, to_conn, mut rx) = waiting_connection(if pending { 1 } else { 2 });
            to_conn.unbounded_send(frame.clone()).unwrap();
            assert!(matches!(poll_once(&mut conn, &Arc::default()), Poll::Ready(None)));
            drop(conn);
            assert_eq!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed));
        }
    }

    /// A request from the peer is dropped by its id byte, before any decode: a body that would
    /// not decode does not end the connection, and an answer after it still reaches its waiter.
    #[test]
    fn a_request_frame_from_a_peer_is_dropped_unread() {
        use reth_eth_wire_types::snap::SnapMessageId as Id;
        let requests = [
            Id::GetAccountRange as u8,
            Id::GetStorageRanges as u8,
            Id::GetByteCodes as u8,
            GET_TRIE_NODES,
        ];
        for id in requests {
            let (mut conn, to_conn, mut rx) = waiting_connection(1);
            to_conn.unbounded_send(BytesMut::from(&[id, 0xff, 0xff][..])).unwrap();
            assert!(poll_once(&mut conn, &Arc::default()).is_pending(), "id {id}");
            to_conn.unbounded_send(codes_reply(1, 0)).unwrap();
            assert!(poll_once(&mut conn, &Arc::default()).is_pending(), "id {id}");
            assert!(rx.try_recv().is_ok(), "id {id}");
        }
    }

    #[test]
    fn a_reply_at_the_item_budget_reaches_its_waiter() {
        // Storage slots carry no per-list cap of their own, so only the budget applies: three
        // accounts of 1363 slots fill it exactly (4 + 3 + 3 * 1363 = 4096).
        let (msg, items) = response_of(3, &[454, 454, 455], 0);
        assert_eq!(items, MAX_RESPONSE_ITEMS);
        let (mut conn, to_conn, mut rx) = waiting_connection(1);
        to_conn.unbounded_send(BytesMut::from(msg.encode().unwrap().as_ref())).unwrap();
        assert!(poll_once(&mut conn, &Arc::default()).is_pending());
        assert_eq!(rx.try_recv().unwrap(), msg);
        // One more slot is over.
        let (msg, items) = response_of(3, &[454, 454, 456], 0);
        assert!(items > MAX_RESPONSE_ITEMS);
        let (mut conn, to_conn, _rx) = waiting_connection(1);
        to_conn.unbounded_send(BytesMut::from(msg.encode().unwrap().as_ref())).unwrap();
        assert!(matches!(poll_once(&mut conn, &Arc::default()), Poll::Ready(None)));
    }

    /// A response of each kind and the items its lists hold, counted from its shape: the message
    /// list with its id and list fields, plus each entry with the lists inside it.
    fn response_of(kind: usize, sizes: &[usize], proof: usize) -> (S, usize) {
        use reth_eth_wire_types::snap::{AccountData, AccountRangeMessage, StorageData};
        let bytes = |n: usize| vec![alloy_primitives::Bytes::new(); n];
        let n = sizes[0];
        match kind {
            0 => {
                let r =
                    reth_eth_wire_types::snap::ByteCodesMessage { request_id: 1, codes: bytes(n) };
                (S::Shared(M::ByteCodes(r)), 3 + n)
            }
            1 => (
                S::TrieNodes(reth_pulsechain_snap::TrieNodesMessage {
                    request_id: 1,
                    nodes: bytes(n),
                }),
                3 + n,
            ),
            2 => {
                // An account is a list of its hash and its body, a list of four fields.
                let account = AccountData::from_trie_account(B256::ZERO, &Default::default());
                let r = AccountRangeMessage {
                    request_id: 1,
                    accounts: vec![account; n],
                    proof: bytes(proof),
                };
                (S::Shared(M::AccountRange(r)), 4 + 7 * n + proof)
            }
            _ => {
                // One list per account, and a slot is a list of its hash and its value.
                let slot = StorageData { hash: B256::ZERO, data: Default::default() };
                let slots: Vec<Vec<StorageData>> =
                    sizes.iter().map(|k| vec![slot.clone(); *k]).collect();
                let items = 4 + sizes.iter().map(|k| 1 + 3 * k).sum::<usize>() + proof;
                let r = reth_eth_wire_types::snap::StorageRangesMessage {
                    request_id: 1,
                    slots,
                    proof: bytes(proof),
                };
                (S::Shared(M::StorageRanges(r)), items)
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// A response of any kind reaches its waiter while its lists hold at most
        /// MAX_RESPONSE_ITEMS items and each list fits its snap/1 cap, and ends the connection
        /// past that, however deep the items sit.
        #[test]
        fn a_response_of_any_kind_is_delivered_only_within_the_item_budget(
            kind in 0..4usize,
            sizes in proptest::collection::vec(
                proptest::prop_oneof![0..2 * MAX_RESPONSE_ITEMS, MAX_RESPONSE_ITEMS - 8..MAX_RESPONSE_ITEMS],
                1..4,
            ),
            proof in 0..200usize,
        ) {
            // Deep kinds reach the budget with fewer entries: scale the sizes to straddle it.
            let sizes: Vec<usize> = match kind {
                2 => sizes.iter().map(|n| n / 7).collect(),
                3 => sizes.iter().map(|n| n / (3 * sizes.len())).collect(),
                _ => sizes,
            };
            let (msg, items) = response_of(kind, &sizes, proof);
            let (mut conn, to_conn, mut rx) = waiting_connection(1);
            to_conn.unbounded_send(BytesMut::from(msg.encode().unwrap().as_ref())).unwrap();
            let polled = poll_once(&mut conn, &Arc::default());
            // The snap/1 decoder also caps single lists, as its server does.
            let n = sizes[0];
            let lists_fit = proof <= reth_pulsechain_snap::MAX_RANGE_PROOF_NODES &&
                match kind {
                    0 => n <= reth_pulsechain_snap::MAX_BYTE_CODES_SERVE,
                    1 => n <= reth_pulsechain_snap::MAX_TRIE_NODE_LOOKUPS,
                    _ => true,
                };
            if items <= MAX_RESPONSE_ITEMS && lists_fit {
                proptest::prop_assert!(polled.is_pending(), "{} items: {:?}", items, polled);
                proptest::prop_assert_eq!(rx.try_recv().unwrap(), msg);
            } else {
                proptest::prop_assert!(matches!(polled, Poll::Ready(None)), "{} items: {:?}", items, polled);
                drop(conn);
                proptest::prop_assert_eq!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed));
            }
        }
    }

    #[test]
    fn the_largest_answers_the_client_accepts_fit_the_item_budget() {
        use reth_eth_wire_types::snap::{
            AccountData, AccountRangeMessage, StorageData, StorageRangesMessage,
        };
        let proof = vec![alloy_primitives::Bytes::from(vec![0x80; 532]); 128];
        let account = AccountData::from_trie_account(B256::ZERO, &Default::default());
        let accounts = S::Shared(M::AccountRange(AccountRangeMessage {
            request_id: u64::MAX,
            accounts: vec![account; 16],
            proof: proof.clone(),
        }));
        let slot = StorageData { hash: B256::ZERO, data: vec![1u8; 32].into() };
        let storage = S::Shared(M::StorageRanges(StorageRangesMessage {
            request_id: u64::MAX,
            slots: vec![vec![slot; 16]],
            proof,
        }));
        for msg in [accounts, storage] {
            assert!(fits_item_budget(&msg.encode().unwrap()), "{msg:?}");
        }
        // Requests are not counted: this node ignores them.
        let hashes = vec![B256::ZERO; MAX_RESPONSE_ITEMS];
        let ask = S::Shared(M::GetByteCodes(reth_eth_wire_types::snap::GetByteCodesMessage {
            request_id: 1,
            hashes,
            response_bytes: 1,
        }));
        assert!(fits_item_budget(&ask.encode().unwrap()));
    }

    #[test]
    fn a_request_goes_out_once_given_up_waiters_free_the_pending_slots() {
        let client = Snap1Client::default();
        let (mut conn, _to_conn, waiters, _queued) =
            full_connection(&client, PeerId::repeat_byte(5));
        drop(waiters);
        assert_eq!(sent_id(poll_once(&mut conn, &Arc::default())), Some(1000));
    }

    #[test]
    fn a_waiter_giving_up_on_a_full_connection_wakes_it_to_send_the_next_request() {
        let client = Snap1Client::default();
        let (mut conn, _to_conn, mut waiters, _queued) =
            full_connection(&client, PeerId::repeat_byte(6));
        let wakes = Arc::new(Wakes::default());
        assert!(poll_once(&mut conn, &wakes).is_pending());
        assert_eq!(wakes.count(), 0);
        waiters.pop();
        assert_eq!(wakes.count(), 1, "a freed slot must wake the connection");
        assert_eq!(sent_id(poll_once(&mut conn, &wakes)), Some(1000));
    }

    #[test]
    fn a_queued_request_whose_waiter_gave_up_is_not_sent() {
        let client = Snap1Client::default();
        let peer = PeerId::repeat_byte(7);
        let mut conn =
            ClientConnection::new(client.shared.clone(), peer, futures::stream::pending());
        let tx = client.shared.peers.lock()[&peer].clone();
        let (reply, gave_up) = oneshot::channel();
        tx.send(Outbound { id: 1, msg: req(1, B256::ZERO), reply }).unwrap();
        let (reply, _live) = oneshot::channel();
        tx.send(Outbound { id: 2, msg: req(2, B256::ZERO), reply }).unwrap();
        drop(gave_up);
        assert_eq!(sent_id(poll_once(&mut conn, &Arc::default())), Some(2));
        assert_eq!(conn.pending.keys().copied().collect::<Vec<_>>(), vec![2]);
    }

    /// A connection of `client` to `peer`, driven in the background. Its frames come out of the
    /// receiver, decoded; frames into the sender reach it from the peer. The task ends with the
    /// connection.
    fn probed(
        client: &Snap1Client,
        peer: PeerId,
    ) -> (tokio::task::JoinHandle<()>, fmpsc::UnboundedSender<BytesMut>, mpsc::UnboundedReceiver<S>)
    {
        let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
        let mut conn = client.connection(peer, inbound);
        let (out, sent) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(frame) = conn.next().await {
                let _ = out.send(S::decode(&frame).unwrap());
            }
        });
        (task, to_conn, sent)
    }

    fn frame_of(msg: &S) -> BytesMut {
        BytesMut::from(msg.encode().unwrap().as_ref())
    }

    /// A discovered peer that never answers the probe loses its session when the probe times
    /// out, and not before. The probe asks for the code of a hash that no account has.
    #[tokio::test(start_paused = true)]
    async fn a_discovered_peer_that_never_answers_the_probe_is_dropped() {
        let client = Snap1Client::new(HashSet::new(), Some(PROBE_TIMEOUT));
        let peer = PeerId::repeat_byte(1);
        let (task, _to_conn, mut sent) = probed(&client, peer);
        tokio::time::sleep(PROBE_TIMEOUT - Duration::from_millis(1)).await;
        assert_eq!(client.peers(), vec![peer]);
        let ended = tokio::time::timeout(Duration::from_millis(2), task).await;
        assert!(ended.is_ok(), "a peer that never answered the probe was kept");
        assert!(client.peers().is_empty());
        let probe = sent.try_recv().unwrap();
        let S::Shared(M::GetByteCodes(r)) = &probe else { panic!("{probe:?}") };
        assert_eq!(r.hashes, vec![PROBE_HASH]);
        assert_eq!(sent.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
    }

    /// An honest peer answers the probe at once and keeps its session; its requests are served
    /// as before.
    #[tokio::test(start_paused = true)]
    async fn an_honest_peer_is_kept_after_the_probe() {
        let w = Arc::new(world(&[(A, Acct { balance: 9, ..Default::default() })]));
        let client = Snap1Client::new(HashSet::new(), Some(PROBE_TIMEOUT));
        let peer = PeerId::repeat_byte(2);
        let (task, to_conn, mut sent) = probed(&client, peer);
        let ww = w.clone();
        let _server = tokio::spawn(async move {
            while let Some(msg) = sent.recv().await {
                let _ = to_conn.unbounded_send(frame_of(&serve_snap(&ww, msg)));
            }
        });
        tokio::time::sleep(PROBE_TIMEOUT * 10).await;
        assert_eq!(client.peers(), vec![peer]);
        assert!(!task.is_finished());
        assert_eq!(response_id(&client.request(peer, req(7, w.root)).await.unwrap()), Some(7));
    }

    /// Any answer passes the probe: an empty one that lands just before the timeout, or the
    /// answer to another request of the peer's.
    #[tokio::test(start_paused = true)]
    async fn a_late_or_other_answer_passes_the_probe() {
        for answer_probe in [true, false] {
            let client = Snap1Client::new(HashSet::new(), Some(PROBE_TIMEOUT));
            let peer = PeerId::repeat_byte(3);
            let (task, to_conn, mut sent) = probed(&client, peer);
            let c = client.clone();
            let asked = tokio::spawn(async move { c.request(peer, req(5, B256::ZERO)).await });
            let first = tokio::time::timeout(PROBE_TIMEOUT, sent.recv()).await.unwrap().unwrap();
            let second = tokio::time::timeout(PROBE_TIMEOUT, sent.recv()).await.unwrap().unwrap();
            assert_eq!((request_id(&first), request_id(&second)), (Some(PROBE_ID), Some(5)));
            tokio::time::sleep(PROBE_TIMEOUT - Duration::from_millis(10)).await;
            let id = if answer_probe { PROBE_ID } else { 5 };
            to_conn.unbounded_send(codes_reply(id, 0)).unwrap();
            tokio::time::sleep(PROBE_TIMEOUT * 10).await;
            assert_eq!(client.peers(), vec![peer], "answer_probe={answer_probe}");
            assert!(!task.is_finished(), "answer_probe={answer_probe}");
            assert_eq!(asked.is_finished(), !answer_probe);
        }
    }

    /// A static peer that never answers the probe is kept, as the operator named it, and a
    /// warning names it.
    #[tokio::test(start_paused = true)]
    async fn a_static_peer_that_never_answers_the_probe_is_kept_with_a_warning() {
        let peer = PeerId::repeat_byte(4);
        let client = Snap1Client::new(HashSet::from([peer]), Some(PROBE_TIMEOUT));
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let (task, _to_conn, _sent) = probed(&client, peer);
        tokio::time::sleep(PROBE_TIMEOUT * 10).await;
        assert_eq!(client.peers(), vec![peer]);
        assert!(!task.is_finished());
        let text = logs.text();
        let warnings: Vec<&str> = text.lines().collect();
        assert_eq!(warnings.len(), 1, "{text}");
        assert!(warnings[0].contains(&format!("peer={peer}")), "{text}");
        assert!(warnings[0].contains("probe"), "{text}");
    }

    /// Over the network: a discovered peer that advertises `snap/1` and never answers (another
    /// lite node, which serves nothing) loses its session after the probe, so its slot is free.
    /// The same peer as a static peer keeps its session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_silent_snap_peer_loses_its_session_unless_it_is_static() {
        let rt = reth_tasks::Runtime::test();
        let b_opts = NetOptions { max_peers: 0, ..test_opts(369, vec![]) };
        let b = LiteNetwork::start_with(b_opts, rt.clone()).await.unwrap();
        let (b_id, b_rec) = (b.local_record().id, loopback(&b));
        let probing = NetOptions { snap_probe: Some(PROBE_TIMEOUT), ..test_opts(369, vec![]) };
        let a = LiteNetwork::start_with(probing.clone(), rt.clone()).await.unwrap();
        a.connect(b_rec);
        wait_for("A to keep B", || a.peers() == vec![b_id]).await;
        let kept = std::time::Instant::now();
        while !a.peers().is_empty() {
            assert!(kept.elapsed() <= PROBE_TIMEOUT + Duration::from_secs(2), "A kept B");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let statik = NetOptions { statics: vec![b_rec], discovery: false, ..probing };
        let a = LiteNetwork::start_with(statik, rt).await.unwrap();
        wait_for("A to connect to B", || a.peers() == vec![b_id]).await;
        tokio::time::sleep(PROBE_TIMEOUT + Duration::from_secs(2)).await;
        assert_eq!(a.peers(), vec![b_id], "a static peer was dropped");
    }

    fn test_opts(chain_id: u64, boot: Vec<NodeRecord>) -> NetOptions {
        NetOptions {
            chain_id,
            key: reth_network::config::rng_secret_key(),
            statics: Vec::new(),
            discovery: true,
            max_peers: 4,
            bootnodes: Some(boot),
            max_inbound: 4,
            discovery_interval: Some(Duration::from_millis(500)),
            dns: false,
            ban_for: BAN_FOR,
            snap_probe: None,
        }
    }

    /// `net`'s record as a peer on this machine would dial it.
    fn loopback(net: &LiteNetwork) -> NodeRecord {
        let mut r = net.local_record();
        r.address = std::net::Ipv4Addr::LOCALHOST.into();
        r
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..900 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// Two in-process nodes on loopback, no real network: B is the boot node, A finds B through
    /// discv4 and keeps it; a node on the other `PulseChain` network that boots from the same B is
    /// never kept by either side.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn discovery_finds_a_matching_peer_and_not_one_on_another_chain() {
        let rt = reth_tasks::Runtime::test();
        // B only accepts: if it dialed A as well the two dials would race and one is dropped.
        let b_opts = NetOptions { max_peers: 0, ..test_opts(369, vec![]) };
        let b = LiteNetwork::start_with(b_opts, rt.clone()).await.unwrap();
        let boot = vec![loopback(&b)];
        let a = LiteNetwork::start_with(test_opts(369, boot.clone()), rt.clone()).await.unwrap();
        let other = LiteNetwork::start_with(test_opts(943, boot), rt).await.unwrap();
        let b_id = b.local_record().id;
        wait_for("A to keep B", || a.peers() == vec![b_id]).await;
        assert_eq!(a.peer_counts(), (0, 1));
        // B keeps A too, and never keeps the other chain's node.
        let (a_id, other_id) = (a.local_record().id, other.local_record().id);
        wait_for("B to keep A", || b.peers().contains(&a_id)).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!b.peers().contains(&other_id));
        assert!(other.peers().is_empty());
    }

    #[test]
    fn snap_replies_are_capped_near_the_code_budget() {
        let limits = Snap1Client::default().inbound_limits();
        assert_eq!(limits.max_frame_bytes(), Some(MAX_FRAME_BYTES));
        // The largest honest reply: the whole code budget, passed by one maximal contract.
        let max_code = 24 * 1024;
        let codes = vec![
            alloy_primitives::Bytes::from(vec![0x60; max_code]);
            CODE_BYTES as usize / max_code + 1
        ];
        let msg = S::Shared(M::ByteCodes(reth_eth_wire_types::snap::ByteCodesMessage {
            request_id: u64::MAX,
            codes,
        }));
        let frame = msg.encode().unwrap();
        assert!(
            frame.len() > CODE_BYTES as usize && frame.len() <= MAX_FRAME_BYTES,
            "{}",
            frame.len()
        );
        assert!(fits_item_budget(&frame));
    }

    /// A banned discovered peer is refused for the ban time only, then may connect again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_network_ban_of_a_discovered_peer_ends() {
        let rt = reth_tasks::Runtime::test();
        let b_key = reth_network::config::rng_secret_key();
        let b_opts = NetOptions { key: b_key, max_peers: 0, ..test_opts(369, vec![]) };
        let b = LiteNetwork::start_with(b_opts, rt.clone()).await.unwrap();
        let a_opts = NetOptions { ban_for: Duration::from_secs(10), ..test_opts(369, vec![]) };
        let a = LiteNetwork::start_with(a_opts, rt.clone()).await.unwrap();
        let (b_id, b_rec) = (b.local_record().id, loopback(&b));
        a.connect(b_rec);
        wait_for("A to keep B", || a.peers() == vec![b_id]).await;
        Transport::ban(&a, b_id);
        wait_for("A to drop B", || a.peers().is_empty()).await;
        // A backs off its own dials to B after any disconnect; only the ban refuses B's dials.
        // A fresh node with B's key dials A at once, and without the ban A keeps it.
        let again =
            LiteNetwork::start_with(NetOptions { key: b_key, ..test_opts(369, vec![]) }, rt)
                .await
                .unwrap();
        again.connect(loopback(&a));
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(a.peers().is_empty(), "A kept B during the ban");
        }
        // Redial until the ban ends; an endless ban refuses every dial.
        wait_for("A to keep B again", || {
            a.connect(b_rec);
            a.peers() == vec![b_id]
        })
        .await;
    }

    /// A plain reth node on `PulseChain` mainnet: it passes the eth handshake but has no `snap/1`.
    /// `handler`, when given, gets its incoming eth requests.
    async fn eth_only_peer(
        rt: reth_tasks::Runtime,
        handler: Option<
            mpsc::Sender<reth_network::eth_requests::IncomingEthRequest<EthNetworkPrimitives>>,
        >,
    ) -> (NetworkHandle<EthNetworkPrimitives>, NodeRecord) {
        use reth_network::{NetworkConfig, NetworkManager};
        let head = Head {
            number: u64::MAX,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..Default::default()
        };
        let key = reth_network::config::rng_secret_key();
        let cfg = NetworkConfig::<(), EthNetworkPrimitives>::builder(key, rt.clone())
            .set_head(head)
            .disable_nat()
            .disable_discovery()
            .listener_port(0)
            .build_with_noop_provider(reth_pulsechain_forks::chainspec::PULSECHAIN.clone());
        let mut manager = NetworkManager::new(cfg).await.unwrap();
        if let Some(tx) = handler {
            manager.set_eth_request_handler(tx);
        }
        let handle = manager.handle().clone();
        rt.spawn_task(manager);
        let mut record = handle.local_node_record();
        record.address = std::net::Ipv4Addr::LOCALHOST.into();
        (handle, record)
    }

    /// A discovered peer that passes the eth handshake but not the keep rule (it has no `snap/1`)
    /// has its session ended by the audit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_audit_drops_a_discovered_peer_that_fails_the_keep_rule() {
        use reth_network_api::{events::PeerEvent, NetworkEvent, NetworkEventListenerProvider};
        let rt = reth_tasks::Runtime::test();
        let (b, b_rec) = eth_only_peer(rt.clone(), None).await;
        let mut events = b.event_listener();
        let a = LiteNetwork::start_with(test_opts(369, vec![]), rt).await.unwrap();
        let a_id = a.local_record().id;
        a.connect(b_rec);
        // B sees the session open, then end.
        let opened_then_closed = tokio::time::timeout(Duration::from_secs(15), async {
            let mut opened = false;
            while let Some(ev) = events.next().await {
                match ev {
                    NetworkEvent::ActivePeerSession { info, .. } |
                    NetworkEvent::Peer(PeerEvent::SessionEstablished(info))
                        if info.peer_id == a_id =>
                    {
                        opened = true
                    }
                    NetworkEvent::Peer(PeerEvent::SessionClosed { peer_id, .. })
                        if peer_id == a_id =>
                    {
                        return opened
                    }
                    _ => {}
                }
            }
            false
        })
        .await;
        assert_eq!(opened_then_closed, Ok(true), "A kept a peer without snap/1");
        assert!(a.peers().is_empty());
    }

    /// `Transport::receipts` over a real eth session: a block's receipts, an empty block list, a
    /// peer that is not connected, one that never answers, and one that leaves mid-request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn receipts_over_the_wire_map_each_outcome() {
        use reth_network::eth_requests::IncomingEthRequest;
        let rt = reth_tasks::Runtime::test();
        let receipt = WireReceipt {
            receipt: alloy_consensus::EthereumReceipt {
                tx_type: alloy_consensus::TxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![],
            },
            logs_bloom: Default::default(),
        };
        let (known, absent, silent) =
            (B256::with_last_byte(1), B256::with_last_byte(2), B256::with_last_byte(3));
        let (tx, mut rx) = mpsc::channel(16);
        let served = receipt.clone();
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let IncomingEthRequest::GetReceipts { request, response, .. } = req else {
                    continue
                };
                // Any other hash is never answered: the dropped sender sends nothing.
                let blocks = match request.0.first() {
                    Some(h) if *h == known => vec![vec![served.clone()]],
                    Some(h) if *h == absent => vec![],
                    _ => continue,
                };
                let _ = response.send(Ok(reth_eth_wire_types::Receipts(blocks)));
            }
        });
        let (b, b_rec) = eth_only_peer(rt.clone(), Some(tx)).await;
        let opts = NetOptions { statics: vec![b_rec], discovery: false, ..test_opts(369, vec![]) };
        let a = LiteNetwork::start_with(opts, rt).await.unwrap();
        wait_for("A to connect to B", || a.handle.num_connected_peers() == 1).await;
        assert_eq!(Transport::receipts(&a, b_rec.id, known).await, Ok(Some(vec![receipt])));
        assert_eq!(Transport::receipts(&a, b_rec.id, absent).await, Ok(None));
        assert_eq!(
            Transport::receipts(&a, PeerId::repeat_byte(9), known).await,
            Err(TransportError::Disconnected)
        );
        let start = std::time::Instant::now();
        assert_eq!(Transport::receipts(&a, b_rec.id, silent).await, Err(TransportError::Timeout));
        assert!(start.elapsed() >= Duration::from_secs(4), "{:?}", start.elapsed());
        let a_id = a.local_record().id;
        let leave = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            b.disconnect_peer(a_id);
        };
        let (res, ()) = tokio::join!(Transport::receipts(&a, b_rec.id, silent), leave);
        assert_eq!(res, Err(TransportError::Disconnected));
    }

    /// A reth peer that asks this node for headers, bodies or receipts gets an empty answer at
    /// once, as reth answers for blocks it does not hold. With no answer at all, a reth peer
    /// bans the node for a protocol breach once its request times out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eth_requests_from_a_peer_get_empty_answers() {
        let rt = reth_tasks::Runtime::test();
        let (b, b_rec) = eth_only_peer(rt.clone(), None).await;
        let opts = NetOptions { statics: vec![b_rec], discovery: false, ..test_opts(369, vec![]) };
        let a = LiteNetwork::start_with(opts, rt).await.unwrap();
        let a_id = a.local_record().id;
        wait_for("B to connect to A", || b.num_connected_peers() == 1).await;
        let answered = Duration::from_secs(5);

        let (tx, rx) = oneshot::channel();
        let request = GetBlockHeaders {
            start_block: 1u64.into(),
            limit: 1,
            skip: 0,
            direction: HeadersDirection::Rising,
        };
        b.send_request(a_id, PeerRequest::GetBlockHeaders { request, response: tx });
        let headers = tokio::time::timeout(answered, rx).await.expect("headers answered in time");
        assert_eq!(headers.unwrap().unwrap().0, Vec::<Header>::new());

        let (tx, rx) = oneshot::channel();
        let request = reth_eth_wire_types::GetBlockBodies(vec![B256::with_last_byte(1)]);
        b.send_request(a_id, PeerRequest::GetBlockBodies { request, response: tx });
        let bodies = tokio::time::timeout(answered, rx).await.expect("bodies answered in time");
        assert!(bodies.unwrap().unwrap().0.is_empty());

        let (tx, rx) = oneshot::channel();
        let request = GetReceipts(vec![B256::with_last_byte(1)]);
        b.send_request(a_id, PeerRequest::GetReceipts { request, response: tx });
        let receipts = tokio::time::timeout(answered, rx).await.expect("receipts answered in time");
        assert!(receipts.unwrap().unwrap().0.is_empty());
        assert_eq!(b.num_connected_peers(), 1, "the session stays up");
    }

    /// `max_peers` caps discovered peers only: a static peer does not take one of their slots.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_static_peer_does_not_take_a_discovered_peer_slot() {
        let rt = reth_tasks::Runtime::test();
        let accept_only = || NetOptions { max_peers: 0, ..test_opts(369, vec![]) };
        let s = LiteNetwork::start_with(accept_only(), rt.clone()).await.unwrap();
        let d = LiteNetwork::start_with(accept_only(), rt.clone()).await.unwrap();
        let (s_id, d_id) = (s.local_record().id, d.local_record().id);
        let opts =
            NetOptions { statics: vec![loopback(&s)], max_peers: 1, ..test_opts(369, vec![]) };
        let a = LiteNetwork::start_with(opts, rt).await.unwrap();
        wait_for("A to connect to its static peer", || a.peers() == vec![s_id]).await;
        let d_rec = loopback(&d);
        let mut kept = false;
        for _ in 0..150 {
            a.connect(d_rec);
            if a.peers().contains(&d_id) {
                kept = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(kept, "A never kept a discovered peer next to its static one");
        assert_eq!(a.peer_counts(), (1, 1));
    }

    /// A static peer that has no `snap/1` keeps its session, which serves heads, and a warning
    /// names the cause: no state read can reach it. A discovered one is left to the audit.
    #[test]
    fn a_static_peer_without_snap1_is_kept_with_a_warning() {
        use reth_eth_wire::{protocol::Protocol, Capability};
        use reth_eth_wire_types::EthVersion;
        let (statik, found) = (PeerId::repeat_byte(1), PeerId::repeat_byte(2));
        let client = Snap1Client::new(HashSet::from([statik]), None);
        let caps = SharedCapabilities::try_new(
            vec![Protocol::eth(EthVersion::Eth68)],
            vec![Capability::eth(EthVersion::Eth68)],
        )
        .unwrap();
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        for peer in [found, statik] {
            let kept =
                client.clone().on_unsupported_by_peer(&caps, Direction::Outgoing(peer), peer);
            assert!(matches!(kept, OnNotSupported::KeepAlive), "{peer}");
        }
        let text = logs.text();
        let warnings: Vec<&str> = text.lines().collect();
        assert_eq!(warnings.len(), 1, "{text}");
        assert!(warnings[0].contains(&format!("peer={statik}")), "{text}");
        assert!(warnings[0].contains("--pulsechain.snap1"), "{text}");
    }

    /// A peer dropped for giving no answers loses its session but is not banned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dropped_peer_is_disconnected_and_may_connect_again() {
        let rt = reth_tasks::Runtime::test();
        let b_opts = NetOptions { max_peers: 0, ..test_opts(369, vec![]) };
        let b = LiteNetwork::start_with(b_opts, rt.clone()).await.unwrap();
        let a = LiteNetwork::start_with(test_opts(369, vec![]), rt).await.unwrap();
        let (b_id, b_rec) = (b.local_record().id, loopback(&b));
        a.connect(b_rec);
        wait_for("A to keep B", || a.peers() == vec![b_id]).await;
        Transport::drop_peer(&a, b_id);
        wait_for("A to drop B", || a.peers().is_empty()).await;
        wait_for("A to keep B again", || {
            a.connect(b_rec);
            a.peers() == vec![b_id]
        })
        .await;
    }

    #[cfg(unix)]
    #[test]
    fn node_key_is_owner_only_and_loosened_files_are_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("nodekey");
        load_or_create_node_key(&path).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_or_create_node_key(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn a_node_key_file_that_does_not_parse_is_an_error_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodekey");
        let zero = alloy_primitives::hex::encode([0u8; 32]);
        for bad in [b"not hex".as_slice(), b"abcd", zero.as_bytes(), &[0xff; 64]] {
            std::fs::write(&path, bad).unwrap();
            let err = load_or_create_node_key(&path).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(
                err.to_string(),
                format!(
                    "node key file {} does not hold a hex secret key; move it aside to create a new key",
                    path.display()
                )
            );
            assert_eq!(std::fs::read(&path).unwrap(), bad, "the file is not replaced");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_node_key_file_is_an_error_and_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodekey");
        let a = load_or_create_node_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let res = load_or_create_node_key(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A process that may read anything (root) loads the key; anyone else gets the error.
        match res {
            Ok(b) => assert_eq!(a.to_secret_bytes(), b.to_secret_bytes()),
            Err(err) => {
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(
                    err.to_string()
                        .starts_with(&format!("cannot read node key file {}: ", path.display())),
                    "{err}"
                );
            }
        }
        let b = load_or_create_node_key(&path).unwrap();
        assert_eq!(a.to_secret_bytes(), b.to_secret_bytes(), "the key is not replaced");
    }

    /// A read error other than a missing file, for any user: root may read a mode 000 file, but
    /// no one reads a directory as a file.
    #[test]
    fn a_node_key_path_that_cannot_be_read_is_an_error_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodekey");
        std::fs::create_dir(&path).unwrap();
        let read_err = std::fs::read(&path).unwrap_err();
        let err = load_or_create_node_key(&path).unwrap_err();
        assert_eq!(err.kind(), read_err.kind());
        assert_eq!(
            err.to_string(),
            format!("cannot read node key file {}: {read_err}", path.display())
        );
        assert!(path.is_dir(), "the path is not replaced");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no temp file is left");
    }

    #[test]
    fn node_key_is_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodekey");
        let a = load_or_create_node_key(&path).unwrap();
        let b = load_or_create_node_key(&path).unwrap();
        assert_eq!(a.to_secret_bytes(), b.to_secret_bytes());
    }

    /// One message of every `snap/1` and shared `snap` kind, all with `id`, and whether each is
    /// a request, a response, or neither for this client.
    fn every_kind(id: u64) -> Vec<(S, Option<bool>)> {
        use reth_eth_wire_types::{
            snap::{
                AccountRangeMessage, BlockAccessListsMessage, ByteCodesMessage,
                GetBlockAccessListsMessage, GetByteCodesMessage, GetStorageRangesMessage,
                StorageRangesMessage,
            },
            BlockAccessLists,
        };
        use reth_pulsechain_snap::{GetTrieNodesMessage, TrieNodesMessage};
        vec![
            (req(id, B256::ZERO), Some(true)),
            (
                S::Shared(M::AccountRange(AccountRangeMessage {
                    request_id: id,
                    accounts: vec![],
                    proof: vec![],
                })),
                Some(false),
            ),
            (
                S::Shared(M::GetStorageRanges(GetStorageRangesMessage {
                    request_id: id,
                    root_hash: B256::ZERO,
                    account_hashes: vec![B256::ZERO],
                    starting_hash: B256::ZERO.into(),
                    limit_hash: B256::ZERO.into(),
                    response_bytes: 1,
                })),
                Some(true),
            ),
            (
                S::Shared(M::StorageRanges(StorageRangesMessage {
                    request_id: id,
                    slots: vec![],
                    proof: vec![],
                })),
                Some(false),
            ),
            (
                S::Shared(M::GetByteCodes(GetByteCodesMessage {
                    request_id: id,
                    hashes: vec![],
                    response_bytes: 1,
                })),
                Some(true),
            ),
            (
                S::Shared(M::ByteCodes(ByteCodesMessage { request_id: id, codes: vec![] })),
                Some(false),
            ),
            (
                S::GetTrieNodes(GetTrieNodesMessage {
                    request_id: id,
                    root_hash: B256::ZERO,
                    paths: vec![],
                    response_bytes: 1,
                }),
                Some(true),
            ),
            (S::TrieNodes(TrieNodesMessage { request_id: id, nodes: vec![] }), Some(false)),
            // snap/2 only: this client neither sends nor matches them.
            (
                S::Shared(M::GetBlockAccessLists(GetBlockAccessListsMessage {
                    request_id: id,
                    block_hashes: vec![],
                    response_bytes: 1,
                })),
                None,
            ),
            (
                S::Shared(M::BlockAccessLists(BlockAccessListsMessage {
                    request_id: id,
                    block_access_lists: BlockAccessLists::default(),
                })),
                None,
            ),
        ]
    }

    /// A frame a peer may send: any bytes, or a well-formed message of some kind and id.
    fn frame() -> impl proptest::strategy::Strategy<Value = BytesMut> {
        use proptest::prelude::*;
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..64).prop_map(|b| BytesMut::from(&b[..])),
            (0..8u64, 0..8usize).prop_map(|(id, kind)| {
                let msg = every_kind(id).swap_remove(kind).0;
                BytesMut::from(msg.encode().unwrap().as_ref())
            }),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Ids sort every kind into requests, responses or neither, and survive the wire.
        #[test]
        fn request_and_response_ids_partition_the_kinds(id: u64) {
            for (msg, request) in every_kind(id) {
                let (q, r) = (request_id(&msg), response_id(&msg));
                proptest::prop_assert_eq!(q.is_some(), request == Some(true), "{:?}", msg);
                proptest::prop_assert_eq!(r.is_some(), request == Some(false), "{:?}", msg);
                proptest::prop_assert_eq!(q.or(r).unwrap_or(id), id);
                if request.is_some() {
                    let back = S::decode(&msg.encode().unwrap()).unwrap();
                    proptest::prop_assert_eq!((request_id(&back), response_id(&back)), (q, r));
                    proptest::prop_assert_eq!(back, msg);
                }
            }
        }

        /// Decoding never panics, and what decodes encodes back to itself.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            if let Ok(msg) = S::decode(&bytes) {
                proptest::prop_assert_eq!(S::decode(&msg.encode().unwrap()).unwrap(), msg);
            }
        }

        /// Whatever frames a peer sends: each response reaches only the waiter of its id (and
        /// only the first one), a frame with a request id makes no output, decoded or not, and
        /// the first other frame that does not decode ends the connection.
        #[test]
        fn any_frame_sequence_only_answers_the_waiter_of_its_id(
            frames in proptest::collection::vec(frame(), 0..12),
        ) {
            let client = Snap1Client::default();
            let (to_conn, inbound) = fmpsc::unbounded::<BytesMut>();
            let mut conn = ClientConnection::new(client.shared, PeerId::repeat_byte(9), inbound);
            let mut waiters = Vec::new();
            for id in 0..4u64 {
                let (reply, rx) = oneshot::channel();
                conn.pending.insert(id, reply);
                waiters.push(rx);
            }
            let mut want: HashMap<u64, S> = HashMap::new();
            let mut ends = false;
            for f in &frames {
                to_conn.unbounded_send(f.clone()).unwrap();
                if ends || is_request_frame(f) {
                    continue;
                }
                match S::decode(f) {
                    Err(_) => ends = true,
                    Ok(msg) => {
                        if let Some(id) = response_id(&msg).filter(|id| *id < 4) {
                            want.entry(id).or_insert(msg);
                        }
                    }
                }
            }
            let polled = poll_once(&mut conn, &Arc::default());
            if ends {
                proptest::prop_assert!(matches!(polled, Poll::Ready(None)), "{:?}", polled);
            } else {
                proptest::prop_assert!(polled.is_pending(), "{:?}", polled);
            }
            for (id, mut rx) in (0..4u64).zip(waiters) {
                match want.remove(&id) {
                    Some(msg) => proptest::prop_assert_eq!(rx.try_recv().unwrap(), msg),
                    None => proptest::prop_assert!(rx.try_recv().is_err()),
                }
            }
            proptest::prop_assert!(conn.pending.len() <= 4);
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// A key file of any text either loads or is an error that does not show the text, and
        /// the file is never replaced.
        #[test]
        fn any_key_file_text_is_loaded_or_refused_and_kept(
            text in "[ \t\n0-9a-fA-Fx]{0,80}|[[:print:]]{0,80}",
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("nodekey");
            std::fs::write(&path, &text).unwrap();
            match load_or_create_node_key(&path) {
                Ok(key) => {
                    let hex = alloy_primitives::hex::encode(key.to_secret_bytes());
                    proptest::prop_assert_eq!(hex, text.trim().trim_start_matches("0x").to_lowercase());
                }
                Err(err) => {
                    let msg = err.to_string();
                    let shown = text.trim();
                    proptest::prop_assert!(shown.len() < 8 || !msg.contains(shown), "{msg}");
                    proptest::prop_assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
                }
            }
            proptest::prop_assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
    }

    #[test]
    fn a_key_file_with_a_valid_key_loads_it_whatever_the_case_and_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodekey");
        let key = reth_network::config::rng_secret_key();
        let hex = alloy_primitives::hex::encode(key.to_secret_bytes());
        for text in [hex.clone(), format!("  {}\n", hex.to_uppercase()), format!("0x{hex}")] {
            std::fs::write(&path, &text).unwrap();
            let got = load_or_create_node_key(&path).unwrap();
            assert_eq!(got.to_secret_bytes(), key.to_secret_bytes(), "{text:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
    }
}
