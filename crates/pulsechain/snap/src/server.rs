//! The `snap/1` request server: admission control and dispatch.
//!
//! Requests from light clients such as reth-lite arrive as dozens of one-key lookups per peer,
//! mostly at the head. Upstream's admission (two range requests at once, one per peer) would answer
//! most of them empty, and the client would bench us. So there are two lanes:
//!
//! - **Hot**: roots of the persisted tip (the `Finish` checkpoint) and of the blocks above it,
//!   whose views need no reverts. Up to [`Snap1Config::hot_workers`] requests run at once, up to
//!   [`Snap1Config::hot_per_peer`] of them from one peer, and never more than half the workers;
//!   more wait for a slot, up to [`Snap1Config::hot_queue_timeout`]. Per-peer token buckets bound
//!   the request rate and the reply bytes. A request over a rate waits for its tokens, so a client
//!   that sends faster is paced, not answered empty; only one whose tokens come after the hot queue
//!   timeout is.
//! - **Cold**: older roots, which rebuild reverts, also of a block still in memory below the tip.
//!   At most [`Snap1Config::cold_concurrency`] run at once, [`Snap1Config::cold_per_peer`] per peer
//!   and never more than half of them; more wait for a slot. A request that finds no slot within
//!   [`Snap1Config::cold_queue_timeout`] is answered empty. Resolved state views are cached for a
//!   short time, so a burst at one cold root builds its reverts at most once per cold slot.
//!
//! Admission runs cheapest first: the token bucket, then the root's lane, then the slots. A root
//! the backend does not retain is answered empty before it takes a slot; the server keeps the
//! backend's list of retained roots for a short time, and answers a root empty only when a
//! listing that started after the request lacks it. The listing runs on a task of its own, and
//! a request waits for it at most [`ROOTS_LISTING_WAIT`], so no peer's request can hold it. A
//! request waits for its slots on a task of its own, so a connection that is no longer polled
//! cannot hold a slot with no job. A request's blocking job owns its slots, so they stay taken
//! until the job ends even when the peer goes away. A peer's admission state outlives its
//! connection for [`Snap1Config::peer_cooldown`].
//!
//! Over a limit the answer is empty, never an error and never a disconnect. A peer that sends a
//! response-shaped message gets `None`, which the connection turns into a disconnect.
//!
//! `GetByteCodes` needs no root and runs in the hot lane.

use crate::{
    backend::Snap1Backend,
    bytecodes::SOFT_RESPONSE_LIMIT,
    message::{Snap1Message, TrieNodesMessage},
    metrics::Snap1Metrics,
    ranges::{serve_account_range, serve_storage_ranges},
    trie_nodes::serve_trie_nodes,
};
use alloy_primitives::{Bytes, B256, B512};
use alloy_rlp::Encodable;
use reth_eth_wire_types::snap::{
    AccountRangeMessage, ByteCodesMessage, SnapProtocolMessage, StorageRangesMessage,
};
use reth_storage_api::{
    errors::provider::ProviderResult, StateRangeProvider, StateRangeProviderFactory, StateRangeView,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

/// A remote peer's id.
pub type PeerId = B512;

/// How costly serving a state root is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lane {
    /// The state view is cheap to build.
    Hot,
    /// The state view needs reverts from persisted history.
    Cold,
}

impl Lane {
    pub(crate) const ALL: [Self; 2] = [Self::Hot, Self::Cold];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Cold => "cold",
        }
    }
}

/// The request messages the server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RequestKind {
    AccountRange,
    StorageRanges,
    TrieNodes,
    ByteCodes,
}

impl RequestKind {
    pub(crate) const ALL: [Self; 4] =
        [Self::AccountRange, Self::StorageRanges, Self::TrieNodes, Self::ByteCodes];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::AccountRange => "get_account_range",
            Self::StorageRanges => "get_storage_ranges",
            Self::TrieNodes => "get_trie_nodes",
            Self::ByteCodes => "get_byte_codes",
        }
    }
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Outcome {
    Served,
    EmptyUnknownRoot,
    EmptyBusy,
    RateLimited,
    Error,
}

impl Outcome {
    pub(crate) const ALL: [Self; 5] =
        [Self::Served, Self::EmptyUnknownRoot, Self::EmptyBusy, Self::RateLimited, Self::Error];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::EmptyUnknownRoot => "empty_unknown_root",
            Self::EmptyBusy => "empty_busy",
            Self::RateLimited => "rate_limited",
            Self::Error => "error",
        }
    }
}

/// Limits of the request server.
#[derive(Debug, Clone)]
pub struct Snap1Config {
    /// Hot-lane requests that run at once.
    pub hot_workers: usize,
    /// Hot-lane requests one peer runs at once. The server uses at most half of
    /// [`Self::hot_workers`], so one peer cannot take them all.
    pub hot_per_peer: usize,
    /// Per-peer request rate in requests per second, on both lanes.
    ///
    /// The slot limits bound the work; this bounds cheap requests, such as those for unknown
    /// roots. A request over the rate waits for a token.
    pub hot_rate: u32,
    /// Per-peer burst size of the token bucket.
    pub hot_burst: u32,
    /// How long a request waits for its tokens, and a hot request for its tokens and a free
    /// slot, before it is answered empty. It also bounds how long a request waits for room on
    /// its connection.
    pub hot_queue_timeout: Duration,
    /// Cold-lane requests that run at once.
    pub cold_concurrency: usize,
    /// Cold-lane requests one peer runs at once, at most half of [`Self::cold_concurrency`].
    pub cold_per_peer: usize,
    /// How long a cold request waits for its tokens and a free slot before it is answered
    /// empty, unless the tokens alone took longer.
    pub cold_queue_timeout: Duration,
    /// Number of resolved cold state views kept.
    pub view_cache_entries: usize,
    /// How long a cached view is reused. A view holds a database read transaction, so keep it
    /// short. A background sweep drops expired views even when no request comes.
    pub view_cache_ttl: Duration,
    /// How long a disconnected peer's admission state is kept, so a reconnect does not refill
    /// its token bucket or free the slots of its running jobs.
    pub peer_cooldown: Duration,
    /// How long, from its start, the backend's list of retained roots is used before it is
    /// listed again.
    pub roots_ttl: Duration,
    /// The shortest time from the end of one listing to the start of the next. A root missing
    /// from the list makes the server list again, but no sooner than this, so unknown roots
    /// cannot keep the backend listing even when a listing is slow.
    pub roots_min_refresh: Duration,
    /// Per-peer reply rate in bytes per second.
    ///
    /// A request is charged its reply budget before it runs and its real reply size after, so
    /// concurrent requests cannot overdraw the bucket by more than their budgets. A request
    /// dropped before its job starts is charged nothing; one dropped after pays its reply, at no
    /// less than its budget. A request that finds the bucket in debt waits for the refill, as for
    /// [`Self::hot_rate`].
    pub byte_rate: u32,
    /// Per-peer burst of reply bytes.
    pub byte_burst: u32,
}

impl Default for Snap1Config {
    fn default() -> Self {
        Self {
            hot_workers: 8,
            hot_per_peer: 4,
            hot_rate: 1000,
            hot_burst: 2000,
            hot_queue_timeout: Duration::from_secs(2),
            cold_concurrency: 2,
            cold_per_peer: 1,
            cold_queue_timeout: Duration::from_secs(2),
            view_cache_entries: 4,
            view_cache_ttl: Duration::from_secs(2),
            peer_cooldown: Duration::from_secs(60),
            roots_ttl: Duration::from_secs(2),
            roots_min_refresh: Duration::from_millis(100),
            byte_rate: 8 * 1024 * 1024,
            byte_burst: 32 * 1024 * 1024,
        }
    }
}

/// A token bucket refilled at `rate` tokens per second up to `burst`.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: tokio::time::Instant,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            rate: f64::from(rate),
            burst: f64::from(burst),
            last: tokio::time::Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = elapsed.mul_add(self.rate, self.tokens).min(self.burst);
    }

    /// How long until the balance reaches `level`: zero when it has, `None` when it never will.
    fn time_to(&mut self, level: f64) -> Option<Duration> {
        self.refill();
        let short = level - self.tokens;
        if short <= 0.0 {
            return Some(Duration::ZERO)
        }
        if self.rate <= 0.0 || level > self.burst {
            return None
        }
        Duration::try_from_secs_f64(short / self.rate).ok()
    }

    /// Takes `cost`. The balance may go below zero, and then later charges wait for the refill.
    fn charge(&mut self, cost: f64) {
        self.tokens -= cost;
    }

    /// Replaces a charge of `charged` with one of `actual`.
    fn settle(&mut self, charged: f64, actual: f64) {
        self.tokens = (self.tokens + charged - actual).min(self.burst);
    }
}

/// One peer's admission state.
struct PeerState {
    bucket: Mutex<Bucket>,
    /// Reply bytes.
    bytes: Mutex<Bucket>,
    /// The turn to take tokens. Requests that wait for tokens take turns in arrival order, so
    /// only the first one sleeps on a timer.
    pacing: tokio::sync::Mutex<()>,
    hot: Arc<Semaphore>,
    cold: Arc<Semaphore>,
}

/// A resolved view shared by concurrent cold requests.
///
/// A [`StateRangeView`] is `Send` but not `Sync`, so calls take turns.
struct SharedView(Arc<Mutex<StateRangeView>>);

impl SharedView {
    fn with<T>(&self, f: impl FnOnce(&StateRangeView) -> T) -> T {
        f(&self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

impl StateRangeProvider for SharedView {
    fn account_range(
        &self,
        start: B256,
        limit: B256,
        response_bytes: usize,
    ) -> reth_storage_api::RangeResult<(B256, reth_primitives_traits::Account)> {
        self.with(|v| v.account_range(start, limit, response_bytes))
    }

    fn storage_root_by_hash(&self, hashed_address: B256) -> ProviderResult<B256> {
        self.with(|v| v.storage_root_by_hash(hashed_address))
    }

    fn storage_range(
        &self,
        hashed_address: B256,
        start: B256,
        limit: B256,
        response_bytes: usize,
    ) -> reth_storage_api::StorageRangeResult {
        self.with(|v| v.storage_range(hashed_address, start, limit, response_bytes))
    }

    fn account_range_proof(&self, keys: &[B256]) -> ProviderResult<Vec<Bytes>> {
        self.with(|v| v.account_range_proof(keys))
    }

    fn storage_range_proof(
        &self,
        hashed_address: B256,
        keys: &[B256],
    ) -> ProviderResult<Vec<Bytes>> {
        self.with(|v| v.storage_range_proof(hashed_address, keys))
    }
}

/// Resolved cold views, newest last.
#[derive(Default)]
struct ViewCache {
    entries: VecDeque<(B256, Instant, Arc<Mutex<StateRangeView>>)>,
}

impl ViewCache {
    /// Drops the views older than `ttl`, which closes their read transactions once no request
    /// uses them.
    fn evict_expired(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.entries.retain(|(_, at, _)| now.duration_since(*at) < ttl);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A factory for one request: resolves the root through the backend, or through the view cache on
/// the cold lane, and notes when the root does not resolve.
struct RequestFactory<'a, F> {
    backend: &'a F,
    cache: Option<(&'a Mutex<ViewCache>, &'a Snap1Config, &'a Snap1Metrics)>,
    unknown_root: AtomicBool,
}

impl<F: Snap1Backend> StateRangeProviderFactory for RequestFactory<'_, F> {
    fn state_range_provider(&self, root: B256) -> ProviderResult<Option<StateRangeView>> {
        let Some((cache, cfg, metrics)) = self.cache else {
            let view = self.backend.state_range_provider(root)?;
            if view.is_none() {
                self.unknown_root.store(true, Ordering::Relaxed);
            }
            return Ok(view)
        };

        {
            let mut cache = lock(cache);
            cache.evict_expired(cfg.view_cache_ttl);
            if let Some((_, _, view)) = cache.entries.iter().find(|(r, ..)| *r == root) {
                metrics.view_cache(true);
                return Ok(Some(Box::new(SharedView(view.clone()))))
            }
        }
        metrics.view_cache(false);
        let Some(view) = self.backend.state_range_provider(root)? else {
            self.unknown_root.store(true, Ordering::Relaxed);
            return Ok(None)
        };
        let view = Arc::new(Mutex::new(view));
        if cfg.view_cache_entries > 0 {
            let mut cache = lock(cache);
            cache.evict_expired(cfg.view_cache_ttl);
            // A concurrent miss at the same root cached its view first: share that one, so the
            // root takes one entry.
            if let Some((_, _, cached)) = cache.entries.iter().find(|(r, ..)| *r == root) {
                return Ok(Some(Box::new(SharedView(cached.clone()))))
            }
            while cache.entries.len() >= cfg.view_cache_entries {
                cache.entries.pop_front();
            }
            cache.entries.push_back((root, Instant::now(), view.clone()));
        }
        Ok(Some(Box::new(SharedView(view))))
    }
}

/// The lane and depth of each retained root, as last listed by the backend.
type RootMap = HashMap<B256, (Lane, u64)>;

/// The backend's last listing of retained roots.
#[derive(Default)]
struct RootCache {
    /// When the last listing started and ended, and its list; `None` when the backend gave none.
    listed: Option<(Instant, Instant, Option<Arc<RootMap>>)>,
    /// While listings fail: the last list and when its listing started. It places roots for one
    /// more [`Snap1Config::roots_ttl`], so a transient failure does not empty the head.
    kept: Option<(Instant, Arc<RootMap>)>,
    /// Whether a listing is due or runs now.
    listing: bool,
}

/// What the root cache says about a root.
#[derive(Debug, PartialEq, Eq)]
enum RootLookup {
    Known(Lane, Option<u64>),
    Unknown,
    /// The backend gives no list: ask it per request.
    Unlisted,
    /// The list is missing or too old to trust.
    Refresh,
}

impl RootCache {
    /// What the list says about `root` for a request that arrived at `asked`.
    ///
    /// Only a listing that started after `asked` can say a root is not retained: an older one
    /// may predate the root's block.
    fn lookup(&self, root: B256, asked: Instant, cfg: &Snap1Config) -> RootLookup {
        let Some((started, _, listed)) = &self.listed else { return RootLookup::Refresh };
        let after_ask = *started >= asked;
        let fresh = after_ask || started.elapsed() < cfg.roots_ttl;
        match listed {
            None if fresh => self.kept_lookup(root, cfg),
            None => RootLookup::Refresh,
            Some(map) => match map.get(&root) {
                Some(&(lane, depth)) if fresh => RootLookup::Known(lane, Some(depth)),
                None if after_ask => RootLookup::Unknown,
                _ => RootLookup::Refresh,
            },
        }
    }

    /// What the list kept from before a failed listing says about `root`. It never says a root
    /// is not retained, since a root may be newer than the list.
    fn kept_lookup(&self, root: B256, cfg: &Snap1Config) -> RootLookup {
        self.kept
            .as_ref()
            .filter(|(started, _)| started.elapsed() < cfg.roots_ttl.saturating_mul(2))
            .and_then(|(_, map)| map.get(&root))
            .map_or(RootLookup::Unlisted, |&(lane, depth)| RootLookup::Known(lane, Some(depth)))
    }

    /// Stores a listing that ran from `started` to `ended`. A failed one keeps the last list.
    fn store(&mut self, started: Instant, ended: Instant, found: Option<Arc<RootMap>>) {
        match (&found, self.listed.take()) {
            (Some(_), _) => self.kept = None,
            (None, Some((last_started, _, Some(map)))) => self.kept = Some((last_started, map)),
            (None, _) => {}
        }
        self.listed = Some((started, ended, found));
    }

    /// When the next listing may start: [`Snap1Config::roots_min_refresh`] after the last one
    /// ended, and not before now.
    fn next_listing(&self, cfg: &Snap1Config) -> Instant {
        let now = Instant::now();
        self.listed
            .as_ref()
            .and_then(|(_, ended, _)| ended.checked_add(cfg.roots_min_refresh))
            .map_or(now, |at| at.max(now))
    }

    /// What the last list says about `root`, however old it is.
    fn last_listed(&self, root: B256, cfg: &Snap1Config) -> RootLookup {
        match &self.listed {
            None => RootLookup::Unknown,
            Some((_, _, None)) => self.kept_lookup(root, cfg),
            Some((_, _, Some(map))) => map
                .get(&root)
                .map_or(RootLookup::Unknown, |&(lane, depth)| RootLookup::Known(lane, Some(depth))),
        }
    }
}

/// A request, split into what admission needs and the message to serve.
enum Request {
    AccountRange(reth_eth_wire_types::snap::GetAccountRangeMessage),
    StorageRanges(reth_eth_wire_types::snap::GetStorageRangesMessage),
    TrieNodes(crate::message::GetTrieNodesMessage),
    ByteCodes(reth_eth_wire_types::snap::GetByteCodesMessage),
}

impl Request {
    /// Returns `None` for a message a client must not send.
    fn from_message(msg: Snap1Message) -> Option<Self> {
        match msg {
            Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(m)) => {
                Some(Self::AccountRange(m))
            }
            Snap1Message::Shared(SnapProtocolMessage::GetStorageRanges(m)) => {
                Some(Self::StorageRanges(m))
            }
            Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(m)) => Some(Self::ByteCodes(m)),
            Snap1Message::GetTrieNodes(m) => Some(Self::TrieNodes(m)),
            _ => None,
        }
    }

    const fn kind(&self) -> RequestKind {
        match self {
            Self::AccountRange(_) => RequestKind::AccountRange,
            Self::StorageRanges(_) => RequestKind::StorageRanges,
            Self::TrieNodes(_) => RequestKind::TrieNodes,
            Self::ByteCodes(_) => RequestKind::ByteCodes,
        }
    }

    /// The state root the request reads, if it has one.
    const fn root(&self) -> Option<B256> {
        match self {
            Self::AccountRange(m) => Some(m.root_hash),
            Self::StorageRanges(m) => Some(m.root_hash),
            Self::TrieNodes(m) => Some(m.root_hash),
            Self::ByteCodes(_) => None,
        }
    }

    /// The answer that carries no data.
    const fn empty(&self) -> Snap1Message {
        match self {
            Self::AccountRange(m) => {
                Snap1Message::Shared(SnapProtocolMessage::AccountRange(AccountRangeMessage {
                    request_id: m.request_id,
                    accounts: Vec::new(),
                    proof: Vec::new(),
                }))
            }
            Self::StorageRanges(m) => {
                Snap1Message::Shared(SnapProtocolMessage::StorageRanges(StorageRangesMessage {
                    request_id: m.request_id,
                    slots: Vec::new(),
                    proof: Vec::new(),
                }))
            }
            Self::TrieNodes(m) => Snap1Message::TrieNodes(TrieNodesMessage {
                request_id: m.request_id,
                nodes: Vec::new(),
            }),
            Self::ByteCodes(m) => {
                Snap1Message::Shared(SnapProtocolMessage::ByteCodes(ByteCodesMessage {
                    request_id: m.request_id,
                    codes: Vec::new(),
                }))
            }
        }
    }

    fn serve<F: Snap1Backend>(
        &self,
        backend: &F,
        factory: &RequestFactory<'_, F>,
    ) -> ProviderResult<Snap1Message> {
        Ok(match self {
            Self::AccountRange(m) => Snap1Message::Shared(SnapProtocolMessage::AccountRange(
                serve_account_range(factory, m)?,
            )),
            Self::StorageRanges(m) => Snap1Message::Shared(SnapProtocolMessage::StorageRanges(
                serve_storage_ranges(factory, m)?,
            )),
            Self::TrieNodes(m) => Snap1Message::TrieNodes(serve_trie_nodes(factory, m)?),
            Self::ByteCodes(m) => {
                Snap1Message::Shared(SnapProtocolMessage::ByteCodes(backend.byte_codes(m)?))
            }
        })
    }
}

/// The reply bytes a request asks for, capped at [`SOFT_RESPONSE_LIMIT`]; zero for a message that
/// is not a request.
pub(crate) fn reply_budget(msg: &Snap1Message) -> usize {
    let asked = match msg {
        Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(m)) => m.response_bytes,
        Snap1Message::Shared(SnapProtocolMessage::GetStorageRanges(m)) => m.response_bytes,
        Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(m)) => m.response_bytes,
        Snap1Message::GetTrieNodes(m) => m.response_bytes,
        _ => 0,
    };
    usize::try_from(asked).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT)
}

/// The encoded size of a response body.
fn body_len(msg: &Snap1Message) -> usize {
    match msg {
        Snap1Message::Shared(SnapProtocolMessage::AccountRange(m)) => m.length(),
        Snap1Message::Shared(SnapProtocolMessage::StorageRanges(m)) => m.length(),
        Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m)) => m.length(),
        Snap1Message::TrieNodes(m) => m.length(),
        _ => 0,
    }
}

/// Serves `snap/1` requests with admission control.
pub struct Snap1Server<F> {
    backend: Arc<F>,
    cfg: Snap1Config,
    hot_workers: Arc<Semaphore>,
    cold_workers: Arc<Semaphore>,
    /// Connected peers' open connections and state.
    peers: Mutex<PeerMap>,
    /// Disconnected peers' state and when they left, kept for [`Snap1Config::peer_cooldown`].
    cooling: Mutex<HashMap<PeerId, (Instant, Arc<PeerState>)>>,
    views: Arc<Mutex<ViewCache>>,
    roots: Arc<Mutex<RootCache>>,
    /// Sent to when a listing ends, so the requests that wait for it wake.
    listed: Arc<watch::Sender<()>>,
    metrics: Arc<Snap1Metrics>,
}

/// Each connected peer's number of open connections, and its admission state.
type PeerMap = HashMap<PeerId, (usize, Arc<PeerState>)>;

/// Caps a peer's share of a lane of `workers` slots at half of them, and at least one.
fn per_peer_cap(asked: usize, workers: usize) -> usize {
    asked.clamp(1, (workers / 2).max(1))
}

/// The longest a request waits for a root listing to end.
const ROOTS_LISTING_WAIT: Duration = Duration::from_secs(1);

/// The most disconnected peers whose state is kept. Past it the oldest is forgotten.
const MAX_COOLING_PEERS: usize = 4096;

impl<F> std::fmt::Debug for Snap1Server<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snap1Server").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

impl<F> Snap1Server<F> {
    /// Registers a connection of a peer that negotiated `snap/1`.
    ///
    /// A reconnecting peer can open its new connection before the old one closes; both share
    /// one admission state.
    pub fn peer_connected(&self, peer: PeerId) {
        let mut peers = self.lock_peers();
        self.live_entry(&mut peers, peer).0 += 1;
    }

    /// Closes one of a peer's connections. When it was the last, moves the peer's admission state
    /// to the cool-down set.
    ///
    /// The state is kept for [`Snap1Config::peer_cooldown`], so a peer that reconnects finds its
    /// spent token bucket, and its jobs still running hold their per-peer slots.
    pub fn peer_disconnected(&self, peer: PeerId) {
        let mut peers = self.lock_peers();
        let Some((connections, _)) = peers.get_mut(&peer) else { return };
        *connections = connections.saturating_sub(1);
        if *connections > 0 {
            return
        }
        if let Some((_, state)) = peers.remove(&peer) {
            let mut cooling = lock(&self.cooling);
            let cooldown = self.cfg.peer_cooldown;
            cooling.retain(|_, (left, _)| left.elapsed() < cooldown);
            if cooling.len() >= MAX_COOLING_PEERS &&
                let Some(oldest) =
                    cooling.iter().min_by_key(|(_, (left, _))| *left).map(|(id, _)| *id)
            {
                cooling.remove(&oldest);
            }
            cooling.insert(peer, (Instant::now(), state));
        }
        self.metrics.peers(peers.len());
    }

    fn new_peer(&self) -> PeerState {
        PeerState {
            bucket: Mutex::new(Bucket::new(self.cfg.hot_rate, self.cfg.hot_burst)),
            bytes: Mutex::new(Bucket::new(self.cfg.byte_rate, self.cfg.byte_burst)),
            pacing: tokio::sync::Mutex::new(()),
            hot: Arc::new(Semaphore::new(self.cfg.hot_per_peer)),
            cold: Arc::new(Semaphore::new(self.cfg.cold_per_peer)),
        }
    }

    fn lock_peers(&self) -> std::sync::MutexGuard<'_, PeerMap> {
        lock(&self.peers)
    }

    /// Returns the peer's state.
    fn peer(&self, peer: PeerId) -> Arc<PeerState> {
        let mut peers = self.lock_peers();
        self.live_entry(&mut peers, peer).1.clone()
    }

    /// Returns the peer's live entry, adding one with no connections when it has none: with the
    /// state kept from its last connection if it is still cooling down, else a fresh one.
    fn live_entry<'a>(
        &self,
        peers: &'a mut PeerMap,
        peer: PeerId,
    ) -> &'a mut (usize, Arc<PeerState>) {
        self.metrics.peers(peers.len() + usize::from(!peers.contains_key(&peer)));
        peers.entry(peer).or_insert_with(|| {
            let kept = lock(&self.cooling)
                .remove(&peer)
                .filter(|(left, _)| left.elapsed() < self.cfg.peer_cooldown)
                .map(|(_, state)| state);
            (0, kept.unwrap_or_else(|| Arc::new(self.new_peer())))
        })
    }
}

impl<F: Snap1Backend> Snap1Server<F> {
    /// Creates a server over `factory` with the limits in `cfg`.
    ///
    /// Inside a tokio runtime it also starts a task that drops expired cold views, so an idle
    /// server holds no read transaction past [`Snap1Config::view_cache_ttl`]. The task ends when
    /// the server is dropped.
    pub fn new(factory: Arc<F>, mut cfg: Snap1Config) -> Self {
        cfg.hot_workers = cfg.hot_workers.max(1);
        cfg.cold_concurrency = cfg.cold_concurrency.max(1);
        cfg.hot_per_peer = per_peer_cap(cfg.hot_per_peer, cfg.hot_workers);
        cfg.cold_per_peer = per_peer_cap(cfg.cold_per_peer, cfg.cold_concurrency);
        let views: Arc<Mutex<ViewCache>> = Arc::default();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let views = Arc::downgrade(&views);
            let ttl = cfg.view_cache_ttl;
            runtime.spawn(async move {
                let mut tick = tokio::time::interval((ttl / 2).max(Duration::from_millis(10)));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let Some(views) = views.upgrade() else { break };
                    lock(&views).evict_expired(ttl);
                }
            });
        }
        Self {
            hot_workers: Arc::new(Semaphore::new(cfg.hot_workers)),
            cold_workers: Arc::new(Semaphore::new(cfg.cold_concurrency)),
            backend: factory,
            cfg,
            peers: Mutex::default(),
            cooling: Mutex::default(),
            views,
            roots: Arc::default(),
            listed: Arc::new(watch::Sender::new(())),
            metrics: Arc::new(Snap1Metrics::new()),
        }
    }

    /// Answers one request from `peer`.
    ///
    /// Every request gets a reply, empty when the server is over a limit, the root is unknown or
    /// the provider failed. Returns `None` for a message that is not a request, which the
    /// connection must treat as a protocol violation.
    pub async fn handle(&self, peer: PeerId, msg: Snap1Message) -> Option<Snap1Message> {
        let budget = reply_budget(&msg);
        let request = Request::from_message(msg)?;
        let kind = request.kind();
        let state = self.peer(peer);

        // The rate limits come first: a limited request touches nothing else and is charged
        // nothing.
        let arrived = tokio::time::Instant::now();
        if !pace(&state, budget as f64, arrived + self.cfg.hot_queue_timeout).await {
            self.metrics.request(kind, Outcome::RateLimited);
            return Some(request.empty())
        }
        let paced = arrived.elapsed();
        let charge = Arc::new(ReplyCharge { peer: state.clone(), budget, reply: Mutex::new(None) });

        let finish = |outcome: Outcome, response: Snap1Message| {
            charge.record(body_len(&response));
            self.metrics.request(kind, outcome);
            if outcome == Outcome::Served {
                self.metrics.response_bytes(body_len(&response));
            }
            Some(response)
        };

        let (lane, depth) = match request.root() {
            None => (Lane::Hot, None),
            Some(root) => match self.classify(root).await {
                Some(placed) => placed,
                None => return finish(Outcome::EmptyUnknownRoot, request.empty()),
            },
        };

        let (workers, wait) = match lane {
            Lane::Hot => (self.hot_workers.clone(), self.cfg.hot_queue_timeout),
            Lane::Cold => (self.cold_workers.clone(), self.cfg.cold_queue_timeout),
        };
        // The wait for a token counts towards the wait for a slot, so pacing adds no latency
        // past the queue timeout.
        let wait = wait.saturating_sub(paced);
        let peer_state = state.clone();
        let backend = self.backend.clone();
        let views = self.views.clone();
        let cfg = self.cfg.clone();
        let metrics = self.metrics.clone();
        let job_charge = Arc::downgrade(&charge);
        let empty = request.empty();
        // Admission runs on a task of its own: tokio hands a freed slot to the first waiter, and a
        // waiter in a future its connection no longer polls would hold the slot with no job.
        // Dropping the set aborts the task while it waits. The provider work is blocking, so it
        // runs off the async threads, and the job owns the permits: if this future is dropped
        // after admission, as when the peer disconnects, the job keeps its slots until it ends.
        let mut task = tokio::task::JoinSet::new();
        task.spawn(async move {
            let permits = admit(lane, &peer_state, workers, wait).await?;
            // The job holds the charge only once it starts: a request gone before then has
            // refunded its budget already.
            let job_charge = job_charge.upgrade()?;
            let admitted = Instant::now();
            let joined = tokio::task::spawn_blocking(move || {
                let _permits = permits;
                let factory = RequestFactory {
                    backend: &*backend,
                    cache: (lane == Lane::Cold).then(|| (&*views, &cfg, &*metrics)),
                    unknown_root: AtomicBool::new(false),
                };
                let result = request.serve(&*backend, &factory);
                // The cost when no caller remains to record the reply: the work done, at no
                // less than the budget.
                job_charge.record(result.as_ref().map_or(0, body_len).max(budget));
                (result, factory.unknown_root.load(Ordering::Relaxed))
            })
            .await;
            Some((joined, admitted.elapsed()))
        });
        let joined = match task.join_next().await.expect("the set holds the request's task") {
            Ok(Some((joined, ran))) => {
                self.metrics.latency(kind, lane, ran.as_secs_f64());
                joined
            }
            Ok(None) => return finish(Outcome::EmptyBusy, empty),
            Err(err) => Err(err),
        };

        match joined {
            Ok((Ok(response), false)) => {
                if let Some(depth) = depth {
                    self.metrics.root_depth(depth);
                }
                finish(Outcome::Served, response)
            }
            Ok((Ok(_), true)) => finish(Outcome::EmptyUnknownRoot, empty),
            Ok((Err(err), _)) => {
                tracing::debug!(target: "pulsechain::snap1", %err, "snap/1 request failed");
                finish(Outcome::Error, empty)
            }
            Err(err) => {
                tracing::warn!(target: "pulsechain::snap1", %err, "snap/1 request task failed");
                finish(Outcome::Error, empty)
            }
        }
    }

    /// How long a request waits for room on its connection.
    pub(crate) const fn connection_queue_timeout(&self) -> Duration {
        self.cfg.hot_queue_timeout
    }

    /// Answers a request empty because its connection is full, without touching any limit.
    ///
    /// Returns `None` for a message that is not a request.
    pub(crate) fn answer_busy(&self, msg: Snap1Message) -> Option<Snap1Message> {
        let request = Request::from_message(msg)?;
        self.metrics.request(request.kind(), Outcome::EmptyBusy);
        Some(request.empty())
    }

    /// Returns the lane and depth of `root`, or `None` when it is not served.
    ///
    /// With a backend that lists its roots this reads the cached list, and lists again off the
    /// async threads when the list is old or lacks `root`. A root is not served only when a
    /// listing that started after the request lacks it. If no such listing has ended within
    /// [`ROOTS_LISTING_WAIT`], the last list answers. Without a list it asks the backend.
    async fn classify(&self, root: B256) -> Option<(Lane, Option<u64>)> {
        let asked = Instant::now();
        let deadline = tokio::time::Instant::now() + ROOTS_LISTING_WAIT;
        let lookup = loop {
            let mut ended = {
                let mut cache = lock(&self.roots);
                match cache.lookup(root, asked, &self.cfg) {
                    RootLookup::Refresh => {}
                    lookup => break lookup,
                }
                // Subscribed under the lock the listing ends under, so its end cannot be missed.
                let ended = self.listed.subscribe();
                if !cache.listing {
                    cache.listing = true;
                    self.spawn_listing(cache.next_listing(&self.cfg));
                }
                ended
            };
            if !matches!(tokio::time::timeout_at(deadline, ended.changed()).await, Ok(Ok(()))) {
                tracing::debug!(target: "pulsechain::snap1", "root listing still running");
                break lock(&self.roots).last_listed(root, &self.cfg)
            }
        };
        match lookup {
            RootLookup::Known(lane, depth) => Some((lane, depth)),
            RootLookup::Unlisted => self.backend.classify(root),
            RootLookup::Unknown | RootLookup::Refresh => None,
        }
    }

    /// Lists the backend's roots at `not_before` or later, on a blocking task that writes the
    /// result itself, so the list is kept even when no request waits for it any more.
    fn spawn_listing(&self, not_before: Instant) {
        let backend = self.backend.clone();
        let roots = self.roots.clone();
        let listed = self.listed.clone();
        let list = move || {
            let started = Instant::now();
            let found = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                backend.retained_roots()
            })) {
                Ok(found) => found,
                Err(_) => {
                    tracing::warn!(target: "pulsechain::snap1", "listing retained roots panicked");
                    None
                }
            };
            let found = found.map(|roots| {
                let mut map = RootMap::with_capacity(roots.len());
                for r in roots {
                    // A root repeats when blocks change no state. The newest block's entry wins:
                    // its view is the one the backend resolves, from memory when it is hot.
                    map.entry(r.root)
                        .and_modify(|e| {
                            if r.depth < e.1 {
                                *e = (r.lane, r.depth)
                            }
                        })
                        .or_insert((r.lane, r.depth));
                }
                Arc::new(map)
            });
            {
                let mut cache = lock(&roots);
                cache.store(started, Instant::now(), found);
                cache.listing = false;
            }
            listed.send_replace(());
        };
        tokio::spawn(async move {
            tokio::time::sleep_until(not_before.into()).await;
            drop(tokio::task::spawn_blocking(list));
        });
    }
}

/// A reply budget charged to a peer's byte bucket, shared by a request and its provider job. When
/// the last holder drops it, the charge is replaced by the last reply size recorded: the reply
/// sent, or, when the caller went away while the job ran, the job's reply at no less than the
/// budget, so a cancelled request gets no cheaper work. With nothing recorded, as when the peer
/// goes away before the job starts, the budget is refunded.
struct ReplyCharge {
    peer: Arc<PeerState>,
    budget: usize,
    reply: Mutex<Option<usize>>,
}

impl ReplyCharge {
    /// Records a reply of `reply` bytes, which replaces any recorded before.
    fn record(&self, reply: usize) {
        *lock(&self.reply) = Some(reply);
    }
}

impl Drop for ReplyCharge {
    fn drop(&mut self) {
        let actual = lock(&self.reply).map_or(0.0, |r| r as f64);
        lock(&self.peer.bytes).settle(self.budget as f64, actual);
    }
}

/// Charges a request with a reply `budget` to the peer's buckets, waiting until `deadline` for
/// its tokens. Returns `false`, and charges nothing, when they do not come by then.
///
/// Requests take their tokens in arrival order. A request waits for its turn without a timer,
/// then sleeps once until its tokens are due, so a waiter wakes about once however many wait
/// ahead of it.
async fn pace(peer: &PeerState, budget: f64, deadline: tokio::time::Instant) -> bool {
    let Ok(_turn) = tokio::time::timeout_at(deadline, peer.pacing.lock()).await else {
        return false
    };
    loop {
        let wait = {
            let mut requests = lock(&peer.bucket);
            let mut bytes = lock(&peer.bytes);
            // A reply budget may take the byte bucket into debt, so it needs only a positive
            // balance.
            let Some(wait) = requests
                .time_to(1.0)
                .zip(bytes.time_to(f64::MIN_POSITIVE))
                .map(|(requests, bytes)| requests.max(bytes))
            else {
                return false
            };
            if wait.is_zero() {
                requests.charge(1.0);
                bytes.charge(budget);
                return true
            }
            wait
        };
        let Some(at) = tokio::time::Instant::now().checked_add(wait) else { return false };
        if at > deadline {
            return false
        }
        // Only this turn charges the buckets, so the tokens are due on waking. A reply over its
        // budget, settled meanwhile, can lower the byte balance and take one more wait.
        tokio::time::sleep_until(at).await;
    }
}

/// Takes the slots a request on `lane` needs from `peer` and from the lane's `workers`, waiting
/// at most `wait`, or returns `None` when the lane is too busy.
///
/// A peer's requests over its share of the lane wait in turn, so a burst at one root is served
/// rather than answered empty.
async fn admit(
    lane: Lane,
    peer: &PeerState,
    workers: Arc<Semaphore>,
    wait: Duration,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    let per_peer = match lane {
        Lane::Hot => peer.hot.clone(),
        Lane::Cold => peer.cold.clone(),
    };
    let acquire = async {
        let per_peer = per_peer.acquire_owned().await.ok()?;
        let worker = workers.acquire_owned().await.ok()?;
        Some((per_peer, worker))
    };
    tokio::time::timeout(wait, acquire).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{verify_key, FakeFactory, FakeState};
    use alloy_primitives::{keccak256, U512};
    use reth_eth_wire_types::snap::{GetAccountRangeMessage, GetByteCodesMessage};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::{RangeResult, StorageRangeResult};
    use std::sync::atomic::AtomicUsize;

    /// Counts how many calls run at once inside a view, and how often a view was resolved.
    #[derive(Default)]
    struct Probe {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        resolutions: AtomicUsize,
        /// Calls to `lane`, `depth` and `retained_roots`.
        lane_calls: AtomicUsize,
        depth_calls: AtomicUsize,
        retained_calls: AtomicUsize,
        /// Views dropped, so idle views can be seen to be released.
        views_dropped: AtomicUsize,
        delay: Duration,
        /// How long a view takes to resolve, known root or not.
        resolve_delay: Duration,
        /// How long `retained_roots` takes.
        list_delay: Mutex<Duration>,
        /// Roots `retained_roots` lists after the ones in `lanes`.
        extra_listed: Mutex<Vec<crate::RetainedRoot>>,
        /// When each `retained_roots` call started.
        list_starts: Mutex<Vec<Instant>>,
        /// Whether `retained_roots` fails.
        listing_fails: AtomicBool,
    }

    struct ProbeView {
        inner: StateRangeView,
        probe: Arc<Probe>,
    }

    impl Drop for ProbeView {
        fn drop(&mut self) {
            self.probe.views_dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl StateRangeProvider for ProbeView {
        fn account_range(
            &self,
            start: B256,
            limit: B256,
            bytes: usize,
        ) -> RangeResult<(B256, reth_primitives_traits::Account)> {
            let now = self.probe.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.probe.max_in_flight.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.probe.delay);
            let out = self.inner.account_range(start, limit, bytes);
            self.probe.in_flight.fetch_sub(1, Ordering::SeqCst);
            out
        }
        fn storage_root_by_hash(&self, a: B256) -> ProviderResult<B256> {
            self.inner.storage_root_by_hash(a)
        }
        fn storage_range(&self, a: B256, s: B256, l: B256, b: usize) -> StorageRangeResult {
            self.inner.storage_range(a, s, l, b)
        }
        fn account_range_proof(&self, k: &[B256]) -> ProviderResult<Vec<Bytes>> {
            self.inner.account_range_proof(k)
        }
        fn storage_range_proof(&self, a: B256, k: &[B256]) -> ProviderResult<Vec<Bytes>> {
            self.inner.storage_range_proof(a, k)
        }
    }

    struct TestBackend {
        ranges: FakeFactory,
        lanes: HashMap<B256, Lane>,
        /// The lane of a root missing from `lanes`. `Some(Lane::Cold)` acts like a backend that
        /// cannot tell a cold root from an unknown one.
        default_lane: Option<Lane>,
        /// Whether `retained_roots` lists `lanes`.
        lists_roots: bool,
        codes: MockEthProvider,
        probe: Arc<Probe>,
    }

    impl StateRangeProviderFactory for TestBackend {
        fn state_range_provider(&self, root: B256) -> ProviderResult<Option<StateRangeView>> {
            self.probe.resolutions.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.probe.resolve_delay);
            Ok(self.ranges.state_range_provider(root)?.map(|inner| {
                Box::new(ProbeView { inner, probe: self.probe.clone() }) as StateRangeView
            }))
        }
    }

    impl crate::RootLanes for TestBackend {
        fn lane(&self, root: B256) -> Option<Lane> {
            self.probe.lane_calls.fetch_add(1, Ordering::SeqCst);
            self.lanes.get(&root).copied().or(self.default_lane)
        }

        fn depth(&self, _root: B256) -> Option<u64> {
            self.probe.depth_calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        fn retained_roots(&self) -> Option<Vec<crate::RetainedRoot>> {
            self.probe.retained_calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.probe.list_starts).push(Instant::now());
            // Like a real listing, it reads the chain first and returns later.
            let lists = self.lists_roots && !self.probe.listing_fails.load(Ordering::SeqCst);
            let roots = lists.then(|| {
                self.lanes
                    .iter()
                    .map(|(root, lane)| crate::RetainedRoot { root: *root, lane: *lane, depth: 0 })
                    .chain(lock(&self.probe.extra_listed).iter().copied())
                    .collect()
            });
            std::thread::sleep(*lock(&self.probe.list_delay));
            roots
        }
    }

    impl Snap1Backend for TestBackend {
        fn byte_codes(
            &self,
            req: &reth_eth_wire_types::snap::GetByteCodesMessage,
        ) -> ProviderResult<ByteCodesMessage> {
            crate::serve_byte_codes(&self.codes, req)
        }
    }

    const CODE: [u8; 2] = [0x60, 0x01];

    /// A backend with one state at `lane`, and its root.
    fn backend(lane: Lane, delay: Duration) -> (Arc<TestBackend>, B256, FakeState) {
        let (backend, root, state) = test_backend(lane, Probe { delay, ..Default::default() });
        (Arc::new(backend), root, state)
    }

    fn test_backend(lane: Lane, probe: Probe) -> (TestBackend, B256, FakeState) {
        let state = FakeState::generated(40, 0);
        let mut ranges = FakeFactory::default();
        let root = ranges.add(state.clone());
        let codes = MockEthProvider::default();
        codes.add_account(
            alloy_primitives::Address::with_last_byte(1),
            ExtendedAccount::new(0, Default::default()).with_bytecode(Bytes::from_static(&CODE)),
        );
        let backend = TestBackend {
            ranges,
            lanes: HashMap::from([(root, lane)]),
            default_lane: None,
            lists_roots: false,
            codes,
            probe: Arc::new(probe),
        };
        (backend, root, state)
    }

    fn peer(n: u8) -> PeerId {
        PeerId::repeat_byte(n)
    }

    fn one_key(root: B256, key: B256) -> Snap1Message {
        Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(GetAccountRangeMessage {
            request_id: 1,
            root_hash: root,
            starting_hash: key,
            limit_hash: key,
            response_bytes: 1,
        }))
    }

    fn accounts(msg: Option<Snap1Message>) -> AccountRangeMessage {
        match msg {
            Some(Snap1Message::Shared(SnapProtocolMessage::AccountRange(m))) => m,
            other => panic!("not an account range response: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sixty_four_concurrent_one_key_requests_from_one_peer_at_a_hot_root_are_served() {
        let (backend, root, state) = backend(Lane::Hot, Duration::from_millis(2));
        let server = Arc::new(Snap1Server::new(backend.clone(), Snap1Config::default()));
        let keys: Vec<B256> = state.accounts.keys().copied().take(8).collect();

        let mut tasks = Vec::new();
        for i in 0..64usize {
            let server = server.clone();
            let key = keys[i % keys.len()];
            tasks.push(tokio::spawn(async move {
                (key, accounts(server.handle(peer(1), one_key(root, key)).await))
            }));
        }
        for task in tasks {
            let (key, resp) = task.await.unwrap();
            assert_eq!(resp.accounts.len(), 1);
            let proof: Vec<Bytes> = resp.proof;
            let expected = alloy_rlp::encode(state.accounts[&key].trie_account());
            verify_key(root, key, Some(expected), &proof).unwrap();
        }
        // One peer runs at most its per-peer share, which 64 requests fill.
        assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), 4);
    }

    /// Three peers send twice their per-peer share of slow hot jobs, so every worker is busy
    /// and more wait. An honest peer's one-key request waits only behind the jobs that hold a
    /// per-peer slot, not behind every queued one, and is served within the hot queue timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_waits_only_for_the_per_peer_shares_other_peers_hold() {
        let job = Duration::from_millis(500);
        let (backend, root, state) = backend(Lane::Hot, job);
        let cfg = Snap1Config::default();
        let server = Arc::new(Snap1Server::new(backend.clone(), cfg.clone()));
        let key = *state.accounts.keys().next().unwrap();
        let flood: Vec<_> = (0..3 * 2 * cfg.hot_per_peer)
            .map(|i| {
                let server = server.clone();
                let from = peer(1 + (i % 3) as u8);
                tokio::spawn(async move { server.handle(from, one_key(root, key)).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(backend.probe.in_flight.load(Ordering::SeqCst), cfg.hot_workers);

        let asked = Instant::now();
        let honest = accounts(server.handle(peer(9), one_key(root, key)).await);
        let waited = asked.elapsed();
        assert_eq!(honest.accounts.len(), 1, "the honest peer is served");
        // 12 jobs hold a per-peer slot, so it runs in the second round of 8: after one job, not
        // three. That is well within the hot queue timeout.
        assert!(waited >= job + job / 2 && waited < 3 * job, "{waited:?}");
        for task in flood {
            assert_eq!(accounts(task.await.unwrap()).accounts.len(), 1);
        }
        assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), cfg.hot_workers);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_peer_takes_at_most_half_the_hot_workers() {
        // The default, and a per-peer cap set above the pool.
        for cfg in [Snap1Config::default(), Snap1Config { hot_per_peer: 16, ..Default::default() }]
        {
            let (backend, root, state) = backend(Lane::Hot, Duration::from_millis(300));
            let cfg = Snap1Config { hot_queue_timeout: Duration::from_millis(200), ..cfg };
            let server = Arc::new(Snap1Server::new(backend.clone(), cfg));
            let key = *state.accounts.keys().next().unwrap();
            let flood: Vec<_> = (0..16)
                .map(|_| {
                    let server = server.clone();
                    tokio::spawn(async move { server.handle(peer(1), one_key(root, key)).await })
                })
                .collect();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let other = accounts(server.handle(peer(2), one_key(root, key)).await);
            assert_eq!(other.accounts.len(), 1, "peer 2 must find a free worker");
            for task in flood {
                task.await.unwrap();
            }
            assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), 5);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cold_lane_never_exceeds_its_cap_and_answers_empty_when_busy() {
        let (backend, root, state) = backend(Lane::Cold, Duration::from_millis(300));
        let cfg = Snap1Config {
            cold_concurrency: 2,
            cold_queue_timeout: Duration::from_millis(50),
            view_cache_entries: 0,
            ..Default::default()
        };
        let server = Arc::new(Snap1Server::new(backend.clone(), cfg));
        let key = *state.accounts.keys().next().unwrap();

        let mut tasks = Vec::new();
        for i in 0..6u8 {
            let server = server.clone();
            tasks.push(tokio::spawn(async move {
                accounts(server.handle(peer(i), one_key(root, key)).await)
            }));
        }
        let mut served = 0;
        for task in tasks {
            let resp = task.await.unwrap();
            assert_eq!(resp.request_id, 1);
            served += usize::from(!resp.accounts.is_empty());
        }
        assert_eq!(served, 2);
        assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cold_lane_runs_one_request_per_peer() {
        let (backend, root, state) = backend(Lane::Cold, Duration::from_millis(200));
        let cfg = Snap1Config {
            view_cache_entries: 0,
            cold_queue_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let server = Arc::new(Snap1Server::new(backend.clone(), cfg));
        let key = *state.accounts.keys().next().unwrap();
        // The second request waits for the first one's per-peer slot, past its timeout.
        let (a, b) = tokio::join!(
            server.handle(peer(1), one_key(root, key)),
            server.handle(peer(1), one_key(root, key)),
        );
        let served = usize::from(!accounts(a).accounts.is_empty()) +
            usize::from(!accounts(b).accounts.is_empty());
        assert_eq!(served, 1);
        assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_burst_from_one_peer_at_a_cold_root_is_served_in_turn() {
        // reth-lite sends the misses of an eth_call at the finalized block all at once.
        let (backend, root, state) = backend(Lane::Cold, Duration::from_millis(20));
        let server = Snap1Server::new(backend.clone(), Snap1Config::default());
        let keys: Vec<B256> = state.accounts.keys().copied().take(16).collect();
        let replies = futures::future::join_all(
            keys.iter().map(|&key| server.handle(peer(1), one_key(root, key))),
        )
        .await;
        let empty = replies.into_iter().filter(|r| accounts(r.clone()).accounts.is_empty());
        assert_eq!(empty.count(), 0);
        assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cold_views_are_cached_for_the_ttl() {
        let (backend, root, state) = backend(Lane::Cold, Duration::ZERO);
        let cfg = Snap1Config { view_cache_ttl: Duration::from_millis(150), ..Default::default() };
        let server = Snap1Server::new(backend.clone(), cfg);
        let key = *state.accounts.keys().next().unwrap();
        for _ in 0..3 {
            assert_eq!(
                accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len(),
                1
            );
        }
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(250)).await;
        server.handle(peer(1), one_key(root, key)).await;
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_bucket_answers_empty_beyond_the_burst() {
        let (backend, root, state) = backend(Lane::Hot, Duration::ZERO);
        // The bucket refills too slowly for a waiting request to get a token in time.
        let cfg = Snap1Config {
            hot_rate: 1,
            hot_burst: 3,
            hot_queue_timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let server = Snap1Server::new(backend, cfg);
        let key = *state.accounts.keys().next().unwrap();
        let mut served = Vec::new();
        let started = Instant::now();
        for _ in 0..5 {
            let resp = accounts(server.handle(peer(1), one_key(root, key)).await);
            served.push(!resp.accounts.is_empty());
        }
        assert_eq!(served, [true, true, true, false, false]);
        // A request whose token comes after the queue timeout does not wait for it.
        assert!(started.elapsed() < Duration::from_millis(150), "{:?}", started.elapsed());
        // Another peer has its own bucket.
        let other = accounts(server.handle(peer(2), one_key(root, key)).await);
        assert_eq!(other.accounts.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn requests_over_the_rate_wait_for_their_token_and_are_served() {
        let (backend, root, state) = backend(Lane::Hot, Duration::ZERO);
        let cfg = Snap1Config { hot_rate: 20, hot_burst: 2, ..Default::default() };
        let server = Snap1Server::new(backend, cfg);
        let key = *state.accounts.keys().next().unwrap();
        let started = Instant::now();
        let replies =
            futures::future::join_all((0..10).map(|_| server.handle(peer(1), one_key(root, key))))
                .await;
        let served = replies.into_iter().filter(|r| accounts(r.clone()).accounts.len() == 1);
        assert_eq!(served.count(), 10);
        // Eight requests waited for a token at 20 per second.
        assert!(started.elapsed() >= Duration::from_millis(350), "{:?}", started.elapsed());
    }

    #[test]
    fn paced_requests_take_their_tokens_in_arrival_order_and_wake_about_once() {
        use futures::StreamExt;
        let (backend, _, _) = backend(Lane::Hot, Duration::ZERO);
        let cfg = Snap1Config { hot_rate: 100, hot_burst: 1, ..Default::default() };
        let (order, polls) = with_paused_time(async {
            let state = Snap1Server::new(backend, cfg).new_peer();
            let start = tokio::time::Instant::now();
            let deadline = start + Duration::from_secs(2);
            let order = Mutex::new(Vec::new());
            // 64 waiters, one connection's running requests, for 64 tokens due 10 ms apart.
            let polls: Vec<usize> = (0..64)
                .map(|i| {
                    let (state, order) = (&state, &order);
                    async move {
                        let mut paced = std::pin::pin!(pace(state, 1.0, deadline));
                        let mut polls = 0;
                        let granted = std::future::poll_fn(|cx| {
                            polls += 1;
                            paced.as_mut().poll(cx)
                        })
                        .await;
                        assert!(granted, "waiter {i} refused at {:?}", start.elapsed());
                        lock(order).push(i);
                        polls
                    }
                })
                .collect::<futures::stream::FuturesOrdered<_>>()
                .collect()
                .await;
            (order.into_inner().unwrap(), polls)
        });
        assert_eq!(order, (0..64).collect::<Vec<_>>());
        // A first poll, the turn, and the token: three, where waiters racing for each token
        // would wake once per token ahead of them.
        assert!(polls.iter().all(|&p| p <= 3), "{polls:?}");
    }

    #[test]
    fn a_waiter_dropped_in_its_sleep_charges_nothing_and_passes_its_turn() {
        let (backend, _, _) = backend(Lane::Hot, Duration::ZERO);
        let cfg = Snap1Config { hot_rate: 10, hot_burst: 1, byte_rate: 0, ..Default::default() };
        let budget = 1000.0;
        let (waited, requests, bytes) = with_paused_time(async {
            let state = Snap1Server::new(backend, cfg.clone()).new_peer();
            let start = tokio::time::Instant::now();
            let deadline = start + Duration::from_secs(2);
            assert!(pace(&state, budget, deadline).await);
            // The next token is 100 ms away: this waiter takes the turn and sleeps, then goes.
            let dropped =
                tokio::time::timeout(Duration::from_millis(50), pace(&state, budget, deadline));
            assert!(dropped.await.is_err());
            assert!(pace(&state, budget, deadline).await);
            let requests = lock(&state.bucket).tokens;
            let bytes = lock(&state.bytes).tokens;
            (start.elapsed(), requests, bytes)
        });
        // Had the dropped waiter kept a token, the last one would wait until 200 ms.
        assert_eq!(waited, Duration::from_millis(100));
        assert!(requests.abs() < 1e-9, "{requests}");
        assert_eq!(bytes, budget.mul_add(-2.0, f64::from(cfg.byte_burst)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reth_lite_refresh_through_the_default_limits_gets_no_empty_answer() {
        use futures::StreamExt;
        let (backend, root, state) = backend(Lane::Hot, Duration::ZERO);
        let server = Snap1Server::new(backend, Snap1Config::default());
        let keys: Vec<B256> = state.accounts.keys().copied().collect();
        // reth-lite sends one request per key, 32 at a time, with no pacing: a hot-set refresh
        // of 2000 slots and accounts is about 4000 requests per head.
        let empty = futures::stream::iter(0..4000usize)
            .map(|i| server.handle(peer(1), one_key(root, keys[i % keys.len()])))
            .buffer_unordered(32)
            .filter(|r| std::future::ready(accounts(r.clone()).accounts.is_empty()))
            .count()
            .await;
        assert_eq!(empty, 0);
    }

    /// A server whose backend holds a 100 KB code, the code's hash, and a request for ten copies
    /// of it with a 1 MiB reply budget: a reply of about 1 MB.
    fn big_code_server(cfg: Snap1Config) -> (Snap1Server<TestBackend>, Snap1Message) {
        let (backend, _, _) = test_backend(Lane::Hot, Probe::default());
        let code = Bytes::from(vec![0x5b; 100_000]);
        backend.codes.add_account(
            alloy_primitives::Address::with_last_byte(2),
            ExtendedAccount::new(0, Default::default()).with_bytecode(code.clone()),
        );
        let request =
            Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
                request_id: 1,
                hashes: vec![keccak256(&code); 10],
                response_bytes: 1 << 20,
            }));
        (Snap1Server::new(Arc::new(backend), cfg), request)
    }

    fn code_count(msg: Option<Snap1Message>) -> usize {
        match msg {
            Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) => m.codes.len(),
            other => panic!("not a byte codes response: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reply_bytes_are_limited_per_peer() {
        let cfg = Snap1Config { byte_rate: 0, byte_burst: 2 << 20, ..Default::default() };
        let (server, request) = big_code_server(cfg);
        let mut served = Vec::new();
        for _ in 0..5 {
            served.push(code_count(server.handle(peer(1), request.clone()).await));
        }
        // The third reply starts with bytes left and takes the bucket into debt.
        assert_eq!(served, [10, 10, 10, 0, 0]);
        // Another peer has its own byte budget.
        assert_eq!(code_count(server.handle(peer(2), request).await), 10);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_reply_budget_is_charged_before_the_work() {
        let cfg = Snap1Config { byte_rate: 0, byte_burst: 2 << 20, ..Default::default() };
        let (server, request) = big_code_server(cfg);
        let server = Arc::new(server);
        // With every worker held, no reply is known until all eight passed the byte bucket, so
        // only the budget can limit them.
        let workers = u32::try_from(server.cfg.hot_workers).unwrap();
        let held = server.hot_workers.clone().acquire_many_owned(workers).await.unwrap();
        let replies = tokio::spawn({
            let server = server.clone();
            async move {
                futures::future::join_all((0..8).map(|_| server.handle(peer(1), request.clone())))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        let served: Vec<usize> = replies.await.unwrap().into_iter().map(code_count).collect();
        assert_eq!(served, [10, 10, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_the_byte_bucket_refuses_spends_no_request_token() {
        let cfg = Snap1Config {
            hot_rate: 0,
            hot_burst: 10,
            hot_queue_timeout: Duration::from_millis(20),
            byte_rate: 0,
            byte_burst: 1 << 20,
            ..Default::default()
        };
        let (server, request) = big_code_server(cfg);
        let mut served = Vec::new();
        for _ in 0..6 {
            served.push(code_count(server.handle(peer(1), request.clone()).await));
        }
        // The second reply starts with bytes left and takes the bucket into debt.
        assert_eq!(served, [10, 10, 0, 0, 0, 0]);
        assert_eq!(lock(&server.peer(peer(1)).bucket).tokens, 8.0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_dropped_before_its_reply_refunds_its_reply_budget() {
        let burst = 2 << 20;
        let cfg = Snap1Config { byte_rate: 0, byte_burst: burst, ..Default::default() };
        let (server, request) = big_code_server(cfg);
        // The request is charged, then waits for a worker until its peer goes away.
        let workers = u32::try_from(server.cfg.hot_workers).unwrap();
        let held = server.hot_workers.clone().acquire_many_owned(workers).await.unwrap();
        let fut = server.handle(peer(1), request.clone());
        assert!(tokio::time::timeout(Duration::from_millis(50), fut).await.is_err());
        drop(held);
        assert_eq!(lock(&server.peer(peer(1)).bytes).tokens, f64::from(burst));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_dropped_after_its_job_starts_keeps_its_reply_budget() {
        let (backend, root, state) = backend(Lane::Hot, Duration::from_millis(300));
        let burst = 2 << 20;
        let cfg = Snap1Config { byte_rate: 0, byte_burst: burst, ..Default::default() };
        let server = Snap1Server::new(backend.clone(), cfg);
        let key = *state.accounts.keys().next().unwrap();
        let budget = 1 << 20;
        let request =
            Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(GetAccountRangeMessage {
                request_id: 1,
                root_hash: root,
                starting_hash: key,
                limit_hash: key,
                response_bytes: budget,
            }));
        // The peer goes away while the provider works, which must not make the work free.
        let fut = server.handle(peer(1), request);
        assert!(tokio::time::timeout(Duration::from_millis(50), fut).await.is_err());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 1);
        assert_eq!(lock(&server.peer(peer(1)).bytes).tokens, f64::from(burst) - budget as f64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_dropped_after_its_job_starts_pays_at_least_its_reply() {
        let (backend, root, state) = backend(Lane::Hot, Duration::from_millis(300));
        let burst = 2 << 20;
        let cfg = Snap1Config { byte_rate: 0, byte_burst: burst, ..Default::default() };
        let server = Snap1Server::new(backend.clone(), cfg);
        // reth-lite's shape: a 1-byte budget still gets one account and its proofs.
        let request = one_key(root, *state.accounts.keys().next().unwrap());
        let reply = body_len(&server.handle(peer(2), request.clone()).await.unwrap());
        assert!(reply > 1, "{reply}");
        let fut = server.handle(peer(1), request);
        assert!(tokio::time::timeout(Duration::from_millis(50), fut).await.is_err());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 2);
        assert_eq!(lock(&server.peer(peer(1)).bytes).tokens, f64::from(burst) - reply as f64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_root_is_answered_empty_on_both_paths() {
        let (backend, root, state) = backend(Lane::Cold, Duration::ZERO);
        let server = Snap1Server::new(backend, Snap1Config::default());
        let key = *state.accounts.keys().next().unwrap();
        // No lane for the root.
        let unknown = B256::repeat_byte(0xab);
        let resp = accounts(server.handle(peer(1), one_key(unknown, key)).await);
        assert!(resp.accounts.is_empty() && resp.proof.is_empty() && resp.request_id == 1);
        // A lane, but the view does not resolve: also empty, never an error.
        let mut lanes = HashMap::new();
        lanes.insert(unknown, Lane::Cold);
        let backend = TestBackend {
            ranges: FakeFactory::default(),
            lanes,
            default_lane: None,
            lists_roots: false,
            codes: MockEthProvider::default(),
            probe: Arc::default(),
        };
        let server = Snap1Server::new(Arc::new(backend), Snap1Config::default());
        let resp = accounts(server.handle(peer(1), one_key(unknown, key)).await);
        assert!(resp.accounts.is_empty());
        let _ = root;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn byte_codes_and_trie_nodes_are_served() {
        let (backend, root, _) = backend(Lane::Hot, Duration::ZERO);
        let server = Snap1Server::new(backend, Snap1Config::default());
        let codes = server
            .handle(
                peer(1),
                Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
                    request_id: 5,
                    hashes: vec![keccak256(CODE)],
                    response_bytes: 1 << 20,
                })),
            )
            .await;
        match codes {
            Some(Snap1Message::Shared(SnapProtocolMessage::ByteCodes(m))) => {
                assert_eq!(m.request_id, 5);
                assert_eq!(m.codes, vec![Bytes::from_static(&CODE)]);
            }
            other => panic!("unexpected {other:?}"),
        }
        let nodes = server
            .handle(
                peer(1),
                Snap1Message::GetTrieNodes(crate::GetTrieNodesMessage {
                    request_id: 6,
                    root_hash: root,
                    paths: vec![vec![Bytes::from_static(&[0x00])]],
                    response_bytes: 1 << 20,
                }),
            )
            .await;
        match nodes {
            Some(Snap1Message::TrieNodes(m)) => {
                assert_eq!(m.request_id, 6);
                assert_eq!(keccak256(&m.nodes[0]), root);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_requests_keep_their_slots_until_the_job_ends() {
        let (backend, root, state) = backend(Lane::Hot, Duration::from_millis(400));
        let cfg = Snap1Config { hot_workers: 2, ..Default::default() };
        let server = Arc::new(Snap1Server::new(backend.clone(), cfg));
        let key = *state.accounts.keys().next().unwrap();
        // Each request is dropped 20 ms in, as when its peer disconnects. The blocking job of an
        // admitted request runs on, so its slot must stay taken.
        for i in 0..8u8 {
            let fut = server.handle(peer(i), one_key(root, key));
            assert!(tokio::time::timeout(Duration::from_millis(20), fut).await.is_err());
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(backend.probe.max_in_flight.load(Ordering::SeqCst), 2);
        // A request dropped while it waits for a slot never runs.
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 2);
        // The slots come back when the jobs end.
        assert_eq!(accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reconnecting_peer_keeps_its_spent_bucket() {
        let (backend, root, state) = backend(Lane::Hot, Duration::ZERO);
        let cfg = Snap1Config { hot_rate: 0, hot_burst: 3, ..Default::default() };
        let server = Snap1Server::new(backend, cfg);
        let key = *state.accounts.keys().next().unwrap();
        server.peer_connected(peer(1));
        for _ in 0..3 {
            assert_eq!(
                accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len(),
                1
            );
        }
        server.peer_disconnected(peer(1));
        server.peer_connected(peer(1));
        let resp = accounts(server.handle(peer(1), one_key(root, key)).await);
        assert!(resp.accounts.is_empty(), "a reconnect must not refill the bucket");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closing_one_of_two_connections_keeps_the_peer_live() {
        let (backend, root, state) = backend(Lane::Hot, Duration::ZERO);
        let cooldown = Duration::from_millis(50);
        let cfg = Snap1Config {
            hot_rate: 0,
            hot_burst: 3,
            peer_cooldown: cooldown,
            ..Default::default()
        };
        let server = Snap1Server::new(backend, cfg);
        let key = *state.accounts.keys().next().unwrap();
        // A reconnect: the new connection opens before the old one closes.
        server.peer_connected(peer(1));
        server.peer_connected(peer(1));
        for _ in 0..3 {
            assert_eq!(
                accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len(),
                1
            );
        }
        server.peer_disconnected(peer(1));
        assert!(server.lock_peers().contains_key(&peer(1)), "one connection is still open");
        // The live connection's spent bucket must not expire with the cool-down.
        tokio::time::sleep(cooldown * 2).await;
        let resp = accounts(server.handle(peer(1), one_key(root, key)).await);
        assert!(resp.accounts.is_empty(), "the live peer's bucket was refilled");
        server.peer_disconnected(peer(1));
        assert!(!server.lock_peers().contains_key(&peer(1)));
        assert!(lock(&server.cooling).contains_key(&peer(1)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_rate_limited_flood_does_not_touch_the_backend() {
        let (backend, root, state) = backend(Lane::Hot, Duration::ZERO);
        let cfg = Snap1Config { hot_rate: 0, hot_burst: 3, ..Default::default() };
        let server = Snap1Server::new(backend.clone(), cfg);
        let key = *state.accounts.keys().next().unwrap();
        let mut served = 0;
        for _ in 0..100 {
            served += accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len();
        }
        assert_eq!(served, 3);
        // Only the three admitted requests look up their root, once each.
        assert_eq!(backend.probe.lane_calls.load(Ordering::SeqCst), 3);
        assert!(backend.probe.depth_calls.load(Ordering::SeqCst) <= 3);
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_backend_that_lists_its_roots_is_asked_once_per_refresh() {
        let (mut backend, root, state) = test_backend(Lane::Hot, Probe::default());
        backend.lists_roots = true;
        let backend = Arc::new(backend);
        let server = Snap1Server::new(backend.clone(), Snap1Config::default());
        let key = *state.accounts.keys().next().unwrap();
        for i in 0..50u8 {
            assert_eq!(
                accounts(server.handle(peer(i), one_key(root, key)).await).accounts.len(),
                1
            );
        }
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.probe.lane_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.probe.depth_calls.load(Ordering::SeqCst), 0);
    }

    /// A server whose backend lists its roots, each listing taking `list_delay`.
    fn listing_server(
        list_delay: Duration,
        cfg: Snap1Config,
    ) -> (Arc<TestBackend>, Snap1Server<TestBackend>, Snap1Message) {
        let probe = Probe { list_delay: Mutex::new(list_delay), ..Default::default() };
        let (mut backend, root, state) = test_backend(Lane::Hot, probe);
        backend.lists_roots = true;
        let backend = Arc::new(backend);
        let key = *state.accounts.keys().next().unwrap();
        (backend.clone(), Snap1Server::new(backend, cfg), one_key(root, key))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_that_is_never_polled_again_does_not_hold_the_root_listing() {
        let (backend, server, request) =
            listing_server(Duration::from_millis(200), Snap1Config::default());
        // Peer 1's request starts the listing, then its session stops polling it.
        let mut stalled = Box::pin(server.handle(peer(1), request.clone()));
        assert!(tokio::time::timeout(Duration::from_millis(20), stalled.as_mut()).await.is_err());
        let other = tokio::time::timeout(Duration::from_secs(5), server.handle(peer(2), request))
            .await
            .expect("peer 2 must not wait on peer 1's request");
        assert_eq!(accounts(other).accounts.len(), 1);
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 1);
        drop(stalled);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn requests_that_are_never_polled_again_do_not_hold_worker_slots() {
        for lane in Lane::ALL {
            let (backend, root, state) = backend(lane, Duration::ZERO);
            // Two workers per lane give each peer one slot, so two stalled peers could hold a lane.
            let cfg = Snap1Config {
                hot_workers: 2,
                hot_queue_timeout: Duration::from_millis(500),
                cold_concurrency: 2,
                cold_queue_timeout: Duration::from_millis(500),
                view_cache_entries: 0,
                ..Default::default()
            };
            let server = Arc::new(Snap1Server::new(backend, cfg));
            let key = *state.accounts.keys().next().unwrap();
            let workers = match lane {
                Lane::Hot => server.hot_workers.clone(),
                Lane::Cold => server.cold_workers.clone(),
            };
            let held = workers.acquire_many_owned(2).await.unwrap();
            // Peers 1 and 3 queue behind the full lane, then their sessions stop polling them.
            let mut stalled: Vec<_> = [1, 3]
                .map(|n| Box::pin(server.handle(peer(n), one_key(root, key))))
                .into_iter()
                .collect();
            for request in &mut stalled {
                assert!(tokio::time::timeout(Duration::from_millis(20), request.as_mut())
                    .await
                    .is_err());
            }
            drop(held);
            let other = accounts(server.handle(peer(2), one_key(root, key)).await);
            assert_eq!(other.accounts.len(), 1, "{lane:?}: peer 2 must find a free worker");
            drop(stalled);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_request_keeps_the_listing_it_started() {
        let (backend, server, request) =
            listing_server(Duration::from_millis(100), Snap1Config::default());
        let started = server.handle(peer(1), request.clone());
        assert!(tokio::time::timeout(Duration::from_millis(20), started).await.is_err());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(accounts(server.handle(peer(2), request).await).accounts.len(), 1);
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_listing_is_waited_for_a_bounded_time_then_the_last_list_answers() {
        let cfg = Snap1Config {
            roots_ttl: Duration::from_millis(50),
            roots_min_refresh: Duration::from_millis(10),
            ..Default::default()
        };
        let slow = ROOTS_LISTING_WAIT + Duration::from_millis(300);
        let (backend, server, request) = listing_server(slow, cfg);
        // No list yet: the root is answered empty once the wait ends.
        let begun = Instant::now();
        assert!(accounts(server.handle(peer(1), request.clone()).await).accounts.is_empty());
        let waited = begun.elapsed();
        assert!(waited >= ROOTS_LISTING_WAIT && waited < ROOTS_LISTING_WAIT * 2, "{waited:?}");
        // Once a list exists, a slow refresh falls back to it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 1);
        assert!(lock(&server.roots).listed.is_some());
        assert_eq!(accounts(server.handle(peer(2), request).await).accounts.len(), 1);
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_listings_are_spaced_by_the_minimum_refresh_from_their_end() {
        let list_delay = Duration::from_millis(150);
        let cfg = Snap1Config::default();
        let gap = list_delay + cfg.roots_min_refresh;
        let (backend, server, request) = listing_server(list_delay, cfg);
        let Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(known)) = request else {
            unreachable!()
        };
        // Each unknown root needs a listing that starts after it was asked.
        for i in 0..4u8 {
            let unknown = one_key(B256::repeat_byte(i), known.starting_hash);
            assert!(accounts(server.handle(peer(1), unknown).await).accounts.is_empty());
        }
        let starts = lock(&backend.probe.list_starts).clone();
        assert_eq!(starts.len(), 4);
        for pair in starts.windows(2) {
            let spacing = pair[1].duration_since(pair[0]);
            assert!(spacing >= gap, "listings started {spacing:?} apart, less than {gap:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_root_is_looked_up_in_a_listing_that_starts_after_the_request() {
        let probe =
            Probe { list_delay: Mutex::new(Duration::from_millis(150)), ..Default::default() };
        let (mut backend, root, state) = test_backend(Lane::Hot, probe);
        backend.lists_roots = true;
        // Two head states the backend lists only once their blocks are imported.
        let heads = [FakeState::generated(41, 0), FakeState::generated(42, 0)];
        let roots = heads.clone().map(|head| backend.ranges.add(head));
        let backend = Arc::new(backend);
        let server = Arc::new(Snap1Server::new(backend.clone(), Snap1Config::default()));
        let import = |n: usize| {
            lock(&backend.probe.extra_listed).push(crate::RetainedRoot {
                root: roots[n],
                lane: Lane::Hot,
                depth: 0,
            });
        };
        let ask = |n: usize| one_key(roots[n], *heads[n].accounts.keys().next().unwrap());

        // A listing starts, the block is imported, and its root is asked while the listing runs.
        let first = tokio::spawn({
            let server = server.clone();
            let key = *state.accounts.keys().next().unwrap();
            async move { server.handle(peer(1), one_key(root, key)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        import(0);
        let during = accounts(server.handle(peer(2), ask(0)).await);
        assert_eq!(during.accounts.len(), 1, "asked while an older listing ran");
        assert_eq!(accounts(first.await.unwrap()).accounts.len(), 1);

        // The next block's root is asked right after a listing ended.
        *lock(&backend.probe.list_delay) = Duration::ZERO;
        import(1);
        let after = accounts(server.handle(peer(2), ask(1)).await);
        assert_eq!(after.accounts.len(), 1, "asked right after a listing ended");
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_listing_falls_back_to_the_last_list_for_one_more_ttl() {
        let (mut backend, root, state) = test_backend(Lane::Hot, Probe::default());
        // Like `ProviderBackend`, the backend places no root without a listing.
        backend.lanes.clear();
        backend.lists_roots = true;
        lock(&backend.probe.extra_listed).push(crate::RetainedRoot {
            root,
            lane: Lane::Hot,
            depth: 0,
        });
        let backend = Arc::new(backend);
        let ttl = Duration::from_millis(200);
        let cfg = Snap1Config {
            roots_ttl: ttl,
            roots_min_refresh: Duration::from_millis(10),
            ..Default::default()
        };
        let server = Snap1Server::new(backend.clone(), cfg);
        let request = one_key(root, *state.accounts.keys().next().unwrap());
        assert_eq!(accounts(server.handle(peer(1), request.clone()).await).accounts.len(), 1);

        // The list is past its TTL and the next listing fails.
        backend.probe.listing_fails.store(true, Ordering::SeqCst);
        tokio::time::sleep(ttl + Duration::from_millis(20)).await;
        assert_eq!(
            accounts(server.handle(peer(1), request.clone()).await).accounts.len(),
            1,
            "a failed listing must not empty the last list's roots"
        );
        assert_eq!(backend.probe.retained_calls.load(Ordering::SeqCst), 2);

        // Two TTLs after the last good listing started, the fallback ends.
        tokio::time::sleep(ttl).await;
        assert!(accounts(server.handle(peer(1), request).await).accounts.is_empty());
        assert_eq!(backend.probe.lane_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_root_listed_hot_and_cold_is_served_on_the_hot_lane() {
        let probe = Probe { delay: Duration::from_millis(100), ..Default::default() };
        let (mut backend, root, state) = test_backend(Lane::Hot, probe);
        backend.lists_roots = true;
        // A persisted block deeper down has the same root, as when no block between changed state.
        lock(&backend.probe.extra_listed).push(crate::RetainedRoot {
            root,
            lane: Lane::Cold,
            depth: 10,
        });
        let cfg = Snap1Config { view_cache_entries: 0, ..Default::default() };
        let server = Snap1Server::new(Arc::new(backend), cfg);
        let key = *state.accounts.keys().next().unwrap();
        // The cold lane runs one request per peer, the hot lane more.
        let (a, b) = tokio::join!(
            server.handle(peer(1), one_key(root, key)),
            server.handle(peer(1), one_key(root, key)),
        );
        assert_eq!((accounts(a).accounts.len(), accounts(b).accounts.len()), (1, 1));
        assert_eq!(
            lock(&server.roots).last_listed(root, &server.cfg),
            RootLookup::Known(Lane::Hot, Some(0))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_roots_do_not_take_cold_slots() {
        let probe = Probe {
            delay: Duration::from_millis(50),
            resolve_delay: Duration::from_millis(300),
            ..Default::default()
        };
        let (mut backend, root, state) = test_backend(Lane::Cold, probe);
        // An unknown root looks cold, but the listed roots tell.
        backend.default_lane = Some(Lane::Cold);
        backend.lists_roots = true;
        let backend = Arc::new(backend);
        let cfg = Snap1Config {
            cold_concurrency: 2,
            cold_queue_timeout: Duration::from_millis(50),
            view_cache_entries: 0,
            ..Default::default()
        };
        let server = Arc::new(Snap1Server::new(backend.clone(), cfg));
        let key = *state.accounts.keys().next().unwrap();
        let mut flood = Vec::new();
        for i in 10..20u8 {
            let server = server.clone();
            flood.push(tokio::spawn(async move {
                accounts(server.handle(peer(i), one_key(B256::repeat_byte(i), key)).await)
            }));
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        let known = accounts(server.handle(peer(1), one_key(root, key)).await);
        assert_eq!(known.accounts.len(), 1, "a known cold root still finds a slot");
        for task in flood {
            assert!(task.await.unwrap().accounts.is_empty());
        }
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 1, "only the known root");
    }

    /// The number of samples of each histogram in `snapshot`, by name and labels.
    ///
    /// Taking a snapshot drains the histograms, so take one and read it all.
    fn histogram_samples(
        snapshot: metrics_util::debugging::Snapshot,
    ) -> HashMap<(String, Vec<(String, String)>), usize> {
        snapshot
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| {
                let metrics_util::debugging::DebugValue::Histogram(samples) = value else {
                    return None
                };
                let key = key.key();
                let labels =
                    key.labels().map(|l| (l.key().to_owned(), l.value().to_owned())).collect();
                Some(((key.name().to_owned(), labels), samples.len()))
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn latency_and_depth_are_recorded_only_for_requests_that_ran() {
        let probe = Probe { delay: Duration::from_millis(100), ..Default::default() };
        let (mut backend, root, state) = test_backend(Lane::Cold, probe);
        backend.lists_roots = true;
        let cfg = Snap1Config {
            hot_rate: 0,
            hot_burst: 2,
            cold_queue_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // The metric handles bind to the recorder they are created under.
        let server =
            metrics::with_local_recorder(&recorder, || Snap1Server::new(Arc::new(backend), cfg));
        let key = *state.accounts.keys().next().unwrap();
        // Served, EmptyBusy (the second waits past the timeout for the peer's one cold slot),
        // RateLimited, EmptyUnknownRoot.
        let (a, b) = tokio::join!(
            server.handle(peer(1), one_key(root, key)),
            server.handle(peer(1), one_key(root, key)),
        );
        assert_eq!(accounts(a).accounts.len() + accounts(b).accounts.len(), 1);
        assert!(accounts(server.handle(peer(1), one_key(root, key)).await).accounts.is_empty());
        let unknown = one_key(B256::repeat_byte(0xab), key);
        assert!(accounts(server.handle(peer(2), unknown).await).accounts.is_empty());

        let samples = histogram_samples(snapshotter.snapshot());
        let latency = |lane: &str| {
            let labels = [("message", "get_account_range"), ("lane", lane)]
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .to_vec();
            samples.get(&("pulsechain_snap1.serve_latency_seconds".to_owned(), labels)).copied()
        };
        assert_eq!((latency("cold"), latency("hot")), (Some(1), Some(0)));
        let depth = samples.get(&("pulsechain_snap1.root_depth".to_owned(), Vec::new())).copied();
        assert_eq!(depth, Some(1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn idle_cold_views_are_released_after_the_ttl() {
        let (backend, root, state) = backend(Lane::Cold, Duration::ZERO);
        let cfg = Snap1Config { view_cache_ttl: Duration::from_millis(100), ..Default::default() };
        let server = Snap1Server::new(backend.clone(), cfg);
        let key = *state.accounts.keys().next().unwrap();
        assert_eq!(accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len(), 1);
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 1);
        // No request comes after it, yet the view and its read transaction must go.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(backend.probe.views_dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn response_shaped_messages_get_no_answer() {
        let (backend, _, _) = backend(Lane::Hot, Duration::ZERO);
        let server = Snap1Server::new(backend, Snap1Config::default());
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
            assert!(server.handle(peer(1), msg).await.is_none());
        }
    }

    /// Runs `body` on a current-thread runtime whose clock moves only when the test advances it.
    fn with_paused_time<T>(body: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(body)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Over any span of time a request bucket grants at most its burst plus its refill over
        /// that span, so idle time never saves up more than the burst.
        #[test]
        fn a_request_bucket_grants_at_most_its_burst_plus_its_refill(
            rate in 0u32..50,
            burst in 0u32..20,
            steps in proptest::collection::vec((0u64..3000, 0usize..40), 0..30),
        ) {
            with_paused_time(async {
                let start = tokio::time::Instant::now();
                let mut bucket = Bucket::new(rate, burst);
                // The time and the grants so far after each step, from the bucket's creation.
                let mut marks = vec![(Duration::ZERO, 0u32)];
                for (wait, takes) in steps {
                    tokio::time::advance(Duration::from_millis(wait)).await;
                    let mut granted = marks.last().unwrap().1;
                    for _ in 0..takes {
                        if bucket.time_to(1.0) == Some(Duration::ZERO) {
                            bucket.charge(1.0);
                            granted += 1;
                        }
                    }
                    let now = start.elapsed();
                    for &(then, before) in &marks {
                        let refill = (now - then).as_secs_f64() * f64::from(rate);
                        proptest::prop_assert!(
                            f64::from(granted - before) <= f64::from(burst) + refill + 1e-6,
                            "{} granted in {:?}, burst {}, refill {}",
                            granted - before, now - then, burst, refill
                        );
                    }
                    marks.push((now, granted));
                }
                Ok(())
            })?;
        }

        /// Over any span of time a byte bucket gives out at most its burst plus its refill over
        /// that span plus the largest budget, counting each admitted budget less what settling
        /// returns. Requests settle in any order after others were admitted, as concurrent
        /// requests do.
        #[test]
        fn a_byte_bucket_pays_at_most_its_burst_plus_its_refill_plus_one_budget(
            rate in 0u32..10_000,
            burst in 0u32..20_000,
            steps in proptest::collection::vec(
                (0u64..500, proptest::option::of((0u32..8000, 0u32..=100))),
                0..60,
            ),
        ) {
            with_paused_time(async {
                let start = tokio::time::Instant::now();
                let mut bucket = Bucket::new(rate, burst);
                // Admitted budgets with their real sizes, not yet settled.
                let mut pending = VecDeque::new();
                let mut marks = vec![(Duration::ZERO, 0f64)];
                let mut largest = 0f64;
                for (wait, charge) in steps {
                    tokio::time::advance(Duration::from_millis(wait)).await;
                    let mut given = marks.last().unwrap().1;
                    match charge {
                        Some((budget, percent)) => {
                            let budget = f64::from(budget);
                            if bucket.time_to(f64::MIN_POSITIVE) == Some(Duration::ZERO) {
                                bucket.charge(budget);
                                given += budget;
                                largest = largest.max(budget);
                                pending.push_back((budget, budget * f64::from(percent) / 100.0));
                            }
                        }
                        None => {
                            if let Some((budget, actual)) = pending.pop_front() {
                                bucket.settle(budget, actual);
                                given -= budget - actual;
                            }
                        }
                    }
                    let now = start.elapsed();
                    for &(then, before) in &marks {
                        let refill = (now - then).as_secs_f64() * f64::from(rate);
                        proptest::prop_assert!(
                            given - before <= f64::from(burst) + refill + largest + 1e-6,
                            "{} given in {:?}, burst {}, refill {}, largest {}",
                            given - before, now - then, burst, refill, largest
                        );
                    }
                    marks.push((now, given));
                }
                Ok(())
            })?;
        }

        /// Waiting the time a bucket names brings its balance to the level, so a paced request
        /// wakes to find its token.
        #[test]
        fn waiting_the_named_time_reaches_the_level(
            rate in 1u32..10_000,
            burst in 1u32..20_000,
            spent in 0u32..40_000,
            percent in 1u32..=100,
        ) {
            with_paused_time(async {
                let mut bucket = Bucket::new(rate, burst);
                bucket.charge(f64::from(spent));
                let level = f64::from(burst) * f64::from(percent) / 100.0;
                let wait = bucket.time_to(level).expect("a refilling bucket reaches its burst");
                tokio::time::advance(wait + Duration::from_millis(1)).await;
                proptest::prop_assert_eq!(bucket.time_to(level), Some(Duration::ZERO));
                Ok(())
            })?;
        }

        /// A root lookup gives a root only the lane and depth the list holds for it, says a root
        /// is not retained only from a listing that started after the request, and trusts an
        /// older listing only within the TTL.
        #[test]
        fn root_lookups_never_invent_a_lane_or_an_unknown_root(
            started_ago in 0u64..5000,
            asked_ago in 0u64..5000,
            ttl in 1u64..3000,
            listed in proptest::option::of(proptest::option::of(proptest::collection::vec(
                (proptest::bool::ANY, 0u64..300),
                0..6,
            ))),
            probe in 0u8..8,
        ) {
            let now = Instant::now();
            let ago = |ms| now.checked_sub(Duration::from_millis(ms)).unwrap();
            let started = ago(started_ago);
            let map: Option<Option<RootMap>> = listed.map(|list| {
                list.map(|roots| {
                    roots
                        .into_iter()
                        .enumerate()
                        .map(|(i, (hot, depth))| {
                            let lane = if hot { Lane::Hot } else { Lane::Cold };
                            (B256::with_last_byte(i as u8), (lane, depth))
                        })
                        .collect()
                })
            });
            let cache = RootCache {
                listed: map.clone().map(|list| (started, started, list.map(Arc::new))),
                kept: None,
                listing: false,
            };
            let cfg = Snap1Config { roots_ttl: Duration::from_millis(ttl), ..Default::default() };
            let root = B256::with_last_byte(probe);
            let got = cache.lookup(root, ago(asked_ago), &cfg);

            let after_ask = started_ago <= asked_ago;
            // 100 ms of slack for the time the test itself takes.
            let fresh = after_ask || started_ago + 100 < ttl;
            let stale = !after_ask && started_ago > ttl;
            let expected = match &map {
                None => Some(RootLookup::Refresh),
                Some(None) if fresh => Some(RootLookup::Unlisted),
                Some(Some(roots)) => match roots.get(&root) {
                    Some(&(lane, depth)) if fresh => Some(RootLookup::Known(lane, Some(depth))),
                    None if after_ask => Some(RootLookup::Unknown),
                    None => Some(RootLookup::Refresh),
                    Some(_) if stale => Some(RootLookup::Refresh),
                    Some(_) => None,
                },
                Some(None) if stale => Some(RootLookup::Refresh),
                Some(None) => None,
            };
            match expected {
                Some(expected) => proptest::prop_assert_eq!(got, expected),
                // Within the slack either answer is right, but never a lane the list lacks.
                None => proptest::prop_assert!(
                    matches!(got, RootLookup::Refresh | RootLookup::Unlisted) ||
                        map.as_ref().and_then(|l| l.as_ref()).and_then(|l| l.get(&root)).is_some_and(
                            |&(lane, depth)| got == RootLookup::Known(lane, Some(depth))
                        ),
                    "{:?}", got
                ),
            }
        }

        /// The next listing starts no sooner than the minimum refresh after the last one ended,
        /// and never in the past.
        #[test]
        fn the_next_listing_waits_the_minimum_refresh_from_the_last_end(
            ended_ago in proptest::option::of(0u64..1000),
            min_refresh in 0u64..1000,
        ) {
            let before = Instant::now();
            let ended = ended_ago.map(|ms| before.checked_sub(Duration::from_millis(ms)).unwrap());
            let cache = RootCache {
                listed: ended.map(|ended| (ended, ended, None)),
                kept: None,
                listing: false,
            };
            let min_refresh = Duration::from_millis(min_refresh);
            let cfg = Snap1Config { roots_min_refresh: min_refresh, ..Default::default() };
            let next = cache.next_listing(&cfg);
            let after = Instant::now();
            proptest::prop_assert!(next >= before);
            match ended {
                Some(ended) => {
                    let earliest = ended + min_refresh;
                    proptest::prop_assert!(next >= earliest);
                    proptest::prop_assert!(next <= earliest.max(after));
                }
                None => proptest::prop_assert!(next <= after),
            }
        }
    }

    #[test]
    fn failed_listings_keep_the_last_list_and_a_good_one_replaces_it() {
        let cfg = Snap1Config { roots_ttl: Duration::from_secs(60), ..Default::default() };
        let (listed, missing) = (B256::with_last_byte(1), B256::with_last_byte(2));
        let map = Arc::new(RootMap::from([(listed, (Lane::Cold, 7))]));
        let mut cache = RootCache::default();
        let first = Instant::now();
        cache.store(first, first, Some(map.clone()));
        assert!(cache.kept.is_none());

        // Two failures in a row keep the list and the start of its own listing.
        for _ in 0..2 {
            let now = Instant::now();
            cache.store(now, now, None);
            assert!(matches!(&cache.kept, Some((at, kept)) if *at == first && *kept == map));
        }
        let asked = first;
        assert_eq!(cache.lookup(listed, asked, &cfg), RootLookup::Known(Lane::Cold, Some(7)));
        assert_eq!(cache.last_listed(listed, &cfg), RootLookup::Known(Lane::Cold, Some(7)));
        // A root may be newer than the kept list, so its absence proves nothing.
        assert_eq!(cache.lookup(missing, asked, &cfg), RootLookup::Unlisted);
        assert_eq!(cache.last_listed(missing, &cfg), RootLookup::Unlisted);

        let now = Instant::now();
        cache.store(now, now, Some(Arc::default()));
        assert!(cache.kept.is_none());
        assert_eq!(cache.lookup(listed, asked, &cfg), RootLookup::Unknown);
    }

    /// A backend with five states at the cold lane and their roots, and a root it lacks.
    fn five_cold_states() -> (TestBackend, Vec<B256>) {
        let mut ranges = FakeFactory::default();
        let mut roots: Vec<B256> =
            (0..5).map(|i| ranges.add(FakeState::generated(3 + i, 0))).collect();
        let lanes = roots.iter().map(|root| (*root, Lane::Cold)).collect();
        roots.push(B256::repeat_byte(0xab));
        let backend = TestBackend {
            ranges,
            lanes,
            default_lane: None,
            lists_roots: false,
            codes: MockEthProvider::default(),
            probe: Arc::default(),
        };
        (backend, roots)
    }

    /// The view cache holds at most its entries, each root once, and drops the oldest first. A
    /// view it hands out answers for the asked root, and an expired view is never handed out.
    #[test]
    fn the_view_cache_stays_bounded_and_serves_only_the_asked_root() {
        use proptest::prelude::*;
        let (backend, roots) = five_cold_states();
        let input = (0usize..4, any::<bool>(), proptest::collection::vec(0..roots.len(), 1..40));
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(128));
        runner
            .run(&input, |(entries, expire, asks)| {
                let ttl = if expire { Duration::ZERO } else { Duration::from_secs(3600) };
                let cfg = Snap1Config {
                    view_cache_entries: entries,
                    view_cache_ttl: ttl,
                    ..Default::default()
                };
                let views = Mutex::default();
                let metrics = Snap1Metrics::new();
                let factory = RequestFactory {
                    backend: &backend,
                    cache: Some((&views, &cfg, &metrics)),
                    unknown_root: AtomicBool::new(false),
                };
                // The roots the cache should hold, oldest first.
                let mut model: VecDeque<B256> = VecDeque::new();
                for ask in asks {
                    let root = roots[ask];
                    let before = backend.probe.resolutions.load(Ordering::SeqCst);
                    let view = factory.state_range_provider(root)?;
                    let resolved = backend.probe.resolutions.load(Ordering::SeqCst) > before;
                    if ask == roots.len() - 1 {
                        prop_assert!(view.is_none());
                        prop_assert!(factory.unknown_root.load(Ordering::Relaxed));
                    } else {
                        let accounts = view
                            .unwrap()
                            .account_range(B256::ZERO, B256::repeat_byte(0xff), usize::MAX)?
                            .items
                            .len();
                        prop_assert_eq!(accounts, 3 + ask, "a view of another root");
                        let cached = !expire && model.contains(&root);
                        prop_assert_eq!(resolved, !cached);
                        if !cached && entries > 0 && !expire {
                            if model.len() == entries {
                                model.pop_front();
                            }
                            model.push_back(root);
                        }
                    }
                    let held: Vec<B256> = lock(&views).entries.iter().map(|(r, ..)| *r).collect();
                    prop_assert!(held.len() <= entries, "{} views held", held.len());
                    if !expire {
                        prop_assert_eq!(held, Vec::from(model.clone()));
                    }
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn concurrent_misses_at_one_cold_root_cache_one_view() {
        let (mut backend, roots) = five_cold_states();
        backend.probe =
            Arc::new(Probe { resolve_delay: Duration::from_millis(100), ..Default::default() });
        let cfg = Snap1Config { view_cache_entries: 2, ..Default::default() };
        let views = Mutex::default();
        let metrics = Snap1Metrics::new();
        let factory = RequestFactory {
            backend: &backend,
            cache: Some((&views, &cfg, &metrics)),
            unknown_root: AtomicBool::new(false),
        };
        let (other, burst) = (roots[0], roots[1]);
        assert!(factory.state_range_provider(other).unwrap().is_some());
        // Two cold slots miss the same root at once, and both build a view.
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| assert!(factory.state_range_provider(burst).unwrap().is_some()));
            }
        });
        assert_eq!(backend.probe.resolutions.load(Ordering::SeqCst), 3);
        // The second view is not cached beside the first, so the other root's view stays.
        let held: Vec<B256> = lock(&views).entries.iter().map(|(r, ..)| *r).collect();
        assert_eq!(held, [other, burst]);
    }

    /// The value of the gauge `name` in `snapshot`.
    fn gauge(snapshot: metrics_util::debugging::Snapshot, name: &str) -> Option<f64> {
        snapshot.into_vec().into_iter().find_map(|(key, _, _, value)| match value {
            metrics_util::debugging::DebugValue::Gauge(v) if key.key().name() == name => {
                Some(v.into_inner())
            }
            _ => None,
        })
    }

    /// Over any order of connects and disconnects, including overlapping connections of one
    /// peer, a peer is live exactly while it has a connection, keeps one admission state for its
    /// whole life within the cool-down, and the peers gauge counts the live peers.
    #[test]
    fn peer_admission_state_follows_its_connections() {
        use proptest::prelude::*;
        let (backend, _, _) = test_backend(Lane::Hot, Probe::default());
        let backend = Arc::new(backend);
        let input = proptest::collection::vec((0u8..4, any::<bool>()), 0..60);
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(128));
        runner
            .run(&input, |ops| {
                let recorder = metrics_util::debugging::DebuggingRecorder::new();
                let snapshotter = recorder.snapshotter();
                let cfg =
                    Snap1Config { peer_cooldown: Duration::from_secs(3600), ..Default::default() };
                let server = metrics::with_local_recorder(&recorder, || {
                    Snap1Server::new(backend.clone(), cfg)
                });
                let mut connections = [0usize; 4];
                // Each peer's first state, held so a new state cannot reuse its address.
                let mut states: [Option<Arc<PeerState>>; 4] = Default::default();
                for (p, connect) in ops {
                    let id = peer(p);
                    let p = usize::from(p);
                    // A connect and a last disconnect set the gauge.
                    let sets_gauge = connect || connections[p] == 1;
                    if connect {
                        server.peer_connected(id);
                        connections[p] += 1;
                    } else {
                        server.peer_disconnected(id);
                        connections[p] = connections[p].saturating_sub(1);
                    }
                    let peers = server.lock_peers();
                    let cooling = lock(&server.cooling);
                    for (p, &open) in connections.iter().enumerate() {
                        let id = peer(p as u8);
                        let state = match (open, peers.get(&id), cooling.get(&id)) {
                            (0, None, kept) => kept.map(|(_, state)| state),
                            (n, Some((live, state)), None) if n > 0 => {
                                prop_assert_eq!(*live, n);
                                Some(state)
                            }
                            (n, live, kept) => {
                                return Err(TestCaseError::fail(format!(
                                    "peer {p} with {n} connections: live {}, cooling {}",
                                    live.is_some(),
                                    kept.is_some()
                                )))
                            }
                        };
                        prop_assert_eq!(state.is_some(), states[p].is_some() || open > 0);
                        if let Some(state) = state {
                            let first = states[p].get_or_insert_with(|| state.clone());
                            prop_assert!(Arc::ptr_eq(first, state), "peer {} state replaced", p);
                        }
                    }
                    // Taking a snapshot zeroes the gauges, so read it only after a set.
                    if sets_gauge {
                        let live = connections.iter().filter(|n| **n > 0).count();
                        let shown = gauge(snapshotter.snapshot(), "pulsechain_snap1.peers");
                        prop_assert_eq!(shown, Some(live as f64));
                    }
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn at_most_the_cooling_cap_of_peers_is_kept_and_the_oldest_goes_first() {
        let (backend, _, _) = test_backend(Lane::Hot, Probe::default());
        let server = Snap1Server::new(Arc::new(backend), Snap1Config::default());
        let ids: Vec<PeerId> =
            (0..=MAX_COOLING_PEERS as u64).map(|i| PeerId::from(U512::from(i))).collect();
        for id in &ids {
            server.peer_connected(*id);
            server.peer_disconnected(*id);
        }
        let cooling = lock(&server.cooling);
        assert_eq!(cooling.len(), MAX_COOLING_PEERS);
        assert!(!cooling.contains_key(&ids[0]), "the oldest peer is kept");
        assert!(cooling.contains_key(&ids[MAX_COOLING_PEERS]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hot_request_past_the_queue_timeout_is_answered_empty_and_frees_its_slot() {
        let (backend, root, state) = backend(Lane::Hot, Duration::from_millis(400));
        // Two workers give each peer one hot slot.
        let cfg = Snap1Config {
            hot_workers: 2,
            hot_queue_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let server = Arc::new(Snap1Server::new(backend, cfg));
        let key = *state.accounts.keys().next().unwrap();
        let busy: Vec<_> = [2, 3]
            .map(|n| {
                let server = server.clone();
                tokio::spawn(async move { server.handle(peer(n), one_key(root, key)).await })
            })
            .into();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let asked = Instant::now();
        let resp = accounts(server.handle(peer(1), one_key(root, key)).await);
        let waited = asked.elapsed();
        assert!(resp.accounts.is_empty(), "served past the queue timeout");
        assert!(
            waited >= Duration::from_millis(100) && waited < Duration::from_millis(300),
            "{waited:?}"
        );
        assert_eq!(server.peer(peer(1)).hot.available_permits(), 1, "the per-peer slot is held");
        for task in busy {
            assert_eq!(accounts(task.await.unwrap()).accounts.len(), 1);
        }
        assert_eq!(accounts(server.handle(peer(1), one_key(root, key)).await).accounts.len(), 1);
    }
}
