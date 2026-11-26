//! The p2p fetcher: asks peers for what a round missed, verifies every answer, and moves on to
//! another peer when an answer does not verify.
//!
//! The wire is behind [`Transport`] so the policy is testable without sockets. Request shapes:
//! account and storage proofs are one-key range requests with a
//! response limit of one byte (the server returns the one item plus its proof), code goes in
//! chunks of 64 hashes with a 4 MiB limit.

use super::peers::{PeerBook, RETRY_PAUSE};
use crate::{
    exec::{FetchError, Fetcher},
    metrics::{FailureSource, LiteMetrics},
    state::{Lookup, MissKey, PartialState},
    store::NodeStore,
    verify::{
        verify_account, verify_receipts, verify_storage, AccountProof, ProvenAccount, VerifyError,
    },
};
use alloy_consensus::{constants::EMPTY_ROOT_HASH, Header, ReceiptWithBloom};
use alloy_primitives::{keccak256, map::AddressMap, Address, Bytes, B256};
use async_trait::async_trait;
use futures::{
    channel::oneshot,
    future::{BoxFuture, FutureExt},
    stream::{FuturesUnordered, StreamExt},
};
use parking_lot::Mutex;
use reth_eth_wire_types::snap::{
    ByteCodesMessage, GetAccountRangeMessage, GetByteCodesMessage, GetStorageRangesMessage,
    SnapProtocolMessage as M,
};
use reth_network_peers::PeerId;
use reth_pulsechain_snap::Snap1Message;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};
use tokio::{
    sync::{futures::Notified, Notify, OwnedSemaphorePermit, Semaphore},
    time::{sleep, sleep_until, timeout, Instant},
};

/// Timeout of a one-key account or storage proof request.
pub const PROOF_TIMEOUT: Duration = Duration::from_secs(4);
/// Timeout of a code request.
pub const CODE_TIMEOUT: Duration = Duration::from_secs(8);
/// Code hashes per request.
pub const CODE_CHUNK: usize = 64;
/// Response limit of a code request.
pub const CODE_BYTES: u64 = 4 << 20;
/// Requests in flight to peers at once, across all fetches, besides hedges. A request holds its
/// permit until it lands or times out, also after another peer answered first.
pub const MAX_CONCURRENT_FETCHES: usize = 32;
/// Permits kept for hedges, on top of [`MAX_CONCURRENT_FETCHES`], so at most the sum of the two
/// requests are out at once. A hedge does not wait behind first attempts, whose permits peers
/// that do not answer may hold.
pub const HEDGE_PERMITS: usize = 8;
/// Requests held for one peer at once (waiting for a fetch permit or for its pace, or on the
/// wire), hedges included. A request past it goes to another candidate of its pass or waits: one
/// peer cannot hold every permit.
pub const MAX_PEER_FETCHES: usize = MAX_CONCURRENT_FETCHES / 2;
/// Requests held at once, together, for the peers without a good answer in the last
/// [`ANSWERED_WITHIN`](super::peers::ANSWERED_WITHIN), hedges included. Peers that do not answer
/// cannot hold more than this share of the permits, however many of them there are, so the rest
/// stays free for the peers that answer.
pub const MAX_QUIET_FETCHES: usize = MAX_CONCURRENT_FETCHES / 4;
/// Most proof nodes accepted in one account or storage proof response. A one-key proof walks one
/// path (an absence proof two), each at most 64 nodes deep for a 32-byte key.
pub const MAX_PROOF_NODES: usize = 128;
/// The largest trie node: a branch with 16 hash children, 3 + 16 x 33 + 1 bytes.
pub const MAX_PROOF_NODE_BYTES: usize = 532;
/// How long a request waits for a peer to connect before it gives up.
pub const NO_PEER_WAIT: Duration = Duration::from_secs(3);

/// Why one request to one peer produced nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The peer did not answer in time.
    #[error("request timed out")]
    Timeout,
    /// The peer went away.
    #[error("peer disconnected")]
    Disconnected,
    /// The peer sent something that is not the answer to the request.
    #[error("unexpected response")]
    Unexpected,
}

/// How a peer's answer fared.
#[derive(Debug)]
pub enum Check<R> {
    /// Verified.
    Good(R),
    /// The peer answered, but not with what was asked (empty, wrong shape): not a lie, a miss.
    Unavailable,
    /// The answer failed verification.
    Bad,
}

/// A receipt as it comes off the eth wire.
pub type WireReceipt = ReceiptWithBloom<alloy_consensus::EthereumReceipt>;

/// What the fetcher needs from the network: the peers that speak both eth and snap, and their
/// request channels.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Connected peers that have both an eth and a snap channel.
    fn peers(&self) -> Vec<PeerId>;
    /// Whether `peer` is one of the operator's own `--peer` nodes (tried first).
    fn is_static(&self, _peer: &PeerId) -> bool {
        false
    }
    /// `peer` sent data that failed verification: drop and ban it at the network level.
    fn ban(&self, _peer: PeerId) {}
    /// `peer` has given nothing useful for [`DROP_AFTER`](super::peers::DROP_AFTER) requests in a
    /// row: end its session so its slot can go to another peer. It is not banned and may connect
    /// again. No default: a wrapper that forgets to forward it would keep such peers forever.
    fn drop_peer(&self, peer: PeerId);
    /// Sends one snap/1 request and waits for the matching response.
    async fn snap(&self, peer: PeerId, msg: Snap1Message) -> Result<Snap1Message, TransportError>;
    /// Asks for the receipts of one block (eth/68 `GetReceipts`). `None` when the peer answers
    /// with an empty list: it does not hold the block.
    async fn receipts(
        &self,
        peer: PeerId,
        block_hash: B256,
    ) -> Result<Option<Vec<WireReceipt>>, TransportError>;
}

/// Fetches and verifies state over a [`Transport`].
pub struct P2pFetcher<T> {
    transport: Arc<T>,
    store: Arc<dyn NodeStore>,
    book: Arc<Mutex<PeerBook>>,
    metrics: LiteMetrics,
    ids: AtomicU64,
    /// Bounds requests in flight across every fetch, besides hedges.
    permits: Arc<Semaphore>,
    /// Bounds hedges in flight across every fetch.
    hedge_permits: Arc<Semaphore>,
    /// Wakes the passes that wait for a peer's hold: a hold that was at a cap was released, or a
    /// quiet peer answered.
    wake: Arc<Notify>,
}

impl<T> std::fmt::Debug for P2pFetcher<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pFetcher").finish_non_exhaustive()
    }
}

type CallFuture<R> = BoxFuture<'static, Result<Check<R>, TransportError>>;
type Call<R> = dyn Fn(PeerId) -> CallFuture<R> + Send + Sync;
/// A verified account (`None` when proven absent) and the proof nodes read.
type AccountRead = (Option<ProvenAccount>, Vec<(B256, Bytes)>);

impl<T: Transport> P2pFetcher<T> {
    /// A fetcher that writes verified nodes and code into `store`.
    pub fn new(transport: Arc<T>, store: Arc<dyn NodeStore>, metrics: LiteMetrics) -> Self {
        Self {
            transport,
            store,
            book: Arc::default(),
            metrics,
            ids: AtomicU64::new(1),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_FETCHES)),
            hedge_permits: Arc::new(Semaphore::new(HEDGE_PERMITS)),
            wake: Arc::default(),
        }
    }

    /// The peer statistics (for tests and the peers gauge).
    pub fn book(&self) -> &Mutex<PeerBook> {
        &self.book
    }

    fn next_id(&self) -> u64 {
        self.ids.fetch_add(1, Ordering::Relaxed)
    }

    async fn wait_for_peers(&self) -> Vec<PeerId> {
        let deadline = Instant::now() + NO_PEER_WAIT;
        loop {
            let p = self.transport.peers();
            if !p.is_empty() || Instant::now() >= deadline {
                return p;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Tries peers best-first, hedging to the next after a quarter of `timeout` but at most
    /// 500 ms ([`MAX_SNAP_HEDGE`](super::peers::MAX_SNAP_HEDGE)), until one gives a verified
    /// answer. A bad answer bans its peer for [`BAN_FOR`](super::peers::BAN_FOR), in
    /// the peer book and on the network, and does not count as a failure. After every candidate
    /// failed it pauses 750 ms and goes through them once more. A request still out when another
    /// peer answered keeps its permit and is judged when it lands. The hedge delay counts from
    /// when the latest attempt went out, or from when it was queued while it waits for a permit.
    /// No attempt, first or hedge, goes past [`MAX_PEER_FETCHES`] or [`MAX_QUIET_FETCHES`]: it
    /// goes to another candidate or waits.
    async fn hedged<R: Send + 'static>(
        &self,
        request_timeout: Duration,
        call: &Call<R>,
    ) -> Result<R, FetchError> {
        let mut saw_bad = false;
        for pass in 0..2 {
            let connected = self.wait_for_peers().await;
            if connected.is_empty() {
                return Err(FetchError::NoSource);
            }
            let cands = self.book.lock().candidates_preferring(
                &connected,
                Instant::now().into_std(),
                |p| self.transport.is_static(p),
            );
            if !cands.is_empty() &&
                let Some(r) = self.one_pass(&cands, request_timeout, call, &mut saw_bad).await
            {
                return Ok(r);
            }
            if pass == 0 {
                sleep(RETRY_PAUSE).await;
            }
        }
        Err(if saw_bad { FetchError::Unverifiable } else { FetchError::NoSource })
    }

    async fn one_pass<R: Send + 'static>(
        &self,
        cands: &[PeerId],
        request_timeout: Duration,
        call: &Call<R>,
        saw_bad: &mut bool,
    ) -> Option<R> {
        type Done<R> = (PeerId, Attempt<R>);
        let hedge = PeerBook::hedge_delay(request_timeout);
        let mut running: FuturesUnordered<BoxFuture<'static, Done<R>>> = FuturesUnordered::new();
        let mut live = LiveAttempts { book: &self.book, peers: HashMap::new() };
        // Dropped once the pass has its answer: an attempt that has not gone out by then ends.
        let (answered, ended) = oneshot::channel::<()>();
        let ended = ended.shared();
        // The candidates that had their turn in this pass.
        let mut tried = vec![false; cands.len()];
        // A start that found each candidate it may use at a cap. It holds no permit, and tries
        // again when a hold is released or a quiet peer answers.
        let mut waiting: Option<Want> = None;
        let mut woken: Pin<Box<Notified<'_>>> = Box::pin(self.wake.notified());
        // `may_skip`: the pass has a candidate after this one, so a peer that is paced, benched
        // or banned once the attempt has its permit passes its turn (and the permit) on to that
        // one instead of waiting.
        let start = |peer: PeerId,
                     may_skip: bool,
                     from: PermitFrom,
                     hold: Hold,
                     running: &mut FuturesUnordered<BoxFuture<'static, Done<R>>>,
                     live: &mut HashMap<PeerId, Arc<OnceLock<Instant>>>| {
            self.book.lock().start(peer);
            let sent = Arc::new(OnceLock::new());
            live.insert(peer, sent.clone());
            let last_sent = sent.clone();
            let fut = call(peer);
            let (main, hedges) = (self.permits.clone(), self.hedge_permits.clone());
            let book = self.book.clone();
            let ended = ended.clone();
            running.push(Box::pin(async move {
                // Released when the attempt ends, however it ends.
                let hold = hold;
                // The timeout and the latency sample start once the request may go out, not
                // while it waits for a permit or for its peer's pace.
                let ready = async move {
                    let (pool, permit) = match from {
                        PermitFrom::Given(pool, p) => (pool, p),
                        PermitFrom::Take(pool) => {
                            let sem = match pool {
                                Pool::Main => main,
                                Pool::Hedge => hedges,
                            };
                            match sem.acquire_owned().await {
                                Ok(p) => (pool, p),
                                Err(_) => {
                                    let res = Err(TransportError::Disconnected);
                                    return Err(Attempt::Ran(Instant::now(), None, res));
                                }
                            }
                        }
                    };
                    let at = {
                        let mut book = book.lock();
                        let now = Instant::now().into_std();
                        // An attempt that waited for its permit checks its peer again: it may
                        // have been benched or banned meanwhile.
                        if may_skip &&
                            (book.is_paced(&peer, now) ||
                                book.is_benched(&peer, now) ||
                                book.is_banned(&peer, now))
                        {
                            return Err(Attempt::Skipped(pool, permit));
                        }
                        book.pace(peer, now)
                    };
                    let turn = Turn { book, peer, at, seq: None };
                    sleep_until(at.into()).await;
                    Ok((permit, turn))
                };
                let (permit, mut turn) = tokio::select! {
                    biased;
                    _ = ended => return (peer, Attempt::Ended),
                    ready = ready => match ready {
                        Ok(ready) => ready,
                        Err(attempt) => return (peer, attempt),
                    },
                };
                let started = *sent.get_or_init(Instant::now);
                let seq = turn.book.lock().sent(peer);
                turn.seq = Some(seq);
                let res = match timeout(request_timeout, fut).await {
                    Ok(r) => r,
                    Err(_) => Err(TransportError::Timeout),
                };
                // Off the wire before the answer is judged, so it excuses no later empty answer.
                drop(turn);
                drop(hold);
                drop(permit);
                (peer, Attempt::Ran(started, Some(seq), res))
            }));
            last_sent
        };
        // When the latest attempt was queued, and when it went out.
        let mut last_queued = Instant::now();
        let mut last_sent: Arc<OnceLock<Instant>> = Arc::default();
        let mut hedge_timer = Box::pin(sleep(hedge));
        let mut want = Some(Want { from: PermitFrom::Take(Pool::Main), fallback: None });
        let answer = loop {
            // Every start goes through here, so no send passes the caps of its peer.
            if let Some(w) = want.take() {
                if let Some(waiting) = &mut waiting {
                    // The waiting start goes first; this one has nowhere else to go.
                    waiting.fallback = waiting.fallback.or(w.fallback);
                } else {
                    // Enabled before the check, so a release right after it is not missed.
                    woken = Box::pin(self.wake.notified());
                    woken.as_mut().enable();
                    match pick(&self.book, cands, &mut tried, w.fallback) {
                        Pick::Go { at, quiet, may_skip } => {
                            let peer = cands[at];
                            let hold = Hold {
                                book: self.book.clone(),
                                wake: self.wake.clone(),
                                peer,
                                quiet,
                            };
                            last_sent =
                                start(peer, may_skip, w.from, hold, &mut running, &mut live.peers);
                            last_queued = Instant::now();
                            hedge_timer = Box::pin(sleep(hedge));
                        }
                        // A permit passed on is given back: a start that waits holds none.
                        Pick::Wait => {
                            let from = PermitFrom::Take(w.from.pool());
                            waiting = Some(Want { from, fallback: w.fallback });
                        }
                        Pick::Nothing => {}
                    }
                }
            }
            if running.is_empty() && waiting.is_none() {
                break None;
            }
            tokio::select! {
                done = running.next(), if !running.is_empty() => {
                    let (peer, attempt) = done.expect("not empty");
                    live.peers.remove(&peer);
                    match attempt {
                        Attempt::Ran(started, seq, res) => {
                            let judged = judge(
                                &self.book,
                                &*self.transport,
                                &self.metrics,
                                &self.wake,
                                (peer, started, seq),
                                res,
                                saw_bad,
                            );
                            if let Some(r) = judged {
                                break Some(r);
                            }
                            // A failed attempt frees its turn at once, also while others run.
                            want = Some(Want { from: PermitFrom::Take(Pool::Main), fallback: None });
                        }
                        Attempt::Skipped(pool, permit) => {
                            // Busy, not failed. With no other candidate it goes back to its peer.
                            self.book.lock().abandon(peer, Duration::ZERO);
                            let fallback = cands.iter().position(|c| *c == peer);
                            want = Some(Want { from: PermitFrom::Given(pool, permit), fallback });
                        }
                        // Only once the pass has its answer, which ends the loop.
                        Attempt::Ended => self.book.lock().abandon(peer, Duration::ZERO),
                    }
                }
                () = &mut hedge_timer => {
                    hedge_timer = Box::pin(sleep(hedge));
                    // The hedge counts from when the latest attempt went out or, while it waits
                    // for a permit, from when it was queued: an attempt that waits behind the
                    // permits of peers that do not answer is hedged too. The hedge takes a permit
                    // of its own pool, so it does not queue behind those permits.
                    let due = last_sent.get().copied().unwrap_or(last_queued) + hedge;
                    if waiting.is_some() {
                        // The waiting start goes out as soon as a candidate can take it.
                    } else if due > Instant::now() {
                        hedge_timer = Box::pin(sleep_until(due));
                    } else if tried.contains(&false) {
                        want = Some(Want { from: PermitFrom::Take(Pool::Hedge), fallback: None });
                    }
                }
                () = &mut woken, if waiting.is_some() => want = waiting.take(),
            }
        };
        // The pass has its answer. An attempt that has not gone out ends; a request that is out
        // keeps its permit and is judged when it lands, so a peer is charged only for a request
        // it did not answer in its timeout, not for one another peer answered first.
        drop(answered);
        if !running.is_empty() {
            live.peers.clear();
            let (book, transport, metrics, wake) = (
                self.book.clone(),
                self.transport.clone(),
                self.metrics.clone(),
                self.wake.clone(),
            );
            tokio::spawn(async move {
                while let Some((peer, attempt)) = running.next().await {
                    match attempt {
                        Attempt::Ran(started, seq, res) => {
                            judge(
                                &book,
                                &*transport,
                                &metrics,
                                &wake,
                                (peer, started, seq),
                                res,
                                &mut false,
                            );
                        }
                        Attempt::Skipped(..) | Attempt::Ended => {
                            book.lock().abandon(peer, Duration::ZERO)
                        }
                    }
                }
            });
        }
        answer
    }

    /// One account, proven against `root`, or `None` when it is proven absent. The nodes read go
    /// into the store.
    pub async fn fetch_account(
        &self,
        root: B256,
        address: Address,
    ) -> Result<Option<ProvenAccount>, FetchError> {
        let hashed = keccak256(address);
        let transport = self.transport.clone();
        let id = self.next_id();
        let call = move |peer: PeerId| -> CallFuture<AccountRead> {
            let transport = transport.clone();
            Box::pin(async move {
                let req = Snap1Message::Shared(M::GetAccountRange(GetAccountRangeMessage {
                    request_id: id,
                    root_hash: root,
                    starting_hash: hashed,
                    limit_hash: hashed,
                    response_bytes: 1,
                }));
                let Snap1Message::Shared(M::AccountRange(r)) = transport.snap(peer, req).await?
                else {
                    return Err(TransportError::Unexpected);
                };
                if r.request_id != id {
                    return Err(TransportError::Unexpected);
                }
                if r.accounts.is_empty() && r.proof.is_empty() {
                    return Ok(Check::Unavailable);
                }
                if r.proof.len() > MAX_PROOF_NODES || r.accounts.len() > 16 || oversized(&r.proof) {
                    return Ok(Check::Bad);
                }
                let proof = AccountProof::from_account_range(address, &r);
                Ok(match verify_account(root, address, &proof) {
                    Ok(proven) => Check::Good(proven),
                    Err(_) => Check::Bad,
                })
            })
        };
        let (account, nodes) = self.hedged(PROOF_TIMEOUT, &call).await?;
        for (h, n) in nodes {
            self.store.put(h, n);
        }
        Ok(account)
    }

    /// The `slots` of `address`. Its account is fetched first, once, when the store does not
    /// hold it.
    pub async fn fetch_slots(
        &self,
        root: B256,
        address: Address,
        slots: &[B256],
    ) -> Result<(), FetchError> {
        let state = PartialState::new(self.store.clone(), root);
        let account = match state.account(&address) {
            Lookup::Hit(a) => a,
            // The verified answer, not a second lookup: the store may already have dropped it.
            Lookup::Miss(_) => self.fetch_account(root, address).await?,
        };
        // An absent account has no slots to fetch, and an empty storage trie proves every slot
        // zero: a peer has no proof to send for it, so asking would count against honest peers.
        let Some(storage_root) = account.map(|a| a.storage_root) else { return Ok(()) };
        if storage_root == EMPTY_ROOT_HASH {
            return Ok(());
        }
        let slot_futs = slots.iter().map(|s| self.fetch_slot(root, address, storage_root, *s));
        // Partial progress is kept in the store; report the first failure.
        futures::future::join_all(slot_futs).await.into_iter().collect()
    }

    /// One slot of `address`, proven against its `storage_root`.
    async fn fetch_slot(
        &self,
        root: B256,
        address: Address,
        storage_root: B256,
        slot: B256,
    ) -> Result<(), FetchError> {
        let hashed_account = keccak256(address);
        let hashed_slot = keccak256(slot);
        let transport = self.transport.clone();
        let id = self.next_id();
        let call = move |peer: PeerId| -> CallFuture<Vec<(B256, Bytes)>> {
            let transport = transport.clone();
            Box::pin(async move {
                let req = Snap1Message::Shared(M::GetStorageRanges(GetStorageRangesMessage {
                    request_id: id,
                    root_hash: root,
                    account_hashes: vec![hashed_account],
                    starting_hash: hashed_slot.into(),
                    limit_hash: hashed_slot.into(),
                    response_bytes: 1,
                }));
                let Snap1Message::Shared(M::StorageRanges(r)) = transport.snap(peer, req).await?
                else {
                    return Err(TransportError::Unexpected);
                };
                if r.request_id != id {
                    return Err(TransportError::Unexpected);
                }
                if r.slots.first().is_none_or(Vec::is_empty) && r.proof.is_empty() {
                    return Ok(Check::Unavailable);
                }
                if r.proof.len() > MAX_PROOF_NODES ||
                    oversized(&r.proof) ||
                    r.slots.len() > 1 ||
                    r.slots.first().is_some_and(|s| s.len() > 16)
                {
                    return Ok(Check::Bad);
                }
                let claimed = AccountProof::from_account_range(address, &empty_range())
                    .with_storage_range(slot, &r);
                let entry = &claimed.storage_proof[0];
                Ok(match verify_storage(storage_root, slot, entry.value, &entry.proof) {
                    Ok((_, nodes)) => Check::Good(nodes),
                    Err(_) => Check::Bad,
                })
            })
        };
        let nodes = self.hedged(PROOF_TIMEOUT, &call).await?;
        for (h, n) in nodes {
            self.store.put(h, n);
        }
        Ok(())
    }

    /// Contract code for `hashes`, verified by hash, in chunks of [`CODE_CHUNK`]. Fails unless
    /// one peer returns a whole chunk.
    pub async fn fetch_codes(&self, hashes: &[B256]) -> Result<(), FetchError> {
        for chunk in hashes.chunks(CODE_CHUNK) {
            let wanted: Arc<[B256]> = chunk.into();
            let transport = self.transport.clone();
            let store = self.store.clone();
            let id = self.next_id();
            let call = move |peer: PeerId| -> CallFuture<Vec<(B256, Bytes)>> {
                let transport = transport.clone();
                let store = store.clone();
                let wanted = wanted.clone();
                Box::pin(async move {
                    let req = Snap1Message::Shared(M::GetByteCodes(GetByteCodesMessage {
                        request_id: id,
                        hashes: wanted.to_vec(),
                        response_bytes: CODE_BYTES,
                    }));
                    let Snap1Message::Shared(M::ByteCodes(ByteCodesMessage { request_id, codes })) =
                        transport.snap(peer, req).await?
                    else {
                        return Err(TransportError::Unexpected);
                    };
                    if request_id != id {
                        return Err(TransportError::Unexpected);
                    }
                    // Code is keyed by its own hash, so the check is that every returned blob
                    // hashes to a hash that was asked for (once).
                    let mut good = Vec::new();
                    let mut left = wanted.to_vec();
                    for code in codes {
                        let h = keccak256(&code);
                        let Some(pos) = left.iter().position(|w| *w == h) else {
                            return Ok(Check::Bad);
                        };
                        left.swap_remove(pos);
                        good.push((h, code));
                    }
                    if left.is_empty() {
                        return Ok(Check::Good(good));
                    }
                    // A whole chunk fits the snap server's 2 MiB reply limit, so a short answer
                    // is a miss. The code it did carry is verified and kept.
                    for (h, c) in good {
                        store.put_code(h, c);
                    }
                    Ok(Check::Unavailable)
                })
            };
            for (h, c) in self.hedged(CODE_TIMEOUT, &call).await? {
                self.store.put_code(h, c);
            }
        }
        Ok(())
    }

    /// The receipts of `header`'s block, verified against its receipts root (eth/68).
    pub async fn fetch_receipts(&self, header: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        let hash = header.hash_slow();
        let header = header.clone();
        let transport = self.transport.clone();
        let call = move |peer: PeerId| -> CallFuture<Vec<WireReceipt>> {
            let transport = transport.clone();
            let header = header.clone();
            Box::pin(async move {
                let Some(receipts) = transport.receipts(peer, hash).await? else {
                    return Ok(Check::Unavailable);
                };
                Ok(match verify_receipts(&header, &receipts) {
                    Ok(()) => Check::Good(receipts),
                    Err(VerifyError::ReceiptsMismatch) => Check::Bad,
                    Err(_) => Check::Unavailable,
                })
            })
        };
        self.hedged(PROOF_TIMEOUT, &call).await
    }
}

/// A pool of fetch permits.
#[derive(Debug, Clone, Copy)]
enum Pool {
    /// The shared pool of [`MAX_CONCURRENT_FETCHES`].
    Main,
    /// The hedge pool of [`HEDGE_PERMITS`].
    Hedge,
}

/// Where an attempt gets its fetch permit.
enum PermitFrom {
    /// It takes one from the pool once its peer is held.
    Take(Pool),
    /// It has one of the pool: an attempt that skipped its peer passed it on.
    Given(Pool, OwnedSemaphorePermit),
}

impl PermitFrom {
    const fn pool(&self) -> Pool {
        match self {
            Self::Take(pool) | Self::Given(pool, _) => *pool,
        }
    }
}

/// An attempt a pass wants to start.
struct Want {
    from: PermitFrom,
    /// A candidate that skipped its turn, which the attempt may go back to when no other one can
    /// take it.
    fallback: Option<usize>,
}

/// Where an attempt the pass wants goes.
enum Pick {
    /// To the candidate at `at`, now held for it.
    Go {
        at: usize,
        /// Whether the hold counts in the quiet share.
        quiet: bool,
        /// Whether a candidate the pass has not tried is left.
        may_skip: bool,
    },
    /// A candidate is at a cap: the attempt waits for it.
    Wait,
    /// No candidate is left.
    Nothing,
}

/// Holds a request for the first candidate the pass has not tried that is under its caps, else for
/// `fallback`. A candidate benched or banned since the pass began counts as tried.
fn pick(
    book: &Mutex<PeerBook>,
    cands: &[PeerId],
    tried: &mut [bool],
    fallback: Option<usize>,
) -> Pick {
    let mut book = book.lock();
    let now = Instant::now().into_std();
    let mut capped = false;
    for (at, peer) in cands.iter().enumerate() {
        if tried[at] {
            continue;
        }
        if book.is_benched(peer, now) || book.is_banned(peer, now) {
            tried[at] = true;
            continue;
        }
        match book.hold(*peer, now) {
            Some(quiet) => {
                tried[at] = true;
                return Pick::Go { at, quiet, may_skip: tried.contains(&false) };
            }
            None => capped = true,
        }
    }
    if let Some(at) = fallback &&
        !book.is_benched(&cands[at], now) &&
        !book.is_banned(&cands[at], now)
    {
        match book.hold(cands[at], now) {
            Some(quiet) => return Pick::Go { at, quiet, may_skip: false },
            None => capped = true,
        }
    }
    if capped {
        Pick::Wait
    } else {
        Pick::Nothing
    }
}

/// A request held for a peer under [`MAX_PEER_FETCHES`] and [`MAX_QUIET_FETCHES`]. Released when
/// its attempt ends; a release that frees a capped peer or quiet share wakes the waiting passes.
struct Hold {
    book: Arc<Mutex<PeerBook>>,
    wake: Arc<Notify>,
    peer: PeerId,
    quiet: bool,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let freed = self.book.lock().release(self.peer, self.quiet);
        if freed {
            self.wake.notify_waiters();
        }
    }
}

/// How one attempt of a pass ended.
enum Attempt<R> {
    /// Its peer's pace was spent, or its peer was benched or banned, once it had its permit, and
    /// the pass had another candidate: the permit of the pool goes to that one, so the overflow
    /// of one peer goes to the others.
    Skipped(Pool, OwnedSemaphorePermit),
    /// The pass had its answer before the request went out.
    Ended,
    /// The request went out at `.0` with send number `.1` (`None`: it never went out) and ended
    /// with `.2`.
    Ran(Instant, Option<u64>, Result<Check<R>, TransportError>),
}

/// Books how the request `sent` (its peer, when it went out and its send number) ended, and
/// returns its verified answer. A bad answer bans the peer and sets `saw_bad`. A good answer from
/// a quiet peer takes it out of the quiet share and wakes the passes that wait for a hold.
fn judge<T: Transport, R>(
    book: &Mutex<PeerBook>,
    transport: &T,
    metrics: &LiteMetrics,
    wake: &Notify,
    sent: (PeerId, Instant, Option<u64>),
    res: Result<Check<R>, TransportError>,
    saw_bad: &mut bool,
) -> Option<R> {
    let (peer, started, seq) = sent;
    let due = match res {
        Ok(Check::Good(r)) => {
            let was_quiet = {
                let mut book = book.lock();
                book.success(peer, started.elapsed());
                book.answered(peer, Instant::now().into_std())
            };
            if was_quiet {
                wake.notify_waiters();
            }
            return Some(r);
        }
        Ok(Check::Bad) => {
            *saw_bad = true;
            // Its data failed verification: never use this peer for a while.
            metrics.proof_failure(FailureSource::Peer);
            book.lock().ban(peer, Instant::now().into_std());
            transport.ban(peer);
            tracing::warn!(%peer, "peer sent data that failed verification; banned");
            return None;
        }
        Ok(Check::Unavailable) => {
            book.lock().empty(peer, seq, started.elapsed(), Instant::now().into_std())
        }
        Err(TransportError::Timeout) => {
            book.lock().timed_out(peer, started.elapsed(), Instant::now().into_std())
        }
        Err(_) => book.lock().failure(peer, Instant::now().into_std()),
    };
    if due && !transport.is_static(&peer) {
        tracing::debug!(%peer, "dropping a peer that gives no answers");
        transport.drop_peer(peer);
    }
    None
}

/// The attempts of one pass still running, with the time each request went out. Dropping it
/// while they run (the caller dropped the fetch, so no peer answered) abandons them: they were not
/// judged, so they are not failures. Once the pass has its answer, the requests still out are
/// judged as they land instead.
struct LiveAttempts<'a> {
    book: &'a Mutex<PeerBook>,
    peers: HashMap<PeerId, Arc<OnceLock<Instant>>>,
}

impl Drop for LiveAttempts<'_> {
    fn drop(&mut self) {
        let mut book = self.book.lock();
        for (peer, sent) in self.peers.drain() {
            book.abandon(peer, sent.get().map_or(Duration::ZERO, Instant::elapsed));
        }
    }
}

/// An attempt's turn with its peer: its booked pace turn until the request goes out, then its
/// place on the wire. Dropped before the request went out (the caller gave up during the pace
/// wait), it gives the pace turn back, so the wait is at most one pace interval per attempt that
/// holds a permit, plus one. Dropped after, it takes the request off the wire.
struct Turn {
    book: Arc<Mutex<PeerBook>>,
    peer: PeerId,
    at: std::time::Instant,
    /// The send number, once the request went out.
    seq: Option<u64>,
}

impl Drop for Turn {
    fn drop(&mut self) {
        let mut book = self.book.lock();
        match self.seq {
            Some(seq) => book.landed(self.peer, seq),
            None => book.unpace(self.peer, self.at, Instant::now().into_std()),
        }
    }
}

/// Whether a proof holds a node no trie can hold; checked before any node is hashed.
fn oversized(proof: &[Bytes]) -> bool {
    proof.iter().any(|n| n.len() > MAX_PROOF_NODE_BYTES)
}

const fn empty_range() -> reth_eth_wire_types::snap::AccountRangeMessage {
    reth_eth_wire_types::snap::AccountRangeMessage {
        request_id: 0,
        accounts: Vec::new(),
        proof: Vec::new(),
    }
}

#[async_trait]
impl<T: Transport> Fetcher for P2pFetcher<T> {
    async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
        // The slots of one account share its proof, so they go with it.
        let mut accounts: AddressMap<Vec<B256>> = AddressMap::default();
        let mut codes = Vec::new();
        for m in misses {
            match m {
                MissKey::Account(a, _) => {
                    accounts.entry(*a).or_default();
                }
                MissKey::Slot(a, s) => accounts.entry(*a).or_default().push(*s),
                MissKey::Code(h) => codes.push(*h),
                // Block hashes come from the header chain, not from a peer.
                MissKey::Header(_) => {}
            }
        }
        for slots in accounts.values_mut() {
            slots.sort_unstable();
            slots.dedup();
        }
        codes.sort_unstable();
        codes.dedup();
        let acct_futs = accounts.iter().map(|(a, slots)| self.fetch_slots(root, *a, slots));
        let (acct_res, code_res) =
            futures::join!(futures::future::join_all(acct_futs), self.fetch_codes(&codes));
        // Partial progress is kept in the store; report the first failure.
        acct_res.into_iter().chain([code_res]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        net::peers::{BENCH_AFTER, DROP_AFTER, PEER_BURST, PEER_RATE},
        store::Store,
        testing::{serve_snap, world, Acct, World},
    };
    use alloy_primitives::{address, U256};
    use std::sync::atomic::AtomicUsize;

    const A1: Address = address!("00000000000000000000000000000000000a0001");
    const A2: Address = address!("00000000000000000000000000000000000a0002");
    const CODE_ADDR: Address = address!("00000000000000000000000000000000000c0001");

    fn pid(n: u8) -> PeerId {
        PeerId::repeat_byte(n)
    }

    type Behavior =
        Arc<dyn Fn(Snap1Message, usize) -> Result<Snap1Message, TransportError> + Send + Sync>;
    type ReceiptsBehavior =
        Arc<dyn Fn() -> Result<Option<Vec<WireReceipt>>, TransportError> + Send + Sync>;
    type Delays = Arc<dyn Fn(usize) -> Duration + Send + Sync>;

    struct Mock {
        peers: Mutex<Vec<PeerId>>,
        behavior: Mutex<HashMap<PeerId, (Behavior, Duration)>>,
        seen: Mutex<HashMap<PeerId, usize>>,
        calls: AtomicUsize,
        banned: Mutex<Vec<PeerId>>,
        dropped: Mutex<Vec<PeerId>>,
        statics: Mutex<Vec<PeerId>>,
        receipts: Mutex<HashMap<PeerId, ReceiptsBehavior>>,
        inflight: AtomicUsize,
        max_inflight: AtomicUsize,
        /// Per-peer delays by call number, in place of the fixed delay.
        delays: Mutex<HashMap<PeerId, Delays>>,
    }

    /// Counts a mock request as ended also when the fetcher drops it.
    struct Leave<'a>(&'a AtomicUsize);

    impl Drop for Leave<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Mock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                peers: Mutex::default(),
                behavior: Mutex::default(),
                seen: Mutex::default(),
                calls: AtomicUsize::new(0),
                banned: Mutex::default(),
                dropped: Mutex::default(),
                statics: Mutex::default(),
                receipts: Mutex::default(),
                inflight: AtomicUsize::new(0),
                max_inflight: AtomicUsize::new(0),
                delays: Mutex::default(),
            })
        }
        fn add(&self, p: PeerId, delay: Duration, b: Behavior) {
            self.peers.lock().push(p);
            self.behavior.lock().insert(p, (b, delay));
        }
    }

    #[async_trait]
    impl Transport for Mock {
        fn peers(&self) -> Vec<PeerId> {
            self.peers.lock().clone()
        }
        fn is_static(&self, peer: &PeerId) -> bool {
            self.statics.lock().contains(peer)
        }
        fn ban(&self, peer: PeerId) {
            self.banned.lock().push(peer);
        }
        fn drop_peer(&self, peer: PeerId) {
            self.dropped.lock().push(peer);
        }
        async fn snap(
            &self,
            peer: PeerId,
            msg: Snap1Message,
        ) -> Result<Snap1Message, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (b, delay) = self.behavior.lock().get(&peer).cloned().expect("known peer");
            let n = {
                let mut s = self.seen.lock();
                let e = s.entry(peer).or_default();
                *e += 1;
                *e
            };
            let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_inflight.fetch_max(now, Ordering::SeqCst);
            let _leave = Leave(&self.inflight);
            let delay = self.delays.lock().get(&peer).map_or(delay, |d| d(n));
            sleep(delay).await;
            b(msg, n)
        }
        async fn receipts(
            &self,
            peer: PeerId,
            _: B256,
        ) -> Result<Option<Vec<WireReceipt>>, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let delay = self.behavior.lock().get(&peer).map_or(Duration::ZERO, |(_, d)| *d);
            let b = self.receipts.lock().get(&peer).cloned();
            sleep(delay).await;
            b.map_or(Err(TransportError::Disconnected), |b| b())
        }
    }

    fn setup() -> (Arc<World>, Arc<dyn NodeStore>, B256) {
        let w = Arc::new(world(&[
            (
                A1,
                Acct {
                    balance: 100,
                    nonce: 1,
                    storage: vec![(U256::from(1), U256::from(11)), (U256::from(2), U256::from(22))],
                    ..Default::default()
                },
            ),
            (A2, Acct { balance: 200, ..Default::default() }),
            (CODE_ADDR, Acct { code: vec![0x60, 0, 0x60, 0, 0xf3], ..Default::default() }),
        ]));
        let root = w.root;
        (w, Arc::new(Store::in_memory(1 << 22)), root)
    }

    fn honest(w: Arc<World>) -> Behavior {
        Arc::new(move |m, _| Ok(serve_snap(&w, m)))
    }

    /// Honest, but the account's balance is inflated so the proof cannot verify.
    fn liar(w: Arc<World>) -> Behavior {
        Arc::new(move |m, _| {
            let mut r = serve_snap(&w, m);
            if let Snap1Message::Shared(M::AccountRange(a)) = &mut r &&
                let Some(first) = a.accounts.first_mut()
            {
                let mut acct = first.trie_account();
                acct.balance += U256::from(1);
                *first =
                    reth_eth_wire_types::snap::AccountData::from_trie_account(first.hash, &acct);
            }
            Ok(r)
        })
    }

    fn fetcher(t: Arc<Mock>, store: Arc<dyn NodeStore>) -> P2pFetcher<Mock> {
        P2pFetcher::new(t, store, LiteMetrics::new())
    }

    #[tokio::test(start_paused = true)]
    async fn a_bad_proof_from_one_peer_is_retried_on_another() {
        let (w, store, root) = setup();
        let t = Mock::new();
        // The liar is faster, so it is asked first.
        t.add(pid(1), Duration::from_millis(1), liar(w.clone()));
        t.add(pid(2), Duration::from_millis(50), honest(w.clone()));
        let f = fetcher(t.clone(), store.clone());
        f.book().lock().success(pid(1), Duration::from_millis(1));
        f.fetch_account(root, A1).await.unwrap();
        let st = PartialState::new(store, root);
        let Lookup::Hit(Some(a)) = st.account(&A1) else { panic!("not held") };
        assert_eq!((a.balance, a.nonce), (U256::from(100), 1));
        assert!(t.seen.lock()[&pid(1)] >= 1, "the liar was asked");
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_whose_data_fails_verification_is_banned_and_not_asked_again() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(1), liar(w.clone()));
        t.add(pid(2), Duration::from_millis(50), honest(w.clone()));
        let f = fetcher(t.clone(), store.clone());
        f.book().lock().success(pid(1), Duration::from_millis(1));
        f.fetch_account(root, A1).await.unwrap();
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
        assert!(f.book().lock().is_banned(&pid(1), Instant::now().into_std()));
        // Later requests never reach the banned peer, however fast it is.
        let before = t.seen.lock()[&pid(1)];
        f.fetch_account(root, A2).await.unwrap();
        assert_eq!(t.seen.lock()[&pid(1)], before);
        // And its failure is on the books as a proof failure, not a quiet timeout.
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lone_lying_peer_gives_unverifiable_and_is_banned() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, liar(w));
        let f = fetcher(t.clone(), store);
        assert!(f.fetch_account(root, A1).await.is_err());
        assert_eq!(t.banned.lock().first(), Some(&pid(1)));
        // Banned: the next request has no candidate and does not ask it again.
        let n = t.calls.load(Ordering::SeqCst);
        assert!(f.fetch_account(root, A1).await.is_err());
        assert_eq!(t.calls.load(Ordering::SeqCst), n);
    }

    #[tokio::test(start_paused = true)]
    async fn static_peers_are_asked_before_faster_discovered_ones() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(1), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(100), honest(w));
        t.statics.lock().push(pid(2));
        let f = fetcher(t.clone(), store);
        f.book().lock().success(pid(1), Duration::from_millis(1));
        f.fetch_account(root, A1).await.unwrap();
        assert_eq!(t.seen.lock().get(&pid(2)), Some(&1), "static peer asked");
        assert_eq!(t.seen.lock().get(&pid(1)), None, "discovered peer not needed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_tampered_response_never_reaches_the_store() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, liar(w));
        let f = fetcher(t, store.clone());
        let err = f.fetch_account(root, A1).await.unwrap_err();
        assert_eq!(err, FetchError::Unverifiable);
        assert_eq!(store.bytes(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn after_all_candidates_fail_it_retries_once_after_750ms() {
        let (w, store, root) = setup();
        let t = Mock::new();
        let good = honest(w);
        t.add(
            pid(1),
            Duration::ZERO,
            Arc::new(
                move |m, n| if n == 1 { Err(TransportError::Disconnected) } else { good(m, n) },
            ),
        );
        let f = fetcher(t.clone(), store);
        let start = Instant::now();
        f.fetch_account(root, A2).await.unwrap();
        let took = start.elapsed();
        assert!(took >= RETRY_PAUSE && took < Duration::from_secs(2), "{took:?}");
        assert_eq!(t.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn five_consecutive_failures_bench_a_peer() {
        let (_w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, Arc::new(|_, _| Err(TransportError::Disconnected)));
        let f = fetcher(t.clone(), store);
        // Each call makes two passes, so three calls reach five failures.
        for _ in 0..3 {
            let _ = f.fetch_account(root, A1).await;
        }
        assert!(f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
        let before = t.calls.load(Ordering::SeqCst);
        let err = f.fetch_account(root, A1).await.unwrap_err();
        assert_eq!(err, FetchError::NoSource);
        assert_eq!(t.calls.load(Ordering::SeqCst), before, "a benched peer is not asked");
    }

    #[tokio::test(start_paused = true)]
    async fn no_peers_waits_then_gives_up() {
        let (_w, store, root) = setup();
        let f = fetcher(Mock::new(), store);
        let start = Instant::now();
        assert_eq!(f.fetch_account(root, A1).await.unwrap_err(), FetchError::NoSource);
        assert!(start.elapsed() >= NO_PEER_WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_peer_is_hedged_and_not_benched() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(10), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        let f = fetcher(t, store);
        // The slow peer looks best (it has a sample), the hedge goes to the other.
        f.book().lock().success(pid(1), Duration::from_millis(1));
        let start = Instant::now();
        f.fetch_account(root, A1).await.unwrap();
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(500) && took < Duration::from_secs(2), "{took:?}");
        // The slow request is still out, and counted, until its timeout.
        assert_eq!(f.book().lock().inflight(&pid(1)), 1);
        sleep(PROOF_TIMEOUT).await;
        let book = f.book().lock();
        assert_eq!(book.inflight(&pid(1)), 0);
        // It timed out: one failure, short of a bench, and a latency sample.
        assert!(!book.is_benched(&pid(1), Instant::now().into_std()));
        assert_eq!(book.latency(&pid(1)), Some((Duration::from_millis(7) + PROOF_TIMEOUT) / 8));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_fetch_leaves_no_request_in_flight() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(10), honest(w.clone()));
        t.add(pid(2), Duration::from_secs(10), honest(w));
        let f = fetcher(t.clone(), store);
        // Past the hedge delay, so both peers have an attempt running when the caller gives up.
        let gave_up = timeout(Duration::from_millis(600), f.fetch_account(root, A1)).await;
        assert!(gave_up.is_err());
        assert_eq!(t.calls.load(Ordering::SeqCst), 2);
        let book = f.book().lock();
        assert_eq!((book.inflight(&pid(1)), book.inflight(&pid(2))), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_gives_up_after_the_hedge_delay_does_not_fail_the_peer() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(10), honest(w));
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let hedge = PeerBook::hedge_delay(PROOF_TIMEOUT);
        // No other peer answered, so the peer did not lose to anyone: each cancel is an abandon.
        for _ in 0..BENCH_AFTER {
            let gave_up =
                timeout(hedge + Duration::from_millis(100), f.fetch_account(root, A1)).await;
            assert!(gave_up.is_err());
        }
        assert_eq!(t.calls.load(Ordering::SeqCst), BENCH_AFTER as usize);
        let book = f.book().lock();
        assert!(!book.is_benched(&pid(1), Instant::now().into_std()));
        assert_eq!(book.inflight(&pid(1)), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_peer_that_lost_to_a_hedge_is_not_asked_first_again() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(10), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        // The stalled peer once answered fast; the honest one has a normal sample.
        f.book().lock().success(pid(1), Duration::from_millis(1));
        f.book().lock().success(pid(2), Duration::from_millis(20));
        f.fetch_account(root, A1).await.unwrap();
        let start = Instant::now();
        f.fetch_account(root, A2).await.unwrap();
        let took = start.elapsed();
        assert!(took < PeerBook::hedge_delay(PROOF_TIMEOUT), "{took:?}");
        assert_eq!(t.seen.lock()[&pid(1)], 1, "the stalled peer is not asked first again");
    }

    /// Two honest peers that take 1.2 s per code chunk. The hedge goes to the second at 500 ms
    /// and the first answers at 1.2 s. The second ran for less time than the winner took, so it
    /// did not stall, and losing every pass never benches it.
    #[tokio::test(start_paused = true)]
    async fn a_hedge_that_loses_to_an_earlier_request_is_not_a_stall() {
        let (w, store, _) = setup();
        let t = Mock::new();
        let chunk = Duration::from_millis(1200);
        t.add(pid(1), chunk, honest(w.clone()));
        t.add(pid(2), chunk, honest(w));
        let f = fetcher(t.clone(), store);
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        for _ in 0..BENCH_AFTER {
            // The first peer stays the fastest, so it is asked first and wins every pass.
            f.book().lock().success(pid(1), Duration::from_millis(1));
            f.fetch_codes(&[code_hash]).await.unwrap();
        }
        assert_eq!(t.seen.lock()[&pid(2)], BENCH_AFTER as usize, "the hedge went out each time");
        assert!(!f.book().lock().is_benched(&pid(2), Instant::now().into_std()));
    }

    /// A peer that answers every request with an empty range.
    fn empty() -> Behavior {
        Arc::new(|m, _| {
            let Snap1Message::Shared(M::GetAccountRange(q)) = m else { panic!("{m:?}") };
            Ok(Snap1Message::Shared(M::AccountRange(
                reth_eth_wire_types::snap::AccountRangeMessage {
                    request_id: q.request_id,
                    ..empty_range()
                },
            )))
        })
    }

    /// An empty answer of the asked kind, as a busy `snap/1` server gives.
    fn busy_reply(m: Snap1Message) -> Snap1Message {
        let reply = match m {
            Snap1Message::Shared(M::GetAccountRange(q)) => {
                M::AccountRange(reth_eth_wire_types::snap::AccountRangeMessage {
                    request_id: q.request_id,
                    ..empty_range()
                })
            }
            Snap1Message::Shared(M::GetStorageRanges(q)) => {
                M::StorageRanges(reth_eth_wire_types::snap::StorageRangesMessage {
                    request_id: q.request_id,
                    slots: Vec::new(),
                    proof: Vec::new(),
                })
            }
            m => panic!("{m:?}"),
        };
        Snap1Message::Shared(reply)
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_answered_empty_by_a_busy_peer_does_not_bench_it() {
        let (w, store, root) = setup();
        let t = Mock::new();
        // A snap server's cold lane: it runs one request of the peer (call 2, 100 ms) and answers
        // the rest of the burst empty at once. The account (call 1) and later calls are served.
        let good = honest(w);
        let busy = 3..=9;
        t.add(
            pid(1),
            Duration::ZERO,
            Arc::new(move |m, n| if busy.contains(&n) { Ok(busy_reply(m)) } else { good(m, n) }),
        );
        t.delays.lock().insert(
            pid(1),
            Arc::new(|n| match n {
                1 => Duration::from_millis(10),
                2 => Duration::from_millis(100),
                _ => Duration::ZERO,
            }),
        );
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let slots: Vec<B256> = (1..=8u64).map(|i| B256::from(U256::from(i))).collect();
        let other = async {
            sleep(Duration::from_millis(50)).await;
            assert!(!f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
            let start = Instant::now();
            f.fetch_account(root, A2).await.unwrap();
            start.elapsed()
        };
        let (res, took) = tokio::join!(f.fetch_slots(root, A1, &slots), other);
        res.unwrap();
        assert!(took < RETRY_PAUSE, "another caller waited out a bench: {took:?}");
    }

    /// Fetches until `peer` was asked `n` times, waiting out its benches.
    async fn ask_until(f: &P2pFetcher<Mock>, t: &Mock, root: B256, peer: PeerId, n: usize) {
        for _ in 0..1000 {
            if t.seen.lock().get(&peer).copied().unwrap_or(0) >= n {
                return;
            }
            let _ = f.fetch_account(root, A1).await;
            sleep(Duration::from_secs(1)).await;
        }
        panic!("{peer} was not asked {n} times");
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovered_peer_that_never_helps_is_dropped() {
        let (_w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, empty());
        let f = fetcher(t.clone(), store);
        ask_until(&f, &t, root, pid(1), DROP_AFTER as usize - 1).await;
        assert!(t.dropped.lock().is_empty());
        ask_until(&f, &t, root, pid(1), DROP_AFTER as usize).await;
        assert_eq!(*t.dropped.lock(), vec![pid(1)]);
        assert!(t.banned.lock().is_empty(), "dropped, not banned");
    }

    /// A `snap/1` server's cold lane at its defaults (`cold_per_peer: 1`): one request of the
    /// peer runs at once, for `run`, and one that arrives meanwhile is answered empty at once.
    fn cold_lane(t: &Mock, peer: PeerId, w: Arc<World>, run: Duration) {
        let lane = Arc::new(Mutex::new((Instant::now(), std::collections::HashSet::new())));
        let admit = lane.clone();
        t.delays.lock().insert(
            peer,
            Arc::new(move |n| {
                let mut lane = admit.lock();
                let now = Instant::now();
                if lane.0 > now {
                    return Duration::ZERO;
                }
                lane.0 = now + run;
                lane.1.insert(n);
                run
            }),
        );
        let good = honest(w);
        t.add(
            peer,
            Duration::ZERO,
            Arc::new(
                move |m, n| if lane.lock().1.contains(&n) { good(m, n) } else { Ok(busy_reply(m)) },
            ),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_cold_lane_benches_no_peer_whatever_the_burst() {
        let (w, store, root) = setup();
        let t = Mock::new();
        cold_lane(&t, pid(1), w, Duration::from_millis(100));
        let f = fetcher(t.clone(), store);
        // More lookups than a pace burst, at a cold root: the lane serves them one at a time and
        // answers the others empty while one runs. Most find it busy in both passes.
        let misses: Vec<MissKey> = (0..300).map(absent).collect();
        let watch = async {
            for _ in 0..40 {
                assert!(!f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
                sleep(Duration::from_millis(50)).await;
            }
        };
        let (res, ()) = tokio::join!(f.fetch(root, &misses), watch);
        assert_eq!(res, Err(FetchError::NoSource));
        let calls = t.calls.load(Ordering::SeqCst);
        assert!(calls > misses.len() * 3 / 2, "the retries were not asked: {calls}");
        assert!(!f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
        assert!(t.dropped.lock().is_empty(), "a busy peer was dropped");
        // Once the lane is free, it serves at once.
        let start = Instant::now();
        f.fetch_account(root, A2).await.unwrap();
        assert!(start.elapsed() < RETRY_PAUSE, "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovered_peer_that_helps_once_in_65_answers_is_benched_and_dropped() {
        let (w, store, root) = setup();
        let t = Mock::new();
        let (good, none) = (honest(w), empty());
        t.add(
            pid(1),
            Duration::ZERO,
            Arc::new(move |m, n| if n % 65 == 1 { good(m, n) } else { none(m, n) }),
        );
        let f = fetcher(t.clone(), store);
        let mut benched = false;
        for _ in 0..1000 {
            if !t.dropped.lock().is_empty() {
                break;
            }
            let _ = f.fetch_account(root, A1).await;
            benched |= f.book().lock().is_benched(&pid(1), Instant::now().into_std());
            sleep(Duration::from_secs(1)).await;
        }
        assert!(benched);
        assert_eq!(t.dropped.lock().first(), Some(&pid(1)));
        assert!(t.seen.lock()[&pid(1)] <= 65, "it had a second good answer first");
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovered_peer_that_never_answers_is_dropped_while_another_answers() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(3600), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(100), honest(w));
        let f = fetcher(t.clone(), store);
        for _ in 0..1000 {
            if !t.dropped.lock().is_empty() {
                break;
            }
            // Two reads at once: the honest peer has one in flight when the second picks, so
            // the silent one sorts first for it.
            let (a, b) = tokio::join!(f.fetch_account(root, A1), f.fetch_account(root, A2));
            assert_eq!((a.is_ok(), b.is_ok()), (true, true));
            sleep(Duration::from_secs(1)).await;
        }
        assert_eq!(*t.dropped.lock(), vec![pid(1)]);
        assert!(t.banned.lock().is_empty(), "dropped, not banned");
    }

    #[tokio::test(start_paused = true)]
    async fn a_static_peer_that_never_answers_is_kept_while_another_answers() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(3600), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(100), honest(w));
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        // The static peer is asked first whenever it is not benched, and stalls every time.
        while t.seen.lock().get(&pid(1)).copied().unwrap_or(0) < DROP_AFTER as usize + 5 {
            f.fetch_account(root, A1).await.unwrap();
            sleep(Duration::from_secs(1)).await;
        }
        assert!(t.dropped.lock().is_empty(), "the operator's peer was dropped");
    }

    #[tokio::test(start_paused = true)]
    async fn a_hedge_takes_a_permit_of_its_own_pool() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(600), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        f.book().lock().success(pid(1), Duration::from_millis(1));
        // One permit is free and the first attempt takes it. The hedge does not wait for the
        // first attempt to answer: it takes a hedge permit.
        let _held =
            f.permits.clone().acquire_many_owned(MAX_CONCURRENT_FETCHES as u32 - 1).await.unwrap();
        let start = Instant::now();
        f.fetch_account(root, A1).await.unwrap();
        let took = start.elapsed();
        let hedge = PeerBook::hedge_delay(PROOF_TIMEOUT);
        assert_eq!(took, hedge + Duration::from_millis(20));
        assert_eq!(t.seen.lock().get(&pid(2)), Some(&1), "the hedge was sent");
        // The first request keeps its permit until it lands, 600 ms after it went out.
        assert_eq!(f.permits.available_permits(), 0);
        assert_eq!(f.hedge_permits.available_permits(), HEDGE_PERMITS);
        sleep(Duration::from_millis(100)).await;
        let book = f.book().lock();
        assert_eq!((book.inflight(&pid(1)), book.inflight(&pid(2))), (0, 0));
        drop(book);
        assert_eq!(f.permits.available_permits(), 1, "the permit is back");
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_failure_starts_the_next_candidate_while_another_attempt_runs() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(10), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(5), empty());
        t.add(pid(3), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        for (n, ms) in [(1, 1), (2, 2), (3, 3)] {
            f.book().lock().success(pid(n), Duration::from_millis(ms));
        }
        let start = Instant::now();
        f.fetch_account(root, A1).await.unwrap();
        let took = start.elapsed();
        // The hedge at 500 ms, the empty answer 5 ms later, then the third peer at once.
        let hedge = PeerBook::hedge_delay(PROOF_TIMEOUT);
        let want = hedge + Duration::from_millis(25);
        assert!(took >= want && took < want + Duration::from_millis(10), "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_static_peer_that_never_helps_is_kept() {
        let (_w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, empty());
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        ask_until(&f, &t, root, pid(1), DROP_AFTER as usize + 5).await;
        assert!(t.dropped.lock().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn slots_and_code_and_the_fetcher_trait() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w.clone()));
        let f = fetcher(t, store.clone());
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        f.fetch(
            root,
            &[
                MissKey::Account(A1, None),
                MissKey::Slot(A1, B256::from(U256::from(2))),
                MissKey::Slot(A1, B256::from(U256::from(99))),
                MissKey::Code(code_hash),
                MissKey::Header(5),
            ],
        )
        .await
        .unwrap();
        let st = PartialState::new(store, root);
        assert_eq!(st.storage(&A1, U256::from(2)), Lookup::Hit(U256::from(22)));
        assert_eq!(st.storage(&A1, U256::from(99)), Lookup::Hit(U256::ZERO));
        assert!(matches!(st.code(&code_hash), Lookup::Hit(c) if c.len() == 5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slot_is_asked_for_even_when_the_store_loses_its_account() {
        let (w, _store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w));
        // Too small to hold any node: everything put is gone at once.
        let f = fetcher(t.clone(), Arc::new(Store::in_memory(1)));
        f.fetch_slots(root, A1, &[B256::from(U256::from(2))]).await.unwrap();
        assert_eq!(t.calls.load(Ordering::SeqCst), 2, "the account, then the slot");
    }

    #[tokio::test(start_paused = true)]
    async fn one_account_proof_serves_every_slot_of_a_round() {
        let (w, store, root) = setup();
        let t = Mock::new();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (good, log) = (honest(w), asked.clone());
        // A peer that takes time, so the slots start before the account proof is held.
        t.add(
            pid(1),
            Duration::from_millis(10),
            Arc::new(move |m, n| {
                log.lock().push(match &m {
                    Snap1Message::Shared(M::GetAccountRange(_)) => "account",
                    Snap1Message::Shared(M::GetStorageRanges(_)) => "slot",
                    _ => "other",
                });
                good(m, n)
            }),
        );
        let f = fetcher(t, store.clone());
        let (s1, s2) = (B256::from(U256::from(1)), B256::from(U256::from(2)));
        let misses = [
            MissKey::Account(A1, None),
            MissKey::Slot(A1, s1),
            MissKey::Slot(A1, s1),
            MissKey::Slot(A1, s2),
        ];
        f.fetch(root, &misses).await.unwrap();
        let mut asked = asked.lock().clone();
        asked.sort_unstable();
        assert_eq!(asked, vec!["account", "slot", "slot"]);
        let st = PartialState::new(store, root);
        assert_eq!(st.storage(&A1, U256::from(1)), Lookup::Hit(U256::from(11)));
        assert_eq!(st.storage(&A1, U256::from(2)), Lookup::Hit(U256::from(22)));
    }

    fn absent(i: u32) -> MissKey {
        let mut a = [0xeeu8; 20];
        a[..4].copy_from_slice(&i.to_be_bytes());
        MissKey::Account(Address::from(a), None)
    }

    #[tokio::test(start_paused = true)]
    async fn fetches_are_capped_and_the_timeout_starts_when_a_request_is_sent() {
        let (w, store, root) = setup();
        let t = Mock::new();
        // Each answer takes 3 s, under the 4 s proof timeout. A request that waited for a slot
        // and had its timeout running meanwhile would time out.
        t.add(pid(1), Duration::from_secs(3), honest(w));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..100).map(absent).collect();
        f.fetch(root, &misses).await.unwrap();
        let max = t.max_inflight.load(Ordering::SeqCst);
        assert!(max <= MAX_CONCURRENT_FETCHES, "{max} requests in flight");
        assert!(!f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
    }

    /// `inner` behind a per-peer token bucket of 200 requests a second and a burst of 400, five
    /// times tighter than a `snap/1` server's default: a request that finds no token is answered
    /// empty.
    fn rate_limited(inner: Behavior) -> Behavior {
        let (rate, burst) = (200.0, 400.0);
        let bucket = Mutex::new((burst, Instant::now()));
        Arc::new(move |m, n| {
            {
                let mut b = bucket.lock();
                let now = Instant::now();
                b.0 = (now - b.1).as_secs_f64().mul_add(rate, b.0).min(burst);
                b.1 = now;
                if b.0 < 1.0 {
                    return empty()(m, n);
                }
                b.0 -= 1.0;
            }
            inner(m, n)
        })
    }

    /// A discovered peer that never answers gets half the first attempts of a burst. It holds at
    /// most its share of the permits, and the attempts past that share go to the honest peer.
    /// The hedges take permits of their own pool, so the burst ends in about one hedge delay, not
    /// in rounds of the proof timeout.
    #[tokio::test(start_paused = true)]
    async fn a_silent_discovered_peer_cannot_hold_every_permit() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(3600), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..100).map(absent).collect();
        let start = Instant::now();
        f.fetch(root, &misses).await.unwrap();
        let took = start.elapsed();
        assert!(took < 2 * PeerBook::hedge_delay(PROOF_TIMEOUT), "{took:?}");
    }

    /// Five discovered peers that never answer and one honest one. However the hedges and the
    /// slow requests overlap, the requests out at once never pass the main permits plus the
    /// hedge reserve.
    #[tokio::test(start_paused = true)]
    async fn requests_in_flight_never_pass_the_bound_with_many_silent_peers() {
        let (w, store, root) = setup();
        let t = Mock::new();
        for n in 1..=5 {
            t.add(pid(n), Duration::from_secs(3600), honest(w.clone()));
        }
        t.add(pid(6), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..300).map(absent).collect();
        let codes = [keccak256([0x60, 0, 0x60, 0, 0xf3])];
        let (res, codes) = tokio::join!(f.fetch(root, &misses), f.fetch_codes(&codes));
        res.unwrap();
        codes.unwrap();
        let max = t.max_inflight.load(Ordering::SeqCst);
        assert!(max <= MAX_CONCURRENT_FETCHES + HEDGE_PERMITS, "{max} requests in flight");
    }

    /// Three discovered peers that never answer and one honest one. The silent peers hold at
    /// most the quiet share of the permits together, so the honest peer keeps answering the
    /// burst and it ends long before the silent requests time out.
    #[tokio::test(start_paused = true)]
    async fn three_silent_peers_cannot_starve_an_honest_one() {
        let (w, store, root) = setup();
        let t = Mock::new();
        for n in 1..=3 {
            t.add(pid(n), Duration::from_secs(3600), honest(w.clone()));
        }
        t.add(pid(4), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..200).map(absent).collect();
        let start = Instant::now();
        f.fetch(root, &misses).await.unwrap();
        let took = start.elapsed();
        assert!(took < PROOF_TIMEOUT / 2, "{took:?}");
        let max = t.max_inflight.load(Ordering::SeqCst);
        assert!(max <= MAX_CONCURRENT_FETCHES, "{max} requests in flight");
    }

    /// A lone peer that never answers is the last candidate of each pass, so no attempt can skip
    /// it. The attempts past the quiet share wait for it instead of going out.
    #[tokio::test(start_paused = true)]
    async fn a_lone_silent_peer_gets_no_more_than_the_quiet_share() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(3600), honest(w));
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..100).map(absent).collect();
        assert!(timeout(Duration::from_secs(1), f.fetch(root, &misses)).await.is_err());
        let max = t.max_inflight.load(Ordering::SeqCst);
        assert_eq!(max, MAX_QUIET_FETCHES, "{max} requests in flight");
    }

    /// The operator's static peer answers honestly in 1.2 s per code chunk, a discovered one in
    /// 20 ms. The hedge to the discovered one wins each pass, but the static peer answers well
    /// inside the code timeout, so it is never charged and never benched.
    #[tokio::test(start_paused = true)]
    async fn a_slow_static_peer_that_loses_to_a_hedge_is_not_benched() {
        let (w, store, _) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(1200), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        for n in 1..=2 * BENCH_AFTER as usize {
            f.fetch_codes(&[code_hash]).await.unwrap();
            assert!(!f.book().lock().is_benched(&pid(1), Instant::now().into_std()), "pass {n}");
            let asked = t.seen.lock()[&pid(1)];
            assert_eq!(asked, n, "the static peer is asked first each time");
        }
        sleep(CODE_TIMEOUT).await;
        let book = f.book().lock();
        assert_eq!(book.inflight(&pid(1)), 0);
        assert!(book.latency(&pid(1)) >= Some(Duration::from_millis(1200)), "its answers count");
    }

    /// An attempt checks its peer again once it gets a permit. When the peer was benched or
    /// banned while the attempt waited, the attempt goes to the next candidate.
    #[tokio::test(start_paused = true)]
    async fn an_attempt_whose_peer_was_benched_or_banned_while_it_waited_goes_to_the_next() {
        for ban in [false, true] {
            let (w, store, root) = setup();
            let t = Mock::new();
            t.add(pid(1), Duration::from_millis(20), honest(w.clone()));
            t.add(pid(2), Duration::from_millis(20), honest(w));
            let f = fetcher(t.clone(), store);
            f.book().lock().success(pid(1), Duration::from_millis(1));
            let held =
                f.permits.clone().acquire_many_owned(MAX_CONCURRENT_FETCHES as u32).await.unwrap();
            let judge = async {
                sleep(Duration::from_millis(100)).await;
                let now = Instant::now().into_std();
                let mut book = f.book().lock();
                if ban {
                    book.start(pid(1));
                    book.ban(pid(1), now);
                } else {
                    for _ in 0..BENCH_AFTER {
                        book.start(pid(1));
                        book.failure(pid(1), now);
                    }
                }
                drop(book);
                drop(held);
            };
            let (res, ()) = tokio::join!(f.fetch_account(root, A1), judge);
            res.unwrap();
            assert_eq!(t.seen.lock().get(&pid(1)), None, "ban: {ban}");
            assert_eq!(t.seen.lock().get(&pid(2)), Some(&1), "ban: {ban}");
            assert_eq!(f.book().lock().inflight(&pid(1)), 0, "ban: {ban}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_large_fetch_from_one_peer_stays_under_the_servers_default_rate() {
        let (w, store, root) = setup();
        let t = Mock::new();
        // A warm one-key lookup takes a few milliseconds.
        t.add(pid(1), Duration::from_millis(5), rate_limited(honest(w)));
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..1000).map(absent).collect();
        f.fetch(root, &misses).await.unwrap();
        assert_eq!(t.calls.load(Ordering::SeqCst), misses.len(), "no request was answered empty");
    }

    #[tokio::test(start_paused = true)]
    async fn callers_that_give_up_in_the_pace_wait_do_not_delay_later_requests() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(5), honest(w));
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let interval = Duration::from_secs(1) / PEER_RATE;
        // The burst is spent, so every request waits for its pace.
        let now = Instant::now().into_std();
        for _ in 0..PEER_BURST {
            f.book().lock().pace(pid(1), now);
        }
        // Callers that give up during that wait, faster than the pace refills.
        for _ in 0..300 {
            let gave_up = timeout(Duration::from_millis(1), f.fetch_account(root, A1)).await;
            assert!(gave_up.is_err());
        }
        let start = Instant::now();
        f.fetch_account(root, A1).await.unwrap();
        let took = start.elapsed();
        let most = interval * (MAX_CONCURRENT_FETCHES as u32 + 1) + Duration::from_millis(5);
        assert!(took <= most, "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_large_fetch_overflows_a_paced_static_peer_to_the_others() {
        let (w, store, root) = setup();
        let t = Mock::new();
        for n in 1..=3 {
            t.add(pid(n), Duration::from_millis(5), rate_limited(honest(w.clone())));
        }
        t.statics.lock().push(pid(1));
        let f = fetcher(t.clone(), store);
        let misses: Vec<MissKey> = (0..2000).map(absent).collect();
        let start = Instant::now();
        f.fetch(root, &misses).await.unwrap();
        let took = start.elapsed();
        assert_eq!(t.calls.load(Ordering::SeqCst), misses.len(), "a request was answered empty");
        // Past the bursts, three peers at their pace take a third of the time one would.
        let burst = 3 * PEER_BURST as usize;
        let paced = Duration::from_secs(1) * (misses.len() - burst) as u32 / (3 * PEER_RATE);
        assert!(took < paced + Duration::from_millis(500), "{took:?}");
        let seen = t.seen.lock();
        assert!((1..=3).all(|n| seen[&pid(n)] > PEER_BURST as usize), "{seen:?}");
    }

    /// Every main permit is taken for 3 s. The first attempt waits for one, and the hedge goes
    /// out one hedge delay after that attempt was queued, on a permit of its own pool.
    #[tokio::test(start_paused = true)]
    async fn a_request_waiting_for_a_permit_is_hedged_from_when_it_was_queued() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(20), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        f.book().lock().success(pid(1), Duration::from_millis(1));
        let held =
            f.permits.clone().acquire_many_owned(MAX_CONCURRENT_FETCHES as u32).await.unwrap();
        let release = async {
            sleep(Duration::from_secs(3)).await;
            drop(held);
        };
        let start = Instant::now();
        let fetch = async {
            f.fetch_account(root, A1).await.unwrap();
            start.elapsed()
        };
        let (took, ()) = tokio::join!(fetch, release);
        assert_eq!(took, PeerBook::hedge_delay(PROOF_TIMEOUT) + Duration::from_millis(20));
        let seen = t.seen.lock();
        assert_eq!((seen.get(&pid(1)), seen.get(&pid(2))), (None, Some(&1)), "{seen:?}");
    }

    /// A first attempt that waited 300 ms for its permit, less than the hedge delay, is hedged
    /// one hedge delay after it went out.
    #[tokio::test(start_paused = true)]
    async fn the_hedge_counts_from_when_the_request_went_out() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::from_secs(10), honest(w.clone()));
        t.add(pid(2), Duration::from_millis(20), honest(w));
        let f = fetcher(t.clone(), store);
        f.book().lock().success(pid(1), Duration::from_millis(1));
        let held =
            f.permits.clone().acquire_many_owned(MAX_CONCURRENT_FETCHES as u32).await.unwrap();
        let wait = Duration::from_millis(300);
        let release = async {
            sleep(wait).await;
            drop(held);
        };
        let start = Instant::now();
        let (res, ()) = tokio::join!(f.fetch_account(root, A1), release);
        res.unwrap();
        let took = start.elapsed();
        let hedged_at = wait + PeerBook::hedge_delay(PROOF_TIMEOUT);
        assert!(took >= hedged_at && took < hedged_at + Duration::from_millis(100), "{took:?}");
        assert_eq!(t.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_proof_with_too_many_nodes_is_bad() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(
            pid(1),
            Duration::ZERO,
            Arc::new(move |m, _| {
                let mut r = serve_snap(&w, m);
                if let Snap1Message::Shared(M::AccountRange(a)) = &mut r {
                    // The real proof, padded with junk nodes.
                    a.proof.extend((0..1000u32).map(|i| Bytes::from(i.to_be_bytes().to_vec())));
                }
                Ok(r)
            }),
        );
        let f = fetcher(t.clone(), store.clone());
        assert_eq!(f.fetch_account(root, A1).await.unwrap_err(), FetchError::Unverifiable);
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
        assert_eq!(store.bytes(), 0);
    }

    /// An honest answer padded with one node no trie can hold.
    fn oversized_node(w: Arc<World>) -> Behavior {
        Arc::new(move |m, _| {
            let mut r = serve_snap(&w, m);
            let junk = Bytes::from(vec![0xc0; MAX_PROOF_NODE_BYTES + 1]);
            match &mut r {
                Snap1Message::Shared(M::AccountRange(a)) => a.proof.push(junk),
                Snap1Message::Shared(M::StorageRanges(s)) => s.proof.push(junk),
                _ => {}
            }
            Ok(r)
        })
    }

    #[test]
    fn a_full_branch_node_is_the_largest_proof_node() {
        use alloy_rlp::Encodable;
        use alloy_trie::{
            nodes::{BranchNode, RlpNode},
            TrieMask,
        };
        let children = vec![RlpNode::word_rlp(&B256::repeat_byte(0xff)); 16];
        let branch = BranchNode::new(children, TrieMask::new(0xffff));
        assert_eq!(branch.length(), MAX_PROOF_NODE_BYTES);
    }

    #[tokio::test(start_paused = true)]
    async fn an_account_proof_with_an_oversized_node_is_bad() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, oversized_node(w));
        let f = fetcher(t.clone(), store.clone());
        assert_eq!(f.fetch_account(root, A1).await.unwrap_err(), FetchError::Unverifiable);
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
        assert_eq!(store.bytes(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_storage_proof_with_an_oversized_node_is_bad() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w.clone()));
        let f = fetcher(t.clone(), store.clone());
        f.fetch_account(root, A1).await.unwrap();
        let held = store.bytes();
        t.behavior.lock().insert(pid(1), (oversized_node(w), Duration::ZERO));
        let slot = B256::from(U256::from(2));
        assert_eq!(f.fetch_slots(root, A1, &[slot]).await.unwrap_err(), FetchError::Unverifiable);
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
        assert_eq!(store.bytes(), held);
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_alternating_good_and_bad_answers_is_benched() {
        let (w, store, root) = setup();
        let t = Mock::new();
        let (good, bad) = (honest(w.clone()), liar(w));
        t.add(
            pid(1),
            Duration::ZERO,
            Arc::new(move |m, n| if n % 2 == 1 { good(m, n) } else { bad(m, n) }),
        );
        let f = fetcher(t.clone(), store);
        f.fetch_account(root, A1).await.unwrap();
        assert!(f.fetch_account(root, A2).await.is_err(), "the bad answer is not used");
        // The good answer that follows does not clear it: it is never asked again.
        let n = t.calls.load(Ordering::SeqCst);
        for _ in 0..4 {
            assert!(f.fetch_account(root, A2).await.is_err());
        }
        assert_eq!(t.calls.load(Ordering::SeqCst), n);
        assert!(f.book().lock().is_banned(&pid(1), Instant::now().into_std()));
    }

    #[tokio::test(start_paused = true)]
    async fn unrequested_or_repeated_code_is_bad_and_never_stored() {
        let (w, store, _root) = setup();
        let asked = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        let other = Bytes::from_static(&[0x60, 1, 0xf3]);
        for extra in [other.clone(), w.codes[&asked].clone()] {
            let t = Mock::new();
            let (w, extra) = (w.clone(), extra.clone());
            t.add(
                pid(1),
                Duration::ZERO,
                Arc::new(move |m, _| {
                    let mut r = serve_snap(&w, m);
                    if let Snap1Message::Shared(M::ByteCodes(c)) = &mut r {
                        // Valid code, but not asked for (or asked for once only).
                        c.codes.push(extra.clone());
                    }
                    Ok(r)
                }),
            );
            let f = fetcher(t, store.clone());
            assert_eq!(f.fetch_codes(&[asked]).await.unwrap_err(), FetchError::Unverifiable);
            assert!(store.code(&asked).is_none());
            assert!(store.code(&keccak256(&other)).is_none());
        }
    }

    /// Five distinct contracts' code, by hash.
    fn five_codes() -> Vec<(B256, Bytes)> {
        (0..5u8)
            .map(|i| {
                let c = Bytes::from(vec![0x60, i, 0xf3]);
                (keccak256(&c), c)
            })
            .collect()
    }

    /// Answers a code request with at most `max` of the asked codes, in the asked order.
    fn serves_codes(codes: Vec<(B256, Bytes)>, max: usize) -> Behavior {
        Arc::new(move |m, _| {
            let Snap1Message::Shared(M::GetByteCodes(q)) = m else { panic!("{m:?}") };
            let codes = q
                .hashes
                .iter()
                .filter_map(|h| codes.iter().find(|(k, _)| k == h).map(|(_, c)| c.clone()))
                .take(max)
                .collect();
            Ok(Snap1Message::Shared(M::ByteCodes(ByteCodesMessage {
                request_id: q.request_id,
                codes,
            })))
        })
    }

    #[tokio::test(start_paused = true)]
    async fn code_a_peer_withholds_is_an_error_and_what_it_gave_is_kept() {
        let (_w, store, _root) = setup();
        let codes = five_codes();
        let hashes: Vec<B256> = codes.iter().map(|(h, _)| *h).collect();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, serves_codes(codes, 1));
        let f = fetcher(t.clone(), store.clone());
        assert_eq!(f.fetch_codes(&hashes).await.unwrap_err(), FetchError::NoSource);
        assert!(store.code(&hashes[0]).is_some());
        assert!(t.banned.lock().is_empty(), "short, not wrong");
    }

    #[tokio::test(start_paused = true)]
    async fn a_short_code_answer_moves_to_another_peer() {
        let (_w, store, _root) = setup();
        let codes = five_codes();
        let hashes: Vec<B256> = codes.iter().map(|(h, _)| *h).collect();
        let t = Mock::new();
        t.add(pid(1), Duration::from_millis(1), serves_codes(codes.clone(), 1));
        t.add(pid(2), Duration::from_millis(50), serves_codes(codes, usize::MAX));
        let f = fetcher(t.clone(), store.clone());
        f.book().lock().success(pid(1), Duration::from_millis(1));
        f.fetch_codes(&hashes).await.unwrap();
        assert!(hashes.iter().all(|h| store.code(h).is_some()));
        // No credit for the short answer: its latency estimate is still the seeded one.
        assert_eq!(f.book().lock().latency(&pid(1)), Some(Duration::from_millis(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_code_is_rejected() {
        let (w, store, _root) = setup();
        let t = Mock::new();
        t.add(
            pid(1),
            Duration::ZERO,
            Arc::new(move |m, _| {
                let mut r = serve_snap(&w, m);
                if let Snap1Message::Shared(M::ByteCodes(c)) = &mut r {
                    for code in &mut c.codes {
                        *code = Bytes::from_static(&[0xff]);
                    }
                }
                Ok(r)
            }),
        );
        let f = fetcher(t, store.clone());
        let h = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        assert_eq!(f.fetch_codes(&[h]).await.unwrap_err(), FetchError::Unverifiable);
        assert!(store.code(&h).is_none());
    }

    /// Honest, with `edit` applied to every response.
    fn edited(w: Arc<World>, edit: impl Fn(&mut Snap1Message) + Send + Sync + 'static) -> Behavior {
        Arc::new(move |m, _| {
            let mut r = serve_snap(&w, m);
            edit(&mut r);
            Ok(r)
        })
    }

    /// A fetcher whose store already holds A1's account, so slot fetches ask for the slot only.
    async fn with_a1_held(
        w: &Arc<World>,
        t: &Arc<Mock>,
        store: Arc<dyn NodeStore>,
    ) -> P2pFetcher<Mock> {
        t.add(pid(1), Duration::ZERO, honest(w.clone()));
        let f = fetcher(t.clone(), store);
        f.fetch_account(w.root, A1).await.unwrap();
        f
    }

    #[tokio::test(start_paused = true)]
    async fn a_reply_with_another_id_or_of_another_kind_is_not_used() {
        let (w, _, root) = setup();
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        let slot = B256::from(U256::from(2));
        let wrong_id = |r: &mut Snap1Message| match r {
            Snap1Message::Shared(M::AccountRange(r)) => r.request_id += 1,
            Snap1Message::Shared(M::StorageRanges(r)) => r.request_id += 1,
            Snap1Message::Shared(M::ByteCodes(r)) => r.request_id += 1,
            _ => {}
        };
        // An honest answer to a different question, under the asked id.
        let wrong_kind = |r: &mut Snap1Message| {
            let id = crate::net::wire::response_id(r).unwrap();
            *r = match r {
                Snap1Message::Shared(M::AccountRange(_)) => {
                    Snap1Message::Shared(M::ByteCodes(ByteCodesMessage {
                        request_id: id,
                        codes: vec![],
                    }))
                }
                _ => Snap1Message::Shared(M::AccountRange(
                    reth_eth_wire_types::snap::AccountRangeMessage {
                        request_id: id,
                        ..empty_range()
                    },
                )),
            };
        };
        let edits: [fn(&mut Snap1Message); 2] = [wrong_id, wrong_kind];
        for edit in edits {
            let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
            let t = Mock::new();
            let f = with_a1_held(&w, &t, store.clone()).await;
            let held = store.bytes();
            t.behavior.lock().insert(pid(1), (edited(w.clone(), edit), Duration::ZERO));
            let before = t.calls.load(Ordering::SeqCst);
            assert_eq!(f.fetch_account(root, A2).await.unwrap_err(), FetchError::NoSource);
            assert_eq!(f.fetch_slots(root, A1, &[slot]).await.unwrap_err(), FetchError::NoSource);
            assert_eq!(f.fetch_codes(&[code_hash]).await.unwrap_err(), FetchError::NoSource);
            // Each fetch asked in both passes until the fifth failure benched the peer; none of the
            // answers was used or punished as a lie.
            assert_eq!(t.calls.load(Ordering::SeqCst) - before, 5);
            assert_eq!(store.bytes(), held);
            assert!(store.code(&code_hash).is_none());
            assert!(t.banned.lock().is_empty());
            assert!(f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_tampered_or_renamed_slot_is_bad() {
        let (w, _, root) = setup();
        let slot = B256::from(U256::from(2));
        let tamper = |r: &mut Snap1Message| {
            if let Snap1Message::Shared(M::StorageRanges(s)) = r {
                s.slots[0][0].data = crate::verify::slot_rlp(U256::from(23));
            }
        };
        // The right value under another slot's hash is claimed zero, which the proof refutes.
        let rename = |r: &mut Snap1Message| {
            if let Snap1Message::Shared(M::StorageRanges(s)) = r {
                s.slots[0][0].hash = B256::repeat_byte(7);
            }
        };
        let edits: [fn(&mut Snap1Message); 2] = [tamper, rename];
        for edit in edits {
            let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
            let t = Mock::new();
            let f = with_a1_held(&w, &t, store.clone()).await;
            let held = store.bytes();
            t.behavior.lock().insert(pid(1), (edited(w.clone(), edit), Duration::ZERO));
            assert_eq!(
                f.fetch_slots(root, A1, &[slot]).await.unwrap_err(),
                FetchError::Unverifiable
            );
            assert_eq!(*t.banned.lock(), vec![pid(1)]);
            assert_eq!(store.bytes(), held);
            let st = PartialState::new(store, root);
            assert!(matches!(st.storage(&A1, U256::from(2)), Lookup::Miss(_)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_bad_slot_or_code_from_one_peer_is_retried_on_another() {
        let (w, _, root) = setup();
        let slot = B256::from(U256::from(2));
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        let tamper = |r: &mut Snap1Message| match r {
            Snap1Message::Shared(M::StorageRanges(s)) => {
                s.slots[0][0].data = crate::verify::slot_rlp(U256::from(23));
            }
            Snap1Message::Shared(M::ByteCodes(c)) => {
                c.codes.iter_mut().for_each(|code| *code = Bytes::from_static(&[0xff]));
            }
            _ => {}
        };
        for code in [false, true] {
            let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
            let t = Mock::new();
            // The liar answered A1's account well, so it is the faster, preferred peer.
            let f = with_a1_held(&w, &t, store.clone()).await;
            t.behavior.lock().insert(pid(1), (edited(w.clone(), tamper), Duration::ZERO));
            t.add(pid(2), Duration::from_millis(50), honest(w.clone()));
            let before = t.seen.lock()[&pid(1)];
            let st = PartialState::new(store.clone(), root);
            if code {
                f.fetch_codes(&[code_hash]).await.unwrap();
                assert!(matches!(st.code(&code_hash), Lookup::Hit(c) if c.len() == 5));
            } else {
                f.fetch_slots(root, A1, &[slot]).await.unwrap();
                assert_eq!(st.storage(&A1, U256::from(2)), Lookup::Hit(U256::from(22)));
            }
            assert_eq!(t.seen.lock()[&pid(1)], before + 1, "the liar was asked once (code {code})");
            assert_eq!(*t.banned.lock(), vec![pid(1)], "code {code}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_storage_or_code_answer_is_a_miss_not_a_lie() {
        let (w, _, root) = setup();
        let slot = B256::from(U256::from(2));
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        let empty = |r: &mut Snap1Message| match r {
            Snap1Message::Shared(M::StorageRanges(s)) => {
                s.slots.clear();
                s.proof.clear();
            }
            Snap1Message::Shared(M::ByteCodes(c)) => c.codes.clear(),
            _ => {}
        };
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
        let t = Mock::new();
        let f = with_a1_held(&w, &t, store.clone()).await;
        t.behavior.lock().insert(pid(1), (edited(w, empty), Duration::ZERO));
        assert_eq!(f.fetch_slots(root, A1, &[slot]).await.unwrap_err(), FetchError::NoSource);
        assert_eq!(f.fetch_codes(&[code_hash]).await.unwrap_err(), FetchError::NoSource);
        assert!(t.banned.lock().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_absent_account_or_an_empty_storage_trie_needs_no_slot_request() {
        let (w, store, root) = setup();
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w));
        let f = fetcher(t.clone(), store.clone());
        let slot = B256::from(U256::from(1));
        let absent = address!("00000000000000000000000000000000000dead1");
        f.fetch_slots(root, absent, &[slot]).await.unwrap();
        assert_eq!(t.calls.load(Ordering::SeqCst), 1, "the account only");
        // A2 has no storage: its slots are zero by its storage root.
        f.fetch_slots(root, A2, &[slot]).await.unwrap();
        assert_eq!(t.calls.load(Ordering::SeqCst), 2, "the account only");
        let st = PartialState::new(store, root);
        assert_eq!(st.storage(&absent, U256::from(1)), Lookup::Hit(U256::ZERO));
        assert_eq!(st.storage(&A2, U256::from(1)), Lookup::Hit(U256::ZERO));
    }

    /// An honest answer with its proof padded by junk nodes to `nodes` in all, or with `items`
    /// copies of its first item.
    fn padded(w: Arc<World>, nodes: Option<usize>, items: Option<usize>) -> Behavior {
        edited(w, move |r| {
            let (proof, n) = match r {
                Snap1Message::Shared(M::AccountRange(a)) => {
                    if let Some(k) = items {
                        a.accounts = vec![a.accounts[0].clone(); k];
                    }
                    (&mut a.proof, nodes)
                }
                Snap1Message::Shared(M::StorageRanges(s)) => {
                    if let Some(k) = items {
                        s.slots[0] = vec![s.slots[0][0].clone(); k];
                    }
                    (&mut s.proof, nodes)
                }
                _ => return,
            };
            if let Some(n) = n {
                let junk = (0u32..).map(|i| Bytes::from(i.to_be_bytes().to_vec()));
                let more = n - proof.len();
                proof.extend(junk.take(more));
            }
        })
    }

    #[tokio::test(start_paused = true)]
    async fn proof_and_item_counts_are_capped_at_their_limits() {
        let (w, _, root) = setup();
        let slot = B256::from(U256::from(2));
        for (nodes, items, ok) in [
            (Some(MAX_PROOF_NODES), None, true),
            (Some(MAX_PROOF_NODES + 1), None, false),
            (None, Some(16), true),
            (None, Some(17), false),
        ] {
            let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
            let t = Mock::new();
            t.add(pid(1), Duration::ZERO, padded(w.clone(), nodes, items));
            let f = fetcher(t.clone(), store.clone());
            let res = f.fetch_account(root, A1).await.map(|a| a.map(|a| a.balance));
            let want = if ok { Ok(Some(U256::from(100))) } else { Err(FetchError::Unverifiable) };
            assert_eq!(res, want, "account, {nodes:?} nodes, {items:?} items");
            // The same limits on a slot answer, with the account held.
            let t = Mock::new();
            let f = with_a1_held(&w, &t, store.clone()).await;
            t.behavior.lock().insert(pid(1), (padded(w.clone(), nodes, items), Duration::ZERO));
            let res = f.fetch_slots(root, A1, &[slot]).await;
            let want = if ok { Ok(()) } else { Err(FetchError::Unverifiable) };
            assert_eq!(res, want, "slot, {nodes:?} nodes, {items:?} items");
        }
        // Two slot lists for a one-account request.
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
        let t = Mock::new();
        let f = with_a1_held(&w, &t, store).await;
        let two_lists = edited(w.clone(), |r| {
            if let Snap1Message::Shared(M::StorageRanges(s)) = r {
                s.slots.push(s.slots[0].clone());
            }
        });
        t.behavior.lock().insert(pid(1), (two_lists, Duration::ZERO));
        assert_eq!(f.fetch_slots(root, A1, &[slot]).await, Err(FetchError::Unverifiable));
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
    }

    fn wire_receipt(cumulative: u64) -> WireReceipt {
        ReceiptWithBloom {
            receipt: alloy_consensus::EthereumReceipt {
                tx_type: alloy_consensus::TxType::Legacy,
                success: true,
                cumulative_gas_used: cumulative,
                logs: vec![],
            },
            logs_bloom: Default::default(),
        }
    }

    fn header_for(receipts: &[WireReceipt]) -> Header {
        Header {
            number: 7,
            receipts_root: alloy_consensus::proofs::calculate_receipt_root(receipts),
            ..Default::default()
        }
    }

    fn answers(r: Result<Vec<WireReceipt>, TransportError>) -> ReceiptsBehavior {
        Arc::new(move || r.clone().map(Some))
    }

    #[tokio::test(start_paused = true)]
    async fn receipts_are_verified_against_the_receipts_root() {
        let (w, store, _) = setup();
        let good = vec![wire_receipt(21_000), wire_receipt(42_000)];
        let header = header_for(&good);
        for (reply, want, banned) in [
            (Ok(good.clone()), Ok(good.clone()), false),
            (
                Ok(vec![wire_receipt(21_000), wire_receipt(42_001)]),
                Err(FetchError::Unverifiable),
                true,
            ),
            (Ok(good[..1].to_vec()), Err(FetchError::Unverifiable), true),
            (Ok(vec![]), Err(FetchError::Unverifiable), true),
            (Err(TransportError::Unexpected), Err(FetchError::NoSource), false),
            (Err(TransportError::Timeout), Err(FetchError::NoSource), false),
            (Err(TransportError::Disconnected), Err(FetchError::NoSource), false),
        ] {
            let t = Mock::new();
            t.add(pid(1), Duration::ZERO, honest(w.clone()));
            t.receipts.lock().insert(pid(1), answers(reply.clone()));
            let f = fetcher(t.clone(), store.clone());
            assert_eq!(f.fetch_receipts(&header).await, want, "{reply:?}");
            assert_eq!(t.banned.lock().contains(&pid(1)), banned, "{reply:?}");
            assert_eq!(f.book().lock().inflight(&pid(1)), 0);
        }
        // A block without transactions has no receipts, which is a good answer.
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w));
        t.receipts.lock().insert(pid(1), answers(Ok(vec![])));
        let f = fetcher(t, store);
        assert_eq!(f.fetch_receipts(&header_for(&[])).await, Ok(vec![]));
    }

    /// A peer that does not hold the block yet (one block behind) answers with an empty list. That
    /// is a miss, which good answers excuse, not a fault that benches an honest peer.
    #[tokio::test(start_paused = true)]
    async fn an_empty_receipts_answer_is_a_miss_not_a_fault() {
        let (w, store, _) = setup();
        let header = header_for(&[wire_receipt(21_000)]);
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w));
        t.receipts.lock().insert(pid(1), Arc::new(|| Ok(None)));
        let f = fetcher(t.clone(), store);
        // Three good answers excuse twelve empty ones; each fetch asks twice.
        for _ in 0..3 {
            f.book().lock().success(pid(1), Duration::from_millis(1));
        }
        for _ in 0..BENCH_AFTER {
            assert_eq!(f.fetch_receipts(&header).await, Err(FetchError::NoSource));
        }
        assert_eq!(t.calls.load(Ordering::SeqCst), 2 * BENCH_AFTER as usize);
        assert!(!f.book().lock().is_benched(&pid(1), Instant::now().into_std()));
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_receipts_from_one_peer_are_replaced_by_another_peers() {
        let (w, store, _) = setup();
        let good = vec![wire_receipt(21_000)];
        let t = Mock::new();
        t.add(pid(1), Duration::ZERO, honest(w.clone()));
        t.add(pid(2), Duration::from_millis(30), honest(w));
        t.receipts.lock().insert(pid(1), answers(Ok(vec![wire_receipt(1)])));
        t.receipts.lock().insert(pid(2), answers(Ok(good.clone())));
        let f = fetcher(t.clone(), store);
        f.book().lock().success(pid(1), Duration::from_millis(1));
        assert_eq!(f.fetch_receipts(&header_for(&good)).await, Ok(good));
        assert_eq!(*t.banned.lock(), vec![pid(1)]);
    }

    /// A store that logs every write, to check what the fetcher wrote.
    struct Recording {
        inner: Store,
        nodes: Mutex<Vec<(B256, Bytes)>>,
        codes: Mutex<Vec<(B256, Bytes)>>,
    }

    impl Recording {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: Store::in_memory(1 << 22),
                nodes: Mutex::default(),
                codes: Mutex::default(),
            })
        }
    }

    impl NodeStore for Recording {
        fn get(&self, hash: &B256) -> Option<Bytes> {
            self.inner.get(hash)
        }
        fn put(&self, hash: B256, node: Bytes) {
            self.nodes.lock().push((hash, node.clone()));
            self.inner.put(hash, node);
        }
        fn code(&self, hash: &B256) -> Option<Bytes> {
            self.inner.code(hash)
        }
        fn put_code(&self, hash: B256, code: Bytes) {
            self.codes.lock().push((hash, code.clone()));
            self.inner.put_code(hash, code);
        }
        fn bytes(&self) -> u64 {
            self.inner.bytes()
        }
    }

    fn paused<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(f)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// Whatever blobs a peer returns for whatever hashes were asked, only code whose hash
        /// was asked for reaches the store, with its exact bytes, and no more often than asked.
        #[test]
        fn only_asked_code_is_stored_and_only_as_often_as_asked(
            asked in proptest::collection::vec(0..6usize, 1..6),
            sent in proptest::collection::vec(0..8usize, 0..10),
        ) {
            let pool: Vec<(B256, Bytes)> = (0..8u8)
                .map(|i| {
                    let c = Bytes::from(vec![0x60, i, 0xf3]);
                    (keccak256(&c), c)
                })
                .collect();
            let hashes: Vec<B256> = asked.iter().map(|i| pool[*i].0).collect();
            let reply: Vec<Bytes> = sent.iter().map(|i| pool[*i].1.clone()).collect();
            let mut left = hashes.clone();
            let mut lie = false;
            for c in &reply {
                match left.iter().position(|h| *h == keccak256(c)) {
                    Some(at) => {
                        left.swap_remove(at);
                    }
                    None => {
                        lie = true;
                        break;
                    }
                }
            }
            let want = if lie {
                Err(FetchError::Unverifiable)
            } else if left.is_empty() {
                Ok(())
            } else {
                Err(FetchError::NoSource)
            };
            let store = Recording::new();
            let t = Mock::new();
            let codes = reply;
            t.add(
                pid(1),
                Duration::ZERO,
                Arc::new(move |m, _| {
                    let Snap1Message::Shared(M::GetByteCodes(q)) = m else { panic!("{m:?}") };
                    Ok(Snap1Message::Shared(M::ByteCodes(ByteCodesMessage {
                        request_id: q.request_id,
                        codes: codes.clone(),
                    })))
                }),
            );
            let f = fetcher(t.clone(), store.clone());
            let complete = want.is_ok();
            proptest::prop_assert_eq!(paused(f.fetch_codes(&hashes)), want);
            let replies = t.calls.load(Ordering::SeqCst);
            let stored = store.codes.lock();
            for (h, c) in stored.iter() {
                proptest::prop_assert_eq!(keccak256(c), *h);
                let times_asked = hashes.iter().filter(|x| *x == h).count();
                let times_stored = stored.iter().filter(|(x, _)| x == h).count();
                proptest::prop_assert!(times_asked > 0, "{h} was not asked for");
                proptest::prop_assert!(times_stored <= times_asked * replies);
            }
            if lie {
                proptest::prop_assert!(stored.is_empty());
            }
            if complete {
                proptest::prop_assert!(hashes.iter().all(|h| store.code(h).is_some()));
            }
        }
    }

    /// One way to spoil an honest snap reply.
    #[derive(Debug, Clone)]
    enum Garble {
        FlipBit { item: usize, at: usize, bit: u8 },
        Drop(usize),
        Swap(usize, usize),
        Add(Vec<u8>),
        Grow(usize, usize),
        Bump,
        Truncate,
        Rename(u8),
        OtherId,
        OtherKind,
    }

    fn garble() -> impl proptest::strategy::Strategy<Value = Garble> {
        use proptest::prelude::*;
        prop_oneof![
            3 => (any::<usize>(), any::<usize>(), any::<u8>())
                .prop_map(|(item, at, bit)| Garble::FlipBit { item, at, bit }),
            1 => any::<usize>().prop_map(Garble::Drop),
            1 => (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Garble::Swap(a, b)),
            1 => proptest::collection::vec(any::<u8>(), 0..64).prop_map(Garble::Add),
            1 => (any::<usize>(), 1..600usize).prop_map(|(i, by)| Garble::Grow(i, by)),
            2 => Just(Garble::Bump),
            1 => Just(Garble::Truncate),
            1 => any::<u8>().prop_map(Garble::Rename),
            1 => Just(Garble::OtherId),
            1 => Just(Garble::OtherKind),
        ]
    }

    /// A reply's proof nodes, or a code reply's blobs.
    fn blobs(r: &mut Snap1Message) -> Option<&mut Vec<Bytes>> {
        match r {
            Snap1Message::Shared(M::AccountRange(a)) => Some(&mut a.proof),
            Snap1Message::Shared(M::StorageRanges(s)) => Some(&mut s.proof),
            Snap1Message::Shared(M::ByteCodes(c)) => Some(&mut c.codes),
            _ => None,
        }
    }

    fn spoil(r: &mut Snap1Message, g: &Garble) {
        match g {
            Garble::FlipBit { item, at, bit } => {
                if let Some(b) = blobs(r).filter(|b| !b.is_empty()) {
                    let i = item % b.len();
                    let mut v = b[i].to_vec();
                    if !v.is_empty() {
                        let j = at % v.len();
                        v[j] ^= 1 << (bit % 8);
                    }
                    b[i] = v.into();
                }
            }
            Garble::Drop(i) => {
                if let Some(b) = blobs(r).filter(|b| !b.is_empty()) {
                    b.remove(i % b.len());
                }
            }
            Garble::Swap(i, j) => {
                if let Some(b) = blobs(r).filter(|b| !b.is_empty()) {
                    let n = b.len();
                    b.swap(i % n, j % n);
                }
            }
            Garble::Add(v) => {
                if let Some(b) = blobs(r) {
                    b.push(v.clone().into());
                }
            }
            Garble::Grow(i, by) => {
                if let Some(b) = blobs(r).filter(|b| !b.is_empty()) {
                    let i = i % b.len();
                    let mut v = b[i].to_vec();
                    v.extend(std::iter::repeat_n(0x80, *by));
                    b[i] = v.into();
                }
            }
            Garble::Bump => match r {
                Snap1Message::Shared(M::AccountRange(a)) => {
                    if let Some(first) = a.accounts.first_mut() {
                        let mut acct = first.trie_account();
                        acct.nonce += 1;
                        *first = reth_eth_wire_types::snap::AccountData::from_trie_account(
                            first.hash, &acct,
                        );
                    }
                }
                Snap1Message::Shared(M::StorageRanges(s)) => {
                    if let Some(d) = s.slots.first_mut().and_then(|l| l.first_mut()) {
                        let v = <U256 as alloy_rlp::Decodable>::decode(&mut d.data.as_ref())
                            .unwrap_or_default();
                        d.data = crate::verify::slot_rlp(v.wrapping_add(U256::from(1)));
                    }
                }
                _ => {}
            },
            Garble::Truncate => match r {
                Snap1Message::Shared(M::AccountRange(a)) => a.accounts.clear(),
                Snap1Message::Shared(M::StorageRanges(s)) => s.slots.clear(),
                Snap1Message::Shared(M::ByteCodes(c)) => {
                    c.codes.pop();
                }
                _ => {}
            },
            Garble::Rename(b) => match r {
                Snap1Message::Shared(M::AccountRange(a)) => {
                    if let Some(first) = a.accounts.first_mut() {
                        first.hash = B256::repeat_byte(*b);
                    }
                }
                Snap1Message::Shared(M::StorageRanges(s)) => {
                    if let Some(d) = s.slots.first_mut().and_then(|l| l.first_mut()) {
                        d.hash = B256::repeat_byte(*b);
                    }
                }
                _ => {}
            },
            Garble::OtherId => match r {
                Snap1Message::Shared(M::AccountRange(r)) => r.request_id += 1,
                Snap1Message::Shared(M::StorageRanges(r)) => r.request_id += 1,
                Snap1Message::Shared(M::ByteCodes(r)) => r.request_id += 1,
                _ => {}
            },
            Garble::OtherKind => {
                let Some(id) = crate::net::wire::response_id(r) else { return };
                *r = match r {
                    Snap1Message::Shared(M::ByteCodes(_)) => Snap1Message::Shared(M::AccountRange(
                        reth_eth_wire_types::snap::AccountRangeMessage {
                            request_id: id,
                            ..empty_range()
                        },
                    )),
                    _ => Snap1Message::Shared(M::ByteCodes(ByteCodesMessage {
                        request_id: id,
                        codes: vec![],
                    })),
                };
            }
        }
    }

    const ABSENT: Address = address!("00000000000000000000000000000000000dead1");

    /// The account and slot reads of the property below, each the value or an error.
    type Reads = (
        [Result<Option<ProvenAccount>, FetchError>; 3],
        Result<(), FetchError>,
        Result<(), FetchError>,
    );

    async fn read_all(f: &P2pFetcher<Mock>, root: B256) -> Reads {
        let slots = [1u64, 2, 99].map(|s| B256::from(U256::from(s)));
        let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
        (
            [
                f.fetch_account(root, A1).await,
                f.fetch_account(root, A2).await,
                f.fetch_account(root, ABSENT).await,
            ],
            f.fetch_slots(root, A1, &slots).await,
            f.fetch_codes(&[code_hash]).await,
        )
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// A peer that spoils every reply in some way never gets a wrong value into a fetch
        /// result or the store: every stored node and blob hashes to its key, and every read
        /// is the true value or a miss. With an honest peer beside it, every read succeeds.
        #[test]
        fn a_garbled_reply_is_never_used(
            garbles in proptest::collection::vec(garble(), 1..4),
            with_honest: bool,
        ) {
            paused(async {
                let (w, truth_store, root) = setup();
                let truth_peer = Mock::new();
                truth_peer.add(pid(1), Duration::ZERO, honest(w.clone()));
                let truth = read_all(&fetcher(truth_peer, truth_store.clone()), root).await;

                let store = Recording::new();
                let t = Mock::new();
                let gs = garbles.clone();
                t.add(pid(1), Duration::ZERO, edited(w.clone(), move |r| gs.iter().for_each(|g| spoil(r, g))));
                if with_honest {
                    t.add(pid(2), Duration::from_millis(30), honest(w.clone()));
                }
                let f = fetcher(t, store.clone());
                // The spoiling peer is asked first.
                f.book().lock().success(pid(1), Duration::from_millis(1));
                let got = read_all(&f, root).await;

                for (g, want) in got.0.iter().zip(&truth.0) {
                    if let Ok(v) = g {
                        proptest::prop_assert_eq!(Ok(*v), want.clone());
                    }
                }
                if with_honest {
                    proptest::prop_assert_eq!(&got, &truth);
                }
                for (h, n) in store.nodes.lock().iter().chain(store.codes.lock().iter()) {
                    proptest::prop_assert_eq!(keccak256(n), *h);
                }
                let (st, real) = (PartialState::new(store, root), PartialState::new(truth_store, root));
                for a in [A1, A2, ABSENT] {
                    let got = st.account(&a);
                    proptest::prop_assert!(
                        matches!(got, Lookup::Miss(_)) || got == real.account(&a),
                        "{a}: {got:?}"
                    );
                    proptest::prop_assert!(!with_honest || matches!(got, Lookup::Hit(_)));
                }
                for slot in [1u64, 2, 99].map(U256::from) {
                    let got = st.storage(&A1, slot);
                    proptest::prop_assert!(
                        matches!(got, Lookup::Miss(_)) || got == real.storage(&A1, slot),
                        "{slot}: {got:?}"
                    );
                    proptest::prop_assert!(!with_honest || matches!(got, Lookup::Hit(_)));
                }
                let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
                let got = st.code(&code_hash);
                proptest::prop_assert!(matches!(got, Lookup::Miss(_)) || got == real.code(&code_hash));
                Ok(())
            })?;
        }
    }

    /// How a peer in the cancellation property behaves.
    #[derive(Debug, Clone, Copy)]
    enum Mode {
        Honest,
        Fail,
        Empty,
        Lie,
        Silent,
    }

    fn mode() -> impl proptest::strategy::Strategy<Value = Mode> {
        use proptest::prelude::*;
        prop_oneof![
            Just(Mode::Honest),
            Just(Mode::Fail),
            Just(Mode::Empty),
            Just(Mode::Lie),
            Just(Mode::Silent),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// Fetches of every kind, run together and dropped at arbitrary points (waiting for a
        /// permit, in flight, hedged, in the retry pause), leave no request counted in flight,
        /// return every permit, and never had more than the cap of requests out.
        #[test]
        fn dropped_fetches_leave_no_request_in_flight_and_no_permit_taken(
            peers in proptest::collection::vec((mode(), 0..3000u64), 1..4),
            ops in proptest::collection::vec((0..4u8, 0..6000u64), 1..5),
        ) {
            paused(async {
                let (w, store, root) = setup();
                let good = vec![wire_receipt(21_000)];
                let t = Mock::new();
                for (i, (mode, ms)) in peers.iter().enumerate() {
                    let peer = pid(i as u8 + 1);
                    let (b, delay): (Behavior, u64) = match mode {
                        Mode::Honest => (honest(w.clone()), *ms),
                        Mode::Fail => (Arc::new(|_, _| Err(TransportError::Disconnected)), *ms),
                        Mode::Empty => (
                            edited(w.clone(), |r| {
                                if let Some(b) = blobs(r) {
                                    b.clear();
                                }
                                spoil(r, &Garble::Truncate);
                            }),
                            *ms,
                        ),
                        Mode::Lie => (liar(w.clone()), *ms),
                        Mode::Silent => (honest(w.clone()), 60_000),
                    };
                    t.add(peer, Duration::from_millis(delay), b);
                    let receipts = match mode {
                        Mode::Honest | Mode::Silent => answers(Ok(good.clone())),
                        Mode::Lie => answers(Ok(vec![wire_receipt(1)])),
                        Mode::Fail => answers(Err(TransportError::Unexpected)),
                        Mode::Empty => Arc::new(|| Ok(None)),
                    };
                    t.receipts.lock().insert(peer, receipts);
                }
                let f = fetcher(t.clone(), store);
                let header = header_for(&good);
                let code_hash = keccak256([0x60, 0, 0x60, 0, 0xf3]);
                let misses: Vec<MissKey> = (0..40)
                    .map(absent)
                    .chain([MissKey::Slot(A1, B256::from(U256::from(2))), MissKey::Code(code_hash)])
                    .collect();
                let runs = ops.iter().map(|(which, at)| {
                    let (f, misses, header) = (&f, &misses, &header);
                    async move {
                        let op: futures::future::LocalBoxFuture<'_, ()> = match which {
                            0 => Box::pin(async move { let _ = f.fetch_account(root, A1).await; }),
                            1 => Box::pin(async move { let _ = f.fetch(root, misses).await; }),
                            2 => Box::pin(async move { let _ = f.fetch_codes(&[code_hash]).await; }),
                            _ => Box::pin(async move { let _ = f.fetch_receipts(header).await; }),
                        };
                        let _ = timeout(Duration::from_millis(*at), op).await;
                    }
                });
                futures::future::join_all(runs).await;
                // Requests still out when another peer answered first land by their timeout.
                sleep(CODE_TIMEOUT).await;
                let book = f.book().lock();
                for i in 0..peers.len() {
                    proptest::prop_assert_eq!(book.inflight(&pid(i as u8 + 1)), 0, "peer {}", i + 1);
                    proptest::prop_assert_eq!(book.held(&pid(i as u8 + 1)), 0, "peer {}", i + 1);
                }
                proptest::prop_assert_eq!(book.quiet_held(), 0);
                proptest::prop_assert_eq!(f.permits.available_permits(), MAX_CONCURRENT_FETCHES);
                proptest::prop_assert_eq!(f.hedge_permits.available_permits(), HEDGE_PERMITS);
                let most = MAX_CONCURRENT_FETCHES + HEDGE_PERMITS;
                proptest::prop_assert!(t.max_inflight.load(Ordering::SeqCst) <= most);
                Ok(())
            })?;
        }
    }
}
