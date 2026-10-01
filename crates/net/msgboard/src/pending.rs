//! In-flight request tracking for announced message IDs.
//!
//! Gossip converges by every peer announcing every message. Without in-flight
//! tracking, `filter_wanted` accepts an ID until the moment it lands in the
//! index, so each of the N peers that announce a new message gets its own
//! `GetBoardMessages` request. All N answer, and the board pays a full `PoW`
//! verification for each — a secp256k1 scalar multiplication — to keep one.
//!
//! The waste cannot be removed inside verification. A message's index key is
//! the sha256 of its compressed `PoW` point, so nothing can look a message up
//! without first paying for its `PoW`. The only place to spend less is before the request goes out,
//! which is what [`PendingRequests`] does.
//!
//! Measured on the production fleet before this existed (2026-08-17):
//!
//! | box | `requests_sent` | `accepted_remote` | `skipped_duplicate` |
//! |---|---|---|---|
//! | `direct-a-evm-943` | 445 | 45 | 400 (90%) |
//! | `direct-a-evm-1` | 65 | 1 | 64 (98%) |

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

use alloy_primitives::B256;
use reth_msgboard_types::{MsgID, MAX_GET_BOARD_MESSAGES};
use reth_network_api::PeerId;
// The tokio clock, so tests can pause and advance time through these TTLs.
use tokio::time::Instant;

use crate::protocol::{SERVE_MIN_BURST_BYTES, SERVE_REFILL_BYTES_PER_SEC};

/// What [`RequestPacer`] keeps back from a responder's reply budget.
pub(crate) const PACE_RESERVE_BYTES: u64 = 256 * 1024;

/// The burst [`RequestPacer`] allows: the smallest reth reply burst, less the
/// reserve.
const PACE_BURST_BYTES: u64 = SERVE_MIN_BURST_BYTES - PACE_RESERVE_BYTES;

/// The refill rate [`RequestPacer`] assumes: 90% of the responder's.
const PACE_REFILL_BYTES_PER_SEC: u64 = SERVE_REFILL_BYTES_PER_SEC / 10 * 9;

/// How long a claimed ID blocks further requests for the same message.
///
/// This covers one request/response round trip. A peer that answers releases
/// the claim by supplying the message, which puts it in the index and makes
/// the claim irrelevant. A peer that never answers holds the claim only until
/// this expires, after which another peer's announcement is requested instead.
///
/// Ten seconds is well above any realistic RTT and far below the message
/// lifetime (`block_range` = 120 blocks ≈ 20 minutes), so a silent peer costs
/// under 1% of the window during which the message could still be fetched.
pub(crate) const PENDING_REQUEST_TTL: Duration = Duration::from_secs(10);

/// Maximum number of simultaneously claimed IDs.
///
/// The map is keyed by peer-supplied IDs, so it needs a bound: an ID passes
/// `filter_wanted` on its declared fields alone, and a peer can mint unlimited
/// IDs that carry a live block hash but correspond to no real message.
///
/// 8192 entries is roughly 1.3 MB at `MSG_ID_SIZE` = 121 plus map overhead,
/// and sits far above any honest in-flight count — one announcement frame
/// holds at most 846 IDs, so this absorbs nearly ten peers announcing wholly
/// disjoint full frames at once.
pub(crate) const MAX_PENDING_REQUESTS: usize = 8192;

/// Maximum number of claims one peer may own at once.
///
/// Without it one peer can fill [`MAX_PENDING_REQUESTS`] with fabricated IDs
/// (they need no `PoW`) and switch off deduplication for everybody. At this
/// figure a flood needs eight peers to fill the map. It is above
/// `MAX_IDS_PER_FRAME` = 846, so one full announcement frame always fits.
pub(crate) const MAX_CLAIMS_PER_PEER: usize = 1024;

/// Maximum number of later announcers remembered per claim.
///
/// When a claim expires with its message still missing, the next of these is
/// asked. A peer that announces and then withholds can therefore delay a
/// message by one TTL per withholding peer asked, not suppress it.
///
/// When the list is full, the list is a uniform random sample of the
/// distinct announcers seen so far (reservoir sampling; see
/// [`Claim::admit`]). The attacker cannot pick which honest announcer to push
/// out, and announcing again buys nothing, because each peer counts once (see
/// [`SeenFilter`]). With `k` distinct announcers, each one is in the list with
/// odds 16/k. Memory is 16 x 64 bytes per claim at most.
pub(crate) const MAX_ALTERNATES: usize = 16;

/// Bits in the per-claim filter of peers that already announced the ID.
///
/// 4096 bits is 512 bytes per claim, 4 MiB at [`MAX_PENDING_REQUESTS`]. See
/// [`SeenFilter`] for the false-positive rate.
const SEEN_FILTER_BITS: usize = 4096;

/// Announcers per subnet that enter one claim's reservoir draw.
///
/// Distinct peer IDs are free, and inbound connections are cheap to open from
/// one address range. Counting at most two announcers per IPv4 /24 or IPv6
/// /56 makes each draw ticket cost a real network prefix: to cut an honest
/// announcer's odds to 16/k, an attacker needs about k/2 distinct prefixes.
/// Further announcers from a full subnet are never candidates. A peer already
/// counted in the subnet re-enters from a new session without a new slot.
/// Trusted peers are never capped.
const MAX_CANDIDATES_PER_SUBNET: u8 = 2;

/// Candidates after which a claim's reservoir is frozen.
///
/// Past this count no peer is inserted into the [`SeenFilter`] and none enters
/// the draw, so the filter's false-positive rate stays at its figure for 1000
/// entries, about 14%, instead of climbing towards saturation. Honest odds at
/// the freeze are 16/1000, which needs about 500 distinct prefixes to reach.
const MAX_DRAW_CANDIDATES: u64 = 1000;

/// Window in which repeated withholding counts as a pattern.
pub(crate) const WITHHOLD_WINDOW: Duration = Duration::from_secs(60);

/// Withholding events inside [`WITHHOLD_WINDOW`] that earn the larger penalty.
pub(crate) const WITHHOLD_STRIKES: usize = 3;

/// Peers whose withholding strikes are remembered at once.
///
/// Peer IDs are free to mint, so the map needs a bound. A peer enters only by
/// withholding on a live connection, and leaves once its strikes age out of
/// [`WITHHOLD_WINDOW`]. Filling the map needs this many connections that
/// withhold inside one window. Memory is about 100 bytes per peer.
///
/// Known limit: 4096 fresh peer IDs that each withhold once inside one window
/// fill the map and push out older entries, which resets those peers to zero
/// strikes. That costs the attacker 4096 connections in a minute; the small
/// penalty for each event still applies.
pub(crate) const MAX_STRUCK_PEERS: usize = 4096;

/// How long a reservation authorises a peer to deliver one message.
///
/// Erigon's `WantTimeout` (`msgboard/protocol.go`). It is deliberately longer
/// than [`PENDING_REQUEST_TTL`]: the claim stops us re-asking, and it must
/// expire first so another peer can be asked, while the reservation still
/// authorises the original peer's late answer.
pub(crate) const WANT_TIMEOUT: Duration = Duration::from_secs(15);

/// Reservations one peer may hold at once.
///
/// Erigon's `MaxWantPerPeer`. It bounds what a peer can make us verify: to buy
/// one scalar multiplication it must first announce an ID we want, and it can
/// be owed at most this many at a time. Above `MAX_IDS_PER_FRAME` = 846, so a
/// peer announcing a full frame is never refused.
///
/// Erigon also caps the total across peers at `MaxWantEntries` = 4096. Reth has
/// no equivalent: the list is per connection, so the fleet-wide bound is this
/// figure times the msgboard peer count — 32 KiB of hashes per peer.
pub(crate) const MAX_WANT_PER_PEER: usize = 1024;

/// Peers that did not announce an exhausted claim's ID and are asked for it.
///
/// A claim is exhausted when every announcer it remembered was asked and none
/// delivered. Three extra requests reach an honest holder when most peers are
/// honest, and they cost each peer asked one lookup of a hash.
pub(crate) const SPECULATIVE_PEERS_PER_CLAIM: usize = 3;

/// Requests to non-announcers allowed per second, across all claims.
///
/// An attacker exhausts a claim cheaply: it announces an ID that backs no
/// message and withholds it. Without a global bound, each such ID would make
/// us ask [`SPECULATIVE_PEERS_PER_CLAIM`] honest peers for nothing. At 16 per
/// second the worst case is 16 hash lookups per second spread over our peers.
pub(crate) const MAX_SPECULATIVE_FETCHES_PER_SEC: u32 = 16;

/// Exhausted claims that wait for [`PendingRequests::settle_exhausted`].
///
/// The queue holds one claim per first-owner subnet, so 64 subnets must
/// exhaust claims at once to fill it. Past it a claim is still counted but
/// gets no speculative fetch, unless it has priority and replaces the oldest
/// claim without priority.
const MAX_QUEUED_EXHAUSTED: usize = 64;

/// How long an exhausted claim may wait for speculative budget.
///
/// A message lives about 20 minutes (`block_range` = 120 blocks). A claim the
/// budget has not served within a minute is dropped, so a long flood cannot
/// keep stale entries in the queue.
const MAX_EXHAUSTED_AGE: Duration = Duration::from_secs(60);

/// Tracks message IDs that have been requested but not yet received.
///
/// Each claim records the peer that was asked (the owner) and up to
/// [`MAX_ALTERNATES`] later announcers. When a claim expires and the message
/// is still missing, the sweep moves the claim to the next alternate and
/// queues a retry for that peer. Its connection task collects the retry with
/// [`take_retries`](Self::take_retries) and sends the request.
///
/// Erigon has no alternates: a peer that announces and withholds costs erigon
/// the message until some peer announces it again. This is stricter than
/// erigon about *fetching*. It does not change which messages the board
/// accepts.
///
/// Residual risk: an attacker that controls most of our msgboard peers can
/// still delay delivery, one TTL per withholding peer asked, or cause its loss
/// for this node if every alternate withholds and no peer it asks without an
/// announcement holds the message. Each distinct announcer counts once per
/// claim and session, so an attacker lowers an
/// honest announcer's odds of staying in the list only by adding connections:
/// with `k` distinct announcers the odds are 16/k. Hand-offs go through the
/// alternates, and each peer enters them at most once per claim and session,
/// so every hand-off, and every TTL of delay, costs the attacker one more
/// connection that announced the ID.
///
/// Three things narrow that risk. A peer re-enters a claim from a new session,
/// so an honest peer that reconnects and re-announces is asked again. Trusted
/// peers (reth `PeerKind::Trusted`) are asked first after the owner and never
/// leave the alternates by the draw. A claim that runs out of announcers asks
/// up to [`SPECULATIVE_PEERS_PER_CLAIM`] peers that never announced the ID; see
/// [`settle_exhausted`](Self::settle_exhausted). Erigon has no alternates, so it loses the message
/// to the first withholding peer.
///
/// Not thread-safe on its own — [`MsgBoard`](crate::MsgBoard) keeps it inside
/// the state mutex that `filter_wanted` already holds.
#[derive(Debug)]
pub(crate) struct PendingRequests {
    claims: HashMap<MsgID, Claim>,
    /// Claims owned per peer, for [`MAX_CLAIMS_PER_PEER`].
    owned: HashMap<PeerId, usize>,
    /// IDs the sweep moved to a peer that its connection task has not yet
    /// requested. Entries can go stale; [`take_retries`](Self::take_retries)
    /// checks each one against its claim.
    retries: HashMap<PeerId, Vec<MsgID>>,
    ttl: Duration,
    capacity: usize,
    /// Earliest instant the next full sweep may run.
    next_sweep: Option<Instant>,
    /// Peers that withheld, and when. Alternates with a strike inside
    /// [`WITHHOLD_WINDOW`] are asked last. A strike never decides eviction.
    struck: HashMap<PeerId, Instant>,
    /// Withholding events per peer, for the escalated penalty.
    strikes: WithholdStrikes,
    /// Xorshift state for picking which alternate a full list replaces.
    rng: u64,
    /// Process-random key for [`SeenFilter`], so a remote peer cannot pick
    /// peer IDs that collide with an honest one.
    seen_key: std::collections::hash_map::RandomState,
    /// Live `msg/1` sessions. One entry per connected peer, so the map is
    /// bounded by the peer count.
    sessions: HashMap<PeerId, PeerSession>,
    /// The id the next session gets. Starts at 1: 0 means "no session known".
    next_session: u64,
    /// Claims the sweep found exhausted, for
    /// [`settle_exhausted`](Self::settle_exhausted).
    exhausted: Vec<Exhausted>,
    /// Claims exhausted since the last
    /// [`settle_exhausted`](Self::settle_exhausted), including ones past
    /// [`MAX_QUEUED_EXHAUSTED`].
    exhausted_count: u64,
    /// Message IDs to request from peers that never announced them. See
    /// [`take_speculative`](Self::take_speculative).
    speculative: HashMap<PeerId, Vec<MsgID>>,
    /// Start of the current one-second window for
    /// [`MAX_SPECULATIVE_FETCHES_PER_SEC`].
    speculative_window: Option<Instant>,
    /// Speculative requests queued in the current window.
    speculative_used: u32,
    /// First-owner subnets served in the current window.
    speculative_groups: Vec<Option<u64>>,
}

impl PendingRequests {
    /// Create a tracker with the given expiry and entry cap.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            claims: HashMap::new(),
            owned: HashMap::new(),
            retries: HashMap::new(),
            ttl,
            capacity,
            next_sweep: None,
            struck: HashMap::new(),
            strikes: WithholdStrikes::default(),
            // Seeded from the process's random hasher keys, so a remote peer
            // cannot predict the sequence. `| 1` keeps xorshift off zero.
            rng: {
                use std::hash::{BuildHasher, Hasher};
                std::collections::hash_map::RandomState::new().build_hasher().finish() | 1
            },
            seen_key: std::collections::hash_map::RandomState::new(),
            sessions: HashMap::new(),
            next_session: 1,
            exhausted: Vec::new(),
            exhausted_count: 0,
            speculative: HashMap::new(),
            speculative_window: None,
            speculative_used: 0,
            speculative_groups: Vec::new(),
        }
    }

    /// Try to claim `id` for a request to `peer`.
    ///
    /// Returns `true` when the caller should send the request, `false` when
    /// another peer's announcement already claimed it and the claim is live.
    /// A refused peer is kept as an alternate for the claim.
    ///
    /// Claims are **not** rejected when the map is full or `peer` is at
    /// [`MAX_CLAIMS_PER_PEER`]: the request goes out, but nothing is recorded.
    /// Failing closed would let whoever fills the map block every real ID
    /// announced after it. The per-peer quota stops one peer from filling the
    /// map; failing open stops many peers that fill it together from censoring
    /// anything. The cost is the duplicate requests this type exists to avoid,
    /// which is strictly better than dropping messages we actually want.
    #[cfg(test)]
    pub(crate) fn claim(&mut self, id: MsgID, peer: PeerId, now: Instant) -> bool {
        self.claim_from(id, peer, None, now)
    }

    /// [`claim`](Self::claim) for an announcer whose remote address is in
    /// `subnet` (see [`subnet_of`]). Announcers with no known subnet are
    /// never capped per subnet.
    pub(crate) fn claim_from(
        &mut self,
        id: MsgID,
        peer: PeerId,
        subnet: Option<u64>,
        now: Instant,
    ) -> bool {
        let Self { claims, owned, retries, struck, rng, ttl, capacity, seen_key, sessions, .. } =
            self;
        let keys = AnnouncerKeys::of(seen_key, sessions, peer);
        let Some(claim) = claims.get_mut(&id) else {
            let held = owned.get(&peer).copied().unwrap_or_default();
            if claims.len() < *capacity && held < MAX_CLAIMS_PER_PEER {
                claims.insert(
                    id,
                    Claim {
                        claimed_at: now,
                        owner: peer,
                        alternates: Vec::new(),
                        seen: SeenFilter::with(keys.session),
                        announcers: SeenFilter::with(keys.peer),
                        group: subnet,
                        trusted_announcer: is_trusted(sessions, &peer),
                        candidates: 0,
                        subnets: Vec::new(),
                        retry: false,
                        tried: 1,
                        tried_subnets: subnet.into_iter().collect(),
                    },
                );
                *owned.entry(peer).or_default() += 1;
            }
            return true;
        };
        if now.duration_since(claim.claimed_at) >= *ttl {
            if claim.alternates.is_empty() {
                // An expired claim with nobody waiting is re-taken rather than
                // left to the sweep, so a peer that went silent does not
                // delay the retry past the TTL.
                let previous = std::mem::replace(&mut claim.owner, peer);
                claim.claimed_at = now;
                claim.retry = false;
                if claim.candidates < MAX_DRAW_CANDIDATES {
                    claim.seen.insert(keys.session);
                    claim.announcers.insert(keys.peer);
                }
                claim.note_tried(subnet);
                decrement(owned, previous);
                *owned.entry(peer).or_default() += 1;
                return true;
            }
            // Peers are waiting. Do what the sweep would do, so an announcer
            // that arrives just after expiry cannot jump the queue.
            decrement(owned, claim.owner);
            claim.hand_to_next_alternate(now, struck, sessions, owned, retries, id);
        }
        claim.admit(peer, keys, subnet, sessions, rng);
        false
    }

    /// Give up the claim on `id`.
    ///
    /// Called when the request that a claim was taken for never reached
    /// `peer`. If an alternate announced the ID, the claim moves to it at once.
    /// Otherwise the claim is dropped, so the next announcement re-requests it
    /// instead of waiting out the TTL.
    ///
    /// Does nothing unless `peer` still owns the claim. A request frame can
    /// wait longer than the TTL before it is dropped, and by then the claim may
    /// belong to another peer.
    pub(crate) fn release(&mut self, id: &MsgID, peer: PeerId, now: Instant) {
        let Some(claim) = self.claims.get_mut(id) else { return };
        if claim.owner != peer {
            return;
        }
        let previous = claim.owner;
        if claim.alternates.is_empty() {
            self.claims.remove(id);
        } else {
            claim.hand_to_next_alternate(
                now,
                &self.struck,
                &self.sessions,
                &mut self.owned,
                &mut self.retries,
                *id,
            );
        }
        decrement(&mut self.owned, previous);
    }

    /// Run [`sweep`](Self::sweep) if the last one was long enough ago.
    ///
    /// A sweep is O(map size) and runs under the board mutex, so it runs at
    /// most ten times per TTL, not once per announcement. An expired claim
    /// that waits for the next sweep does no harm: [`claim`](Self::claim)
    /// re-takes it.
    pub(crate) fn maybe_sweep(&mut self, now: Instant, is_held: impl Fn(&MsgID) -> bool) {
        if self.next_sweep.is_some_and(|at| now < at) {
            return;
        }
        self.sweep(now, is_held);
        self.next_sweep = Some(now + self.ttl / 10);
    }

    /// Resolve every claim older than the TTL.
    ///
    /// The sweep drops a claim whose message `is_held`, or that has no
    /// alternate left. It moves any other expired claim to its next alternate
    /// and queues a retry for that peer.
    ///
    /// Dropping an exhausted claim re-arms its ID: the next peer to announce it
    /// claims it at once and is asked. A claim dropped with no alternate left
    /// and its message missing is kept for
    /// [`settle_exhausted`](Self::settle_exhausted), which the caller runs next.
    pub(crate) fn sweep(&mut self, now: Instant, is_held: impl Fn(&MsgID) -> bool) {
        let ttl = self.ttl;
        self.struck.retain(|_, at| now.duration_since(*at) < WITHHOLD_WINDOW);
        self.strikes.prune(now);
        let Self { claims, owned, retries, struck, sessions, exhausted, exhausted_count, .. } =
            self;
        claims.retain(|id, claim| {
            if now.duration_since(claim.claimed_at) < ttl {
                return true;
            }
            decrement(owned, claim.owner);
            if is_held(id) {
                return false;
            }
            if claim.alternates.is_empty() {
                // Every announcer the claim kept was asked, and none delivered.
                *exhausted_count += 1;
                let entry = Exhausted {
                    id: *id,
                    tried: claim.tried,
                    announcers: std::mem::replace(&mut claim.announcers, SeenFilter::empty()),
                    priority: claim.trusted_announcer || claim.tried_subnets.len() >= 2,
                    tried_subnets: std::mem::take(&mut claim.tried_subnets),
                    group: claim.group,
                    at: now,
                };
                queue_exhausted(exhausted, entry);
                return false;
            }
            claim.hand_to_next_alternate(now, struck, sessions, owned, retries, *id);
            true
        });
        // A retry goes stale when its claim moves on, for example to a later
        // alternate because the peer it was queued for has disconnected.
        retries.retain(|peer, ids| {
            ids.retain(|id| claims.get(id).is_some_and(|c| c.retry && c.owner == *peer));
            !ids.is_empty()
        });
    }

    /// Record that `peer` withheld a message it was asked for, first-hand or
    /// through a retry.
    pub(crate) fn note_withheld(&mut self, peer: PeerId, now: Instant) {
        self.struck.insert(peer, now);
    }

    /// Record one withholding event by `peer`. Returns `true` when it earns
    /// the larger penalty; see [`WithholdStrikes`].
    pub(crate) fn record_strike(&mut self, peer: PeerId, now: Instant) -> bool {
        self.strikes.record(peer, now)
    }

    /// Take the IDs the sweep moved to `peer`, and restart their TTL.
    ///
    /// The caller must request every returned ID from `peer`, or give it back
    /// with [`release`](Self::release).
    pub(crate) fn take_retries(&mut self, peer: PeerId, now: Instant) -> Vec<MsgID> {
        let Some(ids) = self.retries.remove(&peer) else { return Vec::new() };
        ids.into_iter()
            .filter(|id| match self.claims.get_mut(id) {
                Some(claim) if claim.retry && claim.owner == peer => {
                    claim.retry = false;
                    claim.claimed_at = now;
                    true
                }
                _ => false,
            })
            .collect()
    }

    /// Number of live claims. Test and metrics use only.
    pub(crate) fn len(&self) -> usize {
        self.claims.len()
    }

    /// Record a new `msg/1` session with `peer`, whose address is in `subnet`.
    /// Returns the session's id, for [`close_session`](Self::close_session).
    pub(crate) fn open_session(&mut self, peer: PeerId, subnet: Option<u64>) -> u64 {
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.insert(peer, PeerSession { id, subnet, trusted: false });
        id
    }

    /// Forget session `session` of `peer`. Does nothing when a newer session
    /// of the same peer replaced it.
    pub(crate) fn close_session(&mut self, peer: PeerId, session: u64) {
        if self.sessions.get(&peer).is_some_and(|s| s.id == session) {
            self.sessions.remove(&peer);
            self.speculative.remove(&peer);
        }
    }

    /// Mark session `session` of `peer` as one with a peer that reth trusts.
    pub(crate) fn set_trusted(&mut self, peer: PeerId, session: u64) {
        if let Some(s) = self.sessions.get_mut(&peer) &&
            s.id == session
        {
            s.trusted = true;
        }
    }

    /// Handle the claims the sweep found exhausted.
    ///
    /// Each one whose message `is_wanted` still is gets up to
    /// [`SPECULATIVE_PEERS_PER_CLAIM`] requests to connected peers that did
    /// not announce it, inside [`MAX_SPECULATIVE_FETCHES_PER_SEC`].
    ///
    /// The budget is shared fairly. Claims with a trusted announcer, or whose
    /// owners came from two or more subnets, go first, then the oldest. Each
    /// window serves at most one claim per first-owner subnet, and the queue
    /// keeps at most one claim per first-owner subnet (see
    /// [`queue_exhausted`]). A claim the budget cannot serve stays queued for
    /// a later window, for at most [`MAX_EXHAUSTED_AGE`].
    ///
    /// Returns how many claims were exhausted since the last call, and what
    /// happened to each claim this call finished with.
    pub(crate) fn settle_exhausted(
        &mut self,
        now: Instant,
        is_wanted: impl Fn(&MsgID) -> bool,
    ) -> (u64, Vec<ExhaustedClaim>) {
        if self
            .speculative_window
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(1))
        {
            self.speculative_window = Some(now);
            self.speculative_used = 0;
            self.speculative_groups.clear();
        }
        let count = std::mem::take(&mut self.exhausted_count);
        let mut queue = std::mem::take(&mut self.exhausted);
        queue.sort_by_key(|claim| (!claim.priority, claim.at));
        let mut settled = Vec::new();
        for claim in queue {
            let done = |asked| ExhaustedClaim { id: claim.id, tried: claim.tried, asked };
            if !is_wanted(&claim.id) || now.duration_since(claim.at) >= MAX_EXHAUSTED_AGE {
                settled.push(done(0));
            } else if self.speculative_used >= MAX_SPECULATIVE_FETCHES_PER_SEC ||
                self.speculative_groups.contains(&claim.group)
            {
                self.exhausted.push(claim);
            } else {
                self.speculative_groups.push(claim.group);
                let asked = self.ask_non_announcers(&claim);
                settled.push(done(asked));
            }
        }
        (count, settled)
    }

    /// Queue `claim`'s ID for up to [`SPECULATIVE_PEERS_PER_CLAIM`] connected
    /// peers that did not announce it, inside the global rate. Returns how
    /// many were queued.
    ///
    /// Trusted peers come first. Then peers outside the subnets already
    /// asked, one per subnet, in random order, so the attacker that withheld
    /// cannot predict or crowd out who is asked. A peer that announced in any
    /// session is never asked.
    fn ask_non_announcers(&mut self, claim: &Exhausted) -> usize {
        let room = MAX_SPECULATIVE_FETCHES_PER_SEC.saturating_sub(self.speculative_used) as usize;
        let want = SPECULATIVE_PEERS_PER_CLAIM.min(room);
        let Self { sessions, seen_key, rng, speculative, .. } = self;
        let mut candidates: Vec<_> = sessions
            .iter()
            .filter(|(peer, _)| {
                !claim.announcers.contains(std::hash::BuildHasher::hash_one(&*seen_key, **peer)) &&
                    speculative.get(*peer).is_none_or(|q| q.len() < MAX_GET_BOARD_MESSAGES)
            })
            .map(|(peer, session)| {
                let tried = session.subnet.is_some_and(|s| claim.tried_subnets.contains(&s));
                (!session.trusted, tried, next_random(rng), *peer, session.subnet)
            })
            .collect();
        candidates.sort_unstable();
        // One peer per subnet first; trusted peers are never held back.
        let mut picked = Vec::with_capacity(want);
        let mut subnets = Vec::with_capacity(want);
        for (untrusted, _, _, peer, subnet) in &candidates {
            if picked.len() == want {
                break;
            }
            if !untrusted || subnet.is_none_or(|s| !subnets.contains(&s)) {
                picked.push(*peer);
                subnets.extend(*subnet);
            }
        }
        for (_, _, _, peer, _) in &candidates {
            if picked.len() == want {
                break;
            }
            if !picked.contains(peer) {
                picked.push(*peer);
            }
        }
        for peer in &picked {
            speculative.entry(*peer).or_default().push(claim.id);
        }
        self.speculative_used += picked.len() as u32;
        picked.len()
    }

    /// Take the IDs queued for `peer` by
    /// [`settle_exhausted`](Self::settle_exhausted). `peer` never announced
    /// them, so the caller must request them in a way that never penalises
    /// `peer` for an empty answer.
    pub(crate) fn take_speculative(&mut self, peer: PeerId) -> Vec<MsgID> {
        self.speculative.remove(&peer).unwrap_or_default()
    }
}

/// What [`PendingRequests::settle_exhausted`] did with one exhausted claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExhaustedClaim {
    /// The claimed ID.
    pub(crate) id: MsgID,
    /// Announcers the claim asked before it ran out.
    pub(crate) tried: u32,
    /// Non-announcers queued to be asked for it.
    pub(crate) asked: usize,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new(PENDING_REQUEST_TTL, MAX_PENDING_REQUESTS)
    }
}

/// The messages one peer is authorised to deliver.
///
/// [`PendingRequests`] decides what we *ask* for; this decides what we are
/// willing to *pay* for when it arrives. They are separate questions and the
/// second one was unasked until now: the `BOARD_MESSAGES` arm handed whatever a
/// peer sent straight to `add_remote_msgs`, which runs a secp256k1 scalar
/// multiplication per message. One 100 KiB frame holds about 1,200 minimal
/// messages, so a peer that had requested nothing still bought ~1,200 scalar
/// multiplications on the connection task.
///
/// Mirrors erigon-pulse's `wantList` (`msgboard/want_list.go`, `pulse-v3.4.4`
/// `78fbcffb8b`), which keys pending requests by `(peer, hash)` and calls
/// `Take(peer, hash, now)` on the inbound path before any `PoW` work. One
/// instance lives in each connection task, so the peer half of erigon's key is
/// the instance itself and only the hash is stored.
///
/// [`take_kind`](Self::take_kind) spends the reservation for a named hash, mirroring
/// erigon's `Take(peer, hash, now)`. It relies on the claimed hash that
/// `WirePoWMsg` carries: without one, nothing identifies a delivery before
/// verification, because the index key is the sha256 of the compressed `PoW`
/// point.
#[derive(Debug)]
pub(crate) struct WantList {
    /// Reserved hashes in reservation order. Every entry shares one TTL, so
    /// insertion order is expiry order and the front is always the oldest.
    ///
    /// Spent and released entries stay here until they surface or a
    /// compaction removes them, so this can be longer than `live`.
    queue: VecDeque<Want>,
    /// Unspent reservations and the expiry of each. A queue entry cancels a
    /// reservation only when its expiry matches, so the expiry of an old,
    /// released reservation cannot cancel a newer one for the same hash.
    live: HashMap<B256, Live>,
    /// Reservations that expired unspent since the last
    /// [`take_expired`](Self::take_expired).
    expired: Expired,
    /// The request that new reservations belong to. See
    /// [`start_request`](Self::start_request).
    request: u64,
    /// Per request: reservations still unspent, and whether the peer answered
    /// any of it.
    requests: HashMap<u64, RequestState>,
    ttl: Duration,
    capacity: usize,
    /// Paces requests to this peer to what it will serve. See
    /// [`RequestPacer`].
    pub(crate) pacer: RequestPacer,
    /// The peer's subnet, from [`subnet_of`], for its claims.
    pub(crate) subnet: Option<u64>,
}

impl WantList {
    /// Create a want list with the given expiry and entry cap.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            live: HashMap::new(),
            expired: Expired::default(),
            request: 0,
            requests: HashMap::new(),
            ttl,
            capacity,
            pacer: RequestPacer::default(),
            subnet: None,
        }
    }

    /// Start a new request. Reservations made after this belong to it.
    ///
    /// A request is everything asked for in response to one announcement,
    /// which may span several frames. A peer that delivers any of it has
    /// answered it; see [`Expired::silent`].
    pub(crate) const fn start_request(&mut self) {
        self.request += 1;
    }

    /// Forget one unspent reservation of `request`, noting whether it was
    /// answered in part.
    fn settle(&mut self, request: u64, answered: bool) {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.requests.entry(request) {
            let state = e.get_mut();
            state.answered |= answered;
            state.outstanding -= 1;
            if state.outstanding == 0 {
                e.remove();
            }
        }
    }

    /// Drop every reservation older than the TTL.
    ///
    /// Expiry is lazy, as in erigon: `reserve` and `take` prune. The
    /// connection task also prunes on a timer, to find reservations a silent
    /// peer left unspent.
    pub(crate) fn prune(&mut self, now: Instant) {
        while let Some(front) = self.queue.front() {
            if now < front.expires_at {
                break;
            }
            let expired = self.queue.pop_front().expect("front exists");
            if self.live.get(&expired.hash).is_some_and(|l| l.expires_at == expired.expires_at) {
                let live = self.live.remove(&expired.hash).expect("checked above");
                match live.kind {
                    RequestKind::FirstHand => {
                        self.expired.first_hand += 1;
                        let answered = self.requests.get(&live.request).is_some_and(|r| r.answered);
                        self.expired.silent |= !answered;
                    }
                    RequestKind::Retry => self.expired.retries += 1,
                    // The peer never said it held the message.
                    RequestKind::Speculative => {}
                }
                self.settle(live.request, false);
            }
        }
    }

    /// Return what expired unspent since the last call, and reset it.
    pub(crate) fn take_expired(&mut self) -> Expired {
        std::mem::take(&mut self.expired)
    }

    /// Reserve `hash` for a first-hand request. Test use only.
    #[cfg(test)]
    pub(crate) fn reserve(&mut self, hash: B256, now: Instant) -> bool {
        self.reserve_kind(hash, now, RequestKind::FirstHand)
    }

    /// Reserve `hash`, authorising this peer to deliver one message, for a
    /// request of this `kind`.
    ///
    /// Returns `false` when the peer already owes us that hash or the list is
    /// full. Only unspent reservations count toward the cap, as in erigon
    /// (`msgboard/want_list.go`). Unlike [`PendingRequests::claim`] this fails
    /// **closed**, matching erigon's `Reserve`: a reservation we do not record
    /// is a message we would refuse to verify on arrival, so requesting it
    /// would waste the round trip. The caller must hand a refused ID back to
    /// [`PendingRequests`] rather than request it.
    ///
    /// Only a [`RequestKind::FirstHand`] reservation counts as withholding
    /// when it expires. A [`RequestKind::Retry`] reaches this peer a TTL or
    /// more after it announced, when it may have evicted or pruned the
    /// message, and a responder sends nothing for a hash it lacks. Its expiry
    /// counts only toward [`take_expired`](Self::take_expired)'s `retries`. A
    /// [`RequestKind::Speculative`] reservation goes to a peer that never
    /// announced the message, so its expiry counts for nothing at all.
    pub(crate) fn reserve_kind(&mut self, hash: B256, now: Instant, kind: RequestKind) -> bool {
        if self.live.contains_key(&hash) || self.live.len() >= self.capacity {
            return false;
        }
        // Spent entries wait in the queue until their TTL. Compact when they
        // outnumber the live ones, so the queue stays O(capacity) however fast
        // a peer spends its reservations. Each compaction removes at least
        // `capacity` entries, so its cost is amortised over them.
        if self.queue.len() >= 2 * self.capacity {
            let live = &self.live;
            self.queue.retain(|w| live.get(&w.hash).is_some_and(|l| l.expires_at == w.expires_at));
        }
        let expires_at = now + self.ttl;
        self.queue.push_back(Want { hash, expires_at });
        self.live.insert(hash, Live { expires_at, kind, request: self.request });
        self.requests.entry(self.request).or_default().outstanding += 1;
        true
    }

    /// Give back reservations for a request that never reached the peer.
    ///
    /// The queue entry is left in place and skipped when it surfaces, so this
    /// stays O(1) per hash. Mirrors erigon's `Drop`.
    pub(crate) fn release(&mut self, hashes: impl IntoIterator<Item = B256>) {
        for hash in hashes {
            if let Some(live) = self.live.remove(&hash) {
                self.settle(live.request, false);
            }
        }
    }

    /// Spend the reservation for `hash`, authorising one `PoW` verification.
    ///
    /// Returns `false` when this peer does not owe us that hash, which is the
    /// signal to drop the message unverified. Mirrors erigon's
    /// `Take(peer, hash, now)` (`msgboard/want_list.go`, `pulse-v3.4.4`): the
    /// delivery names itself, so an unsolicited message in the middle of a
    /// frame does not spend the reservation standing behind it.
    ///
    /// The queue entry is left in place and skipped when it surfaces, keeping
    /// this O(1) — the same bookkeeping [`release`](Self::release) uses. A
    /// spent reservation is not restored if the message then fails validation,
    /// matching erigon: the peer is penalised, and another peer may already
    /// hold its own reservation for the same message.
    ///
    /// Returns why the reservation was made, or `None` when there was none.
    pub(crate) fn take_kind(&mut self, hash: B256, now: Instant) -> Option<RequestKind> {
        self.prune(now);
        let live = self.live.remove(&hash)?;
        self.settle(live.request, true);
        Some(live.kind)
    }

    /// Whether [`take_kind`](Self::take_kind) found a reservation. Test use
    /// only.
    #[cfg(test)]
    pub(crate) fn take(&mut self, hash: B256, now: Instant) -> bool {
        self.take_kind(hash, now).is_some()
    }

    /// Number of live reservations, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live.len()
    }

    /// Reservations this list can still take before it refuses.
    pub(crate) fn room(&self) -> usize {
        self.capacity.saturating_sub(self.live.len())
    }
}

impl Default for WantList {
    fn default() -> Self {
        Self::new(WANT_TIMEOUT, MAX_WANT_PER_PEER)
    }
}

/// Paces requests to one peer to what an honest reth responder serves, and
/// holds the announced IDs that do not fit yet.
///
/// A reth responder serves each peer from a token bucket of reply bytes (see
/// `protocol::ServeBudget`). It serves the prefix of a reply that fits and
/// drops the rest without a word. A requester that asks for more than the
/// bucket holds reads the dropped rest as withholding, so two honest reth
/// nodes penalise each other on every bulk sync.
///
/// This is a copy of the responder's bucket on our side, with a margin. Each
/// request spends an upper bound of its reply's encoded size. The responder's
/// bucket starts full when our first request arrives and is charged no more
/// than ours. Its refill time between two requests can be shorter than ours,
/// though: a request that waits in transit longer than the next one shrinks
/// the gap the responder sees. The copy therefore keeps
/// [`PACE_RESERVE_BYTES`] back from the smallest burst any reth responder
/// uses, and refills at 90% of its rate. 256 KiB covers 250 ms of arrival
/// jitter at once, and the slower refill absorbs drift over time.
///
/// An erigon responder has no reply budget, so the pacing only slows a sync
/// from it to the reth rate.
#[derive(Debug, Default)]
pub(crate) struct RequestPacer {
    /// `None` until first use, when the bucket starts full.
    tokens: Option<u64>,
    refilled_at: Option<Instant>,
    /// Announced IDs that passed [`MsgBoard::fetchable`] and wait for budget,
    /// oldest first. Not claimed: another peer that announces one meanwhile
    /// is asked for it.
    ///
    /// [`MsgBoard::fetchable`]: crate::MsgBoard::fetchable
    deferred: VecDeque<MsgID>,
    deferred_set: HashSet<MsgID>,
}

impl RequestPacer {
    /// Queue announced IDs behind the ones already waiting. IDs already queued
    /// are skipped. Past `max` queued IDs the rest are dropped; returns how
    /// many.
    pub(crate) fn defer(&mut self, ids: impl IntoIterator<Item = MsgID>, max: usize) -> usize {
        let mut dropped = 0;
        for id in ids {
            if self.deferred.len() >= max {
                dropped += 1;
                continue;
            }
            if self.deferred_set.insert(id) {
                self.deferred.push_back(id);
            }
        }
        dropped
    }

    /// Take queued IDs from the front while their `cost` fits the bucket, up
    /// to `room` of them, and spend the bucket on them.
    ///
    /// With nothing spent since the bucket was last full, the first ID is
    /// taken whatever its cost, so an ID larger than the burst cannot block
    /// the queue for ever.
    pub(crate) fn take_affordable(
        &mut self,
        now: Instant,
        room: usize,
        cost: impl Fn(&MsgID) -> u64,
    ) -> Vec<MsgID> {
        let mut tokens = self.refill(now);
        let full = tokens == PACE_BURST_BYTES;
        let mut out = Vec::new();
        while out.len() < room &&
            let Some(id) = self.deferred.front()
        {
            let c = cost(id);
            if c > tokens && !(full && out.is_empty()) {
                break;
            }
            tokens = tokens.saturating_sub(c);
            let id = self.deferred.pop_front().expect("front exists");
            self.deferred_set.remove(&id);
            out.push(id);
        }
        self.tokens = Some(tokens);
        out
    }

    /// Spend `bytes` whether or not the bucket holds them. For retries, which
    /// are not queued.
    pub(crate) fn charge(&mut self, bytes: u64, now: Instant) {
        let tokens = self.refill(now);
        self.tokens = Some(tokens.saturating_sub(bytes));
    }

    /// Give back `bytes` spent on a request that was never sent.
    pub(crate) fn refund(&mut self, bytes: u64) {
        if let Some(tokens) = self.tokens.as_mut() {
            *tokens = tokens.saturating_add(bytes).min(PACE_BURST_BYTES);
        }
    }

    /// Number of queued IDs, for tests.
    #[cfg(test)]
    pub(crate) fn deferred(&self) -> usize {
        self.deferred.len()
    }

    /// The bucket's level at `now`, with the refill since the last call.
    fn refill(&mut self, now: Instant) -> u64 {
        let elapsed =
            self.refilled_at.map_or(Duration::ZERO, |at| now.saturating_duration_since(at));
        self.refilled_at = Some(now);
        let refill = (elapsed.as_micros() * u128::from(PACE_REFILL_BYTES_PER_SEC) / 1_000_000)
            .min(u128::from(PACE_BURST_BYTES)) as u64;
        self.tokens.map_or(PACE_BURST_BYTES, |t| t.saturating_add(refill).min(PACE_BURST_BYTES))
    }
}

/// Counts withholding events per peer and picks the penalty.
///
/// A withholding event is one check that found reservations which expired
/// unspent. An honest peer can cause one now and then, for example when a
/// message leaves its index before it answers, so a single event earns a small
/// penalty. [`WITHHOLD_STRIKES`] events inside [`WITHHOLD_WINDOW`] earn the
/// larger one.
///
/// Keyed by peer and kept on the board, not per connection. A per-connection
/// count let a peer reconnect before its third strike and start again at
/// zero.
#[derive(Debug, Default)]
pub(crate) struct WithholdStrikes {
    peers: HashMap<PeerId, VecDeque<Instant>>,
}

impl WithholdStrikes {
    /// Record one withholding event for `peer`. Returns `true` when it is part
    /// of a pattern and earns the larger penalty.
    pub(crate) fn record(&mut self, peer: PeerId, now: Instant) -> bool {
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_STRUCK_PEERS {
            self.prune(now);
            if self.peers.len() >= MAX_STRUCK_PEERS {
                // Still full of live entries: forget the peer whose last
                // strike is oldest. That peer is the furthest from escalation.
                if let Some(oldest) = self
                    .peers
                    .iter()
                    .min_by_key(|(_, events)| events.back().copied())
                    .map(|(peer, _)| *peer)
                {
                    self.peers.remove(&oldest);
                }
            }
        }
        let recent = self.peers.entry(peer).or_default();
        while recent.front().is_some_and(|t| now.duration_since(*t) >= WITHHOLD_WINDOW) {
            recent.pop_front();
        }
        recent.push_back(now);
        if recent.len() < WITHHOLD_STRIKES {
            return false;
        }
        // Start counting again, so the larger penalty fires once per
        // `WITHHOLD_STRIKES` events, not on every event past the threshold.
        self.peers.remove(&peer);
        true
    }

    /// Drop every peer with no event inside [`WITHHOLD_WINDOW`].
    pub(crate) fn prune(&mut self, now: Instant) {
        self.peers.retain(|_, events| {
            events.back().is_some_and(|t| now.duration_since(*t) < WITHHOLD_WINDOW)
        });
    }
}

/// One claimed ID: who was asked, when, and who else announced it.
#[derive(Debug)]
struct Claim {
    claimed_at: Instant,
    owner: PeerId,
    /// Later announcers, in announcement order.
    alternates: Vec<PeerId>,
    /// Every announcer of this ID, the first owner included, keyed per
    /// session (see [`AnnouncerKeys`]).
    seen: Box<SeenFilter>,
    /// Distinct announcers after the first owner: the reservoir count.
    candidates: u64,
    /// Candidates counted per subnet, for [`MAX_CANDIDATES_PER_SUBNET`]. At
    /// most [`MAX_DRAW_CANDIDATES`] entries.
    subnets: Vec<SubnetCount>,
    /// The claim moved to `owner`, which has not been asked yet.
    retry: bool,
    /// Owners asked so far, the first one included.
    tried: u32,
    /// Subnets of the owners asked so far, without repeats. At most
    /// `2 * MAX_ALTERNATES` entries.
    tried_subnets: Vec<u64>,
    /// Every announcer by peer ID alone, in any session. Only the
    /// speculative fetch reads it, so that an announcer is never asked as a
    /// non-announcer. Filled like `seen`, so its false-positive rate matches.
    announcers: Box<SeenFilter>,
    /// The first owner's subnet; see [`Exhausted::group`].
    group: Option<u64>,
    /// A trusted peer announced this ID.
    trusted_announcer: bool,
}

impl Claim {
    /// Consider `peer`, which announced this claimed ID, as an alternate.
    ///
    /// A peer is considered once per claim and session. While the list has
    /// room, every newcomer joins. Once it is full, the `k`-th distinct
    /// candidate replaces a random entry with odds `MAX_ALTERNATES / k` and is
    /// dropped otherwise (reservoir sampling). Every candidate then holds a
    /// slot with the same odds, whatever the order of announcements. A fixed
    /// choice, such as the oldest or a struck peer, lets an attacker push out
    /// a chosen honest peer: it controls the announcement order, and it can
    /// steer a soft strike onto an honest peer. Strikes only order who is
    /// asked.
    ///
    /// A peer that announced in an earlier session re-enters as a new
    /// candidate. Honest peers re-announce their whole board on every new
    /// session, and without this a peer whose session ended before its turn
    /// could never be asked again. A looping peer must reconnect for each new
    /// ticket, and reth throttles inbound connections from one IP for 30 s
    /// (`INBOUND_IP_THROTTLE_DURATION`). A peer counted in its subnet before
    /// does not need a new subnet slot to re-enter.
    ///
    /// Trusted peers skip the subnet cap. A trusted newcomer to a full list
    /// replaces a random untrusted entry, and the draw never evicts a trusted
    /// entry. Without trusted peers the draw is unchanged.
    fn admit(
        &mut self,
        peer: PeerId,
        keys: AnnouncerKeys,
        subnet: Option<u64>,
        sessions: &HashMap<PeerId, PeerSession>,
        rng: &mut u64,
    ) {
        if self.owner == peer ||
            self.candidates >= MAX_DRAW_CANDIDATES ||
            self.alternates.contains(&peer)
        {
            return;
        }
        let trusted = is_trusted(sessions, &peer);
        // A full subnet is checked before the filter, so its extra announcers
        // neither enter the draw nor fill the filter. They cannot re-enter
        // later either: the subnet stays full for the life of the claim.
        let slot =
            subnet.map(|subnet| self.subnets.iter().position(|c| c.subnet == subnet).ok_or(subnet));
        // A member gets one rejoin per claim, so it holds at most two draw
        // tickets however often it reconnects.
        let rejoin = match slot {
            Some(Ok(i)) => self.subnets[i].member(keys.peer).map(|m| (i, m)),
            _ => None,
        };
        if let Some((i, m)) = rejoin &&
            self.subnets[i].rejoined[m]
        {
            return;
        }
        if !trusted &&
            rejoin.is_none() &&
            let Some(Ok(i)) = slot &&
            self.subnets[i].count >= MAX_CANDIDATES_PER_SUBNET
        {
            return;
        }
        if !self.seen.insert(keys.session) {
            return;
        }
        self.announcers.insert(keys.peer);
        self.trusted_announcer |= trusted;
        if let Some((i, m)) = rejoin {
            // A rejoin in the member's first session is a repeat, which the
            // filter refused above, so this is a new session.
            self.subnets[i].rejoined[m] = true;
        } else {
            match slot {
                Some(Ok(i)) => self.subnets[i].add(keys.peer),
                Some(Err(subnet)) => self.subnets.push(SubnetCount::new(subnet, keys.peer)),
                None => {}
            }
        }
        self.candidates += 1;
        if self.alternates.len() < MAX_ALTERNATES {
            self.alternates.push(peer);
            return;
        }
        if trusted {
            let untrusted: Vec<usize> = (0..self.alternates.len())
                .filter(|i| !is_trusted(sessions, &self.alternates[*i]))
                .collect();
            if !untrusted.is_empty() {
                let i = untrusted[(next_random(rng) % untrusted.len() as u64) as usize];
                self.alternates[i] = peer;
            }
            return;
        }
        let slot = (next_random(rng) % self.candidates) as usize;
        if slot < MAX_ALTERNATES && !is_trusted(sessions, &self.alternates[slot]) {
            self.alternates[slot] = peer;
        }
    }

    /// Make the next alternate the owner and queue a retry for it. Trusted
    /// alternates go first, then alternates without a live strike, each in
    /// announcement order. A retry still queued for the previous owner is
    /// withdrawn. The caller accounts for the previous owner's claim count.
    ///
    /// Trust outranks a strike on purpose. A compromised trusted peer that
    /// withholds is asked first on every claim it announces, so it costs one
    /// TTL of delay per such claim. That is accepted: the operator chose to
    /// trust it, and the other alternates are still asked after it.
    fn hand_to_next_alternate(
        &mut self,
        now: Instant,
        struck: &HashMap<PeerId, Instant>,
        sessions: &HashMap<PeerId, PeerSession>,
        owned: &mut HashMap<PeerId, usize>,
        retries: &mut HashMap<PeerId, Vec<MsgID>>,
        id: MsgID,
    ) {
        let pick = self
            .alternates
            .iter()
            .enumerate()
            .min_by_key(|(i, p)| (!is_trusted(sessions, p), is_struck(struck, p, now), *i))
            .map_or(0, |(i, _)| i);
        let next = self.alternates.remove(pick);
        if self.retry &&
            let std::collections::hash_map::Entry::Occupied(mut e) = retries.entry(self.owner)
        {
            e.get_mut().retain(|queued| *queued != id);
            if e.get().is_empty() {
                e.remove();
            }
        }
        self.owner = next;
        self.claimed_at = now;
        self.retry = true;
        self.note_tried(sessions.get(&next).and_then(|s| s.subnet));
        *owned.entry(next).or_default() += 1;
        retries.entry(next).or_default().push(id);
    }

    /// Count one more owner asked, from `subnet`.
    fn note_tried(&mut self, subnet: Option<u64>) {
        self.tried += 1;
        if let Some(subnet) = subnet &&
            self.tried_subnets.len() < 2 * MAX_ALTERNATES &&
            !self.tried_subnets.contains(&subnet)
        {
            self.tried_subnets.push(subnet);
        }
    }
}

/// The candidates one subnet has put into a claim's draw.
#[derive(Debug)]
struct SubnetCount {
    subnet: u64,
    count: u8,
    /// The first [`MAX_CANDIDATES_PER_SUBNET`] candidates, as truncated
    /// [`AnnouncerKeys::peer`] hashes, so they can rejoin from a new session.
    /// A collision only lets one more peer in, so 32 bits is enough.
    members: [u32; MAX_CANDIDATES_PER_SUBNET as usize],
    /// Which members have used their one rejoin in this claim.
    rejoined: [bool; MAX_CANDIDATES_PER_SUBNET as usize],
}

impl SubnetCount {
    fn new(subnet: u64, peer: u64) -> Self {
        let mut count = Self {
            subnet,
            count: 0,
            members: [0; MAX_CANDIDATES_PER_SUBNET as usize],
            rejoined: [false; MAX_CANDIDATES_PER_SUBNET as usize],
        };
        count.add(peer);
        count
    }

    fn add(&mut self, peer: u64) {
        if let Some(slot) = self.members.get_mut(self.count as usize) {
            *slot = peer as u32;
        }
        self.count = self.count.saturating_add(1);
    }

    /// The member slot of `peer`, if it is a member.
    fn member(&self, peer: u64) -> Option<usize> {
        self.members[..(self.count as usize).min(self.members.len())]
            .iter()
            .position(|m| *m == peer as u32)
    }
}

/// The filter keys of one announcer.
#[derive(Debug, Clone, Copy)]
struct AnnouncerKeys {
    /// Keyed hash of the peer ID alone.
    peer: u64,
    /// Keyed hash of the peer ID and its session, so a new session reads as a
    /// new announcer. Equal to `peer` when no session is known.
    session: u64,
}

impl AnnouncerKeys {
    fn of(
        key: &std::collections::hash_map::RandomState,
        sessions: &HashMap<PeerId, PeerSession>,
        peer: PeerId,
    ) -> Self {
        match sessions.get(&peer) {
            Some(session) => Self::for_session(key, peer, session.id),
            None => {
                let peer = std::hash::BuildHasher::hash_one(key, peer);
                Self { peer, session: peer }
            }
        }
    }

    fn for_session(
        key: &std::collections::hash_map::RandomState,
        peer: PeerId,
        session: u64,
    ) -> Self {
        Self {
            peer: std::hash::BuildHasher::hash_one(key, peer),
            session: std::hash::BuildHasher::hash_one(key, (peer, session)),
        }
    }
}

/// The peers that announced one claimed ID: a Bloom filter with three probes,
/// keyed per process.
///
/// It must remember every announcer of the current session: a forgotten peer
/// could announce again, re-enter the reservoir draw, and buy itself unlimited
/// tickets. Keys include the session (see [`AnnouncerKeys`]), so a new session
/// reads as a new announcer, at the cost of one reconnect. A filter
/// remembers all of them in fixed memory. Its only error is a false positive,
/// which refuses an honest newcomer as if it had announced already. With 4096
/// bits and three probes the rate is (1 - e^(-3n/4096))^3 for n entries:
/// about 0.0096% at 64, 2.9% at 500 and 14% at 1000. The reservoir freezes at
/// [`MAX_DRAW_CANDIDATES`], so the filter stays near the 1000 figure.
#[derive(Debug)]
struct SeenFilter([u64; SEEN_FILTER_BITS / 64]);

impl SeenFilter {
    /// A filter holding one peer.
    fn with(peer_hash: u64) -> Box<Self> {
        let mut filter = Self::empty();
        filter.insert(peer_hash);
        filter
    }

    /// An empty filter.
    fn empty() -> Box<Self> {
        Box::new(Self([0; SEEN_FILTER_BITS / 64]))
    }

    /// Whether a peer is (probably) present.
    fn contains(&self, peer_hash: u64) -> bool {
        (0..3).all(|probe| {
            let bit = (peer_hash >> (probe * 16)) as usize % SEEN_FILTER_BITS;
            self.0[bit / 64] & (1u64 << (bit % 64)) != 0
        })
    }

    /// Add a peer. Returns `false` when it was (probably) present already.
    fn insert(&mut self, peer_hash: u64) -> bool {
        let mut fresh = false;
        for probe in 0..3 {
            let bit = (peer_hash >> (probe * 16)) as usize % SEEN_FILTER_BITS;
            let (word, mask) = (bit / 64, 1u64 << (bit % 64));
            fresh |= self.0[word] & mask == 0;
            self.0[word] |= mask;
        }
        fresh
    }
}

/// Why a peer was asked for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestKind {
    /// The peer announced the message and was asked first-hand.
    FirstHand,
    /// The peer announced the message and was asked because another
    /// announcer withheld it.
    Retry,
    /// The peer never announced the message. It was asked because every
    /// announcer withheld it.
    Speculative,
}

/// One live `msg/1` session, as the claims see it.
#[derive(Debug, Clone, Copy)]
struct PeerSession {
    /// Unique per session for the life of the process.
    id: u64,
    subnet: Option<u64>,
    /// Reth marks the peer as trusted.
    trusted: bool,
}

/// A claim the sweep dropped with its message still missing.
#[derive(Debug)]
struct Exhausted {
    id: MsgID,
    tried: u32,
    /// Every announcer of the claim, by peer ID in any session, so none is
    /// asked speculatively.
    announcers: Box<SeenFilter>,
    /// Subnets of the announcers that were asked.
    tried_subnets: Vec<u64>,
    /// The first owner's subnet. The queue and each window hold one claim
    /// per group, so one subnet cannot take the whole budget.
    group: Option<u64>,
    /// A trusted peer announced the claim, or owners from two or more
    /// subnets withheld it. Served first.
    priority: bool,
    /// When the sweep found it exhausted.
    at: Instant,
}

/// Add `entry` to the exhausted queue, keeping one claim per group and at
/// most [`MAX_QUEUED_EXHAUSTED`] claims.
///
/// A newer claim replaces its group's queued one, unless only the older one
/// has priority. When the queue is full, a priority claim replaces the oldest
/// claim without priority; any other claim is dropped. It is still counted.
fn queue_exhausted(queue: &mut Vec<Exhausted>, entry: Exhausted) {
    if let Some(old) = queue.iter_mut().find(|e| e.group == entry.group) {
        if entry.priority || !old.priority {
            *old = entry;
        }
        return;
    }
    if queue.len() < MAX_QUEUED_EXHAUSTED {
        queue.push(entry);
        return;
    }
    if entry.priority &&
        let Some(oldest) = queue.iter_mut().filter(|e| !e.priority).min_by_key(|e| e.at)
    {
        *oldest = entry;
    }
}

/// The subnet an address counts in for [`Claim::admit`]: its IPv4 /24, or its
/// IPv6 /56. An IPv4-mapped IPv6 address counts as IPv4.
pub(crate) fn subnet_of(ip: std::net::IpAddr) -> u64 {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => u64::from(u32::from(v4) >> 8),
        std::net::IpAddr::V6(v6) => (1 << 63) | (u128::from(v6) >> 72) as u64,
    }
}

/// Whether reth marks the session of `peer` as trusted.
fn is_trusted(sessions: &HashMap<PeerId, PeerSession>, peer: &PeerId) -> bool {
    sessions.get(peer).is_some_and(|s| s.trusted)
}

/// Step the xorshift state and return it.
const fn next_random(rng: &mut u64) -> u64 {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    *rng
}

/// Whether `peer` withheld first-hand inside [`WITHHOLD_WINDOW`] before `now`.
fn is_struck(struck: &HashMap<PeerId, Instant>, peer: &PeerId, now: Instant) -> bool {
    struck.get(peer).is_some_and(|at| now.duration_since(*at) < WITHHOLD_WINDOW)
}

/// Decrement a per-peer count. The entry goes at zero, so the map does not
/// keep one entry for every peer ever seen.
fn decrement(owned: &mut HashMap<PeerId, usize>, peer: PeerId) {
    if let std::collections::hash_map::Entry::Occupied(mut entry) = owned.entry(peer) {
        *entry.get_mut() -= 1;
        if *entry.get() == 0 {
            entry.remove();
        }
    }
}

/// An unspent reservation.
#[derive(Debug)]
struct Live {
    expires_at: Instant,
    /// Why this peer was asked.
    kind: RequestKind,
    /// The request this reservation belongs to.
    request: u64,
}

/// What expired unspent in a peer's want list.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Expired {
    /// First-hand reservations: the peer announced these and did not deliver.
    pub(crate) first_hand: usize,
    /// Retry reservations. These cost no reputation: the peer may have
    /// evicted or pruned the message by the time the retry reached it.
    pub(crate) retries: usize,
    /// At least one expired first-hand reservation belongs to a request the
    /// peer answered none of. Only this counts toward the larger penalty: an
    /// honest peer that pruned part of a request at a block boundary still
    /// answers the rest.
    pub(crate) silent: bool,
}

/// Bookkeeping for one request in a [`WantList`].
#[derive(Debug, Default)]
struct RequestState {
    outstanding: usize,
    answered: bool,
}

/// One reserved hash and the instant it stops authorising anything.
#[derive(Debug)]
struct Want {
    hash: B256,
    expires_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a distinct `MsgID` per `n` without mining anything — `claim` reads
    /// only the bytes, never the `PoW`.
    fn id(n: u8) -> MsgID {
        let mut raw = [0u8; reth_msgboard_types::MSG_ID_SIZE];
        raw[0] = n;
        MsgID::decode_list(&raw).expect("one id-sized record")[0]
    }

    fn p(n: u8) -> PeerId {
        PeerId::repeat_byte(n)
    }

    /// A claim that expires with its message still missing moves to the next
    /// announcer, in announcement order, and is dropped once none is left.
    #[test]
    fn an_expired_claim_is_retried_from_the_next_announcer() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();

        assert!(pending.claim(id(1), p(1), t0));
        assert!(!pending.claim(id(1), p(2), t0));
        assert!(!pending.claim(id(1), p(3), t0));
        assert!(pending.take_retries(p(2), t0).is_empty(), "nothing to retry while p1 is live");

        pending.sweep(t0 + ttl, |_| false);
        assert!(pending.take_retries(p(3), t0 + ttl).is_empty(), "p3 is second in line");
        assert_eq!(pending.take_retries(p(2), t0 + ttl), vec![id(1)], "p2 is asked next");
        assert!(pending.take_retries(p(2), t0 + ttl).is_empty(), "and only once");

        pending.sweep(t0 + 2 * ttl, |_| false);
        assert_eq!(pending.take_retries(p(3), t0 + 2 * ttl), vec![id(1)]);

        pending.sweep(t0 + 3 * ttl, |_| false);
        assert_eq!(pending.len(), 0, "no announcer left");
    }

    #[test]
    fn a_delivered_message_is_not_retried() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();

        pending.claim(id(1), p(1), t0);
        pending.claim(id(1), p(2), t0);
        pending.sweep(t0 + ttl, |_| true);

        assert_eq!(pending.len(), 0);
        assert!(pending.take_retries(p(2), t0 + ttl).is_empty());
    }

    #[test]
    fn a_released_claim_moves_to_the_next_announcer_at_once() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        pending.claim(id(1), p(1), now);
        pending.claim(id(1), p(2), now);
        pending.release(&id(1), p(1), now);

        assert_eq!(pending.take_retries(p(2), now), vec![id(1)]);
        assert!(!pending.claim(id(1), p(1), now), "the claim is live under p2");
    }

    /// An attacker that controls the announcement order cannot choose which
    /// alternate a full list drops. Over many fresh trackers, the honest
    /// peer sometimes survives 16 more announcers and sometimes does not.
    #[test]
    fn a_full_alternate_list_drops_a_random_entry() {
        let now = Instant::now();
        let honest = p(0x77);
        let survived = (0..200)
            .filter(|_| {
                let mut pending = PendingRequests::default();
                pending.claim(id(1), p(0), now);
                pending.claim(id(1), honest, now);
                for n in 1..=u8::try_from(2 * MAX_ALTERNATES).unwrap() {
                    pending.claim(id(1), p(n), now);
                }
                pending.claims[&id(1)].alternates.contains(&honest)
            })
            .count();
        assert!(survived > 0, "the honest peer was evicted every time");
        assert!(survived < 200, "the honest peer was never evicted; eviction is not random");
    }

    /// A strike must not make an announcer the certain victim of eviction.
    /// Honest peers collect soft strikes routinely, and an attacker can steer
    /// one onto a chosen peer, so a full list still drops a random entry.
    #[test]
    fn a_struck_alternate_is_not_evicted_first() {
        let now = Instant::now();
        let honest = p(0x77);
        let survived = (0..200)
            .filter(|_| {
                let mut pending = PendingRequests::default();
                pending.note_withheld(honest, now);
                pending.claim(id(1), p(0), now);
                pending.claim(id(1), honest, now);
                for n in 1..=u8::try_from(2 * MAX_ALTERNATES).unwrap() {
                    pending.claim(id(1), p(n), now);
                }
                pending.claims[&id(1)].alternates.contains(&honest)
            })
            .count();
        // 33 distinct candidates for 16 slots: an unstruck peer survives with
        // odds 16/33, about 97 of 200 runs. A strike must not move that much.
        assert!(
            (70..=125).contains(&survived),
            "a soft-struck honest peer survived {survived} of 200 runs; expected about 97",
        );
    }

    /// Sybils that announce first must not lock a later honest announcer out.
    /// Every distinct announcer stays in the reservoir draw, so after one
    /// owner and 64 sybils the honest peer keeps a slot with odds 16/65,
    /// about 98 of 400 runs.
    #[test]
    fn sixty_four_sybils_first_do_not_lock_out_an_honest_announcer() {
        let now = Instant::now();
        let honest = p(0x77);
        let survived = (0..400)
            .filter(|_| {
                let mut pending = PendingRequests::default();
                pending.claim(id(1), p(0), now);
                for n in 1..=64 {
                    pending.claim(id(1), p(n), now);
                }
                pending.claim(id(1), honest, now);
                pending.claims[&id(1)].alternates.contains(&honest)
            })
            .count();
        assert!(
            (60..=140).contains(&survived),
            "the honest peer survived {survived} of 400 runs; expected about 98",
        );
    }

    /// Sybils on one subnet cannot dilute the draw. 1000 announcers from one
    /// /24 count as two candidates, so an honest peer from another subnet
    /// always finds a slot.
    #[test]
    fn a_thousand_sybils_on_one_subnet_do_not_dilute_the_draw() {
        let now = Instant::now();
        let sybil_net = Some(subnet_of("203.0.113.9".parse().unwrap()));
        let honest_net = Some(subnet_of("198.51.100.7".parse().unwrap()));
        let honest = p(0x77);
        let survived = (0..50)
            .filter(|_| {
                let mut pending = PendingRequests::default();
                for n in 0..1000u64 {
                    let sybil = PeerId::left_padding_from(&(n + 1000).to_be_bytes());
                    pending.claim_from(id(1), sybil, sybil_net, now);
                }
                pending.claim_from(id(1), honest, honest_net, now);
                pending.claims[&id(1)].alternates.contains(&honest)
            })
            .count();
        assert_eq!(survived, 50, "the honest peer lost its slot in {} of 50 runs", 50 - survived);
    }

    /// Past the candidate cap the reservoir is frozen, so the filter stops
    /// filling and its false-positive rate stays near the cap's figure.
    #[test]
    fn the_reservoir_freezes_before_the_filter_saturates() {
        let now = Instant::now();
        let mut pending = PendingRequests::default();
        for n in 0..5000u64 {
            pending.claim(id(1), PeerId::left_padding_from(&n.to_be_bytes()), now);
        }
        let claim = &pending.claims[&id(1)];
        assert!(claim.candidates <= 1000, "{} candidates entered the draw", claim.candidates);
        let fresh = (0..2000u64)
            .filter(|n| {
                let peer = PeerId::left_padding_from(&(n + 1_000_000).to_be_bytes());
                claim.seen.contains(std::hash::BuildHasher::hash_one(&pending.seen_key, peer))
            })
            .count();
        assert!(fresh <= 400, "{fresh} of 2000 fresh peers read as seen");
    }

    /// A hand-off leaves no retry queued for the peer that lost the claim.
    #[test]
    fn a_hand_off_clears_the_previous_owners_retry() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();

        pending.claim(id(1), p(1), t0);
        pending.claim(id(1), p(2), t0);
        pending.claim(id(1), p(3), t0);
        pending.sweep(t0 + ttl, |_| false);
        assert!(pending.retries.contains_key(&p(2)), "p2 is queued to be asked");

        // p2 never collects its retry. A late announcer triggers the next
        // hand-off before the sweep runs.
        pending.claim(id(1), p(4), t0 + 2 * ttl);
        assert!(!pending.retries.contains_key(&p(2)), "p2 kept a stale retry");
        assert_eq!(pending.take_retries(p(3), t0 + 2 * ttl), vec![id(1)]);
    }

    /// A sybil evicted from a full list must not re-enter by announcing the
    /// same ID again. If it could, a few looping sybils would roll the
    /// eviction dice without limit and flush every honest announcer.
    ///
    /// One sybil owns the claim, and 16 more sybils plus one honest peer
    /// announce: 17 distinct candidates for 16 slots. Each candidate keeps
    /// its slot with odds 16/17, so the honest peer survives about 188 of 200
    /// runs however often the sybils loop.
    #[test]
    fn looping_sybils_do_not_flush_an_honest_announcer() {
        let now = Instant::now();
        let honest = p(0x77);
        let survived = (0..200)
            .filter(|_| {
                let mut pending = PendingRequests::default();
                pending.claim(id(1), p(0), now);
                for n in 1..=8 {
                    pending.claim(id(1), p(n), now);
                }
                pending.claim(id(1), honest, now);
                for _ in 0..50 {
                    for n in 1..=16 {
                        pending.claim(id(1), p(n), now);
                    }
                }
                pending.claims[&id(1)].alternates.contains(&honest)
            })
            .count();
        assert!(survived >= 170, "the honest peer survived {survived} of 200 runs; expected ~188");
    }

    /// An honest announcer whose session ended before its turn re-enters the
    /// claim when it reconnects and announces again, and is asked. Honest
    /// peers re-announce their whole board on every new session, so this is
    /// how they recover.
    #[test]
    fn a_reconnected_announcer_re_enters_the_claim() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let honest = p(0x77);
        for n in 0..=2 {
            pending.open_session(p(n), None);
        }
        let first = pending.open_session(honest, None);

        pending.claim(id(1), p(0), t0);
        pending.claim(id(1), honest, t0);
        pending.claim(id(1), p(1), t0);
        pending.claim(id(1), p(2), t0);
        // The hand-off reaches the honest peer after its session ended.
        pending.close_session(honest, first);
        pending.sweep(t0 + ttl, |_| false);
        pending.sweep(t0 + 2 * ttl, |_| false);

        pending.open_session(honest, None);
        pending.claim(id(1), honest, t0 + 2 * ttl);
        pending.sweep(t0 + 3 * ttl, |_| false);
        assert_eq!(pending.take_retries(p(2), t0 + 3 * ttl), vec![id(1)]);
        pending.sweep(t0 + 4 * ttl, |_| false);
        assert_eq!(
            pending.take_retries(honest, t0 + 4 * ttl),
            vec![id(1)],
            "the reconnected honest peer was never asked again",
        );
    }

    /// Inside one session a repeat announcement never re-enters a claim, so a
    /// peer cannot loop its announcements to buy draw tickets.
    #[test]
    fn a_repeat_announcement_in_one_session_does_not_re_enter() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let looping = p(0x66);
        for n in 0..=1 {
            pending.open_session(p(n), None);
        }
        pending.open_session(looping, None);

        pending.claim(id(1), p(0), t0);
        pending.claim(id(1), looping, t0);
        pending.claim(id(1), p(1), t0);
        pending.sweep(t0 + ttl, |_| false);
        assert_eq!(pending.take_retries(looping, t0 + ttl), vec![id(1)]);
        pending.sweep(t0 + 2 * ttl, |_| false);
        pending.claim(id(1), looping, t0 + 2 * ttl);
        pending.claim(id(1), looping, t0 + 2 * ttl);
        assert!(pending.claims[&id(1)].alternates.is_empty(), "the looping peer re-entered");
    }

    /// A rejoin from a subnet whose cap is full still re-enters: the peer was
    /// counted in that subnet already.
    #[test]
    fn a_reconnected_announcer_re_enters_through_a_full_subnet() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let net = Some(subnet_of("198.51.100.7".parse().unwrap()));
        let honest = p(0x77);
        pending.open_session(p(0), None);
        pending.open_session(p(1), net);
        let first = pending.open_session(honest, net);

        pending.claim_from(id(1), p(0), None, t0);
        pending.claim_from(id(1), honest, net, t0);
        pending.claim_from(id(1), p(1), net, t0);
        pending.close_session(honest, first);
        pending.sweep(t0 + ttl, |_| false);
        pending.sweep(t0 + 2 * ttl, |_| false);

        pending.open_session(honest, net);
        pending.claim_from(id(1), honest, net, t0 + 2 * ttl);
        assert!(pending.claims[&id(1)].alternates.contains(&honest), "the subnet cap kept it out");
    }

    /// After the first owner fails, a trusted announcer is asked before
    /// untrusted ones that announced earlier.
    #[test]
    fn a_trusted_alternate_is_asked_first() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let trusted = p(0x7E);
        for n in 0..=3 {
            pending.open_session(p(n), None);
        }
        let session = pending.open_session(trusted, None);
        pending.set_trusted(trusted, session);

        pending.claim(id(1), p(0), t0);
        for n in 1..=3 {
            pending.claim(id(1), p(n), t0);
        }
        pending.claim(id(1), trusted, t0);
        pending.sweep(t0 + ttl, |_| false);
        assert_eq!(pending.take_retries(trusted, t0 + ttl), vec![id(1)], "trusted is not first");
    }

    /// The random draw never evicts a trusted alternate.
    #[test]
    fn a_trusted_alternate_is_never_evicted() {
        let now = Instant::now();
        let trusted = p(0x7E);
        for _ in 0..100 {
            let mut pending = PendingRequests::default();
            for n in 0..=100 {
                pending.open_session(p(n), None);
            }
            let session = pending.open_session(trusted, None);
            pending.set_trusted(trusted, session);
            pending.claim(id(1), p(0), now);
            pending.claim(id(1), trusted, now);
            for n in 1..=100 {
                pending.claim(id(1), p(n), now);
            }
            assert!(pending.claims[&id(1)].alternates.contains(&trusted), "trusted was evicted");
        }
    }

    /// A trusted announcer that arrives when the list is full of untrusted
    /// ones always takes a slot.
    #[test]
    fn a_late_trusted_announcer_always_finds_a_slot() {
        let now = Instant::now();
        let trusted = p(0x7E);
        for _ in 0..100 {
            let mut pending = PendingRequests::default();
            for n in 0..=100 {
                pending.open_session(p(n), None);
            }
            let session = pending.open_session(trusted, None);
            pending.set_trusted(trusted, session);
            for n in 0..=100 {
                pending.claim(id(1), p(n), now);
            }
            pending.claim(id(1), trusted, now);
            assert!(pending.claims[&id(1)].alternates.contains(&trusted), "trusted found no slot");
        }
    }

    /// A claim whose announcers all withhold is counted, and up to three
    /// connected peers that did not announce it are queued to be asked, a
    /// trusted one first. No announcer is asked speculatively.
    #[test]
    fn an_exhausted_claim_asks_peers_that_did_not_announce_it() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let trusted = p(0x7E);
        let others: Vec<PeerId> = (0x10..0x16).map(p).collect();
        pending.open_session(p(1), None);
        pending.open_session(p(2), None);
        for (n, peer) in others.iter().enumerate() {
            let ip = format!("198.51.{n}.7").parse().unwrap();
            pending.open_session(*peer, Some(subnet_of(ip)));
        }
        let session = pending.open_session(trusted, None);
        pending.set_trusted(trusted, session);

        pending.claim(id(1), p(1), t0);
        pending.claim(id(1), p(2), t0);
        pending.sweep(t0 + ttl, |_| false);
        assert_eq!(pending.take_retries(p(2), t0 + ttl), vec![id(1)]);
        pending.sweep(t0 + 2 * ttl, |_| false);

        let (count, claims) = pending.settle_exhausted(t0 + 2 * ttl, |_| true);
        assert_eq!(count, 1);
        assert_eq!(claims, vec![ExhaustedClaim { id: id(1), tried: 2, asked: 3 }]);
        assert!(pending.take_speculative(p(1)).is_empty(), "an announcer was asked again");
        assert!(pending.take_speculative(p(2)).is_empty(), "an announcer was asked again");
        assert_eq!(pending.take_speculative(trusted), vec![id(1)], "trusted was not picked");
        let asked = others.iter().filter(|o| !pending.take_speculative(**o).is_empty()).count();
        assert_eq!(asked, 2);
    }

    /// An exhausted claim whose message is no longer wanted is counted but
    /// asks nobody.
    #[test]
    fn an_exhausted_claim_no_longer_wanted_asks_nobody() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        pending.open_session(p(1), None);
        pending.open_session(p(9), None);

        pending.claim(id(1), p(1), t0);
        pending.sweep(t0 + ttl, |_| false);
        let (count, claims) = pending.settle_exhausted(t0 + ttl, |_| false);
        assert_eq!(count, 1);
        assert_eq!(claims, vec![ExhaustedClaim { id: id(1), tried: 1, asked: 0 }]);
        assert!(pending.take_speculative(p(9)).is_empty());
    }

    /// Speculative requests stay inside the global rate however many claims
    /// run out at once.
    #[test]
    fn speculative_fetches_are_rate_limited() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        for n in 0x10..0x20 {
            pending.open_session(p(n), None);
        }
        let speculative = |pending: &mut PendingRequests| {
            std::mem::take(&mut pending.speculative).values().map(Vec::len).sum::<usize>()
        };

        // Each claim's owner is on its own subnet, so fairness between
        // subnets does not limit this test.
        for n in 0..40u8 {
            pending.open_session(owner(n), Some(u64::from(n)));
        }
        for n in 0..20 {
            pending.claim_from(id(n), owner(n), Some(u64::from(n)), t0);
        }
        pending.sweep(t0 + ttl, |_| false);
        let (count, _) = pending.settle_exhausted(t0 + ttl, |_| true);
        assert_eq!(count, 20);
        assert_eq!(speculative(&mut pending), MAX_SPECULATIVE_FETCHES_PER_SEC as usize);

        for n in 20..40 {
            pending.claim_from(id(n), owner(n), Some(u64::from(n)), t0 + ttl);
        }
        pending.sweep(t0 + 2 * ttl, |_| false);
        pending.settle_exhausted(t0 + 2 * ttl, |_| true);
        assert_eq!(
            speculative(&mut pending),
            MAX_SPECULATIVE_FETCHES_PER_SEC as usize,
            "the next window allows a fresh budget, and no more",
        );
    }

    /// A distinct peer, by number, for tests that need more than 255 peers.
    fn owner(n: u8) -> PeerId {
        PeerId::left_padding_from(&[0xEE, n])
    }

    /// A peer for tests that need many distinct peers.
    fn many(n: u64) -> PeerId {
        PeerId::left_padding_from(&(n + 1_000_000).to_be_bytes())
    }

    /// A counted member that reconnects many times holds at most two draw
    /// tickets in one claim: its first and one rejoin.
    #[test]
    fn reconnecting_does_not_multiply_draw_tickets() {
        let now = Instant::now();
        let net = Some(subnet_of("198.51.100.7".parse().unwrap()));
        let member = p(0x77);
        for _ in 0..20 {
            let mut pending = PendingRequests::default();
            pending.open_session(p(0), None);
            pending.claim(id(1), p(0), now);
            for n in 0..100u64 {
                let peer = many(n);
                pending.open_session(peer, Some(n << 8));
                pending.claim_from(id(1), peer, Some(n << 8), now);
            }
            let before = pending.claims[&id(1)].candidates;
            for _ in 0..10 {
                pending.open_session(member, net);
                pending.claim_from(id(1), member, net, now);
            }
            let tickets = pending.claims[&id(1)].candidates - before;
            assert!(tickets <= 2, "one member bought {tickets} tickets by reconnecting");
        }
    }

    /// The subnet bypass is for members only. While a member rejoins a full
    /// subnet, a new peer from that subnet is still refused.
    #[test]
    fn only_members_bypass_a_full_subnet() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let net = Some(subnet_of("198.51.100.7".parse().unwrap()));
        pending.open_session(p(0), None);
        pending.open_session(p(1), net);
        let first = pending.open_session(p(2), net);
        pending.claim_from(id(1), p(0), None, t0);
        pending.claim_from(id(1), p(2), net, t0);
        pending.claim_from(id(1), p(1), net, t0);
        pending.close_session(p(2), first);
        pending.sweep(t0 + ttl, |_| false);
        pending.sweep(t0 + 2 * ttl, |_| false);

        pending.open_session(p(2), net);
        pending.open_session(p(3), net);
        pending.claim_from(id(1), p(2), net, t0 + 2 * ttl);
        pending.claim_from(id(1), p(3), net, t0 + 2 * ttl);
        let alternates = &pending.claims[&id(1)].alternates;
        assert!(alternates.contains(&p(2)), "the member did not rejoin");
        assert!(!alternates.contains(&p(3)), "a new peer passed the full subnet");
    }

    /// Closing or trusting a stale session leaves the newer one alone.
    #[test]
    fn a_stale_session_id_changes_nothing() {
        let mut pending = PendingRequests::default();
        let old = pending.open_session(p(1), None);
        let new = pending.open_session(p(1), None);
        pending.set_trusted(p(1), old);
        assert!(!is_trusted(&pending.sessions, &p(1)), "a stale id set trust");
        pending.close_session(p(1), old);
        assert_eq!(pending.sessions.get(&p(1)).map(|s| s.id), Some(new), "a stale id closed it");
        pending.close_session(p(1), new);
        assert!(!pending.sessions.contains_key(&p(1)));
    }

    /// An announcer that reconnected without announcing again is still an
    /// announcer, and is not asked speculatively.
    #[test]
    fn a_reconnected_announcer_is_not_asked_speculatively() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let first = pending.open_session(p(1), None);
        pending.claim(id(1), p(1), t0);
        pending.close_session(p(1), first);
        pending.open_session(p(1), None);
        pending.open_session(p(9), None);
        pending.sweep(t0 + ttl, |_| false);
        pending.settle_exhausted(t0 + ttl, |_| true);
        assert!(pending.take_speculative(p(1)).is_empty(), "the announcer was asked");
        assert_eq!(pending.take_speculative(p(9)), vec![id(1)]);
    }

    /// One subnet's flood of exhausted claims does not keep another subnet's
    /// exhausted claim from being asked for.
    #[test]
    fn one_subnets_exhausted_claims_do_not_starve_another() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        let flood = Some(1);
        let honest = Some(2);
        pending.open_session(p(1), flood);
        pending.open_session(p(2), honest);
        for n in 0x10..0x14 {
            pending.open_session(p(n), Some(u64::from(n)));
        }
        for n in 0..1000u64 {
            let mut raw = [0u8; reth_msgboard_types::MSG_ID_SIZE];
            raw[..8].copy_from_slice(&(n + 1).to_be_bytes());
            raw[8] = 0xF0;
            let fake = MsgID::decode_list(&raw).expect("one id-sized record")[0];
            pending.claim_from(fake, p(1), flood, t0);
        }
        pending.claim_from(id(1), p(2), honest, t0);
        pending.sweep(t0 + ttl, |_| false);
        let (_, settled) = pending.settle_exhausted(t0 + ttl, |_| true);
        let real = settled.iter().find(|c| c.id == id(1));
        assert!(real.is_some_and(|c| c.asked > 0), "the honest claim was starved: {real:?}");
    }

    /// Claims past the rate are kept for a later window, and the queue stays
    /// bounded.
    #[test]
    fn exhausted_claims_past_the_rate_wait_for_the_next_window() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();
        for n in 0x10..0x20 {
            pending.open_session(p(n), None);
        }
        for n in 0..100u8 {
            pending.open_session(owner(n), Some(u64::from(n)));
            pending.claim_from(id(n), owner(n), Some(u64::from(n)), t0);
        }
        pending.sweep(t0 + ttl, |_| false);
        assert!(pending.exhausted.len() <= MAX_QUEUED_EXHAUSTED);
        let asked = |pending: &mut PendingRequests| {
            std::mem::take(&mut pending.speculative).values().map(Vec::len).sum::<usize>()
        };
        pending.settle_exhausted(t0 + ttl, |_| true);
        assert_eq!(asked(&mut pending), MAX_SPECULATIVE_FETCHES_PER_SEC as usize);
        assert!(pending.exhausted.len() <= MAX_QUEUED_EXHAUSTED);
        pending.settle_exhausted(t0 + ttl + Duration::from_secs(1), |_| true);
        assert_eq!(
            asked(&mut pending),
            MAX_SPECULATIVE_FETCHES_PER_SEC as usize,
            "claims past the rate were dropped instead of kept",
        );
    }

    /// An announcer that arrives after the claim expires, before the sweep
    /// runs, must not take the claim from the peers already waiting.
    #[test]
    fn a_late_announcer_does_not_jump_the_alternates() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();

        pending.claim(id(1), p(1), t0);
        pending.claim(id(1), p(2), t0);
        assert!(!pending.claim(id(1), p(3), t0 + ttl), "p3 jumped the queue");
        assert_eq!(pending.take_retries(p(2), t0 + ttl), vec![id(1)], "p2 is asked next");
    }

    #[test]
    fn alternates_are_bounded() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        for n in 0..=u8::try_from(MAX_ALTERNATES).unwrap() + 3 {
            pending.claim(id(1), p(n), now);
        }
        assert_eq!(pending.claims[&id(1)].alternates.len(), MAX_ALTERNATES);
    }

    /// One peer's fabricated IDs cannot fill the map. Past its quota its
    /// claims are granted but not recorded, so another peer still gets
    /// deduplication.
    #[test]
    fn one_peer_cannot_fill_the_claim_map() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        for n in 0..MAX_CLAIMS_PER_PEER + 100 {
            let mut raw = [0u8; reth_msgboard_types::MSG_ID_SIZE];
            raw[..8].copy_from_slice(&(n as u64).to_be_bytes());
            let flood = MsgID::decode_list(&raw).expect("one id-sized record")[0];
            assert!(pending.claim(flood, p(9), now), "fail open: the request still goes out");
        }
        assert_eq!(pending.len(), MAX_CLAIMS_PER_PEER);

        assert!(pending.claim(id(255), p(1), now));
        assert!(!pending.claim(id(255), p(2), now), "another peer's claims still deduplicate");
    }

    #[test]
    fn maybe_sweep_runs_at_most_once_per_tenth_of_the_ttl() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();

        pending.claim(id(1), p(1), t0);
        pending.maybe_sweep(t0, |_| false);
        pending.maybe_sweep(t0 + ttl, |_| false);
        assert_eq!(pending.len(), 0, "a sweep due by now runs");

        pending.claim(id(2), p(1), t0);
        pending.maybe_sweep(t0 + ttl + Duration::from_millis(1), |_| false);
        assert_eq!(pending.len(), 1, "a second sweep inside the interval is skipped");
    }

    /// A request frame can wait longer than the claim TTL before it is dropped.
    /// Its late release must not free the claim another peer has taken since.
    #[test]
    fn a_stale_release_does_not_steal_a_newer_claim() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let t0 = Instant::now();

        assert!(pending.claim(id(1), p(1), t0));
        let later = t0 + ttl + Duration::from_secs(1);
        assert!(pending.claim(id(1), p(2), later), "p2 re-takes the expired claim");

        pending.release(&id(1), p(1), later);
        assert!(!pending.claim(id(1), p(3), later), "p1's late release freed p2's live claim");
    }

    /// The larger penalty fires once per window, not on every event after the
    /// threshold, so a steady trickle cannot turn into a stream of them.
    #[test]
    fn escalation_fires_once_per_window() {
        let mut strikes = WithholdStrikes::default();
        let t0 = Instant::now();

        strikes.record(p(1), t0);
        strikes.record(p(1), t0 + Duration::from_secs(1));
        assert!(strikes.record(p(1), t0 + Duration::from_secs(2)), "third event escalates");
        assert!(
            !strikes.record(p(1), t0 + Duration::from_secs(3)),
            "the fourth does not escalate again"
        );
    }

    #[test]
    fn repeated_withholding_earns_the_larger_penalty() {
        let mut strikes = WithholdStrikes::default();
        let t0 = Instant::now();

        assert!(!strikes.record(p(1), t0));
        assert!(!strikes.record(p(2), t0), "strikes are counted per peer");
        assert!(!strikes.record(p(1), t0 + Duration::from_secs(10)));
        assert!(strikes.record(p(1), t0 + Duration::from_secs(20)), "third in a minute");
        assert!(
            !strikes.record(p(1), t0 + Duration::from_secs(90)),
            "older events leave the window"
        );
    }

    /// The strike map is bounded and forgets peers whose strikes aged out.
    #[test]
    fn the_strike_map_is_bounded() {
        let mut strikes = WithholdStrikes::default();
        let t0 = Instant::now();
        for n in 0..MAX_STRUCK_PEERS as u64 + 10 {
            strikes.record(PeerId::left_padding_from(&n.to_be_bytes()), t0);
        }
        assert_eq!(strikes.peers.len(), MAX_STRUCK_PEERS);
        strikes.prune(t0 + WITHHOLD_WINDOW);
        assert!(strikes.peers.is_empty());
    }

    #[test]
    fn an_unspent_reservation_is_counted_when_it_expires() {
        let ttl = Duration::from_secs(15);
        let mut wants = WantList::new(ttl, MAX_WANT_PER_PEER);
        let now = Instant::now();

        wants.reserve(hash(1), now);
        wants.reserve(hash(2), now);
        wants.reserve(hash(3), now);
        wants.take(hash(1), now);
        wants.release([hash(2)]);
        wants.prune(now + ttl);

        let expired = wants.take_expired();
        assert_eq!(expired.first_hand, 1, "only the unspent, unreleased one");
        assert!(!expired.silent, "hash(1) was delivered, so the request was answered");
        assert_eq!(wants.take_expired(), Expired::default());
    }

    #[test]
    fn first_claim_is_granted_and_the_second_is_not() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        assert!(pending.claim(id(1), p(1), now), "first peer to announce should request");
        assert!(!pending.claim(id(1), p(2), now), "second peer announcing the same id should not");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn distinct_ids_do_not_block_each_other() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        assert!(pending.claim(id(1), p(1), now));
        assert!(pending.claim(id(2), p(1), now));
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn a_claim_is_retakeable_once_it_expires() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let now = Instant::now();

        assert!(pending.claim(id(1), p(1), now));
        assert!(!pending.claim(id(1), p(1), now + ttl - Duration::from_millis(1)));
        assert!(pending.claim(id(1), p(1), now + ttl), "expired claim should be retaken");
    }

    #[test]
    fn release_frees_the_claim_immediately() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        assert!(pending.claim(id(1), p(1), now));
        pending.release(&id(1), p(1), now);
        assert_eq!(pending.len(), 0);
        assert!(pending.claim(id(1), p(1), now), "a released id should be requestable again");
    }

    #[test]
    fn sweep_drops_only_expired_claims() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let now = Instant::now();

        pending.claim(id(1), p(1), now);
        pending.claim(id(2), p(1), now + Duration::from_secs(9));
        pending.sweep(now + ttl, |_| false);

        assert_eq!(pending.len(), 1, "only the older claim should be swept");
        assert!(!pending.claim(id(2), p(1), now + ttl), "the newer claim should survive");
    }

    #[test]
    fn the_map_stops_growing_at_capacity_but_still_grants_claims() {
        let capacity = 4;
        let mut pending = PendingRequests::new(PENDING_REQUEST_TTL, capacity);
        let now = Instant::now();

        for n in 0..u8::try_from(capacity).unwrap() {
            assert!(pending.claim(id(n), p(1), now));
        }
        assert_eq!(pending.len(), capacity);

        // Past the cap the tracker fails open: the request still goes out, it
        // just stops being deduplicated.
        assert!(pending.claim(id(200), p(1), now), "claims past the cap must still be granted");
        assert!(pending.claim(id(200), p(1), now), "and are not deduplicated, by design");
        assert_eq!(pending.len(), capacity, "but the map does not grow");
    }

    fn hash(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    // ── request pacer ────────────────────────────────────────────────────────

    /// The pacer allows one burst, then the refill rate, and keeps the rest
    /// queued in order.
    #[test]
    fn the_pacer_allows_one_burst_then_the_refill() {
        let mut pacer = RequestPacer::default();
        let t0 = Instant::now();
        let cost = PACE_BURST_BYTES / 4;
        let ids: Vec<MsgID> = (0..10).map(id).collect();
        assert_eq!(pacer.defer(ids.clone(), 100), 0);

        assert_eq!(pacer.take_affordable(t0, usize::MAX, |_| cost), ids[..4].to_vec());
        assert!(pacer.take_affordable(t0, usize::MAX, |_| cost).is_empty(), "the burst is spent");
        // The pacer refills at 90% of the responder rate, so one cost takes
        // just over a second.
        let later = t0 + Duration::from_millis(1100);
        assert_eq!(pacer.take_affordable(later, usize::MAX, |_| cost), ids[4..5].to_vec());
        assert_eq!(pacer.deferred(), 5);
    }

    #[test]
    fn the_pacer_queue_is_bounded_and_skips_duplicates() {
        let mut pacer = RequestPacer::default();
        assert_eq!(pacer.defer([id(1), id(1), id(2)], 3), 0);
        assert_eq!(pacer.deferred(), 2, "a duplicate is queued once");
        assert_eq!(pacer.defer([id(3), id(4)], 3), 1, "past the cap the rest is dropped");
        assert_eq!(pacer.deferred(), 3);
    }

    // ── want list ────────────────────────────────────────────────────────────

    #[test]
    fn re_announcing_an_owed_hash_does_not_buy_a_second_verification() {
        let mut wants = WantList::default();
        let now = Instant::now();

        assert!(wants.reserve(hash(1), now));
        assert!(!wants.reserve(hash(1), now), "the peer already owes us this one");
        assert_eq!(wants.len(), 1);
    }

    /// Unlike [`PendingRequests::claim`], which fails open, a full want list
    /// refuses — an unrecorded reservation is a message we would drop on
    /// arrival, so asking for it wastes the round trip.
    #[test]
    fn the_want_list_fails_closed_at_capacity() {
        let capacity = 4;
        let mut wants = WantList::new(WANT_TIMEOUT, capacity);
        let now = Instant::now();

        for n in 0..u8::try_from(capacity).unwrap() {
            assert!(wants.reserve(hash(n), now));
        }
        assert!(!wants.reserve(hash(200), now), "past the cap a reservation is refused");
        assert_eq!(wants.len(), capacity);
    }

    #[test]
    fn releasing_a_reservation_withdraws_its_authorisation() {
        let mut wants = WantList::default();
        let now = Instant::now();

        wants.reserve(hash(1), now);
        wants.reserve(hash(2), now);
        wants.release([hash(1)]);

        assert_eq!(wants.len(), 1);
        assert!(wants.take(hash(2), now), "the surviving reservation still pays for one");
        assert!(!wants.take(hash(1), now), "the released one does not");
    }

    /// A delivery that names itself spends its own reservation, not the oldest
    /// one. Erigon keys the want list by `(peer, hash)` and takes by hash, so a
    /// late answer to an earlier request stays authorised.
    #[test]
    fn taking_by_hash_spends_only_that_hash() {
        let mut wants = WantList::default();
        let now = Instant::now();

        wants.reserve(hash(1), now);
        wants.reserve(hash(2), now);

        assert!(wants.take(hash(2), now), "the message that arrived is paid for");
        assert!(!wants.take(hash(2), now), "and only once");
        assert_eq!(wants.len(), 1);
        assert!(wants.take(hash(1), now), "the older reservation survived");
    }

    #[test]
    fn taking_a_hash_we_never_reserved_authorises_nothing() {
        let mut wants = WantList::default();
        let now = Instant::now();
        wants.reserve(hash(1), now);

        assert!(!wants.take(hash(9), now), "an unrequested message is not authorised");
        assert_eq!(wants.len(), 1, "and it does not consume someone else's reservation");
    }

    #[test]
    fn a_reservation_taken_by_hash_stops_authorising_once_it_expires() {
        let ttl = Duration::from_secs(15);
        let mut wants = WantList::new(ttl, MAX_WANT_PER_PEER);
        let now = Instant::now();

        wants.reserve(hash(1), now);
        assert!(!wants.take(hash(1), now + ttl), "a late answer buys nothing");
        assert_eq!(wants.len(), 0);
    }

    /// Released entries stay in the queue and are skipped when they surface, so
    /// a release must not shorten the budget of the reservations behind it.
    #[test]
    fn a_released_entry_does_not_consume_a_later_reservation() {
        let mut wants = WantList::default();
        let now = Instant::now();

        for n in 0..3 {
            wants.reserve(hash(n), now);
        }
        wants.release([hash(0), hash(1)]);

        assert!(wants.take(hash(2), now));
        assert!(!wants.take(hash(2), now), "only one reservation survived the release");
    }

    /// Spent reservations do not count against the cap. An honest peer that
    /// delivers everything it is asked for must never be refused.
    #[test]
    fn spent_reservations_do_not_use_up_the_cap() {
        let mut wants = WantList::default();
        let now = Instant::now();

        for n in 0..=MAX_WANT_PER_PEER as u64 {
            let h = B256::left_padding_from(&n.to_be_bytes());
            assert!(wants.reserve(h, now), "reservation {n} refused with nothing outstanding");
            assert!(wants.take(h, now), "reservation {n} not spendable");
        }
    }

    /// The expiry of an old, released reservation must not cancel a newer
    /// reservation for the same hash.
    #[test]
    fn an_old_expiry_does_not_cancel_a_newer_reservation() {
        let ttl = Duration::from_secs(15);
        let mut wants = WantList::new(ttl, MAX_WANT_PER_PEER);
        let t0 = Instant::now();

        assert!(wants.reserve(hash(1), t0));
        wants.release([hash(1)]);
        assert!(wants.reserve(hash(1), t0 + Duration::from_secs(10)));

        // Past the first reservation's expiry, inside the second's.
        assert!(
            wants.take(hash(1), t0 + Duration::from_secs(16)),
            "the newer reservation was lost"
        );
    }
}
