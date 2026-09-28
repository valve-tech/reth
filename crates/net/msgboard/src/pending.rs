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
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use reth_msgboard_types::MsgID;
use reth_network_api::PeerId;

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
/// message by one TTL, not suppress it.
pub(crate) const MAX_ALTERNATES: usize = 4;

/// Window in which repeated withholding counts as a pattern.
pub(crate) const WITHHOLD_WINDOW: Duration = Duration::from_secs(60);

/// Withholding events inside [`WITHHOLD_WINDOW`] that earn the larger penalty.
pub(crate) const WITHHOLD_STRIKES: usize = 3;

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
    pub(crate) fn claim(&mut self, id: MsgID, peer: PeerId, now: Instant) -> bool {
        match self.claims.get_mut(&id) {
            Some(claim) if now.duration_since(claim.claimed_at) < self.ttl => {
                if claim.owner != peer &&
                    !claim.alternates.contains(&peer) &&
                    claim.alternates.len() < MAX_ALTERNATES
                {
                    claim.alternates.push(peer);
                }
                false
            }
            // An expired claim is re-taken rather than left to the sweep, so a
            // peer that went silent does not delay the retry past the TTL.
            Some(claim) => {
                let previous = std::mem::replace(&mut claim.owner, peer);
                claim.claimed_at = now;
                claim.retry = false;
                claim.alternates.retain(|p| *p != peer);
                decrement(&mut self.owned, previous);
                *self.owned.entry(peer).or_default() += 1;
                true
            }
            None => {
                let owned = self.owned.get(&peer).copied().unwrap_or_default();
                if self.claims.len() < self.capacity && owned < MAX_CLAIMS_PER_PEER {
                    self.claims.insert(
                        id,
                        Claim {
                            claimed_at: now,
                            owner: peer,
                            alternates: Vec::new(),
                            retry: false,
                        },
                    );
                    *self.owned.entry(peer).or_default() += 1;
                }
                true
            }
        }
    }

    /// Give up the claim on `id`.
    ///
    /// Called when the request that a claim was taken for never reached the
    /// peer. If an alternate announced the ID, the claim moves to it at once.
    /// Otherwise the claim is dropped, so the next announcement re-requests it
    /// instead of waiting out the TTL.
    pub(crate) fn release(&mut self, id: &MsgID, now: Instant) {
        let Some(claim) = self.claims.get_mut(id) else { return };
        let previous = claim.owner;
        if claim.alternates.is_empty() {
            self.claims.remove(id);
        } else {
            claim.hand_to_next_alternate(now, &mut self.owned, &mut self.retries, *id);
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
    pub(crate) fn sweep(&mut self, now: Instant, is_held: impl Fn(&MsgID) -> bool) {
        let ttl = self.ttl;
        let Self { claims, owned, retries, .. } = self;
        claims.retain(|id, claim| {
            if now.duration_since(claim.claimed_at) < ttl {
                return true;
            }
            decrement(owned, claim.owner);
            if claim.alternates.is_empty() || is_held(id) {
                return false;
            }
            claim.hand_to_next_alternate(now, owned, retries, *id);
            true
        });
        // A retry goes stale when its claim moves on, for example to a later
        // alternate because the peer it was queued for has disconnected.
        retries.retain(|peer, ids| {
            ids.retain(|id| claims.get(id).is_some_and(|c| c.retry && c.owner == *peer));
            !ids.is_empty()
        });
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
/// [`take`](Self::take) spends the reservation for a named hash, mirroring
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
    live: HashMap<B256, Instant>,
    /// Reservations that expired unspent since the last
    /// [`take_expired_unspent`](Self::take_expired_unspent).
    expired_unspent: usize,
    ttl: Duration,
    capacity: usize,
}

impl WantList {
    /// Create a want list with the given expiry and entry cap.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self { queue: VecDeque::new(), live: HashMap::new(), expired_unspent: 0, ttl, capacity }
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
            if self.live.get(&expired.hash) == Some(&expired.expires_at) {
                self.live.remove(&expired.hash);
                self.expired_unspent += 1;
            }
        }
    }

    /// Return the number of reservations that expired unspent since the last
    /// call, and reset it.
    pub(crate) fn take_expired_unspent(&mut self) -> usize {
        std::mem::take(&mut self.expired_unspent)
    }

    /// Reserve `hash`, authorising this peer to deliver one message.
    ///
    /// Returns `false` when the peer already owes us that hash or the list is
    /// full. Only unspent reservations count toward the cap, as in erigon
    /// (`msgboard/want_list.go`). Unlike [`PendingRequests::claim`] this fails
    /// **closed**, matching erigon's `Reserve`: a reservation we do not record
    /// is a message we would refuse to verify on arrival, so requesting it
    /// would waste the round trip. The caller must hand a refused ID back to
    /// [`PendingRequests`] rather than request it.
    pub(crate) fn reserve(&mut self, hash: B256, now: Instant) -> bool {
        if self.live.contains_key(&hash) || self.live.len() >= self.capacity {
            return false;
        }
        // Spent entries wait in the queue until their TTL. Compact when they
        // outnumber the live ones, so the queue stays O(capacity) however fast
        // a peer spends its reservations. Each compaction removes at least
        // `capacity` entries, so its cost is amortised over them.
        if self.queue.len() >= 2 * self.capacity {
            let live = &self.live;
            self.queue.retain(|w| live.get(&w.hash) == Some(&w.expires_at));
        }
        let expires_at = now + self.ttl;
        self.queue.push_back(Want { hash, expires_at });
        self.live.insert(hash, expires_at);
        true
    }

    /// Give back reservations for a request that never reached the peer.
    ///
    /// The queue entry is left in place and skipped when it surfaces, so this
    /// stays O(1) per hash. Mirrors erigon's `Drop`.
    pub(crate) fn release(&mut self, hashes: impl IntoIterator<Item = B256>) {
        for hash in hashes {
            self.live.remove(&hash);
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
    pub(crate) fn take(&mut self, hash: B256, now: Instant) -> bool {
        self.prune(now);
        self.live.remove(&hash).is_some()
    }

    /// Number of live reservations, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live.len()
    }
}

impl Default for WantList {
    fn default() -> Self {
        Self::new(WANT_TIMEOUT, MAX_WANT_PER_PEER)
    }
}

/// Counts withholding events for one peer and picks the penalty.
///
/// A withholding event is one check that found reservations which expired
/// unspent. An honest peer can cause one now and then, for example when a
/// message leaves its index before it answers, so a single event earns a small
/// penalty. [`WITHHOLD_STRIKES`] events inside [`WITHHOLD_WINDOW`] earn the
/// larger one.
#[derive(Debug, Default)]
pub(crate) struct WithholdStrikes {
    recent: VecDeque<Instant>,
}

impl WithholdStrikes {
    /// Record one withholding event. Returns `true` when it is part of a
    /// pattern and earns the larger penalty.
    pub(crate) fn record(&mut self, now: Instant) -> bool {
        while self.recent.front().is_some_and(|t| now.duration_since(*t) >= WITHHOLD_WINDOW) {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        self.recent.len() >= WITHHOLD_STRIKES
    }
}

/// One claimed ID: who was asked, when, and who else announced it.
#[derive(Debug)]
struct Claim {
    claimed_at: Instant,
    owner: PeerId,
    /// Later announcers, in announcement order.
    alternates: Vec<PeerId>,
    /// The claim moved to `owner`, which has not been asked yet.
    retry: bool,
}

impl Claim {
    /// Make the first alternate the owner and queue a retry for it. The caller
    /// accounts for the previous owner.
    fn hand_to_next_alternate(
        &mut self,
        now: Instant,
        owned: &mut HashMap<PeerId, usize>,
        retries: &mut HashMap<PeerId, Vec<MsgID>>,
        id: MsgID,
    ) {
        let next = self.alternates.remove(0);
        self.owner = next;
        self.claimed_at = now;
        self.retry = true;
        *owned.entry(next).or_default() += 1;
        retries.entry(next).or_default().push(id);
    }
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
        pending.release(&id(1), now);

        assert_eq!(pending.take_retries(p(2), now), vec![id(1)]);
        assert!(!pending.claim(id(1), p(1), now), "the claim is live under p2");
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

    #[test]
    fn repeated_withholding_earns_the_larger_penalty() {
        let mut strikes = WithholdStrikes::default();
        let t0 = Instant::now();

        assert!(!strikes.record(t0));
        assert!(!strikes.record(t0 + Duration::from_secs(10)));
        assert!(strikes.record(t0 + Duration::from_secs(20)), "third in a minute");
        assert!(!strikes.record(t0 + Duration::from_secs(90)), "older events leave the window",);
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

        assert_eq!(wants.take_expired_unspent(), 1, "only the unspent, unreleased one");
        assert_eq!(wants.take_expired_unspent(), 0);
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
        pending.release(&id(1), now);
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
