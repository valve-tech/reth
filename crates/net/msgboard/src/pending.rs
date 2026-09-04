//! In-flight request tracking for announced message IDs.
//!
//! Gossip converges by every peer announcing every message. Without in-flight
//! tracking, `filter_wanted` accepts an ID until the moment it lands in the
//! index, so each of the N peers that announce a new message gets its own
//! `GetBoardMessages` request. All N answer, and the board pays a full `PoW`
//! verification for each — a secp256k1 scalar multiplication — to keep one.
//!
//! The waste cannot be removed inside verification. A message's index key is
//! `sha256(challenge ‖ category ‖ data)` and `challenge` *is* the elliptic
//! curve point, so nothing can look a message up without first paying for its
//! `PoW`. The only place to spend less is before the request goes out, which is
//! what [`PendingRequests`] does.
//!
//! Measured on the production fleet before this existed (2026-08-17):
//!
//! | box | `requests_sent` | `accepted_remote` | `skipped_duplicate` |
//! |---|---|---|---|
//! | `direct-a-evm-943` | 445 | 45 | 400 (90%) |
//! | `direct-a-evm-1` | 65 | 1 | 64 (98%) |

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use reth_msgboard_types::MsgID;

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
/// Not thread-safe on its own — [`MsgBoard`](crate::MsgBoard) keeps it inside
/// the state mutex that `filter_wanted` already holds.
#[derive(Debug)]
pub(crate) struct PendingRequests {
    claims: HashMap<MsgID, Instant>,
    ttl: Duration,
    capacity: usize,
}

impl PendingRequests {
    /// Create a tracker with the given expiry and entry cap.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self { claims: HashMap::new(), ttl, capacity }
    }

    /// Try to claim `id` for a request.
    ///
    /// Returns `true` when the caller should send the request, `false` when
    /// another peer's announcement already claimed it and the claim is live.
    ///
    /// Claims are **not** rejected once the map is full. Failing open keeps a
    /// peer that floods synthetic IDs from suppressing real ones; the cost of
    /// falling back is the duplicate requests this type exists to avoid, which
    /// is strictly better than dropping messages we actually want.
    pub(crate) fn claim(&mut self, id: MsgID, now: Instant) -> bool {
        match self.claims.get(&id) {
            Some(claimed_at) if now.duration_since(*claimed_at) < self.ttl => false,
            // An expired claim is re-taken rather than left to the sweep, so a
            // peer that went silent does not delay the retry past the TTL.
            Some(_) => {
                self.claims.insert(id, now);
                true
            }
            None => {
                if self.claims.len() < self.capacity {
                    self.claims.insert(id, now);
                }
                true
            }
        }
    }

    /// Drop the claim on `id`.
    ///
    /// Called when the request that a claim was taken for never reached the
    /// peer, so the next announcement re-requests it instead of waiting out
    /// the TTL.
    pub(crate) fn release(&mut self, id: &MsgID) {
        self.claims.remove(id);
    }

    /// Drop every claim older than the TTL.
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.claims.retain(|_, claimed_at| now.duration_since(*claimed_at) < self.ttl);
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
/// Reth cannot yet match a delivered message to its reservation, because it
/// takes a scalar multiplication to learn which message arrived — the index key
/// is `sha256(challenge ‖ category ‖ data)` and `challenge` *is* the curve
/// point. Erigon closed that gap by putting the sender's claimed hash on the
/// wire (`WirePoWMsg`). Until reth speaks that format,
/// [`take_any`](Self::take_any) spends the oldest live reservation instead of
/// the matching one, which bounds the work exactly and identifies it only
/// approximately.
#[derive(Debug)]
pub(crate) struct WantList {
    /// Reserved hashes in reservation order. Every entry shares one TTL, so
    /// insertion order is expiry order and the front is always the oldest.
    queue: VecDeque<Want>,
    /// Membership, so a peer re-announcing an ID it already owes us does not
    /// reserve a second slot.
    live: HashSet<B256>,
    ttl: Duration,
    capacity: usize,
}

impl WantList {
    /// Create a want list with the given expiry and entry cap.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self { queue: VecDeque::new(), live: HashSet::new(), ttl, capacity }
    }

    /// Drop every reservation older than the TTL.
    ///
    /// Expiry is lazy, as in erigon: `reserve` and `take_any` prune, and
    /// nothing runs on a timer.
    pub(crate) fn prune(&mut self, now: Instant) {
        while let Some(front) = self.queue.front() {
            if now < front.expires_at {
                break;
            }
            let expired = self.queue.pop_front().expect("front exists");
            self.live.remove(&expired.hash);
        }
    }

    /// Reserve `hash`, authorising this peer to deliver one message.
    ///
    /// Returns `false` when the peer already owes us that hash or the list is
    /// full. Unlike [`PendingRequests::claim`] this fails **closed**, matching
    /// erigon's `Reserve`: a reservation we do not record is a message we would
    /// refuse to verify on arrival, so requesting it would waste the round trip.
    /// The caller must hand a refused ID back to [`PendingRequests`] rather than
    /// request it.
    pub(crate) fn reserve(&mut self, hash: B256, now: Instant) -> bool {
        if self.live.contains(&hash) || self.queue.len() >= self.capacity {
            return false;
        }
        self.queue.push_back(Want { hash, expires_at: now + self.ttl });
        self.live.insert(hash);
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

    /// Spend one reservation, authorising one `PoW` verification.
    ///
    /// Returns `false` when the peer has none left, which is the signal to drop
    /// the message unverified. The oldest live reservation is spent because
    /// reth cannot tell *which* message arrived before verifying it — see the
    /// type comment. A spent reservation is not restored if the message then
    /// fails validation, matching erigon: the peer is penalised, and another
    /// peer may already hold its own reservation for the same message.
    pub(crate) fn take_any(&mut self, now: Instant) -> bool {
        self.prune(now);
        while let Some(want) = self.queue.pop_front() {
            if self.live.remove(&want.hash) {
                return true;
            }
        }
        false
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

    #[test]
    fn first_claim_is_granted_and_the_second_is_not() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        assert!(pending.claim(id(1), now), "first peer to announce should request");
        assert!(!pending.claim(id(1), now), "second peer announcing the same id should not");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn distinct_ids_do_not_block_each_other() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        assert!(pending.claim(id(1), now));
        assert!(pending.claim(id(2), now));
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn a_claim_is_retakeable_once_it_expires() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let now = Instant::now();

        assert!(pending.claim(id(1), now));
        assert!(!pending.claim(id(1), now + ttl - Duration::from_millis(1)));
        assert!(pending.claim(id(1), now + ttl), "expired claim should be retaken");
    }

    #[test]
    fn release_frees_the_claim_immediately() {
        let mut pending = PendingRequests::default();
        let now = Instant::now();

        assert!(pending.claim(id(1), now));
        pending.release(&id(1));
        assert_eq!(pending.len(), 0);
        assert!(pending.claim(id(1), now), "a released id should be requestable again");
    }

    #[test]
    fn sweep_drops_only_expired_claims() {
        let ttl = Duration::from_secs(10);
        let mut pending = PendingRequests::new(ttl, MAX_PENDING_REQUESTS);
        let now = Instant::now();

        pending.claim(id(1), now);
        pending.claim(id(2), now + Duration::from_secs(9));
        pending.sweep(now + ttl);

        assert_eq!(pending.len(), 1, "only the older claim should be swept");
        assert!(!pending.claim(id(2), now + ttl), "the newer claim should survive");
    }

    #[test]
    fn the_map_stops_growing_at_capacity_but_still_grants_claims() {
        let capacity = 4;
        let mut pending = PendingRequests::new(PENDING_REQUEST_TTL, capacity);
        let now = Instant::now();

        for n in 0..u8::try_from(capacity).unwrap() {
            assert!(pending.claim(id(n), now));
        }
        assert_eq!(pending.len(), capacity);

        // Past the cap the tracker fails open: the request still goes out, it
        // just stops being deduplicated.
        assert!(pending.claim(id(200), now), "claims past the cap must still be granted");
        assert!(pending.claim(id(200), now), "and are not deduplicated, by design");
        assert_eq!(pending.len(), capacity, "but the map does not grow");
    }

    fn hash(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    // ── want list ────────────────────────────────────────────────────────────

    #[test]
    fn a_reservation_authorises_exactly_one_delivery() {
        let mut wants = WantList::default();
        let now = Instant::now();

        assert!(wants.reserve(hash(1), now));
        assert!(wants.take_any(now), "the message we asked for is paid for");
        assert!(!wants.take_any(now), "a second message on one request is not");
    }

    #[test]
    fn an_unrequested_delivery_is_never_authorised() {
        let mut wants = WantList::default();
        assert!(!wants.take_any(Instant::now()), "nothing was asked for");
    }

    #[test]
    fn re_announcing_an_owed_hash_does_not_buy_a_second_verification() {
        let mut wants = WantList::default();
        let now = Instant::now();

        assert!(wants.reserve(hash(1), now));
        assert!(!wants.reserve(hash(1), now), "the peer already owes us this one");
        assert_eq!(wants.len(), 1);
    }

    #[test]
    fn a_reservation_stops_authorising_once_it_expires() {
        let ttl = Duration::from_secs(15);
        let mut wants = WantList::new(ttl, MAX_WANT_PER_PEER);
        let now = Instant::now();

        wants.reserve(hash(1), now);
        assert!(!wants.take_any(now + ttl), "a late answer buys nothing");
        assert_eq!(wants.len(), 0);
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
        assert!(wants.take_any(now), "the surviving reservation still pays for one");
        assert!(!wants.take_any(now), "the released one does not");
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

        assert!(wants.take_any(now));
        assert!(!wants.take_any(now), "only one reservation survived the release");
    }
}
