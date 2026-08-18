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
    collections::HashMap,
    time::{Duration, Instant},
};

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
}
