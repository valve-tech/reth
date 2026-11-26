//! Peer choice, hedging and benching.
//!
//! [`PeerBook`] is pure bookkeeping over a clock the caller supplies, so the policy is testable
//! with paused tokio time:
//!
//! * candidates need an eth and a snap channel (the transport only reports such peers), sorted by
//!   requests in flight, then latency EWMA (a peer with no sample counts as 400 ms);
//! * at most [`MAX_CANDIDATES`] peers are tried per request;
//! * a peer that fails [`BENCH_AFTER`] times in a row is benched for `min(fails - 4, 6) * 2 s`;
//! * a failure that lands while the peer is benched is not counted, so a burst of concurrent
//!   requests that fail together counts as [`BENCH_AFTER`] failures at most;
//! * an empty answer while an older request to the same peer is still on the wire is taken as a
//!   busy server, not as a failure: a `snap/1` server answers empty over its per-peer limits, and
//!   the older request is the one it is busy with. Each good answer also excuses [`BUSY_PER_GOOD`]
//!   other empty answers, up to [`BUSY_CREDIT`]; past that, or before any good answer, an empty
//!   answer is a failure. Like an abandoned attempt, an empty answer slower than the latency
//!   estimate counts as a latency sample;
//! * a discovered peer that fails [`DROP_AFTER`] times in a row has its session ended, so its slot
//!   can go to another peer; its failure count stays until it gives a good answer or leaves. Each
//!   failure past [`BENCH_AFTER`] needs the bench before it to end, so this takes 150 s at least;
//! * a peer that is not connected is forgotten once it has no ban, bench or request in flight;
//! * static peers sort ahead of discovered ones;
//! * a peer whose data failed verification is banned for [`BAN_FOR`] and never a candidate
//!   meanwhile;
//! * a request still out when another peer answered first keeps running and is judged when it
//!   lands, as any other: losing a race is not a failure, a timeout is. A timeout is also a latency
//!   sample of the time the request ran;
//! * an attempt that is abandoned (the caller gave up on the fetch) is not a failure, but if it ran
//!   longer than the peer's latency estimate, the time it ran counts as a latency sample;
//! * requests to one peer are paced at [`PEER_RATE`] a second after a burst of [`PEER_BURST`], a
//!   wide margin under the rate a `snap/1` server allows one peer by default (1000 a second, a
//!   burst of 2000). The server holds a request over that rate for a token, up to 2 s, and then
//!   answers it empty. A booked send that is given up before its time gives its turn back, so
//!   callers that give up while they wait cannot push the pace ahead. A request whose peer would
//!   have to wait goes to the next candidate, if the pass has one, and so does one whose peer is
//!   benched or banned by the time it gets its fetch permit;
//! * one peer has at most [`MAX_PEER_FETCHES`] requests held (waiting for a fetch permit or for its
//!   pace, or on the wire), and quiet peers, those without a good answer in the last
//!   [`ANSWERED_WITHIN`], have at most [`MAX_QUIET_FETCHES`] held together. This holds on every
//!   send: a request goes to another candidate or waits, it never goes past either cap.

use super::client::{MAX_PEER_FETCHES, MAX_QUIET_FETCHES};
use reth_network_peers::PeerId;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Peers tried for one request.
pub const MAX_CANDIDATES: usize = 6;
/// Consecutive failures that bench a peer.
pub const BENCH_AFTER: u32 = 5;
/// Consecutive failures, across benches, after which a discovered peer's session is ended.
pub const DROP_AFTER: u32 = 20;
/// Empty answers, with no older request to the peer on the wire, that one good answer excuses.
pub const BUSY_PER_GOOD: u32 = 4;
/// The most such empty answers a peer can have excused in advance.
pub const BUSY_CREDIT: u32 = 64;
/// How long a peer that sent data failing verification is ignored.
pub const BAN_FOR: Duration = Duration::from_secs(30 * 60);
/// Latency assumed for a peer with no sample.
pub const UNSAMPLED_LATENCY: Duration = Duration::from_millis(400);
/// Pause before the one retry after every candidate failed.
pub const RETRY_PAUSE: Duration = Duration::from_millis(750);
/// The longest wait before starting the next hedged attempt of a snap request.
pub const MAX_SNAP_HEDGE: Duration = Duration::from_millis(500);
/// Requests a second sent to one peer once its burst is spent.
pub const PEER_RATE: u32 = 150;
/// Requests one peer may be sent at once.
pub const PEER_BURST: u32 = 200;
/// How long a good answer keeps a peer out of the quiet share.
pub const ANSWERED_WITHIN: Duration = Duration::from_secs(4);
/// The time between two paced sends to one peer.
const PACE_INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / PEER_RATE as u64);

#[derive(Debug, Clone, Default)]
struct PeerStat {
    inflight: u32,
    ewma: Option<Duration>,
    fails: u32,
    benched_until: Option<Instant>,
    banned_until: Option<Instant>,
    /// When the next request may go out if the peer's burst were spent.
    next_send: Option<Instant>,
    /// Empty answers excused in advance by good ones.
    credit: u32,
    /// The requests on the wire, by send number. At most one per fetch permit, since a request
    /// holds its permit until it lands.
    wire: Vec<u64>,
    /// Requests sent so far: the last send number.
    sends: u64,
    /// Requests held for the peer: waiting for a fetch permit or for its pace, or on the wire.
    held: usize,
    /// When the peer last gave a good answer.
    answered_at: Option<Instant>,
}

impl PeerStat {
    fn sample(&mut self, latency: Duration) {
        self.ewma = Some(
            self.ewma.map_or(latency, |old| old.saturating_mul(7).saturating_add(latency) / 8),
        );
    }
}

/// Per-peer request statistics.
#[derive(Debug, Default)]
pub struct PeerBook {
    peers: HashMap<PeerId, PeerStat>,
    /// Requests held for peers that were quiet when the request was held.
    quiet_held: usize,
}

impl PeerBook {
    /// The delay before hedging a request with `timeout` to the next candidate.
    pub fn hedge_delay(timeout: Duration) -> Duration {
        (timeout / 4).min(MAX_SNAP_HEDGE)
    }

    /// Orders `connected` peers for one request: not benched, fewest in flight, then fastest.
    pub fn candidates(&mut self, connected: &[PeerId], now: Instant) -> Vec<PeerId> {
        self.candidates_preferring(connected, now, |_| false)
    }

    /// Like [`Self::candidates`], with the peers `preferred` picks (the static ones) first.
    pub fn candidates_preferring(
        &mut self,
        connected: &[PeerId],
        now: Instant,
        preferred: impl Fn(&PeerId) -> bool,
    ) -> Vec<PeerId> {
        // A peer that left keeps its entry only while a ban, a bench or a request is live, so
        // peer churn cannot grow the book.
        self.peers.retain(|p, s| {
            connected.contains(p) ||
                s.inflight > 0 ||
                s.held > 0 ||
                s.benched_until.is_some_and(|t| t > now) ||
                s.banned_until.is_some_and(|t| t > now)
        });
        let unsampled = PeerStat::default();
        let mut c: Vec<(bool, u32, Duration, PeerId)> = connected
            .iter()
            .filter_map(|p| {
                let s = self.peers.get(p).unwrap_or(&unsampled);
                if s.benched_until.is_some_and(|t| t > now) ||
                    s.banned_until.is_some_and(|t| t > now)
                {
                    return None;
                }
                Some((!preferred(p), s.inflight, s.ewma.unwrap_or(UNSAMPLED_LATENCY), *p))
            })
            .collect();
        c.sort_by_key(|(other, inflight, lat, _)| (*other, *inflight, *lat));
        c.into_iter().take(MAX_CANDIDATES).map(|(_, _, _, p)| p).collect()
    }

    /// `peer` sent data that failed verification: it is ignored until `now + BAN_FOR`.
    pub fn ban(&mut self, peer: PeerId, now: Instant) {
        let s = self.peers.entry(peer).or_default();
        s.inflight = s.inflight.saturating_sub(1);
        s.banned_until = Some(now + BAN_FOR);
    }

    /// Whether `peer` is banned at `now`.
    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.peers.get(peer).and_then(|s| s.banned_until).is_some_and(|t| t > now)
    }

    /// A request to `peer` started.
    pub fn start(&mut self, peer: PeerId) {
        self.peers.entry(peer).or_default().inflight += 1;
    }

    /// A request to `peer` ended without being judged (abandoned) after it ran for `ran_for`. It
    /// is not a failure, but a run longer than the latency estimate is a lower bound on the
    /// peer's latency, so it counts as a sample: a peer that stops answering loses its place.
    pub fn abandon(&mut self, peer: PeerId, ran_for: Duration) {
        if let Some(s) = self.peers.get_mut(&peer) {
            s.inflight = s.inflight.saturating_sub(1);
            if ran_for > s.ewma.unwrap_or(UNSAMPLED_LATENCY) {
                s.sample(ran_for);
            }
        }
    }

    /// A request to `peer` timed out after it ran for `ran_for`: a latency sample like
    /// [`Self::abandon`], and a [`Self::failure`]. Returns what that returns.
    pub fn timed_out(&mut self, peer: PeerId, ran_for: Duration, now: Instant) -> bool {
        let s = self.peers.entry(peer).or_default();
        if ran_for > s.ewma.unwrap_or(UNSAMPLED_LATENCY) {
            s.sample(ran_for);
        }
        self.failure(peer, now)
    }

    /// A request to `peer` returned good data after `latency`.
    pub fn success(&mut self, peer: PeerId, latency: Duration) {
        let s = self.peers.entry(peer).or_default();
        s.inflight = s.inflight.saturating_sub(1);
        s.fails = 0;
        s.benched_until = None;
        s.credit = s.credit.saturating_add(BUSY_PER_GOOD).min(BUSY_CREDIT);
        s.sample(latency);
    }

    /// A request to `peer` went out: returns its send number, which stays on the wire until
    /// [`Self::landed`].
    pub fn sent(&mut self, peer: PeerId) -> u64 {
        let s = self.peers.entry(peer).or_default();
        s.sends += 1;
        s.wire.push(s.sends);
        s.sends
    }

    /// The request to `peer` with send number `seq` is no longer on the wire.
    pub fn landed(&mut self, peer: PeerId, seq: u64) {
        if let Some(s) = self.peers.get_mut(&peer) &&
            let Some(i) = s.wire.iter().position(|w| *w == seq)
        {
            s.wire.swap_remove(i);
        }
    }

    /// The request to `peer` with send number `seq` (`None`: not sent) was answered empty after
    /// `ran_for`. A busy peer while an older request to it is on the wire or while it has credit,
    /// otherwise a [`Self::failure`]. Returns what that returns.
    pub fn empty(
        &mut self,
        peer: PeerId,
        seq: Option<u64>,
        ran_for: Duration,
        now: Instant,
    ) -> bool {
        let s = self.peers.entry(peer).or_default();
        if ran_for > s.ewma.unwrap_or(UNSAMPLED_LATENCY) {
            s.sample(ran_for);
        }
        let busy = seq.is_some_and(|seq| s.wire.iter().any(|w| *w < seq));
        if busy || s.credit > 0 {
            if !busy {
                s.credit -= 1;
            }
            s.inflight = s.inflight.saturating_sub(1);
            return false;
        }
        self.failure(peer, now)
    }

    /// A request to `peer` failed (timeout, disconnect, no answer). Returns whether `peer` has
    /// now failed [`DROP_AFTER`] times in a row, with no success between.
    pub fn failure(&mut self, peer: PeerId, now: Instant) -> bool {
        let s = self.peers.entry(peer).or_default();
        s.inflight = s.inflight.saturating_sub(1);
        // The requests in flight when the bench began fail with it; counting them too would let
        // one busy moment of an honest peer end its session.
        if !s.benched_until.is_some_and(|t| t > now) {
            s.fails = s.fails.saturating_add(1);
            if s.fails >= BENCH_AFTER {
                let secs = u64::from((s.fails - 4).min(6)) * 2;
                s.benched_until = Some(now + Duration::from_secs(secs));
            }
        }
        s.fails >= DROP_AFTER
    }

    /// Whether `peer` is benched at `now`.
    pub fn is_benched(&self, peer: &PeerId, now: Instant) -> bool {
        self.peers.get(peer).and_then(|s| s.benched_until).is_some_and(|t| t > now)
    }

    /// Books a send to `peer` and returns when it may go out: `now`, or later once the burst is
    /// spent.
    pub fn pace(&mut self, peer: PeerId, now: Instant) -> Instant {
        let s = self.peers.entry(peer).or_default();
        let due = s.next_send.map_or(now, |t| t.max(now));
        s.next_send = Some(due + PACE_INTERVAL);
        due.checked_sub(PACE_INTERVAL * (PEER_BURST - 1)).map_or(now, |t| t.max(now))
    }

    /// Whether a send to `peer` booked at `now` would have to wait for its pace.
    pub fn is_paced(&self, peer: &PeerId, now: Instant) -> bool {
        self.peers
            .get(peer)
            .and_then(|s| s.next_send)
            .and_then(|t| t.checked_sub(PACE_INTERVAL * (PEER_BURST - 1)))
            .is_some_and(|t| t > now)
    }

    /// A send that [`Self::pace`] booked for `at` did not go out. While `at` is still ahead, the
    /// turn goes back. A later booking then goes out no sooner than this one would have, so the
    /// sends still fit the pace.
    pub fn unpace(&mut self, peer: PeerId, at: Instant, now: Instant) {
        if at <= now {
            return;
        }
        if let Some(t) = self.peers.get_mut(&peer).and_then(|s| s.next_send.as_mut()) &&
            let Some(earlier) = t.checked_sub(PACE_INTERVAL)
        {
            *t = earlier;
        }
    }

    /// Requests to `peer` on the wire: sent and not yet landed.
    pub fn on_wire(&self, peer: &PeerId) -> usize {
        self.peers.get(peer).map_or(0, |s| s.wire.len())
    }

    /// Whether `peer` gave no good answer in the last [`ANSWERED_WITHIN`] before `now`.
    pub fn is_quiet(&self, peer: &PeerId, now: Instant) -> bool {
        self.peers
            .get(peer)
            .and_then(|s| s.answered_at)
            .is_none_or(|t| now.saturating_duration_since(t) > ANSWERED_WITHIN)
    }

    /// `peer` gave a good answer at `now`. Returns whether it was quiet until then.
    pub fn answered(&mut self, peer: PeerId, now: Instant) -> bool {
        let quiet = self.is_quiet(&peer, now);
        self.peers.entry(peer).or_default().answered_at = Some(now);
        quiet
    }

    /// Holds a request for `peer` unless that passes [`MAX_PEER_FETCHES`] for the peer or, for a
    /// quiet peer, [`MAX_QUIET_FETCHES`] for the quiet peers together. Returns whether the hold
    /// counts in the quiet share, which [`Self::release`] needs back.
    pub fn hold(&mut self, peer: PeerId, now: Instant) -> Option<bool> {
        let quiet = self.is_quiet(&peer, now);
        let s = self.peers.entry(peer).or_default();
        if s.held >= MAX_PEER_FETCHES || (quiet && self.quiet_held >= MAX_QUIET_FETCHES) {
            return None;
        }
        s.held += 1;
        self.quiet_held += usize::from(quiet);
        Some(quiet)
    }

    /// Releases a hold of [`Self::hold`]. Returns whether that may let another hold through.
    pub fn release(&mut self, peer: PeerId, quiet: bool) -> bool {
        let mut freed = false;
        if let Some(s) = self.peers.get_mut(&peer) {
            freed = s.held == MAX_PEER_FETCHES;
            s.held = s.held.saturating_sub(1);
        }
        if quiet {
            freed |= self.quiet_held == MAX_QUIET_FETCHES;
            self.quiet_held = self.quiet_held.saturating_sub(1);
        }
        freed
    }

    /// Requests held for `peer`.
    pub fn held(&self, peer: &PeerId) -> usize {
        self.peers.get(peer).map_or(0, |s| s.held)
    }

    /// Requests held for quiet peers together.
    pub const fn quiet_held(&self) -> usize {
        self.quiet_held
    }

    /// Requests in flight to `peer`.
    pub fn inflight(&self, peer: &PeerId) -> u32 {
        self.peers.get(peer).map_or(0, |s| s.inflight)
    }

    /// The latency estimate of `peer`, `None` before its first sample.
    pub fn latency(&self, peer: &PeerId) -> Option<Duration> {
        self.peers.get(peer).and_then(|s| s.ewma)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> PeerId {
        PeerId::repeat_byte(n)
    }

    #[test]
    fn the_pace_is_under_the_snap1_servers_default_rate() {
        let server = reth_pulsechain_snap::Snap1Config::default();
        assert!(PEER_RATE < server.hot_rate, "{PEER_RATE} vs {}", server.hot_rate);
        assert!(PEER_BURST < server.hot_burst, "{PEER_BURST} vs {}", server.hot_burst);
    }

    #[test]
    fn quiet_peers_share_one_cap_and_an_answer_lifts_it() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        // Quiet peers, however many, hold the quiet share together.
        for n in 0..MAX_QUIET_FETCHES {
            assert_eq!(b.hold(p(n as u8 % 3 + 1), now), Some(true), "hold {n}");
        }
        assert_eq!(b.hold(p(4), now), None);
        // A peer that answered holds up to its own cap, outside the quiet share.
        assert!(b.answered(p(5), now));
        for _ in 0..MAX_PEER_FETCHES {
            assert_eq!(b.hold(p(5), now), Some(false));
        }
        assert_eq!(b.hold(p(5), now), None);
        // Releases at a cap say so; the others do not.
        assert!(b.release(p(5), false));
        assert!(!b.release(p(5), false));
        assert!(b.release(p(1), true));
        assert!(!b.release(p(2), true));
        assert_eq!(b.quiet_held(), MAX_QUIET_FETCHES - 2);
        // Without an answer for longer than ANSWERED_WITHIN, the peer is quiet again.
        let later = now + ANSWERED_WITHIN + Duration::from_millis(1);
        assert!(!b.is_quiet(&p(5), now + ANSWERED_WITHIN));
        assert!(b.is_quiet(&p(5), later));
        assert_eq!(b.hold(p(5), later), Some(true));
    }

    #[test]
    fn orders_by_inflight_then_latency_and_caps_at_six() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        b.success(p(1), Duration::from_millis(50));
        b.success(p(2), Duration::from_millis(10));
        // p(3) is unsampled: 400 ms.
        let order = b.candidates(&[p(1), p(2), p(3)], now);
        assert_eq!(order, vec![p(2), p(1), p(3)]);
        // In flight beats latency.
        b.start(p(2));
        assert_eq!(b.candidates(&[p(1), p(2), p(3)], now)[0], p(1));
        let many: Vec<_> = (1..=10).map(p).collect();
        assert_eq!(b.candidates(&many, now).len(), MAX_CANDIDATES);
    }

    #[test]
    fn five_failures_bench_and_a_success_clears() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        for _ in 0..4 {
            b.start(p(1));
            b.failure(p(1), now);
        }
        assert!(!b.is_benched(&p(1), now));
        b.start(p(1));
        b.failure(p(1), now);
        // fails = 5 -> min(1, 6) * 2 s.
        assert!(b.is_benched(&p(1), now));
        assert!(b.is_benched(&p(1), now + Duration::from_millis(1999)));
        assert!(!b.is_benched(&p(1), now + Duration::from_secs(2)));
        assert!(b.candidates(&[p(1)], now).is_empty());
        // The sixth failure, once the bench is over, benches for 4 s.
        let mut now = now + Duration::from_secs(2);
        b.start(p(1));
        b.failure(p(1), now);
        assert!(b.is_benched(&p(1), now + Duration::from_millis(3999)));
        assert!(!b.is_benched(&p(1), now + Duration::from_secs(4)));
        // The bench is capped at 12 s.
        for _ in 0..20 {
            now += Duration::from_secs(12);
            b.start(p(1));
            b.failure(p(1), now);
        }
        assert!(b.is_benched(&p(1), now + Duration::from_millis(11_999)));
        assert!(!b.is_benched(&p(1), now + Duration::from_secs(12)));
        b.start(p(1));
        b.success(p(1), Duration::from_millis(5));
        assert_eq!(b.candidates(&[p(1)], now), vec![p(1)]);
    }

    #[test]
    fn a_failure_reports_drop_after_its_count_and_a_success_resets_it() {
        let mut b = PeerBook::default();
        let mut now = Instant::now();
        // Each failure lands as the bench before it ends, the fastest way to the drop.
        let start = now;
        for _ in 1..DROP_AFTER {
            b.start(p(1));
            assert!(!b.failure(p(1), now));
            while b.is_benched(&p(1), now) {
                now += Duration::from_secs(1);
            }
        }
        b.start(p(1));
        assert!(b.failure(p(1), now));
        assert_eq!(now - start, Duration::from_secs(150));
        b.start(p(1));
        assert!(b.failure(p(1), now), "it stays due until it helps");
        b.start(p(1));
        b.success(p(1), Duration::from_millis(5));
        b.start(p(1));
        assert!(!b.failure(p(1), now));
    }

    #[test]
    fn failures_while_benched_are_not_counted() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        // One burst of concurrent requests that all fail at once.
        for _ in 0..MAX_CANDIDATES * 32 {
            b.start(p(1));
        }
        for _ in 0..MAX_CANDIDATES * 32 {
            assert!(!b.failure(p(1), now));
        }
        assert_eq!(b.inflight(&p(1)), 0);
        // Still the first bench: 2 s, not the 12 s cap.
        assert!(b.is_benched(&p(1), now + Duration::from_millis(1999)));
        assert!(!b.is_benched(&p(1), now + Duration::from_secs(2)));
        // A late failure of the same burst, after the bench, is the sixth.
        let later = now + Duration::from_secs(2);
        b.start(p(1));
        b.failure(p(1), later);
        assert!(b.is_benched(&p(1), later + Duration::from_millis(3999)));
        assert!(!b.is_benched(&p(1), later + Duration::from_secs(4)));
    }

    #[test]
    fn a_banned_peer_is_not_a_candidate_until_the_ban_ends() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        b.start(p(1));
        b.ban(p(1), now);
        assert_eq!(b.inflight(&p(1)), 0);
        assert!(b.is_banned(&p(1), now));
        assert_eq!(b.candidates(&[p(1), p(2)], now), vec![p(2)]);
        assert!(b.is_banned(&p(1), now + BAN_FOR - Duration::from_secs(1)));
        assert_eq!(b.candidates(&[p(1)], now + BAN_FOR), vec![p(1)]);
        // A success does not lift a ban early.
        b.success(p(1), Duration::from_millis(1));
        assert!(b.is_banned(&p(1), now));
    }

    #[test]
    fn static_peers_sort_first_even_when_slower() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        b.success(p(1), Duration::from_millis(5));
        b.success(p(2), Duration::from_millis(900));
        assert_eq!(b.candidates_preferring(&[p(1), p(2)], now, |x| *x == p(2)), vec![p(2), p(1)]);
        // A cap of six still leaves room for the static peer.
        let many: Vec<_> = (1..=10).map(p).collect();
        assert_eq!(b.candidates_preferring(&many, now, |x| *x == p(10))[0], p(10));
    }

    #[test]
    fn abandoned_attempts_are_not_failures() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        for _ in 0..10 {
            b.start(p(1));
            b.abandon(p(1), Duration::from_secs(1));
        }
        assert_eq!(b.inflight(&p(1)), 0);
        assert!(!b.is_benched(&p(1), now));
        assert_eq!(b.candidates(&[p(1)], now), vec![p(1)]);
    }

    #[test]
    fn an_abandoned_attempt_only_raises_the_latency_estimate() {
        let mut b = PeerBook::default();
        b.success(p(1), Duration::from_millis(80));
        // Ended early because another peer answered: no information, no sample.
        b.start(p(1));
        b.abandon(p(1), Duration::from_millis(10));
        assert_eq!(b.latency(&p(1)), Some(Duration::from_millis(80)));
        // Ran past the estimate without an answer: a sample.
        b.start(p(1));
        b.abandon(p(1), Duration::from_millis(560));
        assert_eq!(b.latency(&p(1)), Some(Duration::from_millis(140)));
        // An unsampled peer counts as UNSAMPLED_LATENCY until it runs past that.
        b.start(p(2));
        b.abandon(p(2), UNSAMPLED_LATENCY);
        assert_eq!(b.latency(&p(2)), None);
        b.start(p(2));
        b.abandon(p(2), Duration::from_millis(520));
        assert_eq!(b.latency(&p(2)), Some(Duration::from_millis(520)));
    }

    #[test]
    fn peers_that_left_are_forgotten_unless_banned_benched_or_busy() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        for n in 10..=200 {
            b.start(p(n));
            b.success(p(n), Duration::from_millis(5));
        }
        b.start(p(1));
        b.ban(p(1), now);
        for _ in 0..BENCH_AFTER {
            b.start(p(2));
            b.failure(p(2), now);
        }
        b.start(p(3));
        assert_eq!(b.candidates(&[p(4)], now), vec![p(4)]);
        let mut kept: Vec<_> = b.peers.keys().copied().collect();
        kept.sort();
        assert_eq!(kept, vec![p(1), p(2), p(3)]);
        // A ban outlives the peer's session.
        assert_eq!(b.candidates(&[p(1), p(4)], now), vec![p(4)]);
        // Once the bench and ban end and nothing is in flight, the entries go too.
        b.abandon(p(3), Duration::ZERO);
        b.candidates(&[], now + BAN_FOR);
        assert!(b.peers.is_empty());
    }

    #[test]
    fn the_latency_estimate_is_the_first_sample_then_an_eighth_of_each_new_one() {
        let mut b = PeerBook::default();
        b.success(p(1), Duration::from_millis(80));
        assert_eq!(b.latency(&p(1)), Some(Duration::from_millis(80)));
        b.success(p(1), Duration::from_millis(160));
        assert_eq!(b.latency(&p(1)), Some(Duration::from_millis(90)));
        // One slow sample does not put a peer behind one that is always a little slower.
        b.success(p(2), Duration::from_millis(100));
        assert_eq!(b.candidates(&[p(2), p(1)], Instant::now()), vec![p(1), p(2)]);
    }

    #[derive(Debug, Clone)]
    enum Op {
        Start(u8),
        Success(u8, u16),
        /// `.1` failures in a row, so benches reach their cap.
        Failure(u8, u8),
        /// `.1` empty answers in a row after `.2` ms, so the credit runs out; each answers the
        /// request on the wire at index `.3`, if any.
        Empty(u8, u8, u16, usize),
        /// A request goes out.
        Send(u8),
        /// The request on the wire at index `.1` lands with no answer.
        Land(u8, usize),
        Abandon(u8, u16),
        TimedOut(u8, u16),
        Ban(u8),
        Advance(u16),
        Candidates {
            connected: u8,
            statics: u8,
        },
    }

    fn op() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::prelude::*;
        let peer = 0..8u8;
        prop_oneof![
            3 => peer.clone().prop_map(Op::Start),
            2 => (peer.clone(), 0..2000u16).prop_map(|(n, ms)| Op::Success(n, ms)),
            3 => (peer.clone(), 1..16u8).prop_map(|(n, times)| Op::Failure(n, times)),
            3 => (peer.clone(), 1..80u8, 0..1000u16, any::<usize>())
                .prop_map(|(n, times, ms, at)| Op::Empty(n, times, ms, at)),
            3 => peer.clone().prop_map(Op::Send),
            1 => (peer.clone(), any::<usize>()).prop_map(|(n, at)| Op::Land(n, at)),
            2 => (peer.clone(), 0..2000u16).prop_map(|(n, ms)| Op::Abandon(n, ms)),
            2 => (peer.clone(), 0..2000u16).prop_map(|(n, ms)| Op::TimedOut(n, ms)),
            1 => peer.prop_map(Op::Ban),
            2 => (0..20_000u16).prop_map(Op::Advance),
            3 => (any::<u8>(), any::<u8>())
                .prop_map(|(connected, statics)| Op::Candidates { connected, statics }),
        ]
    }

    /// What the book must know of one peer, kept by hand from the rules in the module docs.
    #[derive(Debug, Clone, Copy, Default)]
    struct Model {
        inflight: u32,
        fails: u32,
        ewma: Option<Duration>,
        benched_until: Option<Instant>,
        banned_until: Option<Instant>,
        credit: u32,
    }

    impl Model {
        fn sample(&mut self, d: Duration) {
            self.ewma = Some(self.ewma.map_or(d, |old| (old * 7 + d) / 8));
        }
        /// A failure, its inflight already taken off.
        fn fail(&mut self, now: Instant) {
            if !self.benched_until.is_some_and(|t| t > now) {
                self.fails += 1;
                if self.fails >= BENCH_AFTER {
                    let secs = (self.fails - 4).min(6) * 2;
                    self.benched_until = Some(now + Duration::from_secs(secs.into()));
                }
            }
        }
        fn live(&self, now: Instant) -> bool {
            self.inflight > 0 ||
                self.benched_until.is_some_and(|t| t > now) ||
                self.banned_until.is_some_and(|t| t > now)
        }
    }

    fn peers_in(mask: u8) -> Vec<PeerId> {
        (0..8u8).filter(|i| mask & (1 << i) != 0).map(|i| p(i + 1)).collect()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Arbitrary start, end, ban and candidate sequences over a moving clock keep every
        /// documented rule of the book.
        #[test]
        fn the_book_keeps_its_rules_under_any_sequence(
            ops in proptest::collection::vec(op(), 1..200),
        ) {
            let mut b = PeerBook::default();
            let mut m: HashMap<PeerId, Model> = HashMap::new();
            // Send numbers on the wire, per peer. The book forgets a peer's sends with the peer,
            // so this is kept apart from the model, which forgets too.
            let mut wire: HashMap<PeerId, Vec<u64>> = HashMap::new();
            let mut now = Instant::now();
            for op in ops {
                match op {
                    Op::Start(n) => {
                        b.start(p(n + 1));
                        m.entry(p(n + 1)).or_default().inflight += 1;
                    }
                    Op::Success(n, ms) => {
                        let d = Duration::from_millis(ms.into());
                        b.success(p(n + 1), d);
                        let s = m.entry(p(n + 1)).or_default();
                        s.inflight = s.inflight.saturating_sub(1);
                        s.fails = 0;
                        s.benched_until = None;
                        s.credit = (s.credit + BUSY_PER_GOOD).min(BUSY_CREDIT);
                        s.sample(d);
                    }
                    Op::Failure(n, times) => {
                        for _ in 0..times {
                            let due = b.failure(p(n + 1), now);
                            let s = m.entry(p(n + 1)).or_default();
                            s.inflight = s.inflight.saturating_sub(1);
                            s.fail(now);
                            proptest::prop_assert_eq!(due, s.fails >= DROP_AFTER);
                        }
                    }
                    Op::Empty(n, times, ms, at) => {
                        let d = Duration::from_millis(ms.into());
                        for _ in 0..times {
                            let on = wire.entry(p(n + 1)).or_default();
                            let seq = (!on.is_empty()).then(|| on.swap_remove(at % on.len()));
                            if let Some(seq) = seq {
                                b.landed(p(n + 1), seq);
                            }
                            let busy = seq.is_some_and(|q| on.iter().any(|w| *w < q));
                            let due = b.empty(p(n + 1), seq, d, now);
                            let s = m.entry(p(n + 1)).or_default();
                            s.inflight = s.inflight.saturating_sub(1);
                            if d > s.ewma.unwrap_or(UNSAMPLED_LATENCY) {
                                s.sample(d);
                            }
                            if busy || s.credit > 0 {
                                if !busy {
                                    s.credit -= 1;
                                }
                                proptest::prop_assert!(!due);
                                continue;
                            }
                            s.fail(now);
                            proptest::prop_assert_eq!(due, s.fails >= DROP_AFTER);
                        }
                    }
                    Op::Send(n) => {
                        let seq = b.sent(p(n + 1));
                        let on = wire.entry(p(n + 1)).or_default();
                        proptest::prop_assert!(on.iter().all(|w| *w < seq), "send numbers rise");
                        on.push(seq);
                        m.entry(p(n + 1)).or_default();
                    }
                    Op::Land(n, at) => {
                        let on = wire.entry(p(n + 1)).or_default();
                        if !on.is_empty() {
                            b.landed(p(n + 1), on.swap_remove(at % on.len()));
                        }
                    }
                    Op::TimedOut(n, ms) => {
                        let d = Duration::from_millis(ms.into());
                        let due = b.timed_out(p(n + 1), d, now);
                        let s = m.entry(p(n + 1)).or_default();
                        s.inflight = s.inflight.saturating_sub(1);
                        if d > s.ewma.unwrap_or(UNSAMPLED_LATENCY) {
                            s.sample(d);
                        }
                        s.fail(now);
                        proptest::prop_assert_eq!(due, s.fails >= DROP_AFTER);
                    }
                    Op::Abandon(n, ms) => {
                        let d = Duration::from_millis(ms.into());
                        b.abandon(p(n + 1), d);
                        if let Some(s) = m.get_mut(&p(n + 1)) {
                            s.inflight = s.inflight.saturating_sub(1);
                            if d > s.ewma.unwrap_or(UNSAMPLED_LATENCY) {
                                s.sample(d);
                            }
                        }
                    }
                    Op::Ban(n) => {
                        b.ban(p(n + 1), now);
                        let s = m.entry(p(n + 1)).or_default();
                        s.inflight = s.inflight.saturating_sub(1);
                        s.banned_until = Some(now + BAN_FOR);
                    }
                    Op::Advance(ms) => now += Duration::from_millis(ms.into()),
                    Op::Candidates { connected, statics } => {
                        let connected = peers_in(connected);
                        let statics = peers_in(statics);
                        let got = b.candidates_preferring(&connected, now, |x| statics.contains(x));
                        m.retain(|peer, s| connected.contains(peer) || s.live(now));
                        wire.retain(|peer, _| m.contains_key(peer));
                        let usable: Vec<PeerId> = connected
                            .iter()
                            .copied()
                            .filter(|x| {
                                m.get(x).is_none_or(|s| {
                                    !s.benched_until.is_some_and(|t| t > now) &&
                                        !s.banned_until.is_some_and(|t| t > now)
                                })
                            })
                            .collect();
                        proptest::prop_assert_eq!(got.len(), usable.len().min(MAX_CANDIDATES));
                        let mut seen = got.clone();
                        seen.sort_unstable();
                        seen.dedup();
                        proptest::prop_assert_eq!(seen.len(), got.len(), "duplicates: {:?}", got);
                        let key = |x: &PeerId| {
                            let s = m.get(x).copied().unwrap_or_default();
                            (!statics.contains(x), s.inflight, s.ewma.unwrap_or(UNSAMPLED_LATENCY))
                        };
                        for x in &got {
                            proptest::prop_assert!(usable.contains(x), "{x} is not usable");
                        }
                        for w in got.windows(2) {
                            proptest::prop_assert!(key(&w[0]) <= key(&w[1]), "order {:?}", got);
                        }
                        // Nothing left out sorts ahead of the last one picked.
                        if let Some(last) = got.last() {
                            for x in usable.iter().filter(|x| !got.contains(x)) {
                                proptest::prop_assert!(key(last) <= key(x));
                            }
                        }
                        // The book forgets what the rules let it forget.
                        proptest::prop_assert!(b.peers.keys().all(|x| m.contains_key(x)));
                    }
                }
                for n in 1..=8 {
                    let x = p(n);
                    let s = m.get(&x).copied().unwrap_or_default();
                    proptest::prop_assert_eq!(b.inflight(&x), s.inflight);
                    proptest::prop_assert_eq!(b.latency(&x), s.ewma);
                    proptest::prop_assert_eq!(
                        b.is_banned(&x, now),
                        s.banned_until.is_some_and(|t| t > now)
                    );
                    proptest::prop_assert_eq!(
                        b.is_benched(&x, now),
                        s.benched_until.is_some_and(|t| t > now)
                    );
                    proptest::prop_assert!(!b.is_benched(&x, now + Duration::from_secs(12)));
                    proptest::prop_assert!(!b.is_banned(&x, now + BAN_FOR));
                }
            }
        }
    }

    #[test]
    fn each_good_answer_excuses_a_few_empty_ones_up_to_the_credit() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        let quick = Duration::from_millis(1);
        // Before any good answer, an empty one is a failure.
        for _ in 0..BENCH_AFTER {
            b.start(p(1));
            b.empty(p(1), None, quick, now);
        }
        assert!(b.is_benched(&p(1), now));
        // One good answer excuses BUSY_PER_GOOD empty ones, not more.
        b.start(p(1));
        b.success(p(1), Duration::from_millis(5));
        for _ in 0..BUSY_PER_GOOD {
            b.start(p(1));
            assert!(!b.empty(p(1), None, quick, now));
        }
        assert_eq!(b.inflight(&p(1)), 0);
        assert!(!b.is_benched(&p(1), now));
        for _ in 0..BENCH_AFTER {
            b.start(p(1));
            b.empty(p(1), None, quick, now);
        }
        assert!(b.is_benched(&p(1), now));
        // Good answers add up to the cap.
        for _ in 0..2 * BUSY_CREDIT {
            b.start(p(1));
            b.success(p(1), Duration::from_millis(5));
        }
        for _ in 0..BUSY_CREDIT {
            b.start(p(1));
            assert!(!b.empty(p(1), None, quick, now));
        }
        assert!(!b.is_benched(&p(1), now));
        b.start(p(1));
        b.empty(p(1), None, quick, now);
        assert!(!b.is_benched(&p(1), now), "one failure");
    }

    #[test]
    fn an_empty_answer_while_an_older_request_is_on_the_wire_is_busy() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        let quick = Duration::from_millis(1);
        // No good answer yet and no credit: only the wire excuses an empty answer.
        let oldest = b.sent(p(1));
        for _ in 0..10 * BUSY_CREDIT {
            b.start(p(1));
            let seq = b.sent(p(1));
            b.landed(p(1), seq);
            assert!(!b.empty(p(1), Some(seq), quick, now));
        }
        assert!(!b.is_benched(&p(1), now));
        // The oldest request has nothing older to wait on: its empty answer is judged.
        b.landed(p(1), oldest);
        for _ in 0..BENCH_AFTER {
            b.start(p(1));
            let seq = b.sent(p(1));
            b.landed(p(1), seq);
            b.empty(p(1), Some(seq), quick, now);
        }
        assert!(b.is_benched(&p(1), now));
        // A newer request on the wire excuses nothing, nor does another peer's.
        let mut b = PeerBook::default();
        let first = b.sent(p(1));
        b.sent(p(1));
        b.sent(p(2));
        for _ in 0..BENCH_AFTER {
            b.start(p(1));
            b.empty(p(1), Some(first), quick, now);
        }
        assert!(b.is_benched(&p(1), now));
        assert_eq!(b.inflight(&p(1)), 0);
    }

    #[test]
    fn a_slow_empty_answer_raises_the_latency_estimate() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        b.success(p(1), Duration::from_millis(80));
        b.start(p(1));
        b.empty(p(1), None, Duration::from_millis(10), now);
        assert_eq!(b.latency(&p(1)), Some(Duration::from_millis(80)));
        b.start(p(1));
        b.empty(p(1), None, Duration::from_millis(480), now);
        assert_eq!(b.latency(&p(1)), Some(Duration::from_millis(130)));
    }

    #[test]
    fn sends_to_one_peer_are_paced_after_a_burst() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        let interval = Duration::from_secs(1) / PEER_RATE;
        for _ in 0..PEER_BURST {
            assert!(!b.is_paced(&p(1), now));
            assert_eq!(b.pace(p(1), now), now);
        }
        assert!(b.is_paced(&p(1), now));
        assert_eq!(b.pace(p(1), now), now + interval);
        assert_eq!(b.pace(p(1), now), now + interval * 2);
        // Each peer has a pace of its own.
        assert!(!b.is_paced(&p(2), now));
        assert_eq!(b.pace(p(2), now), now);
        assert!(!b.is_paced(&p(1), now + interval * 3));
        // An idle peer has its burst back.
        let later = now + Duration::from_secs(10);
        for _ in 0..PEER_BURST {
            assert_eq!(b.pace(p(1), later), later);
        }
        assert_eq!(b.pace(p(1), later), later + interval);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Whatever the demand, the sends to one peer never empty a token bucket of 200 a second
        /// and a burst of 400, five times tighter than a `snap/1` server's default.
        #[test]
        fn paced_sends_fit_a_bucket_tighter_than_the_servers_default(
            demand in proptest::collection::vec(
                (proptest::prop_oneof![9 => 0..50u16, 1 => 0..5000u16], 0..64u16),
                1..200,
            ),
        ) {
            let (rate, burst) = (200.0, 400.0);
            let mut b = PeerBook::default();
            let mut now = Instant::now();
            let (mut tokens, mut last) = (burst, now);
            for (wait, sends) in demand {
                now += Duration::from_millis(wait.into());
                for _ in 0..sends {
                    let at = b.pace(p(1), now);
                    proptest::prop_assert!(at >= last);
                    tokens = (at - last).as_secs_f64().mul_add(rate, tokens).min(burst);
                    last = at;
                    proptest::prop_assert!(tokens >= 1.0, "the server would answer empty");
                    tokens -= 1.0;
                }
            }
        }
    }

    #[test]
    fn a_send_given_up_before_its_time_gives_its_turn_back() {
        let mut b = PeerBook::default();
        let now = Instant::now();
        for _ in 0..PEER_BURST {
            b.pace(p(1), now);
        }
        // Callers that book a turn and give up while they wait leave the pace where it was.
        for _ in 0..1000 {
            let at = b.pace(p(1), now);
            assert_eq!(at, now + PACE_INTERVAL);
            b.unpace(p(1), at, now);
        }
        // A turn whose time has come is spent: the request may be on the wire.
        let at = b.pace(p(1), now);
        b.unpace(p(1), at, at);
        assert_eq!(b.pace(p(1), now), now + PACE_INTERVAL * 2);
        // A peer the book does not know has nothing to give back.
        b.unpace(p(2), now + PACE_INTERVAL, now);
        assert_eq!(b.pace(p(2), now), now);
    }

    /// One step of the pace property below.
    #[derive(Debug, Clone)]
    enum PaceOp {
        Book(u16),
        Advance(u16),
        /// Gives up the waiting booking at this index, modulo the count.
        GiveUp(usize),
    }

    fn pace_op() -> impl proptest::strategy::Strategy<Value = PaceOp> {
        use proptest::prelude::*;
        prop_oneof![
            4 => (0..64u16).prop_map(PaceOp::Book),
            2 => (0..40u16).prop_map(PaceOp::Advance),
            3 => any::<usize>().prop_map(PaceOp::GiveUp),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Sends booked and given up in any order keep to the pace: the sends that went out fit
        /// both the pace's own bucket and the server's default one, and a new booking never
        /// waits longer than one interval for each booking still waiting, plus one.
        #[test]
        fn given_up_turns_keep_the_sends_to_the_pace(
            ops in proptest::collection::vec(pace_op(), 1..300),
        ) {
            let mut b = PeerBook::default();
            let start = Instant::now();
            let mut now = start;
            let (mut waiting, mut sent): (Vec<Instant>, Vec<Instant>) = (Vec::new(), Vec::new());
            for op in ops {
                match op {
                    PaceOp::Book(n) => {
                        for _ in 0..n {
                            let at = b.pace(p(1), now);
                            let ahead = u32::try_from(waiting.len()).unwrap() + 1;
                            proptest::prop_assert!(
                                at - now <= PACE_INTERVAL * ahead,
                                "{:?} with {} waiting",
                                at - now,
                                waiting.len()
                            );
                            if at <= now { sent.push(at) } else { waiting.push(at) }
                        }
                    }
                    PaceOp::Advance(ms) => {
                        now += Duration::from_millis(ms.into());
                        let (gone, left): (Vec<Instant>, Vec<Instant>) =
                            waiting.into_iter().partition(|at| *at <= now);
                        waiting = left;
                        sent.extend(gone);
                    }
                    PaceOp::GiveUp(i) => {
                        if !waiting.is_empty() {
                            let at = waiting.swap_remove(i % waiting.len());
                            b.unpace(p(1), at, now);
                        }
                    }
                }
            }
            sent.extend(waiting);
            sent.sort_unstable();
            let own_rate = 1.0 / PACE_INTERVAL.as_secs_f64();
            for (rate, burst) in [(own_rate, f64::from(PEER_BURST)), (200.0, 400.0)] {
                let (mut tokens, mut last) = (burst, start);
                for at in &sent {
                    tokens = (*at - last).as_secs_f64().mul_add(rate, tokens).min(burst);
                    last = *at;
                    // A little slack for the interval's rounding to whole nanoseconds.
                    proptest::prop_assert!(tokens >= 1.0 - 1e-6, "{rate}/s, burst {burst}: empty");
                    tokens -= 1.0;
                }
            }
        }
    }

    #[test]
    fn hedge_delay_is_a_quarter_capped_at_500ms() {
        assert_eq!(PeerBook::hedge_delay(Duration::from_secs(4)), Duration::from_millis(500));
        assert_eq!(PeerBook::hedge_delay(Duration::from_millis(800)), Duration::from_millis(200));
    }
}
