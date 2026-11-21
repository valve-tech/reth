//! Refuse to run a `PulseChain` network on a fork schedule this binary does not implement.
//!
//! [`check_fork_schedule`] runs in [`PulsechainChainSpecParser::parse`], so every CLI
//! command stops before it opens the database. It applies only to a chain ID with a
//! [`PULSECHAIN_NETWORKS`] entry. Every other chain passes unchanged.
//!
//! A fork that the network schedules after this binary ships is not in any chain
//! spec, so the parser cannot see it. [`watch_peer_fork_ids`] only warns about
//! one: `PulseChain` peers compute fork IDs from another schedule, so a peer's
//! fork ID is not reliable enough to reject on.
//!
//! [`PulsechainChainSpecParser::parse`]: crate::cli::PulsechainChainSpecParser
//! [`PULSECHAIN_NETWORKS`]: reth_pulsechain_forks::network::PULSECHAIN_NETWORKS

use std::{collections::HashMap, fmt};

use alloy_eips::eip7892::BlobScheduleBlobParams;
use futures_util::StreamExt;
use reth_chainspec::{ChainSpec, ForkCondition, ForkId, Hardforks};
use reth_network::{events::PeerEvent, NetworkEvent, NetworkEventListenerProvider};
use reth_network_peers::PeerId;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::BlockReaderIdExt;
use reth_pulsechain_forks::{
    hardfork::PulsechainHardfork,
    network::{pulsechain_network, PulsechainNetwork},
};
use reth_tracing::tracing::warn;

/// Why [`check_fork_schedule`] refused a chain spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkScheduleError {
    /// The chain ID is a `PulseChain` network, but the spec has no `PrimordialPulse` fork.
    MissingPrimordialPulse {
        /// The chain ID.
        chain_id: u64,
    },
    /// The spec has a fork that `PulseChain` does not configure.
    UnconfiguredFork {
        /// The chain ID.
        chain_id: u64,
        /// The fork name.
        fork: &'static str,
        /// The activation the spec gives it.
        activation: ForkCondition,
    },
    /// The spec activates a known fork at another point than the network does.
    MovedFork {
        /// The chain ID.
        chain_id: u64,
        /// The fork name.
        fork: &'static str,
        /// The activation the network uses.
        expected: ForkCondition,
        /// The activation the spec gives it.
        found: ForkCondition,
    },
    /// The spec sets blob parameters, and `PulseChain` has no blobs.
    BlobSchedule {
        /// The chain ID.
        chain_id: u64,
    },
}

impl fmt::Display for ForkScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrimordialPulse { chain_id } => write!(
                f,
                "chain {chain_id} is a PulseChain network, but its chain spec has no \
                 PrimordialPulse fork"
            ),
            Self::UnconfiguredFork { chain_id, fork, activation } => write!(
                f,
                "chain {chain_id}: the chain spec schedules {fork} at {activation:?}, but \
                 PulseChain does not configure {fork} and this binary does not implement it"
            ),
            Self::MovedFork { chain_id, fork, expected, found } => write!(
                f,
                "chain {chain_id}: the chain spec activates {fork} at {found:?}, but PulseChain \
                 activates it at {expected:?}"
            ),
            Self::BlobSchedule { chain_id } => write!(
                f,
                "chain {chain_id}: the chain spec sets a blob schedule, but PulseChain has no \
                 blob transactions"
            ),
        }
    }
}

impl core::error::Error for ForkScheduleError {}

/// Checks a chain spec against the `PulseChain` network that its chain ID names.
///
/// Returns `Ok` for a chain ID with no `PulseChain` network.
pub fn check_fork_schedule(spec: &ChainSpec) -> Result<(), ForkScheduleError> {
    let Some(network) = pulsechain_network(spec.chain.id()) else { return Ok(()) };
    check_against(spec, network)
}

fn check_against(spec: &ChainSpec, network: &PulsechainNetwork) -> Result<(), ForkScheduleError> {
    let chain_id = network.chain_id;

    if spec.fork(PulsechainHardfork::PrimordialPulse) == ForkCondition::Never {
        return Err(ForkScheduleError::MissingPrimordialPulse { chain_id });
    }

    let configured = (network.hardforks)();
    for (fork, found) in spec.forks_iter() {
        let name = fork.name();
        let expected = configured
            .forks_iter()
            .find_map(|(known, condition)| (known.name() == name).then_some(condition));
        match expected {
            None => {
                return Err(ForkScheduleError::UnconfiguredFork {
                    chain_id,
                    fork: name,
                    activation: found,
                })
            }
            Some(expected) if expected != found => {
                return Err(ForkScheduleError::MovedFork { chain_id, fork: name, expected, found })
            }
            Some(_) => {}
        }
    }

    if spec.blob_params != BlobScheduleBlobParams::default() {
        return Err(ForkScheduleError::BlobSchedule { chain_id });
    }

    Ok(())
}

/// Returns the `next` value of a peer's fork ID if this binary's schedule has no fork there.
///
/// `next` is the block number or timestamp of the peer's next fork, or zero for none.
/// Returns `None` for a chain ID with no `PulseChain` network.
pub fn unconfigured_peer_fork(spec: &ChainSpec, peer: ForkId) -> Option<u64> {
    if peer.next == 0 || pulsechain_network(spec.chain.id()).is_none() {
        return None;
    }
    let known = spec.forks_iter().any(|(_, condition)| match condition {
        ForkCondition::Block(block) => block == peer.next,
        ForkCondition::Timestamp(timestamp) => timestamp == peer.next,
        ForkCondition::TTD { fork_block, .. } => fork_block == Some(peer.next),
        ForkCondition::Never => false,
    });
    (!known).then_some(peer.next)
}

/// Fork IDs encode a fork at or above this value as a timestamp, and below it as a block
/// number. The value is Ethereum's genesis timestamp, as in go-ethereum's `forkid` package.
const TIMESTAMP_THRESHOLD: u64 = 1_438_269_973;

/// How far ahead of the head a timestamp fork may be and still count: two years.
const TIMESTAMP_HORIZON: u64 = 2 * 365 * 24 * 60 * 60;

/// How far ahead of the head a block fork may be and still count: two years of 10-second
/// `PulseChain` slots.
const BLOCK_HORIZON: u64 = TIMESTAMP_HORIZON / 10;

/// The most distinct `next` values [`PeerForkWatch`] tracks.
pub const MAX_TRACKED_FORKS: usize = 16;

/// How many distinct peers must announce a value before [`PeerForkWatch`] warns.
pub const MIN_ANNOUNCING_PEERS: usize = 2;

/// Returns whether a peer's `next` value is a plausible upcoming fork, given our head.
///
/// It must be after the head and within two years of it, by timestamp or block number as the
/// fork ID encodes it.
pub const fn is_plausible_next_fork(next: u64, head_number: u64, head_timestamp: u64) -> bool {
    if next >= TIMESTAMP_THRESHOLD {
        next > head_timestamp && next - head_timestamp <= TIMESTAMP_HORIZON
    } else {
        next > head_number && next - head_number <= BLOCK_HORIZON
    }
}

/// How often [`PeerForkWatch`] may repeat its "suppressed" line, in seconds.
pub const SUPPRESSED_LINE_INTERVAL_SECS: u64 = 60 * 60;

/// What [`PeerForkWatch::observe`] asks the caller to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerForkEvent {
    /// Enough distinct peers announce an unconfigured fork at `next`.
    Warn {
        /// The fork's block number or timestamp.
        next: u64,
    },
    /// Every slot holds a confirmed value, so the watch ignored a new one.
    Suppressed,
}

/// One tracked `next` value.
#[derive(Debug)]
struct Entry {
    /// Peers counted for the value, at most [`MIN_ANNOUNCING_PEERS`]. Empty once confirmed.
    peers: Vec<PeerId>,
    /// Whether [`MIN_ANNOUNCING_PEERS`] distinct peers announced it.
    confirmed: bool,
    /// Insertion order, for eviction.
    seq: u64,
}

/// Bounded state for the peer fork ID warning.
///
/// Peers control their fork IDs, so every limit here assumes a hostile peer:
///
/// - Each peer counts toward one value at a time. A new announcement replaces its old one.
/// - The watch holds at most [`MAX_TRACKED_FORKS`] values. When full, a new value evicts an
///   unconfirmed one, so junk from a few peers cannot crowd out a real fork. It refuses a new value
///   only when every slot is confirmed, and then says so at most once an hour.
/// - It warns about a value only once [`MIN_ANNOUNCING_PEERS`] distinct peers announce it, and only
///   once per value.
#[derive(Debug, Default)]
pub struct PeerForkWatch {
    tracked: HashMap<u64, Entry>,
    /// The value each counted peer announced. Holds only peers in an unconfirmed entry.
    peer_value: HashMap<PeerId, u64>,
    next_seq: u64,
    /// When the "suppressed" line was last returned, in the caller's seconds.
    last_suppressed: Option<u64>,
}

impl PeerForkWatch {
    /// Records that `peer` announced `next`, already checked as unconfigured and plausible.
    ///
    /// `now` is a monotonic time in seconds. Returns the line to log, if any.
    pub fn observe(&mut self, peer: PeerId, next: u64, now: u64) -> Option<PeerForkEvent> {
        if self.peer_value.get(&peer) == Some(&next) {
            return None;
        }
        self.release(peer);

        if !self.tracked.contains_key(&next) && self.tracked.len() >= MAX_TRACKED_FORKS {
            if !self.evict_unconfirmed() {
                let due = self
                    .last_suppressed
                    .is_none_or(|last| now.saturating_sub(last) >= SUPPRESSED_LINE_INTERVAL_SECS);
                if due {
                    self.last_suppressed = Some(now);
                    return Some(PeerForkEvent::Suppressed);
                }
                return None;
            }
        }

        let seq = self.next_seq;
        let entry = self.tracked.entry(next).or_insert_with(|| Entry {
            peers: Vec::new(),
            confirmed: false,
            seq,
        });
        if entry.confirmed {
            return None;
        }
        self.next_seq += 1;
        entry.peers.push(peer);
        if entry.peers.len() < MIN_ANNOUNCING_PEERS {
            self.peer_value.insert(peer, next);
            return None;
        }
        entry.confirmed = true;
        for counted in entry.peers.drain(..) {
            self.peer_value.remove(&counted);
        }
        Some(PeerForkEvent::Warn { next })
    }

    /// Stops counting `peer`, for example when its session closes.
    ///
    /// Drops the peer's unconfirmed value if no other peer holds it.
    pub fn release(&mut self, peer: PeerId) {
        let Some(old) = self.peer_value.remove(&peer) else { return };
        if let Some(entry) = self.tracked.get_mut(&old) {
            entry.peers.retain(|p| *p != peer);
            if !entry.confirmed && entry.peers.is_empty() {
                self.tracked.remove(&old);
            }
        }
    }

    /// Evicts the unconfirmed entry with the fewest peers, oldest first. Returns false if
    /// every entry is confirmed.
    fn evict_unconfirmed(&mut self) -> bool {
        let Some(victim) = self
            .tracked
            .iter()
            .filter(|(_, entry)| !entry.confirmed)
            .min_by_key(|(_, entry)| (entry.peers.len(), entry.seq))
            .map(|(next, _)| *next)
        else {
            return false;
        };
        if let Some(entry) = self.tracked.remove(&victim) {
            for peer in entry.peers {
                self.peer_value.remove(&peer);
            }
        }
        true
    }

    /// Returns how many distinct values the watch holds.
    pub fn tracked(&self) -> usize {
        self.tracked.len()
    }
}

/// Warns about forks that peers announce and this binary's schedule lacks.
///
/// It never disconnects or rejects a peer, and logs only peer IDs, never peer-supplied
/// strings. See [`PeerForkWatch`] for the limits. Does nothing on a chain ID with no
/// `PulseChain` network.
pub async fn watch_peer_fork_ids<N, P>(network: N, provider: P, spec: std::sync::Arc<ChainSpec>)
where
    N: NetworkEventListenerProvider,
    P: BlockReaderIdExt,
{
    if pulsechain_network(spec.chain.id()).is_none() {
        return;
    }
    let started = std::time::Instant::now();
    let mut events = network.event_listener();
    let mut watch = PeerForkWatch::default();
    while let Some(event) = events.next().await {
        let info = match &event {
            NetworkEvent::ActivePeerSession { info, .. } |
            NetworkEvent::Peer(PeerEvent::SessionEstablished(info)) => info,
            NetworkEvent::Peer(PeerEvent::SessionClosed { peer_id, .. }) => {
                watch.release(*peer_id);
                continue;
            }
            NetworkEvent::Peer(_) => continue,
        };
        let Some(next) = unconfigured_peer_fork(&spec, info.status.forkid) else { continue };
        let Ok(Some(head)) = provider.latest_header() else { continue };
        if !is_plausible_next_fork(next, head.number(), head.timestamp()) {
            continue;
        }
        match watch.observe(info.peer_id, next, started.elapsed().as_secs()) {
            Some(PeerForkEvent::Warn { next }) => warn!(
                target: "reth::cli",
                chain_id = spec.chain.id(),
                peer_id = %info.peer_id,
                next,
                "At least {MIN_ANNOUNCING_PEERS} peers announce a fork at {next} that this \
                 binary does not configure. Upgrade before it activates."
            ),
            Some(PeerForkEvent::Suppressed) => warn!(
                target: "reth::cli",
                chain_id = spec.chain.id(),
                "Further fork ID warnings suppressed: all {MAX_TRACKED_FORKS} tracked forks are \
                 already confirmed."
            ),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip7840::BlobParams;
    use reth_chainspec::{Chain, EthereumHardfork, ForkHash, MAINNET};
    use reth_pulsechain_forks::{
        chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4},
        hardfork::SHANGHAI_MAINNET_TIMESTAMP,
    };

    fn pulsechain() -> ChainSpec {
        (**PULSECHAIN).clone()
    }

    #[test]
    fn built_in_specs_pass() {
        check_fork_schedule(&PULSECHAIN).unwrap();
        check_fork_schedule(&PULSECHAIN_TESTNET_V4).unwrap();
    }

    #[test]
    fn rejects_an_unconfigured_fork() {
        let mut spec = pulsechain();
        spec.hardforks.insert(EthereumHardfork::Cancun, ForkCondition::Timestamp(1_800_000_000));
        let err = check_fork_schedule(&spec).unwrap_err();
        assert_eq!(
            err.to_string(),
            "chain 369: the chain spec schedules Cancun at Timestamp(1800000000), but PulseChain \
             does not configure Cancun and this binary does not implement it"
        );
    }

    #[test]
    fn rejects_a_moved_fork() {
        let mut spec = pulsechain();
        spec.hardforks.insert(
            EthereumHardfork::Shanghai,
            ForkCondition::Timestamp(SHANGHAI_MAINNET_TIMESTAMP + 1),
        );
        let err = check_fork_schedule(&spec).unwrap_err();
        assert_eq!(
            err.to_string(),
            "chain 369: the chain spec activates Shanghai at Timestamp(1683786516), but PulseChain \
             activates it at Timestamp(1683786515)"
        );
    }

    #[test]
    fn rejects_a_missing_primordial_pulse() {
        let mut spec = (**PULSECHAIN_TESTNET_V4).clone();
        spec.hardforks.remove(&PulsechainHardfork::PrimordialPulse);
        let err = check_fork_schedule(&spec).unwrap_err();
        assert_eq!(
            err.to_string(),
            "chain 943 is a PulseChain network, but its chain spec has no PrimordialPulse fork"
        );
    }

    #[test]
    fn rejects_a_blob_schedule() {
        let mut spec = pulsechain();
        spec.blob_params = BlobScheduleBlobParams::default()
            .with_scheduled([(1_800_000_000, BlobParams::cancun())]);
        let err = check_fork_schedule(&spec).unwrap_err();
        assert_eq!(
            err.to_string(),
            "chain 369: the chain spec sets a blob schedule, but PulseChain has no blob transactions"
        );
    }

    #[test]
    fn other_chains_are_unaffected() {
        check_fork_schedule(&MAINNET).unwrap();
        // PulseChain's own forks under another chain ID, plus a fork PulseChain lacks.
        let mut spec = pulsechain();
        spec.chain = Chain::from_id(12_345);
        spec.hardforks.insert(EthereumHardfork::Cancun, ForkCondition::Timestamp(1_800_000_000));
        check_fork_schedule(&spec).unwrap();
    }

    #[test]
    fn peer_fork_ids() {
        let id = |next| ForkId { hash: ForkHash([0; 4]), next };
        assert_eq!(unconfigured_peer_fork(&PULSECHAIN, id(0)), None, "no next fork");
        assert_eq!(
            unconfigured_peer_fork(&PULSECHAIN, id(SHANGHAI_MAINNET_TIMESTAMP)),
            None,
            "a fork we configure"
        );
        assert_eq!(unconfigured_peer_fork(&PULSECHAIN, id(1_800_000_000)), Some(1_800_000_000));
        assert_eq!(unconfigured_peer_fork(&MAINNET, id(1_800_000_000)), None, "not PulseChain");
    }

    fn peer(n: u16) -> PeerId {
        let mut id = PeerId::ZERO;
        id[..2].copy_from_slice(&n.to_be_bytes());
        id
    }

    const NEXT: u64 = 1_800_000_000;

    /// One peer alone never triggers a warning, however often it repeats a value.
    #[test]
    fn a_single_peer_causes_no_warning() {
        let mut watch = PeerForkWatch::default();
        for _ in 0..10 {
            assert_eq!(watch.observe(peer(1), NEXT, 0), None);
        }
    }

    /// The second distinct peer triggers one warning, and later peers add nothing.
    #[test]
    fn two_peers_trigger_one_warning() {
        let mut watch = PeerForkWatch::default();
        assert_eq!(watch.observe(peer(1), NEXT, 0), None);
        assert_eq!(watch.observe(peer(2), NEXT, 0), Some(PeerForkEvent::Warn { next: NEXT }));
        assert_eq!(watch.observe(peer(3), NEXT, 0), None);
    }

    /// A peer that cycles through many values holds one slot and logs nothing.
    #[test]
    fn one_peer_cycling_values_holds_one_slot() {
        let mut watch = PeerForkWatch::default();
        for i in 0..1_000 {
            assert_eq!(watch.observe(peer(1), NEXT + i, 0), None);
            assert!(watch.tracked() <= 1);
        }
        assert_eq!(watch.tracked(), 1);
    }

    /// Single-peer junk in every slot does not hide a value that two peers announce.
    #[test]
    fn junk_in_every_slot_does_not_hide_a_real_fork() {
        let mut watch = PeerForkWatch::default();
        for p in 0..MAX_TRACKED_FORKS as u16 {
            assert_eq!(watch.observe(peer(100 + p), NEXT + 1 + u64::from(p), 0), None);
        }
        assert_eq!(watch.tracked(), MAX_TRACKED_FORKS);

        assert_eq!(watch.observe(peer(1), NEXT, 0), None);
        assert_eq!(watch.observe(peer(2), NEXT, 0), Some(PeerForkEvent::Warn { next: NEXT }));
        assert_eq!(watch.tracked(), MAX_TRACKED_FORKS);
    }

    /// Two colluding peers can confirm at most the cap, then get one suppressed line an hour.
    #[test]
    fn colluding_peers_are_capped_and_the_suppressed_line_repeats_hourly() {
        let mut watch = PeerForkWatch::default();
        let mut lines = 0;
        for i in 0..1_000 {
            for p in [1, 2] {
                lines += usize::from(watch.observe(peer(p), NEXT + i, 0).is_some());
            }
        }
        assert_eq!(watch.tracked(), MAX_TRACKED_FORKS);
        assert_eq!(lines, MAX_TRACKED_FORKS + 1, "cap warnings plus one suppressed line");

        let hour = SUPPRESSED_LINE_INTERVAL_SECS;
        assert_eq!(watch.observe(peer(3), NEXT + 5_000, hour - 1), None, "within the hour");
        assert_eq!(watch.observe(peer(4), NEXT + 5_001, hour), Some(PeerForkEvent::Suppressed));
    }

    /// A closed session releases the peer's unconfirmed value.
    #[test]
    fn release_drops_the_peers_value() {
        let mut watch = PeerForkWatch::default();
        watch.observe(peer(1), NEXT, 0);
        assert_eq!(watch.tracked(), 1);
        watch.release(peer(1));
        assert_eq!(watch.tracked(), 0);
    }

    /// Values in the past, or too far ahead, are not plausible forks.
    #[test]
    fn implausible_values_are_ignored() {
        let (number, timestamp) = (27_900_000, 1_761_000_000);
        assert!(is_plausible_next_fork(timestamp + 86_400, number, timestamp));
        assert!(is_plausible_next_fork(number + 1_000, number, timestamp));
        assert!(!is_plausible_next_fork(timestamp, number, timestamp), "at the head");
        assert!(!is_plausible_next_fork(timestamp - 1, number, timestamp), "in the past");
        assert!(!is_plausible_next_fork(timestamp + TIMESTAMP_HORIZON + 1, number, timestamp));
        assert!(!is_plausible_next_fork(u64::MAX, number, timestamp));
        assert!(!is_plausible_next_fork(number - 1, number, timestamp), "a past block");
        assert!(!is_plausible_next_fork(number + BLOCK_HORIZON + 1, number, timestamp));
    }
}
