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

use std::{collections::HashSet, fmt};

use alloy_eips::eip7892::BlobScheduleBlobParams;
use futures_util::StreamExt;
use reth_chainspec::{ChainSpec, ForkCondition, ForkId, Hardfork, Hardforks};
use reth_network::{events::PeerEvent, NetworkEvent, NetworkEventListenerProvider};
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

/// Warns once for each fork that peers announce and this binary's schedule lacks.
///
/// It never disconnects or rejects a peer. Does nothing on a chain ID with no
/// `PulseChain` network.
pub async fn watch_peer_fork_ids<N>(network: N, spec: std::sync::Arc<ChainSpec>)
where
    N: NetworkEventListenerProvider,
{
    if pulsechain_network(spec.chain.id()).is_none() {
        return;
    }
    let mut events = network.event_listener();
    let mut warned = HashSet::new();
    while let Some(event) = events.next().await {
        let info = match &event {
            NetworkEvent::ActivePeerSession { info, .. } |
            NetworkEvent::Peer(PeerEvent::SessionEstablished(info)) => info,
            NetworkEvent::Peer(_) => continue,
        };
        if let Some(next) = unconfigured_peer_fork(&spec, info.status.forkid) &&
            warned.insert(next)
        {
            warn!(
                target: "reth::cli",
                chain_id = spec.chain.id(),
                peer_id = %info.peer_id,
                client = %info.client_version,
                next,
                "A peer announces a fork at {next} that this binary does not configure. \
                 Upgrade before it activates."
            );
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
}
