//! Which peers the lite node keeps.
//!
//! A discovered peer is kept only if it negotiated `eth/68`, advertises `snap/1`, and its status
//! carries this chain's genesis hash and a fork id this chain's fork filter accepts. The eth
//! handshake already refuses a wrong genesis or fork id; checking again here makes the rule
//! explicit and testable, and drops a peer that slipped through a changed handshake. Static
//! `--peer` nodes skip this: the operator named them.
//!
//! None of this is a trust decision. Whatever a kept peer answers is still verified against the
//! beacon-anchored state root before it is used.

use alloy_eips::eip2124::{ForkFilter, ForkId};
use alloy_primitives::B256;
use reth_eth_wire_types::{Capabilities, EthVersion};
use reth_network_api::PeerInfo;

/// What this node requires of a discovered peer.
#[derive(Debug, Clone)]
pub struct Expect {
    /// The chain's genesis hash.
    pub genesis: B256,
    /// Accepts a peer's fork id for this chain.
    pub fork_filter: ForkFilter,
}

/// Why a peer is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    /// The negotiated eth version is not 68.
    #[error("eth version is not 68")]
    EthVersion,
    /// The peer does not advertise `snap/1`.
    #[error("no snap/1")]
    NoSnap,
    /// The peer's genesis hash is not this chain's.
    #[error("genesis mismatch")]
    Genesis,
    /// The peer's fork id is not acceptable for this chain.
    #[error("fork id mismatch")]
    ForkId,
}

/// Whether the capabilities include `snap/1`.
pub fn has_snap1(caps: &Capabilities) -> bool {
    caps.capabilities().iter().any(|c| c.name == "snap" && c.version == 1)
}

/// Applies the keep rule to one peer's handshake facts.
pub fn admit(
    expect: &Expect,
    caps: &Capabilities,
    eth_version: EthVersion,
    genesis: B256,
    fork_id: ForkId,
) -> Result<(), Reject> {
    if eth_version != EthVersion::Eth68 {
        return Err(Reject::EthVersion);
    }
    if !has_snap1(caps) {
        return Err(Reject::NoSnap);
    }
    if genesis != expect.genesis {
        return Err(Reject::Genesis);
    }
    expect.fork_filter.validate(fork_id).map_err(|_| Reject::ForkId)
}

/// [`admit`] over a connected peer's info.
pub fn admit_peer(expect: &Expect, info: &PeerInfo) -> Result<(), Reject> {
    admit(expect, &info.capabilities, info.eth_version, info.status.genesis, info.status.forkid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip2124::Head;
    use reth_chainspec::{EthChainSpec, Hardforks};
    use reth_eth_wire_types::Capability;
    use reth_pulsechain_forks::chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4};

    fn caps(list: &[(&str, usize)]) -> Capabilities {
        Capabilities::new(list.iter().map(|(n, v)| Capability::new((*n).to_owned(), *v)).collect())
    }

    fn mainnet() -> (Expect, ForkId) {
        let head = Head { number: u64::MAX, timestamp: 2_000_000_000, ..Default::default() };
        let spec = PULSECHAIN.clone();
        let expect = Expect { genesis: spec.genesis_hash(), fork_filter: spec.fork_filter(head) };
        (expect, spec.fork_id(&head))
    }

    #[test]
    fn keeps_a_snap_eth68_peer_on_this_chain() {
        let (e, fid) = mainnet();
        let c = caps(&[("eth", 68), ("snap", 1)]);
        assert_eq!(admit(&e, &c, EthVersion::Eth68, e.genesis, fid), Ok(()));
    }

    #[test]
    fn drops_peers_that_miss_any_requirement() {
        let (e, fid) = mainnet();
        let good = caps(&[("eth", 68), ("snap", 1)]);
        assert_eq!(admit(&e, &good, EthVersion::Eth69, e.genesis, fid), Err(Reject::EthVersion));
        let no_snap = caps(&[("eth", 68)]);
        assert_eq!(admit(&e, &no_snap, EthVersion::Eth68, e.genesis, fid), Err(Reject::NoSnap));
        // snap/2 is not snap/1.
        let snap2 = caps(&[("eth", 68), ("snap", 2)]);
        assert_eq!(admit(&e, &snap2, EthVersion::Eth68, e.genesis, fid), Err(Reject::NoSnap));
        assert_eq!(
            admit(&e, &good, EthVersion::Eth68, B256::repeat_byte(9), fid),
            Err(Reject::Genesis)
        );
        let bad_fork = ForkId { hash: alloy_eips::eip2124::ForkHash([1, 2, 3, 4]), next: 0 };
        assert_eq!(admit(&e, &good, EthVersion::Eth68, e.genesis, bad_fork), Err(Reject::ForkId));
    }

    #[test]
    fn the_other_pulsechain_network_is_not_this_chain() {
        let (e, _) = mainnet();
        let test_spec = PULSECHAIN_TESTNET_V4.clone();
        let head = Head { number: u64::MAX, timestamp: 2_000_000_000, ..Default::default() };
        let c = caps(&[("eth", 68), ("snap", 1)]);
        assert!(admit(
            &e,
            &c,
            EthVersion::Eth68,
            test_spec.genesis_hash(),
            test_spec.fork_id(&head)
        )
        .is_err());
    }
}
