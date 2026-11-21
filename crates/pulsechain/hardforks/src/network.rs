//! One table entry per `PulseChain` network.
//!
//! Code that needs a per-network value looks it up here by chain ID, through
//! [`pulsechain_network`]. A new `PulseChain` network is one new entry in
//! [`PULSECHAIN_NETWORKS`], plus its chain spec static and hardfork list.
//!
//! Lookups go by chain ID, not by the hardfork list in a chain spec. A chain
//! spec read from a genesis file has no `PrimordialPulse` entry, but the node
//! still treats chain 369 or 943 as `PulseChain`.

use crate::{
    chainspec::{PULSECHAIN_MAINNET_CHAIN_ID, PULSECHAIN_TESTNET_V4_CHAIN_ID},
    hardfork::{
        PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_MAINNET_TIMESTAMP,
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP,
    },
};

/// The per-network values of one `PulseChain` network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PulsechainNetwork {
    /// The chain ID after `PrimordialPulse`.
    pub chain_id: u64,
    /// The `PrimordialPulse` block. Blocks below it are Ethereum blocks.
    pub primordial_pulse_block: u64,
    /// The timestamp of the `PrimordialPulse` block.
    pub primordial_pulse_timestamp: u64,
    /// The block gas limit the payload builder targets when `--builder.gaslimit` is unset.
    ///
    /// This is the live network's gas limit. reth's own default for a chain it does not
    /// name is 36M, which would vote the limit away from it.
    pub default_gas_limit: u64,
}

/// Every `PulseChain` network this node knows.
pub const PULSECHAIN_NETWORKS: [PulsechainNetwork; 2] = [
    PulsechainNetwork {
        chain_id: PULSECHAIN_MAINNET_CHAIN_ID,
        primordial_pulse_block: PRIMORDIAL_PULSE_MAINNET_BLOCK,
        primordial_pulse_timestamp: PRIMORDIAL_PULSE_MAINNET_TIMESTAMP,
        default_gas_limit: 45_000_000,
    },
    PulsechainNetwork {
        chain_id: PULSECHAIN_TESTNET_V4_CHAIN_ID,
        primordial_pulse_block: PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        primordial_pulse_timestamp: PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP,
        default_gas_limit: 30_000_000,
    },
];

/// Returns the `PulseChain` network with `chain_id`, or `None` for any other chain.
pub fn pulsechain_network(chain_id: u64) -> Option<&'static PulsechainNetwork> {
    PULSECHAIN_NETWORKS.iter().find(|network| network.chain_id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4},
        hardfork::PulsechainHardfork,
    };
    use reth_chainspec::{ForkCondition, Hardforks};

    /// Each entry agrees with its chain spec static and hardfork list.
    #[test]
    fn entries_match_the_chain_specs() {
        for spec in [&*PULSECHAIN, &*PULSECHAIN_TESTNET_V4] {
            let network = pulsechain_network(spec.chain.id()).expect("a table entry");
            assert_eq!(
                spec.fork(PulsechainHardfork::PrimordialPulse),
                ForkCondition::Block(network.primordial_pulse_block),
                "chain {}",
                network.chain_id,
            );
        }
    }

    /// The upstream crates that cannot see this table ask
    /// `reth_chainspec::is_pulsechain_chain_id` instead. The two must agree.
    #[test]
    fn entries_match_the_upstream_chain_id_check() {
        for network in PULSECHAIN_NETWORKS {
            assert!(reth_chainspec::is_pulsechain_chain_id(network.chain_id));
        }
        for id in [1, 1337, 11_155_111, 32_382] {
            assert!(!reth_chainspec::is_pulsechain_chain_id(id));
            assert!(pulsechain_network(id).is_none());
        }
    }
}
