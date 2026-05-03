//! Launch-time helpers that wrap a stock reth `NodeBuilder` with PulseChain
//! defaults. Kept thin and side-effect-free so the entrypoint binary can call
//! them without dragging more upstream surface into the diff.

use reth_network_peers::TrustedPeer;
use reth_pulsechain_forks::chainspec::{
    pulsechain_nodes, pulsechain_testnet_v4_nodes, PULSECHAIN_TESTNET_V4_CHAIN_ID,
};

/// Returns the PulseChain bootnode set for the given chain id.
///
/// Selects the testnet-v4 list for `PULSECHAIN_TESTNET_V4_CHAIN_ID` and
/// falls back to the mainnet list otherwise.
pub fn pulsechain_bootnodes_for(chain_id: u64) -> Vec<TrustedPeer> {
    let nodes = if chain_id == PULSECHAIN_TESTNET_V4_CHAIN_ID {
        pulsechain_testnet_v4_nodes()
    } else {
        pulsechain_nodes()
    };
    nodes.into_iter().map(Into::into).collect()
}

/// Populate `bootnodes` with the PulseChain default set when the user has not
/// already supplied a `--bootnodes` override.
///
/// Replace, not extend — leaving the upstream Ethereum-mainnet bootnodes
/// (delegated by the inner `ChainSpec`) in the set wastes outbound slots on
/// guaranteed-failure handshakes.
pub fn inject_pulsechain_bootnodes_if_unset(
    bootnodes: &mut Option<Vec<TrustedPeer>>,
    chain_id: u64,
) {
    if bootnodes.is_some() {
        return;
    }
    *bootnodes = Some(pulsechain_bootnodes_for(chain_id));
}
