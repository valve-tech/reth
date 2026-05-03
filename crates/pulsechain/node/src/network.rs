//! PulseChain network builder.
//!
//! Wraps the stock Ethereum network setup and injects PulseChain peer discovery
//! (static bootnodes + `enrtree://` DNS) so the node finds PulseChain peers
//! instead of falling back to upstream Ethereum mainnet bootnodes (which are
//! present on the cloned `ChainSpec` and serve chain ID 1, not 369/943).

use reth_chainspec::{EthChainSpec, Hardforks};
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle, NetworkManager, PeersInfo};
use reth_network_peers::{NodeRecord, TrustedPeer};
use reth_node_api::PrimitivesTy;
use reth_node_builder::{
    components::NetworkBuilder,
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_pulsechain_forks::chainspec::{
    pulsechain_nodes, pulsechain_testnet_v4_nodes, PULSECHAIN_DNS_NETWORK,
    PULSECHAIN_MAINNET_CHAIN_ID, PULSECHAIN_TESTNET_V4_CHAIN_ID, PULSECHAIN_TESTNET_V4_DNS_NETWORK,
};
use reth_tracing::tracing::info;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};

/// Network builder that injects PulseChain peer discovery (static bootnodes +
/// DNS) before starting the P2P stack.
///
/// The upstream `NetworkConfigBuilder` resolves bootnodes and DNS networks from
/// the `ChainSpec`. `PulsechainChainSpec` clones upstream `MAINNET`, so without
/// this builder the node would bootstrap from Ethereum mainnet bootnodes and
/// have no DNS discovery — discv4 then surfaces random eth-ecosystem peers
/// (different chain IDs, sometimes eth/69), all of which fail handshake and
/// get dropped, leaving the node effectively peer-starved.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PulsechainNetworkBuilder;

impl<Node, Pool> NetworkBuilder<Node, Pool> for PulsechainNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks + EthChainSpec>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = reth_node_api::TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let mut config = ctx.network_config()?;
        let chain_id = ctx.chain_spec().chain().id();

        if let Some(nodes) = pulsechain_bootnodes_for_chain(chain_id) {
            // Replace, not extend — upstream `MAINNET`'s Ethereum bootnodes serve
            // chain ID 1 and waste outbound slots on guaranteed-handshake-failures.
            config.boot_nodes = nodes.into_iter().map(TrustedPeer::from).collect();
        }

        if let Some(url) = pulsechain_dns_for_chain(chain_id) {
            if let Some(ref mut dns) = config.dns_discovery_config {
                let networks = dns.bootstrap_dns_networks.get_or_insert_with(Default::default);
                networks.insert(url.parse().expect("valid enrtree DNS link entry"));
            }
        }

        let builder = NetworkManager::builder(config).await?;
        let handle = ctx.start_network(builder, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}

/// Returns the PulseChain static bootnode list for `chain_id`, or `None` for
/// non-PulseChain chains.
fn pulsechain_bootnodes_for_chain(chain_id: u64) -> Option<Vec<NodeRecord>> {
    match chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => Some(pulsechain_nodes()),
        PULSECHAIN_TESTNET_V4_CHAIN_ID => Some(pulsechain_testnet_v4_nodes()),
        _ => None,
    }
}

/// Returns the PulseChain `enrtree://` DNS discovery URL for `chain_id`, or
/// `None` for non-PulseChain chains.
fn pulsechain_dns_for_chain(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => Some(PULSECHAIN_DNS_NETWORK),
        PULSECHAIN_TESTNET_V4_CHAIN_ID => Some(PULSECHAIN_TESTNET_V4_DNS_NETWORK),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_bootnodes_resolve_to_full_pulsechain_set() {
        let nodes =
            pulsechain_bootnodes_for_chain(PULSECHAIN_MAINNET_CHAIN_ID).expect("mainnet bootnodes");
        assert_eq!(nodes.len(), 10, "PulseChain mainnet bootnode list size");
    }

    #[test]
    fn testnet_v4_bootnodes_resolve_to_full_pulsechain_set() {
        let nodes = pulsechain_bootnodes_for_chain(PULSECHAIN_TESTNET_V4_CHAIN_ID)
            .expect("testnet v4 bootnodes");
        assert_eq!(nodes.len(), 8, "PulseChain testnet v4 bootnode list size");
    }

    #[test]
    fn non_pulsechain_chain_has_no_bootnode_override() {
        // Ethereum mainnet (1), Sepolia (11155111), and Polygon (137) must fall
        // through so upstream resolution decides their bootnodes.
        assert!(pulsechain_bootnodes_for_chain(1).is_none());
        assert!(pulsechain_bootnodes_for_chain(11_155_111).is_none());
        assert!(pulsechain_bootnodes_for_chain(137).is_none());
    }

    #[test]
    fn mainnet_dns_resolves_to_pulsechain_enrtree() {
        assert_eq!(
            pulsechain_dns_for_chain(PULSECHAIN_MAINNET_CHAIN_ID),
            Some(PULSECHAIN_DNS_NETWORK)
        );
    }

    #[test]
    fn testnet_v4_dns_resolves_to_testnet_enrtree() {
        assert_eq!(
            pulsechain_dns_for_chain(PULSECHAIN_TESTNET_V4_CHAIN_ID),
            Some(PULSECHAIN_TESTNET_V4_DNS_NETWORK)
        );
    }

    #[test]
    fn non_pulsechain_chain_has_no_dns_override() {
        assert!(pulsechain_dns_for_chain(1).is_none());
        assert!(pulsechain_dns_for_chain(137).is_none());
    }
}
