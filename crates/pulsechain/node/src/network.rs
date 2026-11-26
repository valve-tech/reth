//! `PulseChain` network builder.
//!
//! Wraps the stock Ethereum network setup and injects `PulseChain` peer discovery
//! (static bootnodes + `enrtree://` DNS) so the node finds `PulseChain` peers
//! instead of falling back to upstream Ethereum mainnet bootnodes (which are
//! present on the cloned `ChainSpec` and serve chain ID 1, not 369/943).

use reth_chainspec::{EthChainSpec, Hardforks};
use reth_network::{
    primitives::BasicNetworkPrimitives, protocol::RlpxSubProtocols, NetworkHandle, NetworkManager,
    PeersInfo,
};
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
use reth_pulsechain_snap::{ProviderBackend, Snap1Backend, Snap1Config, Snap1Handler, Snap1Server};
use reth_tracing::tracing::info;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use std::sync::Arc;

/// Network builder that injects `PulseChain` peer discovery (static bootnodes +
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
pub struct PulsechainNetworkBuilder {
    /// Whether to serve `snap/1` (`--pulsechain.snap1`). Off by default.
    snap1: bool,
}

impl PulsechainNetworkBuilder {
    /// Serves `snap/1` to light clients when `enabled`.
    pub const fn with_snap1(mut self, enabled: bool) -> Self {
        self.snap1 = enabled;
        self
    }

    /// Returns whether `snap/1` serving is on.
    pub const fn snap1(&self) -> bool {
        self.snap1
    }
}

/// Builds the `snap/1` sub-protocol handler served from `backend`.
///
/// Shared with network builders that wrap their own network setup (such as the msgboard one in
/// `pulse-reth`) so every build path serves `snap/1` identically.
pub fn snap1_handler<B: Snap1Backend>(backend: Arc<B>) -> Snap1Handler<B> {
    let server = Arc::new(Snap1Server::new(backend, Snap1Config::default()));
    Snap1Handler::new(server)
}

/// Adds the `snap/1` sub-protocol, served from `backend`, to `protocols`.
fn add_snap1_protocol<B: Snap1Backend>(protocols: &mut RlpxSubProtocols, backend: Arc<B>) {
    protocols.push(snap1_handler(backend));
}

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

        if let Some(url) = pulsechain_dns_for_chain(chain_id) &&
            let Some(ref mut dns) = config.dns_discovery_config
        {
            let networks = dns.bootstrap_dns_networks.get_or_insert_with(Default::default);
            networks.insert(url.parse().expect("valid enrtree DNS link entry"));
        }

        if self.snap1 {
            add_snap1_protocol(
                &mut config.extra_protocols,
                Arc::new(ProviderBackend::new(ctx.provider().clone())),
            );
            info!(target: "reth::cli", "Serving snap/1 (--pulsechain.snap1)");
        }

        let builder = NetworkManager::builder(config).await?;
        let handle = ctx.start_network(builder, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}

/// Returns the `PulseChain` static bootnode list for `chain_id`, or `None` for
/// non-PulseChain chains.
fn pulsechain_bootnodes_for_chain(chain_id: u64) -> Option<Vec<NodeRecord>> {
    match chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => Some(pulsechain_nodes()),
        PULSECHAIN_TESTNET_V4_CHAIN_ID => Some(pulsechain_testnet_v4_nodes()),
        _ => None,
    }
}

/// Returns the `PulseChain` `enrtree://` DNS discovery URL for `chain_id`, or
/// `None` for non-PulseChain chains.
const fn pulsechain_dns_for_chain(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => Some(PULSECHAIN_DNS_NETWORK),
        PULSECHAIN_TESTNET_V4_CHAIN_ID => Some(PULSECHAIN_TESTNET_V4_DNS_NETWORK),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NoSnapBackend(reth_provider::test_utils::MockEthProvider);

    impl reth_pulsechain_snap::RootLanes for NoSnapBackend {
        fn lane(&self, _root: alloy_primitives::B256) -> Option<reth_pulsechain_snap::Lane> {
            None
        }
    }

    impl reth_pulsechain_snap::StateRangeProviderFactory for NoSnapBackend {
        fn state_range_provider(
            &self,
            root: alloy_primitives::B256,
        ) -> reth_provider::ProviderResult<Option<reth_pulsechain_snap::StateRangeView>> {
            reth_pulsechain_snap::StateRangeProviderFactory::state_range_provider(&self.0, root)
        }
    }

    impl Snap1Backend for NoSnapBackend {
        fn byte_codes(
            &self,
            req: &reth_pulsechain_snap::GetByteCodesMessage,
        ) -> reth_provider::ProviderResult<reth_pulsechain_snap::ByteCodesMessage> {
            reth_pulsechain_snap::serve_byte_codes(&self.0, req)
        }
    }

    #[test]
    fn snap1_is_off_by_default_and_the_flag_turns_it_on() {
        assert!(!PulsechainNetworkBuilder::default().snap1());
        assert!(PulsechainNetworkBuilder::default().with_snap1(true).snap1());
        assert!(!PulsechainNetworkBuilder::default().with_snap1(true).with_snap1(false).snap1());
    }

    #[test]
    fn adding_snap1_registers_exactly_one_sub_protocol() {
        let mut protocols = RlpxSubProtocols::default();
        assert_eq!(format!("{protocols:?}").matches("Snap1Handler").count(), 0);
        add_snap1_protocol(&mut protocols, Arc::new(NoSnapBackend(Default::default())));
        assert_eq!(format!("{protocols:?}").matches("Snap1Handler").count(), 1);
    }

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
