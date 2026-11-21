//! `PulseChain` payload builder.
//!
//! [`PulsechainPayloadBuilder`] builds the stock Ethereum payload builder. It
//! differs from `EthereumPayloadBuilder` only in the default gas limit: on a
//! `PulseChain` network with no `--builder.gaslimit`, it targets the network's
//! live gas limit from [`PULSECHAIN_NETWORKS`] instead of reth's 36M.
//!
//! [`PULSECHAIN_NETWORKS`]: reth_pulsechain_forks::network::PULSECHAIN_NETWORKS

use reth_chainspec::{Chain, EthChainSpec, EthereumHardforks};
use reth_ethereum_engine_primitives::{EthBuiltPayload, EthPayloadAttributes};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::PayloadBuilderBuilder, BuilderContext, PayloadBuilderConfig, PayloadTypes,
};
use reth_pulsechain_forks::network::pulsechain_network;
use reth_transaction_pool::{PoolTransaction, TransactionPool};

/// Returns the gas limit the payload builder targets on `chain`.
///
/// An explicit `--builder.gaslimit` always wins. Without it, a `PulseChain`
/// network gets its table default, and any other chain gets reth's default.
pub fn builder_gas_limit(conf: &impl PayloadBuilderConfig, chain: Chain) -> u64 {
    if let Some(limit) = conf.gas_limit() {
        return limit;
    }
    match pulsechain_network(chain.id()) {
        Some(network) => network.default_gas_limit,
        None => conf.gas_limit_for(chain),
    }
}

/// The payload builder for `PulsechainNode`. See the module docs.
#[derive(Clone, Default, Debug)]
#[non_exhaustive]
pub struct PulsechainPayloadBuilder;

impl<Types, Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for PulsechainPayloadBuilder
where
    Types: NodeTypes<ChainSpec: EthereumHardforks, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<
            Primitives = PrimitivesTy<Types>,
            NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes,
        > + 'static,
    Types::Payload:
        PayloadTypes<BuiltPayload = EthBuiltPayload, PayloadAttributes = EthPayloadAttributes>,
{
    type PayloadBuilder =
        reth_ethereum_payload_builder::EthereumPayloadBuilder<Pool, Node::Provider, Evm>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        let gas_limit = builder_gas_limit(&conf, ctx.chain_spec().chain());
        let skip_state_root = ctx.config().tree_config().skip_state_root();

        Ok(reth_ethereum_payload_builder::EthereumPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new()
                .with_gas_limit(gas_limit)
                .with_max_blobs_per_block(conf.max_blobs_per_block())
                .with_extra_data(conf.extra_data())
                .with_skip_state_root(skip_state_root),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_node_core::args::PayloadBuilderArgs;

    fn args(gas_limit: Option<u64>) -> PayloadBuilderArgs {
        PayloadBuilderArgs { gas_limit, ..Default::default() }
    }

    #[test]
    fn pulsechain_networks_default_to_their_live_gas_limit() {
        assert_eq!(builder_gas_limit(&args(None), Chain::from_id(369)), 45_000_000);
        assert_eq!(builder_gas_limit(&args(None), Chain::from_id(943)), 30_000_000);
    }

    #[test]
    fn explicit_builder_gas_limit_wins() {
        for id in [369, 943, 1, 12_345] {
            assert_eq!(builder_gas_limit(&args(Some(50_000_000)), Chain::from_id(id)), 50_000_000);
        }
    }

    #[test]
    fn other_chains_keep_reth_defaults() {
        for id in [1, 12_345] {
            let chain = Chain::from_id(id);
            assert_eq!(builder_gas_limit(&args(None), chain), args(None).gas_limit_for(chain));
        }
    }
}
