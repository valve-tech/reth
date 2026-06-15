// ---------------------------------------------------------------------------
// FirehoseExecutorBuilder + PulsechainFirehoseExecutorBuilder
// ---------------------------------------------------------------------------

use alloy_consensus::Header;
use alloy_evm::eth::spec::EthExecutorSpec;
use reth_chainspec::EthChainSpec;
use reth_ethereum_forks::{EthereumHardforks, Hardforks};
use reth_ethereum_primitives::EthPrimitives;
use reth_firehose::{prelude::eyre, FirehoseEvmConfig};
use reth_node_builder::{
    components::ExecutorBuilder,
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_node_ethereum::EthEvmConfig;
use reth_pulsechain_node::evm::PulsechainEvmConfig;

/// Node-builder executor builder that wraps [`EthEvmConfig`] in a [`FirehoseEvmConfig`].
#[derive(Debug, Default, Clone, Copy)]
pub struct FirehoseExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for FirehoseExecutorBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec: EthExecutorSpec
                           + reth_chainspec::EthChainSpec
                           + EthereumHardforks
                           + reth_ethereum_forks::Hardforks,
            Primitives = EthPrimitives,
        >,
    >,
{
    type EVM = FirehoseEvmConfig<EthEvmConfig<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(FirehoseEvmConfig::new(EthEvmConfig::new(ctx.chain_spec())))
    }
}

/// PulseChain analogue of [`FirehoseExecutorBuilder`] — wraps
/// [`PulsechainEvmConfig`] in [`FirehoseEvmConfig`] so the firehose tracer sees
/// PulseChain's executor (CHAINID override, custom Shanghai gap, PrimordialPulse
/// transition) the same way it sees the upstream Ethereum executor.
///
/// The trait bounds mirror [`PulsechainExecutorBuilder`] in
/// `crates/pulsechain/node/src/evm.rs`: any chain spec that satisfies the
/// EthExecutor trait stack with `Header`-typed headers is acceptable, which
/// covers both `PulsechainChainSpec` and the pulsechain testnet variant.
#[derive(Debug, Default, Clone, Copy)]
pub struct PulsechainFirehoseExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for PulsechainFirehoseExecutorBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec: EthExecutorSpec
                           + EthChainSpec<Header = Header>
                           + EthereumHardforks
                           + Hardforks
                           + 'static,
            Primitives = EthPrimitives,
        >,
    >,
{
    type EVM = FirehoseEvmConfig<PulsechainEvmConfig<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(FirehoseEvmConfig::new(PulsechainEvmConfig::new(ctx.chain_spec())))
    }
}
