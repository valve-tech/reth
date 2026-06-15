//! `PulseChain` node type.
//!
//! [`PulsechainNode`] implements the same `NodeTypes` as `EthereumNode`, swapping in
//! PulseChain-specific component builders for consensus, EVM execution, transaction
//! pool, and networking. The chain ID and hardfork schedule come from the `ChainSpec`
//! statics in `reth-pulsechain-forks`.

use reth_ethereum_primitives::EthPrimitives;
use reth_node_builder::{
    components::{BasicPayloadServiceBuilder, ComponentsBuilder},
    node::{FullNodeTypes, Node, NodeTypes},
    NodeAdapter,
};
use reth_node_ethereum::{
    EthEngineTypes, EthereumAddOns, EthereumEngineValidatorBuilder, EthereumEthApiBuilder,
    EthereumPayloadBuilder,
};

use crate::{
    consensus::PulsechainConsensusBuilder, evm::PulsechainExecutorBuilder,
    network::PulsechainNetworkBuilder, pool::PulsechainPoolBuilder, spec::PulsechainChainSpec,
};
use reth_provider::EthStorage;

/// Type configuration for a `PulseChain` node.
///
/// Shares execution primitives with `EthereumNode` but swaps in PulseChain-specific
/// builders for consensus (Shanghai gap fix), EVM execution (CHAINID override +
/// PrimordialPulse), networking (DNS discovery), and transaction pool.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PulsechainNode;

impl PulsechainNode {
    /// Returns a [`ComponentsBuilder`] configured for a `PulseChain` node.
    ///
    /// Delegates to `EthereumNode::components()` — all Ethereum builders satisfy
    /// the trait bounds for `PulsechainNode` because the associated types are identical.
    pub fn components<N>() -> ComponentsBuilder<
        N,
        PulsechainPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        PulsechainNetworkBuilder,
        PulsechainExecutorBuilder,
        PulsechainConsensusBuilder,
    >
    where
        N: FullNodeTypes<Types = Self>,
    {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(PulsechainPoolBuilder::default())
            .executor(PulsechainExecutorBuilder)
            .payload(BasicPayloadServiceBuilder::default())
            .network(PulsechainNetworkBuilder::default())
            .consensus(PulsechainConsensusBuilder::default())
    }
}

impl NodeTypes for PulsechainNode {
    type Primitives = EthPrimitives;
    type ChainSpec = PulsechainChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}

impl<N> Node<N> for PulsechainNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        PulsechainPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        PulsechainNetworkBuilder,
        PulsechainExecutorBuilder,
        PulsechainConsensusBuilder,
    >;

    type AddOns =
        EthereumAddOns<NodeAdapter<N>, EthereumEthApiBuilder, EthereumEngineValidatorBuilder>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::default()
    }
}
