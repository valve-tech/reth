// Common imports used across both ethereum and optimism implementations

// Reth core types
pub use reth_evm::evm::Evm;
pub use reth_node_api::{ConfigureEvm, FullNodeComponents};
pub use reth_provider::StateProviderBox;
pub use reth_tracing::tracing::{debug, error, info, trace, warn};

// Alloy types
pub use alloy_consensus::{BlockHeader, Transaction};
pub use alloy_eips;
pub use alloy_primitives::{B256, U256};

// Other common imports
pub use eyre;

/// Type alias for RecoveredBlock that can be used with any Node that implements FullNodeComponents
pub type RecoveredBlock<Node> = reth_primitives_traits::RecoveredBlock<
    <<<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::Primitives as reth_node_api::NodePrimitives>::Block,
>;

/// Type alias for ChainSpec that can be used with any Node that implements FullNodeComponents
pub type ChainSpec<Node> =
    <<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::ChainSpec;

/// Type alias for SignedTx from a Node primitives
pub type SignedTx<Node> =
    <<<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::Primitives as reth_node_api::NodePrimitives>::SignedTx;

/// Type alias for Receipt from a Node primitives
pub type Receipt<Node> =
    <<<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::Primitives as reth_node_api::NodePrimitives>::Receipt;
