//! Network builder that registers the msgboard sub-protocol before the network
//! starts accepting peers.

use reth_chainspec::Hardforks;
use reth_msgboard::MsgboardLauncher;
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle, PeersInfo};
use reth_node_api::{NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{components::NetworkBuilder, BuilderContext, FullNodeTypes};
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use tracing::info;

/// Builds the network the way `EthereumNetworkBuilder` does, and registers the
/// `msg/1` sub-protocol on the manager before it is spawned.
///
/// The registration cannot wait for `extend_rpc_modules`, which is where it used
/// to live. That hook runs once the network is already dialling, and a session
/// fixes its capability set from the `Hello` it exchanged — `SessionManager`
/// reads the protocol list per connection and nothing renegotiates afterwards.
/// Every peer connected during that window is stuck without `msg/1` for the life
/// of the session.
///
/// Trusted peers lose every time, because the node dials them the instant the
/// network starts and then holds those links open. That is the whole bug: on
/// 2026-09-05 two testnet-v4 nodes listing each other as trusted peers held
/// **zero** msgboard sessions until both processes happened to restart, while a
/// mainnet pair fed by discovery churn looked healthy throughout.
#[derive(Debug, Clone)]
pub struct MsgboardNetworkBuilder {
    launcher: MsgboardLauncher,
}

impl MsgboardNetworkBuilder {
    /// Wrap a launcher whose board this network will serve.
    pub const fn new(launcher: MsgboardLauncher) -> Self {
        Self { launcher }
    }
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for MsgboardNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
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
        let datadir = ctx.config().datadir().data_dir().to_path_buf();
        let board = self.launcher.init_board(datadir);

        // `handle()` hands out a usable handle before the manager is spawned,
        // which is what lets the reputation reporter exist this early.
        let mut builder = ctx.network_builder().await?;
        let protocol = self.launcher.rlpx_sub_protocol(board, builder.handle());
        builder.network_mut().add_rlpx_sub_protocol(protocol);

        let handle = ctx.start_network(builder, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}
