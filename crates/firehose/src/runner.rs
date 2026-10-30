use crate::{inspector, mapper, prelude::*};
use alloy_consensus::transaction::TxHashRef as _;
use alloy_primitives::Bytes;
use eyre::Context;
use futures::StreamExt;
use reth_chainspec::EthChainSpec;
use reth_ethereum_forks::EthereumHardforks;
use reth_evm::execute::BlockExecutor;
use reth_exex::{ExExContext, ExExEvent};
use reth_provider::{
    BlockIdReader, BlockNumReader, BlockReader, EvmStateProviderBox, StateProviderFactory,
};


pub async fn run_exex<Node>(mut ctx: ExExContext<Node>) -> eyre::Result<()>
where
    Node: FullNodeComponents,
    Node::Provider: BlockReader + BlockNumReader + StateProviderFactory,
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    SignedTx<Node>: mapper::SignatureFields,
{
    let chain_id = ctx.config.chain.chain().id();
    let replica = crate::health::resolve_replica();
    let datadir = ctx.config.datadir().data_dir().to_path_buf();
    let mut health = crate::health::HealthPublisher::start(&datadir, chain_id, replica)?;

    // `init_blockchain` (from the node builder's `on_component_initialized` hook) emits
    // FIRE INIT and the genesis block before the consensus engine starts. This ExEx only
    // publishes the thatis health.json heartbeat.

    while let Some(notification) = ctx.notifications.next().await {
        let notification = notification?;

        if let Some(committed) = notification.committed_chain() {
            debug!(chain = ?committed.range(), "Chain committed, tracing {} blocks", committed.len());

            for (block, _receipts) in committed.blocks_and_receipts() {
                let num_hash = block.num_hash();
                let block_time = block.header().timestamp();
                if let Err(err) = health.record_finished_height(num_hash.number, block_time) {
                    warn!(
                        target: "firehose::health",
                        error = %err,
                        height = num_hash.number,
                        "Failed to write firehose health.json"
                    );
                }

                ctx.events.send(ExExEvent::FinishedHeight(num_hash))?;
            }
        }
    }

    if let Err(err) = health.mark_dead() {
        warn!(target: "firehose::health", error = %err, "Failed to write dead health.json on shutdown");
    }

    Ok(())
}
