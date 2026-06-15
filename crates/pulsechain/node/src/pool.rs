//! PulseChain transaction pool builder.
//!
//! Post-fork, all new transactions use the native PulseChain chain ID (369 mainnet,
//! 943 testnet v4). The `chain_id = 1` CHAINID opcode override only applies to
//! *historical block execution* (pre-PrimordialPulse), not the mempool.
//!
//! The standard `EthTransactionValidator` is correct here — it validates against
//! the configured chain ID, which is 369 or 943.

use std::time::SystemTime;

use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_primitives::TransactionSigned;
use reth_evm::ConfigureEvm;
use reth_node_api::{NodePrimitives, PrimitivesTy};
use reth_node_builder::{
    components::{PoolBuilder, TxPoolBuilder},
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, EthTransactionPool, TransactionValidationTaskExecutor,
};

// ---------------------------------------------------------------------------
// PulsechainPoolBuilder
// ---------------------------------------------------------------------------

/// Builder for the PulseChain transaction pool.
///
/// Uses the stock Ethereum transaction validator, which validates against the
/// native PulseChain chain ID (369 mainnet / 943 testnet v4). This is correct
/// because all post-fork mempool transactions must use the native chain ID.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PulsechainPoolBuilder;

impl<Types, Node, Evm> PoolBuilder<Node, Evm> for PulsechainPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: EthChainSpec + EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = TransactionSigned>,
    >,
    Node: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>> + Clone + 'static,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore, Evm>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let pool_config = ctx.pool_config();

        let blobs_disabled = ctx.config().txpool.disable_blobs_support ||
            ctx.config().txpool.blobpool_max_count == 0;

        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            Some(blob_cache_size)
        } else {
            // Derive the blob cache size from the target blob count, auto-scaling by
            // multiplying with the slot count for 2 epochs (384 for pectra).
            let current_timestamp =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or_else(BlobParams::cancun);

            Some((blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32)
        };

        let blob_store =
            reth_node_builder::components::create_blob_store_with_cache(ctx, blob_cache_size)?;

        let validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .set_eip4844(!blobs_disabled)
                .kzg_settings(ctx.kzg_settings()?)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
                .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
                .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        if validator.validator().eip4844() {
            // Initialising KZG settings is expensive; do it in the background so it
            // doesn't delay the first block or the first gossiped blob transaction.
            let kzg_settings = validator.validator().kzg_settings().clone();
            ctx.task_executor().spawn_blocking_task(async move {
                let _ = kzg_settings.get();
                debug!(target: "reth::cli", "Initialized KZG settings");
            });
        }

        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}
