use crate::{inspector, mapper, prelude::*};
use alloy_consensus::transaction::TxHashRef as _;
use alloy_primitives::Bytes;
use eyre::Context;
use futures::StreamExt;
use reth_chainspec::EthChainSpec;
use reth_ethereum_forks::EthereumHardforks;
use reth_evm::execute::BlockExecutor;
use reth_exex::{ExExContext, ExExEvent};
use reth_primitives_traits::SealedBlock;
use reth_provider::{
    BlockIdReader, BlockNumReader, BlockReader, StateProviderBox, StateProviderFactory,
};
use reth_revm::{
    database::StateProviderDatabase,
    revm::{context::Block as _, Database as _},
    State,
};

pub fn trace_block<Node: FullNodeComponents, F>(
    ctx: &ExExContext<Node>,
    evm_config: &Node::Evm,
    block: &RecoveredBlock<Node>,
    receipts: &Vec<Receipt<Node>>,
    get_signature: &F,
    shared_state: &mut State<StateProviderDatabase<StateProviderBox>>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    F: Fn(&SignedTx<Node>) -> (B256, B256, Bytes),
{
    use alloy_consensus::TxReceipt;

    let tracer = &mut *crate::tracer();

    tracer.on_block_start(firehose_tracer::types::BlockEvent {
        block: mapper::to_block_data(block.sealed_block()),
        finalized: mapper::to_finalized_ref(ctx.provider().finalized_block_num_hash()),
        flash_block: None,
    });

    let evm_env = evm_config
        .evm_env(block.header())
        .wrap_err_with(|| format!("Failed to build EVM env for block {}", block.number()))?;
    let exec_ctx = evm_config
        .context_for_block(block.sealed_block())
        .wrap_err_with(|| format!("Failed to build EVM context for block {}", block.number()))?;

    let inspector = inspector::FirehoseInspector::new(tracer);
    let evm = evm_config.evm_with_env_and_inspector(&mut *shared_state, evm_env, inspector);
    let mut executor = evm_config.create_executor(evm, exec_ctx);

    executor.evm_mut().inspector_mut().tracer_mut().on_system_call_start();
    executor.apply_pre_execution_changes().wrap_err_with(|| {
        format!("Failed to apply pre-execution changes for block {}", block.number())
    })?;
    executor.evm_mut().inspector_mut().tracer_mut().on_system_call_end();

    let mut prev_cumulative_gas: u64 = 0;
    let mut log_index: u32 = 0;

    for (tx_index, (recovered_tx, receipt)) in
        block.transactions_recovered().zip(receipts.iter()).enumerate()
    {
        let tx: &SignedTx<Node> = &**recovered_tx;
        let (r, s, v) = get_signature(tx);
        let tx_event = mapper::signed_tx_to_tx_event(tx, recovered_tx.signer(), tx_index, r, s, v);

        executor.evm_mut().inspector_mut().tracer_mut().on_tx_start(tx_event, None);

        let caller_nonce = executor
            .evm_mut()
            .db_mut()
            .basic(recovered_tx.signer())?
            .ok_or_else(|| {
                eyre::eyre!(
                    "Failed to get caller account info for block {} tx_index={tx_index} tx_hash={}",
                    block.number(),
                    recovered_tx.tx_hash()
                )
            })?
            .nonce;
        debug!(target: "firehose", block = block.number(), tx_index, tx_hash = ?recovered_tx.tx_hash(), caller_nonce, "Executing transaction");

        let tx_result =
            executor.execute_transaction_without_commit(recovered_tx).wrap_err_with(|| {
                format!(
                    "Failed to execute transaction block={} tx_index={tx_index} tx_hash={}",
                    block.number(),
                    recovered_tx.tx_hash()
                )
            })?;

        {
            let result_gas_used = {
                use alloy_evm::block::TxResult as _;
                tx_result.result().result.tx_gas_used()
            };
            let sender = recovered_tx.signer();
            let coinbase = block.header().beneficiary();
            let gas_limit = tx.gas_limit();
            let base_fee = block.header().base_fee_per_gas().unwrap_or(0);
            let effective_gas_price: u128 = if tx.is_dynamic_fee() {
                std::cmp::min(
                    tx.max_fee_per_gas(),
                    base_fee as u128 + tx.max_priority_fee_per_gas().unwrap_or(0),
                )
            } else {
                tx.gas_price().unwrap_or(0)
            };

            let committed_log_count = {
                use alloy_evm::block::TxResult as _;
                tx_result.result().result.logs().len() as u32
            };
            let (db, inspector, _) = executor.evm_mut().components_mut();
            inspector.process_post_tx_balance_changes(
                sender,
                coinbase,
                gas_limit,
                result_gas_used,
                effective_gas_price,
                base_fee,
                committed_log_count,
                |addr| db.basic(addr).ok().flatten().map(|info| info.balance).unwrap_or(U256::ZERO),
            );
        }

        executor.commit_transaction(tx_result);

        let cumulative_gas = receipt.cumulative_gas_used();
        let gas_used = cumulative_gas - prev_cumulative_gas;
        let log_count = receipt.logs().len() as u32;
        let blob_gas_used = tx.blob_gas_used().unwrap_or(0);
        let blob_gas_price = executor.evm().block().blob_gasprice().map(U256::from);
        let receipt_data = mapper::to_receipt_data(
            receipt,
            tx_index as u32,
            gas_used,
            log_index,
            blob_gas_used,
            blob_gas_price,
        );
        prev_cumulative_gas = cumulative_gas;
        log_index += log_count;

        executor.evm_mut().inspector_mut().tracer_mut().on_tx_end(Some(&receipt_data), None);
    }

    executor.evm_mut().inspector_mut().tracer_mut().on_system_call_start();

    executor.apply_post_execution_changes().wrap_err_with(|| {
        format!("Failed to apply post-execution changes for block {}", block.number())
    })?;

    tracer.on_system_call_end();

    tracer.on_block_end(None);

    Ok(())
}

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

    crate::tracer().on_blockchain_init(
        "reth",
        env!("CARGO_PKG_VERSION"),
        firehose_tracer::config::ChainConfig::new(chain_id),
    );

    let head = ctx
        .provider()
        .last_block_number()
        .wrap_err("failed to read last_block_number — provider not initialized?")?;
    if head == 0 {
        let genesis_block = ctx
            .provider()
            .block_by_number(0)
            .wrap_err("failed to read genesis block from provider")?
            .ok_or_else(|| {
                eyre::eyre!(
                    "reth has no block 0 in DB at run_exex start — chain spec init didn't run?"
                )
            })?;
        let genesis = SealedBlock::seal_slow(genesis_block);
        info!(
            number = 0,
            hash = %genesis.hash(),
            "Emitting FIRE BLOCK 0 with chain-spec genesis allocations (fresh chain detected)"
        );
        crate::tracer().on_genesis_block(
            firehose_tracer::types::BlockEvent {
                block: mapper::to_block_data(&genesis),
                finalized: None,
                flash_block: None,
            },
            mapper::to_genesis_alloc(ctx.config.chain.genesis()),
        );
    }

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
