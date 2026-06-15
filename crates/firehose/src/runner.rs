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

/// Executes EVM transactions in a block one by one, firing tracer hooks at the appropriate times.
///
/// This is a re-implementation for usage within ExEx and compatible with Firehose Geth Live
/// Tracing.
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

    // Block 1 used to short-circuit here and emit `on_genesis_block` with block 1's
    // data + chain-spec alloc, which was wrong on two counts: (a) the genesis-block
    // event represents block 0 not block 1, and (b) firing it during block-execution
    // means it never fires for nodes where reth's pipeline has already advanced past
    // block 1. The proper genesis emit now happens in `run_exex` at chain-init time
    // (see below) when `last_block_number() == 0`. Block 1 flows through the normal
    // `on_block_start` → execute → `on_block_end` path like any other block.

    tracer.on_block_start(firehose_tracer::types::BlockEvent {
        block: mapper::to_block_data(block.sealed_block()),
        finalized: mapper::to_finalized_ref(ctx.provider().finalized_block_num_hash()),
        flash_block: None,
    });

    let evm_env = evm_config
        .evm_env(block.header())
        .wrap_err_with(|| format!("Failed to build EVM env for block {}", block.number()))?;
    // context_for_block type-checks because FullNodeComponents bounds Node::Evm:
    // ConfigureEvm<Primitives = <Node::Types as NodeTypes>::Primitives>
    let exec_ctx = evm_config
        .context_for_block(block.sealed_block())
        .wrap_err_with(|| format!("Failed to build EVM context for block {}", block.number()))?;

    // Inspector borrows tracer mutably for the duration of the block execution.
    // All tracer lifecycle calls (on_tx_start, on_tx_end, etc.) go through
    // executor.evm_mut().inspector_mut().tracer_mut() while the inspector is live.
    let inspector = inspector::FirehoseInspector::new(tracer);
    // The EVM borrows `shared_state` mutably for the duration of this block. Bundle updates
    // from prior blocks in the same ChainCommitted notification are already reflected in its
    // cache via earlier `commit_transaction` calls, so nonce / balance reads here see the
    // correct pre-block state without re-querying the historical provider.
    let evm = evm_config.evm_with_env_and_inspector(&mut *shared_state, evm_env, inspector);
    let mut executor = evm_config.create_executor(evm, exec_ctx);

    // AFAIK this is actually unused for tracing, commented out to try, will delete if conclusive
    // // Set state hook to log EvmState changes after each transaction and system call
    // executor.set_state_hook(Some(Box::new(
    //     |source: reth_evm::block::StateChangeSource, state: &reth::revm::revm::state::EvmState| {
    //         inspector::log_evm_state(&format!("state_hook({source:?})"), state);
    //     },
    // )));

    // System calls (EIP-4788, EIP-2935, etc.) — handled by apply_pre_execution_changes
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

        // Fresh state reader per transaction for on_tx_start StateReader.
        //
        // KNOWN LIMITATION: this reader is resolved from the provider at `parent_hash`, not
        // from the live `shared_state`. The firehose StateReader observations it produces are
        // pre-block, not pre-tx. EVM-level nonce validation is unaffected (that uses the
        // shared_state cache, not this reader).
        //let state_reader_provider = ctx
        //    .provider()
        //    .state_by_block_hash(parent_hash)
        //    .wrap_err_with(|| {
        //        format!(
        //            "Failed to get state reader for block {} tx_index={tx_index} tx_hash={}",
        //            block.number(),
        //            recovered_tx.tx_hash()
        //        )
        //    })?;
        //let state_reader = Box::new(mapper::StateReaderAdapter(state_reader_provider));

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
        info!(target: "firehose", block = block.number(), tx_index, tx_hash = ?recovered_tx.tx_hash(), caller_nonce, "Executing transaction");

        // execute_transaction_without_commit runs the full EVM execution (including po
        // gas refund and miner fee) and returns the final EvmState without committing to DB.
        // Inspector hooks (on_call_enter, on_call_exit, on_opcode, etc.) fire during transact().
        let tx_result =
            executor.execute_transaction_without_commit(recovered_tx).wrap_err_with(|| {
                format!(
                    "Failed to execute transaction block={} tx_index={tx_index} tx_hash={}",
                    block.number(),
                    recovered_tx.tx_hash()
                )
            })?;

        // Emit post-execution balance changes (gas refund to sender, miner fee to coinbase).
        // revm's post_execution runs reimburse_caller and reward_beneficiary after the last
        // inspector hook, so we explicitly compute and emit them using Ethereum gas rules.
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

            // Committed log count from the ExecutionResult (empty on Revert/Halt).
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
        // EIP-4844 receipt fields. `blob_gas_used()` returns `None` for non-blob tx types;
        // `blob_gasprice()` returns `None` for pre-Cancun blocks. Matches Geth's receipt shape.
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

    // Post-execution changes (block rewards, withdrawals, etc.)
    // This consumes the executor, dropping the inspector and releasing the tracer borrow.
    // State mutations (pre-execution changes, tx commits, post-execution changes) remain in
    // `shared_state`, ready for the next block in this chain notification.
    executor.apply_post_execution_changes().wrap_err_with(|| {
        format!("Failed to apply post-execution changes for block {}", block.number())
    })?;

    // Tracer borrow released — can call directly again
    tracer.on_system_call_end();

    tracer.on_block_end(None);

    Ok(())
}

/// ExEx entry point for Firehose live-block tracing.
///
/// Loops over `ChainCommitted` notifications, re-executes each block with `trace_block`, and
/// signals `FinishedHeight` after each block so the WAL can be pruned.
pub async fn run_exex<Node>(mut ctx: ExExContext<Node>) -> eyre::Result<()>
where
    Node: FullNodeComponents,
    Node::Provider: BlockReader + BlockNumReader + StateProviderFactory,
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    SignedTx<Node>: mapper::SignatureFields,
{
    let chain_id = ctx.config.chain.chain().id();
    crate::tracer().on_blockchain_init(
        "reth",
        env!("CARGO_PKG_VERSION"),
        firehose_tracer::config::ChainConfig::new(chain_id),
    );

    // Emit FIRE BLOCK 0 ONCE when reth boots on a fresh chain (canonical head == 0,
    // i.e. only the chain-spec-installed genesis block is in the DB, nothing synced
    // past it). This synthesizes the genesis block event with the chain's pre-allocated
    // state (balances, code, nonces, storage) carried inside as `REASON_GENESIS_BALANCE`
    // / OnCodeChange / OnNonceChange / OnStorageChange events — mirroring geth's
    // `OnGenesisBlock` hook fired from `core/blockchain.go:500-514`.
    //
    // Without this, no `0000000000-*.dbin.zst` one-block file is ever produced, and the
    // downstream fireeth merger sits in a "too many unlinkable blocks at base 401" loop
    // forever because block 1's parent_hash (the genesis hash) has no anchor in the stream.
    //
    // On restarts where reth's head is already past 0 (i.e. the firehose pipeline already
    // received the genesis event in an earlier run), this is a no-op. Reading the head via
    // `last_block_number` rather than checking for the absence of a one-block file in the
    // downstream MinIO bucket keeps the ExEx ignorant of downstream storage state.
    let head = ctx
        .provider()
        .last_block_number()
        .wrap_err("failed to read last_block_number — provider not initialized?")?;
    if head == 0 {
        // Pull the genesis block from the provider (reth initializes it from the chain spec
        // at first boot) and seal it into a SealedBlock. `SealedBlock::seal_slow` computes the
        // hash from the header — fine here since this fires once per chain lifetime.
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
            info!(chain = ?committed.range(), "Chain committed, tracing {} blocks", committed.len());
            //let first_block = committed.first();
            //let parent_hash = first_block.parent_hash();

            //let state_provider =
            //    ctx.provider().state_by_block_hash(parent_hash).wrap_err_with(|| {
            //        format!("Failed to get state provider for parent block {}", parent_hash)
            //    })?;

            //let mut _shared_state = State::builder()
            //    .with_database(StateProviderDatabase::new(state_provider))
            //    .with_bundle_update()
            //    .build();

            //let _evm_config = ctx.evm_config().clone();

            for (block, _receipts) in committed.blocks_and_receipts() {
                // trace_block(
                //     &ctx,
                //     &evm_config,
                //     block,
                //     receipts,
                //     &|tx: &SignedTx<Node>| tx.signature_fields(),
                //     &mut shared_state,
                // )?;

                ctx.events.send(ExExEvent::FinishedHeight(block.num_hash()))?;
            }
        }
    }

    Ok(())
}
