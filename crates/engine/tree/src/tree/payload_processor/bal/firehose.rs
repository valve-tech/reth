//! Firehose twin of the BAL executor.
//!
//! [`execute_and_trace_block`] runs a block like [`super::execute::execute_block`], with every
//! executor wrapped in a [`FirehoseWrappedExecutor`]. Each worker traces the transactions it
//! executes into a tracer detached from the block's tracer, and ships each trace with the
//! uncommitted result. The canonical executor, wrapped over the block's own inspector, commits the
//! results in transaction order and attaches the traces to the block as it goes, so the Firehose
//! block is the one serial traced execution produces. The system calls and the withdrawals run on
//! the canonical executor, as in the serial path.
//!
//! MAINTENANCE CONTRACT: keep this module in sync with `execute.rs` and `worker.rs`. Any change to
//! the upstream logic (ordering of pre/post steps, error adjudication, executor resets, etc.) must
//! be mirrored here. The intent of duplicating rather than branching is to keep the diff against
//! upstream minimal and localized.

use super::{
    execute::{log_bal_divergence, AbortGuard},
    ordered_outputs::{ordered_worker_outputs, OrderedWorkerOutputError},
    worker::{BalWorkerError, BalWorkerOutput, WorkerDatabase},
    BalExecutionError,
};
use alloy_consensus::Transaction;
use alloy_eip7928::{bal::DecodedBal, BlockAccessIndex, BlockAccessList};
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::Address;
use crossbeam_channel::{Receiver, Sender};
use evm2::evm::Bal as EvmBal;
use reth_engine_primitives::BlockAccessListDecodeError;
use reth_evm::{
    BlockExecutionOutput, BlockExecutor, BlockExecutorFactory, BlockExecutorFor, ConfigureEvm,
    Database, EvmEnvFor, ExecutableTxFor, ExecutionCtxFor,
};
use reth_firehose::{
    mapper::SignatureFields, BlockFees, FirehoseBlockTracer, FirehoseInspector, FirehoseLiveHooks,
    FirehoseWrappedExecutor, TracedTransaction,
};
use reth_primitives_traits::{ReceiptTy, TxTy};
use reth_tasks::Runtime;
use std::{cell::RefCell, ops::DerefMut, rc::Rc, sync::Arc};

use crate::tree::payload_processor::receipt_root_task::IndexedReceipt;

/// A worker's traced, uncommitted transaction result.
type TracedResult<'a, Evm> =
    TracedTransaction<<BlockExecutorFor<'a, Evm> as BlockExecutor>::TransactionResultWithState>;

/// Firehose twin of [`super::execute::execute_block`]: executes one block on the BAL path using
/// the runtime's persistent BAL worker pool, tracing it into `tracer`.
///
/// `withdrawals` are the block's EIP-4895 withdrawals, emitted as balance changes once the
/// post-execution system calls ran. `tracer` holds the block's tracer: the process-wide one on
/// the engine path, or a caller-owned one in tests.
#[expect(clippy::too_many_arguments, clippy::type_complexity)]
pub fn execute_and_trace_block<'a, Evm, Tx, Err, DB, MakeDb, G>(
    runtime: &Runtime,
    evm_config: &'a Evm,
    make_db: &'a MakeDb,
    input_bal: Arc<DecodedBal>,
    evm_env: EvmEnvFor<Evm>,
    ctx: ExecutionCtxFor<'a, Evm>,
    transaction_count: usize,
    txs: Receiver<(usize, Result<Tx, Err>)>,
    receipt_tx: Sender<IndexedReceipt<ReceiptTy<Evm::Primitives>>>,
    tracer: &FirehoseBlockTracer<G>,
    withdrawals: Option<Withdrawals>,
) -> Result<
    (BlockExecutionOutput<ReceiptTy<Evm::Primitives>>, Vec<Address>, BlockAccessList, Arc<EvmBal>),
    BalExecutionError,
>
where
    Evm: ConfigureEvm + FirehoseLiveHooks + 'static,
    TxTy<Evm::Primitives>: SignatureFields,
    G: DerefMut<Target = firehose_tracer::Tracer> + 'static,
    Tx: ExecutableTxFor<Evm> + Send + 'a,
    Err: core::error::Error + Send + Sync + 'static,
    DB: Database + Send + 'a,
    MakeDb: Fn(bool) -> Result<DB, BalExecutionError> + Sync + 'a,
{
    let worker_pool = runtime.bal_streaming_pool();
    let worker_count = worker_pool.current_num_threads().max(1).min(transaction_count);

    worker_pool.in_place_scope(|scope| {
        execute_and_trace_block_inner(
            scope,
            evm_config,
            make_db,
            input_bal,
            evm_env,
            ctx,
            transaction_count,
            txs,
            receipt_tx,
            worker_count,
            tracer,
            withdrawals,
        )
    })
}

#[expect(clippy::too_many_arguments, clippy::type_complexity)]
fn execute_and_trace_block_inner<'scope, Evm, Tx, Err, DB, MakeDb, G>(
    scope: &rayon::Scope<'scope>,
    evm_config: &'scope Evm,
    make_db: &'scope MakeDb,
    input_bal: Arc<DecodedBal>,
    evm_env: EvmEnvFor<Evm>,
    ctx: ExecutionCtxFor<'scope, Evm>,
    transaction_count: usize,
    txs: Receiver<(usize, Result<Tx, Err>)>,
    receipt_tx: Sender<IndexedReceipt<ReceiptTy<Evm::Primitives>>>,
    worker_count: usize,
    tracer: &FirehoseBlockTracer<G>,
    withdrawals: Option<Withdrawals>,
) -> Result<
    (BlockExecutionOutput<ReceiptTy<Evm::Primitives>>, Vec<Address>, BlockAccessList, Arc<EvmBal>),
    BalExecutionError,
>
where
    Evm: ConfigureEvm + FirehoseLiveHooks + 'scope,
    TxTy<Evm::Primitives>: SignatureFields,
    G: DerefMut<Target = firehose_tracer::Tracer> + 'static,
    Tx: ExecutableTxFor<Evm> + Send + 'scope,
    Err: core::error::Error + Send + Sync + 'static,
    DB: Database + Send + 'scope,
    MakeDb: Fn(bool) -> Result<DB, BalExecutionError> + Sync + 'scope,
{
    // See `execute_block_inner` for why the conversion can fail.
    let received_bal = Arc::new(
        <BlockExecutorFor<'scope, Evm> as BlockExecutor>::convert_block_access_list(
            input_bal.as_bal().as_vec(),
        )
        .map_err(BlockAccessListDecodeError::new)?,
    );
    let fees = BlockFees::new(&evm_env);
    let (result_tx, result_rx) = crossbeam_channel::unbounded();
    let (abort_guard, abort_rx) = AbortGuard::new();

    for _ in 0..worker_count {
        spawn_traced_worker(
            scope,
            txs.clone(),
            abort_rx.clone(),
            result_tx.clone(),
            evm_config,
            make_db,
            Arc::clone(&received_bal),
            evm_env.clone(),
            ctx.clone(),
            fees.clone(),
            tracer.detached_tracer(),
        );
    }
    drop(result_tx);

    let evm = evm_config.evm_with_env(make_db(false)?, evm_env);
    let inner = evm_config.block_executor_factory().create_executor(evm, ctx.clone());
    let mut canonical_executor = FirehoseWrappedExecutor::with_hooks(
        inner,
        tracer.inspector(),
        fees,
        withdrawals,
        <Evm as FirehoseLiveHooks>::PreTxAdjust::default(),
        <Evm as FirehoseLiveHooks>::PostTxExtras::default(),
    );
    canonical_executor.enable_block_access_list_builder();
    canonical_executor.apply_pre_execution_changes()?;

    let mut senders = Vec::with_capacity(transaction_count);
    let mut last_sent_len = 0;
    for output in ordered_worker_outputs(&result_rx, transaction_count) {
        let output = match output {
            Ok(output) => output,
            Err(OrderedWorkerOutputError::Worker(BalWorkerError::Execution {
                tx_index,
                tx_gas_limit,
                source,
            })) => {
                // Block-gas admission is adjudicated in transaction order and takes
                // precedence over the failure at this slot.
                canonical_executor.validate_transaction_gas_limit(tx_gas_limit)?;

                // The transaction is admitted, so its execution failure is the block's
                // verdict: a BAL miss proves the received BAL diverges from this execution.
                return Err(BalWorkerError::Execution { tx_index, tx_gas_limit, source }.into());
            }
            Err(error) => return Err(error.into()),
        };
        canonical_executor.validate_transaction_gas_limit(output.tx_gas_limit)?;
        canonical_executor.commit_traced_transaction(output.result)?;
        senders.push(output.signer);

        let current_len = canonical_executor.receipts().len();
        if current_len > last_sent_len {
            last_sent_len = current_len;
            if let Some(receipt) = canonical_executor.receipts().last() {
                let _ = receipt_tx.send(IndexedReceipt::new(current_len - 1, receipt.clone()));
            }
        }
    }
    drop(abort_guard);

    let (output, built_bal) = canonical_executor.finish_with_block_access_list()?;
    let built_bal = built_bal.expect("BAL builder was enabled for parallel execution");
    log_bal_divergence(&built_bal, input_bal.as_bal());
    Ok((output, senders, built_bal, received_bal))
}

/// Firehose twin of [`super::worker::spawn_worker`]: the worker executes its transactions through
/// a [`FirehoseWrappedExecutor`] over `tracer`, and ships each trace with the uncommitted result.
///
/// The inspector outlives the executor resets that follow a speculative failure: the tracer it
/// holds is clean after a failed transaction, and the next transaction resets the inspector's
/// own state.
#[expect(clippy::too_many_arguments)]
fn spawn_traced_worker<'scope, Evm, Tx, Err, DB, MakeDb>(
    scope: &rayon::Scope<'scope>,
    tx_rx: Receiver<(usize, Result<Tx, Err>)>,
    abort_rx: Receiver<()>,
    result_tx: Sender<Result<BalWorkerOutput<TracedResult<'scope, Evm>>, BalWorkerError>>,
    evm_config: &'scope Evm,
    make_db: &'scope MakeDb,
    received_bal: Arc<<BlockExecutorFor<'scope, Evm> as BlockExecutor>::BlockAccessList>,
    evm_env: EvmEnvFor<Evm>,
    ctx: ExecutionCtxFor<'scope, Evm>,
    fees: BlockFees,
    tracer: firehose_tracer::Tracer,
) where
    Evm: ConfigureEvm + FirehoseLiveHooks + 'scope,
    TxTy<Evm::Primitives>: SignatureFields,
    Tx: ExecutableTxFor<Evm> + Send + 'scope,
    Err: core::error::Error + Send + Sync + 'static,
    DB: Database + Send + 'scope,
    MakeDb: Fn(bool) -> Result<DB, BalExecutionError> + Sync + 'scope,
{
    scope.spawn(move |_| {
        let inspector = FirehoseInspector::new(Box::new(tracer));
        let worker_result = (|| -> Result<(), BalWorkerError> {
            // Keep the cache-filling database across executor resets so a speculative failure
            // cannot introduce an unindexed provider setup error ahead of its ordered verdict.
            let database = Rc::new(RefCell::new(make_db(true).map_err(BalWorkerError::Setup)?));
            'worker: loop {
                let evm =
                    evm_config.evm_with_env(WorkerDatabase(database.clone()), evm_env.clone());
                let inner = evm_config.block_executor_factory().create_executor(evm, ctx.clone());
                let mut executor = FirehoseWrappedExecutor::with_hooks(
                    inner,
                    inspector.clone(),
                    fees.clone(),
                    None,
                    <Evm as FirehoseLiveHooks>::PreTxAdjust::default(),
                    <Evm as FirehoseLiveHooks>::PostTxExtras::default(),
                );
                executor.set_block_access_list(Arc::clone(&received_bal));

                loop {
                    let (tx_index, tx) = crossbeam_channel::select_biased! {
                        recv(abort_rx) -> _ => break 'worker,
                        recv(tx_rx) -> msg => match msg {
                            Ok(ix_tx) => ix_tx,
                            Err(_) => break 'worker,
                        },
                    };
                    let tx = match tx {
                        Ok(tx) => tx,
                        Err(source) => {
                            let error =
                                BalWorkerError::Transaction { tx_index, source: Box::new(source) };
                            if result_tx.send(Err(error)).is_err() {
                                break 'worker;
                            }
                            continue;
                        }
                    };
                    let signer = *tx.signer();
                    let tx_gas_limit = tx.tx().gas_limit();

                    executor
                        .set_block_access_index(BlockAccessIndex::from_tx_index(tx_index as u64));
                    let message = match executor.execute_transaction_detached(tx) {
                        Ok(result) => {
                            Ok(BalWorkerOutput { index: tx_index, signer, tx_gas_limit, result })
                        }
                        Err(source) => {
                            Err(BalWorkerError::Execution { tx_index, tx_gas_limit, source })
                        }
                    };
                    let failed = message.is_err();
                    if result_tx.send(message).is_err() {
                        break 'worker;
                    }
                    if failed {
                        // The executor trait does not guarantee reuse after an error. Rebuild
                        // its EVM and state before serving more work: the queue can still contain
                        // earlier transactions whose verdict must precede this failure.
                        break;
                    }
                }
            }

            Ok(())
        })();

        if let Err(err) = worker_result {
            let _ = result_tx.send(Err(err));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header, TxLegacy};
    use alloy_eip7928::{bal::Bal as AlloyBal, compute_block_access_list_hash};
    use alloy_eips::{
        eip2935::{HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE},
        eip4788::{BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE},
        eip7002::{WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_CODE},
    };
    use alloy_primitives::{Bytes, TxKind, B256, U256};
    use evm2::evm::{CacheDB, EmptyDB};
    use firehose_tracer::pb::sf::ethereum::r#type::v2::Block as FirehoseBlock;
    use firehose_tracer_test::BlockInvariants;
    use reth_chainspec::{ChainSpecBuilder, MAINNET};
    use reth_ethereum_primitives::{
        Block, BlockBody, EthPrimitives, Transaction, TransactionSigned,
    };
    use reth_evm::cached::{AccountInfo, Bytecode};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_firehose::{
        record_block_access_list, run_wrapped_block, NoPostTxExtras, NoPreTxAdjust,
    };
    use reth_firehose_tests::parse_fire_block_for;
    use reth_primitives_traits::{
        crypto::secp256k1::public_key_to_address, Block as _, Recovered, RecoveredBlock,
        SealedBlock,
    };
    use reth_testing_utils::generators::{generate_key, rng, sign_tx_with_key_pair};
    use secp256k1::Keypair;
    use std::convert::Infallible;

    /// Increments storage slot 0 and emits `LOG1` with topic `0xaa`.
    const COUNTER: Address = Address::repeat_byte(0xc1);
    const COUNTER_CODE: &[u8] = &[
        0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x60, 0xaa, 0x60, 0x00, 0x60, 0x00,
        0xa1, 0x00,
    ];
    /// Reverts with no data.
    const REVERTER: Address = Address::repeat_byte(0xc2);
    const REVERTER_CODE: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];
    /// Calls [`COUNTER`], then emits `LOG0`.
    const CALLER: Address = Address::repeat_byte(0xc3);
    const COINBASE: Address = Address::repeat_byte(0xbe);

    fn caller_code() -> Bytes {
        let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        code.extend_from_slice(COUNTER.as_slice());
        code.extend_from_slice(&[0x5a, 0xf1, 0x50, 0x60, 0x00, 0x60, 0x00, 0xa0, 0x00]);
        code.into()
    }

    fn evm_config() -> EthEvmConfig {
        EthEvmConfig::new(Arc::new(ChainSpecBuilder::mainnet().amsterdam_activated().build()))
    }

    fn contract(code: Bytes) -> AccountInfo {
        AccountInfo::default().with_nonce(1).with_code(Bytecode::new_raw(code))
    }

    /// The post-Cancun system contracts, the three test contracts and the funded senders.
    fn block_db(senders: &[Address]) -> CacheDB<EmptyDB> {
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(&BEACON_ROOTS_ADDRESS, contract(BEACON_ROOTS_CODE.clone()));
        db.insert_account_info(
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            contract(WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone()),
        );
        db.insert_account_info(&HISTORY_STORAGE_ADDRESS, contract(HISTORY_STORAGE_CODE.clone()));
        db.insert_account_info(&COUNTER, contract(Bytes::from_static(COUNTER_CODE)));
        db.insert_account_info(&REVERTER, contract(Bytes::from_static(REVERTER_CODE)));
        db.insert_account_info(&CALLER, contract(caller_code()));
        for sender in senders {
            db.insert_account_info(
                sender,
                AccountInfo::default()
                    .with_balance(U256::from(alloy_consensus::constants::ETH_TO_WEI)),
            );
        }
        db
    }

    fn signed_call(key: &Keypair, nonce: u64, to: Address) -> Recovered<TransactionSigned> {
        let tx = Transaction::Legacy(TxLegacy {
            chain_id: Some(MAINNET.chain.id()),
            nonce,
            gas_price: 1,
            // Covers the Amsterdam state gas of a new storage slot inside a nested call.
            gas_limit: 400_000,
            to: TxKind::Call(to),
            value: U256::from(1),
            input: Default::default(),
        });
        Recovered::new_unchecked(
            sign_tx_with_key_pair(*key, tx),
            public_key_to_address(key.public_key()),
        )
    }

    fn sealed_block(
        transactions: Vec<TransactionSigned>,
        block_access_list_hash: B256,
    ) -> SealedBlock<Block> {
        let header = Header {
            timestamp: 1,
            number: 1,
            gas_limit: 30_000_000,
            beneficiary: COINBASE,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            block_access_list_hash: Some(block_access_list_hash),
            slot_number: Some(0),
            ..Header::default()
        };
        Block {
            header,
            body: BlockBody { transactions, ommers: vec![], withdrawals: Some(vec![].into()) },
        }
        .seal_slow()
    }

    /// A block tracer over a buffer-backed tracer configured like the node's.
    fn block_tracer(
        block: &SealedBlock<Block>,
    ) -> (FirehoseBlockTracer<Box<firehose_tracer::Tracer>>, firehose_tracer::InMemoryBuffer) {
        let (tracer, buffer) = firehose_tracer::Tracer::with_buffer(
            firehose_tracer::config::Config::default(),
            firehose_tracer::config::ChainConfig {
                chain_id: MAINNET.chain.id(),
                shanghai_time: Some(0),
                cancun_time: Some(0),
                prague_time: Some(0),
                verkle_time: None,
            },
            "reth-engine-tree-test",
            "0",
        );
        let finalized = Some(firehose_tracer::types::FinalizedBlockRef {
            number: block.number(),
            hash: Some(block.hash()),
        });
        (
            FirehoseBlockTracer::start_local::<EthPrimitives>(Box::new(tracer), block, finalized),
            buffer,
        )
    }

    /// The block access list `block` produces, from an execution whose trace is discarded.
    fn rebuilt_bal(
        evm_config: &EthEvmConfig,
        mut db: CacheDB<EmptyDB>,
        block: &RecoveredBlock<Block>,
    ) -> BlockAccessList {
        let (mut tracer, _buffer) = block_tracer(block.sealed_block());
        let (_, bal) = run_wrapped_block(
            evm_config,
            &mut db,
            block,
            &mut tracer,
            NoPreTxAdjust,
            NoPostTxExtras,
        )
        .expect("serial execution succeeds");
        bal.expect("the header declares a block access list")
    }

    /// Traces `block` serially and returns its Firehose block with the access list it rebuilt.
    fn trace_serially(
        evm_config: &EthEvmConfig,
        mut db: CacheDB<EmptyDB>,
        block: &RecoveredBlock<Block>,
    ) -> (FirehoseBlock, BlockAccessList) {
        let (mut tracer, buffer) = block_tracer(block.sealed_block());
        let (_, bal) = run_wrapped_block(
            evm_config,
            &mut db,
            block,
            &mut tracer,
            NoPreTxAdjust,
            NoPostTxExtras,
        )
        .expect("serial traced execution succeeds");
        let bal = bal.expect("the header declares a block access list");
        record_block_access_list(block, Some(&bal), &mut tracer).expect("the rebuilt BAL matches");
        tracer.mark_verified();
        (parse_fire_block_for(&buffer.get_bytes(), 1).expect("the block is emitted"), bal)
    }

    /// Traces `block` on the BAL path, with the test runtime's two workers, and returns its
    /// Firehose block, or the execution error and the tracer output.
    fn trace_in_parallel(
        evm_config: &EthEvmConfig,
        db: CacheDB<EmptyDB>,
        block: &RecoveredBlock<Block>,
        received_bal: BlockAccessList,
    ) -> Result<FirehoseBlock, (BalExecutionError, Vec<u8>)> {
        let (mut tracer, buffer) = block_tracer(block.sealed_block());
        let txs = block.transactions_recovered().map(|tx| tx.cloned()).collect::<Vec<_>>();
        let (tx_sender, tx_receiver) = crossbeam_channel::unbounded();
        for (index, tx) in txs.iter().cloned().enumerate() {
            tx_sender.send((index, Ok::<_, Infallible>(tx))).unwrap();
        }
        drop(tx_sender);
        let (receipt_tx, _receipt_rx) = crossbeam_channel::unbounded();
        let alloy_bal: AlloyBal = received_bal.into();
        let raw = alloy_rlp::encode(&alloy_bal).into();
        let input_bal = Arc::new(DecodedBal::new(alloy_bal, raw));
        let make_db = |_| Ok(db.clone());

        let executed = execute_and_trace_block(
            &Runtime::test(),
            evm_config,
            &make_db,
            input_bal,
            evm_config.evm_env(block.header()).unwrap(),
            evm_config.context_for_block(block.sealed_block()).unwrap(),
            txs.len(),
            tx_receiver,
            receipt_tx,
            &tracer,
            block.body().withdrawals.clone(),
        );
        match executed {
            Ok((_, senders, built_bal, _)) => {
                assert_eq!(senders.as_slice(), block.senders());
                record_block_access_list(block, Some(&built_bal), &mut tracer)
                    .expect("the rebuilt BAL matches");
                tracer.mark_verified();
                Ok(parse_fire_block_for(&buffer.get_bytes(), 1).expect("the block is emitted"))
            }
            Err(err) => {
                drop(tracer);
                Err((err, buffer.get_bytes()))
            }
        }
    }

    /// Four senders, one of them the coinbase, interleaving calls that write storage and emit
    /// logs at two depths, revert, and transfer value.
    fn traced_block(evm_config: &EthEvmConfig) -> (CacheDB<EmptyDB>, RecoveredBlock<Block>) {
        let keys = (0..3).map(|_| generate_key(&mut rng())).collect::<Vec<_>>();
        let coinbase_key = generate_key(&mut rng());
        let coinbase = public_key_to_address(coinbase_key.public_key());
        let mut senders =
            keys.iter().map(|key| public_key_to_address(key.public_key())).collect::<Vec<_>>();
        senders.push(coinbase);

        let mut txs = vec![
            signed_call(&keys[0], 0, COUNTER),
            signed_call(&keys[1], 0, CALLER),
            signed_call(&keys[2], 0, REVERTER),
            signed_call(&keys[0], 1, CALLER),
            signed_call(&coinbase_key, 0, COUNTER),
            signed_call(&keys[1], 1, COUNTER),
            signed_call(&keys[2], 1, Address::repeat_byte(0xee)),
            signed_call(&keys[0], 2, REVERTER),
        ];
        // Above the payload processor's sequential conversion threshold, so a block like it is
        // also converted in parallel on the engine path.
        for nonce in 2..24 {
            txs.push(signed_call(&keys[1], nonce, COUNTER));
        }

        let mut db = block_db(&senders);
        // The coinbase pays its own gas and earns its own fee: two changes of one balance per
        // transaction, read from the block access list on the workers.
        db.insert_account_info(
            &coinbase,
            AccountInfo::default().with_balance(U256::from(alloy_consensus::constants::ETH_TO_WEI)),
        );
        let senders = txs.iter().map(|tx| tx.signer()).collect::<Vec<_>>();
        let transactions = txs.into_iter().map(|tx| tx.into_inner()).collect::<Vec<_>>();

        // The block access list of the header comes from a first execution.
        let probe =
            RecoveredBlock::new_sealed(sealed_block(transactions.clone(), B256::ZERO), senders);
        let bal = rebuilt_bal(evm_config, db.clone(), &probe);
        let (_, senders) = probe.split();
        let block = RecoveredBlock::new_sealed(
            sealed_block(transactions, compute_block_access_list_hash(&bal)),
            senders,
        );
        (db, block)
    }

    #[test]
    fn parallel_tracing_matches_serial_tracing() {
        let evm_config = evm_config();
        let (db, block) = traced_block(&evm_config);

        let (serial, bal) = trace_serially(&evm_config, db.clone(), &block);
        let parallel = trace_in_parallel(&evm_config, db, &block, bal)
            .unwrap_or_else(|(err, _)| panic!("parallel traced execution failed: {err}"));

        BlockInvariants::assert(&serial).expect("the serial block holds the invariants");
        assert_eq!(serial.transaction_traces.len(), 30);
        let reverted = &serial.transaction_traces[2];
        assert!(reverted.calls[0].status_reverted);
        // The nested call's log sits between the root call's EIP-7708 transfer log and its
        // own log, after the two logs of the first transaction.
        let nested = &serial.transaction_traces[1];
        assert_eq!(nested.calls.len(), 2);
        let logs = &nested.receipt.as_ref().unwrap().logs;
        assert_eq!(logs.len(), 3);
        assert_eq!(logs.iter().map(|log| log.block_index).collect::<Vec<_>>(), [2, 3, 4]);
        assert_eq!(nested.calls[1].logs[0].block_index, 3);

        assert_eq!(parallel, serial);
    }

    #[test]
    fn parallel_tracing_failure_discards_the_block() {
        let evm_config = evm_config();
        let (db, block) = traced_block(&evm_config);

        // A received access list that declares no account makes every worker fail its
        // transaction on an undeclared access.
        let (err, output) = trace_in_parallel(&evm_config, db, &block, BlockAccessList::default())
            .expect_err("execution against an empty access list fails");
        assert!(matches!(err, BalExecutionError::Execution(_)), "{err}");
        assert!(
            parse_fire_block_for(&output, 1).is_err(),
            "a block whose execution failed was emitted"
        );
    }
}
