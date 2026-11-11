//! Compares the execution of one Amsterdam block of contract calls on the serial path and on the
//! block access list path, untraced and traced by Firehose, for several BAL worker counts.
//!
//! The block holds `CALLS` calls from `SENDERS` senders to a contract that hashes in a loop,
//! increments a storage slot and emits a log, so every transaction runs a few thousand opcodes
//! (the inspector's per-opcode hooks are where tracing costs) and writes state. The traced paths
//! include the end-of-block encoding of the `FIRE BLOCK` line, written to a sink.
//!
//! ```sh
//! cargo bench -p reth-engine-tree --bench firehose_bal_tracing
//! ```

#![allow(missing_docs)]

use alloy_consensus::{BlockHeader, Header, TxLegacy};
use alloy_eip7928::{bal::Bal as AlloyBal, compute_block_access_list_hash, BlockAccessList};
use alloy_eips::{
    eip2935::{HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE},
    eip4788::{BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE},
    eip7002::{WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_CODE},
};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use evm2::evm::{CacheDB, EmptyDB};
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_engine_tree::tree::payload_processor::bal;
use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives, Transaction, TransactionSigned};
use reth_evm::{
    cached::{AccountInfo, Bytecode},
    BlockExecutor, ConfigureEvm,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose::{run_wrapped_block, FirehoseBlockTracer, NoPostTxExtras, NoPreTxAdjust};
use reth_primitives_traits::{Block as _, Recovered, RecoveredBlock, SealedBlock};
use reth_tasks::{RayonConfig, Runtime, RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_testing_utils::generators::{generate_key, rng, sign_tx_with_key_pair};
use std::{convert::Infallible, sync::Arc, time::Duration};

/// Senders of the block, each with `CALLS / SENDERS` consecutive nonces.
const SENDERS: usize = 20;
/// Transactions in the block.
const CALLS: usize = 200;
/// BAL worker counts to run the parallel paths with.
const WORKERS: [usize; 4] = [1, 2, 4, 8];

/// Hashes the first memory word 1000 times, then increments storage slot 0 and emits `LOG1`
/// with topic `0xaa`.
const COUNTER: Address = Address::repeat_byte(0xc1);
const COUNTER_CODE: &[u8] = &[
    // PUSH2 1000; JUMPDEST; PUSH1 32 PUSH1 0 KECCAK256; PUSH1 0 MSTORE; PUSH1 1 SWAP1 SUB; DUP1;
    // PUSH1 3 JUMPI; POP.
    0x61, 0x03, 0xe8, 0x5b, 0x60, 0x20, 0x60, 0x00, 0x20, 0x60, 0x00, 0x52, 0x60, 0x01, 0x90, 0x03,
    0x80, 0x60, 0x03, 0x57, 0x50, //
    0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x60, 0xaa, 0x60, 0x00, 0x60, 0x00, 0xa1,
    0x00,
];
const COINBASE: Address = Address::repeat_byte(0xbe);

fn evm_config() -> EthEvmConfig {
    EthEvmConfig::new(Arc::new(ChainSpecBuilder::mainnet().amsterdam_activated().build()))
}

fn contract(code: Bytes) -> AccountInfo {
    AccountInfo::default().with_nonce(1).with_code(Bytecode::new_raw(code))
}

fn block_db(senders: &[Address]) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::<EmptyDB>::default();
    db.insert_account_info(&BEACON_ROOTS_ADDRESS, contract(BEACON_ROOTS_CODE.clone()));
    db.insert_account_info(
        &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        contract(WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone()),
    );
    db.insert_account_info(&HISTORY_STORAGE_ADDRESS, contract(HISTORY_STORAGE_CODE.clone()));
    db.insert_account_info(&COUNTER, contract(Bytes::from_static(COUNTER_CODE)));
    for sender in senders {
        db.insert_account_info(
            sender,
            AccountInfo::default().with_balance(U256::from(alloy_consensus::constants::ETH_TO_WEI)),
        );
    }
    db
}

fn sealed_block(transactions: Vec<TransactionSigned>, bal_hash: B256) -> SealedBlock<Block> {
    let header = Header {
        timestamp: 1,
        number: 1,
        gas_limit: 60_000_000,
        beneficiary: COINBASE,
        parent_beacon_block_root: Some(B256::ZERO),
        withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
        requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
        excess_blob_gas: Some(0),
        blob_gas_used: Some(0),
        block_access_list_hash: Some(bal_hash),
        slot_number: Some(0),
        ..Header::default()
    };
    Block {
        header,
        body: BlockBody { transactions, ommers: vec![], withdrawals: Some(vec![].into()) },
    }
    .seal_slow()
}

/// A block tracer over a tracer that encodes its block into a sink.
fn block_tracer(block: &SealedBlock<Block>) -> FirehoseBlockTracer<Box<firehose_tracer::Tracer>> {
    let config = firehose_tracer::config::Config {
        chain_client: firehose_tracer::config::ChainClient::Reth,
        ..Default::default()
    };
    let mut tracer = firehose_tracer::Tracer::new_with_writer(config, Box::new(std::io::sink()));
    tracer.on_blockchain_init(
        "reth-bench",
        "0",
        firehose_tracer::config::ChainConfig {
            chain_id: MAINNET.chain.id(),
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            verkle_time: None,
        },
    );
    let finalized = Some(firehose_tracer::types::FinalizedBlockRef {
        number: block.number(),
        hash: Some(block.hash()),
    });
    FirehoseBlockTracer::start_local::<EthPrimitives>(Box::new(tracer), block, finalized)
}

struct Fixture {
    evm_config: EthEvmConfig,
    db: CacheDB<EmptyDB>,
    block: RecoveredBlock<Block>,
    bal: BlockAccessList,
}

fn fixture() -> Fixture {
    let evm_config = evm_config();
    let keys = (0..SENDERS).map(|_| generate_key(&mut rng())).collect::<Vec<_>>();
    let senders = keys
        .iter()
        .map(|key| Address::from_raw_public_key(&key.public_key().serialize_uncompressed()[1..]))
        .collect::<Vec<_>>();
    let txs = (0..CALLS)
        .map(|index| {
            let key = &keys[index % SENDERS];
            let tx = Transaction::Legacy(TxLegacy {
                chain_id: Some(MAINNET.chain.id()),
                nonce: (index / SENDERS) as u64,
                gas_price: 1,
                gas_limit: 300_000,
                to: TxKind::Call(COUNTER),
                value: U256::from(1),
                input: Default::default(),
            });
            Recovered::new_unchecked(sign_tx_with_key_pair(*key, tx), senders[index % SENDERS])
        })
        .collect::<Vec<_>>();
    let db = block_db(&senders);
    let signers = txs.iter().map(|tx| tx.signer()).collect::<Vec<_>>();
    let transactions = txs.into_iter().map(|tx| tx.into_inner()).collect::<Vec<_>>();

    let probe =
        RecoveredBlock::new_sealed(sealed_block(transactions.clone(), B256::ZERO), signers.clone());
    let (_, bal) = serial_untraced(&evm_config, db.clone(), &probe);
    let bal = bal.expect("the header declares a block access list");
    let block = RecoveredBlock::new_sealed(
        sealed_block(transactions, compute_block_access_list_hash(&bal)),
        signers,
    );
    Fixture { evm_config, db, block, bal }
}

fn runtime(workers: usize) -> Runtime {
    let config = RuntimeConfig::default()
        .with_tokio(TokioConfig::Owned {
            worker_threads: Some(1),
            thread_keep_alive: Duration::from_secs(10),
            thread_name: "bench",
        })
        .with_rayon(RayonConfig { bal_streaming_threads: Some(workers), ..Default::default() });
    RuntimeBuilder::new(config).build().expect("runtime")
}

fn serial_untraced(
    evm_config: &EthEvmConfig,
    db: CacheDB<EmptyDB>,
    block: &RecoveredBlock<Block>,
) -> (u64, Option<BlockAccessList>) {
    let mut executor = evm_config.executor_for_block(db, block.sealed_block()).expect("executor");
    executor.enable_block_access_list_builder();
    executor.apply_pre_execution_changes().expect("pre-execution");
    for tx in block.transactions_recovered() {
        executor.execute_transaction(tx.cloned()).expect("transaction");
    }
    let (output, bal) = executor.finish_with_block_access_list().expect("post-execution");
    (output.result.gas_used, bal)
}

/// The untraced serial path with a no-op inspector installed: the cost of evm2's inspected
/// dispatch loop alone, which no tracer hook can remove.
fn serial_noop_inspector(
    evm_config: &EthEvmConfig,
    db: CacheDB<EmptyDB>,
    block: &RecoveredBlock<Block>,
) -> u64 {
    let mut executor = evm_config.executor_for_block(db, block.sealed_block()).expect("executor");
    executor.evm_mut().set_inspector(evm2::NoopInspector::default());
    executor.enable_block_access_list_builder();
    executor.apply_pre_execution_changes().expect("pre-execution");
    for tx in block.transactions_recovered() {
        executor.execute_transaction(tx.cloned()).expect("transaction");
    }
    executor.finish_with_block_access_list().expect("post-execution").0.result.gas_used
}

fn serial_traced(fixture: &Fixture, mut db: CacheDB<EmptyDB>) -> u64 {
    let mut tracer = block_tracer(fixture.block.sealed_block());
    let (output, _) = run_wrapped_block(
        &fixture.evm_config,
        &mut db,
        &fixture.block,
        &mut tracer,
        NoPreTxAdjust,
        NoPostTxExtras,
    )
    .expect("traced execution");
    tracer.mark_verified();
    output.result.gas_used
}

fn decoded_bal(bal: &BlockAccessList) -> Arc<alloy_eip7928::bal::DecodedBal> {
    let alloy_bal: AlloyBal = bal.clone().into();
    let raw = alloy_rlp::encode(&alloy_bal).into();
    Arc::new(alloy_eip7928::bal::DecodedBal::new(alloy_bal, raw))
}

fn tx_stream(
    block: &RecoveredBlock<Block>,
) -> crossbeam_channel::Receiver<(usize, Result<Recovered<TransactionSigned>, Infallible>)> {
    let (tx, rx) = crossbeam_channel::unbounded();
    for (index, transaction) in block.transactions_recovered().enumerate() {
        tx.send((index, Ok(transaction.cloned()))).unwrap();
    }
    rx
}

fn parallel_untraced(fixture: &Fixture, runtime: &Runtime, db: CacheDB<EmptyDB>) -> u64 {
    let block = &fixture.block;
    let (receipt_tx, _receipt_rx) = crossbeam_channel::unbounded();
    let make_db = |_| Ok(db.clone());
    let (output, _, _, _) = bal::execute_block(
        runtime,
        &fixture.evm_config,
        &make_db,
        decoded_bal(&fixture.bal),
        fixture.evm_config.evm_env(block.header()).unwrap(),
        fixture.evm_config.context_for_block(block.sealed_block()).unwrap(),
        block.body().transactions.len(),
        tx_stream(block),
        receipt_tx,
    )
    .expect("parallel execution");
    output.result.gas_used
}

fn parallel_traced(fixture: &Fixture, runtime: &Runtime, db: CacheDB<EmptyDB>) -> u64 {
    let block = &fixture.block;
    let tracer = block_tracer(block.sealed_block());
    let (receipt_tx, _receipt_rx) = crossbeam_channel::unbounded();
    let make_db = |_| Ok(db.clone());
    let (output, _, _, _) = bal::firehose::execute_and_trace_block(
        runtime,
        &fixture.evm_config,
        &make_db,
        decoded_bal(&fixture.bal),
        fixture.evm_config.evm_env(block.header()).unwrap(),
        fixture.evm_config.context_for_block(block.sealed_block()).unwrap(),
        block.body().transactions.len(),
        tx_stream(block),
        receipt_tx,
        &tracer,
        block.body().withdrawals.clone(),
    )
    .expect("parallel traced execution");
    tracer.mark_verified();
    output.result.gas_used
}

fn bench(c: &mut Criterion) {
    let fixture = fixture();
    let mut group = c.benchmark_group("firehose_bal_tracing");
    group.throughput(Throughput::Elements(CALLS as u64));
    group.sample_size(20);

    group.bench_function("serial/untraced", |b| {
        b.iter_batched(
            || fixture.db.clone(),
            |db| serial_untraced(&fixture.evm_config, db, &fixture.block),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("serial/noop-inspector", |b| {
        b.iter_batched(
            || fixture.db.clone(),
            |db| serial_noop_inspector(&fixture.evm_config, db, &fixture.block),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("serial/traced", |b| {
        b.iter_batched(
            || fixture.db.clone(),
            |db| serial_traced(&fixture, db),
            BatchSize::SmallInput,
        )
    });
    for workers in WORKERS {
        let runtime = runtime(workers);
        group.bench_with_input(BenchmarkId::new("parallel/untraced", workers), &workers, |b, _| {
            b.iter_batched(
                || fixture.db.clone(),
                |db| parallel_untraced(&fixture, &runtime, db),
                BatchSize::SmallInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("parallel/traced", workers), &workers, |b, _| {
            b.iter_batched(
                || fixture.db.clone(),
                |db| parallel_traced(&fixture, &runtime, db),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
