//! Regression test: staged sync stores the block access lists it rebuilds.
//!
//! The execution stage rebuilds and validates the BAL of each Amsterdam block, but it did not
//! store it. `engine_getPayloadBodiesByHashV2` and `ByRangeV2` then answered
//! `blockAccessList: null` for every block that staged sync wrote, and the consensus client
//! failed to serve those payload envelopes (`PayloadBodyMissingBlockAccessList`).

use std::{path::PathBuf, sync::Arc};

use alloy_consensus::{
    constants::EMPTY_WITHDRAWALS, proofs::calculate_transaction_root, Header, EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::{keccak256, B256};
use reth_chainspec::ChainSpec;
use reth_consensus::noop::NoopConsensus;
use reth_db_common::init::init_genesis;
use reth_ethereum_primitives::{Block, BlockBody};
use reth_evm::execute::{BasicBlockExecutor, Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose_tests::prestate::{seed_cache_db, Prestate};
use reth_primitives_traits::{Block as _, RecoveredBlock};
use reth_provider::{
    test_utils::create_test_provider_factory_with_chain_spec, BalProvider, BlockWriter, DBProvider,
    DatabaseProviderFactory, StaticFileProviderFactory, StaticFileWriter,
};
use reth_revm::State;
use reth_stages::stages::ExecutionStage;
use reth_stages_api::{ExecInput, Stage};
use reth_static_file_types::StaticFileSegment;
use revm::database::{CacheDB, EmptyDB};

#[test]
fn execution_stage_stores_the_rebuilt_block_access_list() {
    let case = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/cases/amsterdam_block_access_list/prestate.json");
    let mut prestate: Prestate = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    // The stage executes block 1 on top of a genesis at block 0.
    prestate.genesis.number = Some(0);
    let chain_spec = Arc::new(ChainSpec::from(prestate.genesis.clone()));
    let evm_config = EthEvmConfig::new(chain_spec.clone());

    // Reference BAL from the upstream executor. A placeholder hash only arms its BAL builder.
    let mut db = CacheDB::new(EmptyDB::default());
    seed_cache_db(&mut db, &prestate.genesis).unwrap();
    let mut reference = BasicBlockExecutor::new(
        evm_config.clone(),
        State::builder().with_database(db).with_bundle_update().build(),
    );
    reference.execute_one(&block(&prestate, B256::repeat_byte(0x11))).unwrap();
    let expected_rlp = alloy_rlp::encode(reference.take_bal().expect("upstream builds a BAL"));
    let block = block(&prestate, keccak256(&expected_rlp));

    let factory = create_test_provider_factory_with_chain_spec(chain_spec);
    init_genesis(&factory).unwrap();
    let provider = factory.database_provider_rw().unwrap();
    provider.insert_block(&block).unwrap();
    provider
        .static_file_provider()
        .latest_writer(StaticFileSegment::Headers)
        .unwrap()
        .commit()
        .unwrap();
    provider.commit().unwrap();

    let mut stage =
        ExecutionStage::new_with_executor(evm_config, Arc::new(NoopConsensus::default()))
            .with_bal_store(factory.bal_store().clone());
    let provider = factory.database_provider_rw().unwrap();
    let output = stage.execute(&provider, ExecInput { target: Some(1), checkpoint: None }).unwrap();
    assert!(output.done);
    assert_eq!(output.checkpoint.block_number, 1);
    provider.commit().unwrap();

    let stored = factory.get_bal_by_hash(block.hash()).unwrap();
    assert_eq!(
        stored.as_ref().map(|bal| bal.as_ref()),
        Some(expected_rlp.as_slice()),
        "staged sync must store the BAL it validated against the header"
    );
}

fn block(prestate: &Prestate, bal_hash: B256) -> RecoveredBlock<Block> {
    let ctx = &prestate.context;
    let header = Header {
        parent_hash: B256::ZERO,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: ctx.miner,
        transactions_root: calculate_transaction_root::<reth_ethereum_primitives::TransactionSigned>(
            &[],
        ),
        withdrawals_root: Some(EMPTY_WITHDRAWALS),
        number: 1,
        timestamp: ctx.timestamp,
        gas_limit: ctx.gas_limit,
        base_fee_per_gas: ctx.base_fee_per_gas.map(|v| v as u64),
        parent_beacon_block_root: Some(B256::ZERO),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        slot_number: Some(1),
        block_access_list_hash: Some(bal_hash),
        ..Default::default()
    };
    Block {
        header,
        body: BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: Some(Withdrawals::default()),
        },
    }
    .try_into_recovered()
    .unwrap()
}
