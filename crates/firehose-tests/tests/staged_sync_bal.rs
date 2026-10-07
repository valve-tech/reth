//! Regression test: staged sync gets a block access list for Amsterdam blocks.
//!
//! The execution stage hashes the access list it takes from the executor with
//! [`Executor::take_bal`] and rejects an Amsterdam block when there is none
//! (`BlockAccessListHashMissing`). [`FirehoseBlockExecutor`] must therefore rebuild it on both its
//! traced and untraced paths, and record it on the traced Firehose block.
//!
//! It lives in its own integration-test binary because it installs the process-wide tracer.

use std::path::PathBuf;

use alloy_consensus::BlockHeader;
use alloy_primitives::keccak256;
use reth_evm::execute::Executor;
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose::FirehoseBlockExecutor;
use reth_firehose_tests::{load_prestate, parse_fire_block_for, LoadedPrestate};

#[test]
fn staged_sync_rebuilds_the_block_access_list() {
    let case = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("cases")
        .join("amsterdam_block_access_list");
    let LoadedPrestate { prestate, chain_spec, block, db } =
        load_prestate(&case).expect("loading the amsterdam_block_access_list prestate");
    let expected_hash = block
        .header()
        .block_access_list_hash()
        .expect("the Amsterdam fixture declares a block access list hash");
    let evm_config = EthEvmConfig::new(chain_spec);

    let mut executor = FirehoseBlockExecutor::new(evm_config.clone(), db.clone());
    executor.execute_one(&block).expect("execute_one succeeds");
    let bal = executor.take_bal().expect("execute_one rebuilds the block access list");
    assert_eq!(keccak256(alloy_rlp::encode(&bal)), expected_hash);

    let config = &prestate.genesis.config;
    let buffer = reth_firehose::init_tracer_with_buffer(
        config.chain_id,
        config.shanghai_time,
        config.cancun_time,
        config.prague_time,
    );
    let mut executor = FirehoseBlockExecutor::new(evm_config, db);
    executor.execute_and_trace_one(&block).expect("execute_and_trace_one succeeds");
    let bal = executor.take_bal().expect("execute_and_trace_one rebuilds the block access list");
    assert_eq!(keccak256(alloy_rlp::encode(&bal)), expected_hash);

    // Reaching `into_state` confirms the last block passed validation, which flushes it.
    let _ = executor.into_state();
    let fire_block = parse_fire_block_for(&buffer.get_bytes(), block.header().number())
        .expect("the traced block is emitted");
    let header = fire_block.header.expect("the Firehose block has a header");
    assert_eq!(header.block_access_list_rlp, Some(alloy_rlp::encode(&bal)));
}
