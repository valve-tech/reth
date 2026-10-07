//! Regression test: blocks re-executed through [`Executor::execute`] are not emitted.
//!
//! Staged sync executes blocks through [`Executor::execute_and_trace_one`], which emits each block
//! once the caller confirms it passed post-execution validation. `execute` is used to re-execute
//! blocks that were already traced (single-block ExEx backfill, for example); emitting there
//! published the block a second time, out of order, and before the caller validated anything.
//!
//! It lives in its own integration-test binary because it installs the process-wide tracer.

use std::sync::Arc;

use alloy_consensus::Header;
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_ethereum_primitives::{Block, BlockBody};
use reth_evm::execute::Executor;
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose::FirehoseBlockExecutor;
use reth_primitives_traits::RecoveredBlock;
use revm::database::EmptyDB;

#[test]
fn only_execute_and_trace_one_emits_the_block() {
    let buffer = reth_firehose::init_tracer_with_buffer(MAINNET.chain.id(), None, None, None);

    let evm_config =
        EthEvmConfig::new(Arc::new(ChainSpecBuilder::mainnet().paris_activated().build()));
    let block = RecoveredBlock::new_unhashed(
        Block {
            header: Header {
                number: 1,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1),
                ..Default::default()
            },
            body: BlockBody::default(),
        },
        Vec::new(),
    );

    FirehoseBlockExecutor::new(evm_config.clone(), EmptyDB::default())
        .execute(&block)
        .expect("execute succeeds");
    assert_eq!(fire_blocks(&buffer.get_bytes()), 0, "execute emitted the block");

    let mut executor = FirehoseBlockExecutor::new(evm_config, EmptyDB::default());
    executor.execute_and_trace_one(&block).expect("execute_and_trace_one succeeds");
    // Reaching `into_state` confirms the last block passed validation, which flushes it.
    let _ = executor.into_state();
    assert_eq!(fire_blocks(&buffer.get_bytes()), 1, "execute_and_trace_one did not emit the block");
}

/// Counts the `FIRE BLOCK` lines in the tracer output.
fn fire_blocks(output: &[u8]) -> usize {
    String::from_utf8_lossy(output).lines().filter(|line| line.starts_with("FIRE BLOCK ")).count()
}
