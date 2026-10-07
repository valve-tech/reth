//! Regression test for Firehose tracing on the engine-tree live-block path.
//!
//! The Firehose "live-path" hooks in `tree::payload_validator` route blocks arriving through the
//! engine API (`newPayload` / `forkchoiceUpdated`) into the Firehose tracer. On `firehose/2.x`
//! those hooks were once dropped during a merge, silently disabling live-block tracing while the
//! historical/stage path kept working — a regression that compiled and passed every existing test.
//!
//! This test guards that path end-to-end: it installs a buffer-backed global tracer, drives a real
//! [`EthereumNode`] through `newPayload` (which calls `validate_block_with_state`, the path under
//! test), and asserts that `FIRE BLOCK` lines are emitted for the live blocks. If the dispatch into
//! `execute_and_trace_block` is missing, no `FIRE BLOCK` lines are produced and the test fails.
//!
//! It lives in its own integration-test binary (rather than alongside the other engine-tree tests)
//! because it installs a process-wide tracer; cargo/nextest run each integration binary in its own
//! process, keeping the global tracer isolated from the rest of the suite.

use eyre::Result;
use reth_chainspec::{ChainSpecBuilder, MAINNET};
use reth_e2e_test_utils::testsuite::{
    actions::{MakeCanonical, ProduceBlocks},
    setup::{NetworkSetup, Setup},
    TestBuilder,
};
use reth_engine_tree::tree::TreeConfig;
use reth_ethereum_engine_primitives::EthEngineTypes;
use reth_node_ethereum::EthereumNode;
use std::sync::Arc;

/// Number of blocks to produce. All of them (block 1 included — the genesis block itself is
/// emitted separately at node startup, not through this path) exercise the live
/// `execute_and_trace_block` path.
const PRODUCED_BLOCKS: u64 = 3;

#[tokio::test]
async fn live_payload_validation_emits_firehose_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();

    // Install a buffer-backed global Firehose tracer BEFORE the node validates any block, so the
    // live path's `is_tracer_initialized()` gate activates and routes execution through
    // `execute_and_trace_block`. Fork timings only affect how block contents are mapped, not
    // whether a block is emitted; activate Shanghai + Cancun at genesis to match the
    // `cancun_activated` chain spec below.
    let buffer = reth_firehose::init_tracer_with_buffer(
        MAINNET.chain.id(),
        Some(0), // shanghai
        Some(0), // cancun
        None,    // prague
    );

    let setup = Setup::<EthEngineTypes>::default()
        .with_chain_spec(Arc::new(
            ChainSpecBuilder::default()
                .chain(MAINNET.chain)
                .genesis(
                    serde_json::from_str(include_str!(
                        "../../../e2e-test-utils/src/testsuite/assets/genesis.json"
                    ))
                    .unwrap(),
                )
                .cancun_activated()
                .build(),
        ))
        .with_network(NetworkSetup::single_node())
        .with_tree_config(TreeConfig::default().with_has_enough_parallelism(true));

    // Each produced block is submitted via `engine_newPayload`, which drives
    // `validate_block_with_state` — the path under test.
    let test = TestBuilder::new()
        .with_setup(setup)
        .with_action(ProduceBlocks::<EthEngineTypes>::new(PRODUCED_BLOCKS))
        .with_action(MakeCanonical::new());

    test.run::<EthereumNode>().await?;

    // Collect the block numbers from every captured `FIRE BLOCK <num> ...` line.
    let raw = buffer.get_bytes();
    let text = String::from_utf8(raw).expect("captured tracer output is UTF-8");
    let traced: Vec<u64> = text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(' ');
            if parts.next()? != "FIRE" || parts.next()? != "BLOCK" {
                return None;
            }
            parts.next()?.parse::<u64>().ok()
        })
        .collect();

    assert!(
        !traced.is_empty(),
        "no FIRE BLOCK lines were emitted — the live payload-validation path is not traced.\n\
         Captured tracer output:\n{text}"
    );

    // Every produced block goes through the live `execute_and_trace_block` path. Require each to
    // have been traced.
    for number in 1..=PRODUCED_BLOCKS {
        assert!(
            traced.contains(&number),
            "expected a FIRE BLOCK line for live block #{number}, got traced blocks {traced:?}"
        );
    }

    Ok(())
}
