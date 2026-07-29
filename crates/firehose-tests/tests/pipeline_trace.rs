//! Pipeline-path firehose coverage.
//!
//! Drives a prestate block through [`reth_firehose::FirehoseBlockExecutor`]'s
//! `Executor::execute_and_trace_one` — the staged-sync production path, using the process-wide
//! tracer — and asserts the captured Firehose `Block` is byte-identical to the golden produced
//! by the (golden-verified) `run_wrapped_block` path.
//!
//! This guards the parts of the pipeline path that the local-tracer prestate harness does NOT
//! exercise: the process-wide tracer lifecycle, the `Executor<DB>` trait impl
//! (`execute_and_trace_one` / `into_state` / `take_bal`), and the deferred `mark_verified` flush
//! (the per-block guard is stashed in `pending_tracer` and only emitted on `into_state`).
//!
//! NOTE: this is its own test binary on purpose — it initializes the process-wide firehose tracer
//! (`init_tracer` is once-per-process). Keep it to a single test.

use std::path::PathBuf;

use reth_firehose_tests::{assert_block_equals_golden, run_prestate_via_block_executor};

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("cases").join(name)
}

#[test]
fn pipeline_executor_matches_golden() {
    let folder = case_dir("nop_transfer");

    let outcome = run_prestate_via_block_executor(&folder)
        .expect("pipeline execute_and_trace_one must succeed");

    // The pipeline executor must emit the same Firehose output as the golden-verified
    // run_wrapped_block path — same block envelope, ordinals, balance/nonce/system-call events.
    let golden = folder.join("block.2099.binpb");
    assert_block_equals_golden(&outcome.block, &golden)
        .expect("pipeline-captured block must match the golden");

    // The pipeline path must also route pre-execution system calls through the inspector.
    assert!(
        !outcome.block.system_calls.is_empty(),
        "pipeline path produced no system calls — the alloy-evm inspector patch may not be active \
         (see progress.txt)",
    );
}
