//! End-to-end Firehose integration tests driven by `prestate.json` fixtures.

use std::path::PathBuf;

use firehose_tracer::pb::sf::ethereum::r#type::v2::{CallType, TransactionTraceStatus};
use reth_firehose_tests::{assert_block_equals_golden, run_prestate};

#[test]
fn nop_transfer() {
    let folder = case_dir("nop_transfer");
    let outcome = run_prestate(&folder).expect("running nop_transfer prestate must succeed");

    let golden = golden_dir(&folder, "block.2099.binpb");
    assert_block_equals_golden(&outcome.block, &golden).expect("captured block must match golden");
}

/// Regression: an `SSTORE` that runs out of gas on its dynamic cost must NOT emit a
/// `StorageChange`. revm writes the `StorageChanged` journal entry before charging dynamic gas,
/// so a naive journal scan would record the would-have-been change with a shifted ordinal even
/// though the opcode halted and the write was reverted.
#[test]
fn storage_sstore_oog() {
    let folder = case_dir("storage_sstore_oog");
    let outcome = run_prestate(&folder).expect("running storage_sstore_oog prestate must succeed");

    let golden = golden_dir(&folder, "block.2713.binpb");
    assert_block_equals_golden(&outcome.block, &golden).expect("captured block must match golden");
}

/// EIP-7843: the mapper must read `slot_number` from the header rather than hardcoding `None`.
#[test]
fn amsterdam_slot_number() {
    let folder = case_dir("amsterdam_slot_number");
    let outcome =
        run_prestate(&folder).expect("running amsterdam_slot_number prestate must succeed");

    let golden = golden_dir(&folder, "block.2099.binpb");
    assert_block_equals_golden(&outcome.block, &golden).expect("captured block must match golden");
}

/// EIP-7928: `run_wrapped_block` (this repo's pipeline/backfill path) has no payload sidecar to
/// source the block access list from, so it must reconstruct it via re-execution, and
/// `take_traced_block_access_list` only surfaces it once the reconstructed hash matches the
/// header's declared `block_access_list_hash`.
///
/// Because of that check the fixture's `context.blockAccessListHash` is not free-standing: it has
/// to be regenerated from the reconstructed value whenever anything about the block changes,
/// including its fork configuration, since the accesses a newly-active system call makes belong in
/// the list too. A stale value here fails as a hash mismatch, not as a golden diff.
#[test]
fn amsterdam_block_access_list() {
    let folder = case_dir("amsterdam_block_access_list");
    let outcome =
        run_prestate(&folder).expect("running amsterdam_block_access_list prestate must succeed");

    let golden = golden_dir(&folder, "block.2099.binpb");
    assert_block_equals_golden(&outcome.block, &golden).expect("captured block must match golden");
}

/// EIP-7928: a header declaring a `block_access_list_hash` that doesn't match what re-execution
/// reconstructs must hard-fail the block rather than silently ship a wrong `block_access_list_rlp`.
#[test]
fn amsterdam_block_access_list_hash_mismatch() {
    let folder = case_dir("amsterdam_block_access_list_hash_mismatch");
    let err = run_prestate(&folder)
        .expect_err("running amsterdam_block_access_list_hash_mismatch prestate must fail");

    let message = err.to_string();
    assert!(
        message.contains("reconstructed block access list hash mismatch"),
        "unexpected error: {message}"
    );
}

/// EIP-8282: the two builder-execution-request predeploys are drained by post-block system calls
/// from Amsterdam onward, and the activation block is where each one's excess counter flips from
/// the `EXCESS_INHIBITOR` sentinel to 0 — a storage change that belongs to no transaction.
///
/// Nothing in the Firehose code reaches for these calls specifically: they go through
/// `Evm::transact_system_call`, which the StreamingFast `alloy-evm` fork routes to the inspector,
/// inside the window `run_wrapped_block` already opens around `apply_post_execution_changes`. That
/// is exactly why the case is worth having — the coverage is incidental, so nothing would catch it
/// being lost.
///
/// The fixture stands the predeploys up with the EIP-7002 withdrawal-request runtime code. EIP-8282
/// does not publish its own bytecode in anything we depend on, and it specifies the same design:
/// an excess counter in slot 0, the same `2^256 - 1` sentinel, and the same drain on a
/// `SYSTEM_ADDRESS` call with empty calldata. What this pins is the Firehose side — that the
/// resulting state change is reported, and reported outside any transaction — not the predeploy's
/// own behaviour.
///
/// Both predeploys need Prague live as well as Amsterdam: the EIP-8282 calls sit inside the
/// EIP-7685 requests branch, which is gated on Prague.
#[test]
fn amsterdam_builder_execution_requests() {
    let folder = case_dir("amsterdam_builder_execution_requests");
    let outcome = run_prestate(&folder)
        .expect("running amsterdam_builder_execution_requests prestate must succeed");

    let golden = golden_dir(&folder, "block.2099.binpb");
    assert_block_equals_golden(&outcome.block, &golden).expect("captured block must match golden");
}

/// Amsterdam: a creation transaction whose gas covers its intrinsic cost but not the EIP-8037
/// account-creation state gas that EIP-2780 charges before the root frame opens. revm includes it
/// as an out-of-gas halt without ever opening that frame, so the root `CREATE` has to be traced
/// by the executor, and it has to be the transaction's own even though the block's system calls
/// opened depth-0 frames before it ran. Left untraced, the transaction had no call at all, and
/// the tracer dropped its receipt and left its status unknown.
///
/// Battlefield `contract_fail_code_copy` hits this with a 99309 gas deployment.
#[test]
fn amsterdam_create_runtime_out_of_gas() {
    const GAS_LIMIT: u64 = 30_000;

    let folder = case_dir("amsterdam_create_runtime_out_of_gas");
    let outcome =
        run_prestate(&folder).expect("running amsterdam_create_runtime_out_of_gas must succeed");

    let trx = outcome.block.transaction_traces.first().expect("the transaction is included");
    assert_eq!(trx.status, TransactionTraceStatus::Failed as i32);
    assert_eq!(trx.gas_used, GAS_LIMIT, "an out-of-gas halt charges the whole gas limit");
    let receipt = trx.receipt.as_ref().expect("the receipt is kept");
    assert_eq!(receipt.cumulative_gas_used, GAS_LIMIT);

    let root = trx.calls.first().expect("a root call");
    assert_eq!(root.call_type, CallType::Create as i32);
    assert!(root.status_failed);
    assert_eq!(root.gas_consumed, root.gas_limit);
    assert_eq!(root.nonce_changes.len(), 1, "the creation's nonce bump survives the halt");

    let golden = golden_dir(&folder, "block.2099.binpb");
    assert_block_equals_golden(&outcome.block, &golden).expect("captured block must match golden");
}

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("cases").join(name)
}

fn golden_dir(case_dir: &PathBuf, name: &str) -> PathBuf {
    case_dir.join(name)
}
