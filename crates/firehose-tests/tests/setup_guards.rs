//! Setup guards — fast tests that fail loudly if the firehose build configuration
//! silently regresses.
//!
//! These don't test firehose *logic*; they assert that the surrounding setup our
//! firehose output depends on is actually in effect. The motivating regression: on
//! the reth v2.3.0 upgrade the `[patch.crates-io] alloy-evm` override stopped
//! version-matching the workspace requirement, so cargo silently dropped it and
//! firehose stopped tracing pre-execution system calls. See `progress.txt`.

use std::path::{Path, PathBuf};

use reth_firehose_tests::run_prestate;

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("cases").join(name)
}

/// #2 — Functional guard: a Cancun block with a `parentBeaconBlockRoot` must produce a
/// non-empty firehose `system_calls` (the EIP-4788 beacon-root call).
///
/// If the alloy-evm system-call inspector patch is not in effect, stock
/// `EthEvm::transact_system_call` runs `system_call_with_caller` (no inspector), the
/// firehose inspector never sees the call frame, and `system_calls` comes back empty
/// while every event ordinal shifts down by 2. This catches that immediately and with
/// a clear message, instead of via an opaque binary-golden diff.
///
/// `nop_transfer` is a Cancun-active (`cancunTime: 0`) case whose parent block carries a
/// `parentBeaconBlockRoot`, so block 2099 executes the EIP-4788 system call.
#[test]
fn cancun_block_emits_beacon_root_system_call() {
    let outcome = run_prestate(&case_dir("nop_transfer"))
        .expect("running nop_transfer prestate must succeed");

    assert!(
        !outcome.block.system_calls.is_empty(),
        "firehose captured zero system calls for a Cancun block with a beacon-root \
         (EIP-4788) system call. The alloy-evm system-call inspector patch is almost \
         certainly not in effect: stock alloy-evm's transact_system_call does not route \
         through the inspector. Check reth Cargo.toml's [patch.crates-io] alloy-evm — its \
         branch must version-match the workspace alloy-evm requirement, or cargo silently \
         ignores it. See progress.txt for the full history.",
    );
}

/// #10 — Structural guard: the workspace `alloy-evm` must resolve to the valve-tech/evm
/// fork (which carries the system-call inspector commit), not unpatched crates.io.
///
/// This catches the silent patch-drop at the dependency level — before any execution —
/// with a message pointing straight at the fix. It complements the functional guard
/// above: this one explains *why* `system_calls` would be empty.
#[test]
fn alloy_evm_resolves_to_valve_fork() {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("reading workspace Cargo.lock at {}: {e}", lock_path.display()));

    // Cargo.lock is TOML: a sequence of `[[package]]` blocks. Find the alloy-evm block and
    // read its `source` line. (A simple scan avoids pulling in a TOML parser dependency.)
    let source = lock
        .split("[[package]]")
        .find(|block| block.contains("name = \"alloy-evm\""))
        .and_then(|block| {
            block.lines().find_map(|line| line.trim().strip_prefix("source = ").map(str::trim))
        });

    let source = source.unwrap_or_else(|| {
        panic!(
            "could not find an `alloy-evm` package with a `source` in Cargo.lock — the firehose \
             build depends on a patched alloy-evm. See progress.txt / [patch.crates-io] alloy-evm.",
        )
    });

    assert!(
        source.contains("valve-tech/evm"),
        "alloy-evm resolves to `{source}`, NOT the valve-tech/evm fork. The system-call \
         inspector patch is not active, so firehose will not trace pre-execution system calls. \
         Re-point reth Cargo.toml's [patch.crates-io] alloy-evm at a valve-tech/evm branch that \
         version-matches the workspace alloy-evm requirement. See progress.txt.",
    );
}
