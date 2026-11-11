//! Setup guards — fast tests that fail loudly if the firehose build configuration
//! silently regresses.
//!
//! These don't test firehose *logic*; they assert that the surrounding setup our
//! firehose output depends on is actually in effect. The motivating regression: on
//! the reth v2.3.0 upgrade the `[patch.crates-io] alloy-evm` override stopped
//! version-matching the workspace requirement, so cargo silently dropped it and
//! firehose stopped tracing pre-execution system calls. From reth v2.9 to v2.10 the same patch
//! pointed evm2 at the StreamingFast fork. Since v2.11 upstream evm2 has opt-in system-call
//! inspection (alloy-rs/evm2#888), so no fork is needed, and the functional guard below checks
//! that the opt-in is actually switched on.

use std::path::{Path, PathBuf};

use reth_chainspec::MAINNET;
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose::FirehoseEvmConfig;
use reth_firehose_tests::run_prestate;

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("cases").join(name)
}

/// #2 — Functional guard: a Cancun block with a `parentBeaconBlockRoot` must produce a
/// non-empty firehose `system_calls` (the EIP-4788 beacon-root call).
///
/// If system-call inspection is not switched on (`set_inspect_system_calls`), evm2 runs system
/// calls without the inspector ("System calls are not inspected"), the firehose inspector never
/// sees the call frame, and `system_calls` comes back empty
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
         (EIP-4788) system call. System-call inspection is almost certainly not switched \
         on: evm2 runs system calls without the inspector unless the executor calls \
         set_inspect_system_calls(true) (FirehoseWrappedExecutor does).",
    );
}

/// Structural guard: the EVM config a firehose node actually builds must never expose a JIT
/// backend, and must not acquire one when asked to.
///
/// This mirrors `FirehoseExecutorBuilder::build_evm` (`bin/pulse-reth/src/firehose.rs`), which wraps
/// `EthEvmConfig::new(...)` — whose default factory is `alloy_evm::EthEvmFactory`, not reth's
/// `RethEvmFactory` — so revmc is structurally absent from a firehose node's type graph.
///
/// The hazard being guarded: revmc's compiled path never calls `Inspector::step`/`step_end` and
/// routes logs through `Inspector::log`, which firehose does not override (it implements
/// `log_full`). A JIT-backed firehose node would keep streaming blocks while silently dropping
/// every SSTORE storage change, KECCAK256 preimage, log and value-transfer balance change from
/// JIT-compiled contracts. `FirehoseEvmConfig::new` rejects a JIT-capable inner config outright;
/// this test pins the property from the other side, on the exact type the node constructs.
#[test]
fn firehose_evm_config_never_exposes_a_jit_backend() {
    let config = FirehoseEvmConfig::new(EthEvmConfig::new(MAINNET.clone()));

    assert!(
        config.jit_backend().is_none(),
        "a firehose EVM config handed out a JIT backend. revmc's compiled path drops the \
         Inspector step/step_end hooks, so firehose would emit silently incomplete blocks. See \
         reth_firehose::reject_jit_capable_inner.",
    );

    // `with_jit_support` must be swallowed by the wrapper rather than delegated to `inner`.
    let config = config.with_jit_support();

    assert!(
        config.jit_backend().is_none(),
        "a firehose EVM config acquired a JIT backend after with_jit_support(). \
         FirehoseEvmConfig must override with_jit_support_enabled as a no-op — delegating it to \
         the inner config reintroduces the silent-data-loss hazard.",
    );
}
