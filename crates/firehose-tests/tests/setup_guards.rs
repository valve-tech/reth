//! Setup guards — fast tests that fail loudly if the firehose build configuration
//! silently regresses.
//!
//! These don't test firehose *logic*; they assert that the surrounding setup our
//! firehose output depends on is actually in effect. The motivating regression: on
//! the reth v2.3.0 upgrade the `[patch.crates-io] alloy-evm` override stopped
//! version-matching the workspace requirement, so cargo silently dropped it and
//! firehose stopped tracing pre-execution system calls. Since reth v2.9 the same patch is
//! `[patch."https://github.com/alloy-rs/evm2"]`, pointing evm2 at the StreamingFast fork.

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
/// If the evm2 system-call inspector patch is not in effect, stock evm2 runs system calls
/// without the inspector ("System calls are not inspected"), the firehose inspector never
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
         (EIP-4788) system call. The evm2 system-call inspector patch is almost \
         certainly not in effect: stock evm2 does not run system calls through the \
         inspector. Check reth Cargo.toml's [patch.\"https://github.com/alloy-rs/evm2\"] \
         section: it must point evm2 at the streamingfast/evm2 fork.",
    );
}

/// #10 — Structural guard: the workspace `evm2` must resolve to the streamingfast/evm2 fork
/// (which runs block system calls through the inspector), not upstream alloy-rs/evm2.
///
/// This catches the silent patch-drop at the dependency level — before any execution —
/// with a message pointing straight at the fix. It complements the functional guard
/// above: this one explains *why* `system_calls` would be empty.
#[test]
fn evm2_resolves_to_streamingfast_fork() {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("reading workspace Cargo.lock at {}: {e}", lock_path.display()));

    // Cargo.lock is TOML: a sequence of `[[package]]` blocks. Find the evm2 block and read its
    // `source` line. (A simple scan avoids pulling in a TOML parser dependency.)
    let source = lock
        .split("[[package]]")
        .find(|block| block.lines().any(|line| line.trim() == "name = \"evm2\""))
        .and_then(|block| {
            block.lines().find_map(|line| line.trim().strip_prefix("source = ").map(str::trim))
        });

    let source = source.unwrap_or_else(|| {
        panic!(
            "could not find an `evm2` package with a `source` in Cargo.lock — the firehose \
             build depends on a patched evm2. See [patch.\"https://github.com/alloy-rs/evm2\"] \
             in Cargo.toml.",
        )
    });

    assert!(
        source.contains("streamingfast/evm2"),
        "evm2 resolves to `{source}`, NOT the streamingfast/evm2 fork. The system-call \
         inspector patch is not active, so firehose will not trace block system calls. \
         Re-point reth Cargo.toml's [patch.\"https://github.com/alloy-rs/evm2\"] evm2, \
         evm2-inspectors and evm2-jit at the streamingfast/evm2 tag for this reth release.",
    );
}

/// Structural guard: the EVM config a firehose node actually builds must never expose a JIT
/// backend, and must not acquire one when asked to.
///
/// This mirrors `FirehoseExecutorBuilder::build_evm` (`bin/reth/src/firehose.rs`), which wraps
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
