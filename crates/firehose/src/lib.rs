//! Firehose crate providing blockchain data processing modules.
//!
//! This crate contains modules for inspection, mapping, prelude utilities, and running tasks.
//!
//! # Firehose is incompatible with the revmc JIT
//!
//! Firehose reconstructs a block from Inspector callbacks, so it can only observe what the
//! executing EVM actually reports. revmc's compiled path reports a strict subset:
//!
//! * **`step` / `step_end` are never called.** There is no step callback in the compiled-code ABI
//!   at all — only `on_log`. revmc's `InspectorEvmTr::inspect_frame_run` hand-reconstructs just
//!   `log`, `inspect_selfdestruct` and `frame_end`, falling back to the interpreter only for
//!   `LookupDecision::Interpret`. Firehose drives SSTORE storage changes, KECCAK256 preimages and
//!   value-transfer balance changes from `step`, so all of those are lost.
//! * **Logs are lost too**, for a subtler reason: revmc calls `Inspector::log`, while
//!   [`inspector::FirehoseInspector`] overrides only `log_full`. In revm-inspector, `log_full`'s
//!   default delegates *to* `log`, not the reverse — and the interpreter path calls `log_full` — so
//!   firehose's `log` is the trait-default no-op.
//!
//! The failure mode is silent: blocks keep streaming, missing data. Downstream consumers cannot
//! tell a partial block from a complete one, and the resulting index corruption is only fixable by
//! a re-sync. So [`FirehoseEvmConfig::new`] **panics** on a JIT-capable inner config rather than
//! degrading — see [`reject_jit_capable_inner`].
//!
//! Combining the two safely would require an upstream revmc change: `inspect_frame_run` would have
//! to defer to the interpreter whenever the attached inspector needs step-level hooks. Until then
//! `--jit` is inert on a firehose node, and the CLI warns when it is passed.

/// Block-level drop guard that manages the Firehose tracer lifecycle across validation.
pub mod block_tracer;
/// Executor module with Firehose-aware block executors and EVM configs.
pub mod executor;
/// Inspector module for analyzing blockchain data.
pub mod inspector;
/// Mapper module for transforming blockchain data.
pub mod mapper;
/// Prelude module with common imports and utilities.
pub mod prelude;
/// PrimordialPulse state-transition emission (PulseChain-specific).
pub mod primordial_pulse;
/// Runner module for executing processing tasks.
pub mod runner;

pub use block_tracer::{FirehoseBlockTracer, GlobalTracerGuard};
pub use executor::{
    reject_jit_capable_inner, run_wrapped_block, ChainHooks, FirehoseBlockExecutor,
    FirehoseEvmConfig, FirehoseWrappedExecutor, NoChainHooks, NoPostTxExtras, NoPreTxAdjust,
    PostTxExtras, PreTxAdjust,
};
pub use runner::run_exex;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

static GLOBAL_TRACER: OnceLock<Arc<Mutex<firehose_tracer::Tracer>>> = OnceLock::new();

/// Returns `true` if the process-wide tracer has been initialized via [`init_tracer`].
///
/// Use this for zero-cost checks at call sites that should only run when Firehose is active.
pub fn is_tracer_initialized() -> bool {
    GLOBAL_TRACER.get().is_some()
}

/// Initialize the process-wide tracer instance.
///
/// Must be called exactly once before any call to [`tracer`]. Panics if called more than once.
pub fn init_tracer(t: firehose_tracer::Tracer) {
    GLOBAL_TRACER.set(Arc::new(Mutex::new(t))).ok().expect("init_tracer called more than once");
}

/// Acquire exclusive access to the process-wide tracer.
///
/// Panics if [`init_tracer`] has not been called yet, or if the mutex is poisoned.
pub fn tracer() -> MutexGuard<'static, firehose_tracer::Tracer> {
    GLOBAL_TRACER
        .get()
        .expect("firehose tracer not initialized — call init_tracer first")
        .lock()
        .expect("firehose tracer mutex poisoned")
}

/// Non-blocking variant of [`tracer`]. Returns `None` if the tracer mutex is
/// already held (typically by `FirehoseWrappedExecutor::finish` further up
/// the call stack — see `crates/firehose/src/executor.rs`) or if the tracer
/// has not yet been initialized.
///
/// Use this from code paths that may be reached re-entrantly under the
/// wrapper — `std::sync::Mutex` is non-reentrant, so a plain [`tracer`]
/// call from such a path would deadlock on the same thread. The
/// PulseChain `PrimordialPulse` handler in
/// `crates/pulsechain/node/src/evm.rs` is the canonical example.
pub fn try_lock_tracer() -> Option<MutexGuard<'static, firehose_tracer::Tracer>> {
    GLOBAL_TRACER.get().and_then(|m| m.try_lock().ok())
}
