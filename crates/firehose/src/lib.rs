//! Firehose crate providing blockchain data processing modules.
//!
//! This crate contains modules for inspection, mapping, prelude utilities, and node startup.
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
/// Resolves which finalized block a Firehose block event may advertise.
pub mod finality;
/// thatis health.json publisher (on-disk + loopback GET).
pub mod health;
/// Startup module emitting `FIRE INIT` and the genesis block.
pub mod init;
/// Inspector module for analyzing blockchain data.
pub mod inspector;
/// Mapper module for transforming blockchain data.
pub mod mapper;
/// Prelude module with common imports and utilities.
pub mod prelude;
/// PrimordialPulse state-transition emission (PulseChain-specific).
pub mod primordial_pulse;
/// Firehose ExEx: publishes the thatis health.json heartbeat per committed block.
pub mod runner;

pub use block_tracer::{FirehoseBlockTracer, GlobalTracerGuard};
pub use executor::{
    reject_jit_capable_inner, run_wrapped_block, take_traced_block_access_list, ChainHooks,
    FirehoseBlockExecutor, FirehoseEvmConfig, FirehoseLiveHooks, FirehoseWrappedExecutor,
    LiveTracedEvm, NoChainHooks, NoPostTxExtras, NoPreTxAdjust, PostTxExtras, PreTxAdjust,
};
pub use finality::finalized_ref_for_block;
pub use firehose_tracer::types::FinalizedBlockRef;
pub use health::{
    default_health_path, resolve_replica, resolve_replica_from, write_health_json, HealthPublisher,
    HealthStatus, HEALTH_HTTP_PATH, HEALTH_LISTEN_ADDR, HEALTH_REL_PATH,
};
pub use init::{emit_genesis_block_on_empty_chain, init_blockchain};
pub use inspector::{FramelessTx, PostTxGasAccounting};
pub use runner::run_exex;

use std::{
    io::Write,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

static GLOBAL_TRACER: OnceLock<Arc<Mutex<firehose_tracer::Tracer>>> = OnceLock::new();

/// Process-wide stdout write lock.
///
/// When two [`firehose_tracer::Tracer`] instances exist simultaneously (e.g. the global
/// live-block tracer and a flashblock-specific tracer), their writes to stdout must not
/// interleave. Both tracers receive a [`SynchronizedStdout`] backed by this same
/// `Arc<Mutex<()>>` so each `write_all` call is serialised.
///
/// Initialized by [`init_stdout_lock`] and retrieved by [`stdout_lock`].
static STDOUT_LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

/// Initialize the process-wide stdout write lock, or return the existing one.
///
/// Idempotent: subsequent calls return the same lock. Called automatically by [`init_tracer`];
/// there is no need to call this directly unless constructing a tracer outside of that path.
/// Returns the lock so callers can wrap it in a [`SynchronizedStdout`] for additional tracers
/// (e.g. a flashblock tracer).
pub fn init_stdout_lock() -> Arc<Mutex<()>> {
    STDOUT_LOCK.get_or_init(|| Arc::new(Mutex::new(()))).clone()
}

/// Returns the process-wide stdout write lock.
///
/// Panics if [`init_tracer`] (or [`init_stdout_lock`]) has not been called yet.
pub fn stdout_lock() -> Arc<Mutex<()>> {
    STDOUT_LOCK.get().expect("stdout lock not initialized — call init_tracer first").clone()
}

/// A `Write` implementation that serialises stdout writes across multiple tracer instances.
///
/// Each call to `write` / `write_all` / `flush` acquires the shared `Arc<Mutex<()>>`
/// before delegating to [`std::io::stdout`]. When only one tracer is active the lock is
/// uncontested and the overhead is negligible.
#[derive(Debug)]
pub struct SynchronizedStdout {
    lock: Arc<Mutex<()>>,
}

impl SynchronizedStdout {
    /// Creates a new `SynchronizedStdout` backed by the given lock.
    pub fn new(lock: Arc<Mutex<()>>) -> Self {
        Self { lock }
    }
}

impl Write for SynchronizedStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _guard = self.lock.lock().expect("stdout lock poisoned");
        std::io::stdout().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _guard = self.lock.lock().expect("stdout lock poisoned");
        std::io::stdout().flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let _guard = self.lock.lock().expect("stdout lock poisoned");
        std::io::stdout().write_all(buf)
    }
}

/// Returns `true` if the process-wide tracer has been initialized via [`init_tracer`].
///
/// Use this for zero-cost checks at call sites that should only run when Firehose is active.
pub fn is_tracer_initialized() -> bool {
    GLOBAL_TRACER.get().is_some()
}

/// Initialize the process-wide tracer and stdout lock in a single call.
///
/// Initialises the shared [`STDOUT_LOCK`], wraps it in a [`SynchronizedStdout`], and constructs
/// the [`firehose_tracer::Tracer`] with that writer. Callers that create additional tracers
/// (e.g. a flashblock tracer) can retrieve the same lock via [`stdout_lock`] and wrap it in
/// their own [`SynchronizedStdout`], ensuring all tracer writes are serialised.
///
/// Must be called exactly once before any call to [`tracer`]. Panics if called more than once.
pub fn init_tracer(config: firehose_tracer::config::Config) {
    let lock = init_stdout_lock();
    let writer = SynchronizedStdout::new(lock);
    let tracer = firehose_tracer::Tracer::new_with_writer(config, Box::new(writer));
    GLOBAL_TRACER
        .set(Arc::new(Mutex::new(tracer)))
        .ok()
        .expect("init_tracer called more than once");
}

/// Initialize the process-wide tracer to capture all output into an in-memory buffer, returning a
/// handle to read it back.
///
/// This is the buffer-backed counterpart to [`init_tracer`] (which writes to stdout): it builds a
/// fully blockchain-initialized [`firehose_tracer::Tracer`] over a
/// [`firehose_tracer::InMemoryBuffer`] and installs it as the process-wide tracer, so the live
/// engine path — [`is_tracer_initialized`] plus [`block_tracer::FirehoseBlockTracer::start`] —
/// becomes active and every `FIRE BLOCK` line is captured instead of printed.
///
/// Intended for integration tests that drive the real validation path and need to assert on the
/// emitted Firehose blocks. Like [`init_tracer`], it must be called at most once per process.
///
/// `shanghai_time` / `cancun_time` / `prague_time` are the timestamp-based fork activations the
/// tracer uses when mapping block contents (`Some(0)` = active from genesis, `None` = never). They
/// do not gate whether a block is emitted.
pub fn init_tracer_with_buffer(
    chain_id: u64,
    shanghai_time: Option<u64>,
    cancun_time: Option<u64>,
    prague_time: Option<u64>,
) -> firehose_tracer::InMemoryBuffer {
    // Mirror `init_tracer`: ensure the shared stdout lock exists so any code path that later
    // reaches for it (e.g. an additional flashblock tracer) does not panic.
    let _ = init_stdout_lock();
    let (tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id,
            shanghai_time,
            cancun_time,
            prague_time,
            verkle_time: None,
        },
        "reth-firehose",
        env!("CARGO_PKG_VERSION"),
    );
    GLOBAL_TRACER
        .set(Arc::new(Mutex::new(tracer)))
        .ok()
        .expect("init_tracer/init_tracer_with_buffer called more than once");
    buffer
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
