//! Block-level drop guard that owns the Firehose tracer lifecycle for a single block.
//!
//! A [`FirehoseBlockTracer`] acquires the global tracer lock and emits `on_block_start` on
//! construction. The caller must later consume the guard via
//! [`FirehoseBlockTracer::mark_verified`] (flushes the block to stdout) or
//! [`FirehoseBlockTracer::mark_failed`] (discards it). If the guard is dropped without
//! being consumed, it emits `on_block_end(Some(err))` as a safety net so incomplete
//! blocks are never flushed as valid.
//!
//! Block 0 (genesis) is NOT routed through this guard — it's emitted standalone at
//! chain-init time by `runner::run_exex` via `tracer.on_genesis_block(...)` so the chain's
//! pre-allocated state surfaces as a single FIRE BLOCK 0 event before any normal block
//! execution begins. The downstream merger relies on that event as its chain anchor.
//!
//! This type exists so that the `on_block_end` call can be deferred until **after** all
//! post-execution validation (receipt root, state root, consensus) has completed. Without
//! this deferral, invalid blocks would be flushed to the downstream Firehose consumer
//! before their failure is detected.

use alloy_consensus::BlockHeader;
use alloy_primitives::Sealable;
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{Block as BlockTrait, BlockBody, SealedBlock};
use std::{fmt::Debug, ops::DerefMut, sync::MutexGuard};

use crate::{inspector::FirehoseInspector, mapper};

/// Default tracer-handle type: a `MutexGuard` over the process-wide global tracer.
pub type GlobalTracerGuard = MutexGuard<'static, firehose_tracer::Tracer>;

/// Drop guard wrapping a tracer handle for the duration of a single block.
///
/// `G` is the tracer-handle type. By default it's [`GlobalTracerGuard`] — i.e. a `MutexGuard`
/// pointing at the process-wide tracer installed via [`crate::init_tracer`]. Tests and other
/// callers that need a self-contained tracer can use `FirehoseBlockTracer<&'a mut
/// firehose_tracer::Tracer>` via [`FirehoseBlockTracer::start_local`] to bypass the global
/// entirely.
///
/// See the module-level documentation for the full lifecycle contract.
pub struct FirehoseBlockTracer<G = GlobalTracerGuard>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    guard: G,
    status: Status,
}

impl<G> Debug for FirehoseBlockTracer<G>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirehoseBlockTracer").field("status", &self.status).finish()
    }
}

impl FirehoseBlockTracer<GlobalTracerGuard> {
    /// Acquires the global tracer and emits the start-of-block event.
    ///
    /// Always emits `on_block_start`. The genesis block (block 0) is NOT routed through this
    /// guard — it's emitted standalone at chain-init time by `runner::run_exex` via
    /// `tracer.on_genesis_block(...)`. See that function's comments for the rationale.
    ///
    /// Takes a [`SealedBlock`] rather than a `RecoveredBlock` so the guard can be started before
    /// transaction senders have been recovered. Block-level data read by the mapper is signer-free.
    ///
    /// `finalized` is the finalized block ref to advertise in the emitted `BlockEvent`. In the
    /// pipeline / staged sync path, the currently executing block is by definition already
    /// finalized, so callers should pass `Some(block_ref)`. Live engine callers that do not yet
    /// know the finalized head should pass `None`.
    pub fn start<N>(
        block: &SealedBlock<N::Block>,
        finalized: Option<firehose_tracer::types::FinalizedBlockRef>,
    ) -> Self
    where
        N: NodePrimitives,
        N::Block: BlockTrait,
        <N::Block as BlockTrait>::Header: BlockHeader + Sealable,
        <N::Block as BlockTrait>::Body: BlockBody,
        <<N::Block as BlockTrait>::Body as BlockBody>::OmmerHeader: BlockHeader + Sealable,
    {
        let mut guard = crate::tracer();
        guard.on_block_start(firehose_tracer::types::BlockEvent {
            block: mapper::to_block_data(block),
            finalized,
            flash_block: None,
        });
        Self { guard, status: Status::Started }
    }
}

impl<'a> FirehoseBlockTracer<&'a mut firehose_tracer::Tracer> {
    /// Borrow-based variant of [`Self::start`] that drives the block lifecycle through a
    /// caller-supplied tracer instance instead of the process-wide global.
    ///
    /// This is intended for tests and one-off integration harnesses that need a self-contained
    /// tracer (e.g. one whose output writer is an in-memory buffer they can later inspect).
    /// Callers must keep the tracer alive for the lifetime of the returned guard.
    pub fn start_local<N>(
        tracer: &'a mut firehose_tracer::Tracer,
        block: &SealedBlock<N::Block>,
        finalized: Option<firehose_tracer::types::FinalizedBlockRef>,
    ) -> Self
    where
        N: NodePrimitives,
        N::Block: BlockTrait,
        <N::Block as BlockTrait>::Header: BlockHeader + Sealable,
        <N::Block as BlockTrait>::Body: BlockBody,
        <<N::Block as BlockTrait>::Body as BlockBody>::OmmerHeader: BlockHeader + Sealable,
    {
        tracer.on_block_start(firehose_tracer::types::BlockEvent {
            block: mapper::to_block_data(block),
            finalized,
            flash_block: None,
        });
        Self { guard: tracer, status: Status::Started }
    }
}

impl<G> FirehoseBlockTracer<G>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    /// Returns a mutable reference to the held tracer, for in-block event emission.
    pub fn tracer_mut(&mut self) -> &mut firehose_tracer::Tracer {
        &mut self.guard
    }

    /// Builds a [`FirehoseInspector`] that borrows the tracer held by this guard.
    ///
    /// The returned inspector is valid for as long as `self` is not otherwise borrowed.
    /// Typically this inspector is moved into an EVM via `evm_with_env_and_inspector`, then
    /// dropped automatically when the executor is consumed by `finish()` — at which point the
    /// tracer becomes accessible again via [`Self::tracer_mut`] / [`Self::mark_verified`].
    pub fn inspector(&mut self) -> FirehoseInspector<'_> {
        FirehoseInspector::new(&mut self.guard)
    }

    /// Consumes the guard and emits `on_block_end(None)`, flushing the block to stdout.
    ///
    /// Call this only after **all** post-execution validations (receipt root, state root,
    /// consensus checks) have succeeded. Calling it earlier risks flushing a block that later
    /// turns out to be invalid.
    pub fn mark_verified(mut self) {
        self.guard.on_block_end(None);
        self.status = Status::Consumed;
    }

    /// Consumes the guard and emits `on_block_end(Some(err))`, discarding the block.
    pub fn mark_failed(mut self, err: &dyn std::error::Error) {
        self.guard.on_block_end(Some(err));
        self.status = Status::Consumed;
    }
}

impl<G> Drop for FirehoseBlockTracer<G>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    fn drop(&mut self) {
        // Safety net: any early-return path that fails to call mark_verified/mark_failed ends
        // here. Treat it as failure so the block is discarded rather than flushed.
        if matches!(self.status, Status::Started) {
            let err = std::io::Error::other(
                "FirehoseBlockTracer dropped without mark_verified/mark_failed",
            );
            self.guard.on_block_end(Some(&err));
        }
    }
}

#[derive(Debug)]
enum Status {
    /// `on_block_start` has been emitted; awaiting `mark_verified` or `mark_failed`.
    Started,
    /// `on_block_end` has already been emitted; Drop must not emit it again.
    Consumed,
}
