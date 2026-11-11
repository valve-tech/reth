//! Block-level drop guard that owns the Firehose tracer lifecycle for a single block.
//!
//! A [`FirehoseBlockTracer`] acquires the global tracer lock and emits `on_block_start`
//! on construction. The caller must later consume the guard via
//! [`FirehoseBlockTracer::mark_verified`] (flushes the block to stdout) or
//! [`FirehoseBlockTracer::mark_failed`] (discards it). If the guard is dropped without
//! being consumed, it emits `on_block_end(Some(err))` as a safety net so incomplete
//! blocks are never flushed as valid.
//!
//! This type exists so that the `on_block_end` call can be deferred until **after** all
//! post-execution validation (receipt root, state root, consensus) has completed. Without
//! this deferral, invalid blocks would be flushed to the downstream Firehose consumer
//! before their failure is detected.

use alloy_consensus::BlockHeader;
use alloy_primitives::Sealable;
use firehose_tracer::types::BlockEvent;
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{Block as BlockTrait, BlockBody, SealedBlock};
use std::{cell::RefMut, fmt::Debug, ops::DerefMut, sync::MutexGuard};

use crate::{inspector::FirehoseInspector, mapper};

/// Default tracer-handle type: a `MutexGuard` over the process-wide global tracer.
pub type GlobalTracerGuard = MutexGuard<'static, firehose_tracer::Tracer>;

/// Drop guard wrapping a tracer handle for the duration of a single block.
///
/// `G` is the tracer-handle type. By default it's [`GlobalTracerGuard`] — i.e. a `MutexGuard`
/// pointing at the process-wide tracer installed via [`crate::init_tracer`]. Tests and other
/// callers that need a self-contained tracer pass their own handle (a `Box<Tracer>`, for one) to
/// [`FirehoseBlockTracer::start_local`] to bypass the global entirely.
///
/// The handle is owned by the block's [`FirehoseInspector`] state and released once the guard and
/// every inspector clone installed on an EVM are dropped.
///
/// See the module-level documentation for the full lifecycle contract.
pub struct FirehoseBlockTracer<G = GlobalTracerGuard>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    inspector: FirehoseInspector<G>,
    /// The event the block was started with, replayed on the detached tracers.
    block_event: BlockEvent,
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
    /// The genesis block (block 0) never goes through this guard: reth writes it directly to
    /// the database without executing it, and it is emitted standalone via
    /// [`crate::init::emit_genesis_block_on_empty_chain`] at startup.
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
        Self::start_local::<N>(crate::tracer(), block, finalized)
    }
}

impl<G> FirehoseBlockTracer<G>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    /// Variant of [`Self::start`] that drives the block lifecycle through a
    /// caller-supplied tracer instance instead of the process-wide global.
    ///
    /// This is intended for tests and one-off integration harnesses that need a self-contained
    /// tracer (e.g. one whose output writer is an in-memory buffer they can later inspect).
    pub fn start_local<N>(
        mut tracer: G,
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
        let block_event =
            BlockEvent { block: mapper::to_block_data(block), finalized, flash_block: None };
        tracer.on_block_start(block_event.clone());
        Self { inspector: FirehoseInspector::new(tracer), block_event, status: Status::Started }
    }

    /// Variant of the flashblock constructor that drives the block lifecycle
    /// through a caller-supplied tracer instead of the process-wide global.
    ///
    /// Emits `on_block_start` with a [`firehose_tracer::types::FlashBlockData`] annotation so
    /// the downstream Firehose consumer knows this is a partial (pre-canonical) block emission.
    ///
    /// Use this when the flashblock processor owns its own dedicated tracer instance.
    pub fn start_flashblock_local<N>(
        mut tracer: G,
        block: &SealedBlock<N::Block>,
        finalized: Option<firehose_tracer::types::FinalizedBlockRef>,
        flash_block_idx: u64,
        is_final: bool,
    ) -> Self
    where
        N: NodePrimitives,
        N::Block: BlockTrait,
        <N::Block as BlockTrait>::Header: BlockHeader + Sealable,
        <N::Block as BlockTrait>::Body: BlockBody,
        <<N::Block as BlockTrait>::Body as BlockBody>::OmmerHeader: BlockHeader + Sealable,
    {
        let block_event = BlockEvent {
            block: mapper::to_block_data(block),
            finalized,
            flash_block: Some(firehose_tracer::types::FlashBlockData {
                idx: flash_block_idx,
                is_final,
            }),
        };
        tracer.on_block_start(block_event.clone());
        Self { inspector: FirehoseInspector::new(tracer), block_event, status: Status::Started }
    }

    /// Returns the held tracer, for in-block event emission.
    ///
    /// Panics when called while an inspector hook of this block is running.
    pub fn tracer_mut(&mut self) -> RefMut<'_, firehose_tracer::Tracer> {
        self.inspector.tracer_mut()
    }

    /// Returns a tracer that traces transactions of this block on another thread, for
    /// [`crate::FirehoseWrappedExecutor::execute_transaction_detached`]. The traces it completes
    /// are attached to this block by
    /// [`crate::FirehoseWrappedExecutor::commit_traced_transaction`] on an executor wrapped over
    /// [`Self::inspector`].
    ///
    /// Panics when called while an inspector hook of this block is running.
    pub fn detached_tracer(&self) -> firehose_tracer::Tracer {
        let mut tracer = self.inspector.tracer_mut().detached();
        tracer.on_block_start(self.block_event.clone());
        tracer
    }

    /// Returns the [`FirehoseInspector`] tracing this block into the held tracer.
    ///
    /// The inspector shares its state with this guard. It is installed on the block's EVM by
    /// [`crate::FirehoseWrappedExecutor`] and must be dropped with that EVM before the block ends,
    /// so the tracer handle is released.
    pub fn inspector(&self) -> FirehoseInspector<G> {
        self.inspector.clone()
    }

    /// Consumes the guard and emits `on_block_end(None)`, flushing the block to stdout.
    ///
    /// Call this only after **all** post-execution validations (receipt root, state root,
    /// consensus checks) have succeeded. Calling it earlier risks flushing a block that later
    /// turns out to be invalid.
    pub fn mark_verified(mut self) {
        self.inspector.tracer_mut().on_block_end(None);
        self.status = Status::Consumed;
    }

    /// Consumes the guard and immediately emits `on_block_end(None)`, flushing the partial
    /// flashblock to stdout.
    ///
    /// Unlike [`Self::mark_verified`], this method does **not** gate on post-execution
    /// validation. Flashblock partial emissions are intentionally pre-canonical — there is no
    /// state-root to validate — so the flush is unconditional.
    ///
    /// Do not call this on a guard created by [`Self::start`] or [`Self::start_local`]; use
    /// [`Self::mark_verified`] for normal blocks and reserve this for guards created by
    /// [`Self::start_flashblock_local`].
    pub fn mark_flashblock(mut self) {
        self.inspector.tracer_mut().on_block_end(None);
        self.status = Status::Consumed;
    }

    /// Consumes the guard and emits `on_block_end(Some(err))`, discarding the block.
    pub fn mark_failed(mut self, err: &dyn std::error::Error) {
        self.inspector.tracer_mut().on_block_end(Some(err));
        self.status = Status::Consumed;
    }
}

impl<G> Drop for FirehoseBlockTracer<G>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    fn drop(&mut self) {
        // Safety net: any early-return path that fails to call mark_verified/mark_failed ends here.
        // Treat it as failure so the block is discarded rather than flushed.
        if matches!(self.status, Status::Started) {
            let err = std::io::Error::other(
                "FirehoseBlockTracer dropped without mark_verified/mark_failed",
            );
            self.inspector.tracer_mut().on_block_end(Some(&err));
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
