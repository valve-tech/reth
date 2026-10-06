### Required Changes to `reth-firehose` (streamingfast/reth)

The `reth-firehose` crate at tag `v1.11.4-fh-1` passes `flash_block: None` in all
`BlockEvent` constructions and has no `start_flashblock` / `mark_flashblock` API.
`firehose-tracer` at version 5.1.1 (on `firehose/0.x`) already has:

```rust
pub struct FlashBlockData {
    pub idx: u64,
    pub is_final: bool,
}
// and BlockEvent { flash_block: Option<FlashBlockData> }
```

**Two changes are needed in `streamingfast/reth`:**

#### 1. `FirehoseBlockTracer::start_flashblock` constructor

Add a new constructor to `FirehoseBlockTracer` in `crates/firehose/src/block_tracer.rs`:

```rust
impl FirehoseBlockTracer<GlobalTracerGuard> {
    /// Acquires the global tracer and emits on_block_start with a FlashBlock annotation.
    /// Used by the flashblock processor for pre-canonical partial block emission.
    pub fn start_flashblock<N>(
        block: &SealedBlock<N::Block>,
        finalized: Option<firehose_tracer::types::FinalizedBlockRef>,
        flash_block_idx: u64,
        is_final: bool,
    ) -> Self
    where ...
    {
        let mut guard = crate::tracer();
        guard.on_block_start(firehose_tracer::types::BlockEvent {
            block: mapper::to_block_data(block),
            finalized,
            flash_block: Some(firehose_tracer::types::FlashBlockData {
                idx: flash_block_idx,
                is_final,
            }),
        });
        Self { guard, status: Status::Started, is_genesis: false }
    }
}
```

However, the flashblock processor uses a **dedicated tracer** (not the global). So a
`start_flashblock_local` variant (like the existing `start_local`) is also needed:

```rust
impl<'a> FirehoseBlockTracer<&'a mut firehose_tracer::Tracer> {
    pub fn start_flashblock_local<N>(
        tracer: &'a mut firehose_tracer::Tracer,
        block: &SealedBlock<N::Block>,
        finalized: Option<firehose_tracer::types::FinalizedBlockRef>,
        flash_block_idx: u64,
        is_final: bool,
    ) -> Self
    where ...
    {
        tracer.on_block_start(firehose_tracer::types::BlockEvent {
            block: mapper::to_block_data(block),
            finalized,
            flash_block: Some(firehose_tracer::types::FlashBlockData {
                idx: flash_block_idx,
                is_final,
            }),
        });
        Self { guard: tracer, status: Status::Started, is_genesis: false }
    }
}
```

#### 2. `mark_flashblock` method (immediate flush without validation gate)

The existing `mark_verified` is intended for use **after** state-root validation. For flashblocks we
want to flush immediately (partial blocks have no state root yet). Add:

```rust
impl<G> FirehoseBlockTracer<G>
where G: DerefMut<Target = firehose_tracer::Tracer>
{
    /// Emits on_block_end(None) immediately, without the "verified" semantics.
    /// Use this for flashblock partial emissions where state-root validation is not available.
    pub fn mark_flashblock(mut self) {
        self.guard.on_block_end(None);
        self.status = Status::Consumed;
    }
}
```

#### 3. Stdout write coordination

Currently `firehose_tracer::Tracer` writes to stdout without coordination. When two `Tracer`
instances exist simultaneously (global live-block tracer + flashblock tracer), their writes may
interleave.

The fix: install a process-wide `Arc<Mutex<()>>` that both tracers acquire before each `write_all`
to stdout. This requires:

- A new `init_stdout_lock()` function in `reth-firehose` `lib.rs` (or `runner.rs`) that
  initializes a `static STDOUT_LOCK: OnceLock<Arc<Mutex<()>>>`.
- Both `init_tracer` (global) and the flashblock `Tracer::new(...)` construction must use a writer
  that acquires `STDOUT_LOCK` before writing.
- In `firehose-tracer`, `Tracer::new` accepts any `impl Write`. The solution: create a newtype
  `SynchronizedStdout(Arc<Mutex<()>>)` that implements `Write` by acquiring the lock then calling
  `std::io::stdout().write_all(...)`. Both tracer instances receive the same `Arc<Mutex<()>>`.

This approach is zero-cost when only one tracer is active (the lock is uncontested) and correct
when both are active simultaneously.

**Summary of `streamingfast/reth` changes** (tag `v1.11.4-fh-2` or a new patch tag):

| Change                                           | File                                  | Scope             |
| ------------------------------------------------ | ------------------------------------- | ----------------- |
| Add `start_flashblock_local`                     | `crates/firehose/src/block_tracer.rs` | New method        |
| Add `mark_flashblock`                            | `crates/firehose/src/block_tracer.rs` | New method        |
| Add `SynchronizedStdout` writer + `STDOUT_LOCK`  | `crates/firehose/src/lib.rs`          | New type + static |
| Expose `stdout_lock()` / `init_stdout_lock()`    | `crates/firehose/src/lib.rs`          | New pub fns       |
| Update `init_tracer` to use `SynchronizedStdout` | `crates/firehose/src/lib.rs`          | Modify existing   |

**Step 1 — Changes to `streamingfast/reth` (`reth-firehose` crate)**

In the `streamingfast/reth` repository:

1. **`crates/firehose/src/lib.rs`**: Add `SynchronizedStdout` newtype + `STDOUT_LOCK: OnceLock<Arc<Mutex<()>>>` static. Add `init_stdout_lock()` and `stdout_lock()` accessors. Modify `init_tracer` to use `SynchronizedStdout` as the writer. Expose `stdout_lock()` publicly.

2. **`crates/firehose/src/block_tracer.rs`**: Add `start_flashblock_local<N>` on `FirehoseBlockTracer<&'a mut Tracer>`. Add `mark_flashblock` on `FirehoseBlockTracer<G>`.
