# Changelog

All notable changes to the StreamingFast Firehose fork of reth are documented here.

This changelog covers Firehose-specific changes only. For upstream reth changes, see the
[official reth releases](https://github.com/paradigmxyz/reth/releases).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## reth-v2.7.0-fh3.1-2

### Fixed

- Staged sync no longer rejects Amsterdam blocks with `BlockAccessListHashMissing`. The Firehose
  block executor now rebuilds each block's access list on both its traced and untraced paths and
  hands it to the execution stage for validation.

### Changed

- `reth_firehose::run_wrapped_block` leaves the rebuilt block access list in the state. Call the
  new `reth_firehose::take_traced_block_access_list` afterwards to check its hash and record its
  RLP on the traced block; `FirehoseBlockExecutor` already does.

## reth-v2.7.0-fh3.1-1

### Fixed

- Fixed glamsterdam hard fork crash when BAL executes in parallel (when a block has more than 30 transactions)

### Changed

- `reth` no longer installs a Firehose execution extension (ExEx). It only emitted `FIRE INIT`
  and the genesis block; blocks are traced by the engine. Both are now emitted at startup before
  the consensus engine exists, so no block can be traced ahead of `FIRE INIT`, and the node
  stops writing the ExEx write-ahead log.

### Removed

- `reth_firehose::run_exex` and `reth_firehose::emit_genesis_block_if_empty`. Call
  `reth_firehose::init_blockchain(&provider)` from the node builder's `on_component_initialized`
  hook instead. `reth-firehose` no longer depends on `reth-exex`.

## reth-v2.7.0-fh3.1

### Changed

- Update to upstream reth [v2.7.0](https://github.com/paradigmxyz/reth/releases/tag/v2.7.0)
  (through [v2.6.0](https://github.com/paradigmxyz/reth/releases/tag/v2.6.0)): revm 43, and
  alloy-evm 0.39 through the `streamingfast/evm` fork tag `v0.39.0-sf`, which still routes system
  calls through the inspector.

- Amsterdam only: gas reported by Firehose follows revm 43's glamsterdam devnet-8
  [EIP-8038](https://eips.ethereum.org/EIPS/eip-8038) costs. For example, a cold storage access
  now costs 2,100 gas instead of 3,000.

### Fixed

- Build the [EIP-7928](https://eips.ethereum.org/EIPS/eip-7928) block access list when a block
  runs through Firehose live tracing, the same way upstream does for untraced execution. Before,
  the traced path built no access list. Blocks skipped the access-list hash check and nothing was
  stored for them. From reth 2.7.0, consensus rejects an Amsterdam block that produced no access
  list, so a node with tracing enabled would have rejected every Amsterdam block it received
  through the Engine API.

- Trace Amsterdam transactions that run out of gas before their root call starts. Under
  [EIP-2780](https://eips.ethereum.org/EIPS/eip-2780), the state gas for a created or newly
  funded account is charged before the first frame opens. When it can't be paid, the transaction
  is still included as an out-of-gas failure, but no frame ever runs. Such a transaction used to
  come out with no call, no receipt, zero gas used and an unknown status. It now carries a failed
  root call, its gas buy and nonce change, and a receipt matching what the node reports over RPC.

## reth-v2.5.2-fh3.1-3

### Changed

- Firehose `Call.keccak_preimages` now keeps only the preimages that explain a storage slot written by the transaction: the hash is the storage key, the storage key is the hash plus a small offset (a struct field or array position), or the hash appears inside another kept preimage (up to 16 levels). Preimages of hashes that never lead to a written storage slot, and preimages over 256 bytes, are no longer recorded (see streamingfast/reth#57).
- Firehose limits the call input and return data a transaction records: past 50 MiB of internal call input or 25 MiB of return data, later calls keep only the 4-byte selector of their input and no return data, and set `Call.input_truncated` / `Call.return_data_truncated`. The root call is never cut, and a block that would still encode to more than 1 GiB has both limits halved until it fits (see streamingfast/reth#57).

## reth-v2.5.2-fh3.1-2

### Changed

- Track `evm-firehose-tracer-rs` `5.4.4` from crates.io instead of a pinned git commit, now that
  the protobuf bindings it needs have shipped in a release.

### Fixed

- Stop reporting a call as self-destructed when its `SELFDESTRUCT` ran out of gas. revm mutates
  the journal inside `Journal::selfdestruct` and charges the dynamic cost afterwards, so the
  instruction can halt on gas with the account already marked destroyed; geth charges before
  running the opcode body and never reports a suicide there. The opcode is now reported as failed
  for every instruction result other than `SelfDestruct`, not only for an undefined instruction.

- Stop reporting the finalization cleanup (`nonce → 0` and code cleared) for a `SELFDESTRUCT`
  whose frame reverted. revm truncates the `AccountDestroyed` journal entry on revert without
  notifying the inspector, so an account that survived with its nonce and code intact was reported
  as cleared. The cleanup is now taken from the committed journal.

- Resolve the post-transaction balance of an account that executed a self-beneficiary
  `SELFDESTRUCT` correctly under [EIP-8246](https://eips.ethereum.org/EIPS/eip-8246): Amsterdam
  keeps the balance on the account instead of burning it, so the `GasRefund` and
  `RewardTransactionFee` events that follow no longer report `old_balance = 0` for an account that
  still holds its ether. Reachable when a transaction creates and self-destructs the coinbase
  address, or through a chain's post-transaction extras. Only affects chains with Amsterdam
  
- Populate `BlockHeader.slot_number` (EIP-7843, Amsterdam) from the block header instead of
  always emitting `None`.
  
- Populate `BlockHeader.block_access_list_hash`/`block_access_list_rlp` (EIP-7928, Amsterdam).
  The hash comes straight from the header. The RLP-encoded list isn't part of the header (it only
  commits to the hash), so it's sourced differently depending on path: on the live engine path
  it's read from the payload's decoded BAL sidecar; on the pipeline/backfill path, which has no
  sidecar, it's reconstructed via re-execution (the same BAL-index tracking
  `BasicBlockExecutor::execute_one` uses); the block execution hard-fails if the reconstructed
  hash doesn't match the header's declared one, since this is the first re-execution-based
  reconstruction shipped and a mismatch means the reconstruction is wrong, not the block.

- Report the EIP-8037 state gas in `Call.gas_consumed`. A frame's regular gas and its state gas
  are tracked separately, and only the regular half was reported: a call was charged less than it
  consumed when the state gas came out of the transaction's reservoir, and more when a revert
  handed that gas back. Only affects chains with Amsterdam activated.

## reth-v2.5.2-fh3.1-1

### Added

- `FirehoseLiveHooks`, implemented by the node's EVM configuration, selects the chain-specific
  hooks (`PreTxAdjust`, `PostTxExtras`) installed on live engine-API traced execution. Before,
  blocks received through `engine_newPayload` were traced without them, so only staged sync
  applied a chain's fee handling. Every EVM configuration used with the engine validator must
  implement it.
- `PostTxExtras::gas_accounting` lets a chain choose the gas price used for the post-transaction
  `GasRefund` and `RewardTransactionFee` balance changes, add an extra reward to the fee, or
  suppress both. The default keeps Ethereum fee rules, so existing chains produce the same output.

### Fixed

- Report EIP-7708 native ETH transfer logs. revm reports them through `Inspector::log`, which the
  Firehose inspector did not implement, so they were dropped from the call tree while still
  appearing in the receipt — the tracer then aborted block processing with
  `mismatch between call logs and receipt logs`. The logs are now drained from the journal at a
  frame's first opcode as well as at its exit, which also settles their attribution: a native
  transfer log belongs to the frame whose checkpoint scopes it, meaning the callee for `CALL`,
  the created account for `CREATE`/`CREATE2`, the root call for a transaction's own value
  transfer, and the destructing call for `SELFDESTRUCT`. Only affects chains with Amsterdam
  activated.

### Changed

- Drop KECCAK256 preimages larger than 256 bytes instead of recording them in
  `Call.keccak_preimages`, matching the geth Firehose tracer. Solidity storage-slot derivations
  fit well under that size; values could otherwise reach 65536 bytes each. Oversized preimages
  are dropped, not truncated, so every recorded value still hashes back to its key.
- Track the development version of `evm-firehose-tracer-rs` instead of the published `5.x` crate,
  picking up the regenerated protobuf bindings that follow `firehose-ethereum` `develop`. The
  dependency is pinned to a commit rather than a branch so builds stay reproducible.

### Fixed

- `Executor::execute` on `FirehoseBlockExecutor` no longer traces. Callers that re-execute blocks
  for other purposes, such as the ExEx backfill job, emitted those blocks a second time and out of
  order. `execute_and_trace_one` now falls back to untraced execution when the tracer is not
  initialized instead of returning an error.
- Stop reporting a call as self-destructed when a chain replaces SELFDESTRUCT with an undefined
  instruction. SELFDESTRUCT is now reported after the instruction runs, and reported as failed
  when it halted as an undefined opcode.

### Build

- The Docker image bundles `firehose-ethereum` v2.23.0.

## reth-v2.5.2-fh3.1

### Changed

- Merge upstream reth v2.5.2 (from v2.5.0). No Firehose code changed.

## reth-v2.5.0-fh3.2

### Fixed

- Stop advertising a finalized block that is not an ancestor of the block being emitted. Every
  `FIRE BLOCK` line carried the node's finalized head as of the moment the block executed, so a
  block from a side branch was published with a LIB number naming the canonical chain's block at
  that height; the consumer marked its own block at that height irreversible and then saw the
  reorg replace it. The advertised block is now the node's finalized head when that head is on
  the emitted block's own chain, the fork point where its branch left the canonical chain
  otherwise, and genesis when the branch cannot be tied to the canonical chain at all. Seen on
  BSC mainnet at block 120653740, where a four-block side branch was published with LIB
  120653741 — one of those blocks naming a height above its own number.

### Build

- `install_llvm_ubuntu.sh` configures the apt.llvm.org repository directly instead of
  running that site's `llvm.sh` installer. The installer is fetched unpinned at build time
  and gates on a distro allow-list of its own, so it rejected Debian 13 — the base of the
  `cargo-chef:latest-rust-1.95-trixie` image — even though
  `apt.llvm.org/trixie/llvm-toolchain-trixie-22` carries every package the build needs.

## reth-v2.5.0-fh3.1

Rebase of the Firehose fork onto upstream reth v2.5.0. Covers everything since
`v2.3.0-fh-7`, including the untagged `v2.4.1-fh`, `v2.4.1-fh-1` and
`reth-v2.5.0-fh3.0` builds.

### Added

- Emit the genesis block (block 0) at ExEx startup when the head is still at
  genesis. Genesis is written to the DB without execution, so no tracing hook
  ever fired for it and streams began at block 1. The old block-1 "genesis
  marker" hack is gone: it emitted block 1 through `on_genesis_block` with an
  empty alloc and never traced its transactions. Block 1 now takes the normal
  tracing path.

### Changed

- Rebase onto upstream reth v2.5.0 (from v2.3.0, via v2.4.1).
- Reject `reth_jit` `Enable`/`Unpause` over RPC while the Firehose tracer is
  active, and refuse to start `FirehoseExecutorBuilder::build_evm` when `--jit`
  was passed. JIT-compiled frames only call `log`/`selfdestruct`/`frame_end` on
  the Inspector — `step`/`step_end` never fire — so per-opcode storage and
  gas-reason data silently vanishes under JIT. `--jit` at startup was already
  inert for the Firehose executor builder, but the RPC method is a second,
  independent way to flip JIT on at runtime.

### Fixed

- Collapse the duplicate `alloy-evm` entry left in `Cargo.lock` by the v2.4.1
  merge. With both the unpatched 0.37.1 crate and our `streamingfast/evm` patch
  in the graph, most of the executor pipeline linked against the unpatched copy,
  which does not route system calls through the Inspector — silently dropping
  the block's EIP-4788/EIP-2935 `system_calls` from Firehose output.

### Build

- `Dockerfile.sf`: bump the cargo-chef base image to Rust 1.95 and install LLVM
  in the build stage.
- `sf-release.yml` now builds on `release/*` branch pushes (the fork's branches
  were renamed from `firehose/*`). The sibling release branches
  (`release/optimism-2.x`, `release/base-2.x`, `release/bnb-0.x`) no longer
  publish images or releases — their tags exist only as refs for downstream
  projects to pin.

## v2.3.0-fh-7

### Fixed

- Include the SELFDESTRUCT refund when resolving an account's post-transaction balance. On the truly-destroyed path (EIP-6780: contract created in the same transaction, or pre-Cancun) revm credits the beneficiary in place and records the move only inside its `AccountDestroyed` journal entry — no `BalanceTransfer` is pushed — so the journal walk backing the `RewardTransactionFee` and `GasRefund` events missed it. A coinbase or sender that received a suicide refund then reported an `old_balance` contradicting the `SuicideRefund` event emitted moments earlier. First seen on Ethereum mainnet block 25690108.

## v2.3.0-fh-6

### Fixed

- Emit the value-transfer balance changes when a transaction sends value to a precompile and then fails (e.g. the precompile runs out of gas). The transfer creates a revm `BalanceTransfer` journal entry that is normally read in `call_end`, but a reverted no-step callee has that entry truncated by the checkpoint rollback before the journal walk runs, so both balance changes were dropped. They are now captured at call-enter and re-emitted synthetically on revert, matching geth (which records the transfer that happened before the revert). Aborts that occur *before* the transfer (`OutOfFunds` / `CallTooDeep`) correctly emit nothing.

## v2.3.0-fh-5

### Fixed

- Fix a call/receipt log-count mismatch panic (`assign_ordinal_and_index_to_receipt_logs`: "N call logs but N+1 receipt logs") when a native-precompile log (e.g. a B-20 token event) is emitted at a journal index just freed by a reverted opcode `LOG`. The opcode log advanced the `gather_precompile_logs` watermark via `log_full`; revm truncated it on revert but left the watermark stale-high, so the precompile log was skipped as already-emitted. `gather_precompile_logs` now re-clamps the watermark to the live journal log count, mirroring `gather_precompile_storage_changes`. First seen on Base mainnet block 48387796 (a Uniswap V4 revert-based quote hiding a B-20 log).

## v2.3.0-fh-4

### Added

- Add StreamingFast Docker image build, push and release CI (`Dockerfile.sf`, `.github/workflows/sf-release.yml`). Pushing the `firehose/*` branch or a `*-fh*` tag builds the Firehose-instrumented `reth` and publishes it to `ghcr.io/streamingfast/reth`; tag builds use the `maxperf` profile and attach a `reth_linux_amd64` release asset. The runtime image bundles `fireeth`, which drives `reth` as its reader node.

## v2.3.0-fh-3

### Fixed

- Add a gas-bound cap on `step_keccak256` to prevent an out-of-memory panic for operations that would out-of-gas anyway.

## v2.3.0-fh-2

### Added

- Expose the post-tx balance resolver so chains can supply post-tx balance extras.

## v2.3.0-fh-1

### Added

- Capture native-precompile state changes in the Firehose tracer.

### Changed

- Drive the precompile test through the real `call` / `call_end` hooks.

## v2.3.0-fh

Rebase the Firehose fork onto upstream reth v2.3.0, keeping Firehose tracing intact.

## v2.2.0-fh

First Firehose-instrumented release on top of upstream reth v2.2.0.

### Added

- Add flashblocks support to `reth-firehose`: `start_flashblock_local` and `mark_flashblock` methods on `FirehoseBlockTracer` allow partial block ("flashblock") boundaries to be emitted during block execution.
- Add `SynchronizedStdout` for coordinated stdout writes across multiple concurrent tracer instances; stdout lock initialization is now handled internally by `init_tracer`.
- Expose prestate types and helpers as `pub` in `reth-firehose-tests` crate to allow reuse in downstream integration test suites.

### Changed

- `init_tracer` now accepts `Config` directly and sets up the stdout lock internally, removing the need for callers to manage stdout coordination themselves.
- Update `firehose-tracer` dependency to version 5.1.1.

### Fixed

- Restore the Firehose live-path hooks in the engine-tree payload validator so blocks arriving through the engine API (`newPayload` / `forkchoiceUpdated`) are traced again. The hooks had been dropped during a merge, leaving only the historical/stage execution path instrumented.
