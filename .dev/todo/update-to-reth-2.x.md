# Update to reth 2.x

mode: feature
state: review
root_git: .worktrees/feature-update-to-reth-2.x
worktree: .worktrees/feature-update-to-reth-2.x
branch: feature/update-to-reth-2.x
target_branch: release/reth-2.x (sf remote)

> **Resume protocol:** read **Dev Feedback** and the **State Tracker** below first, then jump to the
> step marked `Current`. Ensure that you are in the correct worktree and branch according to preamble here. Update current with Developer feedback and update the tracker after every meaningful change.
> Do not mutate completed steps; append a new entry instead.

---

## Initial Description

Update our SF fork of reth to upstream `v2.2.0`, preserving the Firehose integration from `release/reth-1.x`.

**Context:**

- Main worktree is on `release/reth-1.x` (the authoritative Firehose implementation)
- `origin` = `paradigmxyz/reth` (upstream)
- `sf` = `streamingfast/reth` (our fork)
- Working branch `feature/update-to-reth-2.x` is already based on `release/reth-1.x`
- Goal: merge `v2.2.0` into this branch, resolve conflicts, validate, then push as `sf/release/reth-2.x`

## Dev Feedback

Branch `sf/v0.34.0` has been created on `streamingfast/evm`, finish work and ensure tests are working.

## Spec & Implementation

### Approach (Option B — Fresh branch from reth-1.x, merge v2.2.0)

Starting point is the clean `release/reth-1.x` Firehose implementation (already checked out in this worktree). We do a single merge of the upstream `v2.2.0` tag, resolve conflicts (scope limited to Firehose integration code), validate compilation and tests, then push as `sf/release/reth-2.x`.

**Conflict resolution strategy for Firehose files:**

- Accept upstream's structural/trait changes (BlockExecutor, BlockExecutionStrategyFactory, EvmConfig, revm Inspector)
- Re-apply SF's Firehose hooks (inspector, balance tracking, journal traversal, mapping logic)
- Reference: `git show release/reth-1.x:crates/firehose/src/<file>` for authoritative SF code

### What was done

The merge of `v2.2.0` is committed. Conflicts resolved:

**Non-firehose conflicts (all took upstream):**

- `.github/dependabot.yml` — upstream has more complete version with github-actions + cooldown
- `docs/vocs/vocs.config.ts` — version bump v1.11.3 → v2.2.0
- `Cargo.toml` — upstream dependency versions (alloy 2.0.4, revm 38.x, alloy-evm 0.34.0, tokio 1.51.1, reqwest 0.13, discv5 pinned to git); kept SF Firehose additions (firehose-tracer, reth-firehose, reth-firehose-tests, profile.dev override)
- `crates/tasks/src/runtime.rs` — upstream adds BAL streaming / prewarming rayon pools
- `crates/trie/trie/src/proof_v2/mod.rs` — upstream updates to V2 trie types
- `crates/engine/**`, `crates/node/builder/src/rpc.rs` — upstream additions

**Firehose API adaptations for alloy-evm 0.34.0 / revm-bytecode 10.0.0:**

- `executor.rs`: `commit_transaction` now returns `GasOutput` (not `Result<u64>`); `execute_transaction_with_commit_condition` closure now takes `&Self::Result` (not `&ExecutionResult`); `GasOutput` added to imports; `gas_used()` → `tx_gas_used()`
- `inspector.rs`: `Bytecode::Eip7702(eip)` enum pattern replaced with `code.eip7702_address()` method; `gas.spent()` → `gas.total_gas_spent()`
- `runner.rs`: `gas_used()` → `tx_gas_used()`; `commit_transaction` no longer returns `Result` so dropped `wrap_err_with`

**firehose-tests:** `ChainConfig::from_genesis` takes `alloy_genesis::Genesis` (1.x) but workspace now uses 2.0.4 — resolved by constructing `ChainConfig` fields manually.

**firehose-tracer:** pinned to `=5.0.0` (5.1.0 introduces `rbase64` which registers a conflicting `#[global_allocator]`).

### ⚠️ Known Issue: Missing alloy-evm patch for system calls

The SF fork maintained a patch to `alloy-evm` (`sf/v0.27.3` branch) that routed EIP-4788 and EIP-2935 system calls through the revm Inspector. This patch is not compatible with `alloy-evm v0.34.0`.

**Impact:** The `system_calls` field in Firehose blocks is now empty. Golden file tests fail because:

- Two events (ordinal 1 and 2: the system call begin/end) are missing
- All subsequent ordinals are offset by -2
- `system_calls: [...]` section is empty instead of containing EIP-4788/2935 calls

**Resolution needed:** The SF evm fork needs a `sf/v0.34.0` branch (based on `alloy-evm v0.34.0`) that applies the same system call routing patch. Once available, add to `[patch.crates-io]`:

```toml
alloy-evm = { git = "https://github.com/streamingfast/evm.git", branch = "sf/v0.34.0" }
```

The `[patch.crates-io]` section is already in `Cargo.toml` with a commented-out placeholder for this.

See upstream PR: https://github.com/alloy-rs/evm/pull/323

**Test status:**

- `cargo check --workspace` — ✅ clean
- `cargo nextest run -p reth-firehose` — ✅ 18/18 pass
- `cargo nextest run -p reth-firehose-tests` — ❌ 2/2 fail (golden file ordinal mismatch due to missing system call patch)

---

## State Tracker

**Last Updated:** 2026-05-12
**Current Step:** Review — all tests passing, ready for merge
**Status:** Complete. alloy-evm SF patch enabled; all Firehose tests pass.

| Step                                        | Status   | Notes                                                       |
| ------------------------------------------- | -------- | ----------------------------------------------------------- |
| Task file cleanup (Option B, reduce noise)  | Done     | Simplified, branch/target updated                           |
| Fetch v2.2.0 from origin                    | Done     | Tag fetched                                                 |
| Initiate merge `v2.2.0 --no-commit --no-ff` | Done     | 11 files conflicted                                         |
| Resolve all conflicts                       | Done     | All 11 resolved                                             |
| Fix Firehose API changes                    | Done     | executor, inspector, runner updated                         |
| Fix firehose-tests alloy-genesis mismatch   | Done     | ChainConfig built manually                                  |
| Pin firehose-tracer to =5.0.0               | Done     | Avoids rbase64 global allocator conflict                    |
| `cargo check --workspace` passes            | Done     | ✅ clean                                                    |
| Commit merge                                | Done     | `a72ef1e793`                                                |
| Commit Firehose API fixes                   | Done     | Included in same merge commit                               |
| `cargo nextest run -p reth-firehose`        | Done     | ✅ 18/18 pass                                               |
| Update alloy-evm SF fork for v0.34.0        | Done     | streamingfast/evm sf/v0.34.0 branch created by reviewer     |
| Enable alloy-evm patch in Cargo.toml        | Done     | Uncommented patch, committed `d696272cc0`                   |
| `cargo nextest run -p reth-firehose-tests`  | Done     | ✅ 2/2 pass (system_calls now populated correctly)          |

</content>
