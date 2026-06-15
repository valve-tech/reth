# Open Up reth-firehose-tests for Reuse in Base

mode: feature
state: review
root_git: .
worktree: .worktrees/feature/open-up-reth-firehose-tests
branch: feature/open-up-reth-firehose-tests
target_branch: firehose/1.x

> **Resume protocol:** read **Dev Feedback** and the **State Tracker** below first, then jump to the
> step marked `Current`. Ensure that you are in the correct worktree and branch according to preamble here. Update current with Developer feedback and update the tracker after every meaningful change.
> Do not mutate completed steps; append a new entry instead.

---

## Initial Description

### Part 1 — Changes to `reth-firehose-tests` (upstream PR to `streamingfast/reth`)

#### What to expose

The following items in `src/prestate.rs` are currently private but are entirely generic (no Ethereum-specific types). They must be made `pub` so `base-firehose-tests` can import them:

| Item                            | Current visibility    | Change                                                    |
| ------------------------------- | --------------------- | --------------------------------------------------------- |
| `RunOutcome` struct             | `pub` ✓               | Already public — no change needed                         |
| `Prestate` struct               | `struct` (private)    | Make `pub`                                                |
| `TraceContext` struct           | `struct` (private)    | Make `pub`                                                |
| `seed_cache_db` fn              | `fn` (private)        | Make `pub`                                                |
| `build_account_info` fn         | `fn` (private)        | Make `pub`                                                |
| `parse_fire_block_for` fn       | `fn` (private)        | Make `pub`                                                |
| `assert_block_equals_golden` fn | `pub` ✓               | Already public — no change needed                         |
| `decode_hex` fn                 | `fn` (private)        | Make `pub`                                                |
| serde helpers module `private`  | private `mod private` | Make `pub mod serde_helpers` (or `pub` items re-exported) |

**Important:** `Prestate` and `TraceContext` use serde `#[serde(deserialize_with = "...")]` referencing local private functions. Once the module is made public, the referenced deserializer functions must also be public (or the private module re-structured so they are callable from outside).

#### Recommended approach for serde helpers

Instead of exposing `deser_u64_str` / `deser_opt_u128_str` / `deser_opt_u256_str` as bare pub functions (which users normally don't call directly), move them into a `pub mod serde_helpers` submodule and re-export from `lib.rs`. The internal `private` module (`parse_decimal_or_hex_u128`) stays private since it is only called by the serde helpers.

Because `Prestate` and `TraceContext` carry `#[serde(deserialize_with = ...)]` attributes that reference these functions by path, the deserializer functions need to be accessible. Since they are referenced in attribute macros, they need to be in scope as `crate::prestate::deser_u64_str` etc. — simply keeping them as `pub fn` in `prestate.rs` (rather than `fn`) is sufficient. The `private` inner module for `parse_decimal_or_hex_u128` can remain private.

#### OP-specific `TraceContext` extension

`base-firehose-tests` may need additional fields in the block context for OP Stack (e.g., `prevRandao`/`mixHash`). Rather than modifying the shared `TraceContext` with OP-specific optional fields, the recommended approach is:

- Keep `reth-firehose-tests`'s `TraceContext` as is (the common Ethereum fields)
- In `base-firehose-tests`'s `src/prestate.rs`, define a separate `OpTraceContext` struct that **contains** a `TraceContext` (via `#[serde(flatten)]`) plus any OP-specific optional fields

This avoids polluting the Ethereum-centric `TraceContext` with OP fields.

#### `lib.rs` changes in `reth-firehose-tests`

Add re-exports of the newly-public items following AGENTS.md conventions:

```rust
// existing
pub mod prestate;
pub use prestate::{assert_block_equals_golden, run_prestate, RunOutcome};

// new re-exports
pub use prestate::{
    Prestate, TraceContext,
    seed_cache_db, build_account_info,
    parse_fire_block_for, decode_hex,
};
```

## Dev Feedback

## Spec & Implementation

### Changes made

**`crates/firehose-tests/src/prestate.rs`:**
- `Prestate` struct → `pub struct Prestate` with all fields made `pub` and documented
- `TraceContext` struct → `pub struct TraceContext` with all fields made `pub` and documented
- `seed_cache_db` fn → `pub fn seed_cache_db` with doc comment
- `build_account_info` fn → `pub fn build_account_info` with doc comment
- `parse_fire_block_for` fn → `pub fn parse_fire_block_for` (already had doc comment)
- `decode_hex` fn → `pub fn decode_hex` with doc comment
- `deser_u64_str`, `deser_opt_u128_str`, `deser_opt_u256_str` → all made `pub fn` with doc comments
- The inner `mod private` remains private (only contains `parse_decimal_or_hex_u128` and the `de_*` helpers called by the public serde functions)

**`crates/firehose-tests/src/lib.rs`:**
- Added re-exports: `Prestate`, `TraceContext`, `seed_cache_db`, `build_account_info`, `parse_fire_block_for`, `decode_hex`

## State Tracker

**Last Updated:** 2026-05-13
**Current Step:** Step 2 — Implementation complete, ready for review
**Status:** All items made public, documented, compiles clean (no warnings), formatted
