//! Integration test framework for the Firehose tracer.
//!
//! Mirrors the upstream `streamingfast/go-ethereum` `TestFirehosePrestate` harness: each test
//! case is a folder containing a `prestate.json` (genesis + block context + RLP-encoded
//! transaction) and one or more `<model>/block.<num>.golden.bin` golden files (the expected
//! Firehose `Block` protobuf, binary-encoded).
//!
//! The framework loads the prestate, bootstraps a [`reth_chainspec::ChainSpec`] from the embedded
//! genesis, seeds a `CacheDB` from `genesis.alloc`, decodes the input as a single signed
//! transaction, and runs it through [`reth_firehose::run_wrapped_block`] with a caller-owned
//! [`firehose_tracer::Tracer`] whose writer is an in-memory `Vec<u8>`. The captured `FIRE BLOCK`
//! lines are parsed back into protobuf `Block` messages and compared against the goldens.

/// Prestate file loader and per-block test runner.
pub mod prestate;

pub use prestate::{
    assert_block_equals_golden, build_account_info, decode_hex, parse_fire_block_for, run_prestate,
    seed_cache_db, Prestate, RunOutcome, TraceContext,
};
