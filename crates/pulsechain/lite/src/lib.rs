//! `reth-lite`: a small `PulseChain` node that follows a beacon API for the head, fetches state on
//! demand and verifies state, code, bodies and receipts against that head's roots.
//!
//! It depends on no chain database and no node builder. It sizes its memory budgets to the memory
//! it finds; the README lists what it holds.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod backfill;
pub mod beacon;
pub mod call;
pub mod chain;
pub mod config;
pub mod exec;
#[cfg(test)]
pub(crate) mod fake_beacon;
#[cfg(feature = "fuzzing")]
pub mod fuzz_api;
pub mod hot_set;
pub mod light_client;
pub mod memory;
pub mod metrics;
pub mod net;
pub mod node;
pub mod payload;
pub mod rpc;
pub mod state;
pub mod store;
pub mod sync_committee_file;
#[cfg(test)]
pub(crate) mod testing;
pub mod upstream;
pub mod verify;

pub use reth_pulsechain_light_client::sync_committee;
