//! A `PulseChain` light-client data server. It reads the standard beacon endpoints that
//! `PulseChain` servers answer and serves the beacon light-client API from them. See `DESIGN.md`.
//!
//! [`upstream`] fetches blocks, states and heads with bounded requests. [`checkpoint`] builds the
//! bootstrap, finality and period answers at each finalized checkpoint, and [`head`] builds the
//! optimistic update at each head. [`answers`] holds what the server serves, after its own
//! light-client store has accepted it, and [`archive`] keeps the answers that must outlive a
//! restart. [`api`] serves them over HTTP, [`config`] reads the flags, and [`server`] starts it
//! all for one chain.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod answers;
pub mod api;
pub mod archive;
pub mod checkpoint;
pub mod config;
pub mod head;
pub mod server;
pub mod upstream;

#[cfg(test)]
mod fake;

use reth_pulsechain_forks::network::PulsechainBeacon;
use std::time::{SystemTime, UNIX_EPOCH};

/// `SECONDS_PER_SLOT` on every `PulseChain` network.
pub const SECONDS_PER_SLOT: u64 = 10;

/// Returns the wall-clock slot at `now`, plus one slot for clock drift: the newest signature slot
/// the self-check store accepts.
pub fn current_slot(pins: &PulsechainBeacon, now: SystemTime) -> u64 {
    let since_genesis = now.duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
    since_genesis.saturating_sub(pins.genesis_time) / SECONDS_PER_SLOT + 1
}
