//! `PulseChain` hardfork definitions and chain specs.
//!
//! This crate is the lowest-level `PulseChain` crate, intended to be a dependency
//! of both the EVM crate (`reth-pulsechain-evm`, Phase 3+) and the node crate
//! (`reth-pulsechain-node`). Placing hardfork constants and `ChainSpec` statics
//! here avoids a backwards dependency between evm → node.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod chainspec;
pub mod hardfork;
