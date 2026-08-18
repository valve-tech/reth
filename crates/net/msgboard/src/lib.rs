//! `PulseChain` msgboard P2P sub-protocol.
//!
//! This crate implements the `msg/1` devp2p satellite capability that
//! `PulseChain` nodes negotiate alongside `eth/68`.
//!
//! ## Architecture
//!
//! - [`MsgBoard`] — shared in-memory board state (chain window + message index)
//! - [`MsgboardProtocolHandler`] — reth `ProtocolHandler` that creates a
//!   [`MsgboardConnectionHandler`] for each peer connection
//! - [`MsgboardConnectionHandler`] — spawns a tokio task that drives the three-opcode gossip
//!   exchange for one peer

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Used via `#[serde(with = "alloy_serde::quantity")]` in `rpc_api.rs`. The
// `unused_crate_dependencies` lint can't see references inside attribute
// strings, so name the crate explicitly here.
use alloy_serde as _;

pub mod args;
pub mod block_filter;
pub mod board;
pub mod db;
pub mod index;
pub mod launch;
pub mod metrics;
mod pending;
pub mod protocol;
pub mod rpc;
pub mod rpc_api;

pub use args::MsgboardArgs;
pub use board::MsgBoard;
pub use launch::MsgboardLauncher;
pub use protocol::{
    MsgboardConnectionHandler, MsgboardProtocolHandler, MSG_CAPABILITY, MSG_PROTOCOL,
};
