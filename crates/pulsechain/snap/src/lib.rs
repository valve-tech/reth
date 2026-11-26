//! `snap/1` serving for `PulseChain` light clients.
//!
//! Light clients such as reth-lite read state on demand over `snap/1` and verify every answer
//! with Merkle proofs against a state root from their consensus client. Upstream reth speaks
//! only `snap/2` (EIP-8189), which drops the trie-node messages these clients use.
//!
//! This crate holds the `snap/1` pieces that upstream lacks:
//!
//! - [`message`]: the `snap/1` message set. Ids `0x00..=0x05` reuse the upstream message types, and
//!   `0x06`/`0x07` (`GetTrieNodes`/`TrieNodes`) are defined here.
//! - [`bytecodes`]: serving `GetByteCodes`, which needs no state root.
//! - [`trie_nodes`]: serving `GetTrieNodes` by walking proofs.
//! - [`ranges`]: serving `GetAccountRange` and `GetStorageRanges` from a state range provider.
//!
//! - [`server`] and [`protocol`]: admission control and the `RLPx` sub-protocol handler.
//!
//! The node crate adds the handler behind `--pulsechain.snap1`.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod backend;
pub mod bytecodes;
pub mod message;
pub mod protocol;
pub mod ranges;
pub mod server;
pub mod trie_nodes;

mod metrics;

#[cfg(test)]
mod provider_tests;
#[cfg(any(test, feature = "fuzzing"))]
#[cfg_attr(not(test), allow(dead_code))]
mod test_utils;

#[cfg(feature = "fuzzing")]
pub mod fuzz_api;

pub use backend::{ProviderBackend, RetainedRoot, RootLanes, Snap1Backend};
pub use bytecodes::{serve_byte_codes, MAX_BYTE_CODES_SERVE, SOFT_RESPONSE_LIMIT};
pub use message::{
    GetTrieNodesMessage, Snap1Error, Snap1Message, TrieNodePathSet, TrieNodesMessage,
    MAX_RANGE_PROOF_NODES, SNAP1_MESSAGE_COUNT, SNAP1_VERSION,
};
pub use protocol::{snap1_protocol, Snap1Connection, Snap1Handler};
pub use ranges::{
    serve_account_range, serve_storage_ranges, MAX_RANGE_TIME, MAX_STORAGE_RANGE_ACCOUNTS_SERVE,
    PROOF_RESERVE,
};
pub use server::{Lane, PeerId, Snap1Config, Snap1Server};
pub use trie_nodes::{
    compact_to_nibbles, serve_trie_nodes, serve_trie_nodes_with_clock, MAX_TRIE_NODE_LOOKUPS,
    MAX_TRIE_NODE_TIME,
};

// Re-exported so a backend can be written without depending on the wire and storage crates.
pub use reth_eth_wire_types::snap::{ByteCodesMessage, GetByteCodesMessage};
pub use reth_storage_api::{StateRangeProviderFactory, StateRangeView};
