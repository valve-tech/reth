//! `msgboard` RPC interface.
//!
//! Exposes the PulseChain `msg/1` board over JSON-RPC. All methods are
//! prefixed with `msgboard_` and the subscription fires on every new
//! accepted message.

use std::collections::HashMap;

use alloy_primitives::{Bytes, B256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

/// JSON-serializable representation of a validated msgboard message.
///
/// Mirrors erigon-pulse's `RPCPoWMsg`: all integer fields are encoded as
/// `0x`-prefixed hex strings (the Ethereum JSON-RPC "quantity" format), and
/// the field set matches `specs/02-msgboard.md` §3.4 exactly. This is the
/// shape returned by [`MsgboardApiServer::msgboard_get_message`] and
/// [`MsgboardApiServer::msgboard_content`], and emitted by the
/// `msgboard_subscribe` subscription.
///
/// `timestamp` is *not* part of this shape — erigon's RPC layer omits it,
/// and `CheckedPoWMsg::timestamp` is a server-side bookkeeping field that
/// stays inside the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MsgboardMsg {
    /// Encoding version (always 1 for `msg/1`).
    #[serde(with = "alloy_serde::quantity")]
    pub version: u8,
    /// Keccak-256 of the block when the message was submitted.
    pub block_hash: B256,
    /// Block number corresponding to `block_hash`.
    #[serde(with = "alloy_serde::quantity")]
    pub block_number: u64,
    /// PoW nonce found during mining.
    #[serde(with = "alloy_serde::quantity")]
    pub nonce: u64,
    /// Work multiplier used in the difficulty calculation.
    #[serde(with = "alloy_serde::quantity")]
    pub work_multiplier: u64,
    /// Work divisor used in the difficulty calculation.
    #[serde(with = "alloy_serde::quantity")]
    pub work_divisor: u64,
    /// Application-defined 32-byte category id. The protocol does not
    /// interpret this value; clients commonly use `keccak256(text)` but any
    /// 32-byte scheme is allowed (token addresses, EIP-712 domains, etc.).
    pub category: B256,
    /// Arbitrary message body.
    pub data: Bytes,
    /// SHA-256 PoW hash that identifies this message.
    pub hash: B256,
}

/// Board statistics returned by `msgboard_status`.
///
/// Field names and integer encoding match erigon-pulse's `BoardStatus`
/// (`count`, `size`, both hex-encoded). `headBlock` is a reth-only addition
/// — useful for clients that want the current chain head without making
/// a separate `eth_blockNumber` call. Erigon clients that ignore unknown
/// fields will not be affected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MsgboardStatus {
    /// Whether the msgboard is currently accepting messages.
    pub enabled: bool,
    /// Number of live messages currently held.
    #[serde(with = "alloy_serde::quantity")]
    pub count: u64,
    /// Total size in bytes of all message data fields.
    #[serde(with = "alloy_serde::quantity")]
    pub size: u64,
    /// Minimum accepted work multiplier.
    #[serde(with = "alloy_serde::quantity")]
    pub work_multiplier: u64,
    /// Minimum accepted work divisor.
    #[serde(with = "alloy_serde::quantity")]
    pub work_divisor: u64,
    /// Block number of the current chain head as seen by the board.
    /// **Reth extension** — not present in erigon-pulse's `BoardStatus`.
    #[serde(with = "alloy_serde::quantity")]
    pub head_block: u64,
}

/// Optional filter for `msgboard_content`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentFilter {
    /// Category to filter by. If `None`, returns all categories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<B256>,
    /// Minimum block number (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_block: Option<u64>,
    /// Maximum block number (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_block: Option<u64>,
}

/// Optional filter for `msgboard_subscribe`. Only one option for now.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewMessagesFilter {
    /// Category to filter by. If `None`, every accepted message is emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<B256>,
}

/// Msgboard API — `msgboard_*` namespace.
#[rpc(server, namespace = "msgboard")]
pub trait MsgboardApi {
    /// Submit a new message to the board.
    ///
    /// The single parameter is a `0x`-prefixed hex string carrying the
    /// **RLP-encoded `PoWMsg`** — matching erigon-pulse's
    /// `msgboard_addMessage` which takes `hexutility.Bytes`. The node decodes
    /// the RLP, verifies the `PoW`, and on success stores the message and
    /// announces it to connected peers; it returns the message's SHA-256
    /// `PoW` hash.
    ///
    /// Wire example:
    /// ```json
    /// {"jsonrpc":"2.0","method":"msgboard_addMessage","params":["0xf8…"],"id":1}
    /// ```
    #[method(name = "addMessage")]
    async fn msgboard_add_message(&self, input: Bytes) -> RpcResult<B256>;

    /// List all category hashes currently represented in the live board.
    #[method(name = "categories")]
    async fn msgboard_categories(&self) -> RpcResult<Vec<B256>>;

    /// Return live messages, optionally filtered by category and/or block range.
    ///
    /// The result is a map from category (lowercase `0x…` hex string) to the
    /// list of messages in that category, matching erigon-pulse's JSON-RPC
    /// shape. If a `category` filter is supplied, the map contains at most
    /// one entry; if no messages match, the map is empty.
    #[method(name = "content")]
    async fn msgboard_content(
        &self,
        filter: Option<ContentFilter>,
    ) -> RpcResult<HashMap<String, Vec<MsgboardMsg>>>;

    /// Look up a single message by its SHA-256 PoW hash.
    #[method(name = "getMessage")]
    async fn msgboard_get_message(&self, hash: B256) -> RpcResult<Option<MsgboardMsg>>;

    /// Return board statistics (current head block and message count).
    #[method(name = "status")]
    async fn msgboard_status(&self) -> RpcResult<MsgboardStatus>;

    /// Subscribe to new messages. Emits a [`MsgboardMsg`] for each new
    /// message accepted into the board.
    ///
    /// The first parameter must be the literal string `"newMessages"` (the
    /// only subscription kind currently supported), matching erigon-pulse's
    /// JSON-RPC shape `["newMessages", filter?]`. Pass an optional
    /// [`NewMessagesFilter`] as the second parameter to restrict notifications
    /// to a single category.
    #[subscription(
        name = "subscribe",
        unsubscribe = "unsubscribe",
        item = MsgboardMsg
    )]
    async fn msgboard_subscribe(
        &self,
        kind: String,
        filter: Option<NewMessagesFilter>,
    ) -> jsonrpsee::core::SubscriptionResult;
}

#[cfg(test)]
mod wire_shape_tests {
    //! Lock the JSON wire shape against erigon-pulse's RPC layer
    //! (`turbo/jsonrpc/msgboard_api.go`, `msgboard/pow_message.go`). Field
    //! names and `0x`-prefixed hex encoding must match byte-for-byte so that
    //! clients written against either implementation work against the other.

    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn status_serialises_with_erigon_field_names_and_hex_uints() {
        let s = MsgboardStatus {
            enabled: true,
            count: 0,
            size: 0,
            work_multiplier: 10_000,
            work_divisor: 1_000_000,
            head_block: 0x1234,
        };
        let v: Value = serde_json::to_value(&s).unwrap();
        assert_eq!(
            v,
            json!({
                "enabled": true,
                "count": "0x0",
                "size": "0x0",
                "workMultiplier": "0x2710",
                "workDivisor": "0xf4240",
                "headBlock": "0x1234",
            }),
        );
    }

    #[test]
    fn msg_serialises_with_erigon_field_names_and_no_timestamp() {
        let m = MsgboardMsg {
            version: 1,
            block_hash: B256::ZERO,
            block_number: 100,
            nonce: 42,
            work_multiplier: 10_000,
            work_divisor: 1_000_000,
            category: B256::ZERO,
            data: Bytes::from_static(&[0xab, 0xcd]),
            hash: B256::ZERO,
        };
        let v: Value = serde_json::to_value(&m).unwrap();
        // Hex on every uint field, matches erigon's `RPCPoWMsg`.
        assert_eq!(v["version"], "0x1");
        assert_eq!(v["blockNumber"], "0x64");
        assert_eq!(v["nonce"], "0x2a");
        assert_eq!(v["workMultiplier"], "0x2710");
        assert_eq!(v["workDivisor"], "0xf4240");
        assert_eq!(v["data"], "0xabcd");
        // No timestamp leak — erigon's RPCPoWMsg has no such field.
        assert!(v.get("timestamp").is_none(), "timestamp must not be exposed via RPC");
    }
}
