//! `msgboard_*` RPC method implementations.
//!
//! [`MsgboardApi`] wraps an `Arc<MsgBoard>` and implements
//! [`MsgboardApiServer`]. The subscription converts the board's
//! `tokio::sync::broadcast` channel into a `Stream` via `BroadcastStream`,
//! silently dropping lagged notifications.

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Bytes, B256};
use async_trait::async_trait;
use futures::{future::ready, StreamExt};
use jsonrpsee::{
    core::RpcResult, types::ErrorObjectOwned, PendingSubscriptionSink, SubscriptionMessage,
};
use reth_msgboard_types::{decode_validated_pow_msg, CheckedPoWMsg, MsgboardError};
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    board::MsgBoard,
    rpc_api::{ContentFilter, MsgboardApiServer, MsgboardMsg, MsgboardStatus, NewMessagesFilter},
};

/// Subscription kind discriminator. Matches erigon-pulse's
/// `msgboard_subscribe(["newMessages", filter?])` shape.
const SUBSCRIPTION_KIND_NEW_MESSAGES: &str = "newMessages";

/// `msgboard_*` API implementation.
#[derive(Debug, Clone)]
pub struct MsgboardApi {
    board: Arc<MsgBoard>,
}

impl MsgboardApi {
    /// Create a new instance backed by the given shared board.
    pub fn new(board: Arc<MsgBoard>) -> Self {
        Self { board }
    }
}

#[async_trait]
impl MsgboardApiServer for MsgboardApi {
    async fn msgboard_add_message(&self, input: Bytes) -> RpcResult<B256> {
        // Mirror erigon-pulse `PoWMsgFromRLP`: decode + validate at the RPC
        // boundary so the board's hot path can trust its inputs and the
        // validation error code is identical to erigon's.
        let msg = decode_validated_pow_msg(input.as_ref()).map_err(msgboard_error_to_rpc)?;

        match self.board.add_local_msg(msg) {
            Ok(checked) => Ok(checked.hash),
            Err(err) => Err(msgboard_error_to_rpc(err)),
        }
    }

    async fn msgboard_categories(&self) -> RpcResult<Vec<B256>> {
        Ok(self.board.categories())
    }

    async fn msgboard_content(
        &self,
        filter: Option<ContentFilter>,
    ) -> RpcResult<HashMap<String, Vec<MsgboardMsg>>> {
        let filter = filter.unwrap_or_default();
        let msgs = match filter.category {
            Some(cat) => {
                self.board.category_msgs_filtered(&cat, filter.from_block, filter.to_block)
            }
            None => self.board.all_msgs_filtered(filter.from_block, filter.to_block),
        };
        let mut grouped: HashMap<String, Vec<MsgboardMsg>> = HashMap::new();
        for m in &msgs {
            let rpc = to_rpc_msg(m);
            // Lowercase 0x-hex matches alloy's Display impl and erigon-pulse output.
            let key = rpc.category.to_string();
            grouped.entry(key).or_default().push(rpc);
        }
        Ok(grouped)
    }

    async fn msgboard_get_message(&self, hash: B256) -> RpcResult<Option<MsgboardMsg>> {
        Ok(self.board.get_message(&hash).as_ref().map(|m| to_rpc_msg(m.as_ref())))
    }

    async fn msgboard_status(&self) -> RpcResult<MsgboardStatus> {
        let (enabled, head_block, count, size, work_multiplier, work_divisor) = self.board.status();
        Ok(MsgboardStatus { enabled, count, size, work_multiplier, work_divisor, head_block })
    }

    async fn msgboard_subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: String,
        filter: Option<NewMessagesFilter>,
    ) -> jsonrpsee::core::SubscriptionResult {
        if kind != SUBSCRIPTION_KIND_NEW_MESSAGES {
            let err = ErrorObjectOwned::owned(
                -32602,
                format!("unsupported subscription kind: {kind:?}"),
                None::<()>,
            );
            pending.reject(err).await;
            return Ok(());
        }

        let category_filter = filter.and_then(|f| f.category);
        let sink = pending.accept().await?;
        let board = Arc::clone(&self.board);

        tokio::spawn(async move {
            let rx = board.subscribe();
            // `ready(result.ok())` is Unpin (unlike `async move` blocks),
            // which lets the FilterMap stream work inside `tokio::select!`.
            let mut stream = BroadcastStream::new(rx).filter_map(|result| ready(result.ok()));

            loop {
                tokio::select! {
                    _ = sink.closed() => break,
                    maybe_msg = stream.next() => {
                        let Some(checked) = maybe_msg else { break };
                        if let Some(want) = category_filter.as_ref() {
                            if &checked.msg.category != want {
                                continue;
                            }
                        }
                        let rpc_msg = to_rpc_msg(&checked);
                        let msg = match SubscriptionMessage::new(
                            sink.method_name(),
                            sink.subscription_id(),
                            &rpc_msg,
                        ) {
                            Ok(m) => m,
                            Err(err) => {
                                tracing::error!(
                                    target: "rpc::msgboard",
                                    %err,
                                    "failed to serialize subscription message"
                                );
                                break;
                            }
                        };
                        if sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

/// Map a [`MsgboardError`] to a JSON-RPC error with a code matching erigon-pulse.
///
/// `powmsg:` errors → `-32602` (InvalidParams, matching Go's `rpc.InvalidParamsError`).
/// `msgboard:` errors → `-32000` (default error code, matching Go's `defaultErrorCode`).
fn msgboard_error_to_rpc(err: MsgboardError) -> ErrorObjectOwned {
    let code = match &err {
        // powmsg: decode + validation errors → InvalidParams
        MsgboardError::InvalidVersion |
        MsgboardError::InvalidBlockHash |
        MsgboardError::InvalidNonce |
        MsgboardError::InvalidDifficulty |
        MsgboardError::InvalidData |
        MsgboardError::InvalidWork |
        MsgboardError::Rlp(_) |
        MsgboardError::MalformedIdList => -32602,
        // msgboard: board-level errors → default
        _ => -32000,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

/// Convert a [`CheckedPoWMsg`] to the JSON-RPC response type.
///
/// The server-side `timestamp` is intentionally omitted — erigon-pulse's
/// `RPCPoWMsg` has no equivalent field, and clients depend on the spec
/// shape, not on internal bookkeeping.
fn to_rpc_msg(m: &CheckedPoWMsg) -> MsgboardMsg {
    MsgboardMsg {
        version: m.msg.version,
        block_hash: m.msg.block_hash,
        block_number: m.block_number,
        nonce: m.msg.nonce,
        work_multiplier: m.msg.work_multiplier,
        work_divisor: m.msg.work_divisor,
        category: m.msg.category,
        data: m.msg.data.clone(),
        hash: m.hash,
    }
}

#[cfg(test)]
mod tests {
    //! These drive the *registered* `RpcModule` rather than calling the impl
    //! methods directly, so method names, parameter deserialization, result
    //! serialization, and error codes are all exercised — the same path a real
    //! client takes, minus the socket.

    use alloy_primitives::Bytes;
    use jsonrpsee::{core::server::MethodsError, RpcModule};
    use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};
    use serde_json::{json, Value};

    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn block_hash_one() -> B256 {
        B256::repeat_byte(0x01)
    }

    fn category(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    /// Config with trivial `PoW` so tests mine a valid nonce in a few tries.
    fn easy_cfg() -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: 1,
            work_divisor: 1_000_000,
            size_limit: 8 * 1024,
            count_limit: 10_000,
            block_range: 120,
            stale_block_buffer: 3,
            gossip_disabled: false,
        }
    }

    fn pow_msg(nonce: u64, data: &[u8], cat: B256) -> PoWMsg {
        PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: cat,
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Mine a valid message for `(data, cat)` anchored at `block`.
    fn mined(data: &[u8], cat: B256, block: u64) -> PoWMsg {
        for n in 1u64..=1_000_000 {
            if pow_msg(n, data, cat).to_checked(block, 0).is_ok() {
                return pow_msg(n, data, cat);
            }
        }
        panic!("no valid nonce found for data={data:?}");
    }

    /// Ready board with `block_hash_one` registered at `height`.
    fn ready_board(height: u64) -> Arc<MsgBoard> {
        let board = Arc::new(MsgBoard::new(easy_cfg()));
        board.set_ready();
        board.set_head(height, block_hash_one());
        board
    }

    fn module(board: Arc<MsgBoard>) -> RpcModule<MsgboardApi> {
        MsgboardApi::new(board).into_rpc()
    }

    /// RLP-encode a `PoWMsg` the way a client submits it to `addMessage`.
    fn rlp_hex(msg: &PoWMsg) -> String {
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(msg, &mut buf);
        format!("0x{}", alloy_primitives::hex::encode(buf))
    }

    /// Error code from a failed `call`, or panic if the call succeeded.
    async fn call_err_code(m: &RpcModule<MsgboardApi>, method: &str, params: Vec<Value>) -> i32 {
        match m.call::<_, Value>(method, params).await {
            Err(MethodsError::JsonRpc(e)) => e.code(),
            other => panic!("expected a JSON-RPC error from {method}, got {other:?}"),
        }
    }

    // ── status ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_reports_head_count_and_size() {
        let board = ready_board(10);
        board.add_local_msg(mined(&[1, 2, 3], category(0xCA), 10)).unwrap();
        let m = module(board);

        let v: Value = m.call("msgboard_status", rpc_params_none()).await.unwrap();
        assert_eq!(v["enabled"], json!(true));
        assert_eq!(v["count"], json!("0x1"));
        assert_eq!(v["size"], json!("0x3")); // 3 data bytes
        assert_eq!(v["headBlock"], json!("0xa"));
        assert_eq!(v["workMultiplier"], json!("0x1"));
        assert_eq!(v["workDivisor"], json!("0xf4240"));
    }

    #[tokio::test]
    async fn status_reports_not_enabled_before_the_board_is_ready() {
        let board = Arc::new(MsgBoard::new(easy_cfg()));
        let m = module(board);
        let v: Value = m.call("msgboard_status", rpc_params_none()).await.unwrap();
        assert_eq!(v["enabled"], json!(false));
        assert_eq!(v["count"], json!("0x0"));
    }

    // ── addMessage ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn add_message_accepts_rlp_hex_and_returns_the_pow_hash() {
        let board = ready_board(10);
        let msg = mined(&[7, 7], category(0xCA), 10);
        let expected = msg.clone().to_checked(10, 0).unwrap().hash;
        let m = module(Arc::clone(&board));

        let hash: B256 = m.call("msgboard_addMessage", vec![rlp_hex(&msg)]).await.unwrap();
        assert_eq!(hash, expected);
        assert!(board.get_message(&hash).is_some(), "message should be on the board");
    }

    /// Decode/validation failures map to `-32602` (`InvalidParams`), matching
    /// erigon's `rpc.InvalidParamsError` for `powmsg:` errors.
    #[tokio::test]
    async fn add_message_rejects_undecodable_rlp_with_invalid_params() {
        let m = module(ready_board(10));
        let code = call_err_code(&m, "msgboard_addMessage", vec![json!("0xdeadbeef")]).await;
        assert_eq!(code, -32602);
    }

    #[tokio::test]
    async fn add_message_rejects_a_structurally_invalid_message_with_invalid_params() {
        // nonce = 0 is rejected by `validate()` at the decode boundary.
        let m = module(ready_board(10));
        let bad = pow_msg(0, &[1], category(0xCA));
        let code = call_err_code(&m, "msgboard_addMessage", vec![json!(rlp_hex(&bad))]).await;
        assert_eq!(code, -32602);
    }

    /// Board-level rejections map to `-32000`, matching erigon's
    /// `defaultErrorCode` for `msgboard:` errors.
    #[tokio::test]
    async fn add_message_on_a_not_ready_board_returns_the_default_error_code() {
        let board = Arc::new(MsgBoard::new(easy_cfg()));
        let m = module(board);
        let msg = mined(&[1], category(0xCA), 0);
        let code = call_err_code(&m, "msgboard_addMessage", vec![json!(rlp_hex(&msg))]).await;
        assert_eq!(code, -32000);
    }

    #[tokio::test]
    async fn add_message_with_an_unknown_block_hash_returns_the_default_error_code() {
        let board = ready_board(10);
        let mut msg = mined(&[1], category(0xCA), 10);
        msg.block_hash = B256::repeat_byte(0xEE); // never registered via set_head
        let m = module(board);
        let code = call_err_code(&m, "msgboard_addMessage", vec![json!(rlp_hex(&msg))]).await;
        assert_eq!(code, -32000);
    }

    #[tokio::test]
    async fn add_message_rejects_a_duplicate() {
        let board = ready_board(10);
        let msg = mined(&[9], category(0xCA), 10);
        let m = module(board);
        let _: B256 = m.call("msgboard_addMessage", vec![rlp_hex(&msg)]).await.unwrap();
        let code = call_err_code(&m, "msgboard_addMessage", vec![json!(rlp_hex(&msg))]).await;
        assert_eq!(code, -32000);
    }

    // ── categories ───────────────────────────────────────────────────────────

    /// `specs/02-msgboard.md` §9.2: the category list is sorted. The index
    /// stores categories in a `HashMap`, so without an explicit sort this
    /// returns a different order on every run.
    /// Uses 16 categories rather than a handful: `HashMap` key order is
    /// effectively random per process, so with only 3–4 keys an unsorted
    /// implementation would still land on sorted order by chance a few percent
    /// of runs. At 16 keys that probability is 1/16!, so this fails reliably if
    /// the sort is dropped.
    #[tokio::test]
    async fn categories_are_returned_sorted() {
        let board = ready_board(10);
        let bytes: [u8; 16] = [
            0xEE, 0x11, 0x99, 0x44, 0x03, 0xC7, 0x5A, 0xF0, 0x22, 0x8B, 0x6D, 0x31, 0xAC, 0x77,
            0x08, 0xD4,
        ];
        for (i, byte) in bytes.into_iter().enumerate() {
            board.add_local_msg(mined(&[i as u8], category(byte), 10)).unwrap();
        }
        let m = module(board);

        let cats: Vec<B256> = m.call("msgboard_categories", rpc_params_none()).await.unwrap();
        assert_eq!(cats.len(), 16);

        let mut expected: Vec<B256> = bytes.into_iter().map(category).collect();
        expected.sort_unstable();
        assert_eq!(cats, expected, "categories must be sorted ascending");
    }

    #[tokio::test]
    async fn categories_is_empty_on_an_empty_board() {
        let m = module(ready_board(10));
        let cats: Vec<B256> = m.call("msgboard_categories", rpc_params_none()).await.unwrap();
        assert!(cats.is_empty());
    }

    // ── content ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn content_groups_all_messages_by_category() {
        let board = ready_board(10);
        board.add_local_msg(mined(&[1], category(0xAA), 10)).unwrap();
        board.add_local_msg(mined(&[2], category(0xAA), 10)).unwrap();
        board.add_local_msg(mined(&[3], category(0xBB), 10)).unwrap();
        let m = module(board);

        let v: Value = m.call("msgboard_content", rpc_params_none()).await.unwrap();
        let map = v.as_object().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[&category(0xAA).to_string()].as_array().unwrap().len(), 2);
        assert_eq!(map[&category(0xBB).to_string()].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn content_category_filter_returns_only_that_category() {
        let board = ready_board(10);
        board.add_local_msg(mined(&[1], category(0xAA), 10)).unwrap();
        board.add_local_msg(mined(&[2], category(0xBB), 10)).unwrap();
        let m = module(board);

        let v: Value =
            m.call("msgboard_content", vec![json!({"category": category(0xAA)})]).await.unwrap();
        let map = v.as_object().unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&category(0xAA).to_string()));
    }

    #[tokio::test]
    async fn content_unknown_category_returns_an_empty_map() {
        let board = ready_board(10);
        board.add_local_msg(mined(&[1], category(0xAA), 10)).unwrap();
        let m = module(board);

        let v: Value =
            m.call("msgboard_content", vec![json!({"category": category(0xFF)})]).await.unwrap();
        assert!(v.as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn content_block_range_filter_is_inclusive_on_both_ends() {
        let board = ready_board(30);
        // Register several block hashes so messages can anchor to them.
        for h in [10u64, 20, 30] {
            board.set_head(h, B256::repeat_byte(h as u8));
        }
        // Re-register the window head last so all three stay in bounds.
        board.set_head(30, B256::repeat_byte(30));

        for h in [10u64, 20, 30] {
            let mut msg = mined(&[h as u8], category(0xAA), h);
            msg.block_hash = B256::repeat_byte(h as u8);
            // Re-mine against the new block hash.
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let mut c = msg.clone();
                    c.nonce = n;
                    c.clone().to_checked(h, 0).is_ok().then_some(c)
                })
                .expect("nonce");
            board.add_local_msg(msg).unwrap();
        }
        let m = module(board);

        let count = |v: &Value| {
            v.as_object().unwrap().values().map(|a| a.as_array().unwrap().len()).sum::<usize>()
        };

        let all: Value = m.call("msgboard_content", rpc_params_none()).await.unwrap();
        assert_eq!(count(&all), 3);

        let mid: Value = m
            .call("msgboard_content", vec![json!({"fromBlock": 20, "toBlock": 20})])
            .await
            .unwrap();
        assert_eq!(count(&mid), 1);

        let from: Value = m.call("msgboard_content", vec![json!({"fromBlock": 20})]).await.unwrap();
        assert_eq!(count(&from), 2);

        let to: Value = m.call("msgboard_content", vec![json!({"toBlock": 20})]).await.unwrap();
        assert_eq!(count(&to), 2);
    }

    /// The category path used to iterate a `HashMap`'s values, which yields an
    /// arbitrary order. Asserting only that repeated calls agree does **not**
    /// catch that: `HashMap` iteration is stable within a process for an
    /// unmodified map, so a regressed implementation still returns a consistent
    /// (but wrong, and node-dependent) order. This pins the order against the
    /// board's actual precedence order instead, which is the real contract.
    #[tokio::test]
    async fn content_returns_messages_in_board_precedence_order() {
        let board = ready_board(10);
        for i in 0..12u8 {
            board.add_local_msg(mined(&[i], category(0xAA), 10)).unwrap();
        }
        let expected: Vec<B256> = board.all_messages().iter().map(|m| m.hash).collect();
        let m = module(board);

        let v: Value =
            m.call("msgboard_content", vec![json!({"category": category(0xAA)})]).await.unwrap();
        let got: Vec<B256> = v[&category(0xAA).to_string()]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m["hash"].clone()).unwrap())
            .collect();

        assert_eq!(got, expected, "content must follow board precedence order");
    }

    /// The category-filtered path and the unfiltered path must agree on order;
    /// they are different code paths over the same board.
    #[tokio::test]
    async fn content_category_order_matches_the_unfiltered_order() {
        let board = ready_board(10);
        for i in 0..10u8 {
            board.add_local_msg(mined(&[i], category(0xAA), 10)).unwrap();
        }
        let m = module(board);
        let key = category(0xAA).to_string();

        let filtered: Value =
            m.call("msgboard_content", vec![json!({"category": category(0xAA)})]).await.unwrap();
        let unfiltered: Value = m.call("msgboard_content", rpc_params_none()).await.unwrap();

        assert_eq!(filtered[&key], unfiltered[&key]);
    }

    // ── getMessage ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_message_returns_the_message_for_a_known_hash() {
        let board = ready_board(10);
        let checked = board.add_local_msg(mined(&[4, 2], category(0xCA), 10)).unwrap();
        let m = module(board);

        let v: Value = m.call("msgboard_getMessage", vec![checked.hash]).await.unwrap();
        assert_eq!(v["hash"], json!(checked.hash));
        assert_eq!(v["data"], json!("0x0402"));
        assert_eq!(v["blockNumber"], json!("0xa"));
        assert!(v.get("timestamp").is_none(), "timestamp must not leak through RPC");
    }

    #[tokio::test]
    async fn get_message_returns_null_for_an_unknown_hash() {
        let m = module(ready_board(10));
        let v: Value = m.call("msgboard_getMessage", vec![B256::repeat_byte(0xAB)]).await.unwrap();
        assert_eq!(v, Value::Null);
    }

    // ── subscribe ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn subscribe_rejects_an_unknown_subscription_kind() {
        let m = module(ready_board(10));
        let res = m.subscribe_unbounded("msgboard_subscribe", vec!["somethingElse"]).await;
        assert!(res.is_err(), "unknown subscription kind must be rejected");
    }

    #[tokio::test]
    async fn subscribe_emits_newly_accepted_messages() {
        let board = ready_board(10);
        let m = module(Arc::clone(&board));

        let mut sub =
            m.subscribe_unbounded("msgboard_subscribe", vec!["newMessages"]).await.unwrap();

        let checked = board.add_local_msg(mined(&[5], category(0xCA), 10)).unwrap();

        let (got, _id) =
            sub.next::<MsgboardMsg>().await.expect("subscription yielded nothing").unwrap();
        assert_eq!(got.hash, checked.hash);
        assert_eq!(got.block_number, 10);
    }

    #[tokio::test]
    async fn subscribe_category_filter_suppresses_other_categories() {
        let board = ready_board(10);
        let m = module(Arc::clone(&board));

        let mut sub = m
            .subscribe_unbounded(
                "msgboard_subscribe",
                vec![json!("newMessages"), json!({"category": category(0xBB)})],
            )
            .await
            .unwrap();

        // Non-matching category first — must not be delivered.
        board.add_local_msg(mined(&[1], category(0xAA), 10)).unwrap();
        // Matching category second — must be the first thing we see.
        let wanted = board.add_local_msg(mined(&[2], category(0xBB), 10)).unwrap();

        let (got, _id) =
            sub.next::<MsgboardMsg>().await.expect("subscription yielded nothing").unwrap();
        assert_eq!(got.hash, wanted.hash, "filtered-out category leaked through");
        assert_eq!(got.category, category(0xBB));
    }

    /// `jsonrpsee` needs a concrete type for a no-params call; `Vec<Value>`
    /// serializes an empty positional list, which is what a client sends.
    fn rpc_params_none() -> Vec<Value> {
        Vec::new()
    }
}
