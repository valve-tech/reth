//! `msgboard_*` RPC method implementations.
//!
//! [`MsgboardApi`] wraps an `Arc<MsgBoard>` and implements
//! [`MsgboardApiServer`]. The subscription converts the board's
//! `tokio::sync::broadcast` channel into a `Stream` via `BroadcastStream`,
//! silently dropping lagged notifications.

use std::{collections::BTreeMap, sync::Arc};

use alloy_primitives::{Bytes, B256};
use async_trait::async_trait;
use futures::{future::ready, StreamExt};
use jsonrpsee::{
    core::RpcResult, types::ErrorObjectOwned, PendingSubscriptionSink, ResponsePayload,
    SubscriptionMessage,
};
use reth_msgboard_types::{decode_validated_pow_msg, CheckedPoWMsg, MsgboardError};
use serde::Serialize;
use serde_json::value::RawValue;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    board::MsgBoard,
    index::IndexPage,
    metrics::MsgboardMetrics,
    rpc_api::{
        ContentFilter, ContentPage, ContentPageRequest, MsgboardApiServer, MsgboardMsg,
        MsgboardStatus, NewMessagesFilter, MSGBOARD_CONTENT_PAGE_MAX_LIMIT,
    },
};

/// Subscription kinds that `msgboard_subscribe` accepts.
///
/// Erigon-pulse registers the subscription as its Go method `Messages`, and
/// `formatName` in its `rpc` package lower-cases the first letter, so
/// erigon's wire name is `"messages"`. `"newMessages"` is the name in
/// erigon's doc comment and reth's older name; reth keeps it for clients
/// written against it.
const SUBSCRIPTION_KINDS: [&str; 2] = ["messages", "newMessages"];

/// Holds the live-subscription gauge up for as long as a subscription runs.
///
/// A guard rather than a pair of calls around the loop, because the loop has
/// four exits — a closed sink, an exhausted stream, a serialisation failure and
/// a send failure — and a panic in the spawned task is a fifth. `Drop` covers
/// all five; a decrement written after the loop covers four.
#[derive(Debug)]
pub struct SubscriptionGuard {
    metrics: MsgboardMetrics,
}

impl SubscriptionGuard {
    /// Open a subscription: raise the gauge and count the open.
    pub fn new(metrics: MsgboardMetrics) -> Self {
        metrics.rpc_subscriptions.increment(1.0);
        metrics.rpc_subscriptions_opened.increment(1);
        Self { metrics }
    }
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.metrics.rpc_subscriptions.decrement(1.0);
        self.metrics.rpc_subscriptions_closed.increment(1);
    }
}

/// `msgboard_*` API implementation.
#[derive(Debug, Clone)]
pub struct MsgboardApi {
    board: Arc<MsgBoard>,
    /// Bounds concurrent `msgboard_content` responses; see
    /// [`CONTENT_CONCURRENT_BUILDS`].
    content_permits: Arc<Semaphore>,
    /// Bounds concurrent `msgboard_contentPage` responses; see
    /// [`CONTENT_PAGE_CONCURRENT_BUILDS`].
    page_permits: Arc<Semaphore>,
    /// Bounds concurrent `msgboard_addMessage` verifications; see
    /// [`ADD_MESSAGE_CONCURRENT_VERIFIES`].
    add_permits: Arc<Semaphore>,
    #[cfg(test)]
    probe: Arc<tests::BuildProbe>,
}

impl MsgboardApi {
    /// Create a new instance backed by the given shared board.
    pub fn new(board: Arc<MsgBoard>) -> Self {
        Self {
            board,
            content_permits: Arc::new(Semaphore::new(CONTENT_CONCURRENT_BUILDS)),
            page_permits: Arc::new(Semaphore::new(CONTENT_PAGE_CONCURRENT_BUILDS)),
            add_permits: Arc::new(Semaphore::new(ADD_MESSAGE_CONCURRENT_VERIFIES)),
            #[cfg(test)]
            probe: Default::default(),
        }
    }

    /// Waits for one of `permits`, then runs `f` on the blocking pool and
    /// serialises its result there.
    ///
    /// A full default board is about 80 MB of `data` and 167 MB of JSON, and
    /// building it takes seconds. The blocking pool does the snapshot, the
    /// deep copy and the hex serialisation: the handler returns
    /// pre-serialised JSON, so jsonrpsee has nothing left to serialise on the
    /// runtime worker.
    ///
    /// The permit lives until jsonrpsee reports the response processed, not
    /// only until the build ends. jsonrpsee copies the JSON into its own
    /// response buffer, and that copy lives until the transport takes it. On
    /// `WebSocket` and IPC, the report comes when the response enters the
    /// connection's send queue. On HTTP, it comes when jsonrpsee hands the
    /// response to the HTTP layer. After that point the transport owns the
    /// bytes, and the permit does not cover them.
    async fn build<T: Serialize>(
        &self,
        permits: &Arc<Semaphore>,
        method: &'static str,
        f: impl FnOnce(&MsgBoard) -> T + Send + 'static,
    ) -> ResponsePayload<'static, Box<RawValue>> {
        let permit = match Arc::clone(permits).acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => {
                return ResponsePayload::error(internal_error(format!("{method} permit: {err}")))
            }
        };
        #[cfg(test)]
        let probe = Arc::clone(&self.probe);
        let board = Arc::clone(&self.board);

        // The permit moves into the blocking task and comes back with the
        // result, so a build that outlives a disconnected caller still holds
        // it until the build ends.
        let built = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let _guard = probe.enter();
            (permit, serde_json::value::to_raw_value(&f(&board)))
        })
        .await;
        let (permit, json) = match built {
            Ok(built) => built,
            Err(err) => {
                return ResponsePayload::error(internal_error(format!(
                    "{method} task failed: {err}"
                )))
            }
        };
        let json = match json {
            Ok(json) => json,
            Err(err) => {
                return ResponsePayload::error(internal_error(format!(
                    "{method} serialisation failed: {err}"
                )))
            }
        };

        let (payload, processed) = ResponsePayload::success(json).notify_on_completion();
        // `processed` also resolves, with an error, when jsonrpsee drops the
        // response unsent, so the permit always comes back.
        tokio::spawn(async move {
            let _ = processed.await;
            drop(permit);
        });
        payload
    }
}

/// Most `msgboard_content` responses the node holds at once.
///
/// One full default board holds about 80 MB of copied `data` and 167 MB of
/// JSON while it is built, so unbounded callers could hold gigabytes. A call
/// past this bound waits for a permit. A caller that disconnects while it
/// waits drops the handler future, and with it the wait, so nothing is built.
/// A permit covers the build and jsonrpsee's copy of the response until the
/// transport takes it; see [`MsgboardApi::build`].
pub const CONTENT_CONCURRENT_BUILDS: usize = 2;

/// Most `msgboard_contentPage` responses the node holds at once.
///
/// A page holds at most [`MSGBOARD_CONTENT_PAGE_MAX_LIMIT`] messages, about
/// 17 MB of JSON at the default 8 KiB size limit. These permits are separate
/// from [`CONTENT_CONCURRENT_BUILDS`], so callers that loop full-board builds
/// cannot starve a pager.
pub const CONTENT_PAGE_CONCURRENT_BUILDS: usize = 4;

/// Most `msgboard_addMessage` verifications the node runs at once.
///
/// Each call takes a thread from tokio's shared blocking pool (512 threads by
/// default) and then the board mutex. Without a cap, a flood of calls could
/// fill that pool with threads that wait on one lock, and starve every other
/// blocking task in the node. Eight is about one per core on the fleet's
/// boxes. A call past the cap waits for a permit before it takes a thread, so
/// a caller that disconnects while it waits costs nothing.
pub const ADD_MESSAGE_CONCURRENT_VERIFIES: usize = 8;

#[async_trait]
impl MsgboardApiServer for MsgboardApi {
    async fn msgboard_add_message(&self, input: Bytes) -> RpcResult<B256> {
        // Mirror erigon-pulse `PoWMsgFromRLP`: decode + validate at the RPC
        // boundary so the board's hot path can trust its inputs and the
        // validation error code is identical to erigon's. The `PoW` check is
        // a secp256k1 scalar multiplication, so it runs on the blocking pool,
        // not on the runtime worker, under `add_permits`.
        let permit = Arc::clone(&self.add_permits)
            .acquire_owned()
            .await
            .map_err(|err| internal_error(format!("msgboard_addMessage permit: {err}")))?;
        #[cfg(test)]
        let probe = Arc::clone(&self.probe);
        let board = Arc::clone(&self.board);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            let _guard = probe.enter_verify();
            let msg = decode_validated_pow_msg(input.as_ref())?;
            board.add_local_msg(msg).map(|checked| checked.hash)
        })
        .await
        .map_err(|err| internal_error(format!("msgboard_addMessage task failed: {err}")))?
        .map_err(msgboard_error_to_rpc)
    }

    async fn msgboard_categories(&self) -> RpcResult<Vec<B256>> {
        Ok(self.board.categories())
    }

    async fn msgboard_content(
        &self,
        filter: Option<ContentFilter>,
    ) -> ResponsePayload<'static, Box<RawValue>> {
        let filter = filter.unwrap_or_default();
        if filter.after.is_some() {
            return ResponsePayload::error(invalid_params(
                "msgboard_content has no `after` cursor; page with msgboard_contentPage",
            ));
        }
        if filter.limit == Some(0) {
            return ResponsePayload::error(invalid_params(
                "msgboard_content: `limit` must be at least 1",
            ));
        }
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);
        let ContentFilter { category, from_block, to_block, .. } = filter;
        self.build(&self.content_permits, "msgboard_content", move |board| {
            let msgs = matching(board, category, from_block, to_block);
            group_by_category(msgs.iter().skip(offset).take(limit))
        })
        .await
    }

    async fn msgboard_content_page(
        &self,
        request: ContentPageRequest,
    ) -> ResponsePayload<'static, Box<RawValue>> {
        let ContentPageRequest { limit, after, category, from_block, to_block } = request;
        if limit == 0 || limit > MSGBOARD_CONTENT_PAGE_MAX_LIMIT {
            return ResponsePayload::error(invalid_params(format!(
                "msgboard_contentPage: `limit` must be from 1 to \
                 {MSGBOARD_CONTENT_PAGE_MAX_LIMIT}, got {limit}"
            )));
        }

        self.build(&self.page_permits, "msgboard_contentPage", move |board| {
            // A hash never changes and every replica computes the same one,
            // so inserts and evictions cannot shift a message across the
            // cursor.
            let IndexPage { msgs, next, .. } =
                board.content_page(category.as_ref(), from_block, to_block, after, limit);
            ContentPage { content: group_by_category(msgs.iter()), next }
        })
        .await
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
        if !SUBSCRIPTION_KINDS.contains(&kind.as_str()) {
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
        // Taken after `accept`, so a rejected subscription never counts.
        let subscription = SubscriptionGuard::new(self.board.metrics());

        tokio::spawn(async move {
            // Moved into the task so the gauge falls when the task ends,
            // however it ends.
            let _subscription = subscription;
            let rx = board.subscribe();
            // `ready(result.ok())` is Unpin (unlike `async move` blocks),
            // which lets the FilterMap stream work inside `tokio::select!`.
            let mut stream = BroadcastStream::new(rx).filter_map(|result| ready(result.ok()));

            loop {
                tokio::select! {
                    _ = sink.closed() => break,
                    maybe_msg = stream.next() => {
                        let Some(checked) = maybe_msg else { break };
                        if let Some(want) = category_filter.as_ref()
                            && &checked.msg.category != want {
                                continue;
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

/// Map a [`MsgboardError`] to a JSON-RPC error code.
///
/// Board-level rejections follow erigon: its RPC layer classifies them by a
/// literal string prefix, `powmsg:` giving `InvalidParams` and everything else
/// the default code (`rpc/jsonrpc/msgboard_api.go:87`).
///
/// **Decode failures deliberately diverge.** Erigon never classifies them at
/// all. `GrpcServer.AddMessage` returns a decode error as a transport error
/// (`msgboard/msgboard_grpc_server.go`), so `MsgBoardAPIImpl.AddMessage`
/// returns at its `if err != nil` and the prefix check below it never runs —
/// a malformed payload gets the generic code by omission rather than by
/// decision. Reth reports every failure of one `decode_validated_pow_msg` call
/// as `InvalidParams`, because a caller cannot be told that a truncated
/// payload is a bad parameter while a padded one is a server fault.
fn msgboard_error_to_rpc(err: MsgboardError) -> ErrorObjectOwned {
    let code = match &err {
        // Malformed input from the caller → InvalidParams.
        MsgboardError::InvalidVersion |
        MsgboardError::InvalidBlockHash |
        MsgboardError::InvalidNonce |
        MsgboardError::InvalidDifficulty |
        MsgboardError::InvalidData |
        MsgboardError::InvalidWork |
        MsgboardError::Rlp(_) |
        MsgboardError::TrailingBytes |
        MsgboardError::MalformedIdList |
        MsgboardError::MalformedHashList => -32602,
        // Board-level rejections → default.
        _ => -32000,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

/// JSON-RPC internal error (`-32603`) with `msg` as its message.
fn internal_error(msg: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg, None::<()>)
}

/// JSON-RPC invalid params error (`-32602`) with `msg` as its message.
fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, msg.into(), None::<()>)
}

/// The board's messages that match the category and block filters, in board
/// precedence order. The board hands back `Arc`s, so its lock covers pointer
/// copies only.
fn matching(
    board: &MsgBoard,
    category: Option<B256>,
    from_block: Option<u64>,
    to_block: Option<u64>,
) -> Vec<Arc<CheckedPoWMsg>> {
    match category {
        Some(cat) => board.category_msgs_filtered(&cat, from_block, to_block),
        None => board.all_msgs_filtered(from_block, to_block),
    }
}

/// Groups messages into erigon's category map. `BTreeMap` sorts the category
/// keys, as Go's `encoding/json` does for erigon's map.
fn group_by_category<'a>(
    msgs: impl Iterator<Item = &'a Arc<CheckedPoWMsg>>,
) -> BTreeMap<String, Vec<MsgboardMsg>> {
    let mut grouped = BTreeMap::<String, Vec<MsgboardMsg>>::new();
    for m in msgs {
        let rpc = to_rpc_msg(m);
        // Lowercase 0x-hex matches alloy's Display impl and erigon-pulse output.
        grouped.entry(rpc.category.to_string()).or_default().push(rpc);
    }
    grouped
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

    use std::collections::HashSet;

    use alloy_primitives::Bytes;
    use jsonrpsee::{
        core::server::{ConnectionId, Extensions, MethodCallback, MethodsError},
        types::{Id, Params},
        RpcModule,
    };
    use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};
    use serde_json::{json, Value};

    use super::*;

    /// Counts `msgboard_content` builds in flight and records the peak.
    /// Each build also sleeps briefly so concurrent calls overlap.
    #[derive(Debug, Default)]
    pub(super) struct BuildProbe {
        in_flight: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        /// Thread that ran the last `msgboard_addMessage` `PoW` verification.
        pub(super) verify_thread: std::sync::Mutex<Option<std::thread::ThreadId>>,
    }

    impl BuildProbe {
        /// Records the verifying thread, then counts the verification like a
        /// build.
        pub(super) fn enter_verify(self: &Arc<Self>) -> BuildGuard {
            *self.verify_thread.lock().unwrap() = Some(std::thread::current().id());
            self.enter()
        }

        pub(super) fn enter(self: &Arc<Self>) -> BuildGuard {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(50));
            BuildGuard(Arc::clone(self))
        }
    }

    pub(super) struct BuildGuard(Arc<BuildProbe>);

    impl Drop for BuildGuard {
        fn drop(&mut self) {
            self.0.in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Each full-board build holds hundreds of megabytes, so the node must
    /// not run more than [`CONTENT_CONCURRENT_BUILDS`] at once however many
    /// callers arrive. Every caller must still get its answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn content_builds_are_bounded_by_the_permit_count() {
        let api = MsgboardApi::new(filled_board(4, 8));
        let probe = Arc::clone(&api.probe);
        let m = api.into_rpc();

        let m = &m;
        let calls = (0..12).map(|_| async move {
            m.call::<_, Value>("msgboard_content", rpc_params_none()).await.unwrap()
        });
        for v in futures::future::join_all(calls).await {
            assert_eq!(total_msgs(&v), 4);
        }

        let peak = probe.peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            peak <= CONTENT_CONCURRENT_BUILDS,
            "{peak} builds ran at once; the bound is {CONTENT_CONCURRENT_BUILDS}",
        );
        assert!(peak >= 1);
    }

    /// Erigon's map goes through Go's `encoding/json`, which writes map keys
    /// sorted. The raw response text must list categories the same way.
    #[tokio::test]
    async fn content_lists_categories_in_sorted_order() {
        let board = ready_board(10);
        for b in [0xC0u8, 0x10, 0xF0, 0x55, 0x01, 0xAA] {
            board.add_local_msg(mined(&[b], category(b), 10)).unwrap();
        }
        let m = module(board);

        let (resp, _) = m
            .raw_json_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"msgboard_content","params":[]}"#,
                1,
            )
            .await
            .unwrap();
        let text = resp.get();
        let positions: Vec<usize> = [0x01u8, 0x10, 0x55, 0xAA, 0xC0, 0xF0]
            .iter()
            .map(|b| text.find(&format!("\"{}\":", category(*b))).unwrap())
            .collect();
        assert!(positions.is_sorted(), "category keys out of order in {positions:?}");
    }

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

    /// Config whose `PoW` difficulty `D` is exactly 1 for a `data` field of
    /// `data_len` bytes, so nonce 1 always verifies.
    ///
    /// `D = (2^24 + 10_000 × data_len) × M / Div`, so `M = 1` paired with
    /// `Div = 2^24 + 10_000 × data_len` gives 1, and every hash clears the
    /// target. Mining against [`easy_cfg`] instead costs about a hundred
    /// secp256k1 multiplications per message, which is minutes for the
    /// thousand-message boards below.
    fn trivial_pow_cfg(data_len: usize) -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: 1,
            work_divisor: (1 << 24) + 10_000 * data_len as u64,
            ..easy_cfg()
        }
    }

    /// Ready board holding `count` messages of `data_len` bytes, all in one
    /// category at block 10. Each message carries its index in the first eight
    /// bytes so no two hash alike.
    fn filled_board(count: usize, data_len: usize) -> Arc<MsgBoard> {
        assert!(data_len >= 8, "the index needs eight bytes to make messages unique");
        let cfg = trivial_pow_cfg(data_len);
        let board = Arc::new(MsgBoard::new(cfg.clone()));
        board.set_ready();
        board.set_head(10, block_hash_one());

        for i in 0..count {
            let mut data = vec![0u8; data_len];
            data[..8].copy_from_slice(&(i as u64).to_be_bytes());
            board
                .add_local_msg(PoWMsg {
                    version: VERSION_V1,
                    block_hash: block_hash_one(),
                    nonce: 1,
                    work_multiplier: cfg.work_multiplier,
                    work_divisor: cfg.work_divisor,
                    category: category(0xAA),
                    data: Bytes::from(data),
                })
                .unwrap();
        }
        board
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

    /// Decode and validation failures map to `-32602` (`InvalidParams`).
    ///
    /// This is the documented divergence from erigon, which returns a decode
    /// error before its own classifier runs. See `msgboard_error_to_rpc`.
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

    /// Both ways one `decode_validated_pow_msg` call can fail report the same
    /// code. A caller must not be told that a truncated payload is a bad
    /// parameter while a padded one is a server fault.
    #[tokio::test]
    async fn every_decode_failure_reports_the_same_code() {
        let m = module(ready_board(10));
        let good = pow_msg(1, &[1], category(0xCA));

        // Truncated: the value ends before the payload does.
        let hex = rlp_hex(&good);
        let truncated = &hex[..hex.len() - 4];
        let truncated_code = call_err_code(&m, "msgboard_addMessage", vec![json!(truncated)]).await;

        // Padded: a complete value with bytes after it.
        let padded = format!("{hex}c0");
        let padded_code = call_err_code(&m, "msgboard_addMessage", vec![json!(padded)]).await;

        assert_eq!(truncated_code, -32602, "a truncated payload is a bad parameter");
        assert_eq!(padded_code, truncated_code, "so is a padded one");
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

    /// The notification method must be `msgboard_subscription`.
    ///
    /// The typed `subscribe_unbounded` helper above matches on subscription id
    /// and never looks at the method name, so it passes either way — and it did
    /// pass for the whole time the name was wrong. This reads the raw frame.
    ///
    /// The spec's worked example names `msgboard_subscription`, jsonrpsee
    /// defaults it to the subscribe method's own name, and the failure is
    /// silent: the subscription opens, carries traffic, and a client filtering
    /// on the documented name sees an empty board.
    #[tokio::test]
    async fn subscription_notifications_use_the_method_name_the_spec_documents() {
        let board = ready_board(10);
        let m = module(Arc::clone(&board));

        let (_resp, mut stream) = m
            .raw_json_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"msgboard_subscribe","params":["newMessages"]}"#,
                4,
            )
            .await
            .expect("subscribe must be accepted");

        board.add_local_msg(mined(&[7], category(0xCA), 10)).unwrap();

        let raw = stream.recv().await.expect("subscription yielded nothing");
        let parsed: serde_json::Value =
            serde_json::from_str(raw.get()).expect("notification must be JSON");

        assert_eq!(
            parsed["method"], "msgboard_subscription",
            "notification method must match the spec, not the subscribe method name",
        );
        // The id's wire form is the harness's own (a bare number here, a hex
        // string from the real server), so only its presence is asserted.
        assert!(!parsed["params"]["subscription"].is_null());
        assert!(parsed["params"]["result"]["hash"].is_string());
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

    // ── content paging ───────────────────────────────────────────────────────

    /// A no-argument call is the shape erigon clients use, and erigon answers
    /// it with the whole board (`rpc/jsonrpc/msgboard_api.go`). A board past
    /// any old page size must come back whole, so a client never mistakes a
    /// partial answer for the full board.
    #[tokio::test]
    async fn content_without_a_limit_returns_the_whole_board() {
        let count = 1_000 + 8;
        let m = module(filled_board(count, 8));

        let v: Value = m.call("msgboard_content", rpc_params_none()).await.unwrap();
        assert_eq!(total_msgs(&v), count);

        let v: Value = m.call("msgboard_content", vec![json!({})]).await.unwrap();
        assert_eq!(total_msgs(&v), count, "an empty filter is the same call");
    }

    /// `limit` has no ceiling: a client can already get everything by leaving
    /// it out, so refusing a large one would protect nothing.
    #[tokio::test]
    async fn content_accepts_any_explicit_limit() {
        let m = module(filled_board(5, 8));
        let v: Value =
            m.call("msgboard_content", vec![json!({"limit": usize::MAX})]).await.unwrap();
        assert_eq!(total_msgs(&v), 5);
    }

    /// Paging must walk the board exactly once. Asserting only "no duplicates"
    /// would pass on an unordered source, so this pins the concatenated pages
    /// against board precedence order.
    #[tokio::test]
    async fn content_pages_walk_the_board_once_in_precedence_order() {
        let board = ready_board(10);
        for i in 0..10u8 {
            board.add_local_msg(mined(&[i], category(0xAA), 10)).unwrap();
        }
        let expected: Vec<B256> = board.all_messages().iter().map(|m| m.hash).collect();
        let m = module(board);
        let key = category(0xAA).to_string();

        let mut walked: Vec<B256> = Vec::new();
        for offset in [0, 4, 8] {
            let v: Value = m
                .call("msgboard_content", vec![json!({"limit": 4, "offset": offset})])
                .await
                .unwrap();
            let Some(page) = v.get(&key) else { continue };
            walked.extend(
                page.as_array()
                    .unwrap()
                    .iter()
                    .map(|msg| serde_json::from_value::<B256>(msg["hash"].clone()).unwrap()),
            );
        }

        assert_eq!(walked, expected, "paging must cover the board once, in precedence order");
    }

    /// The limit counts messages, not categories: a page may hold part of one
    /// category, and the categories together must not exceed it.
    #[tokio::test]
    async fn content_limit_counts_messages_across_every_category() {
        let board = ready_board(10);
        board.add_local_msg(mined(&[1], category(0xAA), 10)).unwrap();
        board.add_local_msg(mined(&[2], category(0xBB), 10)).unwrap();
        board.add_local_msg(mined(&[3], category(0xCC), 10)).unwrap();
        let m = module(board);

        let v: Value = m.call("msgboard_content", vec![json!({"limit": 2})]).await.unwrap();
        assert_eq!(total_msgs(&v), 2);
    }

    /// The category path is separate code over the same board, so it needs its
    /// own proof that the page bound applies.
    #[tokio::test]
    async fn content_limit_applies_to_a_category_filtered_query() {
        let board = ready_board(10);
        for i in 0..5u8 {
            board.add_local_msg(mined(&[i], category(0xAA), 10)).unwrap();
        }
        let m = module(board);

        let v: Value = m
            .call("msgboard_content", vec![json!({"category": category(0xAA), "limit": 2})])
            .await
            .unwrap();
        assert_eq!(total_msgs(&v), 2);
    }

    /// An offset past the end is the normal end of a walk, not an error — a
    /// client paging a board that shrank under it must not see a failure.
    #[tokio::test]
    async fn content_offset_past_the_end_returns_an_empty_map() {
        let board = ready_board(10);
        board.add_local_msg(mined(&[1], category(0xAA), 10)).unwrap();
        let m = module(board);

        let v: Value = m.call("msgboard_content", vec![json!({"offset": 99})]).await.unwrap();
        assert!(v.as_object().unwrap().is_empty());
    }

    /// Paging composes with the block-range filter: `offset` counts messages
    /// that survived the range, not messages on the board.
    #[tokio::test]
    async fn content_paging_applies_after_the_block_range_filter() {
        let board = ready_board(10);
        for i in 0..6u8 {
            board.add_local_msg(mined(&[i], category(0xAA), 10)).unwrap();
        }
        let m = module(board);

        let out_of_range: Value =
            m.call("msgboard_content", vec![json!({"fromBlock": 11, "limit": 3})]).await.unwrap();
        assert!(out_of_range.as_object().unwrap().is_empty());

        let in_range: Value =
            m.call("msgboard_content", vec![json!({"toBlock": 10, "limit": 3})]).await.unwrap();
        assert_eq!(total_msgs(&in_range), 3);
    }

    // ── contentPage: hash cursor ─────────────────────────────────────────────

    /// A full walk returns every message exactly once, in ascending hash
    /// order, across every category.
    #[tokio::test]
    async fn content_page_walk_returns_every_message_once() {
        let board = ready_board(10);
        for i in 0..11u8 {
            board.add_local_msg(mined(&[i], category(0xA0 + i % 3), 10)).unwrap();
        }
        let expected = sorted_hashes(&board, |_| true);
        let m = module(board);

        let walked = walk_pages(&m, json!({}), 3, || {}).await;
        assert_eq!(walked, expected, "the walk must cover the board once, in hash order");
    }

    /// The cursor composes with the category and block filters.
    #[tokio::test]
    async fn content_page_walk_combines_with_the_filters() {
        let board = ready_board(10);
        for i in 0..9u8 {
            board.add_local_msg(mined(&[i], category(0xA0 + i % 2), 10)).unwrap();
        }
        let expected = sorted_hashes(&board, |m| m.msg.category == category(0xA0));
        let m = module(board);

        let base = json!({"category": category(0xA0), "fromBlock": 10, "toBlock": 10});
        assert_eq!(walk_pages(&m, base, 2, || {}).await, expected);

        let out_of_range = json!({"category": category(0xA0), "fromBlock": 11});
        assert!(walk_pages(&m, out_of_range, 2, || {}).await.is_empty());
    }

    /// Inserts and evictions between pages must not make the walk repeat a
    /// message, or skip one that stayed on the board for the whole walk.
    #[tokio::test]
    async fn content_page_walk_is_stable_while_the_board_changes() {
        let data_len = 8;
        let cfg = MsgboardConfig { count_limit: 24, ..trivial_pow_cfg(data_len) };
        let board = Arc::new(MsgBoard::new(cfg.clone()));
        board.set_ready();
        board.set_head(10, block_hash_one());

        // Work multiplier 1 is the lowest precedence. Later messages use a
        // higher one, so a full board evicts the original messages first.
        let make = |i: u64, multiplier: u64| {
            let mut data = vec![0u8; data_len];
            data[..8].copy_from_slice(&i.to_be_bytes());
            (1u64..)
                .map(|nonce| PoWMsg {
                    version: VERSION_V1,
                    block_hash: block_hash_one(),
                    nonce,
                    work_multiplier: multiplier,
                    work_divisor: cfg.work_divisor,
                    category: category(0xA0 + (i % 3) as u8),
                    data: Bytes::from(data.clone()),
                })
                .find(|msg| msg.clone().to_checked(10, 0).is_ok())
                .unwrap()
        };
        for i in 0..24 {
            board.add_local_msg(make(i, 1)).unwrap();
        }
        let before: HashSet<B256> = board.all_messages().iter().map(|m| m.hash).collect();
        let m = module(Arc::clone(&board));

        let mut next = 1_000u64;
        let walked = walk_pages(&m, json!({}), 4, || {
            for _ in 0..2 {
                board.add_local_msg(make(next, 2)).unwrap();
                next += 1;
            }
        })
        .await;

        let after: HashSet<B256> = board.all_messages().iter().map(|m| m.hash).collect();
        assert!(before.difference(&after).count() > 0, "the test must evict messages");
        assert!(after.difference(&before).count() > 0, "the test must insert messages");

        let seen: HashSet<B256> = walked.iter().copied().collect();
        assert_eq!(seen.len(), walked.len(), "the walk repeated a message");
        for h in before.intersection(&after) {
            assert!(seen.contains(h), "the walk skipped {h}, present for the whole walk");
        }
    }

    /// `next` is the last hash of the page while messages remain, and null
    /// exactly at the end, also when the last page is exactly `limit` long.
    #[tokio::test]
    async fn content_page_next_is_null_exactly_at_the_end() {
        let board = filled_board(6, 8);
        let hashes = sorted_hashes(&board, |_| true);
        let m = module(board);

        let page = |limit: usize, after: Option<B256>| {
            let mut request = json!({"limit": limit});
            if let Some(a) = after {
                request["after"] = json!(a);
            }
            let m = &m;
            async move { m.call::<_, Value>("msgboard_contentPage", vec![request]).await.unwrap() }
        };

        let first = page(3, None).await;
        assert_eq!(first["next"], json!(hashes[2]), "`next` is the last hash of the page");
        let second = page(3, Some(hashes[2])).await;
        assert_eq!(total_msgs(&second["content"]), 3);
        assert!(second["next"].is_null(), "a full last page must still end the walk");

        assert!(page(6, None).await["next"].is_null());
        assert_eq!(page(5, None).await["next"], json!(hashes[4]));

        let past = page(3, Some(B256::repeat_byte(0xFF))).await;
        assert_eq!(past, json!({"content": {}, "next": null}));
    }

    /// `limit` is required and must be from 1 to the cap.
    #[tokio::test]
    async fn content_page_limit_bounds() {
        let m = module(filled_board(3, 8));
        for request in [json!({}), json!({"limit": 0}), json!({"limit": 1_001})] {
            assert_eq!(call_err_code(&m, "msgboard_contentPage", vec![request]).await, -32602);
        }
        let v: Value = m.call("msgboard_contentPage", vec![json!({"limit": 1_000})]).await.unwrap();
        assert_eq!(total_msgs(&v["content"]), 3);
    }

    /// `msgboard_content` has no cursor. An `after` sent to it is an error
    /// that names the method to use, never silently ignored.
    #[tokio::test]
    async fn content_rejects_after() {
        let m = module(filled_board(3, 8));
        for filter in [json!({"after": B256::ZERO}), json!({"after": B256::ZERO, "limit": 2})] {
            match m.call::<_, Value>("msgboard_content", vec![filter]).await {
                Err(MethodsError::JsonRpc(e)) => {
                    assert_eq!(e.code(), -32602);
                    assert!(e.message().contains("msgboard_contentPage"), "{}", e.message());
                }
                other => panic!("expected -32602, got {other:?}"),
            }
        }
    }

    /// `limit` 0 is a client error on `msgboard_content` too.
    #[tokio::test]
    async fn content_rejects_a_zero_limit() {
        let m = module(filled_board(3, 8));
        assert_eq!(call_err_code(&m, "msgboard_content", vec![json!({"limit": 0})]).await, -32602);
    }

    // ── subscribe: the server's own cap ──────────────────────────────────────

    /// `msgboard_subscribe` spawns a task per subscriber, which looked
    /// unbounded. It is not: jsonrpsee caps concurrent subscriptions per
    /// connection, and reth feeds that cap from
    /// `--rpc.max-subscriptions-per-connection` (default 1024) alongside
    /// `--rpc.max-connections` (default 500). `msgboard_subscribe` inherits the
    /// same bound as `eth_subscribe`, so the board adds no cap of its own.
    ///
    /// This drives a real server over a socket because the in-process
    /// `RpcModule` harness carries no server config and enforces nothing.
    #[tokio::test]
    async fn subscribe_is_bounded_by_the_jsonrpsee_per_connection_cap() {
        use jsonrpsee::{
            core::client::SubscriptionClientT,
            rpc_params,
            server::{ServerBuilder, ServerConfig},
            ws_client::WsClientBuilder,
        };

        let config = ServerConfig::builder().max_subscriptions_per_connection(2).build();
        let server = ServerBuilder::default()
            .set_config(config)
            .build("127.0.0.1:0")
            .await
            .expect("bind an ephemeral port");
        let addr = server.local_addr().expect("bound address");
        let handle = server.start(module(ready_board(10)));

        let client =
            WsClientBuilder::default().build(format!("ws://{addr}")).await.expect("ws connect");

        let mut open = Vec::new();
        for i in 0..2 {
            open.push(
                client
                    .subscribe::<MsgboardMsg, _>(
                        "msgboard_subscribe",
                        rpc_params!["newMessages"],
                        "msgboard_unsubscribe",
                    )
                    .await
                    .unwrap_or_else(|err| panic!("subscription {i} is within the cap: {err}")),
            );
        }

        let over_cap = client
            .subscribe::<MsgboardMsg, _>(
                "msgboard_subscribe",
                rpc_params!["newMessages"],
                "msgboard_unsubscribe",
            )
            .await;
        assert!(over_cap.is_err(), "the server must refuse a subscription past its cap");

        drop(open);
        handle.stop().expect("server still running");
    }

    // ── measurement ──────────────────────────────────────────────────────────

    /// Largest `msgboard_content` response a default board can produce:
    /// 10,000 messages of 8 KiB, every integer field at its widest hex form,
    /// and every message in a category of its own so each pays for a map key.
    ///
    /// This is the number an operator has to fit under
    /// `--rpc.max-response-size`. `docs/msgboard-rpc.md` and
    /// [`MsgboardApiServer::msgboard_content`] quote it. It is computed from one
    /// serialised message rather than by building the board, so it runs fast.
    #[test]
    fn worst_case_full_board_response_size() {
        let cfg = MsgboardConfig::default();
        let msg = MsgboardMsg {
            version: u8::MAX,
            block_hash: B256::repeat_byte(0xff),
            block_number: u64::MAX,
            nonce: u64::MAX,
            work_multiplier: u64::MAX,
            work_divisor: u64::MAX,
            category: B256::repeat_byte(0xff),
            data: Bytes::from(vec![0xff; cfg.size_limit]),
            hash: B256::repeat_byte(0xff),
        };
        let one = serde_json::to_string(&msg).unwrap().len();
        // `"0x<64 hex>":[<msg>]` plus the comma between map entries.
        let per_msg = 68 + 1 + 2 + one + 1;
        let result = 2 + cfg.count_limit * per_msg;
        let envelope = r#"{"jsonrpc":"2.0","id":4294967295,"result":}"#.len();
        let total = result + envelope;
        println!("worst-case msgboard_content response: {total} bytes");

        const DEFAULT_MAX_RESPONSE: usize = 160 * 1024 * 1024;
        const DOCUMENTED_MAX_RESPONSE: usize = 200 * 1024 * 1024;
        assert!(
            total > DEFAULT_MAX_RESPONSE,
            "the docs tell operators to raise --rpc.max-response-size; a full board now \
             fits the default, so update them: {total}",
        );
        assert!(
            total < DOCUMENTED_MAX_RESPONSE,
            "the documented --rpc.max-response-size=200 no longer fits a full board: {total}",
        );
    }

    /// Records what the no-argument `msgboard_content` call costs on a full
    /// default board through the RPC module.
    ///
    /// Ignored by default: it holds 10,000 x 8 KiB of messages and builds a
    /// response of about 167 MB, which runs past the slow-test timeout. Run it
    /// on its own with
    /// `cargo nextest run -p reth-msgboard --run-ignored ignored-only \
    ///  -E 'test(measure_content)' --no-capture`.
    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    async fn measure_content_on_a_full_board() {
        let cfg = trivial_pow_cfg(8 * 1024);
        let m = module(filled_board(cfg.count_limit, cfg.size_limit));

        let t = std::time::Instant::now();
        let (resp, _) = m
            .raw_json_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"msgboard_content","params":[]}"#,
                1,
            )
            .await
            .unwrap();
        println!(
            "full board: {} bytes of JSON-RPC response in {:?}",
            resp.get().len(),
            t.elapsed()
        );
    }

    /// Total messages across every category in a `msgboard_content` response.
    fn total_msgs(v: &Value) -> usize {
        v.as_object().unwrap().values().map(|a| a.as_array().unwrap().len()).sum()
    }

    /// Walk `msgboard_contentPage` with `limit`, passing `next` back as
    /// `after` until it is null. `between` runs before every page after the
    /// first. Returns every hash the walk saw, in walk order.
    async fn walk_pages(
        m: &RpcModule<MsgboardApi>,
        base: Value,
        limit: usize,
        mut between: impl FnMut(),
    ) -> Vec<B256> {
        let mut walked = Vec::new();
        let mut after = Value::Null;
        for page_number in 0..1_000 {
            let mut request = base.clone();
            request["limit"] = json!(limit);
            if page_number > 0 {
                between();
                request["after"] = after.clone();
            }
            let v: Value = m.call("msgboard_contentPage", vec![request]).await.unwrap();
            let page: Vec<B256> = v["content"]
                .as_object()
                .unwrap()
                .values()
                .flat_map(|a| a.as_array().unwrap().iter())
                .map(|msg| serde_json::from_value(msg["hash"].clone()).unwrap())
                .collect();
            assert!(page.len() <= limit, "a page must hold at most `limit` messages");
            let mut sorted = page.clone();
            sorted.sort_unstable();
            if !v["next"].is_null() {
                assert_eq!(v["next"], json!(sorted.last().unwrap()), "`next` is the last hash");
            }
            walked.extend(sorted);
            after = v["next"].clone();
            if after.is_null() {
                return walked;
            }
        }
        panic!("the page walk never returned a null `next`");
    }

    /// Hashes of the board's messages that pass `keep`, ascending.
    fn sorted_hashes(board: &MsgBoard, keep: impl Fn(&CheckedPoWMsg) -> bool) -> Vec<B256> {
        let mut hashes: Vec<B256> =
            board.all_messages().iter().filter(|m| keep(m)).map(|m| m.hash).collect();
        hashes.sort_unstable();
        hashes
    }

    /// `jsonrpsee` needs a concrete type for a no-params call; `Vec<Value>`
    /// serializes an empty positional list, which is what a client sends.
    fn rpc_params_none() -> Vec<Value> {
        Vec::new()
    }

    // ── review round 2 ───────────────────────────────────────────────────────

    /// Erigon names the subscription after its Go method `Messages`, and
    /// `formatName` lower-cases the first letter, so its wire name is
    /// `"messages"`. Reth also keeps its older `"newMessages"`.
    #[tokio::test]
    async fn subscribe_accepts_the_erigon_and_the_legacy_kind_names() {
        for kind in ["messages", "newMessages"] {
            let board = ready_board(10);
            let m = module(Arc::clone(&board));
            let mut sub = m
                .subscribe_unbounded("msgboard_subscribe", vec![kind])
                .await
                .unwrap_or_else(|e| panic!("kind {kind:?} must subscribe: {e:?}"));
            let msg = mined(&[9], category(0xAB), 10);
            let hash = board.add_local_msg(msg).unwrap().hash;
            let (got, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), sub.next::<MsgboardMsg>())
                    .await
                    .expect("notification in time")
                    .expect("stream open")
                    .expect("decodes");
            assert_eq!(got.hash, hash, "kind {kind:?}");
        }
    }

    /// Ready board at head 30 with one message at each of blocks 10, 20 and 30.
    fn three_block_board() -> Arc<MsgBoard> {
        let board = ready_board(30);
        for h in [10u64, 20, 30] {
            board.set_head(h, B256::repeat_byte(h as u8));
        }
        board.set_head(30, B256::repeat_byte(30));
        for h in [10u64, 20, 30] {
            let msg = (1u64..=1_000_000)
                .find_map(|n| {
                    let mut c = pow_msg(n, &[h as u8], category(0xAA));
                    c.block_hash = B256::repeat_byte(h as u8);
                    c.clone().to_checked(h, 0).is_ok().then_some(c)
                })
                .expect("nonce");
            board.add_local_msg(msg).unwrap();
        }
        board
    }

    /// `fromBlock` and `toBlock` take every form erigon's `rpc.BlockNumber`
    /// takes, with erigon's meaning, on both content methods.
    #[tokio::test]
    async fn content_block_bounds_accept_erigon_block_number_forms() {
        let m = module(three_block_board());
        // (filter, messages expected)
        let cases = [
            (json!({"fromBlock": 20, "toBlock": 20}), 1),
            (json!({"fromBlock": "0x14", "toBlock": "0x14"}), 1),
            (json!({"fromBlock": "20", "toBlock": "20"}), 1),
            (json!({"fromBlock": "0x14"}), 2),
            (json!({"fromBlock": null, "toBlock": null}), 3),
            // Erigon reads 0 as "no bound", and "earliest" is 0.
            (json!({"toBlock": 0}), 3),
            (json!({"toBlock": "earliest"}), 3),
            (json!({"fromBlock": "earliest", "toBlock": "0x14"}), 2),
            // A tag is a negative int64 in erigon, cast to uint64: as an upper
            // bound it admits every block, as a lower bound none.
            (json!({"toBlock": "latest"}), 3),
            (json!({"toBlock": "pending"}), 3),
            (json!({"toBlock": "safe"}), 3),
            (json!({"toBlock": "finalized"}), 3),
            (json!({"fromBlock": "latest"}), 0),
        ];
        for (filter, want) in cases {
            let v: Value = m
                .call("msgboard_content", vec![filter.clone()])
                .await
                .unwrap_or_else(|e| panic!("content {filter}: {e:?}"));
            assert_eq!(total_msgs(&v), want, "content {filter}");

            let mut request = filter.clone();
            request["limit"] = json!(10);
            let v: Value = m
                .call("msgboard_contentPage", vec![request])
                .await
                .unwrap_or_else(|e| panic!("contentPage {filter}: {e:?}"));
            assert_eq!(total_msgs(&v["content"]), want, "contentPage {filter}");
        }

        for bad in [json!("foo"), json!("0x8000000000000000"), json!(-1), json!(1.5)] {
            let code = call_err_code(&m, "msgboard_content", vec![json!({"toBlock": bad})]).await;
            assert_eq!(code, -32602, "toBlock {bad}");
        }
    }

    /// Full-board builds that hold every content permit must not stall a
    /// page call: `msgboard_contentPage` has permits of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn content_page_is_not_starved_by_full_board_builds() {
        let api = MsgboardApi::new(filled_board(4, 8));
        let held = Arc::clone(&api.content_permits)
            .acquire_many_owned(CONTENT_CONCURRENT_BUILDS as u32)
            .await
            .unwrap();
        let m = api.into_rpc();

        let page = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            m.call::<_, Value>("msgboard_contentPage", vec![json!({"limit": 10})]),
        )
        .await
        .expect("a page call must not wait for full-board builds")
        .unwrap();
        assert_eq!(total_msgs(&page["content"]), 4);
        drop(held);
    }

    /// The content permit must cover the serialised response until the
    /// transport takes it, not only the build: otherwise N slow clients each
    /// hold a full-board response with no permit.
    #[tokio::test]
    async fn content_permit_is_held_until_the_response_is_handed_off() {
        let api = MsgboardApi::new(filled_board(4, 8));
        let permits = Arc::clone(&api.content_permits);
        let m = api.into_rpc();
        let Some(MethodCallback::Async(cb)) = m.method("msgboard_content") else {
            panic!("msgboard_content must be an async method");
        };

        let response =
            cb(Id::Number(1), Params::new(None), ConnectionId(0), usize::MAX, Extensions::new())
                .await;
        assert!(response.is_success());
        assert_eq!(
            permits.available_permits(),
            CONTENT_CONCURRENT_BUILDS - 1,
            "the response exists but the transport has not taken it: the permit must be held",
        );

        let (_json, notify, _) = response.into_parts();
        notify.expect("the response must ask to be told when it is sent").notify(true);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while permits.available_permits() != CONTENT_CONCURRENT_BUILDS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the permit must come back once the transport has the response");
    }

    /// A flood of `msgboard_addMessage` calls must not fill the shared
    /// blocking pool: at most [`ADD_MESSAGE_CONCURRENT_VERIFIES`] run at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn add_message_verifies_are_bounded_by_the_permit_count() {
        let api = MsgboardApi::new(ready_board(10));
        let probe = Arc::clone(&api.probe);
        let m = api.into_rpc();
        let n = 3 * ADD_MESSAGE_CONCURRENT_VERIFIES;
        let msgs: Vec<_> =
            (0..n).map(|i| mined(&(i as u32).to_be_bytes(), category(0xCA), 10)).collect();

        let m = &m;
        let calls = msgs.iter().map(|msg| async move {
            m.call::<_, B256>("msgboard_addMessage", vec![rlp_hex(msg)]).await.unwrap()
        });
        futures::future::join_all(calls).await;

        let peak = probe.peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            (2..=ADD_MESSAGE_CONCURRENT_VERIFIES).contains(&peak),
            "{peak} verifies ran at once; the bound is {ADD_MESSAGE_CONCURRENT_VERIFIES}",
        );
    }

    /// `PoW` verification is a secp256k1 scalar multiplication; it must run on the
    /// blocking pool, not on the runtime worker that serves the call.
    #[tokio::test(flavor = "current_thread")]
    async fn add_message_verifies_off_the_runtime_worker() {
        let api = MsgboardApi::new(ready_board(10));
        let probe = Arc::clone(&api.probe);
        let m = api.into_rpc();
        let msg = mined(&[5, 5], category(0xCA), 10);

        let _: B256 = m.call("msgboard_addMessage", vec![rlp_hex(&msg)]).await.unwrap();
        let verified_on = probe.verify_thread.lock().unwrap().expect("verify ran");
        assert_ne!(verified_on, std::thread::current().id(), "verify ran on the runtime worker");
    }
}
