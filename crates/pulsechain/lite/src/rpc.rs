//! The JSON-RPC server: a fixed method list on loopback HTTP, with the contract's errors.
//!
//! The server is a small hyper service with its own JSON-RPC dispatch rather than a generic RPC
//! framework, because the contract fixes error texts that frameworks own: an unserved method is
//! `-32601 "method not served"`, a state miss is `-32046 "state not verified locally"` with
//! `{"missing": N}`, a halted node answers `-32000 "not serving: finalized anchor mismatch"`, or
//! `-32000 "not serving: the head is behind the finalized anchor"`.
//! Every reply is counted in `lite_requests_total{method,outcome}` with the outcome the client
//! gets.

use crate::{
    call::{eth_call, eth_estimate_gas, CallError, CallOutcome, ExecCtx},
    chain::{HaltReason, HeaderChain, HeldBlock},
    config::{LiteConfig, OnMiss},
    exec::{run_rounds, FetchError, Fetcher, RoundsError},
    hot_set::{Hot, HotSet},
    metrics::{LiteMetrics, Outcome},
    net::client::WireReceipt,
    state::{BlockHashes, MissingDb, PartialState},
    store::NodeStore,
};
use alloy_consensus::{
    constants::KECCAK_EMPTY, transaction::Recovered, Header, Receipt as AlloyReceipt,
    ReceiptEnvelope, ReceiptWithBloom, Transaction as _, TxEnvelope,
};
use alloy_eips::{calc_next_block_base_fee, eip1559::BaseFeeParams};
use alloy_primitives::{
    map::{B256Map, B256Set},
    Address, Bytes, Keccak256, TxKind, B256, U256,
};
use alloy_rpc_types_eth::{
    Block, BlockTransactions, Log, Transaction, TransactionInfo, TransactionReceipt,
    TransactionRequest,
};
use async_trait::async_trait;
use evm2::evm::Database;
use futures::future::{BoxFuture, FutureExt, Shared};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::{
    body::{Body, Bytes as HBytes, Frame, SizeHint},
    server::conn::http1,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    time::Instant,
};

/// Miss error code.
pub const MISS_CODE: i64 = -32046;
/// Miss error message.
pub const MISS_MESSAGE: &str = "state not verified locally";
/// Refusal text.
pub const REFUSED_MESSAGE: &str = "method not served";
/// Not-in-window text, for state at a block above the head or at an unknown hash.
pub const NOT_IN_WINDOW: &str = "not available in lite node: outside the recent block window";
/// reth's code for a block below the earliest available one (EIP-4444).
pub const PRUNED_HISTORY_CODE: i64 = 4444;
/// The prefix of reth's text for a block below the earliest available one:
/// `pruned history unavailable: requested N, earliest available M`.
pub const PRUNED_HISTORY: &str = "pruned history unavailable";
/// Halted text.
pub const HALTED_MESSAGE: &str = "not serving: finalized anchor mismatch";
/// Halted text while the finalized anchor is above the head and nothing checks the head against
/// it.
pub const BEHIND_ANCHOR: &str = "not serving: the head is behind the finalized anchor";
/// Finality-stalled text: the head ran more than [`crate::chain::MAX_HELD`] blocks past the
/// finalized block.
pub const FINALITY_STALLED: &str =
    "not serving state: the head is too far past the finalized block (finality stalled)";
/// The unrecoverable-sender text.
pub const BAD_SENDER: &str = "transaction sender could not be recovered from its signature";
/// The fee-history rewards text.
pub const NO_REWARDS: &str =
    "rewardPercentiles are not supported by the lite node: rewards need receipts it does not hold";
/// The re-seeded-during-the-request text.
pub const RESEEDED: &str = "not serving: the chain was re-seeded during the request";
/// The EIP-1898 requireCanonical text.
pub const NOT_CANONICAL: &str = "block is not canonical";
/// The unconfirmed-finality text, for the `safe` and `finalized` tags.
pub const FINALITY_UNCONFIRMED: &str = "finalized block not confirmed yet";
/// The stale-head text.
pub const STALE_HEAD: &str = "head is stale";
/// The text for a `BLOCKHASH` of a block in range but not held (below the seeded anchor).
pub const BLOCKHASH_NOT_HELD: &str =
    "not available in lite node: BLOCKHASH of a block outside the held headers";
/// The response-too-large text.
pub const RESPONSE_TOO_LARGE: &str = "response too large";
/// The text for an answer the shared response budget has no room for.
pub const RESPONSE_BUDGET_FULL: &str = "server busy: too many large responses in flight";
/// The text for a request body whose parsed form the shared body budget has no room for.
pub const BODY_BUDGET_FULL: &str = "server busy: too many large requests in flight";
/// The text for a batch of more than [`MAX_BATCH`] requests (geth's).
pub const BATCH_TOO_LARGE: &str = "batch too large";
/// No head yet text.
pub const NO_HEAD: &str = "no head yet: waiting for the consensus client";
/// The prefix of the text for state no source could serve: `state unavailable: <reason>`.
pub const STATE_UNAVAILABLE: &str = "state unavailable";
/// The prefix of the text for state discovery that ran out of rounds: `... after N rounds`.
pub const NOT_CONVERGED: &str = "state discovery did not converge";
/// The text for an execution the node stopped.
pub const EXECUTION_ABORTED: &str = "execution aborted";
/// The prefix of the text for receipts no source could serve: `receipts unavailable: <reason>`.
pub const RECEIPTS_UNAVAILABLE: &str = "receipts unavailable";
/// The prefix of the text for a block or receipt that could not be rendered.
pub const RENDERING_FAILED: &str = "rendering failed";
/// The text for receipts whose count differs from the block's transactions.
pub const RECEIPTS_MISMATCH: &str = "receipts do not match the block";

/// The largest request body (geth's limit).
const MAX_BODY: usize = 5 << 20;
/// Request body memory, the body and its parsed form ([`JsonCost`]), not charged to the shared
/// body budget: the connection cap times this (16 MiB by default) bounds what bodies hold outside
/// the budget, beside hyper's buffers ([`CONN_BUF`]).
const FREE_BODY: usize = 64 << 10;
/// The bound on hyper's read buffer of each connection, and so on a request head, and on its
/// write queue. hyper checks each after a read or a queued chunk, so each holds at most about
/// twice this. Neither is charged to a budget: at the default connection cap they hold at most
/// about 32 MiB for reads and 20 MiB for writes.
const CONN_BUF: usize = 64 << 10;
/// How long a body may wait for room in the shared body budget, for its read charge or for the
/// charge of its parsed form.
const PARSED_CHARGE_WAIT: Duration = Duration::from_secs(1);
/// The largest batch response body: geth's `BatchResponseMaxSize`, 25,000,000 bytes.
const MAX_RESPONSE: usize = 25_000_000;
/// The largest answer to a single request. geth caps batches only; a log-spam block of a 45M gas
/// limit renders about 45 MB of receipts. The response budget bounds the memory it holds: an
/// answer is held only as its text ([`Answer`]).
const MAX_SINGLE_RESPONSE: usize = 64 << 20;
/// Response bytes of each reply not charged to the shared response budget, so small answers are
/// served while large ones fill it: the connection cap times this (16 MiB by default) bounds what
/// replies hold outside the budget, beside hyper's write queue ([`CONN_BUF`]).
const FREE_RESPONSE: usize = 64 << 10;
/// Largest batch (geth's limit). The request timeout and [`MAX_RESPONSE`] bound its work.
const MAX_BATCH: usize = 1000;
/// Concurrent warm jobs.
const MAX_WARM: usize = 64;
/// Params memory ([`JsonCost`]) all warm jobs hold at once: each job keeps a copy until it ends.
const MAX_WARM_BYTES: usize = 16 << 20;
/// Warm `eth_call` and `eth_estimateGas` jobs running at once, so they leave EVM permits for
/// live calls.
const WARM_CALLS_RUNNING: usize = 2;
/// Warm call jobs queued or running at once, so they leave most of the [`MAX_WARM`] keys to other
/// warm jobs. A call past them is not warmed.
const WARM_CALLS_HELD: usize = 16;
/// Other warm jobs running at once: they wait on peers, not on the EVM.
const WARM_READS_RUNNING: usize = 16;
/// How long one warm job may run once it has its turn, and how long it may wait for its turn.
const WARM_TIMEOUT: Duration = Duration::from_secs(60);
/// Full blocks, block receipts and large receipts rendered at once (one sender recovery per
/// transaction). Apart from the EVM permits, so reads that run no EVM do not queue behind
/// `eth_call` runs. A render holds the typed answer and its [`Value`] form, several times its
/// text, until it has rendered the text: these permits bound that memory, which the response
/// budget does not charge.
const MAX_CONCURRENT_RENDERS: usize = 2;
/// The most logs a transaction receipt may hold and still be rendered without a render permit.
/// Its [`Value`] form is then at most a few hundred KiB.
const INLINE_RECEIPT_LOGS: usize = 256;
/// Receipt sets kept.
const RECEIPT_CACHE: usize = 64;
/// Receipt bytes kept ([`receipt_set_bytes`]): a log-heavy block holds several MiB, outside
/// `--cache.size`.
pub(crate) const RECEIPT_CACHE_BYTES: usize = 32 << 20;
/// How long one receipt fetch may run. Each read waits on it at most its own request timeout.
const RECEIPT_FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// A receipt fetch that every read of its block waits on.
type ReceiptFetch = Shared<BoxFuture<'static, Result<Arc<Vec<WireReceipt>>, FetchError>>>;

/// Methods served, exactly the contract's table.
pub const SERVED: &[&str] = &[
    "eth_blockNumber",
    "eth_chainId",
    "net_version",
    "eth_syncing",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
    "eth_estimateGas",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionReceipt",
    "eth_getBlockReceipts",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
];

/// A JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// Code.
    pub code: i64,
    /// Message.
    pub message: String,
    /// Optional data.
    pub data: Option<Value>,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }
    /// The shared miss error: `-32046`, `{"missing": n}`.
    pub fn miss(n: u64) -> Self {
        Self {
            code: MISS_CODE,
            message: MISS_MESSAGE.into(),
            data: Some(json!({"missing": n.max(1)})),
        }
    }
    fn other(msg: impl Into<String>) -> Self {
        Self::new(-32000, msg)
    }
    fn params(msg: impl Into<String>) -> Self {
        Self::new(-32602, msg)
    }
    /// reth's `PrunedHistoryUnavailable`, with its code and text.
    fn pruned(requested: u64, earliest_available: u64) -> Self {
        Self::new(
            PRUNED_HISTORY_CODE,
            format!(
                "{PRUNED_HISTORY}: requested {requested}, earliest available {earliest_available}"
            ),
        )
    }
}

/// The metric outcome of a reply with error code `code`.
const fn error_outcome(code: i64) -> Outcome {
    match code {
        MISS_CODE => Outcome::Miss,
        -32601 => Outcome::Refused,
        // A revert is an answer.
        3 => Outcome::Local,
        _ => Outcome::Error,
    }
}

/// Receipts are not in a beacon payload: they come from a peer.
#[async_trait]
pub trait ReceiptSource: Send + Sync {
    /// Fetches and verifies the receipts of `header`'s block.
    async fn receipts(&self, header: &Header) -> Result<Vec<WireReceipt>, FetchError>;
}

#[async_trait]
impl<T: crate::net::client::Transport> ReceiptSource for crate::net::client::P2pFetcher<T> {
    async fn receipts(&self, header: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        self.fetch_receipts(header).await
    }
}

/// Everything the RPC methods read.
pub struct Api {
    cfg: LiteConfig,
    chain: Arc<HeaderChain>,
    exec: ExecCtx,
    render_permits: Arc<tokio::sync::Semaphore>,
    store: Arc<dyn NodeStore>,
    hashes: BlockHashes,
    fetcher: Arc<dyn Fetcher>,
    receipt_source: Arc<dyn ReceiptSource>,
    metrics: LiteMetrics,
    hot: Arc<HotSet>,
    receipts: Mutex<ReceiptCache>,
    /// The receipt fetches running, at most one per block. Each removes itself when it ends.
    receipt_fetches: Mutex<B256Map<ReceiptFetch>>,
    warming: Mutex<WarmQueue>,
    warm_calls: tokio::sync::Semaphore,
    warm_reads: tokio::sync::Semaphore,
    trust_label: String,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").field("chain_id", &self.cfg.chain_id).finish_non_exhaustive()
    }
}

/// What [`Api::new`] needs.
pub struct ApiParts {
    /// Configuration.
    pub cfg: LiteConfig,
    /// The header chain.
    pub chain: Arc<HeaderChain>,
    /// The node store.
    pub store: Arc<dyn NodeStore>,
    /// Where state misses are fetched.
    pub fetcher: Arc<dyn Fetcher>,
    /// Where receipts are fetched.
    pub receipts: Arc<dyn ReceiptSource>,
    /// Metrics.
    pub metrics: LiteMetrics,
    /// The hot set.
    pub hot: Arc<HotSet>,
    /// "follows <host>; finalized checked against <host>".
    pub trust_label: String,
}

impl std::fmt::Debug for ApiParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiParts").finish_non_exhaustive()
    }
}

impl Api {
    /// Builds the API.
    pub fn new(p: ApiParts) -> Option<Arc<Self>> {
        let chain = p.chain.clone();
        let hashes: BlockHashes = Arc::new(move |n| chain.by_number(n).map(|b| b.hash));
        let mut exec = ExecCtx::new(
            p.cfg.chain_id,
            p.store.clone(),
            hashes.clone(),
            p.fetcher.clone(),
            p.cfg.on_miss,
            p.cfg.max_rounds,
        )?;
        exec.evm_timeout = p.cfg.evm_timeout;
        Some(Arc::new(Self {
            cfg: p.cfg,
            chain: p.chain,
            exec,
            render_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RENDERS)),
            store: p.store,
            hashes,
            fetcher: p.fetcher,
            receipt_source: p.receipts,
            metrics: p.metrics,
            hot: p.hot,
            receipts: Mutex::new(ReceiptCache::default()),
            receipt_fetches: Mutex::default(),
            warming: Mutex::new(WarmQueue::default()),
            warm_calls: tokio::sync::Semaphore::new(WARM_CALLS_RUNNING),
            warm_reads: tokio::sync::Semaphore::new(WARM_READS_RUNNING),
            trust_label: p.trust_label,
        }))
    }

    /// The trust label (hosts only).
    pub fn trust_label(&self) -> &str {
        &self.trust_label
    }

    /// Answers one request. The server counts the reply it sends ([`Self::count_reply`]).
    pub async fn handle(
        self: &Arc<Self>,
        method: &str,
        params: &Value,
    ) -> Result<Rendered, RpcError> {
        let epoch = self.chain.epoch();
        let mut res = self.dispatch(method, params, self.cfg.on_miss).await;
        // The chain may have halted or re-seeded while the request ran: an answer computed
        // against the old chain is not sent.
        if !outlives_chain_change(method, res.as_ref().err().map(|e| e.code)) {
            if let Some(reason) = self.chain.halt_reason() {
                res = Err(RpcError::other(halted_message(reason)));
            } else if self.chain.epoch() != epoch {
                res = Err(RpcError::other(RESEEDED));
            }
        }
        res
    }

    /// Counts `reply`, the reply to `method` as the client gets it: a timeout or a size refusal
    /// that replaced an answer is counted as that error, and only a reply with data counts in
    /// `lite_answers_total`.
    fn count_reply(&self, method: &str, reply: &Answer) {
        let outcome = reply.code.map_or(Outcome::Local, error_outcome);
        self.metrics.request(metric_method(method), outcome);
        if reply.data && !matches!(method, "eth_chainId" | "net_version") {
            // State, code, bodies and receipts are checked against a block's roots. The head
            // choice, the sync status and fee estimates are not.
            let unchecked = matches!(
                method,
                "eth_blockNumber" |
                    "eth_syncing" |
                    "eth_gasPrice" |
                    "eth_maxPriorityFeePerGas" |
                    "eth_feeHistory"
            );
            self.metrics.answer(!unchecked);
        }
    }

    async fn dispatch(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
    ) -> Result<Rendered, RpcError> {
        if !SERVED.contains(&method) {
            return Err(RpcError::new(-32601, REFUSED_MESSAGE));
        }
        // As geth: extra params are refused, not kept for the whole request and its warm job.
        let want = max_params(method);
        if p.as_array().is_some_and(|a| a.len() > want) {
            return Err(RpcError::params(format!("too many arguments, want at most {want}")));
        }
        match method {
            "eth_chainId" => return Rendered::of(&json!(format!("{:#x}", self.cfg.chain_id))),
            "net_version" => return Rendered::of(&json!(self.cfg.chain_id.to_string())),
            _ => {}
        }
        if let Some(reason) = self.chain.halt_reason() {
            return Err(RpcError::other(halted_message(reason)));
        }
        // Nothing is served from a seeded anchor alone, by tag, number or hash.
        if !self.chain.is_live() {
            return Err(RpcError::other(NO_HEAD));
        }
        // The answers that may be large are rendered as they are built.
        match method {
            "eth_getBlockByNumber" | "eth_getBlockByHash" => self.get_block(method, p).await,
            "eth_getTransactionReceipt" => self.tx_receipt(p, mode).await,
            "eth_getBlockReceipts" => self.block_receipts(p, mode).await,
            _ => self.answer_value(method, p, mode).await.and_then(|v| Rendered::of(&v)),
        }
    }

    /// The answers [`Self::dispatch`] does not render as they are built.
    async fn answer_value(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
    ) -> Result<Value, RpcError> {
        match method {
            "eth_blockNumber" => Ok(json!(hex_u64(self.head()?.header.number))),
            "eth_syncing" => self.syncing(),
            "eth_getBalance" => {
                self.account_read(method, p, mode, |a| {
                    json!(hex_u256(a.map_or(U256::ZERO, |a| a.balance)))
                })
                .await
            }
            "eth_getTransactionCount" => {
                self.account_read(method, p, mode, |a| json!(hex_u64(a.map_or(0, |a| a.nonce))))
                    .await
            }
            "eth_getCode" => self.get_code(method, p, mode).await,
            "eth_getStorageAt" => self.get_storage(method, p, mode).await,
            "eth_call" => self.call(method, p, mode, false).await,
            "eth_estimateGas" => self.call(method, p, mode, true).await,
            "eth_getBlockTransactionCountByNumber" | "eth_getBlockTransactionCountByHash" => {
                let b = self.block_param(method, p, 0)?;
                Ok(b.map_or(Value::Null, |b| json!(hex_u64(b.body.transactions.len() as u64))))
            }
            "eth_getTransactionByHash" => self.tx_by_hash(p),
            "eth_getTransactionByBlockHashAndIndex" | "eth_getTransactionByBlockNumberAndIndex" => {
                let b = self.block_param(method, p, 0)?;
                let idx = index_param(p, 1)?;
                Ok(b.map(|b| rpc_tx(&b, idx))
                    .transpose()?
                    .flatten()
                    .map_or(Value::Null, |t| json!(t)))
            }
            "eth_gasPrice" => {
                let head = self.head()?;
                let tip = self.suggested_tip();
                Ok(json!(hex_u128(tip + u128::from(head.header.base_fee_per_gas.unwrap_or(0)))))
            }
            "eth_maxPriorityFeePerGas" => {
                self.head()?;
                Ok(json!(hex_u128(self.suggested_tip())))
            }
            "eth_feeHistory" => self.fee_history(p),
            _ => Err(RpcError::new(-32601, REFUSED_MESSAGE)),
        }
    }

    // --- blocks ---

    fn head(&self) -> Result<HeldBlock, RpcError> {
        // A seeded anchor is not served until the follower has moved to a confirmed head.
        if !self.chain.is_live() {
            return Err(RpcError::other(NO_HEAD));
        }
        let head = self.chain.head().ok_or_else(|| RpcError::other(NO_HEAD))?;
        if self.chain.finality_stalled() {
            return Err(RpcError::other(FINALITY_STALLED));
        }
        // Latest and state reads need a recent head: an old one (finality or the beacons
        // stalled, a peer keeps vetoing) is refused rather than served as latest.
        let max = self.cfg.head_max_age;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let too_old = now.saturating_sub(head.header.timestamp) > max.as_secs();
        let not_moved = self.chain.since_head_moved().is_none_or(|d| d > max);
        if too_old || not_moved {
            return Err(RpcError::other(STALE_HEAD));
        }
        Ok(head)
    }

    fn syncing(&self) -> Result<Value, RpcError> {
        // Not syncing exactly when latest reads are served, so a health check on this agrees with
        // the stale-head refusal. A stale head, or one too far past finality, is reported.
        let head = match self.head() {
            Ok(_) => return Ok(json!(false)),
            Err(e) if e.message == STALE_HEAD || e.message == FINALITY_STALLED => {
                self.chain.head().ok_or(e)?
            }
            Err(e) => return Err(e),
        };
        let n = hex_u64(head.header.number);
        let lowest = hex_u64(self.chain.lowest().unwrap_or(head.header.number));
        Ok(json!({"startingBlock": lowest, "currentBlock": n, "highestBlock": n}))
    }

    /// Resolves a block parameter (tag, number, hash or EIP-1898 object) to a held block.
    /// `Ok(None)` is an unknown block: a hash not held or a number above the head. Errors are for
    /// tags that cannot be resolved at all, and, as reth, [`RpcError::pruned`] for a number below
    /// the lowest held block. Its earliest available block is that one, or `earliest_served`
    /// when that is higher.
    fn resolve(&self, v: &Value, earliest_served: u64) -> Result<Option<HeldBlock>, RpcError> {
        if let Some(s) = v.as_str() {
            return match s {
                // No transaction pool: the pending view is the latest one.
                "latest" | "pending" => Ok(Some(self.head()?)),
                "safe" | "finalized" => {
                    self.head()?;
                    // Only finality a beacon quorum confirmed at depth is served.
                    if !self.chain.finality_confirmed() {
                        return Err(RpcError::other(FINALITY_UNCONFIRMED));
                    }
                    Ok(self.chain.finalized())
                }
                // As reth, the earliest available block.
                "earliest" => Ok(self.chain.lowest().and_then(|n| self.chain.by_number(n))),
                s if s.len() == 66 => {
                    let h: B256 = s.parse().map_err(|_| RpcError::params("invalid block hash"))?;
                    Ok(self.chain.by_hash(&h))
                }
                s => {
                    let n = parse_quantity(s)
                        .ok_or_else(|| RpcError::params("invalid block number"))?;
                    self.by_number(n, earliest_served)
                }
            };
        }
        if let Some(o) = v.as_object() {
            if let Some(h) = o.get("blockHash") {
                let h: B256 = serde_json::from_value(h.clone())
                    .map_err(|_| RpcError::params("invalid block hash"))?;
                // EIP-1898: with requireCanonical the block must be on the canonical chain.
                let canonical = o.get("requireCanonical").and_then(Value::as_bool) == Some(true);
                if canonical && self.chain.by_hash(&h).is_some() && !self.chain.is_canonical(&h) {
                    return Err(RpcError::other(NOT_CANONICAL));
                }
                return Ok(self.chain.by_hash(&h));
            }
            if let Some(n) = o.get("blockNumber") {
                return self.resolve(n, earliest_served);
            }
        }
        // As geth, a bare JSON number is not a block number.
        Err(RpcError::params("invalid block parameter"))
    }

    /// The canonical block at `n`. See [`Self::resolve`] for `None` and the pruned error.
    fn by_number(&self, n: u64, earliest_served: u64) -> Result<Option<HeldBlock>, RpcError> {
        if let Some(b) = self.chain.by_number(n) {
            return Ok(Some(b));
        }
        // The lowest held block is at most the head, so a number below it is not above the head.
        match self.chain.lowest() {
            Some(lowest) if n < lowest => Err(RpcError::pruned(n, lowest.max(earliest_served))),
            _ => Ok(None),
        }
    }

    fn block_param(
        &self,
        method: &str,
        p: &Value,
        i: usize,
    ) -> Result<Option<HeldBlock>, RpcError> {
        let v = p.get(i).ok_or_else(|| RpcError::params("missing block parameter"))?;
        let _ = method;
        self.resolve(v, 0)
    }

    async fn get_block(&self, method: &str, p: &Value) -> Result<Rendered, RpcError> {
        let full = match p.get(1) {
            None | Some(Value::Null) => false,
            Some(Value::Bool(full)) => *full,
            Some(_) => return Err(RpcError::params("invalid full transactions flag")),
        };
        let Some(b) = self.block_param(method, p, 0)? else { return Rendered::of(&Value::Null) };
        if !full {
            return Rendered::of(&json!(rpc_block(&b, false)?));
        }
        render_blocking(&self.render_permits, move || rpc_block(&b, true).map(|blk| json!(blk)))
            .await
    }

    fn tx_by_hash(&self, p: &Value) -> Result<Value, RpcError> {
        let h: B256 = serde_json::from_value(p.get(0).cloned().unwrap_or(Value::Null))
            .map_err(|_| RpcError::params("invalid transaction hash"))?;
        self.head()?;
        let tx = self.chain.find_tx(&h).map(|(b, i)| rpc_tx(&b, i)).transpose()?.flatten();
        Ok(tx.map_or(Value::Null, |t| json!(t)))
    }

    // --- state ---

    /// Rejects state for blocks older than the state window with [`RpcError::pruned`], as reth
    /// answers state below its history.
    fn state_block(&self, p: &Value, i: usize) -> Result<HeldBlock, RpcError> {
        // A null block is latest, as reth's `Option<BlockId>` and geth's eth_call read it.
        let v = p.get(i).filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("latest"));
        let head = self.head()?;
        if self.chain.finality_stalled() {
            return Err(RpcError::other(FINALITY_STALLED));
        }
        let earliest = head.header.number.saturating_sub(self.cfg.state_window);
        let b = self.resolve(&v, earliest)?.ok_or_else(|| RpcError::other(NOT_IN_WINDOW))?;
        if b.header.number < earliest {
            let lowest = self.chain.lowest().unwrap_or(earliest);
            return Err(RpcError::pruned(b.header.number, earliest.max(lowest)));
        }
        Ok(b)
    }

    fn map_rounds(&self, e: RoundsError) -> RpcError {
        match e {
            RoundsError::Missing(n) => RpcError::miss(n),
            RoundsError::Fetch(f) => RpcError::other(format!("{STATE_UNAVAILABLE}: {f}")),
            RoundsError::BlockHashUnavailable(_) | RoundsError::NoProgress(_) => {
                RpcError::other(e.to_string())
            }
            RoundsError::TooManyRounds(r) => {
                RpcError::other(format!("{NOT_CONVERGED} after {r} rounds"))
            }
            RoundsError::Aborted => RpcError::other(EXECUTION_ABORTED),
        }
    }

    fn warm_if_needed(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
        res: &Result<impl Sized, RpcError>,
    ) {
        if mode != OnMiss::ErrorAndWarm || !matches!(res, Err(e) if e.code == MISS_CODE) {
            return;
        }
        let is_call = matches!(method, "eth_call" | "eth_estimateGas");
        let (key, bytes) = warm_key(method, p);
        {
            let mut w = self.warming.lock();
            let held = w.bytes.checked_add(bytes).filter(|n| *n <= MAX_WARM_BYTES);
            let Some(held) = held else { return };
            if is_call && w.calls >= WARM_CALLS_HELD {
                return;
            }
            if w.keys.len() >= MAX_WARM || !w.keys.insert(key) {
                return;
            }
            w.bytes = held;
            w.calls += usize::from(is_call);
            self.metrics.warm_queue.set(w.keys.len() as f64);
        }
        /// Frees the key, its bytes and its call count when the job ends, panics included.
        struct Warming(Arc<Api>, B256, usize, bool);
        impl Drop for Warming {
            fn drop(&mut self) {
                let mut w = self.0.warming.lock();
                w.keys.remove(&self.1);
                w.bytes -= self.2;
                w.calls -= usize::from(self.3);
                self.0.metrics.warm_queue.set(w.keys.len() as f64);
            }
        }
        let guard = Warming(self.clone(), key, bytes, is_call);
        let (method, p) = (method.to_owned(), p.clone());
        tokio::spawn(async move {
            let api = &guard.0;
            let slots = if guard.3 { &api.warm_calls } else { &api.warm_reads };
            // The wait is bounded, so a stuck job holds its key at most twice the timeout.
            let Ok(Ok(_slot)) = tokio::time::timeout(WARM_TIMEOUT, slots.acquire()).await else {
                return
            };
            // The whole request again, fetching: it converges over as many rounds as it needs.
            let run = api.dispatch_boxed(&method, &p, OnMiss::Fetch);
            // The outcome is not kept: a success has filled the store for the next call.
            let _ = tokio::time::timeout(WARM_TIMEOUT, run).await;
        });
    }

    fn dispatch_boxed<'a>(
        self: &'a Arc<Self>,
        method: &'a str,
        p: &'a Value,
        mode: OnMiss,
    ) -> BoxFuture<'a, Result<Rendered, RpcError>> {
        Box::pin(self.dispatch(method, p, mode))
    }

    async fn state_read<T: Send>(
        &self,
        blk: &HeldBlock,
        mode: OnMiss,
        f: impl FnMut(&mut MissingDb) -> T + Send,
    ) -> Result<T, RpcError> {
        let state = PartialState::new(self.store.clone(), blk.header.state_root);
        run_rounds(&state, &self.hashes, &*self.fetcher, None, mode, self.cfg.max_rounds, f)
            .await
            .map(|r| r.value)
            .map_err(|e| self.map_rounds(e))
    }

    async fn account_read(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
        render: impl Fn(Option<crate::verify::ProvenAccount>) -> Value + Send,
    ) -> Result<Value, RpcError> {
        let addr: Address = param(p, 0, "address")?;
        let blk = self.state_block(p, 1)?;
        self.hot.record(Hot::Account(addr));
        let res = self
            .state_read(&blk, mode, |db| {
                let acct = db.get_account(&addr).ok().flatten();
                acct.map(|a| (a.balance, a.nonce))
            })
            .await
            .map(|a| {
                render(a.map(|(balance, nonce)| crate::verify::ProvenAccount {
                    nonce,
                    balance,
                    storage_root: B256::ZERO,
                    code_hash: B256::ZERO,
                }))
            });
        self.warm_if_needed(method, p, mode, &res);
        res
    }

    async fn get_code(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
    ) -> Result<Value, RpcError> {
        let addr: Address = param(p, 0, "address")?;
        let blk = self.state_block(p, 1)?;
        self.hot.record(Hot::Account(addr));
        let res = self
            .state_read(&blk, mode, |db| {
                let hash =
                    db.get_account(&addr).ok().flatten().map_or(KECCAK_EMPTY, |a| a.code_hash);
                if hash == KECCAK_EMPTY {
                    Bytes::new()
                } else {
                    db.code_bytes(&hash)
                }
            })
            .await
            .map(|c| json!(c));
        self.warm_if_needed(method, p, mode, &res);
        res
    }

    async fn get_storage(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
    ) -> Result<Value, RpcError> {
        let addr: Address = param(p, 0, "address")?;
        let slot = parse_slot(p.get(1).ok_or_else(|| RpcError::params("missing slot"))?)?;
        let blk = self.state_block(p, 2)?;
        self.hot.record(Hot::Slot(addr, B256::from(slot)));
        let res = self
            .state_read(&blk, mode, |db| db.get_storage(&addr, &slot).unwrap_or_default())
            .await
            .map(|v| json!(format!("0x{}", alloy_primitives::hex::encode(v.to_be_bytes::<32>()))));
        self.warm_if_needed(method, p, mode, &res);
        res
    }

    async fn call(
        self: &Arc<Self>,
        method: &str,
        p: &Value,
        mode: OnMiss,
        estimate: bool,
    ) -> Result<Value, RpcError> {
        let req: TransactionRequest =
            serde_json::from_value(p.get(0).cloned().unwrap_or(Value::Null))
                .map_err(|e| RpcError::params(format!("invalid call object: {e}")))?;
        check_call_fields(&req, self.cfg.chain_id)?;
        // State and block overrides are refused: null and {} are fine.
        for i in 2..=3 {
            match p.get(i) {
                None | Some(Value::Null) => {}
                Some(Value::Object(o)) if o.is_empty() => {}
                Some(_) => {
                    return Err(RpcError::params(
                        "state/block overrides are not supported by the lite node",
                    ));
                }
            }
        }
        let blk = self.state_block(p, 1)?;
        if let Some(TxKind::Call(to)) = req.to {
            self.hot.record(Hot::Account(to));
        }
        let mut ctx = self.exec.clone();
        ctx.mode = mode;
        let unheld = Arc::new(Unheld::default());
        ctx.hashes = call_block_hashes(self.chain.clone(), &blk, unheld.clone());
        let res = if estimate {
            eth_estimate_gas(&ctx, req, &blk.header).await.map(|g| json!(hex_u64(g)))
        } else {
            eth_call(&ctx, req, &blk.header).await.and_then(|o| match o {
                CallOutcome::Success(out) => Ok(json!(out)),
                CallOutcome::Revert { data } => Err(CallError::EstimateReverted(data)),
            })
        };
        let res = res.map_err(|e| match e {
            // A round missed only unheld hashes: no fetch adds a header, so the rounds end there.
            CallError::Rounds(RoundsError::BlockHashUnavailable(_)) => {
                RpcError::other(BLOCKHASH_NOT_HELD)
            }
            // The error modes stop at the first round with misses, so the hashes asked for are
            // that round's header misses: all of them, or other state is missing too.
            CallError::Rounds(RoundsError::Missing(n)) if n == unheld.asked.lock().len() as u64 => {
                RpcError::other(BLOCKHASH_NOT_HELD)
            }
            e => self.map_call_error(e),
        });
        self.warm_if_needed(method, p, mode, &res);
        res
    }

    fn map_call_error(&self, e: CallError) -> RpcError {
        match e {
            CallError::Rounds(r) => self.map_rounds(r),
            CallError::EstimateReverted(data) => revert_error(&data),
            CallError::Invalid(m) | CallError::Halted(m) | CallError::Evm(m) => RpcError::other(m),
            timeout @ CallError::Timeout(_) => RpcError::other(timeout.to_string()),
        }
    }

    // --- receipts ---

    async fn receipts_for(
        self: &Arc<Self>,
        b: &HeldBlock,
        mode: OnMiss,
    ) -> Result<Arc<Vec<WireReceipt>>, RpcError> {
        if b.body.transactions.is_empty() {
            return Ok(Arc::new(Vec::new()));
        }
        let fetch = {
            let mut fetches = self.receipt_fetches.lock();
            // A fetch caches its set before it leaves `fetches`, so one that ends meanwhile is
            // found in one or the other.
            if let Some(r) = self.receipts.lock().get(&b.hash) {
                return Ok(r);
            }
            if mode != OnMiss::Fetch {
                return Err(RpcError::miss(1));
            }
            fetches.entry(b.hash).or_insert_with(|| self.start_receipt_fetch(b)).clone()
        };
        fetch.await.map_err(|e| RpcError::other(format!("{RECEIPTS_UNAVAILABLE}: {e}")))
    }

    /// Fetches `b`'s receipts in a task of its own, so the reads that wait on it can leave.
    fn start_receipt_fetch(self: &Arc<Self>, b: &HeldBlock) -> ReceiptFetch {
        let (api, header, hash) = (self.clone(), b.header.clone(), b.hash);
        let task = tokio::spawn(async move {
            let fetch = AssertUnwindSafe(api.receipt_source.receipts(&header)).catch_unwind();
            // A fetch that ran out of time or panicked found no source.
            let res = match tokio::time::timeout(RECEIPT_FETCH_TIMEOUT, fetch).await {
                Ok(Ok(res)) => res.map(Arc::new),
                Ok(Err(_)) | Err(_) => Err(FetchError::NoSource),
            };
            if let Ok(r) = &res {
                api.receipts.lock().insert(hash, r.clone());
            }
            api.receipt_fetches.lock().remove(&hash);
            res
        });
        // The task fails to join only when the runtime shuts down.
        task.map(|joined| joined.unwrap_or(Err(FetchError::NoSource))).boxed().shared()
    }

    async fn tx_receipt(self: &Arc<Self>, p: &Value, mode: OnMiss) -> Result<Rendered, RpcError> {
        let h: B256 = serde_json::from_value(p.get(0).cloned().unwrap_or(Value::Null))
            .map_err(|_| RpcError::params("invalid transaction hash"))?;
        self.head()?;
        let Some((b, idx)) = self.chain.find_tx(&h) else { return Rendered::of(&Value::Null) };
        let res = match self.receipts_for(&b, mode).await {
            Ok(r) => match check_receipts(&b, &r) {
                Ok(()) => {
                    let logs = r[idx].receipt.logs.len();
                    let render = move || {
                        let log_index =
                            r[..idx].iter().map(|wr| wr.receipt.logs.len() as u64).sum();
                        rpc_receipt(&b, &r, idx, log_index).map(|rc| json!(rc))
                    };
                    if logs <= INLINE_RECEIPT_LOGS {
                        render().and_then(|v| Rendered::of(&v))
                    } else {
                        render_blocking(&self.render_permits, render).await
                    }
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        self.warm_if_needed("eth_getTransactionReceipt", p, mode, &res);
        res
    }

    async fn block_receipts(
        self: &Arc<Self>,
        p: &Value,
        mode: OnMiss,
    ) -> Result<Rendered, RpcError> {
        let Some(b) = self.block_param("eth_getBlockReceipts", p, 0)? else {
            return Rendered::of(&Value::Null)
        };
        let res = match self.receipts_for(&b, mode).await {
            Ok(r) => {
                let render = move || rpc_receipts(&b, &r).map(|v| json!(v));
                render_blocking(&self.render_permits, render).await
            }
            Err(e) => Err(e),
        };
        self.warm_if_needed("eth_getBlockReceipts", p, mode, &res);
        res
    }

    // --- fees ---

    fn recent(&self, n: u64) -> Vec<HeldBlock> {
        let Some(head) = self.chain.head() else { return vec![] };
        let lowest = self.chain.lowest().unwrap_or(0);
        (head.header.number.saturating_sub(n.saturating_sub(1)).max(lowest)..=head.header.number)
            .filter_map(|i| self.chain.by_number(i))
            .collect()
    }

    /// 60th percentile of the three lowest tips of each of the last 20 blocks; 1 gwei when the
    /// window holds none.
    fn suggested_tip(&self) -> u128 {
        let mut tips = Vec::new();
        for b in self.recent(20) {
            let base = b.header.base_fee_per_gas;
            let mut t: Vec<u128> = b
                .body
                .transactions
                .iter()
                .filter_map(|tx| tx.effective_tip_per_gas(base.unwrap_or(0)))
                .collect();
            t.sort_unstable();
            tips.extend(t.into_iter().take(3));
        }
        if tips.is_empty() {
            return 1_000_000_000;
        }
        tips.sort_unstable();
        tips[(tips.len() - 1) * 60 / 100]
    }

    fn fee_history(&self, p: &Value) -> Result<Value, RpcError> {
        let count = match p.get(0) {
            Some(Value::String(s)) => parse_hex_or_decimal(s),
            Some(v) => v.as_u64(),
            None => None,
        }
        .ok_or_else(|| RpcError::params("invalid block count"))?
        .min(1024);
        let rewards = match p.get(2) {
            None | Some(Value::Null) => false,
            Some(Value::Array(a)) => !a.is_empty(),
            Some(_) => return Err(RpcError::params("invalid reward percentiles")),
        };
        let newest = self.resolve(p.get(1).unwrap_or(&Value::Null), 0);
        // As geth: the newest block is decoded before the oracle runs, so a malformed one is
        // refused, but the oracle answers no blocks with an empty history without looking it up.
        if count == 0 {
            return match newest {
                Err(e) if e.code == -32602 => Err(e),
                _ => Ok(json!({"oldestBlock": "0x0", "gasUsedRatio": null})),
            };
        }
        let newest = newest?.ok_or_else(|| RpcError::other(NOT_IN_WINDOW))?;
        // Rewards need each transaction's gas used, which only receipts hold. Zeros would be a
        // wrong answer, so percentiles are refused.
        if rewards {
            return Err(RpcError::other(NO_REWARDS));
        }
        // Walk the newest block's own ancestry and stop at the first block not held: the held
        // numbers are not contiguous (the finalized block is kept below the window), and entry i
        // must be block oldestBlock + i.
        let mut blocks = vec![newest.clone()];
        while (blocks.len() as u64) < count &&
            let Some(parent) = blocks.last().and_then(|b| {
                (b.header.number > 0).then(|| self.chain.by_hash(&b.header.parent_hash)).flatten()
            })
        {
            blocks.push(parent);
        }
        blocks.reverse();
        let first = blocks[0].header.number;
        let mut base_fees: Vec<String> =
            blocks.iter().map(|b| hex_u64(b.header.base_fee_per_gas.unwrap_or(0))).collect();
        let next = calc_next_block_base_fee(
            newest.header.gas_used,
            newest.header.gas_limit,
            newest.header.base_fee_per_gas.unwrap_or(0),
            BaseFeeParams::ethereum(),
        );
        base_fees.push(hex_u64(next));
        let ratios: Vec<f64> = blocks
            .iter()
            .map(|b| b.header.gas_used as f64 / b.header.gas_limit.max(1) as f64)
            .collect();
        let out = json!({
            "oldestBlock": hex_u64(first),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": ratios,
        });
        Ok(out)
    }
}

/// The warm jobs queued or running.
#[derive(Debug, Default)]
struct WarmQueue {
    /// [`warm_key`] of each job's request.
    keys: B256Set,
    /// The [`JsonCost`] of the params the jobs hold, at most [`MAX_WARM_BYTES`].
    bytes: usize,
    /// The `eth_call` and `eth_estimateGas` jobs, at most [`WARM_CALLS_HELD`].
    calls: usize,
}

/// The keccak of `method` and the serialized `p`, and the [`JsonCost`] of `p`, which its clone
/// takes: the key does not keep a second copy of the params.
fn warm_key(method: &str, p: &Value) -> (B256, usize) {
    struct Hash(Keccak256, JsonCost);
    impl std::io::Write for Hash {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.update(b);
            self.1.feed(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut h = Hash(Keccak256::new(), JsonCost::default());
    h.0.update(method);
    // A method name holds no NUL, so the split between name and params is unique.
    h.0.update([0]);
    // Writing a `Value` to a sink that never fails cannot fail.
    match serde_json::to_writer(&mut h, p) {
        Ok(()) => (h.0.finalize(), h.1.cost()),
        Err(_) => (B256::ZERO, usize::MAX),
    }
}

/// Refuses call fields that change gas or execution but that the call does not model. An access
/// list is modelled (the call runs as an EIP-2930 or EIP-1559 transaction); blobs and
/// authorizations are not: the chain schedules neither Cancun nor Prague.
fn check_call_fields(req: &TransactionRequest, chain_id: u64) -> Result<(), RpcError> {
    if req.blob_versioned_hashes.as_ref().is_some_and(|h| !h.is_empty()) || req.sidecar.is_some() {
        return Err(RpcError::params("blob transactions are not supported by the lite node"));
    }
    if req.authorization_list.as_ref().is_some_and(|l| !l.is_empty()) {
        return Err(RpcError::params("authorizationList is not supported by the lite node"));
    }
    if let Some(have) = req.chain_id.filter(|id| *id != chain_id) {
        return Err(RpcError::params(format!(
            "chainId does not match node's (have={have}, want={chain_id})"
        )));
    }
    Ok(())
}

/// `BLOCKHASH` for a call at `blk`: its own ancestry (it may be off the canonical chain), and only
/// the 256 blocks below it. evm2 already range-limits before asking; this does not rely on it.
/// Records in `unheld` each ancestor in that range that is not held. Answers are kept for the
/// call (at most 256), so they stay the same for its whole run.
fn call_block_hashes(chain: Arc<HeaderChain>, blk: &HeldBlock, unheld: Arc<Unheld>) -> BlockHashes {
    let (hash, number) = (blk.hash, blk.header.number);
    // A `BLOCKHASH` loop asks the same numbers up to a million times in one run, and each ask of a
    // side block's or an unheld ancestor walks up to 255 parents: each number is walked once.
    let walked = Mutex::new(HashMap::<u64, Option<B256>>::new());
    Arc::new(move |n| {
        if n >= number || number - n > 256 {
            return None;
        }
        *walked.lock().entry(n).or_insert_with(|| {
            let h = chain.ancestor_hash(&hash, n);
            if h.is_none() {
                unheld.asked.lock().insert(n);
            }
            h
        })
    })
}

/// The unheld ancestors one call asked `BLOCKHASH` for.
#[derive(Debug, Default)]
struct Unheld {
    /// Their numbers: at most 256, the range `BLOCKHASH` reaches.
    asked: Mutex<HashSet<u64>>,
}

/// The most params a served `method` takes: its arguments in geth.
fn max_params(method: &str) -> usize {
    match method {
        "eth_getBlockTransactionCountByNumber" |
        "eth_getBlockTransactionCountByHash" |
        "eth_getTransactionByHash" |
        "eth_getTransactionReceipt" |
        "eth_getBlockReceipts" => 1,
        "eth_getBalance" |
        "eth_getTransactionCount" |
        "eth_getCode" |
        "eth_getBlockByNumber" |
        "eth_getBlockByHash" |
        "eth_getTransactionByBlockHashAndIndex" |
        "eth_getTransactionByBlockNumberAndIndex" => 2,
        "eth_getStorageAt" | "eth_feeHistory" => 3,
        // The call, the block, state overrides and block overrides.
        "eth_call" | "eth_estimateGas" => 4,
        _ => 0,
    }
}

fn metric_method(method: &str) -> &str {
    // Unknown names are counted under one label so a client cannot create unbounded series.
    if SERVED.contains(&method) || method == "eth_sendRawTransaction" {
        method
    } else {
        "other"
    }
}

// --- JSON helpers ---

fn hex_u64(n: u64) -> String {
    format!("{n:#x}")
}
fn hex_u128(n: u128) -> String {
    format!("{n:#x}")
}
fn hex_u256(n: U256) -> String {
    format!("{n:#x}")
}

/// A `0x` hex quantity. Leading zeros are accepted: they do not change the value.
fn parse_quantity(s: &str) -> Option<u64> {
    let h = s.strip_prefix("0x")?;
    // `from_str_radix` takes a leading `+`.
    if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(h, 16).ok()
}

/// geth's `math.ParseUint64`, as `math.HexOrDecimal64` reads text: a `0x` quantity, decimal
/// digits, or the empty string for zero.
fn parse_hex_or_decimal(s: &str) -> Option<u64> {
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => (h, 16),
        None if s.is_empty() => return Some(0),
        None => (s, 10),
    };
    // `from_str_radix` takes a leading `+`, and an empty string is an error.
    if !digits.bytes().all(|b| b.is_ascii_digit() || (radix == 16 && b.is_ascii_hexdigit())) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

fn param<T: serde::de::DeserializeOwned>(p: &Value, i: usize, what: &str) -> Result<T, RpcError> {
    let v = p.get(i).ok_or_else(|| RpcError::params(format!("missing {what}")))?;
    serde_json::from_value(v.clone()).map_err(|_| RpcError::params(format!("invalid {what}")))
}

fn index_param(p: &Value, i: usize) -> Result<usize, RpcError> {
    p.get(i)
        .and_then(Value::as_str)
        .and_then(parse_quantity)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| RpcError::params("invalid index"))
}

/// A storage key: `0x` hex of up to 64 digits, left-padded.
fn parse_slot(v: &Value) -> Result<U256, RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::params("invalid storage key"))?;
    let h = s.strip_prefix("0x").unwrap_or(s);
    // `U256::from_str_radix` skips `_`, so "0x_" would read slot 0.
    if h.is_empty() || h.len() > 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RpcError::params("invalid storage key"));
    }
    U256::from_str_radix(h, 16).map_err(|_| RpcError::params("invalid storage key"))
}

fn revert_error(data: &Bytes) -> RpcError {
    let reason = decode_revert_reason(data);
    let message = reason
        .map_or_else(|| "execution reverted".to_owned(), |r| format!("execution reverted: {r}"));
    RpcError { code: 3, message, data: Some(json!(data)) }
}

/// `Error(string)`: selector, offset, length, bytes.
fn decode_revert_reason(data: &[u8]) -> Option<String> {
    let body = data.strip_prefix(&[0x08, 0xc3, 0x79, 0xa0])?;
    let off = usize::try_from(U256::from_be_slice(body.get(..32)?)).ok()?;
    let start = off.checked_add(32)?;
    let len = usize::try_from(U256::from_be_slice(body.get(off..start)?)).ok()?;
    let s = body.get(start..start.checked_add(len)?)?;
    String::from_utf8(s.to_vec()).ok()
}

/// The sender of `tx`. A signature that does not recover is an error, never the zero address.
fn recover(tx: &TxEnvelope) -> Result<Address, RpcError> {
    use alloy_consensus::transaction::SignerRecoverable;
    tx.recover_signer().map_err(|_| RpcError::other(BAD_SENDER))
}

fn tx_info(b: &HeldBlock, i: usize) -> TransactionInfo {
    TransactionInfo {
        hash: Some(*b.body.transactions[i].tx_hash()),
        index: Some(i as u64),
        block_hash: Some(b.hash),
        block_number: Some(b.header.number),
        block_timestamp: Some(b.header.timestamp),
        base_fee: b.header.base_fee_per_gas,
    }
}

fn rpc_tx(b: &HeldBlock, i: usize) -> Result<Option<Transaction>, RpcError> {
    let Some(tx) = b.body.transactions.get(i).cloned() else { return Ok(None) };
    let from = recover(&tx)?;
    Ok(Some(Transaction::from_transaction(Recovered::new_unchecked(tx, from), tx_info(b, i))))
}

fn rpc_block(b: &HeldBlock, full: bool) -> Result<Block, RpcError> {
    let transactions = if full {
        BlockTransactions::Full(
            (0..b.body.transactions.len())
                .filter_map(|i| rpc_tx(b, i).transpose())
                .collect::<Result<_, _>>()?,
        )
    } else {
        BlockTransactions::Hashes(b.body.transactions.iter().map(|t| *t.tx_hash()).collect())
    };
    // The total difficulty is not in the header, so it is left out (as pulse-reth does).
    let header = alloy_rpc_types_eth::Header::from_sealed(alloy_consensus::Sealed::new_unchecked(
        b.header.clone(),
        b.hash,
    ));
    Ok(Block { header, uncles: vec![], transactions, withdrawals: b.body.withdrawals.clone() })
}

/// Runs CPU-heavy rendering (one sender recovery per transaction) off the runtime workers, under
/// one of `permits`, and renders its answer to text there. The typed answer and its [`Value`]
/// form are dropped before the permit: only the text leaves the task.
async fn render_blocking(
    permits: &Arc<tokio::sync::Semaphore>,
    f: impl FnOnce() -> Result<Value, RpcError> + Send + 'static,
) -> Result<Rendered, RpcError> {
    let permit = permits.clone().acquire_owned().await.map_err(|e| render_failed(&e))?;
    // The permit moves into the task: a request that times out does not free it early.
    tokio::task::spawn_blocking(move || {
        let out = f().and_then(|v| Rendered::of(&v));
        drop(permit);
        out
    })
    .await
    .map_err(|e| render_failed(&e))?
}

/// The error of a block or receipt that could not be rendered.
fn render_failed(e: &dyn std::fmt::Display) -> RpcError {
    RpcError::other(format!("{RENDERING_FAILED}: {e}"))
}

/// Verified receipt sets by block hash, the least recently used first.
#[derive(Debug, Default)]
struct ReceiptCache {
    /// At most [`RECEIPT_CACHE`] sets, each with its [`receipt_set_bytes`].
    sets: VecDeque<(B256, Arc<Vec<WireReceipt>>, usize)>,
    /// The sum of the sets' bytes: at most [`RECEIPT_CACHE_BYTES`].
    bytes: usize,
}

impl ReceiptCache {
    fn get(&mut self, hash: &B256) -> Option<Arc<Vec<WireReceipt>>> {
        let i = self.sets.iter().position(|(h, ..)| h == hash)?;
        let set = self.sets.remove(i)?;
        let receipts = set.1.clone();
        self.sets.push_back(set);
        Some(receipts)
    }

    /// Keeps `receipts`, pushing out the least recently used sets to make room. A set over the
    /// whole bound, or one a concurrent fetch already kept, is not kept.
    fn insert(&mut self, hash: B256, receipts: Arc<Vec<WireReceipt>>) {
        let bytes = receipt_set_bytes(&receipts);
        if bytes > RECEIPT_CACHE_BYTES || self.sets.iter().any(|(h, ..)| *h == hash) {
            return;
        }
        // Both terms are at most the bound, so the sum cannot overflow.
        while self.sets.len() >= RECEIPT_CACHE || self.bytes + bytes > RECEIPT_CACHE_BYTES {
            let Some((.., gone)) = self.sets.pop_front() else { break };
            self.bytes -= gone;
        }
        self.bytes += bytes;
        self.sets.push_back((hash, receipts, bytes));
    }
}

/// The memory one receipt set holds: each receipt and log, and the log topics and data.
fn receipt_set_bytes(receipts: &[WireReceipt]) -> usize {
    let log = |l: &alloy_primitives::Log| {
        size_of::<alloy_primitives::Log>()
            .saturating_add(l.topics().len().saturating_mul(size_of::<B256>()))
            .saturating_add(l.data.data.len())
    };
    receipts.iter().fold(0, |sum: usize, r| {
        r.receipt
            .logs
            .iter()
            .map(log)
            .fold(sum.saturating_add(size_of::<WireReceipt>()), usize::saturating_add)
    })
}

fn check_receipts(b: &HeldBlock, receipts: &[WireReceipt]) -> Result<(), RpcError> {
    if receipts.len() != b.body.transactions.len() {
        return Err(RpcError::other(RECEIPTS_MISMATCH));
    }
    Ok(())
}

fn rpc_receipts(
    b: &HeldBlock,
    receipts: &[WireReceipt],
) -> Result<Vec<TransactionReceipt>, RpcError> {
    check_receipts(b, receipts)?;
    let mut log_index = 0u64;
    let mut out = Vec::with_capacity(receipts.len());
    for i in 0..receipts.len() {
        out.push(rpc_receipt(b, receipts, i, log_index)?);
        log_index += receipts[i].receipt.logs.len() as u64;
    }
    Ok(out)
}

/// The receipt of transaction `i`, whose first log is the block's log number `log_index`.
/// `receipts` matches the block (see [`check_receipts`]).
fn rpc_receipt(
    b: &HeldBlock,
    receipts: &[WireReceipt],
    i: usize,
    log_index: u64,
) -> Result<TransactionReceipt, RpcError> {
    let (tx, wr) = (&b.body.transactions[i], &receipts[i]);
    let from = recover(tx)?;
    let r = &wr.receipt;
    let logs: Vec<Log> = (log_index..)
        .zip(&r.logs)
        .map(|(log_index, l)| Log {
            inner: l.clone(),
            block_hash: Some(b.hash),
            block_number: Some(b.header.number),
            block_timestamp: Some(b.header.timestamp),
            transaction_hash: Some(*tx.tx_hash()),
            transaction_index: Some(i as u64),
            log_index: Some(log_index),
            removed: false,
        })
        .collect();
    let cumulative = r.cumulative_gas_used;
    let prev_gas = i.checked_sub(1).map_or(0, |p| receipts[p].receipt.cumulative_gas_used);
    let envelope = ReceiptEnvelope::from_typed(
        r.tx_type,
        ReceiptWithBloom {
            receipt: AlloyReceipt {
                status: alloy_consensus::Eip658Value::Eip658(r.success),
                cumulative_gas_used: cumulative,
                logs,
            },
            logs_bloom: wr.logs_bloom,
        },
    );
    let to = match tx.kind() {
        TxKind::Call(a) => Some(a),
        TxKind::Create => None,
    };
    Ok(TransactionReceipt {
        inner: envelope,
        transaction_hash: *tx.tx_hash(),
        transaction_index: Some(i as u64),
        block_hash: Some(b.hash),
        block_number: Some(b.header.number),
        gas_used: cumulative.saturating_sub(prev_gas),
        effective_gas_price: tx.effective_gas_price(b.header.base_fee_per_gas),
        blob_gas_used: None,
        blob_gas_price: None,
        from,
        to,
        contract_address: to.is_none().then(|| from.create(tx.nonce())),
    })
}

// --- the HTTP server ---

fn rpc_response(id: &Value, res: Result<Value, RpcError>) -> Value {
    match res {
        Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err(e) => {
            let mut err = json!({"code": e.code, "message": e.message});
            if let Some(d) = e.data {
                err["data"] = d;
            }
            json!({"jsonrpc": "2.0", "id": id, "error": err})
        }
    }
}

/// A result rendered to JSON text, as it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered(Vec<u8>);

impl Rendered {
    /// Renders `v` into a buffer of its exact size, so the buffer holds what the response budget
    /// charges for it. A text past [`MAX_SINGLE_RESPONSE`], which no answer may pass, is refused
    /// before it is rendered.
    fn of(v: &Value) -> Result<Self, RpcError> {
        let len = json_len(v);
        if len > MAX_SINGLE_RESPONSE {
            return Err(RpcError::new(-32003, RESPONSE_TOO_LARGE));
        }
        let mut text = Vec::with_capacity(len);
        serde_json::to_writer(&mut text, v).map_err(|e| render_failed(&e))?;
        Ok(Self(text))
    }

    /// The JSON text.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One reply rendered to JSON text: the text, and what counting and replacing the reply read.
/// The text is the same as [`rpc_response`]'s, byte for byte.
#[derive(Debug)]
struct Answer {
    /// The text in pieces, written one after another: a large result is not copied into the
    /// reply around it.
    pieces: Vec<Cow<'static, [u8]>>,
    /// The length of the text.
    len: usize,
    /// The error code, `None` for a result.
    code: Option<i64>,
    /// A result that is not null.
    data: bool,
}

impl Answer {
    fn new(id: &Value, res: Result<Rendered, RpcError>) -> Self {
        match res {
            Ok(Rendered(result)) => {
                // The keys in the order a `Value` map writes them.
                const OPEN: &[u8] = b"{\"id\":";
                const RESULT: &[u8] = b",\"jsonrpc\":\"2.0\",\"result\":";
                let mut head = exact_buffer(json_len(id).saturating_add(OPEN.len() + RESULT.len()));
                head.extend_from_slice(OPEN);
                // Writing a `Value` to a `Vec` cannot fail.
                let _ = serde_json::to_writer(&mut head, id);
                head.extend_from_slice(RESULT);
                let data = result != b"null";
                let len = head.len() + result.len() + 1;
                let pieces = vec![head.into(), result.into(), Cow::Borrowed(&b"}"[..])];
                Self { pieces, len, code: None, data }
            }
            Err(e) => {
                let code = Some(e.code);
                let reply = rpc_response(id, Err(e));
                let mut text = exact_buffer(json_len(&reply));
                // Writing a `Value` to a `Vec` cannot fail.
                let _ = serde_json::to_writer(&mut text, &reply);
                Self { len: text.len(), pieces: vec![text.into()], code, data: false }
            }
        }
    }

    /// The text in one buffer.
    fn to_vec(&self) -> Vec<u8> {
        self.pieces.concat()
    }
}

/// An empty buffer with room for exactly `len` bytes, so a text written to it holds only the
/// bytes the response budget charges for it. A text longer than `len` still fits: the buffer
/// grows.
fn exact_buffer(len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    // `len` is `usize::MAX` only for a text that cannot be written. The write then fails too.
    let _ = buf.try_reserve_exact(len);
    buf
}

/// A reply body: JSON text in pieces, written one after another. A batch is not copied into one
/// buffer: each answer stays in the buffers it was rendered to.
#[derive(Debug, Default)]
pub struct ReplyBody {
    pieces: Vec<Cow<'static, [u8]>>,
    len: usize,
}

impl ReplyBody {
    /// The reply to a single request.
    fn one(answer: Answer) -> Self {
        Self { pieces: answer.pieces, len: answer.len }
    }

    /// The reply to a batch: its answers as a JSON array.
    fn batch(answers: Vec<Answer>) -> Self {
        let mut body = Self { pieces: Vec::with_capacity(answers.len() * 4 + 1), len: 1 };
        body.pieces.push(Cow::Borrowed(b"["));
        for (i, answer) in answers.into_iter().enumerate() {
            if i > 0 {
                body.pieces.push(Cow::Borrowed(b","));
                body.len += 1;
            }
            body.len += answer.len;
            body.pieces.extend(answer.pieces);
        }
        body.pieces.push(Cow::Borrowed(b"]"));
        body.len += 1;
        body
    }

    /// The length of the text.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// The body has no text.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The text in one buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        self.pieces.concat()
    }
}

impl From<Vec<u8>> for ReplyBody {
    fn from(text: Vec<u8>) -> Self {
        Self { len: text.len(), pieces: vec![text.into()] }
    }
}

impl std::fmt::Display for ReplyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for piece in &self.pieces {
            f.write_str(std::str::from_utf8(piece).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}

/// The request id: a string, a number or null (JSON-RPC 2.0). `None` for any other value.
fn request_id(req: &Value) -> Option<Value> {
    match req.get("id") {
        None => Some(Value::Null),
        Some(id @ (Value::Null | Value::Number(_) | Value::String(_))) => Some(id.clone()),
        Some(_) => None,
    }
}

/// The request names JSON-RPC version `2.0`, as geth and jsonrpsee require.
fn versioned(req: &Value) -> bool {
    req.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
}

/// A request that gets no reply (JSON-RPC 2.0). Its method still runs.
fn is_notification(req: &Value) -> bool {
    versioned(req) && req.get("id").is_none() && req.get("method").is_some_and(Value::is_string)
}

async fn handle_one(api: &Arc<Api>, req: &Value) -> Answer {
    let invalid = || Err(RpcError::new(-32600, "invalid request"));
    let Some(id) = request_id(req) else { return Answer::new(&Value::Null, invalid()) };
    if !versioned(req) {
        return Answer::new(&id, invalid());
    }
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return Answer::new(&id, invalid());
    };
    // As geth: the method is looked up before the params are read.
    if !SERVED.contains(&method) {
        return Answer::new(&id, Err(RpcError::new(-32601, REFUSED_MESSAGE)));
    }
    static NO_PARAMS: Value = Value::Array(Vec::new());
    // As geth: absent or null params are none, and named params are refused.
    let params = match req.get("params") {
        None | Some(Value::Null) => &NO_PARAMS,
        Some(p @ Value::Array(_)) => p,
        Some(_) => return Answer::new(&id, Err(RpcError::params("non-array args"))),
    };
    Answer::new(&id, api.handle(method, params).await)
}

/// The answers of one response so far: the size of their text and its charge to the server's
/// response budget. An answer is held only as its text, so the charge bounds the memory the
/// answers hold.
struct ResponseCharge<'a> {
    budget: &'a Arc<tokio::sync::Semaphore>,
    /// [`MAX_RESPONSE`] for a batch, [`MAX_SINGLE_RESPONSE`] for a single request.
    cap: usize,
    size: usize,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// The budget refused an answer: the later ones are refused without being computed.
    full: bool,
}

impl<'a> ResponseCharge<'a> {
    const fn new(budget: &'a Arc<tokio::sync::Semaphore>, cap: usize) -> Self {
        Self { budget, cap, size: 0, permit: None, full: false }
    }
}

/// [`answer_capped`], with the reply counted.
async fn handle_capped(api: &Arc<Api>, req: &Value, charge: &mut ResponseCharge<'_>) -> Answer {
    let reply = answer_capped(api, req, charge).await;
    api.count_reply(method_of(req), &reply);
    reply
}

/// The method `req` names, or the empty string (counted as `other`).
fn method_of(req: &Value) -> &str {
    req.get("method").and_then(Value::as_str).unwrap_or_default()
}

/// Answers `req` unless the response so far is over its cap or the budget is full, and
/// charges the answer's bytes past [`FREE_RESPONSE`] to `charge`. An answer that crosses the cap,
/// or that the budget has no room for, is replaced.
async fn answer_capped(api: &Arc<Api>, req: &Value, charge: &mut ResponseCharge<'_>) -> Answer {
    // geth's response-too-large code, and EIP-1474's retryable limit-exceeded code for a full
    // budget, which frees as other replies are written.
    let refuse = |code: i64, msg: &str| {
        Answer::new(&request_id(req).unwrap_or(Value::Null), Err(RpcError::new(code, msg)))
    };
    if charge.size > charge.cap {
        return refuse(-32003, RESPONSE_TOO_LARGE);
    }
    if charge.full {
        return refuse(-32005, RESPONSE_BUDGET_FULL);
    }
    let resp = handle_one(api, req).await;
    // A result refused before it was rendered was past every cap.
    let len = if resp.code == Some(-32003) { usize::MAX } else { resp.len };
    let before = charge.size;
    charge.size = charge.size.saturating_add(len);
    if charge.size > charge.cap {
        return refuse(-32003, RESPONSE_TOO_LARGE);
    }
    // The part of the reply past `FREE_RESPONSE` is charged.
    let cost = charge.size.saturating_sub(FREE_RESPONSE) - before.saturating_sub(FREE_RESPONSE);
    if cost == 0 {
        return resp;
    }
    // No wait for room: an answer waiting would hold its bytes uncharged.
    let permit =
        u32::try_from(cost).ok().and_then(|n| charge.budget.clone().try_acquire_many_owned(n).ok());
    let Some(permit) = permit else {
        charge.size = before;
        charge.full = true;
        return refuse(-32005, RESPONSE_BUDGET_FULL);
    };
    match &mut charge.permit {
        Some(held) => held.merge(permit),
        None => charge.permit = Some(permit),
    }
    resp
}

/// Memory a parsed [`Value`] may take per value or object entry, peak included: 112 bytes
/// measured for `[[0],[0],..]`, 96 for `[0,0,..]`.
const PARSED_VALUE_COST: usize = 128;

/// A bound on the memory the [`Value`] parsed from JSON text takes, fed the text in pieces: a copy
/// of its bytes (strings) and [`PARSED_VALUE_COST`] for each value or entry it opens. The parsed
/// form of `0,` is 48 times the text, so byte budgets that count only the text do not bound it.
#[derive(Debug, Default)]
struct JsonCost {
    bytes: usize,
    values: usize,
    in_string: bool,
    escaped: bool,
}

impl JsonCost {
    fn feed(&mut self, text: &[u8]) {
        self.bytes = self.bytes.saturating_add(text.len());
        for &c in text {
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if c == b'\\' {
                    self.escaped = true;
                } else if c == b'"' {
                    self.in_string = false;
                }
                continue;
            }
            match c {
                b'"' => self.in_string = true,
                // A value follows each of these, or the first value of the text.
                b',' | b':' | b'[' | b'{' => self.values = self.values.saturating_add(1),
                _ => {}
            }
        }
    }

    const fn cost(&self) -> usize {
        self.values.saturating_add(1).saturating_mul(PARSED_VALUE_COST).saturating_add(self.bytes)
    }
}

/// The serialized length of `v`, without building it.
fn json_len(v: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(b.len());
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    // Writing a `Value` to a sink that never fails cannot fail.
    serde_json::to_writer(&mut c, v).map_or(usize::MAX, |()| c.0)
}

/// The refusal text of a node halted for `reason`.
const fn halted_message(reason: HaltReason) -> &'static str {
    match reason {
        HaltReason::AnchorMismatch => HALTED_MESSAGE,
        HaltReason::BehindAnchor => BEHIND_ANCHOR,
    }
}

/// Replaces the answers of a batch begun at `epoch` once the chain has halted or re-seeded: an
/// early item's answer would otherwise go out long after it, next to the later items' errors.
fn drop_stale_answers(api: &Api, epoch: u64, batch: &[Value], out: &mut [Answer]) {
    let message = if let Some(reason) = api.chain.halt_reason() {
        halted_message(reason)
    } else if api.chain.epoch() != epoch {
        RESEEDED
    } else {
        return;
    };
    for (req, resp) in batch.iter().zip(out) {
        if !outlives_chain_change(method_of(req), resp.code) {
            // Only a request with a valid id has an answer that does not outlive the change.
            let id = request_id(req).unwrap_or(Value::Null);
            *resp = Answer::new(&id, Err(RpcError::other(message)));
        }
    }
}

/// A reply to `method` with error code `code` (`None` for a result) that holds across a halt or a
/// re-seed: the chain id, refusals of the request itself, and the server's timeout (`-32002`) and
/// size refusals (`-32003`, `-32005`), which tell the client what to send again. Any other reply,
/// a revert or an EVM error included, came from the chain.
const fn outlives_chain_change(method: &str, code: Option<i64>) -> bool {
    matches!(method.as_bytes(), b"eth_chainId" | b"net_version") ||
        matches!(code, Some(-32602..=-32600 | -32002 | -32003 | -32005))
}

/// The timeout answer to `req`, with geth's timeout code.
fn timed_out(req: &Value) -> Answer {
    let err = RpcError::new(-32002, REQUEST_TIMED_OUT);
    Answer::new(&request_id(req).unwrap_or(Value::Null), Err(err))
}

/// [`timed_out`], counted.
fn count_timed_out(api: &Api, req: &Value) -> Answer {
    let reply = timed_out(req);
    api.count_reply(method_of(req), &reply);
    reply
}

/// Handles one HTTP body: a request or a batch. A request still unanswered at `deadline` gets
/// [`REQUEST_TIMED_OUT`]; a batch keeps the answers it finished before it. The answers are
/// charged to `budget`, and the reply comes with the permit to hold until it is written. Each
/// answer is held as its text from the moment it is computed, so the permit bounds the memory
/// the reply holds. `None` when the body holds only notifications.
pub async fn handle_body(
    api: &Arc<Api>,
    body: &[u8],
    deadline: Instant,
    budget: &Arc<tokio::sync::Semaphore>,
) -> Option<(ReplyBody, Option<tokio::sync::OwnedSemaphorePermit>)> {
    let mut charge = ResponseCharge::new(budget, MAX_RESPONSE);
    // A reply to the whole body, counted once under `other`.
    let whole = |err: RpcError| {
        let reply = Answer::new(&Value::Null, Err(err));
        api.count_reply("", &reply);
        ReplyBody::one(reply)
    };
    let reply = match serde_json::from_slice::<Value>(body) {
        Err(_) => Some(whole(RpcError::new(-32700, "parse error"))),
        Ok(Value::Array(batch)) => {
            if batch.is_empty() {
                return Some((whole(RpcError::new(-32600, "empty batch")), None));
            }
            if batch.len() > MAX_BATCH {
                // As geth: an array of one error, with the id of the first call.
                let call = |r: &Value| {
                    r.get("method").is_some_and(Value::is_string) && r.get("id").is_some()
                };
                let id = batch
                    .iter()
                    .find_map(|r| call(r).then(|| request_id(r)).flatten())
                    .unwrap_or(Value::Null);
                let reply = Answer::new(&id, Err(RpcError::new(-32600, BATCH_TOO_LARGE)));
                api.count_reply("", &reply);
                return Some((ReplyBody::batch(vec![reply]), None));
            }
            let epoch = api.chain.epoch();
            let mut out = Vec::with_capacity(batch.len());
            for r in &batch {
                // `timeout_at` polls its future once even past the deadline.
                let resp = if Instant::now() < deadline {
                    tokio::time::timeout_at(deadline, answer_capped(api, r, &mut charge)).await.ok()
                } else {
                    None
                };
                out.push(resp.unwrap_or_else(|| timed_out(r)));
                // Items that never suspend would otherwise run the whole batch in one poll, out
                // of reach of the request timeout and of every other task on this worker.
                tokio::task::yield_now().await;
            }
            drop_stale_answers(api, epoch, &batch, &mut out);
            // Counted only now: a halt or a re-seed replaces answers computed before it.
            for (r, v) in batch.iter().zip(&out) {
                api.count_reply(method_of(r), v);
            }
            // A notification's answer counts toward the response cap: `out` holds it until here.
            let out: Vec<Answer> = batch
                .iter()
                .zip(out)
                .filter(|(r, _)| !is_notification(r))
                .map(|(_, v)| v)
                .collect();
            (!out.is_empty()).then(|| ReplyBody::batch(out))
        }
        Ok(single) => {
            charge.cap = MAX_SINGLE_RESPONSE;
            let resp = tokio::time::timeout_at(deadline, handle_capped(api, &single, &mut charge))
                .await
                .unwrap_or_else(|_| count_timed_out(api, &single));
            (!is_notification(&single)).then(|| ReplyBody::one(resp))
        }
    };
    reply.map(|v| (v, charge.permit))
}

/// Bounds of the HTTP server.
#[derive(Debug, Clone, Copy)]
pub struct ServerLimits {
    /// Connections served at once; more wait in the accept backlog.
    pub max_connections: usize,
    /// Time a client has to send a request's headers once they begin, and a new connection its
    /// first request's headers.
    pub header_timeout: Duration,
    /// Time a kept-alive connection may wait for its next request. Above one slot, so a client
    /// that polls once per slot does not send as the server closes the connection.
    pub idle_timeout: Duration,
    /// Time one request (or batch) may take before it is answered with an error.
    pub request_timeout: Duration,
    /// Request body bytes held at once, across all connections: each body and its parsed form.
    pub body_budget: usize,
    /// The most of the body budget one body may hold (at most the budget). A body charged more
    /// is answered HTTP 413, so one request cannot hold the whole budget until its timeout. A
    /// quarter of the budget by default: four bodies at this cap always fit, and so does a body
    /// of [`MAX_BODY`] text whose parsed form is about its own size.
    pub max_body_charge: usize,
    /// Response bytes held at once, across all connections, until they are written. Answers are
    /// held only as their text, so this bounds the memory they hold. At least 64 MiB, the cap on
    /// one answer, or the largest answers are always refused.
    pub response_budget: usize,
    /// Time a response write may make no progress before the connection is closed.
    pub write_timeout: Duration,
    /// The slowest a client may read a response, in bytes per second: a response must be written
    /// within `write_timeout` plus its length at this rate.
    pub min_write_rate: usize,
    /// Time a request body may send nothing before it is answered with an error.
    pub body_idle_timeout: Duration,
    /// The slowest a client may send a request body, in bytes per second: once it has its share of
    /// the body budget, a body must arrive within `body_idle_timeout` plus its declared length at
    /// this rate, so a body sent a byte at a time cannot hold the budget until the request
    /// timeout.
    pub min_body_rate: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            header_timeout: Duration::from_secs(10),
            // geth's idle timeout.
            idle_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(60),
            body_budget: 48 << 20,
            max_body_charge: 12 << 20,
            response_budget: 64 << 20,
            write_timeout: Duration::from_secs(30),
            min_write_rate: 256 << 10,
            body_idle_timeout: Duration::from_secs(10),
            min_body_rate: 256 << 10,
        }
    }
}

/// The request-timeout text.
pub const REQUEST_TIMED_OUT: &str = "request timed out";

/// Binds `addr` and serves until dropped. Returns the bound address.
pub async fn serve(
    api: Arc<Api>,
    addr: SocketAddr,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    serve_listener(api, TcpListener::bind(addr).await?)
}

/// Serves on an already bound listener. Binding first lets the node accept connections while it
/// is still starting up (requests wait in the backlog).
pub fn serve_listener(
    api: Arc<Api>,
    listener: TcpListener,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    serve_listener_with(api, listener, ServerLimits::default())
}

/// [`serve_listener`] with explicit limits.
pub fn serve_listener_with(
    api: Arc<Api>,
    listener: TcpListener,
    limits: ServerLimits,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let local = listener.local_addr()?;
    let listener = Arc::new(listener);
    let accept = move || {
        let listener = listener.clone();
        async move { listener.accept().await.map(|(sock, _)| sock) }
    };
    Ok((local, tokio::spawn(accept_loop(api, limits, accept))))
}

/// Serves each connection `accept` returns.
async fn accept_loop<A, F>(api: Arc<Api>, limits: ServerLimits, mut accept: A)
where
    A: FnMut() -> F,
    F: Future<Output = io::Result<tokio::net::TcpStream>>,
{
    let conns = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let budget = Arc::new(tokio::sync::Semaphore::new(limits.body_budget));
    let responses = Arc::new(tokio::sync::Semaphore::new(limits.response_budget));
    loop {
        // At the cap, stop accepting: new connections wait in the backlog.
        let Ok(permit) = conns.clone().acquire_owned().await else { return };
        let sock = match accept().await {
            Ok(sock) => sock,
            Err(e) => {
                if let Some(pause) = accept_pause(&e) {
                    tracing::warn!(error = %e, "rpc accept failed; pausing");
                    tokio::time::sleep(pause).await;
                }
                continue;
            }
        };
        let (api, budget, responses) = (api.clone(), budget.clone(), responses.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let write_by = Arc::new(Mutex::new(None));
            let phase = Arc::new(Mutex::new(ReadPhase::Head(after(limits.header_timeout))));
            let sock = ConnDeadlines {
                sock,
                timeout: limits.write_timeout,
                write_by: write_by.clone(),
                stalled: None,
                header_timeout: limits.header_timeout,
                phase: phase.clone(),
                head_timer: None,
            };
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let (api, budget, responses) = (api.clone(), budget.clone(), responses.clone());
                let write_by = write_by.clone();
                // hyper has read the whole head; the body has its own timeouts.
                *phase.lock() = ReadPhase::Request;
                let phase = phase.clone();
                async move {
                    let reply = |data: ReplyBody, status: u16, permit| {
                        *phase.lock() = ReadPhase::Idle;
                        // Progress does not move this deadline: a client that reads a little
                        // now and then cannot keep the response for hours.
                        let at_rate = at_rate(data.len(), limits.min_write_rate);
                        *write_by.lock() =
                            Some(after(limits.write_timeout.saturating_add(at_rate)));
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(ChargedBody::new(data, permit))
                            .map_err(std::io::Error::other)
                    };
                    let ok = |data: Vec<u8>, status: u16| reply(data.into(), status, None);
                    if !local_host(req.headers()) {
                        return ok(b"{\"error\":\"invalid host specified\"}".to_vec(), 403);
                    }
                    // As geth: a GET with no body and no query is a load balancer's health check.
                    if req.method() == hyper::Method::GET &&
                        req.uri().query().is_none() &&
                        req.body().is_end_stream()
                    {
                        return ok(Vec::new(), 200);
                    }
                    if req.method() != hyper::Method::POST {
                        return ok(b"{\"error\":\"POST only\"}".to_vec(), 405);
                    }
                    if !json_content_type(req.headers()) {
                        let msg = b"{\"error\":\"invalid content type, only application/json is supported\"}";
                        return ok(msg.to_vec(), 415);
                    }
                    let deadline = after(limits.request_timeout);
                    // The body and its parsed form live under these permits, so many large
                    // requests at once wait instead of exhausting memory.
                    let read = read_body(req.into_body(), &budget, &limits);
                    let (body, _bytes) = match tokio::time::timeout_at(deadline, read).await {
                        Ok(Ok(read)) => read,
                        Ok(Err((status, msg))) => return ok(msg, status),
                        Err(_) => return ok(timed_out(&Value::Null).to_vec(), 200),
                    };
                    match handle_body(&api, &body, deadline, &responses).await {
                        Some((data, permit)) => reply(data, 200, permit),
                        None => ok(Vec::new(), 200),
                    }
                }
            });
            // hyper runs this timer from the end of each response to the end of the next head,
            // so it bounds the idle time. `ConnDeadlines` bounds a head from its first byte.
            let _ = http1::Builder::new()
                .max_buf_size(CONN_BUF)
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(limits.idle_timeout.max(limits.header_timeout))
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}

/// Limits of the Prometheus listener.
#[derive(Debug, Clone, Copy)]
pub struct MetricsLimits {
    /// Connections served at once; more wait in the accept backlog.
    pub max_connections: usize,
    /// Time a connection may take to send a whole request head: from its start, and after each
    /// answer on a kept-alive connection.
    pub idle_timeout: Duration,
    /// Time a connection may stay open in all.
    pub lifetime: Duration,
}

impl Default for MetricsLimits {
    fn default() -> Self {
        // A scraper sends one small request; a slot is plenty more than it needs.
        Self {
            max_connections: 16,
            idle_timeout: Duration::from_secs(10),
            lifetime: Duration::from_secs(30),
        }
    }
}

/// Serves the Prometheus text that `render` returns on `listener`, for a `GET` or `HEAD` on any
/// path. It has a connection cap, the limits above and the RPC's pause after an accept error,
/// since the process shares one file-descriptor limit with the RPC and the peers. Returns the
/// bound address.
///
/// The server decides the `Host` check for each connection, from the address that the connection
/// reached (see [`metrics_checks_host`]). A connection to a loopback address has the RPC's `Host`
/// check, which stops a DNS-rebound page, also on a wildcard bind such as `0.0.0.0`. On any other
/// address a scraper sends the node's DNS name, which the server cannot know, so it takes any
/// host: whoever can reach that address can read the metrics, as with the stock exporter.
pub fn serve_metrics(
    listener: TcpListener,
    limits: MetricsLimits,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let local = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let conns = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
        loop {
            // At the cap, stop accepting: new connections wait in the backlog.
            let Ok(permit) = conns.clone().acquire_owned().await else { return };
            let sock = match listener.accept().await {
                Ok((sock, _)) => sock,
                Err(e) => {
                    if let Some(pause) = accept_pause(&e) {
                        tracing::warn!(error = %e, "metrics accept failed; pausing");
                        tokio::time::sleep(pause).await;
                    }
                    continue;
                }
            };
            // The address this connection reached, not the bound one: on a wildcard bind a
            // DNS-rebound page reaches the server on loopback. Without it, check the host.
            let check_host = sock.local_addr().map_or(true, |a| metrics_checks_host(a.ip()));
            let render = render.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let reply = |status: u16, kind: &str, body: String| {
                        Response::builder()
                            .status(status)
                            .header("content-type", kind)
                            .body(http_body_util::Full::new(HBytes::from(body)))
                    };
                    let resp = if !matches!(*req.method(), hyper::Method::GET | hyper::Method::HEAD)
                    {
                        reply(405, "text/plain", "GET only\n".to_owned())
                    } else if check_host && !local_host(req.headers()) {
                        reply(403, "text/plain", "invalid host specified\n".to_owned())
                    } else {
                        reply(200, "text/plain; version=0.0.4", render())
                    };
                    std::future::ready(resp)
                });
                let conn = http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(limits.idle_timeout)
                    .serve_connection(TokioIo::new(sock), svc);
                let _ = tokio::time::timeout(limits.lifetime, conn).await;
            });
        }
    });
    Ok((local, task))
}

/// Reads a request body of at most [`MAX_BODY`]. Once a byte past [`FREE_BODY`] arrives, the rest
/// of the declared length (the cap, for a body that declared none) is charged to `budget` in
/// one go. Once the body is read, what its parsed form adds (see [`JsonCost`]) is charged too. A
/// body whose charge is more than [`ServerLimits::max_body_charge`] is answered HTTP 413 and is
/// never parsed. A
/// charge that finds no room within [`PARSED_CHARGE_WAIT`] is answered [`BODY_BUDGET_FULL`]. A
/// refused body is still read to its end, and dropped as it arrives, so the client gets the
/// answer. The permit comes back with the body. A body that sends nothing for the idle timeout,
/// or arrives slower than the minimum rate, is answered [`REQUEST_TIMED_OUT`].
async fn read_body(
    body: hyper::body::Incoming,
    budget: &Arc<tokio::sync::Semaphore>,
    limits: &ServerLimits,
) -> Result<(Vec<u8>, Option<tokio::sync::OwnedSemaphorePermit>), (u16, Vec<u8>)> {
    let too_large = || (413, b"{\"error\":\"body too large\"}".to_vec());
    let busy = || {
        let err = RpcError::new(-32005, BODY_BUDGET_FULL);
        (200, serde_json::to_vec(&rpc_response(&Value::Null, Err(err))).unwrap_or_default())
    };
    let declared = body.size_hint().upper().unwrap_or(MAX_BODY as u64);
    let declared =
        usize::try_from(declared).ok().filter(|n| *n <= MAX_BODY).ok_or_else(too_large)?;
    let charge = declared.saturating_sub(FREE_BODY);
    let cap = limits.max_body_charge.min(limits.body_budget);
    let mut body = Limited::new(body, MAX_BODY);
    let (mut buf, mut permit, mut parsed) = (Vec::new(), None, JsonCost::default());
    // Set once the body is refused: the rest is read and dropped.
    let mut refused = None;
    let in_time = limits.body_idle_timeout.saturating_add(at_rate(declared, limits.min_body_rate));
    let mut read_by = after(in_time);
    loop {
        let idle = after(limits.body_idle_timeout).min(read_by);
        let frame = match tokio::time::timeout_at(idle, body.frame()).await {
            Err(_) => return Err((200, timed_out(&Value::Null).to_vec())),
            Ok(None) => break,
            Ok(Some(Err(e))) if e.is::<LengthLimitError>() => return Err(too_large()),
            Ok(Some(Err(_))) => return Err((400, b"{\"error\":\"invalid request body\"}".to_vec())),
            Ok(Some(Ok(frame))) => frame,
        };
        // Trailers carry no body bytes.
        let Ok(data) = frame.into_data() else { continue };
        if refused.is_some() {
            continue;
        }
        if permit.is_none() && buf.len().saturating_add(data.len()) > FREE_BODY {
            let bytes = match u32::try_from(charge) {
                Ok(n) if charge <= cap => {
                    let wait = budget.clone().acquire_many_owned(n);
                    tokio::time::timeout(PARSED_CHARGE_WAIT, wait).await.map_err(|_| busy())
                }
                _ => Err(too_large()),
            };
            // The wait for the budget is not the client's: its time starts again.
            read_by = after(in_time);
            match bytes {
                Ok(bytes) => permit = Some(bytes.expect("the body budget is never closed")),
                Err(reply) => {
                    refused = Some(reply);
                    buf = Vec::new();
                    continue;
                }
            }
        }
        parsed.feed(&data);
        buf.extend_from_slice(&data);
        // Refused as soon as it passes its cap: its parsed form would hold more than one body
        // may.
        if buf.len().saturating_add(parsed.cost()).saturating_sub(FREE_BODY) > cap {
            refused = Some(too_large());
            (buf, permit) = (Vec::new(), None);
        }
    }
    if let Some(reply) = refused {
        return Err(reply);
    }
    let total = buf.len().saturating_add(parsed.cost()).saturating_sub(FREE_BODY);
    let held = permit.as_ref().map_or(0, |p: &tokio::sync::OwnedSemaphorePermit| p.num_permits());
    let more = total.saturating_sub(held);
    if more > 0 {
        let more = u32::try_from(more).map_err(|_| too_large())?;
        // Short whether or not the body holds a read charge: bodies that each wait for room the
        // others hold would otherwise all wait until the request timeout.
        let wait = budget.clone().acquire_many_owned(more);
        let bytes = tokio::time::timeout(PARSED_CHARGE_WAIT, wait).await.map_err(|_| busy())?;
        let bytes = bytes.expect("the body budget is never closed");
        match &mut permit {
            Some(held) => held.merge(bytes),
            None => permit = Some(bytes),
        }
    }
    Ok((buf, permit))
}

/// The largest chunk a response body hands hyper at once.
const RESPONSE_CHUNK: usize = 16 << 10;

/// A response body that holds its charge to the response budget until hyper has taken its last
/// chunk. Each chunk is a copy, so the whole response is freed with the permit: hyper queues at
/// most [`CONN_BUF`] and one chunk beyond it. Each piece is freed once it is copied.
struct ChargedBody {
    pieces: Vec<Cow<'static, [u8]>>,
    /// The piece the next chunk starts in, and the offset in it.
    at: usize,
    offset: usize,
    /// The bytes not yet handed to hyper.
    left: usize,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl ChargedBody {
    fn new(data: ReplyBody, permit: Option<tokio::sync::OwnedSemaphorePermit>) -> Self {
        Self { left: data.len, pieces: data.pieces, at: 0, offset: 0, _permit: permit }
    }
}

impl Body for ChargedBody {
    type Data = HBytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<HBytes>, Self::Error>>> {
        let this = self.get_mut();
        let want = this.left.min(RESPONSE_CHUNK);
        if want == 0 {
            return Poll::Ready(None);
        }
        let mut chunk = Vec::with_capacity(want);
        // The pieces from `at` on hold `left` bytes, so they fill the chunk.
        while chunk.len() < want {
            let piece = &this.pieces[this.at];
            let take = (want - chunk.len()).min(piece.len() - this.offset);
            chunk.extend_from_slice(&piece[this.offset..this.offset + take]);
            this.offset += take;
            if this.offset == piece.len() {
                this.pieces[this.at] = Cow::Borrowed(&[]);
                (this.at, this.offset) = (this.at + 1, 0);
            }
        }
        this.left -= want;
        Poll::Ready(Some(Ok(Frame::data(HBytes::from(chunk)))))
    }

    fn is_end_stream(&self) -> bool {
        self.left == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.left as u64)
    }
}

/// How long the accept loop waits after an accept error.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_secs(1);

/// The pause after accept error `e`. A client that dropped its own connection is skipped at once;
/// any other error (EMFILE, ENFILE) leaves the connection in the backlog and fails again at once.
fn accept_pause(e: &io::Error) -> Option<Duration> {
    match e.kind() {
        io::ErrorKind::ConnectionAborted |
        io::ErrorKind::ConnectionReset |
        io::ErrorKind::ConnectionRefused => None,
        _ => Some(ACCEPT_ERROR_PAUSE),
    }
}

/// geth's JSON media types. A browser sends any other type cross-origin only after a CORS
/// preflight, and the server refuses the preflight's `OPTIONS`.
fn json_content_type(headers: &hyper::HeaderMap) -> bool {
    let Some(v) = headers.get(hyper::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let media = v.split(';').next().unwrap_or_default().trim();
    ["application/json", "application/json-rpc", "application/jsonrequest"]
        .iter()
        .any(|t| media.eq_ignore_ascii_case(t))
}

/// Whether a metrics connection that reached `local` has the `Host` check: only a loopback
/// address, which a DNS-rebound page can reach. An IPv4-mapped address counts as its IPv4 one.
pub(crate) const fn metrics_checks_host(local: std::net::IpAddr) -> bool {
    local.to_canonical().is_loopback()
}

/// `localhost` or an IP literal, as geth's default `--http.vhosts`: a DNS-rebound page sends its
/// own host name. A request without a Host header did not come from a browser.
fn local_host(headers: &hyper::HeaderMap) -> bool {
    let Some(v) = headers.get(hyper::header::HOST) else { return true };
    let Some(a) = v.to_str().ok().and_then(|s| s.parse::<hyper::http::uri::Authority>().ok())
    else {
        return false;
    };
    let host = a.host();
    host.eq_ignore_ascii_case("localhost") ||
        host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok()
}

/// The time `len` bytes take at `rate` bytes per second.
fn at_rate(len: usize, rate: usize) -> Duration {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    let rate = u64::try_from(rate.max(1)).unwrap_or(u64::MAX);
    Duration::from_millis(len.saturating_mul(1000) / rate)
}

/// `d` from now. A time past `Instant`'s range is 30 years, as `tokio::time::timeout`.
fn after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).unwrap_or_else(|| now + Duration::from_secs(30 * 365 * 86_400))
}

/// Where a connection is in its request cycle, for the header deadline.
#[derive(Debug, Clone, Copy)]
enum ReadPhase {
    /// A response was handed to hyper: the next byte begins a head.
    Idle,
    /// A head has begun, and must be read by this time.
    Head(Instant),
    /// The service has the request.
    Request,
}

/// A socket whose writes fail once they make no progress for `timeout`, or once the response
/// being written passes its `write_by` deadline, so a client that stops reading, or reads too
/// slowly, cannot hold its connection slot and its response. Its reads fail once a head is not
/// read `header_timeout` after its first byte.
struct ConnDeadlines {
    sock: tokio::net::TcpStream,
    timeout: Duration,
    /// Set by the service as it hands hyper each response.
    write_by: Arc<Mutex<Option<Instant>>>,
    /// Running while the socket refuses writes.
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
    header_timeout: Duration,
    /// Set by the service as it takes each request and hands hyper each response.
    phase: Arc<Mutex<ReadPhase>>,
    /// Running while a head is read.
    head_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl ConnDeadlines {
    fn deadline<T>(
        &mut self,
        cx: &mut Context<'_>,
        res: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if res.is_ready() {
            self.stalled = None;
            return res;
        }
        let mut until = after(self.timeout);
        if let Some(by) = *self.write_by.lock() {
            until = until.min(by);
        }
        let stalled = self.stalled.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(until)));
        if stalled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response write stalled",
            )));
        }
        Poll::Pending
    }
}

impl AsyncRead for ConnDeadlines {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = buf.filled().len();
        let res = Pin::new(&mut self.sock).poll_read(cx, buf);
        let phase = {
            let mut phase = self.phase.lock();
            if matches!(*phase, ReadPhase::Idle) && buf.filled().len() > filled {
                *phase = ReadPhase::Head(after(self.header_timeout));
            }
            *phase
        };
        let ReadPhase::Head(by) = phase else {
            self.head_timer = None;
            return res;
        };
        if res.is_ready() {
            return res;
        }
        let timer = self.head_timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(by)));
        // A later head has a later deadline.
        if timer.deadline() != by {
            timer.as_mut().reset(by);
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request head not read in time",
            )));
        }
        Poll::Pending
    }
}

impl AsyncWrite for ConnDeadlines {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.sock).poll_write(cx, buf);
        self.deadline(cx, res)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.sock).poll_write_vectored(cx, bufs);
        self.deadline(cx, res)
    }

    fn is_write_vectored(&self) -> bool {
        self.sock.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.sock).poll_flush(cx);
        self.deadline(cx, res)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.sock).poll_shutdown(cx);
        self.deadline(cx, res)
    }
}

#[cfg(test)]
mod tests;
