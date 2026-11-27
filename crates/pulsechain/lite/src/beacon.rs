//! Following the head from beacon REST APIs.
//!
//! Each `--beacon.url` is a base URL that gets `/eth/...` appended. It may carry a key in its
//! path, so the whole URL is a secret: it is never logged, never put in a metric label and never
//! in an error. [`SourceError`] carries a kind only, and logs name at most the last two labels
//! of the host (see [`host_label`]).
//!
//! Per source, SSE (`/eth/v1/events`) is used when it works, with `headers/head` fetched once at
//! start. Otherwise the source is polled: `headers/head` every `--beacon.poll`, the finality
//! checkpoint every sixth poll, SSE retried at most once a minute. A head reported by at least
//! `--beacon.quorum` sources is turned into an execution block (see [`crate::payload`]), its
//! ancestry is completed through beacon `parent_root`s down to a held block, and the head moves.
//! A head or block a source marks `execution_optimistic` is not used: that source has not
//! validated the payload.
//!
//! With `--head.confirm=peer` (the default) a new head also needs a static `--peer` to report
//! the same block hash: the rebuilt hash proves only that a payload is self-consistent, so a
//! beacon could otherwise forge header fields (timestamp, base fee, prevrandao, transactions) of a
//! block that carries the real state root. Confirming the head confirms its ancestry too, since
//! each hash commits to its parent's. With `--head.confirm=none` the beacon quorum is trusted
//! alone.
//!
//! Nothing is followed before the finalized anchor is fetched and verified. The anchor is
//! re-checked when finality moves and at least every `--finalized.recheck`; a held block that
//! disagrees with it halts serving. The node re-seeds from the anchor only when the head-confirm
//! peer or a beacon quorum vouches for the anchor block, and never to a lower finalized number;
//! otherwise it stays halted until the anchor agrees again or an operator restarts it. With no
//! such source, an anchor above the head halts serving too, until the head reaches it and it
//! agrees.
//!
//! With `--head.verify=sync-committee` heads and finality come from light-client updates the
//! sync committee signed instead (the `sync` child module).

use crate::{
    chain::{body_bytes, AnchorStatus, HaltReason, HeaderChain, HeldBlock},
    config::LiteConfig,
    light_client::{parse_update, UpdateKind},
    metrics::{FailureSource, LiteMetrics},
    payload::{parse_beacon_block, ForkSchedule, ParsedBlock, PayloadError},
    sync_committee::{LightClientUpdate, Preset},
};
use alloy_primitives::B256;
use futures::StreamExt;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Notify, time::sleep};
use url::Url;

mod sync;

/// How many ancestors are fetched to connect a head to the held chain.
pub const MAX_ANCESTORS: usize = 512;
/// The oldest finalized anchor accepted at start. Finality runs about two epochs (some 11
/// minutes) behind the head; an anchor much older is stale, replayed or from another chain.
pub const MAX_ANCHOR_AGE: Duration = Duration::from_secs(60 * 60);
/// The shortest gap between two anchor checks woken by finality events.
pub const MIN_ANCHOR_GAP: Duration = Duration::from_secs(30);
/// Anchor checks after a finality event until finality moves: at [`MIN_ANCHOR_GAP`] apart they
/// cover the 320 s epoch up to the next event.
pub const FINALITY_RETRIES: u32 = 10;
/// How many blocks below the held head a new head may be (a short reorg).
pub const MAX_BACKWARD: u64 = 2;
/// How much older than the held head a new head's timestamp may be (two 10 s slots).
pub const MAX_BACKWARD_SECS: u64 = 20;
/// The shortest idle bound of an event stream: one 10 s slot plus 5 s, so an honest stream that
/// sends one head event per slot stays open at any `--beacon.poll`.
pub const MIN_SSE_IDLE: Duration = Duration::from_secs(15);
/// The shortest interval of the `headers/head` poll while an event stream is open.
pub const MIN_SSE_WATCHDOG: Duration = Duration::from_secs(2);
/// The finality checkpoint is read every this many polls.
pub const FINALITY_EVERY: u64 = 6;
/// The shortest poll and anchor re-check interval: at zero, the poll and anchor loops spin.
pub const MIN_POLL: Duration = Duration::from_millis(100);

/// A failed request to a source. Never carries the URL or the body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// Could not connect.
    #[error("could not connect")]
    Connect,
    /// Timed out.
    #[error("timed out")]
    Timeout,
    /// Another request failure.
    #[error("request failed")]
    Request,
    /// A non-success status.
    #[error("http status {0}")]
    Status(u16),
    /// The body was not what the API returns.
    #[error("unexpected response body")]
    Body,
    /// The body is larger than the call's limit: [`MAX_SMALL_BODY`] for `headers/head` and
    /// `finality_checkpoints`, [`MAX_BEACON_BODY`] for a block.
    #[error("response body too large")]
    TooLarge,
    /// The source has not validated the execution payload (`execution_optimistic`).
    #[error("execution payload not validated by the source")]
    Optimistic,
    /// The source says the block it served as finalized is not finalized.
    #[error("block not finalized")]
    NotFinalized,
    /// Light-client data of a fork this binary cannot verify, such as Deneb.
    #[error("light-client data of an unsupported fork")]
    UnsupportedFork,
}

/// The largest beacon block answer read. The consensus gossip limit holds a block to 10 MiB of
/// SSZ, and JSON hex doubles its transaction bytes: a block at the 45M gas limit full of zero
/// calldata (4 gas a byte, no EIP-7623 floor) is over 20 MiB of JSON.
pub const MAX_BEACON_BODY: usize = 32 << 20;
/// How long a `headers/head` or `finality_checkpoints` request may take in all, and a block
/// request before what it has read earns it more time ([`MIN_BLOCK_RATE`]).
pub(crate) const SMALL_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest a block request may take, however fast its bytes come: about
/// [`MAX_BEACON_BODY`] at [`MIN_BLOCK_RATE`].
pub(crate) const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);
/// Each this many bytes a block answer has sent give it one second past [`SMALL_TIMEOUT`]. An
/// honest large block comes faster, and a source that sends less is cut off at
/// [`SMALL_TIMEOUT`]. One that sends more can keep a request open up to [`BLOCK_TIMEOUT`]:
/// [`ADVANCE_BUDGET`] bounds how long that holds the head coordinator.
const MIN_BLOCK_RATE: u64 = 512 << 10;
/// How long any request may wait for its next bytes.
const READ_IDLE: Duration = Duration::from_secs(10);
/// The largest `headers/head` or `finality_checkpoints` body read. An honest one is under 1 KiB.
pub const MAX_SMALL_BODY: usize = 64 << 10;
/// The largest event read from an event stream. An honest head event is under 1 KiB.
pub const MAX_SSE_EVENT: usize = 64 << 10;
/// The most transactions a block answer may list. Each costs at least 21000 gas, so this many
/// need over 1.3 billion gas, far above `PulseChain`'s block gas limit.
pub const MAX_TRANSACTIONS: usize = 1 << 16;
/// The most items a block answer may list in `withdrawals` or one `execution_requests` list
/// (the consensus presets allow at most 16 and 8192).
pub const MAX_WITHDRAWALS: usize = 1 << 13;
/// Block parses that run at once, each on a blocking thread. A parse of a full answer can take
/// a large fraction of a second of CPU; the bound keeps hostile answers from taking every core.
const MAX_CONCURRENT_PARSES: usize = 2;

pub(crate) fn classify(e: &reqwest::Error) -> SourceError {
    if e.is_timeout() {
        SourceError::Timeout
    } else if e.is_connect() {
        SourceError::Connect
    } else {
        SourceError::Request
    }
}

/// An event from the SSE stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new head, by beacon block root.
    Head(B256),
    /// The finalized checkpoint moved.
    Finalized,
    /// A `light_client_optimistic_update`, as an update with no finality and no next committee.
    OptimisticUpdate(Box<LightClientUpdate>),
    /// A `light_client_finality_update`, as an update with no next committee.
    FinalityUpdate(Box<LightClientUpdate>),
}

/// The topics an event stream subscribes to. A stream yields only the events of its topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topics {
    /// `head` and `finalized_checkpoint`.
    Head,
    /// `light_client_optimistic_update` and `light_client_finality_update`, for a committee of
    /// the preset's size.
    LightClient(Preset),
}

impl Topics {
    /// The `topics` query of the event stream request.
    const fn query(self) -> &'static str {
        match self {
            Self::Head => "topics=head,finalized_checkpoint",
            Self::LightClient(_) => {
                "topics=light_client_optimistic_update,light_client_finality_update"
            }
        }
    }
}

/// A beacon REST client for one base URL.
#[derive(Clone)]
pub struct BeaconClient {
    http: reqwest::Client,
    stream: reqwest::Client,
    base: Url,
    host: String,
}

impl std::fmt::Debug for BeaconClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The base URL is a secret: show the host only.
        f.debug_struct("BeaconClient").field("host", &self.host).finish_non_exhaustive()
    }
}

/// `scheme://host` of `url`, for logs, errors and the trust label. Never the userinfo, port,
/// path or query, and of a domain only the last two labels (`*.provider.example`): any of them
/// may hold a key.
pub fn host_label(url: &Url) -> String {
    let host = match url.host() {
        Some(url::Host::Domain(d)) => match d.rmatch_indices('.').nth(1) {
            Some((i, _)) => format!("*{}", &d[i..]),
            None => d.to_string(),
        },
        Some(_) => url.host_str().unwrap_or_default().to_string(),
        None => "unknown".to_string(),
    };
    format!("{}://{host}", url.scheme())
}

impl BeaconClient {
    /// A client for `base`.
    pub fn new(base: Url) -> Self {
        // Redirects are not followed: one could move a request to another host or to plain http.
        let http = reqwest::Client::builder()
            .read_timeout(READ_IDLE)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let stream = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let host = host_label(&base);
        Self { http, stream, base, host }
    }

    /// The [`host_label`] of the base URL.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// `path` under the base URL. The base query is kept, since it may hold the key, and
    /// `query` is appended to it.
    fn url(&self, path: &str, query: Option<&str>) -> Url {
        let mut u = self.base.clone();
        let joined = format!("{}{}", self.base.path().trim_end_matches('/'), path);
        u.set_path(&joined);
        if let Some(extra) = query {
            match self.base.query().filter(|q| !q.is_empty()) {
                Some(base) => u.set_query(Some(&format!("{base}&{extra}"))),
                None => u.set_query(Some(extra)),
            }
        }
        u
    }

    /// Fetches at most `limit` bytes from `path` and keeps only what `shape` names. The request
    /// may take `timeout`, plus one second for each [`MIN_BLOCK_RATE`] bytes read, up to `max`.
    async fn get_json(
        &self,
        path: &str,
        limit: usize,
        timeout: Duration,
        max: Duration,
        shape: &'static Shape,
    ) -> Result<Value, SourceError> {
        shape.parse(&self.get_body(path, None, limit, timeout, max).await?)
    }

    /// Fetches the body of `path` with `query`: at most `limit` bytes, within the time
    /// [`Self::get_json`] allows.
    pub(crate) async fn get_body(
        &self,
        path: &str,
        query: Option<&str>,
        limit: usize,
        timeout: Duration,
        max: Duration,
    ) -> Result<Vec<u8>, SourceError> {
        let started = tokio::time::Instant::now();
        let deadline = |read: usize| {
            let read = u64::try_from(read).unwrap_or(u64::MAX);
            let earned = Duration::from_millis(read.saturating_mul(1000) / MIN_BLOCK_RATE);
            started + timeout.saturating_add(earned).min(max)
        };
        let mut resp =
            tokio::time::timeout_at(deadline(0), self.http.get(self.url(path, query)).send())
                .await
                .map_err(|_| SourceError::Timeout)?
                .map_err(|e| classify(&e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(SourceError::Status(status.as_u16()));
        }
        // Streamed and bounded: a hostile source cannot make us buffer without limit.
        if resp.content_length().is_some_and(|n| n > limit as u64) {
            return Err(SourceError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = tokio::time::timeout_at(deadline(bytes.len()), resp.chunk())
            .await
            .map_err(|_| SourceError::Timeout)?
            .map_err(|e| classify(&e))?
        {
            if bytes.len() + chunk.len() > limit {
                return Err(SourceError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// The beacon head root (`headers/head`), unless the source has not validated its payload.
    pub async fn head_root(&self) -> Result<B256, SourceError> {
        let v = self
            .get_json(
                "/eth/v1/beacon/headers/head",
                MAX_SMALL_BODY,
                SMALL_TIMEOUT,
                SMALL_TIMEOUT,
                &HEAD_SHAPE,
            )
            .await?;
        match optimistic(&v) {
            Some(false) => root_at(&v, &["data", "root"]),
            Some(true) => Err(SourceError::Optimistic),
            None => Err(SourceError::Body),
        }
    }

    /// The finalized checkpoint root (`finality_checkpoints`).
    pub async fn finalized_root(&self) -> Result<B256, SourceError> {
        let v = self
            .get_json(
                "/eth/v1/beacon/states/head/finality_checkpoints",
                MAX_SMALL_BODY,
                SMALL_TIMEOUT,
                SMALL_TIMEOUT,
                &FINALITY_SHAPE,
            )
            .await?;
        root_at(&v, &["data", "finalized", "root"])
    }

    /// A beacon block by root, holding only the fields [`parse_beacon_block`] reads. A block
    /// whose payload the source has not validated is refused when it is parsed
    /// ([`PayloadError::Optimistic`]), so every caller counts it the same way.
    pub async fn block(&self, id: &str) -> Result<Value, SourceError> {
        let path = format!("/eth/v2/beacon/blocks/{id}");
        self.get_json(&path, MAX_BEACON_BODY, SMALL_TIMEOUT, BLOCK_TIMEOUT, &BLOCK_SHAPE).await
    }

    /// The finalized beacon block, as [`Self::block`], unless the source marks it not finalized.
    /// A source that does not send the `finalized` flag is taken at its word.
    pub async fn finalized_block(&self) -> Result<Value, SourceError> {
        let v = self.block("finalized").await?;
        if v.get("finalized") == Some(&Value::Bool(false)) {
            return Err(SourceError::NotFinalized);
        }
        Ok(v)
    }

    /// Opens the event stream of [`Topics::Head`]. Only a 200 with an event stream counts. A
    /// server that sends no response headers within `idle`, or a stream that then sends nothing
    /// for `idle`, ends.
    pub async fn events(&self, idle: Duration) -> Result<EventStream, SourceError> {
        self.events_of(Topics::Head, idle).await
    }

    /// Opens the event stream of `topics`, as [`Self::events`] does.
    pub async fn events_of(
        &self,
        topics: Topics,
        idle: Duration,
    ) -> Result<EventStream, SourceError> {
        let request = self.stream.get(self.url("/eth/v1/events", Some(topics.query()))).send();
        let resp = tokio::time::timeout(idle, request)
            .await
            .map_err(|_| SourceError::Timeout)?
            .map_err(|e| classify(&e))?;
        let status = resp.status();
        if status.as_u16() != 200 {
            return Err(SourceError::Status(status.as_u16()));
        }
        let is_sse = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        if !is_sse {
            return Err(SourceError::Body);
        }
        Ok(EventStream {
            inner: Box::pin(resp.bytes_stream()),
            topics,
            buf: Vec::new(),
            start: 0,
            scanned: 0,
            after_cr: false,
            idle,
            last_data: tokio::time::Instant::now(),
        })
    }
}

/// The JSON a beacon answer may hold. A field the shape does not name is skipped while
/// parsing, never built: a parsed `Value` of small maps costs about 100 times its text.
pub(crate) enum Shape {
    /// A string, number, bool or null.
    Scalar,
    /// A list of at most this many items of one shape.
    List(&'static Self, usize),
    /// An object; only these keys are kept.
    Object(&'static [(&'static str, Self)]),
}

use Shape::{List, Object, Scalar};

pub(crate) static HEAD_SHAPE: Shape =
    Object(&[("execution_optimistic", Scalar), ("data", Object(&[("root", Scalar)]))]);
pub(crate) static FINALITY_SHAPE: Shape =
    Object(&[("data", Object(&[("finalized", Object(&[("root", Scalar)]))]))]);
pub(crate) static SSE_HEAD_SHAPE: Shape =
    Object(&[("block", Scalar), ("execution_optimistic", Scalar)]);
pub(crate) static BLOCK_SHAPE: Shape = Object(&[
    ("execution_optimistic", Scalar),
    ("finalized", Scalar),
    (
        "data",
        Object(&[(
            "message",
            Object(&[
                ("parent_root", Scalar),
                (
                    "body",
                    Object(&[
                        (
                            "execution_payload",
                            Object(&[
                                ("parent_hash", Scalar),
                                ("fee_recipient", Scalar),
                                ("state_root", Scalar),
                                ("receipts_root", Scalar),
                                ("logs_bloom", Scalar),
                                ("prev_randao", Scalar),
                                ("block_number", Scalar),
                                ("gas_limit", Scalar),
                                ("gas_used", Scalar),
                                ("timestamp", Scalar),
                                ("extra_data", Scalar),
                                ("base_fee_per_gas", Scalar),
                                ("block_hash", Scalar),
                                ("blob_gas_used", Scalar),
                                ("excess_blob_gas", Scalar),
                                ("transactions", List(&Scalar, MAX_TRANSACTIONS)),
                                (
                                    "withdrawals",
                                    List(
                                        &Object(&[
                                            ("index", Scalar),
                                            ("validator_index", Scalar),
                                            ("address", Scalar),
                                            ("amount", Scalar),
                                        ]),
                                        MAX_WITHDRAWALS,
                                    ),
                                ),
                            ]),
                        ),
                        (
                            "execution_requests",
                            Object(&[
                                (
                                    "deposits",
                                    List(
                                        &Object(&[
                                            ("pubkey", Scalar),
                                            ("withdrawal_credentials", Scalar),
                                            ("amount", Scalar),
                                            ("signature", Scalar),
                                            ("index", Scalar),
                                        ]),
                                        MAX_WITHDRAWALS,
                                    ),
                                ),
                                (
                                    "withdrawals",
                                    List(
                                        &Object(&[
                                            ("source_address", Scalar),
                                            ("validator_pubkey", Scalar),
                                            ("amount", Scalar),
                                        ]),
                                        MAX_WITHDRAWALS,
                                    ),
                                ),
                                (
                                    "consolidations",
                                    List(
                                        &Object(&[
                                            ("source_address", Scalar),
                                            ("source_pubkey", Scalar),
                                            ("target_pubkey", Scalar),
                                        ]),
                                        MAX_WITHDRAWALS,
                                    ),
                                ),
                            ]),
                        ),
                    ]),
                ),
            ]),
        )]),
    ),
]);

impl Shape {
    pub(crate) fn parse(&'static self, bytes: &[u8]) -> Result<Value, SourceError> {
        use serde::de::DeserializeSeed;
        let mut de = serde_json::Deserializer::from_slice(bytes);
        let v = self.deserialize(&mut de).map_err(|_| SourceError::Body)?;
        de.end().map_err(|_| SourceError::Body)?;
        Ok(v)
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for &'static Shape {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        match self {
            Scalar => d.deserialize_any(self),
            List(..) => d.deserialize_seq(self),
            Object(_) => d.deserialize_map(self),
        }
    }
}

impl<'de> serde::de::Visitor<'de> for &'static Shape {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a beacon API answer")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let List(item, max) = self else {
            return Err(serde::de::Error::invalid_type(serde::de::Unexpected::Seq, &self));
        };
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(*item)? {
            if out.len() == *max {
                return Err(serde::de::Error::invalid_length(max + 1, &self));
            }
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let Object(fields) = self else {
            return Err(serde::de::Error::invalid_type(serde::de::Unexpected::Map, &self));
        };
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            match fields.iter().find(|(k, _)| *k == key) {
                Some((_, shape)) => {
                    out.insert(key, map.next_value_seed(shape)?);
                }
                None => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        Ok(Value::Object(out))
    }
}

/// Whether a beacon answer says the source has not validated the execution payload. A source
/// that does not send the flag is taken as validating. A flag that is not a bool is `None`:
/// the answer is malformed, as [`parse_beacon_block`] takes it.
fn optimistic(v: &Value) -> Option<bool> {
    match v.get("execution_optimistic") {
        None => Some(false),
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => None,
    }
}

fn root_at(v: &Value, path: &[&str]) -> Result<B256, SourceError> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k).ok_or(SourceError::Body)?;
    }
    cur.as_str().and_then(|s| s.parse().ok()).ok_or(SourceError::Body)
}

type ByteStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>;

/// A live SSE stream.
pub struct EventStream {
    inner: ByteStream,
    topics: Topics,
    /// Received bytes, every line end (CRLF, LF or CR) stored as LF. Events before `start` are
    /// already returned.
    buf: Vec<u8>,
    start: usize,
    /// `buf` up to here holds no event end: each byte is searched once, whatever the chunk size.
    scanned: usize,
    /// Whether the last byte received was a CR: an LF that starts the next chunk ends no line.
    after_cr: bool,
    idle: Duration,
    last_data: tokio::time::Instant,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStream").finish_non_exhaustive()
    }
}

impl EventStream {
    /// A stream that delivers `chunks` and then ends, for the fuzz targets.
    #[cfg(feature = "fuzzing")]
    pub(crate) fn from_chunks<I>(chunks: I, idle: Duration) -> Self
    where
        I: IntoIterator<Item = Vec<u8>>,
        I::IntoIter: Send + 'static,
    {
        let inner = futures::stream::iter(chunks).map(|c| Ok(bytes::Bytes::from(c)));
        Self {
            inner: Box::pin(inner),
            topics: Topics::Head,
            buf: Vec::new(),
            start: 0,
            scanned: 0,
            after_cr: false,
            idle,
            last_data: tokio::time::Instant::now(),
        }
    }

    /// The next event we care about, or `None` when the stream ended or failed.
    pub async fn next_event(&mut self) -> Option<Event> {
        loop {
            // An event end found by the last scan may straddle `scanned`.
            let from = self.scanned.saturating_sub(1).max(self.start);
            if let Some(at) = self.buf[from..].windows(2).position(|w| w == b"\n\n") {
                let end = from + at + 2;
                // One event longer than the cap ends the stream, however the chunks fell.
                if end - self.start > MAX_SSE_EVENT {
                    return None;
                }
                let block = String::from_utf8_lossy(&self.buf[self.start..end]).into_owned();
                (self.start, self.scanned) = (end, end);
                if let Some(e) = parse_sse_block(&block, self.topics) {
                    return Some(e);
                }
                continue;
            }
            self.scanned = self.buf.len();
            if self.start > 0 {
                self.buf.drain(..self.start);
                self.scanned -= self.start;
                self.start = 0;
            }
            // A hostile source cannot make us buffer without bound: `buf` now holds one
            // unfinished event. The cap is checked here, not on a whole chunk, so a chunk of many
            // small events is read, not dropped.
            if self.buf.len() > MAX_SSE_EVENT {
                return None;
            }
            // A stream that goes quiet is as good as gone: the caller polls and reconnects.
            // The deadline runs from the last data, not from this call, so a caller that drops
            // and re-polls this future does not keep a silent stream alive.
            let deadline = self.last_data + self.idle;
            let chunk = tokio::time::timeout_at(deadline, self.inner.next()).await.ok()??.ok()?;
            self.last_data = tokio::time::Instant::now();
            for &b in &chunk {
                match (b, std::mem::replace(&mut self.after_cr, b == b'\r')) {
                    (b'\r', _) => self.buf.push(b'\n'),
                    (b'\n', true) => {}
                    _ => self.buf.push(b),
                }
            }
        }
    }
}

/// The event in one SSE block, if it is of `topics` and parses.
pub(crate) fn parse_sse_block(block: &str, topics: Topics) -> Option<Event> {
    let mut event = None;
    let mut data = String::new();
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            event = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(v.trim());
        }
    }
    match (topics, event.as_deref()?) {
        (Topics::Head, "head") => {
            let v = SSE_HEAD_SHAPE.parse(data.as_bytes()).ok()?;
            if optimistic(&v)? {
                return None;
            }
            Some(Event::Head(root_at(&v, &["block"]).ok()?))
        }
        (Topics::Head, "finalized_checkpoint") => Some(Event::Finalized),
        (Topics::LightClient(preset), "light_client_optimistic_update") => {
            let update = parse_update(data.as_bytes(), preset, UpdateKind::Optimistic).ok()?;
            Some(Event::OptimisticUpdate(Box::new(update)))
        }
        (Topics::LightClient(preset), "light_client_finality_update") => {
            let update = parse_update(data.as_bytes(), preset, UpdateKind::Finality).ok()?;
            Some(Event::FinalityUpdate(Box::new(update)))
        }
        _ => None,
    }
}

/// What the follower needs from the configuration.
#[derive(Clone)]
pub struct FollowConfig {
    /// Beacon base URLs (secret).
    pub urls: Vec<Url>,
    /// Sources that must agree on a head.
    pub quorum: usize,
    /// Poll interval.
    pub poll: Duration,
    /// Finalized anchor source (secret-free by convention, but never logged in full).
    pub anchor_url: Url,
    /// Maximum time between anchor checks.
    pub recheck: Duration,
    /// Minimum time between SSE attempts while polling.
    pub sse_retry: Duration,
    /// The shortest gap between two anchor checks woken by finality events.
    pub anchor_gap: Duration,
    /// How long a root that could not be completed is left alone.
    pub failed_ttl: Duration,
    /// The oldest finalized anchor accepted, by its timestamp against the wall clock.
    pub max_anchor_age: Duration,
    /// The chain's fork schedule: a payload must have the shape of the fork at its timestamp.
    pub forks: ForkSchedule,
}

impl std::fmt::Debug for FollowConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let urls: Vec<String> = self.urls.iter().map(host_label).collect();
        f.debug_struct("FollowConfig")
            .field("urls", &urls)
            .field("quorum", &self.quorum)
            .field("poll", &self.poll)
            .field("anchor_url", &host_label(&self.anchor_url))
            .field("recheck", &self.recheck)
            .field("sse_retry", &self.sse_retry)
            .field("anchor_gap", &self.anchor_gap)
            .field("failed_ttl", &self.failed_ttl)
            .finish()
    }
}

impl From<&LiteConfig> for FollowConfig {
    fn from(c: &LiteConfig) -> Self {
        Self {
            urls: c.beacon_urls.clone(),
            quorum: c.beacon_quorum.max(1) as usize,
            poll: c.beacon_poll.max(MIN_POLL),
            anchor_url: c.anchor_url.clone(),
            recheck: c.anchor_recheck.max(MIN_POLL),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: MAX_ANCHOR_AGE,
            forks: ForkSchedule::for_chain(c.chain_id)
                .unwrap_or_else(|| ForkSchedule::fixed(crate::payload::Profile::Shanghai)),
        }
    }
}

/// The trust label: hosts only, never a path.
pub fn trust_label(cfg: &FollowConfig) -> String {
    let beacons: Vec<String> = cfg.urls.iter().map(host_label).collect();
    format!(
        "follows {}; finalized checked against {}",
        beacons.join(", "),
        host_label(&cfg.anchor_url)
    )
}

/// What a peer says about a head block hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// A peer holds a block with this hash.
    Confirmed,
    /// A peer holds a different block at this number.
    Mismatch,
    /// No peer could say (not reached yet, not connected).
    Unknown,
}

/// One header as a peer reports it on its canonical chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerHeader {
    /// The block hash.
    pub hash: B256,
    /// The parent hash.
    pub parent_hash: B256,
}

/// Independent execution peers (the static `--peer`s) asked to confirm a block.
#[async_trait::async_trait]
pub trait HeadConfirm: Send + Sync + std::fmt::Debug {
    /// Each peer's canonical header at `number` (`GetBlockHeaders` with a number origin, so a
    /// block the peer merely stores on a side chain does not count), in a fixed peer order.
    /// `None` where a peer has none.
    async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>>;

    /// A name for the peer at `index` of [`Self::headers_at`], for logs.
    fn peer_name(&self, index: usize) -> String {
        format!("#{index}")
    }
}

/// Asks `peers` whether `hash` is the canonical block at `number`.
///
/// A peer with a different canonical block at `number` vetoes, whatever the others say. With
/// `descendants` above zero a peer confirms only when its canonical chain also runs that many
/// blocks past `number` on top of `hash`, so the block is not just its latest tip.
pub async fn confirm_canonical(
    peers: &dyn HeadConfirm,
    number: u64,
    hash: B256,
    descendants: u64,
    depth: u64,
) -> Confirmation {
    let at = peers.headers_at(number).await;
    // Any veto wins (fail closed); the dissenting peer is named.
    if let Some(i) = at.iter().position(|h| h.is_some_and(|h| h.hash != hash)) {
        tracing::warn!(number, peer = %peers.peer_name(i), "a peer's canonical block differs");
        return Confirmation::Mismatch;
    }
    let mut ok: Vec<bool> = at.iter().map(|h| h.is_some()).collect();
    let mut want: Vec<B256> = vec![hash; at.len()];
    for k in 1..=descendants {
        if !ok.contains(&true) {
            break;
        }
        // No block can be that far above the last number.
        let Some(at) = number.checked_add(k) else { return Confirmation::Unknown };
        let above = peers.headers_at(at).await;
        for (i, h) in above.iter().enumerate() {
            match h {
                Some(h) if ok.get(i) == Some(&true) && h.parent_hash == want[i] => want[i] = h.hash,
                Some(_) if ok.get(i) == Some(&true) => {
                    tracing::warn!(number, peer = %peers.peer_name(i), "a peer's chain does not build on the block");
                    return Confirmation::Mismatch;
                }
                _ => {
                    if let Some(o) = ok.get_mut(i) {
                        *o = false;
                    }
                }
            }
        }
        // A peer the answer leaves out showed no block there.
        for o in ok.iter_mut().skip(above.len()) {
            *o = false;
        }
    }
    // With a depth, a peer also needs a canonical block that far above: the block is deep in
    // its chain, not near its tip.
    if depth > descendants && ok.contains(&true) {
        let Some(at) = number.checked_add(depth) else { return Confirmation::Unknown };
        let far = peers.headers_at(at).await;
        for (i, o) in ok.iter_mut().enumerate() {
            if far.get(i).is_none_or(Option::is_none) {
                *o = false;
            }
        }
    }
    if ok.contains(&true) {
        Confirmation::Confirmed
    } else {
        Confirmation::Unknown
    }
}

/// Blocks above an anchor whose parent links a peer's canonical chain must show.
pub const ANCHOR_DESCENDANTS: u64 = 2;
/// How deep below the head a block must be before it is taken as finalized (two epochs of 32
/// slots), and how far a peer's canonical chain must run past an anchor.
pub const FINALITY_MIN_DEPTH: u64 = 64;

/// How long a root no peer confirmed is left alone before the peers are asked again, without
/// waiting for another report while it still has quorum. It doubles with each try in a row
/// that stays unconfirmed, up to [`MAX_REPORT_BACKOFF`].
const UNCONFIRMED_TTL: Duration = Duration::from_secs(2);
/// Event streams in a row that each get an immediate reconnect; after them the source waits for
/// the `sse_retry` gate.
const MAX_QUICK_RECONNECTS: u32 = 3;
/// How often an unknown head is asked about before the next head report.
const CONFIRM_TRIES: u32 = 3;
/// The pause between confirmation tries.
const CONFIRM_PAUSE: Duration = Duration::from_millis(500);
/// A block answer that takes this long counts against its source's place in the order.
const SLOW_ANSWER: Duration = Duration::from_secs(2);
/// With quorum 1, how long the roots a source reports wait after one it reported failed,
/// counted from when that one was taken up (or, when it took [`SLOW_ANSWER`] or longer, from
/// when it ended) and doubling with each failure in a row.
const REPORT_BACKOFF: Duration = Duration::from_secs(1);
/// The longest [`REPORT_BACKOFF`]: below one 10 s slot, so an honest source that failed is
/// heard again by its next head.
const MAX_REPORT_BACKOFF: Duration = Duration::from_secs(8);
/// With two or more sources, the longest the head coordinator waits on one try to move the head:
/// one 10 s slot. A try still running then is dropped and the other reports are read; the
/// sources that held it are backed off for at least as long as they held it, and the ancestors
/// it fetched are kept for the next try. A source holds a try with a slow answer that the try
/// did not use and that took [`SLOW_ANSWER`] or more past the slowest answer of its own the try
/// used, counted as [`SLOW_ANSWER`] at most: a slow answer the walk used is progress, so sources
/// that are all honest and slow still move the head, a try at a time. Another source's slow
/// answer excuses nothing, and a source's own excuses one [`SLOW_ANSWER`] at most.
const ADVANCE_BUDGET: Duration = Duration::from_secs(10);
/// How many roots that moved the head or named a followed block the coordinator keeps. A
/// report of one again is passed over while its block is still followed: a source that lags
/// one block would otherwise send the head root back to the sources each time it reports.
const RECENT_OK: usize = 8;

/// The latest head root each source reported: one slot per source, so a source that floods
/// reports costs one slot, not a queue.
#[derive(Debug)]
struct Reports {
    slots: parking_lot::Mutex<Vec<(u64, Option<B256>)>>,
    wake: Notify,
}

impl Reports {
    fn new(n: usize) -> Self {
        Self { slots: parking_lot::Mutex::new(vec![(0, None); n]), wake: Notify::new() }
    }

    fn send(&self, idx: usize, root: B256) {
        if let Some(slot) = self.slots.lock().get_mut(idx) {
            *slot = (slot.0 + 1, Some(root));
        }
        self.wake.notify_one();
    }

    /// Waits for new reports and returns each source's latest one since `seen`.
    async fn changed(&self, seen: &mut [u64]) -> Vec<(usize, B256)> {
        loop {
            {
                let slots = self.slots.lock();
                let out: Vec<(usize, B256)> = slots
                    .iter()
                    .enumerate()
                    .filter(|(i, (seq, _))| *seq != seen[*i])
                    .filter_map(|(i, (_, r))| r.map(|r| (i, r)))
                    .collect();
                for (i, (seq, _)) in slots.iter().enumerate() {
                    seen[i] = *seq;
                }
                if !out.is_empty() {
                    return out;
                }
            }
            self.wake.notified().await;
        }
    }
}

/// Why the head did not move.
enum AdvanceError {
    /// This root could not be had: the reports of it from the sources that had reported it are
    /// ignored for `failed_ttl`.
    Failed,
    /// No peer confirmed the head yet: tried again after [`UNCONFIRMED_TTL`].
    Unconfirmed,
    /// The root names a block already followed, and another source may still serve a new one
    /// under it: tried again as [`Self::Unconfirmed`] is. Each new root adds a strike to its
    /// reporters' backoff, so a source that floods made-up roots answered with the held head
    /// waits longer each time. A try of the same root again waits one [`REPORT_BACKOFF`] that
    /// does not grow, so an honest source that reports the real root of a block taken under
    /// another root still hears its next head.
    Followed,
    /// Every source answered that it does not hold the root. It is tried once more after
    /// [`UNCONFIRMED_TTL`], as an honest source may not have imported the block yet, and then
    /// fails.
    Unserved,
    /// The ancestor walk found no way down from the block at root `at`; `led` are the sources
    /// that served that block under its root. The head root may be sound: a source that steered
    /// the walk may have made the line up.
    DeadEnd { at: B256, led: Vec<usize> },
    /// The head is more than [`MAX_ANCESTORS`] above the held chain: re-seed forward.
    Gap,
    /// The try ran past [`ADVANCE_BUDGET`] and was dropped.
    Slow,
}

/// Why the follower halted the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    /// The anchor disagreed with the held chain; this is the highest number it disagreed at.
    Mismatch(u64),
    /// The anchor's finalized block at this number is above the head, and no confirmation
    /// source can vouch for it. Heads are followed meanwhile, and an anchor that agrees at this
    /// number or above clears it. A head too far behind for the ancestor walk needs a restart.
    Behind(u64),
}

impl Halt {
    const fn number(self) -> u64 {
        match self {
            Self::Mismatch(n) | Self::Behind(n) => n,
        }
    }

    const fn reason(self) -> HaltReason {
        match self {
            Self::Mismatch(_) => HaltReason::AnchorMismatch,
            Self::Behind(_) => HaltReason::BehindAnchor,
        }
    }

    /// This halt over `old`, one already set: a mismatch outranks `Behind`, and the higher number
    /// is kept, so a later halt never lowers the number that clears it.
    fn over(self, old: Option<Self>) -> Self {
        let Some(old) = old else { return self };
        let number = self.number().max(old.number());
        match (self, old) {
            (Self::Mismatch(_), _) | (_, Self::Mismatch(_)) => Self::Mismatch(number),
            (Self::Behind(_), Self::Behind(_)) => Self::Behind(number),
        }
    }
}

/// Follows beacons and keeps a [`HeaderChain`].
pub struct Follower {
    cfg: FollowConfig,
    chain: Arc<HeaderChain>,
    metrics: LiteMetrics,
    /// Answers per source that failed verification. Sources with fewer go first.
    failures: parking_lot::Mutex<Vec<u64>>,
    /// Slow or timed-out requests, roots that led the ancestor walk nowhere, and head blocks
    /// that could not move the head under a root another source's block moved it with, per
    /// source: orders sources, never counts as a verification failure.
    slow: parking_lot::Mutex<Vec<u64>>,
    /// Confirms a head with a peer before it is followed (`--head.confirm=peer`).
    confirm: Option<Arc<dyn HeadConfirm>>,
    /// [`ADVANCE_BUDGET`], shorter in tests.
    advance_budget: Duration,
    /// The slow block answers of the current try to move the head, finished or cut off with
    /// the try: what [`Self::holds`] reads to find the sources that held the coordinator.
    held: parking_lot::Mutex<Vec<SlowAnswer>>,
    /// Ancestors the ancestor walk fetched, by hash, kept while a try is cut off by the budget so
    /// the next try resumes from them. Every try that ends clears them.
    walked: parking_lot::Mutex<HashMap<B256, ParsedBlock>>,
    /// The light-client store that verifies heads (`--head.verify=sync-committee`).
    sync: Option<sync::SyncFollow>,
    /// Why the follower halted the chain, if it did. The chain's halted flag is set and
    /// cleared only under this lock, so the two change together.
    halt: parking_lot::Mutex<Option<Halt>>,
    /// With a light-client store, the number and hash of the last anchor block that disagreed
    /// with the verified chain: each disagreement is logged once.
    disagreement: parking_lot::Mutex<Option<(u64, B256)>>,
    /// Wakes the anchor task for a check under its floor. Head moves and gaps under a halt wake it
    /// instead of asking the anchor inline: each slot would ask it, and a slow anchor would hold
    /// up head following.
    anchor_wake: Notify,
    /// Bounds the block parses that run at once: see [`Self::parse`].
    parse_permits: Arc<tokio::sync::Semaphore>,
    /// Test hook: runs after the beacon quorum agreed on a finalized block and before finality
    /// moves, to interleave a re-seed there.
    #[cfg(test)]
    before_finality: parking_lot::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// Test hook: runs after an agreeing anchor read the halt and before it clears it, to
    /// interleave a new halt there.
    #[cfg(test)]
    before_halt_clear: parking_lot::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for Follower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follower").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

/// A block answer of the current try that took [`Follower::slow_answer`] or longer.
#[derive(Debug, Clone, Copy)]
struct SlowAnswer {
    idx: usize,
    root: B256,
    took: Duration,
    /// The try took the block it served: the head or an ancestor on the walk.
    used: bool,
}

/// One block request's clock. When it ends, or is dropped unfinished with the try it belongs
/// to, a slow or timed-out request moves its source back in the order, and a slow one is noted
/// in [`Follower::held`]. A request dropped because its answer is no longer needed counts for
/// nothing.
struct BlockRequest<'a> {
    follower: &'a Follower,
    idx: usize,
    host: &'a str,
    root: B256,
    started: Instant,
    timed_out: bool,
    /// Set by the caller when it drops the request unfinished because it no longer needs it.
    unneeded: Option<&'a AtomicBool>,
}

impl Drop for BlockRequest<'_> {
    fn drop(&mut self) {
        if self.unneeded.is_some_and(|u| u.load(Ordering::Relaxed)) {
            return;
        }
        let took = self.started.elapsed();
        let slow = took >= self.follower.slow_answer();
        if self.timed_out || slow {
            self.follower.count_slow(self.idx, self.host);
        }
        if slow {
            self.follower.held.lock().push(SlowAnswer {
                idx: self.idx,
                root: self.root,
                took,
                used: false,
            });
        }
    }
}

enum Fetched {
    Block(Box<ParsedBlock>),
    /// No source could serve it.
    Unavailable,
    /// A source served something that failed verification.
    Bad,
}

impl Follower {
    /// A follower writing into `chain`.
    pub fn new(cfg: FollowConfig, chain: Arc<HeaderChain>, metrics: LiteMetrics) -> Self {
        let failures = parking_lot::Mutex::new(vec![0; cfg.urls.len()]);
        let slow = parking_lot::Mutex::new(vec![0; cfg.urls.len()]);
        let held = parking_lot::Mutex::new(Vec::new());
        Self {
            cfg,
            chain,
            metrics,
            failures,
            slow,
            confirm: None,
            advance_budget: ADVANCE_BUDGET,
            held,
            walked: parking_lot::Mutex::new(HashMap::new()),
            sync: None,
            halt: parking_lot::Mutex::new(None),
            disagreement: parking_lot::Mutex::new(None),
            anchor_wake: Notify::new(),
            parse_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PARSES)),
            #[cfg(test)]
            before_finality: parking_lot::Mutex::new(None),
            #[cfg(test)]
            before_halt_clear: parking_lot::Mutex::new(None),
        }
    }

    /// Requires `confirm` to report a head's hash before the head moves.
    pub fn with_confirm(mut self, confirm: Arc<dyn HeadConfirm>) -> Self {
        self.confirm = Some(confirm);
        self
    }

    async fn confirmed(&self, number: u64, hash: B256) -> Confirmation {
        for attempt in 0..CONFIRM_TRIES {
            if attempt > 0 {
                sleep(CONFIRM_PAUSE).await;
            }
            match self.confirm_once(number, hash).await {
                Confirmation::Unknown => {}
                res => return res,
            }
        }
        tracing::debug!(number, "no peer confirmed the beacon head yet");
        Confirmation::Unknown
    }

    /// One peer query for a head block. A veto is counted and logged.
    async fn confirm_once(&self, number: u64, hash: B256) -> Confirmation {
        let Some(c) = &self.confirm else { return Confirmation::Confirmed };
        let res = confirm_canonical(&**c, number, hash, 0, 0).await;
        if res == Confirmation::Mismatch {
            self.metrics.proof_failure(FailureSource::Beacon);
            tracing::warn!(
                number,
                "a peer holds a different block at the beacon head; not following it"
            );
        }
        res
    }

    /// With quorum 1 and a confirming peer: asks the sources for `root` in order and takes the
    /// first block the peer confirms that can move the head. A source whose block the peer
    /// vetoes is charged. A block already followed is taken only when no other source serves a
    /// new one, and a block [`Self::is_behind`] is never taken, so a hostile first source cannot
    /// hold the head back with a block that cannot move it: once another source's block is
    /// taken, the sources that served those go back in the order. The sources after the pick
    /// are not asked. A source that holds its answer instead is cut off with the whole try at
    /// [`ADVANCE_BUDGET`].
    ///
    /// The peer is asked about a block when it is served. A block it could not place is asked
    /// about again after each [`CONFIRM_PAUSE`], up to [`CONFIRM_TRIES`] queries, while the next
    /// sources are fetched: a block a source made up costs one query and no pause, and a slow
    /// later source does not delay a block the peer confirms on a later query.
    async fn pick_head(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        root: B256,
    ) -> Result<ParsedBlock, AdvanceError> {
        // Each block already put to the peer, by (hash, parent root), and whether it vetoed it.
        let mut asked: Vec<((B256, B256), bool)> = Vec::new();
        // A source that gave no usable block: an honest one may be among them.
        let mut unheard = false;
        // A block already followed, and whether a source did not serve the root (a 404).
        let mut followed: Option<ParsedBlock> = None;
        let mut missing = false;
        // A block that can never be the head, and the sources that served it or a followed one.
        let mut behind = false;
        let mut held_back: Vec<usize> = Vec::new();
        // The blocks the peer could not place yet: the source that served each, the queries
        // made, and when the next one is due.
        let mut unknown: Vec<(usize, ParsedBlock, u32, tokio::time::Instant)> = Vec::new();
        // Set when the pick is made: a fetch still in flight then is not the source's delay.
        let picked = AtomicBool::new(false);
        let picked = &picked;
        let fetch = move |i: usize| {
            Box::pin(
                async move { (i, self.fetch_root_unless(clients, i, root, Some(picked)).await) },
            )
        };
        // The re-queries in flight. They run beside the block fetch, so a slow peer does not
        // stall a source's answer and charge it as slow.
        let query = move |i: usize, p: ParsedBlock, tries: u32| {
            Box::pin(async move {
                let res = self.confirm_once(p.block.header.number, p.block.hash).await;
                (i, p, tries, res)
            })
        };
        let mut queries = futures::stream::FuturesUnordered::new();
        let mut sources = order.iter().copied();
        let mut in_flight = sources.next().map(fetch);
        loop {
            let due = unknown.iter().map(|(.., at)| *at).min();
            if in_flight.is_none() && due.is_none() && queries.is_empty() {
                break;
            }
            let answer = tokio::select! {
                biased;
                Some((i, p, tries, res)) = futures::StreamExt::next(&mut queries),
                    if !queries.is_empty() =>
                {
                    match res {
                        Confirmation::Confirmed => {
                            picked.store(true, Ordering::Relaxed);
                            self.used(&[i], root);
                            self.move_back(clients, &held_back);
                            return Ok(p)
                        }
                        Confirmation::Mismatch => {
                            self.charge(i, clients[i].host(), &PayloadError::HashMismatch);
                            let key = (p.block.hash, p.parent_root);
                            if let Some((_, vetoed)) =
                                asked.iter_mut().find(|(served, _)| *served == key)
                            {
                                *vetoed = true;
                            }
                        }
                        Confirmation::Unknown if tries + 1 < CONFIRM_TRIES => {
                            let at = tokio::time::Instant::now() + CONFIRM_PAUSE;
                            unknown.push((i, p, tries + 1, at));
                        }
                        // It stays open in `asked`.
                        Confirmation::Unknown => {
                            tracing::debug!(
                                number = p.block.header.number,
                                "no peer confirmed the beacon head yet"
                            );
                        }
                    }
                    None
                }
                () = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)),
                    if due.is_some() =>
                {
                    let now = tokio::time::Instant::now();
                    for (i, p, tries, _) in unknown.extract_if(.., |(.., at)| *at <= now) {
                        queries.push(query(i, p, tries));
                    }
                    None
                }
                Some(answer) = futures::future::OptionFuture::from(in_flight.as_mut()),
                    if in_flight.is_some() =>
                {
                    in_flight = sources.next().map(fetch);
                    Some(answer)
                }
            };
            let Some((i, res)) = answer else { continue };
            let v = match res {
                Ok(v) => v,
                // The source answered that it does not hold the root.
                Err(SourceError::Status(404)) => {
                    missing = true;
                    continue;
                }
                Err(_) => {
                    unheard = true;
                    continue;
                }
            };
            let p = match self.parse(v, root).await {
                Ok(p) => p,
                Err(PayloadError::Optimistic) => {
                    self.skip_optimistic(FailureSource::Beacon, clients[i].host());
                    unheard = true;
                    continue;
                }
                Err(e) => {
                    self.count_failure(i, clients[i].host(), &e);
                    unheard = true;
                    continue;
                }
            };
            let key = (p.block.hash, p.parent_root);
            if let Some((_, vetoed)) = asked.iter().find(|(k, _)| *k == key) {
                if *vetoed {
                    self.charge(i, clients[i].host(), &PayloadError::HashMismatch);
                }
                continue;
            }
            // The held chain was confirmed when it was followed: no peer is asked again.
            if self.follows(&p.block) {
                followed.get_or_insert(p);
                held_back.push(i);
                continue;
            }
            // No peer is asked: a peer confirms an old canonical block by its number.
            if self.is_behind(&p.block) {
                behind = true;
                held_back.push(i);
                continue;
            }
            match self.confirm_once(p.block.header.number, p.block.hash).await {
                Confirmation::Confirmed => {
                    picked.store(true, Ordering::Relaxed);
                    self.used(&[i], root);
                    self.move_back(clients, &held_back);
                    return Ok(p)
                }
                Confirmation::Mismatch => {
                    self.charge(i, clients[i].host(), &PayloadError::HashMismatch);
                    asked.push((key, true));
                }
                Confirmation::Unknown => {
                    asked.push((key, false));
                    unknown.push((i, p, 1, tokio::time::Instant::now() + CONFIRM_PAUSE));
                }
            }
        }
        // A block already followed is the answer only when every other source served it or a
        // vetoed block: one without the root may not have imported the new block yet, and a new
        // block no peer could confirm yet is asked about again.
        if let Some(p) = followed {
            let open = unheard || missing || asked.iter().any(|(_, vetoed)| !vetoed);
            return if open { Err(AdvanceError::Followed) } else { Ok(p) };
        }
        // The root fails only when every source answered and every answer was vetoed or behind.
        // A source that timed out or sent junk, or a peer that could not say, leaves it open.
        Err(if unheard {
            AdvanceError::Unconfirmed
        } else if asked.is_empty() && !behind {
            AdvanceError::Unserved
        } else if asked.iter().all(|(_, vetoed)| *vetoed) {
            AdvanceError::Failed
        } else {
            AdvanceError::Unconfirmed
        })
    }

    /// Whether `block` is already followed: the held head itself (the seeded anchor before the
    /// head first moves), or a canonical block at or below it (a lagging source reporting an
    /// ancestor). Following it moves nothing.
    fn follows(&self, block: &HeldBlock) -> bool {
        let held_head = self.chain.head();
        held_head.as_ref().is_some_and(|h| h.hash == block.hash) ||
            (self.chain.is_live() &&
                self.chain.is_canonical(&block.hash) &&
                held_head.is_some_and(|h| block.header.number <= h.header.number))
    }

    /// Whether `block`, when not followed, can never become the head: at or below the finalized
    /// number, where only the finalized block lives, or more than [`MAX_BACKWARD`] blocks or
    /// [`MAX_BACKWARD_SECS`] behind the live head (a reorg of a block or two is fine).
    fn is_behind(&self, block: &HeldBlock) -> bool {
        let (number, timestamp) = (block.header.number, block.header.timestamp);
        number <= self.chain.finalized_number().unwrap_or(0) ||
            (self.chain.is_live() &&
                self.chain.head().is_some_and(|held| {
                    number.saturating_add(MAX_BACKWARD) < held.header.number ||
                        timestamp.saturating_add(MAX_BACKWARD_SECS) < held.header.timestamp
                }))
    }

    /// Moves `sources` back in the order: each served a block that could not move the head under
    /// a root another source's block moved it with.
    fn move_back(&self, clients: &[BeaconClient], sources: &[usize]) {
        for &i in sources {
            self.count_slow(i, clients[i].host());
        }
    }

    /// Source `i`'s answer for the block at `root`. A timeout or an answer slower than
    /// [`Self::slow_answer`] moves the source back in the order, also when the request is cut
    /// off unfinished, and a slow one is noted in [`Self::held`].
    async fn fetch_root(
        &self,
        clients: &[BeaconClient],
        i: usize,
        root: B256,
    ) -> Result<Value, SourceError> {
        self.fetch_root_unless(clients, i, root, None).await
    }

    /// [`Self::fetch_root`], counting for nothing when it is dropped unfinished after
    /// `unneeded` was set.
    async fn fetch_root_unless(
        &self,
        clients: &[BeaconClient],
        i: usize,
        root: B256,
        unneeded: Option<&AtomicBool>,
    ) -> Result<Value, SourceError> {
        let mut request = BlockRequest {
            follower: self,
            idx: i,
            host: clients[i].host(),
            root,
            started: Instant::now(),
            timed_out: false,
            unneeded,
        };
        let res = clients[i].block(&format!("{root:#x}")).await;
        request.timed_out = res == Err(SourceError::Timeout);
        drop(request);
        if let Err(e) = &res {
            tracing::debug!(source = clients[i].host(), error = %e, "beacon block request failed");
        }
        res
    }

    /// How long a block answer takes to count as slow: [`SLOW_ANSWER`], or half the advance
    /// budget when that is shorter (in tests).
    fn slow_answer(&self) -> Duration {
        SLOW_ANSWER.min(self.advance_budget / 2)
    }

    /// Notes that the try took the blocks `sources` served under `root`: their slow answers for
    /// it held nothing.
    fn used(&self, sources: &[usize], root: B256) {
        for a in self.held.lock().iter_mut() {
            if a.root == root && sources.contains(&a.idx) {
                a.used = true;
            }
        }
    }

    /// Per source of `n`, how long it held the current try: the slow answers the try did not
    /// use and that took [`Self::slow_answer`] or more past the slowest answer of the same
    /// source the try used, counted as one [`Self::slow_answer`] at most. An honest source cut
    /// off by the budget mid-answer, no slower than its answers the try used, holds nothing.
    /// Another source's slow answer excuses nothing: a holder could otherwise hide behind one
    /// slow honest answer, or behind a slow answer of its own the try used.
    fn holds(&self, n: usize) -> Vec<Duration> {
        let answers = self.held.lock();
        let slow = self.slow_answer();
        let mut excused = vec![Duration::ZERO; n];
        for a in answers.iter().filter(|a| a.used) {
            if let Some(e) = excused.get_mut(a.idx) {
                *e = (*e).max(a.took.min(slow));
            }
        }
        let mut held = vec![Duration::ZERO; n];
        for a in answers.iter().filter(|a| !a.used) {
            if let (Some(h), Some(e)) = (held.get_mut(a.idx), excused.get(a.idx)) &&
                a.took.saturating_sub(*e) >= slow
            {
                *h += a.took;
            }
        }
        held
    }

    /// Sorts `order` by each source's failed and slow answers together. The sort is stable, so
    /// ties keep their place.
    fn sort_sources(&self, order: &mut [usize]) {
        let (failures, slow) = (self.failures.lock(), self.slow.lock());
        order.sort_by_key(|i| failures[*i].saturating_add(slow[*i]));
    }

    /// How many answers from source `idx` failed verification.
    pub fn source_failures(&self, idx: usize) -> u64 {
        self.failures.lock().get(idx).copied().unwrap_or(0)
    }

    /// [`parse_beacon_block`] on a blocking thread, at most [`MAX_CONCURRENT_PARSES`] at once. A
    /// parse decodes and hashes an answer of up to the beacon answer limit, and on an async
    /// worker it would hold up every other task there.
    async fn parse(&self, v: Value, root: B256) -> Result<ParsedBlock, PayloadError> {
        // The permit moves into the blocking task: a caller that gives up does not free the slot
        // while the parse still runs.
        let Ok(permit) = self.parse_permits.clone().acquire_owned().await else {
            return Err(PayloadError::Malformed("parse aborted"))
        };
        let forks = self.cfg.forks.clone();
        let parse = tokio::task::spawn_blocking(move || {
            let parsed = parse_beacon_block(&v, root, &forks);
            drop(permit);
            parsed
        });
        match parse.await {
            Ok(parsed) => parsed,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // The runtime shuts down.
            Err(_) => Err(PayloadError::Malformed("parse aborted")),
        }
    }

    fn count_slow(&self, idx: usize, host: &str) {
        if let Some(n) = self.slow.lock().get_mut(idx) {
            *n += 1;
        }
        tracing::debug!(source = host, "beacon source moved back in the order");
    }

    fn count_failure(&self, idx: usize, host: &str, e: &PayloadError) {
        self.metrics.proof_failure(FailureSource::Beacon);
        self.charge(idx, host, e);
    }

    /// Charges source `idx` for a rejected answer without raising the failure metric: for a
    /// veto, [`Self::confirmed`] already counted the block once.
    fn charge(&self, idx: usize, host: &str, e: &PayloadError) {
        if let Some(n) = self.failures.lock().get_mut(idx) {
            *n += 1;
        }
        tracing::warn!(source = host, error = %e, "beacon block rejected");
    }

    /// Records a failed fetch of the finalized anchor. An anchor that answered with a block it
    /// does not mark finalized is up: its answer is rejected, not unreachable.
    fn anchor_fetch_failed(&self, host: &str, e: &SourceError) {
        if *e == SourceError::NotFinalized {
            self.metrics.proof_failure(FailureSource::Anchor);
            tracing::warn!(
                anchor = host,
                "finalized anchor rejected: it does not mark the block it served finalized"
            );
        } else {
            self.metrics.anchor_unreachable();
            tracing::warn!(anchor = host, error = %e, "finalized anchor unavailable");
        }
    }

    /// Records an answer refused as [`PayloadError::Optimistic`]. It is unavailable, not bad: an
    /// honest source serves one while its execution client syncs.
    fn skip_optimistic(&self, source: FailureSource, host: &str) {
        self.metrics.beacon_optimistic(source);
        tracing::debug!(
            source = host,
            "beacon block skipped: the source has not validated its execution yet"
        );
    }

    /// The header chain.
    pub const fn chain(&self) -> &Arc<HeaderChain> {
        &self.chain
    }

    /// Runs until the task is dropped. The source, anchor and lag tasks it starts stop with it.
    pub async fn run(self: Arc<Self>) {
        let anchor = BeaconClient::new(self.cfg.anchor_url.clone());
        let clients: Vec<BeaconClient> =
            self.cfg.urls.iter().cloned().map(BeaconClient::new).collect();
        if self.sync.as_ref().is_some_and(sync::SyncFollow::seeds_from_store) {
            self.seed_from_store(&clients).await;
        } else {
            self.seed_from_anchor(&anchor, &clients).await;
        }
        let reports = Arc::new(Reports::new(clients.len()));
        let fin = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        // Dropping the set aborts its tasks.
        let mut tasks = tokio::task::JoinSet::new();
        for (idx, c) in clients.iter().cloned().enumerate() {
            tasks.spawn(self.clone().source_task(idx, c, reports.clone(), fin.clone()));
        }
        if self.sync.is_some() {
            tasks.spawn(self.clone().committee_task(clients.clone(), fin.clone()));
        }
        tasks.spawn(self.clone().anchor_task(anchor.clone(), clients.clone(), fin, resume.clone()));
        tasks.spawn(self.clone().lag_task());
        self.coordinate(anchor, clients, reports, resume).await;
    }

    /// Fetches, verifies and confirms the anchor, retrying with backoff (at least every 30 s).
    ///
    /// The anchor is one source, a third party by default. Before it seeds the chain it must be
    /// recent (its timestamp within `max_anchor_age` of the wall clock, not more than 60 s
    /// ahead) and, when a confirmation source is configured, confirmed by it the same way a re-seed
    /// is: the head-confirm peer has it canonical with blocks on top, or a beacon quorum
    /// reports it as finalized. With no confirmation source the anchor is trusted alone, and
    /// that is logged.
    ///
    /// With a light-client store the anchor block is the block under the bootstrap root, and it
    /// must have the execution `block_hash` and beacon `parent_root` the bootstrap proves. The
    /// store does not confirm the seed: its bootstrap came from the anchor's root. Only the
    /// head-confirm peer can then confirm it, and only its execution block: the anchor's root
    /// alone decides the committee.
    async fn seed_from_anchor(&self, anchor: &BeaconClient, clients: &[BeaconClient]) {
        let mut delay = Duration::from_millis(500);
        let can_confirm = self.peer_or_quorum();
        if !can_confirm && self.sync.is_some() {
            tracing::warn!(
                anchor = anchor.host(),
                "no head-confirm peer confirms the light-client bootstrap block \
                 (--head.confirm=none; --beacon.quorum confirms nothing in this mode): trusting \
                 the anchor alone"
            );
        } else if !can_confirm {
            tracing::warn!(
                anchor = anchor.host(),
                "no independent source confirms the finalized anchor (--head.confirm=none and \
                 --beacon.quorum 1): trusting the anchor alone. Give a second --beacon.url and \
                 --beacon.quorum 2, or --head.confirm=peer with a --peer, or \
                 --head.verify=sync-committee with a checkpoint"
            );
        }
        loop {
            let fetched = match &self.sync {
                Some(sync) => {
                    let root = sync.anchor().root;
                    anchor.block(&format!("{root:#x}")).await.map(|v| (v, root))
                }
                None => anchor.finalized_block().await.map(|v| (v, B256::ZERO)),
            };
            match fetched {
                Ok((v, root)) => match self.parse(v, root).await {
                    Ok(p) => {
                        let number = p.block.header.number;
                        let proven = self.sync.as_ref().is_none_or(|sync| {
                            let a = sync.anchor();
                            p.block.hash == a.block_hash && p.parent_root == a.parent_root
                        });
                        if !proven {
                            self.metrics.proof_failure(FailureSource::Anchor);
                            tracing::warn!(
                                number,
                                anchor = anchor.host(),
                                "finalized anchor's block is not the one the light-client \
                                 bootstrap proves; not seeding from it"
                            );
                        } else if !self.anchor_recent(&p.block) {
                            self.metrics.proof_failure(FailureSource::Anchor);
                            tracing::warn!(
                                number,
                                anchor = anchor.host(),
                                timestamp = p.block.header.timestamp,
                                "finalized anchor is not recent; not seeding from it"
                            );
                            // The bootstrap root is fixed, so its block never becomes recent.
                            self.bootstrap_again(anchor, clients).await;
                        } else if can_confirm && !self.anchor_confirmed(clients, &p.block).await {
                            tracing::warn!(
                                number,
                                anchor = anchor.host(),
                                "finalized anchor is not confirmed by a peer or a beacon quorum yet; \
                                 not seeding from it"
                            );
                        } else {
                            if can_confirm {
                                tracing::info!(
                                    number,
                                    anchor = anchor.host(),
                                    "finalized anchor verified; following"
                                );
                            } else {
                                tracing::warn!(
                                    number,
                                    hash = %p.block.hash,
                                    anchor = anchor.host(),
                                    "UNCONFIRMED SEED: seeded from the finalized anchor alone, \
                                     which no peer or beacon quorum confirmed; trusting the \
                                     anchor alone. Check this block hash against a source you \
                                     trust"
                                );
                            }
                            self.chain.seed(p.block);
                            self.publish_head();
                            return;
                        }
                    }
                    Err(PayloadError::Optimistic) => {
                        self.metrics.beacon_optimistic(FailureSource::Anchor);
                        tracing::warn!(
                            anchor = anchor.host(),
                            "finalized anchor's execution is not validated by its source yet; waiting"
                        );
                    }
                    Err(e) => {
                        self.metrics.proof_failure(FailureSource::Anchor);
                        tracing::warn!(anchor = anchor.host(), error = %e, "finalized anchor rejected");
                    }
                },
                Err(e) => self.anchor_fetch_failed(anchor.host(), &e),
            }
            sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }

    fn publish_head(&self) {
        if let Some(h) = self.chain.head() {
            self.metrics.head_number.set(h.header.number as f64);
            self.metrics.head_lag_seconds.set(lag_seconds(h.header.timestamp));
        }
    }

    async fn lag_task(self: Arc<Self>) {
        loop {
            sleep(Duration::from_secs(1)).await;
            self.publish_head();
        }
    }

    async fn source_task(
        self: Arc<Self>,
        idx: usize,
        client: BeaconClient,
        tx: Arc<Reports>,
        fin: Arc<Notify>,
    ) {
        if self.sync.is_some() {
            return self.sync_source_task(idx, client, tx, fin).await;
        }
        // Whether the last request failed: a failure is logged when it starts and when it ends,
        // not on every poll. The finality read keeps its own flag: a source that answers
        // headers/head but not finality_checkpoints would otherwise flip one flag every read.
        let mut failing = false;
        let mut finality_failing = false;
        // One headers/head at start, in either mode.
        if let Some(root) =
            note_answer(&mut failing, "headers/head", client.host(), client.head_root().await)
        {
            tx.send(idx, root);
        }
        let mut last_sse: Option<Instant> = None;
        let mut reconnect = false;
        // Immediate event-stream reconnects in a row, see `quick_reconnect`.
        let mut quick: u32 = 0;
        let mut polls: u64 = 0;
        let mut last_fin: Option<B256> = None;
        loop {
            if reconnect || last_sse.is_none_or(|t| t.elapsed() >= self.cfg.sse_retry) {
                reconnect = false;
                last_sse = Some(Instant::now());
                let idle = (self.cfg.poll * 3).max(MIN_SSE_IDLE);
                let watchdog = (self.cfg.poll * 6).max(MIN_SSE_WATCHDOG);
                let opened = client.events(idle).await;
                if let Err(e) = &opened {
                    tracing::debug!(source = client.host(), error = %e, "no event stream");
                }
                if let Ok(mut events) = opened {
                    let opened = Instant::now();
                    tracing::info!(source = client.host(), "following by event stream");
                    let mut dog = Box::pin(sleep(watchdog));
                    loop {
                        tokio::select! {
                            e = events.next_event() => match e {
                                Some(Event::Head(root)) => tx.send(idx, root),
                                Some(Event::Finalized) => fin.notify_one(),
                                // A head stream yields no light-client events.
                                Some(Event::OptimisticUpdate(_) | Event::FinalityUpdate(_)) => {}
                                None => break,
                            },
                            // A slow headers/head poll while streaming, in case events stop
                            // coming while the stream stays open.
                            () = &mut dog => {
                                if let Some(root) = note_answer(
                                    &mut failing,
                                    "headers/head",
                                    client.host(),
                                    client.head_root().await,
                                ) {
                                    tx.send(idx, root);
                                }
                                dog = Box::pin(sleep(watchdog));
                            }
                        }
                    }
                    tracing::warn!(source = client.host(), "event stream ended; polling");
                    reconnect = quick_reconnect(&mut quick, opened.elapsed(), self.cfg.sse_retry);
                    // A head sent while no stream is open is read before the next one opens.
                    // Without a quick reconnect the poll below reads it at once.
                    if reconnect {
                        if let Some(root) = note_answer(
                            &mut failing,
                            "headers/head",
                            client.host(),
                            client.head_root().await,
                        ) {
                            tx.send(idx, root);
                        }
                        continue;
                    }
                }
            }
            if let Some(root) =
                note_answer(&mut failing, "headers/head", client.host(), client.head_root().await)
            {
                tx.send(idx, root);
            }
            if polls % FINALITY_EVERY == FINALITY_EVERY - 1 &&
                let Some(root) = note_answer(
                    &mut finality_failing,
                    "finality_checkpoints",
                    client.host(),
                    client.finalized_root().await,
                ) &&
                last_fin != Some(root)
            {
                if last_fin.is_some() {
                    fin.notify_one();
                }
                last_fin = Some(root);
            }
            polls += 1;
            sleep(self.cfg.poll).await;
        }
    }

    async fn anchor_task(
        self: Arc<Self>,
        anchor: BeaconClient,
        clients: Vec<BeaconClient>,
        fin: Arc<Notify>,
        resume: Arc<Notify>,
    ) {
        // Finality events can come in a flood: at most one check per floor interval.
        let floor = self.cfg.recheck.min(self.cfg.anchor_gap);
        let mut last = Instant::now();
        // Only the number counts: confirming the seed while the anchor lags the beacons leaves
        // a newer finalized block to follow.
        let finality = || self.chain.finalized_number();
        // At a finality event the new finalized block is at most `FINALITY_MIN_DEPTH` slots below
        // the beacon head, so the check then often finds it a block short, or finds the anchor
        // a checkpoint away from the beacons. Later checks, `floor` apart, follow until finality
        // moves.
        let mut retries = 0u32;
        let mut at_event = finality();
        loop {
            tokio::select! {
                () = sleep(self.cfg.recheck) => {}
                () = sleep(floor), if retries > 0 => retries -= 1,
                () = fin.notified() => {
                    let since = last.elapsed();
                    if since < floor {
                        sleep(floor - since).await;
                    }
                    retries = FINALITY_RETRIES;
                    at_event = finality();
                }
                () = self.anchor_wake.notified() => {
                    let since = last.elapsed();
                    if since < floor {
                        sleep(floor - since).await;
                    }
                }
            }
            last = Instant::now();
            self.check_anchor(&anchor, &clients, &resume).await;
            if finality() != at_event {
                retries = 0;
            }
        }
    }

    /// How many beacons report the held canonical `block`, or a held canonical block above it,
    /// as their finalized block. A canonical block above it descends from it, so it is final
    /// too: an anchor that lags the beacons by a checkpoint or more still moves finality.
    async fn beacons_finalized(&self, clients: &[BeaconClient], block: &HeldBlock) -> usize {
        let mut agree = 0;
        for c in clients {
            if let Ok(v) = c.finalized_block().await &&
                self.parse(v, B256::ZERO).await.is_ok_and(|p| {
                    p.block.hash == block.hash ||
                        (p.block.header.number > block.header.number &&
                            self.chain.is_canonical(&p.block.hash))
                })
            {
                agree += 1;
            }
        }
        agree
    }

    /// Whether a head-confirm peer or a beacon quorum of two or more can vouch for an anchor
    /// block: the sources that can confirm the first seed. With a light-client store only the
    /// peer can: the beacon quorum has no job there.
    fn peer_or_quorum(&self) -> bool {
        self.confirm.is_some() || self.sync.is_none() && self.cfg.quorum >= 2
    }

    /// Whether a source other than the anchor can vouch for an anchor block: a head-confirm
    /// peer, a beacon quorum of two or more without a light-client store, or the light-client
    /// store (see [`Self::anchor_confirmed`]).
    fn can_confirm(&self) -> bool {
        self.peer_or_quorum() || self.sync.is_some()
    }

    /// How many sources must report a head root: one with a light-client store, whose reports
    /// are roots it verified.
    const fn head_quorum(&self) -> usize {
        if self.sync.is_some() {
            1
        } else {
            self.cfg.quorum
        }
    }

    /// Whether heads are followed while halted. With no confirmation source a halt clears only
    /// when the anchor agrees at or above the halt's number, which the head must reach; serving
    /// stays off meanwhile. Otherwise a halt waits for a confirmed re-seed.
    fn follows_while_halted(&self) -> bool {
        !self.can_confirm() && self.halt.lock().is_some()
    }

    /// Sets the halt held under the lock `h`, with the chain's halt reason and the halt gauges.
    fn set_halt(&self, h: &mut Option<Halt>, halt: Option<Halt>) {
        *h = halt;
        let reason = halt.map(Halt::reason);
        self.chain.set_halted(reason);
        let gauge = |r| if reason == Some(r) { 1.0 } else { 0.0 };
        self.metrics.anchor_mismatch.set(gauge(HaltReason::AnchorMismatch));
        self.metrics.anchor_ahead.set(gauge(HaltReason::BehindAnchor));
    }

    /// Whether `block` is recent enough to be an anchor: not older than `max_anchor_age`, and
    /// not more than 60 s ahead of the wall clock (clock skew).
    fn anchor_recent(&self, block: &HeldBlock) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let ts = block.header.timestamp;
        ts <= now + 60 && now.saturating_sub(ts) <= self.cfg.max_anchor_age.as_secs()
    }

    /// Fetches the anchor and re-seeds forward to it, see [`Self::reseed_forward_to`]. With a
    /// light-client store the block is the store's verified finalized block, fetched from the
    /// sources by its root: the anchor is not needed.
    async fn reseed_forward(&self, anchor: &BeaconClient, clients: &[BeaconClient]) -> bool {
        if let Some(sync) = &self.sync {
            let Some(finalized) = sync.latest_finalized() else { return false };
            let mut order: Vec<usize> = (0..clients.len()).collect();
            self.sort_sources(&mut order);
            return match self.fetch_verified(clients, &order, finalized).await {
                Fetched::Block(p) => self.reseed_forward_to(clients, p.block).await,
                Fetched::Bad | Fetched::Unavailable => false,
            };
        }
        let v = match anchor.finalized_block().await {
            Ok(v) => v,
            Err(e) => {
                self.anchor_fetch_failed(anchor.host(), &e);
                return false;
            }
        };
        match self.parse(v, B256::ZERO).await {
            Ok(p) => self.reseed_forward_to(clients, p.block).await,
            Err(PayloadError::Optimistic) => {
                self.skip_optimistic(FailureSource::Anchor, anchor.host());
                false
            }
            Err(_) => {
                self.metrics.proof_failure(FailureSource::Anchor);
                false
            }
        }
    }

    /// Re-seeds at `block` when it is above the held head and finalized block, recent, and
    /// confirmed the same way as the first seed. Returns whether it did.
    async fn reseed_forward_to(&self, clients: &[BeaconClient], block: HeldBlock) -> bool {
        let epoch = self.chain.epoch();
        let number = block.header.number;
        let head = self.chain.head().map_or(0, |h| h.header.number);
        if number <= head || self.chain.finalized_number().is_some_and(|f| number < f) {
            return false;
        }
        if !self.anchor_recent(&block) {
            return false;
        }
        if !self.can_confirm() {
            // After start-up the anchor's word alone never swaps the chain: halt instead.
            if !self.chain.halted() {
                tracing::error!(
                    number,
                    head,
                    "the finalized anchor is above the head and no confirmation source is \
                     configured (--peer with --head.confirm=peer, or --beacon.quorum of 2 or \
                     more); halted until the head reaches the anchor and the anchor agrees, or \
                     an operator restarts the node"
                );
            }
            let mut h = self.halt.lock();
            let halt = Halt::Behind(number).over(*h);
            self.set_halt(&mut h, Some(halt));
            return false;
        }
        if !self.anchor_confirmed(clients, &block).await {
            tracing::warn!(
                number,
                "finalized anchor above the head is not confirmed; not re-seeding"
            );
            return false;
        }
        if !self.reseed_confirmed(epoch, block) {
            return false;
        }
        tracing::warn!(
            number,
            head,
            "the head fell too far behind; re-seeded forward from the anchor"
        );
        true
    }

    /// Re-seeds at an independently confirmed anchor block, unless the chain moved since
    /// `epoch` (see [`HeaderChain::reseed_since`]), and clears any halt: the held chain that
    /// disagreed with the anchor is dropped with it. Returns whether it re-seeded.
    fn reseed_confirmed(&self, epoch: u64, block: HeldBlock) -> bool {
        let number = block.header.number;
        if !self.chain.reseed_since(epoch, block) {
            tracing::debug!(
                number,
                "the chain moved while the anchor was confirmed; not re-seeding"
            );
            return false;
        }
        self.set_halt(&mut self.halt.lock(), None);
        self.publish_head();
        self.apply_verified_finality();
        true
    }

    /// Whether a source other than the anchor vouches for the anchor block: the light-client
    /// store proved it finalized from a signed update, the head-confirm peer has it as its
    /// canonical block at that number with [`ANCHOR_DESCENDANTS`] canonical blocks on top, or
    /// (with `--beacon.quorum` of 2 or more and no light-client store) a quorum of beacons report
    /// it as their finalized block. A peer that holds another block at that number vetoes.
    async fn anchor_confirmed(&self, clients: &[BeaconClient], block: &HeldBlock) -> bool {
        let (number, hash) = (block.header.number, block.hash);
        if self.sync.as_ref().is_some_and(|sync| sync.confirms(hash)) {
            return true;
        }
        if let Some(c) = &self.confirm {
            match confirm_canonical(&**c, number, hash, ANCHOR_DESCENDANTS, FINALITY_MIN_DEPTH)
                .await
            {
                Confirmation::Confirmed => return true,
                Confirmation::Mismatch => return false,
                Confirmation::Unknown => {}
            }
        }
        if self.sync.is_some() || self.cfg.quorum < 2 {
            return false;
        }
        let mut agree = 0;
        for c in clients {
            if let Ok(v) = c.finalized_block().await &&
                self.parse(v, B256::ZERO).await.is_ok_and(|p| p.block.hash == hash)
            {
                agree += 1;
            }
        }
        agree >= self.cfg.quorum
    }

    async fn check_anchor(&self, anchor: &BeaconClient, clients: &[BeaconClient], resume: &Notify) {
        let v = match anchor.finalized_block().await {
            Ok(v) => v,
            Err(e) => {
                self.anchor_fetch_failed(anchor.host(), &e);
                return;
            }
        };
        let block = match self.parse(v, B256::ZERO).await {
            Ok(p) => p.block,
            Err(PayloadError::Optimistic) => {
                self.skip_optimistic(FailureSource::Anchor, anchor.host());
                return;
            }
            Err(e) => {
                self.metrics.proof_failure(FailureSource::Anchor);
                tracing::warn!(anchor = anchor.host(), error = %e, "finalized anchor rejected");
                return;
            }
        };
        let epoch = self.chain.epoch();
        match self.chain.check_anchor(block.header.number, &block.hash) {
            AnchorStatus::Mismatch if self.sync.is_some() => {
                self.anchor_disagrees(anchor, clients, epoch, block, resume).await;
            }
            AnchorStatus::Mismatch => {
                // Stop serving at once. The anchor's word alone never swaps the chain: a lying
                // anchor would then control it. Re-seed only from an anchor another source
                // vouches for, never from a stale one and never to a lower finalized number.
                let first = {
                    let mut h = self.halt.lock();
                    // A behind-anchor halt held first does not silence the mismatch.
                    let first = h.map(Halt::reason) != Some(HaltReason::AnchorMismatch);
                    let halt = Halt::Mismatch(block.header.number).over(*h);
                    self.set_halt(&mut h, Some(halt));
                    first
                };
                let number = block.header.number;
                if self.chain.finalized_number().is_some_and(|f| number < f) {
                    if first {
                        tracing::error!(
                            number,
                            "finalized anchor is below the held finalized block and disagrees \
                             with it; halted, the anchor is not followed back"
                        );
                    }
                    return;
                }
                if !self.anchor_recent(&block) {
                    if first {
                        tracing::error!(
                            number,
                            "finalized anchor disagrees with the held chain and is older than \
                             the anchor age limit; halted, a stale anchor is not re-seeded from"
                        );
                    }
                    return;
                }
                if !self.can_confirm() {
                    if first {
                        tracing::error!(
                            number,
                            "finalized anchor disagrees with the held chain and no confirmation \
                             source is configured (--peer with --head.confirm=peer, or \
                             --beacon.quorum of 2 or more); halted until the anchor agrees \
                             again or an operator restarts the node"
                        );
                    }
                    return;
                }
                if !self.anchor_confirmed(clients, &block).await {
                    if first {
                        tracing::error!(
                            number,
                            "finalized anchor disagrees with the held chain and is not \
                             confirmed by a peer or a beacon quorum; halted"
                        );
                    }
                    return;
                }
                if !self.reseed_confirmed(epoch, block) {
                    return;
                }
                tracing::error!(
                    number,
                    "finalized anchor, confirmed independently, disagrees with the held chain; \
                     re-seeded from it"
                );
                resume.notify_one();
            }
            AnchorStatus::Agree => {
                *self.disagreement.lock() = None;
                // The anchor's word alone never moves finality: the block must be deep below
                // the head, and a beacon quorum must report it (or a held canonical block above
                // it) as finalized too. With a light-client store only verified finality
                // updates move it.
                let head = self.chain.head().map_or(0, |h| h.header.number);
                let epoch = self.chain.epoch();
                if self.sync.is_none() &&
                    block
                        .header
                        .number
                        .checked_add(FINALITY_MIN_DEPTH)
                        .is_some_and(|d| head >= d) &&
                    self.beacons_finalized(clients, &block).await >= self.cfg.quorum.max(1)
                {
                    #[cfg(test)]
                    if let Some(hook) = self.before_finality.lock().as_ref() {
                        hook();
                    }
                    // A re-seed while the beacons were asked voids the check.
                    if self.chain.epoch() == epoch {
                        self.chain.confirm_finalized(&block);
                    }
                }
                // Agreement below the number that mismatched or was out of reach says nothing
                // about that number. One lock over the check and the clear: a halt set meanwhile
                // is not cleared.
                let mut h = self.halt.lock();
                let cleared = h.is_none_or(|halt| block.header.number >= halt.number());
                #[cfg(test)]
                if let Some(hook) = self.before_halt_clear.lock().as_ref() {
                    hook();
                }
                if self.chain.halted() && cleared {
                    self.set_halt(&mut h, None);
                    drop(h);
                    tracing::warn!("finalized anchor agrees again; resuming");
                    resume.notify_one();
                }
            }
            AnchorStatus::NotHeld => {
                // Finality is above the held head: re-seed forward through the confirmed path.
                // With no confirmation source that path halts: nothing checks the head against
                // the anchor. Heads are still followed, and the anchor clears the halt once the
                // walk brings the head to it.
                let head = self.chain.head().map_or(0, |h| h.header.number);
                if block.header.number > head && self.reseed_forward_to(clients, block).await {
                    resume.notify_one();
                }
            }
        }
    }

    /// With a light-client store, handles an anchor `block` that disagrees with the held chain.
    /// Verified finality wins: the node keeps serving, and re-seeds at the block only when it is
    /// recent, not below the held finalized block, confirmed by the store or the head-confirm
    /// peer, and, unless the store proved it finalized, the store has proved no other block
    /// finalized at or above its number. Else it counts the disagreement and logs it once.
    async fn anchor_disagrees(
        &self,
        anchor: &BeaconClient,
        clients: &[BeaconClient],
        epoch: u64,
        block: HeldBlock,
        resume: &Notify,
    ) {
        let (number, hash) = (block.header.number, block.hash);
        let Some(sync) = &self.sync else { return };
        let verified = sync.latest_finalized();
        let finalized = self.chain.finalized_number();
        let contradicts = finalized.is_some_and(|f| number < f) ||
            !sync.confirms(hash) &&
                verified.is_some_and(|v| v.number >= number && v.block_hash != hash);
        if !contradicts &&
            self.anchor_recent(&block) &&
            self.anchor_confirmed(clients, &block).await &&
            self.reseed_confirmed(epoch, block)
        {
            *self.disagreement.lock() = None;
            tracing::error!(
                number,
                "finalized anchor, confirmed independently, disagrees with the held chain; \
                 re-seeded from it"
            );
            resume.notify_one();
            return;
        }
        self.metrics.anchor_disagreement();
        if self.disagreement.lock().replace((number, hash)) != Some((number, hash)) {
            tracing::warn!(
                anchor = anchor.host(),
                number,
                finalized,
                verified_finalized = verified.map(|v| v.number),
                "the finalized anchor disagrees with the verified chain; verified finality wins, \
                 so the node keeps serving and does not follow the anchor"
            );
        }
    }

    async fn coordinate(
        &self,
        anchor: BeaconClient,
        clients: Vec<BeaconClient>,
        incoming: Arc<Reports>,
        resume: Arc<Notify>,
    ) {
        let mut seen = vec![0u64; clients.len()];
        let every = vec![true; clients.len()];
        let mut reports: Vec<Option<B256>> = vec![None; clients.len()];
        // Roots that could not be had: since when, and which sources' reports of them are
        // ignored. A source that had not reported the root yet is still heard: it may not have
        // imported the block when the others were asked, or a dead end below the head may have
        // been steered by the ones that had.
        let mut failed: HashMap<B256, (Instant, Vec<bool>)> = HashMap::new();
        // Roots no peer confirmed: until when they wait, and the tries in a row. Only roots with
        // quorum are kept, so the count lasts past the wait and the map holds one per source.
        let mut unconfirmed: HashMap<B256, (Instant, u32)> = HashMap::new();
        // Roots no source held when last taken up. Only roots with quorum are kept.
        let mut unserved: HashSet<B256> = HashSet::new();
        let mut agreed: Option<B256> = None;
        // The last roots that ended well, oldest first, with the hash of the block at each.
        let mut recent_ok: VecDeque<(B256, B256)> = VecDeque::with_capacity(RECENT_OK);
        // With quorum 1 one source alone starts an advance, which asks every other source and
        // the peers: per source, failures in a row and until when the roots it reports wait.
        let mut backoff: Vec<(u32, Option<Instant>)> = vec![(0, None); clients.len()];
        // Per source, the last root it reported that ended `Followed`: a try of it again adds
        // no strike, a new one does.
        let mut followed_root: Vec<Option<B256>> = vec![None; clients.len()];
        let quorum = self.head_quorum();
        let has_quorum = |reports: &[Option<B256>], root: B256| {
            reports.iter().filter(|r| **r == Some(root)).count() >= quorum
        };
        // Roots tried again without a report, and when: an event stream reports a root once per
        // slot, so a root left unconfirmed or held back by a backoff would otherwise wait for the
        // next slot. Each root keeps its own time, so a report of another root does not take its
        // place. Only roots with quorum are kept: one per source at most.
        let mut retries: HashMap<B256, Instant> = HashMap::new();
        // Whether this halt was logged as one only a restart clears.
        let mut restart_logged = false;
        let retry_by = |retries: &mut HashMap<B256, Instant>,
                        reports: &[Option<B256>],
                        root: B256,
                        at: Instant| {
            retries.retain(|r, _| has_quorum(reports, *r));
            let due = retries.entry(root).or_insert(at);
            *due = (*due).min(at);
        };
        loop {
            let next_retry = retries.values().min().copied();
            // Each wake gives (the source that reported, the root to retry).
            let batch: Vec<(Option<usize>, Option<B256>)> = tokio::select! {
                changed = incoming.changed(&mut seen) => {
                    for (idx, root) in &changed {
                        reports[*idx] = Some(*root);
                    }
                    changed.into_iter().map(|(i, _)| (Some(i), None)).collect()
                }
                () = resume.notified() => {
                    // Re-seeded: roots that did not connect to the old chain may connect now.
                    failed.clear();
                    unconfirmed.clear();
                    recent_ok.clear();
                    self.walked.lock().clear();
                    vec![(None, None)]
                }
                () = tokio::time::sleep_until(
                    next_retry.map_or_else(tokio::time::Instant::now, tokio::time::Instant::from_std),
                ), if next_retry.is_some() => {
                    let now = Instant::now();
                    retries.extract_if(|_, due| *due <= now).map(|(r, _)| (None, Some(r))).collect()
                }
            };
            for (reporter, retry) in batch {
                let candidate = match retry {
                    Some(r) => Some(r).filter(|r| has_quorum(&reports, *r)),
                    None => reporter
                        .and_then(|i| reports[i])
                        .filter(|r| has_quorum(&reports, *r))
                        .or_else(|| agreed.filter(|a| has_quorum(&reports, *a))),
                };
                let Some(root) = candidate else { continue };
                agreed = Some(root);
                let halted = self.chain.halted();
                restart_logged &= halted;
                if halted && !self.follows_while_halted() {
                    continue;
                }
                if recent_ok.iter().any(|(r, hash)| {
                    *r == root && self.chain.by_hash(hash).is_some_and(|b| self.follows(&b))
                }) {
                    continue;
                }
                failed.retain(|_, (t, _)| t.elapsed() < self.cfg.failed_ttl);
                // Only a fresh report of the root itself, from a source not ignored for it, tries
                // it again: a reporter of another root falls back to the agreed one.
                if failed.get(&root).is_some_and(|(_, ignored)| {
                    reporter.is_none_or(|i| ignored[i] || reports[i] != Some(root))
                }) {
                    continue;
                }
                // An unconfirmed root waits a little before the peers are asked again.
                unconfirmed.retain(|r, _| has_quorum(&reports, *r));
                if let Some((until, _)) = unconfirmed.get(&root) &&
                    Instant::now() < *until
                {
                    retry_by(&mut retries, &reports, root, *until);
                    continue;
                }
                // With quorum 1, the root waits while every source that reports it is backed off,
                // on a report and on a retry alike.
                let reporters: Vec<usize> = if quorum == 1 {
                    (0..clients.len()).filter(|i| reports[*i] == Some(root)).collect()
                } else {
                    Vec::new()
                };
                let started = Instant::now();
                let backed_off: Option<Vec<Instant>> = reporters
                    .iter()
                    .map(|i| backoff[*i].1.filter(|until| started < *until))
                    .collect();
                if let Some(until) = backed_off.and_then(|w| w.into_iter().min()) {
                    retry_by(&mut retries, &reports, root, until);
                    continue;
                }
                retries.remove(&root);
                let was_unserved = unserved.remove(&root);
                let unconfirmed_tries = unconfirmed.remove(&root).map_or(0, |(_, n)| n);
                // Sources with fewer failed or slow answers first, so a slow or bad source moves
                // back on its own even when it reports first; among equals, the ones that
                // reported the root.
                let mut order: Vec<usize> = (0..clients.len()).collect();
                order.sort_by_key(|i| reports[*i] != Some(root));
                self.sort_sources(&mut order);
                self.held.lock().clear();
                let walked_before = self.walked.lock().len();
                // With another source to hear, one try holds the coordinator for the budget at
                // most. The try is dropped then; the ancestors it fetched are kept.
                let budgeted = clients.len() > 1;
                let res = if budgeted {
                    tokio::time::timeout(self.advance_budget, self.advance(&clients, &order, root))
                        .await
                        .unwrap_or(Err(AdvanceError::Slow))
                } else {
                    self.advance(&clients, &order, root).await
                };
                let res = match res {
                    Err(AdvanceError::Unserved) if was_unserved => Err(AdvanceError::Failed),
                    res => res,
                };
                // A lone source holds no other source's head back.
                let held = if budgeted {
                    self.holds(clients.len())
                } else {
                    vec![Duration::ZERO; clients.len()]
                };
                // A slow try starts the window when it ends: a source that holds its answer would
                // otherwise outwait it. A quick one starts it when taken up, so the peer's pauses
                // do not delay an honest source's next head.
                let from = if started.elapsed() < SLOW_ANSWER { started } else { Instant::now() };
                let strike = |b: &mut (u32, Option<Instant>), from: Instant, at_least: Duration| {
                    let strikes = b.0.saturating_add(1);
                    let wait = REPORT_BACKOFF
                        .saturating_mul(1 << (strikes - 1).min(3))
                        .min(MAX_REPORT_BACKOFF)
                        .max(at_least);
                    *b = (strikes, Some(from + wait));
                };
                // Only a head that moved clears the strikes: a source could otherwise clear them
                // between made-up roots with a root already followed. A source that held the try
                // waits at least as long as it held it, whatever the result.
                for &i in &reporters {
                    let moved = matches!(res, Ok((_, true)));
                    if !held[i].is_zero() {
                        if moved {
                            backoff[i] = (0, Some(Instant::now() + held[i]));
                        } else {
                            strike(&mut backoff[i], Instant::now(), held[i]);
                        }
                        continue;
                    }
                    match res {
                        Ok((_, true)) => backoff[i] = (0, None),
                        Ok((_, false)) | Err(AdvanceError::Gap | AdvanceError::Slow) => {}
                        // A new root adds a strike, so a source that floods made-up roots
                        // answered with the held head waits longer each time. The retries of one
                        // root do not, so an honest source that reported the real root of a
                        // block taken under another root still hears its next head.
                        Err(AdvanceError::Followed) if followed_root[i] == Some(root) => {
                            let until = from + REPORT_BACKOFF;
                            backoff[i].1 = Some(backoff[i].1.map_or(until, |u| u.max(until)));
                        }
                        Err(AdvanceError::Followed) => {
                            followed_root[i] = Some(root);
                            strike(&mut backoff[i], from, Duration::ZERO);
                        }
                        Err(
                            AdvanceError::Failed |
                            AdvanceError::DeadEnd { .. } |
                            AdvanceError::Unconfirmed |
                            AdvanceError::Unserved,
                        ) => strike(&mut backoff[i], from, Duration::ZERO),
                    }
                }
                // A try cut off with no source holding it and no ancestor fetched waits like an
                // unconfirmed one: a slow peer, not a source, ran out the budget.
                let holders: Vec<bool> = held.iter().map(|h| !h.is_zero()).collect();
                let progressed = self.walked.lock().len() > walked_before;
                let res = match res {
                    Err(AdvanceError::Slow) if !holders.contains(&true) && !progressed => {
                        Err(AdvanceError::Unconfirmed)
                    }
                    res => res,
                };
                match res {
                    Ok((hash, moved)) => {
                        recent_ok.retain(|(r, _)| *r != root);
                        if recent_ok.len() >= RECENT_OK {
                            recent_ok.pop_front();
                        }
                        recent_ok.push_back((root, hash));
                        // A head that reached a halt's number lets the anchor clear it at the
                        // anchor task's next check under its floor, not at the next recheck.
                        let halted_at = self.halt.lock().map(Halt::number);
                        let head = self.chain.head().map_or(0, |h| h.header.number);
                        if moved && halted_at.is_some_and(|n| head >= n) {
                            self.anchor_wake.notify_one();
                        }
                        if moved {
                            self.apply_verified_finality();
                        }
                    }
                    Err(AdvanceError::Failed) => {
                        let reported = reports.iter().map(|r| *r == Some(root)).collect();
                        failed.insert(root, (Instant::now(), reported));
                    }
                    Err(AdvanceError::DeadEnd { at: bad_root, ref led }) => {
                        // Only the sources that steered the walk there named `bad_root`: it may
                        // be a real root a hostile source put under a block of its own, so the
                        // others' reports of it are still heard.
                        let steered = (0..clients.len()).map(|i| led.contains(&i)).collect();
                        failed.insert(bad_root, (Instant::now(), steered));
                        let reported = reports.iter().map(|r| *r == Some(root)).collect();
                        failed.insert(root, (Instant::now(), reported));
                    }
                    Err(
                        AdvanceError::Unconfirmed | AdvanceError::Unserved | AdvanceError::Followed,
                    ) => {
                        if matches!(res, Err(AdvanceError::Unserved)) {
                            unserved.retain(|r| has_quorum(&reports, *r));
                            unserved.insert(root);
                        }
                        let tries = unconfirmed_tries.saturating_add(1);
                        let wait = UNCONFIRMED_TTL
                            .saturating_mul(1 << (tries - 1).min(2))
                            .min(MAX_REPORT_BACKOFF);
                        let until = Instant::now() + wait;
                        unconfirmed.insert(root, (until, tries));
                        retry_by(&mut retries, &reports, root, until);
                    }
                    // With no confirmation source a re-seed can only set the halt, which holds
                    // already: the anchor task's check, under its floor, raises its number.
                    Err(AdvanceError::Gap) if !self.can_confirm() && self.chain.halted() => {
                        // The walk cannot bring the head to the beacons', and the anchor alone
                        // never re-seeds it.
                        if !restart_logged {
                            restart_logged = true;
                            tracing::error!(
                                head = self.chain.head().map_or(0, |h| h.header.number),
                                "the beacons' head is more than {MAX_ANCESTORS} blocks above the \
                                 held head and no confirmation source is configured; only an \
                                 operator restart clears the halt"
                            );
                        }
                        self.anchor_wake.notify_one();
                        failed.insert(root, (Instant::now(), every.clone()));
                    }
                    Err(AdvanceError::Slow) => {
                        let reported: Vec<bool> =
                            reports.iter().map(|r| *r == Some(root)).collect();
                        if holders.contains(&true) {
                            // The line a holder steered is not resumed.
                            self.walked.lock().clear();
                        }
                        if reported.iter().zip(&holders).all(|(r, h)| !r || *h) &&
                            holders.contains(&true)
                        {
                            // Every reporter held it: the root is theirs alone, however far the
                            // walk got. A holder that names a made-up root can walk real
                            // ancestors first, from its own answers or another source's, and
                            // the line it steered is not resumed: progress would let it hold
                            // every try again.
                            failed.insert(root, (Instant::now(), reported));
                        } else {
                            // Another reporter tries it again at once, with the holders now
                            // further back in the order.
                            retry_by(&mut retries, &reports, root, Instant::now());
                        }
                    }
                    Err(AdvanceError::Gap) => {
                        if self.reseed_forward(&anchor, &clients).await {
                            failed.clear();
                            recent_ok.clear();
                        } else {
                            failed.insert(root, (Instant::now(), every.clone()));
                        }
                    }
                }
            }
        }
    }

    /// Fetches a block by root from the first source whose answer verifies (and, with
    /// `expected`, has that hash). Every source is asked until one gives the expected block.
    ///
    /// Blame: an invalid answer counts against its source; a timeout counts against its
    /// liveness only; an optimistic answer counts against nobody. A valid block with another hash
    /// is judged only when the root is `trusted` (a quorum of two or more agreed on it),
    /// against the others: when some source serves the expected block,
    /// the ones that served another are charged; when none does, the root itself is the wrong
    /// candidate, and only outliers against a strict majority are charged (all agreeing on the
    /// same other block charges nobody). Sources after the first that serves the expected block
    /// are not asked, so they are not charged: blame follows `order`.
    async fn fetch_block(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        root: B256,
        expected: Option<B256>,
        trusted: bool,
    ) -> Fetched {
        let mut bad = false;
        let mut others: Vec<(usize, B256)> = Vec::new();
        let mut found = None;
        for &i in order {
            let Ok(v) = self.fetch_root(clients, i, root).await else { continue };
            match self.parse(v, root).await {
                Ok(p) if expected.is_none_or(|h| h == p.block.hash) => {
                    self.used(&[i], root);
                    found = Some(p);
                    break;
                }
                Ok(p) => {
                    tracing::debug!(
                        source = clients[i].host(),
                        "beacon root leads to another block"
                    );
                    others.push((i, p.block.hash));
                }
                Err(PayloadError::Optimistic) => {
                    self.skip_optimistic(FailureSource::Beacon, clients[i].host())
                }
                Err(e) => {
                    bad = true;
                    // An invalid answer under a root only one source named may be that root's
                    // fault: charge only under a trusted root.
                    if trusted {
                        self.count_failure(i, clients[i].host(), &e);
                    } else {
                        tracing::debug!(source = clients[i].host(), error = %e, "beacon block rejected");
                    }
                }
            }
        }
        if !trusted {
            // The root came from one source: a valid block under it says nothing about who is
            // honest (the namer may have made it up and serve the wanted block under it).
        } else if found.is_some() {
            for (i, _) in &others {
                self.count_failure(*i, clients[*i].host(), &PayloadError::HashMismatch);
            }
        } else if others.len() > 1 {
            let mut counts: HashMap<B256, usize> = HashMap::new();
            for (_, h) in &others {
                *counts.entry(*h).or_default() += 1;
            }
            let (top, n) = counts.iter().max_by_key(|(_, n)| **n).map(|(h, n)| (*h, *n)).unwrap();
            if n * 2 > others.len() {
                for (i, h) in &others {
                    if *h != top {
                        self.count_failure(*i, clients[*i].host(), &PayloadError::HashMismatch);
                    }
                }
            }
        }
        match found {
            Some(p) => Fetched::Block(Box::new(p)),
            None if bad => Fetched::Bad,
            None => Fetched::Unavailable,
        }
    }

    /// Fetches the execution parent of `child`.
    ///
    /// The parent's hash is pinned by `child`'s `parent_hash`, but its beacon root comes from
    /// whichever source served `child`, and before Cancun the execution header does not commit to
    /// it. When the root `child` names does not lead to the pinned parent, the other sources are
    /// asked for `child` and the parent roots they name are tried too. When none leads there, the
    /// sources that serve `child` under its root go back in the order, and they are returned.
    async fn fetch_parent(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        child: &ParsedBlock,
        trusted: bool,
    ) -> Result<Box<ParsedBlock>, Vec<usize>> {
        let want = child.block.header.parent_hash;
        let mut tried = vec![child.parent_root];
        if let Fetched::Block(b) =
            self.fetch_block(clients, order, child.parent_root, Some(want), trusted).await
        {
            return Ok(b);
        }
        let child_root = child.block.beacon_root;
        // The sources that serve `child` under `child_root`.
        let mut named = Vec::new();
        for &i in order {
            let Ok(v) = self.fetch_root(clients, i, child_root).await else { continue };
            let Ok(p) = self.parse(v, child_root).await else { continue };
            if p.block.hash != child.block.hash {
                continue;
            }
            named.push(i);
            if tried.contains(&p.parent_root) {
                continue;
            }
            tried.push(p.parent_root);
            if let Fetched::Block(b) =
                self.fetch_block(clients, order, p.parent_root, Some(want), false).await
            {
                // This source's answer for the child steered the walk to the parent.
                self.used(&[i], child_root);
                return Ok(b);
            }
        }
        // `child_root` may be a root its server made up, which no other source can answer: its
        // servers go back in the order, so the next walk is steered by another source.
        for &i in &named {
            self.count_slow(i, clients[i].host());
        }
        Err(named)
    }

    /// Fetches the head block at `root` and accepts it only when `quorum` distinct sources serve
    /// a block with the same execution `block_hash` and the same beacon `parent_root`.
    ///
    /// Agreeing on a beacon root is not enough: a source can answer the agreed root with any
    /// self-consistent block. Each answer has already passed the rebuilt-hash check, so two
    /// answers with the same `block_hash` have the same header and body. Agreement on the hash
    /// therefore carries the quorum's trust from the root to the content, without rebuilding the
    /// SSZ `hash_tree_root` of the whole beacon block. The `parent_root` is part of the key too:
    /// before Cancun the execution header does not commit to it, and it steers the ancestor
    /// walk. Ancestors need no quorum: their hashes are pinned by the head through `parent_hash`.
    ///
    /// Once a quorum agrees, each source asked before it that served another valid block is
    /// charged. Without a quorum nobody is charged for a valid block.
    #[cfg(test)]
    async fn fetch_head(&self, clients: &[BeaconClient], order: &[usize], root: B256) -> Fetched {
        self.fetch_head_by(clients, order, root).await.0
    }

    /// [`Self::fetch_head`], with the sources that served the agreed block: a peer that vetoes it
    /// charges each of them, as [`Self::pick_head`] charges the source of a vetoed pick.
    async fn fetch_head_by(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        root: B256,
    ) -> (Fetched, Vec<usize>) {
        let mut seen: HashMap<(B256, B256), (usize, ParsedBlock)> = HashMap::new();
        // Which block each source served, to charge the ones the quorum outvotes.
        let mut served: Vec<(usize, (B256, B256))> = Vec::new();
        let mut disagreed = false;
        for &i in order {
            let Ok(v) = self.fetch_root(clients, i, root).await else { continue };
            match self.parse(v, root).await {
                Ok(p) => {
                    let hash = (p.block.hash, p.parent_root);
                    if seen.keys().any(|h| *h != hash) {
                        disagreed = true;
                    }
                    served.push((i, hash));
                    let n = {
                        let entry = seen.entry(hash).or_insert((0, p));
                        entry.0 += 1;
                        entry.0
                    };
                    if n >= self.cfg.quorum {
                        if disagreed {
                            tracing::warn!(
                                "beacon sources served different blocks for one root; \
                                 following the block a quorum agrees on"
                            );
                            // One root names one block: another valid block under it is a lie.
                            for (j, _) in served.iter().filter(|(_, h)| *h != hash) {
                                self.count_failure(
                                    *j,
                                    clients[*j].host(),
                                    &PayloadError::HashMismatch,
                                );
                            }
                        }
                        let servers =
                            served.iter().filter(|(_, h)| *h == hash).map(|(j, _)| *j).collect();
                        let fetched = seen
                            .remove(&hash)
                            .map_or(Fetched::Unavailable, |(_, p)| Fetched::Block(Box::new(p)));
                        return (fetched, servers);
                    }
                }
                Err(PayloadError::Optimistic) => {
                    self.skip_optimistic(FailureSource::Beacon, clients[i].host())
                }
                Err(e) => {
                    disagreed = true;
                    self.count_failure(i, clients[i].host(), &e);
                }
            }
        }
        if disagreed {
            tracing::warn!("no quorum of beacon sources served the same block for the head root");
            (Fetched::Bad, Vec::new())
        } else {
            (Fetched::Unavailable, Vec::new())
        }
    }

    /// Moves the head to the block at beacon `root`, completing its ancestry first and, with a
    /// confirmer, after a peer reports the same hash. Returns the block's hash and whether the
    /// head moved: a block already followed moves nothing. On failure returns why, so the root
    /// is not retried every poll.
    ///
    /// When the ancestor walk dead-ends, the head is fetched and walked again with the sources
    /// that led it there asked last, while some source did not.
    async fn advance(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        root: B256,
    ) -> Result<(B256, bool), AdvanceError> {
        let mut last: Vec<usize> = Vec::new();
        loop {
            let res = self.advance_once(clients, order, root, &last).await;
            // A try that ends leaves no walk to resume, and a try again re-steers the walk: it
            // must not take up the line the sources now asked last steered.
            self.walked.lock().clear();
            match res {
                Err(AdvanceError::DeadEnd { at, led }) => {
                    let before = last.len();
                    for i in led {
                        if !last.contains(&i) {
                            last.push(i);
                        }
                    }
                    // A try helps only with a new source asked last and another one ahead of it.
                    if last.len() == before || last.len() >= clients.len() {
                        return Err(AdvanceError::DeadEnd { at, led: last });
                    }
                }
                res => return res,
            }
        }
    }

    /// One try of [`Self::advance`], asking the sources in `last` after all others.
    async fn advance_once(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        root: B256,
        last: &[usize],
    ) -> Result<(B256, bool), AdvanceError> {
        let mut order = order.to_vec();
        order.sort_by_key(|i| last.contains(i));
        let order = order.as_slice();
        let pick = self.sync.is_none() &&
            self.confirm.is_some() &&
            self.cfg.quorum == 1 &&
            clients.len() > 1;
        // On the quorum path, the sources that served the agreed block.
        let mut servers = Vec::new();
        let (head, confirmed) = if let Some(sync) = &self.sync {
            // Only a root the store verified is reported, and only its verified block is taken.
            let Some(verified) = sync.head(root) else { return Err(AdvanceError::Failed) };
            match self.fetch_verified(clients, order, verified).await {
                Fetched::Block(b) => (*b, false),
                Fetched::Unavailable => return Err(AdvanceError::Unserved),
                Fetched::Bad => return Err(AdvanceError::Failed),
            }
        } else if pick {
            (self.pick_head(clients, order, root).await?, true)
        } else {
            let (fetched, by) = self.fetch_head_by(clients, order, root).await;
            servers = by;
            match fetched {
                Fetched::Block(b) => (*b, false),
                Fetched::Bad | Fetched::Unavailable => return Err(AdvanceError::Failed),
            }
        };
        if self.follows(&head.block) {
            return Ok((head.block.hash, false));
        }
        if self.is_behind(&head.block) {
            tracing::warn!(
                number = head.block.header.number,
                held = ?self.chain.head().map(|h| h.header.number),
                "beacon head is behind the held head; not following it"
            );
            return Err(AdvanceError::Failed);
        }
        // The block can become the head: its servers' answers held nothing, also when the peer
        // is slow to confirm it. The other paths note their servers themselves.
        self.used(&servers, root);
        let (target, head_number) = (head.block.hash, head.block.header.number);
        // Confirm before walking: an unconfirmed head costs no ancestor fetches.
        if !confirmed {
            match self.confirmed(head_number, target).await {
                Confirmation::Confirmed => {}
                Confirmation::Mismatch => {
                    // The veto was counted once; each source that served the block is charged.
                    for &i in &servers {
                        self.charge(i, clients[i].host(), &PayloadError::HashMismatch);
                    }
                    return Err(AdvanceError::Failed);
                }
                Confirmation::Unknown => return Err(AdvanceError::Unconfirmed),
            }
        }
        // The walk connects at a held block at the earliest, so a head this far above every
        // held block ends in a gap whatever is fetched.
        let highest = self.chain.highest().unwrap_or(0);
        if head_number.saturating_sub(highest) > MAX_ANCESTORS as u64 + 1 {
            return Err(AdvanceError::Gap);
        }
        let finalized = self.chain.finalized_number().unwrap_or(0);
        let mut pending: Vec<HeldBlock> = Vec::new();
        let mut cur = head;
        let mut walk_bytes = body_bytes(&cur.block.body);
        let mut order = order.to_vec();
        while !self.chain.contains(&cur.block.header.parent_hash) {
            // Only the finalized block, always held, lives at or below the finalized number.
            if cur.block.header.number <= finalized.saturating_add(1) {
                return Err(AdvanceError::Failed);
            }
            if pending.len() >= MAX_ANCESTORS {
                return Err(AdvanceError::Gap);
            }
            // Only the head's parent root was agreed by a quorum or signed by the committee.
            let trusted = pending.is_empty() && (self.cfg.quorum >= 2 || self.sync.is_some());
            // A source that was slow on the last ancestor is asked last for the next one.
            self.sort_sources(&mut order);
            order.sort_by_key(|i| last.contains(i));
            // A try cut off by the budget left the ancestors it fetched: their hashes are pinned
            // by the head through `parent_hash`.
            let cached = self.walked.lock().get(&cur.block.header.parent_hash).cloned();
            let mut parent = match cached {
                Some(p) => p,
                None => match self.fetch_parent(clients, &order, &cur, trusted).await {
                    Ok(b) => *b,
                    // No source leads to the execution parent: refuse the whole line.
                    Err(led) => return Err(AdvanceError::DeadEnd { at: cur.parent_root, led }),
                },
            };
            pending.push(cur.block);
            // The walk holds bodies up to the chain's budget. Past it, the oldest blocks are
            // inserted without theirs: only the target needs one to become the head.
            walk_bytes = walk_bytes.saturating_add(body_bytes(&parent.block.body));
            if walk_bytes > self.chain.body_budget() {
                parent.block.body = Arc::default();
            }
            {
                let mut walked = self.walked.lock();
                if walked.len() < MAX_ANCESTORS {
                    walked.insert(parent.block.hash, parent.clone());
                }
            }
            cur = parent;
        }
        if !self.chain.contains(&cur.block.hash) && self.chain.insert(cur.block).is_err() {
            return Err(AdvanceError::Failed);
        }
        for b in pending.into_iter().rev() {
            if !self.chain.contains(&b.hash) && self.chain.insert(b).is_err() {
                return Err(AdvanceError::Failed);
            }
        }
        if self.chain.set_head(target).is_err() {
            return Err(AdvanceError::Failed);
        }
        self.publish_head();
        Ok((target, true))
    }
}

/// Whether an event stream that lived `lived` gets an immediate reconnect, counting them in a row
/// in `quick`. A stream that lived under a second gets none and falls back to polling and the
/// `sse_retry` gate; so does one after [`MAX_QUICK_RECONNECTS`] in a row. A stream that outlived
/// the gate was healthy, so its drop starts a new count.
fn quick_reconnect(quick: &mut u32, lived: Duration, sse_retry: Duration) -> bool {
    if lived >= sse_retry {
        *quick = 0;
    }
    let again = lived >= Duration::from_secs(1) && *quick < MAX_QUICK_RECONNECTS;
    if again {
        *quick += 1;
    }
    again
}

/// `res` as an `Option`, logging when a source starts failing and when it answers again, so a
/// dead, rate-limited or refusing source shows in the log without a line per poll.
fn note_answer<T>(
    failing: &mut bool,
    request: &str,
    host: &str,
    res: Result<T, SourceError>,
) -> Option<T> {
    match res {
        Ok(v) => {
            if std::mem::take(failing) {
                tracing::info!(source = host, request, "beacon source answers again");
            }
            Some(v)
        }
        Err(e) => {
            if !std::mem::replace(failing, true) {
                tracing::warn!(source = host, request, error = %e, "beacon source request failed");
            }
            None
        }
    }
}

fn lag_seconds(timestamp: u64) -> f64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    now.saturating_sub(timestamp) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fake_beacon::{Fake, FakeChain, KEY_PATH},
        payload::fake::{FakeBlock, Fork},
    };
    use parking_lot::Mutex;

    const START: u64 = 1000;
    /// The fake chain's timestamps are from 2023: accept any anchor age.
    const TEST_ANCHOR_AGE: Duration = Duration::from_secs(1 << 40);

    struct Rig {
        beacon: Fake,
        anchor: Fake,
        chain: Arc<HeaderChain>,
        fc: FakeChain,
        metrics: LiteMetrics,
        task: tokio::task::JoinHandle<()>,
    }

    impl Rig {
        async fn start(sse: bool, fork: Fork, poll_ms: u64) -> Self {
            Self::start_with(sse, fork, poll_ms, None).await
        }

        async fn start_with(sse: bool, fork: Fork, poll_ms: u64, peer: Option<Arc<Peer>>) -> Self {
            let beacon = Fake::start(sse, false).await;
            let anchor = Fake::start(false, true).await;
            let fc = FakeChain::new(fork, START);
            let first = fc.head().clone();
            beacon.push(&first);
            beacon.finalize(&first);
            anchor.set_anchor_block(&first);
            let chain = Arc::new(HeaderChain::new());
            let cfg = FollowConfig {
                urls: vec![beacon.beacon_url()],
                quorum: 1,
                poll: Duration::from_millis(poll_ms),
                anchor_url: anchor.anchor_url(),
                recheck: Duration::from_millis(poll_ms),
                sse_retry: Duration::from_secs(60),
                anchor_gap: MIN_ANCHOR_GAP,
                failed_ttl: Duration::from_secs(60),
                max_anchor_age: TEST_ANCHOR_AGE,
                forks: crate::payload::fake::forks(fork),
            };
            let metrics = LiteMetrics::new();
            let mut f = Follower::new(cfg, chain.clone(), metrics.clone());
            if let Some(p) = peer {
                f = f.with_confirm(p);
            }
            let task = tokio::spawn(Arc::new(f).run());
            Self { beacon, anchor, chain, fc, metrics, task }
        }

        async fn wait_head(&self, n: u64) {
            for _ in 0..1500 {
                if self.chain.head().is_some_and(|h| h.header.number == n) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("head never reached {n}: {:?}", self.chain.head().map(|h| h.header.number));
        }

        async fn stays(&self, n: u64, ms: u64) {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            assert_eq!(self.chain.head().unwrap().header.number, n);
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn aborting_the_follower_stops_its_source_and_anchor_tasks() {
        let r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        r.task.abort();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let calls = || {
            (
                r.beacon.calls("/eth/v1/beacon/headers/head"),
                r.anchor.calls("/eth/v2/beacon/blocks/finalized"),
            )
        };
        let before = calls();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(calls(), before, "a task polled on after the follower was aborted");
    }

    #[tokio::test]
    async fn polling_follows_heads_when_events_404_and_reaches_a_skipped_head() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let b1 = r.fc.next();
        r.beacon.push(&b1);
        r.wait_head(START + 1).await;
        // Two heads between polls: the newest is reached through the parent root.
        let (b2, b3) = (r.fc.next(), r.fc.next());
        r.beacon.serve_only(&b2);
        r.beacon.push(&b3);
        r.wait_head(START + 3).await;
        assert_eq!(r.chain.by_number(START + 2).unwrap().hash, b2.hash);
        // About one headers/head per poll, SSE tried once, finality read less often.
        let before = r.beacon.calls("/eth/v1/beacon/headers/head");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let got = r.beacon.calls("/eth/v1/beacon/headers/head") - before;
        assert!((4..=14).contains(&got), "{got} polls in 500ms at 50ms");
        assert_eq!(r.beacon.calls("/eth/v1/events"), 1);
        assert!(
            r.beacon.calls("/eth/v1/beacon/states/head/finality_checkpoints") <
                r.beacon.calls("/eth/v1/beacon/headers/head")
        );
    }

    #[tokio::test]
    async fn sse_follows_without_polling() {
        let mut r = Rig::start(true, Fork::Prague, 300).await;
        r.wait_head(START).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let start = r.beacon.calls("/eth/v1/beacon/headers/head");
        let b = r.fc.next();
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(r.beacon.calls("/eth/v1/beacon/headers/head") - start <= 1);
    }

    #[tokio::test]
    async fn a_wrong_block_hash_is_never_a_head_and_is_not_refetched() {
        for sse in [true, false] {
            let mut r = Rig::start(sse, Fork::Shanghai, 50).await;
            r.wait_head(START).await;
            let good = r.fc.next();
            r.beacon.push(&good);
            r.wait_head(START + 1).await;
            let mut bad =
                crate::payload::fake::make(Fork::Shanghai, START + 2, good.hash, good.root, "bad");
            bad.json["data"]["message"]["body"]["execution_payload"]["block_hash"] =
                serde_json::json!(crate::payload::fake::hx(&[1u8; 32]));
            r.beacon.push(&bad);
            r.stays(START + 1, 400).await;
            let n = r.beacon.calls(&format!("/eth/v2/beacon/blocks/{:#x}", bad.root));
            assert!((1..=2).contains(&n), "bad block fetched {n} times");
            // The next good block is accepted.
            let next = r.fc.next();
            r.beacon.push(&next);
            r.wait_head(START + 2).await;
            drop(r);
        }
    }

    #[tokio::test]
    async fn an_orphan_is_not_served_and_its_parent_is_not_chased_every_poll() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let orphan = crate::payload::fake::make(
            Fork::Cancun,
            START + 5,
            B256::repeat_byte(0x77),
            B256::repeat_byte(0x78),
            "orphan",
        );
        r.beacon.push(&orphan);
        r.stays(START, 500).await;
        let parent_path = format!("/eth/v2/beacon/blocks/{:#x}", orphan.parent_root);
        assert_eq!(r.beacon.calls(&parent_path), 1);
        let next = r.fc.next();
        r.beacon.push(&next);
        r.wait_head(START + 1).await;
    }

    #[tokio::test]
    async fn a_reorg_switches_the_head_within_the_window() {
        let mut r = Rig::start(true, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let a1 = r.fc.next();
        let a2 = r.fc.next();
        r.beacon.push(&a1);
        r.wait_head(START + 1).await;
        r.beacon.push(&a2);
        r.wait_head(START + 2).await;
        // A sibling branch from START: b1, b2, b3.
        let anchor_block = r.fc.blocks[0].clone();
        let b1 = crate::payload::fake::make(
            Fork::Cancun,
            START + 1,
            anchor_block.hash,
            anchor_block.root,
            "b",
        );
        let b2 = crate::payload::fake::make(Fork::Cancun, START + 2, b1.hash, b1.root, "b");
        let b3 = crate::payload::fake::make(Fork::Cancun, START + 3, b2.hash, b2.root, "b");
        r.beacon.serve_only(&b1);
        r.beacon.serve_only(&b2);
        r.beacon.push(&b3);
        r.wait_head(START + 3).await;
        assert_eq!(r.chain.by_number(START + 1).unwrap().hash, b1.hash);
        assert!(r.chain.contains(&a2.hash));
        assert!(!r.chain.is_canonical(&a2.hash));
    }

    async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..300 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// A peer whose canonical chain is `fc`'s first block and the two after it, so it confirms
    /// `fc`'s first block as an anchor.
    fn honest_peer(fc: &FakeChain) -> Arc<Peer> {
        let p = peer_with(&[&fc.blocks[0]]);
        hold_line(&p, &fc.blocks[0], FINALITY_MIN_DEPTH as usize + 2);
        p
    }

    /// Holds `n` blocks on top of `from` on `peer`'s canonical chain, as `FakeChain::next` makes
    /// them (so they equal the test chain's own later blocks), and returns them.
    fn hold_line(peer: &Peer, from: &FakeBlock, n: usize) -> Vec<FakeBlock> {
        let mut c = FakeChain { fork: Fork::Cancun, blocks: vec![from.clone()] };
        (0..n)
            .map(|_| {
                let b = c.next();
                peer.hold(&b);
                b
            })
            .collect()
    }

    struct DefaultRig {
        beacons: Vec<Fake>,
        anchor: Fake,
        chain: Arc<HeaderChain>,
        fc: FakeChain,
        peer: Arc<Peer>,
        follower: Arc<Follower>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for DefaultRig {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// The default mode: `n` beacons, quorum 1, a confirming static peer whose canonical chain
    /// runs past the start.
    async fn default_rig(n: usize) -> DefaultRig {
        default_rig_with(n, Duration::from_millis(50), FINALITY_MIN_DEPTH as usize + 20).await
    }

    async fn default_rig_with(n: usize, recheck: Duration, peer_line: usize) -> DefaultRig {
        let mut beacons = Vec::new();
        for _ in 0..n {
            beacons.push(Fake::start(false, false).await);
        }
        let anchor = Fake::start(false, true).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        let first = fc.head().clone();
        let peer = Arc::new(Peer::default());
        peer.hold(&first);
        hold_line(&peer, &first, peer_line);
        for b in &beacons {
            b.push(&first);
            b.finalize(&first);
        }
        anchor.set_anchor_block(&first);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: beacons.iter().map(Fake::beacon_url).collect(),
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck,
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_millis(200),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let follower = Arc::new(
            Follower::new(cfg, chain.clone(), LiteMetrics::new()).with_confirm(peer.clone()),
        );
        let task = tokio::spawn(follower.clone().run());
        wait_until("the seed", || chain.head().is_some()).await;
        DefaultRig { beacons, anchor, chain, fc, peer, follower, task }
    }

    #[tokio::test]
    async fn finality_moves_only_to_a_deep_block_the_beacons_also_finalized() {
        let mut r = default_rig(2).await;
        let blocks: Vec<_> = (0..FINALITY_MIN_DEPTH + 6).map(|_| r.fc.next()).collect();
        for b in &blocks {
            for f in &r.beacons {
                f.serve_only(b);
            }
        }
        // The head is START + 3, and the anchor calls the head's parent finalized: too shallow.
        for f in &r.beacons {
            f.push(&blocks[2]);
        }
        wait_until("START + 3", || r.chain.head().is_some_and(|h| h.hash == blocks[2].hash)).await;
        for f in &r.beacons {
            f.finalize(&blocks[1]);
        }
        r.anchor.set_anchor_block(&blocks[1]);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(r.chain.finalized_number(), Some(START), "finality moved to a shallow block");
        assert!(!r.chain.finality_confirmed());
        // Deep enough, but the beacons do not report it as finalized: no move either.
        let last = blocks.last().unwrap();
        for f in &r.beacons {
            f.push(last);
            f.finalize(&blocks[0]);
        }
        wait_until("the far head", || r.chain.head().is_some_and(|h| h.hash == last.hash)).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(r.chain.finalized_number(), Some(START));
        // The beacons agree with the anchor, and it is deep: finality moves.
        for f in &r.beacons {
            f.finalize(&blocks[1]);
        }
        wait_until("finality", || r.chain.finalized_number() == Some(START + 2)).await;
        assert!(r.chain.finality_confirmed());
        let _ = (&r.peer, &r.follower);
    }

    #[tokio::test]
    async fn a_slow_source_is_moved_back_within_one_walk() {
        let mut r = default_rig(2).await;
        r.beacons[0].state.lock().block_delay = SLOW_ANSWER + Duration::from_millis(300);
        // An old charge on the fast source does not keep the slow one first for good.
        r.follower.failures.lock()[1] = 1;
        let blocks: Vec<_> = (0..8).map(|_| r.fc.next()).collect();
        for b in &blocks {
            for f in &r.beacons {
                f.serve_only(b);
            }
        }
        let last = blocks.last().unwrap().clone();
        for f in &r.beacons {
            f.push(&last);
        }
        for _ in 0..3000 {
            if r.chain.head().is_some_and(|h| h.hash == last.hash) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(r.chain.head().map(|h| h.hash), Some(last.hash));
        // Slow answers move the source back: the rest of the walk asks the fast one.
        let slow: usize = blocks
            .iter()
            .map(|b| r.beacons[0].calls(&format!("/eth/v2/beacon/blocks/{:#x}", b.root)))
            .sum();
        assert!(slow <= 3, "the slow source answered {slow} of 8 block requests");
        let _ = (&r.anchor, &r.peer, &r.follower);
    }

    #[tokio::test]
    async fn a_vetoed_block_charges_its_source_and_the_other_sources_answer_is_followed() {
        let mut r = default_rig(2).await;
        let real = r.fc.next();
        // The hostile source (asked first) serves a forged block under the real root.
        let mut forged = retimed(&real, 1, 0);
        forged.root = real.root;
        r.beacons[0].push(&forged);
        r.beacons[1].push(&real);
        wait_until("the real head", || r.chain.head().is_some_and(|h| h.hash == real.hash)).await;
        assert!(r.follower.source_failures(0) >= 1, "the vetoed block's source is charged");
        assert_eq!(r.follower.source_failures(1), 0);
        assert!(!r.chain.contains(&forged.hash));
    }

    #[tokio::test]
    async fn one_veto_raises_the_beacon_failure_metric_once() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let real = fc.next();
        let mut forged = retimed(&real, 1, 0);
        forged.root = real.root;
        let mut beacons = Vec::new();
        for b in [&forged, &forged, &real] {
            let f = Fake::start(false, false).await;
            f.serve_only(b);
            beacons.push(f);
        }
        let peer = Arc::new(Peer::default());
        peer.hold(&real);
        let f = bare_follower(beacons.iter().map(Fake::beacon_url).collect(), &fc.blocks[0], peer);
        let clients: Vec<_> = beacons.iter().map(|b| BeaconClient::new(b.beacon_url())).collect();
        let got = f.pick_head(&clients, &[0, 1, 2], real.root).await;
        assert!(got.is_ok_and(|p| p.block.hash == real.hash));
        assert_eq!((f.source_failures(0), f.source_failures(1)), (1, 1));
        let out = handle.render();
        assert!(out.contains("lite_proof_failures_total{source=\"beacon\"} 1\n"), "{out}");
    }

    #[tokio::test]
    async fn a_root_is_not_failed_while_a_source_is_unheard() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let real = fc.next();
        let mut forged = retimed(&real, 1, 0);
        forged.root = real.root;
        let (liar, liar2) = (Fake::start(false, false).await, Fake::start(false, false).await);
        liar.serve_only(&forged);
        liar2.serve_only(&forged);
        let peer = Arc::new(Peer::default());
        peer.hold(&real);
        // Nothing listens here: the source is never heard. A 404 would be an answer.
        let silent: Url = "http://127.0.0.1:1".parse().unwrap();
        let urls = vec![liar.beacon_url(), silent, liar2.beacon_url()];
        let f = bare_follower(urls.clone(), &fc.blocks[0], peer);
        let clients: Vec<_> = urls.into_iter().map(BeaconClient::new).collect();
        // The only answer is vetoed, but the silent source may hold the real block.
        let got = f.pick_head(&clients, &[0, 1], real.root).await;
        assert!(matches!(got, Err(AdvanceError::Unconfirmed)));
        // Positive control: every source answered and every answer was vetoed.
        let got = f.pick_head(&clients, &[0, 2], real.root).await;
        assert!(matches!(got, Err(AdvanceError::Failed)));
    }

    #[tokio::test]
    async fn a_reseed_between_the_quorum_check_and_the_finality_move_leaves_finality_unconfirmed() {
        let mut r = default_rig(1).await;
        let blocks: Vec<_> = (0..FINALITY_MIN_DEPTH + 6).map(|_| r.fc.next()).collect();
        for b in &blocks {
            r.beacons[0].serve_only(b);
        }
        r.beacons[0].push(blocks.last().unwrap());
        wait_until("the far head", || {
            r.chain.head().is_some_and(|h| h.hash == blocks.last().unwrap().hash)
        })
        .await;
        // A re-seed (to the very block about to be finalized) lands after the quorum check.
        let (chain, b2) = (r.chain.clone(), blocks[1].clone());
        let held = r.chain.by_hash(&b2.hash).unwrap();
        *r.follower.before_finality.lock() = Some(Box::new(move || chain.reseed(held.clone())));
        r.beacons[0].finalize(&b2);
        r.anchor.set_anchor_block(&b2);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!r.chain.finality_confirmed(), "finality confirmed for a re-seeded chain");
    }

    /// A peer that holds `blocks`.
    fn peer_with(blocks: &[&crate::payload::fake::FakeBlock]) -> Arc<Peer> {
        let p = Arc::new(Peer::default());
        for b in blocks {
            p.hold(b);
        }
        p
    }

    #[tokio::test]
    async fn a_lying_anchor_at_startup_is_not_seeded() {
        let beacon = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let (b0, b1, b2) = (fc.head().clone(), fc.next(), fc.next());
        let peer = peer_with(&[&b0]);
        let line = hold_line(&peer, &b0, FINALITY_MIN_DEPTH as usize + 2);
        assert_eq!((line[0].hash, line[1].hash), (b1.hash, b2.hash));
        beacon.push(&b2);
        beacon.serve_only(&b1);
        // The anchor serves a block the peer does not have on its canonical chain.
        anchor.set_anchor_block(&fc.alt(START));
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let f = Follower::new(cfg, chain.clone(), LiteMetrics::new()).with_confirm(peer);
        let task = tokio::spawn(Arc::new(f).run());
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(chain.head().is_none(), "a lying anchor was seeded");
        // The honest anchor is confirmed by the peer and seeded; the head then moves.
        anchor.set_anchor_block(&b0);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b2.hash)).await;
        assert!(chain.is_live());
        task.abort();
    }

    #[tokio::test]
    async fn a_stale_anchor_at_startup_is_not_seeded() {
        let beacon = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        beacon.push(fc.head());
        anchor.set_anchor_block(fc.head());
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            // The fake chain is from 2023.
            max_anchor_age: MAX_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(chain.head().is_none(), "a stale anchor was seeded");
        task.abort();
        // Positive control: the same anchor with a wide enough age bound is seeded.
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        wait_until("the seed", || chain.head().is_some()).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_gap_over_the_ancestor_limit_reseeds_from_the_anchor() {
        // The anchor recheck is slow, so only the walk's Gap branch can re-seed.
        let n = MAX_ANCESTORS + 100;
        let mut r =
            default_rig_with(1, Duration::from_secs(600), n + FINALITY_MIN_DEPTH as usize).await;
        let blocks: Vec<_> = (0..n).map(|_| r.fc.next()).collect();
        for b in &blocks {
            r.beacons[0].serve_only(b);
        }
        // Finality moved too, far above the held head and 70 below the new one.
        r.anchor.set_anchor_block(&blocks[n - 70]);
        r.beacons[0].push(blocks.last().unwrap());
        wait_until("the far head", || {
            r.chain.head().is_some_and(|h| h.hash == blocks.last().unwrap().hash)
        })
        .await;
        assert!(!r.chain.halted());
    }

    /// A follower seeded at `fc`'s block `seed` with one beacon serving all of `fc` and a peer
    /// confirming all of it, and the beacon's client.
    async fn walk_rig(fc: &FakeChain, seed: usize) -> (Fake, Arc<Follower>, Vec<BeaconClient>) {
        let beacon = Fake::start(false, false).await;
        let peer = Arc::new(Peer::default());
        for b in &fc.blocks {
            beacon.serve_only(b);
            peer.hold(b);
        }
        let f = bare_follower(vec![beacon.beacon_url()], &fc.blocks[seed], peer);
        let clients = vec![BeaconClient::new(beacon.beacon_url())];
        (beacon, f, clients)
    }

    #[tokio::test]
    async fn a_head_at_or_below_the_finalized_block_is_refused_without_a_walk() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        (0..10).for_each(|_| drop(fc.next()));
        // Seeded at START + 10: a real, peer-confirmed block below it can never connect.
        let (beacon, f, clients) = walk_rig(&fc, 10).await;
        let (old, parent) = (&fc.blocks[5], &fc.blocks[4]);
        let res = f.advance(&clients, &[0], old.root).await;
        assert!(matches!(res, Err(AdvanceError::Failed)));
        assert_eq!(beacon.calls(&format!("/eth/v2/beacon/blocks/{:#x}", parent.root)), 0);
    }

    #[tokio::test]
    async fn a_head_at_the_last_timestamp_does_not_overflow_the_backward_check() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        (0..2).for_each(|_| drop(fc.next()));
        let (beacon, f, clients) = walk_rig(&fc, 0).await;
        assert!(f.advance(&clients, &[0], fc.blocks[1].root).await.is_ok());
        let last = retimed(&retimed(&fc.blocks[2], i64::MAX, 0x77), i64::MAX, 0x77);
        assert_eq!(last.header.timestamp, u64::MAX);
        beacon.serve_only(&last);
        // The peer holds the real block at that number and vetoes this one.
        let res = f.advance(&clients, &[0], last.root).await;
        assert!(matches!(res, Err(AdvanceError::Failed)));
        assert_eq!(f.chain.head().unwrap().hash, fc.blocks[1].hash);
    }

    #[tokio::test]
    async fn confirmation_at_the_last_block_number_does_not_overflow() {
        let peer = Peer::default();
        let hash = B256::repeat_byte(1);
        peer.0.lock().insert(u64::MAX, PeerHeader { hash, parent_hash: B256::repeat_byte(2) });
        let got =
            confirm_canonical(&peer, u64::MAX, hash, ANCHOR_DESCENDANTS, FINALITY_MIN_DEPTH).await;
        assert_eq!(got, Confirmation::Unknown);
        let got = confirm_canonical(&peer, u64::MAX, hash, 0, FINALITY_MIN_DEPTH).await;
        assert_eq!(got, Confirmation::Unknown);
    }

    #[tokio::test]
    async fn an_agreeing_anchor_at_the_last_numbers_does_not_overflow_the_depth_check() {
        let mut b = FakeChain::new(Fork::Cancun, START).head().clone();
        b.header.number = u64::MAX - 1;
        let p = &mut b.json["data"]["message"]["body"]["execution_payload"];
        p["block_number"] = serde_json::json!(b.header.number.to_string());
        b.hash = b.header.hash_slow();
        p["block_hash"] = serde_json::json!(crate::payload::fake::hx(b.hash.as_slice()));
        let anchor = Fake::start(false, true).await;
        anchor.set_anchor_block(&b);
        let f = bare_follower(vec![], &b, Arc::new(Peer::default()));
        f.check_anchor(&BeaconClient::new(anchor.anchor_url()), &[], &Notify::new()).await;
        assert!(!f.chain.finality_confirmed(), "a block at the head is not deep");
    }

    #[tokio::test]
    async fn an_agreeing_anchor_is_finalized_only_once_the_head_is_64_blocks_above_it() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        (0..=FINALITY_MIN_DEPTH).for_each(|_| drop(fc.next()));
        let (beacon, f, clients) = walk_rig(&fc, 0).await;
        let anchor = Fake::start(false, true).await;
        let target = &fc.blocks[1];
        anchor.set_anchor_block(target);
        beacon.finalize(target);
        let anchor = BeaconClient::new(anchor.anchor_url());
        let last = fc.blocks.len() - 1;
        assert!(f.advance(&clients, &[0], fc.blocks[last - 1].root).await.is_ok());
        f.check_anchor(&anchor, &clients, &Notify::new()).await;
        assert_eq!(f.chain.finalized_number(), Some(START), "the head is 63 blocks above");
        assert!(!f.chain.finality_confirmed());
        assert!(f.advance(&clients, &[0], fc.blocks[last].root).await.is_ok());
        assert_eq!(f.chain.head().unwrap().header.number, START + 1 + FINALITY_MIN_DEPTH);
        f.check_anchor(&anchor, &clients, &Notify::new()).await;
        assert_eq!(f.chain.finalized_number(), Some(START + 1), "the head is 64 blocks above");
        assert!(f.chain.finality_confirmed());
    }

    #[tokio::test]
    async fn a_head_too_far_above_the_held_blocks_is_a_gap_without_a_walk() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let reach = MAX_ANCESTORS + 1;
        (0..=reach).for_each(|_| drop(fc.next()));
        let (beacon, f, clients) = walk_rig(&fc, 0).await;
        let (far, parent) = (&fc.blocks[reach + 1], &fc.blocks[reach]);
        let res = f.advance(&clients, &[0], far.root).await;
        assert!(matches!(res, Err(AdvanceError::Gap)));
        assert_eq!(beacon.calls(&format!("/eth/v2/beacon/blocks/{:#x}", parent.root)), 0);
        // One block nearer, the walk still connects.
        let near = &fc.blocks[reach];
        assert!(f.advance(&clients, &[0], near.root).await.is_ok());
        assert_eq!(f.chain.head().unwrap().hash, near.hash);
    }

    #[tokio::test]
    async fn an_anchor_above_the_head_reseeds_forward() {
        let mut r = default_rig(1).await;
        let blocks: Vec<_> = (0..60).map(|_| r.fc.next()).collect();
        // The blocks between the held head and the new finalized one are not served.
        for b in &blocks[9..] {
            r.beacons[0].serve_only(b);
        }
        r.anchor.set_anchor_block(&blocks[9]);
        r.beacons[0].push(blocks.last().unwrap());
        wait_until("the head", || {
            r.chain.head().is_some_and(|h| h.hash == blocks.last().unwrap().hash)
        })
        .await;
    }

    #[tokio::test]
    async fn a_confirmed_forward_reseed_clears_a_halt() {
        // A slow recheck: only the direct check below runs.
        let mut r = default_rig_with(1, Duration::from_secs(600), 100).await;
        // Halted on a mismatch at the held head, which stays frozen while finality moves on.
        r.chain.set_halted(Some(HaltReason::AnchorMismatch));
        *r.follower.halt.lock() = Some(Halt::Mismatch(START));
        let blocks: Vec<_> = (0..10).map(|_| r.fc.next()).collect();
        r.anchor.set_anchor_block(&blocks[9]);
        let clients: Vec<BeaconClient> =
            r.beacons.iter().map(|b| BeaconClient::new(b.beacon_url())).collect();
        let anchor = BeaconClient::new(r.anchor.anchor_url());
        r.follower.check_anchor(&anchor, &clients, &Notify::new()).await;
        assert_eq!(r.chain.head().unwrap().hash, blocks[9].hash, "not re-seeded forward");
        assert!(!r.chain.halted(), "still halted after a confirmed re-seed");
        assert_eq!(*r.follower.halt.lock(), None);
    }

    #[tokio::test]
    async fn with_no_confirmation_source_a_gap_halts_instead_of_trusting_the_anchor() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let blocks: Vec<_> = (0..MAX_ANCESTORS + 60).map(|_| r.fc.next()).collect();
        for b in &blocks[MAX_ANCESTORS + 9..] {
            r.beacon.serve_only(b);
        }
        r.anchor.set_anchor_block(&blocks[MAX_ANCESTORS + 9]);
        r.beacon.push(blocks.last().unwrap());
        wait_until("the halt", || r.chain.halted()).await;
        assert_eq!(r.chain.head().unwrap().header.number, START, "re-seeded on the anchor's word");
    }

    #[tokio::test]
    async fn with_no_confirmation_source_an_anchor_above_the_head_stops_serving_until_it_agrees() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        // The beacon stops serving blocks while finality moves past the head: nothing checks the
        // head against the anchor, so serving stops.
        let blocks: Vec<_> = (0..30).map(|_| r.fc.next()).collect();
        r.anchor.set_anchor_block(&blocks[9]);
        wait_until("the halt", || r.chain.halt_reason() == Some(HaltReason::BehindAnchor)).await;
        assert_eq!(r.chain.head().unwrap().header.number, START, "re-seeded on the anchor's word");
        // The beacon answers again: the walk catches up past the anchor, which then agrees.
        for b in &blocks {
            r.beacon.serve_only(b);
        }
        r.beacon.push(blocks.last().unwrap());
        r.wait_head(START + 30).await;
        wait_until("the halt to clear", || !r.chain.halted()).await;
    }

    #[tokio::test]
    async fn with_no_confirmation_source_a_mismatch_halt_clears_when_a_later_anchor_agrees() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let blocks: Vec<_> = (0..30).map(|_| r.fc.next()).collect();
        for b in &blocks {
            r.beacon.serve_only(b);
        }
        r.beacon.push(&blocks[1]);
        r.wait_head(START + 2).await;
        // The anchor flaps to a sibling of a held block, then moves on past the held head.
        r.anchor.set_anchor_block(&r.fc.alt(START + 1));
        wait_until("the halt", || r.chain.halted()).await;
        r.beacon.push(blocks.last().unwrap());
        tokio::time::sleep(Duration::from_millis(300)).await;
        r.anchor.set_anchor_block(&blocks[20]);
        r.wait_head(START + 30).await;
        wait_until("the halt to clear", || !r.chain.halted()).await;
    }

    #[tokio::test]
    async fn a_gap_halt_clears_once_the_walk_in_flight_reaches_the_anchor() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let blocks: Vec<_> = (0..10).map(|_| fc.next()).collect();
        let anchor = Fake::start(false, true).await;
        let mut cfg = follow_cfg(vec![]);
        cfg.anchor_url = anchor.anchor_url();
        let f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        f.chain.seed(f.held(&fc.blocks[0]));
        assert!(!f.reseed_forward_to(&[], f.held(&blocks[5])).await);
        assert!(f.chain.halted());
        // A walk that was in flight when the halt was set lands above the anchor.
        for b in &blocks {
            f.chain.insert(f.held(b)).unwrap();
        }
        f.chain.set_head(blocks[9].hash).unwrap();
        let client = BeaconClient::new(anchor.anchor_url());
        anchor.set_anchor_block(&blocks[4]);
        f.check_anchor(&client, &[], &Notify::new()).await;
        assert!(f.chain.halted(), "an anchor below the gap cleared the halt");
        anchor.set_anchor_block(&blocks[5]);
        f.check_anchor(&client, &[], &Notify::new()).await;
        assert!(!f.chain.halted(), "the gap closed and the halt stayed");
        assert_eq!(*f.halt.lock(), None);
    }

    #[tokio::test]
    async fn a_gap_halt_with_no_confirmation_source_is_not_cleared_by_an_agreeing_anchor() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let blocks: Vec<_> = (0..10).map(|_| fc.next()).collect();
        let anchor = Fake::start(false, true).await;
        let cfg = FollowConfig {
            urls: vec![],
            quorum: 1,
            poll: Duration::from_secs(10),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(600),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        f.chain.seed(f.held(&fc.blocks[0]));
        assert!(!f.reseed_forward_to(&[], f.held(&blocks[9])).await);
        assert!(f.chain.halted());
        // A lagging anchor reports the held seed block again.
        anchor.set_anchor_block(&fc.blocks[0]);
        let resume = Notify::new();
        f.check_anchor(&BeaconClient::new(anchor.anchor_url()), &[], &resume).await;
        assert!(f.chain.halted(), "an agreeing anchor cleared the gap halt");
    }

    #[tokio::test]
    async fn a_gap_halt_set_while_an_agreeing_anchor_clears_the_halt_stays() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let blocks: Vec<_> = (0..20).map(|_| fc.next()).collect();
        let anchor = Fake::start(false, true).await;
        let mut cfg = follow_cfg(vec![]);
        cfg.anchor_url = anchor.anchor_url();
        let f = Arc::new(Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new()));
        f.chain.seed(f.held(&fc.blocks[0]));
        for b in &blocks[..10] {
            f.chain.insert(f.held(b)).unwrap();
        }
        f.chain.set_head(blocks[9].hash).unwrap();
        anchor.set_anchor_block(&blocks[4]);
        // While the anchor task checks an agreeing anchor, the coordinator meets a gap to a
        // finalized block above the head and halts.
        let far = Mutex::new(Some(f.held(&blocks[19])));
        let gap = Arc::new(Mutex::new(None));
        let (weak, slot) = (Arc::downgrade(&f), gap.clone());
        *f.before_halt_clear.lock() = Some(Box::new(move || {
            let (Some(f), Some(far)) = (weak.upgrade(), far.lock().take()) else { return };
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                assert!(!rt.block_on(f.reseed_forward_to(&[], far)));
                tx.send(()).unwrap();
            });
            // Without a shared lock the halt lands here; with one it waits for the clear.
            let waited = rx.recv_timeout(Duration::from_millis(300));
            assert!(matches!(waited, Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout)));
            *slot.lock() = Some((thread, rx));
        }));
        f.check_anchor(&BeaconClient::new(anchor.anchor_url()), &[], &Notify::new()).await;
        let (thread, _rx) = gap.lock().take().unwrap();
        thread.join().unwrap();
        assert_eq!(*f.halt.lock(), Some(Halt::Behind(blocks[19].header.number)));
        assert!(f.chain.halted(), "the gap halt was cleared by an anchor below it");
    }

    #[tokio::test]
    async fn with_no_confirmation_source_any_anchor_above_the_head_halts() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let blocks: Vec<_> = (0..=MAX_ANCESTORS).map(|_| fc.next()).collect();
        let anchor = Fake::start(false, true).await;
        let mut cfg = follow_cfg(vec![]);
        cfg.anchor_url = anchor.anchor_url();
        let f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        f.chain.seed(f.held(&fc.blocks[0]));
        let client = BeaconClient::new(anchor.anchor_url());
        // One block above the head, 70, the walk's full reach and past it.
        for b in [&blocks[0], &blocks[69], &blocks[MAX_ANCESTORS - 1], &blocks[MAX_ANCESTORS]] {
            anchor.set_anchor_block(b);
            f.check_anchor(&client, &[], &Notify::new()).await;
            assert_eq!(*f.halt.lock(), Some(Halt::Behind(b.header.number)));
            assert_eq!(f.chain.halt_reason(), Some(HaltReason::BehindAnchor));
        }
    }

    #[tokio::test]
    async fn a_gap_halt_follows_the_head_and_keeps_its_highest_number() {
        let source = Fake::start(false, false).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..MAX_ANCESTORS + 20).map(|_| fc.next()).collect();
        source.serve_only(&blocks[0]);
        let (f, reports, task) = coordinated(vec![source.beacon_url()], Fork::Cancun, &seed, None);
        let (far, nearer) = (&blocks[MAX_ANCESTORS + 19], &blocks[MAX_ANCESTORS + 9]);
        assert!(!f.reseed_forward_to(&[], f.held(far)).await);
        // A later gap to a lower number does not lower the number that clears the halt.
        assert!(!f.reseed_forward_to(&[], f.held(nearer)).await);
        assert_eq!(*f.halt.lock(), Some(Halt::Behind(far.header.number)));
        assert_eq!(f.chain.halt_reason(), Some(HaltReason::BehindAnchor));
        // A head the walk can reach is followed under the halt, which stays: the head is below
        // the halt's number.
        reports.send(0, blocks[0].root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == blocks[0].hash)).await;
        assert_eq!(*f.halt.lock(), Some(Halt::Behind(far.header.number)));
        // A mismatch outranks the gap and keeps the higher number.
        f.set_halt(&mut f.halt.lock(), Some(Halt::Mismatch(START).over(Some(Halt::Behind(9)))));
        assert_eq!(*f.halt.lock(), Some(Halt::Mismatch(START.max(9))));
        assert_eq!(f.chain.halt_reason(), Some(HaltReason::AnchorMismatch));
        task.abort();
    }

    /// A quorum-1 follower with no confirmation source on `source`, checked against `anchor`
    /// at least `anchor_gap` apart, seeded at `seed`. Its coordinator and anchor task run; the
    /// test sends each report by hand.
    fn halted_rig(
        source: &Fake,
        anchor: &Fake,
        anchor_gap: Duration,
        seed: &FakeBlock,
    ) -> (Arc<Follower>, Arc<Reports>, tokio::task::JoinSet<()>) {
        let mut cfg = follow_cfg(vec![source.beacon_url()]);
        cfg.anchor_url = anchor.anchor_url();
        cfg.anchor_gap = anchor_gap;
        let f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        f.chain.seed(f.held(seed));
        let f = Arc::new(f);
        let reports = Arc::new(Reports::new(1));
        let clients = vec![BeaconClient::new(source.beacon_url())];
        let anchor = BeaconClient::new(anchor.anchor_url());
        let resume = Arc::new(Notify::new());
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(f.clone().anchor_task(
            anchor.clone(),
            clients.clone(),
            Arc::new(Notify::new()),
            resume.clone(),
        ));
        tasks.spawn({
            let (f, reports) = (f.clone(), reports.clone());
            async move { f.coordinate(anchor, clients, reports, resume).await }
        });
        (f, reports, tasks)
    }

    #[tokio::test]
    async fn head_moves_under_a_mismatch_halt_do_not_ask_the_anchor_past_its_floor() {
        let (source, anchor) = (Fake::start(false, false).await, Fake::start(false, true).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..6).map(|_| fc.next()).collect();
        for b in &blocks {
            source.serve_only(b);
        }
        // The anchor holds a sibling of a held block: a mismatch that never clears.
        anchor.set_anchor_block(&fc.alt(START + 1));
        let (f, reports, _tasks) = halted_rig(&source, &anchor, MIN_ANCHOR_GAP, &seed);
        f.set_halt(&mut f.halt.lock(), Some(Halt::Mismatch(START)));
        for b in &blocks {
            reports.send(0, b.root);
            wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b.hash)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Six head moves inside one 30 s floor: the anchor is not asked at all.
        assert_eq!(anchor.calls("/eth/v2/beacon/blocks/finalized"), 0);
        assert_eq!(f.chain.halt_reason(), Some(HaltReason::AnchorMismatch));
    }

    #[tokio::test]
    async fn a_head_that_reaches_a_halts_number_wakes_the_anchor_check() {
        let (source, anchor) = (Fake::start(false, false).await, Fake::start(false, true).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..20).map(|_| fc.next()).collect();
        for b in &blocks {
            source.serve_only(b);
        }
        // The recheck is 600 s: only a wake from the head checks the anchor in time.
        let (f, reports, _tasks) = halted_rig(&source, &anchor, Duration::from_millis(100), &seed);
        assert!(!f.reseed_forward_to(&[], f.held(&blocks[5])).await);
        anchor.set_anchor_block(&blocks[5]);
        reports.send(0, blocks[19].root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == blocks[19].hash)).await;
        wait_until("the halt to clear", || !f.chain.halted()).await;
    }

    #[tokio::test]
    async fn gaps_under_a_halt_with_no_confirmation_source_do_not_ask_the_anchor_each_slot() {
        let (source, anchor) = (Fake::start(false, false).await, Fake::start(false, true).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..MAX_ANCESTORS + 10).map(|_| fc.next()).collect();
        let far = &blocks[MAX_ANCESTORS + 2..];
        for b in far {
            source.serve_only(b);
        }
        anchor.set_anchor_block(&blocks[MAX_ANCESTORS + 2]);
        let (f, reports, _tasks) = halted_rig(&source, &anchor, MIN_ANCHOR_GAP, &seed);
        f.set_halt(&mut f.halt.lock(), Some(Halt::Behind(blocks[MAX_ANCESTORS + 2].header.number)));
        // One far head per slot, each out of the walk's reach.
        for b in far {
            reports.send(0, b.root);
            wait_until("the head block", || block_calls(&source, b.root) == 1).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(anchor.calls("/eth/v2/beacon/blocks/finalized"), 0);
        assert_eq!(f.chain.head().unwrap().hash, seed.hash);
        assert!(f.chain.halted());
    }

    /// One event-stream source, a 600 s recheck as in production and a 100 ms anchor gap.
    async fn one_stream_source(
    ) -> (Fake, Fake, Arc<HeaderChain>, FakeChain, tokio::task::JoinHandle<()>) {
        let beacon = Fake::start(true, false).await;
        let anchor = Fake::start(false, true).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        beacon.push(fc.head());
        beacon.finalize(fc.head());
        anchor.set_anchor_block(fc.head());
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(600),
            sse_retry: Duration::from_secs(60),
            anchor_gap: Duration::from_millis(100),
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        (beacon, anchor, chain, fc, task)
    }

    #[tokio::test]
    async fn finality_moves_on_a_later_check_when_the_head_was_a_block_short_at_the_event() {
        let (beacon, anchor, chain, mut fc, task) = one_stream_source().await;
        let blocks: Vec<_> = (0..=FINALITY_MIN_DEPTH).map(|_| fc.next()).collect();
        let (fin, short, deep) = (&blocks[0], &blocks[63], &blocks[64]);
        for b in &blocks {
            beacon.serve_only(b);
        }
        beacon.push(short);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == short.hash)).await;
        // The finality event lands while the head is one block short of the depth.
        anchor.set_anchor_block(fin);
        beacon.finalize(fin);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(chain.finalized_number(), Some(START), "finality moved to a shallow block");
        // The next head makes the block deep enough, and no other finality event comes.
        beacon.push(deep);
        wait_until("finality", || chain.finalized_number() == Some(fin.header.number)).await;
        assert!(chain.finality_confirmed());
        task.abort();
    }

    #[tokio::test]
    async fn finality_moves_on_a_later_check_when_the_anchor_was_a_checkpoint_behind() {
        let (beacon, anchor, chain, mut fc, task) = one_stream_source().await;
        let blocks: Vec<_> = (0..FINALITY_MIN_DEPTH + 6).map(|_| fc.next()).collect();
        for b in &blocks {
            beacon.serve_only(b);
        }
        let last = blocks.last().unwrap();
        beacon.push(last);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == last.hash)).await;
        // The beacons finalize a new block; the anchor still serves the seed.
        beacon.finalize(&blocks[1]);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(chain.finalized_number(), Some(START));
        // The anchor catches up with no further finality event.
        anchor.set_anchor_block(&blocks[1]);
        wait_until("finality", || chain.finalized_number() == Some(blocks[1].header.number)).await;
        task.abort();
    }

    #[tokio::test]
    async fn finality_moves_when_the_beacons_finalized_a_held_canonical_block_above_the_anchor() {
        let (beacon, anchor, chain, mut fc, task) = one_stream_source().await;
        let blocks: Vec<_> = (0..FINALITY_MIN_DEPTH + 6).map(|_| fc.next()).collect();
        for b in &blocks {
            beacon.serve_only(b);
        }
        let last = blocks.last().unwrap();
        beacon.push(last);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == last.hash)).await;
        // The beacons report a sibling above the anchor block: it is not held, so it says
        // nothing about the anchor block.
        anchor.set_anchor_block(&blocks[1]);
        beacon.finalize(&fc.alt(blocks[4].header.number));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(chain.finalized_number(), Some(START), "finality moved on a sibling");
        // The anchor stays one checkpoint behind the beacons, whose finalized block is held
        // and canonical above it.
        beacon.finalize(&blocks[4]);
        wait_until("finality", || chain.finalized_number() == Some(blocks[1].header.number)).await;
        assert!(chain.finality_confirmed());
        task.abort();
    }

    #[tokio::test]
    async fn a_flood_of_finality_events_does_not_flood_the_anchor() {
        let r = Rig::start(true, Fork::Cancun, 300).await;
        r.wait_head(START).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = r.anchor.calls("/eth/v2/beacon/blocks/finalized");
        let first = r.fc.blocks[0].clone();
        for _ in 0..200 {
            r.beacon.finalize(&first);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let n = r.anchor.calls("/eth/v2/beacon/blocks/finalized") - before;
        // About one second of events at one check per 300 ms.
        assert!(n <= 6, "{n} anchor checks");
    }

    #[tokio::test]
    async fn a_beacon_quorum_on_the_finalized_block_confirms_a_reseed() {
        let fakes = [
            Fake::start(false, false).await,
            Fake::start(false, false).await,
            Fake::start(false, false).await,
        ];
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let first = fc.head().clone();
        for f in &fakes {
            f.push(&first);
            f.finalize(&first);
        }
        anchor.set_anchor_block(&first);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: fakes.iter().map(Fake::beacon_url).collect(),
            quorum: 2,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_millis(50),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_millis(200),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        let b1 = fc.next();
        for f in &fakes {
            f.push(&b1);
        }
        wait_until("START + 1", || chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        // The beacons follow a false branch for a while...
        let fake2 = crate::payload::fake::make(Fork::Cancun, START + 2, b1.hash, b1.root, "lie");
        for f in &fakes {
            f.push(&fake2);
        }
        wait_until("the false head", || chain.head().is_some_and(|h| h.hash == fake2.hash)).await;
        // ...then finality lands on the real START + 2, which they all report as finalized.
        let b2 = fc.next();
        for f in &fakes {
            f.finalize(&b2);
        }
        anchor.set_anchor_block(&b2);
        wait_until("the re-seed", || chain.by_number(START + 2).is_some_and(|b| b.hash == b2.hash))
            .await;
        assert!(!chain.contains(&fake2.hash));
        task.abort();
    }

    #[tokio::test]
    async fn a_flood_of_head_events_is_handled_latest_first() {
        let mut r = Rig::start(true, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        // 2000 head events for roots nobody serves, in one burst, then a real head.
        let mut burst = String::new();
        for i in 0..2000u32 {
            let mut root = [0u8; 32];
            root[..4].copy_from_slice(&i.to_be_bytes());
            burst.push_str(&format!(
                "event: head\ndata: {}\n\n",
                serde_json::json!({"slot": "1", "block": crate::payload::fake::hx(&root)})
            ));
        }
        let _ = r.beacon.events.send(burst);
        let b = r.fc.next();
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
        let fetched: usize = r
            .beacon
            .state
            .lock()
            .calls
            .iter()
            .filter(|(p, _)| p.starts_with("/eth/v2/beacon/blocks/0x0000"))
            .map(|(_, n)| *n)
            .sum();
        assert!(fetched < 100, "{fetched} stale roots fetched");
    }

    /// `b` with its timestamp moved by `delta` seconds and its hash rebuilt.
    fn retimed(b: &FakeBlock, delta: i64, root: u8) -> FakeBlock {
        let mut b = b.clone();
        b.header.timestamp = b.header.timestamp.saturating_add_signed(delta);
        let p = &mut b.json["data"]["message"]["body"]["execution_payload"];
        p["timestamp"] = serde_json::json!(b.header.timestamp.to_string());
        b.hash = b.header.hash_slow();
        p["block_hash"] = serde_json::json!(crate::payload::fake::hx(b.hash.as_slice()));
        b.root = B256::repeat_byte(root);
        b
    }

    #[tokio::test]
    async fn a_canonical_ancestor_reported_as_head_does_not_move_or_refresh_the_head() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let blocks: Vec<_> = (0..3).map(|_| r.fc.next()).collect();
        for b in &blocks {
            r.beacon.serve_only(b);
        }
        r.beacon.push(&blocks[2]);
        r.wait_head(START + 3).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = r.chain.since_head_moved().unwrap();
        // A lagging beacon reports the canonical parent as its head.
        r.beacon.push(&blocks[1]);
        r.stays(START + 3, 400).await;
        let after = r.chain.since_head_moved().unwrap();
        assert!(after > before, "the moved-at timer was reset by a backward report");
    }

    #[tokio::test]
    async fn a_sibling_head_much_older_than_the_held_one_is_refused() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let blocks: Vec<_> = (0..3).map(|_| r.fc.next()).collect();
        for b in &blocks {
            r.beacon.serve_only(b);
        }
        r.beacon.push(&blocks[2]);
        r.wait_head(START + 3).await;
        // Same number as the head, another branch, but 30 s older: only the timestamp rule
        // refuses it.
        let sib = crate::payload::fake::make(
            Fork::Cancun,
            START + 3,
            blocks[1].hash,
            blocks[1].root,
            "sib",
        );
        let old = retimed(&sib, -30, 0x71);
        r.beacon.push(&old);
        r.stays(START + 3, 400).await;
        assert_eq!(r.chain.head().unwrap().hash, blocks[2].hash);
    }

    #[tokio::test]
    async fn the_head_never_moves_far_backward() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let blocks: Vec<_> = (0..5).map(|_| r.fc.next()).collect();
        for b in &blocks {
            r.beacon.serve_only(b);
        }
        r.beacon.push(&blocks[4]);
        r.wait_head(START + 5).await;
        // A sibling branch three blocks back, from START + 1: still above finalized.
        let back = crate::payload::fake::make(
            Fork::Cancun,
            START + 2,
            blocks[0].hash,
            blocks[0].root,
            "back",
        );
        r.beacon.push(&back);
        r.stays(START + 5, 400).await;
        assert!(!r.chain.is_canonical(&back.hash));
        assert_eq!(r.chain.by_number(START + 2).unwrap().hash, blocks[1].hash);
    }

    /// A follower seeded at `fc.blocks[0]` and advanced to the last block, its peer holding the
    /// whole line.
    async fn advanced_rig(fc: &FakeChain) -> (Fake, Arc<Follower>, Vec<BeaconClient>, Arc<Peer>) {
        let beacon = Fake::start(false, false).await;
        let peer = Arc::new(Peer::default());
        for b in &fc.blocks {
            beacon.serve_only(b);
            peer.hold(b);
        }
        let f = bare_follower(vec![beacon.beacon_url()], &fc.blocks[0], peer.clone());
        let clients = vec![BeaconClient::new(beacon.beacon_url())];
        assert!(f.advance(&clients, &[0], fc.head().root).await.is_ok());
        assert!(f.chain.is_live());
        (beacon, f, clients, peer)
    }

    /// A peer-confirmed sibling of `fc.blocks[at]`, `delta` seconds off its timestamp.
    fn confirmed_sibling(
        fc: &FakeChain,
        at: usize,
        delta: i64,
        root: u8,
        peer: &Peer,
    ) -> FakeBlock {
        let parent = &fc.blocks[at - 1];
        let b = crate::payload::fake::make(
            Fork::Cancun,
            parent.header.number + 1,
            parent.hash,
            parent.root,
            "sib",
        );
        let b = retimed(&b, delta, root);
        peer.hold(&b);
        b
    }

    #[tokio::test]
    async fn a_head_two_blocks_back_is_followed_and_three_back_is_refused() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        (0..5).for_each(|_| drop(fc.next()));
        let (beacon, f, clients, peer) = advanced_rig(&fc).await;
        let head = fc.head().hash;
        // Timed as the held head, so only the number rule applies.
        let three = confirmed_sibling(&fc, 2, 30, 0x71, &peer);
        beacon.serve_only(&three);
        let res = f.advance(&clients, &[0], three.root).await;
        assert!(matches!(res, Err(AdvanceError::Failed)));
        assert_eq!(f.chain.head().unwrap().hash, head);
        let two = confirmed_sibling(&fc, 3, 20, 0x72, &peer);
        beacon.serve_only(&two);
        assert!(f.advance(&clients, &[0], two.root).await.is_ok());
        assert_eq!(f.chain.head().unwrap().hash, two.hash);
    }

    #[tokio::test]
    async fn a_head_20_seconds_older_is_followed_and_21_seconds_older_is_refused() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        (0..5).for_each(|_| drop(fc.next()));
        let (beacon, f, clients, peer) = advanced_rig(&fc).await;
        let head = fc.head().hash;
        let late = confirmed_sibling(&fc, 5, -21, 0x71, &peer);
        beacon.serve_only(&late);
        let res = f.advance(&clients, &[0], late.root).await;
        assert!(matches!(res, Err(AdvanceError::Failed)));
        assert_eq!(f.chain.head().unwrap().hash, head);
        let ok = confirmed_sibling(&fc, 5, -20, 0x72, &peer);
        beacon.serve_only(&ok);
        assert!(f.advance(&clients, &[0], ok.root).await.is_ok());
        assert_eq!(f.chain.head().unwrap().hash, ok.hash);
    }

    #[test]
    fn an_anchor_is_recent_from_the_age_limit_to_60_seconds_ahead() {
        let fc = FakeChain::new(Fork::Cancun, START);
        let mut cfg = follow_cfg(vec![]);
        cfg.max_anchor_age = Duration::from_secs(3600);
        let f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        let mut block = f.held(fc.head());
        let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut recent = |ts: u64| {
            block.header.timestamp = ts;
            f.anchor_recent(&block)
        };
        // Retried when the clock ticks a second between the reads.
        let got = loop {
            let t = now();
            let got = [t + 60, t + 61, t - 3600, t - 3601, 0, u64::MAX].map(&mut recent);
            if now() == t {
                break got;
            }
        };
        assert_eq!(got, [true, false, true, false, false, false]);
    }

    #[tokio::test]
    async fn a_halt_clears_only_on_agreement_at_or_above_the_mismatched_number() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let (b1, b2) = (r.fc.next(), r.fc.next());
        r.beacon.serve_only(&b1);
        r.beacon.push(&b2);
        r.wait_head(START + 2).await;
        r.anchor.set_anchor_block(&r.fc.alt(START + 2));
        wait_until("the halt", || r.chain.halted()).await;
        // Agreement lower down does not clear it.
        r.anchor.set_anchor_block(&b1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(r.chain.halted(), "cleared by an agreement below the mismatch");
        // Agreement at the mismatched number does.
        r.anchor.set_anchor_block(&b2);
        wait_until("the resume", || !r.chain.halted()).await;
    }

    #[tokio::test]
    async fn a_lying_anchor_with_no_confirmation_source_keeps_the_node_halted() {
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let b = r.fc.next();
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
        let alt = r.fc.alt(START);
        r.anchor.set_anchor_block(&alt);
        wait_until("the halt", || r.chain.halted()).await;
        // Halted, and the anchor's word alone does not swap the chain. The head is still
        // followed, so a later anchor can agree at or above the mismatched number.
        let b2 = r.fc.next();
        r.beacon.push(&b2);
        r.wait_head(START + 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(r.chain.halted());
        assert!(!r.chain.contains(&alt.hash));
        // The anchor agrees again: serving resumes.
        r.anchor.set_anchor_block(&r.fc.blocks[0].clone());
        wait_until("the resume", || !r.chain.halted()).await;
        let _ = &r.metrics;
    }

    /// With no peer and a beacon quorum of one, the anchor alone chooses the first block. The
    /// seed itself then warns and names the block; a seed that a peer confirmed does not.
    #[tokio::test]
    async fn a_seed_from_the_anchor_alone_warns_and_names_the_block() {
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let text = logs.text();
        let hash = r.chain.head().unwrap().hash.to_string();
        assert!(text.contains("UNCONFIRMED SEED") && text.contains(&hash), "{text}");
        drop((r, logs));

        let fc = FakeChain::new(Fork::Cancun, START);
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let r = Rig::start_with(false, Fork::Cancun, 50, Some(honest_peer(&fc))).await;
        r.wait_head(START).await;
        let text = logs.text();
        assert!(!text.contains("UNCONFIRMED") && !text.contains("anchor alone"), "{text}");
    }

    #[tokio::test]
    async fn a_lying_anchor_contradicted_by_the_peer_keeps_the_held_chain_and_the_halt() {
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = honest_peer(&fc);
        let mut r = Rig::start_with(false, Fork::Cancun, 50, Some(peer.clone())).await;
        r.wait_head(START).await;
        let b = r.fc.next();
        peer.hold(&b);
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
        let alt = r.fc.alt(START);
        r.anchor.set_anchor_block(&alt);
        wait_until("the halt", || r.chain.halted()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(r.chain.halted());
        assert_eq!(r.chain.head().unwrap().hash, b.hash, "the held chain is kept");
        assert!(!r.chain.contains(&alt.hash));
    }

    #[tokio::test]
    async fn a_wrong_held_chain_reseeds_when_a_peer_confirms_the_anchor() {
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = honest_peer(&fc);
        let mut r = Rig::start_with(false, Fork::Cancun, 50, Some(peer.clone())).await;
        r.wait_head(START).await;
        let b1 = r.fc.next();
        peer.hold(&b1);
        r.beacon.push(&b1);
        r.wait_head(START + 1).await;
        // A false branch from b1 that the peer is fooled into holding too.
        let fake2 = crate::payload::fake::make(Fork::Cancun, START + 2, b1.hash, b1.root, "lie");
        let fake3 =
            crate::payload::fake::make(Fork::Cancun, START + 3, fake2.hash, fake2.root, "lie");
        peer.hold(&fake2);
        peer.hold(&fake3);
        r.beacon.serve_only(&fake2);
        r.beacon.push(&fake3);
        r.wait_head(START + 3).await;
        // The real chain finalizes START + 2, and the peer now holds the real block.
        let (b2, b3, b4) = (r.fc.next(), r.fc.next(), r.fc.next());
        for b in [&b2, &b3, &b4] {
            peer.hold(b);
        }
        r.anchor.set_anchor_block(&b2);
        wait_until("the re-seed", || {
            r.chain.by_number(START + 2).is_some_and(|b| b.hash == b2.hash)
        })
        .await;
        assert!(!r.chain.contains(&fake3.hash), "the lie is dropped");
        r.beacon.serve_only(&b3);
        r.beacon.push(&b4);
        r.wait_head(START + 4).await;
        assert!(!r.chain.halted());
    }

    #[tokio::test]
    async fn an_anchor_below_the_held_finalized_block_is_rejected() {
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = honest_peer(&fc);
        let mut r = Rig::start_with(false, Fork::Cancun, 50, Some(peer.clone())).await;
        r.wait_head(START).await;
        // Finality at START + 2 needs a head 64 blocks above it.
        let blocks: Vec<_> = (0..FINALITY_MIN_DEPTH + 2).map(|_| r.fc.next()).collect();
        let b2 = blocks[1].clone();
        for b in &blocks {
            r.beacon.serve_only(b);
        }
        r.beacon.push(blocks.last().unwrap());
        r.wait_head(START + FINALITY_MIN_DEPTH + 2).await;
        r.beacon.finalize(&b2);
        r.anchor.set_anchor_block(&b2);
        wait_until("finality at START + 2", || {
            r.chain.finalized().is_some_and(|f| f.hash == b2.hash)
        })
        .await;
        // The anchor rolls back to a sibling of b1, and the peer vouches for it fully: it holds
        // it canonical with two blocks on top. Only the below-finalized guard can refuse it.
        let alt = r.fc.alt(START + 1);
        peer.hold(&alt);
        let mut line = FakeChain { fork: Fork::Cancun, blocks: vec![alt.clone()] };
        for _ in 0..FINALITY_MIN_DEPTH + 2 {
            peer.hold(&line.next());
        }
        r.anchor.set_anchor_block(&alt);
        wait_until("the halt", || r.chain.halted()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!r.chain.contains(&alt.hash), "finality never rolls back");
        assert_eq!(r.chain.finalized().unwrap().hash, b2.hash);
        assert!(r.chain.halted());
    }

    #[tokio::test]
    async fn a_silent_event_stream_is_kept_for_a_slot_then_dropped_and_the_head_still_polled() {
        let r = Rig::start(true, Fork::Cancun, 100).await;
        r.wait_head(START).await;
        let heads = r.beacon.calls("/eth/v1/beacon/headers/head");
        // The fake stream sends nothing after connecting. An honest stream sends one head
        // event per 10 s slot, so a shorter silence, even at a short poll, keeps it.
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert_eq!(r.beacon.calls("/eth/v1/events"), 1, "a stream silent for under a slot dropped");
        assert!(r.beacon.calls("/eth/v1/beacon/headers/head") > heads, "no watchdog poll");
        // Past the idle bound it is dropped and reopened.
        tokio::time::sleep(MIN_SSE_IDLE).await;
        assert!(r.beacon.calls("/eth/v1/events") >= 2, "a silent stream was kept");
    }

    #[tokio::test]
    async fn a_head_the_event_stream_does_not_announce_is_found_by_the_watchdog_poll() {
        let mut r = Rig::start(true, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        wait_until("the stream", || r.beacon.calls("/eth/v1/events") == 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        // As a head event sent between the first `headers/head` and the subscribe.
        let b = r.fc.next();
        r.beacon.push_silently(&b);
        let t0 = Instant::now();
        r.wait_head(START + 1).await;
        let bound = MIN_SSE_WATCHDOG + Duration::from_secs(1);
        assert!(t0.elapsed() < bound, "the head waited {:?}", t0.elapsed());
        assert_eq!(r.beacon.calls("/eth/v1/events"), 1, "the stream was reopened");
    }

    #[tokio::test]
    async fn an_event_stream_that_drops_reconnects() {
        let mut r = Rig::start(true, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        // Let the stream live a moment, then cut it.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(r.beacon.calls("/eth/v1/events"), 1);
        let _ = r.beacon.kill_streams.send(());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(r.beacon.calls("/eth/v1/events"), 2, "one immediate reconnect");
        let b = r.fc.next();
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
    }

    #[tokio::test]
    async fn an_event_stream_that_drops_without_a_quick_reconnect_reads_the_head_once() {
        let r = Rig::start(true, Fork::Cancun, 5000).await;
        r.wait_head(START).await;
        wait_until("the stream", || r.beacon.calls("/eth/v1/events") == 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = r.beacon.calls("/eth/v1/beacon/headers/head");
        // A stream that lived under a second gets no quick reconnect: the follower polls.
        let _ = r.beacon.kill_streams.send(());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(r.beacon.calls("/eth/v1/beacon/headers/head") - before, 1);
    }

    #[tokio::test]
    async fn event_streams_that_keep_dropping_stop_reconnecting_at_once() {
        let mut r = Rig::start(true, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        // Each stream lives just over a second, then drops.
        for _ in 0..=MAX_QUICK_RECONNECTS {
            tokio::time::sleep(Duration::from_millis(1300)).await;
            let _ = r.beacon.kill_streams.send(());
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            r.beacon.calls("/eth/v1/events"),
            1 + MAX_QUICK_RECONNECTS as usize,
            "the quick reconnects stop at the limit"
        );
        let b = r.fc.next();
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
    }

    #[test]
    fn quick_reconnects_stop_at_the_limit_until_a_stream_outlives_the_retry_gate() {
        let (short, lived, retry) =
            (Duration::from_millis(900), Duration::from_millis(1100), Duration::from_secs(60));
        let mut quick = 0;
        assert!(!quick_reconnect(&mut quick, short, retry), "a short stream reconnected");
        for _ in 0..MAX_QUICK_RECONNECTS {
            assert!(quick_reconnect(&mut quick, lived, retry));
        }
        assert!(!quick_reconnect(&mut quick, lived, retry), "past the limit");
        assert!(quick_reconnect(&mut quick, retry, retry), "a healthy stream reset the count");
        assert_eq!(quick, 1);
    }

    #[tokio::test]
    async fn nothing_is_followed_until_the_anchor_is_held() {
        let beacon = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await; // serves no finalized block yet
        let mut fc = FakeChain::new(Fork::Cancun, START);
        beacon.push(&fc.head().clone());
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let f = Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new()));
        let task = tokio::spawn(f.run());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(chain.head().is_none());
        assert_eq!(beacon.calls("/eth/v1/beacon/headers/head"), 0, "the beacon is not asked yet");
        anchor.set_anchor_block(&fc.head().clone());
        for _ in 0..400 {
            if chain.head().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().header.number, START);
        let _ = fc.next();
        task.abort();
    }

    #[tokio::test]
    async fn quorum_needs_agreement() {
        let a = Fake::start(false, false).await;
        let b = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let first = fc.head().clone();
        for f in [&a, &b] {
            f.push(&first);
            f.finalize(&first);
        }
        anchor.set_anchor_block(&first);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![a.beacon_url(), b.beacon_url()],
            quorum: 2,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        // The seed can take longer than the window below on a loaded runner.
        wait_for("the seed", Duration::from_secs(30), || chain.head().is_some()).await;
        let n1 = fc.next();
        a.push(&n1);
        b.serve_only(&n1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(chain.head().unwrap().header.number, START, "one source is not a quorum");
        b.push(&n1);
        wait_for("the agreed head", Duration::from_secs(30), || {
            chain.head().is_some_and(|h| h.header.number == START + 1)
        })
        .await;
        task.abort();
    }

    /// `n` beacons and an anchor, all at `START`.
    async fn sources(
        n: usize,
        quorum: usize,
        fork: Fork,
    ) -> (Vec<Fake>, Arc<HeaderChain>, FakeChain, tokio::task::JoinHandle<()>, Arc<Follower>) {
        let mut fakes = Vec::new();
        for _ in 0..n {
            fakes.push(Fake::start(false, false).await);
        }
        let anchor = Fake::start(false, true).await;
        let fc = FakeChain::new(fork, START);
        let first = fc.head().clone();
        for f in &fakes {
            f.push(&first);
            f.finalize(&first);
        }
        anchor.set_anchor_block(&first);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: fakes.iter().map(Fake::beacon_url).collect(),
            quorum,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_millis(200),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(fork),
        };
        let follower = Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new()));
        let task = tokio::spawn(follower.clone().run());
        for _ in 0..300 {
            if chain.head().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (fakes, chain, fc, task, follower)
    }

    async fn two_sources() -> (Fake, Fake, Arc<HeaderChain>, FakeChain, tokio::task::JoinHandle<()>)
    {
        let (mut f, chain, fc, task, _) = sources(2, 2, Fork::Cancun).await;
        let b = f.pop().unwrap();
        let a = f.pop().unwrap();
        (a, b, chain, fc, task)
    }

    #[tokio::test]
    async fn a_first_responder_with_a_wrong_parent_root_does_not_steer_the_ancestor_walk() {
        // Shanghai: the parent root is not in the execution header, so block_hash does not
        // cover it.
        let (f, chain, mut fc, task, _) = sources(3, 2, Fork::Shanghai).await;
        let (b1, b2) = (fc.next(), fc.next());
        for s in &f {
            s.serve_only(&b1);
        }
        // The first responder serves the agreed block_hash with a wrong parent root.
        let mut lie = b2.clone();
        lie.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(&[0x5au8; 32]));
        f[0].push(&lie);
        f[1].push(&b2);
        f[2].push(&b2);
        for _ in 0..300 {
            if chain.head().unwrap().header.number == START + 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().hash, b2.hash);
        assert_eq!(chain.by_number(START + 1).unwrap().hash, b1.hash, "the correct parent");
        task.abort();
    }

    /// A static peer: its canonical chain by number.
    #[derive(Debug, Default)]
    struct Peer(Mutex<HashMap<u64, PeerHeader>>);

    impl Peer {
        fn hold(&self, b: &crate::payload::fake::FakeBlock) {
            self.0.lock().insert(
                b.header.number,
                PeerHeader { hash: b.hash, parent_hash: b.header.parent_hash },
            );
        }
    }

    #[async_trait::async_trait]
    impl HeadConfirm for Peer {
        async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>> {
            vec![self.0.lock().get(&number).copied()]
        }
    }

    /// A peer that runs `hook` once, the first time it is asked about `at`: a stand-in for work
    /// that lands on the chain while a confirmation is in flight.
    struct HookPeer {
        peer: Arc<Peer>,
        at: u64,
        hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl std::fmt::Debug for HookPeer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HookPeer").field("at", &self.at).finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl HeadConfirm for HookPeer {
        async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>> {
            if number == self.at &&
                let Some(hook) = self.hook.lock().take()
            {
                hook();
            }
            self.peer.headers_at(number).await
        }
    }

    /// A quorum-1 configuration on `urls` with an unreachable anchor.
    fn follow_cfg(urls: Vec<Url>) -> FollowConfig {
        FollowConfig {
            urls,
            quorum: 1,
            poll: Duration::from_secs(10),
            anchor_url: "http://127.0.0.1:1".parse().unwrap(),
            recheck: Duration::from_secs(600),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        }
    }

    /// A follower on `urls`, confirming with `peer`, and a chain seeded at `seed`.
    fn bare_follower(
        urls: Vec<Url>,
        seed: &FakeBlock,
        peer: Arc<dyn HeadConfirm>,
    ) -> Arc<Follower> {
        let f = Follower::new(follow_cfg(urls), Arc::new(HeaderChain::new()), LiteMetrics::new())
            .with_confirm(peer);
        f.chain.seed(f.held(seed));
        Arc::new(f)
    }

    impl Follower {
        fn held(&self, b: &FakeBlock) -> HeldBlock {
            parse_beacon_block(&b.json, b.root, &self.cfg.forks).unwrap().block
        }
    }

    /// A block parse decodes and hashes the whole answer. It runs off the async runtime, so
    /// other tasks keep running while it works, even on a runtime with one thread.
    #[tokio::test(flavor = "current_thread")]
    async fn a_large_block_parse_does_not_hold_the_runtime() {
        use alloy_consensus::{Signed, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        let mut b = crate::payload::fake::make(Fork::Cancun, START, B256::ZERO, B256::ZERO, "");
        let raw: Vec<Vec<u8>> = (0..20_000)
            .map(|nonce| {
                TxEnvelope::Legacy(Signed::new_unhashed(
                    TxLegacy { nonce, gas_limit: 21_000, ..Default::default() },
                    alloy_primitives::Signature::test_signature(),
                ))
                .encoded_2718()
            })
            .collect();
        b.header.transactions_root = alloy_trie::root::ordered_trie_root_encoded(&raw);
        b.hash = b.header.hash_slow();
        let p = &mut b.json["data"]["message"]["body"]["execution_payload"];
        p["transactions"] =
            serde_json::json!(raw.iter().map(|t| crate::payload::fake::hx(t)).collect::<Vec<_>>());
        p["block_hash"] = serde_json::json!(crate::payload::fake::hx(b.hash.as_slice()));
        let f = Follower::new(follow_cfg(vec![]), Arc::new(HeaderChain::new()), LiteMetrics::new());

        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ticker = tokio::spawn({
            let ticks = ticks.clone();
            async move {
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });
        // Lets the ticker start.
        tokio::task::yield_now().await;
        let before = ticks.load(Ordering::Relaxed);
        let parsed = f.parse(b.json.clone(), b.root).await.expect("the block parses");
        let during = ticks.load(Ordering::Relaxed) - before;
        ticker.abort();
        assert_eq!((parsed.block.hash, parsed.block.body.transactions.len()), (b.hash, 20_000));
        assert!(during > 0, "the ticker did not run while the block was parsed");
    }

    #[tokio::test]
    async fn a_forward_reseed_does_not_undo_what_landed_while_it_was_confirmed() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        hold_line(&peer, fc.head(), 100);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..20).map(|_| fc.next()).collect();
        // [a] The head connects through ancestors past the anchor block. [b] A newer re-seed
        // (the walk's Gap path) lands.
        for newer_reseed in [false, true] {
            let slot = Arc::new(Mutex::new(None::<Arc<Follower>>));
            let hook_slot = slot.clone();
            let line = blocks.clone();
            let hook = Box::new(move || {
                let f = hook_slot.lock().clone().unwrap();
                if newer_reseed {
                    f.chain.reseed(f.held(&line[15]));
                } else {
                    for b in &line[..16] {
                        f.chain.insert(f.held(b)).unwrap();
                    }
                    f.chain.set_head(line[15].hash).unwrap();
                }
            });
            let at = blocks[9].header.number;
            let hooked =
                Arc::new(HookPeer { peer: peer.clone(), at, hook: Mutex::new(Some(hook)) });
            let f = bare_follower(Vec::new(), &seed, hooked);
            *slot.lock() = Some(f.clone());
            assert!(!f.reseed_forward_to(&[], f.held(&blocks[9])).await, "case {newer_reseed}");
            assert_eq!(f.chain.head().unwrap().hash, blocks[15].hash, "case {newer_reseed}");
            if newer_reseed {
                assert_eq!(f.chain.finalized_number(), Some(blocks[15].header.number));
            }
        }
    }

    /// Runs the coordinator alone on `urls` (quorum 1, failed roots left alone for 60 s) from a
    /// chain seeded at `seed`: the test sends each report by hand.
    fn coordinated(
        urls: Vec<Url>,
        fork: Fork,
        seed: &FakeBlock,
        confirm: Option<Arc<dyn HeadConfirm>>,
    ) -> (Arc<Follower>, Arc<Reports>, tokio::task::JoinHandle<()>) {
        coordinated_with(urls, 1, fork, seed, confirm)
    }

    /// [`coordinated`] with `quorum`.
    fn coordinated_with(
        urls: Vec<Url>,
        quorum: usize,
        fork: Fork,
        seed: &FakeBlock,
        confirm: Option<Arc<dyn HeadConfirm>>,
    ) -> (Arc<Follower>, Arc<Reports>, tokio::task::JoinHandle<()>) {
        coordinated_budget(urls, quorum, fork, seed, confirm, ADVANCE_BUDGET)
    }

    /// [`coordinated_with`] with an advance budget of `budget`.
    fn coordinated_budget(
        urls: Vec<Url>,
        quorum: usize,
        fork: Fork,
        seed: &FakeBlock,
        confirm: Option<Arc<dyn HeadConfirm>>,
        budget: Duration,
    ) -> (Arc<Follower>, Arc<Reports>, tokio::task::JoinHandle<()>) {
        let n = urls.len();
        let mut cfg = follow_cfg(urls);
        cfg.quorum = quorum;
        cfg.forks = crate::payload::fake::forks(fork);
        let mut f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        f.advance_budget = budget;
        if let Some(c) = confirm {
            f = f.with_confirm(c);
        }
        f.chain.seed(f.held(seed));
        let f = Arc::new(f);
        let clients: Vec<BeaconClient> =
            f.cfg.urls.iter().cloned().map(BeaconClient::new).collect();
        let reports = Arc::new(Reports::new(n));
        let task = tokio::spawn({
            let (f, reports) = (f.clone(), reports.clone());
            let anchor = BeaconClient::new(f.cfg.anchor_url.clone());
            async move { f.coordinate(anchor, clients, reports, Arc::new(Notify::new())).await }
        });
        (f, reports, task)
    }

    /// How often `fake` was asked for the block at `root`.
    fn block_calls(fake: &Fake, root: B256) -> usize {
        fake.calls(&format!("/eth/v2/beacon/blocks/{root:#x}"))
    }

    /// The hostile source's answers for a Shanghai line `b2`, `b3`: `b3` with a made-up parent
    /// root, under which it serves the real `b2` naming another made-up root it does not serve.
    fn made_up_parent_roots(hostile: &Fake, b2: &FakeBlock, b3: &FakeBlock) -> (B256, B256) {
        let (f2, f1) = (B256::repeat_byte(0x5a), B256::repeat_byte(0x5b));
        let mut lie3 = b3.clone();
        lie3.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(f2.as_slice()));
        let mut lie2 = b2.clone();
        lie2.root = f2;
        lie2.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(f1.as_slice()));
        hostile.serve_only(&lie2);
        hostile.serve_only(&lie3);
        (f2, f1)
    }

    #[tokio::test]
    async fn a_source_that_wins_the_report_race_with_made_up_parent_roots_does_not_stall_the_walk()
    {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        made_up_parent_roots(&hostile, &b2, &b3);
        for b in [&b1, &b2, &b3] {
            honest.serve_only(b);
        }
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        // One report per source, as an event stream sends it, the hostile one first.
        reports.send(0, b3.root);
        tokio::time::sleep(Duration::from_millis(20)).await;
        reports.send(1, b3.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        assert_eq!(f.chain.by_number(START + 1).unwrap().hash, b1.hash);
        task.abort();
    }

    #[tokio::test]
    async fn a_head_whose_walk_dead_ended_below_it_is_tried_again_when_another_source_reports_it() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let (f2, _) = made_up_parent_roots(&hostile, &b2, &b3);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        // The honest source does not hold the line yet when the hostile one reports it.
        reports.send(0, b3.root);
        wait_until("the dead end", || block_calls(&honest, f2) >= 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        for b in [&b1, &b2, &b3] {
            honest.serve_only(b);
        }
        reports.send(1, b3.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_dead_end_root_is_not_walked_again_on_reports_of_another_root() {
        let fakes = [
            Fake::start(false, false).await,
            Fake::start(false, false).await,
            Fake::start(false, false).await,
        ];
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (_b1, b2) = (fc.next(), fc.next());
        // Two sources serve the head but not its parent: the walk dead-ends.
        for fake in &fakes[..2] {
            fake.serve_only(&b2);
        }
        let (_f, reports, task) = coordinated_with(
            fakes.iter().map(Fake::beacon_url).collect(),
            2,
            Fork::Shanghai,
            &seed,
            None,
        );
        reports.send(0, b2.root);
        reports.send(1, b2.root);
        wait_until("the dead end", || block_calls(&fakes[0], b2.parent_root) >= 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let walked = block_calls(&fakes[0], b2.root);
        // The third source reports roots of its own, which have no quorum.
        for k in 0..5u8 {
            reports.send(2, B256::repeat_byte(0x40 + k));
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(block_calls(&fakes[0], b2.root), walked, "the dead end was walked again");
        task.abort();
    }

    #[tokio::test]
    async fn a_walk_that_dead_ends_is_walked_again_with_the_sources_that_led_it_there_last() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        made_up_parent_roots(&hostile, &b2, &b3);
        for b in [&b1, &b2, &b3] {
            honest.serve_only(b);
        }
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        // The honest source was slow before, so one dead end does not move it ahead.
        f.slow.lock()[1] = 5;
        reports.send(0, b3.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn an_alias_head_that_names_the_real_head_root_as_its_parent_does_not_block_that_root() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2) = (fc.next(), fc.next());
        honest.serve_only(&b1);
        honest.serve_only(&b2);
        // The hostile source serves the real head under a made-up root, and names the real
        // head root as its parent: the walk dead-ends at the real head root.
        let alias = B256::repeat_byte(0x6c);
        let mut lie = b2.clone();
        lie.root = alias;
        lie.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(b2.root.as_slice()));
        hostile.serve_only(&lie);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        reports.send(0, alias);
        wait_until("the dead end", || block_calls(&hostile, alias) >= 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(f.chain.head().unwrap().hash, seed.hash);
        // The honest source reports the real head root: it is not ignored.
        reports.send(1, b2.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b2.hash)).await;
        task.abort();
    }

    /// How long a hostile source holds a block answer in the tests of the advance budget.
    const HOLD: Duration = Duration::from_secs(5);
    /// The advance budget in those tests.
    const TEST_BUDGET: Duration = Duration::from_millis(300);

    #[tokio::test]
    async fn a_source_that_holds_its_answer_for_a_root_of_its_own_does_not_hold_back_the_head() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        honest.serve_only(&b1);
        // The hostile source serves the real block under a root of its own, and holds it.
        let alias = B256::repeat_byte(0x6d);
        let mut lie = b1.clone();
        lie.root = alias;
        hostile.serve_only(&lie);
        hostile.state.lock().block_delay = HOLD;
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        peer.hold(&b1);
        let (f, reports, task) = coordinated_budget(
            vec![hostile.beacon_url(), honest.beacon_url()],
            1,
            Fork::Shanghai,
            &seed,
            Some(peer),
            TEST_BUDGET,
        );
        reports.send(0, alias);
        wait_until("the hold", || block_calls(&hostile, alias) >= 1).await;
        reports.send(1, b1.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_source_that_holds_an_ancestor_under_a_root_of_its_own_does_not_hold_back_the_head() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        for b in [&b1, &b2, &b3] {
            honest.serve_only(b);
        }
        // The hostile source serves the real head with a made-up parent root, and holds the
        // real parent it serves under that root.
        let (f2, _) = made_up_parent_roots(&hostile, &b2, &b3);
        hostile.state.lock().root_delays.insert(f2, HOLD);
        let (f, reports, task) = coordinated_budget(
            vec![hostile.beacon_url(), honest.beacon_url()],
            1,
            Fork::Shanghai,
            &seed,
            None,
            TEST_BUDGET,
        );
        reports.send(0, b3.root);
        wait_until("the hold", || block_calls(&hostile, f2) >= 1).await;
        reports.send(1, b3.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        assert_eq!(f.chain.by_number(START + 1).unwrap().hash, b1.hash);
        task.abort();
    }

    #[tokio::test]
    async fn a_source_that_held_a_try_is_backed_off_even_when_the_head_moved() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2) = (fc.next(), fc.next());
        honest.serve_only(&b1);
        honest.serve_only(&b2);
        // The hostile source reports the root and holds its answer that it has no block, inside
        // the budget: the honest source's block moves the head.
        let budget = Duration::from_millis(1500);
        hostile.state.lock().root_delays.insert(b1.root, budget * 2 / 3);
        let (f, reports, task) = coordinated_budget(
            vec![hostile.beacon_url(), honest.beacon_url()],
            1,
            Fork::Shanghai,
            &seed,
            None,
            budget,
        );
        reports.send(0, b1.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        reports.send(0, b2.root);
        tokio::time::sleep(REPORT_BACKOFF / 2).await;
        assert_eq!(block_calls(&hostile, b2.root), 0, "the holder's next root was not backed off");
        wait_until("the next head", || f.chain.head().is_some_and(|h| h.hash == b2.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_walk_longer_than_the_advance_budget_resumes_from_the_ancestors_it_fetched() {
        let sources = [Fake::start(false, false).await, Fake::start(false, false).await];
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let line: Vec<_> = (0..12).map(|_| fc.next()).collect();
        for s in &sources {
            for b in &line {
                s.serve_only(b);
            }
            // Each answer is quick, but the walk takes about three budgets.
            s.state.lock().block_delay = TEST_BUDGET / 6;
        }
        let head = line.last().unwrap();
        let (f, reports, task) = coordinated_budget(
            sources.iter().map(Fake::beacon_url).collect(),
            1,
            Fork::Shanghai,
            &seed,
            None,
            TEST_BUDGET,
        );
        reports.send(0, head.root);
        reports.send(1, head.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == head.hash)).await;
        // Each ancestor is fetched once, or twice when the budget cut its first request off.
        for b in &line[..line.len() - 1] {
            let calls: usize = sources.iter().map(|s| block_calls(s, b.root)).sum();
            assert!(calls <= 2, "ancestor {} fetched {calls} times", b.header.number);
        }
        task.abort();
    }

    /// Polls `cond` every 50 ms for up to `limit`.
    async fn wait_for(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + limit;
        while !cond() {
            assert!(Instant::now() < deadline, "timed out after {limit:?} waiting for {what}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[test]
    fn only_an_unused_answer_slower_than_the_used_ones_of_its_source_holds_a_try() {
        let f = Follower::new(
            follow_cfg(vec!["http://127.0.0.1:1".parse().unwrap(); 3]),
            Arc::new(HeaderChain::new()),
            LiteMetrics::new(),
        );
        let (head, ancestor) = (B256::repeat_byte(1), B256::repeat_byte(2));
        let answer = |idx, root, secs: f64| SlowAnswer {
            idx,
            root,
            took: Duration::from_secs_f64(secs),
            used: false,
        };
        // Source 0's head and source 1's ancestor are used; source 1's next request is cut off
        // as slow as they were, and source 2 holds its answer far longer.
        f.held.lock().extend([
            answer(0, head, 2.5),
            answer(1, ancestor, 2.5),
            answer(1, B256::repeat_byte(3), 2.4),
            answer(2, ancestor, 6.0),
        ]);
        f.used(&[0], head);
        f.used(&[1], ancestor);
        let held = f.holds(3);
        assert_eq!(held[..2], [Duration::ZERO; 2]);
        assert_eq!(held[2], Duration::from_secs(6));
    }

    #[tokio::test]
    async fn honest_sources_that_all_answer_slowly_still_move_the_head() {
        let sources = [Fake::start(false, false).await, Fake::start(false, false).await];
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let line: Vec<_> = (0..5).map(|_| fc.next()).collect();
        for s in &sources {
            for b in &line {
                s.serve_only(b);
            }
            // Every answer is correct and slow: the head and its ancestors take more than one
            // budget.
            s.state.lock().block_delay = SLOW_ANSWER + Duration::from_millis(500);
        }
        let head = line.last().unwrap();
        let (f, reports, task) = coordinated(
            sources.iter().map(Fake::beacon_url).collect(),
            Fork::Shanghai,
            &seed,
            None,
        );
        reports.send(0, head.root);
        reports.send(1, head.root);
        // About two budgets: the second try resumes from the ancestors the first one fetched.
        wait_for("the head", ADVANCE_BUDGET * 4, || {
            f.chain.head().is_some_and(|h| h.hash == head.hash)
        })
        .await;
        task.abort();
    }

    #[tokio::test]
    async fn a_slow_answer_of_another_source_does_not_excuse_a_hold() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2) = (fc.next(), fc.next());
        honest.serve_only(&b1);
        honest.serve_only(&b2);
        // The hostile source reports the root and holds its answer that it has no block. The
        // honest block that moves the head is slow too, almost as slow as the hold.
        let hold = SLOW_ANSWER + Duration::from_millis(500);
        hostile.state.lock().root_delays.insert(b1.root, hold);
        honest.state.lock().root_delays.insert(b1.root, SLOW_ANSWER + Duration::from_millis(300));
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        reports.send(0, b1.root);
        wait_for("the head", ADVANCE_BUDGET, || f.chain.head().is_some_and(|h| h.hash == b1.hash))
            .await;
        // The holder waits as long as it held the try before its next root is tried.
        reports.send(0, b2.root);
        tokio::time::sleep(hold / 2).await;
        assert_eq!(block_calls(&hostile, b2.root), 0, "the holder's next root was not backed off");
        task.abort();
    }

    #[tokio::test]
    async fn a_slow_used_answer_excuses_at_most_one_slow_answer_of_its_sources_hold() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        for b in [&b1, &b2, &b3] {
            honest.serve_only(b);
        }
        // The hostile source serves the real head slowly, and then holds its answer that it
        // has no parent for longer, but for less than one slow answer past the head.
        hostile.serve_only(&b2);
        let hold = SLOW_ANSWER * 2 + Duration::from_millis(500);
        {
            let mut s = hostile.state.lock();
            s.root_delays.insert(b2.root, SLOW_ANSWER + Duration::from_secs(1));
            s.root_delays.insert(b1.root, hold);
        }
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        // The honest source is asked last, so the hostile one serves the head and is asked
        // first for its parent.
        f.slow.lock()[1] = 100;
        reports.send(0, b2.root);
        // The head and the hold together fit in the budget: the honest parent moves the head.
        wait_for("the head", ADVANCE_BUDGET * 2, || {
            f.chain.head().is_some_and(|h| h.hash == b2.hash)
        })
        .await;
        reports.send(0, b3.root);
        tokio::time::sleep(hold / 4).await;
        assert_eq!(block_calls(&hostile, b3.root), 0, "the holder's next root was not backed off");
        task.abort();
    }

    #[tokio::test]
    async fn a_holder_that_walks_real_ancestors_under_a_root_of_its_own_fails_that_root() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let line: Vec<_> = (0..4).map(|_| fc.next()).collect();
        for b in &line {
            honest.serve_only(b);
        }
        // The hostile source alone reports a made-up root for the real head. It serves the
        // real ancestors down to the lowest one quickly, and holds that one past the budget.
        let alias = B256::repeat_byte(0x6e);
        let mut lie = line[3].clone();
        lie.root = alias;
        hostile.serve_only(&lie);
        hostile.serve_only(&line[2]);
        hostile.serve_only(&line[1]);
        hostile.state.lock().root_delays.insert(line[0].root, HOLD);
        let budget = Duration::from_millis(1500);
        let (f, reports, task) = coordinated_budget(
            vec![hostile.beacon_url(), honest.beacon_url()],
            1,
            Fork::Shanghai,
            &seed,
            None,
            budget,
        );
        reports.send(0, alias);
        wait_for("the hold", budget * 2, || block_calls(&hostile, line[0].root) >= 1).await;
        // The walk got two ancestors down before the hold.
        assert_eq!(block_calls(&hostile, line[1].root), 1);
        // A try again would come after the budget and one backoff as long as the hold.
        tokio::time::sleep(budget + MAX_REPORT_BACKOFF / 2).await;
        assert_eq!(block_calls(&hostile, alias), 1, "the holder's root was tried again");
        assert_eq!(f.chain.head().unwrap().hash, seed.hash);
        // The honest source's report of the real head root is still heard.
        reports.send(1, line[3].root);
        wait_for("the head", ADVANCE_BUDGET, || {
            f.chain.head().is_some_and(|h| h.hash == line[3].hash)
        })
        .await;
        task.abort();
    }

    #[tokio::test]
    async fn a_holder_whose_tries_move_the_head_does_not_build_up_a_backoff() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let line: Vec<_> = (0..4).map(|_| fc.next()).collect();
        let hold = Duration::from_secs(1);
        for b in &line {
            honest.serve_only(b);
            // The hostile source reports each root and holds its answer that it has no block.
            hostile.state.lock().root_delays.insert(b.root, hold);
        }
        let (f, reports, task) = coordinated_budget(
            vec![hostile.beacon_url(), honest.beacon_url()],
            1,
            Fork::Shanghai,
            &seed,
            None,
            hold * 3 / 2,
        );
        // The honest source is asked second, so each try waits on the hostile one first.
        f.slow.lock()[1] = 100;
        for b in &line[..3] {
            reports.send(0, b.root);
            wait_for("the head", hold * 10, || f.chain.head().is_some_and(|h| h.hash == b.hash))
                .await;
        }
        let sent = Instant::now();
        reports.send(0, line[3].root);
        wait_for("the last head", hold * 10, || {
            f.chain.head().is_some_and(|h| h.hash == line[3].hash)
        })
        .await;
        // One hold and one backoff as long as the hold, not a wait that grew with each try.
        assert!(sent.elapsed() < hold * 7 / 2, "the last head took {:?}", sent.elapsed());
        task.abort();
    }

    #[tokio::test]
    async fn a_quorum_head_the_peer_vetoes_is_charged_to_the_sources_that_served_it() {
        let fakes = [Fake::start(false, false).await, Fake::start(false, false).await];
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        let fake_head = fc.alt(START + 1);
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        peer.hold(&b1);
        for fake in &fakes {
            fake.serve_only(&fake_head);
        }
        let (f, reports, task) = coordinated_with(
            fakes.iter().map(Fake::beacon_url).collect(),
            2,
            Fork::Cancun,
            &seed,
            Some(peer),
        );
        reports.send(0, fake_head.root);
        reports.send(1, fake_head.root);
        wait_until("the veto", || (0..2).all(|i| f.source_failures(i) == 1)).await;
        assert_eq!(f.chain.head().unwrap().hash, seed.hash);
        task.abort();
    }

    #[tokio::test]
    async fn a_report_of_the_followed_head_left_open_does_not_back_off_its_reporter_for_long() {
        let (other, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let (b0, b1) = (fc.head().clone(), fc.next());
        let b2 = fc.next();
        honest.serve_only(&b1);
        honest.serve_only(&b2);
        let peer = Arc::new(Peer::default());
        for b in [&b0, &b1, &b2] {
            peer.hold(b);
        }
        // The head is already b1, and the other source does not hold its root: the root stays
        // open and is tried again.
        let (f, reports, task) = coordinated(
            vec![other.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            &b1,
            Some(peer),
        );
        reports.send(1, b1.root);
        wait_until("the retry", || block_calls(&other, b1.root) >= 2).await;
        tokio::time::sleep(REPORT_BACKOFF / 2).await;
        // The tries in a row did not grow the reporter's wait past one backoff.
        reports.send(1, b2.root);
        tokio::time::sleep(REPORT_BACKOFF * 3 / 4).await;
        assert_eq!(f.chain.head().unwrap().hash, b2.hash);
        task.abort();
    }

    #[tokio::test]
    async fn a_source_with_more_failures_is_asked_after_the_others_even_when_it_reported_first() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let (f2, _) = made_up_parent_roots(&hostile, &b2, &b3);
        for b in [&b1, &b2, &b3] {
            honest.serve_only(b);
        }
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Shanghai,
            &seed,
            None,
        );
        f.slow.lock()[0] = 1;
        reports.send(0, b3.root);
        tokio::time::sleep(Duration::from_millis(20)).await;
        reports.send(1, b3.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        assert_eq!(block_calls(&hostile, b3.root), 0, "the first reporter served the head");
        assert_eq!(block_calls(&hostile, f2), 0);
        task.abort();
    }

    #[tokio::test]
    async fn a_report_skipped_inside_the_backoff_window_is_tried_when_the_window_ends() {
        let source = Fake::start(false, false).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        source.serve_only(&b1);
        let (f, reports, task) = coordinated(vec![source.beacon_url()], Fork::Cancun, &seed, None);
        // A root nobody serves backs the source off for a second.
        reports.send(0, B256::repeat_byte(0x61));
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Its next head comes inside the window, once, as an event stream sends it.
        reports.send(0, b1.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn the_backoff_window_starts_when_the_report_is_taken_up() {
        let source = Fake::start(false, false).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let (b1, b2) = (fc.next(), fc.next());
        source.serve_only(&b1);
        source.serve_only(&b2);
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        let (f, reports, task) =
            coordinated(vec![source.beacon_url()], Fork::Cancun, &seed, Some(peer.clone()));
        let t0 = Instant::now();
        // The peer is 1.2 s behind the beacon: its three tries over a second miss b1.
        reports.send(0, b1.root);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        peer.hold(&b1);
        peer.hold(&b2);
        tokio::time::sleep(Duration::from_millis(200)).await;
        reports.send(0, b2.root);
        while !f.chain.head().is_some_and(|h| h.hash == b2.hash) {
            assert!(t0.elapsed() < Duration::from_millis(1800), "the next head waited");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_source_that_holds_its_answer_past_the_backoff_window_is_still_backed_off() {
        let source = Fake::start(false, false).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        source.state.lock().block_delay = SLOW_ANSWER + Duration::from_millis(200);
        let (_f, reports, task) =
            coordinated(vec![source.beacon_url()], Fork::Cancun, fc.head(), None);
        // A root nobody serves, answered after the one-second window from its take-up is over.
        reports.send(0, B256::repeat_byte(0x61));
        wait_until("the first root", || block_calls(&source, B256::repeat_byte(0x61)) == 1).await;
        tokio::time::sleep(SLOW_ANSWER + Duration::from_millis(300)).await;
        reports.send(0, B256::repeat_byte(0x62));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(block_calls(&source, B256::repeat_byte(0x62)), 0);
        task.abort();
    }

    #[tokio::test]
    async fn a_root_already_followed_does_not_reset_the_backoff() {
        let source = Fake::start(false, false).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let (b1, b2) = (fc.next(), fc.next());
        source.serve_only(&b1);
        source.serve_only(&b2);
        let (f, reports, task) = coordinated(vec![source.beacon_url()], Fork::Cancun, &seed, None);
        reports.send(0, b2.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b2.hash)).await;
        let made_up = [B256::repeat_byte(0x61), B256::repeat_byte(0x62), B256::repeat_byte(0x63)];
        // A made-up root: one strike, a one-second window.
        reports.send(0, made_up[0]);
        wait_until("the first made-up root", || block_calls(&source, made_up[0]) == 1).await;
        tokio::time::sleep(REPORT_BACKOFF + Duration::from_millis(100)).await;
        // A canonical root below the head moves nothing and keeps the strike.
        let walked = block_calls(&source, b1.root);
        reports.send(0, b1.root);
        wait_until("the canonical root", || block_calls(&source, b1.root) == walked + 1).await;
        // A second strike in a row: a two-second window from here.
        reports.send(0, made_up[1]);
        wait_until("the second made-up root", || block_calls(&source, made_up[1]) == 1).await;
        tokio::time::sleep(REPORT_BACKOFF + Duration::from_millis(200)).await;
        reports.send(0, made_up[2]);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(block_calls(&source, made_up[2]), 0, "the strikes were reset");
        // The root is tried when the window ends.
        wait_until("the third made-up root", || block_calls(&source, made_up[2]) == 1).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_head_root_the_peer_vetoes_is_not_asked_about_again() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        hold_line(&peer, fc.head(), 4);
        // A sibling of the peer's canonical block at START + 1.
        let lie = crate::payload::fake::make(
            Fork::Cancun,
            START + 1,
            fc.head().hash,
            fc.head().root,
            "lie",
        );
        hostile.serve_only(&lie);
        let (_f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        reports.send(0, lie.root);
        tokio::time::sleep(Duration::from_millis(2600)).await;
        assert_eq!(block_calls(&honest, lie.root), 1);
        task.abort();
    }

    #[tokio::test]
    async fn a_first_source_that_answers_a_root_with_a_block_the_peer_cannot_place_costs_no_pause()
    {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let line = hold_line(&peer, fc.head(), 1);
        honest.serve_only(&line[0]);
        // A self-consistent block far above the peer's head, under the real root.
        let far = crate::payload::fake::make(
            Fork::Cancun,
            START + 1000,
            fc.head().hash,
            fc.head().root,
            "far",
        );
        hostile.state.lock().blocks.insert(line[0].root, far);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        let t0 = Instant::now();
        reports.send(0, line[0].root);
        reports.send(1, line[0].root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == line[0].hash)).await;
        assert!(t0.elapsed() < CONFIRM_PAUSE, "the head waited {:?}", t0.elapsed());
        task.abort();
    }

    #[tokio::test]
    async fn a_first_source_that_answers_a_new_root_with_the_held_head_does_not_hold_it_back() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let line = hold_line(&peer, fc.head(), 2);
        let third = FakeChain { fork: Fork::Cancun, blocks: vec![line[1].clone()] }.next();
        // The hostile source answers the real roots with the held head, which the peer confirms.
        for b in &line[..2] {
            honest.serve_only(b);
        }
        hostile.state.lock().blocks.insert(line[0].root, fc.head().clone());
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer.clone()),
        );
        // One slow answer from the honest source puts the hostile one first in the order.
        f.slow.lock()[1] = 1;
        reports.send(1, line[0].root);
        wait_until("the real head", || f.chain.head().is_some_and(|h| h.hash == line[0].hash))
            .await;
        assert_eq!(block_calls(&hostile, line[0].root), 1, "the hostile source was not asked");
        // It answers the next root with the head just followed, before the honest source has the
        // block: the root is heard again once the honest source serves it.
        hostile.state.lock().blocks.insert(line[1].root, line[0].clone());
        honest.state.lock().blocks.remove(&line[1].root);
        reports.send(0, line[1].root);
        tokio::time::sleep(Duration::from_millis(100)).await;
        honest.serve_only(&line[1]);
        reports.send(1, line[1].root);
        wait_until("the next head", || f.chain.head().is_some_and(|h| h.hash == line[1].hash))
            .await;
        // The honest source serves the next block before the peer holds it: the root is asked
        // about again, not taken as the held head.
        hostile.state.lock().blocks.insert(third.root, line[1].clone());
        honest.serve_only(&third);
        reports.send(1, third.root);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        peer.hold(&third);
        wait_until("the third head", || f.chain.head().is_some_and(|h| h.hash == third.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_first_source_that_answers_a_new_root_with_an_old_canonical_block_does_not_hold_it_back(
    ) {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let line = hold_line(&peer, fc.head(), 613);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            &line[9],
            Some(peer),
        );
        // [a] Before the head first moves: a block the peer holds below the seeded anchor.
        hostile.state.lock().blocks.insert(line[10].root, fc.head().clone());
        honest.serve_only(&line[10]);
        reports.send(0, line[10].root);
        reports.send(1, line[10].root);
        wait_until("the first head", || f.chain.head().is_some_and(|h| h.hash == line[10].hash))
            .await;
        assert_eq!(f.slow.lock()[0], 1, "the hostile source was not moved back");
        // [b] Live: a block the peer holds 600 below the head, above the finalized one and no
        // longer held.
        for b in &line[11..612] {
            f.chain.insert(f.held(b)).unwrap();
        }
        f.chain.set_head(line[611].hash).unwrap();
        assert!(!f.chain.contains(&line[11].hash));
        // An earlier slow answer from the honest source puts the hostile one first again.
        f.slow.lock()[1] = 5;
        hostile.state.lock().blocks.insert(line[612].root, line[11].clone());
        honest.serve_only(&line[612]);
        reports.send(0, line[612].root);
        reports.send(1, line[612].root);
        wait_until("the next head", || f.chain.head().is_some_and(|h| h.hash == line[612].hash))
            .await;
        assert_eq!(
            block_calls(&hostile, line[612].root),
            1,
            "the hostile source was not asked first"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_slow_later_source_does_not_delay_a_head_the_peer_confirms_on_its_second_query() {
        let (honest, slow) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        honest.serve_only(&b1);
        slow.serve_only(&b1);
        slow.state.lock().block_delay = Duration::from_secs(5);
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        let (f, reports, task) = coordinated(
            vec![honest.beacon_url(), slow.beacon_url()],
            Fork::Cancun,
            &seed,
            Some(peer.clone()),
        );
        let t0 = Instant::now();
        reports.send(0, b1.root);
        // The peer imports the block 200 ms after the beacon reported it.
        tokio::time::sleep(Duration::from_millis(200)).await;
        peer.hold(&b1);
        while !f.chain.head().is_some_and(|h| h.hash == b1.hash) {
            assert!(t0.elapsed() < Duration::from_secs(1), "the head waited for the slow source");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_lagging_source_reporting_an_ancestor_does_not_send_the_head_root_back_to_the_sources(
    ) {
        let (healthy, lagging) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let peer = Arc::new(Peer::default());
        for b in [&seed, &b1, &b2, &b3] {
            peer.hold(b);
        }
        healthy.serve_only(&b1);
        healthy.serve_only(&b2);
        lagging.serve_only(&b1);
        let (f, reports, task) = coordinated(
            vec![healthy.beacon_url(), lagging.beacon_url()],
            Fork::Cancun,
            &seed,
            Some(peer),
        );
        reports.send(0, b2.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b2.hash)).await;
        // The lagging source reports the parent, which both sources serve as a held block.
        let walked = block_calls(&healthy, b1.root);
        reports.send(1, b1.root);
        wait_until("the ancestor", || block_calls(&healthy, b1.root) == walked + 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The healthy source polls its head again: nobody is asked for it, and it is not struck.
        reports.send(0, b2.root);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(block_calls(&healthy, b2.root), 1, "the head root was taken up again");
        healthy.serve_only(&b3);
        let t0 = Instant::now();
        reports.send(0, b3.root);
        while !f.chain.head().is_some_and(|h| h.hash == b3.hash) {
            assert!(t0.elapsed() < Duration::from_millis(600), "the next head was backed off");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_root_followed_before_a_reorg_is_followed_again_when_reported_after_it() {
        let (first, second) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        let alt = fc.alt(START + 1);
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        peer.hold(&b1);
        for fake in [&first, &second] {
            fake.serve_only(&b1);
            fake.serve_only(&alt);
        }
        let (f, reports, task) = coordinated(
            vec![first.beacon_url(), second.beacon_url()],
            Fork::Cancun,
            &seed,
            Some(peer.clone()),
        );
        reports.send(0, b1.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        peer.hold(&alt);
        reports.send(0, alt.root);
        wait_until("the reorg", || f.chain.head().is_some_and(|h| h.hash == alt.hash)).await;
        peer.hold(&b1);
        reports.send(0, b1.root);
        wait_until("the reorg back", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_source_that_answers_made_up_roots_with_the_held_head_cannot_flood_the_others() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let line = hold_line(&peer, fc.head(), 4);
        let roots: Vec<B256> =
            (0..500u64).map(|i| B256::from(alloy_primitives::U256::from(i + 1))).collect();
        for r in &roots {
            hostile.state.lock().blocks.insert(*r, fc.head().clone());
        }
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        for r in &roots {
            reports.send(0, *r);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let junk: usize = roots.iter().map(|r| block_calls(&honest, *r)).sum();
        assert!(junk <= 3, "the honest source was asked for {junk} made-up roots");
        honest.serve_only(&line[0]);
        reports.send(1, line[0].root);
        wait_until("the real head", || f.chain.head().is_some_and(|h| h.hash == line[0].hash))
            .await;
        task.abort();
    }

    #[tokio::test]
    async fn a_source_that_keeps_making_up_roots_for_the_held_head_waits_longer_each_time() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let (_f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        let started = Instant::now();
        let mut roots = Vec::new();
        while started.elapsed() < Duration::from_secs(6) {
            let r = B256::from(alloy_primitives::U256::from(roots.len() + 1));
            hostile.state.lock().blocks.insert(r, fc.head().clone());
            reports.send(0, r);
            roots.push(r);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Waits of 1 s, 2 s and 4 s: three tries in 6 s, not one a second.
        let junk: usize = roots.iter().map(|r| block_calls(&honest, *r)).sum();
        assert!(junk <= 4, "the honest source was asked for {junk} made-up roots in 6 s");
        task.abort();
    }

    #[tokio::test]
    async fn a_vetoed_decoy_for_a_root_another_source_has_not_imported_yet_does_not_fail_it() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let line = hold_line(&peer, fc.head(), 4);
        // A sibling of the real block that the peer does not hold, served under the real root.
        let decoy = crate::payload::fake::make(
            Fork::Cancun,
            START + 1,
            fc.head().hash,
            fc.head().root,
            "decoy",
        );
        hostile.state.lock().blocks.insert(line[0].root, decoy);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        // The hostile source reports the root before the honest one has imported the block.
        reports.send(0, line[0].root);
        wait_until("the veto", || f.source_failures(0) >= 1).await;
        honest.serve_only(&line[0]);
        reports.send(1, line[0].root);
        wait_until("the real head", || f.chain.head().is_some_and(|h| h.hash == line[0].hash))
            .await;
        task.abort();
    }

    #[tokio::test]
    async fn with_quorum_two_a_head_a_source_had_not_imported_yet_is_tried_again_on_its_report() {
        let fakes = [
            Fake::start(false, false).await,
            Fake::start(false, false).await,
            Fake::start(false, false).await,
        ];
        let mut fc = FakeChain::new(Fork::Shanghai, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        // Source 0 reports the root and never serves it; source 2 has not imported it yet.
        fakes[1].serve_only(&b1);
        let (f, reports, task) = coordinated_with(
            fakes.iter().map(Fake::beacon_url).collect(),
            2,
            Fork::Shanghai,
            &seed,
            None,
        );
        reports.send(0, b1.root);
        reports.send(1, b1.root);
        wait_until("the first try", || block_calls(&fakes[2], b1.root) >= 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        fakes[2].serve_only(&b1);
        reports.send(2, b1.root);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn with_quorum_one_a_flooding_source_cannot_make_the_others_fetch_every_root() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let line = hold_line(&peer, fc.head(), 4);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        // A fresh made-up root every 2 ms for a second.
        for i in 0..500u64 {
            reports.send(0, B256::from(alloy_primitives::U256::from(i + 1)));
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let junk = honest
            .state
            .lock()
            .calls
            .iter()
            .filter(|(p, _)| p.starts_with("/eth/v2/beacon/blocks/0x"))
            .map(|(_, n)| n)
            .sum::<usize>();
        assert!(junk <= 3, "the honest source was asked for {junk} made-up roots");
        // The honest source's real head is still followed at once.
        honest.serve_only(&line[0]);
        reports.send(1, line[0].root);
        wait_until("the real head", || f.chain.head().is_some_and(|h| h.hash == line[0].hash))
            .await;
        task.abort();
    }

    #[tokio::test]
    async fn a_mismatch_reseed_does_not_undo_a_newer_reseed() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        hold_line(&peer, fc.head(), 100);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..20).map(|_| fc.next()).collect();
        // The held chain is a lie from START + 1.
        let lie = crate::payload::fake::make(Fork::Cancun, START + 1, seed.hash, seed.root, "lie");
        let anchor = Fake::start(false, true).await;
        anchor.set_anchor_block(&blocks[0]);
        let slot = Arc::new(Mutex::new(None::<Arc<Follower>>));
        let hook_slot = slot.clone();
        let newer = blocks[15].clone();
        let hook = Box::new(move || {
            let f = hook_slot.lock().clone().unwrap();
            assert!(f.reseed_confirmed(f.chain.epoch(), f.held(&newer)));
        });
        let hooked =
            Arc::new(HookPeer { peer, at: blocks[0].header.number, hook: Mutex::new(Some(hook)) });
        let f = bare_follower(Vec::new(), &seed, hooked);
        *slot.lock() = Some(f.clone());
        f.chain.insert(f.held(&lie)).unwrap();
        f.chain.set_head(lie.hash).unwrap();
        f.check_anchor(&BeaconClient::new(anchor.anchor_url()), &[], &Notify::new()).await;
        assert_eq!(f.chain.head().unwrap().hash, blocks[15].hash, "re-seeded back");
        assert_eq!(f.chain.finalized_number(), Some(blocks[15].header.number));
        assert!(!f.chain.halted());
    }

    #[tokio::test]
    async fn a_stale_mismatching_anchor_does_not_reseed() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        hold_line(&peer, fc.head(), 100);
        let seed = fc.head().clone();
        let real = fc.next();
        // The held chain is a lie from START + 1; the peer vouches for the real block there.
        let lie = crate::payload::fake::make(Fork::Cancun, START + 1, seed.hash, seed.root, "lie");
        let anchor = Fake::start(false, true).await;
        anchor.set_anchor_block(&real);
        let client = BeaconClient::new(anchor.anchor_url());
        // The fake chain is from 2023: stale under MAX_ANCHOR_AGE. Positive control: the same
        // anchor re-seeds with a wide enough age bound.
        for (max_age, reseeds) in [(MAX_ANCHOR_AGE, false), (TEST_ANCHOR_AGE, true)] {
            let mut f = Arc::into_inner(bare_follower(Vec::new(), &seed, peer.clone())).unwrap();
            f.cfg.max_anchor_age = max_age;
            f.chain.insert(f.held(&lie)).unwrap();
            f.chain.set_head(lie.hash).unwrap();
            f.check_anchor(&client, &[], &Notify::new()).await;
            let head = f.chain.head().unwrap().hash;
            assert_eq!(head == real.hash, reseeds, "max age {max_age:?}");
            assert_eq!(f.chain.halted(), !reseeds, "max age {max_age:?}");
        }
    }

    /// Several peers, each with its own canonical chain.
    #[derive(Debug)]
    struct Peers(Vec<Peer>);

    #[async_trait::async_trait]
    impl HeadConfirm for Peers {
        async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>> {
            self.0.iter().map(|p| p.0.lock().get(&number).copied()).collect()
        }
    }

    #[tokio::test]
    async fn confirmation_asks_for_the_canonical_block_by_number() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let side = fc.alt(START + 1);
        // [a] One peer stores b1 only on a side chain; its canonical block there is another.
        // The other peer has b1 canonical. The first vetoes.
        let (p, q) = (Peer::default(), Peer::default());
        p.hold(&side);
        q.hold(&b1);
        let peers = Peers(vec![p, q]);
        assert_eq!(
            confirm_canonical(&peers, START + 1, b1.hash, 0, 0).await,
            Confirmation::Mismatch
        );
        // [b] A peer whose canonical block at that number matches confirms.
        let only = Peer::default();
        only.hold(&b1);
        assert_eq!(
            confirm_canonical(&only, START + 1, b1.hash, 0, 0).await,
            Confirmation::Confirmed
        );
        // [c] For an anchor: a match with nothing on top does not confirm...
        assert_eq!(
            confirm_canonical(&only, START + 1, b1.hash, ANCHOR_DESCENDANTS, 0).await,
            Confirmation::Unknown
        );
        // ...canonical descendants do...
        only.hold(&b2);
        only.hold(&b3);
        assert_eq!(
            confirm_canonical(&only, START + 1, b1.hash, ANCHOR_DESCENDANTS, 0).await,
            Confirmation::Confirmed
        );
        // ...and a block above that does not build on it vetoes.
        let broken = Peer::default();
        broken.hold(&b1);
        broken.hold(&crate::payload::fake::make(
            Fork::Cancun,
            START + 2,
            side.hash,
            side.root,
            "x",
        ));
        assert_eq!(
            confirm_canonical(&broken, START + 1, b1.hash, ANCHOR_DESCENDANTS, 0).await,
            Confirmation::Mismatch
        );
    }

    /// A peer holding a linked line of `len` blocks from `number`, the first being `hash`.
    fn line_peer(number: u64, hash: B256, len: u64) -> Peer {
        let peer = Peer::default();
        let mut parent = B256::ZERO;
        for k in 0..len {
            let h = if k == 0 { hash } else { B256::from(alloy_primitives::U256::from(k)) };
            peer.0.lock().insert(number + k, PeerHeader { hash: h, parent_hash: parent });
            parent = h;
        }
        peer
    }

    #[tokio::test]
    async fn a_finality_depth_of_64_needs_a_canonical_block_64_above() {
        let hash = B256::repeat_byte(1);
        let short = line_peer(START, hash, FINALITY_MIN_DEPTH);
        let got = confirm_canonical(&short, START, hash, ANCHOR_DESCENDANTS, FINALITY_MIN_DEPTH);
        assert_eq!(got.await, Confirmation::Unknown, "blocks up to number + 63");
        let deep = line_peer(START, hash, FINALITY_MIN_DEPTH + 1);
        let got = confirm_canonical(&deep, START, hash, ANCHOR_DESCENDANTS, FINALITY_MIN_DEPTH);
        assert_eq!(got.await, Confirmation::Confirmed, "a block at number + 64");
    }

    /// [`Peers`] whose answers for any number but `number` list only the first `keep` peers, as
    /// a peer set that shrinks between two queries answers.
    #[derive(Debug)]
    struct Shrinking {
        peers: Peers,
        number: u64,
        keep: usize,
    }

    #[async_trait::async_trait]
    impl HeadConfirm for Shrinking {
        async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>> {
            let mut at = self.peers.headers_at(number).await;
            if number != self.number {
                at.truncate(self.keep);
            }
            at
        }
    }

    /// What a generated peer holds at one offset above the asked number.
    #[derive(Debug, Clone, Copy)]
    enum Slot {
        Missing,
        /// The block of line `0` or `1` (line `0` holds the asked hash at offset 0).
        Line(u8),
        /// A block of line `0` whose parent is not the block below.
        BadParent,
    }

    fn slot_hash(offset: u64, line: u8) -> B256 {
        if offset == 0 && line == 0 {
            return B256::repeat_byte(0xaa);
        }
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&offset.to_be_bytes());
        b[8] = line + 1;
        B256::from(b)
    }

    fn slot() -> impl proptest::strategy::Strategy<Value = Slot> {
        use proptest::prelude::*;
        prop_oneof![
            2 => Just(Slot::Missing),
            6 => Just(Slot::Line(0)),
            2 => Just(Slot::Line(1)),
            1 => Just(Slot::BadParent),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn a_confirmation_needs_a_linked_peer_chain_and_any_veto_wins(
            number in proptest::prop_oneof![0u64..1000, (u64::MAX - 70)..=u64::MAX],
            descendants in 0u64..=3,
            depth in proptest::prop_oneof![0u64..=5, proptest::strategy::Just(FINALITY_MIN_DEPTH)],
            tables in proptest::collection::vec(
                (proptest::collection::vec(slot(), 4), proptest::bool::ANY), 1..4
            ),
            keep in proptest::option::of(0usize..3),
        ) {
            let hash = slot_hash(0, 0);
            let keep = keep.unwrap_or(usize::MAX);
            let peers = Peers(tables.iter().map(|(slots, far)| {
                let peer = Peer::default();
                let mut below = B256::repeat_byte(0xee);
                for (k, s) in (0u64..).zip(slots) {
                    let Some(n) = number.checked_add(k) else { break };
                    let (h, parent) = match *s {
                        Slot::Missing => {
                            below = B256::repeat_byte(0xee);
                            continue;
                        }
                        Slot::Line(l) => (slot_hash(k, l), below),
                        Slot::BadParent => (slot_hash(k, 0), B256::repeat_byte(0xdd)),
                    };
                    peer.0.lock().insert(n, PeerHeader { hash: h, parent_hash: parent });
                    below = h;
                }
                if *far && let Some(n) = number.checked_add(depth) {
                    peer.0.lock().entry(n).or_insert_with(|| PeerHeader {
                        hash: slot_hash(depth, 1),
                        parent_hash: B256::ZERO,
                    });
                }
                peer
            }).collect());
            // The naive rule: per peer, its own line from `number` up. A peer left out of an
            // answer above `number` holds nothing there.
            let header = |i: usize, k: u64| {
                if k > 0 && i >= keep {
                    return None;
                }
                number.checked_add(k).and_then(|n| peers.0[i].0.lock().get(&n).copied())
            };
            let n_peers = peers.0.len();
            let veto = (0..n_peers).any(|i| header(i, 0).is_some_and(|h| h.hash != hash));
            // How far each peer's line runs linked on top of `hash`, up to `descendants`.
            let linked = |i: usize| {
                let mut want = hash;
                if header(i, 0).is_none() {
                    return (None, false);
                }
                for k in 1..=descendants {
                    match header(i, k) {
                        Some(h) if h.parent_hash == want => want = h.hash,
                        Some(_) => return (Some(k), true),
                        None => return (Some(k), false),
                    }
                }
                (Some(descendants + 1), false)
            };
            let broken = (0..n_peers).any(|i| linked(i).1);
            let full = (0..n_peers).any(|i| {
                linked(i).0 == Some(descendants + 1) &&
                    (depth <= descendants || header(i, depth).is_some())
            });
            let want = if veto || broken {
                Confirmation::Mismatch
            } else if full {
                Confirmation::Confirmed
            } else {
                Confirmation::Unknown
            };
            let peers = Shrinking { peers, number, keep };
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let got = rt.block_on(confirm_canonical(&peers, number, hash, descendants, depth));
            proptest::prop_assert_eq!(got, want);
        }
    }

    #[tokio::test]
    async fn an_unconfirmed_head_is_not_walked_and_not_retried_every_report() {
        let fc0 = FakeChain::new(Fork::Cancun, START);
        let peer = honest_peer(&fc0);
        let mut r = Rig::start_with(false, Fork::Cancun, 20, Some(peer.clone())).await;
        r.wait_head(START).await;
        let (b1, b2, b3) = (r.fc.next(), r.fc.next(), r.fc.next());
        // The peer's canonical block at START + 3 is another one: it vetoes b3.
        let mut other = FakeChain { fork: Fork::Cancun, blocks: vec![b2.clone()] };
        let mut alt3 = other.next();
        alt3.json["data"]["message"]["body"]["execution_payload"]["extra_data"] =
            serde_json::json!("0x01");
        alt3.hash = B256::repeat_byte(0x33);
        peer.0.lock().insert(START + 3, PeerHeader { hash: alt3.hash, parent_hash: b2.hash });
        r.beacon.serve_only(&b1);
        r.beacon.serve_only(&b2);
        r.beacon.push(&b3);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(r.chain.head().unwrap().header.number, START);
        let walked = r.beacon.calls(&format!("/eth/v2/beacon/blocks/{:#x}", b2.root));
        assert_eq!(walked, 0, "the ancestors of an unconfirmed head were fetched");
        // About 25 reports of b3 in 500 ms; the unconfirmed root is not re-fetched for each.
        let head_fetches = r.beacon.calls(&format!("/eth/v2/beacon/blocks/{:#x}", b3.root));
        assert!(head_fetches <= 3, "{head_fetches} fetches of an unconfirmed head");
    }

    #[tokio::test]
    async fn an_unconfirmed_head_is_asked_about_again_without_a_new_report() {
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let b1 = fc.next();
        let beacon = Fake::start(false, false).await;
        beacon.serve_only(&b1);
        let peer = Arc::new(Peer::default());
        peer.hold(&fc.blocks[0]);
        let f = bare_follower(vec![beacon.beacon_url()], &fc.blocks[0], peer.clone());
        let clients = vec![BeaconClient::new(beacon.beacon_url())];
        let reports = Arc::new(Reports::new(1));
        let task = tokio::spawn({
            let (f, reports) = (f.clone(), reports.clone());
            let anchor = BeaconClient::new(f.cfg.anchor_url.clone());
            async move { f.coordinate(anchor, clients, reports, Arc::new(Notify::new())).await }
        });
        // One report only, as an event stream sends one per slot.
        reports.send(0, b1.root);
        // The peer has the block only after the follower's tries for that report ended.
        tokio::time::sleep(CONFIRM_PAUSE * CONFIRM_TRIES + Duration::from_millis(300)).await;
        assert!(!f.chain.is_live());
        peer.hold(&b1);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn an_unconfirmed_head_is_asked_about_less_often_while_it_stays_unconfirmed() {
        let (a, b) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        a.serve_only(&b1);
        b.serve_only(&b1);
        // The peer never gets b1.
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        let (_f, reports, task) = coordinated_with(
            vec![a.beacon_url(), b.beacon_url()],
            2,
            Fork::Cancun,
            &seed,
            Some(peer),
        );
        reports.send(0, b1.root);
        reports.send(1, b1.root);
        // Each try takes the confirmation pauses. The first retry comes after UNCONFIRMED_TTL,
        // the second after twice that.
        let try_time = CONFIRM_PAUSE * (CONFIRM_TRIES - 1);
        tokio::time::sleep((try_time + UNCONFIRMED_TTL) * 2 + Duration::from_millis(500)).await;
        assert_eq!(block_calls(&a, b1.root), 2);
        task.abort();
    }

    #[tokio::test]
    async fn an_unconfirmed_head_keeps_its_retry_when_another_source_reports_another_root() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        honest.serve_only(&b1);
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        let (f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            &seed,
            Some(peer.clone()),
        );
        reports.send(1, b1.root);
        tokio::time::sleep(CONFIRM_PAUSE * CONFIRM_TRIES).await;
        // After the tries for b1 ended, the other source reports a root nobody serves, once.
        reports.send(0, B256::repeat_byte(0x61));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!f.chain.is_live());
        peer.hold(&b1);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_root_no_source_holds_yet_is_followed_when_a_source_serves_it_before_the_retry() {
        let (other, early) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        let peer = Arc::new(Peer::default());
        peer.hold(&seed);
        peer.hold(&b1);
        let (f, reports, task) = coordinated(
            vec![other.beacon_url(), early.beacon_url()],
            Fork::Cancun,
            &seed,
            Some(peer),
        );
        // The source reports the root before it serves the block, once.
        reports.send(1, b1.root);
        wait_until("the first try", || block_calls(&early, b1.root) == 1).await;
        early.serve_only(&b1);
        wait_until("the head", || f.chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_root_no_source_holds_is_asked_about_once_more_and_then_left_alone() {
        let (hostile, honest) = (Fake::start(false, false).await, Fake::start(false, false).await);
        let fc = FakeChain::new(Fork::Cancun, START);
        let peer = Arc::new(Peer::default());
        peer.hold(fc.head());
        let (_f, reports, task) = coordinated(
            vec![hostile.beacon_url(), honest.beacon_url()],
            Fork::Cancun,
            fc.head(),
            Some(peer),
        );
        let made_up = B256::repeat_byte(0x61);
        reports.send(0, made_up);
        // The one retry comes 2 s after the report.
        tokio::time::sleep(UNCONFIRMED_TTL * 2 + Duration::from_millis(800)).await;
        assert_eq!(block_calls(&honest, made_up), 2);
        // A root left open would be asked again 4 s after the retry.
        tokio::time::sleep(UNCONFIRMED_TTL * 2).await;
        assert_eq!(block_calls(&honest, made_up), 2, "the root was asked about a third time");
        task.abort();
    }

    #[tokio::test]
    async fn with_several_peers_one_veto_keeps_the_head() {
        let beacon = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let (b0, b1, b2) = (fc.head().clone(), fc.next(), fc.next());
        let other1 = fc.alt(START + 1);
        let (p, q) = (Peer::default(), Peer::default());
        for x in [&p, &q] {
            x.hold(&b0);
            hold_line(x, &b0, FINALITY_MIN_DEPTH as usize + 2);
        }
        let peers = Arc::new(Peers(vec![p, q]));
        beacon.push(&b0);
        anchor.set_anchor_block(&b0);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let f = Follower::new(cfg, chain.clone(), LiteMetrics::new()).with_confirm(peers.clone());
        let task = tokio::spawn(Arc::new(f).run());
        wait_until("the seed", || chain.head().is_some()).await;
        // The second peer's canonical block at START + 1 is another: its veto wins.
        peers.0[1].hold(&other1);
        beacon.push(&b1);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!chain.contains(&b1.hash), "followed despite a veto");
        // Both agree again. The vetoed root is left alone, so b1 comes in under the next head.
        peers.0[1].hold(&b1);
        beacon.serve_only(&b1);
        beacon.push(&b2);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b2.hash)).await;
        assert_eq!(chain.by_number(START + 1).unwrap().hash, b1.hash);
        task.abort();
    }

    #[tokio::test]
    async fn a_forged_header_head_is_rejected_when_a_peer_reports_another_hash() {
        let beacon = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let first = fc.head().clone();
        beacon.push(&first);
        anchor.set_anchor_block(&first);
        let real = fc.next();
        // Same parent, same state root, another timestamp: self-consistent, but forged.
        let mut forged =
            crate::payload::fake::make(Fork::Cancun, START + 1, first.hash, first.root, "");
        assert_eq!(forged.header.state_root, real.header.state_root);
        forged.header.timestamp += 1;
        let p = &mut forged.json["data"]["message"]["body"]["execution_payload"];
        p["timestamp"] = serde_json::json!(forged.header.timestamp.to_string());
        forged.hash = forged.header.hash_slow();
        p["block_hash"] = serde_json::json!(crate::payload::fake::hx(forged.hash.as_slice()));
        forged.root = B256::repeat_byte(0x99);

        let peer = Arc::new(Peer::default());
        peer.hold(&first);
        let line = hold_line(&peer, &first, FINALITY_MIN_DEPTH as usize + 2);
        assert_eq!(line[0].hash, real.hash);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let f = Follower::new(cfg, chain.clone(), LiteMetrics::new()).with_confirm(peer.clone());
        let task = tokio::spawn(Arc::new(f).run());
        beacon.push(&forged);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(chain.head().unwrap().header.number, START, "the forged head was followed");
        assert!(!chain.contains(&forged.hash));
        // The real block is confirmed by the peer and followed.
        beacon.push(&real);
        for _ in 0..300 {
            if chain.head().unwrap().header.number == START + 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().hash, real.hash);
        task.abort();
    }

    #[tokio::test]
    async fn an_honest_source_is_not_blamed_for_a_parent_root_another_source_made_up() {
        let (f, chain, mut fc, task, follower) = sources(2, 1, Fork::Shanghai).await;
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        // A real block, but not b2's parent: a sibling of b1.
        let other = fc.alt(START + 1);
        f[1].serve_only(&other);
        // The hostile source names that block's root as b2's parent root.
        let mut lie = b2.clone();
        lie.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(other.root.as_slice()));
        f[0].serve_only(&lie);
        f[1].serve_only(&b2);
        for s in &f {
            s.serve_only(&b1);
            s.push(&b3);
        }
        for _ in 0..300 {
            if chain.head().unwrap().header.number == START + 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().hash, b3.hash, "the bad candidate line is dropped");
        assert_eq!(chain.by_number(START + 1).unwrap().hash, b1.hash);
        assert!(!chain.contains(&other.hash));
        assert_eq!(follower.source_failures(1), 0, "the honest source served a valid block");
        task.abort();
    }

    /// Sources that each serve the chain `START..=START + 3`, with `other` (a real sibling of
    /// b2) served by `other_from` under b2's root.
    async fn pinned_parent_rig(
        n: usize,
        other_from: &[usize],
    ) -> (Vec<Fake>, Arc<HeaderChain>, Vec<FakeBlock>, tokio::task::JoinHandle<()>, Arc<Follower>)
    {
        let quorum = if n >= 3 { 2 } else { 1 };
        let (f, chain, mut fc, task, follower) = sources(n, quorum, Fork::Shanghai).await;
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let mut other = fc.alt(START + 2);
        other.root = b2.root;
        for (i, s) in f.iter().enumerate() {
            s.serve_only(&b1);
            s.serve_only(if other_from.contains(&i) { &other } else { &b2 });
        }
        for s in &f {
            s.push(&b3);
        }
        (f, chain, vec![b1, b2, b3], task, follower)
    }

    #[tokio::test]
    async fn honest_sources_are_not_charged_for_a_root_a_hostile_source_made_up() {
        let (f, chain, mut fc, task, follower) = sources(3, 2, Fork::Shanghai).await;
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        // A real block whose root the hostile source names as b2's parent root.
        let other = fc.alt(START + 1);
        let mut lie = b2.clone();
        lie.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(other.root.as_slice()));
        // The hostile source (asked last) serves b2 with that root, and b1 under it.
        let mut b1_under_r = b1.clone();
        b1_under_r.root = other.root;
        f[2].serve_only(&lie);
        f[2].serve_only(&b1_under_r);
        // The honest sources answer that root with the real block and do not have b2.
        for s in &f[..2] {
            s.serve_only(&other);
        }
        for s in &f {
            s.push(&b3);
        }
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        assert_eq!(chain.by_number(START + 1).unwrap().hash, b1.hash);
        for i in 0..2 {
            assert_eq!(follower.source_failures(i), 0, "honest source {i} charged");
        }
        task.abort();
    }

    #[tokio::test]
    async fn one_mismatched_source_among_three_does_not_stop_the_head() {
        let (_f, chain, b, task, follower) = pinned_parent_rig(3, &[0]).await;
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b[2].hash)).await;
        assert_eq!(chain.by_number(START + 2).unwrap().hash, b[1].hash);
        // Whether the outlier is charged depends on whether it was asked, see the tests below.
        assert_eq!((follower.source_failures(1), follower.source_failures(2)), (0, 0));
        task.abort();
    }

    /// Three sources serving b2, except source 0, which serves a sibling under b2's root. The
    /// follower task is stopped, so only the test asks the sources.
    async fn stopped_pinned_parent_rig() -> (Vec<Fake>, Vec<BeaconClient>, FakeBlock, Arc<Follower>)
    {
        let (f, _chain, mut fc, task, follower) = sources(3, 2, Fork::Shanghai).await;
        task.abort();
        let (_b1, b2) = (fc.next(), fc.next());
        let mut other = fc.alt(START + 2);
        other.root = b2.root;
        for (i, s) in f.iter().enumerate() {
            s.serve_only(if i == 0 { &other } else { &b2 });
        }
        let clients = f.iter().map(|s| BeaconClient::new(s.beacon_url())).collect();
        (f, clients, b2, follower)
    }

    #[tokio::test]
    async fn an_outlier_asked_before_the_block_is_found_is_charged() {
        let (_f, clients, b2, follower) = stopped_pinned_parent_rig().await;
        let got = follower.fetch_block(&clients, &[0, 1, 2], b2.root, Some(b2.hash), true);
        assert!(matches!(got.await, Fetched::Block(p) if p.block.hash == b2.hash));
        assert_eq!(follower.source_failures(0), 1, "the outlier is charged");
        assert_eq!((follower.source_failures(1), follower.source_failures(2)), (0, 0));
    }

    #[tokio::test]
    async fn an_outlier_after_the_source_that_serves_the_block_is_not_asked_or_charged() {
        let (f, clients, b2, follower) = stopped_pinned_parent_rig().await;
        let got = follower.fetch_block(&clients, &[1, 2, 0], b2.root, Some(b2.hash), true);
        assert!(matches!(got.await, Fetched::Block(p) if p.block.hash == b2.hash));
        let path = format!("/eth/v2/beacon/blocks/{:#x}", b2.root);
        assert_eq!(f[0].calls(&path), 0, "the outlier was asked");
        assert_eq!(follower.source_failures(0), 0);
    }

    #[tokio::test]
    async fn a_head_source_that_serves_another_block_than_the_quorum_is_charged() {
        let (_f, clients, b2, follower) = stopped_pinned_parent_rig().await;
        let got = follower.fetch_head(&clients, &[0, 1, 2], b2.root);
        assert!(matches!(got.await, Fetched::Block(p) if p.block.hash == b2.hash));
        assert_eq!(follower.source_failures(0), 1, "the outlier is charged");
        assert_eq!((follower.source_failures(1), follower.source_failures(2)), (0, 0));
    }

    #[tokio::test]
    async fn without_a_quorum_block_no_head_source_is_charged() {
        let (_f, clients, b2, follower) = stopped_pinned_parent_rig().await;
        let got = follower.fetch_head(&clients[..2], &[0, 1], b2.root);
        assert!(matches!(got.await, Fetched::Bad));
        assert_eq!((follower.source_failures(0), follower.source_failures(1)), (0, 0));
    }

    #[tokio::test]
    async fn a_single_mismatched_source_does_not_stop_the_search() {
        let (_f, chain, b, task, _) = pinned_parent_rig(2, &[0]).await;
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b[2].hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn when_every_source_serves_the_same_other_block_nobody_is_charged() {
        let (f, chain, b, task, follower) = pinned_parent_rig(3, &[0, 1, 2]).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(chain.head().unwrap().header.number, START, "the candidate is dropped");
        let path = format!("/eth/v2/beacon/blocks/{:#x}", b[1].root);
        for (i, s) in f.iter().enumerate() {
            assert!(s.calls(&path) >= 1, "source {i} was asked");
            assert_eq!(follower.source_failures(i), 0, "source {i} charged");
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_source_that_makes_up_parent_roots_two_deep_does_not_stall_the_walk() {
        let (f, chain, mut fc, task, _) = sources(2, 1, Fork::Shanghai).await;
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let (f2, f1) = (B256::repeat_byte(0x5a), B256::repeat_byte(0x5b));
        // The hostile source, asked first, names a made-up root for b2 and serves the real b2
        // under it, naming another made-up root it does not serve.
        let mut lie3 = b3.clone();
        lie3.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(f2.as_slice()));
        let mut lie2 = b2.clone();
        lie2.root = f2;
        lie2.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(f1.as_slice()));
        f[0].serve_only(&lie2);
        f[0].push(&lie3);
        f[1].serve_only(&b1);
        f[1].serve_only(&b2);
        f[1].push(&b3);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b3.hash)).await;
        assert_eq!(chain.by_number(START + 1).unwrap().hash, b1.hash);
        task.abort();
    }

    #[tokio::test]
    async fn an_ancestor_with_a_wrong_parent_root_is_routed_around() {
        let (f, chain, mut fc, task, _) = sources(2, 1, Fork::Shanghai).await;
        let (b1, b2, b3) = (fc.next(), fc.next(), fc.next());
        let mut lie = b2.clone();
        lie.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(&[0x5au8; 32]));
        f[0].serve_only(&lie);
        f[1].serve_only(&b2);
        for s in &f {
            s.serve_only(&b1);
            s.push(&b3);
        }
        for _ in 0..300 {
            if chain.head().unwrap().header.number == START + 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().hash, b3.hash);
        assert_eq!(chain.by_number(START + 1).unwrap().hash, b1.hash);
        task.abort();
    }

    #[tokio::test]
    async fn the_quorum_must_agree_on_the_parent_root_too() {
        // Shanghai: the parent root is not in the execution hash, so only the quorum key holds it.
        let (f, chain, mut fc, task, _) = sources(2, 2, Fork::Shanghai).await;
        let b1 = fc.next();
        let mut other_parent = b1.clone();
        other_parent.json["data"]["message"]["parent_root"] =
            serde_json::json!(crate::payload::fake::hx(&[0x5au8; 32]));
        f[0].push(&b1);
        f[1].push(&other_parent);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(chain.head().unwrap().header.number, START, "no quorum on the parent root");
        f[1].push(&b1);
        wait_until("the head", || chain.head().is_some_and(|h| h.hash == b1.hash)).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_hostile_quorum_member_cannot_serve_another_block_for_an_agreed_root() {
        let (a, b, chain, mut fc, task) = two_sources().await;
        for _ in 0..300 {
            if chain.head().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let good = fc.next();
        // Source a reports the agreed root but serves a different, self-consistent block for it.
        let mut evil = crate::payload::fake::make(
            Fork::Cancun,
            START + 1,
            good.header.parent_hash,
            good.parent_root,
            "evil",
        );
        evil.root = good.root;
        a.push(&evil);
        b.push(&good);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!chain.contains(&evil.hash), "the hostile block was accepted");
        assert_eq!(chain.head().unwrap().header.number, START, "no two sources agree on content");
        // Once both serve the same block for the root, the head moves.
        a.push(&good);
        for _ in 0..300 {
            if chain.head().unwrap().header.number == START + 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().hash, good.hash);
        task.abort();
    }

    #[tokio::test]
    async fn one_bad_source_does_not_stop_the_fetch_and_is_counted() {
        let a = Fake::start(false, false).await;
        let b = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let first = fc.head().clone();
        for f in [&a, &b] {
            f.push(&first);
            f.finalize(&first);
        }
        anchor.set_anchor_block(&first);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![a.beacon_url(), b.beacon_url()],
            // Quorum 2: the head's parent root is agreed, so a bad answer under it is charged.
            quorum: 2,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let f = Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new()));
        let task = tokio::spawn(f.clone().run());
        for _ in 0..300 {
            if chain.head().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Two blocks between polls: the head's parent comes from a, which corrupts it.
        let (b1, b2) = (fc.next(), fc.next());
        let mut bad = b1.clone();
        bad.json["data"]["message"]["body"]["execution_payload"]["block_hash"] =
            serde_json::json!(crate::payload::fake::hx(&[1u8; 32]));
        a.serve_only(&bad);
        b.serve_only(&b1);
        a.push(&b2);
        b.push(&b2);
        for _ in 0..300 {
            if chain.head().unwrap().header.number == START + 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(chain.head().unwrap().hash, b2.hash, "the other source served the parent");
        assert!(f.source_failures(0) >= 1, "the bad answer is counted against its source");
        assert_eq!(f.source_failures(1), 0);
        task.abort();
    }

    /// Runs `f` on a current-thread runtime under a local recorder, so every series it records
    /// lands in the returned render.
    fn recorded<F: std::future::Future<Output = ()>>(f: impl FnOnce() -> F) -> String {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        metrics::with_local_recorder(&recorder, || rt.block_on(f()));
        handle.render()
    }

    /// An idle follower over `fakes` and `anchor` (its tasks are not started).
    fn idle_follower(
        fakes: &[Fake],
        anchor: &Fake,
        quorum: usize,
    ) -> (Follower, Vec<BeaconClient>) {
        let cfg = FollowConfig {
            urls: fakes.iter().map(Fake::beacon_url).collect(),
            quorum,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            anchor_gap: MIN_ANCHOR_GAP,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let clients = cfg.urls.iter().cloned().map(BeaconClient::new).collect();
        (Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new()), clients)
    }

    fn optimistic(b: &FakeBlock) -> FakeBlock {
        let mut o = b.clone();
        o.json["execution_optimistic"] = serde_json::json!(true);
        o
    }

    #[test]
    fn an_optimistic_beacon_answer_is_unavailable_not_bad() {
        let out = recorded(|| async {
            let mut fakes = Vec::new();
            for _ in 0..3 {
                fakes.push(Fake::start(false, false).await);
            }
            let anchor = Fake::start(false, true).await;
            let b = FakeChain::new(Fork::Cancun, START).head().clone();
            fakes[0].serve_only(&optimistic(&b));
            fakes[1].serve_only(&b);
            fakes[2].serve_only(&b);
            let (f, clients) = idle_follower(&fakes, &anchor, 2);

            let got = f.fetch_head(&clients, &[0, 1, 2], b.root).await;
            assert!(matches!(&got, Fetched::Block(p) if p.block.hash == b.hash));
            // Without a quorum of validated answers the head is unavailable, not disagreed on.
            assert!(matches!(f.fetch_head(&clients, &[0, 1], b.root).await, Fetched::Unavailable));
            let got = f.fetch_block(&clients, &[0, 1], b.root, Some(b.hash), true).await;
            assert!(matches!(&got, Fetched::Block(p) if p.block.hash == b.hash));
            assert!(matches!(
                f.fetch_block(&clients, &[0], b.root, Some(b.hash), true).await,
                Fetched::Unavailable
            ));
            let got = f.pick_head(&clients, &[0, 1], b.root).await;
            assert!(matches!(&got, Ok(p) if p.block.hash == b.hash));
            assert_eq!(f.source_failures(0), 0, "an optimistic source is not charged");
        });
        // The failure series exist from the start, at zero.
        let failures: Vec<_> =
            out.lines().filter(|l| l.starts_with("lite_proof_failures_total{")).collect();
        assert!(failures.len() == 4 && failures.iter().all(|l| l.ends_with(" 0")), "{out}");
        assert!(out.contains("lite_beacon_optimistic_total{source=\"beacon\"} 5"), "{out}");
    }

    #[test]
    fn an_optimistic_anchor_is_unavailable_not_bad() {
        let out = recorded(|| async {
            let beacon = Fake::start(false, false).await;
            let anchor = Fake::start(false, true).await;
            let b = FakeChain::new(Fork::Cancun, START).head().clone();
            anchor.set_anchor_block(&optimistic(&b));
            let (f, clients) = idle_follower(std::slice::from_ref(&beacon), &anchor, 1);
            let anchor_client = BeaconClient::new(anchor.anchor_url());

            f.check_anchor(&anchor_client, &clients, &Notify::new()).await;
            assert!(!f.reseed_forward(&anchor_client, &clients).await);
            // The first seed waits out the optimistic answer and seeds once it is validated.
            let seed = f.seed_from_anchor(&anchor_client, &clients);
            let validate = async {
                while anchor.calls("/eth/v2/beacon/blocks/finalized") < 3 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                anchor.set_anchor_block(&b);
            };
            tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(seed, validate) })
                .await
                .unwrap();
            assert_eq!(f.chain().head().unwrap().hash, b.hash);
        });
        // The failure series exist from the start, at zero.
        let failures: Vec<_> =
            out.lines().filter(|l| l.starts_with("lite_proof_failures_total{")).collect();
        assert!(failures.len() == 4 && failures.iter().all(|l| l.ends_with(" 0")), "{out}");
        assert!(out.contains("lite_beacon_optimistic_total{source=\"anchor\"} 3"), "{out}");
    }

    /// A peer that cannot place a block on its first two queries, takes `slow` over the second,
    /// and holds `block` from the third on.
    #[derive(Debug)]
    struct LatePeer {
        calls: Mutex<u32>,
        slow: Duration,
        block: PeerHeader,
    }

    #[async_trait::async_trait]
    impl HeadConfirm for LatePeer {
        async fn headers_at(&self, _number: u64) -> Vec<Option<PeerHeader>> {
            let call = {
                let mut calls = self.calls.lock();
                *calls += 1;
                *calls
            };
            match call {
                1 => vec![None],
                2 => {
                    tokio::time::sleep(self.slow).await;
                    vec![None]
                }
                _ => vec![Some(self.block)],
            }
        }
    }

    #[tokio::test]
    async fn a_peer_query_due_during_a_block_fetch_does_not_make_the_source_slow() {
        let fakes = [Fake::start(false, false).await, Fake::start(false, false).await];
        let anchor = Fake::start(false, true).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        let mut chain = FakeChain { fork: Fork::Cancun, blocks: vec![fc.head().clone()] };
        let b1 = chain.next();
        // The first source serves a block the peer cannot place yet under the root.
        let mut other = chain.alt(START + 1);
        other.root = b1.root;
        fakes[0].serve_only(&other);
        fakes[1].serve_only(&b1);
        // The second source's answer is in flight when the re-query comes due.
        fakes[1].state.lock().block_delay = CONFIRM_PAUSE + Duration::from_millis(200);
        let peer = Arc::new(LatePeer {
            calls: Mutex::new(0),
            slow: SLOW_ANSWER + Duration::from_millis(500),
            block: PeerHeader { hash: b1.hash, parent_hash: b1.header.parent_hash },
        });
        let (f, clients) = idle_follower(&fakes, &anchor, 1);
        let f = f.with_confirm(peer);
        f.chain.seed(f.held(fc.head()));
        let got = f.pick_head(&clients, &[0, 1], b1.root).await;
        assert!(matches!(&got, Ok(p) if p.block.hash == b1.hash));
        assert_eq!(f.slow.lock()[1], 0, "the source was charged for the peer's pause");
    }

    #[tokio::test]
    async fn a_block_fetch_cut_off_by_a_pick_the_peer_confirmed_does_not_charge_its_source() {
        let fakes = [Fake::start(false, false).await, Fake::start(false, false).await];
        let anchor = Fake::start(false, true).await;
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let b1 = fc.next();
        for fake in &fakes {
            fake.serve_only(&b1);
        }
        // The second source is still answering when a re-query confirms the first one's block,
        // after more than a slow answer's time.
        fakes[1].state.lock().block_delay = HOLD;
        let peer = Arc::new(LatePeer {
            calls: Mutex::new(0),
            slow: SLOW_ANSWER + Duration::from_millis(500),
            block: PeerHeader { hash: b1.hash, parent_hash: b1.header.parent_hash },
        });
        let (f, clients) = idle_follower(&fakes, &anchor, 1);
        let f = f.with_confirm(peer);
        f.chain.seed(f.held(&seed));
        let got = f.pick_head(&clients, &[0, 1], b1.root).await;
        assert!(matches!(&got, Ok(p) if p.block.hash == b1.hash));
        assert_eq!(f.slow.lock()[1], 0, "the source was charged for a request the pick cut off");
    }

    #[test]
    fn an_anchor_that_marks_its_block_not_finalized_is_rejected_not_unreachable() {
        let out = recorded(|| async {
            let beacon = Fake::start(false, false).await;
            let anchor = Fake::start(false, true).await;
            let mut b = FakeChain::new(Fork::Cancun, START).head().clone();
            b.json["finalized"] = serde_json::json!(false);
            anchor.set_anchor_block(&b);
            let (f, clients) = idle_follower(std::slice::from_ref(&beacon), &anchor, 1);
            let anchor_client = BeaconClient::new(anchor.anchor_url());
            f.check_anchor(&anchor_client, &clients, &Notify::new()).await;
            assert!(!f.reseed_forward(&anchor_client, &clients).await);
        });
        assert!(out.contains("\nlite_anchor_unreachable_total 0\n"), "{out}");
        assert!(out.contains("lite_proof_failures_total{source=\"anchor\"} 2"), "{out}");
    }

    #[tokio::test]
    async fn the_beacon_url_key_never_reaches_logs_or_errors() {
        let logs = crate::testing::logs::capture(tracing::Level::TRACE);
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        // A bad block and an unreachable source both log.
        let mut bad = r.fc.next();
        bad.json["data"]["message"]["body"]["execution_payload"]["block_hash"] =
            serde_json::json!(crate::payload::fake::hx(&[1u8; 32]));
        r.beacon.push(&bad);
        let dead = BeaconClient::new(format!("http://127.0.0.1:1{KEY_PATH}").parse().unwrap());
        let err = dead.head_root().await.unwrap_err();
        assert!(!err.to_string().contains("vk_secret"));
        assert!(!format!("{err:?}").contains("vk_secret"));
        assert!(!format!("{dead:?}").contains("vk_secret"));
        tokio::time::sleep(Duration::from_millis(400)).await;
        let text = logs.text();
        assert!(!text.is_empty(), "something was logged");
        assert!(!text.contains("vk_secret"), "{text}");
        assert_eq!(
            trust_label(&FollowConfig {
                urls: vec![format!("https://one.example{KEY_PATH}").parse().unwrap()],
                quorum: 1,
                poll: Duration::ZERO,
                anchor_url: "https://checkpoint.example/".parse().unwrap(),
                recheck: Duration::ZERO,
                sse_retry: Duration::ZERO,
                anchor_gap: MIN_ANCHOR_GAP,
                failed_ttl: Duration::ZERO,
                max_anchor_age: TEST_ANCHOR_AGE,
                forks: crate::payload::fake::forks(Fork::Cancun),
            }),
            "follows https://one.example; finalized checked against https://checkpoint.example"
        );
    }

    #[tokio::test]
    async fn an_anchor_mismatch_over_a_behind_halt_is_logged() {
        let logs = crate::testing::logs::capture(tracing::Level::ERROR);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let blocks: Vec<_> = (0..3).map(|_| fc.next()).collect();
        let anchor = Fake::start(false, true).await;
        let mut cfg = follow_cfg(vec![]);
        cfg.anchor_url = anchor.anchor_url();
        let f = Follower::new(cfg, Arc::new(HeaderChain::new()), LiteMetrics::new());
        f.chain.seed(f.held(&fc.blocks[0]));
        for b in &blocks {
            f.chain.insert(f.held(b)).unwrap();
        }
        f.chain.set_head(blocks[2].hash).unwrap();
        // A forged fork held the node below the anchor; the anchor now disagrees at a held block.
        f.set_halt(&mut f.halt.lock(), Some(Halt::Behind(START + 9)));
        anchor.set_anchor_block(&fc.alt(START + 1));
        let client = BeaconClient::new(anchor.anchor_url());
        f.check_anchor(&client, &[], &Notify::new()).await;
        assert_eq!(f.chain.halt_reason(), Some(HaltReason::AnchorMismatch));
        let mismatch = "finalized anchor disagrees with the held chain and no confirmation source";
        let text = || logs.text();
        assert_eq!(text().matches(mismatch).count(), 1, "{}", text());
        // The same mismatch again is not a new line.
        f.check_anchor(&client, &[], &Notify::new()).await;
        assert_eq!(text().matches(mismatch).count(), 1, "{}", text());
    }

    #[tokio::test]
    async fn a_halt_only_a_restart_clears_says_so_once() {
        let logs = crate::testing::logs::capture(tracing::Level::ERROR);
        let (source, anchor) = (Fake::start(false, false).await, Fake::start(false, true).await);
        let mut fc = FakeChain::new(Fork::Cancun, START);
        let seed = fc.head().clone();
        let blocks: Vec<_> = (0..MAX_ANCESTORS + 10).map(|_| fc.next()).collect();
        let far = &blocks[MAX_ANCESTORS + 2..];
        for b in far {
            source.serve_only(b);
        }
        anchor.set_anchor_block(&far[0]);
        let (f, reports, _tasks) = halted_rig(&source, &anchor, MIN_ANCHOR_GAP, &seed);
        let restart = "only an operator restart clears the halt";
        let text = || logs.text();
        let send = async |b: &FakeBlock| {
            reports.send(0, b.root);
            wait_until("the head block", || block_calls(&source, b.root) == 1).await;
        };
        // Unhalted, the first gap halts on the anchor; the gaps after it are out of reach too.
        for b in &far[..4] {
            send(b).await;
        }
        assert_eq!(f.chain.halt_reason(), Some(HaltReason::BehindAnchor));
        assert_eq!(text().matches(restart).count(), 1, "{}", text());
        // A halt cleared and set again is a new line.
        f.set_halt(&mut f.halt.lock(), None);
        for b in &far[4..] {
            send(b).await;
        }
        assert_eq!(text().matches(restart).count(), 2, "{}", text());
    }

    #[tokio::test]
    async fn a_key_in_the_query_string_is_sent_with_every_request() {
        let beacon = Fake::start(true, false).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        beacon.push(fc.head());
        beacon.finalize(fc.head());
        beacon.state.lock().require_query = Some("apikey=K1".into());
        let mut url = beacon.beacon_url();
        url.set_query(Some("apikey=K1"));
        let client = BeaconClient::new(url);
        assert_eq!(client.head_root().await, Ok(fc.head().root));
        assert_eq!(client.finalized_root().await, Ok(fc.head().root));
        assert!(client.block(&format!("{:#x}", fc.head().root)).await.is_ok());
        assert!(client.events(Duration::from_secs(2)).await.is_ok());
    }

    #[tokio::test]
    async fn a_failing_source_is_logged_once_not_on_every_poll() {
        let logs = crate::testing::logs::capture(tracing::Level::TRACE);
        let mut r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let text = || logs.text();
        let head_failed = r#"request failed source="http://127.0.0.1" request="headers/head" error=http status 403"#;
        // Every request is refused for about ten polls: one line, not one per poll.
        r.beacon.state.lock().require_query = Some("apikey=K1".into());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(text().matches(head_failed).count(), 1, "{}", text());
        // It recovers, and failing again is a new line.
        r.beacon.state.lock().require_query = None;
        let b = r.fc.next();
        r.beacon.push(&b);
        r.wait_head(START + 1).await;
        r.beacon.state.lock().require_query = Some("apikey=K1".into());
        wait_until("the second failure line", || text().matches(head_failed).count() == 2).await;
        assert!(!text().contains("vk_secret"));
    }

    #[tokio::test]
    async fn a_source_that_refuses_only_finality_checkpoints_is_logged_once() {
        let logs = crate::testing::logs::capture(tracing::Level::TRACE);
        let r = Rig::start(false, Fork::Cancun, 50).await;
        r.wait_head(START).await;
        let text = || logs.text();
        // headers/head still answers; finality_checkpoints answers 404 from now on.
        r.beacon.state.lock().finalized = None;
        let reads = r.beacon.calls("/eth/v1/beacon/states/head/finality_checkpoints");
        wait_until("three refused finality reads", || {
            r.beacon.calls("/eth/v1/beacon/states/head/finality_checkpoints") >= reads + 3
        })
        .await;
        let failed = r#"request failed source="http://127.0.0.1" request="finality_checkpoints" error=http status 404"#;
        assert_eq!(text().matches(failed).count(), 1, "{}", text());
        assert_eq!(text().matches("beacon source request failed").count(), 1, "{}", text());
        assert_eq!(text().matches("beacon source answers again").count(), 0, "{}", text());
    }

    #[test]
    fn a_host_label_masks_all_but_the_last_two_domain_labels() {
        let label = |u: &str| host_label(&u.parse().unwrap());
        assert_eq!(label("https://vk_token.eu.provider.example/k"), "https://*.provider.example");
        assert_eq!(label("https://provider.example/k"), "https://provider.example");
        assert_eq!(label("http://localhost:5052"), "http://localhost");
        assert_eq!(label("http://10.0.0.7:5052"), "http://10.0.0.7");
        assert_eq!(label("http://[::1]:5052"), "http://[::1]");
    }

    #[test]
    fn note_answer_reports_only_changes() {
        let mut failing = false;
        assert_eq!(
            note_answer(&mut failing, "r", "h", Err::<u8, _>(SourceError::Status(429))),
            None
        );
        assert!(failing);
        assert_eq!(note_answer(&mut failing, "r", "h", Err::<u8, _>(SourceError::Timeout)), None);
        assert!(failing);
        assert_eq!(note_answer(&mut failing, "r", "h", Ok(7)), Some(7));
        assert!(!failing);
        assert_eq!(note_answer(&mut failing, "r", "h", Ok(8)), Some(8));
        assert!(!failing);
    }

    #[tokio::test]
    async fn an_event_stream_that_sends_no_headers_times_out() {
        // Accepts, reads the request, and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _open = sock;
                    std::future::pending::<()>().await;
                });
            }
        });
        let client = BeaconClient::new(format!("http://{addr}").parse().unwrap());
        let res =
            tokio::time::timeout(Duration::from_secs(3), client.events(Duration::from_millis(200)))
                .await
                .expect("events() waited past its idle bound for the response headers");
        assert_eq!(res.err(), Some(SourceError::Timeout));
    }

    /// Serves one JSON body per connection: `pad` bytes of padding inside a valid head answer.
    async fn padded_server(pad: usize, with_length: bool) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let root = crate::payload::fake::hx(&[0x11u8; 32]);
                    let body = format!(
                        "{{\"data\":{{\"root\":\"{root}\"}},\"pad\":\"{}\"}}",
                        "x".repeat(pad)
                    );
                    let len = if with_length {
                        format!("Content-Length: {}\r\n", body.len())
                    } else {
                        String::new()
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{len}Connection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}").parse().unwrap()
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = padded_server(10, true).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let to = target.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {to}eth/v1/beacon/headers/head\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        let c = BeaconClient::new(format!("http://{addr}").parse().unwrap());
        assert_eq!(c.head_root().await, Err(SourceError::Status(302)));
    }

    #[tokio::test]
    async fn a_head_body_over_the_small_limit_is_aborted() {
        for with_length in [true, false] {
            let small = BeaconClient::new(padded_server(1024, with_length).await);
            assert_eq!(small.head_root().await, Ok(B256::repeat_byte(0x11)));
            let big = BeaconClient::new(padded_server(17 << 20, with_length).await);
            assert_eq!(big.head_root().await, Err(SourceError::TooLarge), "length {with_length}");
        }
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_limit_is_read_and_one_byte_more_is_refused() {
        // `padded_server`'s body without padding.
        let overhead =
            format!("{{\"data\":{{\"root\":\"0x{}\"}},\"pad\":\"\"}}", "11".repeat(32)).len();
        for with_length in [true, false] {
            for limit in [MAX_SMALL_BODY, MAX_BEACON_BODY] {
                let at = BeaconClient::new(padded_server(limit - overhead, with_length).await);
                let got = at
                    .get_json(
                        "/eth/v1/beacon/headers/head",
                        limit,
                        SMALL_TIMEOUT,
                        BLOCK_TIMEOUT,
                        &HEAD_SHAPE,
                    )
                    .await;
                assert_eq!(root_at(&got.unwrap(), &["data", "root"]), Ok(B256::repeat_byte(0x11)));
                let over =
                    BeaconClient::new(padded_server(limit + 1 - overhead, with_length).await);
                let got = over
                    .get_json(
                        "/eth/v1/beacon/headers/head",
                        limit,
                        SMALL_TIMEOUT,
                        BLOCK_TIMEOUT,
                        &HEAD_SHAPE,
                    )
                    .await;
                assert_eq!(got, Err(SourceError::TooLarge), "limit {limit}, length {with_length}");
            }
        }
    }

    /// Serves `body` with a length on every connection.
    async fn body_server(body: String) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = Arc::new(body);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}").parse().unwrap()
    }

    /// A Shanghai block at the 45M gas limit, full of transactions with zero calldata (4 gas a
    /// byte, no EIP-7623 floor): about 10 MiB of transaction bytes, twice that as JSON hex.
    fn calldata_stuffed_block() -> FakeBlock {
        use alloy_consensus::{Signed, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        const CALLDATA: usize = 128 << 10;
        let tx = TxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                gas_limit: 21_000 + 4 * CALLDATA as u64,
                input: vec![0u8; CALLDATA].into(),
                ..Default::default()
            },
            alloy_primitives::Signature::test_signature(),
        ))
        .encoded_2718();
        let raw = vec![tx; 80];
        let mut b = crate::payload::fake::make(Fork::Shanghai, 7, B256::ZERO, B256::ZERO, "");
        b.header.gas_limit = 45_000_000;
        b.header.transactions_root = alloy_consensus::proofs::ordered_trie_root_encoded(&raw);
        b.hash = b.header.hash_slow();
        let p = &mut b.json["data"]["message"]["body"]["execution_payload"];
        p["gas_limit"] = serde_json::json!("45000000");
        p["block_hash"] = serde_json::json!(crate::payload::fake::hx(b.hash.as_slice()));
        p["transactions"] =
            raw.iter().map(|t| crate::payload::fake::hx(t)).collect::<Vec<_>>().into();
        b
    }

    #[tokio::test]
    async fn a_block_full_of_zero_calldata_at_the_gas_limit_is_read() {
        let b = calldata_stuffed_block();
        let body = b.json.to_string();
        assert!(body.len() > 20 << 20, "the block answer is only {} bytes", body.len());
        let c = BeaconClient::new(body_server(body).await);
        let v = c.block(&format!("{:#x}", b.root)).await.unwrap();
        let p = parse_beacon_block(&v, b.root, &crate::payload::fake::forks(Fork::Shanghai));
        assert_eq!(p.unwrap().block.hash, b.hash);
    }

    /// Serves `body` with a length, in `parts` pieces with `gap` between them.
    async fn trickle_server(body: String, parts: usize, gap: Duration) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            for (k, part) in body.as_bytes().chunks(body.len().div_ceil(parts)).enumerate() {
                if k > 0 {
                    tokio::time::sleep(gap).await;
                }
                let _ = sock.write_all(part).await;
            }
            std::future::pending::<()>().await;
        });
        format!("http://{addr}").parse().unwrap()
    }

    #[tokio::test]
    async fn a_large_block_answer_that_keeps_coming_is_read_past_the_small_answer_timeout() {
        // 8 MiB in four parts with three 4 s pauses: 12 s in all, over the 10 s bound of a small
        // answer, at more than the minimum rate, while no read waits for the 10 s idle bound.
        let b = crate::payload::fake::make(Fork::Shanghai, 7, B256::ZERO, B256::ZERO, "");
        let mut padded = b.json.clone();
        padded["pad"] = serde_json::json!("x".repeat(8 << 20));
        let c =
            BeaconClient::new(trickle_server(padded.to_string(), 4, Duration::from_secs(4)).await);
        let started = Instant::now();
        let v = c.block(&format!("{:#x}", b.root)).await.unwrap();
        assert!(started.elapsed() > SMALL_TIMEOUT, "{:?}", started.elapsed());
        let p = parse_beacon_block(&v, b.root, &crate::payload::fake::forks(Fork::Shanghai));
        assert_eq!(p.unwrap().block.hash, b.hash);
    }

    #[tokio::test]
    async fn a_block_answer_that_trickles_below_the_minimum_rate_ends_at_the_small_answer_bound() {
        // A few KiB in 15 parts a second apart: no read waits for the idle bound, and the
        // answer would end after 14 s.
        let b = crate::payload::fake::make(Fork::Shanghai, 7, B256::ZERO, B256::ZERO, "");
        let c =
            BeaconClient::new(trickle_server(b.json.to_string(), 15, Duration::from_secs(1)).await);
        let started = Instant::now();
        assert_eq!(c.block(&format!("{:#x}", b.root)).await, Err(SourceError::Timeout));
        let took = started.elapsed();
        assert!(took >= SMALL_TIMEOUT && took < SMALL_TIMEOUT + Duration::from_secs(2), "{took:?}");
    }

    #[tokio::test]
    async fn a_block_answer_that_stalls_times_out() {
        let b = crate::payload::fake::make(Fork::Shanghai, 7, B256::ZERO, B256::ZERO, "");
        let c =
            BeaconClient::new(trickle_server(b.json.to_string(), 2, Duration::from_secs(30)).await);
        let started = Instant::now();
        assert_eq!(c.block(&format!("{:#x}", b.root)).await, Err(SourceError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(15), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_head_or_finality_answer_over_64_kib_is_aborted() {
        let big = BeaconClient::new(padded_server(MAX_SMALL_BODY, true).await);
        assert_eq!(big.head_root().await, Err(SourceError::TooLarge));
        assert_eq!(big.finalized_root().await, Err(SourceError::TooLarge));
        let small = BeaconClient::new(padded_server(MAX_SMALL_BODY - 200, true).await);
        assert_eq!(small.head_root().await, Ok(B256::repeat_byte(0x11)));
    }

    #[tokio::test]
    async fn fields_a_block_answer_does_not_need_are_skipped_not_built() {
        let b = crate::payload::fake::make(Fork::Prague, 7, B256::ZERO, B256::ZERO, "");
        let mut padded = b.json.clone();
        // A body of one-entry maps is what makes a parsed `Value` cost about 100x its size.
        let junk = serde_json::Value::Array(vec![serde_json::json!({"": 0}); 100_000]);
        padded["pad"] = junk.clone();
        padded["data"]["message"]["body"]["pad"] = junk.clone();
        padded["data"]["message"]["body"]["execution_payload"]["pad"] = junk;
        let c = BeaconClient::new(body_server(padded.to_string()).await);
        let got = c.block("finalized").await.unwrap();
        assert_eq!(got.get("pad"), None);
        assert_eq!(got["data"]["message"]["body"].get("pad"), None);
        assert_eq!(got["data"]["message"]["body"]["execution_payload"].get("pad"), None);
        let forks = crate::payload::fake::forks(Fork::Prague);
        assert_eq!(parse_beacon_block(&got, b.root, &forks).unwrap().block.hash, b.hash);
        // A field the parser reads keeps its JSON type, so a wrong one is still a payload error.
        let mut null_field = b.json.clone();
        null_field["data"]["message"]["body"]["execution_payload"]["gas_used"] =
            serde_json::Value::Null;
        let c = BeaconClient::new(body_server(null_field.to_string()).await);
        let got = c.block("finalized").await.unwrap();
        assert_eq!(
            parse_beacon_block(&got, b.root, &forks).unwrap_err(),
            PayloadError::Malformed("gas_used")
        );
    }

    #[tokio::test]
    async fn a_block_answer_with_a_list_over_its_cap_is_refused() {
        let b = crate::payload::fake::make(Fork::Cancun, 7, B256::ZERO, B256::ZERO, "");
        let payload = |j: &mut serde_json::Value| -> serde_json::Value {
            j["data"]["message"]["body"]["execution_payload"].take()
        };
        let withdrawal = serde_json::json!({
            "index": "0", "validator_index": "0", "address": crate::payload::fake::hx(&[0u8; 20]), "amount": "0"
        });
        for (key, cap, item) in [
            ("transactions", MAX_TRANSACTIONS, serde_json::json!("0x")),
            ("withdrawals", MAX_WITHDRAWALS, withdrawal),
        ] {
            for (n, ok) in [(cap, true), (cap + 1, false)] {
                let mut j = b.json.clone();
                let mut p = payload(&mut j);
                p[key] = serde_json::Value::Array(vec![item.clone(); n]);
                j["data"]["message"]["body"]["execution_payload"] = p;
                let c = BeaconClient::new(body_server(j.to_string()).await);
                let got = c.block("finalized").await;
                assert_eq!(got.is_ok(), ok, "{key} x{n}: {:?}", got.as_ref().err());
                if !ok {
                    assert_eq!(got, Err(SourceError::Body));
                }
            }
        }
        // A list where a scalar belongs is not the API's shape either.
        let mut j = b.json.clone();
        j["data"]["message"]["parent_root"] = serde_json::json!([{"": 0}]);
        let c = BeaconClient::new(body_server(j.to_string()).await);
        assert_eq!(c.block("finalized").await, Err(SourceError::Body));
    }

    #[tokio::test]
    async fn optimistic_answers_are_refused() {
        let b = crate::payload::fake::make(Fork::Cancun, 7, B256::ZERO, B256::ZERO, "");
        let mut j = b.json.clone();
        j["execution_optimistic"] = serde_json::json!(true);
        let c = BeaconClient::new(body_server(j.to_string()).await);
        let v = c.block("finalized").await.unwrap();
        let forks = crate::payload::fake::forks(Fork::Cancun);
        assert!(matches!(parse_beacon_block(&v, b.root, &forks), Err(PayloadError::Optimistic)));
        let root = crate::payload::fake::hx(&[0x11u8; 32]);
        let head = format!("{{\"execution_optimistic\":true,\"data\":{{\"root\":\"{root}\"}}}}");
        let c = BeaconClient::new(body_server(head).await);
        assert_eq!(c.head_root().await, Err(SourceError::Optimistic));
        // Positive controls: the same answers marked validated are taken.
        j["execution_optimistic"] = serde_json::json!(false);
        let c = BeaconClient::new(body_server(j.to_string()).await);
        assert!(c.block("finalized").await.is_ok());
        let head = format!("{{\"execution_optimistic\":false,\"data\":{{\"root\":\"{root}\"}}}}");
        let c = BeaconClient::new(body_server(head).await);
        assert_eq!(c.head_root().await, Ok(B256::repeat_byte(0x11)));
    }

    #[tokio::test]
    async fn a_head_with_a_non_bool_optimistic_flag_is_refused_as_a_block_is() {
        let root = crate::payload::fake::hx(&[0x11u8; 32]);
        for flag in ["\"true\"", "1", "null"] {
            let head =
                format!("{{\"execution_optimistic\":{flag},\"data\":{{\"root\":\"{root}\"}}}}");
            let c = BeaconClient::new(body_server(head).await);
            assert_eq!(c.head_root().await, Err(SourceError::Body), "flag {flag}");
            let event = format!(
                "event: head\ndata: {{\"block\":\"{root}\",\"execution_optimistic\":{flag}}}\n\n"
            );
            assert_eq!(parse_sse_block(&event, Topics::Head), None, "flag {flag}");
        }
        // Positive control: with no flag the head is taken.
        let event = format!("event: head\ndata: {{\"block\":\"{root}\"}}\n\n");
        assert_eq!(
            parse_sse_block(&event, Topics::Head),
            Some(Event::Head(B256::repeat_byte(0x11)))
        );
    }

    #[tokio::test]
    async fn an_optimistic_head_is_not_followed_without_a_confirming_peer() {
        for sse in [true, false] {
            let mut r = Rig::start(sse, Fork::Cancun, 50).await;
            r.wait_head(START).await;
            let mut b = r.fc.next();
            b.json["execution_optimistic"] = serde_json::json!(true);
            r.beacon.state.lock().optimistic = true;
            r.beacon.push(&b);
            r.stays(START, 400).await;
            // Once the source has validated it, the same block is followed.
            b.json["execution_optimistic"] = serde_json::json!(false);
            r.beacon.state.lock().optimistic = false;
            r.beacon.push(&b);
            r.wait_head(START + 1).await;
        }
    }

    #[tokio::test]
    async fn an_anchor_the_source_says_is_not_finalized_is_not_seeded() {
        let beacon = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let fc = FakeChain::new(Fork::Cancun, START);
        beacon.push(fc.head());
        let mut b = fc.head().clone();
        b.json["finalized"] = serde_json::json!(false);
        anchor.set_anchor_block(&b);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![beacon.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_secs(60),
            sse_retry: Duration::from_secs(60),
            anchor_gap: MIN_ANCHOR_GAP,
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: crate::payload::fake::forks(Fork::Cancun),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(chain.head().is_none(), "an anchor marked not finalized was seeded");
        b.json["finalized"] = serde_json::json!(true);
        anchor.set_anchor_block(&b);
        wait_until("the seed", || chain.head().is_some()).await;
        task.abort();
    }

    /// An event stream over `chunks`, counting how many were read.
    fn stream_of(chunks: Vec<Vec<u8>>) -> (EventStream, Arc<std::sync::atomic::AtomicUsize>) {
        let read = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = read.clone();
        let inner = futures::stream::iter(chunks).map(move |c| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(bytes::Bytes::from(c))
        });
        let stream = EventStream {
            inner: Box::pin(inner),
            topics: Topics::Head,
            buf: Vec::new(),
            start: 0,
            scanned: 0,
            after_cr: false,
            idle: Duration::from_secs(5),
            last_data: tokio::time::Instant::now(),
        };
        (stream, read)
    }

    #[tokio::test]
    async fn an_event_stream_with_no_event_end_stops_at_the_event_cap() {
        let (mut events, read) = stream_of(vec![vec![b'a'; 1024]; 2048]);
        assert_eq!(events.next_event().await, None);
        let read = read.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(read, MAX_SSE_EVENT / 1024 + 1, "{read} KiB read before the stream ended");
    }

    #[tokio::test]
    async fn a_burst_of_small_events_past_the_cap_in_one_chunk_is_all_read() {
        // Over 64 KiB of honest head events, as a source that sends a backlog at once may
        // deliver them: the cap bounds one event, not one read.
        let root = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let one = format!("event: head\ndata: {{\"block\":\"{root}\"}}\n\n");
        let n = MAX_SSE_EVENT / one.len() + 10;
        let text = one.repeat(n).into_bytes();
        let want = vec![Event::Head(B256::repeat_byte(0x22)); n];
        assert_eq!(read_all(vec![text.clone()]).await, want, "one chunk");
        assert_eq!(read_all(text.chunks(100_000).map(<[u8]>::to_vec).collect()).await, want);
        // One event longer than the cap still ends the stream, however it arrives.
        let long = format!("event: head\ndata: {}\n\n", " ".repeat(MAX_SSE_EVENT)).into_bytes();
        let text = [one.as_bytes(), &long, one.as_bytes()].concat();
        let first = vec![Event::Head(B256::repeat_byte(0x22))];
        assert_eq!(read_all(vec![text.clone()]).await, first, "one chunk");
        assert_eq!(read_all(text.iter().map(|b| vec![*b]).collect()).await, first, "bytewise");
    }

    #[tokio::test]
    async fn events_split_across_chunks_and_many_in_one_chunk_are_all_read() {
        let root = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let head = format!("event: head\r\ndata: {{\"block\":\"{root}\"}}\r\n\r\n");
        // One event cut inside its last CRLF, then 100 events and a cut event in one chunk.
        let (a, b) = head.split_at(head.len() - 1);
        let mut many = head.repeat(100);
        many.push_str("event: finalized_checkpoint\ndata: {}\n");
        let (mut events, _) =
            stream_of(vec![a.into(), b.into(), many.into_bytes(), b"\n".to_vec()]);
        for _ in 0..101 {
            assert_eq!(events.next_event().await, Some(Event::Head(B256::repeat_byte(0x11))));
        }
        assert_eq!(events.next_event().await, Some(Event::Finalized));
        assert_eq!(events.next_event().await, None);
    }

    /// Events with LF, CRLF and bare CR line ends, and the events they hold.
    fn mixed_line_ends() -> (Vec<u8>, Vec<Event>) {
        let root = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let head = |eol: &str| format!("event: head{eol}data: {{\"block\":\"{root}\"}}{eol}{eol}");
        let fin = "event: finalized_checkpoint\rdata: {}\r\r";
        let s = [head("\n"), head("\r\n"), head("\r"), fin.to_owned(), head("\r\n")].concat();
        let head = Event::Head(B256::repeat_byte(0x11));
        (s.into_bytes(), vec![head.clone(), head.clone(), head.clone(), Event::Finalized, head])
    }

    async fn read_all(chunks: Vec<Vec<u8>>) -> Vec<Event> {
        let (mut events, _) = stream_of(chunks);
        let mut out = vec![];
        while let Some(e) = events.next_event().await {
            out.push(e);
        }
        out
    }

    #[tokio::test]
    async fn every_two_way_split_of_mixed_line_ends_reads_every_event() {
        let (s, want) = mixed_line_ends();
        for at in 0..=s.len() {
            let (a, b) = s.split_at(at);
            assert_eq!(read_all(vec![a.to_vec(), b.to_vec()]).await, want, "split at {at}");
        }
    }

    proptest::proptest! {
        #[test]
        fn any_split_of_mixed_line_ends_reads_every_event(
            mut cuts in proptest::collection::vec(0usize..=200, 0..12)
        ) {
            let (s, want) = mixed_line_ends();
            for c in &mut cuts {
                *c = (*c).min(s.len());
            }
            cuts.sort_unstable();
            let mut chunks = vec![];
            let mut from = 0;
            for c in cuts.into_iter().chain([s.len()]) {
                chunks.push(s[from..c].to_vec());
                from = c;
            }
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            proptest::prop_assert_eq!(rt.block_on(read_all(chunks)), want);
        }
    }

    /// One generated event-stream entry.
    #[derive(Debug, Clone)]
    enum SseEntry {
        /// A head event; `split` puts the root on a second data line, `note` adds a field with
        /// multi-byte UTF-8.
        Head {
            root: [u8; 32],
            split: bool,
            note: bool,
        },
        Finalized,
        /// An event the follower does not read.
        Other,
        /// A comment block.
        Comment,
    }

    fn sse_entry() -> impl proptest::strategy::Strategy<Value = SseEntry> {
        use proptest::prelude::*;
        prop_oneof![
            4 => (any::<[u8; 32]>(), any::<bool>(), any::<bool>())
                .prop_map(|(root, split, note)| SseEntry::Head { root, split, note }),
            1 => Just(SseEntry::Finalized),
            1 => Just(SseEntry::Other),
            1 => Just(SseEntry::Comment),
        ]
    }

    /// The stream text of `entries`, each with its own line end, and the events it holds.
    fn render_sse(entries: &[(SseEntry, usize)]) -> (Vec<u8>, Vec<Event>) {
        let (mut text, mut want) = (String::new(), vec![]);
        for (entry, eol) in entries {
            let e = ["\n", "\r\n", "\r"][*eol];
            match entry {
                SseEntry::Head { root, split, note } => {
                    let hex = crate::payload::fake::hx(root);
                    let sep = if *split { format!("{e}data: ") } else { String::new() };
                    let note = if *note { ",\"note\":\"h\u{e9}ad \u{2192} \u{20ac}\"" } else { "" };
                    text +=
                        &format!("event: head{e}data: {{\"block\":{sep}\"{hex}\"{note}}}{e}{e}");
                    want.push(Event::Head(B256::from(*root)));
                }
                SseEntry::Finalized => {
                    text += &format!("event: finalized_checkpoint{e}data: {{}}{e}{e}");
                    want.push(Event::Finalized);
                }
                SseEntry::Other => text += &format!("event: block{e}data: {{}}{e}{e}"),
                SseEntry::Comment => text += &format!(": ping{e}{e}"),
            }
        }
        (text.into_bytes(), want)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        #[test]
        fn any_split_of_any_event_stream_reads_the_same_events(
            entries in proptest::collection::vec((sse_entry(), 0usize..3), 0..12),
            mut cuts in proptest::collection::vec(proptest::num::usize::ANY, 0..16),
            bytewise in proptest::bool::weighted(0.2),
        ) {
            let (s, want) = render_sse(&entries);
            let chunks: Vec<Vec<u8>> = if bytewise {
                s.iter().map(|b| vec![*b]).collect()
            } else {
                for c in &mut cuts {
                    *c %= s.len() + 1;
                }
                cuts.sort_unstable();
                let mut from = 0;
                cuts.into_iter()
                    .chain([s.len()])
                    .map(|c| {
                        let chunk = s[from..c].to_vec();
                        from = c;
                        chunk
                    })
                    .collect()
            };
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            proptest::prop_assert_eq!(rt.block_on(read_all(chunks)), want);
        }

        #[test]
        fn an_sse_block_is_a_head_only_with_a_32_byte_hex_root(
            name in proptest::prop_oneof![3 => "head", 1 => "finalized_checkpoint", 1 => "\\PC{0,12}"],
            root in proptest::prop_oneof![3 => "(0x)?[0-9a-fA-F]{64}", 1 => "(0x)?[0-9a-fA-F]{0,70}"],
            optimistic in proptest::option::of(proptest::bool::ANY),
            junk in "\\PC{0,40}",
            raw in proptest::bool::weighted(0.3),
        ) {
            let flag = optimistic.map_or(String::new(), |o| format!(",\"execution_optimistic\":{o}"));
            let block = if raw {
                format!("event: {name}\ndata: {junk}\n\n")
            } else {
                format!("event: {name}\ndata: {{\"block\":\"{root}\"{flag}}}\n\n")
            };
            let digits = root.strip_prefix("0x").unwrap_or(&root);
            let want = if name.trim() == "finalized_checkpoint" {
                Some(Event::Finalized)
            } else if name.trim() == "head" && !raw && digits.len() == 64 && optimistic != Some(true) {
                Some(Event::Head(digits.parse().unwrap()))
            } else {
                None
            };
            let got = parse_sse_block(&block, Topics::Head);
            if raw && name.trim() == "head" {
                // Arbitrary data: no panic, and a head only from a 32-byte hex root in it.
                if let Some(Event::Head(r)) = got {
                    proptest::prop_assert!(
                        junk.to_lowercase().contains(&alloy_primitives::hex::encode(r)),
                        "a head root that is not in the data"
                    );
                }
            } else {
                proptest::prop_assert_eq!(got, want);
            }
        }

        #[test]
        fn shape_parsing_keeps_exactly_the_named_fields(
            v in json_value(),
            items in proptest::collection::vec(json_leaf(), 0..6),
        ) {
            // `items` also as the capped list.
            for v in [v, serde_json::json!({ "l": items })] {
                let text = serde_json::to_vec(&v).unwrap();
                for shape in [&HEAD_SHAPE, &FINALITY_SHAPE, &SSE_HEAD_SHAPE, &TEST_SHAPE] {
                    proptest::prop_assert_eq!(shape.parse(&text).ok(), project(&v, shape));
                }
            }
        }

        #[test]
        fn shape_parsing_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
            v in json_value(),
            at in proptest::num::usize::ANY,
            byte in proptest::num::u8::ANY,
        ) {
            // Raw bytes, and a valid answer with one byte changed.
            let mut near = serde_json::to_vec(&v).unwrap();
            let i = at % near.len();
            near[i] = byte;
            for input in [&bytes, &near] {
                for shape in [&HEAD_SHAPE, &FINALITY_SHAPE, &SSE_HEAD_SHAPE, &BLOCK_SHAPE, &TEST_SHAPE] {
                    if let Ok(v) = shape.parse(input) &&
                        let Ok(r) = root_at(&v, &["data", "root"])
                    {
                        let text = v["data"]["root"].as_str().unwrap_or_default();
                        proptest::prop_assert_eq!(text.parse::<B256>().ok(), Some(r));
                    }
                }
            }
        }
    }

    /// A shape with a capped list, for the parsing properties.
    static TEST_SHAPE: Shape = Object(&[
        ("data", Object(&[("root", Scalar)])),
        ("l", List(&Scalar, 3)),
        ("block", Scalar),
    ]);

    /// What [`Shape::parse`] should build from `v`: only the named keys, and `None` where `v`
    /// does not fit the shape.
    fn project(v: &Value, shape: &Shape) -> Option<Value> {
        match (shape, v) {
            (Scalar, Value::Array(_) | Value::Object(_)) => None,
            (Scalar, v) => Some(v.clone()),
            (List(item, max), Value::Array(items)) if items.len() <= *max => {
                items.iter().map(|i| project(i, item)).collect::<Option<Vec<_>>>().map(Value::Array)
            }
            (Object(fields), Value::Object(map)) => {
                let mut out = serde_json::Map::new();
                for (k, val) in map {
                    if let Some((_, s)) = fields.iter().find(|(name, _)| name == k) {
                        out.insert(k.clone(), project(val, s)?);
                    }
                }
                Some(Value::Object(out))
            }
            _ => None,
        }
    }

    /// JSON scalars.
    fn json_leaf() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            any::<u64>().prop_map(Value::from),
            // Quarters print and parse back exactly.
            (-4000i32..4000).prop_map(|q| Value::from(f64::from(q) / 4.0)),
            "(0x)?[0-9a-f]{0,66}|\\PC{0,8}".prop_map(Value::String),
        ]
    }

    /// JSON values whose keys are mostly ones the shapes name.
    fn json_value() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let key = prop_oneof![
            Just("data".to_owned()),
            Just("root".to_owned()),
            Just("l".to_owned()),
            Just("block".to_owned()),
            Just("finalized".to_owned()),
            Just("execution_optimistic".to_owned()),
            "\\PC{0,6}",
        ];
        json_leaf().prop_recursive(4, 48, 6, move |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                proptest::collection::btree_map(key.clone(), inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    #[test]
    fn sse_data_lines_join_with_a_line_feed() {
        let root = "0x1111111111111111111111111111111111111111111111111111111111111111";
        // Split between tokens, the JSON parses either way.
        let split = format!("event: head\ndata: {{\"block\":\ndata: \"{root}\"}}\n\n");
        assert_eq!(
            parse_sse_block(&split, Topics::Head),
            Some(Event::Head(B256::repeat_byte(0x11)))
        );
        // Joined without a line feed, `1` and `2` would read as the number 12.
        let number = format!("event: head\ndata: {{\"block\":\"{root}\",\"n\":1\ndata: 2}}\n\n");
        assert_eq!(parse_sse_block(&number, Topics::Head), None);
    }

    #[test]
    fn a_zero_poll_or_recheck_is_raised_to_the_floor() {
        // The CLI refuses these values; the floor guards a config built in code.
        let follow = |poll: Duration, recheck: Duration| {
            let cfg = FollowConfig::from(&LiteConfig {
                beacon_poll: poll,
                anchor_recheck: recheck,
                ..Default::default()
            });
            (cfg.poll, cfg.recheck)
        };
        assert_eq!(follow(Duration::ZERO, Duration::ZERO), (MIN_POLL, MIN_POLL));
        let (poll, recheck) = (Duration::from_millis(500), Duration::from_secs(2));
        assert_eq!(follow(poll, recheck), (poll, recheck));
    }

    #[test]
    fn sse_blocks_parse() {
        let head = "event: head\ndata: {\"block\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}\n\n";
        assert_eq!(parse_sse_block(head, Topics::Head), Some(Event::Head(B256::repeat_byte(0x11))));
        let optimistic = "event: head\ndata: {\"block\":\"0x1111111111111111111111111111111111111111111111111111111111111111\",\"execution_optimistic\":true}\n\n";
        assert_eq!(parse_sse_block(optimistic, Topics::Head), None);
        assert_eq!(
            parse_sse_block("event: finalized_checkpoint\ndata: {}\n\n", Topics::Head),
            Some(Event::Finalized)
        );
        assert_eq!(parse_sse_block(": connected\n\n", Topics::Head), None);
        assert_eq!(parse_sse_block("event: head\ndata: not json\n\n", Topics::Head), None);
    }
}
