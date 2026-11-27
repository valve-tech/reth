//! The bounded clients of the server's upstreams.
//!
//! [`Upstream`] is one base URL: the state URL (`--state.url`) or one beacon URL
//! (`--beacon.url`). Every request has a body limit and a deadline, and no request follows a
//! redirect. [`Beacons`] asks the beacon URLs in order, and the first good answer wins.

use alloy_primitives::B256;
use reth_pulsechain_forks::network::PulsechainBeacon;
use reth_pulsechain_light_client::{
    derive::{DeriveError, LightClientBlock},
    json::{check_genesis, parse_genesis, PinError},
    sync_committee::Preset,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};
use tracing::{debug, error, info, warn};
use url::Url;

/// The largest answer to a small JSON request: the genesis, a root or the head header. An honest
/// one is under 1 KiB.
pub const MAX_SMALL_BODY: usize = 64 << 10;
/// The largest SSZ block read: the consensus gossip limit.
pub const MAX_BLOCK_BODY: usize = 10 << 20;
/// The largest SSZ state read. A `PulseChain` 369 state is about 19 MB today.
pub const MAX_STATE_BODY: usize = 64 << 20;
/// The largest head event read from an event stream. An honest one is under 1 KiB.
pub const MAX_SSE_EVENT: usize = 64 << 10;
/// The most events in a row that are not head events, such as keep-alive comments, before an
/// event stream ends. An honest stream sends a head each slot and a few comments between.
pub const MAX_SKIPPED_EVENTS: usize = 1024;
/// The largest answer passed through to a client. A block's JSON is larger than its SSZ: hex
/// doubles its transaction bytes, so a block at the 10 MiB gossip limit is over 20 MiB of JSON.
pub const MAX_PASS_THROUGH_BODY: usize = 32 << 20;
/// Each this many bytes an answer has sent give its request one second past
/// [`Timeouts::request`], up to the request's limit.
const MIN_RATE: u64 = 512 << 10;
/// The media type of an SSZ answer.
const SSZ: &str = "application/octet-stream";

/// Why an upstream request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// Could not connect.
    #[error("could not connect")]
    Connect,
    /// The request passed its deadline.
    #[error("timed out")]
    Timeout,
    /// Another request failure.
    #[error("request failed")]
    Request,
    /// A status other than 200, or 404 where 404 has no meaning.
    #[error("http status {0}")]
    Status(u16),
    /// The body is not what the API sends.
    #[error("unexpected response body")]
    Body,
    /// The body is larger than the request's limit.
    #[error("response body too large")]
    TooLarge,
    /// The upstream has not answered its genesis yet, or is on another chain.
    #[error("the genesis is unchecked or another chain's")]
    Genesis,
}

fn classify(err: &reqwest::Error) -> UpstreamError {
    if err.is_timeout() {
        UpstreamError::Timeout
    } else if err.is_connect() {
        UpstreamError::Connect
    } else {
        UpstreamError::Request
    }
}

/// How long the requests may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// A small request in all, a block or state request before its bytes earn it more time, and
    /// the longest wait for the next bytes of any answer.
    pub request: Duration,
    /// The longest a block request may take, however fast its bytes come.
    pub block: Duration,
    /// The longest a state request may take, however fast its bytes come: about
    /// [`MAX_STATE_BODY`] at 512 KiB a second.
    pub state: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(10),
            block: Duration::from_secs(30),
            state: Duration::from_secs(120),
        }
    }
}

/// `scheme://host` of `url`, for logs and errors. Never the userinfo, port, path or query, and of
/// a domain only the last two labels (`*.provider.example`): any of them may hold a key.
pub fn host_label(url: &Url) -> String {
    let host = match url.host() {
        Some(url::Host::Domain(domain)) => match domain.rmatch_indices('.').nth(1) {
            Some((i, _)) => format!("*{}", &domain[i..]),
            None => domain.to_string(),
        },
        Some(_) => url.host_str().unwrap_or_default().to_string(),
        None => "unknown".to_string(),
    };
    format!("{}://{host}", url.scheme())
}

/// What the genesis checks of an upstream found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenesisCheck {
    /// No check got an answer yet.
    Unchecked,
    /// The genesis matches the pins.
    Matched,
    /// The genesis is another chain's.
    Mismatch,
}

/// A client of one upstream base URL.
#[derive(Clone)]
pub struct Upstream {
    http: reqwest::Client,
    stream: reqwest::Client,
    base: Url,
    host: String,
    timeouts: Timeouts,
    /// Shared by the clones, so that one check serves every task.
    genesis: Arc<parking_lot::Mutex<GenesisCheck>>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The base URL may hold a key: show the host label only.
        f.debug_struct("Upstream").field("host", &self.host).finish_non_exhaustive()
    }
}

/// The `data.root` of a beacon answer.
#[derive(Deserialize)]
struct RootAnswer {
    data: RootData,
}

#[derive(Deserialize)]
struct RootData {
    root: B256,
}

/// The data of a head event.
#[derive(Deserialize)]
struct HeadEvent {
    block: B256,
}

impl Upstream {
    /// A client for `base`.
    pub fn new(base: Url, timeouts: Timeouts) -> Self {
        // A redirect could move a request to another host or to plain http.
        let http = reqwest::Client::builder()
            .read_timeout(timeouts.request)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let stream = reqwest::Client::builder()
            .connect_timeout(timeouts.request)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let host = host_label(&base);
        let genesis = Arc::new(parking_lot::Mutex::new(GenesisCheck::Unchecked));
        Self { http, stream, base, host, timeouts, genesis }
    }

    /// Returns the [`host_label`] of the base URL.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// `path` under the base URL. The base query is kept, since it may hold the key, and `query`
    /// is appended to it.
    fn url(&self, path: &str, query: Option<&str>) -> Url {
        let mut url = self.base.clone();
        url.set_path(&format!("{}{path}", self.base.path().trim_end_matches('/')));
        if let Some(extra) = query {
            match self.base.query().filter(|base| !base.is_empty()) {
                Some(base) => url.set_query(Some(&format!("{base}&{extra}"))),
                None => url.set_query(Some(extra)),
            }
        }
        url
    }

    /// Fetches the body of `path`: at most `limit` bytes, within [`Timeouts::request`] plus one
    /// second for each [`MIN_RATE`] bytes read, up to `max`. With `ssz` it asks for SSZ and
    /// refuses another media type. A 404 is `Ok(None)`.
    async fn get(
        &self,
        path: &str,
        ssz: bool,
        limit: usize,
        max: Duration,
    ) -> Result<Option<Vec<u8>>, UpstreamError> {
        let started = Instant::now();
        let deadline = |read: usize| deadline(started, self.timeouts.request, max, read);
        let mut request = self.http.get(self.url(path, None));
        if ssz {
            request = request.header(reqwest::header::ACCEPT, SSZ);
        }
        let mut resp = tokio::time::timeout_at(deadline(0), request.send())
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|err| classify(&err))?;
        match resp.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => return Err(UpstreamError::Status(status)),
        }
        if ssz && !is_media_type(&resp, SSZ) {
            return Err(UpstreamError::Body);
        }
        // Streamed and bounded: an upstream cannot make the server buffer without limit.
        if resp.content_length().is_some_and(|len| len > limit as u64) {
            return Err(UpstreamError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = tokio::time::timeout_at(deadline(bytes.len()), resp.chunk())
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|err| classify(&err))?
        {
            if bytes.len() + chunk.len() > limit {
                return Err(UpstreamError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Some(bytes))
    }

    /// Fetches a small JSON answer, where a 404 is an error.
    async fn get_small(&self, path: &str) -> Result<Vec<u8>, UpstreamError> {
        self.get(path, false, MAX_SMALL_BODY, self.timeouts.request)
            .await?
            .ok_or(UpstreamError::Status(404))
    }

    /// Fetches a `data.root` answer.
    async fn root(&self, path: &str) -> Result<B256, UpstreamError> {
        let bytes = self.get_small(path).await?;
        let answer: RootAnswer = serde_json::from_slice(&bytes).map_err(|_| UpstreamError::Body)?;
        Ok(answer.data.root)
    }

    /// Fetches `/eth/v1/beacon/genesis` and checks it against `pins`. An answer is kept for
    /// [`Self::genesis_matches`].
    pub async fn check_genesis(
        &self,
        pins: &PulsechainBeacon,
    ) -> Result<(), PinError<UpstreamError>> {
        let endpoint = "/eth/v1/beacon/genesis";
        let unreadable = |error| PinError::Unreadable { endpoint, error };
        let bytes = self.get_small(endpoint).await.map_err(unreadable)?;
        let genesis = parse_genesis(&bytes).map_err(|_| unreadable(UpstreamError::Body))?;
        let checked = check_genesis(&genesis, pins);
        *self.genesis.lock() =
            if checked.is_ok() { GenesisCheck::Matched } else { GenesisCheck::Mismatch };
        checked
    }

    /// Returns whether the genesis matches `pins`. An upstream that has not answered a check
    /// yet is checked now, so one that was down at start is checked before its first use.
    pub async fn genesis_matches(&self, pins: &PulsechainBeacon) -> bool {
        match *self.genesis.lock() {
            GenesisCheck::Matched => return true,
            GenesisCheck::Mismatch => return false,
            GenesisCheck::Unchecked => {}
        }
        match self.check_genesis(pins).await {
            Ok(()) => {
                info!(target: "lc_server::upstream", host = self.host(), "the genesis matches the pins");
                true
            }
            Err(PinError::Unreadable { error, .. }) => {
                debug!(target: "lc_server::upstream", host = self.host(), %error, "no genesis yet");
                false
            }
            Err(err) => {
                error!(target: "lc_server::upstream", host = self.host(), %err, "the upstream is on another chain; it is not used");
                false
            }
        }
    }

    /// Fetches the SSZ block `id`, a root or a slot. `Ok(None)` when the upstream has no such
    /// block, as for a skipped slot.
    pub async fn block(&self, id: &str) -> Result<Option<Vec<u8>>, UpstreamError> {
        let path = format!("/eth/v2/beacon/blocks/{id}");
        self.get(&path, true, MAX_BLOCK_BODY, self.timeouts.block).await
    }

    /// Fetches the SSZ state at `slot`. A 404 is an error: the server asks only for a state that
    /// the state URL should have.
    pub async fn state(&self, slot: u64) -> Result<Vec<u8>, UpstreamError> {
        let path = format!("/eth/v2/debug/beacon/states/{slot}");
        self.get(&path, true, MAX_STATE_BODY, self.timeouts.state)
            .await?
            .ok_or(UpstreamError::Status(404))
    }

    /// Fetches the root of the newest finalized block.
    pub async fn finalized_root(&self) -> Result<B256, UpstreamError> {
        self.root("/eth/v1/beacon/blocks/finalized/root").await
    }

    /// Fetches the root of the head block.
    pub async fn head_root(&self) -> Result<B256, UpstreamError> {
        self.root("/eth/v1/beacon/headers/head").await
    }

    /// Opens the event stream of head events. Only a 200 with an event stream counts. A stream
    /// that sends nothing for `idle` ends.
    pub async fn head_events(&self, idle: Duration) -> Result<HeadEvents, UpstreamError> {
        let request = self.stream.get(self.url("/eth/v1/events", Some("topics=head"))).send();
        let resp = tokio::time::timeout(idle, request)
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|err| classify(&err))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(UpstreamError::Status(status));
        }
        if !is_media_type(&resp, "text/event-stream") {
            return Err(UpstreamError::Body);
        }
        Ok(HeadEvents::new(resp, idle))
    }

    /// Sends a `GET` of `path` with `accept`, for an answer the server passes through. Any
    /// status counts; [`PassThrough::chunk`] reads the body within the limits of a block.
    pub async fn pass_through(
        &self,
        path: &str,
        accept: Option<&reqwest::header::HeaderValue>,
    ) -> Result<PassThrough, UpstreamError> {
        let started = Instant::now();
        let mut request = self.http.get(self.url(path, None));
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        let max = self.timeouts.block;
        let resp = tokio::time::timeout_at(
            deadline(started, self.timeouts.request, max, 0),
            request.send(),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(|err| classify(&err))?;
        if resp.content_length().is_some_and(|len| len > MAX_PASS_THROUGH_BODY as u64) {
            return Err(UpstreamError::TooLarge);
        }
        Ok(PassThrough { resp, started, read: 0, request: self.timeouts.request, max })
    }
}

/// The deadline of a request that started at `started` and has read `read` bytes: `request`,
/// plus one second for each [`MIN_RATE`] bytes, up to `max`.
fn deadline(started: Instant, request: Duration, max: Duration, read: usize) -> Instant {
    let read = u64::try_from(read).unwrap_or(u64::MAX);
    let earned = Duration::from_millis(read.saturating_mul(1000) / MIN_RATE);
    started + request.saturating_add(earned).min(max)
}

/// An upstream answer that the server passes through to a client.
#[derive(Debug)]
pub struct PassThrough {
    resp: reqwest::Response,
    started: Instant,
    read: usize,
    request: Duration,
    max: Duration,
}

impl PassThrough {
    /// Returns the status.
    pub fn status(&self) -> u16 {
        self.resp.status().as_u16()
    }

    /// Returns the header `name`.
    pub fn header(
        &self,
        name: reqwest::header::HeaderName,
    ) -> Option<&reqwest::header::HeaderValue> {
        self.resp.headers().get(name)
    }

    /// Returns the next bytes of the body, or `None` at its end. The body may hold at most
    /// [`MAX_PASS_THROUGH_BODY`] bytes, and it must come within the deadline of a block request.
    pub async fn chunk(&mut self) -> Result<Option<bytes::Bytes>, UpstreamError> {
        let chunk = tokio::time::timeout_at(
            deadline(self.started, self.request, self.max, self.read),
            self.resp.chunk(),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(|err| classify(&err))?;
        if let Some(chunk) = &chunk {
            self.read += chunk.len();
            if self.read > MAX_PASS_THROUGH_BODY {
                return Err(UpstreamError::TooLarge);
            }
        }
        Ok(chunk)
    }
}

/// Returns whether the answer's `Content-Type` is `media_type`.
fn is_media_type(resp: &reqwest::Response, media_type: &str) -> bool {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(media_type))
}

/// An open stream of head events.
#[derive(Debug)]
pub struct HeadEvents {
    resp: reqwest::Response,
    /// The bytes read; the events before `start` are handled.
    buf: Vec<u8>,
    start: usize,
    /// How many bytes after `start` hold no end of an event.
    scanned: usize,
    idle: Duration,
}

impl HeadEvents {
    const fn new(resp: reqwest::Response, idle: Duration) -> Self {
        Self { resp, buf: Vec::new(), start: 0, scanned: 0, idle }
    }

    /// Returns the block root of the next head event. `None` when the stream ends, is idle for
    /// longer than its limit, sends an event over [`MAX_SSE_EVENT`], or sends more than
    /// [`MAX_SKIPPED_EVENTS`] other events in a row.
    pub async fn next_head(&mut self) -> Option<B256> {
        let mut skipped = 0;
        loop {
            while let Some(len) = find_event_end(&self.buf[self.start..], self.scanned) {
                let event = &self.buf[self.start..self.start + len];
                self.start += len;
                self.scanned = 0;
                if let Some(root) = parse_head_event(event) {
                    return Some(root)
                }
                skipped += 1;
                if skipped > MAX_SKIPPED_EVENTS {
                    return None
                }
                tokio::task::yield_now().await;
            }
            self.scanned = self.buf.len() - self.start;
            if self.scanned > MAX_SSE_EVENT {
                return None
            }
            self.buf.drain(..self.start);
            self.start = 0;
            let chunk = tokio::time::timeout(self.idle, self.resp.chunk()).await.ok()?.ok()??;
            self.buf.extend_from_slice(&chunk);
        }
    }
}

/// Returns the length of the first complete event in `buf`, with the blank line that ends it.
/// The first `scanned` bytes hold no end of an event, so the search starts after them and reads
/// each byte once.
fn find_event_end(buf: &[u8], scanned: usize) -> Option<usize> {
    (scanned..buf.len())
        .find(|&i| {
            buf[i] == b'\n' && (buf[..=i].ends_with(b"\n\n") || buf[..=i].ends_with(b"\r\n\r\n"))
        })
        .map(|i| i + 1)
}

/// Returns the block root of a `head` event. `None` for another event or a comment.
fn parse_head_event(event: &[u8]) -> Option<B256> {
    let text = std::str::from_utf8(event).ok()?;
    let (mut name, mut data) = (None, String::new());
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            name = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push_str(value.trim());
        }
    }
    if name != Some("head") {
        return None
    }
    serde_json::from_str::<HeadEvent>(&data).ok().map(|event| event.block)
}

/// An upstream whose genesis is not the chain's, or that did not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{host}: {error}")]
pub struct GenesisError {
    /// The upstream's [`host_label`].
    pub host: String,
    /// How its genesis differs from the pins, or why it did not answer.
    pub error: PinError<UpstreamError>,
}

/// Why the start check of the upstreams failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartCheckError {
    /// An upstream's genesis is another chain's.
    #[error("an upstream does not match the pinned chain values: {0}")]
    WrongChain(GenesisError),
    /// The state URL did not answer its genesis.
    #[error("the state URL did not answer its genesis: {0}")]
    StateUrl(GenesisError),
    /// No beacon URL answered its genesis. The error is the last one.
    #[error("no beacon URL answered its genesis: {0}")]
    NoBeaconUrl(GenesisError),
}

/// Checks the genesis of `state_url` and each of `beacon_urls` against `pins`, as the server
/// does at start. A mismatch stops the check. The state URL and at least one beacon URL must
/// answer; a beacon URL that does not answer stays unchecked, and
/// [`Upstream::genesis_matches`] checks it before its first use.
pub async fn check_upstreams(
    state_url: &Upstream,
    beacon_urls: &[Upstream],
    pins: &PulsechainBeacon,
) -> Result<(), StartCheckError> {
    let check = async |upstream: &Upstream| {
        upstream
            .check_genesis(pins)
            .await
            .map_err(|error| GenesisError { host: upstream.host.clone(), error })
    };
    match check(state_url).await {
        Err(err @ GenesisError { error: PinError::Unreadable { .. }, .. }) => {
            return Err(StartCheckError::StateUrl(err))
        }
        Err(err) => return Err(StartCheckError::WrongChain(err)),
        Ok(()) => {}
    }
    let mut unanswered = None;
    for upstream in beacon_urls {
        match check(upstream).await {
            Ok(()) => {
                debug!(target: "lc_server::upstream", host = upstream.host(), "the genesis matches the pins");
            }
            Err(err @ GenesisError { error: PinError::Unreadable { .. }, .. }) => {
                warn!(target: "lc_server::upstream", %err, "a beacon URL did not answer its genesis; it is checked before its first use");
                unanswered = Some(err);
            }
            Err(err) => return Err(StartCheckError::WrongChain(err)),
        }
    }
    match unanswered {
        Some(err)
            if beacon_urls
                .iter()
                .all(|upstream| *upstream.genesis.lock() != GenesisCheck::Matched) =>
        {
            Err(StartCheckError::NoBeaconUrl(err))
        }
        _ => Ok(()),
    }
}

/// Why a block was not read from the beacon URLs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Every beacon URL failed. The error is the last one.
    #[error("no beacon URL answered: {0}")]
    Upstream(UpstreamError),
    /// A block does not read, or is at a fork the binary does not know.
    #[error(transparent)]
    Derive(DeriveError),
    /// The thread that reads a block panicked or was cancelled.
    #[error("the block read thread failed")]
    ReadThread,
}

/// The beacon URLs, asked in order.
#[derive(Debug, Clone)]
pub struct Beacons {
    preset: Preset,
    pins: PulsechainBeacon,
    upstreams: Vec<Upstream>,
    /// One block read at a time, shared by every clone: a hostile block costs up to a second of
    /// hashing, so the reads must not take more than one blocking thread.
    read: Arc<Semaphore>,
}

impl Beacons {
    /// The beacon URLs `upstreams`, whose blocks are read with `preset` and `pins`.
    pub fn new(preset: Preset, pins: PulsechainBeacon, upstreams: Vec<Upstream>) -> Self {
        Self { preset, pins, upstreams, read: Arc::new(Semaphore::new(1)) }
    }

    /// Returns the beacon URLs.
    pub fn upstreams(&self) -> &[Upstream] {
        &self.upstreams
    }

    /// Returns the pinned chain values.
    pub const fn pins(&self) -> &PulsechainBeacon {
        &self.pins
    }

    /// Fetches the block with `root`. `Ok(None)` when a beacon URL has no such block and none
    /// gave it. A block that does not hash to `root` counts as a failed answer.
    pub async fn block_by_root(&self, root: B256) -> Result<Option<LightClientBlock>, FetchError> {
        self.first_block(&root.to_string(), |block| block.root() == root).await
    }

    /// Fetches the child of `parent` at `slot` that passes `accept`. `Ok(None)` when the slot
    /// has no block. A block at another slot, on another parent or that `accept` refuses counts
    /// as a failed answer, so a beacon URL on another fork does not hide the child that a later
    /// URL has.
    pub async fn child_at_slot(
        &self,
        slot: u64,
        parent: B256,
        accept: impl Fn(&LightClientBlock) -> bool,
    ) -> Result<Option<LightClientBlock>, FetchError> {
        self.first_block(&slot.to_string(), |block| {
            block.slot() == slot && block.header().beacon.parent_root == parent && accept(block)
        })
        .await
    }

    /// Asks each beacon URL for block `id` until one gives a block that passes `matches`.
    ///
    /// When none does and every URL answered, a block that does not read comes first, so an
    /// unknown fork is named. Then a 404 means that there is no such block, and last an upstream
    /// failure. A URL that failed outranks a block that does not read, so the caller tries again.
    async fn first_block(
        &self,
        id: &str,
        matches: impl Fn(&LightClientBlock) -> bool,
    ) -> Result<Option<LightClientBlock>, FetchError> {
        let (mut not_found, mut unreadable, mut failed) = (false, None, None);
        for upstream in &self.upstreams {
            if !upstream.genesis_matches(&self.pins).await {
                failed = Some(UpstreamError::Genesis);
                continue
            }
            match upstream.block(id).await {
                Ok(Some(bytes)) => match self.read_block(bytes).await? {
                    Ok(block) if matches(&block) => return Ok(Some(block)),
                    Ok(_) => {
                        debug!(target: "lc_server::upstream", host = upstream.host(), id, "the answer is another block");
                        failed = Some(UpstreamError::Body);
                    }
                    Err(err) => unreadable = Some(err),
                },
                Ok(None) => not_found = true,
                Err(err) => {
                    debug!(target: "lc_server::upstream", host = upstream.host(), id, %err, "block request failed");
                    failed = Some(err);
                }
            }
        }
        match (unreadable, not_found, failed) {
            (Some(_), _, Some(err)) => Err(FetchError::Upstream(err)),
            (Some(err), _, None) => Err(FetchError::Derive(err)),
            (None, true, _) => Ok(None),
            (None, false, failed) => {
                Err(FetchError::Upstream(failed.unwrap_or(UpstreamError::Request)))
            }
        }
    }

    /// Reads `bytes` as a block on a blocking thread, one read at a time.
    async fn read_block(
        &self,
        bytes: Vec<u8>,
    ) -> Result<Result<LightClientBlock, DeriveError>, FetchError> {
        let _permit = self.read.acquire().await.map_err(|_| FetchError::ReadThread)?;
        let (preset, pins) = (self.preset, self.pins);
        tokio::task::spawn_blocking(move || LightClientBlock::from_ssz_bytes(&bytes, preset, &pins))
            .await
            .map_err(|_| FetchError::ReadThread)
    }

    /// Fetches the head root of each beacon URL that answers, in order and without repeats, so
    /// a URL that lags does not hide the head of another.
    pub async fn head_roots(&self) -> Vec<B256> {
        let mut roots = Vec::new();
        for upstream in &self.upstreams {
            if !upstream.genesis_matches(&self.pins).await {
                continue
            }
            match upstream.head_root().await {
                Ok(root) if !roots.contains(&root) => roots.push(root),
                Ok(_) => {}
                Err(err) => {
                    debug!(target: "lc_server::upstream", host = upstream.host(), %err, "no head");
                }
            }
        }
        roots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{Answer, Fake, TestChain, PRESET, TIMEOUTS};
    use reth_pulsechain_forks::network::pulsechain_network;
    use serde_json::json;

    fn pins(chain_id: u64) -> PulsechainBeacon {
        pulsechain_network(chain_id).unwrap().beacon
    }

    /// Each chain's upstream passes against its own pins and fails against the other chain's.
    #[tokio::test]
    async fn the_genesis_is_checked_against_the_chain_pins() {
        let mainnet = Fake::start(&pins(369)).await;
        let testnet = Fake::start(&pins(943)).await;
        check_upstreams(&mainnet.upstream(), &[mainnet.upstream()], &pins(369)).await.unwrap();
        check_upstreams(&testnet.upstream(), &[testnet.upstream()], &pins(943)).await.unwrap();

        let err = check_upstreams(
            &mainnet.upstream(),
            &[mainnet.upstream(), testnet.upstream()],
            &pins(369),
        )
        .await
        .unwrap_err();
        let StartCheckError::WrongChain(err) = err else { panic!("{err}") };
        assert_eq!(err.host, "http://127.0.0.1");
        assert_eq!(
            err.error,
            PinError::GenesisValidatorsRoot {
                got: pins(943).genesis_validators_root,
                want: pins(369).genesis_validators_root,
            }
        );

        let mut late = pins(369);
        late.genesis_time += 1;
        assert_eq!(
            mainnet.upstream().check_genesis(&late).await,
            Err(PinError::GenesisTime { got: pins(369).genesis_time, want: late.genesis_time })
        );
    }

    /// A state URL on another chain fails the start check, though every beacon URL passes.
    #[tokio::test]
    async fn a_state_url_on_another_chain_fails_the_start_check() {
        let mainnet = Fake::start(&pins(369)).await;
        let testnet = Fake::start(&pins(943)).await;
        let err = check_upstreams(&testnet.upstream(), &[mainnet.upstream()], &pins(369))
            .await
            .unwrap_err();
        let StartCheckError::WrongChain(err) = err else { panic!("{err}") };
        assert_eq!(
            err.error,
            PinError::GenesisValidatorsRoot {
                got: pins(943).genesis_validators_root,
                want: pins(369).genesis_validators_root,
            }
        );
    }

    /// Only a 200 answer with the event-stream media type opens a head event stream.
    #[tokio::test]
    async fn a_head_event_stream_must_be_an_event_stream() {
        let idle = Duration::from_secs(5);
        let fake = Fake::start(&pins(369)).await;
        assert_eq!(fake.upstream().head_events(idle).await.err(), Some(UpstreamError::Status(404)));
        fake.answer("/eth/v1/events", Answer::json(&json!({"data": {}})));
        assert_eq!(fake.upstream().head_events(idle).await.err(), Some(UpstreamError::Body));
        let streams = Fake::start(&pins(369)).await;
        streams.enable_events();
        assert!(streams.upstream().head_events(idle).await.is_ok());
    }

    #[tokio::test]
    async fn an_unreadable_genesis_fails_the_check() {
        let fake = Fake::start(&pins(369)).await;
        let endpoint = "/eth/v1/beacon/genesis";
        fake.answer(endpoint, Answer::status(404));
        assert_eq!(
            fake.upstream().check_genesis(&pins(369)).await,
            Err(PinError::Unreadable { endpoint, error: UpstreamError::Status(404) })
        );
        fake.answer(endpoint, Answer::json(&json!({"data": {}})));
        assert_eq!(
            fake.upstream().check_genesis(&pins(369)).await,
            Err(PinError::Unreadable { endpoint, error: UpstreamError::Body })
        );
    }

    #[tokio::test]
    async fn answers_are_bounded_and_typed() {
        let fake = Fake::start(&pins(369)).await;
        let upstream = fake.upstream();
        assert_eq!(upstream.block("5").await, Ok(None));
        assert_eq!(upstream.state(5).await, Err(UpstreamError::Status(404)));
        assert_eq!(upstream.finalized_root().await, Err(UpstreamError::Status(404)));

        fake.answer("/eth/v2/beacon/blocks/5", Answer::json(&json!({"data": {}})));
        assert_eq!(upstream.block("5").await, Err(UpstreamError::Body));
        fake.answer("/eth/v2/beacon/blocks/5", Answer::status(500));
        assert_eq!(upstream.block("5").await, Err(UpstreamError::Status(500)));

        let large = "x".repeat(MAX_SMALL_BODY);
        fake.answer("/eth/v1/beacon/headers/head", Answer::json(&json!({ "data": large })));
        assert_eq!(upstream.head_root().await, Err(UpstreamError::TooLarge));
        // With no length to refuse up front, the read stops at the limit.
        let answer = Answer::json(&json!({ "data": large })).without_length();
        fake.answer("/eth/v1/beacon/headers/head", answer);
        assert_eq!(upstream.head_root().await, Err(UpstreamError::TooLarge));
        let small = Answer::json(&json!({"data": {"root": B256::ZERO}})).without_length();
        fake.answer("/eth/v1/beacon/headers/head", small);
        assert_eq!(upstream.head_root().await, Ok(B256::ZERO));

        fake.stall("/eth/v1/beacon/blocks/finalized/root");
        let started = tokio::time::Instant::now();
        assert_eq!(upstream.finalized_root().await, Err(UpstreamError::Timeout));
        assert!(started.elapsed() < TIMEOUTS.request * 3);
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_a_connect_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        drop(listener);
        assert_eq!(Upstream::new(url, TIMEOUTS).head_root().await, Err(UpstreamError::Connect));
    }

    /// The first beacon URL fails or serves another block; the second gives the block.
    #[tokio::test]
    async fn the_first_good_answer_wins() {
        let mut chain = TestChain::new();
        chain.extend(64..67);
        let (failing, wrong, good) = (
            Fake::start(&chain.pins).await,
            Fake::start(&chain.pins).await,
            Fake::start(&chain.pins).await,
        );
        good.serve_blocks(&chain);
        let root = chain.root(65);
        failing.answer(&format!("/eth/v2/beacon/blocks/{root}"), Answer::status(500));
        wrong.answer(
            &format!("/eth/v2/beacon/blocks/{root}"),
            Answer::ssz(chain.blocks[&66].0.clone()),
        );
        let beacons = |fakes: &[&Fake]| {
            Beacons::new(PRESET, chain.pins, fakes.iter().map(|fake| fake.upstream()).collect())
        };
        let found = beacons(&[&failing, &wrong, &good]).block_by_root(root).await.unwrap();
        assert_eq!(found.as_ref().map(LightClientBlock::root), Some(root));
        assert_eq!(
            beacons(&[&failing, &wrong]).block_by_root(root).await,
            Err(FetchError::Upstream(UpstreamError::Body))
        );
        assert_eq!(
            beacons(&[&failing]).block_by_root(root).await,
            Err(FetchError::Upstream(UpstreamError::Status(500)))
        );

        // A skipped slot is a 404 from a beacon URL that answers.
        let parent = chain.root(65);
        assert_eq!(beacons(&[&failing, &good]).child_at_slot(70, parent, |_| true).await, Ok(None));
        assert_eq!(
            beacons(&[&good])
                .child_at_slot(66, parent, |_| true)
                .await
                .unwrap()
                .map(|block| block.slot()),
            Some(66)
        );
        wrong.answer("/eth/v2/beacon/blocks/70", Answer::ssz(chain.blocks[&66].0.clone()));
        assert_eq!(
            beacons(&[&wrong]).child_at_slot(70, parent, |_| true).await,
            Err(FetchError::Upstream(UpstreamError::Body))
        );
    }

    /// The first beacon URL is on another fork: its block at the slot has another parent. The
    /// child comes from the second URL.
    #[tokio::test]
    async fn a_child_on_another_parent_is_a_failed_answer() {
        let mut chain = TestChain::new();
        chain.extend(64..67);
        let (forked, good) = (Fake::start(&chain.pins).await, Fake::start(&chain.pins).await);
        good.serve_blocks(&chain);
        // The block at 66 on 64, not on 65.
        let aggregate = reth_pulsechain_light_client::derive::test_utils::sign(
            PRESET,
            &chain.pins,
            &crate::fake::period_keys(1),
            crate::fake::SIGNERS,
            chain.root(64),
            66,
        );
        let bytes = reth_pulsechain_light_client::derive::test_utils::block_ssz(
            PRESET,
            66,
            chain.root(64),
            B256::repeat_byte(9),
            &aggregate,
        );
        forked.answer("/eth/v2/beacon/blocks/66", Answer::ssz(bytes));
        let beacons = Beacons::new(PRESET, chain.pins, vec![forked.upstream(), good.upstream()]);
        let child = beacons.child_at_slot(66, chain.root(65), |_| true).await.unwrap();
        assert_eq!(child.map(|block| block.root()), Some(chain.root(66)));
        let beacons = Beacons::new(PRESET, chain.pins, vec![forked.upstream()]);
        assert_eq!(
            beacons.child_at_slot(66, chain.root(65), |_| true).await,
            Err(FetchError::Upstream(UpstreamError::Body))
        );
    }

    /// A block that does not read is named only when every beacon URL answered. With a URL that
    /// timed out, the error is the timeout, which the caller tries again.
    #[tokio::test]
    async fn an_unreadable_block_beside_a_timeout_is_an_upstream_failure() {
        let mut chain = TestChain::new();
        chain.extend([64]);
        let (fake, stalled) = (Fake::start(&chain.pins).await, Fake::start(&chain.pins).await);
        fake.serve_blocks(&chain);
        stalled.stall("/eth/v2/beacon/blocks/64");
        let mut pins = chain.pins;
        pins.forks[3].epoch = 100;
        let beacons = Beacons::new(PRESET, pins, vec![fake.upstream(), stalled.upstream()]);
        assert_eq!(
            beacons.child_at_slot(64, chain.at(64).header().beacon.parent_root, |_| true).await,
            Err(FetchError::Upstream(UpstreamError::Timeout))
        );
    }

    /// A block at a fork the pins put before Capella is named, even when another URL has none.
    #[tokio::test]
    async fn a_block_of_an_unknown_fork_is_named() {
        let mut chain = TestChain::new();
        chain.extend([64]);
        let fake = Fake::start(&chain.pins).await;
        fake.serve_blocks(&chain);
        let empty = Fake::start(&chain.pins).await;
        let mut pins = chain.pins;
        pins.forks[3].epoch = 100;
        let beacons = Beacons::new(PRESET, pins, vec![fake.upstream(), empty.upstream()]);
        assert_eq!(
            beacons.child_at_slot(64, chain.at(64).header().beacon.parent_root, |_| true).await,
            Err(FetchError::Derive(DeriveError::UnsupportedFork {
                slot: 64,
                fork: reth_pulsechain_forks::network::BeaconFork::Bellatrix
            }))
        );
    }

    /// A beacon URL that was down at start is checked at its first use: on the right chain it
    /// is used from then on with no second check, and on another chain never.
    #[tokio::test]
    async fn an_unchecked_beacon_url_is_checked_at_its_first_use() {
        let mut chain = TestChain::new();
        chain.extend([64]);
        let (other, good) = (Fake::start(&pins(943)).await, Fake::start(&chain.pins).await);
        other.serve_blocks(&chain);
        good.serve_blocks(&chain);
        let beacons = Beacons::new(PRESET, chain.pins, vec![other.upstream(), good.upstream()]);
        let root = chain.root(64);
        for _ in 0..2 {
            let block = beacons.block_by_root(root).await.unwrap();
            assert_eq!(block.map(|block| block.root()), Some(root));
        }
        let path = format!("/eth/v2/beacon/blocks/{root}");
        assert_eq!((other.calls("/eth/v1/beacon/genesis"), other.calls(&path)), (1, 0));
        assert_eq!((good.calls("/eth/v1/beacon/genesis"), good.calls(&path)), (1, 2));
        assert_eq!(
            Beacons::new(PRESET, chain.pins, vec![other.upstream()]).block_by_root(root).await,
            Err(FetchError::Upstream(UpstreamError::Genesis))
        );
    }

    #[test]
    fn head_events_are_parsed() {
        let root = B256::repeat_byte(7);
        let data = json!({"slot": "5", "block": root.to_string()});
        assert_eq!(
            parse_head_event(format!("event: head\ndata: {data}\n\n").as_bytes()),
            Some(root)
        );
        assert_eq!(
            parse_head_event(format!("event:head\r\ndata:{data}\r\n\r\n").as_bytes()),
            Some(root)
        );
        assert_eq!(parse_head_event(b": comment\n\n"), None);
        assert_eq!(parse_head_event(format!("event: block\ndata: {data}\n\n").as_bytes()), None);
        assert_eq!(parse_head_event(b"event: head\ndata: {}\n\n"), None);
        assert_eq!(find_event_end(b"event: head\n", 0), None);
        assert_eq!(find_event_end(b"a\n\nb\r\n\r\n", 0), Some(3));
        assert_eq!(find_event_end(b"a\r\n\r\nb\n\n", 0), Some(5));
        // The search resumes after the bytes it read, and still sees an end that spans them.
        assert_eq!(find_event_end(b"a\r\n\r\n", 4), Some(5));
        assert_eq!(find_event_end(b"a\n\n", 3), None);
    }

    /// A stream whose body is `body`, as one chunk.
    fn events_of(body: Vec<u8>) -> HeadEvents {
        HeadEvents::new(
            reqwest::Response::from(hyper::Response::new(body)),
            Duration::from_secs(60),
        )
    }

    /// Up to [`MAX_SKIPPED_EVENTS`] events that are not heads may come before a head. One more
    /// ends the stream.
    #[tokio::test]
    async fn too_many_events_that_are_not_heads_end_the_stream() {
        let root = B256::repeat_byte(7);
        let head = format!("event: head\ndata: {}\n\n", json!({"slot": "5", "block": root}));
        let stream = |skipped: usize| {
            let mut body = b": keepalive\n\n".repeat(skipped);
            body.extend_from_slice(head.as_bytes());
            events_of(body)
        };
        assert_eq!(stream(MAX_SKIPPED_EVENTS).next_head().await, Some(root));
        assert_eq!(stream(MAX_SKIPPED_EVENTS + 1).next_head().await, None);
    }

    /// A stream whose body comes in `chunks`, one read each.
    fn events_in(chunks: Vec<Vec<u8>>) -> HeadEvents {
        let body = futures::stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));
        HeadEvents::new(
            reqwest::Response::from(hyper::Response::new(reqwest::Body::wrap_stream(body))),
            Duration::from_secs(60),
        )
    }

    /// An event may grow to [`MAX_SSE_EVENT`] bytes over several reads. One byte more ends the
    /// stream before the next read, so the head behind it is never read.
    #[tokio::test]
    async fn an_event_over_the_size_limit_ends_the_stream() {
        let root = B256::repeat_byte(7);
        let head = format!("event: head\ndata: {}\n\n", json!({"slot": "5", "block": root}));
        let stream = |len: usize| {
            let mut tail = b"\n\n".to_vec();
            tail.extend_from_slice(head.as_bytes());
            events_in(vec![[b": ".to_vec(), vec![b'x'; len - 2]].concat(), tail])
        };
        assert_eq!(stream(MAX_SSE_EVENT).next_head().await, Some(root));
        assert_eq!(stream(MAX_SSE_EVENT + 1).next_head().await, None);
    }

    /// A chunk of 417,792 newlines is 208,896 empty events. Each byte is searched once, so the
    /// stream ends at once.
    #[tokio::test]
    async fn a_flood_of_empty_events_ends_the_stream_at_once() {
        let started = std::time::Instant::now();
        assert_eq!(events_of(vec![b'\n'; 417_792]).next_head().await, None);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn the_host_label_hides_the_key() {
        let label = |url: &str| host_label(&url.parse().unwrap());
        assert_eq!(
            label("https://user:key@a.b.provider.example:8443/key/369?k=v"),
            "https://*.provider.example"
        );
        assert_eq!(label("http://127.0.0.1:5052/secret"), "http://127.0.0.1");
    }
}
