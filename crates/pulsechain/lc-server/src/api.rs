//! The HTTP API: the beacon light-client endpoints, the chain's genesis and fork schedule from
//! the pins, and the block endpoints passed through to the beacon URLs.
//!
//! Answers follow Lighthouse. A `bootstrap` for an unknown root is 404, `updates` is 200 with the
//! periods the server has (503 after a restart until it has checked them), and `finality_update` or
//! `optimistic_update` before the first one is 404. A `bootstrap` miss wakes the checkpoint task
//! and waits up to [`BOOTSTRAP_WAIT`] for its step: reth-lite asks for the bootstrap at its
//! anchor's newest finalized root, and exits on a 404.

use crate::{
    answers::{Answers, Latest},
    upstream::{Beacons, PassThrough},
    SECONDS_PER_SLOT,
};
use alloy_primitives::{hex, B256};
use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use hyper::{
    body::{Body, Frame, SizeHint},
    header::{HeaderValue, ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use reth_pulsechain_forks::network::{BeaconFork, PulsechainBeacon};
use reth_pulsechain_light_client::{
    json::{bootstrap_json, update_json, UpdateKind},
    sync_committee::{LightClientBootstrap, LightClientUpdate, Preset},
};
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tracing::{debug, warn};

/// The most updates one `updates` answer holds: `MAX_REQUEST_LIGHT_CLIENT_UPDATES`.
pub const MAX_UPDATES: u64 = 128;
/// The longest a `bootstrap` miss waits for the checkpoint task. Fetching a 19 MB state takes
/// about 2.5 s.
pub const BOOTSTRAP_WAIT: Duration = Duration::from_secs(8);
/// The most connections served at once, event streams included. More wait in the backlog. It is
/// well under the usual limit of 1,024 open files, which upstream requests and archive files
/// share.
pub const MAX_CONNECTIONS: usize = 256;
/// The most event streams open at once, a quarter of [`MAX_CONNECTIONS`], so streams cannot take
/// the slots of other requests. One more is answered 503.
pub const MAX_EVENT_STREAMS: usize = MAX_CONNECTIONS / 4;
/// An event stream ends after this long, and the client opens it again, so a client that stopped
/// reading does not hold a stream slot without end. reth-lite opens an ended stream again at once
/// when it lived longer than its 60 s retry gate.
pub const EVENT_STREAM_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long a client may take to send a request head, and to start the next one.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a write to a client may make no progress before the connection ends.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// The event stream topic of finality updates.
pub const FINALITY_TOPIC: &str = "light_client_finality_update";
/// The event stream topic of optimistic updates.
pub const OPTIMISTIC_TOPIC: &str = "light_client_optimistic_update";
/// The `Eth-Consensus-Version` header, passed through with a block.
const CONSENSUS_VERSION: &str = "eth-consensus-version";

/// The API of one chain.
#[derive(Debug)]
pub struct Api {
    answers: Arc<Answers>,
    beacons: Beacons,
    bootstrap_wait: Duration,
    /// The free event stream slots.
    streams: Arc<Semaphore>,
    /// How long an event stream lasts.
    stream_lifetime: Duration,
}

/// The endpoint of a request, as its metric label names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Genesis,
    ForkSchedule,
    Spec,
    Bootstrap,
    Updates,
    FinalityUpdate,
    OptimisticUpdate,
    Events,
    Block,
    BlockRoot,
    Unknown,
}

impl Route {
    const fn label(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::ForkSchedule => "fork_schedule",
            Self::Spec => "spec",
            Self::Bootstrap => "bootstrap",
            Self::Updates => "updates",
            Self::FinalityUpdate => "finality_update",
            Self::OptimisticUpdate => "optimistic_update",
            Self::Events => "events",
            Self::Block => "block",
            Self::BlockRoot => "block_root",
            Self::Unknown => "unknown",
        }
    }
}

impl Api {
    /// The API that serves `answers` and passes the block endpoints through to `beacons`.
    pub fn new(answers: Arc<Answers>, beacons: Beacons) -> Self {
        Self {
            answers,
            beacons,
            bootstrap_wait: BOOTSTRAP_WAIT,
            streams: Arc::new(Semaphore::new(MAX_EVENT_STREAMS)),
            stream_lifetime: EVENT_STREAM_LIFETIME,
        }
    }

    /// The API with a `bootstrap` miss that waits `wait`.
    #[cfg(test)]
    pub(crate) const fn with_bootstrap_wait(mut self, wait: Duration) -> Self {
        self.bootstrap_wait = wait;
        self
    }

    /// The API with at most `max` event streams, each `lifetime` long.
    #[cfg(test)]
    pub(crate) fn with_event_streams(mut self, max: usize, lifetime: Duration) -> Self {
        self.streams = Arc::new(Semaphore::new(max));
        self.stream_lifetime = lifetime;
        self
    }

    /// Answers `req`.
    pub async fn handle<B>(&self, req: Request<B>) -> Response<ApiBody> {
        let (route, resp) = self.route(&req).await;
        metrics::counter!(
            "lc_server_http_requests_total",
            "route" => route.label(),
            "status" => resp.status().as_str().to_owned(),
        )
        .increment(1);
        resp
    }

    async fn route<B>(&self, req: &Request<B>) -> (Route, Response<ApiBody>) {
        let path = req.uri().path();
        let query = req.uri().query();
        let route = route_of(path);
        if req.method() != Method::GET {
            return (route, error(StatusCode::METHOD_NOT_ALLOWED, "GET only"))
        }
        let light_client = matches!(
            route,
            Route::Bootstrap | Route::Updates | Route::FinalityUpdate | Route::OptimisticUpdate
        );
        if light_client && !accepts_json(req.headers().get(ACCEPT)) {
            return (route, error(StatusCode::NOT_ACCEPTABLE, "only JSON answers are served"))
        }
        let resp = match route {
            Route::Genesis => ok_json(&genesis_json(self.answers.pins())),
            Route::ForkSchedule => ok_json(&fork_schedule_json(self.answers.pins())),
            Route::Spec => ok_json(&spec_json(
                self.answers.chain_id(),
                self.answers.preset(),
                self.answers.pins(),
            )),
            Route::Bootstrap => self.bootstrap(path.rsplit('/').next().unwrap_or_default()).await,
            Route::Updates => self.updates(query).await,
            Route::FinalityUpdate => {
                self.latest(self.answers.finality_update(), UpdateKind::Finality)
            }
            Route::OptimisticUpdate => {
                self.latest(self.answers.optimistic_update(), UpdateKind::Optimistic)
            }
            Route::Events => self.events(query),
            Route::Block | Route::BlockRoot => {
                self.pass_through(route, path, req.headers().get(ACCEPT)).await
            }
            Route::Unknown => error(StatusCode::NOT_FOUND, "unknown endpoint"),
        };
        (route, resp)
    }

    async fn bootstrap(&self, id: &str) -> Response<ApiBody> {
        let Ok(root) = id.parse::<B256>() else {
            return error(StatusCode::BAD_REQUEST, "invalid block root")
        };
        match self.find_bootstrap(root).await {
            Ok(Some(bootstrap)) => {
                let fork = fork_at_slot(&self.answers, bootstrap.header.beacon.slot);
                json_or_error(bootstrap_json(&bootstrap, fork))
            }
            Ok(None) => error(StatusCode::NOT_FOUND, "no bootstrap at this block root"),
            Err(err) => {
                warn!(target: "lc_server::api", %err, "cannot read a stored bootstrap");
                error(StatusCode::INTERNAL_SERVER_ERROR, "cannot read the bootstrap")
            }
        }
    }

    /// Returns the stored bootstrap at `root`. On a miss it waits for a checkpoint step: the
    /// running one when it builds `root`, else the next one, which it wakes. The step builds
    /// `root` only when `root` is the state URL's newest finalized root.
    async fn find_bootstrap(&self, root: B256) -> io::Result<Option<LightClientBootstrap>> {
        if let Some(bootstrap) = self.answers.archive().lock().await.bootstrap(root).await? {
            return Ok(Some(bootstrap))
        }
        let mut progress = self.answers.subscribe_progress();
        let now = *progress.borrow_and_update();
        let target = if now.building == Some(root) {
            now.started
        } else {
            self.answers.wake_checkpoint();
            now.started + 1
        };
        debug!(target: "lc_server::api", %root, joined = now.building == Some(root), "waiting for the checkpoint task");
        // The `Ref` a wait returns holds the channel's lock: drop it before the next await.
        let ended = matches!(
            tokio::time::timeout(self.bootstrap_wait, progress.wait_for(|p| p.done >= target))
                .await,
            Ok(Ok(_))
        );
        if !ended {
            return Ok(None)
        }
        self.answers.archive().lock().await.bootstrap(root).await
    }

    /// The `updates` answer: the stored updates of consecutive periods in `start_period` to
    /// `start_period + count`, at most [`MAX_UPDATES`]. It starts at the first period in the range
    /// that the server has, and ends at the next period it does not have. The JSON of each
    /// update is shared, so a client that reads slowly holds no copy. Until the self-check store
    /// checks the stored updates after a restart, it is 503, so a client asks another source.
    async fn updates(&self, query: Option<&str>) -> Response<ApiBody> {
        let (mut start_period, mut count) = (None, None);
        for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            match &*key {
                "start_period" => start_period = Some(value.parse::<u64>()),
                "count" => count = Some(value.parse::<u64>()),
                _ => {}
            }
        }
        let (Some(Ok(start_period)), Some(Ok(count))) = (start_period, count) else {
            return error(StatusCode::BAD_REQUEST, "start_period and count must be numbers")
        };
        if count == 0 {
            return error(StatusCode::BAD_REQUEST, "count must be at least 1")
        }
        let end = start_period.saturating_add(count.min(MAX_UPDATES));
        let mut body = vec![Bytes::from_static(b"[")];
        let mut next = None;
        let archive = self.answers.archive().lock().await;
        if !archive.is_verified() {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the stored updates wait for the first checkpoint after a restart",
            )
        }
        for (&period, json) in archive.updates_json().range(start_period..end) {
            match next {
                Some(next) if next != period => break,
                Some(_) => body.push(Bytes::from_static(b",")),
                None => {}
            }
            body.push(json.clone());
            next = Some(period + 1);
        }
        drop(archive);
        body.push(Bytes::from_static(b"]"));
        Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(ApiBody::Stream(futures::stream::iter(body.into_iter().map(Ok)).boxed()))
            .expect("a valid response")
    }

    fn update_json(
        &self,
        update: &LightClientUpdate,
        kind: UpdateKind,
    ) -> Result<Value, reth_pulsechain_light_client::json::JsonError> {
        update_json(update, fork_at_slot(&self.answers, update.attested_header.beacon.slot), kind)
    }

    /// The latest finality or optimistic update, or 404 before the first one.
    fn latest(&self, latest: Latest, kind: UpdateKind) -> Response<ApiBody> {
        match latest {
            Some(update) => json_or_error(self.update_json(&update, kind)),
            None => error(StatusCode::NOT_FOUND, "no update yet"),
        }
    }

    /// The event stream of the light-client topics in `query`. Another topic is refused, and a
    /// stream past [`MAX_EVENT_STREAMS`] is 503. The stream ends after
    /// [`EVENT_STREAM_LIFETIME`].
    fn events(&self, query: Option<&str>) -> Response<ApiBody> {
        let (mut finality, mut optimistic) = (false, false);
        for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            if key != "topics" {
                continue
            }
            for topic in value.split(',') {
                match topic.trim() {
                    FINALITY_TOPIC => finality = true,
                    OPTIMISTIC_TOPIC => optimistic = true,
                    _ => {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "only the light-client topics are served",
                        )
                    }
                }
            }
        }
        if !finality && !optimistic {
            return error(StatusCode::BAD_REQUEST, "no topics")
        }
        let Ok(slot) = self.streams.clone().try_acquire_owned() else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "too many event streams")
        };
        let stream = EventStream {
            api: self.answers.clone(),
            _slot: slot,
            ends: Box::pin(tokio::time::sleep(self.stream_lifetime)),
            finality: finality.then(|| self.answers.subscribe_finality()),
            optimistic: optimistic.then(|| self.answers.subscribe_optimistic()),
        };
        Response::builder()
            .header(CONTENT_TYPE, "text/event-stream")
            .header(CACHE_CONTROL, "no-cache")
            .body(ApiBody::Stream(stream.into_stream()))
            .expect("a valid response")
    }

    /// Passes the block or block root request `path` through to the beacon URLs. The first 200
    /// is streamed to the client with its media type and consensus version. When none answers
    /// 200, a 404 from one is 404, and anything else is 502.
    ///
    /// A named block, such as `finalized`, is refused: no client can check the first beacon
    /// URL's answer against a root, so it would make that URL a client's trust root.
    async fn pass_through(
        &self,
        route: Route,
        path: &str,
        accept: Option<&HeaderValue>,
    ) -> Response<ApiBody> {
        let id = path.strip_suffix("/root").unwrap_or(path).rsplit('/').next();
        if id.is_some_and(|id| NAMED_BLOCK_IDS.contains(&id)) {
            return error(
                StatusCode::BAD_REQUEST,
                "the server passes through block roots and slots only: no client can check a \
                 named block against a root",
            )
        }
        let Some(id) = id.and_then(block_id) else {
            return error(StatusCode::BAD_REQUEST, "invalid block id")
        };
        let path = match route {
            Route::BlockRoot => format!("/eth/v1/beacon/blocks/{id}/root"),
            _ => format!("/eth/v2/beacon/blocks/{id}"),
        };
        let mut not_found = false;
        for upstream in self.beacons.upstreams() {
            if !upstream.genesis_matches(self.beacons.pins()).await {
                continue
            }
            match upstream.pass_through(&path, accept).await {
                Ok(answer) if answer.status() == 200 => return streamed(answer),
                Ok(answer) if answer.status() == 404 => not_found = true,
                Ok(answer) => {
                    debug!(target: "lc_server::api", host = upstream.host(), status = answer.status(), "a beacon URL did not pass the block through");
                }
                Err(err) => {
                    debug!(target: "lc_server::api", host = upstream.host(), %err, "a beacon URL did not pass the block through");
                }
            }
        }
        if not_found {
            error(StatusCode::NOT_FOUND, "no such block")
        } else {
            error(StatusCode::BAD_GATEWAY, "no beacon URL answered")
        }
    }
}

/// The route of `path`.
fn route_of(path: &str) -> Route {
    const BOOTSTRAP: &str = "/eth/v1/beacon/light_client/bootstrap/";
    match path {
        "/eth/v1/beacon/genesis" => Route::Genesis,
        "/eth/v1/config/fork_schedule" => Route::ForkSchedule,
        "/eth/v1/config/spec" => Route::Spec,
        "/eth/v1/beacon/light_client/updates" => Route::Updates,
        "/eth/v1/beacon/light_client/finality_update" => Route::FinalityUpdate,
        "/eth/v1/beacon/light_client/optimistic_update" => Route::OptimisticUpdate,
        "/eth/v1/events" => Route::Events,
        _ if path.strip_prefix(BOOTSTRAP).is_some_and(|id| !id.contains('/')) => Route::Bootstrap,
        _ if path
            .strip_prefix("/eth/v2/beacon/blocks/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/')) =>
        {
            Route::Block
        }
        _ if path
            .strip_prefix("/eth/v1/beacon/blocks/")
            .and_then(|rest| rest.strip_suffix("/root"))
            .is_some_and(|id| !id.is_empty() && !id.contains('/')) =>
        {
            Route::BlockRoot
        }
        _ => Route::Unknown,
    }
}

/// The block ids that the beacon API names, which the pass-through refuses.
const NAMED_BLOCK_IDS: [&str; 4] = ["head", "genesis", "finalized", "justified"];

/// `id` as the beacon API names a block by slot or by `0x` root. `None` for another id. A root
/// without its `0x`, as Checkpointz writes roots, gets one: Checkpointz refuses a root without
/// it.
fn block_id(id: &str) -> Option<String> {
    if id.parse::<u64>().is_ok() {
        return Some(id.to_owned())
    }
    id.parse::<B256>().ok().map(|root| format!("{root:#x}"))
}

/// The fork of the light-client data at `slot`.
fn fork_at_slot(answers: &Answers, slot: u64) -> BeaconFork {
    answers.pins().fork_at_epoch(answers.preset().epoch_at_slot(slot)).fork
}

/// The `/eth/v1/beacon/genesis` answer of `pins`.
pub fn genesis_json(pins: &PulsechainBeacon) -> Value {
    json!({"data": {
        "genesis_time": pins.genesis_time.to_string(),
        "genesis_validators_root": pins.genesis_validators_root,
        "genesis_fork_version": hex::encode_prefixed(pins.forks[0].version),
    }})
}

/// The `/eth/v1/config/fork_schedule` answer of `pins`: each pinned fork, with the version
/// before it.
pub fn fork_schedule_json(pins: &PulsechainBeacon) -> Value {
    let mut previous = pins.forks[0].version;
    let forks: Vec<Value> = pins
        .forks
        .iter()
        .map(|fork| {
            let entry = json!({
                "previous_version": hex::encode_prefixed(previous),
                "current_version": hex::encode_prefixed(fork.version),
                "epoch": fork.epoch.to_string(),
            });
            previous = fork.version;
            entry
        })
        .collect();
    json!({ "data": forks })
}

/// The `/eth/v1/config/spec` answer: the chain ID, the preset values the light-client protocol
/// uses, and the pinned forks. Helios reads the chain ID from `DEPOSIT_NETWORK_ID`.
pub fn spec_json(chain_id: u64, preset: Preset, pins: &PulsechainBeacon) -> Value {
    let mut data = serde_json::Map::new();
    let mut put = |key: &str, value: String| data.insert(key.to_owned(), Value::String(value));
    put("DEPOSIT_CHAIN_ID", chain_id.to_string());
    put("DEPOSIT_NETWORK_ID", chain_id.to_string());
    put("SECONDS_PER_SLOT", SECONDS_PER_SLOT.to_string());
    put("SLOTS_PER_EPOCH", preset.slots_per_epoch().to_string());
    put("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", preset.epochs_per_sync_committee_period().to_string());
    put("SYNC_COMMITTEE_SIZE", preset.sync_committee_size().to_string());
    put("GENESIS_FORK_VERSION", hex::encode_prefixed(pins.forks[0].version));
    for fork in &pins.forks[1..] {
        let name = format!("{:?}", fork.fork).to_uppercase();
        put(&format!("{name}_FORK_VERSION"), hex::encode_prefixed(fork.version));
        put(&format!("{name}_FORK_EPOCH"), fork.epoch.to_string());
    }
    json!({ "data": data })
}

/// Returns whether `accept` lets the server answer JSON: no header, or a media range that
/// covers `application/json` with a quality above zero.
fn accepts_json(accept: Option<&HeaderValue>) -> bool {
    let Some(accept) = accept.and_then(|accept| accept.to_str().ok()) else { return true };
    if accept.trim().is_empty() {
        return true
    }
    accept.split(',').any(|range| {
        let mut parts = range.split(';').map(str::trim);
        let media = parts.next().unwrap_or_default().to_ascii_lowercase();
        let refused = parts.any(|param| {
            param.strip_prefix("q=").and_then(|q| q.parse::<f32>().ok()).is_some_and(|q| q <= 0.0)
        });
        !refused && matches!(media.as_str(), "application/json" | "application/*" | "*/*")
    })
}

/// A JSON answer with status 200.
fn ok_json(value: &Value) -> Response<ApiBody> {
    Response::builder()
        .header(CONTENT_TYPE, "application/json")
        .body(ApiBody::full(value.to_string()))
        .expect("a valid response")
}

/// The light-client answer `value` as a 200 with its fork in `Eth-Consensus-Version`, or a 500
/// when the light-client data is of a fork the JSON form lacks.
fn json_or_error(
    value: Result<Value, reth_pulsechain_light_client::json::JsonError>,
) -> Response<ApiBody> {
    match value {
        Ok(value) => {
            let mut resp = ok_json(&value);
            if let Some(version) =
                value["version"].as_str().and_then(|version| HeaderValue::from_str(version).ok())
            {
                resp.headers_mut().insert(CONSENSUS_VERSION, version);
            }
            resp
        }
        Err(err) => {
            warn!(target: "lc_server::api", %err, "cannot write the answer");
            error(StatusCode::INTERNAL_SERVER_ERROR, "cannot write the answer")
        }
    }
}

/// A beacon API error answer.
fn error(status: StatusCode, message: &str) -> Response<ApiBody> {
    let body = json!({"code": status.as_u16(), "message": message});
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(ApiBody::full(body.to_string()))
        .expect("a valid response")
}

/// A 200 that streams `answer`'s body, with its media type and consensus version. A body that
/// fails or passes its limits ends the response with an error, so the client sees it cut off.
fn streamed(answer: PassThrough) -> Response<ApiBody> {
    let mut resp = Response::builder();
    for name in [CONTENT_TYPE, CONSENSUS_VERSION.parse().expect("a valid header name")] {
        if let Some(value) = answer.header(name.clone()) {
            resp = resp.header(name, value);
        }
    }
    let body = futures::stream::unfold(Some(answer), |answer| async move {
        let mut answer = answer?;
        match answer.chunk().await {
            Ok(Some(chunk)) => Some((Ok(chunk), Some(answer))),
            Ok(None) => None,
            Err(err) => {
                debug!(target: "lc_server::api", %err, "a passed-through body failed");
                Some((Err(io::Error::other(err)), None))
            }
        }
    });
    resp.body(ApiBody::Stream(body.boxed())).expect("a valid response")
}

/// The receivers of one event stream.
struct EventStream {
    api: Arc<Answers>,
    /// The stream's slot, held until the stream ends.
    _slot: OwnedSemaphorePermit,
    /// The end of the stream's lifetime.
    ends: Pin<Box<tokio::time::Sleep>>,
    finality: Option<watch::Receiver<Latest>>,
    optimistic: Option<watch::Receiver<Latest>>,
}

impl EventStream {
    /// The events: each new update of the stream's topics, until the stream's lifetime ends. An
    /// update the stream missed while its client read slowly is skipped for the newest one.
    fn into_stream(self) -> BoxStream<'static, Result<Bytes, io::Error>> {
        futures::stream::unfold(self, |mut stream| async move {
            loop {
                let (topic, kind, update) = tokio::select! {
                    () = &mut stream.ends => return None,
                    Some(update) = changed(&mut stream.finality) => {
                        (FINALITY_TOPIC, UpdateKind::Finality, update)
                    }
                    Some(update) = changed(&mut stream.optimistic) => {
                        (OPTIMISTIC_TOPIC, UpdateKind::Optimistic, update)
                    }
                    else => return None,
                };
                let Some(update) = update else { continue };
                let fork = fork_at_slot(&stream.api, update.attested_header.beacon.slot);
                match update_json(&update, fork, kind) {
                    Ok(data) => {
                        let event = format!("event: {topic}\ndata: {data}\n\n");
                        return Some((Ok(Bytes::from(event)), stream))
                    }
                    Err(err) => {
                        warn!(target: "lc_server::api", %err, topic, "cannot write the event");
                    }
                }
            }
        })
        .boxed()
    }
}

/// Waits for the next value of `rx`. `None` when there is no receiver or its sender is gone.
async fn changed(rx: &mut Option<watch::Receiver<Latest>>) -> Option<Latest> {
    let rx = rx.as_mut()?;
    rx.changed().await.ok()?;
    Some(rx.borrow_and_update().clone())
}

/// A response body: a whole answer, or a stream of events or passed-through bytes.
pub enum ApiBody {
    /// A whole answer, until hyper takes it.
    Full(Option<Bytes>),
    /// A stream that ends the response at its end, or cuts it off at an error.
    Stream(BoxStream<'static, Result<Bytes, io::Error>>),
}

impl std::fmt::Debug for ApiBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(body) => {
                f.debug_tuple("Full").field(&body.as_ref().map(Bytes::len)).finish()
            }
            Self::Stream(_) => f.debug_tuple("Stream").finish_non_exhaustive(),
        }
    }
}

impl ApiBody {
    fn full(body: impl Into<Bytes>) -> Self {
        Self::Full(Some(body.into()))
    }
}

impl Body for ApiBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Full(body) => Poll::Ready(body.take().map(|body| Ok(Frame::data(body)))),
            Self::Stream(stream) => {
                stream.poll_next_unpin(cx).map(|item| item.map(|chunk| chunk.map(Frame::data)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(body) => {
                SizeHint::with_exact(body.as_ref().map_or(0, |body| body.len() as u64))
            }
            Self::Stream(_) => SizeHint::default(),
        }
    }
}

/// Serves `api` on `listener`, at most [`MAX_CONNECTIONS`] at once. It ends only when the
/// caller aborts it, which also ends every connection.
pub async fn serve(listener: TcpListener, api: Arc<Api>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let Ok(slot) = slots.clone().acquire_owned().await else { return };
        let sock = match listener.accept().await {
            Ok((sock, _)) => sock,
            Err(err) => {
                // Out of file descriptors, say: wait instead of spinning.
                warn!(target: "lc_server::api", %err, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue
            }
        };
        let api = api.clone();
        connections.spawn(async move {
            let _slot = slot;
            let svc = service_fn(move |req| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(api.handle(req).await) }
            });
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(WriteTimeout::new(sock, WRITE_TIMEOUT)), svc)
                .await
            {
                debug!(target: "lc_server::api", %err, "a connection ended with an error");
            }
        });
    }
}

/// A connection whose write fails when it makes no progress for its timeout, so a client that
/// does not read cannot hold a response, and its memory, without end.
#[derive(Debug)]
struct WriteTimeout<S> {
    inner: S,
    timeout: Duration,
    /// Runs while a write or flush waits for the client, from the first wait on.
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> WriteTimeout<S> {
    const fn new(inner: S, timeout: Duration) -> Self {
        Self { inner, timeout, stalled: None }
    }

    /// Ends the stall on progress, or fails the write when the stall passes the timeout.
    fn check<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.stalled = None;
            return poll
        }
        let timeout = self.timeout;
        let stalled = self.stalled.get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match stalled.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the client stopped reading",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WriteTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WriteTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.check(cx, poll)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_flush(cx);
        this.check(cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod write_timeout_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A peer that does not read fills the pipe, and the next write fails after the timeout.
    #[tokio::test]
    async fn a_write_that_makes_no_progress_fails() {
        let (local, _peer) = tokio::io::duplex(64);
        let mut conn = WriteTimeout::new(local, Duration::from_millis(100));
        conn.write_all(&[0; 64]).await.unwrap();
        let started = tokio::time::Instant::now();
        let err = conn.write_all(&[0; 1]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    /// A peer that reads slowly keeps the connection: each write that makes progress starts the
    /// timeout again.
    #[tokio::test]
    async fn a_slow_reader_keeps_the_connection() {
        let (local, mut peer) = tokio::io::duplex(64);
        let mut conn = WriteTimeout::new(local, Duration::from_millis(200));
        let reader = tokio::spawn(async move {
            let mut buf = [0; 64];
            let mut read = 0;
            while read < 640 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                read += tokio::io::AsyncReadExt::read(&mut peer, &mut buf).await.unwrap();
            }
        });
        conn.write_all(&[0; 640]).await.unwrap();
        reader.await.unwrap();
    }
}
