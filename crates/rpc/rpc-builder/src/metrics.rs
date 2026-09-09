use jsonrpsee::{
    core::middleware::{Batch, Notification},
    server::middleware::rpc::RpcServiceT,
    types::Request,
    MethodResponse, RpcModule,
};
use pin_project::{pin_project, pinned_drop};
use reth_metrics::{
    metrics::{Counter, Histogram},
    Metrics,
};
use reth_primitives_traits::FastInstant as Instant;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::Layer;

/// Metrics for the RPC server.
///
/// Metrics are divided into two categories:
/// - Connection metrics: metrics for the connection (e.g. number of connections opened, relevant
///   for WS and IPC)
/// - Request metrics: metrics for each RPC method (e.g. number of calls started, time taken to
///   process a call)
///
/// # Reading the call counters
///
/// `started_total - successful_total - failed_total` is the number of calls in flight, and every
/// counter here is maintained so that it stays true:
/// - every call counted in `started_total` also reaches exactly one of `successful_total` or
///   `failed_total`, including a call whose caller hangs up (see [`MeteredRequestFuture`]),
/// - batch entries are counted in `batch_entries_total` instead of `started_total`, because nothing
///   observes their individual outcome (see [`RpcServiceT::batch`] below).
#[derive(Default, Debug, Clone)]
pub(crate) struct RpcRequestMetrics {
    inner: Arc<RpcServerMetricsInner>,
}

impl RpcRequestMetrics {
    pub(crate) fn new(module: &RpcModule<()>, transport: RpcTransport) -> Self {
        Self {
            inner: Arc::new(RpcServerMetricsInner {
                connection_metrics: transport.connection_metrics(),
                call_metrics: module
                    .method_names()
                    .map(|method| {
                        (method, RpcServerCallMetrics::new_with_labels(&[("method", method)]))
                    })
                    .collect(),
            }),
        }
    }

    /// Creates a new instance of the metrics layer for HTTP.
    pub(crate) fn http(module: &RpcModule<()>) -> Self {
        Self::new(module, RpcTransport::Http)
    }

    /// Creates a new instance of the metrics layer for same port.
    ///
    /// Note: currently it's not possible to track transport specific metrics for a server that runs http and ws on the same port: <https://github.com/paritytech/jsonrpsee/issues/1345> until we have this feature we will use the http metrics for this case.
    pub(crate) fn same_port(module: &RpcModule<()>) -> Self {
        Self::http(module)
    }

    /// Creates a new instance of the metrics layer for Ws.
    pub(crate) fn ws(module: &RpcModule<()>) -> Self {
        Self::new(module, RpcTransport::WebSocket)
    }

    /// Creates a new instance of the metrics layer for Ipc.
    pub(crate) fn ipc(module: &RpcModule<()>) -> Self {
        Self::new(module, RpcTransport::Ipc)
    }
}

impl<S> Layer<S> for RpcRequestMetrics {
    type Service = RpcRequestMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcRequestMetricsService::new(inner, self.clone())
    }
}

/// Metrics for the RPC server
#[derive(Default, Clone, Debug)]
struct RpcServerMetricsInner {
    /// Connection metrics per transport type
    connection_metrics: RpcServerConnectionMetrics,
    /// Call metrics per RPC method
    call_metrics: HashMap<&'static str, RpcServerCallMetrics>,
}

/// A [`RpcServiceT`] middleware that captures RPC metrics for the server.
///
/// This is created per connection and captures metrics for each request.
#[derive(Clone, Debug)]
pub struct RpcRequestMetricsService<S> {
    /// The metrics collector for RPC requests
    metrics: RpcRequestMetrics,
    /// The inner service being wrapped
    inner: S,
}

impl<S> RpcRequestMetricsService<S> {
    pub(crate) fn new(service: S, metrics: RpcRequestMetrics) -> Self {
        // this instance is kept alive for the duration of the connection
        metrics.inner.connection_metrics.connections_opened_total.increment(1);
        Self { inner: service, metrics }
    }
}

impl<S> RpcServiceT for RpcRequestMetricsService<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Send + Sync + Clone + 'static,
{
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = S::MethodResponse> + Send + 'a {
        self.metrics.inner.connection_metrics.requests_started_total.increment(1);
        let call_metrics = self.metrics.inner.call_metrics.get_key_value(req.method.as_ref());
        if let Some((_, call_metrics)) = &call_metrics {
            call_metrics.started_total.increment(1);
        }
        MeteredRequestFuture {
            fut: self.inner.call(req),
            started_at: Instant::now(),
            metrics: self.metrics.clone(),
            method: call_metrics.map(|(method, _)| *method),
            finished: false,
        }
    }

    fn batch<'a>(&self, req: Batch<'a>) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        self.metrics.inner.connection_metrics.batches_started_total.increment(1);

        // Note the entry methods now, while the batch is still here, but do not touch
        // `started_total` with them.
        //
        // jsonrpsee fans a batch out inside its own innermost service: `RpcService::batch` clones
        // itself and drives every entry through that clone's `call`
        // (`jsonrpsee-server-0.26.0/src/middleware/rpc.rs:151-160`). The entries therefore never
        // travel back up through this layer, so `MeteredRequestFuture` never sees them and
        // nothing records their outcome. Counting them as "started" made every batched call look
        // permanently unfinished: `started - successful - failed` then reported a growing number
        // of in-flight calls that did not exist, which is monotone and never recovers.
        //
        // The aggregate batch response carries no per-entry outcome either -
        // `MethodResponse::from_batch` hard-codes success
        // (`jsonrpsee-core-0.26.0/src/server/method_response.rs:151-159`) - so crediting each
        // entry to `successful_total` would hide real per-entry errors. The entries get their own
        // counter instead, recorded when the batch completes.
        let batch_entries = req
            .iter()
            .flatten()
            .filter_map(|entry| {
                self.metrics
                    .inner
                    .call_metrics
                    .get_key_value(entry.method_name())
                    .map(|(method, _)| *method)
            })
            .collect::<Vec<&'static str>>();

        MeteredBatchRequestsFuture {
            fut: self.inner.batch(req),
            started_at: Instant::now(),
            metrics: self.metrics.clone(),
            batch_entries,
            finished: false,
        }
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.inner.notification(n)
    }
}

impl<S> Drop for RpcRequestMetricsService<S> {
    fn drop(&mut self) {
        // update connection metrics, connection closed
        self.metrics.inner.connection_metrics.connections_closed_total.increment(1);
    }
}

/// Response future to update the metrics for a single request/response pair.
///
/// The future owns the terminal counter for the call it meters: it records one either when the
/// call resolves or, if the caller hangs up first, when it is dropped.
#[pin_project(PinnedDrop)]
pub struct MeteredRequestFuture<F> {
    #[pin]
    fut: F,
    /// time when the request started
    started_at: Instant,
    /// metrics for the method call
    metrics: RpcRequestMetrics,
    /// the method name if known
    method: Option<&'static str>,
    /// whether a terminal counter has already been recorded for this call
    finished: bool,
}

impl<F> std::fmt::Debug for MeteredRequestFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MeteredRequestFuture")
    }
}

impl<F: Future<Output = MethodResponse>> Future for MeteredRequestFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let res = this.fut.poll(cx);
        if let Poll::Ready(resp) = &res {
            let elapsed = this.started_at.elapsed().as_secs_f64();
            *this.finished = true;

            // update transport metrics
            this.metrics.inner.connection_metrics.requests_finished_total.increment(1);
            this.metrics.inner.connection_metrics.request_time_seconds.record(elapsed);

            // update call metrics
            if let Some(call_metrics) =
                this.method.and_then(|method| this.metrics.inner.call_metrics.get(method))
            {
                call_metrics.time_seconds.record(elapsed);
                if resp.is_success() {
                    call_metrics.successful_total.increment(1);
                } else {
                    call_metrics.failed_total.increment(1);
                }
            }
        }
        res
    }
}

#[pinned_drop]
impl<F> PinnedDrop for MeteredRequestFuture<F> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        if *this.finished {
            return;
        }

        // The server dropped the response future before it resolved, which is what happens when
        // an HTTP client disconnects mid-call. Without this the call would stay counted in
        // `started_total` with no terminal counter, and `started - successful - failed` would
        // never come back down.
        this.metrics.inner.connection_metrics.requests_finished_total.increment(1);
        if let Some(call_metrics) =
            this.method.and_then(|method| this.metrics.inner.call_metrics.get(method))
        {
            // Counted in both: `failed_total` keeps the in-flight arithmetic true, and
            // `cancelled_total` lets an operator subtract the hang-ups back out to see the
            // calls that the node itself answered with an error.
            call_metrics.failed_total.increment(1);
            call_metrics.cancelled_total.increment(1);
        }
    }
}

/// Response future to update the metrics for a batch of request/response pairs.
#[pin_project(PinnedDrop)]
pub struct MeteredBatchRequestsFuture<F> {
    #[pin]
    fut: F,
    /// time when the batch request started
    started_at: Instant,
    /// metrics for the batch
    metrics: RpcRequestMetrics,
    /// the method of each entry in the batch, for the entries with known metrics
    batch_entries: Vec<&'static str>,
    /// whether the batch has already been counted as finished
    finished: bool,
}

impl<F> std::fmt::Debug for MeteredBatchRequestsFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MeteredBatchRequestsFuture")
    }
}

impl<F> Future for MeteredBatchRequestsFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = this.fut.poll(cx);

        if res.is_ready() {
            let elapsed = this.started_at.elapsed().as_secs_f64();
            *this.finished = true;
            this.metrics.inner.connection_metrics.batches_finished_total.increment(1);
            this.metrics.inner.connection_metrics.batch_response_time_seconds.record(elapsed);

            // This is the only place that observes the entries completing, so it is where they
            // are counted.
            for method in this.batch_entries.drain(..) {
                if let Some(call_metrics) = this.metrics.inner.call_metrics.get(method) {
                    call_metrics.batch_entries_total.increment(1);
                }
            }
        }
        res
    }
}

#[pinned_drop]
impl<F> PinnedDrop for MeteredBatchRequestsFuture<F> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        if *this.finished {
            return;
        }

        // The caller went away before the batch resolved. Close out the batch so that
        // `batches_started_total - batches_finished_total` stays the number of batches in flight.
        // The entries are left uncounted: they never completed.
        this.metrics.inner.connection_metrics.batches_finished_total.increment(1);
    }
}

/// The transport protocol used for the RPC connection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RpcTransport {
    Http,
    WebSocket,
    Ipc,
}

impl RpcTransport {
    /// Returns the string representation of the transport protocol.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::WebSocket => "ws",
            Self::Ipc => "ipc",
        }
    }

    /// Returns the connection metrics for the transport protocol.
    fn connection_metrics(&self) -> RpcServerConnectionMetrics {
        RpcServerConnectionMetrics::new_with_labels(&[("transport", self.as_str())])
    }
}

/// Metrics for the RPC connections
#[derive(Metrics, Clone)]
#[metrics(scope = "rpc_server.connections")]
struct RpcServerConnectionMetrics {
    /// The number of connections opened
    connections_opened_total: Counter,
    /// The number of connections closed
    connections_closed_total: Counter,
    /// The number of requests started
    requests_started_total: Counter,
    /// The number of requests finished, whether they were answered or the caller hung up
    requests_finished_total: Counter,
    /// Response for a single request/response pair
    request_time_seconds: Histogram,
    /// The number of batch requests started
    batches_started_total: Counter,
    /// The number of batch requests finished, whether they were answered or the caller hung up
    batches_finished_total: Counter,
    /// Response time for a batch request
    batch_response_time_seconds: Histogram,
}

/// Metrics for the RPC calls
#[derive(Metrics, Clone)]
#[metrics(scope = "rpc_server.calls")]
struct RpcServerCallMetrics {
    /// The number of single (non-batched) calls started
    started_total: Counter,
    /// The number of successful calls
    successful_total: Counter,
    /// The number of calls that did not succeed, including the calls whose caller hung up
    failed_total: Counter,
    /// The number of calls whose caller hung up before the response was ready
    ///
    /// These are also counted in `failed_total`; subtract them to get the calls the node itself
    /// answered with an error.
    cancelled_total: Counter,
    /// The number of calls that arrived as entries of a batch request, counted when the batch
    /// completes
    ///
    /// These are not in `started_total`: jsonrpsee resolves batch entries below this middleware,
    /// so their individual outcomes are not observable here.
    batch_entries_total: Counter,
    /// Response for a single call
    time_seconds: Histogram,
}

#[cfg(test)]
mod tests {
    //! These tests are about one property: the call counters must never leave a call that is over
    //! looking as if it were still running.
    //!
    //! An operator reads `started_total - successful_total - failed_total` as "calls in flight"
    //! and pages on it. On 2026-09-04 that expression read 89 on a node with 16 blocking-pool
    //! threads and nothing stuck, because an Otterscan explorer was batching against it.

    use super::*;
    use jsonrpsee::{
        core::middleware::BatchEntry,
        types::{ErrorObject, Id, Request},
        ResponsePayload,
    };
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use std::task::Waker;

    /// A stand-in for jsonrpsee's innermost `RpcService`.
    ///
    /// It reproduces the one thing these tests turn on: `batch` drives the entries through a
    /// clone of itself, so they never travel back up through the middleware stack. See
    /// `jsonrpsee-server-0.26.0/src/middleware/rpc.rs:151-160`.
    #[derive(Clone, Debug)]
    struct FanOutService;

    // `async fn` in the impl would drop the `+ Send` bound the trait asks for.
    #[allow(clippy::manual_async_fn)]
    impl RpcServiceT for FanOutService {
        type MethodResponse = MethodResponse;
        type NotificationResponse = MethodResponse;
        type BatchResponse = MethodResponse;

        fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            let id = req.id.into_owned();
            async move { MethodResponse::response(id, ResponsePayload::success("ok"), usize::MAX) }
        }

        fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            let service = self.clone();
            async move {
                for entry in batch.into_iter().flatten() {
                    if let BatchEntry::Call(req) = entry {
                        let _ = service.call(req).await;
                    }
                }
                MethodResponse::response(Id::Null, ResponsePayload::success("batch"), usize::MAX)
            }
        }

        fn notification<'a>(
            &self,
            _n: Notification<'a>,
        ) -> impl Future<Output = MethodResponse> + Send + 'a {
            async move { MethodResponse::response(Id::Null, ResponsePayload::success("ok"), usize::MAX) }
        }
    }

    /// The same fan-out, with one method that answers with an error.
    ///
    /// A batch entry that fails is the case the aggregate batch response cannot show:
    /// `MethodResponse::from_batch` hard-codes success, so the outer response looks identical
    /// whether every entry succeeded or none did.
    #[derive(Clone, Debug)]
    struct ErringFanOutService;

    #[allow(clippy::manual_async_fn)]
    impl RpcServiceT for ErringFanOutService {
        type MethodResponse = MethodResponse;
        type NotificationResponse = MethodResponse;
        type BatchResponse = MethodResponse;

        fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            let fails = req.method.as_ref() == "eth_getLogs";
            let id = req.id.into_owned();
            async move {
                if fails {
                    MethodResponse::error(id, ErrorObject::owned(-32000, "boom", None::<()>))
                } else {
                    MethodResponse::response(id, ResponsePayload::success("ok"), usize::MAX)
                }
            }
        }

        fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            let service = self.clone();
            async move {
                for entry in batch.into_iter().flatten() {
                    if let BatchEntry::Call(req) = entry {
                        let _ = service.call(req).await;
                    }
                }
                MethodResponse::response(Id::Null, ResponsePayload::success("batch"), usize::MAX)
            }
        }

        fn notification<'a>(
            &self,
            _n: Notification<'a>,
        ) -> impl Future<Output = MethodResponse> + Send + 'a {
            async move { MethodResponse::response(Id::Null, ResponsePayload::success("ok"), usize::MAX) }
        }
    }

    /// A service whose calls never resolve, standing in for a call still running when its caller
    /// disconnects.
    #[derive(Clone, Debug)]
    struct PendingService;

    impl RpcServiceT for PendingService {
        type MethodResponse = MethodResponse;
        type NotificationResponse = MethodResponse;
        type BatchResponse = MethodResponse;

        fn call<'a>(&self, _req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            std::future::pending()
        }

        fn batch<'a>(&self, _b: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            std::future::pending()
        }

        fn notification<'a>(
            &self,
            _n: Notification<'a>,
        ) -> impl Future<Output = MethodResponse> + Send + 'a {
            std::future::pending()
        }
    }

    fn test_module() -> RpcModule<()> {
        let mut module = RpcModule::new(());
        module.register_method("eth_getBlockByNumber", |_, _, _| "ok").unwrap();
        module.register_method("eth_getLogs", |_, _, _| "ok").unwrap();
        module
    }

    fn request(method: &'static str) -> Request<'static> {
        Request::borrowed(method, None, Id::Number(1))
    }

    /// Drives a future to completion on the current thread.
    ///
    /// Everything under test resolves without yielding, so a bounded poll loop is enough and the
    /// tests need no runtime.
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
        panic!("the future did not resolve")
    }

    type Snapshot = Vec<(
        metrics_util::CompositeKey,
        Option<::metrics::Unit>,
        Option<::metrics::SharedString>,
        DebugValue,
    )>;

    /// Reads one counter by name and label. A registered counter that was never incremented reads
    /// 0, so a missing key means the metric was never registered at all.
    fn counter(snapshot: &Snapshot, name: &str, label: (&str, &str)) -> u64 {
        snapshot
            .iter()
            .find_map(|(key, _, _, value)| {
                let key = key.key();
                let matches = key.name() == name &&
                    key.labels().any(|l| l.key() == label.0 && l.value() == label.1);
                matches.then(|| match value {
                    DebugValue::Counter(c) => *c,
                    other => panic!("{name} is a {other:?}, not a counter"),
                })
            })
            .unwrap_or_else(|| panic!("no counter {name} labelled {label:?} was registered"))
    }

    /// The number a paging rule reads as "calls in flight".
    fn in_flight(snapshot: &Snapshot, method: &str) -> i64 {
        let read = |name: &str| counter(snapshot, name, ("method", method)) as i64;
        read("rpc_server.calls.started_total") -
            read("rpc_server.calls.successful_total") -
            read("rpc_server.calls.failed_total")
    }

    fn snapshot(snapshotter: &Snapshotter) -> Snapshot {
        snapshotter.snapshot().into_vec()
    }

    #[test]
    fn a_batch_that_completed_leaves_nothing_in_flight() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        // The metric handles bind to whichever recorder is live when they are built, so the
        // service has to be built inside the closure.
        let response = ::metrics::with_local_recorder(&recorder, || {
            let module = test_module();
            let service =
                RpcRequestMetricsService::new(FanOutService, RpcRequestMetrics::http(&module));

            let mut batch = Batch::new();
            batch.push(request("eth_getBlockByNumber"));
            batch.push(request("eth_getLogs"));
            batch.push(request("eth_getLogs"));

            block_on(service.batch(batch))
        });
        assert!(response.is_success(), "the batch has to have been served");

        let snap = snapshot(&snapshotter);
        for method in ["eth_getBlockByNumber", "eth_getLogs"] {
            assert_eq!(
                in_flight(&snap, method),
                0,
                "a batch that was served must leave no {method} call in flight",
            );
        }

        // The entries are still counted, just not as calls that can be waited on.
        assert_eq!(
            counter(&snap, "rpc_server.calls.batch_entries_total", ("method", "eth_getLogs")),
            2,
        );
        assert_eq!(
            counter(
                &snap,
                "rpc_server.calls.batch_entries_total",
                ("method", "eth_getBlockByNumber")
            ),
            1,
        );
        assert_eq!(
            counter(&snap, "rpc_server.connections.batches_started_total", ("transport", "http")),
            counter(&snap, "rpc_server.connections.batches_finished_total", ("transport", "http")),
        );
    }

    #[test]
    fn a_dropped_request_leaves_nothing_in_flight() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        ::metrics::with_local_recorder(&recorder, || {
            let module = test_module();
            let service =
                RpcRequestMetricsService::new(PendingService, RpcRequestMetrics::http(&module));

            let mut fut = Box::pin(service.call(request("eth_getLogs")));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(fut.as_mut().poll(&mut cx).is_pending(), "the call must still be running");

            // The caller disconnects: the connection task drops the response future.
            drop(fut);
        });

        let snap = snapshot(&snapshotter);
        assert_eq!(
            counter(&snap, "rpc_server.calls.started_total", ("method", "eth_getLogs")),
            1,
            "the call was counted as started",
        );
        assert_eq!(
            in_flight(&snap, "eth_getLogs"),
            0,
            "a call whose caller hung up is over, and must not be counted as in flight",
        );
        assert_eq!(
            counter(&snap, "rpc_server.calls.cancelled_total", ("method", "eth_getLogs")),
            1,
            "the hang-up stays separable from a real method error",
        );
        assert_eq!(
            counter(&snap, "rpc_server.connections.requests_started_total", ("transport", "http")),
            counter(&snap, "rpc_server.connections.requests_finished_total", ("transport", "http")),
        );
    }

    #[test]
    fn a_batch_with_a_failed_entry_returns_the_gauge_to_where_it_started() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let (before, after) = ::metrics::with_local_recorder(&recorder, || {
            let module = test_module();
            let service = RpcRequestMetricsService::new(
                ErringFanOutService,
                RpcRequestMetrics::http(&module),
            );

            // Every call counter is registered when the service is built, so this is the gauge's
            // starting value and not a missing key.
            let before = snapshot(&snapshotter);

            let mut batch = Batch::new();
            batch.push(request("eth_getBlockByNumber"));
            batch.push(request("eth_getLogs")); // this entry answers with an error
            batch.push(request("eth_getLogs"));
            let response = block_on(service.batch(batch));

            // The aggregate response says success whatever the entries did, which is exactly why
            // the entries cannot be credited to `successful_total`.
            assert!(response.is_success());

            (before, snapshot(&snapshotter))
        });

        for method in ["eth_getBlockByNumber", "eth_getLogs"] {
            assert_eq!(in_flight(&before, method), 0, "the gauge starts at 0 for {method}");
            assert_eq!(
                in_flight(&after, method),
                in_flight(&before, method),
                "a batch carrying a failed entry must return {method} to its starting value",
            );
        }

        // The failed entry is still counted, and it is counted in the one place whose meaning
        // does not claim to know how it ended.
        assert_eq!(
            counter(&after, "rpc_server.calls.batch_entries_total", ("method", "eth_getLogs")),
            2,
        );
        assert_eq!(
            counter(&after, "rpc_server.calls.failed_total", ("method", "eth_getLogs")),
            0,
            "a batch entry has no observable outcome here, so it must not be guessed at",
        );
        assert_eq!(
            counter(&after, "rpc_server.connections.batches_started_total", ("transport", "http")),
            counter(&after, "rpc_server.connections.batches_finished_total", ("transport", "http")),
        );
    }

    #[test]
    fn an_answered_call_still_counts_where_it_did() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        ::metrics::with_local_recorder(&recorder, || {
            let module = test_module();
            let service =
                RpcRequestMetricsService::new(FanOutService, RpcRequestMetrics::http(&module));
            let response = block_on(service.call(request("eth_getLogs")));
            assert!(response.is_success());
        });

        let snap = snapshot(&snapshotter);
        assert_eq!(counter(&snap, "rpc_server.calls.started_total", ("method", "eth_getLogs")), 1,);
        assert_eq!(
            counter(&snap, "rpc_server.calls.successful_total", ("method", "eth_getLogs")),
            1,
        );
        assert_eq!(
            counter(&snap, "rpc_server.calls.cancelled_total", ("method", "eth_getLogs")),
            0,
            "a call that resolved must not also be counted as a hang-up",
        );
        assert_eq!(in_flight(&snap, "eth_getLogs"), 0);
    }
}
