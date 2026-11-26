//! Metrics for `snap/1` serving, under the `pulsechain_snap1` scope.

use crate::server::{Lane, Outcome, RequestKind};
use reth_metrics::{
    metrics::{Counter, Gauge, Histogram},
    Metrics,
};
use std::collections::HashMap;

/// Requests of one message kind that ended in one outcome.
#[derive(Metrics)]
#[metrics(scope = "pulsechain_snap1")]
struct RequestOutcomeMetrics {
    /// Requests by message and outcome.
    requests_total: Counter,
}

/// Serve latency of one message kind in one lane.
#[derive(Metrics)]
#[metrics(scope = "pulsechain_snap1")]
struct LaneLatencyMetrics {
    /// Seconds from admission to the finished response of each admitted request, by message
    /// and lane.
    serve_latency_seconds: Histogram,
}

/// Series without labels.
#[derive(Metrics)]
#[metrics(scope = "pulsechain_snap1")]
struct GlobalMetrics {
    /// Bytes of the encoded response bodies served.
    response_bytes: Histogram,
    /// Head minus block number of each served root, when the backend knows it.
    root_depth: Histogram,
    /// Peers with `snap/1` negotiated.
    peers: Gauge,
    /// Cold-lane requests answered from a cached state view.
    view_cache_hits_total: Counter,
    /// Cold-lane requests that had to resolve their state view.
    view_cache_misses_total: Counter,
}

/// All `snap/1` serving metrics.
///
/// Every labelled series is created up front, so a request costs a map lookup and no allocation.
pub(crate) struct Snap1Metrics {
    outcomes: HashMap<(RequestKind, Outcome), RequestOutcomeMetrics>,
    latency: HashMap<(RequestKind, Lane), LaneLatencyMetrics>,
    global: GlobalMetrics,
}

impl Snap1Metrics {
    pub(crate) fn new() -> Self {
        let mut outcomes = HashMap::new();
        let mut latency = HashMap::new();
        for kind in RequestKind::ALL {
            for outcome in Outcome::ALL {
                outcomes.insert(
                    (kind, outcome),
                    RequestOutcomeMetrics::new_with_labels(&[
                        ("message", kind.label()),
                        ("outcome", outcome.label()),
                    ]),
                );
            }
            for lane in Lane::ALL {
                latency.insert(
                    (kind, lane),
                    LaneLatencyMetrics::new_with_labels(&[
                        ("message", kind.label()),
                        ("lane", lane.label()),
                    ]),
                );
            }
        }
        // `default()` caches the handles in a static, bound to the recorder of its first call.
        let global = GlobalMetrics::new_with_labels(Vec::<metrics::Label>::new());
        Self { outcomes, latency, global }
    }

    pub(crate) fn request(&self, kind: RequestKind, outcome: Outcome) {
        if let Some(m) = self.outcomes.get(&(kind, outcome)) {
            m.requests_total.increment(1);
        }
    }

    pub(crate) fn latency(&self, kind: RequestKind, lane: Lane, seconds: f64) {
        if let Some(m) = self.latency.get(&(kind, lane)) {
            m.serve_latency_seconds.record(seconds);
        }
    }

    pub(crate) fn response_bytes(&self, bytes: usize) {
        self.global.response_bytes.record(bytes as f64);
    }

    pub(crate) fn root_depth(&self, depth: u64) {
        self.global.root_depth.record(depth as f64);
    }

    pub(crate) fn view_cache(&self, hit: bool) {
        if hit {
            self.global.view_cache_hits_total.increment(1);
        } else {
            self.global.view_cache_misses_total.increment(1);
        }
    }

    /// Sets the number of peers with `snap/1` negotiated.
    pub(crate) fn peers(&self, peers: usize) {
        self.global.peers.set(peers as f64);
    }
}
