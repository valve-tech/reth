//! The `lite_*` metric series.
//!
//! [`LiteMetrics::new`] registers every unlabeled series, both `lite_answers_total` series and
//! each `source` series of the failure counters at zero, so they are present from the start and
//! `increase()` sees the first failure; `lite_requests_total` series appear after the first
//! request. `lite_head_lag_seconds` starts at `+Inf` instead: a node with no verified
//! head yet serves nothing, and a lag of 0 would read as a perfect head. The two
//! `lite_sync_*` gauges stay 0 without `--head.verify=sync-committee`, and both
//! `lite_head_verify{mode}` series read 0 until the node sets its mode. The two `lite_rounds_*`
//! counters start at zero for each method in [`ROUND_METHODS`]; `lite_rounds` has buckets only
//! with a recorder from [`prometheus_builder`].

use crate::config::HeadVerify;
use metrics::{
    counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram, Counter,
    Gauge, Histogram,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

/// The methods that read state in rounds, the `method` label of the `lite_rounds*` series. A
/// fixed list keeps the series bounded.
pub const ROUND_METHODS: [&str; 7] = [
    "eth_call",
    "eth_estimateGas",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_sendRawTransaction",
];

/// The `le` bounds of `lite_rounds`, up to the round limit of 40 (`LiteConfig::max_rounds`). A
/// larger limit counts in `+Inf`.
pub const ROUND_BUCKETS: [f64; 12] =
    [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 15.0, 20.0, 30.0, 40.0];

/// The exporter with the buckets of the lite histograms. Without them `lite_rounds` renders as a
/// summary.
pub fn prometheus_builder() -> PrometheusBuilder {
    PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Full("lite_rounds".to_owned()), &ROUND_BUCKETS)
        .expect("the bucket list is not empty")
}

/// The round series of one method. The default records nothing.
#[derive(Debug, Clone)]
pub struct RoundMetrics {
    /// `lite_rounds{method}`: the runs of one request.
    rounds: Histogram,
    /// `lite_rounds_fetched_keys_total{method}`
    fetched_keys: Counter,
    /// `lite_rounds_exhausted_total{method}`
    exhausted: Counter,
}

impl Default for RoundMetrics {
    fn default() -> Self {
        Self {
            rounds: Histogram::noop(),
            fetched_keys: Counter::noop(),
            exhausted: Counter::noop(),
        }
    }
}

impl RoundMetrics {
    fn new(method: &'static str) -> Self {
        Self {
            rounds: histogram!("lite_rounds", "method" => method),
            fetched_keys: counter!("lite_rounds_fetched_keys_total", "method" => method),
            exhausted: counter!("lite_rounds_exhausted_total", "method" => method),
        }
    }

    /// Records the runs of one request that ran at least once: answered, failed or dropped.
    pub fn runs(&self, runs: u32) {
        if runs > 0 {
            self.rounds.record(f64::from(runs));
        }
    }

    /// Counts `keys` keys of state that a round fetched and stored.
    pub fn fetched(&self, keys: usize) {
        self.fetched_keys.increment(keys as u64);
    }

    /// Counts one request that still missed state after the round limit.
    pub fn exhausted(&self) {
        self.exhausted.increment(1);
    }
}

/// How a request ended, the `outcome` label of `lite_requests_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered, including `null` and reverts.
    Local,
    /// Refused with `-32601`.
    Refused,
    /// Miss error `-32046`.
    Miss,
    /// Any other error.
    Error,
}

impl Outcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Refused => "refused",
            Self::Miss => "miss",
            Self::Error => "error",
        }
    }
}

/// Where data came from, the `source` label of `lite_proof_failures_total` and
/// `lite_beacon_optimistic_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureSource {
    /// A beacon payload whose rebuilt hash differed.
    Beacon,
    /// The finalized anchor source.
    Anchor,
    /// A p2p peer's proof.
    Peer,
    /// An upstream JSON-RPC source's proof or code (`--upstream.url`).
    Upstream,
}

impl FailureSource {
    /// Every source, in label order of the README.
    const ALL: [Self; 4] = [Self::Beacon, Self::Anchor, Self::Peer, Self::Upstream];

    const fn label(self) -> &'static str {
        match self {
            Self::Beacon => "beacon",
            Self::Anchor => "anchor",
            Self::Peer => "peer",
            Self::Upstream => "upstream",
        }
    }
}

/// Handles to every lite series.
#[derive(Debug, Clone)]
pub struct LiteMetrics {
    /// `lite_cache_bytes`
    pub cache_bytes: Gauge,
    /// `lite_disk_bytes`
    pub disk_bytes: Gauge,
    /// `lite_disk_limit_bytes`
    pub disk_limit_bytes: Gauge,
    /// `lite_head_lag_seconds`
    pub head_lag_seconds: Gauge,
    /// `lite_head_number`
    pub head_number: Gauge,
    peers_static: Gauge,
    peers_discovered: Gauge,
    /// `lite_anchor_mismatch`
    pub anchor_mismatch: Gauge,
    /// `lite_anchor_ahead`
    pub anchor_ahead: Gauge,
    /// `lite_warm_queue`
    pub warm_queue: Gauge,
    /// `lite_sync_committee_period`
    pub sync_committee_period: Gauge,
    /// `lite_sync_participation`
    pub sync_participation: Gauge,
    /// `lite_unconfirmed_start`
    pub unconfirmed_start: Gauge,
    head_verify_quorum: Gauge,
    head_verify_sync_committee: Gauge,
    answers_verified: Counter,
    answers_unverified: Counter,
    anchor_disagreements: Counter,
    rounds: [RoundMetrics; ROUND_METHODS.len()],
}

impl LiteMetrics {
    /// Registers the series with the installed recorder.
    pub fn new() -> Self {
        describe_counter!("lite_requests_total", "Requests by method and outcome");
        describe_counter!("lite_answers_total", "Answers that carried data, by verified");
        describe_counter!("lite_proof_failures_total", "Bad data rejected, by source");
        describe_counter!("lite_anchor_unreachable_total", "Anchor fetches that got no answer");
        describe_counter!(
            "lite_anchor_disagreements_total",
            "Anchor checks that disagreed with the chain the sync committee verified, which wins"
        );
        describe_counter!(
            "lite_beacon_optimistic_total",
            "Beacon blocks skipped because the source had not validated their execution, by source"
        );
        describe_histogram!(
            "lite_rounds",
            "Runs of one state-reading request, answered or not: 1 when the state was held"
        );
        describe_counter!(
            "lite_rounds_fetched_keys_total",
            "Keys of state that rounds fetched and stored, by method"
        );
        describe_counter!(
            "lite_rounds_exhausted_total",
            "Requests that still missed state after the round limit, by method"
        );
        describe_gauge!("lite_cache_bytes", "Verified cache size in memory");
        describe_gauge!("lite_disk_bytes", "Disk used by the store's generations");
        describe_gauge!("lite_disk_limit_bytes", "The effective disk limit");
        describe_gauge!(
            "lite_head_lag_seconds",
            "Seconds between now and the verified head, +Inf before the first head"
        );
        describe_gauge!("lite_head_number", "The verified head number");
        describe_gauge!("lite_peers", "Usable p2p peers, by kind (static or discovered)");
        describe_gauge!("lite_anchor_mismatch", "1 when the finalized anchor disagrees");
        describe_gauge!(
            "lite_anchor_ahead",
            "1 when serving stops because the finalized anchor is above the head"
        );
        describe_gauge!("lite_warm_queue", "Pieces waiting to be warmed");
        describe_gauge!(
            "lite_sync_committee_period",
            "The sync-committee period of the light-client store's finalized header"
        );
        describe_gauge!(
            "lite_sync_participation",
            "Sync-committee members that signed the last light-client update the node accepted"
        );
        describe_gauge!("lite_head_verify", "1 for the head verification mode in use, by mode");
        describe_gauge!(
            "lite_unconfirmed_start",
            "1 when nothing but the finalized anchor confirms the block the node starts from"
        );

        let m = Self {
            cache_bytes: gauge!("lite_cache_bytes"),
            disk_bytes: gauge!("lite_disk_bytes"),
            disk_limit_bytes: gauge!("lite_disk_limit_bytes"),
            head_lag_seconds: gauge!("lite_head_lag_seconds"),
            head_number: gauge!("lite_head_number"),
            peers_static: gauge!("lite_peers", "kind" => "static"),
            peers_discovered: gauge!("lite_peers", "kind" => "discovered"),
            anchor_mismatch: gauge!("lite_anchor_mismatch"),
            anchor_ahead: gauge!("lite_anchor_ahead"),
            warm_queue: gauge!("lite_warm_queue"),
            sync_committee_period: gauge!("lite_sync_committee_period"),
            sync_participation: gauge!("lite_sync_participation"),
            unconfirmed_start: gauge!("lite_unconfirmed_start"),
            head_verify_quorum: gauge!("lite_head_verify", "mode" => "quorum"),
            head_verify_sync_committee: gauge!("lite_head_verify", "mode" => "sync-committee"),
            answers_verified: counter!("lite_answers_total", "verified" => "true"),
            answers_unverified: counter!("lite_answers_total", "verified" => "false"),
            anchor_disagreements: counter!("lite_anchor_disagreements_total"),
            rounds: ROUND_METHODS.map(RoundMetrics::new),
        };
        for g in [
            &m.cache_bytes,
            &m.disk_bytes,
            &m.disk_limit_bytes,
            &m.head_number,
            &m.peers_static,
            &m.peers_discovered,
            &m.anchor_mismatch,
            &m.anchor_ahead,
            &m.warm_queue,
            &m.unconfirmed_start,
        ] {
            g.set(0.0);
        }
        m.head_lag_seconds.set(f64::INFINITY);
        m.answers_verified.increment(0);
        m.answers_unverified.increment(0);
        m.anchor_disagreements.increment(0);
        for r in &m.rounds {
            r.fetched_keys.increment(0);
            r.exhausted.increment(0);
        }
        counter!("lite_anchor_unreachable_total").increment(0);
        for source in FailureSource::ALL {
            counter!("lite_proof_failures_total", "source" => source.label()).increment(0);
            counter!("lite_beacon_optimistic_total", "source" => source.label()).increment(0);
        }
        m
    }

    /// Sets `lite_head_verify{mode}`: 1 for `mode`, 0 for the other.
    pub fn set_head_verify(&self, mode: HeadVerify) {
        let on = |m| if mode == m { 1.0 } else { 0.0 };
        self.head_verify_quorum.set(on(HeadVerify::Quorum));
        self.head_verify_sync_committee.set(on(HeadVerify::SyncCommittee));
    }

    /// Sets `lite_peers{kind=static|discovered}`.
    pub fn set_peers(&self, statics: usize, discovered: usize) {
        self.peers_static.set(statics as f64);
        self.peers_discovered.set(discovered as f64);
    }

    /// Counts one request of `method`.
    pub fn request(&self, method: &str, outcome: Outcome) {
        counter!("lite_requests_total", "method" => method.to_owned(), "outcome" => outcome.label())
            .increment(1);
    }

    /// Counts one answer that carried data.
    pub fn answer(&self, verified: bool) {
        if verified {
            self.answers_verified.increment(1);
        } else {
            self.answers_unverified.increment(1);
        }
    }

    /// The round series of `method`. A method not in [`ROUND_METHODS`] records nothing.
    pub fn rounds(&self, method: &str) -> RoundMetrics {
        ROUND_METHODS
            .iter()
            .position(|m| *m == method)
            .map(|i| self.rounds[i].clone())
            .unwrap_or_default()
    }

    /// Counts one rejected piece of data.
    pub fn proof_failure(&self, source: FailureSource) {
        counter!("lite_proof_failures_total", "source" => source.label()).increment(1);
    }

    /// `lite_anchor_unreachable_total`: an anchor fetch that got no answer.
    pub fn anchor_unreachable(&self) {
        counter!("lite_anchor_unreachable_total").increment(1);
    }

    /// `lite_anchor_disagreements_total`: with `--head.verify=sync-committee`, an anchor check
    /// that disagreed with the verified chain and did not halt serving.
    pub fn anchor_disagreement(&self) {
        self.anchor_disagreements.increment(1);
    }

    /// `lite_beacon_optimistic_total`: a beacon block skipped as `execution_optimistic`.
    pub fn beacon_optimistic(&self, source: FailureSource) {
        counter!("lite_beacon_optimistic_total", "source" => source.label()).increment(1);
    }
}

impl Default for LiteMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_exporter_prometheus::PrometheusBuilder;

    fn render(f: impl FnOnce(&LiteMetrics)) -> String {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || f(&LiteMetrics::new()));
        handle.render()
    }

    #[test]
    fn unlabeled_series_and_both_answer_series_exist_from_the_start() {
        let out = render(|_| {});
        for name in [
            "lite_cache_bytes 0",
            "lite_disk_bytes 0",
            "lite_disk_limit_bytes 0",
            "lite_head_number 0",
            "lite_peers{kind=\"static\"} 0",
            "lite_peers{kind=\"discovered\"} 0",
            "lite_anchor_mismatch 0",
            "lite_anchor_ahead 0",
            "lite_anchor_disagreements_total 0",
            "lite_warm_queue 0",
            "lite_unconfirmed_start 0",
            "lite_answers_total{verified=\"true\"} 0",
            "lite_answers_total{verified=\"false\"} 0",
        ] {
            assert!(out.contains(name), "missing `{name}` in:\n{out}");
        }
    }

    /// Prometheus `increase()` sees no change when a series first appears, so an alert on the
    /// first failure after a start needs the series at zero before it.
    #[test]
    fn the_failure_series_exist_at_zero_from_the_start() {
        let out = render(|_| {});
        for line in [
            "lite_anchor_unreachable_total 0",
            "lite_proof_failures_total{source=\"beacon\"} 0",
            "lite_proof_failures_total{source=\"anchor\"} 0",
            "lite_proof_failures_total{source=\"peer\"} 0",
            "lite_beacon_optimistic_total{source=\"beacon\"} 0",
            "lite_beacon_optimistic_total{source=\"anchor\"} 0",
            "lite_beacon_optimistic_total{source=\"peer\"} 0",
        ] {
            assert!(out.lines().any(|l| l == line), "missing `{line}` in:\n{out}");
        }
    }

    #[test]
    fn the_sync_committee_series_read_zero_until_set() {
        let out = render(|_| {});
        for line in [
            "lite_sync_committee_period 0",
            "lite_sync_participation 0",
            "lite_head_verify{mode=\"quorum\"} 0",
            "lite_head_verify{mode=\"sync-committee\"} 0",
        ] {
            assert!(out.lines().any(|l| l == line), "missing `{line}` in:\n{out}");
        }
        let out = render(|m| m.set_head_verify(HeadVerify::Quorum));
        assert!(out.lines().any(|l| l == "lite_head_verify{mode=\"quorum\"} 1"), "{out}");
        assert!(out.lines().any(|l| l == "lite_head_verify{mode=\"sync-committee\"} 0"), "{out}");
        let out = render(|m| {
            m.set_head_verify(HeadVerify::SyncCommittee);
            m.sync_committee_period.set(1363.0);
            m.sync_participation.set(493.0);
        });
        for line in [
            "lite_head_verify{mode=\"quorum\"} 0",
            "lite_head_verify{mode=\"sync-committee\"} 1",
            "lite_sync_committee_period 1363",
            "lite_sync_participation 493",
        ] {
            assert!(out.lines().any(|l| l == line), "missing `{line}` in:\n{out}");
        }
    }

    #[test]
    fn head_lag_reads_infinite_until_a_head_is_published() {
        let out = render(|_| {});
        assert!(out.lines().any(|l| l == "lite_head_lag_seconds inf"), "{out}");
        let out = render(|m| m.head_lag_seconds.set(3.0));
        assert!(out.lines().any(|l| l == "lite_head_lag_seconds 3"), "{out}");
    }

    #[test]
    fn labeled_series_appear_after_observation() {
        let out = render(|m| {
            m.request("eth_call", Outcome::Miss);
            m.request("eth_sendRawTransaction", Outcome::Refused);
            m.answer(true);
            m.proof_failure(FailureSource::Peer);
            m.anchor_unreachable();
            m.beacon_optimistic(FailureSource::Anchor);
            m.head_number.set(7.0);
            m.set_peers(1, 5);
        });
        assert!(out.contains("lite_peers{kind=\"static\"} 1"), "{out}");
        assert!(out.contains("lite_peers{kind=\"discovered\"} 5"), "{out}");
        assert!(
            out.contains("lite_requests_total{method=\"eth_call\",outcome=\"miss\"} 1"),
            "{out}"
        );
        assert!(out.contains("outcome=\"refused\""), "{out}");
        assert!(out.contains("lite_anchor_unreachable_total 1"), "{out}");
        assert!(out.contains("lite_beacon_optimistic_total{source=\"anchor\"} 1"), "{out}");
        assert!(out.contains("lite_answers_total{verified=\"true\"} 1"), "{out}");
        assert!(out.contains("lite_proof_failures_total{source=\"peer\"} 1"), "{out}");
        assert!(out.contains("lite_head_number 7"), "{out}");
    }

    #[test]
    fn every_outcome_and_failure_source_has_its_own_series() {
        let out = render(|m| {
            for (n, outcome) in [Outcome::Local, Outcome::Refused, Outcome::Miss, Outcome::Error]
                .into_iter()
                .enumerate()
            {
                for _ in 0..=n {
                    m.request("eth_getBalance", outcome);
                }
            }
            for (n, source) in FailureSource::ALL.into_iter().enumerate() {
                for _ in 0..=n {
                    m.proof_failure(source);
                }
            }
            m.answer(false);
        });
        for line in [
            "lite_requests_total{method=\"eth_getBalance\",outcome=\"local\"} 1",
            "lite_requests_total{method=\"eth_getBalance\",outcome=\"refused\"} 2",
            "lite_requests_total{method=\"eth_getBalance\",outcome=\"miss\"} 3",
            "lite_requests_total{method=\"eth_getBalance\",outcome=\"error\"} 4",
            "lite_proof_failures_total{source=\"beacon\"} 1",
            "lite_proof_failures_total{source=\"anchor\"} 2",
            "lite_proof_failures_total{source=\"peer\"} 3",
            "lite_proof_failures_total{source=\"upstream\"} 4",
            "lite_answers_total{verified=\"true\"} 0",
            "lite_answers_total{verified=\"false\"} 1",
        ] {
            assert!(out.lines().any(|l| l == line), "missing `{line}` in:\n{out}");
        }
    }
}
