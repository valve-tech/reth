//! The live-subscription gauge must return to zero on every exit path.
//!
//! The audit asked whether concurrent `msgboard_subscribe` tasks are bounded.
//! They are — jsonrpsee caps them per connection, and
//! `subscribe_is_bounded_by_the_jsonrpsee_per_connection_cap` proves it against
//! a real server. What the audit found missing is the *reading*: nothing told
//! an operator how many subscriptions are live, so a leak that never reaches
//! the cap is invisible and a node sitting at the cap looks identical to a node
//! with none.
//!
//! This lives in its own integration test for the same reason
//! `session_gauge.rs` does: metric handles bind to whichever recorder was live
//! when they were built, so a unit test sharing a binary with two hundred
//! others snapshots a registry its own counters were never registered in.

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use reth_msgboard::{metrics::MsgboardMetrics, rpc::SubscriptionGuard};

/// Opens three subscriptions, closes them three different ways, and reads once.
///
/// `snapshot()` drains, so a read per assertion would report deltas rather than
/// the running value. The paired counters carry the weight: `closed` short of
/// `opened` means a `Drop` did not run, and that is the regression that leaves
/// an operator reading a subscription count with nobody subscribed.
#[test]
fn the_gauge_returns_to_zero_on_every_exit_path() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("no other recorder installed in this test binary");

    let metrics = MsgboardMetrics::default();

    // 1. Falls off the end.
    {
        let _subscription = SubscriptionGuard::new(metrics.clone());
    }

    // 2. Returns early. The subscribe loop breaks out of `tokio::select!` on a closed sink, a
    //    serialisation failure and a send failure alike.
    fn bails(metrics: MsgboardMetrics) -> bool {
        let _subscription = SubscriptionGuard::new(metrics);
        return false;
        #[allow(unreachable_code)]
        true
    }
    assert!(!bails(metrics.clone()));

    // 3. Panics. The subscription runs in a spawned task, so a panic there is contained and would
    //    otherwise leak a count for the life of the process.
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _subscription = SubscriptionGuard::new(metrics);
        panic!("subscription died mid-notification");
    }));
    assert!(caught.is_err(), "the panic must actually have happened");

    let snap = snapshotter.snapshot().into_vec();
    let read = |name: &str| {
        snap.iter().find_map(|(key, _, _, value)| {
            (key.key().name() == name).then(|| match value {
                DebugValue::Gauge(g) => g.into_inner(),
                DebugValue::Counter(c) => *c as f64,
                other => panic!("{name} is {other:?}"),
            })
        })
    };

    assert_eq!(read("msgboard.rpc_subscriptions_opened"), Some(3.0));
    assert_eq!(
        read("msgboard.rpc_subscriptions_closed"),
        Some(3.0),
        "every subscription must close, including the early return and the panic",
    );
    assert_eq!(
        read("msgboard.rpc_subscriptions"),
        Some(0.0),
        "three opened and three closed must leave the gauge where it started",
    );
}
