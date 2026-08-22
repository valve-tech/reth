//! The live-session gauge must return to zero on every exit path.
//!
//! This lives in its own integration test, not beside the code, because it
//! needs a process where the recorder is installed before any
//! [`MsgboardMetrics`] is built. Metric handles bind to whichever recorder was
//! live when they were created, so a unit test sharing a binary with 144 others
//! snapshots a registry its own counters were never registered in.

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use reth_msgboard::{metrics::MsgboardMetrics, protocol::SessionGuard};

/// Opens three sessions, closes them three different ways, and reads once.
///
/// `snapshot()` drains, so a read per assertion would report deltas rather than
/// the running value. The paired counters carry the weight: `closed` short of
/// `opened` means a `Drop` did not run, which is the regression that would leave
/// an operator reading a healthy peer count with no peer attached.
#[test]
fn the_gauge_returns_to_zero_on_every_exit_path() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("no other recorder installed in this test binary");

    let metrics = MsgboardMetrics::default();

    // 1. Falls off the end.
    {
        let _session = SessionGuard::new(metrics.clone());
    }

    // 2. Returns early.
    fn bails(metrics: MsgboardMetrics) -> bool {
        let _session = SessionGuard::new(metrics);
        return false;
        #[allow(unreachable_code)]
        true
    }
    assert!(!bails(metrics.clone()));

    // 3. Panics. The connection task is spawned, so a panic there is contained and would otherwise
    //    leak a count for the life of the process.
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _session = SessionGuard::new(metrics);
        panic!("session died mid-frame");
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

    assert_eq!(read("msgboard.peer_sessions_opened"), Some(3.0));
    assert_eq!(
        read("msgboard.peer_sessions_closed"),
        Some(3.0),
        "every session must close, including the early return and the panic",
    );
    assert_eq!(
        read("msgboard.peer_sessions"),
        Some(0.0),
        "three opened and three closed must leave the gauge where it started",
    );
}
