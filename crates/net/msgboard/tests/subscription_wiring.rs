//! The subscribe path must actually take a [`SubscriptionGuard`].
//!
//! `subscription_gauge.rs` proves the guard counts correctly. It cannot prove
//! the guard is ever constructed, so the gauge could be perfect and still read
//! zero on a node full of subscribers — which is the blind spot the audit
//! named. This drives a real subscription through the RPC module and reads the
//! gauge.
//!
//! Its own binary, because installing a recorder is process-wide and the
//! sibling test installs one of its own.

use std::sync::Arc;

use jsonrpsee::RpcModule;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use reth_msgboard::{board::MsgBoard, rpc::MsgboardApi, rpc_api::MsgboardApiServer};
use reth_msgboard_types::MsgboardConfig;

#[tokio::test]
async fn subscribing_through_the_rpc_module_raises_the_gauge() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("no other recorder installed in this test binary");

    let board = Arc::new(MsgBoard::new(MsgboardConfig::default()));
    board.set_ready();
    let module: RpcModule<MsgboardApi> = MsgboardApi::new(board).into_rpc();

    let _sub = module
        .subscribe_unbounded("msgboard_subscribe", vec!["newMessages"])
        .await
        .expect("the subscription must be accepted");

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

    assert_eq!(
        read("msgboard.rpc_subscriptions_opened"),
        Some(1.0),
        "the subscribe path must take a guard",
    );
    assert_eq!(
        read("msgboard.rpc_subscriptions"),
        Some(1.0),
        "the subscription is still live, so the gauge must still be up",
    );
}
