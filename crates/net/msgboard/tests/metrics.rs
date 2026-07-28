//! Msgboard gauge wiring.
//!
//! `docs/msgboard-parity-gaps.md` §3.1 records `msgboard_msg_count`,
//! `msgboard_msg_size`, and `msgboard_write_to_db_bytes` as wired and updated by
//! `insert_checked` / `set_head` / `load_from_db` — but nothing failed if a call
//! site were dropped, which is how §3.1 came to be needed in the first place
//! (the four histograms had been declared and never instantiated).
//!
//! This lives in `tests/` rather than beside the code on purpose. Asserting a
//! gauge's value needs a process-global recorder, and the msgboard gauges carry
//! no labels — so every `MsgBoard` in a process writes the same keys. Inside the
//! unit-test binary the board tests run in parallel and would clobber each
//! other's values. Cargo gives each integration-test file its own process, so
//! the recorder here is uncontended.

use std::sync::Arc;

use alloy_primitives::{Bytes, B256};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use reth_msgboard::MsgBoard;
use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};

const fn block_hash_one() -> B256 {
    B256::repeat_byte(0x01)
}

const fn easy_cfg() -> MsgboardConfig {
    MsgboardConfig {
        work_multiplier: 1,
        work_divisor: 1_000_000,
        size_limit: 8 * 1024,
        count_limit: 10_000,
        block_range: 120,
        stale_block_buffer: 3,
        gossip_disabled: false,
    }
}

fn pow_msg(nonce: u64, data: &[u8]) -> PoWMsg {
    PoWMsg {
        version: VERSION_V1,
        block_hash: block_hash_one(),
        nonce,
        work_multiplier: 1,
        work_divisor: 1_000_000,
        category: B256::repeat_byte(0xCA),
        data: Bytes::copy_from_slice(data),
    }
}

/// Mine a message valid at `block`.
fn mined(data: &[u8], block: u64) -> PoWMsg {
    (1u64..=1_000_000)
        .find_map(|n| {
            let m = pow_msg(n, data);
            m.clone().to_checked(block, 0).is_ok().then_some(m)
        })
        .expect("no valid nonce found")
}

/// A single point-in-time reading of the recorder.
///
/// Taken once and queried many times: `Snapshotter::snapshot` drains what it
/// reports, so calling it per-assertion would have each assertion observing a
/// different (and mostly empty) picture.
struct Snap(Vec<(String, DebugValue)>);

impl Snap {
    fn take(snapshotter: &Snapshotter) -> Self {
        Self(
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .map(|(key, _unit, _desc, value)| (key.key().name().to_owned(), value))
                .collect(),
        )
    }

    /// Gauge value by metric name. Keys carry the `metrics` crate's dotted form
    /// (`msgboard.msg_count`); the underscored spelling in §3.1 is the
    /// Prometheus rendering.
    fn gauge(&self, name: &str) -> Option<f64> {
        self.0.iter().find_map(|(n, v)| match v {
            DebugValue::Gauge(g) if n == name => Some(g.into_inner()),
            _ => None,
        })
    }

    fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.0.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

fn board_at(height: u64) -> Arc<MsgBoard> {
    let board = Arc::new(MsgBoard::new(easy_cfg()));
    board.set_ready();
    board.set_head(height, block_hash_one());
    board
}

#[test]
fn gauges_track_the_board_through_insert_and_expiry() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("no other recorder installed in this process");

    let board = board_at(10);

    // §3.1's original defect was metrics *declared but never instantiated* —
    // invisible to any test that only reads the ones it already knows work. So
    // assert the whole declared set is present.
    let snap = Snap::take(&snapshotter);
    assert_eq!(
        snap.names(),
        vec![
            "msgboard.add_remote_msgs_duration_seconds",
            "msgboard.change_block_duration_seconds",
            "msgboard.msg_count",
            "msgboard.msg_size",
            "msgboard.sent_to_peer_duration_seconds",
            "msgboard.write_to_db_bytes",
            "msgboard.write_to_db_duration_seconds",
        ],
        "every declared msgboard metric must actually be instantiated",
    );
    assert_eq!(snap.gauge("msgboard.msg_count"), Some(0.0), "empty board");
    assert_eq!(snap.gauge("msgboard.msg_size"), Some(0.0), "empty board");

    // Three messages carrying 1 + 2 + 3 = 6 bytes of data.
    board.add_local_msg(mined(&[1], 10)).expect("accepted");
    board.add_local_msg(mined(&[1, 2], 10)).expect("accepted");
    board.add_local_msg(mined(&[1, 2, 3], 10)).expect("accepted");

    let snap = Snap::take(&snapshotter);
    assert_eq!(snap.gauge("msgboard.msg_count"), Some(3.0), "msg_count must follow insert_checked",);
    assert_eq!(
        snap.gauge("msgboard.msg_size"),
        Some(6.0),
        "msg_size must be the sum of data bytes, not a message count",
    );

    // Advance past the live window: everything expires.
    board.set_head(10 + easy_cfg().block_range + 1, B256::repeat_byte(0x02));

    let snap = Snap::take(&snapshotter);
    assert_eq!(
        snap.gauge("msgboard.msg_count"),
        Some(0.0),
        "msg_count must follow set_head's prune, not just inserts",
    );
    assert_eq!(snap.gauge("msgboard.msg_size"), Some(0.0));
}
