//! Msgboard metric wiring.
//!
//! `docs/msgboard-parity-gaps.md` §3.1 records the gauges as wired and updated
//! by `insert_checked` / `set_head` / `load_from_db` — but nothing failed if a
//! call site were dropped, which is how §3.1 came to be needed in the first
//! place (four histograms had been declared and never instantiated).
//!
//! §14 added counters for the same reason at a different level: two reth-only
//! wire behaviours (rejecting the difficulty overflow, capping inbound
//! requests) were observable only by reading debug logs. A counter that is
//! declared but never incremented would recreate exactly the §3.1 defect, so
//! the movement of each one is asserted here, not just its existence.
//!
//! This is one test rather than several, and it lives in `tests/` rather than
//! beside the code, for a reason worth stating so nobody "tidies" it into
//! per-case tests again.
//!
//! `metrics-derive`'s generated `Default` caches the whole metric struct in a
//! `static OnceLock` (`metrics-derive-0.1.2/src/expand.rs:123`) and hands out
//! `_partial_clone()`s of it. So the handles are registered **once per
//! process**, against whichever recorder was active at the first
//! `MsgBoard::new()`. Every later board — in any test — reuses those handles.
//! That defeats `metrics::with_local_recorder`: a second test's thread-local
//! recorder registers nothing and snapshots empty. It also means the counters
//! are cumulative across everything in this file, hence the single sequence
//! with per-phase snapshots.
//!
//! `Snapshotter::snapshot` drains what it reports, so each phase's snapshot
//! shows that phase's activity — take one per phase and query it, rather than
//! re-snapshotting per assertion.

use std::sync::Arc;

use alloy_primitives::{Bytes, B256};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use reth_msgboard::MsgBoard;
use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};

/// `work_multiplier`/`work_divisor` whose exact difficulty exceeds `u64::MAX`.
/// Erigon's `uint64` arithmetic wraps these to a trivially cheap threshold;
/// reth rejects them. See `docs/msgboard-parity-gaps.md` §14.1.
const OVERFLOW_MULTIPLIER: u64 = 1_014_806_211_241_672_337;
const OVERFLOW_DIVISOR: u64 = 16;

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

/// A nonce whose `PoW` hash does *not* satisfy the difficulty — the ordinary
/// bad-work case, as distinct from the §14.1 overflow.
fn bad_pow(data: &[u8], block: u64) -> PoWMsg {
    (1u64..=1_000_000)
        .find_map(|n| {
            let m = pow_msg(n, data);
            m.clone().to_checked(block, 0).is_err().then_some(m)
        })
        .expect("no invalid nonce found")
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

    fn counter(&self, name: &str) -> u64 {
        self.0
            .iter()
            .find_map(|(n, v)| match v {
                DebugValue::Counter(c) if n == name => Some(*c),
                _ => None,
            })
            .unwrap_or_else(|| panic!("counter {name} was never registered"))
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
fn every_metric_is_instantiated_and_moves() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("no other recorder installed in this process");

    // ── phase 1: the whole declared set exists ───────────────────────────────
    //
    // §3.1's original defect was metrics *declared but never instantiated* —
    // invisible to any test that only reads the ones it already knows work.
    let board = board_at(10);
    let snap = Snap::take(&snapshotter);
    assert_eq!(
        snap.names(),
        vec![
            "msgboard.accepted_local",
            "msgboard.accepted_remote",
            "msgboard.add_remote_msgs_duration_seconds",
            "msgboard.announcements_received",
            "msgboard.announcements_sent",
            "msgboard.bad_message",
            "msgboard.bad_protocol",
            "msgboard.bodies_received",
            "msgboard.bodies_served",
            "msgboard.change_block_duration_seconds",
            "msgboard.evicted",
            "msgboard.expired",
            "msgboard.msg_count",
            "msgboard.msg_size",
            "msgboard.rejected_insufficient_work",
            "msgboard.rejected_invalid_difficulty",
            "msgboard.rejected_invalid_pow",
            "msgboard.rejected_other",
            "msgboard.rejected_oversized",
            "msgboard.requests_received",
            "msgboard.requests_sent",
            "msgboard.requests_truncated",
            "msgboard.sent_to_peer_duration_seconds",
            "msgboard.skipped_block_too_old",
            "msgboard.skipped_board_overflow",
            "msgboard.skipped_duplicate",
            "msgboard.skipped_unknown_block",
            "msgboard.write_to_db_bytes",
            "msgboard.write_to_db_duration_seconds",
        ],
        "every declared msgboard metric must actually be instantiated",
    );
    assert_eq!(snap.gauge("msgboard.msg_count"), Some(0.0), "empty board");
    assert_eq!(snap.gauge("msgboard.msg_size"), Some(0.0), "empty board");

    // ── phase 2: gauges follow inserts, accepted_local counts them ───────────
    // Three messages carrying 1 + 2 + 3 = 6 bytes of data.
    board.add_local_msg(mined(&[1], 10)).expect("accepted");
    board.add_local_msg(mined(&[1, 2], 10)).expect("accepted");
    board.add_local_msg(mined(&[1, 2, 3], 10)).expect("accepted");

    let snap = Snap::take(&snapshotter);
    assert_eq!(snap.gauge("msgboard.msg_count"), Some(3.0), "msg_count must follow insert_checked");
    assert_eq!(
        snap.gauge("msgboard.msg_size"),
        Some(6.0),
        "msg_size must be the sum of data bytes, not a message count",
    );
    assert_eq!(snap.counter("msgboard.accepted_local"), 3);

    // ── phase 3: set_head's prune is counted, not just gauged ────────────────
    board.set_head(10 + easy_cfg().block_range + 1, B256::repeat_byte(0x02));

    let snap = Snap::take(&snapshotter);
    assert_eq!(
        snap.gauge("msgboard.msg_count"),
        Some(0.0),
        "msg_count must follow set_head's prune, not just inserts",
    );
    assert_eq!(snap.gauge("msgboard.msg_size"), Some(0.0));
    assert_eq!(snap.counter("msgboard.expired"), 3, "expiry must be counted, not just gauged");

    // ── phase 4: every rejection reason lands in its own counter ─────────────
    //
    // The split is the point: `rejected_invalid_difficulty` is the §14.1
    // overflow, where reth and erigon genuinely disagree about a message on the
    // wire. Lumping it in with ordinary bad `PoW` would make the one number
    // worth watching after deploy indistinguishable from routine noise.
    let board = board_at(10);
    let base = mined(&[7], 10);

    // `..base` rather than `..base.clone()`: this one overrides `data`, the only
    // non-Copy field, so nothing is moved out of `base` and it stays usable.
    let oversized = PoWMsg { data: Bytes::from(vec![0u8; 9 * 1024]), ..base };

    let weak = PoWMsg { work_divisor: 2_000_000, ..base.clone() };
    let overflow = PoWMsg {
        work_multiplier: OVERFLOW_MULTIPLIER,
        work_divisor: OVERFLOW_DIVISOR,
        ..base.clone()
    };
    let bad_work = bad_pow(&[7], 10);
    let unknown_block = PoWMsg { block_hash: B256::repeat_byte(0xEE), ..base.clone() };

    let (added, kickable) = board.add_remote_msgs(vec![
        oversized,
        weak,
        overflow,
        bad_work,
        unknown_block,
        base.clone(),
        base, // duplicate of the one just accepted
    ]);
    assert_eq!(added, 1, "only the well-formed message is accepted");
    assert_eq!(kickable, 4, "oversized, weak, overflow and bad-pow are all penalised");

    let snap = Snap::take(&snapshotter);
    assert_eq!(snap.counter("msgboard.accepted_remote"), 1);
    assert_eq!(snap.counter("msgboard.rejected_oversized"), 1);
    assert_eq!(snap.counter("msgboard.rejected_insufficient_work"), 1);
    assert_eq!(
        snap.counter("msgboard.rejected_invalid_difficulty"),
        1,
        "the difficulty overflow must be counted separately from ordinary bad PoW",
    );
    assert_eq!(snap.counter("msgboard.rejected_invalid_pow"), 1);
    assert_eq!(snap.counter("msgboard.skipped_unknown_block"), 1);
    assert_eq!(snap.counter("msgboard.skipped_duplicate"), 1);
    assert_eq!(
        snap.counter("msgboard.rejected_other"),
        0,
        "no rejection should fall through to the catch-all",
    );

    // ── phase 5: eviction at count_limit is its own counter ──────────────────
    let cfg = MsgboardConfig { count_limit: 2, ..easy_cfg() };
    let board = Arc::new(MsgBoard::new(cfg));
    board.set_ready();
    board.set_head(10, block_hash_one());

    board.add_local_msg(mined(&[1], 10)).expect("accepted");
    board.add_local_msg(mined(&[2], 10)).expect("accepted");
    board.add_local_msg(mined(&[3], 10)).expect("accepted");

    let snap = Snap::take(&snapshotter);
    assert_eq!(snap.counter("msgboard.evicted"), 1, "one message displaced at count_limit");
    assert_eq!(snap.gauge("msgboard.msg_count"), Some(2.0), "board stays at count_limit");
}
