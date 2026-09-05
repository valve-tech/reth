//! What one flush costs the process.
//!
//! `flush_to_db` runs on a timer for the life of the node, so it pays its cost
//! again every `commit_every` whether or not the board changed. Two defects hid
//! in that path and no correctness test could see either: the flush copied the
//! whole index out under the state lock, and it re-encoded and rewrote every
//! row on disk. At the default limits that is 10,000 message structs copied and
//! 81.92 MB written every 15 seconds, for a board that usually changes by a
//! handful of messages.
//!
//! Allocation volume catches both, and catches them without timing anything.
//! Note what it does *not* measure: a message payload is a refcounted `Bytes`,
//! so copying a `CheckedPoWMsg` never copied the body. The waste was the
//! structs, the vector holding them, and the re-encoding — 48.7 KB per no-op
//! flush over the 800 KiB board below, against 712 bytes once the flush writes
//! only what changed.
//!
//! The counter is thread-local rather than global, so a test running beside
//! this one on another thread cannot pollute the measurement.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use alloy_primitives::{Bytes, B256};
use reth_msgboard::{db::open_msgboard_db, MsgBoard};
use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};

thread_local! {
    /// Bytes this thread has asked the allocator for.
    ///
    /// `const`-initialised so reading it inside the allocator cannot itself
    /// allocate, which would recurse.
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, counting request sizes per thread.
struct CountingAllocator;

// SAFETY: every method forwards to the system allocator unchanged. The counter
// is a thread-local `Cell` of a plain integer, so touching it neither allocates
// nor blocks, and the `try_with` tolerates a thread whose locals are already
// destroyed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATED.try_with(|counted| counted.set(counted.get() + layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Bytes allocated on this thread while `f` runs.
fn allocated_by<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATED.with(Cell::get);
    let value = f();
    let after = ALLOCATED.with(Cell::get);
    (value, after - before)
}

const MESSAGE_COUNT: usize = 200;
const MESSAGE_BYTES: usize = 4 * 1024;

/// A work divisor that leaves the exact difficulty in single digits at this
/// message size. `difficulty` is `(2^24 + size * 10_000) * multiplier /
/// divisor`, so a divisor of `2^24` keeps it near 1 whatever the payload —
/// which is what makes mining 200 messages affordable in a debug build.
const WORK_DIVISOR: u64 = 1 << 24;

const fn block_hash() -> B256 {
    B256::repeat_byte(0x01)
}

fn mine(data: &[u8]) -> PoWMsg {
    for nonce in 1u64..=1_000_000 {
        let msg = PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash(),
            nonce,
            work_multiplier: 1,
            work_divisor: WORK_DIVISOR,
            category: B256::repeat_byte(0xCA),
            data: Bytes::copy_from_slice(data),
        };
        if msg.verify().is_ok() {
            return msg;
        }
    }
    panic!("no valid nonce found within 1M iterations");
}

/// A flush of an unchanged board must cost almost nothing.
///
/// The board here holds 200 messages. A flush that copies the index, or that
/// re-encodes every row, allocates on that scale; one that writes only what
/// changed allocates on the scale of the transaction itself.
#[test]
fn flushing_an_unchanged_board_costs_almost_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = open_msgboard_db(dir.path()).expect("open db");
    let cfg = MsgboardConfig {
        work_multiplier: 1,
        work_divisor: WORK_DIVISOR,
        size_limit: 8 * 1024,
        count_limit: 10_000,
        block_range: 120,
        stale_block_buffer: 3,
        gossip_disabled: false,
    };
    let board = MsgBoard::with_db(cfg, env);
    board.set_ready();
    board.set_head(100, block_hash());

    for i in 0..MESSAGE_COUNT {
        let mut data = vec![0u8; MESSAGE_BYTES];
        data[..8].copy_from_slice(&(i as u64).to_be_bytes());
        board.add_local_msg(mine(&data)).expect("valid message");
    }

    let board_bytes = MESSAGE_COUNT * MESSAGE_BYTES;
    let (first, first_cost) = allocated_by(|| board.flush_to_db().expect("first flush"));
    assert!(first > 0, "the first flush stores the board");

    let (second, second_cost) = allocated_by(|| board.flush_to_db().expect("second flush"));

    // Measured at 712 bytes here, against 48,737 for a flush that copies the
    // index and rewrites every row. The bound sits between the two with room
    // for MDBX to allocate differently on another platform.
    assert!(
        second_cost < 8 * 1024,
        "a no-op flush allocated {second_cost} bytes over a {board_bytes}-byte board \
         (the first flush allocated {first_cost})",
    );
    assert_eq!(second, 0, "an unchanged board rewrites nothing");
}
