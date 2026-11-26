//! The memory tier's charged bytes track what it really allocates. This needs its own test
//! binary: it swaps the global allocator to count live heap bytes.

use alloy_primitives::{keccak256, Bytes};
use reth_pulsechain_lite::store::{NodeStore, Store};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicIsize, Ordering},
};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Heap bytes the store holds per charged byte after 1.5x its cap is put and each key read once.
fn heap_per_charged_byte(len: usize, cap: u64) -> f64 {
    let before = LIVE.load(Ordering::Relaxed);
    let s = Store::in_memory(cap);
    let item = |i: u32| {
        let mut v = vec![(i % 251) as u8; len];
        v[..4].copy_from_slice(&i.to_be_bytes());
        let v = Bytes::from(v);
        (keccak256(&v), v)
    };
    let n = u32::try_from(cap * 3 / 2 / len as u64).unwrap();
    for i in 0..n {
        let (k, v) = item(i);
        s.put(k, v);
    }
    for i in 0..n {
        s.get(&item(i).0);
    }
    let held = LIVE.load(Ordering::Relaxed) - before;
    let ratio = held as f64 / s.bytes() as f64;
    drop(s);
    ratio
}

#[test]
fn memory_tier_heap_stays_within_its_charge() {
    // The caps put the hash map at different points of its growth cycle.
    for cap in [3 << 19, 5 << 19, 7 << 19] {
        for len in [32, 45, 70, 500] {
            let ratio = heap_per_charged_byte(len, cap);
            assert!(ratio <= 1.2, "cap {cap}, {len}-byte values: {ratio:.2} heap per charged byte");
        }
    }
}
