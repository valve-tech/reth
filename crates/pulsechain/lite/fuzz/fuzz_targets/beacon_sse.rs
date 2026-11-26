//! Arbitrary bytes through the SSE event stream reader.
//!
//! The stream is delivered three ways (one chunk, cut at fuzz-chosen points, and one byte at a
//! time) and every way must read the same events, which must also match a whole-text model:
//! line ends normalised to LF, events split at blank lines, each event parsed alone. An input
//! may repeat its text many times, so streams past the 64 KiB event cap are reachable.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use reth_pulsechain_lite::{
    beacon::{Event, MAX_SSE_EVENT},
    fuzz_api::{parse_sse_block, read_sse_events},
};
use reth_pulsechain_lite_fuzz::block_on;

#[derive(Debug, Arbitrary)]
struct Input {
    repeat: u16,
    cuts: Vec<u32>,
    text: Vec<u8>,
}

/// The events a reader of the whole text must return.
fn model(text: &[u8]) -> Vec<Event> {
    let mut norm = Vec::with_capacity(text.len());
    let mut after_cr = false;
    for &b in text {
        match (b, std::mem::replace(&mut after_cr, b == b'\r')) {
            (b'\r', _) => norm.push(b'\n'),
            (b'\n', true) => {}
            _ => norm.push(b),
        }
    }
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(at) = norm[start..].windows(2).position(|w| w == b"\n\n") {
        let end = start + at + 2;
        // An event (its blank line included) longer than the cap ends the stream, wherever the
        // chunks fall.
        if end - start > MAX_SSE_EVENT {
            return out;
        }
        if let Some(e) = parse_sse_block(&String::from_utf8_lossy(&norm[start..end])) {
            out.push(e);
        }
        start = end;
    }
    out
}

fn chunked(text: &[u8], cuts: &[u32]) -> Vec<Vec<u8>> {
    let mut at: Vec<usize> = cuts.iter().map(|c| *c as usize % (text.len() + 1)).collect();
    at.sort_unstable();
    let mut from = 0;
    at.into_iter()
        .chain([text.len()])
        .map(|c| {
            let chunk = text[from..c].to_vec();
            from = c;
            chunk
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = Input::arbitrary(&mut Unstructured::new(data)) else { return };
    let reps = 1 + usize::from(input.repeat) % 64;
    let reps = if input.text.len() * reps > 3 * MAX_SSE_EVENT { 1 } else { reps };
    let text = input.text.repeat(reps);
    let want = model(&text);
    let whole = block_on(read_sse_events(vec![text.clone()]));
    let cut = block_on(read_sse_events(chunked(&text, &input.cuts)));
    assert_eq!(whole, cut, "chunking changed the events read");
    if text.len() <= 1 << 18 {
        let bytewise = block_on(read_sse_events(text.iter().map(|b| vec![*b]).collect()));
        assert_eq!(whole, bytewise, "byte-at-a-time reading changed the events read");
    }
    assert_eq!(whole, want, "the stream reader differs from the whole-text model");
});
