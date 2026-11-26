//! Thin wrappers over crate-private parsers, for the cargo-fuzz targets in `fuzz/` only.
//!
//! Built with the non-default `fuzzing` feature. Nothing here is a stable API.

use crate::{
    beacon::{Event, SourceError},
    config::{ConfigError, LiteArgs},
};
use clap::Parser;
use serde_json::Value;
use std::{path::Path, time::Duration};
use url::Url;

/// Which bounded beacon answer shape to parse with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconShape {
    /// `headers/head`.
    Head,
    /// `finality_checkpoints`.
    Finality,
    /// The data of an SSE `head` event.
    SseHead,
    /// `blocks/{id}`.
    Block,
}

/// Parses `bytes` as the beacon client parses a response body of that `shape`.
pub fn parse_beacon_body(shape: BeaconShape, bytes: &[u8]) -> Result<Value, SourceError> {
    use crate::beacon::{BLOCK_SHAPE, FINALITY_SHAPE, HEAD_SHAPE, SSE_HEAD_SHAPE};
    match shape {
        BeaconShape::Head => HEAD_SHAPE.parse(bytes),
        BeaconShape::Finality => FINALITY_SHAPE.parse(bytes),
        BeaconShape::SseHead => SSE_HEAD_SHAPE.parse(bytes),
        BeaconShape::Block => BLOCK_SHAPE.parse(bytes),
    }
}

/// Every event an event stream that delivers `chunks` yields before it ends. Must run inside a
/// tokio runtime with time enabled.
pub async fn read_sse_events(chunks: Vec<Vec<u8>>) -> Vec<Event> {
    let mut events = crate::beacon::EventStream::from_chunks(chunks, Duration::from_secs(5));
    let mut out = Vec::new();
    while let Some(e) = events.next_event().await {
        out.push(e);
    }
    out
}

/// Parses one SSE event block (the text up to and including its blank line).
pub fn parse_sse_block(block: &str) -> Option<Event> {
    crate::beacon::parse_sse_block(block, crate::beacon::Topics::Head)
}

/// Parses the text of a URL file as `--beacon.url-file` does.
pub fn parse_url_text(text: &str, flag: &'static str) -> Result<Vec<Url>, ConfigError> {
    crate::config::parse_url_text(text, flag, Path::new("urls"))
}

/// Parses `--{flag}={raw}` on the `reth-lite` command line.
fn parse_flag(flag: &str, raw: &str) -> Option<LiteArgs> {
    LiteArgs::try_parse_from(["reth-lite", &format!("--{flag}={raw}")]).ok()
}

/// What `--cache.size` and `--disk.limit` read from `raw`, in that order.
pub fn size_flags(raw: &str) -> [Option<usize>; 2] {
    [
        parse_flag("cache.size", raw).and_then(|a| a.cache_size),
        parse_flag("disk.limit", raw).map(|a| a.disk_limit),
    ]
}

/// What `--beacon.poll`, `--finalized.recheck` and `--head.max-age` read from `raw`, in that
/// order.
pub fn duration_flags(raw: &str) -> [Option<Duration>; 3] {
    [
        parse_flag("beacon.poll", raw).map(|a| a.beacon_poll),
        parse_flag("finalized.recheck", raw).map(|a| a.finalized_recheck),
        parse_flag("head.max-age", raw).map(|a| a.head_max_age),
    ]
}
