//! Command line flags and the resolved [`LiteConfig`].
//!
//! Size flags use pulse-reth's [`parse_byte_size`] (binary `B KB MB GB TB`). Duration flags use
//! [`humantime::parse_duration`], as pulse-reth's humantime flags do, each at most 24 hours. A
//! bare number of seconds, which pulse-reth's `parse_duration_from_secs_or_ms` flags take, is
//! refused.

use crate::{
    chain::MAX_BODY_BYTES,
    light_client::{Checkpoint, StoreOrigin},
    memory::{Memory, MAX_CACHE_BYTES, RUNTIME_BYTES},
    rpc::RECEIPT_CACHE_BYTES,
    store::MIN_DISK_LIMIT,
};
use alloy_primitives::B256;
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Parser,
};
use humantime::parse_duration;
use reth_cli_util::parse_byte_size;
use reth_network_peers::NodeRecord;
use reth_pulsechain_forks::network::pulsechain_network;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use url::Url;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;
/// The shortest `--beacon.poll`: a shorter one hammers the beacon (or spins on a refused loopback
/// connection) for no gain with 10 s slots.
const MIN_POLL: Duration = Duration::from_secs(1);
/// The slot length.
pub(crate) const SLOT: Duration = Duration::from_secs(10);
/// The shortest `--head.max-age`: the held head is up to one slot old, plus delivery, before the
/// next one arrives, so a shorter limit marks a healthy head stale.
const MIN_HEAD_MAX_AGE: Duration = Duration::from_secs(20);
/// The longest duration flag. The follower multiplies `--beacon.poll` by a small factor, which
/// panics on overflow, and a day is already far past any useful value of each flag.
const MAX_DURATION: Duration = Duration::from_secs(24 * 3600);
/// The shortest `--snap.probe-timeout`: any wait above zero.
const MIN_SNAP_PROBE: Duration = Duration::from_millis(1);

/// What to do when a read needs state the node has not verified yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnMiss {
    /// Return the miss error.
    Error,
    /// Return the miss error and fetch the missing pieces in the background.
    ErrorAndWarm,
    /// Fetch and verify before answering.
    #[default]
    Fetch,
}

impl FromStr for OnMiss {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "error" => Ok(Self::Error),
            "error-and-warm" => Ok(Self::ErrorAndWarm),
            "fetch" => Ok(Self::Fetch),
            other => Err(format!("unknown --state.on-miss `{other}` (error|error-and-warm|fetch)")),
        }
    }
}

/// Where state comes from when upstream URLs are given (`--upstream.mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamMode {
    /// Peers first; the upstreams when no peer serves the state, or every answer fails
    /// verification.
    #[default]
    Fallback,
    /// The upstreams only: no state is fetched from peers.
    Only,
}

impl FromStr for UpstreamMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "fallback" => Ok(Self::Fallback),
            "only" => Ok(Self::Only),
            other => Err(format!("unknown --upstream.mode `{other}` (fallback|only)")),
        }
    }
}

/// Whether a new head needs an execution peer to report the same block hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeadConfirm {
    /// A static `--peer` must hold the head's hash before the head moves (the default).
    #[default]
    Peer,
    /// The beacon quorum alone decides the head.
    None,
}

impl FromStr for HeadConfirm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "peer" => Ok(Self::Peer),
            "none" => Ok(Self::None),
            other => Err(format!("unknown --head.confirm `{other}` (peer|none)")),
        }
    }
}

/// How the node verifies a head before it follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeadVerify {
    /// A quorum of beacon sources reports the head (the default).
    #[default]
    Quorum,
    /// The sync committee's signature over the head, checked with the light-client protocol.
    SyncCommittee,
}

impl FromStr for HeadVerify {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "quorum" => Ok(Self::Quorum),
            "sync-committee" => Ok(Self::SyncCommittee),
            other => Err(format!("unknown --head.verify `{other}` (quorum|sync-committee)")),
        }
    }
}

fn parse_loopback(s: &str) -> Result<IpAddr, String> {
    let ip = if s == "localhost" {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        s.parse::<IpAddr>().map_err(|_| format!("--http.addr `{s}` is not an IP address"))?
    };
    if ip.is_loopback() {
        Ok(ip)
    } else {
        Err(format!("--http.addr `{s}` must be a loopback address"))
    }
}

/// Plain http is allowed for loopback hosts only: a key in the URL, and the answers, must not
/// cross a network in the clear. `localhost.` is not loopback here, as some stub resolvers send
/// the absolute name to DNS.
fn require_tls(url: &Url, flag: &'static str, line: Option<usize>) -> Result<(), ConfigError> {
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.scheme() == "https" || loopback {
        Ok(())
    } else {
        Err(ConfigError::InsecureUrl { flag, line })
    }
}

/// The host of `url`, spelled one way: every loopback name or address is `localhost`, a trailing
/// dot is dropped. A loopback name is `localhost` or a name under it (RFC 6761). Two DNS names
/// for one provider still look like two hosts.
fn host_key(url: &Url) -> Option<String> {
    let ip = match url.host()? {
        url::Host::Domain(d) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            let loopback = d == "localhost" || d.ends_with(".localhost");
            return Some(if loopback { "localhost".to_owned() } else { d })
        }
        url::Host::Ipv4(ip) => IpAddr::V4(ip),
        url::Host::Ipv6(ip) => ip.to_canonical(),
    };
    Some(if ip.is_loopback() { "localhost".to_owned() } else { ip.to_string() })
}

/// Parses an http(s) URL; plain http only for loopback. `line` is the 1-based line of a URL file.
/// The error never echoes the value: it may hold a key.
fn parse_url(s: &str, flag: &'static str, line: Option<usize>) -> Result<Url, ConfigError> {
    let url = Url::parse(s).map_err(|_| ConfigError::BadUrl { flag, line })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::BadUrl { flag, line });
    }
    // No request carries the fragment, so a key there is silently lost. The query is kept.
    if url.fragment().is_some() {
        return Err(ConfigError::UrlFragment { flag, line });
    }
    require_tls(&url, flag, line)?;
    Ok(url)
}

/// Whether `s` holds a URL, which may carry a key and must not be echoed.
fn looks_like_url(s: &str) -> bool {
    s.contains("://")
}

/// `path` for messages, or a placeholder when it looks like a URL, with or without its scheme: the
/// URL itself given to a file flag is a secret.
fn shown_path(path: &Path) -> String {
    let shown = path.display().to_string();
    if looks_like_url(&shown) || may_be_schemeless_url(path) {
        "<redacted: looks like a URL>".to_owned()
    } else {
        shown
    }
}

/// Whether `path` may be a URL without its scheme, as `host/key/369` is. A URL is never absolute,
/// so only a relative path may be one: with a query, fragment or user info, or with a `/` when it
/// does not start with `.` or `~` and its first component is not on disk.
fn may_be_schemeless_url(path: &Path) -> bool {
    let shown = path.to_string_lossy();
    if path.is_absolute() {
        return false
    }
    if shown.contains(['?', '#', '@']) {
        return true
    }
    if !shown.contains('/') || shown.starts_with(['.', '~']) {
        return false
    }
    path.components().next().is_none_or(|first| !Path::new(first.as_os_str()).exists())
}

/// Whether `s` holds a URL whose scheme is not `enode`. An enode is public, and redacting it
/// hides why a `--peer` value is refused.
fn holds_non_enode_url(s: &str) -> bool {
    s.match_indices("://").any(|(end, _)| {
        let start = s[..end]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |i| i + 1);
        &s[start..end] != "enode"
    })
}

/// Whether a value clap echoes may hold a key: a URL that is not an enode, or a URL without its
/// scheme, which has a path, query, fragment or user info. An enode keeps its `@` and a
/// `?discport=<digits>` query, which geth prints.
fn may_hold_key(value: &str) -> bool {
    if holds_non_enode_url(value) {
        return true;
    }
    let Some(rest) = value.strip_prefix("enode://") else {
        return value.contains(['/', '?', '#', '@'])
    };
    let (addr, query_ok) = match rest.split_once('?') {
        Some((addr, query)) => (
            addr,
            query
                .strip_prefix("discport=")
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        ),
        None => (rest, true),
    };
    addr.contains(['/', '#']) || !query_ok
}

/// Replaces a clap error that echoes a value that may hold a key: clap repeats a stray or
/// rejected value.
fn redact_clap_error(err: clap::Error) -> clap::Error {
    let echoed = err.context().any(|(_, value)| match value {
        ContextValue::String(v) => may_hold_key(v),
        ContextValue::Strings(vs) => vs.iter().any(|v| may_hold_key(v)),
        _ => false,
    });
    if !err.use_stderr() || !(echoed || holds_non_enode_url(&err.to_string())) {
        return err;
    }
    // For a stray value the invalid "argument" is the value itself.
    let flag = match err.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(arg)) if arg.starts_with('-') && !may_hold_key(arg) => {
            format!(" for {arg}")
        }
        _ => String::new(),
    };
    let what = match err.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => "invalid value",
        kind => kind.as_str().unwrap_or("invalid arguments"),
    };
    clap::Error::raw(
        err.kind(),
        format!("{what}{flag}: a value that may hold a URL or key is not echoed; see --help\n"),
    )
}

/// Reads URLs from `path`, one per line, in order. Blank lines and `#` lines are skipped and
/// whitespace is trimmed. Warns (does not refuse) when the file is group- or world-readable.
fn read_url_file(path: &Path, flag: &'static str) -> Result<Vec<Url>, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::UrlFile {
        flag,
        path: shown_path(path),
        reason: e.to_string(),
    })?;
    warn_if_open(path, flag);
    parse_url_text(&text, flag, path)
}

/// The URLs of a URL file's `text`, as [`read_url_file`] reads them; `path` names the file in
/// an error.
pub(crate) fn parse_url_text(
    text: &str,
    flag: &'static str,
    path: &Path,
) -> Result<Vec<Url>, ConfigError> {
    // Some editors start a file with a byte-order mark, which `trim` keeps.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut urls = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        urls.push(parse_url(line, flag, Some(i + 1))?);
    }
    if urls.is_empty() {
        return Err(ConfigError::EmptyUrlFile { flag, path: shown_path(path) });
    }
    Ok(urls)
}

#[cfg(unix)]
fn warn_if_open(path: &Path, flag: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %shown_path(path),
                mode = format_args!("{:o}", mode & 0o777),
                "{flag} file is group- or world-readable; it holds a secret, run chmod 600"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_open(_path: &Path, _flag: &str) {}

fn parse_chain(s: &str) -> Result<u64, String> {
    let id: u64 = s.parse().map_err(|_| format!("bad --chain `{s}` (369 or 943)"))?;
    pulsechain_network(id)
        .map(|n| n.chain_id)
        .ok_or_else(|| format!("unsupported --chain {id} (369 or 943)"))
}

/// The `reth-lite` command line.
#[derive(Parser)]
#[command(name = "reth-lite", about = "A small verifying PulseChain node", version = env!("RETH_LITE_VERSION"))]
pub struct LiteArgs {
    /// Chain id: 369 or 943.
    #[arg(long = "chain", value_parser = parse_chain, default_value = "369")]
    pub chain: u64,
    /// Data directory.
    #[arg(long = "datadir", default_value = "reth-lite-data")]
    pub datadir: PathBuf,
    /// JSON-RPC bind address. Loopback only.
    #[arg(long = "http.addr", value_parser = parse_loopback, default_value = "127.0.0.1")]
    pub http_addr: IpAddr,
    /// JSON-RPC port.
    #[arg(long = "http.port", default_value_t = 8545)]
    pub http_port: u16,
    /// `IP:port` for `/metrics`. A host name is refused.
    #[arg(long = "metrics.addr", default_value = "127.0.0.1:9001")]
    pub metrics_addr: SocketAddr,
    /// Beacon base URL, repeatable. A key goes in the path or the query (a fragment is refused)
    /// and is a secret.
    // Kept as text and validated in `LiteArgs::into_config`: clap echoes a rejected value in its
    // error, which would leak the key.
    #[arg(long = "beacon.url")]
    pub beacon_url: Vec<String>,
    /// File with one beacon base URL per line, read in order. Blank lines and lines starting
    /// with `#` are ignored. Keeps a key out of the command line. Exclusive with `--beacon.url`.
    #[arg(long = "beacon.url-file")]
    pub beacon_url_file: Option<PathBuf>,
    /// Beacon URLs that must agree on the head.
    ///
    /// Only a majority (more than half the URLs) tolerates a hostile minority: a smaller quorum
    /// lets that many sources set the head alone, and the node warns at start. With
    /// `--head.verify=sync-committee` the committee's signature decides the head, so a quorum
    /// above 1 is refused.
    #[arg(long = "beacon.quorum", default_value_t = 1)]
    pub beacon_quorum: u32,
    /// Poll interval when there is no SSE. At least 1s.
    #[arg(long = "beacon.poll", value_parser = parse_duration, default_value = "10s")]
    pub beacon_poll: Duration,
    /// Finalized anchor source. Default on 369: `https://checkpoint.pulsechain.com`. 943 has no
    /// default: give this flag or `--finalized.url-file`.
    // Kept as text and validated in `LiteArgs::into_config`: clap echoes a rejected value in its
    // error, which would leak a key.
    #[arg(long = "finalized.url")]
    pub finalized_url: Option<String>,
    /// File holding the finalized anchor URL (one URL; blank and `#` lines ignored). Exclusive
    /// with `--finalized.url`.
    #[arg(long = "finalized.url-file")]
    pub finalized_url_file: Option<PathBuf>,
    /// Maximum time between anchor re-checks. At least 30s.
    #[arg(long = "finalized.recheck", value_parser = parse_duration, default_value = "10m")]
    pub finalized_recheck: Duration,
    /// What to do on a state miss: error, error-and-warm or fetch.
    #[arg(long = "state.on-miss", default_value = "fetch")]
    pub state_on_miss: OnMiss,
    /// Hot-set size (0 = off). At most 65536.
    #[arg(long = "state.hot-set", default_value_t = 0, value_parser = parse_hot_set)]
    pub state_hot_set: usize,
    /// In-memory verified cache limit. Default: 25% of the memory found, at least 64MB and at
    /// most 1GB, but no more than the fixed budgets leave. 0 turns the memory cache off: every
    /// read goes to disk. Units are pulse-reth's `B KB MB GB TB`, binary: `1GB` is 2^30 bytes.
    ///
    /// The memory found is the process's cgroup memory limit (on cgroup v2 the lower of
    /// `memory.max` and `memory.high`, systemd's `MemoryMax=` and `MemoryHigh=`), or physical RAM
    /// when no limit is set or the limit is above it; when neither can be read, the default is
    /// 1GB. The fixed budgets are twice the held-body budget, 32MB of receipts and 256MB for the
    /// runtime, the network and the EVM. The node counts the cache at its heap bound, 1.2 times
    /// the value. A value given here wins, but the node refuses to start when that bound and the
    /// fixed budgets do not fit in the memory found. The default is cut to fit, so it can be
    /// below 64MB; when the fixed budgets alone do not fit, the default is 0 and the node warns.
    ///
    /// The limit counts each value plus 384 bytes of bookkeeping, and the cache's heap stays
    /// within about 1.2 times this value.
    #[arg(long = "cache.size", value_parser = parse_byte_size)]
    pub cache_size: Option<usize>,
    /// Disk limit for the state store (`<datadir>/store`). At least 16MB. Units are
    /// pulse-reth's `B KB MB GB TB`, binary: `1GB` is 2^30 bytes.
    #[arg(long = "disk.limit", value_parser = parse_byte_size, default_value = "3GB")]
    pub disk_limit: usize,
    /// JSON-RPC URL of an upstream state source, repeatable. Opt-in. The node fetches state from
    /// it with batched `eth_getProof` and `eth_getCode` and verifies every answer against the
    /// head's roots, as it does a peer's. The whole URL is a secret: logs show only its host.
    // Kept as text and validated in `LiteArgs::into_config`, as `--beacon.url` is.
    #[arg(long = "upstream.url")]
    pub upstream_url: Vec<String>,
    /// File with one upstream URL per line, read in order. Blank lines and lines starting with
    /// `#` are ignored. Keeps a key out of the command line. Exclusive with `--upstream.url`.
    #[arg(long = "upstream.url-file")]
    pub upstream_url_file: Option<PathBuf>,
    /// Where state comes from with upstream URLs: `fallback` (peers first, the upstreams when no
    /// peer serves the state) or `only` (the upstreams alone). Default: `fallback`. Refused
    /// without an upstream URL.
    #[arg(long = "upstream.mode", value_name = "UPSTREAM_MODE")]
    pub upstream_mode: Option<UpstreamMode>,
    /// Static `snap/1` peer enode, repeatable. Always kept and preferred over discovered peers.
    /// The host must be an IP address: a host name is refused.
    #[arg(long = "peer")]
    pub peer: Vec<NodeRecord>,
    /// Peer discovery: `on` or `off`. Default: on without `--peer`, off with `--peer`.
    #[arg(long = "discovery")]
    pub discovery: Option<Toggle>,
    /// Most discovered peers kept connected. Each static peer has a slot of its own on top; while
    /// a static peer is not connected, a discovered peer can take its slot.
    #[arg(long = "max-peers", default_value_t = DEFAULT_MAX_PEERS, value_parser = parse_max_peers)]
    pub max_peers: usize,
    /// Head confirmation: `peer` or `none`. Default: `peer` with `--head.verify=quorum`, `none`
    /// with `--head.verify=sync-committee`.
    ///
    /// The rebuilt block hash proves only that a beacon payload is self-consistent: a beacon (or
    /// a quorum of them) could forge the header fields of a block that has the real state root.
    /// With `peer` a new head is followed only once a static `--peer` reports the same block
    /// hash, so `peer` needs at least one `--peer`. With `none` the beacon quorum is trusted
    /// alone, or with `--head.verify=sync-committee` the committee's signature.
    // No clap default: the default depends on `--head.verify`, see `LiteArgs::into_config`.
    #[arg(long = "head.confirm", value_name = "HEAD_CONFIRM")]
    pub head_confirm: Option<HeadConfirm>,
    /// Head verification: `quorum` or `sync-committee`.
    ///
    /// With `quorum` (the default) `--beacon.quorum` sources must report a head. With
    /// `sync-committee` the node checks the sync committee's signature over each head, as an
    /// Altair light client does. It needs a source with lighthouse-pulse's
    /// `--light-client-server`, and the node does not start without one. The first start
    /// bootstraps at `--checkpoint` or the chain's pin, else at the anchor's finalized root;
    /// after it, an anchor that disagrees with the verified chain is logged and counted, and does
    /// not halt serving.
    #[arg(long = "head.verify", default_value = "quorum")]
    pub head_verify: HeadVerify,
    /// Trusted finalized beacon block root (`0x` hex) that the first
    /// `--head.verify=sync-committee` bootstrap proves the first committee from. Default: the root
    /// pinned for the chain. 943 has no pin, so there the anchor's finalized root decides the
    /// first committee.
    ///
    /// This flag wins over the pin, and a usable store file wins over both. The node refuses a
    /// root or a pin whose block is more than 30 days old. The flag is refused without
    /// `--head.verify=sync-committee`.
    #[arg(long = "checkpoint", value_name = "ROOT")]
    pub checkpoint: Option<B256>,
    /// Latest and state reads answer -32000 "head is stale" when the head block is older than
    /// this, or no new head was followed for this long. Default: six 10 s slots. At least 20s, and
    /// it should be above one slot plus `--beacon.poll`.
    #[arg(long = "head.max-age", value_parser = parse_duration, default_value = "60s")]
    pub head_max_age: Duration,
    /// EVM time limit of one `eth_call` or `eth_estimateGas`. 0 sets no limit. The text and the
    /// default are as geth's `--rpc.evmtimeout` for `eth_call`. The limit on `eth_estimateGas` is
    /// reth-lite's: geth bounds an estimate by the gas cap only.
    ///
    /// The limit covers the EVM time of one run over the state held, not the state fetches
    /// between runs; for `eth_estimateGas` it covers the whole search. A run past it answers
    /// -32000 "execution aborted (timeout = 5s)", with the limit given.
    #[arg(long = "rpc.evmtimeout", value_parser = parse_duration, default_value = "5s")]
    pub rpc_evmtimeout: Duration,
    /// How long a newly connected `snap/1` peer has to answer its first request, a probe that an
    /// honest server answers at once. A discovered peer that answers neither the probe nor any
    /// other request in this time loses its session; a static `--peer` is kept, with a warning.
    /// Above 0.
    #[arg(long = "snap.probe-timeout", value_parser = parse_duration, default_value = "3s")]
    pub snap_probe_timeout: Duration,
}

impl std::fmt::Debug for LiteArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URLs may hold a key: show how many, never the values.
        f.debug_struct("LiteArgs")
            .field("chain", &self.chain)
            .field("datadir", &shown_path(&self.datadir))
            .field("beacon_url", &format_args!("<{} redacted>", self.beacon_url.len()))
            .field("beacon_url_file", &self.beacon_url_file.as_deref().map(shown_path))
            .field("finalized_url", &self.finalized_url.as_ref().map(|_| "<redacted>"))
            .field("finalized_url_file", &self.finalized_url_file.as_deref().map(shown_path))
            .field("upstream_url", &format_args!("<{} redacted>", self.upstream_url.len()))
            .field("upstream_url_file", &self.upstream_url_file.as_deref().map(shown_path))
            .finish_non_exhaustive()
    }
}

/// Default for `--max-peers`: small, for a 1 GB box.
pub const DEFAULT_MAX_PEERS: usize = 8;

fn parse_max_peers(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err("--max-peers must be a number of at least 1".into()),
    }
}

/// A `--state.hot-set` of at most [`MAX_HOT_SET`](crate::hot_set::MAX_HOT_SET) entries.
fn parse_hot_set(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if n <= crate::hot_set::MAX_HOT_SET => Ok(n),
        _ => Err(format!(
            "--state.hot-set must be a number of at most {}",
            crate::hot_set::MAX_HOT_SET
        )),
    }
}

/// `on` or `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    /// Enabled.
    On,
    /// Disabled.
    Off,
}

impl FromStr for Toggle {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            other => Err(format!("unknown value `{other}` (on|off)")),
        }
    }
}

/// Why a configuration is refused. No variant carries a URL: they may hold a key.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `--beacon.quorum` is zero or larger than the number of beacon URLs.
    #[error("--beacon.quorum must be between 1 and the number of beacon URLs")]
    BadQuorum,
    /// A URL is not an http(s) URL. The value is not echoed.
    #[error("{flag} must be an http(s) URL{}", .line.map(|l| format!(" (line {l} of the file)")).unwrap_or_default())]
    BadUrl {
        /// The flag.
        flag: &'static str,
        /// The 1-based line in the URL file, if it came from one.
        line: Option<usize>,
    },
    /// A URL has a fragment, which no request carries. The value is not echoed.
    #[error(
        "{flag} must not have a fragment: the node never sends it; put a key in the path or the \
         query{}",
        .line.map(|l| format!(" (line {l} of the file)")).unwrap_or_default()
    )]
    UrlFragment {
        /// The flag.
        flag: &'static str,
        /// The 1-based line in the URL file, if it came from one.
        line: Option<usize>,
    },
    /// Both `--beacon.url` and `--beacon.url-file` were given.
    #[error("--beacon.url and --beacon.url-file are mutually exclusive: give only one")]
    BeaconUrlConflict,
    /// Neither `--beacon.url` nor `--beacon.url-file` was given.
    #[error("no beacon URL: give --beacon.url (repeatable) or --beacon.url-file")]
    NoBeaconUrl,
    /// Both `--upstream.url` and `--upstream.url-file` were given.
    #[error("--upstream.url and --upstream.url-file are mutually exclusive: give only one")]
    UpstreamUrlConflict,
    /// `--upstream.mode` was given without an upstream URL.
    #[error("--upstream.mode needs --upstream.url or --upstream.url-file")]
    UpstreamModeWithoutUrl,
    /// Both `--finalized.url` and `--finalized.url-file` were given.
    #[error("--finalized.url and --finalized.url-file are mutually exclusive: give only one")]
    FinalizedUrlConflict,
    /// A URL file could not be read.
    #[error("{flag}: cannot read {path}: {reason}")]
    UrlFile {
        /// The flag.
        flag: &'static str,
        /// The file, or a placeholder when the path looks like a URL.
        path: String,
        /// The I/O error text.
        reason: String,
    },
    /// A URL file holds no URL.
    #[error("{flag}: {path} holds no URL")]
    EmptyUrlFile {
        /// The flag.
        flag: &'static str,
        /// The file, or a placeholder when the path looks like a URL.
        path: String,
    },
    /// No finalized anchor was given for a chain without a built-in one.
    #[error(
        "--chain={chain} has no built-in finalized anchor: give --finalized.url or \
         --finalized.url-file"
    )]
    NoDefaultAnchor {
        /// The chain id.
        chain: u64,
    },
    /// `--finalized.url-file` holds more than one URL.
    #[error("--finalized.url-file must hold exactly one URL")]
    TooManyFinalizedUrls,
    /// A plain-http URL for a host that is not loopback. The value is not echoed.
    #[error(
        "{flag} must use https unless the host is loopback{}",
        .line.map(|l| format!(" (line {l} of the file)")).unwrap_or_default()
    )]
    InsecureUrl {
        /// The flag.
        flag: &'static str,
        /// The 1-based line in the URL file, if it came from one.
        line: Option<usize>,
    },
    /// `--checkpoint` without `--head.verify=sync-committee`.
    #[error("--checkpoint is used only with --head.verify=sync-committee")]
    CheckpointWithoutSyncCommittee,
    /// `--beacon.quorum` above 1 with `--head.verify=sync-committee`.
    #[error(
        "--beacon.quorum above 1 is refused with --head.verify=sync-committee: the sync \
         committee's signature decides the head there, so a quorum adds no check; leave \
         --beacon.quorum out"
    )]
    QuorumWithSyncCommittee,
    /// The same beacon URL is given twice: it would count twice toward the quorum.
    #[error("a beacon URL is given more than once")]
    DuplicateUrl,
    /// Two beacon URLs on one host with a quorum above one: one provider would count twice. The
    /// check sees loopback aliases and a trailing dot, not two DNS names for one provider.
    #[error("with --beacon.quorum above 1, every beacon URL must be on its own host")]
    SharedBeaconHost,
    /// A duration flag is below its floor.
    #[error("{flag} must be at least {min:?}")]
    DurationTooShort {
        /// The flag.
        flag: &'static str,
        /// The floor.
        min: Duration,
    },
    /// A duration flag is above [`MAX_DURATION`].
    #[error("{flag} must be at most {}h", .max.as_secs() / 3600)]
    DurationTooLong {
        /// The flag.
        flag: &'static str,
        /// The ceiling.
        max: Duration,
    },
    /// A size flag is below its floor.
    #[error("{flag} must be at least {}MB", .min >> 20)]
    SizeTooSmall {
        /// The flag.
        flag: &'static str,
        /// The floor in bytes.
        min: u64,
    },
    /// `--head.confirm=peer` without a `--peer`.
    #[error("{}", match .mode {
        HeadVerify::Quorum => {
            "--head.confirm=peer (the default) needs at least one --peer to confirm heads with; \
             give --peer, or pass --head.confirm=none to trust the beacon quorum alone"
        }
        HeadVerify::SyncCommittee => {
            "--head.confirm=peer needs at least one --peer to confirm heads with; give --peer, \
             or leave --head.confirm out: with --head.verify=sync-committee it defaults to none"
        }
    })]
    HeadConfirmNeedsPeer {
        /// `--head.verify`, which sets the default.
        mode: HeadVerify,
    },
    /// `--datadir` looks like a URL: the node would name directories after it, key included.
    #[error("--datadir looks like a URL; the value is not echoed")]
    DatadirLooksLikeUrl,
    /// An explicit `--cache.size` whose heap bound, with the fixed budgets, does not fit in the
    /// memory found.
    #[error(
        "--cache.size={} (a heap of up to {}MB) and the node's fixed budgets need {}MB, but the \
         box has {}MB ({}); give a smaller --cache.size, or leave it out for a default sized to \
         the box",
        show_size(*.asked), cache_heap(*.asked).div_ceil(MIB), .need.div_ceil(MIB),
        .found.bytes / MIB, .found.source
    )]
    CacheTooLarge {
        /// The `--cache.size` given, in bytes.
        asked: u64,
        /// The heap bound of `asked` plus the fixed budgets, in bytes.
        need: u64,
        /// The memory found.
        found: Memory,
    },
    /// An explicit `--cache.size` above `0` on a box where the fixed budgets alone do not fit.
    #[error(
        "--cache.size={} does not fit: the node's fixed budgets alone need {}MB of the {}MB the \
         box has ({}), so no cache fits; give --cache.size=0 or leave it out, which turn the \
         cache off, or give the node more memory",
        show_size(*.asked), .fixed.div_ceil(MIB), .found.bytes / MIB, .found.source
    )]
    FixedBudgetsTooLarge {
        /// The `--cache.size` given, in bytes.
        asked: u64,
        /// The fixed budgets, in bytes.
        fixed: u64,
        /// The memory found.
        found: Memory,
    },
}

/// `bytes` as a size flag spells it: in `GB` or `MB` when whole, else as a bare byte count.
fn show_size(bytes: u64) -> String {
    match bytes {
        0 => "0".to_owned(),
        b if b % GIB == 0 => format!("{}GB", b / GIB),
        b if b % MIB == 0 => format!("{}MB", b / MIB),
        b => b.to_string(),
    }
}

/// The resolved configuration of a lite node.
///
/// `Debug` shows the URLs as `scheme://host` only, and hides a `datadir` that looks like a URL.
#[derive(Clone)]
pub struct LiteConfig {
    /// Chain id (369 or 943).
    pub chain_id: u64,
    /// Data directory.
    pub datadir: PathBuf,
    /// JSON-RPC address, always loopback.
    pub rpc_addr: SocketAddr,
    /// Prometheus address.
    pub metrics_addr: SocketAddr,
    /// Memory cache limit in bytes.
    pub cache_max_bytes: u64,
    /// Bytes of held block bodies, by the chain's estimate.
    pub body_budget: u64,
    /// Disk limit in bytes.
    pub disk_limit: u64,
    /// Beacon base URLs. Secret: never log these.
    pub beacon_urls: Vec<Url>,
    /// Beacons that must agree.
    pub beacon_quorum: u32,
    /// Poll interval.
    pub beacon_poll: Duration,
    /// Finalized anchor source.
    pub anchor_url: Url,
    /// Anchor re-check interval.
    pub anchor_recheck: Duration,
    /// Static peers.
    pub peers: Vec<NodeRecord>,
    /// Whether peer discovery (discv4 and DNS) runs.
    pub discovery: bool,
    /// Most discovered peers kept connected, plus one per static peer that is not connected.
    pub max_peers: usize,
    /// Miss behaviour.
    pub on_miss: OnMiss,
    /// Hot-set size.
    pub hot_set: usize,
    /// Blocks whose state is served.
    pub state_window: u64,
    /// Maximum miss-and-retry rounds of one call.
    pub max_rounds: u32,
    /// Whether a head needs a static peer to confirm its hash.
    pub head_confirm: HeadConfirm,
    /// How a head is verified.
    pub head_verify: HeadVerify,
    /// The trusted root of the first sync-committee bootstrap: `--checkpoint`, else the chain's
    /// pin. `None` in quorum mode, and for a chain with no pin: the first bootstrap is then at the
    /// anchor's finalized root.
    pub checkpoint: Option<Checkpoint>,
    /// Latest and state reads are refused when the head's timestamp is older than this, or the
    /// head has not moved for this long.
    pub head_max_age: Duration,
    /// EVM time limit of one `eth_call` or `eth_estimateGas` run; zero sets no limit.
    pub evm_timeout: Duration,
    /// How long a new `snap/1` peer has to answer the probe.
    pub snap_probe_timeout: Duration,
    /// Upstream JSON-RPC state sources. Secret: never log these.
    pub upstream_urls: Vec<Url>,
    /// Where state comes from when `upstream_urls` is not empty.
    pub upstream_mode: UpstreamMode,
}

impl std::fmt::Debug for LiteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let beacons: Vec<String> = self.beacon_urls.iter().map(crate::beacon::host_label).collect();
        let upstreams: Vec<String> =
            self.upstream_urls.iter().map(crate::beacon::host_label).collect();
        f.debug_struct("LiteConfig")
            .field("chain_id", &self.chain_id)
            .field("datadir", &shown_path(&self.datadir))
            .field("rpc_addr", &self.rpc_addr)
            .field("metrics_addr", &self.metrics_addr)
            .field("cache_max_bytes", &self.cache_max_bytes)
            .field("body_budget", &self.body_budget)
            .field("disk_limit", &self.disk_limit)
            .field("beacon_urls", &beacons)
            .field("beacon_quorum", &self.beacon_quorum)
            .field("beacon_poll", &self.beacon_poll)
            .field("anchor_url", &crate::beacon::host_label(&self.anchor_url))
            .field("anchor_recheck", &self.anchor_recheck)
            .field("peers", &self.peers)
            .field("discovery", &self.discovery)
            .field("max_peers", &self.max_peers)
            .field("on_miss", &self.on_miss)
            .field("hot_set", &self.hot_set)
            .field("state_window", &self.state_window)
            .field("max_rounds", &self.max_rounds)
            .field("head_confirm", &self.head_confirm)
            .field("head_verify", &self.head_verify)
            .field("checkpoint", &self.checkpoint)
            .field("head_max_age", &self.head_max_age)
            .field("evm_timeout", &self.evm_timeout)
            .field("snap_probe_timeout", &self.snap_probe_timeout)
            .field("upstream_urls", &upstreams)
            .field("upstream_mode", &self.upstream_mode)
            .finish()
    }
}

/// The start-up warning of an unconfirmed start with `--head.verify=quorum`: see
/// [`LiteConfig::unconfirmed_start`].
pub const UNCONFIRMED_START: &str = "UNCONFIRMED START: nothing but the finalized anchor \
     confirms the block this node starts from (--head.verify=quorum, --beacon.quorum 1 and \
     --head.confirm=none). A wrong or hostile anchor chooses that block, and every verified \
     answer rests on it. To remove the risk, give a second --beacon.url and --beacon.quorum 2 or \
     more, or --head.confirm=peer with a --peer, or --head.verify=sync-committee on a chain with \
     a pinned checkpoint or with --checkpoint. lite_unconfirmed_start reads 1 while this holds";

/// The start-up warning of an unconfirmed start with `--head.verify=sync-committee`: see
/// [`LiteConfig::unconfirmed_start`].
pub const UNCONFIRMED_START_SYNC_COMMITTEE: &str = "UNCONFIRMED START: nothing but the \
     finalized anchor confirms the block this node starts from (--head.verify=sync-committee \
     bootstrapped at the anchor's finalized root, with no pinned checkpoint, no --checkpoint and \
     no saved store, and --head.confirm=none). A wrong or hostile anchor chooses the first sync \
     committee and that block, and every verified answer rests on them. --beacon.quorum confirms \
     nothing in this mode. To remove the risk, give --checkpoint with a root you trust. \
     --head.confirm=peer with a --peer confirms the block and each head, but not the committee. \
     lite_unconfirmed_start reads 1 while this holds";

impl LiteConfig {
    /// Whether nothing but the finalized anchor confirms the block the node starts from, given
    /// where the light-client store came from (`None` without one). That holds with
    /// `--head.confirm=none` and either `--head.verify=quorum` with `--beacon.quorum 1`, or
    /// `--head.verify=sync-committee` with a store bootstrapped at the anchor's root
    /// ([`StoreOrigin::Bootstrap`]: no pin, no `--checkpoint` and no saved store). The node
    /// still starts, and warns.
    pub fn unconfirmed_start(&self, store: Option<&StoreOrigin>) -> bool {
        self.head_confirm == HeadConfirm::None &&
            match self.head_verify {
                HeadVerify::Quorum => self.beacon_quorum < 2,
                HeadVerify::SyncCommittee => {
                    matches!(store, Some(StoreOrigin::Bootstrap { .. }))
                }
            }
    }
}

impl Default for LiteConfig {
    fn default() -> Self {
        Self {
            chain_id: 369,
            datadir: PathBuf::from("reth-lite-data"),
            rpc_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 8545)),
            metrics_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9001)),
            cache_max_bytes: MAX_CACHE_BYTES,
            body_budget: MAX_BODY_BYTES,
            disk_limit: 3 * GIB,
            beacon_urls: Vec::new(),
            beacon_quorum: 1,
            beacon_poll: Duration::from_secs(10),
            anchor_url: Url::parse("https://checkpoint.pulsechain.com").expect("valid"),
            anchor_recheck: Duration::from_secs(600),
            peers: Vec::new(),
            discovery: true,
            max_peers: DEFAULT_MAX_PEERS,
            on_miss: OnMiss::Fetch,
            hot_set: 0,
            state_window: 120,
            max_rounds: 40,
            head_confirm: HeadConfirm::Peer,
            head_verify: HeadVerify::Quorum,
            checkpoint: None,
            head_max_age: Duration::from_secs(60),
            evm_timeout: crate::call::DEFAULT_EVM_TIMEOUT,
            snap_probe_timeout: crate::net::wire::PROBE_TIMEOUT,
            upstream_urls: Vec::new(),
            upstream_mode: UpstreamMode::Fallback,
        }
    }
}

impl LiteArgs {
    /// Parses the process arguments as [`Parser::parse`] does, but an error never echoes a value
    /// that looks like a URL.
    pub fn parse_redacted() -> Self {
        Self::try_parse_redacted(std::env::args_os()).unwrap_or_else(|err| err.exit())
    }

    fn try_parse_redacted<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(args).map_err(redact_clap_error)
    }

    /// Resolves the flags into a [`LiteConfig`], sizing the memory budgets to the memory found
    /// by [`crate::memory::detect`].
    pub fn into_config(self) -> Result<LiteConfig, ConfigError> {
        self.into_config_with(crate::memory::detect())
    }

    /// [`Self::into_config`] on a box with `memory`, or one whose memory is not found.
    fn into_config_with(self, memory: Option<Memory>) -> Result<LiteConfig, ConfigError> {
        if looks_like_url(&self.datadir.display().to_string()) {
            return Err(ConfigError::DatadirLooksLikeUrl);
        }
        let beacon_urls = match (&self.beacon_url_file, self.beacon_url.is_empty()) {
            (Some(_), false) => return Err(ConfigError::BeaconUrlConflict),
            (Some(path), true) => read_url_file(path, "--beacon.url-file")?,
            (None, true) => return Err(ConfigError::NoBeaconUrl),
            (None, false) => self
                .beacon_url
                .iter()
                .map(|s| parse_url(s, "--beacon.url", None))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let upstream_urls = match (&self.upstream_url_file, self.upstream_url.is_empty()) {
            (Some(_), false) => return Err(ConfigError::UpstreamUrlConflict),
            (Some(path), true) => read_url_file(path, "--upstream.url-file")?,
            (None, true) => Vec::new(),
            (None, false) => self
                .upstream_url
                .iter()
                .map(|s| parse_url(s, "--upstream.url", None))
                .collect::<Result<Vec<_>, _>>()?,
        };
        if upstream_urls.is_empty() && self.upstream_mode.is_some() {
            return Err(ConfigError::UpstreamModeWithoutUrl);
        }
        for (i, u) in beacon_urls.iter().enumerate() {
            if beacon_urls[..i].contains(u) {
                return Err(ConfigError::DuplicateUrl);
            }
        }
        let sync_committee = self.head_verify == HeadVerify::SyncCommittee;
        // The committee's signature decides a sync-committee head: a peer is an extra check.
        let head_confirm = self.head_confirm.unwrap_or(if sync_committee {
            HeadConfirm::None
        } else {
            HeadConfirm::Peer
        });
        if sync_committee && self.beacon_quorum > 1 {
            return Err(ConfigError::QuorumWithSyncCommittee);
        }
        let checkpoint = match (self.checkpoint, sync_committee) {
            (Some(_), false) => return Err(ConfigError::CheckpointWithoutSyncCommittee),
            (Some(root), true) => Some(Checkpoint::Flag(root)),
            (None, true) => {
                pulsechain_network(self.chain).and_then(|n| n.checkpoint).map(Checkpoint::Pinned)
            }
            (None, false) => None,
        };
        if self.beacon_quorum == 0 || self.beacon_quorum as usize > beacon_urls.len() {
            return Err(ConfigError::BadQuorum);
        }
        let shared = beacon_urls
            .iter()
            .enumerate()
            .any(|(i, u)| beacon_urls[..i].iter().any(|v| host_key(v) == host_key(u)));
        if shared && self.beacon_quorum > 1 {
            return Err(ConfigError::SharedBeaconHost);
        }
        for (flag, value) in [
            ("--beacon.poll", self.beacon_poll),
            ("--finalized.recheck", self.finalized_recheck),
            ("--head.max-age", self.head_max_age),
            ("--rpc.evmtimeout", self.rpc_evmtimeout),
            ("--snap.probe-timeout", self.snap_probe_timeout),
        ] {
            if value > MAX_DURATION {
                return Err(ConfigError::DurationTooLong { flag, max: MAX_DURATION });
            }
        }
        if self.snap_probe_timeout < MIN_SNAP_PROBE {
            return Err(ConfigError::DurationTooShort {
                flag: "--snap.probe-timeout",
                min: MIN_SNAP_PROBE,
            });
        }
        if self.beacon_poll < MIN_POLL {
            return Err(ConfigError::DurationTooShort { flag: "--beacon.poll", min: MIN_POLL });
        }
        // The anchor check downloads a block from a third-party server each time.
        let min_recheck = crate::beacon::MIN_ANCHOR_GAP;
        if self.finalized_recheck < min_recheck {
            return Err(ConfigError::DurationTooShort {
                flag: "--finalized.recheck",
                min: min_recheck,
            });
        }
        if self.head_max_age < MIN_HEAD_MAX_AGE {
            return Err(ConfigError::DurationTooShort {
                flag: "--head.max-age",
                min: MIN_HEAD_MAX_AGE,
            });
        }
        // A `usize` never exceeds a `u64`.
        let disk_limit = self.disk_limit as u64;
        if disk_limit < MIN_DISK_LIMIT {
            return Err(ConfigError::SizeTooSmall { flag: "--disk.limit", min: MIN_DISK_LIMIT });
        }
        let (cache_max_bytes, body_budget) = memory_budgets(self.cache_size, memory)?;
        if head_confirm == HeadConfirm::Peer && self.peer.is_empty() {
            return Err(ConfigError::HeadConfirmNeedsPeer { mode: self.head_verify });
        }
        let anchor_url = match (&self.finalized_url, &self.finalized_url_file) {
            (Some(_), Some(_)) => return Err(ConfigError::FinalizedUrlConflict),
            (Some(s), None) => parse_url(s, "--finalized.url", None)?,
            (None, Some(path)) => {
                let mut urls = read_url_file(path, "--finalized.url-file")?;
                if urls.len() != 1 {
                    return Err(ConfigError::TooManyFinalizedUrls);
                }
                urls.remove(0)
            }
            // The built-in anchor serves chain 369 only.
            (None, None) if self.chain == LiteConfig::default().chain_id => {
                LiteConfig::default().anchor_url
            }
            (None, None) => return Err(ConfigError::NoDefaultAnchor { chain: self.chain }),
        };
        // Warnings only after every refusal: a config that never runs warns about nothing.
        let n = beacon_urls.len();
        // With a sync committee extra sources give liveness, not votes.
        if !sync_committee && n > 1 && self.beacon_quorum as usize * 2 <= n {
            tracing::warn!(
                quorum = self.beacon_quorum,
                urls = n,
                ?head_confirm,
                "the beacon quorum is not a majority: that many sources can set the head alone; \
                 give --beacon.quorum={} to tolerate a hostile minority",
                n / 2 + 1
            );
        }
        if shared {
            tracing::warn!("two beacon URLs are on the same host: they are one source, not two");
        }
        // A sync-committee head is a slot older: its signature comes in the next block.
        if sync_committee {
            if self.head_max_age <= SLOT * 2 + self.beacon_poll {
                tracing::warn!(
                    head_max_age = ?self.head_max_age,
                    beacon_poll = ?self.beacon_poll,
                    "--head.max-age is not above two slots plus --beacon.poll: a sync-committee \
                     head is one slot behind, so latest and state reads answer \"head is stale\" \
                     between updates"
                );
            }
        } else if self.head_max_age <= SLOT + self.beacon_poll {
            tracing::warn!(
                head_max_age = ?self.head_max_age,
                beacon_poll = ?self.beacon_poll,
                "--head.max-age is not above one slot plus --beacon.poll: without an event stream \
                 latest and state reads answer \"head is stale\" between polls"
            );
        }
        if beacon_urls.iter().any(|u| host_key(u) == host_key(&anchor_url)) {
            tracing::warn!(
                host = %crate::beacon::host_label(&anchor_url),
                "the finalized anchor is on the same host as a beacon URL: it is not an \
                 independent check of that beacon"
            );
        }
        if !self.metrics_addr.ip().is_loopback() {
            tracing::warn!(
                addr = %self.metrics_addr,
                "--metrics.addr is not loopback: anyone who can reach it reads the node's \
                 metrics; put a firewall in front of it"
            );
        }
        Ok(LiteConfig {
            chain_id: self.chain,
            datadir: self.datadir,
            rpc_addr: SocketAddr::new(self.http_addr, self.http_port),
            metrics_addr: self.metrics_addr,
            cache_max_bytes,
            body_budget,
            disk_limit,
            beacon_urls,
            beacon_quorum: self.beacon_quorum,
            beacon_poll: self.beacon_poll,
            anchor_url,
            anchor_recheck: self.finalized_recheck,
            discovery: self.discovery.map_or(self.peer.is_empty(), |t| t == Toggle::On),
            max_peers: self.max_peers,
            peers: self.peer,
            on_miss: self.state_on_miss,
            hot_set: self.state_hot_set,
            head_confirm,
            head_verify: self.head_verify,
            checkpoint,
            head_max_age: self.head_max_age,
            evm_timeout: self.rpc_evmtimeout,
            snap_probe_timeout: self.snap_probe_timeout,
            upstream_urls,
            upstream_mode: self.upstream_mode.unwrap_or_default(),
            ..LiteConfig::default()
        })
    }
}

/// The most heap the cache takes at a limit of `bytes`: the store keeps it within 1.2 times the
/// limit.
const fn cache_heap(bytes: u64) -> u64 {
    bytes.saturating_add(bytes / 5)
}

/// The cache limit and the held-body budget, as `(cache, bodies)` in bytes, sized to `memory`.
/// The cache's heap bound gets at most what the fixed budgets leave: `cache_size` is refused
/// past it, and the default share is cut to it. With no `memory`, the fixed defaults, and
/// `cache_size` unchecked.
fn memory_budgets(
    cache_size: Option<usize>,
    memory: Option<Memory>,
) -> Result<(u64, u64), ConfigError> {
    // A `usize` never exceeds a `u64`.
    let asked = cache_size.map(|s| s as u64);
    let Some(found) = memory else {
        let cache = asked.unwrap_or(MAX_CACHE_BYTES);
        tracing::warn!(
            cache_mb = cache / MIB,
            body_budget_mb = MAX_BODY_BYTES / MIB,
            "cannot read the cgroup memory limit or physical RAM: using the fixed memory budgets"
        );
        return Ok((cache, MAX_BODY_BYTES));
    };
    let bodies = found.body_budget();
    // A catch-up walk holds as many bodies again as the chain (`Follower::advance`).
    let fixed = 2 * bodies + RECEIPT_CACHE_BYTES as u64 + RUNTIME_BYTES;
    let room = found.bytes.saturating_sub(fixed);
    let cache = match asked {
        Some(asked) if cache_heap(asked) > room => {
            return Err(if room == 0 {
                ConfigError::FixedBudgetsTooLarge { asked, fixed, found }
            } else {
                ConfigError::CacheTooLarge {
                    asked,
                    need: cache_heap(asked).saturating_add(fixed),
                    found,
                }
            })
        }
        Some(asked) => asked,
        // The largest cache whose heap bound fits in `room`.
        None => found.default_cache().min(room / 6 * 5),
    };
    if room == 0 {
        tracing::warn!(
            fixed_mb = fixed.div_ceil(MIB),
            memory_mb = found.bytes / MIB,
            source = %found.source,
            "the node's fixed budgets alone need more than the memory found: the memory cache is \
             off, and the node may run out of memory"
        );
    }
    tracing::info!(
        cache_mb = cache / MIB,
        body_budget_mb = bodies / MIB,
        memory_mb = found.bytes / MIB,
        source = %found.source,
        "memory budgets"
    );
    Ok((cache, bodies))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemorySource, CACHE_PERCENT, MIN_CACHE_BYTES};
    use proptest::prelude::*;

    /// Parses `args`, adding `--head.confirm=none` when they name no peer and no mode (most
    /// tests are not about head confirmation).
    fn parse(args: &[&str]) -> Result<LiteArgs, clap::Error> {
        let explicit = args.iter().any(|a| a.starts_with("--peer") || a.starts_with("--head."));
        let extra = (!explicit).then_some("--head.confirm=none");
        parse_exact(&args.iter().copied().chain(extra).collect::<Vec<_>>())
    }

    fn parse_exact(args: &[&str]) -> Result<LiteArgs, clap::Error> {
        LiteArgs::try_parse_from(std::iter::once("reth-lite").chain(args.iter().copied()))
    }

    #[test]
    fn head_confirm_defaults_to_peer_and_needs_a_peer() {
        let enode = "enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@10.3.58.6:30303";
        let beacon = "--beacon.url=http://127.0.0.1:5052";
        let err = parse_exact(&[beacon]).unwrap().into_config().unwrap_err();
        assert!(matches!(err, ConfigError::HeadConfirmNeedsPeer { .. }), "{err}");
        assert!(err.to_string().contains("--head.confirm=none"));
        let peer = format!("--peer={enode}");
        let cfg = parse_exact(&[beacon, &peer]).unwrap().into_config().unwrap();
        assert_eq!(cfg.head_confirm, HeadConfirm::Peer);
        let cfg = parse_exact(&[beacon, "--head.confirm=none"]).unwrap().into_config().unwrap();
        assert_eq!(cfg.head_confirm, HeadConfirm::None);
        assert!(parse_exact(&[beacon, "--head.confirm=maybe"]).is_err());
    }

    /// With `--head.verify=sync-committee` `--head.confirm` defaults to `none`, so no `--peer`
    /// is needed. An explicit `peer` still needs one.
    #[test]
    fn head_confirm_defaults_to_none_with_a_sync_committee() {
        let enode = "enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@10.3.58.6:30303";
        let peer = format!("--peer={enode}");
        let (beacon, sc) = ("--beacon.url=http://127.0.0.1:5052", "--head.verify=sync-committee");
        let cfg = parse_exact(&[beacon, sc]).unwrap().into_config().unwrap();
        assert_eq!((cfg.head_confirm, cfg.discovery), (HeadConfirm::None, true));
        let cfg = parse_exact(&[beacon, sc, &peer]).unwrap().into_config().unwrap();
        assert_eq!(cfg.head_confirm, HeadConfirm::None);
        let err = parse_exact(&[beacon, sc, "--head.confirm=peer"]).unwrap().into_config();
        let err = err.unwrap_err();
        assert!(matches!(err, ConfigError::HeadConfirmNeedsPeer { .. }), "{err}");
        assert_eq!(
            err.to_string(),
            "--head.confirm=peer needs at least one --peer to confirm heads with; give --peer, \
             or leave --head.confirm out: with --head.verify=sync-committee it defaults to none"
        );
        let cfg = parse_exact(&[beacon, sc, "--head.confirm=peer", &peer]).unwrap();
        assert_eq!(cfg.into_config().unwrap().head_confirm, HeadConfirm::Peer);
        // Quorum mode keeps the default `peer`, also when the mode is named.
        let err = parse_exact(&[beacon, "--head.verify=quorum"]).unwrap().into_config();
        assert!(err.unwrap_err().to_string().starts_with("--head.confirm=peer (the default)"));
    }

    #[test]
    fn head_verify_defaults_to_quorum() {
        let beacon = "--beacon.url=http://127.0.0.1:5052";
        let cfg = parse(&[beacon]).unwrap().into_config().unwrap();
        assert_eq!(cfg.head_verify, HeadVerify::Quorum);
        let verify = "--head.verify=sync-committee";
        let cfg = parse_exact(&[beacon, verify, "--head.confirm=none"]).unwrap();
        assert_eq!(cfg.into_config().unwrap().head_verify, HeadVerify::SyncCommittee);
        let cfg = parse_exact(&[beacon, "--head.verify=quorum", "--head.confirm=none"]).unwrap();
        assert_eq!(cfg.into_config().unwrap().head_verify, HeadVerify::Quorum);
    }

    /// In sync-committee mode the first bootstrap trusts `--checkpoint`, else the chain's pin.
    /// 943 has no pin, and quorum mode none; there `--checkpoint` is refused.
    #[test]
    fn checkpoint_defaults_to_the_chain_pin_and_the_flag_wins() {
        let sc = ["--beacon.url=https://a", "--head.verify=sync-committee"];
        let checkpoint = |extra: &[&str]| {
            let args: Vec<&str> = sc.iter().chain(extra).copied().collect();
            parse_exact(&args).unwrap().into_config().unwrap().checkpoint
        };
        let pin = pulsechain_network(369).unwrap().checkpoint.unwrap();
        assert_eq!(checkpoint(&[]), Some(Checkpoint::Pinned(pin)));
        let root = B256::repeat_byte(0xab);
        assert_eq!(checkpoint(&[&format!("--checkpoint={root}")]), Some(Checkpoint::Flag(root)));
        assert_eq!(checkpoint(&["--chain=943", "--finalized.url=https://t"]), None);
        let flag = format!("--checkpoint={root}");
        assert_eq!(
            checkpoint(&["--chain=943", "--finalized.url=https://t", &flag]),
            Some(Checkpoint::Flag(root))
        );

        let quorum = parse(&["--beacon.url=https://a"]).unwrap().into_config().unwrap();
        assert_eq!(quorum.checkpoint, None);
        let err = parse(&["--beacon.url=https://a", &flag]).unwrap().into_config().unwrap_err();
        assert_eq!(err.to_string(), "--checkpoint is used only with --head.verify=sync-committee");
        assert!(parse_exact(&[sc[0], sc[1], "--checkpoint=0x12"]).is_err());
    }

    #[test]
    fn defaults_match_the_contract() {
        let cfg = config_on(ram(16 * GIB), &[]).unwrap();
        let d = LiteConfig::default();
        assert_eq!(cfg.chain_id, 369);
        assert_eq!(cfg.rpc_addr, "127.0.0.1:8545".parse().unwrap());
        assert_eq!((cfg.cache_max_bytes, d.cache_max_bytes), (GIB, GIB));
        assert_eq!((cfg.body_budget, d.body_budget), (256 << 20, 256 << 20));
        assert_eq!(cfg.disk_limit, 3 * GIB);
        assert_eq!(cfg.beacon_poll, Duration::from_secs(10));
        assert_eq!(cfg.anchor_recheck, Duration::from_secs(600));
        assert_eq!(cfg.anchor_url.as_str(), "https://checkpoint.pulsechain.com/");
        assert_eq!(cfg.on_miss, OnMiss::Fetch);
        assert_eq!(cfg.hot_set, 0);
        assert_eq!(cfg.beacon_quorum, 1);
        assert_eq!(cfg.head_max_age, Duration::from_secs(60));
        // No --peer: discovery on, small peer cap.
        assert!(cfg.discovery);
        assert_eq!(cfg.max_peers, 8);
        assert_eq!((d.state_window, d.max_rounds), (120, 40));
        assert_eq!(cfg.state_window, d.state_window);
    }

    #[test]
    fn every_flag_parses() {
        let enode = "enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@10.3.58.6:30303";
        let cfg = parse(&[
            "--chain=943",
            "--datadir=/tmp/x",
            "--http.addr=::1",
            "--http.port=9000",
            "--metrics.addr=127.0.0.1:9100",
            "--beacon.url=https://one.example/beacon/KEY/369",
            "--beacon.url=http://127.0.0.1:5052",
            "--beacon.quorum=2",
            "--beacon.poll=1500ms",
            "--finalized.url=http://127.0.0.1:1234",
            "--finalized.recheck=45s",
            "--state.on-miss=error-and-warm",
            "--state.hot-set=64",
            "--cache.size=512MB",
            "--disk.limit=1536 MB",
            &format!("--peer={enode}"),
        ])
        .unwrap()
        .into_config_with(ram(16 * GIB))
        .unwrap();
        assert_eq!(cfg.chain_id, 943);
        assert_eq!(cfg.rpc_addr, "[::1]:9000".parse().unwrap());
        assert_eq!(cfg.metrics_addr.port(), 9100);
        assert_eq!(cfg.beacon_urls.len(), 2);
        assert_eq!(cfg.beacon_quorum, 2);
        assert_eq!(cfg.beacon_poll, Duration::from_millis(1500));
        assert_eq!(cfg.anchor_recheck, Duration::from_secs(45));
        assert_eq!(cfg.on_miss, OnMiss::ErrorAndWarm);
        assert_eq!(cfg.hot_set, 64);
        assert_eq!(cfg.cache_max_bytes, 512 << 20);
        assert_eq!(cfg.disk_limit, 1536 << 20);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.datadir, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn discovery_defaults_follow_peer_and_can_be_overridden() {
        let enode = "enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@10.3.58.6:30303";
        let peer = format!("--peer={enode}");
        let disc = |args: &[&str]| {
            let mut all = vec!["--beacon.url=http://127.0.0.1:5052"];
            all.extend_from_slice(args);
            parse(&all).unwrap().into_config().unwrap().discovery
        };
        assert!(disc(&[]));
        assert!(!disc(&[&peer]));
        assert!(disc(&[&peer, "--discovery=on"]));
        assert!(!disc(&["--discovery=off"]));
        assert!(parse(&["--discovery=maybe"]).is_err());
        let beacon = "--beacon.url=https://a";
        assert_eq!(parse(&[beacon, "--max-peers=3"]).unwrap().into_config().unwrap().max_peers, 3);
        assert!(parse(&["--max-peers=0"]).is_err());
        assert!(parse(&["--max-peers=x"]).is_err());
    }

    /// Reads one size flag's value from `--{flag}={s}`.
    fn size_flag(flag: &str, s: &str) -> Result<usize, clap::Error> {
        let a = parse(&["--beacon.url=https://a", &format!("--{flag}={s}")])?;
        Ok(if flag == "cache.size" { a.cache_size.unwrap() } else { a.disk_limit })
    }

    /// Reads one duration flag's value from `--{flag}={s}`.
    fn duration_flag(flag: &str, s: &str) -> Result<Duration, clap::Error> {
        let a = parse(&["--beacon.url=https://a", &format!("--{flag}={s}")])?;
        Ok(match flag {
            "beacon.poll" => a.beacon_poll,
            "finalized.recheck" => a.finalized_recheck,
            "rpc.evmtimeout" => a.rpc_evmtimeout,
            "snap.probe-timeout" => a.snap_probe_timeout,
            _ => a.head_max_age,
        })
    }

    const SIZE_FLAGS: [&str; 2] = ["cache.size", "disk.limit"];
    const DURATION_FLAGS: [&str; 5] = [
        "beacon.poll",
        "finalized.recheck",
        "head.max-age",
        "rpc.evmtimeout",
        "snap.probe-timeout",
    ];

    /// Size flags take pulse-reth's sizes: binary `B KB MB GB TB`, whole numbers only.
    #[test]
    fn size_flags_take_pulse_reth_sizes() {
        for (s, want) in [
            ("0", 0),
            ("4096", 4096),
            ("512MB", 512 << 20),
            ("16 MB", 16 << 20),
            ("2gb", 2 << 30),
            ("1TB", 1 << 40),
        ] {
            for flag in SIZE_FLAGS {
                assert_eq!(size_flag(flag, s).unwrap(), want, "--{flag}={s}");
            }
        }
        for (s, why) in [
            ("1GiB", "Invalid unit: GIB. Use B, KB, MB, GB, or TB."),
            ("256MiB", "Invalid unit: MIB. Use B, KB, MB, GB, or TB."),
            ("1.5GB", "Invalid number"),
            ("-1", "Invalid number"),
            ("18446744073709551616", "Invalid number"),
            ("17179869184GB", "Byte size exceeds the maximum supported value"),
        ] {
            for flag in SIZE_FLAGS {
                let err = size_flag(flag, s).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::ValueValidation, "--{flag}={s}: {err}");
                let head = format!("invalid value '{s}' for '--{flag} <");
                let text = err.to_string();
                assert!(text.contains(&head) && text.contains(why), "--{flag}={s}: {text}");
            }
        }
    }

    /// Duration flags take humantime durations, as pulse-reth's humantime flags do. A bare number,
    /// which pulse-reth's `parse_duration_from_secs_or_ms` flags read as seconds, is refused.
    #[test]
    fn duration_flags_take_humantime_durations() {
        let readme = include_str!("../README.md").split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!readme.contains("because reth-lite uses the same parsers"));
        assert!(readme.contains("`--txpool.lifetime 10800`"), "the README names the difference");
        for (s, want) in [
            ("1500ms", Duration::from_millis(1500)),
            ("1.5s", Duration::from_millis(1500)),
            ("45s", Duration::from_secs(45)),
            ("90sec", Duration::from_secs(90)),
            ("10m", Duration::from_secs(600)),
            ("2min", Duration::from_secs(120)),
            ("1h 30m", Duration::from_secs(5400)),
            ("1h30m", Duration::from_secs(5400)),
            ("1d", Duration::from_secs(86_400)),
        ] {
            for flag in DURATION_FLAGS {
                assert_eq!(duration_flag(flag, s).unwrap(), want, "--{flag}={s}");
            }
        }
        for (s, why) in [
            ("10", "time unit needed, for example 10sec or 10ms"),
            ("", "value was empty"),
            ("10x", "unknown time unit \"x\""),
            ("-1s", "expected number at 0"),
            ("18446744073709551616s", "number is too large"),
        ] {
            for flag in DURATION_FLAGS {
                let err = duration_flag(flag, s).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::ValueValidation, "--{flag}={s}: {err}");
                let text = err.to_string();
                assert!(text.contains(why), "--{flag}={s}: {text}");
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// A size flag reads any text exactly as pulse-reth's parser does.
        #[test]
        fn a_size_flag_reads_text_as_pulse_reth_does(
            s in prop_oneof![
                "[+-]?[0-9]{0,22} ?(k|m|g|t|K|M|G|T)?(i|I)?(b|B)?",
                "[0-9 .a-zA-Z]{0,24}",
                "\\PC{0,24}",
            ],
        ) {
            for flag in SIZE_FLAGS {
                let got = size_flag(flag, &s).ok();
                prop_assert_eq!(got, reth_cli_util::parse_byte_size(&s).ok(), "--{}={}", flag, &s);
            }
        }

        /// A duration flag reads any text exactly as `humantime` does.
        #[test]
        fn a_duration_flag_reads_text_as_humantime_does(
            s in prop_oneof![
                "[0-9]{0,22}(\\.[0-9]{0,3})? ?(ns|us|ms|s|sec|m|min|h|hr|d|w|M|y)?",
                "[0-9 .a-zA-Z]{0,24}",
                "\\PC{0,24}",
            ],
        ) {
            for flag in DURATION_FLAGS {
                let got = duration_flag(flag, &s).ok();
                prop_assert_eq!(got, humantime::parse_duration(&s).ok(), "--{}={}", flag, &s);
            }
        }
    }

    /// `--rpc.evmtimeout` is geth's: `5s` by default, and `0` sets no limit.
    #[test]
    fn the_evm_timeout_defaults_to_five_seconds_and_zero_turns_it_off() {
        let cfg = |args: &[&str]| {
            let all = [&["--beacon.url=https://a"], args].concat();
            parse(&all).unwrap().into_config().unwrap().evm_timeout
        };
        assert_eq!(cfg(&[]), Duration::from_secs(5));
        assert_eq!(LiteConfig::default().evm_timeout, Duration::from_secs(5));
        assert_eq!(cfg(&["--rpc.evmtimeout=0"]), Duration::ZERO);
        assert_eq!(cfg(&["--rpc.evmtimeout=0s"]), Duration::ZERO);
        assert_eq!(cfg(&["--rpc.evmtimeout=250ms"]), Duration::from_millis(250));
        // geth bounds `eth_call` only (`DoCall`): `DoEstimateGas` sets no EVM timeout.
        use clap::CommandFactory;
        let cmd = LiteArgs::command();
        let arg = cmd.get_arguments().find(|a| a.get_long() == Some("rpc.evmtimeout")).unwrap();
        let help = arg
            .get_long_help()
            .unwrap()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let readme = include_str!("../README.md");
        let row = readme.lines().find(|l| l.starts_with("| `--rpc.evmtimeout`")).unwrap();
        for doc in [help.as_str(), row] {
            assert!(doc.contains("as geth's `--rpc.evmtimeout` for `eth_call`"), "{doc}");
            assert!(doc.contains("The limit on `eth_estimateGas` is reth-lite's"), "{doc}");
        }
        let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(readme.contains("an `eth_call` ran past `--rpc.evmtimeout`, as geth answers it"));
    }

    #[test]
    fn chains_resolve_from_the_network_table() {
        for id in ["369", "943"] {
            let cfg =
                parse(&["--chain", id, "--beacon.url=https://a", "--finalized.url=https://t"])
                    .unwrap()
                    .into_config()
                    .unwrap();
            assert!(pulsechain_network(cfg.chain_id).is_some());
        }
        assert!(parse(&["--chain=1"]).is_err());
        assert!(parse(&["--chain=abc"]).is_err());
    }

    #[test]
    fn testnet_needs_its_own_finalized_url() {
        // The built-in anchor serves mainnet: on 943 the node would never confirm it.
        let err = parse(&["--chain=943", "--beacon.url=https://a"]).unwrap().into_config();
        let err = err.unwrap_err();
        assert!(matches!(err, ConfigError::NoDefaultAnchor { chain: 943 }), "{err}");
        assert_eq!(
            err.to_string(),
            "--chain=943 has no built-in finalized anchor: give --finalized.url or \
             --finalized.url-file"
        );
        let cfg = parse(&["--chain=943", "--beacon.url=https://a", "--finalized.url=https://t"])
            .unwrap()
            .into_config()
            .unwrap();
        assert_eq!(cfg.anchor_url.as_str(), "https://t/");
    }

    #[test]
    fn durations_do_not_wrap_and_have_a_ceiling() {
        // 307445734561825861 minutes is 2^64 + 44 seconds.
        for s in ["307445734561825861m", "5124095576030432h", "18446744073709551616s"] {
            let err = duration_flag("beacon.poll", s).unwrap_err();
            assert!(err.to_string().contains("number is too large"), "{s}: {err}");
        }
        let cfg = |flag: &str| parse(&["--beacon.url=https://a", flag]).unwrap().into_config();
        for (flag, want) in [
            ("--beacon.poll=3074457345618258603s", "--beacon.poll must be at most 24h"),
            ("--beacon.poll=18446744073709551615s", "--beacon.poll must be at most 24h"),
            ("--finalized.recheck=1441m", "--finalized.recheck must be at most 24h"),
            ("--head.max-age=86401s", "--head.max-age must be at most 24h"),
            ("--rpc.evmtimeout=86401s", "--rpc.evmtimeout must be at most 24h"),
        ] {
            assert_eq!(cfg(flag).unwrap_err().to_string(), want, "{flag}");
        }
        let cfg = parse(&[
            "--beacon.url=https://a",
            "--beacon.poll=24h",
            "--finalized.recheck=24h",
            "--head.max-age=24h",
            "--rpc.evmtimeout=24h",
            "--head.confirm=none",
        ])
        .unwrap()
        .into_config()
        .unwrap();
        assert_eq!(cfg.evm_timeout, Duration::from_secs(86_400));
        assert_eq!(cfg.beacon_poll, Duration::from_secs(86_400));
        assert_eq!(cfg.anchor_recheck, Duration::from_secs(86_400));
        assert_eq!(cfg.head_max_age, Duration::from_secs(86_400));
    }

    fn ram(bytes: u64) -> Option<Memory> {
        Some(Memory { bytes, source: MemorySource::Ram })
    }

    fn cgroup(bytes: u64) -> Option<Memory> {
        Some(Memory { bytes, source: MemorySource::Cgroup })
    }

    /// The config from `args` on a box with `memory`.
    fn config_on(memory: Option<Memory>, args: &[&str]) -> Result<LiteConfig, ConfigError> {
        let mut all = vec!["--beacon.url=http://127.0.0.1:5052"];
        all.extend_from_slice(args);
        parse(&all).unwrap().into_config_with(memory)
    }

    #[test]
    fn memory_budgets_adapt_to_the_box() {
        let budgets = |memory| {
            let cfg = config_on(memory, &[]).unwrap();
            (cfg.cache_max_bytes, cfg.body_budget)
        };
        assert_eq!(budgets(ram(16 * GIB)), (GIB, 256 * MIB));
        assert_eq!(budgets(cgroup(GIB)), (GIB / 100 * 25, GIB / 100 * 10));
        assert_eq!(budgets(ram(2 * GIB)), (2 * GIB / 100 * 25, 2 * GIB / 100 * 10));
        // 512MB: the 25% share (128MB) does not fit beside the fixed budgets; the default takes
        // the largest cache whose heap bound fits in what they leave.
        let bodies = 512 * MIB / 100 * 10;
        let room = 512 * MIB - (2 * bodies + (32 << 20) + (256 << 20));
        assert_eq!(budgets(ram(512 * MIB)), (room / 6 * 5, bodies));
        // The fixed budgets alone do not fit: the cache is off.
        assert_eq!(budgets(cgroup(128 * MIB)), (0, 32 * MIB));
        assert_eq!(budgets(ram(256 * MIB)), (0, 32 * MIB));
        // Memory not found: the fixed defaults.
        assert_eq!(budgets(None), (GIB, 256 * MIB));
    }

    /// One rule for both paths: the default, given as `--cache.size`, always starts, and the
    /// default's heap bound with the fixed budgets fits in the memory found when they leave room.
    #[test]
    fn the_default_cache_passes_the_explicit_check() {
        let mut bytes = 64 * MIB;
        while bytes <= 64 * GIB {
            for found in [ram(bytes), cgroup(bytes + 12_345)] {
                let cfg = config_on(found, &[]).unwrap();
                let flag = format!("--cache.size={}", cfg.cache_max_bytes);
                let given = config_on(found, &[&flag]).unwrap();
                assert_eq!(given.cache_max_bytes, cfg.cache_max_bytes, "{found:?}");
                let fixed = 2 * cfg.body_budget + (32 << 20) + (256 << 20);
                let heap = cfg.cache_max_bytes + cfg.cache_max_bytes / 5;
                assert!(cfg.cache_max_bytes == 0 || heap + fixed <= found.unwrap().bytes);
            }
            bytes += 61 * MIB;
        }
    }

    #[test]
    fn a_box_too_small_for_the_fixed_budgets_starts_with_the_cache_off_and_warns() {
        let cap = crate::testing::logs::capture(tracing::Level::WARN);
        assert_eq!(config_on(ram(256 * MIB), &[]).unwrap().cache_max_bytes, 0);
        let text = cap.text();
        assert!(
            text.contains("the node's fixed budgets alone need more than the memory found"),
            "{text}"
        );
        assert!(text.contains("fixed_mb=352") && text.contains("memory_mb=256"), "{text}");
        drop(cap);
        let cap = crate::testing::logs::capture(tracing::Level::WARN);
        config_on(ram(GIB), &[]).unwrap();
        assert_eq!(cap.text(), "");
    }

    #[test]
    fn an_explicit_cache_size_wins_when_it_fits() {
        let cache = |memory, flag| config_on(memory, &[flag]).unwrap().cache_max_bytes;
        assert_eq!(cache(ram(16 * GIB), "--cache.size=2GB"), 2 * GIB);
        assert_eq!(cache(cgroup(GIB), "--cache.size=256MB"), 256 * MIB);
        assert_eq!(cache(cgroup(GIB), "--cache.size=0"), 0);
        // Memory not found: the value is kept, whatever it is.
        assert_eq!(cache(None, "--cache.size=1TB"), 1 << 40);
        assert_eq!(config_on(None, &["--cache.size=1TB"]).unwrap().body_budget, 256 * MIB);
    }

    /// The fixed budgets are the held bodies (twice: a walk holds as much again), the receipts
    /// and the runtime allowance. The cache counts at its heap bound, 1.2 times its size.
    #[test]
    fn an_explicit_cache_size_the_box_cannot_hold_is_refused() {
        let err = config_on(cgroup(GIB), &["--cache.size=1GB"]).unwrap_err();
        assert!(matches!(err, ConfigError::CacheTooLarge { .. }), "{err:?}");
        assert_eq!(
            err.to_string(),
            "--cache.size=1GB (a heap of up to 1229MB) and the node's fixed budgets need 1722MB, \
             but the box has 1024MB (cgroup memory limit); give a smaller --cache.size, or leave \
             it out for a default sized to the box"
        );
        let err = config_on(ram(512 * MIB), &["--cache.size=300MB"]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--cache.size=300MB (a heap of up to 360MB) and the node's fixed budgets need 751MB, \
             but the box has 512MB (physical RAM); give a smaller --cache.size, or leave it out \
             for a default sized to the box"
        );
        // The boundary: the cache's heap bound may take all that the fixed budgets leave.
        let fixed = 2 * (GIB / 100 * 10) + (32 << 20) + (256 << 20);
        let room = GIB - fixed;
        let fits = room / 6 * 5;
        let flag = format!("--cache.size={fits}");
        assert_eq!(config_on(cgroup(GIB), &[&flag]).unwrap().cache_max_bytes, fits);
        for over in [fits + 5, room] {
            let flag = format!("--cache.size={over}");
            let err = config_on(cgroup(GIB), &[&flag]).unwrap_err();
            assert!(err.to_string().starts_with(&format!("{flag} (a heap of up to ")), "{err}");
        }
        // A box too small for the fixed budgets takes only `0`, as its default is.
        assert_eq!(config_on(ram(256 * MIB), &["--cache.size=0"]).unwrap().cache_max_bytes, 0);
        let err = config_on(ram(256 * MIB), &["--cache.size=1MB"]).unwrap_err();
        assert!(matches!(err, ConfigError::FixedBudgetsTooLarge { .. }), "{err:?}");
        assert_eq!(
            err.to_string(),
            "--cache.size=1MB does not fit: the node's fixed budgets alone need 352MB of the 256MB \
             the box has (physical RAM), so no cache fits; give --cache.size=0 or leave it out, \
             which turn the cache off, or give the node more memory"
        );
        // The docs name the fixed budgets this check counts.
        use clap::CommandFactory;
        let runtime = RUNTIME_BYTES / MIB;
        let receipts = RECEIPT_CACHE_BYTES as u64 / MIB;
        let readme = include_str!("../README.md");
        let row = readme.lines().find(|l| l.starts_with("| `--cache.size`")).unwrap();
        let want = format!("twice the held-body budget (see Notes), {receipts} MiB of receipts and {runtime} MiB for the runtime");
        assert!(row.contains(&want), "{want} not in {row}");
        let cmd = LiteArgs::command();
        let arg = cmd.get_arguments().find(|a| a.get_long() == Some("cache.size")).unwrap();
        let help = arg.get_long_help().unwrap().to_string();
        let want = format!(
            "twice the held-body budget, {receipts}MB of receipts and {runtime}MB for the runtime"
        );
        assert!(help.contains(&want), "{want} not in {help}");
        let (min, max) = (MIN_CACHE_BYTES / MIB, MAX_CACHE_BYTES / GIB);
        let want = format!(
            "Default: {CACHE_PERCENT}% of the memory found, at least {min}MB and at most \
             {max}GB, but no more than the fixed budgets leave"
        );
        assert!(help.contains(&want), "{want} not in {help}");
        for doc in [&help, row] {
            assert!(doc.contains("1.2 times"), "{doc}");
            assert!(doc.contains("the fixed budgets alone do not fit"), "{doc}");
            assert!(doc.contains("the lower of `memory.max` and `memory.high`"), "{doc}");
        }
    }

    #[test]
    fn poll_and_recheck_have_a_floor() {
        let cfg = |flag: &str| parse(&["--beacon.url=https://a", flag]).unwrap().into_config();
        for (flag, want) in [
            ("--beacon.poll=0s", "--beacon.poll must be at least 1s"),
            ("--beacon.poll=999ms", "--beacon.poll must be at least 1s"),
            ("--finalized.recheck=0s", "--finalized.recheck must be at least 30s"),
            ("--finalized.recheck=29s", "--finalized.recheck must be at least 30s"),
        ] {
            assert_eq!(cfg(flag).unwrap_err().to_string(), want, "{flag}");
        }
        assert_eq!(cfg("--beacon.poll=1s").unwrap().beacon_poll, Duration::from_secs(1));
        assert_eq!(cfg("--finalized.recheck=30s").unwrap().anchor_recheck, Duration::from_secs(30));
    }

    /// Every error text the RPC returns, by the name of its constant in `rpc.rs`, in its README
    /// form. A text the RPC builds around a constant prefix is named in that form.
    fn rpc_error_texts() -> Vec<(&'static str, String)> {
        use crate::{call::CallError, exec::RoundsError, rpc::*};
        macro_rules! named {
            ($($name:ident),* $(,)?) => { [$((stringify!($name), $name.to_string())),*] };
        }
        let prefixed = [
            ("STATE_UNAVAILABLE", format!("{STATE_UNAVAILABLE}: <reason>")),
            ("NOT_CONVERGED", format!("{NOT_CONVERGED} after N rounds")),
            ("RECEIPTS_UNAVAILABLE", format!("{RECEIPTS_UNAVAILABLE}: <reason>")),
            ("RENDERING_FAILED", format!("{RENDERING_FAILED}: <reason>")),
            ("PRUNED_HISTORY", format!("{PRUNED_HISTORY}: requested N, earliest available M")),
            ("INVALID_PERCENTILE", format!("{INVALID_PERCENTILE}: <reason>")),
            ("INVALID_TRANSACTION", format!("{INVALID_TRANSACTION}: <reason>")),
            ("WRONG_CHAIN_ID", format!("{WRONG_CHAIN_ID}: have N, want M")),
            ("OVERSIZED_TX", format!("{OVERSIZED_TX}: transaction size N, limit 131072")),
            ("NONCE_TOO_LOW", format!("{NONCE_TOO_LOW}: address A, tx: N state: M")),
            ("INTRINSIC_GAS_TOO_LOW", format!("{INTRINSIC_GAS_TOO_LOW}: gas N, needed M")),
            ("INITCODE_TOO_LARGE", format!("{INITCODE_TOO_LARGE}: code size N, limit 49152")),
            (
                "INSUFFICIENT_FUNDS",
                format!("{INSUFFICIENT_FUNDS}: balance B, tx cost C, overshot O"),
            ),
        ];
        let texts = named![
            MISS_MESSAGE,
            REFUSED_MESSAGE,
            NOT_IN_WINDOW,
            HALTED_MESSAGE,
            BEHIND_ANCHOR,
            FINALITY_STALLED,
            BAD_SENDER,
            RESEEDED,
            NOT_CANONICAL,
            FINALITY_UNCONFIRMED,
            STALE_HEAD,
            BLOCKHASH_NOT_HELD,
            RESPONSE_TOO_LARGE,
            RESPONSE_BUDGET_FULL,
            NO_HEAD,
            REQUEST_TIMED_OUT,
            EXECUTION_ABORTED,
            RECEIPTS_MISMATCH,
            BODY_BUDGET_FULL,
            BATCH_TOO_LARGE,
            RECEIPTS_BUSY,
            TOO_MANY_LOGS,
            LOG_BLOCKS_TOO_MANY,
            INVALID_BLOCK_RANGE,
            TOO_MANY_TOPICS,
            TOO_MANY_FILTER_VALUES,
            TX_TYPE_NOT_SUPPORTED,
            UNPROTECTED_TX,
            NO_TX_PEERS,
            GAS_LIMIT_EXCEEDED,
            TIP_ABOVE_FEE_CAP,
        ];
        // The RPC answers this `RoundsError` with its own text. Its round is `N` in the README.
        // `BlockHashUnavailable` never reaches a client: `eth_call` maps it to
        // `BLOCKHASH_NOT_HELD`, and a state read reads no block hash.
        let no_progress = RoundsError::NoProgress(7).to_string().replace('7', "N");
        // An EVM run past `--rpc.evmtimeout` answers geth's text, with the default in the README.
        let timeout = CallError::Timeout(LiteConfig::default().evm_timeout).to_string();
        assert!(timeout.starts_with(EXECUTION_ABORTED), "{timeout}");
        texts
            .into_iter()
            .chain(prefixed)
            .chain([("NoProgress", no_progress), ("Timeout", timeout)])
            .collect()
    }

    /// The README names every error text the RPC returns, so a client can match on it. The list
    /// is checked against every `&str` constant in `rpc.rs`, so a new text cannot skip it.
    #[test]
    fn readme_names_every_rpc_error_text() {
        let texts = rpc_error_texts();
        let mut declared = include_str!("rpc.rs")
            .lines()
            .filter_map(|l| Some(l.strip_prefix("pub const ")?.split_once(": &str =")?.0))
            .collect::<Vec<_>>();
        declared.sort_unstable();
        let mut listed = texts
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !["NoProgress", "Timeout"].contains(name))
            .collect::<Vec<_>>();
        listed.sort_unstable();
        assert_eq!(listed, declared, "rpc.rs declares a text this test does not list");
        let readme = include_str!("../README.md").split_whitespace().collect::<Vec<_>>().join(" ");
        let missing = texts
            .into_iter()
            .filter(|(_, text)| !readme.contains(&format!("`{text}`")))
            .collect::<Vec<_>>();
        assert_eq!(missing, Vec::<(&str, String)>::new());
        let timeout = readme_error_bullets()
            .into_iter()
            .find(|b| b.contains("`request timed out`"))
            .expect("a bullet names the timeout");
        let limits = crate::rpc::ServerLimits::default();
        for d in [limits.request_timeout, limits.body_idle_timeout] {
            let secs = format!("{} s", d.as_secs());
            assert!(timeout.contains(&secs), "{secs} not in {timeout}");
        }
        let window =
            format!("more than {} blocks below the head", LiteConfig::default().state_window);
        assert!(readme.contains(&window), "{window} not in the README");
    }

    /// The top-level bullets of the README's methods and errors section, each on one line. A
    /// nested list stays in the bullet that introduces it.
    fn readme_error_bullets() -> Vec<String> {
        let readme = include_str!("../README.md");
        let section = readme
            .split("## Methods, errors and metrics")
            .nth(1)
            .and_then(|rest| rest.split("\n## ").next())
            .expect("the README has the section");
        section
            .split("\n* ")
            .skip(1)
            .map(|b| b.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    /// Each error text in the README sits under the code the RPC answers it with: the nearest
    /// code before the text in its bullet. A client matches on the code first.
    #[test]
    fn readme_lists_each_rpc_error_under_its_code() {
        use crate::rpc::{MISS_CODE, PRUNED_HISTORY_CODE};
        let coded = [
            ("REFUSED_MESSAGE", -32601),
            ("MISS_MESSAGE", MISS_CODE),
            ("PRUNED_HISTORY", PRUNED_HISTORY_CODE),
            ("BATCH_TOO_LARGE", -32600),
            ("RESPONSE_TOO_LARGE", -32003),
            ("RESPONSE_BUDGET_FULL", -32005),
            ("BODY_BUDGET_FULL", -32005),
            ("RECEIPTS_BUSY", -32005),
            ("TOO_MANY_LOGS", -32005),
            ("LOG_BLOCKS_TOO_MANY", -32005),
            ("REQUEST_TIMED_OUT", -32002),
        ];
        let code_of =
            |name: &str| coded.iter().find(|(n, _)| *n == name).map_or(-32000, |(_, code)| *code);
        let texts = rpc_error_texts();
        // The table above agrees with each `(<code>, NAME)` and `other(NAME)` in rpc.rs.
        let source = include_str!("rpc.rs");
        for (name, _) in &texts {
            for (at, _) in source.match_indices(&format!(", {name})")) {
                let code = source[..at].rsplit('(').next().unwrap();
                if let Ok(code) = code.parse::<i64>() {
                    assert_eq!(code, code_of(name), "{name} in rpc.rs");
                }
            }
            if source.contains(&format!("other({name})")) {
                assert_eq!(code_of(name), -32000, "{name} in rpc.rs");
            }
        }
        let bullets = readme_error_bullets();
        for (name, text) in &texts {
            let quoted = format!("`{text}`");
            let mut seen = false;
            for bullet in &bullets {
                for (at, _) in bullet.match_indices(&quoted) {
                    seen = true;
                    let code = bullet[..at]
                        .split('`')
                        .skip(1)
                        .step_by(2)
                        .filter_map(|t| t.parse::<i64>().ok())
                        .last();
                    assert_eq!(code, Some(code_of(name)), "{name} in: {bullet}");
                }
            }
            assert!(seen, "{name}: {quoted} is not in the methods and errors section");
        }
    }

    /// The `--cache.size` help and README row name the per-entry charge the store really makes.
    #[test]
    fn cache_docs_name_the_real_per_entry_charge() {
        use crate::store::{NodeStore, Store};
        use alloy_primitives::{keccak256, Bytes};
        use clap::CommandFactory;
        let store = Store::in_memory(1 << 20);
        let value = Bytes::from(vec![7u8; 100]);
        store.put(keccak256(&value), value);
        let charge = format!("plus {} bytes", store.bytes() - 100);
        let cmd = LiteArgs::command();
        let arg = cmd.get_arguments().find(|a| a.get_long() == Some("cache.size")).unwrap();
        let help = arg.get_long_help().unwrap().to_string();
        assert!(help.contains(&charge), "{charge} not in {help}");
        let readme = include_str!("../README.md");
        let row = readme.lines().find(|l| l.starts_with("| `--cache.size`")).unwrap();
        assert!(row.contains(&charge), "{charge} not in {row}");
    }

    /// Each flag's README default cell is exactly its clap default in backticks, one per flag
    /// of the row. A flag with no clap default shows `none`, or the computed default.
    #[test]
    fn readme_rows_name_every_flag_and_its_default() {
        use clap::CommandFactory;
        let toggle = |args: &[&str]| {
            let mut all = vec!["--beacon.url=https://a", "--head.confirm=none"];
            all.extend_from_slice(args);
            if parse_exact(&all).unwrap().into_config().unwrap().discovery {
                "`on`"
            } else {
                "`off`"
            }
        };
        let peer = "--peer=enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@10.3.58.6:30303";
        let confirm = |verify: &str| {
            let args = ["--beacon.url=https://a", peer, verify];
            match parse_exact(&args).unwrap().into_config().unwrap().head_confirm {
                HeadConfirm::Peer => "`peer`",
                HeadConfirm::None => "`none`",
            }
        };
        let d = LiteConfig::default();
        let mode = parse_exact(&[
            "--beacon.url=https://a",
            "--head.confirm=none",
            "--upstream.url=https://up.example/k",
        ])
        .unwrap()
        .into_config()
        .unwrap()
        .upstream_mode;
        assert_eq!(mode, UpstreamMode::Fallback);
        let computed = [
            ("upstream.mode", "`fallback` with an upstream URL".to_owned()),
            (
                "discovery",
                format!("{} without `--peer`, {} with `--peer`", toggle(&[]), toggle(&[peer])),
            ),
            (
                "head.confirm",
                format!(
                    "{} with `--head.verify=quorum`, {} with `--head.verify=sync-committee`",
                    confirm("--head.verify=quorum"),
                    confirm("--head.verify=sync-committee")
                ),
            ),
            (
                "cache.size",
                format!(
                    "{CACHE_PERCENT}% of memory, `{}MB` to `{}GB`",
                    MIN_CACHE_BYTES >> 20,
                    MAX_CACHE_BYTES >> 30
                ),
            ),
            (
                "checkpoint",
                format!(
                    "the root pinned for {} (slot {}); none on 943",
                    d.chain_id,
                    pulsechain_network(d.chain_id).unwrap().checkpoint.unwrap().slot
                ),
            ),
            (
                "finalized.url",
                format!(
                    "`{}` on {}; none on 943",
                    d.anchor_url.as_str().trim_end_matches('/'),
                    d.chain_id
                ),
            ),
        ];
        let readme = include_str!("../README.md");
        let cell =
            |row: &str, i: usize| row.split('|').nth(i).unwrap_or_default().trim().to_owned();
        let mut problems = Vec::new();
        for arg in LiteArgs::command().get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            let flag = format!("`--{long}`");
            let Some(row) = readme
                .lines()
                .find(|row| row.starts_with('|') && cell(row, 1).split(" / ").any(|f| f == flag))
            else {
                problems.push(format!("{flag}: no row"));
                continue
            };
            let flags = cell(row, 1);
            let flags = flags.split(" / ").collect::<Vec<_>>();
            let shown = cell(row, 2);
            let shown = shown.split(" / ").collect::<Vec<_>>();
            if shown.len() != flags.len() {
                problems.push(format!("{flag}: {} flags but defaults {shown:?}", flags.len()));
                continue
            }
            let shown = shown[flags.iter().position(|f| *f == flag).unwrap()];
            let want = match arg.get_default_values() {
                [] => computed
                    .iter()
                    .find(|(name, _)| *name == long)
                    .map_or_else(|| "none".to_owned(), |(_, text)| text.clone()),
                [one] => format!("`{}`", one.to_string_lossy()),
                many => {
                    problems.push(format!("{flag}: {} defaults", many.len()));
                    continue
                }
            };
            if shown != want {
                problems.push(format!("{flag}: README shows `{shown}`, want `{want}`"));
            }
        }
        assert_eq!(problems, Vec::<String>::new(), "README flag table out of date");
    }

    #[test]
    fn the_snap_probe_timeout_defaults_to_3s_reaches_the_network_and_refuses_zero() {
        let cfg = |args: &[&str]| {
            let mut all = vec!["--beacon.url=https://a", "--head.confirm=none"];
            all.extend_from_slice(args);
            parse_exact(&all).unwrap().into_config()
        };
        let key = reth_network::config::rng_secret_key();
        let default = cfg(&[]).unwrap();
        assert_eq!(default.snap_probe_timeout, Duration::from_secs(3));
        assert_eq!(default.snap_probe_timeout, LiteConfig::default().snap_probe_timeout);
        let opts = crate::net::wire::NetOptions::from_config(&default, key);
        assert_eq!(opts.snap_probe, Some(Duration::from_secs(3)));
        let short = cfg(&["--snap.probe-timeout=250ms"]).unwrap();
        assert_eq!(short.snap_probe_timeout, Duration::from_millis(250));
        let opts = crate::net::wire::NetOptions::from_config(&short, key);
        assert_eq!(opts.snap_probe, Some(Duration::from_millis(250)));
        assert_eq!(
            cfg(&["--snap.probe-timeout=0s"]).unwrap_err().to_string(),
            "--snap.probe-timeout must be at least 1ms"
        );
        assert_eq!(
            cfg(&["--snap.probe-timeout=25h"]).unwrap_err().to_string(),
            "--snap.probe-timeout must be at most 24h"
        );
        assert!(format!("{short:?}").contains("snap_probe_timeout: 250ms"));
    }

    #[test]
    fn upstream_urls_are_opt_in_secret_and_take_a_mode() {
        let cfg = |args: &[&str]| {
            let mut all = vec!["--beacon.url=https://a", "--head.confirm=none"];
            all.extend_from_slice(args);
            parse_exact(&all).unwrap().into_config()
        };
        let none = cfg(&[]).unwrap();
        assert!(none.upstream_urls.is_empty());
        let key = "https://rpc.up.example/v1/vk_upstream_secret";
        let one = cfg(&[&format!("--upstream.url={key}"), "--upstream.url=http://127.0.0.1:8545"])
            .unwrap();
        assert_eq!(one.upstream_urls.len(), 2);
        assert_eq!(one.upstream_urls[0].as_str(), key);
        assert_eq!(one.upstream_mode, UpstreamMode::Fallback);
        let shown = format!("{one:?}");
        assert!(!shown.contains("vk_upstream_secret"), "{shown}");
        assert!(
            shown.contains("https://*.up.example") && shown.contains("http://127.0.0.1"),
            "{shown}"
        );
        let args =
            parse_exact(&["--beacon.url=https://a", &format!("--upstream.url={key}")]).unwrap();
        assert!(!format!("{args:?}").contains("vk_upstream_secret"));
        let only = cfg(&["--upstream.url=https://up.example/k", "--upstream.mode=only"]).unwrap();
        assert_eq!(only.upstream_mode, UpstreamMode::Only);
        for (args, want) in [
            (
                vec!["--upstream.mode=only"],
                "--upstream.mode needs --upstream.url or --upstream.url-file",
            ),
            (vec!["--upstream.url=ftp://up.example/k"], "--upstream.url must be an http(s) URL"),
            (
                vec!["--upstream.url=http://up.example/k"],
                "--upstream.url must use https unless the host is loopback",
            ),
            (
                vec!["--upstream.url=https://up.example/#vk_secret"],
                "--upstream.url must not have a fragment: the node never sends it; put a key in \
                 the path or the query",
            ),
        ] {
            assert_eq!(cfg(&args).unwrap_err().to_string(), want, "{args:?}");
        }
        let (_d, file) = url_file("# upstreams\nhttps://up.example/vk_from_file\n");
        let file = file.replace("--beacon.url-file=", "--upstream.url-file=");
        let from_file = cfg(&[&file]).unwrap();
        assert_eq!(from_file.upstream_urls[0].as_str(), "https://up.example/vk_from_file");
        let both = cfg(&[&file, "--upstream.url=https://up.example/k"]).unwrap_err();
        assert_eq!(
            both.to_string(),
            "--upstream.url and --upstream.url-file are mutually exclusive: give only one"
        );
        let bad = parse_exact(&["--beacon.url=https://a", "--upstream.mode=sometimes"]);
        assert!(bad.unwrap_err().to_string().contains("unknown --upstream.mode `sometimes`"));
    }

    #[test]
    fn help_states_what_each_flag_accepts_and_the_version_names_the_build() {
        use clap::CommandFactory;
        let mut cmd = LiteArgs::command();
        let help = cmd.render_long_help().to_string();
        assert!(!help.contains("into_config") && !help.contains("[`"), "{help}");
        let arg_help = |long: &str| {
            let arg = cmd.get_arguments().find(|a| a.get_long() == Some(long)).unwrap();
            arg.get_help().unwrap().to_string()
        };
        assert_eq!(arg_help("metrics.addr"), "`IP:port` for `/metrics`. A host name is refused");
        assert!(arg_help("peer").contains("The host must be an IP address"), "{help}");
        let version = cmd.get_version().unwrap();
        let want = format!("{}-pulse", env!("CARGO_PKG_VERSION"));
        assert!(version.starts_with(&want) && version.ends_with(')'), "{version}");
    }

    /// The floor is the store's: a limit config accepts must open, and the docs name it.
    #[test]
    fn disk_limit_has_the_store_floor() {
        use crate::store::Store;
        let cfg = |flag: &str| parse(&["--beacon.url=https://a", flag]).unwrap().into_config();
        let below = format!("--disk.limit={}", MIN_DISK_LIMIT - 1);
        // A bare number is bytes: `3` meant as 3 GB is 3 bytes.
        for flag in ["--disk.limit=0", "--disk.limit=3", "--disk.limit=1MB", &below] {
            assert_eq!(
                cfg(flag).unwrap_err().to_string(),
                format!("--disk.limit must be at least {}MB", MIN_DISK_LIMIT >> 20),
                "{flag}"
            );
        }
        let floor = cfg(&format!("--disk.limit={MIN_DISK_LIMIT}")).unwrap().disk_limit;
        assert_eq!(floor, MIN_DISK_LIMIT);
        let dir = tempfile::tempdir().unwrap();
        assert!(Store::open(dir.path(), 1 << 20, floor).is_ok());
        assert!(Store::open(dir.path(), 1 << 20, floor - 1).is_err());

        use clap::CommandFactory;
        let shown = format!("{}MB", MIN_DISK_LIMIT >> 20);
        let cmd = LiteArgs::command();
        let arg = cmd.get_arguments().find(|a| a.get_long() == Some("disk.limit")).unwrap();
        let help = arg.get_help().unwrap().to_string();
        assert!(help.contains(&format!("At least {shown}")), "{help}");
        let row = include_str!("../README.md")
            .lines()
            .find(|l| l.starts_with("| `--disk.limit`"))
            .unwrap();
        assert!(row.contains(&format!("at least `{shown}`")), "{row}");
    }

    /// A hot set above the cap is refused, not silently capped at runtime.
    #[test]
    fn hot_set_has_a_cap() {
        use crate::hot_set::MAX_HOT_SET;
        use clap::CommandFactory;
        let cfg = |n: usize| {
            parse(&["--beacon.url=https://a", &format!("--state.hot-set={n}")])
                .map(|a| a.into_config().unwrap().hot_set)
        };
        assert_eq!(cfg(MAX_HOT_SET).unwrap(), MAX_HOT_SET);
        for n in [MAX_HOT_SET + 1, usize::MAX] {
            let err = cfg(n).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation, "{err}");
            assert!(
                err.to_string().contains(&format!(
                    "--state.hot-set must be a number of at most {MAX_HOT_SET}"
                )),
                "{err}"
            );
        }
        let cap = format!("at most {MAX_HOT_SET}");
        let cmd = LiteArgs::command();
        let arg = cmd.get_arguments().find(|a| a.get_long() == Some("state.hot-set")).unwrap();
        let help = arg.get_help().unwrap().to_string();
        assert!(help.contains(&format!("At most {MAX_HOT_SET}")), "{help}");
        let row = include_str!("../README.md")
            .lines()
            .find(|l| l.starts_with("| `--state.hot-set`"))
            .unwrap();
        assert!(row.contains(&cap), "{row}");
    }

    #[test]
    fn head_max_age_has_a_floor_and_is_checked_against_the_poll() {
        let cfg = |args: &[&str]| {
            let mut all = vec!["--beacon.url=https://a", "--head.confirm=none"];
            all.extend_from_slice(args);
            parse(&all).unwrap().into_config()
        };
        for flag in ["--head.max-age=0s", "--head.max-age=500ms", "--head.max-age=19s"] {
            let err = cfg(&[flag]).unwrap_err();
            assert_eq!(err.to_string(), "--head.max-age must be at least 20s", "{flag}");
        }
        assert_eq!(cfg(&["--head.max-age=20s"]).unwrap().head_max_age, Duration::from_secs(20));
        let logs = capture();
        cfg(&[]).unwrap();
        assert!(!logs.text().contains("--head.max-age"), "{}", logs.text());
        let logs = capture();
        cfg(&["--beacon.poll=1m"]).unwrap();
        assert!(logs.text().contains("--head.max-age is not above one slot"), "{}", logs.text());
        // A sync-committee head lags one more slot: 30s is enough for quorum, not for it.
        let logs = capture();
        cfg(&["--head.max-age=31s"]).unwrap();
        assert!(!logs.text().contains("--head.max-age"), "{}", logs.text());
        let logs = capture();
        cfg(&["--head.max-age=30s", "--head.verify=sync-committee"]).unwrap();
        assert!(logs.text().contains("--head.max-age is not above two slots"), "{}", logs.text());
        let logs = capture();
        cfg(&["--head.max-age=31s", "--head.verify=sync-committee"]).unwrap();
        assert!(!logs.text().contains("--head.max-age"), "{}", logs.text());
    }

    #[test]
    fn refuses_bad_values() {
        let clap_err = |args: &[&str], kind: clap::error::ErrorKind, want: &str| {
            let err = parse(args).unwrap_err();
            assert_eq!(err.kind(), kind, "{args:?}: {err}");
            assert!(err.to_string().contains(want), "{args:?}: {err}");
        };
        let invalid = clap::error::ErrorKind::ValueValidation;
        clap_err(&["--http.addr=0.0.0.0"], invalid, "--http.addr `0.0.0.0` must be a loopback");
        clap_err(&["--http.addr=192.168.1.5"], invalid, "`192.168.1.5` must be a loopback");
        clap_err(&["--http.addr=host.example"], invalid, "`host.example` is not an IP address");
        assert_eq!(parse(&["--http.addr=localhost"]).unwrap().http_addr, Ipv4Addr::LOCALHOST);
        clap_err(&["--state.on-miss=bogus"], invalid, "unknown --state.on-miss `bogus`");
        clap_err(&["--head.confirm=maybe"], invalid, "unknown --head.confirm `maybe` (peer|none)");
        let want = "unknown --head.verify `bls` (quorum|sync-committee)";
        clap_err(&["--head.verify=bls", "--head.confirm=none"], invalid, want);
        clap_err(&["--discovery=maybe"], invalid, "unknown value `maybe` (on|off)");
        clap_err(&["--max-peers=0"], invalid, "--max-peers must be a number of at least 1");
        clap_err(&["--chain=1"], invalid, "unsupported --chain 1 (369 or 943)");
        clap_err(&["--chain=abc"], invalid, "bad --chain `abc` (369 or 943)");
        clap_err(&["--cache.size=3TiB"], invalid, "Invalid unit: TIB. Use B, KB, MB, GB, or TB.");
        clap_err(&["--beacon.poll=10x"], invalid, "unknown time unit \"x\"");
        clap_err(&["--metrics.addr=localhost:9001"], invalid, "invalid socket address");
        clap_err(&["--unknown-flag"], clap::error::ErrorKind::UnknownArgument, "'--unknown-flag'");

        let config_err = |args: &[&str]| parse(args).unwrap().into_config().unwrap_err();
        let err = config_err(&["--beacon.url=ftp://x"]);
        assert!(matches!(err, ConfigError::BadUrl { flag: "--beacon.url", line: None }), "{err}");
        assert_eq!(err.to_string(), "--beacon.url must be an http(s) URL");
        for quorum in ["--beacon.quorum=0", "--beacon.quorum=2"] {
            let err = config_err(&[quorum, "--beacon.url=https://a"]);
            assert!(matches!(err, ConfigError::BadQuorum), "{quorum}: {err}");
            assert_eq!(
                err.to_string(),
                "--beacon.quorum must be between 1 and the number of beacon URLs"
            );
        }
    }

    #[test]
    fn into_config_names_the_flag_and_file_and_keeps_explicit_values() {
        let beacon = "--beacon.url=https://a.example/k";
        let (_d, arg) = url_file("# anchor\n\n");
        let fin = arg.replace("--beacon.url-file=", "--finalized.url-file=");
        let path = arg.trim_start_matches("--beacon.url-file=").to_owned();
        let err = parse(&[beacon, &fin]).unwrap().into_config().unwrap_err();
        assert!(
            matches!(&err, ConfigError::EmptyUrlFile { flag: "--finalized.url-file", path: p } if *p == path),
            "{err:?}"
        );
        assert_eq!(err.to_string(), format!("--finalized.url-file: {path} holds no URL"));
        let err =
            parse(&["--beacon.url-file=/nonexistent/urls"]).unwrap().into_config().unwrap_err();
        assert_eq!(
            err.to_string(),
            "--beacon.url-file: cannot read /nonexistent/urls: No such file or directory (os error 2)"
        );

        let (_d, arg) = url_file("https://checkpoint.example/key\n");
        let fin = arg.replace("--beacon.url-file=", "--finalized.url-file=");
        let cfg = parse(&[
            "--chain=943",
            beacon,
            &fin,
            "--head.max-age=90s",
            "--head.confirm=none",
            "--metrics.addr=[::1]:9100",
            "--cache.size=0",
        ])
        .unwrap()
        .into_config_with(ram(16 * GIB))
        .unwrap();
        // 943 takes the anchor from the file, never the built-in 369 anchor.
        assert_eq!(cfg.anchor_url.as_str(), "https://checkpoint.example/key");
        assert_eq!(cfg.head_max_age, Duration::from_secs(90));
        assert_eq!(cfg.metrics_addr, "[::1]:9100".parse().unwrap());
        // 0 turns the memory cache off; it is not refused.
        assert_eq!(cfg.cache_max_bytes, 0);
    }

    #[test]
    fn beacon_url_error_does_not_echo_the_key() {
        let err = parse(&["--beacon.url=ftp://h/SECRETKEY"]).unwrap().into_config().unwrap_err();
        let err = err.to_string();
        assert!(!err.contains("SECRETKEY"), "{err}");
    }

    #[test]
    fn a_url_with_a_fragment_is_refused() {
        let want = "--beacon.url must not have a fragment: the node never sends it; put a key in \
                    the path or the query";
        for url in ["https://provider.example/eth#vk_secret", "https://provider.example/eth?k=v#"] {
            let err = parse(&[&format!("--beacon.url={url}")]).unwrap().into_config().unwrap_err();
            assert_eq!(err.to_string(), want, "{url}");
        }
        let (_d, arg) = url_file("https://one.example/k\nhttps://two.example/#vk_secret\n");
        let err = parse(&[&arg]).unwrap().into_config().unwrap_err();
        assert_eq!(
            err.to_string(),
            "--beacon.url-file must not have a fragment: the node never sends it; put a key in \
             the path or the query (line 2 of the file)"
        );
        let err = parse(&["--beacon.url=https://a", "--finalized.url=https://c.example/#k"])
            .unwrap()
            .into_config()
            .unwrap_err();
        assert!(matches!(err, ConfigError::UrlFragment { flag: "--finalized.url", line: None }));
    }

    /// A provider that takes its key only as `?apikey=` works: the query survives the config
    /// and the beacon client sends it with every request.
    #[tokio::test]
    async fn a_url_with_a_query_key_reaches_the_beacon() {
        use crate::{
            beacon::BeaconClient,
            fake_beacon::{Fake, FakeChain},
            payload::fake::Fork,
        };
        let beacon = Fake::start(true, false).await;
        let fc = FakeChain::new(Fork::Cancun, 100);
        beacon.push(fc.head());
        beacon.finalize(fc.head());
        beacon.state.lock().require_query = Some("apikey=K1".into());
        let mut url = beacon.beacon_url();
        url.set_query(Some("apikey=K1"));
        let (_d, file) = url_file(&format!("{url}\n"));
        let cfg = parse(&[&file, &format!("--finalized.url={url}"), "--head.confirm=none"])
            .unwrap()
            .into_config()
            .unwrap();
        assert_eq!(cfg.beacon_urls, [url.clone()]);
        assert_eq!(cfg.anchor_url, url);
        let client = BeaconClient::new(cfg.beacon_urls[0].clone());
        assert_eq!(client.head_root().await, Ok(fc.head().root));
        assert_eq!(client.finalized_root().await, Ok(fc.head().root));
        assert!(client.block(&format!("{:#x}", fc.head().root)).await.is_ok());
        assert!(client.events(Duration::from_secs(2)).await.is_ok());
    }

    #[test]
    fn on_miss_parses() {
        assert_eq!("error".parse(), Ok(OnMiss::Error));
        assert_eq!("error-and-warm".parse(), Ok(OnMiss::ErrorAndWarm));
        assert_eq!("fetch".parse(), Ok(OnMiss::Fetch));
        assert!("x".parse::<OnMiss>().is_err());
    }

    // ---- URL files ----

    fn capture() -> crate::testing::logs::Capture {
        crate::testing::logs::capture(tracing::Level::TRACE)
    }

    fn url_file(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("urls");
        std::fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let arg = format!("--beacon.url-file={}", path.display());
        (dir, arg)
    }

    #[test]
    fn url_file_is_parsed_in_order_skipping_blanks_and_comments() {
        let (_d, arg) = url_file(
            "# primary\n\n  https://one.example/beacon/vk_secret/369  \n\t\n# off\n#http://no\nhttp://127.0.0.1:5052\r\n",
        );
        let cfg = parse(&[&arg, "--beacon.quorum=2"]).unwrap().into_config().unwrap();
        let got: Vec<&str> = cfg.beacon_urls.iter().map(Url::as_str).collect();
        assert_eq!(got, ["https://one.example/beacon/vk_secret/369", "http://127.0.0.1:5052/"]);
    }

    #[test]
    fn url_file_errors_do_not_echo_the_url() {
        let (_d, arg) = url_file("https://one.example/ok\nftp://h/beacon/vk_secret/369\n");
        let err = parse(&[&arg]).unwrap().into_config().unwrap_err().to_string();
        assert!(err.contains("line 2"), "{err}");
        assert!(!err.contains("vk_secret") && !err.contains("ftp"), "{err}");
        let (_d, arg) = url_file("# nothing\n\n");
        let err = parse(&[&arg]).unwrap().into_config().unwrap_err().to_string();
        assert!(err.contains("holds no URL"), "{err}");
        let err =
            parse(&["--beacon.url-file=/nonexistent/urls"]).unwrap().into_config().unwrap_err();
        assert!(matches!(err, ConfigError::UrlFile { .. }));
    }

    #[test]
    fn beacon_url_and_file_are_mutually_exclusive() {
        let (_d, arg) = url_file("http://127.0.0.1:5052\n");
        let both = parse(&[&arg, "--beacon.url=https://b"]).unwrap().into_config().unwrap_err();
        assert!(matches!(both, ConfigError::BeaconUrlConflict));
        assert!(both.to_string().contains("mutually exclusive"));
        let neither = parse(&[]).unwrap().into_config().unwrap_err();
        assert!(matches!(neither, ConfigError::NoBeaconUrl));
        assert!(neither.to_string().contains("--beacon.url-file"));
        // Quorum counts file URLs the same way as flag URLs.
        assert!(matches!(
            parse(&[&arg, "--beacon.quorum=2"]).unwrap().into_config().unwrap_err(),
            ConfigError::BadQuorum
        ));
    }

    #[test]
    fn finalized_url_file_is_one_url_and_exclusive_with_the_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fin");
        std::fs::write(&path, "# anchor\nhttps://checkpoint.example/key/vk_secret\n").unwrap();
        let file = format!("--finalized.url-file={}", path.display());
        let beacon = "--beacon.url=https://a";
        let cfg = parse(&[beacon, &file]).unwrap().into_config().unwrap();
        assert_eq!(cfg.anchor_url.host_str(), Some("checkpoint.example"));
        assert!(matches!(
            parse(&[beacon, &file, "--finalized.url=https://b"])
                .unwrap()
                .into_config()
                .unwrap_err(),
            ConfigError::FinalizedUrlConflict
        ));
        std::fs::write(&path, "https://a\nhttps://b\n").unwrap();
        assert!(matches!(
            parse(&[beacon, &file]).unwrap().into_config().unwrap_err(),
            ConfigError::TooManyFinalizedUrls
        ));
        let err = parse(&[beacon, "--finalized.url=ftp://h/vk_secret"])
            .unwrap()
            .into_config()
            .unwrap_err()
            .to_string();
        assert!(!err.contains("vk_secret"), "{err}");
    }

    #[test]
    fn urls_never_appear_in_logs_errors_or_debug_output() {
        let logs = capture();
        let secret = "https://one.example/beacon/vk_secret/369";
        let (_d, arg) = url_file(&format!("{secret}\n"));
        let args =
            parse(&[&arg, "--finalized.url=https://c.example/beacon/vk_secret/369"]).unwrap();
        let mut seen = vec![format!("{args:?}")];
        let cfg = args.into_config().unwrap();
        seen.push(format!("{cfg:?}"));
        seen.push(format!("{:?}", crate::beacon::FollowConfig::from(&cfg)));
        seen.push(crate::beacon::trust_label(&(&cfg).into()));
        let bad = |a: &[&str]| parse(a).unwrap().into_config().unwrap_err().to_string();
        seen.push(bad(&["--beacon.url=ftp://h/beacon/vk_secret/369"]));
        seen.push(bad(&["--beacon.url=not a url/vk_secret/369"]));
        seen.push(bad(&["--beacon.url=https://a", "--finalized.url=ftp://h/vk_secret/369"]));
        seen.push(logs.text());
        for text in &seen {
            assert!(!text.contains("vk_secret"), "{text}");
        }
        assert!(seen[1].contains("https://one.example"), "{}", seen[1]);
    }

    #[test]
    fn a_url_given_in_the_wrong_place_is_not_echoed() {
        let file = "--beacon.url-file=https://beacon.example/vk_secret/369";
        let args = parse(&[file]).unwrap();
        assert!(!format!("{args:?}").contains("vk_secret"), "{args:?}");
        let err = args.into_config().unwrap_err();
        assert!(matches!(err, ConfigError::UrlFile { flag: "--beacon.url-file", .. }), "{err:?}");
        assert!(!format!("{err} {err:?}").contains("vk_secret"), "{err:?}");
        let fin = "--finalized.url-file=https://c.example/vk_secret";
        let err = parse(&["--beacon.url=https://a", fin]).unwrap().into_config().unwrap_err();
        assert!(!format!("{err} {err:?}").contains("vk_secret"), "{err:?}");

        let clap_err = |args: &[&str]| {
            LiteArgs::try_parse_redacted(std::iter::once("reth-lite").chain(args.iter().copied()))
                .unwrap_err()
        };
        // A second URL after one --beacon.url is a stray positional.
        let err =
            clap_err(&["--beacon.url", "https://a.example/k1", "https://b.example/vk_secret"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        assert_eq!(
            err.to_string(),
            "error: unexpected argument found: a value that may hold a URL or key is not echoed; \
             see --help\n"
        );
        let err = clap_err(&["--beacon.quorum=https://b.example/vk_secret"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        assert_eq!(
            err.to_string(),
            "error: invalid value for --beacon.quorum <BEACON_QUORUM>: a value that may hold a \
             URL or key is not echoed; see --help\n"
        );
        // Errors without a URL, and --help (it names the default anchor), are left alone.
        assert!(clap_err(&["--unknown-flag"]).to_string().contains("'--unknown-flag'"));
        let help = clap_err(&["--help"]);
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(help.to_string().contains("https://checkpoint.pulsechain.com"));
    }

    #[test]
    fn a_scheme_less_key_in_a_clap_error_is_not_echoed() {
        let clap_err = |args: &[&str]| {
            LiteArgs::try_parse_redacted(std::iter::once("reth-lite").chain(args.iter().copied()))
                .unwrap_err()
                .to_string()
        };
        let redacted = |flag: &str| {
            format!("error: {flag}: a value that may hold a URL or key is not echoed; see --help\n")
        };
        let stray = redacted("unexpected argument found");
        for value in ["beacon.example/vk_secret/369", "h.example?apikey=vk_secret", "u:vk_secret@h"]
        {
            let shown = clap_err(&["--beacon.url", "https://a.example/k", value]);
            assert_eq!(shown, stray, "{value}");
        }
        let quorum = redacted("invalid value for --beacon.quorum <BEACON_QUORUM>");
        assert_eq!(clap_err(&["--beacon.quorum=beacon.example/vk_secret"]), quorum);
        assert_eq!(clap_err(&["--beacon.quorum", "h?k=vk_secret"]), quorum);
        // A plain typo still names the value.
        assert!(clap_err(&["--beacon.quorum=two"]).contains("'two'"));
        // A URL file path that is a URL without its scheme is not echoed either; a path is.
        let schemeless = [
            "beacon.example/vk_secret/369",
            "h.example?apikey=vk_secret",
            "u:vk_secret@h.example/369",
        ];
        for file in schemeless {
            let beacon = [format!("--beacon.url-file={file}")];
            let finalized = [
                "--beacon.url=https://a.example/k".to_owned(),
                format!("--finalized.url-file={file}"),
            ];
            for args in [&beacon[..], &finalized[..]] {
                let args = parse(&args.iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
                assert!(!format!("{args:?}").contains("vk_secret"), "{args:?}");
                let err = args.into_config().unwrap_err();
                assert!(!format!("{err} {err:?}").contains("vk_secret"), "{err}");
            }
        }
        // Tests run in the crate directory, where `src` exists. A systemd template unit's
        // credentials path has an `@`, and an absolute path is never a URL.
        for path in [
            "/no/such/file",
            "./no/such/file",
            "~/no/such/file",
            "urls.txt",
            "src/no/such",
            "/run/credentials/reth-lite@369.service/beacon-urls",
            "/srv/a?b#c",
        ] {
            let err =
                parse(&[&format!("--beacon.url-file={path}")]).unwrap().into_config().unwrap_err();
            assert!(err.to_string().contains(path), "{err}");
        }
    }

    #[test]
    fn a_datadir_that_looks_like_a_url_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let datadir =
            format!("--datadir={}/https://beacon.example/vk_secret", dir.path().display());
        let err = parse(&["--beacon.url=https://a.example/k", &datadir])
            .unwrap()
            .into_config()
            .unwrap_err();
        assert!(matches!(err, ConfigError::DatadirLooksLikeUrl), "{err:?}");
        assert_eq!(err.to_string(), "--datadir looks like a URL; the value is not echoed");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_bad_enode_keeps_its_reason_and_other_urls_stay_redacted() {
        let clap_err = |args: &[&str]| {
            LiteArgs::try_parse_redacted(std::iter::once("reth-lite").chain(args.iter().copied()))
                .unwrap_err()
                .to_string()
        };
        let id = "6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0";
        let refused = |value: &str, reason: &str| {
            format!(
                "error: invalid value '{value}' for '--peer <PEER>': {reason}\n\nFor more \
                 information, try '--help'.\n"
            )
        };
        let host = format!("enode://{id}@host.example:30303");
        assert_eq!(
            clap_err(&[&format!("--peer={host}")]),
            refused(&host, "Failed to parse url: invalid IPv4 address syntax")
        );
        // geth prints `?discport=N` in admin.nodeInfo when the UDP port differs.
        let discport = format!("{host}?discport=30301");
        assert_eq!(
            clap_err(&[&format!("--peer={discport}")]),
            refused(&discport, "Failed to parse url: invalid IPv4 address syntax")
        );
        let no_port = format!("enode://{id}@10.3.58.6");
        assert_eq!(
            clap_err(&[&format!("--peer={no_port}")]),
            refused(&no_port, "Failed to parse url: no port specified")
        );
        let short_id = "enode://abcd@10.3.58.6:30303";
        assert_eq!(
            clap_err(&[&format!("--peer={short_id}")]),
            refused(short_id, "Failed to parse id")
        );
        let redacted =
            "error: invalid value for --peer <PEER>: a value that may hold a URL or key \
                        is not echoed; see --help\n";
        assert_eq!(clap_err(&["--peer=https://h/SECRET"]), redacted);
        // An enode does not shield a second URL in the same value.
        assert_eq!(clap_err(&[&format!("--peer=enode://{id}@https://h/SECRET")]), redacted);
        // Any other query, a path or a fragment may hold a key.
        for tail in
            ["?discport=30301&k=SECRET", "?k=SECRET", "?discport=SECRET", "/SECRET", "#SECRET"]
        {
            assert_eq!(clap_err(&[&format!("--peer={host}{tail}")]), redacted, "{tail}");
        }
        // Nor does a scheme that only ends in `enode`.
        assert_eq!(clap_err(&["--peer=xenode://SECRET@10.3.58.6:30303"]), redacted);
    }

    /// A URL with a `SECRET…` marker in its userinfo, path, query or fragment, and the marker.
    /// The host never holds it: logs name the host on purpose.
    fn secret_url() -> impl Strategy<Value = (String, String)> {
        let hosts =
            vec!["beacon.example", "127.0.0.1:5052", "localhost", "[::1]:5052", "203.0.113.7"];
        (
            "[a-z0-9]{8,12}",
            prop::sample::select(vec!["https", "http", "ftp", "wss"]),
            prop::sample::select(hosts),
            0..5usize,
        )
            .prop_map(|(tail, scheme, host, place)| {
                let marker = format!("SECRET{tail}");
                let url = match place {
                    0 => format!("{scheme}://user:{marker}@{host}/eth"),
                    1 => format!("{scheme}://{marker}@{host}/eth"),
                    2 => format!("{scheme}://{host}/beacon/{marker}/369"),
                    3 => format!("{scheme}://{host}/eth?apikey={marker}"),
                    _ => format!("{scheme}://{host}/eth#{marker}"),
                };
                (url, marker)
            })
    }

    /// Every flag that takes a value, for a URL given to the wrong one.
    const VALUE_FLAGS: [&str; 18] = [
        "chain",
        "datadir",
        "http.addr",
        "http.port",
        "metrics.addr",
        "beacon.quorum",
        "beacon.poll",
        "finalized.recheck",
        "state.on-miss",
        "state.hot-set",
        "cache.size",
        "disk.limit",
        "peer",
        "discovery",
        "max-peers",
        "head.confirm",
        "head.max-age",
        "beacon.url-file",
    ];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Wherever a URL with a key is given, the key reaches no clap error, `ConfigError`
        /// (`Display` or `Debug`), log line, or `Debug` of `LiteArgs`, `LiteConfig` and
        /// `FollowConfig`.
        #[test]
        fn a_url_secret_never_reaches_errors_logs_or_debug_output(
            (url, marker) in secret_url(),
            place in 0..7usize,
            flag in prop::sample::select(VALUE_FLAGS.to_vec()),
        ) {
            let beacon = "--beacon.url=https://a.example/k".to_owned();
            let (_dir, file_arg) = url_file(&format!("# beacons\n{url}\n"));
            let mut args = match place {
                0 => vec![format!("--beacon.url={url}")],
                1 => vec!["--beacon.url".to_owned(), url],
                2 => vec![beacon, format!("--finalized.url={url}")],
                3 => vec![beacon, format!("--finalized.url-file={url}")],
                // A second URL after one --beacon.url is a stray positional.
                4 => vec!["--beacon.url".to_owned(), "https://a.example/k".to_owned(), url],
                5 => vec![beacon, format!("--{flag}={url}")],
                _ => vec![file_arg],
            };
            args.push("--head.confirm=none".to_owned());
            let logs = capture();
            let mut seen = Vec::new();
            match LiteArgs::try_parse_redacted(std::iter::once("reth-lite".to_owned()).chain(args)) {
                Err(err) => seen.push(err.to_string()),
                Ok(parsed) => {
                    seen.push(format!("{parsed:?}"));
                    match parsed.into_config() {
                        Err(err) => seen.push(format!("{err} {err:?}")),
                        Ok(cfg) => {
                            let follow = crate::beacon::FollowConfig::from(&cfg);
                            let trust = crate::beacon::trust_label(&follow);
                            seen.push(format!("{cfg:?} {follow:?} {trust}"));
                        }
                    }
                }
            }
            seen.push(logs.text());
            for text in &seen {
                prop_assert!(!text.contains(&marker), "{}", text);
            }
        }

        /// A URL file of any lines is parsed in order or refused, the refusal names a line that
        /// is neither blank nor a comment, and nothing from the file reaches the error or logs.
        #[test]
        fn a_url_file_of_any_lines_is_parsed_or_refused_without_echoing_it(
            lines in prop::collection::vec(
                // Weighted so that most files parse: a check that wrongly accepts a line then
                // shows up in the accepted URLs.
                prop_oneof![
                    2 => Just(String::new()),
                    1 => Just(" \t ".to_owned()),
                    2 => "[ -~]{0,12}".prop_map(|s| format!("#{s} SECRETfile")),
                    4 => secret_url().prop_map(|(url, marker)| url.replace(&marker, "SECRETfile")),
                    3 => "https://[a-z]{1,8}\\.example/[a-z0-9]{0,8}"
                        .prop_map(|s| format!("  {s}/SECRETfile ")),
                    1 => "[ -~]{0,16}".prop_map(|s| format!("{s}SECRETfile")),
                    1 => "\\PC{0,12}".prop_map(|s| format!("SECRETfile{s}")),
                ],
                1..5,
            ),
            crlf in any::<bool>(),
        ) {
            let text = lines.join(if crlf { "\r\n" } else { "\n" });
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("urls");
            std::fs::write(&path, &text).unwrap();
            let kept = |l: &str| !l.trim().is_empty() && !l.trim().starts_with('#');
            let logs = capture();
            let got = read_url_file(&path, "--beacon.url-file");
            prop_assert!(!logs.text().contains("SECRETfile"), "{}", logs.text());
            match got {
                Ok(urls) => {
                    prop_assert_eq!(urls.len(), lines.iter().filter(|l| kept(l)).count());
                    for u in &urls {
                        prop_assert!(u.fragment().is_none());
                        let loopback = u.host_str().is_some_and(|h| {
                            h == "localhost" || h == "[::1]" || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
                        });
                        prop_assert!(u.scheme() == "https" || loopback, "{}", u);
                    }
                }
                Err(err) => {
                    let shown = format!("{err} {err:?}");
                    prop_assert!(!shown.contains("SECRETfile"), "{}", shown);
                    match err {
                        ConfigError::BadUrl { flag, line } |
                        ConfigError::UrlFragment { flag, line } |
                        ConfigError::InsecureUrl { flag, line } => {
                            prop_assert_eq!(flag, "--beacon.url-file");
                            let l = line.unwrap();
                            prop_assert!(l >= 1 && kept(&lines[l - 1]), "line {}", l);
                        }
                        ConfigError::EmptyUrlFile { .. } => {
                            prop_assert!(!lines.iter().any(|l| kept(l)));
                        }
                        other => prop_assert!(false, "unexpected {:?}", other),
                    }
                }
            }
        }

        /// Arbitrary bytes, valid UTF-8 or not, never panic the URL file reader.
        #[test]
        fn a_url_file_of_any_bytes_never_panics(
            bytes in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("urls");
            std::fs::write(&path, &bytes).unwrap();
            if let Err(err) = read_url_file(&path, "--beacon.url-file") {
                let utf8 = std::str::from_utf8(&bytes).is_ok();
                prop_assert_eq!(matches!(err, ConfigError::UrlFile { .. }), !utf8, "{}", err);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn warns_when_the_url_file_is_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, arg) = url_file("http://127.0.0.1:5052\n");
        let path = arg.trim_start_matches("--beacon.url-file=").to_owned();
        let set =
            |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

        let logs = capture();
        parse(&[&arg]).unwrap().into_config().unwrap();
        assert!(!logs.text().contains("readable"), "0600 must not warn: {}", logs.text());

        for mode in [0o640, 0o604, 0o644] {
            set(mode);
            let logs = capture();
            // Warns, does not refuse.
            parse(&[&arg]).unwrap().into_config().unwrap();
            let text = logs.text();
            assert!(text.contains("WARN") && text.contains("group- or world-readable"), "{text}");
            assert!(text.contains(&path), "{text}");
        }
    }

    #[test]
    fn plain_http_is_loopback_only_and_duplicates_are_refused() {
        let bad = |a: &[&str]| parse(a).unwrap().into_config().unwrap_err();
        let err = bad(&["--beacon.url=http://beacon.example/vk_secret"]);
        assert!(matches!(err, ConfigError::InsecureUrl { .. }), "{err}");
        assert!(!err.to_string().contains("vk_secret"));
        let err = bad(&["--beacon.url=https://a", "--finalized.url=http://checkpoint.example"]);
        assert!(matches!(err, ConfigError::InsecureUrl { .. }), "{err}");
        let err = bad(&["--beacon.url=http://localhost.:5052"]);
        assert!(
            matches!(err, ConfigError::InsecureUrl { flag: "--beacon.url", line: None }),
            "{err}"
        );
        for ok in
            ["http://127.0.0.1:5052", "http://localhost:5052", "http://[::1]:5052", "https://x"]
        {
            parse(&[&format!("--beacon.url={ok}")]).unwrap().into_config().unwrap();
        }
        let err =
            bad(&["--beacon.url=https://a/k", "--beacon.url=https://a/k", "--beacon.quorum=2"]);
        assert!(matches!(err, ConfigError::DuplicateUrl), "{err}");
    }

    #[test]
    fn plain_http_from_a_file_names_the_file_flag_and_line() {
        let (_d, arg) =
            url_file("# beacons\nhttps://one.example/k\nhttp://beacon.example/vk_secret\n");
        let err = parse(&[&arg]).unwrap().into_config().unwrap_err();
        assert_eq!(
            err.to_string(),
            "--beacon.url-file must use https unless the host is loopback (line 3 of the file)"
        );
        let (_d, arg) = url_file("\nhttp://checkpoint.example/vk_secret\n");
        let fin = arg.replace("--beacon.url-file=", "--finalized.url-file=");
        let err = parse(&["--beacon.url=https://a", &fin]).unwrap().into_config().unwrap_err();
        assert_eq!(
            err.to_string(),
            "--finalized.url-file must use https unless the host is loopback (line 2 of the file)"
        );
        let err =
            parse(&["--beacon.url=http://beacon.example"]).unwrap().into_config().unwrap_err();
        assert_eq!(err.to_string(), "--beacon.url must use https unless the host is loopback");
    }

    #[test]
    fn an_anchor_on_a_beacon_host_is_warned_about() {
        let logs = capture();
        parse(&["--beacon.url=https://same.example/k", "--finalized.url=https://same.example/"])
            .unwrap()
            .into_config()
            .unwrap();
        assert!(logs.text().contains("same host"), "{}", logs.text());
        let logs = capture();
        parse(&["--beacon.url=https://a.example/k", "--finalized.url=https://b.example/"])
            .unwrap()
            .into_config()
            .unwrap();
        assert!(!logs.text().contains("same host"));
    }

    #[test]
    fn a_quorum_that_is_not_a_majority_is_warned_about() {
        let urls = [
            "https://a.example/k",
            "https://b.example/k",
            "https://c.example/k",
            "https://d.example/k",
        ];
        let warned = |n: usize, quorum: &str| {
            let mut args: Vec<String> =
                urls[..n].iter().map(|u| format!("--beacon.url={u}")).collect();
            args.push(format!("--beacon.quorum={quorum}"));
            let logs = capture();
            parse(&args.iter().map(String::as_str).collect::<Vec<_>>())
                .unwrap()
                .into_config()
                .unwrap();
            logs.text().contains("is not a majority")
        };
        assert!(!warned(1, "1"));
        assert!(warned(2, "1"));
        assert!(!warned(2, "2"));
        assert!(warned(3, "1"));
        assert!(!warned(3, "2"));
        assert!(warned(4, "2"));
        assert!(!warned(4, "3"));
    }

    /// With `--head.verify=sync-committee` one verified update decides the head, so a quorum
    /// above 1 is refused, even above the number of URLs, and a quorum of 1 is not warned about.
    /// Quorum mode keeps the quorum.
    #[test]
    fn sync_committee_mode_refuses_a_beacon_quorum_above_one() {
        let (a, b) = ("--beacon.url=https://a.example/k", "--beacon.url=https://b.example/k");
        let sc = "--head.verify=sync-committee";
        let want =
            "--beacon.quorum above 1 is refused with --head.verify=sync-committee: the sync \
                    committee's signature decides the head there, so a quorum adds no check; \
                    leave --beacon.quorum out";
        let none = "--head.confirm=none";
        for quorum in ["--beacon.quorum=2", "--beacon.quorum=3"] {
            let err = parse(&[a, b, quorum, sc, none]).unwrap().into_config().unwrap_err();
            assert!(matches!(err, ConfigError::QuorumWithSyncCommittee), "{quorum}: {err}");
            assert_eq!(err.to_string(), want);
        }
        let logs = capture();
        let cfg = parse(&[a, b, "--beacon.quorum=1", sc, none]).unwrap().into_config().unwrap();
        assert_eq!(cfg.beacon_quorum, 1);
        assert!(!logs.text().contains("is not a majority"), "{}", logs.text());
        let cfg = parse(&[a, b, "--beacon.quorum=2"]).unwrap().into_config().unwrap();
        assert_eq!((cfg.beacon_quorum, cfg.head_verify), (2, HeadVerify::Quorum));
    }

    #[test]
    fn beacon_urls_on_one_host_do_not_count_twice() {
        let two = ["--beacon.url=https://one.example/k1", "--beacon.url=https://one.example/k2"];
        let err = parse(&[two[0], two[1], "--beacon.quorum=2"]).unwrap().into_config().unwrap_err();
        assert!(matches!(err, ConfigError::SharedBeaconHost), "{err}");
        assert!(!err.to_string().contains("k1"));
        // Quorum 1: allowed (a fallback), with a warning.
        let logs = capture();
        parse(&two).unwrap().into_config().unwrap();
        assert!(logs.text().contains("same host"), "{}", logs.text());
    }

    /// Beacon providers, each with ways to spell its one host.
    const PROVIDERS: [&[&str]; 5] = [
        &[
            "http://localhost:5052",
            "http://127.0.0.1:5052",
            "http://[::1]:5052",
            "http://127.0.0.2:5052",
        ],
        &["https://a.example", "https://A.example.", "https://a.EXAMPLE"],
        &["https://b.example", "https://b.example."],
        &["https://203.0.113.7", "https://[::ffff:203.0.113.7]"],
        &["https://c.example"],
    ];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// A quorum outside 1..=n is refused, a quorum above 1 is refused when one provider has
        /// two URLs (so an accepted quorum never counts a provider twice), and the start warns
        /// exactly when the quorum is not a majority or a provider has two URLs.
        #[test]
        fn a_quorum_counts_each_provider_once(
            picks in prop::collection::vec((0..PROVIDERS.len(), 0..4usize), 1..=5),
            quorum in prop::option::of(0..=6u32),
        ) {
            let mut args: Vec<String> = picks
                .iter()
                .enumerate()
                .map(|(i, &(p, s))| {
                    format!("--beacon.url={}/k{i}", PROVIDERS[p][s % PROVIDERS[p].len()])
                })
                .collect();
            args.extend(quorum.map(|q| format!("--beacon.quorum={q}")));
            let n = picks.len();
            let q = quorum.unwrap_or(1) as usize;
            let providers = picks.iter().map(|&(p, _)| p).collect::<std::collections::HashSet<_>>();
            let shared = providers.len() < n;
            let want = if q == 0 || q > n {
                Err("BadQuorum".to_owned())
            } else if shared && q > 1 {
                Err("SharedBeaconHost".to_owned())
            } else {
                Ok((n > 1 && 2 * q <= n, shared))
            };
            let logs = capture();
            let got = match parse(&args.iter().map(String::as_str).collect::<Vec<_>>())
                .unwrap()
                .into_config()
            {
                Ok(cfg) => {
                    prop_assert_eq!(cfg.beacon_urls.len(), n);
                    let text = logs.text();
                    Ok((text.contains("is not a majority"), text.contains("on the same host")))
                }
                Err(ConfigError::BadQuorum) => Err("BadQuorum".to_owned()),
                Err(ConfigError::SharedBeaconHost) => Err("SharedBeaconHost".to_owned()),
                Err(other) => Err(other.to_string()),
            };
            prop_assert_eq!(got, want, "{:?}", args);
        }
    }

    #[test]
    fn one_host_spelled_two_ways_is_one_host() {
        for (a, b) in [
            ("http://localhost:5052", "http://127.0.0.1:5052"),
            ("http://[::1]:5052", "http://127.0.0.2:5052"),
            ("https://one.example/k", "https://ONE.example./k"),
            // RFC 6761: every `*.localhost` name is loopback.
            ("https://a.localhost/k", "https://127.0.0.1/k"),
            ("https://a.localhost./k", "https://b.LOCALHOST/k"),
        ] {
            let args =
                [&format!("--beacon.url={a}"), &format!("--beacon.url={b}"), "--beacon.quorum=2"];
            let err = parse(&args).unwrap().into_config().unwrap_err();
            assert!(matches!(err, ConfigError::SharedBeaconHost), "{a} {b}: {err}");
            let logs = capture();
            parse(&[&format!("--beacon.url={a}"), &format!("--finalized.url={b}")])
                .unwrap()
                .into_config()
                .unwrap();
            assert!(logs.text().contains("same host as a beacon"), "{a} {b}: {}", logs.text());
        }
    }

    /// Some editors start a file with a byte-order mark. It is not part of the first line.
    #[test]
    fn a_url_file_may_start_with_a_byte_order_mark() {
        let path = Path::new("urls");
        let urls = parse_url_text("\u{feff}https://a.example/k\n", "--beacon.url-file", path);
        assert_eq!(urls.unwrap(), [Url::parse("https://a.example/k").unwrap()]);
        let text = "\u{feff}# keys\nhttps://a.example/k\n";
        let urls = parse_url_text(text, "--beacon.url-file", path);
        assert_eq!(urls.unwrap(), [Url::parse("https://a.example/k").unwrap()]);
    }

    /// A start that is refused logs no warning about the config: the operator fixes the refusal
    /// first, and a warning for a config that never runs sends them the wrong way.
    #[test]
    fn a_refused_config_logs_no_warnings_first() {
        let shared = ["--beacon.url=https://one.example/k1", "--beacon.url=https://one.example/k2"];
        let minority = ["--beacon.url=https://a.example/k", "--beacon.url=https://b.example/k"];
        for (args, warning) in [
            (&minority[..], "is not a majority"),
            (&shared[..], "on the same host"),
            (
                &["--beacon.url=https://a.example/k", "--head.max-age=20s", "--head.confirm=none"]
                    [..],
                "--head.max-age",
            ),
            (
                &["--beacon.url=https://a.example/k", "--finalized.url=https://a.example/"][..],
                "same host as a beacon",
            ),
            (
                &["--beacon.url=https://a.example/k", "--metrics.addr=0.0.0.0:9001"][..],
                "--metrics.addr",
            ),
        ] {
            let logs = capture();
            parse(args).unwrap().into_config().unwrap();
            assert!(logs.text().contains(warning), "{args:?}: {}", logs.text());
            let logs = capture();
            let refused = args.iter().copied().chain(["--disk.limit=1MB"]).collect::<Vec<_>>();
            let err = parse(&refused).unwrap().into_config().unwrap_err();
            assert!(matches!(err, ConfigError::SizeTooSmall { .. }), "{err}");
            assert!(!logs.text().contains("WARN"), "{refused:?}: {}", logs.text());
        }
    }
}
