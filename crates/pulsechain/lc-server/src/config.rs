//! The command line. A URL may hold a provider key, so no error echoes one.

use alloy_primitives::B256;
use clap::{error::ErrorKind, Parser};
use reth_pulsechain_forks::network::pulsechain_network;
use reth_pulsechain_light_client::checkpoint::{Checkpoint, REFRESH_HINT};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use url::Url;

/// The public Checkpointz server of `PulseChain` 369.
pub const CHECKPOINTZ_369: &str = "https://checkpoint.pulsechain.com";

/// The built-in state URL of `chain_id`. 943 has none: Checkpointz serves 369 only.
pub const fn default_state_url(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        369 => Some(CHECKPOINTZ_369),
        _ => None,
    }
}

/// The `reth-pulsechain-lc-server` command line.
#[derive(Debug, Parser)]
#[command(
    name = "reth-pulsechain-lc-server",
    about = "Serves the beacon light-client API for one PulseChain network",
    version
)]
pub struct Args {
    /// Chain id: 369 or 943. One process serves one chain.
    #[arg(long = "chain", value_parser = parse_chain, default_value = "369")]
    pub chain: u64,
    /// A beacon node URL, repeatable; the first good answer wins. It gives the blocks and the
    /// heads. May hold a key. Plain http only for a loopback host.
    #[arg(long = "beacon.url", required_unless_present = "beacon_url_file")]
    pub beacon_url: Vec<String>,
    /// A file with one beacon URL per line; blank lines and lines that start with `#` are
    /// ignored. Keeps a key out of the command line.
    #[arg(long = "beacon.url-file", conflicts_with = "beacon_url")]
    pub beacon_url_file: Option<PathBuf>,
    /// The URL that gives the finalized states: a Checkpointz server or a beacon node with the
    /// debug API. Default on 369: `https://checkpoint.pulsechain.com`. Required on 943.
    #[arg(long = "state.url")]
    pub state_url: Option<String>,
    /// Trusted finalized beacon block root (`0x` hex) that the self-check store bootstraps
    /// from. Default: the root pinned for the chain. 943 has no pin, so there it is required.
    ///
    /// A usable saved store wins over both: delete `<datadir>/<chain_id>/sync-committee.ssz` to
    /// start again at this root. The server refuses a root whose block is more than 30 days
    /// old. It builds the bootstrap from the state URL's state at the root, so the root must be
    /// recent enough for the state URL to keep its state.
    ///
    /// A store at a root knows only the committee of the root's sync-committee period, and no
    /// upstream gives a past period's update. So a root, and so the pin, starts a new datadir
    /// only while the wall clock is in the root's period, at most about 23 hours, or in the
    /// first 4 epochs after it. After that the start stops and names the periods.
    #[arg(long = "checkpoint", value_name = "ROOT")]
    pub checkpoint: Option<B256>,
    /// The data directory. Each chain keeps its files in `<datadir>/<chain_id>/`.
    #[arg(long = "datadir", default_value = "lc-server-data")]
    pub datadir: PathBuf,
    /// The address of the HTTP API.
    #[arg(long = "http.addr", default_value = "127.0.0.1:9596")]
    pub http_addr: SocketAddr,
    /// The address of the Prometheus `/metrics` endpoint. Off when not given.
    #[arg(long = "metrics.addr")]
    pub metrics_addr: Option<SocketAddr>,
}

/// The resolved command line.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// The chain id.
    pub chain: u64,
    /// The beacon URLs, in order.
    pub beacon_urls: Vec<Url>,
    /// The state URL.
    pub state_url: Url,
    /// The trust root of the self-check store: `--checkpoint`, else the chain's pin.
    pub checkpoint: Checkpoint,
    /// The data directory.
    pub datadir: PathBuf,
    /// The address of the HTTP API.
    pub http_addr: SocketAddr,
    /// The address of the metrics endpoint.
    pub metrics_addr: Option<SocketAddr>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URLs may hold keys: show their host labels only.
        let beacons: Vec<String> =
            self.beacon_urls.iter().map(crate::upstream::host_label).collect();
        f.debug_struct("Config")
            .field("chain", &self.chain)
            .field("beacon_urls", &beacons)
            .field("state_url", &crate::upstream::host_label(&self.state_url))
            .field("checkpoint", &self.checkpoint)
            .field("datadir", &self.datadir)
            .field("http_addr", &self.http_addr)
            .field("metrics_addr", &self.metrics_addr)
            .finish()
    }
}

/// Why the command line does not resolve. No variant holds a URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A URL does not parse, or is not http(s) with a host.
    #[error("{flag}{}: not an http(s) URL with a host", line_suffix(*.line))]
    BadUrl {
        /// The flag.
        flag: &'static str,
        /// The 1-based line of a URL file.
        line: Option<usize>,
    },
    /// A URL to a host that is not loopback is plain http.
    #[error("{flag}{}: plain http is allowed for a loopback host only", line_suffix(*.line))]
    InsecureUrl {
        /// The flag.
        flag: &'static str,
        /// The 1-based line of a URL file.
        line: Option<usize>,
    },
    /// A URL has a fragment, which no request carries.
    #[error("{flag}{}: a URL fragment is never sent; put a key in the path or query", line_suffix(*.line))]
    UrlFragment {
        /// The flag.
        flag: &'static str,
        /// The 1-based line of a URL file.
        line: Option<usize>,
    },
    /// A URL file was not read.
    #[error("{flag} {path}: {reason}")]
    UrlFile {
        /// The flag.
        flag: &'static str,
        /// The file's path.
        path: String,
        /// Why it was not read.
        reason: String,
    },
    /// A URL file holds no URL.
    #[error("{flag} {path}: no URL in the file")]
    EmptyUrlFile {
        /// The flag.
        flag: &'static str,
        /// The file's path.
        path: String,
    },
    /// One beacon URL is given twice.
    #[error("a beacon URL is given twice")]
    DuplicateUrl,
    /// The chain has no built-in state URL.
    #[error("--chain={chain} has no built-in state URL: give --state.url")]
    NoStateUrl {
        /// The chain id.
        chain: u64,
    },
    /// The chain has no pinned checkpoint and no `--checkpoint` is given.
    #[error(
        "--chain={chain} has no pinned checkpoint, and the self-check store needs a trusted \
         root: give --checkpoint=<root> with a recent finalized block root you trust \
         ({REFRESH_HINT})"
    )]
    NoCheckpoint {
        /// The chain id.
        chain: u64,
    },
}

fn line_suffix(line: Option<usize>) -> String {
    line.map(|line| format!(" line {line}")).unwrap_or_default()
}

fn parse_chain(s: &str) -> Result<u64, String> {
    let id: u64 = s.parse().map_err(|_| format!("bad --chain `{s}` (369 or 943)"))?;
    pulsechain_network(id)
        .map(|network| network.chain_id)
        .ok_or_else(|| format!("unsupported --chain {id} (369 or 943)"))
}

/// Parses an http(s) URL with a host and no fragment; plain http only for a loopback host.
fn parse_url(s: &str, flag: &'static str, line: Option<usize>) -> Result<Url, ConfigError> {
    let url = Url::parse(s).map_err(|_| ConfigError::BadUrl { flag, line })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::BadUrl { flag, line })
    }
    if url.fragment().is_some() {
        return Err(ConfigError::UrlFragment { flag, line })
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.scheme() != "https" && !loopback {
        return Err(ConfigError::InsecureUrl { flag, line })
    }
    Ok(url)
}

/// Reads the URLs of `path`, one per line. Blank lines and `#` lines are skipped.
fn read_url_file(path: &Path, flag: &'static str) -> Result<Vec<Url>, ConfigError> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|err| ConfigError::UrlFile {
        flag,
        path: shown.clone(),
        reason: err.to_string(),
    })?;
    let urls = text
        .lines()
        .enumerate()
        .map(|(i, line)| (i, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(i, line)| parse_url(line, flag, Some(i + 1)))
        .collect::<Result<Vec<_>, _>>()?;
    if urls.is_empty() {
        return Err(ConfigError::EmptyUrlFile { flag, path: shown })
    }
    Ok(urls)
}

impl Args {
    /// Parses `args` as [`Parser::try_parse_from`] does, but an error that would echo a URL
    /// names the problem only.
    pub fn try_parse_redacted<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(args).map_err(|err| {
            if err.use_stderr() && err.to_string().contains("://") {
                let what = match err.kind() {
                    ErrorKind::InvalidValue | ErrorKind::ValueValidation => "invalid value",
                    kind => kind.as_str().unwrap_or("invalid arguments"),
                };
                clap::Error::raw(
                    err.kind(),
                    format!(
                        "{what}: a value that may hold a URL or key is not echoed; see --help\n"
                    ),
                )
            } else {
                err
            }
        })
    }

    /// Resolves the flags.
    pub fn into_config(self) -> Result<Config, ConfigError> {
        let beacon_urls = match &self.beacon_url_file {
            Some(path) => read_url_file(path, "--beacon.url-file")?,
            None => self
                .beacon_url
                .iter()
                .map(|s| parse_url(s, "--beacon.url", None))
                .collect::<Result<Vec<_>, _>>()?,
        };
        if beacon_urls.iter().enumerate().any(|(i, url)| beacon_urls[..i].contains(url)) {
            return Err(ConfigError::DuplicateUrl)
        }
        let state_url = match (&self.state_url, default_state_url(self.chain)) {
            (Some(url), _) => parse_url(url, "--state.url", None)?,
            (None, Some(url)) => parse_url(url, "--state.url", None)?,
            (None, None) => return Err(ConfigError::NoStateUrl { chain: self.chain }),
        };
        let pin = pulsechain_network(self.chain).and_then(|network| network.checkpoint);
        let checkpoint = match (self.checkpoint, pin) {
            (Some(root), _) => Checkpoint::Flag(root),
            (None, Some(pin)) => Checkpoint::Pinned(pin),
            (None, None) => return Err(ConfigError::NoCheckpoint { chain: self.chain }),
        };
        Ok(Config {
            chain: self.chain,
            beacon_urls,
            state_url,
            checkpoint,
            datadir: self.datadir,
            http_addr: self.http_addr,
            metrics_addr: self.metrics_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, String> {
        let args = std::iter::once("reth-pulsechain-lc-server").chain(args.iter().copied());
        Args::try_parse_redacted(args)
            .map_err(|err| err.to_string())?
            .into_config()
            .map_err(|err| err.to_string())
    }

    /// Every flag, and the defaults on 369.
    #[test]
    fn every_flag_parses() {
        let cfg = parse(&["--beacon.url", "https://a.example/key"]).unwrap();
        assert_eq!(cfg.chain, 369);
        assert_eq!(cfg.state_url.as_str(), "https://checkpoint.pulsechain.com/");
        assert_eq!(cfg.datadir, PathBuf::from("lc-server-data"));
        assert_eq!(cfg.http_addr, "127.0.0.1:9596".parse().unwrap());
        assert_eq!(cfg.metrics_addr, None);
        let pin = pulsechain_network(369).unwrap().checkpoint.unwrap();
        assert_eq!(cfg.checkpoint, Checkpoint::Pinned(pin));

        let root = B256::repeat_byte(0xab);
        let cfg = parse(&[
            "--chain",
            "943",
            "--checkpoint",
            &root.to_string(),
            "--beacon.url",
            "https://a.example/key",
            "--beacon.url",
            "http://127.0.0.1:5052",
            "--state.url",
            "https://state.example",
            "--datadir",
            "/var/lib/lc",
            "--http.addr",
            "0.0.0.0:9000",
            "--metrics.addr",
            "127.0.0.1:9001",
        ])
        .unwrap();
        assert_eq!(cfg.chain, 943);
        assert_eq!(cfg.beacon_urls.len(), 2);
        assert_eq!(cfg.state_url.as_str(), "https://state.example/");
        assert_eq!(cfg.datadir, PathBuf::from("/var/lib/lc"));
        assert_eq!(cfg.http_addr, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(cfg.metrics_addr, Some("127.0.0.1:9001".parse().unwrap()));
        assert_eq!(cfg.checkpoint, Checkpoint::Flag(root));
    }

    /// A chain with no pin does not start without `--checkpoint`, and the error says how to get
    /// a root. The flag wins over a pin.
    #[test]
    fn a_chain_with_no_pin_needs_a_checkpoint() {
        let err = parse(&[
            "--chain",
            "943",
            "--beacon.url",
            "https://a.example",
            "--state.url",
            "https://s.example",
        ])
        .unwrap_err();
        assert_eq!(
            err,
            "--chain=943 has no pinned checkpoint, and the self-check store needs a trusted root: \
             give --checkpoint=<root> with a recent finalized block root you trust \
             (crates/pulsechain/lite/scripts/checkpoint-root.sh <beacon-url> <check-url> in the \
             reth source prints a recent finalized root and checks it against a second source)"
        );
        let root = B256::repeat_byte(7);
        let flag = format!("--checkpoint={root}");
        let cfg = parse(&["--beacon.url", "https://a.example", &flag]).unwrap();
        assert_eq!(cfg.checkpoint, Checkpoint::Flag(root));
        assert!(parse(&["--beacon.url", "https://a.example", "--checkpoint=0x12"]).is_err());
    }

    #[test]
    fn testnet_943_needs_a_state_url() {
        assert_eq!(
            parse(&["--chain", "943", "--beacon.url", "https://a.example"]).unwrap_err(),
            "--chain=943 has no built-in state URL: give --state.url"
        );
    }

    #[test]
    fn an_unknown_chain_is_refused() {
        let err = parse(&["--chain", "1", "--beacon.url", "https://a.example"]).unwrap_err();
        assert!(err.contains("unsupported --chain 1 (369 or 943)"), "{err}");
    }

    #[test]
    fn the_beacon_urls_come_from_one_flag() {
        let err = parse(&[]).unwrap_err();
        assert!(err.contains("--beacon.url <BEACON_URL>"), "{err}");
        let err =
            parse(&["--beacon.url", "https://a.example", "--beacon.url-file", "urls"]).unwrap_err();
        assert!(err.contains("cannot be used with"), "{err}");
        assert_eq!(
            parse(&["--beacon.url", "https://a.example", "--beacon.url", "https://a.example"])
                .unwrap_err(),
            "a beacon URL is given twice"
        );
    }

    #[test]
    fn a_url_file_gives_the_beacon_urls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("urls");
        std::fs::write(&path, "# a comment\n\nhttps://a.example/key\n  http://localhost:5052  \n")
            .unwrap();
        let cfg = parse(&["--beacon.url-file", path.to_str().unwrap()]).unwrap();
        let urls: Vec<&str> = cfg.beacon_urls.iter().map(Url::as_str).collect();
        assert_eq!(urls, ["https://a.example/key", "http://localhost:5052/"]);

        std::fs::write(&path, "# only a comment\n").unwrap();
        let err = parse(&["--beacon.url-file", path.to_str().unwrap()]).unwrap_err();
        assert!(err.ends_with("no URL in the file"), "{err}");
        std::fs::write(&path, "https://a.example\nhttp://remote.example/key\n").unwrap();
        assert_eq!(
            parse(&["--beacon.url-file", path.to_str().unwrap()]).unwrap_err(),
            "--beacon.url-file line 2: plain http is allowed for a loopback host only"
        );
        let missing = dir.path().join("missing");
        let err = parse(&["--beacon.url-file", missing.to_str().unwrap()]).unwrap_err();
        assert!(err.starts_with("--beacon.url-file "), "{err}");
    }

    /// No error echoes a URL: it may hold a key.
    #[test]
    fn bad_urls_are_refused_without_echo() {
        for (url, want) in [
            (
                "http://remote.example/secret",
                "--beacon.url: plain http is allowed for a loopback host only",
            ),
            ("ftp://a.example/secret", "--beacon.url: not an http(s) URL with a host"),
            ("not a url secret", "--beacon.url: not an http(s) URL with a host"),
            (
                "https://a.example/#secret",
                "--beacon.url: a URL fragment is never sent; put a key in the path or query",
            ),
        ] {
            let err = parse(&["--beacon.url", url]).unwrap_err();
            assert_eq!(err, want);
            assert!(!err.contains("secret"));
        }
        let err =
            parse(&["--beacon.url", "https://a.example", "--state.url", "http://b.example/secret"])
                .unwrap_err();
        assert_eq!(err, "--state.url: plain http is allowed for a loopback host only");
        let err = parse(&["--beacon.url", "https://a.example", "https://stray.example/secret"])
            .unwrap_err();
        assert!(!err.contains("secret"), "{err}");
        assert!(err.contains("is not echoed"), "{err}");
    }

    #[test]
    fn the_debug_form_hides_the_keys() {
        let cfg = parse(&["--beacon.url", "https://a.b.example/secret"]).unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("https://*.b.example"), "{shown}");
    }
}
