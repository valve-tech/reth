//! Firehose ExEx health.json publisher (thatis freshness + loopback GET).
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use serde::Serialize;
use reth_tracing::tracing::{info, warn};

pub const HEALTH_LISTEN_ADDR: &str = "127.0.0.1:8754";

pub const HEALTH_HTTP_PATH: &str = "/health.json";

pub const HEALTH_REL_PATH: &str = "firehose/health.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthStatus {
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub replica: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merged_block_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merged_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_block_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_height: Option<u64>,
    pub exex_alive: bool,
}

impl HealthStatus {
    pub fn alive_starting(chain_id: u64, replica: impl Into<String>) -> Self {
        Self {
            chain_id,
            replica: replica.into(),
            merged_block_time: None,
            merged_height: None,
            one_block_time: None,
            one_height: None,
            exex_alive: true,
        }
    }

    pub fn alive_at_block(
        chain_id: u64,
        replica: impl Into<String>,
        height: u64,
        block_time_unix: u64,
    ) -> Self {
        Self {
            chain_id,
            replica: replica.into(),
            merged_block_time: None,
            merged_height: None,
            one_block_time: Some(block_time_unix),
            one_height: Some(height),
            exex_alive: true,
        }
    }

    pub fn dead(chain_id: u64, replica: impl Into<String>) -> Self {
        Self {
            chain_id,
            replica: replica.into(),
            merged_block_time: None,
            merged_height: None,
            one_block_time: None,
            one_height: None,
            exex_alive: false,
        }
    }

    pub fn to_json(&self) -> eyre::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Parse replica letter from a valve host name.
///
/// Accepts `direct-b-evm-369`, `direct-a-evm-1.internal`, `evm943b`, `evm1b`.
pub fn replica_from_host(host: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let name = host.split('.').next().unwrap_or(&host);

    if let Some(rest) = name.strip_prefix("direct-") {
        let letter = rest.chars().next()?;
        if letter == 'a' || letter == 'b' {
            return Some(letter.to_string());
        }
    }

    if let Some(rest) = name.strip_prefix("evm") {
        let letter = rest.chars().last()?;
        if (letter == 'a' || letter == 'b')
            && rest.chars().rev().nth(1).is_some_and(|c| c.is_ascii_digit())
        {
            return Some(letter.to_string());
        }
    }

    None
}

fn current_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("VALVE_HOST").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

/// Testable replica resolution: env lookup + optional hostname, no process globals.
///
/// Order: `VALVE_REPLICA`, `FIREHOSE_REPLICA`, hostname (`direct-{a|b}-evm-*` /
/// `evm*{a|b}`), then `"a"`. Empty/whitespace values fall through to the next source.
pub fn resolve_replica_from(
    mut env_get: impl FnMut(&str) -> Option<String>,
    hostname: Option<&str>,
) -> String {
    for key in ["VALVE_REPLICA", "FIREHOSE_REPLICA"] {
        if let Some(v) = env_get(key) {
            let v = v.trim().to_ascii_lowercase();
            if !v.is_empty() {
                return v;
            }
        }
    }
    if let Some(host) = hostname {
        if let Some(from_host) = replica_from_host(host) {
            return from_host;
        }
    }
    "a".to_string()
}

/// Replica stamp for health.json.
///
/// Order: `VALVE_REPLICA`, `FIREHOSE_REPLICA`, hostname (`direct-{a|b}-evm-*` /
/// `evm*{a|b}`), then `"a"`.
pub fn resolve_replica() -> String {
    resolve_replica_from(|k| std::env::var(k).ok(), current_hostname().as_deref())
}

pub fn default_health_path(datadir: impl AsRef<Path>) -> PathBuf {
    datadir.as_ref().join(HEALTH_REL_PATH)
}

pub fn write_health_json(path: &Path, status: &HealthStatus) -> eyre::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = status.to_json()?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug)]
pub struct HealthPublisher {
    path: PathBuf,
    chain_id: u64,
    replica: String,
    last: HealthStatus,
}

impl HealthPublisher {
    pub fn start(datadir: impl AsRef<Path>, chain_id: u64, replica: impl Into<String>) -> eyre::Result<Self> {
        Self::start_inner(datadir, chain_id, replica, true)
    }

    /// Like [`Self::start`] but skips the loopback HTTP listener.
    ///
    /// Prefer this in unit tests to avoid binding [`HEALTH_LISTEN_ADDR`].
    pub fn start_without_http(
        datadir: impl AsRef<Path>,
        chain_id: u64,
        replica: impl Into<String>,
    ) -> eyre::Result<Self> {
        Self::start_inner(datadir, chain_id, replica, false)
    }

    fn start_inner(
        datadir: impl AsRef<Path>,
        chain_id: u64,
        replica: impl Into<String>,
        spawn_http: bool,
    ) -> eyre::Result<Self> {
        let replica = replica.into();
        let path = default_health_path(datadir);
        let status = HealthStatus::alive_starting(chain_id, replica.clone());
        write_health_json(&path, &status)?;
        info!(
            target: "firehose::health",
            path = %path.display(),
            chain_id,
            replica = %replica,
            listen = HEALTH_LISTEN_ADDR,
            spawn_http,
            "Wrote initial firehose health.json (exex_alive=true, timestamps omitted)"
        );

        if spawn_http {
            spawn_loopback_server(path.clone());
        }

        Ok(Self {
            path,
            chain_id,
            replica,
            last: status,
        })
    }

    pub fn record_finished_height(&mut self, height: u64, block_time_unix: u64) -> eyre::Result<()> {
        let status = HealthStatus::alive_at_block(
            self.chain_id,
            self.replica.clone(),
            height,
            block_time_unix,
        );
        write_health_json(&self.path, &status)?;
        self.last = status;
        Ok(())
    }

    pub fn mark_dead(&mut self) -> eyre::Result<()> {
        let status = HealthStatus::dead(self.chain_id, self.replica.clone());
        write_health_json(&self.path, &status)?;
        self.last = status;
        info!(
            target: "firehose::health",
            path = %self.path.display(),
            "Wrote firehose health.json (exex_alive=false)"
        );
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HealthPublisher {
    fn drop(&mut self) {
        if self.last.exex_alive {
            if let Err(err) = self.mark_dead() {
                warn!(
                    target: "firehose::health",
                    error = %err,
                    "Failed to write dead health.json on Drop"
                );
            }
        }
    }
}

fn spawn_loopback_server(path: PathBuf) {
    thread::Builder::new()
        .name("firehose-health-http".into())
        .spawn(move || {
            let addr: SocketAddr = match HEALTH_LISTEN_ADDR.parse() {
                Ok(a) => a,
                Err(err) => {
                    warn!(target: "firehose::health", error = %err, "Invalid health listen addr");
                    return;
                }
            };
            let listener = match TcpListener::bind(addr) {
                Ok(l) => l,
                Err(err) => {
                    warn!(
                        target: "firehose::health",
                        error = %err,
                        %addr,
                        "Failed to bind firehose health loopback listener — file publisher still active"
                    );
                    return;
                }
            };
            let _ = listener.set_nonblocking(false);
            info!(
                target: "firehose::health",
                %addr,
                path = HEALTH_HTTP_PATH,
                file = %path.display(),
                "Serving firehose health.json on loopback (file-backed, not public RPC)"
            );
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        let path = path.clone();
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        if let Err(err) = handle_health_http(stream, &path) {
                            warn!(target: "firehose::health", error = %err, "health HTTP request failed");
                        }
                    }
                    Err(err) => {
                        warn!(target: "firehose::health", error = %err, "health HTTP accept failed");
                    }
                }
            }
        })
        .expect("failed to spawn firehose health HTTP thread");
}

fn handle_health_http(mut stream: impl Read + Write, path: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let path_only = target.split('?').next().unwrap_or(target);

    if method != "GET" || path_only != HEALTH_HTTP_PATH {
        write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        return Ok(());
    }

    match fs::read(path) {
        Ok(body) => write_http_response(&mut stream, 200, "application/json", &body)?,
        Err(_) => write_http_response(
            &mut stream,
            503,
            "application/json",
            br#"{"exex_alive":false}"#,
        )?,
    }
    Ok(())
}

fn write_http_response(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
