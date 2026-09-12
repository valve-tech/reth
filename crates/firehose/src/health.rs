//! Firehose ExEx health.json publisher (thatis freshness + loopback GET).
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
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

pub fn resolve_replica() -> String {
    std::env::var("VALVE_REPLICA")
        .or_else(|_| std::env::var("FIREHOSE_REPLICA"))
        .unwrap_or_else(|_| "a".to_string())
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
            "Wrote initial firehose health.json (exex_alive=true, timestamps omitted)"
        );

        spawn_loopback_server(path.clone());

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
            // Ensure accept can be interrupted eventually; we only serve until process exit.
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
                        // Brief timeout so a wedged client cannot pin the acceptor forever.
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

fn handle_health_http(mut stream: TcpStream, path: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // Strip query string if any.
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
    stream: &mut TcpStream,
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
