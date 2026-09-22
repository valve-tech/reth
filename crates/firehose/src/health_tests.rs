use super::*;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{SystemTime, UNIX_EPOCH},
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "firehose-health-{label}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_health_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn env_map(pairs: &[(&str, Option<&str>)]) -> impl FnMut(&str) -> Option<String> {
    let map: HashMap<String, Option<String>> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.map(|s| s.to_string())))
        .collect();
    move |key: &str| map.get(key).cloned().flatten()
}

/// Run `handle_health_http` over an ephemeral loopback socket (never binds :8754).
fn http_exchange(path: &Path, request: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let path = path.to_path_buf();
    let join = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_health_http(stream, &path)
    });
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).unwrap();
    join.join().unwrap().unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

fn http_status_line(resp: &str) -> &str {
    resp.lines().next().unwrap_or("")
}

#[test]
fn alive_starting_omits_timestamps() {
    let s = HealthStatus::alive_starting(369, "a");
    let json = s.to_json().unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["chainId"], 369);
    assert_eq!(v["replica"], "a");
    assert_eq!(v["exex_alive"], true);
    assert!(v.get("one_block_time").is_none());
    assert!(v.get("one_height").is_none());
    assert!(v.get("merged_block_time").is_none());
    assert!(v.get("merged_height").is_none());
    assert!(v.get("chain_id").is_none());
    assert!(v.get("exexAlive").is_none());
    assert!(v.get("oneBlockTime").is_none());
}

#[test]
fn dead_omits_timestamps() {
    let s = HealthStatus::dead(369, "b");
    let json = s.to_json().unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["chainId"], 369);
    assert_eq!(v["replica"], "b");
    assert_eq!(v["exex_alive"], false);
    assert!(v.get("one_block_time").is_none());
    assert!(v.get("one_height").is_none());
    assert!(v.get("merged_block_time").is_none());
    assert!(v.get("merged_height").is_none());
}

#[test]
fn alive_at_block_includes_one_fields_not_merged() {
    let s = HealthStatus::alive_at_block(369, "a", 12_345_678, 1_694_534_400);
    let json = s.to_json().unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["chainId"], 369);
    assert_eq!(v["replica"], "a");
    assert_eq!(v["exex_alive"], true);
    assert_eq!(v["one_height"], 12_345_678);
    assert_eq!(v["one_block_time"], 1_694_534_400);
    assert!(v.get("merged_block_time").is_none(), "merged_* must not be invented");
    assert!(v.get("merged_height").is_none());
}

#[test]
fn atomic_write_roundtrip() {
    let dir = unique_temp_dir("atomic");
    let path = default_health_path(&dir);
    let status = HealthStatus::alive_at_block(369, "a", 42, 100);
    write_health_json(&path, &status).unwrap();
    let read = read_health_json(&path);
    assert_eq!(read["one_height"], 42);
    assert_eq!(read["exex_alive"], true);
    assert!(!path.with_extension("json.tmp").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn replica_from_host_direct_and_evm_names() {
    assert_eq!(replica_from_host("direct-b-evm-369").as_deref(), Some("b"));
    assert_eq!(replica_from_host("direct-a-evm-1").as_deref(), Some("a"));
    assert_eq!(replica_from_host("direct-b-evm-11155111.internal").as_deref(), Some("b"));
    assert_eq!(replica_from_host("evm943b").as_deref(), Some("b"));
    assert_eq!(replica_from_host("evm1b").as_deref(), Some("b"));
    assert_eq!(replica_from_host("evm369a").as_deref(), Some("a"));
    assert_eq!(replica_from_host("localhost"), None);
    assert_eq!(replica_from_host("evma"), None);
}

#[test]
fn resolve_replica_returns_nonempty() {
    let r = resolve_replica();
    assert!(!r.is_empty());
}

#[test]
fn resolve_replica_valve_wins_over_firehose() {
    let got = resolve_replica_from(
        env_map(&[("VALVE_REPLICA", Some("b")), ("FIREHOSE_REPLICA", Some("a"))]),
        Some("direct-a-evm-369"),
    );
    assert_eq!(got, "b");
}

#[test]
fn resolve_replica_firehose_when_valve_unset() {
    let got = resolve_replica_from(
        env_map(&[("VALVE_REPLICA", None), ("FIREHOSE_REPLICA", Some("b"))]),
        Some("direct-a-evm-369"),
    );
    assert_eq!(got, "b");
}

#[test]
fn resolve_replica_empty_and_whitespace_fall_through() {
    // Empty VALVE falls through to FIREHOSE.
    let got = resolve_replica_from(
        env_map(&[("VALVE_REPLICA", Some("")), ("FIREHOSE_REPLICA", Some("b"))]),
        Some("direct-a-evm-369"),
    );
    assert_eq!(got, "b");

    // Whitespace-only values fall through to hostname.
    let got = resolve_replica_from(
        env_map(&[("VALVE_REPLICA", Some("  \t")), ("FIREHOSE_REPLICA", Some("   "))]),
        Some("direct-b-evm-369"),
    );
    assert_eq!(got, "b");

    // Both empty + unparseable host → default "a".
    let got = resolve_replica_from(
        env_map(&[("VALVE_REPLICA", Some("")), ("FIREHOSE_REPLICA", Some(""))]),
        Some("localhost"),
    );
    assert_eq!(got, "a");
}

#[test]
fn resolve_replica_hostname_when_env_unset() {
    let got = resolve_replica_from(env_map(&[]), Some("direct-b-evm-369"));
    assert_eq!(got, "b");

    let got = resolve_replica_from(env_map(&[]), Some("evm369b"));
    assert_eq!(got, "b");

    // VALVE_HOST / HOSTNAME-style FQDN (same replica_from_host path).
    let got = resolve_replica_from(env_map(&[]), Some("direct-b-evm-369.internal"));
    assert_eq!(got, "b");
}

#[test]
fn publisher_start_writes_alive_starting() {
    let dir = unique_temp_dir("pub-start");
    let pub_ = HealthPublisher::start_without_http(&dir, 369, "b").unwrap();
    let path = pub_.path().to_path_buf();
    assert!(path.ends_with(HEALTH_REL_PATH));
    let v = read_health_json(&path);
    assert_eq!(v["chainId"], 369);
    assert_eq!(v["replica"], "b");
    assert_eq!(v["exex_alive"], true);
    assert!(v.get("one_height").is_none());
    assert!(v.get("one_block_time").is_none());
    drop(pub_);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn publisher_record_finished_height_updates_one_fields() {
    let dir = unique_temp_dir("pub-height");
    let mut pub_ = HealthPublisher::start_without_http(&dir, 369, "a").unwrap();
    pub_.record_finished_height(12_345, 1_700_000_000).unwrap();
    let v = read_health_json(pub_.path());
    assert_eq!(v["exex_alive"], true);
    assert_eq!(v["one_height"], 12_345);
    assert_eq!(v["one_block_time"], 1_700_000_000);
    assert!(v.get("merged_height").is_none());
    drop(pub_);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn publisher_mark_dead_clears_timestamps() {
    let dir = unique_temp_dir("pub-dead");
    let mut pub_ = HealthPublisher::start_without_http(&dir, 369, "a").unwrap();
    pub_.record_finished_height(99, 123).unwrap();
    pub_.mark_dead().unwrap();
    let v = read_health_json(pub_.path());
    assert_eq!(v["exex_alive"], false);
    assert!(v.get("one_height").is_none());
    assert!(v.get("one_block_time").is_none());
    // Drop must not rewrite / panic after mark_dead.
    drop(pub_);
    let v2 = read_health_json(&default_health_path(&dir));
    assert_eq!(v2["exex_alive"], false);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn publisher_drop_writes_dead_when_still_alive() {
    let dir = unique_temp_dir("pub-drop");
    let path = {
        let pub_ = HealthPublisher::start_without_http(&dir, 369, "b").unwrap();
        pub_.path().to_path_buf()
    }; // drop here
    let v = read_health_json(&path);
    assert_eq!(v["replica"], "b");
    assert_eq!(v["exex_alive"], false);
    assert!(v.get("one_height").is_none());
    assert!(v.get("one_block_time").is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn http_get_health_json_returns_200_file_body() {
    let dir = unique_temp_dir("http-200");
    let path = default_health_path(&dir);
    let status = HealthStatus::alive_at_block(369, "a", 7, 100);
    write_health_json(&path, &status).unwrap();

    let resp = http_exchange(&path, "GET /health.json HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        http_status_line(&resp).starts_with("HTTP/1.1 200"),
        "status line: {}",
        http_status_line(&resp)
    );
    assert!(resp.contains("application/json"));
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(v["one_height"], 7);
    assert_eq!(v["exex_alive"], true);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn http_get_other_path_returns_404() {
    let dir = unique_temp_dir("http-404");
    let path = default_health_path(&dir);
    write_health_json(&path, &HealthStatus::alive_starting(369, "a")).unwrap();

    let resp = http_exchange(&path, "GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        http_status_line(&resp).starts_with("HTTP/1.1 404"),
        "status line: {}",
        http_status_line(&resp)
    );
    assert!(resp.contains("not found"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn http_missing_file_returns_503() {
    let dir = unique_temp_dir("http-503");
    // Point at a path that does not exist.
    let path = dir.join("firehose").join("missing-health.json");

    let resp = http_exchange(&path, "GET /health.json HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        http_status_line(&resp).starts_with("HTTP/1.1 503"),
        "status line: {}",
        http_status_line(&resp)
    );
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    assert_eq!(body, r#"{"exex_alive":false}"#);
    let _ = fs::remove_dir_all(&dir);
}
