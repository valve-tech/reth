use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

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
    let dir = std::env::temp_dir().join(format!(
        "firehose-health-test-{}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = default_health_path(&dir);
    let status = HealthStatus::alive_at_block(369, "a", 42, 100);
    write_health_json(&path, &status).unwrap();
    let read: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(read["one_height"], 42);
    assert_eq!(read["exex_alive"], true);
    assert!(!path.with_extension("json.tmp").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resolve_replica_returns_nonempty() {
    let r = resolve_replica();
    assert!(!r.is_empty());
}
