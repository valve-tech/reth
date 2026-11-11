//! Valve's Firehose health heartbeat.
//!
//! An ExEx ([`run_exex`]) writes `health.json` for each committed block and serves it on a
//! loopback port, for the thatis freshness probes. It is valve infrastructure, not part of
//! `StreamingFast`'s Firehose, so it lives outside `reth-firehose`.

mod health;
mod runner;

pub use health::{
    default_health_path, resolve_replica, resolve_replica_from, write_health_json, HealthPublisher,
    HealthStatus, HEALTH_HTTP_PATH, HEALTH_LISTEN_ADDR, HEALTH_REL_PATH,
};
pub use runner::run_exex;
