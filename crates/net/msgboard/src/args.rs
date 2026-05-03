//! CLI arguments for the msgboard sub-protocol.

use std::{path::PathBuf, time::Duration};

use clap::Args;
use reth_msgboard_types::MsgboardConfig;

/// Default DB flush interval. Mirrors `CommitEvery = 15s` in
/// `private-erigon-pulse/msgboardcfg/config.go`.
const DEFAULT_COMMIT_EVERY: &str = "15s";

/// Default periodic stats-log cadence. Mirrors `LogEvery = 30s` in
/// `private-erigon-pulse/msgboardcfg/config.go`.
const DEFAULT_LOG_EVERY: &str = "30s";

/// CLI arguments for the `msg/1` board.
///
/// The msgboard module is registered unconditionally — there is no
/// `--msgboard.enabled` flag. These knobs only tune behavior.
#[derive(Debug, Clone, Args)]
#[command(next_help_heading = "Msgboard")]
pub struct MsgboardArgs {
    /// Minimum accepted `work_multiplier` value.
    #[arg(long = "msgboard.work-multiplier", default_value_t = 10_000)]
    pub msgboard_work_multiplier: u64,

    /// Maximum accepted `work_divisor` value.
    #[arg(long = "msgboard.work-divisor", default_value_t = 1_000_000)]
    pub msgboard_work_divisor: u64,

    /// Maximum allowed byte length of a single message's data field.
    #[arg(long = "msgboard.size-limit", default_value_t = 8192)]
    pub msgboard_size_limit: usize,

    /// Maximum number of messages retained in the board.
    #[arg(long = "msgboard.count-limit", default_value_t = 10_000)]
    pub msgboard_count_limit: usize,

    /// Number of blocks a message remains live before expiry.
    #[arg(long = "msgboard.block-range", default_value_t = 120)]
    pub msgboard_block_range: u64,

    /// Stale block buffer for peer filtering (avoid requesting nearly-expired messages).
    #[arg(long = "msgboard.stale-block-buffer", default_value_t = 3)]
    pub msgboard_stale_block_buffer: u64,

    /// Database directory for persistent message storage.
    /// Defaults to `<datadir>/msgboard`.
    #[arg(long = "msgboard.db-dir")]
    pub msgboard_db_dir: Option<PathBuf>,

    /// How often to flush in-memory messages to the on-disk MDBX env.
    ///
    /// Accepts humantime durations: `15s`, `2m`, `500ms`. Lower values bound
    /// in-flight loss on crash; higher values reduce write amplification.
    #[arg(
        long = "msgboard.commit-every",
        value_parser = humantime::parse_duration,
        default_value = DEFAULT_COMMIT_EVERY,
    )]
    pub msgboard_commit_every: Duration,

    /// How often to emit a periodic msgboard stats line at INFO level.
    ///
    /// Useful for log-scraped observability. Set to a very large duration to
    /// effectively disable.
    #[arg(
        long = "msgboard.log-every",
        value_parser = humantime::parse_duration,
        default_value = DEFAULT_LOG_EVERY,
    )]
    pub msgboard_log_every: Duration,

    /// Disable outbound P2P gossip of msgboard messages.
    ///
    /// When set, the node still **receives** announcements and full messages
    /// from peers and serves `GetBoardMessages` requests, but it does **not**
    /// announce its own message IDs (neither the bulk announce on peer connect
    /// nor per-message announces as new messages are accepted). Useful for
    /// read-only observability nodes.
    #[arg(long = "msgboard.gossip-disable", default_value_t = false)]
    pub msgboard_gossip_disable: bool,
}

impl Default for MsgboardArgs {
    fn default() -> Self {
        Self {
            msgboard_work_multiplier: 10_000,
            msgboard_work_divisor: 1_000_000,
            msgboard_size_limit: 8192,
            msgboard_count_limit: 10_000,
            msgboard_block_range: 120,
            msgboard_stale_block_buffer: 3,
            msgboard_db_dir: None,
            msgboard_commit_every: Duration::from_secs(15),
            msgboard_log_every: Duration::from_secs(30),
            msgboard_gossip_disable: false,
        }
    }
}

impl MsgboardArgs {
    /// Convert these CLI arguments into a [`MsgboardConfig`].
    pub fn into_config(self) -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: self.msgboard_work_multiplier,
            work_divisor: self.msgboard_work_divisor,
            size_limit: self.msgboard_size_limit,
            count_limit: self.msgboard_count_limit,
            block_range: self.msgboard_block_range,
            stale_block_buffer: self.msgboard_stale_block_buffer,
            gossip_disabled: self.msgboard_gossip_disable,
        }
    }
}
