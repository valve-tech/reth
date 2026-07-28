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
#[derive(Debug, Clone, PartialEq, Eq, Args)]
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Helper to parse a bare `Args` impl from an argv, mirroring the pattern in
    /// `reth-node-core`'s arg tests.
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    fn parse(argv: &[&str]) -> MsgboardArgs {
        CommandParser::<MsgboardArgs>::parse_from(argv).args
    }

    /// Every default is written twice — once as a clap `default_value_t` and
    /// once in the hand-rolled `Default` impl — with nothing forcing them to
    /// agree. Editing one and not the other means the value an operator gets
    /// depends on whether the args came from the CLI or from `Default`.
    #[test]
    fn default_impl_agrees_with_the_clap_defaults() {
        assert_eq!(parse(&["reth"]), MsgboardArgs::default());
    }

    /// The defaults are erigon-pulse's production values
    /// (`msgboardcfg/config.go`); a node running different limits than its peers
    /// silently accepts or rejects messages the rest of the network does not.
    /// Asserted as literals so this fails if the constants themselves move.
    #[test]
    fn defaults_match_erigon_pulse() {
        let args = parse(&["reth"]);
        assert_eq!(args.msgboard_work_multiplier, 10_000);
        assert_eq!(args.msgboard_work_divisor, 1_000_000);
        assert_eq!(args.msgboard_size_limit, 8192);
        assert_eq!(args.msgboard_count_limit, 10_000);
        assert_eq!(args.msgboard_block_range, 120);
        assert_eq!(args.msgboard_stale_block_buffer, 3);
        assert_eq!(args.msgboard_commit_every, Duration::from_secs(15), "erigon CommitEvery");
        assert_eq!(args.msgboard_log_every, Duration::from_secs(30), "erigon LogEvery");
        assert!(!args.msgboard_gossip_disable, "gossip is on by default");
        assert_eq!(args.msgboard_db_dir, None, "db dir defaults to <datadir>/msgboard");
    }

    /// Every value is distinct, so a transposed assignment in `into_config`
    /// cannot pass. The multiplier/divisor pair is the dangerous one: swapping
    /// them inverts the minimum-difficulty check rather than erroring.
    #[test]
    fn into_config_maps_every_field() {
        let args = MsgboardArgs {
            msgboard_work_multiplier: 11,
            msgboard_work_divisor: 22,
            msgboard_size_limit: 33,
            msgboard_count_limit: 44,
            msgboard_block_range: 55,
            msgboard_stale_block_buffer: 66,
            msgboard_db_dir: Some(PathBuf::from("/tmp/board")),
            msgboard_commit_every: Duration::from_secs(77),
            msgboard_log_every: Duration::from_secs(88),
            msgboard_gossip_disable: true,
        };

        let cfg = args.into_config();
        assert_eq!(cfg.work_multiplier, 11);
        assert_eq!(cfg.work_divisor, 22);
        assert_eq!(cfg.size_limit, 33);
        assert_eq!(cfg.count_limit, 44);
        assert_eq!(cfg.block_range, 55);
        assert_eq!(cfg.stale_block_buffer, 66);
        assert!(cfg.gossip_disabled);
    }

    /// Flag names are an operator-facing contract (`docs/msgboard-parity-gaps.md`
    /// §7): renaming one silently breaks existing systemd units and deploy
    /// configs, which fail closed at startup rather than falling back.
    #[test]
    fn every_documented_flag_name_parses() {
        let args = parse(&[
            "reth",
            "--msgboard.work-multiplier=1",
            "--msgboard.work-divisor=2",
            "--msgboard.size-limit=3",
            "--msgboard.count-limit=4",
            "--msgboard.block-range=5",
            "--msgboard.stale-block-buffer=6",
            "--msgboard.db-dir=/tmp/board",
            "--msgboard.commit-every=7s",
            "--msgboard.log-every=8s",
            "--msgboard.gossip-disable",
        ]);

        assert_eq!(args.msgboard_work_multiplier, 1);
        assert_eq!(args.msgboard_work_divisor, 2);
        assert_eq!(args.msgboard_size_limit, 3);
        assert_eq!(args.msgboard_count_limit, 4);
        assert_eq!(args.msgboard_block_range, 5);
        assert_eq!(args.msgboard_stale_block_buffer, 6);
        assert_eq!(args.msgboard_db_dir, Some(PathBuf::from("/tmp/board")));
        assert_eq!(args.msgboard_commit_every, Duration::from_secs(7));
        assert_eq!(args.msgboard_log_every, Duration::from_secs(8));
        assert!(args.msgboard_gossip_disable);
    }

    /// The two duration flags take humantime, not a bare seconds count — `2m`
    /// must mean two minutes, and a bare integer must be rejected outright
    /// rather than silently parsed as something else.
    #[test]
    fn duration_flags_parse_humantime_units() {
        let args = parse(&["reth", "--msgboard.commit-every=2m", "--msgboard.log-every=500ms"]);
        assert_eq!(args.msgboard_commit_every, Duration::from_secs(120));
        assert_eq!(args.msgboard_log_every, Duration::from_millis(500));

        assert!(
            CommandParser::<MsgboardArgs>::try_parse_from(["reth", "--msgboard.commit-every=15"])
                .is_err(),
            "a unitless duration should be rejected, not silently reinterpreted",
        );
    }
}
