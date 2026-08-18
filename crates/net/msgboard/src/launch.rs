//! Launch-time wiring for the msgboard sub-protocol.
//!
//! [`MsgboardLauncher`] encapsulates the full lifecycle so the entrypoint
//! binary can stay close to upstream's stock shape: open the persistent DB,
//! build the in-memory board, install the JSON-RPC module + `msg/1` rlpx
//! handler, spawn periodic flush/log tasks, subscribe to canonical-state
//! notifications, and flush a final time on shutdown.
//!
//! The helper is node-agnostic — both [`PulsechainNode`] and `EthereumNode`
//! can drive it, so the same binary can serve PulseChain and Ethereum chain
//! IDs from one msgboard implementation.
//!
//! [`PulsechainNode`]: https://docs.rs/reth-pulsechain-node

use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use reth_chain_state::CanonStateSubscriptions;
use reth_msgboard_types::MsgboardConfig;
use reth_network::{protocol::IntoRlpxSubProtocol, NetworkProtocols};
use reth_network_api::{NetworkInfo, Peers, PeersInfo};
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives};
use reth_rpc_builder::TransportRpcModules;
use reth_storage_api::{BlockNumReader, NodePrimitivesProvider};
use tokio::{sync::broadcast::error::RecvError, time::sleep};

use crate::{
    args::MsgboardArgs,
    board::MsgBoard,
    db::open_msgboard_db,
    protocol::{MsgboardProtocolHandler, NetworkPeerReporter},
    rpc::MsgboardApi,
    rpc_api::MsgboardApiServer,
};

/// Periodic interval for the sync watcher loop.
const SYNC_WATCHER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Launch-time orchestrator for the msgboard sub-protocol.
///
/// Cheap to clone — the published board lives behind an `Arc<OnceLock<...>>`
/// so the rpc-modules closure (which moves a clone) and the post-launch
/// task drivers (which read from another clone) share the same handle.
#[derive(Debug, Clone)]
pub struct MsgboardLauncher {
    args: MsgboardArgs,
    config: MsgboardConfig,
    board: Arc<OnceLock<Arc<MsgBoard>>>,
}

impl MsgboardLauncher {
    /// Build a launcher from parsed CLI arguments.
    pub fn new(args: MsgboardArgs) -> Self {
        let config = args.clone().into_config();
        Self { args, config, board: Arc::new(OnceLock::new()) }
    }

    /// Returns the parsed CLI arguments.
    pub const fn args(&self) -> &MsgboardArgs {
        &self.args
    }

    /// Returns the published board if [`Self::install`] has run.
    pub fn board(&self) -> Option<Arc<MsgBoard>> {
        self.board.get().cloned()
    }

    /// Resolve the msgboard DB directory: `--msgboard.db-dir` when given,
    /// otherwise `<datadir>/msgboard`.
    ///
    /// An explicit override is used verbatim — it is deliberately *not* joined
    /// under the datadir, so operators can park the board on a different disk.
    pub fn db_path(&self, datadir: PathBuf) -> PathBuf {
        self.args.msgboard_db_dir.clone().unwrap_or_else(|| datadir.join("msgboard"))
    }

    /// Open the persistent DB, build the in-memory board, register the
    /// `msgboard_*` RPC methods on every transport that requested the module,
    /// install the `msg/1` rlpx sub-protocol with peer-reputation reporting,
    /// spawn the periodic flush + log tasks, and publish the board so
    /// post-launch tasks can read it.
    ///
    /// `datadir` is the node's data directory; the msgboard DB defaults to
    /// `<datadir>/msgboard` unless `--msgboard.db-dir` was provided.
    pub fn install<N>(
        &self,
        modules: &mut TransportRpcModules,
        network: N,
        datadir: PathBuf,
    ) -> eyre::Result<Arc<MsgBoard>>
    where
        N: NetworkProtocols + Peers + Clone + Debug + Send + Sync + 'static,
    {
        let db_path = self.db_path(datadir);

        let board = match open_msgboard_db(&db_path) {
            Ok(env) => {
                let b = Arc::new(MsgBoard::with_db(self.config.clone(), env));
                match b.load_from_db() {
                    Ok(count) if count > 0 => {
                        tracing::debug!(target: "msgboard", count, "restored persisted messages");
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "msgboard",
                            %e,
                            "failed to load msgboard from DB; starting empty",
                        );
                    }
                    _ => {}
                }
                b
            }
            Err(e) => {
                tracing::warn!(
                    target: "reth::cli",
                    %e,
                    "failed to open msgboard DB; running in-memory only",
                );
                Arc::new(MsgBoard::new(self.config.clone()))
            }
        };

        board.spawn_flush_task(self.args.msgboard_commit_every);
        board.spawn_log_task(self.args.msgboard_log_every);

        let rpc = MsgboardApi::new(Arc::clone(&board));
        modules.merge_configured(rpc.into_rpc())?;

        let reporter = Arc::new(NetworkPeerReporter::new(network.clone()));
        let handler = MsgboardProtocolHandler::new(Arc::clone(&board)).with_reporter(reporter);
        network.add_rlpx_sub_protocol(handler.into_rlpx_sub_protocol());

        // Once-only publish; subsequent calls are no-ops.
        let _ = self.board.set(Arc::clone(&board));

        Ok(board)
    }

    /// Spawn post-launch tasks bound to the running node:
    ///
    /// 1. seed `headBlock` immediately from `chain_info()` so RPC reads the real head from the
    ///    first call instead of waiting for the next canonical commit (tens of seconds on a quiet
    ///    chain);
    /// 2. spawn a sync watcher that flips the board's ready flag once the network finishes syncing
    ///    and has at least one peer;
    /// 3. spawn a canonical-state subscriber that pushes each new tip into [`MsgBoard::set_head`]
    ///    so the block-window prune-and-expiry pipeline advances with the chain.
    ///
    /// No-op if [`Self::install`] has not run.
    pub fn install_post_launch_tasks<Net, Provider>(&self, network: Net, provider: Provider)
    where
        Net: NetworkInfo + PeersInfo + Clone + Send + Sync + 'static,
        Provider: CanonStateSubscriptions + BlockNumReader + Clone + Send + Sync + 'static,
        <<Provider as NodePrimitivesProvider>::Primitives as NodePrimitives>::BlockHeader:
            AlloyBlockHeader,
    {
        let Some(board) = self.board.get().cloned() else {
            tracing::warn!(
                target: "msgboard",
                "post-launch tasks called before install; skipping",
            );
            return;
        };

        match provider.chain_info() {
            Ok(info) => board.set_head(info.best_number, info.best_hash),
            Err(err) => tracing::warn!(
                target: "msgboard",
                %err,
                "could not seed msgboard head at startup; will pick up on first canonical commit",
            ),
        }

        let board_for_watcher = Arc::clone(&board);
        let net_for_watcher = network.clone();
        tokio::spawn(async move {
            loop {
                sleep(SYNC_WATCHER_INTERVAL).await;
                if !net_for_watcher.is_syncing() && net_for_watcher.num_connected_peers() > 0 {
                    board_for_watcher.set_ready();
                    break;
                }
            }
        });

        let mut rx = provider.subscribe_to_canonical_state();
        let board_for_canon = Arc::clone(&board);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(notification) => {
                        let tip = notification.tip();
                        board_for_canon.set_head(tip.number(), tip.hash());
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!(
                            target: "msgboard",
                            lagged = n,
                            "canonical-state stream lagged; head update may have skipped blocks",
                        );
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }

    /// Final flush on shutdown — call after `wait_for_node_exit().await`.
    /// Mirrors erigon-pulse `MainLoop`'s `flushBoard(context.Background())`
    /// on the shutdown branch (`board.go:158-166`).
    ///
    /// A no-op if [`Self::install`] never ran — shutdown must stay clean on a
    /// node that failed before msgboard came up.
    pub fn final_flush(&self) {
        let Some(board) = self.board.get() else {
            return;
        };
        match board.flush_to_db() {
            Ok(bytes) => tracing::info!(
                target: "msgboard",
                bytes,
                "final flush on shutdown",
            ),
            Err(err) => tracing::warn!(
                target: "msgboard",
                %err,
                "final flush on shutdown failed",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launcher_with_db_dir(db_dir: Option<&str>) -> MsgboardLauncher {
        MsgboardLauncher::new(MsgboardArgs {
            msgboard_db_dir: db_dir.map(PathBuf::from),
            ..Default::default()
        })
    }

    /// The default lives under the node's datadir, so a msgboard env follows the
    /// chain it belongs to rather than leaking into a shared location.
    #[test]
    fn db_path_defaults_to_msgboard_under_the_datadir() {
        let launcher = launcher_with_db_dir(None);
        assert_eq!(
            launcher.db_path(PathBuf::from("/var/lib/reth")),
            PathBuf::from("/var/lib/reth/msgboard"),
        );
    }

    /// An explicit `--msgboard.db-dir` is used verbatim, *not* re-rooted under
    /// the datadir — operators point this at a separate disk.
    #[test]
    fn db_path_override_is_used_verbatim() {
        let launcher = launcher_with_db_dir(Some("/mnt/fast/board"));
        assert_eq!(
            launcher.db_path(PathBuf::from("/var/lib/reth")),
            PathBuf::from("/mnt/fast/board"),
            "the override must not be joined under the datadir",
        );
    }

    /// The launcher carries the parsed args through unchanged, and derives its
    /// config from them — the board's limits are whatever the CLI said.
    #[test]
    fn new_derives_config_from_args() {
        let args = MsgboardArgs {
            msgboard_count_limit: 4_242,
            msgboard_gossip_disable: true,
            ..Default::default()
        };

        let launcher = MsgboardLauncher::new(args.clone());
        assert_eq!(launcher.args(), &args);
        assert_eq!(launcher.config.count_limit, 4_242);
        assert!(launcher.config.gossip_disabled);
    }

    /// Shutdown runs on nodes that never got as far as installing msgboard —
    /// e.g. a failure earlier in launch. Both post-install entry points must be
    /// inert rather than panicking or unwrapping an absent board.
    #[test]
    fn post_install_entry_points_are_inert_before_install() {
        let launcher = launcher_with_db_dir(None);
        assert!(launcher.board().is_none(), "no board before install");

        // Must not panic.
        launcher.final_flush();

        assert!(launcher.board().is_none(), "final_flush must not publish a board");
    }

    /// The launcher is cloned into the rpc-modules closure while the post-launch
    /// drivers read from another clone, so every clone has to observe the same
    /// published board.
    #[test]
    fn clones_share_one_board_slot() {
        let launcher = launcher_with_db_dir(None);
        let clone = launcher.clone();

        let board = Arc::new(MsgBoard::new(launcher.config.clone()));
        assert!(launcher.board.set(Arc::clone(&board)).is_ok(), "first publish wins");

        assert!(clone.board().is_some(), "the clone must see the published board");
        assert!(
            Arc::ptr_eq(&clone.board().unwrap(), &board),
            "clones must share the slot, not hold independent boards",
        );

        // Publishing is once-only; a second attempt leaves the original in place.
        let other = Arc::new(MsgBoard::new(launcher.config.clone()));
        assert!(launcher.board.set(other).is_err(), "second publish is rejected");
        assert!(Arc::ptr_eq(&launcher.board().unwrap(), &board));
    }
}
