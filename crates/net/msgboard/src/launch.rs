//! Launch-time wiring for the msgboard sub-protocol.
//!
//! [`MsgboardLauncher`] encapsulates the full lifecycle so the entrypoint
//! binary can stay close to upstream's stock shape: open the persistent DB,
//! build the in-memory board, install the JSON-RPC module + `msg/1` rlpx
//! handler, spawn periodic flush/log tasks, subscribe to canonical-state
//! notifications, and flush a final time on shutdown.
//!
//! The helper is node-agnostic — both [`PulsechainNode`] and `EthereumNode`
//! can drive it, so the same binary can serve `PulseChain` and Ethereum chain
//! IDs from one msgboard implementation.
//!
//! [`PulsechainNode`]: https://docs.rs/reth-pulsechain-node

use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use reth_chain_state::{CanonStateNotifications, CanonStateSubscriptions};
use reth_msgboard_types::MsgboardConfig;
use reth_network::{protocol::IntoRlpxSubProtocol, NetworkProtocols};
use reth_network_api::{NetworkInfo, Peers, PeersInfo};
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives};
use reth_rpc_builder::{RethRpcModule, TransportRpcModules};
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
        // `merge_configured` would install the namespace on every enabled
        // transport whatever `--http.api` says. That is how `msgboard_addMessage`
        // — a write method — reached an unauthenticated port under a config whose
        // `--http.api "eth,net,web3"` reads like it excludes everything else.
        install_msgboard_rpc(modules, rpc)?;

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
        let net_for_watcher = network;
        tokio::spawn(async move {
            loop {
                sleep(SYNC_WATCHER_INTERVAL).await;
                if !net_for_watcher.is_syncing() && net_for_watcher.num_connected_peers() > 0 {
                    board_for_watcher.set_ready();
                    break;
                }
            }
        });

        tokio::spawn(drive_canonical_head(
            Arc::clone(&board),
            provider.subscribe_to_canonical_state(),
        ));
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

/// Push each canonical tip into [`MsgBoard::set_head`].
///
/// The block-window prune-and-expiry pipeline advances only from here. If this
/// loop stops, the board keeps serving messages anchored to a chain it no
/// longer follows and rejects every message anchored to a block it has not
/// seen — both silently, because nothing else reads the chain.
///
/// Split out of [`MsgboardLauncher::install_post_launch_tasks`] so a test can
/// drive it with a real notification stream. Inside the `spawn` closure it was
/// reachable only from a running node.
async fn drive_canonical_head<N>(board: Arc<MsgBoard>, mut rx: CanonStateNotifications<N>)
where
    N: NodePrimitives,
    N::BlockHeader: AlloyBlockHeader,
{
    loop {
        match rx.recv().await {
            Ok(notification) => {
                let tip = notification.tip();
                board.set_head(tip.number(), tip.hash());
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
}

/// The namespace an operator names in `--http.api`, `--ws.api` or `--ipc.api`
/// to expose the msgboard methods.
///
/// [`RethRpcModule`] has no msgboard variant, so this rides its `Other`
/// catch-all. That is enough for the allowlist check and keeps the change out
/// of the shared RPC types.
pub const MSGBOARD_RPC_NAMESPACE: &str = "msgboard";

/// The [`RethRpcModule`] the msgboard methods register under.
fn msgboard_rpc_module() -> RethRpcModule {
    RethRpcModule::Other(MSGBOARD_RPC_NAMESPACE.to_string())
}

/// Install the msgboard methods on every transport whose namespace allowlist
/// names [`MSGBOARD_RPC_NAMESPACE`], and on no other.
fn install_msgboard_rpc(modules: &mut TransportRpcModules, api: MsgboardApi) -> eyre::Result<()> {
    modules.merge_if_module_configured(msgboard_rpc_module(), api.into_rpc())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_primitives::B256;
    use reth_chain_state::{test_utils::TestBlockBuilder, CanonStateNotification};
    use reth_execution_types::Chain;
    use reth_msgboard_types::MsgboardConfig;
    use reth_rpc_builder::{RpcModuleSelection, TransportRpcModuleConfig};

    use super::*;

    /// A canonical commit must reach [`MsgBoard::set_head`].
    ///
    /// Nothing else advances the block window, so if this wiring breaks the
    /// board keeps serving messages anchored to a chain it no longer follows
    /// and rejects every message anchored to a block it has not seen. Both
    /// failures are silent, which is why the loop is worth a gate rather than
    /// a reading.
    #[tokio::test]
    async fn a_canonical_commit_advances_the_board_head() {
        const HEIGHT: u64 = 4_242;

        let board = Arc::new(MsgBoard::new(MsgboardConfig::default()));
        assert_eq!(board.status().1, 0, "a fresh board has no head");

        let (tx, rx) = tokio::sync::broadcast::channel::<CanonStateNotification>(4);
        tokio::spawn(drive_canonical_head(Arc::clone(&board), rx));

        let mut builder = TestBlockBuilder::eth();
        let executed = builder.get_executed_block_with_number(HEIGHT, B256::ZERO);
        let block = executed.recovered_block().clone();
        // The execution outcome and trie data are irrelevant here — only the
        // tip's number and hash reach `set_head`.
        let chain = Arc::new(Chain::new([block], Default::default(), BTreeMap::new()));

        tx.send(CanonStateNotification::Commit { new: chain }).expect("receiver is live");

        // The driver runs on its own task, so give it a turn to observe.
        for _ in 0..100 {
            if board.status().1 == HEIGHT {
                break;
            }
            tokio::task::yield_now().await;
        }

        let (_, head, ..) = board.status();
        assert_eq!(head, HEIGHT, "the commit must advance the board head");
    }

    /// A transport whose allowlist does not name msgboard must not carry it.
    ///
    /// `merge_if_module_configured` gates every transport on exactly this
    /// predicate, so this is the decision the install turns on.
    #[test]
    fn a_transport_that_does_not_name_msgboard_does_not_get_it() {
        let config = TransportRpcModuleConfig::default()
            .with_http([RethRpcModule::Eth])
            .with_ipc([RethRpcModule::Eth]);

        assert!(!config.contains_http(&msgboard_rpc_module()));
        assert!(!config.contains_ipc(&msgboard_rpc_module()));
    }

    /// Naming the namespace is what turns it on, on that transport alone.
    #[test]
    fn naming_msgboard_enables_it_on_that_transport_only() {
        let config = TransportRpcModuleConfig::default()
            .with_http([RethRpcModule::Eth, msgboard_rpc_module()])
            .with_ipc([RethRpcModule::Eth]);

        assert!(config.contains_http(&msgboard_rpc_module()));
        assert!(!config.contains_ipc(&msgboard_rpc_module()));
    }

    /// The exact `--http.api` string `etc/docker-compose.yml` ships, on
    /// `--http.addr 0.0.0.0` with 8545 published.
    ///
    /// It reads like a three-namespace restriction and is one. Before the
    /// install honoured it, that published port answered
    /// `msgboard_addMessage` — a write method — with no authentication.
    #[test]
    fn the_shipped_docker_compose_allowlist_excludes_msgboard() {
        let selection: RpcModuleSelection =
            "eth,net,web3".parse().expect("the compose --http.api value must parse");
        let config = TransportRpcModuleConfig::default().with_http(selection);

        assert!(!config.contains_http(&msgboard_rpc_module()));
        assert!(config.contains_http(&RethRpcModule::Eth));
    }

    /// `--http.api "msgboard"` has to parse into the module the install
    /// registers under, or the flag silently does nothing.
    #[test]
    fn the_namespace_string_parses_to_the_module_we_register_under() {
        let parsed: RethRpcModule =
            MSGBOARD_RPC_NAMESPACE.parse().expect("namespace must parse as a module");
        assert_eq!(parsed, msgboard_rpc_module());

        let selection: RpcModuleSelection =
            "eth,msgboard".parse().expect("operators must be able to name it");
        let config = TransportRpcModuleConfig::default().with_http(selection);
        assert!(config.contains_http(&msgboard_rpc_module()));
    }

    /// Drive the install itself and report which transports came away with
    /// msgboard methods on them.
    ///
    /// The four tests above assert on [`TransportRpcModuleConfig`], which is
    /// reth's own type — they pass whether the install honours the allowlist
    /// or ignores it. Only this helper runs `install_msgboard_rpc` and looks
    /// at what it registered.
    fn install_and_report(config: TransportRpcModuleConfig) -> (bool, bool, bool) {
        let board = Arc::new(MsgBoard::new(MsgboardConfig::default()));
        let mut modules = TransportRpcModules::default()
            .with_config(config)
            .with_http(jsonrpsee::RpcModule::new(()))
            .with_ws(jsonrpsee::RpcModule::new(()))
            .with_ipc(jsonrpsee::RpcModule::new(()));

        install_msgboard_rpc(&mut modules, MsgboardApi::new(board)).expect("install must succeed");

        let carries = |m: Option<jsonrpsee::Methods>| {
            m.is_some_and(|methods| methods.method_names().any(|n| n.starts_with("msgboard_")))
        };
        let named = |n: &str| n.starts_with("msgboard_");
        (
            carries(modules.http_methods(named)),
            carries(modules.ws_methods(named)),
            carries(modules.ipc_methods(named)),
        )
    }

    /// The install must put the methods only where the allowlist names them.
    ///
    /// This is the regression the audit found. The install used
    /// `merge_configured`, which merges into every enabled transport and
    /// consults no allowlist, so the namespace rode onto transports that
    /// never asked for it. Swap `merge_if_module_configured` back for
    /// `merge_configured` and this test fails; the four above do not.
    #[test]
    fn the_install_puts_msgboard_only_on_the_transport_that_names_it() {
        let (http, ws, ipc) = install_and_report(
            TransportRpcModuleConfig::default()
                .with_http([RethRpcModule::Eth, msgboard_rpc_module()])
                .with_ws([RethRpcModule::Eth])
                .with_ipc([RethRpcModule::Eth]),
        );

        assert!(http, "http named msgboard, so it must carry the methods");
        assert!(!ws, "ws did not name msgboard");
        assert!(!ipc, "ipc did not name msgboard");
    }

    /// The shipped compose file must not answer msgboard on its published port.
    ///
    /// `etc/docker-compose.yml` runs `--http.api "eth,net,web3"` on
    /// `--http.addr 0.0.0.0` with 8545 published. Before the fix that port
    /// answered `msgboard_addMessage`, a write method, with no
    /// authentication. This drives the install with that exact string.
    #[test]
    fn the_shipped_docker_compose_port_does_not_answer_msgboard() {
        let selection: RpcModuleSelection =
            "eth,net,web3".parse().expect("the compose --http.api value must parse");
        let (http, _, _) =
            install_and_report(TransportRpcModuleConfig::default().with_http(selection));

        assert!(!http, "the published port must not carry a msgboard write method");
    }

    /// An operator who names the namespace gets it, on every transport that
    /// names it.
    ///
    /// The counterpart to the test above: the allowlist must not be so strict
    /// that naming `msgboard` fails to turn it on.
    #[test]
    fn naming_the_namespace_on_two_transports_installs_it_on_both() {
        let (http, ws, ipc) = install_and_report(
            TransportRpcModuleConfig::default()
                .with_http([msgboard_rpc_module()])
                .with_ws([msgboard_rpc_module()])
                .with_ipc([RethRpcModule::Eth]),
        );

        assert!(http, "http named msgboard");
        assert!(ws, "ws named msgboard");
        assert!(!ipc, "ipc did not, and IPC is on by default");
    }

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
