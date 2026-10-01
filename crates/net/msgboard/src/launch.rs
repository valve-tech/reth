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

use alloy_primitives::B256;
use reth_chain_state::{CanonStateNotifications, CanonStateSubscriptions};
use reth_msgboard_types::MsgboardConfig;
use reth_network::protocol::{IntoRlpxSubProtocol, RlpxSubProtocol};
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

    /// Open the persistent DB, build the in-memory board, spawn the periodic
    /// flush and log tasks, and publish the board so the other entry points and
    /// the post-launch tasks can read it.
    ///
    /// Idempotent. A second call returns the published board and does not touch
    /// the DB again.
    ///
    /// `datadir` is the node's data directory; the msgboard DB defaults to
    /// `<datadir>/msgboard` unless `--msgboard.db-dir` was provided.
    pub fn init_board(&self, datadir: PathBuf) -> Arc<MsgBoard> {
        if let Some(board) = self.board.get() {
            return Arc::clone(board);
        }
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

        // Once-only publish; subsequent calls are no-ops.
        let _ = self.board.set(Arc::clone(&board));

        board
    }

    /// Build the `msg/1` sub-protocol, for registration on a network that has
    /// **not started yet**.
    ///
    /// Register it before the network accepts peers. This is not a preference.
    /// A session fixes its capability set once, from the `Hello` exchange, and
    /// `SessionManager` reads the protocol list per connection
    /// (`session/mod.rs`, `on_incoming` / `on_outgoing`). A peer already
    /// connected when this lands therefore never negotiates `msg/1`, and
    /// nothing renegotiates it for the life of the session.
    ///
    /// Trusted peers are the ones that lose. The node dials them the moment the
    /// network starts — exactly the window before a late registration — and it
    /// then holds those links open, so they never re-form. On 2026-09-05 a pair
    /// of testnet-v4 nodes that list each other as trusted peers held zero
    /// msgboard sessions until both processes restarted, while a mainnet pair
    /// relying on discovery churn looked healthy the whole time.
    ///
    /// `network` is only used to report peer reputation. Take it from
    /// [`NetworkBuilder::handle`](reth_network::NetworkBuilder::handle), which
    /// hands out a usable handle before the manager is spawned.
    pub fn rlpx_sub_protocol<N>(&self, board: Arc<MsgBoard>, network: N) -> RlpxSubProtocol
    where
        N: Peers + Clone + Debug + Send + Sync + 'static,
    {
        let reporter = Arc::new(NetworkPeerReporter::new(network));
        MsgboardProtocolHandler::new(board).with_reporter(reporter).into_rlpx_sub_protocol()
    }

    /// Register the `msgboard_*` RPC methods on every transport that named the
    /// namespace.
    ///
    /// Errors if [`Self::init_board`] has not run.
    pub fn install_rpc(&self, modules: &mut TransportRpcModules) -> eyre::Result<()> {
        let board = self
            .board
            .get()
            .ok_or_else(|| eyre::eyre!("msgboard: init_board must run before install_rpc"))?;
        // `merge_configured` would install the namespace on every enabled
        // transport whatever `--http.api` says. That is how `msgboard_addMessage`
        // — a write method — reached an unauthenticated port under a config whose
        // `--http.api "eth,net,web3"` reads like it excludes everything else.
        install_msgboard_rpc(modules, MsgboardApi::new(Arc::clone(board)))
    }

    /// Spawn post-launch tasks bound to the running node:
    ///
    /// 1. seed the block window from the provider (see `seed_head_window`), so RPC reads the real
    ///    head from the first call and the board accepts messages anchored anywhere in the window
    ///    without waiting for the next canonical commit;
    /// 2. spawn a sync watcher that flips the board's ready flag once the network finishes syncing
    ///    and has at least one peer;
    /// 3. spawn a canonical-state subscriber that pushes each new block into [`MsgBoard::set_head`]
    ///    so the block-window prune-and-expiry pipeline advances with the chain.
    ///
    /// No-op if [`Self::init_board`] has not run.
    pub fn install_post_launch_tasks<Net, Provider>(&self, network: Net, provider: Provider)
    where
        Net: NetworkInfo + PeersInfo + Clone + Send + Sync + 'static,
        Provider: CanonStateSubscriptions
            + NodePrimitivesProvider
            + BlockNumReader
            + Clone
            + Send
            + Sync
            + 'static,
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

        // Subscribe before the seed. A block committed between the two then
        // waits in the stream; the driver skips it if the seed already has it.
        let rx = provider.subscribe_to_canonical_state();
        if let Err(err) = seed_head_window(&board, &provider, self.config.block_range) {
            tracing::warn!(
                target: "msgboard",
                %err,
                "could not seed msgboard head at startup; will pick up on first canonical commit",
            );
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
            rx,
            provider,
            self.config.block_range,
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

    /// A guard that runs [`Self::final_flush`] when it drops.
    ///
    /// Hold it in the node's future. On SIGTERM or ctrl-c the CLI runner drops
    /// that future, so the `final_flush` call after `wait_for_node_exit` never
    /// runs, but the guard still drops. The board's own `Drop` flush is not
    /// enough there: network and RPC tasks can hold the board until the
    /// runtime shuts down, and the runner gives that only a few seconds.
    ///
    /// Take the guard before the board exists; it reads the board at drop time.
    pub fn flush_guard(&self) -> FinalFlushGuard {
        FinalFlushGuard { launcher: self.clone() }
    }
}

/// Runs [`MsgboardLauncher::final_flush`] on drop. See
/// [`MsgboardLauncher::flush_guard`].
#[derive(Debug)]
#[must_use = "the flush runs when the guard drops; bind it to a named variable"]
pub struct FinalFlushGuard {
    launcher: MsgboardLauncher,
}

impl Drop for FinalFlushGuard {
    fn drop(&mut self) {
        if let Some(board) = self.launcher.board.get() {
            board.stop_accepting();
        }
        self.launcher.final_flush();
    }
}

/// Push each canonical block into [`MsgBoard::set_head`].
///
/// The block-window prune-and-expiry pipeline advances only from here. If this
/// loop stops, the board keeps serving messages anchored to a chain it no
/// longer follows and rejects every message anchored to a block it has not
/// seen — both silently, because nothing else reads the chain.
///
/// Split out of [`MsgboardLauncher::install_post_launch_tasks`] so a test can
/// drive it with a real notification stream. Inside the `spawn` closure it was
/// reachable only from a running node.
async fn drive_canonical_head<N, P>(
    board: Arc<MsgBoard>,
    mut rx: CanonStateNotifications<N>,
    provider: P,
    block_range: u64,
) where
    N: NodePrimitives,
    P: BlockNumReader,
    N::BlockHeader: AlloyBlockHeader,
{
    loop {
        match rx.recv().await {
            Ok(notification) => {
                // Deliberate divergence from erigon, which passes only the
                // last block of each batch to `ChangeBlock` (`fetch.go:403-407`).
                // Register every committed block in the window, oldest first,
                // so a catch-up or a multi-block reorg leaves no hash in the
                // window unknown. See docs/msgboard-parity-gaps.md §28.1.
                // Reverted blocks need no extra step: a lower `set_head` drops
                // everything above it.
                let committed = notification.committed();
                // A plain commit at or below the head is old news: the stream
                // keeps it after a lag, or the startup seed already read it.
                // Applying it would lower the head and drop the hashes above.
                // A reorg can lower the head on purpose, so it always applies.
                if notification.reverted().is_none() && committed.tip().number() <= board.status().1
                {
                    continue;
                }
                let lower = window_lower(committed.tip().number(), block_range);
                for block in committed.blocks_iter().filter(|b| b.number() >= lower) {
                    board.set_head(block.number(), block.hash());
                }
            }
            Err(RecvError::Lagged(n)) => {
                tracing::warn!(
                    target: "msgboard",
                    lagged = n,
                    "canonical-state stream lagged; head update may have skipped blocks",
                );
                // The skipped blocks are gone from the stream, so read the
                // window back from the provider.
                if let Err(err) = seed_head_window(&board, &provider, block_range) {
                    tracing::warn!(
                        target: "msgboard",
                        %err,
                        "could not re-seed msgboard window after lag",
                    );
                }
            }
            Err(RecvError::Closed) => break,
        }
    }
}

/// Load the canonical hashes of the live block window into the board.
///
/// Mirrors erigon-pulse `BlockFilter.Initialize` (`block_filter.go:37-58`):
/// every canonical hash in `[lower, head]` goes in, oldest first, so the board
/// accepts messages anchored anywhere in the window. Peers send their full
/// board only on connect, so a board that knew only the head would reject the
/// older messages and never get them again.
///
/// The read is bounded by `block_range`, which [`BlockFilter`] caps at
/// [`MAX_BLOCK_RANGE`].
///
/// [`BlockFilter`]: crate::block_filter::BlockFilter
/// [`MAX_BLOCK_RANGE`]: crate::block_filter::MAX_BLOCK_RANGE
fn seed_head_window<P: BlockNumReader>(
    board: &MsgBoard,
    provider: &P,
    block_range: u64,
) -> reth_storage_api::errors::ProviderResult<()> {
    let info = provider.chain_info()?;
    let head = info.best_number;
    let lower = window_lower(head, block_range);
    // `canonical_hashes_range` gives hashes without numbers. Only a full
    // answer can be numbered from `lower`; anything else falls back to the
    // head alone, as the seed did before it read the window.
    let mut blocks: Vec<(u64, B256)> = match provider.canonical_hashes_range(lower, head + 1) {
        Ok(hashes) if hashes.len() as u64 == head + 1 - lower => (lower..).zip(hashes).collect(),
        Ok(hashes) => {
            tracing::warn!(
                target: "msgboard",
                got = hashes.len(),
                want = head + 1 - lower,
                "short canonical hash read; seeding msgboard head only",
            );
            Vec::new()
        }
        Err(err) => {
            tracing::warn!(
                target: "msgboard",
                %err,
                "canonical hash read failed; seeding msgboard head only",
            );
            Vec::new()
        }
    };
    blocks.push((head, info.best_hash));
    board.seed_window(head, blocks);
    Ok(())
}

/// The lowest block of a `block_range` window that ends at `head`.
fn window_lower(head: u64, block_range: u64) -> u64 {
    let range = block_range.clamp(1, crate::block_filter::MAX_BLOCK_RANGE);
    head.saturating_sub(range - 1).max(1)
}

/// The namespace an operator names in `--http.api`, `--ws.api` or `--ipc.api`
/// to expose the msgboard methods.
///
/// [`RethRpcModule`] has no msgboard variant, so this rides its `Other`
/// catch-all. That is enough for the allowlist check and keeps the change out
/// of the shared RPC types.
///
/// `RpcModuleSelection::All` contains every module, `Other` ones included, so
/// `--http.api all` exposes `msgboard_addMessage` to anyone who can reach the
/// port. That is deliberate: an operator who asks for all namespaces gets this
/// one too. Proof of work and `--msgboard.count-limit` bound what a caller can
/// do with it; an operator who wants no public submission endpoint lists
/// namespaces instead of `all`.
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

    use alloy_primitives::{Bytes, B256};
    use reth_chain_state::{test_utils::TestBlockBuilder, CanonStateNotification};
    use reth_execution_types::Chain;
    use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};
    use reth_rpc_builder::{RpcModuleSelection, TransportRpcModuleConfig};
    use reth_storage_api::errors::ProviderResult;

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
        tokio::spawn(drive_canonical_head(Arc::clone(&board), rx, FakeChain::new(0), 120));

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

    /// A canonical chain whose block `n` has hash `chain_hash(n)`.
    #[derive(Debug, Clone)]
    struct FakeChain {
        head: u64,
        range: RangeMode,
    }

    /// How [`FakeChain::canonical_hashes_range`] answers.
    #[derive(Debug, Clone, Copy)]
    enum RangeMode {
        /// Every hash in the range.
        Full,
        /// An error.
        Fail,
        /// The range without its first hash.
        DropFirst,
    }

    impl FakeChain {
        const fn new(head: u64) -> Self {
            Self { head, range: RangeMode::Full }
        }

        const fn with_range(head: u64, range: RangeMode) -> Self {
            Self { head, range }
        }
    }

    fn chain_hash(n: u64) -> B256 {
        B256::left_padding_from(&(n + 1).to_be_bytes())
    }

    impl reth_storage_api::BlockHashReader for FakeChain {
        fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
            Ok((number <= self.head).then(|| chain_hash(number)))
        }

        fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
            let all = (start..end.min(self.head + 1)).map(chain_hash);
            match self.range {
                RangeMode::Full => Ok(all.collect()),
                RangeMode::Fail => {
                    Err(reth_storage_api::errors::ProviderError::BlockHashNotFound(B256::ZERO))
                }
                RangeMode::DropFirst => Ok(all.skip(1).collect()),
            }
        }
    }

    impl BlockNumReader for FakeChain {
        fn chain_info(&self) -> ProviderResult<reth_chainspec::ChainInfo> {
            Ok(reth_chainspec::ChainInfo {
                best_hash: chain_hash(self.head),
                best_number: self.head,
            })
        }

        fn best_block_number(&self) -> ProviderResult<u64> {
            Ok(self.head)
        }

        fn last_block_number(&self) -> ProviderResult<u64> {
            Ok(self.head)
        }

        fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
            Ok((0..=self.head).find(|n| chain_hash(*n) == hash))
        }
    }

    /// A ready board with cheap work limits and the default block window.
    fn window_board() -> Arc<MsgBoard> {
        let board = Arc::new(MsgBoard::new(cheap_launcher().config));
        board.set_ready();
        board
    }

    fn accepts(board: &MsgBoard, anchor: B256, tag: u8) -> bool {
        board.add_local_msg(mine(anchor, &[tag])).is_ok()
    }

    /// Erigon's `BlockFilter.Initialize` loads every canonical hash in
    /// `[lower, head]` at startup (`block_filter.go:37-58`). Peers send their
    /// full board only on connect. A node that knows only the head after a
    /// restart rejects every message anchored to an older block in the window,
    /// and it never gets that message again.
    #[tokio::test]
    async fn startup_seeds_every_hash_in_the_window() {
        const HEAD: u64 = 1_000;
        let board = window_board();
        let range = cheap_launcher().config.block_range;
        seed_head_window(&board, &FakeChain::new(HEAD), range).expect("seed");

        assert!(accepts(&board, chain_hash(HEAD - 50), 1), "H-50 is inside the window");
        assert!(accepts(&board, chain_hash(HEAD - range + 1), 2), "the lower bound is inside");
        assert!(!accepts(&board, chain_hash(HEAD - range), 3), "H-range is outside");
        assert!(!accepts(&board, chain_hash(HEAD - (range + 1)), 4), "H-(range+1) is outside");
    }

    /// Wait until the driver task makes `cond` true, or give up.
    async fn settle(cond: impl Fn() -> bool) {
        for _ in 0..100 {
            if cond() {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    /// A commit of several blocks (catch-up, multi-block reorg) must register
    /// every block, not only the tip. Erigon registers only the last block of a
    /// batch; reth registers all of them on purpose (parity gaps §28.1).
    #[tokio::test]
    async fn a_multi_block_commit_registers_every_block() {
        let board = window_board();
        let (tx, rx) = tokio::sync::broadcast::channel::<CanonStateNotification>(4);
        tokio::spawn(drive_canonical_head(Arc::clone(&board), rx, FakeChain::new(0), 120));

        let mut builder = TestBlockBuilder::eth();
        let blocks: Vec<_> =
            builder.get_executed_blocks(10..15).map(|b| b.recovered_block().clone()).collect();
        let hashes: Vec<_> = blocks.iter().map(|b| b.hash()).collect();
        let chain = Arc::new(Chain::new(blocks, Default::default(), BTreeMap::new()));
        tx.send(CanonStateNotification::Commit { new: chain }).expect("receiver is live");
        settle(|| board.status().1 == 14).await;

        for (i, hash) in hashes.into_iter().enumerate() {
            assert!(accepts(&board, hash, i as u8), "block {} must be known", 10 + i);
        }
    }

    fn commit_at(builder: &mut TestBlockBuilder, n: u64) -> CanonStateNotification {
        let block = builder.get_executed_block_with_number(n, B256::ZERO);
        let chain = Arc::new(Chain::new(
            [block.recovered_block().clone()],
            Default::default(),
            BTreeMap::new(),
        ));
        CanonStateNotification::Commit { new: chain }
    }

    /// After `Lagged` the driver has missed blocks that the stream cannot give
    /// back, so it re-reads the window from the provider. The stream then still
    /// yields the older notifications it kept. Those must not move the head
    /// back: a lower `set_head` drops every hash above it.
    #[tokio::test]
    async fn a_lagged_stream_reseeds_and_keeps_the_head() {
        const HEAD: u64 = 500;
        let board = window_board();
        let (tx, rx) = tokio::sync::broadcast::channel::<CanonStateNotification>(1);

        // Overflow the channel before the driver runs, so its first recv lags
        // and the next recv yields the stale `HEAD - 1` commit.
        let mut builder = TestBlockBuilder::eth();
        for n in [HEAD - 2, HEAD - 1] {
            tx.send(commit_at(&mut builder, n)).expect("receiver is live");
        }
        tokio::spawn(drive_canonical_head(Arc::clone(&board), rx, FakeChain::new(HEAD), 120));
        settle(|| false).await;

        assert_eq!(board.status().1, HEAD, "the stale commit must not lower the head");
        assert!(accepts(&board, chain_hash(HEAD), 1), "the head hash stays known");
        assert!(accepts(&board, chain_hash(HEAD - 60), 2), "the lag re-seed loads the window");
    }

    /// A plain commit at or below the head, sent after the re-seed, is old
    /// news and must be skipped too.
    #[tokio::test]
    async fn an_old_commit_after_a_lag_is_skipped() {
        const HEAD: u64 = 500;
        let board = window_board();
        let (tx, rx) = tokio::sync::broadcast::channel::<CanonStateNotification>(1);
        let mut builder = TestBlockBuilder::eth();
        for n in [HEAD - 3, HEAD - 2] {
            tx.send(commit_at(&mut builder, n)).expect("receiver is live");
        }
        tokio::spawn(drive_canonical_head(Arc::clone(&board), rx, FakeChain::new(HEAD), 120));
        settle(|| false).await;

        tx.send(commit_at(&mut builder, HEAD - 1)).expect("receiver is live");
        settle(|| false).await;

        assert_eq!(board.status().1, HEAD);
        assert!(accepts(&board, chain_hash(HEAD), 1), "the head hash stays known");
    }

    /// A reorg can lower the head, so the skip rule must not apply to it.
    #[tokio::test]
    async fn a_reorg_to_a_lower_tip_still_moves_the_head() {
        let board = window_board();
        let (tx, rx) = tokio::sync::broadcast::channel::<CanonStateNotification>(4);
        tokio::spawn(drive_canonical_head(Arc::clone(&board), rx, FakeChain::new(0), 120));

        let mut builder = TestBlockBuilder::eth();
        let old: Vec<_> =
            builder.get_executed_blocks(10..15).map(|b| b.recovered_block().clone()).collect();
        let old_tip = old.last().expect("five blocks").hash();
        let new_block = builder.get_executed_block_with_number(12, old[1].hash());
        let new_hash = new_block.recovered_block().hash();
        let old_part = Arc::new(Chain::new(old[2..].to_vec(), Default::default(), BTreeMap::new()));
        let old_all = Arc::new(Chain::new(old, Default::default(), BTreeMap::new()));
        tx.send(CanonStateNotification::Commit { new: old_all }).expect("receiver is live");
        settle(|| board.status().1 == 14).await;

        let new = Arc::new(Chain::new(
            [new_block.recovered_block().clone()],
            Default::default(),
            BTreeMap::new(),
        ));
        tx.send(CanonStateNotification::Reorg { old: old_part, new }).expect("receiver is live");
        settle(|| board.status().1 == 12).await;

        assert_eq!(board.status().1, 12, "the reorg lowers the head");
        assert!(accepts(&board, new_hash, 1), "the new tip is known");
        assert!(!accepts(&board, old_tip, 2), "the orphaned tip is forgotten");
    }

    /// If the provider cannot give the window, the seed still loads the head,
    /// as the startup code did before it loaded the window.
    #[tokio::test]
    async fn a_failed_range_read_still_seeds_the_head() {
        const HEAD: u64 = 1_000;
        let board = window_board();
        let range = cheap_launcher().config.block_range;
        let chain = FakeChain::with_range(HEAD, RangeMode::Fail);
        seed_head_window(&board, &chain, range).expect("the head alone is enough");

        assert_eq!(board.status().1, HEAD);
        assert!(accepts(&board, chain_hash(HEAD), 1), "the head hash is known");
    }

    /// `canonical_hashes_range` gives no block numbers. If it returns fewer
    /// hashes than asked for, the seed must not pair a hash with the wrong
    /// number.
    #[tokio::test]
    async fn a_short_range_read_never_misnumbers_a_hash() {
        const HEAD: u64 = 1_000;
        let board = window_board();
        let range = cheap_launcher().config.block_range;
        let chain = FakeChain::with_range(HEAD, RangeMode::DropFirst);
        seed_head_window(&board, &chain, range).expect("seed");

        for (tag, n) in (HEAD - range + 1..=HEAD).enumerate() {
            if let Ok(msg) = board.add_local_msg(mine(chain_hash(n), &[tag as u8, 0xEE])) {
                assert_eq!(msg.block_number, n, "hash of block {n} got the wrong number");
            }
        }
        assert!(accepts(&board, chain_hash(HEAD), 1), "the head hash is known");
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

    /// The RPC namespace cannot be installed before the board exists, and the
    /// board is built by the network builder. That ordering is the fix for the
    /// late-registration bug: if someone moves the board back into the rpc hook,
    /// the sub-protocol goes back to registering on a network that is already
    /// dialling, and trusted peers silently lose `msg/1` again.
    ///
    /// A refusal here is the cheap symptom of that mistake.
    #[test]
    fn the_rpc_namespace_refuses_to_install_before_the_board_exists() {
        let launcher = launcher_with_db_dir(None);
        let mut modules = TransportRpcModules::default();

        let err = launcher.install_rpc(&mut modules).expect_err("no board yet");
        assert!(
            err.to_string().contains("init_board must run before install_rpc"),
            "unexpected error: {err}",
        );
    }

    /// `init_board` runs from the network builder, which is reached once per
    /// launch — but the board is also read by two other entry points, and a
    /// second open of the same MDBX env would fail. Publishing once and handing
    /// the same handle back keeps that safe.
    #[tokio::test]
    async fn init_board_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let launcher = launcher_with_db_dir(None);

        let first = launcher.init_board(dir.path().to_path_buf());
        let second = launcher.init_board(dir.path().to_path_buf());

        assert!(Arc::ptr_eq(&first, &second), "the second call must not build a second board");
        assert!(
            launcher.board().is_some_and(|b| Arc::ptr_eq(&b, &first)),
            "the published board is the one both calls returned",
        );
    }

    /// A work divisor that makes mining cost one or two hashes.
    const CHEAP_WORK_DIVISOR: u64 = 1 << 24;

    fn cheap_launcher() -> MsgboardLauncher {
        MsgboardLauncher::new(MsgboardArgs {
            msgboard_work_multiplier: 1,
            msgboard_work_divisor: CHEAP_WORK_DIVISOR,
            ..Default::default()
        })
    }

    fn mine(block_hash: B256, data: &[u8]) -> PoWMsg {
        (1u64..=1_000_000)
            .map(|nonce| PoWMsg {
                version: VERSION_V1,
                block_hash,
                nonce,
                work_multiplier: 1,
                work_divisor: CHEAP_WORK_DIVISOR,
                category: B256::repeat_byte(0xCA),
                data: Bytes::copy_from_slice(data),
            })
            .find(|msg| msg.verify().is_ok())
            .expect("a valid nonce")
    }

    /// A signal drops the node's future instead of letting it return, so the
    /// `final_flush` after `wait_for_node_exit` never runs. Dropping the last
    /// handle to the board must still write what it accepted.
    #[tokio::test]
    async fn dropping_the_board_without_a_final_flush_keeps_accepted_messages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let launcher = cheap_launcher();
        let board = launcher.init_board(dir.path().to_path_buf());
        board.set_ready();
        board.set_head(1, B256::repeat_byte(0x01));
        let hash = board.add_local_msg(mine(B256::repeat_byte(0x01), &[0x42])).expect("valid").hash;

        drop(board);
        drop(launcher);

        let env = open_msgboard_db(&dir.path().join("msgboard")).expect("reopen");
        let (loaded, _) = crate::db::db_load_all(&env).expect("load");
        assert!(
            loaded.iter().any(|m| m.hash == hash),
            "the accepted message is on disk after shutdown: {} rows",
            loaded.len(),
        );
    }

    /// Network and RPC tasks can still hold the board when the node's future is
    /// dropped, so the board's own drop flush can come too late. The guard in
    /// the node's future flushes when that future goes, whoever else holds the
    /// board.
    #[tokio::test]
    async fn the_flush_guard_flushes_when_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let launcher = cheap_launcher();
        let guard = launcher.flush_guard();
        let board = launcher.init_board(dir.path().to_path_buf());
        board.set_ready();
        board.set_head(1, B256::repeat_byte(0x01));
        board.add_local_msg(mine(B256::repeat_byte(0x01), &[0x43])).expect("valid");

        drop(guard);

        assert_eq!(board.flush_to_db().expect("flush"), 0, "the guard already wrote the message");
        assert!(
            board.add_local_msg(mine(B256::repeat_byte(0x01), &[0x44])).is_err(),
            "after the guard flush the board accepts nothing it would then lose",
        );
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
