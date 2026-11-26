//! Wires the lite node together: store, header chain, beacon follower, network, JSON-RPC server
//! and Prometheus, then waits for a shutdown signal.

use crate::{
    beacon::{trust_label, BeaconClient, FollowConfig, Follower},
    chain::HeaderChain,
    config::{HeadConfirm, HeadVerify, LiteConfig},
    hot_set::{refresh_loop, HotSet},
    light_client::{
        check_sync_committee_start, Checkpoint, StartFrom, StoreOrigin, SyncCommitteeStart,
    },
    metrics::LiteMetrics,
    net::{
        client::{P2pFetcher, Transport, TransportError, WireReceipt},
        wire::LiteNetwork,
    },
    rpc::{serve_listener, Api, ApiParts},
    store::{NodeStore, Store},
    sync_committee::Preset,
    sync_committee_file::SyncCommitteeFile,
};
use alloy_primitives::B256;
use async_trait::async_trait;
use reth_network_peers::PeerId;
use reth_pulsechain_snap::Snap1Message;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

/// The longest the shutdown flush runs before it stops with entries unsaved, well under the 90 s
/// that systemd waits before it kills a unit.
const FLUSH_DEADLINE: Duration = Duration::from_secs(30);

/// The transport when there are no static peers and discovery is off: nobody to ask.
#[derive(Debug, Clone, Copy)]
struct NoNetwork;

#[async_trait]
impl Transport for NoNetwork {
    fn peers(&self) -> Vec<PeerId> {
        Vec::new()
    }
    fn drop_peer(&self, _: PeerId) {}
    async fn snap(&self, _: PeerId, _: Snap1Message) -> Result<Snap1Message, TransportError> {
        Err(TransportError::Disconnected)
    }
    async fn receipts(
        &self,
        _: PeerId,
        _: B256,
    ) -> Result<Option<Vec<WireReceipt>>, TransportError> {
        Err(TransportError::Disconnected)
    }
}

/// Either the real network or nothing.
#[derive(Clone)]
enum AnyNet {
    Real(LiteNetwork),
    None(NoNetwork),
}

#[async_trait]
impl Transport for AnyNet {
    fn peers(&self) -> Vec<PeerId> {
        match self {
            Self::Real(n) => n.peers(),
            Self::None(n) => n.peers(),
        }
    }
    fn is_static(&self, peer: &PeerId) -> bool {
        match self {
            Self::Real(n) => n.is_static(peer),
            Self::None(n) => n.is_static(peer),
        }
    }
    fn ban(&self, peer: PeerId) {
        match self {
            Self::Real(n) => n.ban(peer),
            Self::None(n) => n.ban(peer),
        }
    }
    fn drop_peer(&self, peer: PeerId) {
        match self {
            Self::Real(n) => n.drop_peer(peer),
            Self::None(n) => n.drop_peer(peer),
        }
    }
    async fn snap(&self, peer: PeerId, msg: Snap1Message) -> Result<Snap1Message, TransportError> {
        match self {
            Self::Real(n) => n.snap(peer, msg).await,
            Self::None(n) => n.snap(peer, msg).await,
        }
    }
    async fn receipts(
        &self,
        peer: PeerId,
        hash: B256,
    ) -> Result<Option<Vec<WireReceipt>>, TransportError> {
        match self {
            Self::Real(n) => n.receipts(peer, hash).await,
            Self::None(n) => n.receipts(peer, hash).await,
        }
    }
}

#[async_trait]
impl crate::rpc::PeerNetwork for AnyNet {
    fn peer_count(&self) -> usize {
        match self {
            Self::Real(n) => n.connected_peers(),
            Self::None(_) => 0,
        }
    }
    async fn broadcast_transaction(
        &self,
        raw: &[u8],
    ) -> Result<usize, alloy_eips::eip2718::Eip2718Error> {
        match self {
            Self::Real(n) => n.broadcast_transaction(raw).await,
            Self::None(_) => Ok(0),
        }
    }
}

impl AnyNet {
    /// Usable peers as `(static, discovered)`.
    fn counts(&self) -> (usize, usize) {
        match self {
            Self::Real(n) => n.peer_counts(),
            Self::None(_) => (0, 0),
        }
    }
}

/// The task runtime the network spawns on: the current tokio runtime. The network uses no rayon
/// pool, but the runtime builds three eagerly, so each gets one thread.
fn network_runtime() -> Result<reth_tasks::Runtime, reth_tasks::RuntimeBuildError> {
    let rayon = reth_tasks::RayonConfig {
        cpu_threads: Some(1),
        rpc_threads: Some(1),
        storage_threads: Some(1),
        ..Default::default()
    };
    let config = reth_tasks::RuntimeConfig::default()
        .with_tokio(reth_tasks::TokioConfig::existing_handle(tokio::runtime::Handle::current()))
        .with_rayon(rayon);
    reth_tasks::RuntimeBuilder::new(config).build()
}

/// Runs the start checks of `--head.verify=sync-committee`, which fail closed: the node never
/// falls back to `quorum` by itself.
///
/// A usable store file in the data directory is used first. A damaged, stale or wrong-chain file
/// is logged and ignored. Without one the first store is a bootstrap at `cfg.checkpoint`, or at
/// the anchor's finalized root when there is none.
async fn start_sync_committee(
    cfg: &LiteConfig,
) -> Result<(SyncCommitteeStart, SyncCommitteeFile), Box<dyn std::error::Error + Send + Sync>> {
    let network = reth_pulsechain_forks::network::pulsechain_network(cfg.chain_id).ok_or(
        "--head.verify=sync-committee needs a PulseChain network with pinned beacon values",
    )?;
    let now = std::time::SystemTime::now();
    let file = SyncCommitteeFile::new(&cfg.datadir, cfg.chain_id);
    let saved = match file.load(Preset::PULSECHAIN, network.beacon, now) {
        Ok(saved) => saved,
        Err(error) => {
            tracing::warn!(
                file = crate::sync_committee_file::FILE_NAME,
                %error,
                "the saved sync-committee store is not used; bootstrapping again"
            );
            None
        }
    };
    let from = match (saved, cfg.checkpoint) {
        (Some(store), checkpoint) => {
            if let Some(Checkpoint::Flag(root)) = checkpoint {
                tracing::info!(
                    %root,
                    file = crate::sync_committee_file::FILE_NAME,
                    "--checkpoint is not used: the saved sync-committee store resumes; delete the \
                     file to bootstrap at the checkpoint"
                );
            }
            StartFrom::Saved(Box::new(store))
        }
        (None, Some(checkpoint)) => StartFrom::Checkpoint(checkpoint),
        (None, None) => StartFrom::Anchor,
    };
    let clients: Vec<BeaconClient> =
        cfg.beacon_urls.iter().cloned().map(BeaconClient::new).collect();
    let anchor = BeaconClient::new(cfg.anchor_url.clone());
    let start = check_sync_committee_start(
        &clients,
        &anchor,
        network.beacon,
        Preset::PULSECHAIN,
        from,
        now,
    )
    .await?;
    Ok((start, file))
}

/// Sets `lite_unconfirmed_start`, and warns when nothing but the anchor confirms the block the
/// node starts from (see [`LiteConfig::unconfirmed_start`]). `store` is where the light-client
/// store came from, `None` without one: only then is the start source known.
fn note_unconfirmed_start(cfg: &LiteConfig, store: Option<&StoreOrigin>, metrics: &LiteMetrics) {
    let unconfirmed = cfg.unconfirmed_start(store);
    metrics.unconfirmed_start.set(if unconfirmed { 1.0 } else { 0.0 });
    if unconfirmed {
        let warning = match cfg.head_verify {
            HeadVerify::Quorum => crate::config::UNCONFIRMED_START,
            HeadVerify::SyncCommittee => crate::config::UNCONFIRMED_START_SYNC_COMMITTEE,
        };
        tracing::warn!(
            anchor = %crate::beacon::host_label(&cfg.anchor_url),
            "{warning}"
        );
    }
}

/// Runs the node until the first message on `signals`, or until its sender is gone, then saves
/// the memory cache to disk. A second message, or [`FLUSH_DEADLINE`], stops the save.
pub async fn run(
    cfg: LiteConfig,
    metrics: LiteMetrics,
    mut signals: tokio::sync::mpsc::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Bind first: requests wait in the backlog while the rest starts.
    let listener = tokio::net::TcpListener::bind(cfg.rpc_addr).await?;
    // Owner-only: it holds the node key and the store. An existing directory keeps its mode.
    crate::net::wire::create_private_dir(&cfg.datadir)?;
    let sync_committee = match cfg.head_verify {
        HeadVerify::SyncCommittee => Some(start_sync_committee(&cfg).await?),
        HeadVerify::Quorum => None,
    };
    metrics.set_head_verify(cfg.head_verify);
    note_unconfirmed_start(&cfg, sync_committee.as_ref().map(|(start, _)| &start.origin), &metrics);
    let store =
        Arc::new(Store::open(&cfg.datadir.join("store"), cfg.cache_max_bytes, cfg.disk_limit)?);
    metrics.disk_limit_bytes.set(cfg.disk_limit as f64);
    let chain = Arc::new(HeaderChain::with_body_budget(cfg.body_budget));

    let net = if cfg.peers.is_empty() && !cfg.discovery {
        tracing::warn!(
            "no --peer given and discovery is off: state cannot be fetched, reads outside held state will miss"
        );
        AnyNet::None(NoNetwork)
    } else {
        let net = LiteNetwork::start(&cfg, network_runtime()?).await?;
        // The full node sees this node as an inbound peer, and refuses or rotates out one it
        // does not trust when its inbound slots are full.
        tracing::info!(
            enode = %net.local_record(),
            "node record: on the full node that --peer names, pass --trusted-peers with this id \
             and this node's IP address"
        );
        AnyNet::Real(net)
    };
    let net = Arc::new(net);
    let fetcher = Arc::new(P2pFetcher::new(net.clone(), store.clone(), metrics.clone()));
    let hot = Arc::new(HotSet::new(cfg.state_hot_set_size()));

    let mut follow = FollowConfig::from(&cfg);
    if let Some((start, _)) = &sync_committee {
        // Only the sources that match the pinned chain values.
        follow.urls = start.sources.iter().map(|&i| cfg.beacon_urls[i].clone()).collect();
    }
    let mut label = trust_label(&follow);
    let mut follower = Follower::new(follow, chain.clone(), metrics.clone());
    if let Some((start, file)) = sync_committee {
        label = format!("heads signed by the sync committee; {label}");
        let unchecked = start.unchecked_positions();
        follower = follower
            .with_sync_committee(start.store, start.origin, Some(file))
            .with_unchecked_pins(unchecked);
    }
    if cfg.head_confirm == HeadConfirm::Peer {
        // The configuration guarantees a --peer, so the network is real.
        let AnyNet::Real(n) = &*net else {
            return Err("--head.confirm=peer needs a --peer".into())
        };
        follower = follower.with_confirm(Arc::new(n.clone()));
    }
    let follower = Arc::new(follower);
    let follower_task = tokio::spawn(follower.run());
    let hot_task = tokio::spawn(refresh_loop(chain.clone(), hot.clone(), fetcher.clone()));

    let api = Api::new(ApiParts {
        cfg: cfg.clone(),
        chain: chain.clone(),
        store: store.clone(),
        fetcher: fetcher.clone(),
        receipts: fetcher,
        metrics: metrics.clone(),
        hot,
        net: net.clone(),
        trust_label: label.clone(),
    })
    .ok_or("unsupported chain")?;
    let (addr, server) = serve_listener(api, listener)?;
    tracing::info!(%addr, "{label}");

    let gauges = tokio::spawn({
        let (store, metrics, net) = (store.clone(), metrics.clone(), net.clone());
        async move {
            let mut tick = 0u64;
            loop {
                metrics.cache_bytes.set(store.bytes() as f64);
                let (statics, discovered) = net.counts();
                metrics.set_peers(statics, discovered);
                if tick.is_multiple_of(10) {
                    // A rotation commits, opens an environment and deletes a generation.
                    let s = store.clone();
                    match tokio::task::spawn_blocking(move || s.enforce_disk_limit()).await {
                        Ok(used) => metrics.disk_bytes.set(used as f64),
                        Err(e) => tracing::warn!(%e, "disk limit check failed"),
                    }
                }
                tick += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });

    signals.recv().await;
    tracing::info!("shutting down");
    server.abort();
    follower_task.abort();
    hot_task.abort();
    gauges.abort();
    let second_signal = async move {
        if signals.recv().await.is_none() {
            std::future::pending::<()>().await;
        }
    };
    flush_bounded(store, FLUSH_DEADLINE, second_signal).await;
    Ok(())
}

/// Saves the memory cache on a blocking thread, and stops the save after `deadline` or when
/// `stop` resolves. Returns when the save does: at most one batch commit after a stop.
async fn flush_bounded(store: Arc<Store>, deadline: Duration, stop: impl Future<Output = ()>) {
    let stopping = Arc::new(AtomicBool::new(false));
    let mut flush = tokio::task::spawn_blocking({
        let stopping = stopping.clone();
        move || store.flush(&stopping)
    });
    tokio::select! {
        res = &mut flush => {
            if let Err(e) = res {
                tracing::warn!(%e, "the shutdown flush failed");
            }
            return
        }
        () = tokio::time::sleep(deadline) => {
            tracing::warn!(?deadline, "the shutdown flush ran out of time; stopping it");
        }
        () = stop => tracing::warn!("a second signal stops the shutdown flush"),
    }
    stopping.store(true, Ordering::Relaxed);
    if let Err(e) = flush.await {
        tracing::warn!(%e, "the shutdown flush failed");
    }
}

impl LiteConfig {
    /// The hot-set size (0 = off).
    pub const fn state_hot_set_size(&self) -> usize {
        self.hot_set
    }
}

/// How often the recorder drains its histogram samples, as the exporter's own `install` does.
const METRICS_UPKEEP: Duration = Duration::from_secs(5);

/// Installs the Prometheus recorder and serves its text on `addr` with
/// [`crate::rpc::serve_metrics`]. Must run inside the tokio runtime.
pub fn install_prometheus(addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder()?;
    let upkeep = handle.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(METRICS_UPKEEP).await;
            upkeep.run_upkeep();
        }
    });
    let render = Arc::new(move || handle.render());
    crate::rpc::serve_metrics(listener, crate::rpc::MetricsLimits::default(), render)?;
    Ok(())
}

/// Logs to stderr at info level. Log lines never carry a URL: sources are named by host.
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fake_beacon::Fake,
        light_client::{
            tests::{pinned_anchor, pinned_source, pins_369},
            UPDATES_PATH,
        },
        net::{peers::BAN_FOR, wire::NetOptions},
        sync_committee::{
            test_utils::{branch, node, Real369},
            BeaconBlockHeader, ExecutionPayloadHeader, LightClientHeader, LightClientStore,
        },
        sync_committee_file::FILE_NAME,
    };
    use reth_pulsechain_forks::network::BeaconCheckpoint;
    use std::path::Path;

    /// The source of every `.rs` file under `dir` with the `#[cfg(test)]` part cut off.
    fn non_test_sources(dir: &Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                non_test_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                let code = text.split("#[cfg(test)]").next().unwrap_or_default().to_owned();
                out.push((path, code));
            }
        }
    }

    #[test]
    fn production_code_does_not_build_the_test_runtime() {
        let mut sources = Vec::new();
        non_test_sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut sources);
        let offenders: Vec<_> = sources
            .iter()
            .filter(|(_, code)| code.contains("Runtime::test()"))
            .map(|(path, _)| path.display().to_string())
            .collect();
        assert!(offenders.is_empty(), "Runtime::test() outside #[cfg(test)]: {offenders:?}");
    }

    /// A store whose memory tier holds 20 000 entries no flush has saved yet.
    fn unsaved_store(dir: &Path) -> (Arc<Store>, Vec<(B256, alloy_primitives::Bytes)>) {
        let store = Arc::new(Store::open(dir, 64 << 20, 256 << 20).unwrap());
        let items: Vec<_> = (0..20_000u32)
            .map(|i| {
                let v =
                    alloy_primitives::Bytes::from([i.to_be_bytes().as_slice(), &[7; 996]].concat());
                (alloy_primitives::keccak256(&v), v)
            })
            .collect();
        for (k, v) in &items {
            store.put(*k, v.clone());
        }
        (store, items)
    }

    fn saved(dir: &Path, items: &[(B256, alloy_primitives::Bytes)]) -> usize {
        let store = Store::open(dir, 0, 256 << 20).unwrap();
        items.iter().filter(|(k, v)| store.get(k).as_ref() == Some(v)).count()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_shutdown_flush_stops_at_its_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let (store, items) = unsaved_store(dir.path());
        let done = tokio::time::timeout(
            Duration::from_secs(10),
            flush_bounded(store, Duration::ZERO, std::future::pending()),
        )
        .await;
        assert!(done.is_ok(), "the flush did not stop");
        let saved = saved(dir.path(), &items);
        assert!(saved < items.len() / 2, "{saved} of {} saved", items.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_signal_stops_the_shutdown_flush() {
        let dir = tempfile::tempdir().unwrap();
        let (store, items) = unsaved_store(dir.path());
        let done = tokio::time::timeout(
            Duration::from_secs(10),
            flush_bounded(store, Duration::from_secs(3600), std::future::ready(())),
        )
        .await;
        assert!(done.is_ok(), "the flush did not stop");
        let saved = saved(dir.path(), &items);
        assert!(saved < items.len() / 2, "{saved} of {} saved", items.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unhurried_shutdown_flush_saves_everything() {
        let dir = tempfile::tempdir().unwrap();
        let (store, items) = unsaved_store(dir.path());
        flush_bounded(store, Duration::from_secs(3600), std::future::pending()).await;
        assert_eq!(saved(dir.path(), &items), items.len());
    }

    #[tokio::test]
    async fn sync_committee_mode_does_not_start_when_the_anchor_cannot_be_checked() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = LiteConfig {
            head_verify: HeadVerify::SyncCommittee,
            ..offline_cfg(dir.path(), free_port())
        };
        let (_stop, signals) = tokio::sync::mpsc::channel(1);
        let err = run(cfg, LiteMetrics::new(), signals).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "the finalized anchor http://127.0.0.1 does not match the pinned chain values: \
             /eth/v1/beacon/genesis: could not connect"
        );
        assert!(!dir.path().join("store").exists(), "the store opened before the checks");
    }

    /// Runs the node in `--head.verify=sync-committee` mode against `source` and `anchor` and
    /// returns its start error.
    async fn sync_committee_start_error(source: &Fake, anchor: &Fake) -> String {
        let dir = tempfile::tempdir().unwrap();
        let cfg = LiteConfig {
            head_verify: HeadVerify::SyncCommittee,
            beacon_urls: vec![source.beacon_url()],
            anchor_url: anchor.anchor_url(),
            ..offline_cfg(dir.path(), free_port())
        };
        let (_stop, signals) = tokio::sync::mpsc::channel(1);
        run(cfg, LiteMetrics::new(), signals).await.unwrap_err().to_string()
    }

    #[tokio::test]
    async fn sync_committee_mode_does_not_start_when_no_source_serves_a_bootstrap() {
        let (source, anchor) = (pinned_source(false).await, pinned_anchor().await);
        let err = sync_committee_start_error(&source, &anchor).await;
        let want = "no beacon source served a usable /eth/v1/beacon/light_client/bootstrap: \
                    http://127.0.0.1: http status 404.";
        assert!(err.starts_with(want), "{err}");
    }

    /// The `--head.verify=sync-committee` configuration with `source` and `anchor`.
    fn sync_committee_cfg(datadir: &Path, source: &Fake, anchor: &Fake) -> LiteConfig {
        LiteConfig {
            head_verify: HeadVerify::SyncCommittee,
            beacon_urls: vec![source.beacon_url()],
            anchor_url: anchor.anchor_url(),
            ..offline_cfg(datadir, free_port())
        }
    }

    /// A damaged store file, or one for another chain, is ignored with a warning, and the node
    /// bootstraps from the anchor.
    #[tokio::test]
    async fn a_damaged_or_wrong_chain_store_file_is_ignored_and_the_node_bootstraps() {
        let (source, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let real = Real369::load();
        let root: B256 = real.json["block_root"].as_str().unwrap().parse().unwrap();
        let store =
            LightClientStore::bootstrap(Preset::PULSECHAIN, pins_369(), root, &real.bootstrap())
                .unwrap();
        let on_943 = SyncCommitteeFile::new(Path::new("."), 943).encode(&store);
        for (contents, reason) in [
            (b"not a store".to_vec(), "the checksum does not match"),
            (on_943, "the file is for chain 943, not 369"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(FILE_NAME), contents).unwrap();
            let logs = crate::testing::logs::capture(tracing::Level::WARN);
            let (start, _) =
                start_sync_committee(&sync_committee_cfg(dir.path(), &source, &anchor))
                    .await
                    .unwrap();
            assert_eq!(start.origin, StoreOrigin::Bootstrap { anchor_root: root });
            let text = logs.text();
            assert!(text.contains("the saved sync-committee store is not used"), "{text}");
            assert!(text.contains(reason), "{text}");
        }
    }

    /// A store file of the current period is loaded, and the anchor is not asked for a root.
    #[tokio::test]
    async fn a_current_store_file_is_loaded_instead_of_a_bootstrap() {
        let (source, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let pins = pins_369();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let slot = (now - pins.genesis_time) / 10;
        let execution = ExecutionPayloadHeader { block_number: 5, ..Default::default() };
        let body = [(25, execution.hash_tree_root())];
        let header = LightClientHeader {
            beacon: BeaconBlockHeader { slot, body_root: node(&body, 1, 4), ..Default::default() },
            execution,
            execution_branch: branch(&body, 25, 4).try_into().unwrap(),
        };
        let committee = Real369::load().bootstrap().current_sync_committee;
        let store =
            LightClientStore::restore(Preset::PULSECHAIN, pins, header, committee, None).unwrap();
        let period = store.period();
        source.answer(&format!("{UPDATES_PATH}?start_period={period}&count=1"), "200 OK", "[]");
        let dir = tempfile::tempdir().unwrap();
        let file = SyncCommitteeFile::new(dir.path(), 369);
        file.save(&file.encode(&store)).unwrap();

        // The file also wins over --checkpoint, and the log says so.
        let checkpoint = B256::repeat_byte(7);
        let cfg = LiteConfig {
            checkpoint: Some(Checkpoint::Flag(checkpoint)),
            ..sync_committee_cfg(dir.path(), &source, &anchor)
        };
        let logs = crate::testing::logs::capture(tracing::Level::INFO);
        let (start, _) = start_sync_committee(&cfg).await.unwrap();
        assert_eq!(start.origin, StoreOrigin::Saved);
        assert_eq!(start.store.finalized_header().beacon.slot, slot);
        assert_eq!(anchor.calls("/eth/v1/beacon/blocks/finalized/root"), 0);
        assert_eq!(
            source.calls(&format!("/eth/v1/beacon/light_client/bootstrap/{checkpoint:#x}")),
            0
        );
        let text = logs.text();
        assert!(text.contains("--checkpoint is not used: the saved sync-committee store resumes"));
    }

    /// The configured checkpoint reaches the start checks: a pin at slot 0 is always stale, and
    /// the node stops before it opens the store.
    #[tokio::test]
    async fn a_stale_configured_checkpoint_stops_the_start() {
        let (source, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let dir = tempfile::tempdir().unwrap();
        let pin = BeaconCheckpoint { root: B256::repeat_byte(7), slot: 0, taken: "2023-05-11" };
        let cfg = LiteConfig {
            checkpoint: Some(Checkpoint::Pinned(pin)),
            ..sync_committee_cfg(dir.path(), &source, &anchor)
        };
        let (_stop, signals) = tokio::sync::mpsc::channel(1);
        let err = run(cfg, LiteMetrics::new(), signals).await.unwrap_err().to_string();
        let want = "the checkpoint pinned for this chain (slot 0, taken 2023-05-11) is ";
        assert!(err.starts_with(want), "{err}");
        assert!(err.contains("days old, more than the 30-day limit"), "{err}");
        assert!(!dir.path().join("store").exists(), "the store opened before the checks");
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");
    }

    /// A passing check starts the node in sync-committee mode, and the metrics say so.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_committee_mode_starts_after_passing_checks() {
        let (source, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let cfg = LiteConfig {
            head_verify: HeadVerify::SyncCommittee,
            beacon_urls: vec![source.beacon_url()],
            anchor_url: anchor.anchor_url(),
            ..offline_cfg(dir.path(), port)
        };
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let prometheus = recorder.handle();
        let metrics = metrics::with_local_recorder(&recorder, LiteMetrics::new);
        let (stop, signals) = tokio::sync::mpsc::channel(1);
        let node = tokio::spawn(run(cfg, metrics, signals));
        let started = || {
            prometheus.render().lines().any(|l| l == "lite_head_verify{mode=\"sync-committee\"} 1")
        };
        wait_for("the sync-committee mode", started).await;
        let rendered = prometheus.render();
        assert!(rendered.lines().any(|l| l == "lite_head_verify{mode=\"quorum\"} 0"), "{rendered}");
        // The real 369 bootstrap is in period 1363. The node sets the mode before it builds the
        // follower, which sets the period.
        let period = || gauge(&prometheus.render(), "lite_sync_committee_period") == Some(1363.0);
        wait_for("the store's period", period).await;
        wait_for("the store", || dir.path().join("store").is_dir()).await;
        // No checkpoint, no store file and --head.confirm=none: the anchor's root alone chose the
        // first committee and the first block.
        let rendered = prometheus.render();
        assert_eq!(gauge(&rendered, "lite_unconfirmed_start"), Some(1.0), "{rendered}");
        stop.send(()).await.unwrap();
        let done = tokio::time::timeout(Duration::from_secs(10), node).await;
        assert!(matches!(done, Ok(Ok(Ok(())))), "run did not return Ok after shutdown");
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn the_network_runtime_has_one_thread_rayon_pools() {
        let rt = network_runtime().unwrap();
        assert_eq!(rt.cpu_pool().current_num_threads(), 1);
        assert_eq!(rt.storage_pool().current_num_threads(), 1);
    }

    /// A configuration with no network and beacons that refuse connections.
    fn offline_cfg(datadir: &Path, port: u16) -> LiteConfig {
        let nowhere: url::Url = "http://127.0.0.1:1".parse().unwrap();
        LiteConfig {
            datadir: datadir.to_path_buf(),
            rpc_addr: std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            beacon_urls: vec![nowhere.clone()],
            anchor_url: nowhere,
            discovery: false,
            head_confirm: HeadConfirm::None,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn the_node_serves_its_chain_id_on_loopback_and_returns_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (stop, signals) = tokio::sync::mpsc::channel(1);
        let node = tokio::spawn(run(offline_cfg(dir.path(), port), LiteMetrics::new(), signals));
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
        let http = reqwest::Client::new();
        let mut answer = None;
        for _ in 0..100 {
            let sent = http
                .post(format!("http://127.0.0.1:{port}"))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await;
            if let Ok(resp) = sent {
                answer = Some(
                    serde_json::from_slice::<serde_json::Value>(&resp.bytes().await.unwrap())
                        .unwrap(),
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(answer.expect("the RPC server answered")["result"], "0x171");
        assert!(dir.path().join("store").is_dir());
        stop.send(()).await.unwrap();
        let done = tokio::time::timeout(Duration::from_secs(10), node).await;
        assert!(matches!(done, Ok(Ok(Ok(())))), "run did not return Ok after shutdown");
    }

    /// The value of the unlabeled series `name` in a Prometheus rendering.
    fn gauge(rendered: &str, name: &str) -> Option<f64> {
        rendered.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
    }

    /// With `--head.confirm=none`, two starts let the anchor alone choose the first block:
    /// `--head.verify=quorum` with `--beacon.quorum 1`, and `--head.verify=sync-committee` with a
    /// store bootstrapped at the anchor's root (no pin, no `--checkpoint`, no saved store). Each
    /// warns at start, names the flags that remove the risk, and sets `lite_unconfirmed_start`;
    /// no other start does.
    #[test]
    fn only_an_unconfirmed_start_warns_and_sets_its_gauge() {
        use HeadConfirm::{None as NoConfirm, Peer};
        use HeadVerify::{Quorum, SyncCommittee};
        let anchor = Some(StoreOrigin::Bootstrap { anchor_root: B256::repeat_byte(1) });
        let checkpoint = Some(StoreOrigin::Checkpoint { root: B256::repeat_byte(2) });
        let saved = Some(StoreOrigin::Saved);
        for (head_verify, beacon_quorum, head_confirm, store, unconfirmed) in [
            (Quorum, 1, NoConfirm, None, true),
            (Quorum, 1, Peer, None, false),
            (Quorum, 2, NoConfirm, None, false),
            (Quorum, 2, Peer, None, false),
            (SyncCommittee, 1, NoConfirm, anchor, true),
            (SyncCommittee, 2, NoConfirm, anchor, true),
            (SyncCommittee, 1, Peer, anchor, false),
            (SyncCommittee, 1, NoConfirm, checkpoint, false),
            (SyncCommittee, 1, NoConfirm, saved, false),
            (SyncCommittee, 1, Peer, checkpoint, false),
        ] {
            let case =
                format!("{head_verify:?}, quorum {beacon_quorum}, {head_confirm:?}, {store:?}");
            let cfg = LiteConfig { head_verify, beacon_quorum, head_confirm, ..Default::default() };
            assert_eq!(cfg.unconfirmed_start(store.as_ref()), unconfirmed, "{case}");
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let prometheus = recorder.handle();
            let logs = crate::testing::logs::capture(tracing::Level::WARN);
            metrics::with_local_recorder(&recorder, || {
                note_unconfirmed_start(&cfg, store.as_ref(), &LiteMetrics::new())
            });
            let text = logs.text();
            drop(logs);
            let want = if unconfirmed { 1.0 } else { 0.0 };
            assert_eq!(gauge(&prometheus.render(), "lite_unconfirmed_start"), Some(want), "{case}");
            assert_eq!(text.contains("UNCONFIRMED START"), unconfirmed, "{case}: {text}");
            let flags: &[&str] = match (unconfirmed, head_verify) {
                (false, _) => &[],
                (true, Quorum) => &[
                    "--beacon.url",
                    "--beacon.quorum 2",
                    "--head.confirm=peer",
                    "--peer",
                    "--head.verify=sync-committee",
                ],
                (true, SyncCommittee) => &["--checkpoint", "--head.confirm=peer", "--peer"],
            };
            for flag in flags {
                assert!(text.contains(flag), "{case}: the warning does not name {flag}: {text}");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_gauges_task_runs_the_disk_check_and_reports_disk_use() {
        let dir = tempfile::tempdir().unwrap();
        let limit = crate::store::MIN_DISK_LIMIT;
        // An earlier run with a larger limit left a generation past 80% of this one.
        let items: Vec<_> = (0..12_000u32)
            .map(|i| {
                let v =
                    alloy_primitives::Bytes::from([i.to_be_bytes().as_slice(), &[7; 996]].concat());
                (alloy_primitives::keccak256(&v), v)
            })
            .collect();
        {
            let store = Store::open(&dir.path().join("store"), 64 << 20, 64 << 20).unwrap();
            for (k, v) in &items {
                store.put(*k, v.clone());
            }
            store.flush(&AtomicBool::new(false));
        }
        let gen0 = std::fs::metadata(dir.path().join("store/gen-0/mdbx.dat")).unwrap().len();
        assert!(gen0 > limit / 10 * 8, "the old generation holds only {gen0} bytes");

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let prometheus = recorder.handle();
        let metrics = metrics::with_local_recorder(&recorder, LiteMetrics::new);
        let cfg = LiteConfig { disk_limit: limit, ..offline_cfg(dir.path(), 0) };
        let (stop, signals) = tokio::sync::mpsc::channel(1);
        let node = tokio::spawn(run(cfg, metrics, signals));
        let rotated = dir.path().join("store/gen-1");
        let mut rendered = String::new();
        for _ in 0..200 {
            rendered = prometheus.render();
            if rotated.is_dir() && gauge(&rendered, "lite_disk_bytes").is_some_and(|b| b > 0.0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(rotated.is_dir(), "the disk check did not rotate the store");
        // The check reports what it measured before it rotated: the old generation alone, which
        // MDBX may trim when it reopens it.
        let disk = gauge(&rendered, "lite_disk_bytes").unwrap();
        assert!(disk > (limit / 10 * 8) as f64 && disk <= gen0 as f64, "{disk} of {gen0}");
        assert_eq!(gauge(&rendered, "lite_disk_limit_bytes"), Some(limit as f64), "{rendered}");
        stop.send(()).await.unwrap();
        let done = tokio::time::timeout(Duration::from_secs(10), node).await;
        assert!(matches!(done, Ok(Ok(Ok(())))), "run did not return Ok after shutdown");
    }

    /// The start path makes a new data directory owner-only: it holds the node key and the
    /// store files.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_start_path_makes_a_new_data_directory_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let datadir = dir.path().join("new");
        let (stop, signals) = tokio::sync::mpsc::channel(1);
        drop(stop);
        run(offline_cfg(&datadir, 0), LiteMetrics::new(), signals).await.unwrap();
        let mode = std::fs::metadata(&datadir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{mode:o}");
    }

    /// The node logs its enode at start, so the operator can name it in `--trusted-peers` on the
    /// full node that `--peer` names.
    #[tokio::test]
    async fn the_start_logs_the_node_record_for_trusted_peers() {
        let dir = tempfile::tempdir().unwrap();
        let peer = "enode://6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0@127.0.0.1:1";
        let cfg = LiteConfig { peers: vec![peer.parse().unwrap()], ..offline_cfg(dir.path(), 0) };
        let (stop, signals) = tokio::sync::mpsc::channel(1);
        drop(stop);
        let logs = crate::testing::logs::capture(tracing::Level::INFO);
        run(cfg, LiteMetrics::new(), signals).await.unwrap();
        let key = std::fs::read_to_string(dir.path().join("nodekey")).unwrap();
        let key: reth_network::config::SecretKey = key.trim().parse().unwrap();
        let id = reth_network_peers::pk2id(&key.public_key());
        let text = logs.text();
        assert!(
            text.contains(&format!("enode://{}@", alloy_primitives::hex::encode(id))),
            "{text}"
        );
        assert!(text.contains("--trusted-peers"), "{text}");
    }

    /// The metrics server's limits in a test: connections at once, the time a connection may
    /// send no request, and the time it may stay open.
    struct Limits {
        max: usize,
        idle: Duration,
        life: Duration,
    }

    /// Starts a metrics server on loopback that renders `lite_test 1`, and returns its address.
    async fn metrics_server(limits: Limits) -> std::net::SocketAddr {
        metrics_server_on("127.0.0.1:0", limits).await
    }

    /// As [`metrics_server`], on `bind`.
    async fn metrics_server_on(bind: &str, limits: Limits) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || metrics::gauge!("lite_test").set(1.0));
        let limits = crate::rpc::MetricsLimits {
            max_connections: limits.max,
            idle_timeout: limits.idle,
            lifetime: limits.life,
        };
        let render = Arc::new(move || handle.render());
        crate::rpc::serve_metrics(listener, limits, render).unwrap().0
    }

    /// The answer to a GET with `host`, or `None` when the server sends nothing within 2 s.
    async fn get(addr: std::net::SocketAddr, host: &str) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = connect(addr).await;
        let req = format!("GET /metrics HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        conn.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), conn.read_to_end(&mut out))
            .await
            .ok()?
            .ok()?;
        Some(String::from_utf8_lossy(&out).into_owned())
    }

    async fn connect(addr: std::net::SocketAddr) -> tokio::net::TcpStream {
        for _ in 0..100 {
            if let Ok(conn) = tokio::net::TcpStream::connect(addr).await {
                return conn
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the metrics server does not listen on {addr}");
    }

    const LIMITS: Limits =
        Limits { max: 16, idle: Duration::from_secs(10), life: Duration::from_secs(30) };

    #[test]
    fn the_test_limits_are_the_real_defaults() {
        let real = crate::rpc::MetricsLimits::default();
        assert_eq!(
            (real.max_connections, real.idle_timeout, real.lifetime),
            (LIMITS.max, LIMITS.idle, LIMITS.life)
        );
    }

    /// A DNS-rebound page sends its own host name, as for the RPC.
    #[tokio::test]
    async fn the_metrics_server_refuses_a_foreign_host() {
        let addr = metrics_server(LIMITS).await;
        let local = get(addr, "localhost:9001").await.unwrap();
        assert!(local.starts_with("HTTP/1.1 200") && local.contains("lite_test 1"), "{local}");
        let foreign = get(addr, "evil.example").await.unwrap();
        assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
    }

    /// On a wildcard bind, a browser page that DNS-rebinds to the loopback address reaches the
    /// server there, so a connection to a loopback address has the `Host` check.
    #[tokio::test]
    async fn the_metrics_server_checks_the_host_on_loopback_under_a_wildcard_bind() {
        let port = metrics_server_on("0.0.0.0:0", LIMITS).await.port();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let foreign = get(addr, "attacker.example").await.unwrap();
        assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
        let local = get(addr, "localhost").await.unwrap();
        assert!(local.starts_with("HTTP/1.1 200") && local.contains("lite_test 1"), "{local}");
    }

    /// On a network address a scraper names the node by its DNS name, which the server cannot
    /// know, so the server takes any host there. A test host may have no network address, so
    /// this checks the rule that the server applies to each connection.
    #[test]
    fn the_metrics_server_takes_any_host_on_a_network_address() {
        use crate::rpc::metrics_checks_host;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert!(metrics_checks_host(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(metrics_checks_host(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(metrics_checks_host(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())));
        assert!(!metrics_checks_host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!metrics_checks_host(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped())));
        assert!(!metrics_checks_host("2001:db8::1".parse().unwrap()));
    }

    /// A connection that sends nothing is closed at the idle timeout. The lifetime is longer than
    /// the wait, so only the idle timeout can close it.
    #[tokio::test]
    async fn the_metrics_server_closes_an_idle_connection() {
        use tokio::io::AsyncReadExt;
        let idle = Duration::from_millis(300);
        let addr = metrics_server(Limits { idle, life: Duration::from_secs(60), ..LIMITS }).await;
        let mut conn = connect(addr).await;
        let mut buf = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "an idle connection stayed open");
    }

    /// A client that keeps sending a head a byte at a time is closed at the lifetime. The idle
    /// timeout is longer than the wait, so only the lifetime can close it.
    #[tokio::test]
    async fn the_metrics_server_closes_an_old_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let life = Duration::from_secs(1);
        let addr = metrics_server(Limits { idle: Duration::from_secs(60), life, ..LIMITS }).await;
        let mut conn = connect(addr).await;
        let mut buf = [0u8; 1];
        let started = std::time::Instant::now();
        let mut open = true;
        while open && started.elapsed() < Duration::from_secs(5) {
            open = conn.write_all(b"X").await.is_ok();
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(Ok(0) | Err(_)) =
                tokio::time::timeout(Duration::from_millis(1), conn.read(&mut buf)).await
            {
                open = false;
            }
        }
        assert!(!open, "a trickling connection stayed open past its lifetime");
    }

    /// Past the connection cap a new connection waits in the backlog until one closes.
    #[tokio::test]
    async fn the_metrics_server_serves_at_most_its_connection_cap() {
        let addr = metrics_server(Limits { max: 2, ..LIMITS }).await;
        let held = [connect(addr).await, connect(addr).await];
        assert_eq!(get(addr, "localhost").await, None, "a third connection was served");
        drop(held);
        let answer = get(addr, "localhost").await.expect("served after a connection closed");
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }

    #[tokio::test]
    async fn peer_confirmation_without_a_network_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = LiteConfig { head_confirm: HeadConfirm::Peer, ..offline_cfg(dir.path(), 0) };
        let (_stop, signals) = tokio::sync::mpsc::channel(1);
        let res =
            tokio::time::timeout(Duration::from_secs(10), run(cfg, LiteMetrics::new(), signals))
                .await
                .expect("run returned");
        assert_eq!(res.unwrap_err().to_string(), "--head.confirm=peer needs a --peer");
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..300 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// The fetcher runs over `AnyNet`, so a drop of a peer that gives no answers must reach the
    /// real network and end the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn any_net_forwards_a_drop_to_the_network() {
        let rt = reth_tasks::Runtime::test();
        let opts = |max_peers| NetOptions {
            chain_id: 369,
            key: reth_network::config::rng_secret_key(),
            statics: Vec::new(),
            discovery: true,
            max_peers,
            bootnodes: Some(Vec::new()),
            max_inbound: 4,
            discovery_interval: Some(Duration::from_millis(500)),
            dns: false,
            ban_for: BAN_FOR,
            snap_probe: None,
        };
        // B only accepts, so the two sides do not race their dials.
        let b = LiteNetwork::start_with(opts(0), rt.clone()).await.unwrap();
        let a = LiteNetwork::start_with(opts(4), rt).await.unwrap();
        let mut b_rec = b.local_record();
        b_rec.address = std::net::Ipv4Addr::LOCALHOST.into();
        a.connect(b_rec);
        wait_for("A to keep B", || a.peers() == vec![b_rec.id]).await;
        let net = AnyNet::Real(a.clone());
        Transport::drop_peer(&net, b_rec.id);
        wait_for("A to drop B", || a.peers().is_empty()).await;
    }
}
