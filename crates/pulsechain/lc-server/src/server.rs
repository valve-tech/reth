//! The server of one chain: the start checks, the tasks and the API.

use crate::{
    answers::{Answers, SelfCheckError},
    api::{self, Api},
    archive::{Archive, ANCHOR_FILE, STORE_FILE},
    checkpoint::CheckpointTask,
    config::Config,
    current_slot,
    head::HeadTask,
    upstream::{check_upstreams, Beacons, StartCheckError, Timeouts, Upstream},
    SECONDS_PER_SLOT,
};
use reth_pulsechain_forks::network::{pulsechain_network, PulsechainBeacon};
use reth_pulsechain_light_client::{
    checkpoint::{shipped_bootstrap, stale_days, Checkpoint, MAX_CHECKPOINT_AGE, REFRESH_HINT},
    derive::CheckedState,
    sync_committee::{LightClientBootstrap, LightClientStore, Preset},
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{net::TcpListener, task::JoinSet};
use tracing::{info, warn};

/// How often the tasks poll: once a slot.
pub const POLL: Duration = Duration::from_secs(SECONDS_PER_SLOT);
/// The epochs at the start of a period in which a self-check store that knows only the period
/// before may still start: the newest finalized checkpoint, about 2 epochs behind the head, can
/// still be in that period and give its period update.
pub const START_GRACE_EPOCHS: u64 = 4;

/// Why the server does not start.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The binary has no pins for the chain.
    #[error("unsupported chain {0}")]
    UnknownChain(u64),
    /// The start check of the upstreams' genesis failed.
    #[error(transparent)]
    Genesis(#[from] StartCheckError),
    /// A task ended. The tasks run until the server stops, so this is a bug.
    #[error("the {task} task ended{}", if *panicked { " with a panic" } else { "" })]
    TaskEnded {
        /// The task's name.
        task: &'static str,
        /// Whether it panicked.
        panicked: bool,
    },
    /// The archive did not open.
    #[error("cannot open the archive: {0}")]
    Archive(io::Error),
    /// The checkpoint gave no self-check store.
    #[error("{}", checkpoint_not_built(.checkpoint, .reason))]
    Checkpoint {
        /// The checkpoint.
        checkpoint: Checkpoint,
        /// What went wrong.
        reason: String,
    },
    /// The self-check store has no committee for the wall-clock slot's period, so it can check
    /// no checkpoint and the server would serve nothing new.
    #[error(transparent)]
    NotChained(SelfCheckError),
    /// The checkpoint's block is older than [`MAX_CHECKPOINT_AGE`].
    #[error("{}", stale_checkpoint(.checkpoint, *.slot, *.age_days))]
    StaleCheckpoint {
        /// The checkpoint.
        checkpoint: Checkpoint,
        /// Its block's slot.
        slot: u64,
        /// Its block's age in days, rounded up.
        age_days: u64,
    },
    /// The API address did not bind.
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// What went wrong.
        source: io::Error,
    },
}

/// A started server. Dropping it stops the tasks and the API.
#[derive(Debug)]
pub struct Server {
    /// The address the API listens on.
    pub addr: SocketAddr,
    /// The answers it serves.
    pub answers: Arc<Answers>,
    /// The tasks and the API. Dropping the set aborts them.
    tasks: JoinSet<()>,
    /// The name of each task, by its ID.
    names: HashMap<tokio::task::Id, &'static str>,
}

impl Server {
    /// Starts the server of `cfg` at the wall clock.
    pub async fn start(cfg: &Config) -> Result<Self, RunError> {
        Self::start_at(cfg, SystemTime::now()).await
    }

    /// Checks the upstreams' genesis against the pins of `cfg.chain`, opens the archive, starts
    /// the self-check store, and starts the checkpoint and head tasks and the API. `now` is the
    /// wall clock of the start checks.
    ///
    /// The self-check store is the saved one, when it checks out, is no older than a
    /// checkpoint may be, and has the committee of the wall clock's period once the archive's
    /// stored updates move it. Else it bootstraps at `cfg.checkpoint`, which must reach the
    /// wall clock's period the same way. The store is saved only once it does.
    ///
    /// A datadir with no anchor file writes one: the saved store that loaded, as from an older
    /// build, else the store bootstrapped at `cfg.checkpoint` once it reaches the wall clock's
    /// period.
    pub async fn start_at(cfg: &Config, now: SystemTime) -> Result<Self, RunError> {
        let pins = pulsechain_network(cfg.chain).ok_or(RunError::UnknownChain(cfg.chain))?.beacon;
        let preset = Preset::PULSECHAIN;
        let timeouts = Timeouts::default();
        let state_url = Upstream::new(cfg.state_url.clone(), timeouts);
        let beacon_urls: Vec<Upstream> =
            cfg.beacon_urls.iter().map(|url| Upstream::new(url.clone(), timeouts)).collect();
        check_upstreams(&state_url, &beacon_urls, &pins).await?;
        let pin = pinned_store(cfg.chain, preset, pins);
        let mut archive = Archive::open(&cfg.datadir, cfg.chain, preset, pins, pin)
            .await
            .map_err(RunError::Archive)?;
        let beacons = Beacons::new(preset, pins, beacon_urls);
        let slot = current_slot(&pins, now);
        let saved = match archive.load_store(now).await {
            Ok(Some(store)) => {
                archive.save_anchor(&store).await.map_err(RunError::Archive)?;
                let store = archive.check(store, slot).await.map_err(RunError::Archive)?;
                match reaches(preset, &store, slot) {
                    Ok(()) => {
                        if let Checkpoint::Flag(root) = cfg.checkpoint {
                            info!(target: "lc_server", %root, file = STORE_FILE, "--checkpoint is not used: the saved self-check store goes on; delete the file to bootstrap at the checkpoint, and at a new root move anchor.ssz away too");
                        }
                        Some(store)
                    }
                    Err(err) => {
                        warn!(target: "lc_server", file = STORE_FILE, %err, "the saved self-check store is not used; bootstrapping at the checkpoint");
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(err) => {
                warn!(target: "lc_server", file = STORE_FILE, %err, "the saved self-check store is not used; bootstrapping at the checkpoint");
                None
            }
        };
        let store = match saved {
            Some(store) => store,
            None => {
                let bootstrapped =
                    self_check_store(cfg.checkpoint, &archive, &state_url, &beacons, now).await?;
                let store =
                    archive.check(bootstrapped.clone(), slot).await.map_err(RunError::Archive)?;
                reaches(preset, &store, slot).map_err(RunError::NotChained)?;
                archive.save_anchor(&bootstrapped).await.map_err(RunError::Archive)?;
                warn_other_anchor(&archive, &bootstrapped);
                store
            }
        };
        archive.save_store(&store).await.map_err(RunError::Archive)?;
        info!(target: "lc_server", period = store.period(), slot = store.finalized_header().beacon.slot, "the self-check store starts");
        let answers = Arc::new(Answers::new(preset, pins, archive, store));
        let listener = TcpListener::bind(cfg.http_addr)
            .await
            .map_err(|source| RunError::Bind { addr: cfg.http_addr, source })?;
        let addr = listener
            .local_addr()
            .map_err(|source| RunError::Bind { addr: cfg.http_addr, source })?;

        let mut server = Self { addr, answers, tasks: JoinSet::new(), names: HashMap::new() };
        let answers = server.answers.clone();
        server.spawn(
            "checkpoint",
            CheckpointTask::new(answers.clone(), state_url, beacons.clone()).run(POLL),
        );
        server.spawn("head", HeadTask::new(answers.clone(), beacons.clone()).run(POLL));
        server.spawn("api", api::serve(listener, Arc::new(Api::new(answers, beacons))));
        info!(target: "lc_server", chain = cfg.chain, %addr, beacon_urls = cfg.beacon_urls.len(), "serving the light-client API");
        Ok(server)
    }

    /// Starts the task `name`.
    fn spawn(&mut self, name: &'static str, task: impl Future<Output = ()> + Send + 'static) {
        let id = self.tasks.spawn(task).id();
        self.names.insert(id, name);
    }

    /// Waits until `shutdown` resolves. A task that ends first is an error: the tasks run until
    /// the server stops, so the API would serve old answers.
    pub async fn wait(&mut self, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
        tokio::select! {
            () = shutdown => Ok(()),
            Some(ended) = self.tasks.join_next_with_id() => {
                let (id, panicked) = match ended {
                    Ok((id, ())) => (id, false),
                    Err(err) => (err.id(), err.is_panic()),
                };
                let task = self.names.get(&id).copied().unwrap_or("unknown");
                Err(RunError::TaskEnded { task, panicked })
            }
        }
    }
}

/// Returns the store bootstrapped at the pinned checkpoint of `chain`, from the bootstrap that
/// ships with it, which the archive checks its stored updates from too. `None` on a chain with
/// no pin.
///
/// The pin's age does not matter here, unlike for the self-check store: this store only checks
/// the signatures of updates that the server stored, and is never the server's head.
fn pinned_store(chain: u64, preset: Preset, pins: PulsechainBeacon) -> Option<LightClientStore> {
    let pin = pulsechain_network(chain)?.checkpoint?;
    let Some(bootstrap) = shipped_bootstrap(pin.root, preset) else {
        warn!(target: "lc_server", root = %pin.root, "no bootstrap ships at the pinned checkpoint: the archive serves only the stored updates that the anchor and the self-check store verify");
        return None
    };
    match LightClientStore::bootstrap(preset, pins, pin.root, &bootstrap) {
        Ok(store) => Some(store),
        Err(err) => {
            warn!(target: "lc_server", root = %pin.root, %err, "the bootstrap that ships at the pinned checkpoint does not check out: the archive serves only the stored updates that the anchor and the self-check store verify");
            None
        }
    }
}

/// Bootstraps the self-check store at `checkpoint`, which must be at most
/// [`MAX_CHECKPOINT_AGE`] old at `now`.
///
/// The bootstrap is the one that ships at the root, else the archive's, else one built from the
/// beacon URLs' block and the state URL's state at the root. Each is checked against the root.
pub async fn self_check_store(
    checkpoint: Checkpoint,
    archive: &Archive,
    state_url: &Upstream,
    beacons: &Beacons,
    now: SystemTime,
) -> Result<LightClientStore, RunError> {
    let (root, preset, pins) = (checkpoint.root(), archive.preset(), *beacons.pins());
    if let Checkpoint::Pinned(pin) = checkpoint {
        check_age(checkpoint, pin.slot, &pins, now)?;
    }
    let failed = |reason: String| RunError::Checkpoint { checkpoint, reason };
    let bootstrap = match shipped_bootstrap(root, preset) {
        Some(bootstrap) => bootstrap,
        None => match archive.bootstrap(root).await.map_err(|err| failed(err.to_string()))? {
            Some(bootstrap) => bootstrap,
            None => build_bootstrap(checkpoint, preset, state_url, beacons).await?,
        },
    };
    let store = LightClientStore::bootstrap(preset, pins, root, &bootstrap)
        .map_err(|err| failed(err.to_string()))?;
    // The header hashes to the root, so its slot is the checkpoint's real one.
    check_age(checkpoint, store.finalized_header().beacon.slot, &pins, now)?;
    info!(target: "lc_server", %root, slot = store.finalized_header().beacon.slot, "bootstrapped the self-check store at the checkpoint");
    Ok(store)
}

/// Warns when `bootstrapped`, the store a start bootstrapped, is at another root than the
/// anchor file's store. The anchor file stays, so its walk still serves the updates that the
/// old root verified, before the walk from the pin.
fn warn_other_anchor(archive: &Archive, bootstrapped: &LightClientStore) {
    let Some(anchor) = archive.anchor() else { return };
    let root = bootstrapped.finalized_header().beacon.hash_tree_root();
    let anchor_root = anchor.finalized_header().beacon.hash_tree_root();
    if root != anchor_root {
        warn!(target: "lc_server", %root, %anchor_root, file = ANCHOR_FILE, "the self-check store bootstrapped at another root than the anchor file's: the anchor's walk still serves the stored updates that its root verified; move anchor.ssz away to drop the old root's history, and the next start writes a new one");
    }
}

/// Refuses `store` when it cannot check a checkpoint at the wall-clock slot `current_slot`: it
/// has no committee for the slot's period, after the first [`START_GRACE_EPOCHS`] epochs of it.
/// Such a store would refuse every checkpoint, since no upstream gives a past period's update.
fn reaches(
    preset: Preset,
    store: &LightClientStore,
    current_slot: u64,
) -> Result<(), SelfCheckError> {
    let (period, store_period) = (preset.period_at_slot(current_slot), store.period());
    let next = period == store_period + 1;
    let early = preset.epoch_at_slot(current_slot) % preset.epochs_per_sync_committee_period() <
        START_GRACE_EPOCHS;
    if period <= store_period || next && (store.next_sync_committee().is_some() || early) {
        Ok(())
    } else {
        Err(SelfCheckError::NotChained { period, store_period })
    }
}

/// Builds the bootstrap at `checkpoint` from the beacon URLs' block and the state URL's state.
async fn build_bootstrap(
    checkpoint: Checkpoint,
    preset: Preset,
    state_url: &Upstream,
    beacons: &Beacons,
) -> Result<LightClientBootstrap, RunError> {
    let failed = |reason: String| RunError::Checkpoint { checkpoint, reason };
    let root = checkpoint.root();
    let f = beacons
        .block_by_root(root)
        .await
        .map_err(|err| failed(format!("block {root}: {err}")))?
        .ok_or_else(|| failed(format!("no beacon URL has block {root}")))?;
    let state = state_url
        .state(f.slot())
        .await
        .map_err(|err| failed(format!("the state at slot {}: {err}", f.slot())))?;
    let pins = *beacons.pins();
    let checked = tokio::task::spawn_blocking(move || CheckedState::new(preset, &pins, &f, &state))
        .await
        .map_err(|err| failed(err.to_string()))?
        .map_err(|err| failed(err.to_string()))?;
    Ok(checked.bootstrap())
}

/// Refuses `checkpoint` when the block at `slot` is older than [`MAX_CHECKPOINT_AGE`] at `now`.
fn check_age(
    checkpoint: Checkpoint,
    slot: u64,
    pins: &PulsechainBeacon,
    now: SystemTime,
) -> Result<(), RunError> {
    match stale_days(slot, pins, now) {
        None => Ok(()),
        Some(age_days) => Err(RunError::StaleCheckpoint { checkpoint, slot, age_days }),
    }
}

/// The text of [`RunError::StaleCheckpoint`].
fn stale_checkpoint(checkpoint: &Checkpoint, slot: u64, age_days: u64) -> String {
    let max = MAX_CHECKPOINT_AGE.as_secs() / 86_400;
    match checkpoint {
        Checkpoint::Pinned(pin) => format!(
            "the checkpoint pinned for this chain (slot {slot}, taken {}) is {age_days} days old, \
             more than the {max}-day limit, and there is no usable saved self-check store: use a \
             newer release, or give --checkpoint=<root> with a recent finalized block root you \
             trust ({REFRESH_HINT})",
            pin.taken
        ),
        Checkpoint::Flag(root) => format!(
            "--checkpoint={root:#x} is a block at slot {slot}, {age_days} days old, more than the \
             {max}-day limit: give a recent finalized block root you trust ({REFRESH_HINT})"
        ),
    }
}

/// The text of [`RunError::Checkpoint`].
fn checkpoint_not_built(checkpoint: &Checkpoint, reason: &str) -> String {
    let at = match checkpoint {
        Checkpoint::Pinned(pin) => format!(
            "the checkpoint pinned for this chain ({:#x}, slot {}, taken {})",
            pin.root, pin.slot, pin.taken
        ),
        Checkpoint::Flag(root) => format!("--checkpoint={root:#x}"),
    };
    format!(
        "no self-check store at {at}: {reason}. The server builds the bootstrap from the state \
         URL's state at the root, and a Checkpointz server keeps only about the last 16 epochs \
         of states: give --checkpoint=<root> with the state URL's current finalized root, if \
         you trust it ({REFRESH_HINT})"
    )
}

/// Logs to stderr at info level. Log lines never carry a URL: upstreams are named by host.
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
}

/// Serves `/metrics` on `addr`. Must run inside the tokio runtime.
pub fn install_metrics(addr: SocketAddr) -> Result<(), metrics_exporter_prometheus::BuildError> {
    metrics_exporter_prometheus::PrometheusBuilder::new().with_http_listener(addr).install()
}

/// Runs the server of `cfg` until `shutdown` resolves, or until a task ends.
pub async fn run(cfg: &Config, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
    let mut server = Server::start(cfg).await?;
    let result = server.wait(shutdown).await;
    info!(target: "lc_server", "stopping");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fake::{Fake, Rig, TestChain, PRESET},
        upstream::GenesisError,
    };
    use alloy_primitives::B256;
    use reth_pulsechain_forks::network::BeaconCheckpoint;
    use reth_pulsechain_light_client::json::PinError;
    use std::time::UNIX_EPOCH;
    use url::Url;

    fn pins(chain_id: u64) -> PulsechainBeacon {
        pulsechain_network(chain_id).unwrap().beacon
    }

    fn pin_369() -> BeaconCheckpoint {
        pulsechain_network(369).unwrap().checkpoint.unwrap()
    }

    /// The wall clock `after` the 369 pin's block, so the start checks do not depend on today.
    fn after_pin(after: Duration) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(pins(369).genesis_time + pin_369().slot * 10) + after
    }

    /// Starts the server of `cfg` a minute after the 369 pin's block.
    async fn start(cfg: &Config) -> Result<Server, RunError> {
        Server::start_at(cfg, after_pin(Duration::from_secs(60))).await
    }

    /// A URL where nothing listens.
    fn down() -> Url {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        drop(listener);
        url
    }

    fn config(datadir: &std::path::Path, state_url: Url, beacon_urls: Vec<Url>) -> Config {
        Config {
            chain: 369,
            beacon_urls,
            state_url,
            checkpoint: Checkpoint::Pinned(pin_369()),
            datadir: datadir.to_path_buf(),
            http_addr: "127.0.0.1:0".parse().unwrap(),
            metrics_addr: None,
        }
    }

    /// One beacon URL is down at start. The server starts with the one that answers, and keeps
    /// the other to check before its first use.
    #[tokio::test]
    async fn a_beacon_url_that_is_down_at_start_does_not_stop_it() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![down(), beacon.url()]);
        start(&cfg).await.unwrap();
    }

    /// A beacon URL on another chain stops the start; so does a state URL that does not answer,
    /// and a start with no beacon URL that answers.
    #[tokio::test]
    async fn the_start_check_refuses_a_mismatch_and_needs_answers() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let testnet = Fake::start(&pins(943)).await;
        let datadir = tempfile::tempdir().unwrap();

        let cfg = config(datadir.path(), state.url(), vec![beacon.url(), testnet.url()]);
        let err = start(&cfg).await.unwrap_err();
        assert!(
            matches!(
                &err,
                RunError::Genesis(StartCheckError::WrongChain(GenesisError {
                    error: PinError::GenesisValidatorsRoot { .. },
                    ..
                }))
            ),
            "{err}"
        );

        let cfg = config(datadir.path(), down(), vec![beacon.url()]);
        let err = start(&cfg).await.unwrap_err();
        assert!(matches!(&err, RunError::Genesis(StartCheckError::StateUrl(_))), "{err}");

        let cfg = config(datadir.path(), state.url(), vec![down(), down()]);
        let err = start(&cfg).await.unwrap_err();
        assert!(matches!(&err, RunError::Genesis(StartCheckError::NoBeaconUrl(_))), "{err}");
    }

    /// A task that ends, here by a panic, stops the server with an error that names it.
    #[tokio::test]
    async fn the_server_stops_when_a_task_ends() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let mut server =
            start(&config(datadir.path(), state.url(), vec![beacon.url()])).await.unwrap();
        server.spawn("test", async { panic!("a task bug") });
        let err = server.wait(std::future::pending()).await.unwrap_err();
        assert!(matches!(err, RunError::TaskEnded { task: "test", panicked: true }), "{err}");
        drop(server);

        let mut server =
            start(&config(datadir.path(), state.url(), vec![beacon.url()])).await.unwrap();
        server.wait(std::future::ready(())).await.unwrap();
    }

    /// The self-check store starts at the chain's pin, from the bootstrap that ships with it,
    /// and is saved. A restart goes on from the saved store, and `--checkpoint` is then not
    /// used.
    #[tokio::test]
    async fn the_store_starts_at_the_pin_and_a_restart_from_the_saved_store() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![beacon.url()]);
        let server = start(&cfg).await.unwrap();
        let slot = server.answers.store().finalized_header().beacon.slot;
        assert_eq!(slot, pin_369().slot);
        assert!(server.answers.archive().lock().await.is_verified());
        drop(server);
        assert!(datadir.path().join("369").join(STORE_FILE).exists());

        // No source has a bootstrap at this root, so only the saved store lets the server start.
        let cfg = Config { checkpoint: Checkpoint::Flag(B256::repeat_byte(7)), ..cfg };
        let logs = crate::fake::Logs::capture();
        let server = start(&cfg).await.unwrap();
        assert_eq!(server.answers.store().finalized_header().beacon.slot, pin_369().slot);
        assert!(logs
            .text()
            .contains("--checkpoint is not used: the saved self-check store goes on"));
        assert_eq!(beacon.calls(&format!("/eth/v2/beacon/blocks/{}", B256::repeat_byte(7))), 0);
    }

    /// The first start writes the store it bootstrapped at the pin as the anchor file. A
    /// datadir with a saved store and no anchor file, as an older build left it, writes the
    /// loaded store. A later start never writes the file again, even a damaged one, and starts.
    #[tokio::test]
    async fn a_start_writes_the_anchor_file_once() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![beacon.url()]);
        let (dir, anchor) = (datadir.path().join("369"), datadir.path().join("369/anchor.ssz"));
        drop(start(&cfg).await.unwrap());
        let saved = std::fs::read(dir.join(STORE_FILE)).unwrap();
        assert_eq!(std::fs::read(&anchor).expect("the first start writes it"), saved);

        std::fs::remove_file(&anchor).unwrap();
        drop(start(&cfg).await.unwrap());
        assert_eq!(std::fs::read(&anchor).expect("a start with a saved store writes it"), saved);

        std::fs::write(&anchor, b"damaged").unwrap();
        let logs = crate::fake::Logs::capture();
        drop(start(&cfg).await.unwrap());
        assert_eq!(std::fs::read(&anchor).unwrap(), b"damaged");
        assert!(logs.text().contains("the anchor file does not check out"), "{}", logs.text());
    }

    /// A store bootstrapped at another root than the anchor file's does not replace the file:
    /// the start warns with both roots and the way out. A bootstrap at the anchor's own root
    /// does not warn.
    #[tokio::test]
    async fn a_bootstrap_at_another_root_than_the_anchor_s_warns() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![beacon.url()]);
        let dir = datadir.path().join("369");
        drop(start(&cfg).await.unwrap());
        std::fs::remove_file(dir.join(STORE_FILE)).unwrap();
        let logs = crate::fake::Logs::capture();
        drop(start(&cfg).await.unwrap());
        assert!(!logs.text().contains("move anchor.ssz away"), "{}", logs.text());
        drop(logs);

        // An anchor file at another root: the pin's store with another proposer.
        let pin = pinned_store(369, PRESET_369, pins(369)).unwrap();
        let mut header = pin.finalized_header().clone();
        header.beacon.proposer_index += 1;
        let old_root = header.beacon.hash_tree_root();
        let old = LightClientStore::restore(
            PRESET_369,
            pins(369),
            header,
            pin.current_sync_committee().clone(),
            None,
        )
        .unwrap();
        std::fs::remove_file(dir.join("anchor.ssz")).unwrap();
        let mut archive =
            Archive::open(datadir.path(), 369, PRESET_369, pins(369), None).await.unwrap();
        assert!(archive.save_anchor(&old).await.unwrap());
        drop(archive);
        let anchor = std::fs::read(dir.join("anchor.ssz")).unwrap();

        std::fs::remove_file(dir.join(STORE_FILE)).unwrap();
        let logs = crate::fake::Logs::capture();
        drop(start(&cfg).await.unwrap());
        let text = logs.text();
        assert!(text.contains("move anchor.ssz away"), "{text}");
        assert!(text.contains(&format!("anchor_root={old_root}")), "{text}");
        assert!(text.contains(&format!("root={}", pin_369().root)), "{text}");
        assert_eq!(std::fs::read(dir.join("anchor.ssz")).unwrap(), anchor);
    }

    /// A start whose bootstrapped store does not reach the wall clock's period stops, and
    /// writes no anchor file: the next start writes it from the store that reaches.
    #[tokio::test]
    async fn a_start_that_is_not_chained_writes_no_anchor_file() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![beacon.url()]);
        let epoch = Duration::from_secs(PRESET_369.slots_per_epoch() * SECONDS_PER_SLOT);
        let late = after_pin(to_next_period() + START_GRACE_EPOCHS as u32 * epoch);
        let err = Server::start_at(&cfg, late).await.unwrap_err();
        assert!(matches!(err, RunError::NotChained(_)), "{err}");
        assert!(!datadir.path().join("369/anchor.ssz").exists());
    }

    /// With no saved store, a pin older than the age limit stops the start with the way to
    /// refresh it. So does a saved store that is as old: it is not used.
    #[tokio::test]
    async fn a_stale_pin_stops_the_start() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![beacon.url()]);
        let stale = after_pin(MAX_CHECKPOINT_AGE + Duration::from_secs(1));
        let err = Server::start_at(&cfg, stale).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "the checkpoint pinned for this chain (slot {}, taken {}) is 31 days old, more \
                 than the 30-day limit, and there is no usable saved self-check store: use a \
                 newer release, or give --checkpoint=<root> with a recent finalized block root \
                 you trust ({REFRESH_HINT})",
                pin_369().slot,
                pin_369().taken
            )
        );
        start(&cfg).await.unwrap();
        let err = Server::start_at(&cfg, stale).await.unwrap_err();
        assert!(matches!(err, RunError::StaleCheckpoint { age_days: 31, .. }), "{err}");
    }

    /// The time from the 369 pin's block to the start of the next sync-committee period.
    fn to_next_period() -> Duration {
        let next = (PRESET_369.period_at_slot(pin_369().slot) + 1) *
            PRESET_369.epochs_per_sync_committee_period() *
            PRESET_369.slots_per_epoch();
        Duration::from_secs((next - pin_369().slot) * SECONDS_PER_SLOT)
    }

    const PRESET_369: Preset = Preset::PULSECHAIN;

    /// A store at the pin knows only the pin period's committee, and no upstream gives the
    /// period's update once its states are gone. So once the newest checkpoint can be in the
    /// next period, a first start at the pin stops with the way out, and saves no store. In the
    /// first epochs of the next period it still starts.
    #[tokio::test]
    async fn a_first_start_after_the_pin_s_period_stops() {
        let (state, beacon) = (Fake::start(&pins(369)).await, Fake::start(&pins(369)).await);
        let datadir = tempfile::tempdir().unwrap();
        let cfg = config(datadir.path(), state.url(), vec![beacon.url()]);
        let epoch = Duration::from_secs(PRESET_369.slots_per_epoch() * SECONDS_PER_SLOT);
        let late = after_pin(to_next_period() + START_GRACE_EPOCHS as u32 * epoch);
        let pin_period = PRESET_369.period_at_slot(pin_369().slot);

        let err = Server::start_at(&cfg, late).await.unwrap_err();
        assert!(
            matches!(
                err,
                RunError::NotChained(SelfCheckError::NotChained { period, store_period })
                    if period == pin_period + 1 && store_period == pin_period
            ),
            "{err}"
        );
        assert!(err.to_string().starts_with(&format!(
            "the self-check store at period {pin_period} cannot check a checkpoint of period {}",
            pin_period + 1
        )));
        assert!(!datadir.path().join("369").join(STORE_FILE).exists());

        let early = after_pin(to_next_period() + epoch);
        Server::start_at(&cfg, early).await.unwrap();
        assert!(datadir.path().join("369").join(STORE_FILE).exists());

        // The saved store is as far behind, so it is not used: the start tries --checkpoint.
        let cfg = Config { checkpoint: Checkpoint::Flag(B256::repeat_byte(7)), ..cfg };
        let err = Server::start_at(&cfg, late).await.unwrap_err();
        assert!(matches!(err, RunError::Checkpoint { .. }), "{err}");
        assert_eq!(beacon.calls(&format!("/eth/v2/beacon/blocks/{}", B256::repeat_byte(7))), 1);
    }

    /// The archive's pin store on 369 is the store at the pin, from its shipped bootstrap. A
    /// chain with no pin has none.
    #[test]
    fn the_archive_pin_store_is_the_store_at_the_pin() {
        let pin = pinned_store(369, PRESET_369, pins(369)).unwrap();
        assert_eq!(pin.finalized_header().beacon.hash_tree_root(), pin_369().root);
        assert_eq!(pin.finalized_header().beacon.slot, pin_369().slot);
        assert!(pulsechain_network(943).unwrap().checkpoint.is_none());
        assert!(pinned_store(943, PRESET_369, pins(943)).is_none());
    }

    /// A store reaches its own period, the next one when it knows the next committee, and the
    /// first epochs of the next one when it does not. It never reaches two periods on.
    #[test]
    fn a_store_reaches_the_periods_whose_committee_it_can_learn() {
        let pin = pin_369();
        let bootstrap = shipped_bootstrap(pin.root, PRESET_369).unwrap();
        let store =
            LightClientStore::bootstrap(PRESET_369, pins(369), pin.root, &bootstrap).unwrap();
        let with_next = LightClientStore::restore(
            PRESET_369,
            pins(369),
            store.finalized_header().clone(),
            store.current_sync_committee().clone(),
            Some(store.current_sync_committee().clone()),
        )
        .unwrap();
        let period = store.period();
        let slots = PRESET_369.epochs_per_sync_committee_period() * PRESET_369.slots_per_epoch();
        let next_start = (period + 1) * slots;
        let grace_end = next_start + START_GRACE_EPOCHS * PRESET_369.slots_per_epoch();
        let behind =
            |period, store_period| Err(SelfCheckError::NotChained { period, store_period });
        for (slot, without, with) in [
            (pin.slot, Ok(()), Ok(())),
            (next_start - 1, Ok(()), Ok(())),
            (grace_end - 1, Ok(()), Ok(())),
            (grace_end, behind(period + 1, period), Ok(())),
            (next_start + slots, behind(period + 2, period), behind(period + 2, period)),
        ] {
            assert_eq!(reaches(PRESET_369, &store, slot), without, "slot {slot}");
            assert_eq!(reaches(PRESET_369, &with_next, slot), with, "slot {slot}, next known");
        }
    }

    /// `--checkpoint` bootstraps the store from the beacon URLs' block and the state URL's state
    /// at the root. A root whose state the state URL no longer has gives no store, and the error
    /// says what to do.
    #[tokio::test]
    async fn a_checkpoint_flag_bootstraps_from_the_state_url() {
        let mut chain = TestChain::new();
        chain.extend(64..88);
        chain.checkpoint(88, 72);
        chain.extend(89..92);
        let rig = Rig::start(&chain).await;
        let datadir = tempfile::tempdir().unwrap();
        let archive = Archive::open(datadir.path(), 1, PRESET, chain.pins, None).await.unwrap();
        let checkpoint = Checkpoint::Flag(chain.root(88));
        let now = SystemTime::now();
        let store =
            self_check_store(checkpoint, &archive, &rig.state.upstream(), &rig.beacons(), now)
                .await
                .unwrap();
        assert_eq!(store.finalized_header(), chain.at(88).header());
        assert_eq!(store.period(), PRESET.period_at_slot(88));

        rig.state.answer("/eth/v2/debug/beacon/states/88", crate::fake::Answer::status(404));
        let err =
            self_check_store(checkpoint, &archive, &rig.state.upstream(), &rig.beacons(), now)
                .await
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "no self-check store at --checkpoint={:#x}: the state at slot 88: http status \
                 404. The server builds the bootstrap from the state URL's state at the root, \
                 and a Checkpointz server keeps only about the last 16 epochs of states: give \
                 --checkpoint=<root> with the state URL's current finalized root, if you trust \
                 it ({REFRESH_HINT})",
                chain.root(88)
            )
        );
    }
}
