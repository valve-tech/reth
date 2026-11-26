//! The beacon API's light-client endpoints, and the checks `--head.verify=sync-committee` runs at
//! start.
//!
//! Each answer is bounded and read by [`reth_pulsechain_light_client::json`] into the
//! [`crate::sync_committee`] types. Nothing here checks a signature or a branch:
//! [`LightClientStore`] does that. The start checks compare
//! every source and the anchor with the pinned chain values, and fail closed when no source serves
//! the light-client data the store needs.
//!
//! The first bootstrap starts from a [`Checkpoint`]: the chain's pin in the network table, whose
//! bootstrap ships in the binary, or `--checkpoint`, whose bootstrap a source must serve. Only a
//! chain with neither bootstraps at the anchor's finalized root.

use crate::{
    beacon::{BeaconClient, SourceError, BLOCK_TIMEOUT, MAX_SMALL_BODY, SMALL_TIMEOUT},
    config::SLOT,
    sync_committee::{LightClientBootstrap, LightClientStore, LightClientUpdate, Preset},
};
use alloy_primitives::B256;
use reth_pulsechain_forks::network::PulsechainBeacon;
pub(crate) use reth_pulsechain_light_client::json::UpdateKind;
use reth_pulsechain_light_client::{
    checkpoint::{shipped_bootstrap, stale_days, REFRESH_HINT},
    json::{self, JsonError},
};
pub use reth_pulsechain_light_client::{
    checkpoint::{Checkpoint, MAX_CHECKPOINT_AGE},
    json::{Genesis, ScheduledFork},
};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// `/eth/v1/beacon/genesis`.
pub const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";
/// `/eth/v1/config/fork_schedule`.
pub const FORK_SCHEDULE_PATH: &str = "/eth/v1/config/fork_schedule";
/// `/eth/v1/beacon/light_client/bootstrap`, followed by `/{block_root}`.
pub const BOOTSTRAP_PATH: &str = "/eth/v1/beacon/light_client/bootstrap";
/// `/eth/v1/beacon/light_client/updates`, with `start_period` and `count`.
pub const UPDATES_PATH: &str = "/eth/v1/beacon/light_client/updates";
/// `/eth/v1/beacon/light_client/optimistic_update`.
pub const OPTIMISTIC_UPDATE_PATH: &str = "/eth/v1/beacon/light_client/optimistic_update";
/// `/eth/v1/beacon/light_client/finality_update`.
pub const FINALITY_UPDATE_PATH: &str = "/eth/v1/beacon/light_client/finality_update";

/// The largest bootstrap, and the largest share of an `updates` answer per update. Each holds a
/// committee of 512 keys, about 52 KB of JSON hex; the headers and branches add under 8 KB.
pub const MAX_LIGHT_CLIENT_BODY: usize = 256 << 10;
/// The most updates one `updates` request asks for. A store or a checkpoint at the age limit is
/// about 32 periods behind: two or three requests.
pub const MAX_UPDATES: usize = 16;

/// How a source or the anchor differs from the pinned chain values, or why it did not answer.
pub type PinError = json::PinError<SourceError>;

/// Refuses `checkpoint` when the block at `slot` is older than [`MAX_CHECKPOINT_AGE`] at `now`.
fn check_age(
    checkpoint: Checkpoint,
    slot: u64,
    pins: &PulsechainBeacon,
    now: SystemTime,
) -> Result<(), SyncCommitteeStartError> {
    match stale_days(slot, pins, now) {
        None => Ok(()),
        Some(age_days) => {
            Err(SyncCommitteeStartError::StaleCheckpoint { checkpoint, slot, age_days })
        }
    }
}

/// What the first store of a start comes from.
#[derive(Debug, Clone)]
pub enum StartFrom {
    /// The store file of an earlier run.
    Saved(Box<LightClientStore>),
    /// A bootstrap at a trusted root.
    Checkpoint(Checkpoint),
    /// A bootstrap at the anchor's finalized root, for a chain with no pin and no
    /// `--checkpoint`. The anchor alone then decides the first committee.
    Anchor,
}

impl From<JsonError> for SourceError {
    fn from(error: JsonError) -> Self {
        match error {
            JsonError::Malformed => Self::Body,
            JsonError::UnsupportedFork => Self::UnsupportedFork,
        }
    }
}

/// Why `--head.verify=sync-committee` does not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncCommitteeStartError {
    /// The finalized anchor differs from the pinned chain values, or did not answer.
    #[error("the finalized anchor {host} does not match the pinned chain values: {error}")]
    AnchorPins {
        /// The anchor's host label.
        host: String,
        /// How it differs.
        error: PinError,
    },
    /// The anchor did not give its finalized block root.
    #[error("the finalized anchor {host} did not answer {endpoint}: {error}")]
    AnchorRoot {
        /// The anchor's host label.
        host: String,
        /// The endpoint.
        endpoint: &'static str,
        /// What went wrong.
        error: SourceError,
    },
    /// Every beacon source differs from the pinned chain values.
    #[error("no beacon source matches the pinned chain values: {sources}")]
    NoSource {
        /// Each source's host label and how it differs.
        sources: String,
    },
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
    /// No source served a usable bootstrap at a [`Checkpoint`] root.
    #[error("{}", checkpoint_not_served(.checkpoint, .sources))]
    CheckpointNotServed {
        /// The checkpoint.
        checkpoint: Checkpoint,
        /// Each source's host label and what went wrong.
        sources: String,
    },
    /// No source served usable light-client data at this endpoint.
    #[error(
        "no beacon source served a usable {endpoint}: {sources}. Enable --light-client-server on \
         a lighthouse-pulse source (with light_client/updates support), or use \
         --head.verify=quorum"
    )]
    NotServed {
        /// The endpoint.
        endpoint: &'static str,
        /// Each source's host label and what went wrong.
        sources: String,
    },
}

/// The text of [`SyncCommitteeStartError::StaleCheckpoint`].
fn stale_checkpoint(checkpoint: &Checkpoint, slot: u64, age_days: u64) -> String {
    let max = MAX_CHECKPOINT_AGE.as_secs() / 86_400;
    match checkpoint {
        Checkpoint::Pinned(pin) => format!(
            "the checkpoint pinned for this chain (slot {slot}, taken {}) is {age_days} days old, \
             more than the {max}-day limit: use a newer reth-lite release, or give \
             --checkpoint=<root> with a recent finalized block root you trust ({REFRESH_HINT})",
            pin.taken
        ),
        Checkpoint::Flag(root) => format!(
            "--checkpoint={root:#x} is a block at slot {slot}, {age_days} days old, more than the \
             {max}-day limit: give a recent finalized block root you trust ({REFRESH_HINT})"
        ),
    }
}

/// The text of [`SyncCommitteeStartError::CheckpointNotServed`].
fn checkpoint_not_served(checkpoint: &Checkpoint, sources: &str) -> String {
    let at = match checkpoint {
        Checkpoint::Pinned(pin) => format!(
            "the checkpoint pinned for this chain ({:#x}, slot {}, taken {})",
            pin.root, pin.slot, pin.taken
        ),
        Checkpoint::Flag(root) => format!("--checkpoint={root:#x}"),
    };
    format!(
        "no beacon source served a usable {BOOTSTRAP_PATH} at {at}: {sources}. lighthouse-pulse \
         builds a bootstrap from the block's state and prunes that state about one epoch after \
         the block is finalized, so a source may hold no bootstrap for a root this old: give \
         --checkpoint=<root> with the source's current finalized root ({REFRESH_HINT})"
    )
}

/// Where the store of a start came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOrigin {
    /// A bootstrap at the anchor's finalized block root. The store is only as good as that root:
    /// the follower's seed checks cover the execution block under it, not the committee.
    Bootstrap {
        /// The anchor's finalized block root.
        anchor_root: B256,
    },
    /// A bootstrap at a trusted [`Checkpoint`]. Like a saved store, it seeds from its own
    /// verified finality, not from the anchor.
    Checkpoint {
        /// The checkpoint's block root.
        root: B256,
    },
    /// The store file of an earlier run. Its finalized header was verified then, so the anchor
    /// is not trusted again.
    Saved,
}

/// What the start checks of `--head.verify=sync-committee` hand to the follower.
#[derive(Debug, Clone)]
pub struct SyncCommitteeStart {
    /// The indices of the sources that match the pinned chain values or did not answer them, in
    /// the given order.
    pub sources: Vec<usize>,
    /// The indices of the sources that did not answer the pinned chain values. The follower
    /// checks them again before it uses them.
    pub unchecked: Vec<usize>,
    /// Where `store` came from.
    pub origin: StoreOrigin,
    /// The store the follower verifies updates with.
    pub store: LightClientStore,
}

impl SyncCommitteeStart {
    /// The positions in `sources` of the unchecked sources: their indices among the follower's
    /// beacon URLs, which are the URLs of `sources`.
    pub fn unchecked_positions(&self) -> Vec<usize> {
        self.sources
            .iter()
            .enumerate()
            .filter(|(_, idx)| self.unchecked.contains(idx))
            .map(|(pos, _)| pos)
            .collect()
    }
}

impl BeaconClient {
    /// The source's genesis values (`/eth/v1/beacon/genesis`).
    pub async fn genesis(&self) -> Result<Genesis, SourceError> {
        let body = self.small_body(GENESIS_PATH, None).await?;
        Ok(json::parse_genesis(&body)?)
    }

    /// The source's fork schedule (`/eth/v1/config/fork_schedule`).
    pub async fn fork_schedule(&self) -> Result<Vec<ScheduledFork>, SourceError> {
        let body = self.small_body(FORK_SCHEDULE_PATH, None).await?;
        Ok(json::parse_fork_schedule(&body)?)
    }

    /// The root of block `id` (`/eth/v1/beacon/blocks/{id}/root`), unless the source has not
    /// validated its payload. For `finalized`, a source that marks the block not finalized is
    /// refused.
    pub async fn block_root(&self, id: &str) -> Result<B256, SourceError> {
        let body = self.small_body(&format!("/eth/v1/beacon/blocks/{id}/root"), None).await?;
        let answer: RootAnswer = serde_json::from_slice(&body).map_err(|_| SourceError::Body)?;
        if answer.execution_optimistic == Some(true) {
            return Err(SourceError::Optimistic);
        }
        if id == "finalized" && answer.finalized == Some(false) {
            return Err(SourceError::NotFinalized);
        }
        Ok(answer.data.root)
    }

    /// The bootstrap at block `root`, for a committee of `preset`'s size.
    pub async fn light_client_bootstrap(
        &self,
        root: B256,
        preset: Preset,
    ) -> Result<LightClientBootstrap, SourceError> {
        let path = format!("{BOOTSTRAP_PATH}/{root:#x}");
        let body =
            self.get_body(&path, None, MAX_LIGHT_CLIENT_BODY, SMALL_TIMEOUT, BLOCK_TIMEOUT).await?;
        parse_bootstrap(&body, preset)
    }

    /// At most `count` updates from period `start_period` on, `count` capped at [`MAX_UPDATES`].
    /// An answer with more updates than asked for is refused.
    pub async fn light_client_updates(
        &self,
        start_period: u64,
        count: usize,
        preset: Preset,
    ) -> Result<Vec<LightClientUpdate>, SourceError> {
        let count = count.clamp(1, MAX_UPDATES);
        let query = format!("start_period={start_period}&count={count}");
        let limit = count * MAX_LIGHT_CLIENT_BODY;
        let body =
            self.get_body(UPDATES_PATH, Some(&query), limit, SMALL_TIMEOUT, BLOCK_TIMEOUT).await?;
        parse_updates(&body, preset, count)
    }

    /// The latest optimistic update, as an update with no finality and no next committee.
    pub async fn light_client_optimistic_update(
        &self,
        preset: Preset,
    ) -> Result<LightClientUpdate, SourceError> {
        let body = self.small_body(OPTIMISTIC_UPDATE_PATH, None).await?;
        parse_update(&body, preset, UpdateKind::Optimistic)
    }

    /// The latest finality update, as an update with no next committee.
    pub async fn light_client_finality_update(
        &self,
        preset: Preset,
    ) -> Result<LightClientUpdate, SourceError> {
        let body = self.small_body(FINALITY_UPDATE_PATH, None).await?;
        parse_update(&body, preset, UpdateKind::Finality)
    }

    /// The body of a small answer: at most [`MAX_SMALL_BODY`] within [`SMALL_TIMEOUT`].
    async fn small_body(&self, path: &str, query: Option<&str>) -> Result<Vec<u8>, SourceError> {
        self.get_body(path, query, MAX_SMALL_BODY, SMALL_TIMEOUT, SMALL_TIMEOUT).await
    }
}

/// Checks a source's genesis and fork schedule against `pins`, as [`json::check_pins`] does.
pub fn check_pins(
    genesis: &Genesis,
    schedule: &[ScheduledFork],
    pins: &PulsechainBeacon,
) -> Result<(), PinError> {
    json::check_pins(genesis, schedule, pins)
}

/// Reads a source's genesis and fork schedule and checks them against `pins`.
pub(crate) async fn source_pins(
    client: &BeaconClient,
    pins: &PulsechainBeacon,
) -> Result<(), PinError> {
    let unreadable = |endpoint| move |error| PinError::Unreadable { endpoint, error };
    let genesis = client.genesis().await.map_err(unreadable(GENESIS_PATH))?;
    let schedule = client.fork_schedule().await.map_err(unreadable(FORK_SCHEDULE_PATH))?;
    check_pins(&genesis, &schedule, pins)
}

/// The start checks of `--head.verify=sync-committee`. Fails closed.
///
/// Each source must match `pins`. A source that differs is dropped, and the log names its host
/// label. A source that does not answer is kept as unchecked: one timeout must not drop an honest
/// source for good. At least one source must match.
///
/// The first store comes from `from`. A saved store (from [`crate::sync_committee_file`]) is used
/// as it is. A [`Checkpoint`] must be at most [`MAX_CHECKPOINT_AGE`] old at `now`, and one source
/// must serve a bootstrap at its root that [`LightClientStore::bootstrap`] accepts. In both cases
/// the anchor is not asked anything. With [`StartFrom::Anchor`] the anchor must match the pins
/// too, and the bootstrap is at its finalized root. One source must then serve `updates` for the
/// store's period. When a saved or checkpoint store is behind the wall clock's period, the answer
/// must hold an update signed in the store's period. Otherwise the error names the endpoint and
/// each source's host label.
pub async fn check_sync_committee_start(
    clients: &[BeaconClient],
    anchor: &BeaconClient,
    pins: PulsechainBeacon,
    preset: Preset,
    from: StartFrom,
    now: SystemTime,
) -> Result<SyncCommitteeStart, SyncCommitteeStartError> {
    if let StartFrom::Checkpoint(checkpoint @ Checkpoint::Pinned(pin)) = &from {
        check_age(*checkpoint, pin.slot, &pins, now)?;
    }
    let anchor_pins = async {
        match &from {
            StartFrom::Anchor => source_pins(anchor, &pins).await,
            StartFrom::Saved(_) | StartFrom::Checkpoint(_) => Ok(()),
        }
    };
    let (anchor_pins, source_pins) = futures::join!(
        anchor_pins,
        futures::future::join_all(clients.iter().map(|c| source_pins(c, &pins)))
    );
    if let Err(error) = anchor_pins {
        return Err(SyncCommitteeStartError::AnchorPins { host: anchor.host().to_owned(), error });
    }
    let (mut sources, mut matched, mut unchecked) = (Vec::new(), Vec::new(), Vec::new());
    let mut dropped = Vec::new();
    for (idx, (client, checked)) in clients.iter().zip(source_pins).enumerate() {
        match checked {
            Ok(()) => {
                sources.push(idx);
                matched.push(idx);
            }
            Err(error @ PinError::Unreadable { .. }) => {
                tracing::warn!(
                    source = client.host(),
                    %error,
                    "the beacon source did not answer the pinned chain values; it is kept and \
                     checked again before it is used"
                );
                sources.push(idx);
                unchecked.push(idx);
                dropped.push(format!("{}: {error}", client.host()));
            }
            Err(error) => {
                tracing::error!(
                    source = client.host(),
                    %error,
                    "the beacon source does not match the pinned chain values; it is dropped"
                );
                dropped.push(format!("{}: {error}", client.host()));
            }
        }
    }
    if matched.is_empty() {
        return Err(SyncCommitteeStartError::NoSource { sources: dropped.join("; ") });
    }

    let (origin, store) = match from {
        StartFrom::Saved(store) => (StoreOrigin::Saved, *store),
        StartFrom::Checkpoint(checkpoint) => {
            let root = checkpoint.root();
            let shipped = shipped_bootstrap(root, preset).map(|bootstrap| {
                LightClientStore::bootstrap(preset, pins, root, &bootstrap).inspect_err(|error| {
                    tracing::error!(%root, %error, "the shipped light-client bootstrap is refused")
                })
            });
            let store = match shipped {
                Some(Ok(store)) => store,
                Some(Err(_)) | None => bootstrap_at_root(clients, &matched, root, pins, preset)
                    .await
                    .map_err(|sources| SyncCommitteeStartError::CheckpointNotServed {
                        checkpoint,
                        sources,
                    })?,
            };
            // The header hashes to the root, so its slot is the checkpoint's real one.
            check_age(checkpoint, store.finalized_header().beacon.slot, &pins, now)?;
            (StoreOrigin::Checkpoint { root }, store)
        }
        StartFrom::Anchor => {
            tracing::warn!(
                anchor = anchor.host(),
                "no checkpoint is pinned for this chain and no --checkpoint is given: the first \
                 sync committee trusts the anchor's finalized root"
            );
            bootstrap_at_anchor(clients, &matched, anchor, pins, preset).await?
        }
    };

    let period = store.period();
    // A saved or checkpoint store behind the wall clock learns its next committee only from an
    // update of its own period. lighthouse-pulse skips a period it holds no update for, so `[]`
    // or a later period first means the store could never leave its period. An anchor bootstrap
    // is at the current finality, and is bootstrapped again when it cannot seed.
    let now_slot = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(pins.genesis_time) /
        SLOT.as_secs();
    let needs_period = !matches!(origin, StoreOrigin::Bootstrap { .. }) &&
        period < preset.period_at_slot(now_slot);
    let mut failures = Vec::new();
    let mut served = false;
    for &idx in &matched {
        let client = &clients[idx];
        match client.light_client_updates(period, 1, preset).await {
            Ok(updates)
                if needs_period &&
                    updates
                        .first()
                        .is_none_or(|u| preset.period_at_slot(u.signature_slot) != period) =>
            {
                tracing::warn!(
                    source = client.host(),
                    period,
                    "no light-client update for the period"
                );
                failures.push(format!("{}: no update for period {period}", client.host()));
            }
            Ok(_) => {
                served = true;
                break;
            }
            Err(error) => {
                tracing::warn!(source = client.host(), %error, period, "no light-client updates");
                failures.push(format!("{}: {error}", client.host()));
            }
        }
    }
    if !served {
        return Err(SyncCommitteeStartError::NotServed {
            endpoint: UPDATES_PATH,
            sources: failures.join("; "),
        });
    }
    tracing::info!(
        sources = sources.len(),
        unchecked = unchecked.len(),
        period,
        slot = store.finalized_header().beacon.slot,
        origin = ?origin,
        "sync-committee start checks passed"
    );
    Ok(SyncCommitteeStart { sources, unchecked, origin, store })
}

/// Bootstraps a store at the anchor's finalized root from the first of `sources` that serves a
/// bootstrap the store accepts.
pub(crate) async fn bootstrap_at_anchor(
    clients: &[BeaconClient],
    sources: &[usize],
    anchor: &BeaconClient,
    pins: PulsechainBeacon,
    preset: Preset,
) -> Result<(StoreOrigin, LightClientStore), SyncCommitteeStartError> {
    let root_path = "/eth/v1/beacon/blocks/finalized/root";
    let anchor_root = anchor.block_root("finalized").await.map_err(|error| {
        SyncCommitteeStartError::AnchorRoot {
            host: anchor.host().to_owned(),
            endpoint: root_path,
            error,
        }
    })?;
    let store = bootstrap_at_root(clients, sources, anchor_root, pins, preset).await.map_err(
        |sources| SyncCommitteeStartError::NotServed { endpoint: BOOTSTRAP_PATH, sources },
    )?;
    Ok((StoreOrigin::Bootstrap { anchor_root }, store))
}

/// Bootstraps a store at `root` from the first of `sources` that serves a bootstrap the store
/// accepts. Otherwise gives each source's host label and what went wrong.
async fn bootstrap_at_root(
    clients: &[BeaconClient],
    sources: &[usize],
    root: B256,
    pins: PulsechainBeacon,
    preset: Preset,
) -> Result<LightClientStore, String> {
    let mut failures = Vec::new();
    for &idx in sources {
        let client = &clients[idx];
        let verified = match client.light_client_bootstrap(root, preset).await {
            Ok(bootstrap) => LightClientStore::bootstrap(preset, pins, root, &bootstrap)
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match verified {
            Ok(store) => return Ok(store),
            Err(error) => {
                tracing::warn!(source = client.host(), %error, "no usable light-client bootstrap");
                failures.push(format!("{}: {error}", client.host()));
            }
        }
    }
    Err(failures.join("; "))
}

/// Parses a `bootstrap` answer.
pub(crate) fn parse_bootstrap(
    bytes: &[u8],
    preset: Preset,
) -> Result<LightClientBootstrap, SourceError> {
    Ok(json::parse_bootstrap(bytes, preset)?)
}

/// Parses an `updates` answer of at most `count` updates.
pub(crate) fn parse_updates(
    bytes: &[u8],
    preset: Preset,
    count: usize,
) -> Result<Vec<LightClientUpdate>, SourceError> {
    Ok(json::parse_updates(bytes, preset, count)?)
}

/// Parses one update answer of `kind`: a REST answer or the data of an event.
pub(crate) fn parse_update(
    bytes: &[u8],
    preset: Preset,
    kind: UpdateKind,
) -> Result<LightClientUpdate, SourceError> {
    Ok(json::parse_update(bytes, preset, kind)?)
}

#[derive(Deserialize)]
struct RootAnswer {
    execution_optimistic: Option<bool>,
    finalized: Option<bool>,
    data: RootJson,
}

#[derive(Deserialize)]
struct RootJson {
    root: B256,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        beacon::{parse_sse_block, Event, Topics},
        fake_beacon::Fake,
        sync_committee::{
            test_utils::{hash, Real369},
            BeaconBlockHeader, Gindices, SyncAggregate,
        },
    };
    use alloy_primitives::hex;
    use reth_pulsechain_forks::network::{BeaconCheckpoint, BeaconFork};
    use reth_pulsechain_light_client::json::test_utils::{as_kind, capella_case};
    use serde_json::{json, Value};
    use std::time::Duration;

    /// The all-zero branch of `gindex`, which marks a field an update does not carry.
    fn zero_branch(gindex: u64) -> Vec<B256> {
        vec![B256::ZERO; gindex.ilog2() as usize]
    }

    pub(crate) fn pins_369() -> PulsechainBeacon {
        reth_pulsechain_forks::network::pulsechain_network(369).unwrap().beacon
    }

    /// A beacon API number.
    pub(crate) fn n(value: u64) -> Value {
        Value::String(value.to_string())
    }

    pub(crate) fn bootstrap_json(b: &LightClientBootstrap, fork: BeaconFork) -> Value {
        json::bootstrap_json(b, fork).unwrap()
    }

    /// An update as the endpoint for `kind` sends it: without the fields `kind` does not carry.
    pub(crate) fn update_json(u: &LightClientUpdate, kind: UpdateKind) -> Value {
        json::update_json(u, BeaconFork::Capella, kind).unwrap()
    }

    fn real_369_bootstrap_json() -> (B256, Value) {
        let real = Real369::load();
        let root = hash(&real.json["block_root"]);
        (root, bootstrap_json(&real.bootstrap(), BeaconFork::Capella))
    }

    pub(crate) fn genesis_json(pins: &PulsechainBeacon) -> Value {
        json!({ "data": {
            "genesis_time": n(pins.genesis_time),
            "genesis_validators_root": pins.genesis_validators_root,
            "genesis_fork_version": hex::encode_prefixed(pins.forks[0].version),
        }})
    }

    /// A fork schedule as Checkpointz sends it for 369: the pinned forks, then Deneb and Electra
    /// at `FAR_FUTURE_EPOCH`.
    pub(crate) fn fork_schedule_json(pins: &PulsechainBeacon) -> Value {
        let mut previous = pins.forks[0].version;
        let mut forks: Vec<Value> = pins
            .forks
            .iter()
            .map(|f| {
                let entry = json!({
                    "previous_version": hex::encode_prefixed(previous),
                    "current_version": hex::encode_prefixed(f.version),
                    "epoch": n(f.epoch),
                });
                previous = f.version;
                entry
            })
            .collect();
        for version in ["0xffffffff", "0xffffffff"] {
            forks.push(json!({
                "previous_version": version,
                "current_version": version,
                "epoch": n(u64::MAX),
            }));
        }
        json!({ "data": forks })
    }

    pub(crate) fn serve_pins(fake: &Fake, genesis: &Value, schedule: &Value) {
        fake.answer(GENESIS_PATH, "200 OK", genesis.to_string());
        fake.answer(FORK_SCHEDULE_PATH, "200 OK", schedule.to_string());
    }

    /// The real 369 period: slot 11167808 is in period 1363.
    const REAL_PERIOD_UPDATES: &str =
        "/eth/v1/beacon/light_client/updates?start_period=1363&count=1";

    /// A beacon source with the 369 pins and, when `light_client`, the real 369 bootstrap and an
    /// `updates` answer for its period.
    pub(crate) async fn pinned_source(light_client: bool) -> Fake {
        let fake = Fake::start(false, false).await;
        let pins = pins_369();
        serve_pins(&fake, &genesis_json(&pins), &fork_schedule_json(&pins));
        if light_client {
            let (root, bootstrap) = real_369_bootstrap_json();
            fake.answer(&format!("{BOOTSTRAP_PATH}/{root:#x}"), "200 OK", bootstrap.to_string());
            let updates = json!([real_369_update_json(real_369_slot() + 1)]);
            fake.answer(REAL_PERIOD_UPDATES, "200 OK", updates.to_string());
        }
        fake
    }

    /// An update over the real 369 block signed at `signature_slot`, as `updates` sends it. Its
    /// signature and branches are not real: the start checks read an update, they do not verify
    /// it.
    fn real_369_update_json(signature_slot: u64) -> Value {
        let real = Real369::load().bootstrap();
        let gindices = Gindices::for_fork(BeaconFork::Capella).unwrap();
        let update = LightClientUpdate {
            attested_header: real.header.clone(),
            next_sync_committee: real.current_sync_committee,
            next_sync_committee_branch: zero_branch(gindices.next_sync_committee),
            finalized_header: real.header,
            finality_branch: zero_branch(gindices.finalized_root),
            sync_aggregate: SyncAggregate::from_ssz_bytes(&[0; 64 + 96], Preset::PULSECHAIN)
                .unwrap(),
            signature_slot,
        };
        update_json(&update, UpdateKind::Full)
    }

    /// An anchor with the 369 pins whose finalized root is the real 369 block.
    pub(crate) async fn pinned_anchor() -> Fake {
        let fake = Fake::start(false, true).await;
        let pins = pins_369();
        serve_pins(&fake, &genesis_json(&pins), &fork_schedule_json(&pins));
        let (root, _) = real_369_bootstrap_json();
        let answer =
            json!({"execution_optimistic": false, "finalized": true, "data": {"root": root}});
        fake.answer("/eth/v1/beacon/blocks/finalized/root", "200 OK", answer.to_string());
        fake
    }

    async fn start(
        sources: &[&Fake],
        anchor: &Fake,
    ) -> Result<SyncCommitteeStart, SyncCommitteeStartError> {
        let clients: Vec<BeaconClient> =
            sources.iter().map(|f| BeaconClient::new(f.beacon_url())).collect();
        let anchor = BeaconClient::new(anchor.anchor_url());
        check_sync_committee_start(
            &clients,
            &anchor,
            pins_369(),
            Preset::PULSECHAIN,
            StartFrom::Anchor,
            SystemTime::now(),
        )
        .await
    }

    /// Runs the start checks with `checkpoint` against `source`, at `days` and `secs` after the
    /// real 369 block. The anchor answers nothing.
    async fn start_at_checkpoint(
        source: &Fake,
        anchor: &Fake,
        checkpoint: Checkpoint,
        days: u64,
        secs: u64,
    ) -> Result<SyncCommitteeStart, SyncCommitteeStartError> {
        let clients = [BeaconClient::new(source.beacon_url())];
        let block_time = pins_369().genesis_time + real_369_slot() * 10;
        let now = UNIX_EPOCH + Duration::from_secs(block_time + days * 86_400 + secs);
        check_sync_committee_start(
            &clients,
            &BeaconClient::new(anchor.anchor_url()),
            pins_369(),
            Preset::PULSECHAIN,
            StartFrom::Checkpoint(checkpoint),
            now,
        )
        .await
    }

    fn real_369_slot() -> u64 {
        Real369::load().bootstrap().header.beacon.slot
    }

    /// The real 369 block as a pin taken on its day.
    fn real_369_pin() -> Checkpoint {
        let (root, _) = real_369_bootstrap_json();
        Checkpoint::Pinned(BeaconCheckpoint { root, slot: real_369_slot(), taken: "2026-11-23" })
    }

    /// A pin bootstraps the first store at its root. The anchor answers nothing here, and is not
    /// asked: it does not decide the first committee.
    #[tokio::test]
    async fn a_pinned_checkpoint_is_used_over_the_anchor() {
        let (source, anchor) = (pinned_source(true).await, Fake::start(false, true).await);
        let started = start_at_checkpoint(&source, &anchor, real_369_pin(), 1, 0).await.unwrap();
        let (root, _) = real_369_bootstrap_json();
        assert_eq!(started.origin, StoreOrigin::Checkpoint { root });
        assert_eq!(started.store.finalized_header().beacon.hash_tree_root(), root);
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");
        assert_eq!(source.calls(&format!("{BOOTSTRAP_PATH}/{root:#x}")), 1);
        assert_eq!(source.calls(UPDATES_PATH), 1);
    }

    /// A pin older than the limit is refused before any request, with the way to refresh it.
    /// One at the limit is still used.
    #[tokio::test]
    async fn a_stale_pin_is_refused_with_how_to_refresh_it() {
        let (source, anchor) = (pinned_source(true).await, Fake::start(false, true).await);
        let err = start_at_checkpoint(&source, &anchor, real_369_pin(), 30, 1).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "the checkpoint pinned for this chain (slot 11167808, taken 2026-11-23) is 31 days \
             old, more than the 30-day limit: use a newer reth-lite release, or give \
             --checkpoint=<root> with a recent finalized block root you trust \
             (crates/pulsechain/lite/scripts/checkpoint-root.sh <beacon-url> <check-url> in the \
             reth source prints a recent finalized root and checks it against a second source)"
        );
        assert!(source.state.lock().calls.is_empty(), "a source was asked");
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");
        assert!(start_at_checkpoint(&source, &anchor, real_369_pin(), 30, 0).await.is_ok());
    }

    /// `--checkpoint` gives a root only: the bootstrap header it proves gives the slot, and so
    /// the age.
    #[tokio::test]
    async fn a_checkpoint_flag_is_used_and_its_bootstrap_header_gives_its_age() {
        let (source, anchor) = (pinned_source(true).await, Fake::start(false, true).await);
        let (root, _) = real_369_bootstrap_json();
        let started =
            start_at_checkpoint(&source, &anchor, Checkpoint::Flag(root), 2, 0).await.unwrap();
        assert_eq!(started.origin, StoreOrigin::Checkpoint { root });
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");

        let err =
            start_at_checkpoint(&source, &anchor, Checkpoint::Flag(root), 45, 0).await.unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeStartError::StaleCheckpoint {
                checkpoint: Checkpoint::Flag(root),
                slot: 11_167_808,
                age_days: 45,
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "--checkpoint={root:#x} is a block at slot 11167808, 45 days old, more than the \
                 30-day limit: give a recent finalized block root you trust \
                 (crates/pulsechain/lite/scripts/checkpoint-root.sh <beacon-url> <check-url> in \
                 the reth source prints a recent finalized root and checks it against a second \
                 source)"
            )
        );
    }

    /// A checkpoint that no source serves a bootstrap for fails the start; the anchor's root is
    /// not used instead. The error names the root, says why a source may not hold it, and does
    /// not point to quorum mode.
    #[tokio::test]
    async fn a_checkpoint_without_a_bootstrap_does_not_fall_back_to_the_anchor() {
        let (source, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let root = B256::repeat_byte(7);
        let err =
            start_at_checkpoint(&source, &anchor, Checkpoint::Flag(root), 1, 0).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "no beacon source served a usable {BOOTSTRAP_PATH} at --checkpoint={root:#x}: \
                 http://127.0.0.1: http status 404. lighthouse-pulse builds a bootstrap from the \
                 block's state and prunes that state about one epoch after the block is \
                 finalized, so a source may hold no bootstrap for a root this old: give \
                 --checkpoint=<root> with the source's current finalized root \
                 (crates/pulsechain/lite/scripts/checkpoint-root.sh <beacon-url> <check-url> in \
                 the reth source prints a recent finalized root and checks it against a second \
                 source)"
            )
        );
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");

        // A pin with no bootstrap in the binary names the pin.
        let pin = BeaconCheckpoint { root, slot: real_369_slot(), taken: "2026-11-23" };
        let err = start_at_checkpoint(&source, &anchor, Checkpoint::Pinned(pin), 1, 0)
            .await
            .unwrap_err()
            .to_string();
        let want = format!(
            "no beacon source served a usable {BOOTSTRAP_PATH} at the checkpoint pinned for this \
             chain ({root:#x}, slot 11167808, taken 2026-11-23): http://127.0.0.1: http status \
             404."
        );
        assert!(err.starts_with(&want), "{err}");
        assert!(!err.contains("quorum"), "{err}");
    }

    /// The chain's pin starts from the bootstrap in the binary. No source serves one here, as
    /// lighthouse-pulse does not once the pinned block's state is pruned.
    #[tokio::test]
    async fn the_369_pin_starts_without_a_source_bootstrap() {
        let pins = pins_369();
        let source = Fake::start(false, false).await;
        serve_pins(&source, &genesis_json(&pins), &fork_schedule_json(&pins));
        source.answer(PIN_PERIOD_UPDATES, "200 OK", "[]");
        let anchor = Fake::start(false, true).await;
        let pin = reth_pulsechain_forks::network::pulsechain_network(369).unwrap().checkpoint;
        let pin = pin.unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(pins.genesis_time + pin.slot * 10 + 60);
        let started = check_sync_committee_start(
            &[BeaconClient::new(source.beacon_url())],
            &BeaconClient::new(anchor.anchor_url()),
            pins,
            Preset::PULSECHAIN,
            StartFrom::Checkpoint(Checkpoint::Pinned(pin)),
            now,
        )
        .await
        .unwrap();
        assert_eq!(started.origin, StoreOrigin::Checkpoint { root: pin.root });
        assert_eq!(started.store.finalized_header().beacon.hash_tree_root(), pin.root);
        assert_eq!(source.calls(&format!("{BOOTSTRAP_PATH}/{:#x}", pin.root)), 0);
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");
    }

    /// A checkpoint behind the wall clock must learn its next committee from its own period. A
    /// source with no update for that period (`[]`, or a later period first) cannot move the
    /// store, so the start fails. In the checkpoint's own period `[]` is enough.
    #[tokio::test]
    async fn a_checkpoint_behind_the_wall_clock_needs_an_update_for_its_period() {
        let (source, anchor) = (pinned_source(true).await, Fake::start(false, true).await);
        let next_period_slot = 1364 * 8192 + 5;
        for answer in [json!([]), json!([real_369_update_json(next_period_slot)])] {
            source.answer(REAL_PERIOD_UPDATES, "200 OK", answer.to_string());
            let err =
                start_at_checkpoint(&source, &anchor, real_369_pin(), 1, 0).await.unwrap_err();
            assert_eq!(
                err,
                SyncCommitteeStartError::NotServed {
                    endpoint: UPDATES_PATH,
                    sources: "http://127.0.0.1: no update for period 1363".into(),
                }
            );
        }
        source.answer(REAL_PERIOD_UPDATES, "200 OK", "[]");
        assert!(start_at_checkpoint(&source, &anchor, real_369_pin(), 0, 60).await.is_ok());
    }

    /// The same holds for a saved store.
    #[tokio::test]
    async fn a_saved_store_behind_the_wall_clock_needs_an_update_for_its_period() {
        let (source, anchor) = (pinned_source(true).await, Fake::start(false, true).await);
        source.answer(REAL_PERIOD_UPDATES, "200 OK", "[]");
        let block_time = pins_369().genesis_time + real_369_slot() * 10;
        let err = check_sync_committee_start(
            &[BeaconClient::new(source.beacon_url())],
            &BeaconClient::new(anchor.anchor_url()),
            pins_369(),
            Preset::PULSECHAIN,
            StartFrom::Saved(Box::new(saved_store())),
            UNIX_EPOCH + Duration::from_secs(block_time + 86_400),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SyncCommitteeStartError::NotServed { endpoint: UPDATES_PATH, .. }));
    }

    /// The 369 pin's period: slot 11169568 is in period 1363.
    const PIN_PERIOD_UPDATES: &str =
        "/eth/v1/beacon/light_client/updates?start_period=1363&count=1";

    /// The 369 pin is the root of a real header, and its slot is that header's slot. The
    /// header fields are the ones the pin's comment in the network table names.
    #[test]
    fn the_369_checkpoint_is_the_root_of_its_header() {
        let network = reth_pulsechain_forks::network::pulsechain_network(369).unwrap();
        let pin = network.checkpoint.expect("369 has a pin");
        let header = BeaconBlockHeader {
            slot: 11_169_568,
            proposer_index: 103_648,
            parent_root: alloy_primitives::b256!(
                "0x8329ddc434cb2e3ce1beeecc1251a76713e401c453efa04ec1d5041b9cb85084"
            ),
            state_root: alloy_primitives::b256!(
                "0x5c684f074e872f3391433d3efa59d20f613a0c6ccaed00e3840e195912d06268"
            ),
            body_root: alloy_primitives::b256!(
                "0xc4b0e67b796e842b410ae3869524e01f8151a7971f698c8b5b43f5e9fe86062b"
            ),
        };
        assert_eq!(header.hash_tree_root(), pin.root);
        assert_eq!(header.slot, pin.slot);
        // The pin is a Capella block of the network's own chain.
        assert_eq!(network.beacon.fork_at_epoch(pin.slot / 32).fork, BeaconFork::Capella);
    }

    #[tokio::test]
    async fn a_real_369_bootstrap_is_read_from_json_and_starts_a_store() {
        let fake = pinned_source(true).await;
        let client = BeaconClient::new(fake.beacon_url());
        let (root, _) = real_369_bootstrap_json();
        let bootstrap = client.light_client_bootstrap(root, Preset::PULSECHAIN).await.unwrap();
        assert_eq!(bootstrap, Real369::load().bootstrap());
        let store =
            LightClientStore::bootstrap(Preset::PULSECHAIN, pins_369(), root, &bootstrap).unwrap();
        assert_eq!(store.finalized_header().execution.block_number, 28_133_431);
    }

    #[tokio::test]
    async fn spec_updates_are_read_from_the_updates_endpoint() {
        let (_, _, _, updates) = capella_case();
        let fake = Fake::start(false, false).await;
        let list: Vec<Value> =
            updates.iter().map(|(u, _)| update_json(u, UpdateKind::Full)).collect();
        let path = format!("{UPDATES_PATH}?start_period=0&count={}", list.len());
        fake.answer(&path, "200 OK", Value::Array(list).to_string());
        let client = BeaconClient::new(fake.beacon_url());
        let got = client.light_client_updates(0, updates.len(), Preset::MINIMAL).await.unwrap();
        let want: Vec<LightClientUpdate> = updates.into_iter().map(|(u, _)| u).collect();
        assert_eq!(got, want);
    }

    /// The optimistic and finality endpoints give updates whose defaults the store accepts: the
    /// spec's first update verifies in each form.
    #[tokio::test]
    async fn optimistic_and_finality_updates_verify_with_their_defaults() {
        let (beacon, trusted, bootstrap, updates) = capella_case();
        let (update, current_slot) = &updates[0];
        assert!(update.is_finality_update());
        let fake = Fake::start(false, false).await;
        fake.answer(
            OPTIMISTIC_UPDATE_PATH,
            "200 OK",
            update_json(update, UpdateKind::Optimistic).to_string(),
        );
        fake.answer(
            FINALITY_UPDATE_PATH,
            "200 OK",
            update_json(update, UpdateKind::Finality).to_string(),
        );
        let client = BeaconClient::new(fake.beacon_url());
        let store =
            LightClientStore::bootstrap(Preset::MINIMAL, beacon, trusted, &bootstrap).unwrap();
        let optimistic = client.light_client_optimistic_update(Preset::MINIMAL).await.unwrap();
        assert_eq!(optimistic, as_kind(update, UpdateKind::Optimistic));
        assert!(!optimistic.is_finality_update() && !optimistic.is_sync_committee_update());
        assert_eq!(store.validate_update(&optimistic, *current_slot), Ok(()));
        let finality = client.light_client_finality_update(Preset::MINIMAL).await.unwrap();
        assert_eq!(finality, as_kind(update, UpdateKind::Finality));
        assert!(finality.is_finality_update() && !finality.is_sync_committee_update());
        assert_eq!(store.validate_update(&finality, *current_slot), Ok(()));
    }

    #[test]
    fn malformed_light_client_json_is_refused() {
        let (_, _, _, updates) = capella_case();
        let update = &updates[0].0;
        let full = update_json(update, UpdateKind::Full);
        let parse_full =
            |v: &Value| parse_update(v.to_string().as_bytes(), Preset::MINIMAL, UpdateKind::Full);
        assert_eq!(parse_full(&full), Ok(update.clone()));

        let mut deneb = full.clone();
        deneb["version"] = json!("deneb");
        assert_eq!(parse_full(&deneb), Err(SourceError::UnsupportedFork));
        let mut phase0 = full.clone();
        phase0["version"] = json!("phase0");
        assert_eq!(parse_full(&phase0), Err(SourceError::UnsupportedFork));

        // A Capella header without its execution part, and an Altair one with it.
        let mut bare = full.clone();
        bare["data"]["attested_header"].as_object_mut().unwrap().remove("execution");
        assert_eq!(parse_full(&bare), Err(SourceError::Body));
        let mut altair = full.clone();
        altair["version"] = json!("altair");
        assert_eq!(parse_full(&altair), Err(SourceError::Body));

        let mut short = full.clone();
        short["data"]["finality_branch"].as_array_mut().unwrap().pop();
        assert_eq!(parse_full(&short), Err(SourceError::Body));
        let mut keys = full.clone();
        keys["data"]["next_sync_committee"]["pubkeys"].as_array_mut().unwrap().pop();
        assert_eq!(parse_full(&keys), Err(SourceError::Body));
        let mut bits = full.clone();
        bits["data"]["sync_aggregate"]["sync_committee_bits"] = json!("0xffff");
        assert_eq!(parse_full(&bits), Err(SourceError::Body));
        let mut hex_slot = full.clone();
        hex_slot["data"]["signature_slot"] = json!("0x10");
        assert_eq!(parse_full(&hex_slot), Err(SourceError::Body));
        let mut extra = full;
        extra["data"]["attested_header"]["execution"]["extra_data"] =
            json!(hex::encode_prefixed([1u8; 33]));
        assert_eq!(parse_full(&extra), Err(SourceError::Body));

        // A full update needs its next committee; a finality update does not.
        let finality = update_json(update, UpdateKind::Finality);
        assert_eq!(parse_full(&finality), Err(SourceError::Body));
        let as_finality =
            parse_update(finality.to_string().as_bytes(), Preset::MINIMAL, UpdateKind::Finality);
        assert_eq!(as_finality, Ok(as_kind(update, UpdateKind::Finality)));
    }

    #[test]
    fn an_updates_answer_with_more_updates_than_asked_is_refused() {
        let (_, _, _, updates) = capella_case();
        let list: Vec<Value> =
            updates.iter().map(|(u, _)| update_json(u, UpdateKind::Full)).collect();
        let body = Value::Array(list).to_string();
        assert_eq!(
            parse_updates(body.as_bytes(), Preset::MINIMAL, updates.len()).unwrap().len(),
            5
        );
        assert_eq!(
            parse_updates(body.as_bytes(), Preset::MINIMAL, updates.len() - 1),
            Err(SourceError::Body)
        );
    }

    #[tokio::test]
    async fn a_bootstrap_over_the_size_limit_is_not_read() {
        let fake = Fake::start(false, false).await;
        let (root, bootstrap) = real_369_bootstrap_json();
        let mut padded = bootstrap.clone();
        padded["padding"] = json!("x".repeat(MAX_LIGHT_CLIENT_BODY));
        let path = format!("{BOOTSTRAP_PATH}/{root:#x}");
        fake.answer(&path, "200 OK", padded.to_string());
        let client = BeaconClient::new(fake.beacon_url());
        assert_eq!(
            client.light_client_bootstrap(root, Preset::PULSECHAIN).await,
            Err(SourceError::TooLarge)
        );
        // The same answer without the padding is read.
        fake.answer(&path, "200 OK", bootstrap.to_string());
        assert!(client.light_client_bootstrap(root, Preset::PULSECHAIN).await.is_ok());
    }

    #[tokio::test]
    async fn a_block_root_is_refused_when_optimistic_or_not_finalized() {
        let fake = Fake::start(false, false).await;
        let client = BeaconClient::new(fake.beacon_url());
        let root = B256::repeat_byte(7);
        let path = "/eth/v1/beacon/blocks/finalized/root";
        let answer = |optimistic: bool, finalized: bool| {
            json!({"execution_optimistic": optimistic, "finalized": finalized, "data": {"root": root}})
                .to_string()
        };
        fake.answer(path, "200 OK", answer(false, true));
        assert_eq!(client.block_root("finalized").await, Ok(root));
        fake.answer(path, "200 OK", answer(true, true));
        assert_eq!(client.block_root("finalized").await, Err(SourceError::Optimistic));
        fake.answer(path, "200 OK", answer(false, false));
        assert_eq!(client.block_root("finalized").await, Err(SourceError::NotFinalized));
        fake.answer("/eth/v1/beacon/blocks/head/root", "200 OK", answer(false, false));
        assert_eq!(client.block_root("head").await, Ok(root));
    }

    #[tokio::test]
    async fn genesis_and_fork_schedule_are_read_and_checked_against_the_pins() {
        let pins = pins_369();
        let fake = pinned_source(false).await;
        let client = BeaconClient::new(fake.beacon_url());
        let genesis = client.genesis().await.unwrap();
        assert_eq!(genesis.genesis_validators_root, pins.genesis_validators_root);
        assert_eq!(genesis.genesis_fork_version, [0, 0, 3, 0x69]);
        let schedule = client.fork_schedule().await.unwrap();
        assert_eq!(schedule.len(), 6);
        assert_eq!(check_pins(&genesis, &schedule, &pins), Ok(()));

        let testnet = reth_pulsechain_forks::network::pulsechain_network(943).unwrap().beacon;
        assert_eq!(
            check_pins(&genesis, &schedule, &testnet),
            Err(PinError::GenesisValidatorsRoot {
                got: pins.genesis_validators_root,
                want: testnet.genesis_validators_root,
            })
        );
        let late = Genesis { genesis_time: pins.genesis_time + 1, ..genesis };
        assert_eq!(
            check_pins(&late, &schedule, &pins),
            Err(PinError::GenesisTime { got: pins.genesis_time + 1, want: pins.genesis_time })
        );
        let other = Genesis { genesis_fork_version: [0, 0, 0, 1], ..genesis };
        assert!(matches!(
            check_pins(&other, &schedule, &pins),
            Err(PinError::GenesisForkVersion { got: [0, 0, 0, 1], .. })
        ));

        // Deneb scheduled at a real epoch, or Capella at another epoch, is another chain.
        let mut deneb = schedule.clone();
        deneb[4].epoch = 100_000;
        let err = check_pins(&genesis, &deneb, &pins).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the fork schedule [0x00000369@0, 0x0000036a@1, 0x0000036b@2, 0x0000036c@3, \
             0xffffffff@100000] is not the pinned [0x00000369@0, 0x0000036a@1, 0x0000036b@2, \
             0x0000036c@3]"
        );
        let mut moved = schedule.clone();
        moved[3].epoch = 4;
        assert!(matches!(check_pins(&genesis, &moved, &pins), Err(PinError::ForkSchedule { .. })));
        let missing = &schedule[..3];
        assert!(matches!(check_pins(&genesis, missing, &pins), Err(PinError::ForkSchedule { .. })));
    }

    #[test]
    fn light_client_events_parse_only_on_a_light_client_stream() {
        let (_, _, _, updates) = capella_case();
        let update = &updates[0].0;
        let lc = Topics::LightClient(Preset::MINIMAL);
        let block =
            |event: &str, kind| format!("event: {event}\ndata: {}\n\n", update_json(update, kind));
        let optimistic = block("light_client_optimistic_update", UpdateKind::Optimistic);
        let finality = block("light_client_finality_update", UpdateKind::Finality);
        assert_eq!(
            parse_sse_block(&optimistic, lc),
            Some(Event::OptimisticUpdate(Box::new(as_kind(update, UpdateKind::Optimistic))))
        );
        assert_eq!(
            parse_sse_block(&finality, lc),
            Some(Event::FinalityUpdate(Box::new(as_kind(update, UpdateKind::Finality))))
        );
        assert_eq!(parse_sse_block(&optimistic, Topics::Head), None);
        assert_eq!(parse_sse_block(&finality, Topics::Head), None);
        let head = "event: head\ndata: {\"block\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}\n\n";
        assert_eq!(parse_sse_block(head, lc), None);
        assert_eq!(parse_sse_block("event: finalized_checkpoint\ndata: {}\n\n", lc), None);
        // A committee of another preset's size does not parse.
        assert_eq!(parse_sse_block(&optimistic, Topics::LightClient(Preset::PULSECHAIN)), None);
    }

    #[tokio::test]
    async fn a_light_client_event_stream_yields_updates() {
        let (_, _, _, updates) = capella_case();
        let update = &updates[0].0;
        let fake = Fake::start(true, false).await;
        let client = BeaconClient::new(fake.beacon_url());
        let topics = Topics::LightClient(Preset::MINIMAL);
        let mut events = client.events_of(topics, Duration::from_secs(5)).await.unwrap();
        fake.send_event("light_client_finality_update", &update_json(update, UpdateKind::Finality));
        let got = tokio::time::timeout(Duration::from_secs(5), events.next_event()).await.unwrap();
        assert_eq!(
            got,
            Some(Event::FinalityUpdate(Box::new(as_kind(update, UpdateKind::Finality))))
        );
    }

    #[tokio::test]
    async fn the_start_passes_with_one_light_client_source() {
        let (plain, served, anchor) =
            (pinned_source(false).await, pinned_source(true).await, pinned_anchor().await);
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let started = start(&[&plain, &served], &anchor).await.unwrap();
        // With no checkpoint the anchor decides the first committee, and the log says so.
        let text = logs.text();
        assert!(
            text.contains("the first sync committee trusts the anchor's finalized root"),
            "{text}"
        );
        let (root, _) = real_369_bootstrap_json();
        assert_eq!(started.sources, vec![0, 1]);
        assert_eq!(started.origin, StoreOrigin::Bootstrap { anchor_root: root });
        assert_eq!(started.store.period(), 1363);
        assert_eq!(started.store.finalized_header().beacon.hash_tree_root(), root);
    }

    #[tokio::test]
    async fn a_404_on_every_source_fails_the_start_naming_the_endpoint_and_hosts() {
        let (a, b, anchor) =
            (pinned_source(false).await, pinned_source(false).await, pinned_anchor().await);
        let err = start(&[&a, &b], &anchor).await.unwrap_err();
        assert!(
            matches!(err, SyncCommitteeStartError::NotServed { endpoint: BOOTSTRAP_PATH, .. }),
            "{err}"
        );
        let text = err.to_string();
        let one = "http://127.0.0.1: http status 404";
        assert!(
            text.contains(&format!("{BOOTSTRAP_PATH}: {one}; {one}. Enable --light-client-server")),
            "{text}"
        );
        assert!(text.contains("--head.verify=quorum"), "{text}");
    }

    /// The real 369 store, as a restart loads it from its file.
    fn saved_store() -> LightClientStore {
        let (root, _) = real_369_bootstrap_json();
        let bootstrap = Real369::load().bootstrap();
        LightClientStore::bootstrap(Preset::PULSECHAIN, pins_369(), root, &bootstrap).unwrap()
    }

    /// A restart with a saved store does not ask the anchor anything and does not bootstrap: the
    /// anchor here answers nothing, and would fail the pins.
    #[tokio::test]
    async fn a_saved_store_starts_without_the_anchor_or_a_bootstrap() {
        let (source, anchor) = (pinned_source(true).await, Fake::start(false, true).await);
        let clients = [BeaconClient::new(source.beacon_url())];
        let started = check_sync_committee_start(
            &clients,
            &BeaconClient::new(anchor.anchor_url()),
            pins_369(),
            Preset::PULSECHAIN,
            StartFrom::Saved(Box::new(saved_store())),
            SystemTime::now(),
        )
        .await
        .unwrap();
        assert_eq!(started.origin, StoreOrigin::Saved);
        assert_eq!(started.sources, vec![0]);
        assert_eq!(started.store.period(), 1363);
        assert!(anchor.state.lock().calls.is_empty(), "the anchor was asked");
        let (root, _) = real_369_bootstrap_json();
        assert_eq!(source.calls(&format!("{BOOTSTRAP_PATH}/{root:#x}")), 0);
        assert_eq!(source.calls(GENESIS_PATH), 1);
        assert_eq!(source.calls(UPDATES_PATH), 1);
    }

    /// A saved store still needs a source that serves `updates`, and sources that match the pins.
    #[tokio::test]
    async fn a_saved_store_still_needs_updates_and_pinned_sources() {
        let anchor = BeaconClient::new(Fake::start(false, true).await.anchor_url());
        let start_saved = async |source: &Fake| {
            let clients = [BeaconClient::new(source.beacon_url())];
            let pins = pins_369();
            check_sync_committee_start(
                &clients,
                &anchor,
                pins,
                Preset::PULSECHAIN,
                StartFrom::Saved(Box::new(saved_store())),
                SystemTime::now(),
            )
            .await
            .unwrap_err()
        };
        let served = pinned_source(true).await;
        served.answer(REAL_PERIOD_UPDATES, "404 Not Found", "{}");
        assert!(matches!(
            start_saved(&served).await,
            SyncCommitteeStartError::NotServed { endpoint: UPDATES_PATH, .. }
        ));
        let unpinned = Fake::start(false, false).await;
        assert!(matches!(start_saved(&unpinned).await, SyncCommitteeStartError::NoSource { .. }));
    }

    #[tokio::test]
    async fn a_source_without_updates_fails_the_start_naming_the_updates_endpoint() {
        let (served, anchor) = (pinned_source(true).await, pinned_anchor().await);
        served.answer(REAL_PERIOD_UPDATES, "501 Not Implemented", "{\"code\":501}");
        let err = start(&[&served], &anchor).await.unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeStartError::NotServed {
                endpoint: UPDATES_PATH,
                sources: "http://127.0.0.1: http status 501".into(),
            }
        );
    }

    #[tokio::test]
    async fn a_source_with_a_wrong_genesis_validators_root_is_dropped_and_named() {
        let logs = crate::testing::logs::capture(tracing::Level::ERROR);
        let (wrong, served, anchor) =
            (pinned_source(true).await, pinned_source(true).await, pinned_anchor().await);
        let mut genesis = genesis_json(&pins_369());
        genesis["data"]["genesis_validators_root"] = json!(B256::repeat_byte(1));
        serve_pins(&wrong, &genesis, &fork_schedule_json(&pins_369()));
        let started = start(&[&wrong, &served], &anchor).await.unwrap();
        assert_eq!(started.sources, vec![1]);
        let text = logs.text();
        assert!(
            text.contains(
                "the beacon source does not match the pinned chain values; it is dropped"
            ),
            "{text}"
        );
        assert!(text.contains("source=\"http://127.0.0.1\""), "{text}");
        assert!(
            text.contains(&format!("genesis_validators_root {}", B256::repeat_byte(1))),
            "{text}"
        );

        // With no source left, the node does not start.
        let err = start(&[&wrong], &anchor).await.unwrap_err();
        let want = format!(
            "no beacon source matches the pinned chain values: http://127.0.0.1: \
             genesis_validators_root {} is not the pinned {}",
            B256::repeat_byte(1),
            pins_369().genesis_validators_root
        );
        assert_eq!(err.to_string(), want);
    }

    /// A source that does not answer may be honest and only slow: it is kept, and the follower
    /// checks its pins again before it uses it. The start still needs one source that matches.
    #[tokio::test]
    async fn a_source_that_does_not_answer_the_pins_is_kept_unchecked() {
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let (silent, served, anchor) =
            (Fake::start(false, false).await, pinned_source(true).await, pinned_anchor().await);
        let started = start(&[&silent, &served], &anchor).await.unwrap();
        assert_eq!(started.sources, vec![0, 1]);
        assert_eq!(started.unchecked, vec![0]);
        let text = logs.text();
        assert!(
            text.contains(
                "the beacon source did not answer the pinned chain values; it is kept and \
                 checked again before it is used"
            ),
            "{text}"
        );
        assert!(!text.contains("does not match"), "{text}");
        let (root, _) = real_369_bootstrap_json();
        assert_eq!(silent.calls(&format!("{BOOTSTRAP_PATH}/{root:#x}")), 0);
        assert_eq!(started.unchecked_positions(), vec![0]);

        // A dropped source moves the follower's indices: the unchecked one is second there.
        let wrong = pinned_source(true).await;
        let mut genesis = genesis_json(&pins_369());
        genesis["data"]["genesis_time"] = n(1);
        serve_pins(&wrong, &genesis, &fork_schedule_json(&pins_369()));
        let started = start(&[&served, &wrong, &silent], &anchor).await.unwrap();
        assert_eq!((started.sources.clone(), started.unchecked.clone()), (vec![0, 2], vec![2]));
        assert_eq!(started.unchecked_positions(), vec![1]);
        let err = start(&[&silent], &anchor).await.unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeStartError::NoSource {
                sources: format!("http://127.0.0.1: {GENESIS_PATH}: http status 404"),
            }
        );
    }

    #[tokio::test]
    async fn an_anchor_that_differs_from_the_pins_stops_the_start() {
        let (served, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let mut schedule = fork_schedule_json(&pins_369());
        schedule["data"][3]["epoch"] = n(4);
        serve_pins(&anchor, &genesis_json(&pins_369()), &schedule);
        let err = start(&[&served], &anchor).await.unwrap_err();
        assert!(
            matches!(&err, SyncCommitteeStartError::AnchorPins { host, error: PinError::ForkSchedule { .. } } if host == "http://127.0.0.1"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_source_that_sends_too_much_data_is_not_used() {
        let (flood, served, anchor) =
            (pinned_source(true).await, pinned_source(true).await, pinned_anchor().await);
        let (root, bootstrap) = real_369_bootstrap_json();
        let mut padded = bootstrap;
        padded["padding"] = json!("x".repeat(MAX_LIGHT_CLIENT_BODY));
        flood.answer(&format!("{BOOTSTRAP_PATH}/{root:#x}"), "200 OK", padded.to_string());
        let started = start(&[&flood, &served], &anchor).await.unwrap();
        assert_eq!(started.store.finalized_header().beacon.hash_tree_root(), root);

        let err = start(&[&flood], &anchor).await.unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeStartError::NotServed {
                endpoint: BOOTSTRAP_PATH,
                sources: "http://127.0.0.1: response body too large".into(),
            }
        );
    }

    #[tokio::test]
    async fn a_bootstrap_that_does_not_prove_into_the_anchor_root_is_not_used() {
        let (forged, anchor) = (pinned_source(true).await, pinned_anchor().await);
        let (root, mut bootstrap) = real_369_bootstrap_json();
        bootstrap["data"]["current_sync_committee_branch"][0] = json!(B256::ZERO);
        forged.answer(&format!("{BOOTSTRAP_PATH}/{root:#x}"), "200 OK", bootstrap.to_string());
        let err = start(&[&forged], &anchor).await.unwrap_err();
        let state_root = Real369::load().bootstrap().header.beacon.state_root;
        assert_eq!(
            err,
            SyncCommitteeStartError::NotServed {
                endpoint: BOOTSTRAP_PATH,
                sources: format!(
                    "http://127.0.0.1: the current sync committee branch does not prove into \
                     state root {state_root}"
                ),
            }
        );
    }
}
