//! The server's archive: the light-client answers it keeps across restarts, in
//! `<datadir>/<chain_id>/`.
//!
//! * `sync-committee.ssz`: the self-check store (see [`crate::answers`]), saved each time it moves,
//!   so a restart goes on from it.
//! * `anchor.ssz`: the store that the datadir first bootstrapped, at the operator's `--checkpoint`
//!   or at the chain's pin, or the saved store that a datadir from an older build had. The server
//!   writes it once and never overwrites or deletes it. A file that does not check out stays in
//!   place, unused: it is logged and counted in `lc_server_archive_unreadable_anchor`. It is
//!   trusted as the store file is: a forger must replace one of these two files, and one forged
//!   update file still gets nothing served.
//! * `updates/<period>.ssz`: the period update of each sync-committee period, kept forever.
//!   Upstreams keep only recent states, so the server cannot build a past period again. The archive
//!   writes an update only after the self-check store verified it. At start it serves only the
//!   stored updates whose signatures a walk up checks again, from a trusted store: the pin's store,
//!   bootstrapped at the chain's pinned checkpoint from the bootstrap that ships with it, the
//!   anchor, and the self-check store. Walking up from a store's period, the store's committee of
//!   each period signs the period's update, and the store learns the next committee from it. A
//!   stored update below the periods of all three stores is not served: no trusted committee can
//!   check its signature, and a forger knows the real committees, so its next committee and
//!   branches prove nothing. The archive never moves, replaces or deletes a stored update outside
//!   the chain: it stays in place, unserved, and is counted in
//!   `lc_server_archive_unchained_updates` and logged once, for an operator. An update that the
//!   store accepts for a period that has such a file is written beside it as `<period>.<n>.ssz`.
//!   Until the first check after open, the archive serves no period update.
//! * `bootstraps/<root>.ssz`: the bootstrap at each finalized block root, kept for
//!   [`BOOTSTRAP_MAX_AGE`]. The first check after open stops serving each one whose committee is
//!   not the one verified for its period.
//!
//! Each file is an SSZ container followed by the SHA-256 of the container:
//!
//! ```text
//! version: u64, chain_id: u64, genesis_validators_root: Bytes32,
//! body: LightClientUpdate, LightClientBootstrap (Capella form) or the store
//! ```
//!
//! The body of the store and of the anchor is the store's finalized header, its committee and a
//! list of at most one next committee, as reth-lite's `sync-committee.ssz` holds them.
//!
//! A file is written atomically on a blocking thread: a temporary file, fsync, rename. One
//! process owns the directory. A file that does not check out is ignored with a warning.

use crate::SECONDS_PER_SLOT;
use alloy_primitives::{
    map::{B256Map, B256Set},
    B256,
};
use bytes::Bytes;
use reth_pulsechain_forks::network::{BeaconFork, PulsechainBeacon};
use reth_pulsechain_light_client::{
    checkpoint::stale_days,
    json::{update_json, UpdateKind},
    sync_committee::{
        committee_len, LightClientBootstrap, LightClientHeader, LightClientStore,
        LightClientUpdate, Preset, SyncCommittee, SyncCommitteeError,
    },
};
use sha2::{Digest, Sha256};
use ssz::{DecodeError, Encode, SszDecoderBuilder, SszEncoder};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info, warn};

/// A stored bootstrap whose header is older than this is deleted. Seven days is the age limit
/// of reth-lite's store file.
pub const BOOTSTRAP_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The most bootstraps kept, about 100 MB. Seven days at one checkpoint an epoch is about 1,900,
/// so only a state URL that names more roots than the chain finalizes reaches it.
pub const MAX_BOOTSTRAPS: usize = 4096;
/// The file of the self-check store.
pub const STORE_FILE: &str = "sync-committee.ssz";
/// The file of the store that the datadir first bootstrapped.
pub const ANCHOR_FILE: &str = "anchor.ssz";
/// The layout version this binary writes and reads. Version 1 files come from builds whose
/// store an upstream root could anchor, so their updates and bootstraps may have no trusted
/// signature, and their store no trusted root: they are not read.
const FORMAT_VERSION: u64 = 2;
/// The largest file read. A `PulseChain` update or bootstrap is about 26 KB, a store about 50 KB.
const MAX_FILE_BYTES: u64 = 1 << 20;
/// The length of the trailing checksum.
const CHECKSUM_LEN: usize = 32;
/// The fixed part of the container: the version, the chain ID, the root and the body offset.
const FIXED_LEN: usize = 8 + 8 + 32 + 4;
/// The extension of an archive file.
const EXTENSION: &str = "ssz";
/// The extension of a file that is being written.
const TMP_EXTENSION: &str = "ssz.tmp";
/// The directory of the period updates.
const UPDATES_DIR: &str = "updates";
/// The directory of the bootstraps.
const BOOTSTRAPS_DIR: &str = "bootstraps";

/// Why a stored file is not used.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// The file could not be read.
    #[error("cannot read the file: {0}")]
    Read(#[from] io::Error),
    /// The file is larger than any answer.
    #[error("the file is {0} bytes, more than {MAX_FILE_BYTES}")]
    TooLarge(u64),
    /// The checksum does not match: the file is truncated or damaged.
    #[error("the checksum does not match: the file is truncated or damaged")]
    Checksum,
    /// Another layout version.
    #[error("format version {0} is not {FORMAT_VERSION}")]
    Version(u64),
    /// The container does not decode.
    #[error("the file does not decode: {0:?}")]
    Decode(DecodeError),
    /// The file is for another chain.
    #[error("the file is for chain {got}, not {want}")]
    ChainId {
        /// The chain ID in the file.
        got: u64,
        /// The archive's chain ID.
        want: u64,
    },
    /// The file has another `genesis_validators_root` than the pinned one.
    #[error("the file's genesis_validators_root {got} is not the pinned {want}")]
    GenesisValidatorsRoot {
        /// The value in the file.
        got: B256,
        /// The pinned value.
        want: B256,
    },
    /// The update's attested header is in another period than the file name says.
    #[error("the update is for period {got}, but the file is for period {name}")]
    Period {
        /// The period in the file name.
        name: u64,
        /// The period of the update's attested header.
        got: u64,
    },
    /// The bootstrap's header has another root than the file name says.
    #[error("the bootstrap is at root {got}, but the file is for root {name}")]
    Root {
        /// The root in the file name.
        name: B256,
        /// The root of the bootstrap's header.
        got: B256,
    },
    /// The saved store's finalized header is older than a checkpoint may be.
    #[error(
        "the saved store is {age_days} days old at slot {slot}, over the checkpoint age limit"
    )]
    Stale {
        /// The header's slot.
        slot: u64,
        /// Its age in days, rounded up.
        age_days: u64,
    },
    /// The saved store's header or a committee key does not check out.
    #[error("the saved store does not check out: {0}")]
    Store(#[from] SyncCommitteeError),
}

/// A stored period update and its file.
#[derive(Debug, Clone)]
struct Stored {
    path: PathBuf,
    update: LightClientUpdate,
}

/// The stored period updates that read, by period, in the order of their file names.
type StoredUpdates = BTreeMap<u64, Vec<Stored>>;

/// The anchor file, as open found it.
#[derive(Debug)]
enum Anchor {
    /// There is no anchor file: the next store the server starts from is written as one.
    Missing,
    /// The anchor file's store.
    Read(Box<LightClientStore>),
    /// The anchor file does not check out. It stays in place, unused, and is never written.
    Unreadable,
}

impl Anchor {
    /// Returns the anchor file's store, when it read.
    fn store(&self) -> Option<&LightClientStore> {
        match self {
            Self::Read(store) => Some(store),
            Self::Missing | Self::Unreadable => None,
        }
    }
}

/// The archive of one chain.
#[derive(Debug)]
pub struct Archive {
    /// `<datadir>/<chain_id>`.
    dir: PathBuf,
    chain_id: u64,
    preset: Preset,
    beacon: PulsechainBeacon,
    /// Every stored period update that reads. Shared with the thread that walks them.
    stored: Arc<StoredUpdates>,
    /// The stored update files that do not read.
    unreadable: BTreeSet<PathBuf>,
    /// The store bootstrapped at the chain's pinned checkpoint, which [`Self::check`] walks up
    /// from. `None` on a chain with no pin.
    pin: Option<LightClientStore>,
    /// The anchor file, which [`Self::check`] walks up from too.
    anchor: Anchor,
    /// The stored updates that a walk up from the pin, the anchor or the self-check store
    /// verified, by period, as the index of each in its period's list. Only these are served.
    chain: BTreeMap<u64, usize>,
    /// Whether [`Self::check`] ran since open. Until it does, no period update is served.
    checked: bool,
    /// The files outside the chain that were logged.
    logged: BTreeSet<PathBuf>,
    /// The JSON of each served period update, as an `updates` answer holds it, written once
    /// and shared by every answer.
    updates_json: BTreeMap<u64, Bytes>,
    /// The header slot of each stored bootstrap, by block root.
    bootstraps: B256Map<u64>,
    /// The stored bootstraps that [`Self::check`] found with another committee than the one
    /// verified for their period. They are not served, and are pruned as the others are.
    refused_bootstraps: B256Set,
}

impl Archive {
    /// Opens the archive of `chain_id` in `datadir`, creates its directories, and loads the
    /// files that check out against `chain_id` and `beacon`'s pins. It serves no period update
    /// until [`Self::check`] checks them. `pin` is the store bootstrapped at the chain's pinned
    /// checkpoint, or `None` on a chain with no pin.
    pub async fn open(
        datadir: &Path,
        chain_id: u64,
        preset: Preset,
        beacon: PulsechainBeacon,
        pin: Option<LightClientStore>,
    ) -> io::Result<Self> {
        let dir = datadir.join(chain_id.to_string());
        let (archive, anchor_error) = tokio::task::spawn_blocking(move || {
            Self::open_blocking(dir, chain_id, preset, beacon, pin)
        })
        .await??;
        // On the caller's thread, which a test's log capture and local recorder see.
        if let Some(err) = &anchor_error {
            let path = archive.dir.join(ANCHOR_FILE);
            warn!(target: "lc_server::archive", path = %path.display(), %err, "the anchor file does not check out: it stays in place, unused and never written again, and the stored updates are checked from the pin and the self-check store only; move it away to write a new one at the next start");
        }
        metrics::gauge!("lc_server_archive_unreadable_anchor")
            .set(f64::from(u8::from(anchor_error.is_some())));
        Ok(archive)
    }

    fn open_blocking(
        dir: PathBuf,
        chain_id: u64,
        preset: Preset,
        beacon: PulsechainBeacon,
        pin: Option<LightClientStore>,
    ) -> io::Result<(Self, Option<FileError>)> {
        let mut stored = StoredUpdates::new();
        let mut unreadable = BTreeSet::new();
        let mut files = list_dir(&dir.join(UPDATES_DIR))?;
        // `<period>.ssz` before `<period>.<n>.ssz`, and these by `n`.
        files.sort_by_key(|(_, name)| update_file_order(name));
        for (path, name) in files {
            let Some((period, _)) = update_file_order(&name) else {
                warn!(target: "lc_server::archive", path = %path.display(), "ignoring a file that is not named for a period");
                continue
            };
            match read_file(&path)
                .and_then(|bytes| decode_update(&bytes, chain_id, &beacon, preset, period))
            {
                Ok(update) => stored.entry(period).or_default().push(Stored { path, update }),
                Err(err) => {
                    warn!(target: "lc_server::archive", path = %path.display(), %err, "ignoring a stored update; it stays in place");
                    unreadable.insert(path);
                }
            }
        }
        let mut bootstraps = B256Map::default();
        for (path, name) in list_dir(&dir.join(BOOTSTRAPS_DIR))? {
            let Ok(root) = name.parse::<B256>() else {
                warn!(target: "lc_server::archive", path = %path.display(), "ignoring a file that is not named for a block root");
                continue
            };
            match read_file(&path)
                .and_then(|bytes| decode_bootstrap(&bytes, chain_id, &beacon, preset, root))
            {
                Ok(bootstrap) => {
                    bootstraps.insert(root, bootstrap.header.beacon.slot);
                }
                Err(err) => {
                    warn!(target: "lc_server::archive", path = %path.display(), %err, "ignoring a stored bootstrap")
                }
            }
        }
        let (anchor, anchor_error) = match read_file(&dir.join(ANCHOR_FILE)) {
            Err(FileError::Read(err)) if err.kind() == io::ErrorKind::NotFound => {
                (Anchor::Missing, None)
            }
            bytes => match bytes.and_then(|bytes| decode_anchor(&bytes, chain_id, &beacon, preset))
            {
                Ok(store) => (Anchor::Read(Box::new(store)), None),
                Err(err) => (Anchor::Unreadable, Some(err)),
            },
        };
        debug!(target: "lc_server::archive", dir = %dir.display(), updates = stored.values().map(Vec::len).sum::<usize>(), bootstraps = bootstraps.len(), anchor = ?anchor.store().map(LightClientStore::period), "opened the archive");
        let archive = Self {
            dir,
            chain_id,
            preset,
            beacon,
            stored: Arc::new(stored),
            // Each was logged as it was read.
            logged: unreadable.clone(),
            unreadable,
            pin,
            anchor,
            chain: BTreeMap::new(),
            checked: false,
            updates_json: BTreeMap::new(),
            bootstraps,
            refused_bootstraps: B256Set::default(),
        };
        Ok((archive, anchor_error))
    }

    /// Returns the archive's directory, `<datadir>/<chain_id>`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Returns the preset.
    pub const fn preset(&self) -> Preset {
        self.preset
    }

    /// Returns the served period update of `period`: the stored one that a walk up from the pin,
    /// the anchor or the self-check store verified.
    pub fn update(&self, period: u64) -> Option<&LightClientUpdate> {
        self.chain.get(&period).map(|&index| &self.stored[&period][index].update)
    }

    /// Returns the periods of the served period updates, oldest first.
    pub fn periods(&self) -> impl Iterator<Item = u64> + '_ {
        self.chain.keys().copied()
    }

    /// Returns whether [`Self::check`] has checked the stored period updates since open.
    pub const fn is_verified(&self) -> bool {
        self.checked
    }

    /// Returns the JSON of each served period update that has one, by period.
    pub const fn updates_json(&self) -> &BTreeMap<u64, Bytes> {
        &self.updates_json
    }

    /// Returns the stored update files that are not served: those that no walk up verified, as
    /// those below the periods of the pin, the anchor and the self-check store, and those that
    /// do not read. Before [`Self::check`], every file.
    pub fn unchained(&self) -> BTreeSet<PathBuf> {
        let mut unchained = self.unreadable.clone();
        for (period, stored) in self.stored.iter() {
            let served = self.chain.get(period);
            for (index, file) in stored.iter().enumerate() {
                if served != Some(&index) {
                    unchained.insert(file.path.clone());
                }
            }
        }
        unchained
    }

    /// Returns whether a bootstrap at `root` is stored and served.
    pub fn has_bootstrap(&self, root: &B256) -> bool {
        self.bootstraps.contains_key(root) && !self.refused_bootstraps.contains(root)
    }

    /// Checks the stored period updates, and returns `store`, the self-check store, moved
    /// forward through the stored updates it verifies, at the wall-clock slot `current_slot`.
    ///
    /// Only the stored updates that a walk up verifies are served from then on: the walks from
    /// the pin, from the anchor, and from `store`. Each checks the signature of every update it
    /// takes with the committee of the update's period. The archive serves the union. Where the
    /// walks take different files of a period, the one from `store` is served, else the one from
    /// the anchor, else the one from the pin. The walks from the pin and the anchor do not move
    /// `store`: a saved store ahead of them stays the head, and the stored updates between their
    /// walks and `store` are not served.
    ///
    /// It also stops serving each stored bootstrap whose committee is not the one that the
    /// moved store or the chain's updates verified for its period, as one that a store at
    /// another root stored. A bootstrap of a period whose committee neither knows stays served.
    pub async fn check(
        &mut self,
        store: LightClientStore,
        current_slot: u64,
    ) -> io::Result<LightClientStore> {
        let (stored, preset, beacon) = (self.stored.clone(), self.preset, self.beacon);
        let (dir, chain_id) = (self.dir.clone(), self.chain_id);
        let bootstraps: Vec<(B256, u64)> =
            self.bootstraps.iter().map(|(root, slot)| (*root, *slot)).collect();
        // The walks from the anchor and then the pin, in the order they are preferred. A walk
        // from the same header and committees as a preferred one is that walk.
        let mut starts: Vec<LightClientStore> = Vec::new();
        for start in [self.anchor.store(), self.pin.as_ref()].into_iter().flatten() {
            if !same_walk(start, &store) && !starts.iter().any(|other| same_walk(start, other)) {
                starts.push(start.clone());
            }
        }
        let (chain, store, refused) = tokio::task::spawn_blocking(move || {
            let mut store = store;
            let mut chain = walk_up(preset, &beacon, &stored, &mut store, current_slot);
            for mut start in starts {
                for (period, index) in walk_up(preset, &beacon, &stored, &mut start, current_slot) {
                    chain.entry(period).or_insert(index);
                }
            }
            let known = |period| verified_committee(&store, &stored, &chain, period);
            let refused: B256Set = bootstraps
                .into_iter()
                .filter(|&(root, slot)| {
                    known(preset.period_at_slot(slot)).is_some_and(|committee| {
                        read_file(&bootstrap_path(&dir, root))
                            .and_then(|bytes| {
                                decode_bootstrap(&bytes, chain_id, &beacon, preset, root)
                            })
                            .is_ok_and(|bootstrap| bootstrap.current_sync_committee != *committee)
                    })
                })
                .map(|(root, _)| root)
                .collect();
            (chain, store, refused)
        })
        .await?;
        debug!(target: "lc_server::archive", period = store.period(), served = chain.len(), "checked the stored period updates from the pin, the anchor and the self-check store");
        if !refused.is_empty() {
            warn!(target: "lc_server::archive", count = refused.len(), "stored bootstraps have another committee than the one verified for their period: they are not served, and are deleted when they are old");
        }
        self.refused_bootstraps = refused;
        self.chain = chain;
        self.checked = true;
        self.refresh();
        Ok(store)
    }

    /// Serves the stored updates above the chain that `store` now verifies, and returns `store`
    /// moved forward through them, or `None` when no stored update moves it.
    pub async fn extend(
        &mut self,
        store: &LightClientStore,
        current_slot: u64,
    ) -> io::Result<Option<LightClientStore>> {
        let period = store.period();
        if !self.stored.range(period..).any(|(p, _)| !self.chain.contains_key(p)) {
            return Ok(None)
        }
        let (stored, preset, beacon) = (self.stored.clone(), self.preset, self.beacon);
        let mut moved = store.clone();
        let (chain, moved) = tokio::task::spawn_blocking(move || {
            let chain = walk_up(preset, &beacon, &stored, &mut moved, current_slot);
            (chain, moved)
        })
        .await?;
        let before = self.chain.len();
        for (period, index) in chain {
            self.chain.entry(period).or_insert(index);
        }
        if self.chain.len() == before {
            return Ok(None)
        }
        debug!(target: "lc_server::archive", period = moved.period(), "the self-check store verified stored period updates above its period");
        self.refresh();
        Ok(Some(moved))
    }

    /// Stores `update`, which the self-check store verified, as its attested header's period
    /// update, and serves it. Returns whether it wrote a file. The file is served after a
    /// restart only once a walk up from the pin, the anchor or the self-check store verifies it
    /// again. The anchor's walk reaches it when the server stored every period from the anchor's
    /// period up to it.
    ///
    /// A served update of the period is kept: the store verified it with the same committee. A
    /// stored file of the period outside the chain is left in place, and `update` is written
    /// beside it as `<period>.<n>.ssz`.
    pub async fn save_update(&mut self, update: LightClientUpdate) -> io::Result<bool> {
        let period = self.preset.period_at_slot(update.attested_header.beacon.slot);
        if self.chain.contains_key(&period) {
            debug!(target: "lc_server::archive", period, "keeping the served period update");
            return Ok(false)
        }
        let files = self.stored.get(&period).map_or(&[][..], Vec::as_slice);
        if let Some(index) = files.iter().position(|file| file.update == update) {
            debug!(target: "lc_server::archive", period, "serving the stored copy of the period update");
            self.chain.insert(period, index);
            self.refresh();
            return Ok(false)
        }
        let dir = self.dir.join(UPDATES_DIR);
        let bytes = encode_file(self.chain_id, &self.beacon, &update);
        let path = tokio::task::spawn_blocking(move || {
            // The file, not the map: a file that open could not read is kept too.
            let path = free_update_path(&dir, period)?;
            write_atomic(&path, &bytes)?;
            Ok::<_, io::Error>(path)
        })
        .await??;
        debug!(target: "lc_server::archive", period, path = %path.display(), "stored the period update");
        let files = Arc::make_mut(&mut self.stored).entry(period).or_default();
        files.push(Stored { path, update });
        self.chain.insert(period, files.len() - 1);
        self.refresh();
        Ok(true)
    }

    /// Writes the JSON of each newly served update, drops the JSON of the others, and logs
    /// each stored file outside the chain once.
    fn refresh(&mut self) {
        let Self { stored, chain, updates_json, preset, beacon, .. } = self;
        updates_json.retain(|period, _| chain.contains_key(period));
        for (&period, &index) in chain.iter() {
            if !updates_json.contains_key(&period) &&
                let Some(json) = json_of(*preset, beacon, &stored[&period][index].update)
            {
                updates_json.insert(period, json);
            }
        }
        let unchained = self.unchained();
        metrics::gauge!("lc_server_archive_unchained_updates").set(unchained.len() as f64);
        for path in unchained {
            if !self.logged.contains(&path) {
                warn!(target: "lc_server::archive", path = %path.display(), "no walk up from the pin, the anchor or the self-check store verifies a stored period update: it is not served, and it stays in place for an operator to check");
                self.logged.insert(path);
            }
        }
    }

    /// Loads the saved self-check store, checked against the archive's chain and pins and the
    /// wall clock `now`. `Ok(None)` when there is none.
    pub async fn load_store(&self, now: SystemTime) -> Result<Option<LightClientStore>, FileError> {
        let path = self.dir.join(STORE_FILE);
        let (chain_id, beacon, preset) = (self.chain_id, self.beacon, self.preset);
        tokio::task::spawn_blocking(move || {
            let bytes = match read_file(&path) {
                Err(FileError::Read(err)) if err.kind() == io::ErrorKind::NotFound => {
                    return Ok(None)
                }
                bytes => bytes?,
            };
            decode_store(&bytes, chain_id, &beacon, preset, now).map(Some)
        })
        .await
        .map_err(io::Error::from)?
    }

    /// Saves `store` as the self-check store.
    pub async fn save_store(&self, store: &LightClientStore) -> io::Result<()> {
        let path = self.dir.join(STORE_FILE);
        let bytes = encode_file(self.chain_id, &self.beacon, &StoreBody(store));
        tokio::task::spawn_blocking(move || write_atomic(&path, &bytes)).await?
    }

    /// Saves `store`, a store the server starts from, as the anchor file when open found none,
    /// and walks up from it from then on. Returns whether it wrote the file. An anchor file that
    /// exists, read or not, is never written: the anchor is the store the datadir first started
    /// from, so that every later restart walks up from it.
    pub async fn save_anchor(&mut self, store: &LightClientStore) -> io::Result<bool> {
        if !matches!(self.anchor, Anchor::Missing) {
            return Ok(false)
        }
        let path = self.dir.join(ANCHOR_FILE);
        let bytes = encode_file(self.chain_id, &self.beacon, &StoreBody(store));
        // Open found no file. The write is a last guard, so that the server never replaces an
        // anchor file, even one that another process wrote since.
        let written = tokio::task::spawn_blocking(move || write_new(&path, &bytes)).await??;
        if written {
            info!(target: "lc_server::archive", period = store.period(), slot = store.finalized_header().beacon.slot, "wrote the anchor file: later starts serve the stored updates from its period up");
            self.anchor = Anchor::Read(Box::new(store.clone()));
        }
        Ok(written)
    }

    /// Returns the anchor file's store, when the file read or this archive wrote it.
    pub fn anchor(&self) -> Option<&LightClientStore> {
        self.anchor.store()
    }

    /// Stores `bootstrap` at its header's root, unless the root has one. Returns whether it
    /// stored `bootstrap`.
    pub async fn save_bootstrap(&mut self, bootstrap: LightClientBootstrap) -> io::Result<bool> {
        let root = bootstrap.header.beacon.hash_tree_root();
        if self.bootstraps.contains_key(&root) {
            return Ok(false)
        }
        let slot = bootstrap.header.beacon.slot;
        let path = bootstrap_path(&self.dir, root);
        let (chain_id, beacon) = (self.chain_id, self.beacon);
        tokio::task::spawn_blocking(move || {
            write_atomic(&path, &encode_file(chain_id, &beacon, &bootstrap))
        })
        .await??;
        debug!(target: "lc_server::archive", %root, slot, "stored the bootstrap");
        self.bootstraps.insert(root, slot);
        Ok(true)
    }

    /// Reads the stored bootstrap at `root`. `Ok(None)` when there is none or the file does not
    /// check out.
    pub async fn bootstrap(&self, root: B256) -> io::Result<Option<LightClientBootstrap>> {
        if !self.has_bootstrap(&root) {
            return Ok(None)
        }
        let path = bootstrap_path(&self.dir, root);
        let (chain_id, beacon, preset) = (self.chain_id, self.beacon, self.preset);
        tokio::task::spawn_blocking(move || {
            match read_file(&path)
                .and_then(|bytes| decode_bootstrap(&bytes, chain_id, &beacon, preset, root))
            {
                Ok(bootstrap) => Ok(Some(bootstrap)),
                Err(err) => {
                    warn!(target: "lc_server::archive", path = %path.display(), %err, "ignoring a stored bootstrap");
                    Ok(None)
                }
            }
        })
        .await?
    }

    /// Deletes the bootstraps whose header is older than [`BOOTSTRAP_MAX_AGE`] at the wall
    /// clock `now`, and then the oldest ones above `max`. Returns how many it deleted.
    pub async fn prune(&mut self, now: SystemTime, max: usize) -> io::Result<usize> {
        let genesis_time = self.beacon.genesis_time;
        let mut by_slot: Vec<(u64, B256)> =
            self.bootstraps.iter().map(|(root, slot)| (*slot, *root)).collect();
        by_slot.sort_unstable();
        let over = by_slot.len().saturating_sub(max);
        let stale: Vec<B256> = by_slot
            .iter()
            .enumerate()
            .filter(|(index, (slot, _))| {
                let slot_time = UNIX_EPOCH +
                    Duration::from_secs(
                        genesis_time.saturating_add(slot.saturating_mul(SECONDS_PER_SLOT)),
                    );
                *index < over ||
                    now.duration_since(slot_time).is_ok_and(|age| age > BOOTSTRAP_MAX_AGE)
            })
            .map(|(_, (_, root))| *root)
            .collect();
        if stale.is_empty() {
            return Ok(0)
        }
        let paths: Vec<PathBuf> =
            stale.iter().map(|root| bootstrap_path(&self.dir, *root)).collect();
        tokio::task::spawn_blocking(move || paths.iter().try_for_each(|path| remove_file(path)))
            .await??;
        for root in &stale {
            self.bootstraps.remove(root);
            self.refused_bootstraps.remove(root);
        }
        debug!(target: "lc_server::archive", pruned = stale.len(), "pruned old bootstraps");
        Ok(stale.len())
    }
}

/// Returns the path of the bootstrap at `root` in the archive directory `dir`.
fn bootstrap_path(dir: &Path, root: B256) -> PathBuf {
    dir.join(BOOTSTRAPS_DIR).join(format!("{root}.{EXTENSION}"))
}

/// Returns the committee of `period` that `store` holds, or that the next committee of the
/// served update of the period before proves. `None` when neither knows it.
fn verified_committee<'a>(
    store: &'a LightClientStore,
    stored: &'a StoredUpdates,
    chain: &BTreeMap<u64, usize>,
    period: u64,
) -> Option<&'a SyncCommittee> {
    if period == store.period() {
        return Some(store.current_sync_committee())
    }
    if period == store.period() + 1 {
        return store.next_sync_committee()
    }
    let before = period.checked_sub(1)?;
    chain.get(&before).map(|&index| &stored[&before][index].update.next_sync_committee)
}

/// Returns whether walks up from `a` and from `b` are one walk: the stores have the same
/// finalized header and committees.
fn same_walk(a: &LightClientStore, b: &LightClientStore) -> bool {
    a.finalized_header() == b.finalized_header() &&
        a.current_sync_committee() == b.current_sync_committee() &&
        a.next_sync_committee() == b.next_sync_committee()
}

/// Walks up from `store`'s period: each period's first stored update that the store's committee
/// of the period signs chains, and `store` processes it, so that it learns the next committee
/// and rotates. Returns the chained updates by period, as the index of each in its period's
/// list. A period with no such update ends the walk.
fn walk_up(
    preset: Preset,
    beacon: &PulsechainBeacon,
    stored: &StoredUpdates,
    store: &mut LightClientStore,
    current_slot: u64,
) -> BTreeMap<u64, usize> {
    let mut chain = BTreeMap::new();
    let mut period = store.period();
    loop {
        // With the next committee known, an update of the store's period must carry it.
        let (committee, next) = if period == store.period() {
            (store.current_sync_committee(), store.next_sync_committee())
        } else if let Some(next) =
            store.next_sync_committee().filter(|_| period == store.period() + 1)
        {
            (next, None)
        } else {
            break
        };
        let Some(index) = stored.get(&period).and_then(|files| {
            files.iter().position(|file| signed_by(preset, beacon, committee, next, &file.update))
        }) else {
            break
        };
        let update = &stored[&period][index].update;
        match store.process_update(update, current_slot) {
            // A store whose finalized header is past the update learns nothing from it.
            Ok(()) | Err(SyncCommitteeError::Stale { .. }) => {}
            Err(err) => {
                debug!(target: "lc_server::archive", period, %err, "the self-check store did not process a stored update it verified");
                break
            }
        }
        chain.insert(period, index);
        period += 1;
    }
    chain
}

/// Returns the order of an update file's name stem, `<period>` before `<period>.<n>`, and so its
/// period. `None` for a name that is neither.
fn update_file_order(stem: &str) -> Option<(u64, u64)> {
    match stem.split_once('.') {
        None => Some((stem.parse().ok()?, 0)),
        Some((period, n)) => Some((period.parse().ok()?, n.parse().ok().filter(|&n| n > 0)?)),
    }
}

/// Returns `<period>.ssz` in `dir`, or `<period>.<n>.ssz` with the first free `n` when it is
/// taken, so that a new file never overwrites a stored one. One process owns the directory.
fn free_update_path(dir: &Path, period: u64) -> io::Result<PathBuf> {
    let first = dir.join(format!("{period}.{EXTENSION}"));
    if !first.try_exists()? {
        return Ok(first)
    }
    for n in 1u64.. {
        let numbered = dir.join(format!("{period}.{n}.{EXTENSION}"));
        if !numbered.try_exists()? {
            return Ok(numbered)
        }
    }
    unreachable!("a directory holds fewer than u64::MAX files")
}

/// Returns the JSON of `update` in an `updates` answer, or `None` with a warning at a fork that
/// the JSON form lacks.
fn json_of(preset: Preset, beacon: &PulsechainBeacon, update: &LightClientUpdate) -> Option<Bytes> {
    let fork = beacon.fork_at_epoch(preset.epoch_at_slot(update.attested_header.beacon.slot)).fork;
    match update_json(update, fork, UpdateKind::Full) {
        Ok(json) => Some(Bytes::from(json.to_string())),
        Err(err) => {
            warn!(target: "lc_server::archive", slot = update.attested_header.beacon.slot, %err, "cannot write a period update as JSON");
            None
        }
    }
}

/// Returns whether `committee`, the committee of `update`'s period, signs `update`, with `next`
/// as the next committee it must carry when known. A store at `update`'s finalized header that
/// knows only these committees checks it, so `update` must be signed in the period of its
/// finalized header.
fn signed_by(
    preset: Preset,
    beacon: &PulsechainBeacon,
    committee: &SyncCommittee,
    next: Option<&SyncCommittee>,
    update: &LightClientUpdate,
) -> bool {
    LightClientStore::restore(
        preset,
        *beacon,
        update.finalized_header.clone(),
        committee.clone(),
        next.cloned(),
    )
    .and_then(|store| store.validate_update(update, u64::MAX))
    .is_ok()
}

/// Creates `dir` if it is missing and returns each archive file in it with its name stem.
/// Removes the temporary files that an interrupted write left.
fn list_dir(dir: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    std::fs::create_dir_all(dir)?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue };
        if name.ends_with(&format!(".{TMP_EXTENSION}")) {
            debug!(target: "lc_server::archive", path = %path.display(), "removing a partial write");
            remove_file(&path)?;
        } else if let Some(stem) = name.strip_suffix(&format!(".{EXTENSION}")) {
            files.push((path.clone(), stem.to_owned()));
        }
    }
    Ok(files)
}

/// Removes `path`. A file that is already gone is not an error.
fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// Writes `bytes` to `path` atomically: a temporary file, fsync, rename, then fsync of the
/// directory so that the rename survives a power loss.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(TMP_EXTENSION);
    let written = std::fs::File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(err) = written {
        if let Err(remove) = remove_file(&tmp) {
            warn!(target: "lc_server::archive", path = %tmp.display(), %remove, "cannot remove a partial write");
        }
        return Err(err)
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Writes `bytes` to `path` unless `path` exists. Returns whether it wrote the file.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    if path.try_exists()? {
        return Ok(false)
    }
    write_new_unchecked(path, bytes)
}

/// The final step of [`write_new`]: a temporary file, fsync, a hard link at `path`, then fsync
/// of the directory. A rename replaces a file that exists and a hard link does not, so a file
/// that another process wrote after the check stays. The temporary file has the process ID in
/// its name, so two processes do not write the same one.
fn write_new_unchecked(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let tmp = path.with_extension(format!("{}.{TMP_EXTENSION}", std::process::id()));
    let linked = std::fs::File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::hard_link(&tmp, path));
    if let Err(remove) = remove_file(&tmp) {
        warn!(target: "lc_server::archive", path = %tmp.display(), %remove, "cannot remove a temporary file");
    }
    match linked {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            debug!(target: "lc_server::archive", path = %path.display(), "another process wrote the file first: it stays");
            return Ok(false)
        }
        Err(err) => return Err(err),
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(true)
}

/// The body of the store file: the store's finalized header, its committee and a list of at
/// most one next committee.
struct StoreBody<'a>(&'a LightClientStore);

impl Encode for StoreBody<'_> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let store = self.0;
        let mut encoder = SszEncoder::container(buf, 4 + committee_len(store.preset()) + 4);
        encoder.append(store.finalized_header());
        encoder.append_parameterized(true, |buf| store.current_sync_committee().append_ssz(buf));
        encoder.append_parameterized(false, |buf| {
            if let Some(next) = store.next_sync_committee() {
                next.append_ssz(buf);
            }
        });
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let committee = committee_len(self.0.preset());
        let next = self.0.next_sync_committee().map_or(0, |_| committee);
        4 + self.0.finalized_header().ssz_bytes_len() + committee + 4 + next
    }
}

/// Returns the file's bytes for `body`.
fn encode_file(chain_id: u64, beacon: &PulsechainBeacon, body: &impl Encode) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FIXED_LEN + body.ssz_bytes_len() + CHECKSUM_LEN);
    let mut encoder = SszEncoder::container(&mut buf, FIXED_LEN);
    encoder.append(&FORMAT_VERSION);
    encoder.append(&chain_id);
    encoder.append(&beacon.genesis_validators_root);
    encoder.append(body);
    encoder.finalize();
    let checksum = Sha256::digest(&buf);
    buf.extend_from_slice(&checksum);
    buf
}

/// Reads the file at `path`, up to [`MAX_FILE_BYTES`].
fn read_file(path: &Path) -> Result<Vec<u8>, FileError> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_FILE_BYTES {
        return Err(FileError::TooLarge(len))
    }
    Ok(std::fs::read(path)?)
}

/// Checks a file's checksum, version, chain ID and pinned root, and decodes its body with
/// `decode`.
fn decode_file<T>(
    bytes: &[u8],
    chain_id: u64,
    beacon: &PulsechainBeacon,
    decode: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
) -> Result<T, FileError> {
    let (body, checksum) = bytes
        .split_at_checked(bytes.len().saturating_sub(CHECKSUM_LEN))
        .filter(|(_, checksum)| checksum.len() == CHECKSUM_LEN)
        .ok_or(FileError::Checksum)?;
    if Sha256::digest(body).as_slice() != checksum {
        return Err(FileError::Checksum)
    }
    let Some(version) = body.first_chunk::<8>().map(|b| u64::from_le_bytes(*b)) else {
        let len = body.len();
        return Err(FileError::Decode(DecodeError::InvalidByteLength { len, expected: 8 }))
    };
    if version != FORMAT_VERSION {
        return Err(FileError::Version(version))
    }
    let mut builder = SszDecoderBuilder::new(body);
    let err = FileError::Decode;
    builder.register_type::<u64>().map_err(err)?;
    builder.register_type::<u64>().map_err(err)?;
    builder.register_type::<B256>().map_err(err)?;
    builder.register_type_parameterized(false, 4).map_err(err)?;
    let mut decoder = builder.build().map_err(err)?;
    let _version: u64 = decoder.decode_next().map_err(err)?;
    let got_chain_id: u64 = decoder.decode_next().map_err(err)?;
    let genesis_validators_root: B256 = decoder.decode_next().map_err(err)?;
    if got_chain_id != chain_id {
        return Err(FileError::ChainId { got: got_chain_id, want: chain_id })
    }
    if genesis_validators_root != beacon.genesis_validators_root {
        return Err(FileError::GenesisValidatorsRoot {
            got: genesis_validators_root,
            want: beacon.genesis_validators_root,
        })
    }
    decoder.decode_next_with(decode).map_err(err)
}

/// Decodes the file of `period`'s update.
fn decode_update(
    bytes: &[u8],
    chain_id: u64,
    beacon: &PulsechainBeacon,
    preset: Preset,
    period: u64,
) -> Result<LightClientUpdate, FileError> {
    let update = decode_file(bytes, chain_id, beacon, |body| {
        LightClientUpdate::from_ssz_bytes(body, preset, BeaconFork::Capella)
    })?;
    let got = preset.period_at_slot(update.attested_header.beacon.slot);
    if got != period {
        return Err(FileError::Period { name: period, got })
    }
    Ok(update)
}

/// Decodes the file of the bootstrap at `root`.
fn decode_bootstrap(
    bytes: &[u8],
    chain_id: u64,
    beacon: &PulsechainBeacon,
    preset: Preset,
    root: B256,
) -> Result<LightClientBootstrap, FileError> {
    let bootstrap = decode_file(bytes, chain_id, beacon, |body| {
        LightClientBootstrap::from_ssz_bytes(body, preset, BeaconFork::Capella)
    })?;
    let got = bootstrap.header.beacon.hash_tree_root();
    if got != root {
        return Err(FileError::Root { name: root, got })
    }
    Ok(bootstrap)
}

/// Decodes the store file and restores the store, unless its finalized header is older than a
/// checkpoint may be at the wall clock `now`.
fn decode_store(
    bytes: &[u8],
    chain_id: u64,
    beacon: &PulsechainBeacon,
    preset: Preset,
    now: SystemTime,
) -> Result<LightClientStore, FileError> {
    let (header, current, next) = decode_store_body(bytes, chain_id, beacon, preset)?;
    let slot = header.beacon.slot;
    if let Some(age_days) = stale_days(slot, beacon, now) {
        return Err(FileError::Stale { slot, age_days })
    }
    Ok(LightClientStore::restore(preset, *beacon, header, current, next)?)
}

/// Decodes the anchor file and restores its store. Its age does not matter, as the pin's does
/// not: the anchor only checks the signatures of the stored updates, and is never the head.
fn decode_anchor(
    bytes: &[u8],
    chain_id: u64,
    beacon: &PulsechainBeacon,
    preset: Preset,
) -> Result<LightClientStore, FileError> {
    let (header, current, next) = decode_store_body(bytes, chain_id, beacon, preset)?;
    Ok(LightClientStore::restore(preset, *beacon, header, current, next)?)
}

/// Decodes a file whose body is a store: its finalized header, its committee and its next
/// committee, when it knows it.
fn decode_store_body(
    bytes: &[u8],
    chain_id: u64,
    beacon: &PulsechainBeacon,
    preset: Preset,
) -> Result<(LightClientHeader, SyncCommittee, Option<SyncCommittee>), FileError> {
    decode_file(bytes, chain_id, beacon, |body| {
        let mut builder = SszDecoderBuilder::new(body);
        builder.register_type::<LightClientHeader>()?;
        builder.register_type_parameterized(true, committee_len(preset))?;
        builder.register_type_parameterized(false, 4)?;
        let mut decoder = builder.build()?;
        let header: LightClientHeader = decoder.decode_next()?;
        let current = decoder.decode_next_with(|b| SyncCommittee::from_ssz_bytes(b, preset))?;
        let next = decoder.decode_next_with(|b| {
            if b.is_empty() {
                Ok(None)
            } else {
                SyncCommittee::from_ssz_bytes(b, preset).map(Some)
            }
        })?;
        Ok((header, current, next))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{committee, Logs, TestChain, PRESET};
    use reth_pulsechain_light_client::{
        checkpoint::MAX_CHECKPOINT_AGE,
        derive::CheckedState,
        sync_committee::{
            is_valid_merkle_branch,
            test_utils::{hash, Real369},
            Gindices,
        },
    };

    fn pins(chain_id: u64) -> PulsechainBeacon {
        reth_pulsechain_forks::network::pulsechain_network(chain_id).unwrap().beacon
    }

    async fn open(datadir: &Path, chain_id: u64) -> Archive {
        Archive::open(datadir, chain_id, Preset::PULSECHAIN, pins(chain_id), None).await.unwrap()
    }

    /// Returns whether the parts of `update` that need no committee check out: its headers, and
    /// the finality and next-committee branches into the attested state root. A forger can make
    /// all of them with no key.
    fn proofs_check_out(
        preset: Preset,
        beacon: &PulsechainBeacon,
        update: &LightClientUpdate,
    ) -> bool {
        let fork_at = |slot| beacon.fork_at_epoch(preset.epoch_at_slot(slot)).fork;
        let (attested, finalized) = (&update.attested_header, &update.finalized_header);
        let fork = fork_at(attested.beacon.slot);
        let Some(gindices) = Gindices::for_fork(fork) else { return false };
        attested.validate(fork).is_ok() &&
            finalized.validate(fork_at(finalized.beacon.slot)).is_ok() &&
            is_valid_merkle_branch(
                finalized.beacon.hash_tree_root(),
                &update.finality_branch,
                gindices.finalized_root,
                attested.beacon.state_root,
            ) &&
            is_valid_merkle_branch(
                update.next_sync_committee.hash_tree_root(),
                &update.next_sync_committee_branch,
                gindices.next_sync_committee,
                attested.beacon.state_root,
            )
    }

    /// The served period updates.
    fn served(archive: &Archive) -> BTreeMap<u64, LightClientUpdate> {
        archive.periods().map(|period| (period, archive.update(period).unwrap().clone())).collect()
    }

    /// A period update at the real 369 block. The archive does not check the protocol, so the
    /// branches need only the right lengths.
    fn update(signature_slot: u64) -> LightClientUpdate {
        let real = Real369::load();
        let header = real.light_client_header();
        LightClientUpdate {
            attested_header: header.clone(),
            next_sync_committee: real.committee.clone(),
            next_sync_committee_branch: real.branch("current_sync_committee_branch"),
            finalized_header: header,
            finality_branch: vec![B256::repeat_byte(1); 6],
            sync_aggregate: real.aggregate,
            signature_slot,
        }
    }

    /// The real 369 bootstrap, at `slot`. Its root follows the slot.
    fn bootstrap(slot: u64) -> LightClientBootstrap {
        let mut bootstrap = Real369::load().bootstrap();
        bootstrap.header.beacon.slot = slot;
        bootstrap
    }

    fn root(bootstrap: &LightClientBootstrap) -> B256 {
        bootstrap.header.beacon.hash_tree_root()
    }

    fn real_slot() -> u64 {
        Real369::load().header.slot
    }

    fn period() -> u64 {
        Preset::PULSECHAIN.period_at_slot(real_slot())
    }

    /// The wall clock `after` slot `slot` on 369.
    fn at_slot(slot: u64, after: Duration) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(pins(369).genesis_time + slot * SECONDS_PER_SLOT) + after
    }

    /// The store of the real 369 bootstrap.
    fn real_store() -> LightClientStore {
        let real = Real369::load();
        let root = hash(&real.json["block_root"]);
        LightClientStore::bootstrap(Preset::PULSECHAIN, pins(369), root, &real.bootstrap()).unwrap()
    }

    /// The file `bytes` with format `version` and its checksum again.
    fn with_version(bytes: &[u8], version: u64) -> Vec<u8> {
        let mut body = bytes[..bytes.len() - CHECKSUM_LEN].to_vec();
        body[..8].copy_from_slice(&version.to_le_bytes());
        body.extend_from_slice(&Sha256::digest(&body));
        body
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn saved_answers_load_back_after_a_restart() {
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open(datadir.path(), 369).await;
        assert_eq!(archive.dir(), datadir.path().join("369"));
        assert!(served(&archive).is_empty());
        let (saved_update, saved_bootstrap) = (update(real_slot() + 1), bootstrap(real_slot()));
        let root = root(&saved_bootstrap);
        assert!(archive.bootstrap(root).await.unwrap().is_none());

        assert!(archive.save_update(saved_update.clone()).await.unwrap());
        assert!(archive.save_bootstrap(saved_bootstrap.clone()).await.unwrap());
        assert_eq!(served(&archive), BTreeMap::from([(period(), saved_update.clone())]));
        assert!(archive.has_bootstrap(&root));
        assert_eq!(archive.bootstrap(root).await.unwrap(), Some(saved_bootstrap.clone()));
        // The temporary files were renamed.
        let dir = archive.dir().to_path_buf();
        assert_eq!(names(&dir.join(UPDATES_DIR)), vec![format!("{}.ssz", period())]);
        assert_eq!(names(&dir.join(BOOTSTRAPS_DIR)), vec![format!("{root}.ssz")]);
        drop(archive);

        // The bootstrap is served at once. The update is served once the store accepts it
        // again, and the same update is not written again.
        let mut archive = open(datadir.path(), 369).await;
        assert!(served(&archive).is_empty());
        assert!(archive.has_bootstrap(&root));
        assert_eq!(archive.bootstrap(root).await.unwrap(), Some(saved_bootstrap));
        assert!(!archive.save_update(saved_update.clone()).await.unwrap());
        assert_eq!(served(&archive), BTreeMap::from([(period(), saved_update)]));
        assert_eq!(names(&dir.join(UPDATES_DIR)), vec![format!("{}.ssz", period())]);
    }

    #[tokio::test]
    async fn a_later_update_in_the_same_period_does_not_replace_the_stored_one() {
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open(datadir.path(), 369).await;
        let first = update(real_slot() + 1);
        assert!(archive.save_update(first.clone()).await.unwrap());
        let file = archive.dir().join(UPDATES_DIR).join(format!("{}.ssz", period()));
        let bytes = std::fs::read(&file).unwrap();

        let later = update(real_slot() + 2);
        assert!(!archive.save_update(later.clone()).await.unwrap());
        assert_eq!(archive.update(period()), Some(&first));
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        drop(archive);

        // Nor after a restart, once the stored update is served again.
        let mut archive = open(datadir.path(), 369).await;
        assert!(!archive.save_update(first.clone()).await.unwrap());
        assert!(!archive.save_update(later).await.unwrap());
        assert_eq!(archive.update(period()), Some(&first));
        assert_eq!(std::fs::read(&file).unwrap(), bytes);

        // The same bootstrap root is stored once.
        assert!(archive.save_bootstrap(bootstrap(real_slot())).await.unwrap());
        assert!(!archive.save_bootstrap(bootstrap(real_slot())).await.unwrap());
    }

    #[tokio::test]
    async fn bootstraps_older_than_seven_days_are_pruned() {
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open(datadir.path(), 369).await;
        let (old, new) = (bootstrap(real_slot()), bootstrap(real_slot() + 32));
        assert!(archive.save_bootstrap(old.clone()).await.unwrap());
        assert!(archive.save_bootstrap(new.clone()).await.unwrap());
        assert!(archive.save_update(update(real_slot() + 1)).await.unwrap());

        // At exactly the limit both stay.
        assert_eq!(
            archive.prune(at_slot(real_slot(), BOOTSTRAP_MAX_AGE), MAX_BOOTSTRAPS).await.unwrap(),
            0
        );
        let now = at_slot(real_slot(), BOOTSTRAP_MAX_AGE + Duration::from_secs(1));
        assert_eq!(archive.prune(now, MAX_BOOTSTRAPS).await.unwrap(), 1);
        assert!(!archive.has_bootstrap(&root(&old)));
        assert!(archive.bootstrap(root(&old)).await.unwrap().is_none());
        assert!(archive.has_bootstrap(&root(&new)));
        let dir = archive.dir().to_path_buf();
        assert_eq!(names(&dir.join(BOOTSTRAPS_DIR)), vec![format!("{}.ssz", root(&new))]);
        // Updates are kept forever.
        assert_eq!(
            archive
                .prune(at_slot(real_slot(), BOOTSTRAP_MAX_AGE * 100), MAX_BOOTSTRAPS)
                .await
                .unwrap(),
            1
        );
        assert_eq!(served(&archive).len(), 1);
        assert_eq!(names(&dir.join(UPDATES_DIR)).len(), 1);
        assert!(names(&dir.join(BOOTSTRAPS_DIR)).is_empty());
        drop(archive);

        let archive = open(datadir.path(), 369).await;
        assert!(!archive.has_bootstrap(&root(&new)));
        assert_eq!(names(&dir.join(UPDATES_DIR)).len(), 1);
    }

    /// Above the most bootstraps kept, the oldest go first, whatever their age: a header slot
    /// after the wall clock is never stale.
    #[tokio::test]
    async fn bootstraps_above_the_limit_are_pruned_oldest_first() {
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open(datadir.path(), 369).await;
        let slots = [real_slot() + 64, real_slot(), real_slot() + 1_000_000];
        for slot in slots {
            assert!(archive.save_bootstrap(bootstrap(slot)).await.unwrap());
        }
        let now = at_slot(real_slot(), Duration::ZERO);
        assert_eq!(archive.prune(now, 3).await.unwrap(), 0);
        assert_eq!(archive.prune(now, 1).await.unwrap(), 2);
        assert!(archive.has_bootstrap(&root(&bootstrap(slots[2]))));
        assert_eq!(names(&archive.dir().join(BOOTSTRAPS_DIR)).len(), 1);
    }

    /// A damaged update file stays in place, unserved. The next accepted update of its period
    /// is written beside it, and served after a restart too.
    #[tokio::test]
    async fn a_damaged_file_stays_in_place_and_a_new_update_is_written_beside_it() {
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open(datadir.path(), 369).await;
        let saved = update(real_slot() + 1);
        assert!(archive.save_update(saved.clone()).await.unwrap());
        let saved_bootstrap = bootstrap(real_slot());
        assert!(archive.save_bootstrap(saved_bootstrap.clone()).await.unwrap());
        let dir = archive.dir().to_path_buf();
        drop(archive);

        // One flipped bit in the update, a truncated bootstrap, a leftover temporary file and
        // a stray file.
        let update_file = dir.join(UPDATES_DIR).join(format!("{}.ssz", period()));
        let mut bytes = std::fs::read(&update_file).unwrap();
        bytes[2000] ^= 1;
        std::fs::write(&update_file, &bytes).unwrap();
        let bootstrap_file =
            dir.join(BOOTSTRAPS_DIR).join(format!("{}.ssz", root(&saved_bootstrap)));
        let bootstrap_bytes = std::fs::read(&bootstrap_file).unwrap();
        std::fs::write(&bootstrap_file, &bootstrap_bytes[..bootstrap_bytes.len() / 2]).unwrap();
        std::fs::write(dir.join(UPDATES_DIR).join("7.ssz.tmp"), b"partial").unwrap();
        std::fs::write(dir.join(UPDATES_DIR).join("notes.txt"), b"hello").unwrap();

        let mut archive = open(datadir.path(), 369).await;
        assert!(served(&archive).is_empty());
        assert!(!archive.has_bootstrap(&root(&saved_bootstrap)));
        assert_eq!(archive.unchained(), BTreeSet::from([update_file.clone()]));
        // The temporary file is removed; the stray file is left alone.
        assert_eq!(
            names(&dir.join(UPDATES_DIR)),
            vec![format!("{}.ssz", period()), "notes.txt".into()]
        );

        assert!(archive.save_update(saved.clone()).await.unwrap());
        assert!(archive.save_bootstrap(saved_bootstrap.clone()).await.unwrap());
        let beside = format!("{}.1.ssz", period());
        assert_eq!(
            names(&dir.join(UPDATES_DIR)),
            vec![beside.clone(), format!("{}.ssz", period()), "notes.txt".into()]
        );
        assert_eq!(std::fs::read(&update_file).unwrap(), bytes);
        assert_eq!(archive.unchained(), BTreeSet::from([update_file.clone()]));
        drop(archive);

        let mut archive = open(datadir.path(), 369).await;
        assert!(!archive.save_update(saved.clone()).await.unwrap());
        assert_eq!(served(&archive), BTreeMap::from([(period(), saved)]));
        assert!(archive.has_bootstrap(&root(&saved_bootstrap)));
        assert_eq!(names(&dir.join(UPDATES_DIR)).len(), 3);
        assert_eq!(archive.unchained(), BTreeSet::from([update_file]));
    }

    #[tokio::test]
    async fn a_file_for_another_chain_or_name_is_ignored() {
        let datadir = tempfile::tempdir().unwrap();
        let mut on_943 = open(datadir.path(), 943).await;
        // The 369 block is an old slot on 943 too; the archive does not check the protocol.
        assert!(on_943.save_update(update(real_slot() + 1)).await.unwrap());
        assert!(on_943.save_bootstrap(bootstrap(real_slot())).await.unwrap());
        let on_369 = open(datadir.path(), 369).await;
        for sub in [UPDATES_DIR, BOOTSTRAPS_DIR] {
            for name in names(&on_943.dir().join(sub)) {
                std::fs::copy(
                    on_943.dir().join(sub).join(&name),
                    on_369.dir().join(sub).join(name),
                )
                .unwrap();
            }
        }
        std::fs::write(on_369.dir().join(UPDATES_DIR).join("1363.x.ssz"), b"not ours").unwrap();
        // The update is not read, so the same update is written beside the file that did not
        // read, which stays in place.
        let mut on_369 = open(datadir.path(), 369).await;
        assert!(!on_369.has_bootstrap(&root(&bootstrap(real_slot()))));
        assert!(on_369.save_update(update(real_slot() + 1)).await.unwrap());
        assert_eq!(
            names(&on_369.dir().join(UPDATES_DIR)),
            vec![
                format!("{}.1.ssz", period()),
                format!("{}.ssz", period()),
                format!("{}.x.ssz", period())
            ]
        );
    }

    #[test]
    fn update_file_names_give_their_period_and_order() {
        assert_eq!(update_file_order("1363"), Some((1363, 0)));
        assert_eq!(update_file_order("1363.2"), Some((1363, 2)));
        for name in ["1363.0", "1363.x", "x", "1363.1.2", ""] {
            assert_eq!(update_file_order(name), None, "{name}");
        }
    }

    #[test]
    fn a_file_that_does_not_check_out_gives_the_exact_error() {
        let (chain_id, beacon) = (369, pins(369));
        let saved = update(real_slot() + 1);
        let bytes = encode_file(chain_id, &beacon, &saved);
        let read = |bytes: &[u8], chain_id, beacon: &PulsechainBeacon, name| {
            decode_update(bytes, chain_id, beacon, Preset::PULSECHAIN, name).unwrap_err()
        };
        assert_eq!(
            decode_update(&bytes, chain_id, &beacon, Preset::PULSECHAIN, period()).unwrap(),
            saved
        );

        for len in [0, 31, 32, 100, bytes.len() / 2, bytes.len() - 1] {
            assert!(
                matches!(read(&bytes[..len], chain_id, &beacon, period()), FileError::Checksum),
                "len {len}"
            );
        }
        let mut flipped = bytes.clone();
        flipped[2000] ^= 1;
        assert!(matches!(read(&flipped, chain_id, &beacon, period()), FileError::Checksum));

        // A body that matches its checksum but does not decode: the update cut inside its fixed
        // part. A cut at the end would only shorten the finalized header's `extra_data`.
        let mut short = bytes[..FIXED_LEN + 100].to_vec();
        short.extend_from_slice(&Sha256::digest(&short));
        let err = read(&short, chain_id, &beacon, period());
        assert!(matches!(err, FileError::Decode(_)), "{err}");

        let older = with_version(&bytes, 1);
        assert!(matches!(read(&older, chain_id, &beacon, period()), FileError::Version(1)));

        assert!(matches!(
            read(&bytes, 943, &beacon, period()),
            FileError::ChainId { got: 369, want: 943 }
        ));
        let other = PulsechainBeacon { genesis_validators_root: B256::repeat_byte(1), ..beacon };
        let err = read(&bytes, chain_id, &other, period());
        assert!(
            matches!(err, FileError::GenesisValidatorsRoot { got, want } if got == beacon.genesis_validators_root && want == B256::repeat_byte(1)),
            "{err}"
        );
        assert!(matches!(
            read(&bytes, chain_id, &beacon, period() + 1),
            FileError::Period { name, got } if name == period() + 1 && got == period()
        ));

        let saved = bootstrap(real_slot());
        let bytes = encode_file(chain_id, &beacon, &saved);
        assert_eq!(
            decode_bootstrap(&bytes, chain_id, &beacon, Preset::PULSECHAIN, root(&saved)).unwrap(),
            saved
        );
        let name = B256::repeat_byte(2);
        let err =
            decode_bootstrap(&bytes, chain_id, &beacon, Preset::PULSECHAIN, name).unwrap_err();
        assert!(
            matches!(err, FileError::Root { name: n, got } if n == name && got == root(&saved)),
            "{err}"
        );
    }

    /// The self-check store is saved and loads back with its committees. A file that is
    /// damaged, for another chain, or older than a checkpoint may be is not used.
    #[tokio::test]
    async fn the_self_check_store_loads_back_unless_it_does_not_check_out() {
        let datadir = tempfile::tempdir().unwrap();
        let archive = open(datadir.path(), 369).await;
        let now = at_slot(real_slot(), Duration::from_secs(60));
        assert!(archive.load_store(now).await.unwrap().is_none());

        let store = real_store();
        let with_next = LightClientStore::restore(
            Preset::PULSECHAIN,
            pins(369),
            store.finalized_header().clone(),
            store.current_sync_committee().clone(),
            Some(store.current_sync_committee().clone()),
        )
        .unwrap();
        for saved in [&store, &with_next] {
            archive.save_store(saved).await.unwrap();
            let loaded = archive.load_store(now).await.unwrap().unwrap();
            assert_eq!(loaded.finalized_header(), saved.finalized_header());
            assert_eq!(loaded.current_sync_committee(), saved.current_sync_committee());
            assert_eq!(loaded.next_sync_committee(), saved.next_sync_committee());
        }
        assert_eq!(names(archive.dir()), [BOOTSTRAPS_DIR, STORE_FILE, UPDATES_DIR]);

        let limit = MAX_CHECKPOINT_AGE;
        assert!(archive.load_store(at_slot(real_slot(), limit)).await.unwrap().is_some());
        let err = archive
            .load_store(at_slot(real_slot(), limit + Duration::from_secs(1)))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FileError::Stale { slot, age_days: 31 } if slot == real_slot()),
            "{err}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "the saved store is 31 days old at slot {}, over the checkpoint age limit",
                real_slot()
            )
        );

        let on_943 = open(datadir.path(), 943).await;
        std::fs::copy(archive.dir().join(STORE_FILE), on_943.dir().join(STORE_FILE)).unwrap();
        let err = on_943.load_store(now).await.unwrap_err();
        assert!(matches!(err, FileError::ChainId { got: 369, want: 943 }), "{err}");

        let file = archive.dir().join(STORE_FILE);
        let mut bytes = std::fs::read(&file).unwrap();
        bytes[100] ^= 1;
        std::fs::write(&file, bytes).unwrap();
        assert!(matches!(archive.load_store(now).await.unwrap_err(), FileError::Checksum));
    }

    /// The period updates of a synthetic minimal-preset chain, updates that do not chain, and
    /// the self-check stores of the chain's periods.
    struct Synthetic {
        pins: PulsechainBeacon,
        /// The updates of periods 1, 2 and 3.
        first: LightClientUpdate,
        second: LightClientUpdate,
        third: LightClientUpdate,
        /// Period 1 with a next committee that does not sign period 2.
        bad: LightClientUpdate,
        /// Period 3 with a signature that period 3's committee did not make.
        bad_third: LightClientUpdate,
        /// The bootstrap at the checkpoint of each period, by period.
        bootstraps: BTreeMap<u64, LightClientBootstrap>,
        /// A store bootstrapped at the checkpoint of each period, by period.
        stores: BTreeMap<u64, LightClientStore>,
    }

    fn synthetic_updates() -> Synthetic {
        let checked = |chain: &TestChain, f| {
            CheckedState::new(PRESET, &chain.pins, chain.at(f), &chain.states[&f]).unwrap()
        };
        let update = |chain: &TestChain, f, g| {
            checked(chain, f).period_update(chain.at(g), chain.at(f + 1)).unwrap()
        };
        let mut chain = TestChain::new();
        chain.extend(64..88);
        chain.checkpoint(88, 72);
        chain.extend(89..152);
        chain.checkpoint(152, 136);
        chain.extend(153..216);
        chain.checkpoint(216, 200);
        chain.extend([217]);
        let (first, second, third) =
            (update(&chain, 88, 72), update(&chain, 152, 136), update(&chain, 216, 200));
        let bad = LightClientUpdate { next_sync_committee: committee(7), ..first.clone() };
        let bad_third =
            LightClientUpdate { sync_aggregate: second.sync_aggregate.clone(), ..third.clone() };
        let bootstraps: BTreeMap<u64, LightClientBootstrap> = [(1, 88), (2, 152), (3, 216)]
            .into_iter()
            .map(|(period, f)| (period, checked(&chain, f).bootstrap()))
            .collect();
        let stores = bootstraps
            .iter()
            .map(|(&period, bootstrap)| {
                let root = bootstrap.header.beacon.hash_tree_root();
                let store =
                    LightClientStore::bootstrap(PRESET, chain.pins, root, bootstrap).unwrap();
                (period, store)
            })
            .collect();
        Synthetic { pins: chain.pins, first, second, third, bad, bad_third, bootstraps, stores }
    }

    /// Opens the synthetic archive in `datadir`, with `anchor` as the store at the pin.
    async fn open_synthetic(
        datadir: &Path,
        pins: PulsechainBeacon,
        anchor: Option<&LightClientStore>,
    ) -> Archive {
        Archive::open(datadir, 1, PRESET, pins, anchor.cloned()).await.unwrap()
    }

    /// The path of a synthetic update file named `name`.
    fn synthetic_path(datadir: &tempfile::TempDir, name: &str) -> PathBuf {
        datadir.path().join("1").join(UPDATES_DIR).join(name)
    }

    /// Writes the files of `updates` in a new synthetic archive, as a past run left them.
    fn write_synthetic(
        pins: PulsechainBeacon,
        updates: &[&LightClientUpdate],
    ) -> tempfile::TempDir {
        let datadir = tempfile::tempdir().unwrap();
        let dir = datadir.path().join("1").join(UPDATES_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        for update in updates {
            let period = PRESET.period_at_slot(update.attested_header.beacon.slot);
            let path = free_update_path(&dir, period).unwrap();
            write_atomic(&path, &encode_file(1, &pins, *update)).unwrap();
        }
        datadir
    }

    /// Opens the synthetic archive of `updates`, as a past run left them, with `anchor` as the
    /// store at the pin, and checks it against `store`. Returns the store as the check moved it.
    async fn checked(
        pins: PulsechainBeacon,
        updates: &[&LightClientUpdate],
        anchor: Option<&LightClientStore>,
        store: &LightClientStore,
    ) -> (tempfile::TempDir, Archive, LightClientStore) {
        let datadir = write_synthetic(pins, updates);
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        let store = archive.check(store.clone(), u64::MAX).await.unwrap();
        (datadir, archive, store)
    }

    /// After open the archive serves no stored update until it checks them. Walking up, a store
    /// verifies and moves through the newer updates. With the anchor at the oldest stored period,
    /// a self-check store at any stored period serves the whole chain. Without it, the updates
    /// below the self-check store are not served.
    #[tokio::test]
    async fn the_stored_updates_are_served_once_the_self_check_store_checks_them() {
        let Synthetic { pins, first, second, third, stores, .. } = synthetic_updates();
        let whole = BTreeMap::from([(1, first.clone()), (2, second.clone()), (3, third.clone())]);
        let datadir = write_synthetic(pins, &[&first, &second, &third]);
        let mut archive = open_synthetic(datadir.path(), pins, None).await;
        assert!(!archive.is_verified());
        assert!(served(&archive).is_empty());
        assert!(archive.updates_json().is_empty());
        assert_eq!(archive.unchained().len(), 3);
        let store = archive.check(stores[&1].clone(), u64::MAX).await.unwrap();
        assert!(archive.is_verified());
        assert_eq!(served(&archive), whole);
        assert!(archive.updates_json().keys().eq([&1, &2, &3]));
        assert!(archive.unchained().is_empty());
        // The store moved through periods 2 and 3, and learned nothing past 3.
        assert_eq!(store.period(), 3);
        assert_eq!(store.next_sync_committee(), Some(&committee(4)));
        drop(archive);

        for period in [2, 3] {
            let mut archive = open_synthetic(datadir.path(), pins, Some(&stores[&1])).await;
            let store = archive.check(stores[&period].clone(), u64::MAX).await.unwrap();
            assert_eq!(served(&archive), whole, "store at period {period}");
            assert_eq!(store.period(), 3);

            let mut archive = open_synthetic(datadir.path(), pins, None).await;
            archive.check(stores[&period].clone(), u64::MAX).await.unwrap();
            let above: BTreeMap<_, _> = whole.clone().split_off(&period);
            assert_eq!(served(&archive), above, "store at period {period}, no anchor");
        }

        // Period 3 has no stored update. The anchor's walk serves periods 1 and 2, and the store
        // at period 3 stays where it is.
        let (_datadir, archive, store) =
            checked(pins, &[&first, &second], Some(&stores[&1]), &stores[&3]).await;
        assert_eq!(served(&archive), BTreeMap::from([(1, first), (2, second)]));
        assert_eq!(store.period(), 3);
        assert_eq!(store.next_sync_committee(), None);
    }

    /// A newer stored update that does not chain is not served, and it does not evict the
    /// chain below it. It stays in place, and the update the store accepts for its period is
    /// written beside it. Nothing is moved or renamed.
    #[tokio::test]
    async fn a_newer_hostile_update_cannot_evict_the_chain() {
        let Synthetic { pins, first, second, third, bad_third, stores, .. } = synthetic_updates();
        let kept = BTreeMap::from([(1, first.clone()), (2, second.clone())]);
        let anchor = Some(&stores[&1]);
        for period in [2, 3] {
            let (datadir, archive, _) =
                checked(pins, &[&first, &second, &bad_third], anchor, &stores[&period]).await;
            assert_eq!(served(&archive), kept, "store at period {period}");
            assert!(archive.updates_json().keys().eq([&1, &2]));
            assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.ssz", "2.ssz", "3.ssz"]);
            assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "3.ssz")]));
        }

        let (datadir, mut archive, _) =
            checked(pins, &[&first, &second, &bad_third], anchor, &stores[&3]).await;
        let hostile = std::fs::read(synthetic_path(&datadir, "3.ssz")).unwrap();
        assert!(archive.save_update(third.clone()).await.unwrap());
        assert_eq!(archive.update(3), Some(&third));
        assert_eq!(served(&archive).len(), 3);
        assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.ssz", "2.ssz", "3.1.ssz", "3.ssz"]);
        assert_eq!(std::fs::read(synthetic_path(&datadir, "3.ssz")).unwrap(), hostile);
        drop(archive);

        // After a restart the accepted file chains and the hostile one stays unserved.
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        archive.check(stores[&2].clone(), u64::MAX).await.unwrap();
        assert_eq!(archive.update(3), Some(&third));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "3.ssz")]));
    }

    /// Older stored history that does not chain neither blocks nor evicts the updates that the
    /// self-check store verifies: they are served, the older history is not, and it stays in
    /// place.
    #[tokio::test]
    async fn old_hostile_history_cannot_block_the_chain() {
        let Synthetic { pins, second, third, bad, stores, .. } = synthetic_updates();
        let kept = BTreeMap::from([(2, second.clone()), (3, third.clone())]);
        let anchor = Some(&stores[&1]);
        let (datadir, archive, _) =
            checked(pins, &[&bad, &second, &third], anchor, &stores[&2]).await;
        assert_eq!(served(&archive), kept);
        assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.ssz", "2.ssz", "3.ssz"]);
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.ssz")]));

        let (_datadir, mut archive, _) = checked(pins, &[&bad, &second], anchor, &stores[&2]).await;
        assert!(archive.save_update(third.clone()).await.unwrap());
        assert_eq!(served(&archive), kept);
        assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.ssz", "2.ssz", "3.ssz"]);

        // An update the store accepts in a period of the old history is written beside it.
        let (_datadir, mut archive, _) = checked(pins, &[&bad], anchor, &stores[&1]).await;
        let Synthetic { first, .. } = synthetic_updates();
        assert!(archive.save_update(first.clone()).await.unwrap());
        assert_eq!(served(&archive), BTreeMap::from([(1, first)]));
        assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.1.ssz", "1.ssz"]);
    }

    /// Format version 1 files come from builds whose store an upstream root could anchor, so
    /// such a build stored updates that no trusted committee signed. They are not read: a
    /// forged update of version 1 that carries the store's committee as its next one, with
    /// branches that check out against its own header, is not served. The update this build's
    /// store verified for the period is served, and the forged file stays in place.
    #[tokio::test]
    async fn an_update_from_an_older_format_is_not_served() {
        let Synthetic { pins, first, second, stores, .. } = synthetic_updates();
        let forged = LightClientUpdate {
            sync_aggregate: second.sync_aggregate.clone(),
            signature_slot: first.signature_slot + 1,
            ..first.clone()
        };
        assert!(proofs_check_out(PRESET, &pins, &forged));
        assert_eq!(forged.next_sync_committee, *stores[&2].current_sync_committee());
        let datadir = write_synthetic(pins, &[&forged, &first, &second]);
        let path = synthetic_path(&datadir, "1.ssz");
        std::fs::write(&path, with_version(&std::fs::read(&path).unwrap(), 1)).unwrap();

        let mut archive = open_synthetic(datadir.path(), pins, Some(&stores[&1])).await;
        archive.check(stores[&2].clone(), u64::MAX).await.unwrap();
        assert_eq!(served(&archive), BTreeMap::from([(1, first), (2, second)]));
        assert_eq!(archive.unchained(), BTreeSet::from([path]));
    }

    /// A stored bootstrap whose committee differs from the one that the self-check store, or
    /// the stored chain, verified for its period is not served after the check, as one that a
    /// store at another root stored. One whose period's committee is not known is served.
    #[tokio::test]
    async fn a_stored_bootstrap_with_another_committee_is_not_served() {
        let Synthetic { pins, first, second, bootstraps, stores, .. } = synthetic_updates();
        let other = |period: u64| {
            let mut bootstrap = LightClientBootstrap {
                current_sync_committee: committee(7),
                ..bootstraps[&period].clone()
            };
            bootstrap.header.beacon.slot += 1;
            bootstrap
        };
        let datadir = write_synthetic(pins, &[&first, &second]);
        let anchor = Some(&stores[&1]);
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        let saved = [bootstraps[&1].clone(), other(1), bootstraps[&2].clone(), other(2)]
            .into_iter()
            .chain([bootstraps[&3].clone(), other(3)]);
        let roots: Vec<B256> = saved.clone().map(|bootstrap| root(&bootstrap)).collect();
        for bootstrap in saved {
            assert!(archive.save_bootstrap(bootstrap).await.unwrap());
        }
        drop(archive);

        // The store at period 3 knows committee 3, and the update of period 1, which the walk
        // from the anchor verified, proves committee 2. The check looks no further down.
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        assert!(roots.iter().all(|root| archive.has_bootstrap(root)));
        archive.check(stores[&3].clone(), u64::MAX).await.unwrap();
        let served: Vec<bool> = roots.iter().map(|root| archive.has_bootstrap(root)).collect();
        assert_eq!(served, [true, true, true, false, true, false]);
        assert_eq!(archive.bootstrap(roots[3]).await.unwrap(), None);
        assert_eq!(archive.bootstrap(roots[4]).await.unwrap(), Some(bootstraps[&3].clone()));
    }

    /// A missing period ends the chain: the stored updates beyond it are not served, and stay
    /// in place.
    #[tokio::test]
    async fn a_gap_ends_the_chain() {
        let Synthetic { pins, first, third, stores, .. } = synthetic_updates();
        let anchor = Some(&stores[&1]);
        let (datadir, archive, _) = checked(pins, &[&first, &third], None, &stores[&3]).await;
        assert_eq!(served(&archive), BTreeMap::from([(3, third.clone())]));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.ssz")]));

        let (datadir, archive, _) = checked(pins, &[&first, &third], anchor, &stores[&2]).await;
        assert_eq!(served(&archive), BTreeMap::from([(1, first.clone())]));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "3.ssz")]));

        let (_datadir, archive, _) = checked(pins, &[&first], None, &stores[&3]).await;
        assert!(served(&archive).is_empty());
        assert!(archive.updates_json().is_empty());
        assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.ssz"]);
    }

    /// A self-check store below the stored period updates cannot judge them. They stay in
    /// place, unserved, until the store verifies its way up to them: then they are served and
    /// the store moves through them.
    #[tokio::test]
    async fn stored_updates_above_the_store_wait_until_it_reaches_them() {
        let Synthetic { pins, first, second, third, stores, .. } = synthetic_updates();
        let (_datadir, mut archive, store) =
            checked(pins, &[&second, &third], None, &stores[&1]).await;
        assert!(archive.is_verified());
        assert!(served(&archive).is_empty());
        assert_eq!(archive.unchained().len(), 2);
        assert_eq!(archive.extend(&store, u64::MAX).await.unwrap().map(|s| s.period()), None);

        // The store accepts the period 1 update, so it learns period 2's committee.
        assert!(archive.save_update(first.clone()).await.unwrap());
        let mut store = store;
        store.process_update(&first, u64::MAX).unwrap();
        let moved = archive.extend(&store, u64::MAX).await.unwrap().unwrap();
        assert_eq!(moved.period(), 3);
        assert_eq!(served(&archive), BTreeMap::from([(1, first), (2, second), (3, third)]));
        assert!(archive.unchained().is_empty());
        assert_eq!(archive.extend(&moved, u64::MAX).await.unwrap().map(|s| s.period()), None);
    }

    /// Of two stored files of a period that both chain, the first by name is served and the
    /// other stays in place, unserved. A file that an older version set aside is left alone.
    #[tokio::test]
    async fn a_second_file_of_a_period_stays_in_place() {
        let Synthetic { pins, first, second, stores, .. } = synthetic_updates();
        let later = LightClientUpdate { signature_slot: first.signature_slot + 1, ..first.clone() };
        let datadir = write_synthetic(pins, &[&first, &later, &second]);
        std::fs::write(synthetic_path(&datadir, "2.ssz.unchained"), b"earlier").unwrap();
        let mut archive = open_synthetic(datadir.path(), pins, Some(&stores[&1])).await;
        archive.check(stores[&2].clone(), u64::MAX).await.unwrap();
        assert_eq!(archive.update(1), Some(&first));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.1.ssz")]));
        assert_eq!(
            names(&archive.dir().join(UPDATES_DIR)),
            ["1.1.ssz", "1.ssz", "2.ssz", "2.ssz.unchained"]
        );
    }

    /// Each stored file outside the chain is logged once, however often the archive checks.
    #[tokio::test]
    async fn a_file_outside_the_chain_is_logged_once() {
        let Synthetic { pins, first, second, bad_third, stores, .. } = synthetic_updates();
        let datadir = write_synthetic(pins, &[&first, &second, &bad_third]);
        let logs = Logs::capture();
        let mut archive = open_synthetic(datadir.path(), pins, Some(&stores[&1])).await;
        let store = archive.check(stores[&2].clone(), u64::MAX).await.unwrap();
        archive.extend(&store, u64::MAX).await.unwrap();
        archive.check(store, u64::MAX).await.unwrap();
        let text = logs.text();
        let warning =
            "no walk up from the pin, the anchor or the self-check store verifies a stored";
        assert_eq!(text.matches(warning).count(), 1, "{text}");
        assert!(text.contains("3.ssz"), "{text}");
    }

    /// A write that fails serves nothing new, and the next write tries again.
    #[tokio::test]
    async fn a_failed_write_serves_nothing_new_and_is_tried_again() {
        let Synthetic { pins, first, second, stores, .. } = synthetic_updates();
        let (datadir, mut archive, _) =
            checked(pins, &[&first], Some(&stores[&1]), &stores[&2]).await;
        let dir = datadir.path().join("1").join(UPDATES_DIR);
        // A plain file where the directory was: no process, root included, can write under it.
        let aside = datadir.path().join("updates-aside");
        std::fs::rename(&dir, &aside).unwrap();
        std::fs::write(&dir, b"").unwrap();
        archive.save_update(second.clone()).await.unwrap_err();
        assert_eq!(served(&archive), BTreeMap::from([(1, first.clone())]));
        assert!(archive.updates_json().keys().eq([&1]));

        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&aside, &dir).unwrap();
        assert!(archive.save_update(second.clone()).await.unwrap());
        assert_eq!(served(&archive), BTreeMap::from([(1, first), (2, second)]));
        assert_eq!(names(&dir), ["1.ssz", "2.ssz"]);
    }

    #[test]
    fn a_file_larger_than_the_limit_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.ssz");
        std::fs::write(&path, vec![0; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(
            matches!(read_file(&path), Err(FileError::TooLarge(len)) if len == MAX_FILE_BYTES + 1)
        );
        let err = read_file(&dir.path().join("missing.ssz")).unwrap_err();
        assert!(matches!(&err, FileError::Read(e) if e.kind() == io::ErrorKind::NotFound), "{err}");
    }

    /// The value of `lc_server_archive_unchained_updates` that `recorder` holds.
    fn unchained_gauge(recorder: &metrics_exporter_prometheus::PrometheusRecorder) -> Option<u64> {
        recorder.handle().render().lines().find_map(|line| {
            line.strip_prefix("lc_server_archive_unchained_updates ")?.parse().ok()
        })
    }

    /// A forger who can write `updates/1.ssz` makes an update whose next committee is the real
    /// (public) committee of period 2, with branches that check out against its own header. No
    /// committee signed it. After a restart it is not served: the walk from the anchor at period
    /// 1 checks its signature, and the self-check store at period 2 does not walk down to it.
    /// The genuine update of period 1, written beside it, is served.
    #[tokio::test]
    async fn a_forged_update_below_the_store_is_not_served_after_a_restart() {
        let Synthetic { pins, first, second, third, stores, .. } = synthetic_updates();
        let forged = LightClientUpdate {
            sync_aggregate: second.sync_aggregate.clone(),
            signature_slot: first.signature_slot + 1,
            ..first.clone()
        };
        assert!(proofs_check_out(PRESET, &pins, &forged));
        assert_eq!(forged.next_sync_committee, *stores[&2].current_sync_committee());
        let anchor = Some(&stores[&1]);
        let datadir = write_synthetic(pins, &[&forged, &second, &third]);
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        archive.check(stores[&2].clone(), u64::MAX).await.unwrap();
        assert_eq!(served(&archive), BTreeMap::from([(2, second.clone()), (3, third.clone())]));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.ssz")]));

        let datadir = write_synthetic(pins, &[&forged, &first, &second, &third]);
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        archive.check(stores[&2].clone(), u64::MAX).await.unwrap();
        assert_eq!(served(&archive), BTreeMap::from([(1, first), (2, second), (3, third)]));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.ssz")]));
    }

    /// The updates that the self-check store accepted from the pin's period up are served after
    /// a restart, from a saved store above them.
    #[tokio::test]
    async fn genuine_updates_from_the_pin_up_are_served_after_a_restart() {
        let Synthetic { pins, first, second, third, stores, .. } = synthetic_updates();
        let anchor = Some(&stores[&1]);
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        let mut store = archive.check(stores[&1].clone(), u64::MAX).await.unwrap();
        for update in [&first, &second, &third] {
            assert!(archive.save_update(update.clone()).await.unwrap());
            store.process_update(update, u64::MAX).unwrap();
        }
        drop(archive);

        let whole = BTreeMap::from([(1, first), (2, second), (3, third)]);
        let mut archive = open_synthetic(datadir.path(), pins, anchor).await;
        assert!(served(&archive).is_empty());
        let restarted = archive.check(store.clone(), u64::MAX).await.unwrap();
        assert_eq!(served(&archive), whole);
        assert!(archive.unchained().is_empty());
        assert_eq!(restarted.finalized_header(), store.finalized_header());
    }

    /// The stored updates below the pin's period have no trusted committee to check their
    /// signatures, so after a restart they stay on disk, unserved, and are counted.
    #[tokio::test]
    async fn a_file_below_the_pin_is_unserved_and_counted() {
        let Synthetic { pins, first, second, third, stores, .. } = synthetic_updates();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let datadir = write_synthetic(pins, &[&first, &second, &third]);
        let mut archive = open_synthetic(datadir.path(), pins, Some(&stores[&2])).await;
        archive.check(stores[&3].clone(), u64::MAX).await.unwrap();
        assert_eq!(served(&archive), BTreeMap::from([(2, second), (3, third)]));
        assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.ssz")]));
        assert_eq!(unchained_gauge(&recorder), Some(1));
        assert_eq!(names(&archive.dir().join(UPDATES_DIR)), ["1.ssz", "2.ssz", "3.ssz"]);
    }

    /// A forger who can write `updates/1.ssz`, below the anchor's period 2, makes an update whose
    /// next committee is the real committee of period 2, with branches that check out. After a
    /// restart it is not served, with or without a pin at period 1: the anchor's walk starts
    /// above it, and the pin's walk checks its signature. The anchor's walk serves periods 2 and
    /// 3, below the saved store at period 3.
    #[tokio::test]
    async fn a_forged_update_below_the_anchor_is_not_served_after_a_restart() {
        let Synthetic { pins, first, second, third, stores, .. } = synthetic_updates();
        let forged = LightClientUpdate {
            sync_aggregate: second.sync_aggregate.clone(),
            signature_slot: first.signature_slot + 1,
            ..first.clone()
        };
        assert!(proofs_check_out(PRESET, &pins, &forged));
        assert_eq!(forged.next_sync_committee, *stores[&2].current_sync_committee());
        for pin in [None, Some(&stores[&1])] {
            let datadir = write_synthetic(pins, &[&forged, &second, &third]);
            let mut archive = open_synthetic(datadir.path(), pins, pin).await;
            assert!(archive.save_anchor(&stores[&2]).await.unwrap());
            drop(archive);

            let mut archive = open_synthetic(datadir.path(), pins, pin).await;
            archive.check(stores[&3].clone(), u64::MAX).await.unwrap();
            let kept = BTreeMap::from([(2, second.clone()), (3, third.clone())]);
            assert_eq!(served(&archive), kept, "pin {}", pin.is_some());
            assert_eq!(archive.unchained(), BTreeSet::from([synthetic_path(&datadir, "1.ssz")]));
        }
    }

    /// Where the walks take different files of a period, the one from the self-check store is
    /// served, else the one from the anchor, else the one from the pin. Here `1.ssz` is signed
    /// by period 1's committee, but at a block whose state has another next committee. A store
    /// at period 1 that knows the next committee takes `1.1.ssz`; one that does not takes
    /// `1.ssz`, and its walk then ends at period 2.
    #[tokio::test]
    async fn the_walks_prefer_the_store_then_the_anchor_then_the_pin() {
        let Synthetic { pins, first, second, stores, .. } = synthetic_updates();
        let mut fork = TestChain::new();
        fork.pins = pins;
        fork.extend(64..88);
        fork.checkpoint_with_next(88, 72, &committee(7));
        fork.extend([89]);
        let forked = CheckedState::new(PRESET, &pins, fork.at(88), &fork.states[&88])
            .unwrap()
            .period_update(fork.at(72), fork.at(89))
            .unwrap();
        assert_eq!(forked.next_sync_committee, committee(7));
        let mut knows_next = stores[&1].clone();
        knows_next.process_update(&first, u64::MAX).unwrap();
        let (no_next, at_2) = (&stores[&1], &stores[&2]);
        let genuine = BTreeMap::from([(1, first.clone()), (2, second.clone())]);

        // The self-check store, then the anchor, then the pin, and what is served.
        let cases = [
            (&knows_next, Some(no_next), Some(no_next), &genuine),
            (&knows_next, None, Some(no_next), &genuine),
            (at_2, Some(&knows_next), Some(no_next), &genuine),
            (at_2, Some(no_next), Some(&knows_next), &BTreeMap::from([(1, forked.clone())])),
        ];
        for (case, &(store, anchor, pin, want)) in cases.iter().enumerate() {
            let datadir = write_synthetic(pins, &[&forked, &first, &second]);
            let mut archive = open_synthetic(datadir.path(), pins, pin).await;
            if let Some(anchor) = anchor {
                assert!(archive.save_anchor(anchor).await.unwrap());
            }
            archive.check(store.clone(), u64::MAX).await.unwrap();
            let mut want = want.clone();
            if store.period() == 2 {
                want.insert(2, second.clone());
            }
            assert_eq!(served(&archive), want, "case {case}");
        }
    }

    /// The anchor file is written once. A later save, in this archive or after a restart, writes
    /// nothing, and neither does one when the file does not check out: it stays in place.
    #[tokio::test]
    async fn the_anchor_file_is_written_once_and_never_replaced() {
        let datadir = tempfile::tempdir().unwrap();
        let mut archive = open(datadir.path(), 369).await;
        let file = archive.dir().join(ANCHOR_FILE);
        assert!(archive.save_anchor(&real_store()).await.unwrap());
        let written = std::fs::read(&file).unwrap();
        let with_next = LightClientStore::restore(
            Preset::PULSECHAIN,
            pins(369),
            real_store().finalized_header().clone(),
            real_store().current_sync_committee().clone(),
            Some(real_store().current_sync_committee().clone()),
        )
        .unwrap();
        assert!(!archive.save_anchor(&with_next).await.unwrap());
        drop(archive);
        let mut archive = open(datadir.path(), 369).await;
        assert!(!archive.save_anchor(&with_next).await.unwrap());
        assert_eq!(std::fs::read(&file).unwrap(), written);

        // Damaged, of another version, or of another chain.
        let mut flipped = written.clone();
        flipped[100] ^= 1;
        let on_943 = open(datadir.path(), 943).await;
        let others = [
            (archive.dir().to_path_buf(), flipped),
            (archive.dir().to_path_buf(), with_version(&written, 1)),
            (on_943.dir().to_path_buf(), written.clone()),
        ];
        for (dir, bytes) in others {
            let file = dir.join(ANCHOR_FILE);
            std::fs::write(&file, &bytes).unwrap();
            let chain_id = if dir.ends_with("943") { 943 } else { 369 };
            let mut archive = open(datadir.path(), chain_id).await;
            assert!(!archive.save_anchor(&with_next).await.unwrap());
            assert_eq!(std::fs::read(&file).unwrap(), bytes);
        }
    }

    /// The final step of the anchor write never replaces a file. Here another process writes
    /// the anchor file after the check that it is missing: its file stays, and no temporary
    /// file is left.
    #[test]
    fn the_anchor_write_keeps_a_file_that_appears_after_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHOR_FILE);
        std::fs::write(&path, b"theirs").unwrap();
        assert!(!write_new_unchecked(&path, b"ours").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"theirs");
        assert_eq!(names(dir.path()), [ANCHOR_FILE]);

        let path = dir.path().join("new.ssz");
        assert!(write_new_unchecked(&path, b"ours").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"ours");
        assert_eq!(names(dir.path()), [ANCHOR_FILE, "new.ssz"]);
    }

    /// The anchor file has no age limit, as the pin's store has none: it only checks the
    /// signatures of the stored updates. The store file has one.
    #[test]
    fn the_anchor_file_has_no_age_limit() {
        let (beacon, preset) = (pins(369), Preset::PULSECHAIN);
        let bytes = encode_file(369, &beacon, &StoreBody(&real_store()));
        let old = at_slot(real_slot(), MAX_CHECKPOINT_AGE * 10);
        assert!(matches!(
            decode_store(&bytes, 369, &beacon, preset, old),
            Err(FileError::Stale { .. })
        ));
        let anchor = decode_anchor(&bytes, 369, &beacon, preset).unwrap();
        assert_eq!(anchor.finalized_header(), real_store().finalized_header());
        assert!(matches!(
            decode_anchor(&bytes, 943, &beacon, preset),
            Err(FileError::ChainId { got: 369, want: 943 })
        ));
    }
}
