//! `--head.verify=sync-committee`: heads and finality from light-client updates that a
//! [`LightClientStore`] verified.
//!
//! Each source reports the root of an update's attested header only after the store has checked
//! the update's signature and branches, so a source cannot name a head the committee did not
//! sign. The block under a verified root is taken only with the verified execution `block_hash`
//! and beacon `parent_root`. A verified finality update moves finality on its own. A task fetches
//! `light_client/updates` for the next committee, at start and whenever the store lacks it.
//!
//! With a store file the store is written on a committee change or a finality move, at most once
//! every [`SAVE_EVERY`]. A restart with a usable file seeds from it, not from the anchor. So does
//! a store bootstrapped at a trusted checkpoint.

use super::{
    note_answer, quick_reconnect, BeaconClient, Event, Fetched, Follower, Reports, Topics,
    FINALITY_EVERY, MIN_SSE_IDLE, MIN_SSE_WATCHDOG,
};
use crate::{
    config::SLOT,
    light_client::{bootstrap_at_anchor, source_pins, PinError, StoreOrigin, UPDATES_PATH},
    metrics::FailureSource,
    payload::PayloadError,
    sync_committee::{
        LightClientHeader, LightClientStore, LightClientUpdate, Preset, SyncCommitteeError,
    },
    sync_committee_file::SyncCommitteeFile,
};
use alloy_primitives::B256;
use reth_pulsechain_forks::network::BeaconFork;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Notify, time::sleep};

/// How many verified attested headers are kept for the coordinator to look up by root.
const MAX_VERIFIED: usize = 64;
/// How many finalized headers proven by signed updates are kept to confirm anchor blocks.
const MAX_FINALIZED: usize = 8;
/// The clock drift allowed when the wall clock gives the current slot.
const CLOCK_TOLERANCE: Duration = Duration::from_millis(500);
/// The least time between two writes of the store file.
const SAVE_EVERY: Duration = Duration::from_secs(10 * 60);
/// The longest wait between two reads of an unchecked source's pinned chain values.
const MAX_PIN_RETRY: Duration = Duration::from_secs(5 * 60);
/// The most times the wait before an event stream reopens doubles, after streams in a row that
/// were closed for a rejected update.
const MAX_STREAM_STRIKES: u32 = 5;

/// What a verified light-client header says about its block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verified {
    /// The beacon block root.
    pub(super) root: B256,
    /// The execution block hash.
    pub(super) block_hash: B256,
    /// The execution block number.
    pub(super) number: u64,
    /// The beacon `parent_root`.
    pub(super) parent_root: B256,
}

impl Verified {
    fn of(header: &LightClientHeader) -> Self {
        Self {
            root: header.beacon.hash_tree_root(),
            block_hash: header.execution.block_hash,
            number: header.execution.block_number,
            parent_root: header.beacon.parent_root,
        }
    }
}

/// What one update the store accepted changed.
#[derive(Debug, Clone)]
struct Accepted {
    /// Its attested header, from Capella on: only those carry an execution block.
    head: Option<Verified>,
    /// The store's new finalized header, when the update moved it.
    finalized: Option<Verified>,
    /// The store file's new bytes, when a write is due.
    save: Option<Vec<u8>>,
}

/// Why the store refused an update a source sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// For a reason an honest source can cause (see [`is_bad_data`]).
    Unused,
    /// As bad data: it counts against its source.
    Bad,
}

/// Why a source is not used yet, or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinCheck {
    /// It did not answer the pinned chain values yet.
    Unchecked,
    /// Its values differ from the pins: it is on another chain.
    Differs,
}

/// The store and what the follower keeps of the headers it verified.
#[derive(Debug)]
pub(super) struct SyncFollow {
    inner: parking_lot::Mutex<Inner>,
    /// The sources that are not used, by index. A source that is not here matches the pins.
    pins: parking_lot::Mutex<HashMap<usize, PinCheck>>,
    /// The sources whose last update the store rejected as bad data, by index: a rejection is
    /// logged when a source starts sending bad updates, not for each one.
    rejecting: parking_lot::Mutex<HashSet<usize>>,
    /// Whether the store came from its file or a checkpoint. The seed then comes from the
    /// store, not the anchor.
    from_store: bool,
    /// The store file, when the store is kept across restarts.
    file: Option<SyncCommitteeFile>,
}

#[derive(Debug)]
struct Inner {
    store: LightClientStore,
    /// The store's first finalized header: with a bootstrap, the anchor block the seed must be.
    anchor: Verified,
    /// Verified attested headers, oldest first.
    heads: VecDeque<Verified>,
    /// Finalized headers that signed updates proved, oldest first. The bootstrap is not one.
    finalized: VecDeque<Verified>,
    /// The store period in which the node last logged that it cannot verify a head signed now.
    unverifiable_logged: Option<u64>,
    /// When the store file was last written.
    last_save: Option<Instant>,
    /// Whether the store changed since that write.
    unsaved: bool,
}

impl Inner {
    /// Whether `header` is from Capella on, so it carries an execution block.
    fn is_capella(&self, header: &LightClientHeader) -> bool {
        let epoch = self.store.preset().epoch_at_slot(header.beacon.slot);
        self.store.beacon().fork_at_epoch(epoch).fork >= BeaconFork::Capella
    }

    /// What decides whether the store file must be written: the finalized slot, the period and
    /// whether the next committee is known.
    fn saved_state(&self) -> (u64, u64, bool) {
        let store = &self.store;
        (
            store.finalized_header().beacon.slot,
            store.period(),
            store.next_sync_committee().is_some(),
        )
    }
}

impl SyncFollow {
    fn new(store: LightClientStore, origin: StoreOrigin, file: Option<SyncCommitteeFile>) -> Self {
        let anchor = Verified::of(store.finalized_header());
        let from_store = !matches!(origin, StoreOrigin::Bootstrap { .. });
        let mut inner = Inner {
            store,
            anchor,
            heads: VecDeque::new(),
            finalized: VecDeque::new(),
            unverifiable_logged: None,
            last_save: None,
            unsaved: false,
        };
        // A saved finalized header counts as one a signed update proved. The run that saved it
        // verified it: that run applies updates only after its seed passed the anchor checks,
        // and it writes the file only after an update. A checkpoint header hashes to a root the
        // binary or the operator trusts.
        if from_store && inner.is_capella(inner.store.finalized_header()) {
            inner.finalized.push_back(anchor);
        }
        Self {
            inner: parking_lot::Mutex::new(inner),
            pins: Default::default(),
            rejecting: Default::default(),
            from_store,
            file,
        }
    }

    /// Whether source `idx` matches the pinned chain values, so it may be used.
    fn usable(&self, idx: usize) -> bool {
        !self.pins.lock().contains_key(&idx)
    }

    /// The store's first finalized header.
    pub(super) fn anchor(&self) -> Verified {
        self.inner.lock().anchor
    }

    /// Replaces a bootstrapped store that has not seeded the chain with a new bootstrap.
    fn replace_bootstrap(&self, store: LightClientStore) {
        let mut g = self.inner.lock();
        g.anchor = Verified::of(store.finalized_header());
        g.store = store;
        g.heads.clear();
        g.finalized.clear();
        g.unverifiable_logged = None;
    }

    /// Whether the chain seeds from the store's verified finality, not from the anchor: the
    /// store came from its file or from a checkpoint.
    pub(super) const fn seeds_from_store(&self) -> bool {
        self.from_store
    }

    fn preset(&self) -> Preset {
        self.inner.lock().store.preset()
    }

    /// The store's period.
    pub(super) fn period(&self) -> u64 {
        self.inner.lock().store.period()
    }

    /// The verified attested header with beacon root `root`.
    pub(super) fn head(&self, root: B256) -> Option<Verified> {
        self.inner.lock().heads.iter().rev().find(|v| v.root == root).copied()
    }

    /// The latest finalized header a signed update proved.
    pub(super) fn latest_finalized(&self) -> Option<Verified> {
        self.inner.lock().finalized.back().copied()
    }

    /// Whether a signed update proved `hash` finalized.
    pub(super) fn confirms(&self, hash: B256) -> bool {
        self.inner.lock().finalized.iter().any(|v| v.block_hash == hash)
    }

    /// Checks `update` and applies it to the store. The current slot comes from the wall clock;
    /// `now` decides whether a write of the store file is due.
    fn accept(
        &self,
        update: &LightClientUpdate,
        now: Instant,
    ) -> Result<Accepted, SyncCommitteeError> {
        let mut g = self.inner.lock();
        let before = g.saved_state();
        let current = current_slot(g.store.beacon().genesis_time);
        g.store.process_update(update, current)?;
        let head =
            g.is_capella(&update.attested_header).then(|| Verified::of(&update.attested_header));
        if let Some(v) = head &&
            !g.heads.contains(&v)
        {
            if g.heads.len() >= MAX_VERIFIED {
                g.heads.pop_front();
            }
            g.heads.push_back(v);
        }
        let header = g.store.finalized_header();
        let finalized =
            (header.beacon.slot > before.0 && g.is_capella(header)).then(|| Verified::of(header));
        if let Some(v) = finalized {
            if g.finalized.len() >= MAX_FINALIZED {
                g.finalized.pop_front();
            }
            g.finalized.push_back(v);
        }
        g.unsaved |= g.saved_state() != before;
        let save = match &self.file {
            Some(file) if g.unsaved && g.last_save.is_none_or(|t| now - t >= SAVE_EVERY) => {
                g.last_save = Some(now);
                g.unsaved = false;
                Some(file.encode(&g.store))
            }
            _ => None,
        };
        Ok(Accepted { head, finalized, save })
    }

    /// The `updates` the store needs, up to the wall clock's period. Without the next committee
    /// they start at the store's period, whose update brings it. With it they start at the next
    /// period, whose update rotates the committees. `None` when the store is caught up.
    fn wanted_updates(&self) -> Option<(u64, usize)> {
        let g = self.inner.lock();
        let period = g.store.period();
        let current = g.store.preset().period_at_slot(current_slot(g.store.beacon().genesis_time));
        let start = if g.store.next_sync_committee().is_some() {
            if current <= period {
                return None;
            }
            period + 1
        } else {
            period
        };
        let count = current.saturating_sub(start).saturating_add(1);
        Some((start, usize::try_from(count).unwrap_or(usize::MAX)))
    }

    /// Logs, once per period, that the store cannot verify a head signed now: its period is over
    /// and no source served the next committee, or the wall clock is two or more periods ahead
    /// and no source served the update that rotates the committees.
    fn log_unverifiable_heads(&self) {
        let mut g = self.inner.lock();
        let period = g.store.period();
        let current = g.store.preset().period_at_slot(current_slot(g.store.beacon().genesis_time));
        let next_known = g.store.next_sync_committee().is_some();
        let behind = current.saturating_sub(period);
        if behind == 0 || next_known && behind < 2 || g.unverifiable_logged == Some(period) {
            return;
        }
        g.unverifiable_logged = Some(period);
        if next_known {
            tracing::error!(
                period,
                current,
                endpoint = UPDATES_PATH,
                "the sync-committee store is two or more periods behind the wall clock and no \
                 beacon source served the update that rotates its committees; heads signed now \
                 cannot be verified, so the head goes stale"
            );
        } else {
            tracing::error!(
                period,
                endpoint = UPDATES_PATH,
                "no beacon source served a valid next sync committee for the store's period, \
                 which has ended; heads signed after it cannot be verified, so the head goes stale"
            );
        }
    }
}

/// The slot of the wall clock, [`CLOCK_TOLERANCE`] ahead.
fn current_slot(genesis_time: u64) -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default() + CLOCK_TOLERANCE;
    let since = now.as_millis().saturating_sub(u128::from(genesis_time) * 1000);
    u64::try_from(since / SLOT.as_millis()).unwrap_or(u64::MAX)
}

/// Whether a refused update shows its source sent bad data. A stale update, one signed in a
/// period whose committee the store lacks, one with few signers, one signed in a slot the clock
/// has not reached and one from a fork this binary does not know can all come from an honest
/// source.
const fn is_bad_data(e: &SyncCommitteeError) -> bool {
    match e {
        SyncCommitteeError::SlotOrder { current, signature, .. } => *current >= *signature,
        SyncCommitteeError::Stale { .. } |
        SyncCommitteeError::SignaturePeriod { .. } |
        SyncCommitteeError::TooFewParticipants { .. } |
        SyncCommitteeError::UnsupportedFork(_) |
        SyncCommitteeError::UnknownForkDigest(_) => false,
        _ => true,
    }
}

impl Follower {
    /// Takes heads and finality from light-client updates that `store` verifies
    /// (`--head.verify=sync-committee`). A store with `origin` [`StoreOrigin::Bootstrap`] must be
    /// bootstrapped at the anchor's finalized root: the seed is the block under that root, and
    /// only with the block hash the bootstrap proves. A store from the file or a checkpoint
    /// ([`StoreOrigin::Saved`], [`StoreOrigin::Checkpoint`]) seeds the chain at its latest
    /// verified finalized block, fetched from the sources.
    ///
    /// With a `file`, the store is written there on a committee change or a finality move, at
    /// most once every ten minutes.
    pub fn with_sync_committee(
        mut self,
        store: LightClientStore,
        origin: StoreOrigin,
        file: Option<SyncCommitteeFile>,
    ) -> Self {
        self.metrics.sync_committee_period.set(store.period() as f64);
        self.sync = Some(SyncFollow::new(store, origin, file));
        self
    }

    /// Marks `sources` (indices into the beacon URLs) as unchecked: their pinned chain values
    /// could not be read at start. Each source task reads them again, with backoff, before it
    /// uses its source. Call after [`Self::with_sync_committee`].
    pub fn with_unchecked_pins(self, sources: impl IntoIterator<Item = usize>) -> Self {
        if let Some(sync) = &self.sync {
            sync.pins.lock().extend(sources.into_iter().map(|idx| (idx, PinCheck::Unchecked)));
        }
        self
    }

    /// Reads the pinned chain values of an unchecked source `idx` until it answers, waiting from
    /// one `--beacon.poll` up to [`MAX_PIN_RETRY`] between tries. Returns whether the source may
    /// be used: false once its values differ from the pins.
    async fn check_pins(&self, idx: usize, client: &BeaconClient) -> bool {
        let Some(sync) = &self.sync else { return true };
        let pins = *sync.inner.lock().store.beacon();
        let mut delay = self.cfg.poll;
        while sync.pins.lock().get(&idx) == Some(&PinCheck::Unchecked) {
            match source_pins(client, &pins).await {
                Ok(()) => {
                    tracing::info!(
                        source = client.host(),
                        "the beacon source now matches the pinned chain values; using it"
                    );
                    sync.pins.lock().remove(&idx);
                }
                Err(error @ PinError::Unreadable { .. }) => {
                    tracing::debug!(
                        source = client.host(),
                        %error,
                        "the beacon source still does not answer the pinned chain values"
                    );
                    sleep(delay).await;
                    delay = (delay * 2).min(MAX_PIN_RETRY);
                }
                Err(error) => {
                    tracing::error!(
                        source = client.host(),
                        %error,
                        "the beacon source does not match the pinned chain values; it is dropped"
                    );
                    sync.pins.lock().insert(idx, PinCheck::Differs);
                }
            }
        }
        sync.usable(idx)
    }

    /// Writes the store file off the async threads. A failed write is logged; the next due
    /// write tries again.
    fn save_store(&self, bytes: Vec<u8>) {
        let Some(file) = self.sync.as_ref().and_then(|sync| sync.file.clone()) else { return };
        let span = tracing::Span::current();
        tokio::task::spawn_blocking(move || {
            let _entered = span.enter();
            match file.save(&bytes) {
                Ok(()) => tracing::debug!(bytes = bytes.len(), "saved the sync-committee store"),
                Err(e) => tracing::warn!(error = %e, "could not save the sync-committee store"),
            }
        });
    }

    /// Seeds the chain from a store loaded from its file or bootstrapped at a checkpoint,
    /// retrying with backoff (at least every 30 s). The anchor is not asked.
    ///
    /// Each try first catches the store up with `updates` and each source's latest finality
    /// update. The seed is then the latest verified finalized block, fetched from the sources
    /// with its verified `block_hash` and `parent_root`, once it is recent. The store proved it
    /// final, so finality is confirmed at once.
    pub(super) async fn seed_from_store(&self, clients: &[BeaconClient]) {
        let Some(sync) = &self.sync else { return };
        let preset = sync.preset();
        let fin = Notify::new();
        let mut delay = Duration::from_millis(500);
        loop {
            self.catch_up(clients, &fin).await;
            for (idx, client) in clients.iter().enumerate().filter(|&(i, _)| sync.usable(i)) {
                match client.light_client_finality_update(preset).await {
                    // `sync_accept` applies the finality it moves, and logs and counts a refusal.
                    Ok(update) => match self.sync_accept(idx, client.host(), &update) {
                        Ok(_) | Err(Refused::Unused | Refused::Bad) => {}
                    },
                    Err(e) => {
                        tracing::debug!(source = client.host(), error = %e, "no finality update")
                    }
                }
            }
            // `SyncFollow::new` keeps the saved or checkpoint header, so there is always one.
            if let Some(v) = sync.latest_finalized() {
                let mut order: Vec<usize> = (0..clients.len()).collect();
                self.sort_sources(&mut order);
                match self.fetch_verified(clients, &order, v).await {
                    Fetched::Block(p) if self.anchor_recent(&p.block) => {
                        tracing::info!(
                            number = v.number,
                            "seeded from the sync-committee store's finalized block; following"
                        );
                        self.chain.seed(p.block);
                        self.publish_head();
                        self.apply_verified_finality();
                        return;
                    }
                    Fetched::Block(_) => tracing::warn!(
                        number = v.number,
                        "the sync-committee store's finalized block is not recent; \
                         waiting for a newer finality update"
                    ),
                    Fetched::Bad | Fetched::Unavailable => tracing::warn!(
                        number = v.number,
                        "no beacon source served the sync-committee store's finalized block"
                    ),
                }
            }
            sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }

    /// Bootstraps the store again at the anchor's finalized root, for a bootstrap block that is
    /// too old to seed: it never becomes recent again, and the anchor has moved on. A failure is
    /// logged, and the old store stays.
    pub(super) async fn bootstrap_again(&self, anchor: &BeaconClient, clients: &[BeaconClient]) {
        let Some(sync) = &self.sync else { return };
        let (preset, pins) = {
            let g = sync.inner.lock();
            (g.store.preset(), *g.store.beacon())
        };
        let sources: Vec<usize> = (0..clients.len()).collect();
        match bootstrap_at_anchor(clients, &sources, anchor, pins, preset).await {
            Ok((_, store))
                if store.finalized_header() != sync.inner.lock().store.finalized_header() =>
            {
                tracing::info!(
                    slot = store.finalized_header().beacon.slot,
                    anchor = anchor.host(),
                    "the light-client bootstrap block is too old to seed; bootstrapped again at \
                     the anchor's finalized root"
                );
                self.metrics.sync_committee_period.set(store.period() as f64);
                sync.replace_bootstrap(store);
            }
            Ok(_) => tracing::debug!(
                anchor = anchor.host(),
                "the anchor's finalized root is still the light-client bootstrap root"
            ),
            Err(e) => tracing::warn!(
                anchor = anchor.host(),
                error = %e,
                "could not bootstrap again at the anchor's finalized root"
            ),
        }
    }

    /// Checks `update` from source `idx`. A verified update sets the sync metrics and may move
    /// finality; a bad one counts against its source.
    fn sync_accept(
        &self,
        idx: usize,
        host: &str,
        update: &LightClientUpdate,
    ) -> Result<Accepted, Refused> {
        let Some(sync) = &self.sync else { return Err(Refused::Unused) };
        match sync.accept(update, Instant::now()) {
            Ok(mut accepted) => {
                if sync.rejecting.lock().remove(&idx) {
                    tracing::info!(
                        source = host,
                        "light-client updates from the source verify again"
                    );
                }
                if let Some(bytes) = accepted.save.take() {
                    self.save_store(bytes);
                }
                self.metrics.sync_participation.set(update.sync_aggregate.participants() as f64);
                self.metrics.sync_committee_period.set(sync.period() as f64);
                if accepted.finalized.is_some() {
                    self.apply_verified_finality();
                }
                Ok(accepted)
            }
            Err(e) if is_bad_data(&e) => {
                self.metrics.proof_failure(FailureSource::Beacon);
                if let Some(n) = self.failures.lock().get_mut(idx) {
                    *n += 1;
                }
                if sync.rejecting.lock().insert(idx) {
                    tracing::warn!(source = host, error = %e, "light-client update rejected");
                } else {
                    tracing::debug!(source = host, error = %e, "light-client update rejected");
                }
                Err(Refused::Bad)
            }
            Err(e) => {
                tracing::debug!(source = host, error = %e, "light-client update not used");
                Err(Refused::Unused)
            }
        }
    }

    /// [`Self::sync_accept`] for an update a source pushed or answered: its attested root is
    /// reported as the source's head, and finality wakes the anchor check.
    fn sync_report(
        &self,
        idx: usize,
        host: &str,
        update: &LightClientUpdate,
        tx: &Reports,
        fin: &Notify,
    ) -> Result<(), Refused> {
        let accepted = self.sync_accept(idx, host, update)?;
        if let Some(head) = accepted.head {
            tx.send(idx, head.root);
        }
        if accepted.finalized.is_some() {
            fin.notify_one();
        }
        Ok(())
    }

    /// Marks the latest verified finalized block finalized once the chain holds it canonical.
    /// It needs no beacon quorum and no depth: the committee signed it.
    pub(super) fn apply_verified_finality(&self) {
        let Some(v) = self.sync.as_ref().and_then(SyncFollow::latest_finalized) else { return };
        if self.chain.finality_confirmed() && self.chain.finalized_number() >= Some(v.number) {
            return;
        }
        if !self.chain.is_canonical(&v.block_hash) {
            // Tried again when the head moves.
            return;
        }
        if let Some(block) = self.chain.by_hash(&v.block_hash) &&
            self.chain.confirm_finalized(&block)
        {
            tracing::debug!(number = v.number, "a verified finality update moved finality");
        }
    }

    /// Fetches the block under the verified root of `v`: the first one with its execution
    /// `block_hash` and beacon `parent_root`. A source that serves another block under the
    /// root is charged. `Unavailable` when a source gave no usable answer, so the root may still
    /// come; `Bad` when every source served something else.
    pub(super) async fn fetch_verified(
        &self,
        clients: &[BeaconClient],
        order: &[usize],
        v: Verified,
    ) -> Fetched {
        let mut unheard = false;
        for &i in order {
            if self.sync.as_ref().is_some_and(|sync| !sync.usable(i)) {
                unheard = true;
                continue;
            }
            let host = clients[i].host();
            let Ok(value) = self.fetch_root(clients, i, v.root).await else {
                unheard = true;
                continue;
            };
            match self.parse(value, v.root).await {
                Ok(p) if p.block.hash == v.block_hash && p.parent_root == v.parent_root => {
                    self.used(&[i], v.root);
                    return Fetched::Block(Box::new(p))
                }
                // The committee signed the root: another block under it is a lie.
                Ok(_) => self.count_failure(i, host, &PayloadError::HashMismatch),
                Err(PayloadError::Optimistic) => {
                    self.skip_optimistic(FailureSource::Beacon, host);
                    unheard = true;
                }
                Err(e) => self.count_failure(i, host, &e),
            }
        }
        if unheard {
            Fetched::Unavailable
        } else {
            Fetched::Bad
        }
    }

    /// The source task of `--head.verify=sync-committee`: light-client updates by event stream,
    /// or by polling `optimistic_update` every poll and `finality_update` every sixth.
    pub(super) async fn sync_source_task(
        self: Arc<Self>,
        idx: usize,
        client: BeaconClient,
        tx: Arc<Reports>,
        fin: Arc<Notify>,
    ) {
        if !self.check_pins(idx, &client).await {
            return;
        }
        let preset = self.sync.as_ref().map_or(Preset::PULSECHAIN, SyncFollow::preset);
        let (mut failing, mut finality_failing) = (false, false);
        self.poll_update(idx, &client, false, &tx, &fin, &mut failing).await;
        self.poll_update(idx, &client, true, &tx, &fin, &mut finality_failing).await;
        let mut last_sse: Option<Instant> = None;
        let mut reconnect = false;
        let mut quick: u32 = 0;
        let mut polls: u64 = 0;
        // Streams in a row closed for a rejected update, and the wait before the next one opens.
        let (mut strikes, mut sse_wait) = (0, self.cfg.sse_retry);
        loop {
            if reconnect || last_sse.is_none_or(|t| t.elapsed() >= sse_wait) {
                reconnect = false;
                last_sse = Some(Instant::now());
                let idle = (self.cfg.poll * 3).max(MIN_SSE_IDLE);
                let watchdog = (self.cfg.poll * 6).max(MIN_SSE_WATCHDOG);
                match client.events_of(Topics::LightClient(preset), idle).await {
                    Err(e) => {
                        tracing::debug!(source = client.host(), error = %e, "no event stream")
                    }
                    Ok(mut events) => {
                        let opened = Instant::now();
                        tracing::info!(
                            source = client.host(),
                            "following light-client updates by event stream"
                        );
                        let mut dog = Box::pin(sleep(watchdog));
                        let mut rejected = false;
                        loop {
                            tokio::select! {
                                e = events.next_event() => match e {
                                    Some(Event::OptimisticUpdate(u) | Event::FinalityUpdate(u)) => {
                                        // Each update costs a signature check, and a stream has
                                        // no rate limit: a bad one closes it.
                                        if self.sync_report(idx, client.host(), &u, &tx, &fin) ==
                                            Err(Refused::Bad)
                                        {
                                            rejected = true;
                                            break;
                                        }
                                    }
                                    // A light-client stream yields no head events.
                                    Some(Event::Head(_) | Event::Finalized) => {}
                                    None => break,
                                },
                                // Both updates, in case events stop while the stream stays open.
                                () = &mut dog => {
                                    self.poll_update(idx, &client, false, &tx, &fin, &mut failing)
                                        .await;
                                    self.poll_update(
                                        idx, &client, true, &tx, &fin, &mut finality_failing,
                                    )
                                    .await;
                                    dog = Box::pin(sleep(watchdog));
                                }
                            }
                        }
                        if rejected {
                            strikes = (strikes + 1).min(MAX_STREAM_STRIKES);
                            sse_wait = self.cfg.sse_retry.saturating_mul(1 << strikes);
                            tracing::warn!(
                                source = client.host(),
                                reopen_after = ?sse_wait,
                                "closed the light-client event stream after a rejected update; \
                                 polling"
                            );
                            continue;
                        }
                        (strikes, sse_wait) = (0, self.cfg.sse_retry);
                        tracing::warn!(source = client.host(), "event stream ended; polling");
                        reconnect =
                            quick_reconnect(&mut quick, opened.elapsed(), self.cfg.sse_retry);
                        if reconnect {
                            continue;
                        }
                    }
                }
            }
            self.poll_update(idx, &client, false, &tx, &fin, &mut failing).await;
            if polls % FINALITY_EVERY == FINALITY_EVERY - 1 {
                self.poll_update(idx, &client, true, &tx, &fin, &mut finality_failing).await;
            }
            polls += 1;
            sleep(self.cfg.poll).await;
        }
    }

    /// Asks source `idx` for its latest finality update when `finality`, else for its latest
    /// optimistic update.
    async fn poll_update(
        &self,
        idx: usize,
        client: &BeaconClient,
        finality: bool,
        tx: &Reports,
        fin: &Notify,
        failing: &mut bool,
    ) {
        let Some(preset) = self.sync.as_ref().map(SyncFollow::preset) else { return };
        let (request, res) = if finality {
            ("light_client/finality_update", client.light_client_finality_update(preset).await)
        } else {
            ("light_client/optimistic_update", client.light_client_optimistic_update(preset).await)
        };
        if let Some(update) = note_answer(failing, request, client.host(), res) {
            // `--beacon.poll` limits the rate of polled updates, so a bad one ends nothing.
            match self.sync_report(idx, client.host(), &update, tx, fin) {
                Ok(()) | Err(Refused::Unused | Refused::Bad) => {}
            }
        }
    }

    /// Fetches `light_client/updates` until the store is caught up, at start and then every
    /// sixth poll while it lacks the next committee or is behind the wall clock's period.
    pub(super) async fn committee_task(
        self: Arc<Self>,
        clients: Vec<BeaconClient>,
        fin: Arc<Notify>,
    ) {
        let every = self.cfg.poll.saturating_mul(FINALITY_EVERY as u32);
        loop {
            self.catch_up(&clients, &fin).await;
            sleep(every).await;
        }
    }

    /// One round of [`Self::committee_task`]: the sources in order, until one brings the store
    /// up to date.
    async fn catch_up(&self, clients: &[BeaconClient], fin: &Notify) {
        let Some(sync) = &self.sync else { return };
        let preset = sync.preset();
        let mut order: Vec<usize> = (0..clients.len()).collect();
        self.sort_sources(&mut order);
        for i in order.into_iter().filter(|&i| sync.usable(i)) {
            let Some((start, count)) = sync.wanted_updates() else { return };
            let client = &clients[i];
            let updates = match client.light_client_updates(start, count, preset).await {
                Ok(updates) => updates,
                Err(e) => {
                    tracing::debug!(source = client.host(), error = %e, start, "no light-client updates");
                    continue;
                }
            };
            for update in &updates {
                match self.sync_accept(i, client.host(), update) {
                    Ok(accepted) if accepted.finalized.is_some() => fin.notify_one(),
                    // A stale update, often the best one of a period the store already holds,
                    // does not stop the updates after it.
                    Ok(_) | Err(Refused::Unused) => {}
                    Err(Refused::Bad) => break,
                }
            }
        }
        sync.log_unverifiable_heads();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        beacon::{FollowConfig, HeadConfirm, PeerHeader, FINALITY_MIN_DEPTH, MAX_ANCESTORS},
        chain::HeaderChain,
        fake_beacon::Fake,
        light_client::{
            tests::{
                bootstrap_json, fork_schedule_json, genesis_json, pins_369, serve_pins, update_json,
            },
            StoreOrigin, UpdateKind, BOOTSTRAP_PATH, FINALITY_UPDATE_PATH, FORK_SCHEDULE_PATH,
            GENESIS_PATH, OPTIMISTIC_UPDATE_PATH, UPDATES_PATH,
        },
        metrics::LiteMetrics,
        payload::fake::{forks, make, FakeBlock, Fork},
        sync_committee::{
            compute_domain, compute_signing_root,
            test_utils::{branch, node, repeated_aggregate, repeated_committee, STATE_DEPTH},
            BeaconBlockHeader, ExecutionPayloadHeader, LightClientBootstrap, SyncCommittee,
            DOMAIN_SYNC_COMMITTEE,
        },
    };
    use blst::min_pk::SecretKey;
    use reth_pulsechain_forks::network::PulsechainBeacon;
    use serde_json::json;

    /// The fake chain's timestamps are from 2023: accept any anchor age.
    const TEST_ANCHOR_AGE: Duration = Duration::from_secs(1 << 40);
    /// What the anchor check asks the anchor for.
    const ANCHOR_PATH: &str = "/eth/v2/beacon/blocks/finalized";
    /// The anchor's execution block number.
    const START: u64 = 1000;
    /// The period of the anchor.
    const PERIOD: u64 = 1000;
    const SLOTS_PER_PERIOD: u64 = 8192;
    /// The anchor's slot, early in [`PERIOD`].
    const ANCHOR_SLOT: u64 = PERIOD * SLOTS_PER_PERIOD + 100;
    /// How far below a block the finalized block its state names is.
    const FIN_LAG: u64 = 2;
    /// Distinct keys per committee: member `i` holds key `i % KEYS`.
    const KEYS: usize = 8;
    const SIZE: usize = 512;

    /// The 369 pins with genesis moved so that the wall clock is in period `PERIOD + 2`.
    fn pins() -> PulsechainBeacon {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let slot = (PERIOD + 2) * SLOTS_PER_PERIOD + 100;
        PulsechainBeacon { genesis_time: now - slot * 10, ..pins_369() }
    }

    /// A block with the light-client header that commits to it.
    #[derive(Clone)]
    struct SignedBlock {
        block: FakeBlock,
        header: LightClientHeader,
        /// The leaves of its state: the current and next committees and the finalized root.
        leaves: Vec<(u64, B256)>,
    }

    impl SignedBlock {
        const fn root(&self) -> B256 {
            self.block.root
        }

        const fn number(&self) -> u64 {
            self.block.header.number
        }
    }

    /// A chain whose beacon headers are real `hash_tree_root`s, with committees of test keys.
    struct Signed {
        pins: PulsechainBeacon,
        /// The keys of the committees of `PERIOD`, `PERIOD + 1`, ...
        keys: Vec<Vec<SecretKey>>,
        committees: Vec<SyncCommittee>,
        /// The canonical blocks, from `START - FIN_LAG` up.
        blocks: Vec<SignedBlock>,
    }

    impl Signed {
        /// The chain up to the anchor at `START`, in slots up to [`ANCHOR_SLOT`].
        fn new() -> Self {
            let keys: Vec<Vec<SecretKey>> = (0..4u8)
                .map(|period| {
                    (0..KEYS as u8)
                        .map(|member| {
                            let mut ikm = [0x77; 32];
                            ikm[0] = period;
                            ikm[1] = member;
                            SecretKey::key_gen(&ikm, &[]).unwrap()
                        })
                        .collect()
                })
                .collect();
            let committees = keys.iter().map(|k| repeated_committee(k, SIZE)).collect();
            let mut signed = Self { pins: pins(), keys, committees, blocks: Vec::new() };
            for slot in ANCHOR_SLOT - FIN_LAG..=ANCHOR_SLOT {
                signed.push_at(slot);
            }
            signed
        }

        fn anchor(&self) -> &SignedBlock {
            &self.blocks[FIN_LAG as usize]
        }

        fn by_number(&self, number: u64) -> &SignedBlock {
            &self.blocks[(number + FIN_LAG - START) as usize]
        }

        /// The committee index of `slot`'s period.
        fn index(slot: u64) -> usize {
            (Preset::PULSECHAIN.period_at_slot(slot) - PERIOD) as usize
        }

        /// The next canonical block, at `slot`.
        fn push_at(&mut self, slot: u64) -> SignedBlock {
            let (number, parent_hash, parent_root) = match self.blocks.last() {
                Some(p) => (p.number() + 1, p.block.hash, p.root()),
                None => (START - FIN_LAG, B256::repeat_byte(0xaa), B256::repeat_byte(0xbb)),
            };
            let b = self.block_at(number, parent_hash, parent_root, slot, "");
            self.blocks.push(b.clone());
            b
        }

        /// The next canonical block, one slot after the head.
        fn push(&mut self) -> SignedBlock {
            let slot = self.blocks.last().unwrap().header.beacon.slot + 1;
            self.push_at(slot)
        }

        /// A block at `slot` whose state holds the committees of its period and the root of the
        /// canonical block `FIN_LAG` below it.
        fn block_at(
            &self,
            number: u64,
            parent_hash: B256,
            parent_root: B256,
            slot: u64,
            salt: &str,
        ) -> SignedBlock {
            let mut block = make(Fork::Shanghai, number, parent_hash, parent_root, salt);
            let index = Self::index(slot);
            let mut leaves = vec![
                (54, self.committees[index].hash_tree_root()),
                (55, self.committees[index + 1].hash_tree_root()),
            ];
            if let Some(finalized) = self.blocks.iter().find(|b| b.number() + FIN_LAG == number) {
                leaves.push((105, finalized.header.beacon.hash_tree_root()));
            }
            let execution = ExecutionPayloadHeader {
                parent_hash,
                state_root: block.header.state_root,
                block_number: number,
                timestamp: block.header.timestamp,
                block_hash: block.hash,
                ..Default::default()
            };
            let body = [(25, execution.hash_tree_root())];
            let header = LightClientHeader {
                beacon: BeaconBlockHeader {
                    slot,
                    proposer_index: number,
                    parent_root,
                    state_root: node(&leaves, 1, STATE_DEPTH),
                    body_root: node(&body, 1, 4),
                },
                execution,
                execution_branch: branch(&body, 25, 4).try_into().unwrap(),
            };
            block.root = header.beacon.hash_tree_root();
            block.json["data"]["message"]["slot"] = json!(slot.to_string());
            SignedBlock { block, header, leaves }
        }

        /// A sibling of the canonical block at `number`: same parent, another hash.
        fn forged(&self, number: u64) -> SignedBlock {
            let b = self.by_number(number);
            let (parent_hash, parent_root) =
                (b.block.header.parent_hash, b.header.beacon.parent_root);
            self.block_at(number, parent_hash, parent_root, b.header.beacon.slot, "forged")
        }

        fn bootstrap(&self) -> LightClientBootstrap {
            self.bootstrap_at(self.anchor())
        }

        /// The bootstrap at `b`, a block of [`PERIOD`].
        fn bootstrap_at(&self, b: &SignedBlock) -> LightClientBootstrap {
            LightClientBootstrap {
                header: b.header.clone(),
                current_sync_committee: self.committees[0].clone(),
                current_sync_committee_branch: branch(&b.leaves, 54, STATE_DEPTH),
            }
        }

        /// An update of `kind` over `attested`, signed one slot later by the committee of that
        /// slot's period.
        fn update(&self, attested: &SignedBlock, kind: UpdateKind) -> LightClientUpdate {
            let signature_slot = attested.header.beacon.slot + 1;
            self.update_signed(attested, kind, Self::index(signature_slot), SIZE)
        }

        /// An update of `kind` over `attested`, signed by the first `participants` members of
        /// committee `signer`.
        fn update_signed(
            &self,
            attested: &SignedBlock,
            kind: UpdateKind,
            signer: usize,
            participants: usize,
        ) -> LightClientUpdate {
            let signature_slot = attested.header.beacon.slot + 1;
            let epoch = Preset::PULSECHAIN.epoch_at_slot(signature_slot - 1);
            let domain = compute_domain(
                DOMAIN_SYNC_COMMITTEE,
                self.pins.fork_at_epoch(epoch).version,
                self.pins.genesis_validators_root,
            );
            let signing_root =
                compute_signing_root(attested.header.beacon.hash_tree_root(), domain);
            let finalized = (kind != UpdateKind::Optimistic)
                .then(|| self.by_number(attested.number() - FIN_LAG).header.clone());
            let index = Self::index(attested.header.beacon.slot);
            let full = kind == UpdateKind::Full;
            LightClientUpdate {
                attested_header: attested.header.clone(),
                next_sync_committee: if full {
                    self.committees[index + 1].clone()
                } else {
                    SyncCommittee::from_ssz_bytes(&[0; SIZE * 48 + 48], Preset::PULSECHAIN).unwrap()
                },
                next_sync_committee_branch: if full {
                    branch(&attested.leaves, 55, STATE_DEPTH)
                } else {
                    vec![B256::ZERO; 5]
                },
                finality_branch: if finalized.is_some() {
                    branch(&attested.leaves, 105, STATE_DEPTH)
                } else {
                    vec![B256::ZERO; 6]
                },
                finalized_header: finalized.unwrap_or_default(),
                sync_aggregate: repeated_aggregate(
                    &self.keys[signer],
                    SIZE,
                    participants,
                    signing_root,
                ),
                signature_slot,
            }
        }

        /// The `updates` answer that brings the anchor period's next committee: its attested
        /// header is the anchor, its finalized header the block `FIN_LAG` below it.
        fn next_committee_answer(&self) -> String {
            let update = self.update(self.anchor(), UpdateKind::Full);
            json!([update_json(&update, UpdateKind::Full)]).to_string()
        }
    }

    /// A peer that holds the given canonical headers.
    #[derive(Debug, Default)]
    struct Peer {
        headers: parking_lot::Mutex<HashMap<u64, PeerHeader>>,
    }

    #[async_trait::async_trait]
    impl HeadConfirm for Peer {
        async fn headers_at(&self, number: u64) -> Vec<Option<PeerHeader>> {
            vec![self.headers.lock().get(&number).copied()]
        }
    }

    struct Rig {
        signed: Signed,
        sources: Vec<Fake>,
        anchor: Fake,
        chain: Arc<HeaderChain>,
        follower: Arc<Follower>,
        task: tokio::task::JoinHandle<()>,
    }

    struct Setup {
        sources: usize,
        sse: bool,
        /// Whether `updates` serves the anchor period's next committee.
        next_committee: bool,
        peer: Option<Arc<Peer>>,
        /// A store loaded from its file, used instead of a bootstrap at the anchor.
        saved: Option<LightClientStore>,
        /// Whether the bootstrap at the anchor's root is a checkpoint's.
        checkpoint: bool,
        /// The data directory the store file is written to.
        datadir: Option<std::path::PathBuf>,
        /// Canonical blocks above the anchor that the sources serve from the start.
        extra_blocks: u64,
        /// Canonical blocks after those, at these slots, that the sources serve from the start.
        extra_slots: Vec<u64>,
        /// `--beacon.quorum`.
        quorum: usize,
        /// The anchor age limit.
        max_anchor_age: Duration,
        /// The sources whose pins the start could not read.
        unchecked: Vec<usize>,
    }

    impl Default for Setup {
        fn default() -> Self {
            Self {
                sources: 1,
                sse: false,
                next_committee: true,
                peer: None,
                saved: None,
                checkpoint: false,
                datadir: None,
                extra_blocks: 0,
                extra_slots: Vec::new(),
                quorum: 1,
                max_anchor_age: TEST_ANCHOR_AGE,
                unchecked: Vec::new(),
            }
        }
    }

    impl Rig {
        async fn start(setup: Setup) -> Self {
            Self::start_with(setup, |_, _, _| {}).await
        }

        /// Starts the follower after `before` has seen the chain and changed the anchor and the
        /// sources.
        async fn start_with(setup: Setup, before: impl FnOnce(&Signed, &Fake, &[Fake])) -> Self {
            let mut signed = Signed::new();
            for _ in 0..setup.extra_blocks {
                signed.push();
            }
            for &slot in &setup.extra_slots {
                signed.push_at(slot);
            }
            let mut sources = Vec::new();
            for _ in 0..setup.sources {
                let fake = Fake::start(setup.sse, false).await;
                let updates = if setup.next_committee {
                    signed.next_committee_answer()
                } else {
                    "[]".to_owned()
                };
                fake.answer(UPDATES_PATH, "200 OK", updates);
                for b in &signed.blocks {
                    fake.serve_only(&b.block);
                }
                sources.push(fake);
            }
            let anchor = Fake::start(false, true).await;
            let a = signed.anchor().clone();
            anchor.answer(
                &format!("/eth/v2/beacon/blocks/{:#x}", a.root()),
                "200 OK",
                a.block.json.to_string(),
            );
            anchor.set_anchor_block(&a.block);
            before(&signed, &anchor, &sources);

            let (store, origin) = match setup.saved {
                Some(store) => (store, StoreOrigin::Saved),
                None => (
                    LightClientStore::bootstrap(
                        Preset::PULSECHAIN,
                        signed.pins,
                        a.root(),
                        &signed.bootstrap(),
                    )
                    .unwrap(),
                    if setup.checkpoint {
                        StoreOrigin::Checkpoint { root: a.root() }
                    } else {
                        StoreOrigin::Bootstrap { anchor_root: a.root() }
                    },
                ),
            };
            let file = setup.datadir.map(|dir| SyncCommitteeFile::new(&dir, 369));
            let chain = Arc::new(HeaderChain::new());
            let cfg = FollowConfig {
                urls: sources.iter().map(Fake::beacon_url).collect(),
                quorum: setup.quorum,
                poll: Duration::from_millis(50),
                anchor_url: anchor.anchor_url(),
                recheck: Duration::from_millis(200),
                sse_retry: Duration::from_secs(60),
                anchor_gap: Duration::from_millis(100),
                failed_ttl: Duration::from_secs(60),
                max_anchor_age: setup.max_anchor_age,
                forks: forks(Fork::Shanghai),
            };
            let mut f = Follower::new(cfg, chain.clone(), LiteMetrics::new())
                .with_sync_committee(store, origin, file)
                .with_unchecked_pins(setup.unchecked);
            if let Some(peer) = setup.peer {
                f = f.with_confirm(peer);
            }
            let follower = Arc::new(f);
            let task = tokio::spawn(follower.clone().run());
            Self { signed, sources, anchor, chain, follower, task }
        }

        /// Serves `update` as source `i`'s latest update of `kind`, and sends it to its event
        /// streams.
        fn send(&self, i: usize, update: &LightClientUpdate, kind: UpdateKind) {
            let (path, event) = match kind {
                UpdateKind::Finality => (FINALITY_UPDATE_PATH, "light_client_finality_update"),
                _ => (OPTIMISTIC_UPDATE_PATH, "light_client_optimistic_update"),
            };
            let body = update_json(update, kind);
            self.sources[i].answer(path, "200 OK", body.to_string());
            self.sources[i].send_event(event, &body);
        }

        /// Makes `b` servable by source `i`.
        fn serve(&self, i: usize, b: &SignedBlock) {
            self.sources[i].serve_only(&b.block);
        }

        async fn wait(&self, what: &str, mut cond: impl FnMut() -> bool) {
            for _ in 0..1000 {
                if cond() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("timed out waiting for {what}: head {:?}", self.head());
        }

        async fn wait_head(&self, b: &SignedBlock) {
            let hash = b.block.hash;
            self.wait(&format!("head {}", b.number()), || {
                self.chain.head().is_some_and(|h| h.hash == hash)
            })
            .await;
        }

        fn head(&self) -> Option<u64> {
            self.chain.head().map(|h| h.header.number)
        }

        async fn stays(&self, number: u64, ms: u64) {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            assert_eq!(self.head(), Some(number));
        }

        fn calls(&self, i: usize, path: &str) -> usize {
            self.sources[i].calls(path)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[test]
    fn only_updates_an_honest_source_cannot_send_count_against_it() {
        let slots = |current, signature| SyncCommitteeError::SlotOrder {
            current,
            signature,
            attested: 5,
            finalized: 4,
        };
        // The wall clock is behind the signature: an honest source's update may be early.
        assert!(!is_bad_data(&slots(9, 10)));
        // The signature is not after the attested slot: no honest source sends that.
        assert!(is_bad_data(&slots(10, 5)));
        assert!(!is_bad_data(&SyncCommitteeError::Stale { attested: 1, finalized: 2 }));
        assert!(!is_bad_data(&SyncCommitteeError::TooFewParticipants {
            participants: 1,
            size: 512
        }));
        assert!(is_bad_data(&SyncCommitteeError::NextCommitteeBranch(B256::ZERO)));
        assert!(is_bad_data(&SyncCommitteeError::ExecutionBranch(B256::ZERO)));
    }

    #[tokio::test]
    async fn an_honest_source_moves_the_head_and_finality_without_a_quorum_or_depth() {
        for sse in [false, true] {
            let mut r = Rig::start(Setup { sse, ..Default::default() }).await;
            let anchor = r.signed.anchor().clone();
            r.wait_head(&anchor).await;
            assert!(!r.chain.finality_confirmed());

            let b1 = r.signed.push();
            r.serve(0, &b1);
            // The event stream opens after the start, so the first update may be missed there.
            r.wait("the light-client stream", || !sse || r.calls(0, "/eth/v1/events") > 0).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            r.send(0, &r.signed.update(&b1, UpdateKind::Optimistic), UpdateKind::Optimistic);
            r.wait_head(&b1).await;

            // Two blocks on: the finality update's attested block is the head, its finalized
            // block is two below it, and one source says so.
            let (b2, b3) = (r.signed.push(), r.signed.push());
            r.serve(0, &b2);
            r.serve(0, &b3);
            r.send(0, &r.signed.update(&b3, UpdateKind::Finality), UpdateKind::Finality);
            r.wait_head(&b3).await;
            r.wait("finality", || r.chain.finality_confirmed()).await;
            assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash, "sse {sse}");
            assert_eq!(r.calls(0, "/eth/v1/beacon/headers/head"), 0, "sse {sse}");
            assert_eq!(r.follower.source_failures(0), 0, "sse {sse}");
        }
    }

    #[tokio::test]
    async fn a_hostile_source_that_forges_a_header_is_never_followed() {
        let mut r = Rig::start(Setup { sources: 2, ..Default::default() }).await;
        let anchor = r.signed.anchor().clone();
        r.wait_head(&anchor).await;
        // Source 0 relays the committee's update for the honest block, so it is asked first for
        // the block, and it answers with a forged block under the honest root.
        let honest = r.signed.push();
        let forged = r.signed.forged(honest.number());
        assert_ne!(forged.block.hash, honest.block.hash);
        let mut under_honest = forged.block.clone();
        under_honest.root = honest.root();
        r.sources[0].serve_only(&under_honest);
        r.serve(1, &honest);
        r.send(0, &r.signed.update(&honest, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.wait_head(&honest).await;
        assert_eq!(r.follower.source_failures(0), 1, "the forged block was not charged");

        // Then it signs a forged header with keys that are not the committee's, and serves the
        // forged block under that header's root.
        let next = r.signed.push();
        r.serve(1, &next);
        let forged = r.signed.forged(next.number());
        r.serve(0, &forged);
        let forged_update = r.signed.update_signed(&forged, UpdateKind::Optimistic, 3, SIZE);
        r.send(0, &forged_update, UpdateKind::Optimistic);
        r.wait("the forged signature charged", || r.follower.source_failures(0) > 1).await;
        r.stays(honest.number(), 300).await;
        assert!(!r.chain.contains(&forged.block.hash));
        assert!(!r.chain.contains(&under_honest.hash));
        assert_eq!(r.follower.source_failures(1), 0);
    }

    /// A source that streams forged updates costs one signature check, then its stream closes
    /// and stays closed past the retry gate. Rejections by poll log one warning, not one each.
    #[tokio::test]
    async fn a_source_that_streams_forged_updates_is_cut_off_and_logged_once() {
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let mut r = Rig::start(Setup { sse: true, ..Default::default() }).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        r.wait("the light-client stream", || r.calls(0, "/eth/v1/events") > 0).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let b1 = r.signed.push();
        r.serve(0, &b1);
        let forged = r.signed.update_signed(&b1, UpdateKind::Optimistic, 3, SIZE);
        let body = update_json(&forged, UpdateKind::Optimistic);
        for _ in 0..20 {
            r.sources[0].send_event("light_client_optimistic_update", &body);
        }
        r.wait("the forged update charged", || r.follower.source_failures(0) > 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(r.follower.source_failures(0), 1, "the stream stayed open");
        assert_eq!(r.calls(0, "/eth/v1/events"), 1);

        // By poll, each forged answer is charged, but the log says it once.
        r.sources[0].answer(OPTIMISTIC_UPDATE_PATH, "200 OK", body.to_string());
        r.wait("polled rejections", || r.follower.source_failures(0) > 3).await;
        let rejected = logs.text().matches("light-client update rejected").count();
        assert_eq!(rejected, 1, "{}", logs.text());
        assert_eq!(r.head(), Some(START));
    }

    #[tokio::test]
    async fn too_few_signers_or_a_wrong_execution_branch_never_move_the_head() {
        let mut r = Rig::start(Setup::default()).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        let b1 = r.signed.push();
        r.serve(0, &b1);
        // 341 of 512 is below two thirds.
        let few = r.signed.update_signed(&b1, UpdateKind::Optimistic, 0, 341);
        r.send(0, &few, UpdateKind::Optimistic);
        r.stays(START, 300).await;
        // A header whose execution part is not the one its body root commits to.
        let mut wrong = r.signed.update(&b1, UpdateKind::Optimistic);
        wrong.attested_header.execution.block_hash = B256::repeat_byte(1);
        r.send(0, &wrong, UpdateKind::Optimistic);
        r.stays(START, 300).await;
        assert!(r.follower.source_failures(0) > 0, "the wrong execution branch was not charged");
        let enough = r.signed.update_signed(&b1, UpdateKind::Optimistic, 0, 342);
        r.send(0, &enough, UpdateKind::Optimistic);
        r.wait_head(&b1).await;
    }

    #[tokio::test]
    async fn a_missing_next_committee_makes_the_head_stale_until_a_valid_one_is_served() {
        let mut r = Rig::start(Setup { next_committee: false, ..Default::default() }).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        let b1 = r.signed.push();
        r.serve(0, &b1);
        r.send(0, &r.signed.update(&b1, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.wait_head(&b1).await;

        // The next block is in the next period: its committee signs it.
        let b2 = r.signed.push_at((PERIOD + 1) * SLOTS_PER_PERIOD + 5);
        r.serve(0, &b2);
        r.send(0, &r.signed.update(&b2, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.stays(b1.number(), 500).await;

        // A next committee whose branch does not prove into the attested state is refused.
        let mut bad = r.signed.update(r.signed.anchor(), UpdateKind::Full);
        bad.next_sync_committee_branch[0] = B256::repeat_byte(5);
        let bad = json!([update_json(&bad, UpdateKind::Full)]).to_string();
        r.sources[0].answer(UPDATES_PATH, "200 OK", bad);
        r.wait("the bad committee charged", || r.follower.source_failures(0) > 0).await;
        r.stays(b1.number(), 300).await;

        // A valid next committee lets the next period's update through.
        r.sources[0].answer(UPDATES_PATH, "200 OK", r.signed.next_committee_answer());
        r.wait_head(&b2).await;
    }

    #[tokio::test]
    async fn finality_in_the_next_period_rotates_the_committee() {
        let mut r = Rig::start(Setup::default()).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        let b1 = r.signed.push_at((PERIOD + 1) * SLOTS_PER_PERIOD + 5);
        let (b2, b3) = (r.signed.push(), r.signed.push());
        for b in [&b1, &b2, &b3] {
            r.serve(0, b);
        }
        r.send(0, &r.signed.update(&b3, UpdateKind::Finality), UpdateKind::Finality);
        r.wait_head(&b3).await;
        r.wait("finality", || r.chain.finality_confirmed()).await;
        assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash);
        assert_eq!(r.follower.sync.as_ref().unwrap().period(), PERIOD + 1);
    }

    /// A bootstrap block that is no longer recent can never seed. The node bootstraps again at
    /// the anchor's new finalized root and seeds there.
    #[tokio::test]
    async fn a_bootstrap_block_too_old_to_seed_is_replaced_by_a_new_bootstrap() {
        // The fake timestamps grow 10 s a block: blocks from `START + 50` on are recent.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let max_anchor_age = Duration::from_secs(now - (1_700_000_000 + (START + 50) * 10));
        let setup = Setup { extra_blocks: 60, max_anchor_age, ..Default::default() };
        let r = Rig::start_with(setup, |signed, anchor, sources| {
            let fresh = signed.by_number(START + 60);
            anchor.answer(
                "/eth/v1/beacon/blocks/finalized/root",
                "200 OK",
                json!({"finalized": true, "data": {"root": fresh.root()}}).to_string(),
            );
            anchor.answer(
                &format!("/eth/v2/beacon/blocks/{:#x}", fresh.root()),
                "200 OK",
                fresh.block.json.to_string(),
            );
            let bootstrap = bootstrap_json(&signed.bootstrap_at(fresh), BeaconFork::Capella);
            for source in sources {
                source.answer(
                    &format!("{BOOTSTRAP_PATH}/{:#x}", fresh.root()),
                    "200 OK",
                    bootstrap.to_string(),
                );
            }
        })
        .await;
        let fresh = r.signed.by_number(START + 60).clone();
        r.wait_head(&fresh).await;
        assert!(!r.chain.contains(&r.signed.anchor().block.hash));
        assert_eq!(r.follower.sync.as_ref().unwrap().anchor().root, fresh.root());
    }

    #[tokio::test]
    async fn the_seed_needs_the_anchor_block_to_carry_the_block_hash_the_bootstrap_proves() {
        let r = Rig::start_with(Setup::default(), |signed, anchor, _| {
            // The anchor answers the bootstrap root with another block.
            let path = format!("/eth/v2/beacon/blocks/{:#x}", signed.anchor().root());
            anchor.answer(&path, "200 OK", signed.forged(START).block.json.to_string());
        })
        .await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(r.head(), None, "seeded from a block the bootstrap does not prove");
        let a = r.signed.anchor().clone();
        let path = format!("/eth/v2/beacon/blocks/{:#x}", a.root());
        r.anchor.answer(&path, "200 OK", a.block.json.to_string());
        r.wait_head(&a).await;
    }

    /// The store file is written on a committee change or a finality move, at most once every
    /// [`SAVE_EVERY`]; a change inside that time is written at the first update after it.
    #[test]
    fn the_store_file_is_written_on_a_change_at_most_every_ten_minutes() {
        let mut signed = Signed::new();
        let a = signed.anchor().clone();
        let store = LightClientStore::bootstrap(
            Preset::PULSECHAIN,
            signed.pins,
            a.root(),
            &signed.bootstrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = SyncCommitteeFile::new(dir.path(), 369);
        let origin = StoreOrigin::Bootstrap { anchor_root: a.root() };
        let sync = SyncFollow::new(store, origin, Some(file.clone()));
        let (b1, _, b3) = (signed.push(), signed.push(), signed.push());
        let t0 = Instant::now();
        let saves = |update: &LightClientUpdate, after: u64| {
            let at = t0 + Duration::from_secs(after * 60);
            sync.accept(update, at).unwrap().save
        };
        let loaded = |bytes: &[u8]| {
            file.save(bytes).unwrap();
            file.load(Preset::PULSECHAIN, signed.pins, SystemTime::now()).unwrap().unwrap()
        };

        // The next committee is a change: written at once.
        let bytes = saves(&signed.update(&a, UpdateKind::Full), 0).expect("a committee change");
        assert!(loaded(&bytes).next_sync_committee().is_some());
        // An optimistic update changes neither.
        assert_eq!(saves(&signed.update(&b1, UpdateKind::Optimistic), 1), None);
        // Finality moves within ten minutes of the last write: not yet.
        assert_eq!(saves(&signed.update(&b3, UpdateKind::Finality), 2), None);
        assert_eq!(saves(&signed.update(&b3, UpdateKind::Optimistic), 9), None);
        // Ten minutes on, the next update writes it, though that update changed nothing.
        let bytes = saves(&signed.update(&b3, UpdateKind::Optimistic), 10).expect("a late write");
        assert_eq!(loaded(&bytes).finalized_header(), &b1.header);
        assert_eq!(saves(&signed.update(&b3, UpdateKind::Optimistic), 30), None);

        // Without a file nothing is encoded.
        let store = LightClientStore::bootstrap(
            Preset::PULSECHAIN,
            signed.pins,
            a.root(),
            &signed.bootstrap(),
        )
        .unwrap();
        let sync = SyncFollow::new(store, origin, None);
        assert_eq!(sync.accept(&signed.update(&a, UpdateKind::Full), t0).unwrap().save, None);
    }

    /// A restart with the saved store seeds from the sources at the saved finalized block. The
    /// anchor is not asked for it, so an anchor that lies about it cannot stop the restart.
    #[tokio::test]
    async fn a_restart_resumes_from_the_saved_store_without_trusting_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let setup = Setup { datadir: Some(dir.path().to_path_buf()), ..Default::default() };
        let first = Rig::start(setup).await;
        let a = first.signed.anchor().clone();
        first.wait_head(&a).await;
        // The `updates` answer at start brings the next committee, which is a change.
        let file = SyncCommitteeFile::new(dir.path(), 369);
        first.wait("the store file", || file.path().exists()).await;
        drop(first);

        let saved = file.load(Preset::PULSECHAIN, pins(), SystemTime::now()).unwrap().unwrap();
        assert!(saved.next_sync_committee().is_some());
        let root_path = format!("/eth/v2/beacon/blocks/{:#x}", a.root());
        let setup = Setup { saved: Some(saved), ..Default::default() };
        let mut r = Rig::start_with(setup, |signed, anchor, _| {
            // A bootstrapped start never seeds from this anchor (see the seed test above).
            anchor.answer(&root_path, "200 OK", signed.forged(START).block.json.to_string());
        })
        .await;
        r.wait_head(&a).await;
        assert_eq!(r.anchor.calls(&root_path), 0, "the restart asked the anchor for its seed");
        // The saved header was verified, so it is final at once.
        assert!(r.chain.finality_confirmed());

        let b1 = r.signed.push();
        r.serve(0, &b1);
        r.send(0, &r.signed.update(&b1, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.wait_head(&b1).await;
    }

    /// A store bootstrapped at a checkpoint seeds from the sources, as a saved store does: the
    /// anchor, which here serves a forged block under the root, is not asked.
    #[tokio::test]
    async fn a_checkpoint_store_seeds_from_the_sources_without_the_anchor() {
        let root_path = format!("/eth/v2/beacon/blocks/{:#x}", Signed::new().anchor().root());
        let setup = Setup { checkpoint: true, ..Default::default() };
        let r = Rig::start_with(setup, |signed, anchor, _| {
            anchor.answer(&root_path, "200 OK", signed.forged(START).block.json.to_string());
        })
        .await;
        r.wait_head(&r.signed.anchor().clone()).await;
        assert_eq!(r.anchor.calls(&root_path), 0, "the checkpoint start asked the anchor");
        // The checkpoint header hashes to a trusted root, so it is final at once.
        assert!(r.chain.finality_confirmed());
    }

    /// A restart catches up before it seeds: a source's finality update above the saved
    /// header moves the seed there, so the saved block itself is never fetched.
    #[tokio::test]
    async fn a_restart_seeds_at_the_finality_the_sources_prove_first() {
        let signed = Signed::new();
        let a = signed.anchor().clone();
        let mut saved = LightClientStore::bootstrap(
            Preset::PULSECHAIN,
            signed.pins,
            a.root(),
            &signed.bootstrap(),
        )
        .unwrap();
        let current = current_slot(signed.pins.genesis_time);
        saved.process_update(&signed.update(&a, UpdateKind::Full), current).unwrap();
        let setup = Setup { saved: Some(saved), extra_blocks: 3, ..Default::default() };
        let r = Rig::start_with(setup, |signed, _, sources| {
            let top = signed.by_number(START + 3);
            let update =
                update_json(&signed.update(top, UpdateKind::Finality), UpdateKind::Finality);
            sources[0].answer(FINALITY_UPDATE_PATH, "200 OK", update.to_string());
        })
        .await;
        let (b1, b3) =
            (r.signed.by_number(START + 1).clone(), r.signed.by_number(START + 3).clone());
        r.wait_head(&b3).await;
        assert!(!r.chain.contains(&a.block.hash), "seeded at the saved header");
        assert_eq!(r.calls(0, &format!("/eth/v2/beacon/blocks/{:#x}", a.root())), 0);
        assert!(r.chain.finality_confirmed());
        assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash);
    }

    /// Without the next committee `updates` start at the store's period; with it they start at
    /// the next one. The wall clock is two periods ahead of the store.
    #[test]
    fn updates_start_after_the_period_whose_next_committee_the_store_holds() {
        let signed = Signed::new();
        let a = signed.anchor().clone();
        let mut store = LightClientStore::bootstrap(
            Preset::PULSECHAIN,
            signed.pins,
            a.root(),
            &signed.bootstrap(),
        )
        .unwrap();
        let origin = StoreOrigin::Bootstrap { anchor_root: a.root() };
        assert_eq!(
            SyncFollow::new(store.clone(), origin, None).wanted_updates(),
            Some((PERIOD, 3))
        );
        let current = current_slot(signed.pins.genesis_time);
        store.process_update(&signed.update(&a, UpdateKind::Full), current).unwrap();
        assert_eq!(SyncFollow::new(store, origin, None).wanted_updates(), Some((PERIOD + 1, 2)));
    }

    /// A saved store that knows the next committee, two periods behind the wall clock. The best
    /// update of its own period attests the saved finalized slot, so the store refuses it as
    /// stale; the update of the next period after it must still rotate the committee.
    #[tokio::test]
    async fn a_store_two_periods_behind_catches_up_past_a_stale_update() {
        let signed = Signed::new();
        let a = signed.anchor().clone();
        let mut saved = LightClientStore::bootstrap(
            Preset::PULSECHAIN,
            signed.pins,
            a.root(),
            &signed.bootstrap(),
        )
        .unwrap();
        let current = current_slot(signed.pins.genesis_time);
        saved.process_update(&signed.update(&a, UpdateKind::Full), current).unwrap();
        assert!(saved.next_sync_committee().is_some());
        let next = (PERIOD + 1) * SLOTS_PER_PERIOD + 5;
        let later = (PERIOD + 2) * SLOTS_PER_PERIOD + 5;
        let setup = Setup {
            saved: Some(saved),
            extra_slots: vec![next, next + 1, next + 2, later, later + 1, later + 2],
            ..Default::default()
        };
        let r = Rig::start_with(setup, |signed, _, sources| {
            let stale = signed.update(signed.anchor(), UpdateKind::Full);
            let rotate = signed.update(signed.by_number(START + 3), UpdateKind::Full);
            let updates = json!([
                update_json(&stale, UpdateKind::Full),
                update_json(&rotate, UpdateKind::Full)
            ]);
            sources[0].answer(UPDATES_PATH, "200 OK", updates.to_string());
            let top = signed.update(signed.by_number(START + 6), UpdateKind::Finality);
            let top = update_json(&top, UpdateKind::Finality);
            sources[0].answer(FINALITY_UPDATE_PATH, "200 OK", top.to_string());
        })
        .await;
        let top = r.signed.by_number(START + 6).clone();
        r.wait_head(&top).await;
        assert_eq!(r.follower.sync.as_ref().unwrap().period(), PERIOD + 2);
        assert_eq!(r.chain.finalized().unwrap().hash, r.signed.by_number(START + 4).block.hash);
        assert_eq!(r.follower.source_failures(0), 0);
    }

    #[tokio::test]
    async fn a_gap_re_seeds_forward_from_the_store_without_the_anchor() {
        let mut r = Rig::start(Setup::default()).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        // The anchor goes away: the re-seed must not need it.
        r.anchor.state.lock().answers.clear();
        r.anchor.state.lock().finalized_block = None;
        let far = START + MAX_ANCESTORS as u64 + 100;
        while r.signed.blocks.last().unwrap().number() < far {
            r.signed.push();
        }
        // The source holds only the top three blocks.
        for number in far - FIN_LAG..=far {
            r.serve(0, r.signed.by_number(number));
        }
        let top = r.signed.by_number(far).clone();
        r.send(0, &r.signed.update(&top, UpdateKind::Finality), UpdateKind::Finality);
        r.wait_head(&top).await;
        assert_eq!(r.chain.finalized().unwrap().header.number, far - FIN_LAG);
        assert!(r.chain.finality_confirmed());
    }

    /// With a light-client store the beacon quorum has no job: the seed does not wait for the
    /// beacons to report the bootstrap block as finalized.
    #[tokio::test]
    async fn a_beacon_quorum_does_not_hold_back_the_seed() {
        let r = Rig::start(Setup { sources: 2, quorum: 2, ..Default::default() }).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        for i in 0..2 {
            assert_eq!(r.calls(i, "/eth/v2/beacon/blocks/finalized"), 0, "source {i}");
        }
    }

    /// With a light-client store a beacon quorum confirms no anchor block: the anchor and the
    /// beacons together cannot swap the chain the committee verified for one it did not sign,
    /// nor halt it.
    #[tokio::test]
    async fn a_beacon_quorum_never_replaces_the_verified_chain() {
        let setup = Setup { sources: 2, quorum: 2, ..Default::default() };
        let mut r = Rig::start_with(setup, |signed, _, sources| {
            for source in sources {
                source.finalize(&signed.anchor().block);
            }
        })
        .await;
        let a = r.signed.anchor().clone();
        r.wait_head(&a).await;
        let b1 = r.signed.push();
        for i in 0..2 {
            r.serve(i, &b1);
        }
        r.send(0, &r.signed.update(&b1, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.wait_head(&b1).await;

        // The anchor and both beacons report a sibling of the verified head as finalized.
        let forged = r.signed.forged(b1.number());
        r.anchor.set_anchor_block(&forged.block);
        for source in &r.sources {
            source.finalize(&forged.block);
        }
        let checks = r.anchor.calls(ANCHOR_PATH);
        r.wait("two anchor checks", || r.anchor.calls(ANCHOR_PATH) >= checks + 2).await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!r.chain.contains(&forged.block.hash), "re-seeded at a block nobody signed");
        assert!(!r.chain.halted(), "the anchor halted a verified chain");
        assert_eq!(r.head(), Some(b1.number()));
    }

    /// Verified finality wins over the anchor: an anchor that disagrees with it is logged once
    /// per disagreement, with its host label only, and counted at each check. The node keeps
    /// serving and following heads.
    #[tokio::test]
    async fn an_anchor_that_disagrees_with_verified_finality_does_not_halt() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        let mut r = Rig::start(Setup::default()).await;
        r.wait_head(&r.signed.anchor().clone()).await;
        let (b1, b2, b3) = (r.signed.push(), r.signed.push(), r.signed.push());
        for b in [&b1, &b2, &b3] {
            r.serve(0, b);
        }
        r.send(0, &r.signed.update(&b3, UpdateKind::Finality), UpdateKind::Finality);
        r.wait_head(&b3).await;
        r.wait("finality", || r.chain.finality_confirmed()).await;
        assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash);

        // The anchor reports a sibling of the verified finalized block.
        let line = "the finalized anchor disagrees with the verified chain";
        let disagreements = || {
            let out = handle.render();
            out.lines()
                .find_map(|l| l.strip_prefix("lite_anchor_disagreements_total "))
                .map_or(0, |n| n.parse::<usize>().unwrap())
        };
        for (n, at) in [(1, b1.number()), (2, b2.number())] {
            r.anchor.set_anchor_block(&r.signed.forged(at).block);
            // Wait on checks that saw this anchor: a check already in flight may see the last one.
            let from = disagreements();
            r.wait("two disagreeing checks", || disagreements() >= from + 2).await;
            assert!(!r.chain.halted(), "halted on an anchor at {at}");
            assert_eq!(r.chain.halt_reason(), None);
            assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash);
            assert_eq!(logs.text().matches(line).count(), n, "{}", logs.text());
        }
        assert!(!logs.text().contains(&r.anchor.anchor_url().to_string()), "{}", logs.text());
        assert!(handle.render().contains("lite_anchor_mismatch 0"), "{}", handle.render());

        // Heads still move.
        let b4 = r.signed.push();
        r.serve(0, &b4);
        r.send(0, &r.signed.update(&b4, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.wait_head(&b4).await;
    }

    /// A head-confirm peer and the anchor that agree on a sibling of the verified finalized
    /// block do not re-seed the node there: verified finality wins over both. Above verified
    /// finality the pair still re-seeds, as the committee signed those heads but did not
    /// finalize them.
    #[tokio::test]
    async fn a_peer_confirmed_anchor_never_overrides_verified_finality() {
        for finality in [true, false] {
            let peer = Arc::new(Peer::default());
            let at = |hash, parent_hash| PeerHeader { hash, parent_hash };
            let setup = Setup { peer: Some(peer.clone()), extra_blocks: 3, ..Default::default() };
            let r = Rig::start_with(setup, |signed, _, _| {
                let mut held = peer.headers.lock();
                for n in START..=START + 3 {
                    let b = &signed.by_number(n).block;
                    held.insert(n, at(b.hash, b.header.parent_hash));
                }
                held.insert(START + FINALITY_MIN_DEPTH, at(B256::repeat_byte(5), B256::ZERO));
            })
            .await;
            r.wait_head(&r.signed.anchor().clone()).await;
            let b1 = r.signed.by_number(START + 1).clone();
            let b3 = r.signed.by_number(START + 3).clone();
            let kind = if finality { UpdateKind::Finality } else { UpdateKind::Optimistic };
            r.send(0, &r.signed.update(&b3, kind), kind);
            r.wait_head(&b3).await;
            if finality {
                r.wait("finality", || r.chain.finality_confirmed()).await;
                assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash);
            }

            // The peer moves to a line on a sibling of b1, and the anchor names it.
            let forged = r.signed.forged(b1.number());
            {
                let mut held = peer.headers.lock();
                let (x, y) = (B256::repeat_byte(6), B256::repeat_byte(7));
                held.insert(b1.number(), at(forged.block.hash, forged.block.header.parent_hash));
                held.insert(b1.number() + 1, at(x, forged.block.hash));
                held.insert(b1.number() + 2, at(y, x));
                let far = b1.number() + FINALITY_MIN_DEPTH;
                held.insert(far, at(B256::repeat_byte(8), B256::ZERO));
            }
            r.anchor.set_anchor_block(&forged.block);
            let checks = r.anchor.calls(ANCHOR_PATH);
            r.wait("two anchor checks", || r.anchor.calls(ANCHOR_PATH) >= checks + 2).await;
            assert!(!r.chain.halted(), "finality {finality}");
            if finality {
                assert!(!r.chain.contains(&forged.block.hash), "re-seeded below verified finality");
                assert_eq!(r.head(), Some(b3.number()));
                assert_eq!(r.chain.finalized().unwrap().hash, b1.block.hash);
            } else {
                assert_eq!(r.chain.head().unwrap().hash, forged.block.hash, "not re-seeded");
            }
        }
    }

    /// A source whose pins the start could not read is used once it answers them, and never
    /// when they differ. Until then its updates are not asked for.
    #[tokio::test]
    async fn a_source_unchecked_at_start_is_used_only_once_its_pins_match() {
        for matches in [true, false] {
            let setup = Setup { sources: 2, unchecked: vec![1], ..Default::default() };
            let mut r = Rig::start(setup).await;
            r.wait_head(&r.signed.anchor().clone()).await;
            // Only source 1 has the next block and its update.
            let b1 = r.signed.push();
            r.serve(1, &b1);
            r.send(1, &r.signed.update(&b1, UpdateKind::Optimistic), UpdateKind::Optimistic);
            r.stays(START, 300).await;
            assert_eq!(r.calls(1, OPTIMISTIC_UPDATE_PATH), 0, "matches {matches}");
            assert!(r.calls(1, GENESIS_PATH) > 1, "the pins were not asked again");

            let pins = r.signed.pins;
            let mut genesis = genesis_json(&pins);
            if !matches {
                genesis["data"]["genesis_validators_root"] = json!(B256::repeat_byte(1));
            }
            serve_pins(&r.sources[1], &genesis, &fork_schedule_json(&pins));
            if matches {
                r.wait_head(&b1).await;
            } else {
                r.wait("the pins compared", || r.calls(1, FORK_SCHEDULE_PATH) > 0).await;
                let asked = r.calls(1, GENESIS_PATH);
                r.stays(START, 400).await;
                assert_eq!(
                    r.calls(1, GENESIS_PATH),
                    asked,
                    "a source on another chain is asked again"
                );
                assert_eq!(r.calls(1, OPTIMISTIC_UPDATE_PATH), 0);
                assert_eq!(r.calls(1, UPDATES_PATH), 0);
            }
        }
    }

    #[tokio::test]
    async fn a_peer_veto_still_stops_a_verified_head() {
        let peer = Arc::new(Peer::default());
        let at = |hash, parent_hash| PeerHeader { hash, parent_hash };
        // The peer confirms the anchor: it is canonical there, with blocks on top and one deep
        // above it. Its block above the anchor is not the beacon chain's.
        let setup = Setup { peer: Some(peer.clone()), ..Default::default() };
        let mut r = Rig::start_with(setup, |signed, _, _| {
            let a = signed.anchor().block.hash;
            let mut held = peer.headers.lock();
            held.insert(START, at(a, B256::ZERO));
            held.insert(START + 1, at(B256::repeat_byte(3), a));
            held.insert(START + 2, at(B256::repeat_byte(4), B256::repeat_byte(3)));
            held.insert(START + FINALITY_MIN_DEPTH, at(B256::repeat_byte(5), B256::ZERO));
        })
        .await;
        let a = r.signed.anchor().clone();
        r.wait_head(&a).await;
        let b1 = r.signed.push();
        r.serve(0, &b1);
        r.send(0, &r.signed.update(&b1, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.stays(START, 400).await;
        // A vetoed root is not tried again: the next head brings the block in as its parent.
        let b2 = r.signed.push();
        r.serve(0, &b2);
        peer.headers.lock().insert(b1.number(), at(b1.block.hash, a.block.hash));
        peer.headers.lock().insert(b2.number(), at(b2.block.hash, b1.block.hash));
        r.send(0, &r.signed.update(&b2, UpdateKind::Optimistic), UpdateKind::Optimistic);
        r.wait_head(&b2).await;
        assert!(r.chain.contains(&b1.block.hash));
    }

    #[tokio::test]
    async fn quorum_mode_never_asks_for_light_client_data() {
        let fake = Fake::start(false, false).await;
        let anchor = Fake::start(false, true).await;
        let block = make(Fork::Shanghai, START, B256::repeat_byte(1), B256::repeat_byte(2), "");
        fake.push(&block);
        fake.finalize(&block);
        anchor.set_anchor_block(&block);
        let chain = Arc::new(HeaderChain::new());
        let cfg = FollowConfig {
            urls: vec![fake.beacon_url()],
            quorum: 1,
            poll: Duration::from_millis(50),
            anchor_url: anchor.anchor_url(),
            recheck: Duration::from_millis(50),
            sse_retry: Duration::from_secs(60),
            anchor_gap: Duration::from_millis(100),
            failed_ttl: Duration::from_secs(60),
            max_anchor_age: TEST_ANCHOR_AGE,
            forks: forks(Fork::Shanghai),
        };
        let task =
            tokio::spawn(Arc::new(Follower::new(cfg, chain.clone(), LiteMetrics::new())).run());
        tokio::time::sleep(Duration::from_millis(500)).await;
        task.abort();
        assert_eq!(chain.head().map(|h| h.hash), Some(block.hash));
        assert!(fake.calls("/eth/v1/beacon/headers/head") > 0);
        for path in [OPTIMISTIC_UPDATE_PATH, FINALITY_UPDATE_PATH, UPDATES_PATH] {
            assert_eq!(fake.calls(path), 0, "{path}");
        }
    }
}
