//! What the server serves, and the self-check store that every answer passes first.
//!
//! The checkpoint and head tasks build answers from upstream data. Before the server serves one,
//! it applies the answer to its own [`LightClientStore`], the code reth-lite runs, and serves it
//! only when that store accepts it.
//!
//! The store is the server's trust anchor. It starts from the chain's pinned checkpoint, or
//! from `--checkpoint`, or from the store the server saved before. It then moves only forward,
//! by the updates it verifies, and is saved each time. It is never bootstrapped again at a root
//! that an upstream names: a checkpoint whose committee the store does not know is refused.

use crate::archive::Archive;
use alloy_primitives::B256;
use parking_lot::Mutex;
use reth_pulsechain_forks::network::PulsechainBeacon;
use reth_pulsechain_light_client::sync_committee::{
    LightClientBootstrap, LightClientStore, LightClientUpdate, Preset, SyncCommitteeError,
};
use std::{io, sync::Arc};
use tokio::sync::{watch, Notify};
use tracing::{debug, info};

/// Why the self-check store did not accept an answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelfCheckError {
    /// The store refused the answer.
    #[error("the self-check store refused the answer: {0}")]
    Refused(#[from] SyncCommitteeError),
    /// The checkpoint's bootstrap has another committee than the one the store verified for its
    /// period: the upstream follows another chain.
    #[error(
        "the checkpoint's committee of period {period} is not the one the self-check store \
         verified: the upstream does not follow the store's chain"
    )]
    OtherCommittee {
        /// The checkpoint's period.
        period: u64,
    },
    /// The store does not know the committee of the checkpoint's period, so the checkpoint does
    /// not chain to it.
    #[error(
        "the self-check store at period {store_period} cannot check a checkpoint of period \
         {period}: it needs the period updates in between, which no upstream gives once their \
         states are gone; start once with a recent --checkpoint and no saved store, or with a \
         release whose pin is recent"
    )]
    NotChained {
        /// The checkpoint's period.
        period: u64,
        /// The store's period.
        store_period: u64,
    },
}

/// Why an update the self-check store checked was not taken.
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    /// The store refused it.
    #[error(transparent)]
    SelfCheck(#[from] SelfCheckError),
    /// The archive could not store it or the store.
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// A latest answer, shared with the readers.
pub type Latest = Option<Arc<LightClientUpdate>>;

/// The checkpoint task's steps, for a bootstrap request that waits for one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    /// The steps started.
    pub started: u64,
    /// The steps that ended. Steps run one at a time, so this is `started` or one less.
    pub done: u64,
    /// The root that the running step builds, once it has read it and found it new.
    pub building: Option<B256>,
}

/// The server's answers for one chain.
#[derive(Debug)]
pub struct Answers {
    chain_id: u64,
    preset: Preset,
    pins: PulsechainBeacon,
    /// The self-check store: the trust anchor, moved forward only by updates it verifies.
    store: Mutex<LightClientStore>,
    finality: watch::Sender<Latest>,
    optimistic: watch::Sender<Latest>,
    archive: tokio::sync::Mutex<Archive>,
    progress: watch::Sender<Progress>,
    /// Wakes the checkpoint task before its next poll.
    wake: Notify,
}

impl Answers {
    /// The answers of the chain with `pins`, kept in `archive`, with `store` as the self-check
    /// store. The archive serves no period update until [`Self::check_archive`].
    pub fn new(
        preset: Preset,
        pins: PulsechainBeacon,
        archive: Archive,
        store: LightClientStore,
    ) -> Self {
        Self {
            chain_id: archive.chain_id(),
            preset,
            pins,
            store: Mutex::new(store),
            finality: watch::Sender::new(None),
            optimistic: watch::Sender::new(None),
            archive: tokio::sync::Mutex::new(archive),
            progress: watch::Sender::new(Progress::default()),
            wake: Notify::new(),
        }
    }

    /// Returns the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Returns the preset.
    pub const fn preset(&self) -> Preset {
        self.preset
    }

    /// Returns the pinned chain values.
    pub const fn pins(&self) -> &PulsechainBeacon {
        &self.pins
    }

    /// Returns the archive of period updates and bootstraps.
    pub const fn archive(&self) -> &tokio::sync::Mutex<Archive> {
        &self.archive
    }

    /// Returns the latest finality update, as a `finality_update` answer serves it.
    pub fn finality_update(&self) -> Latest {
        self.finality.borrow().clone()
    }

    /// Returns the latest optimistic update.
    pub fn optimistic_update(&self) -> Latest {
        self.optimistic.borrow().clone()
    }

    /// Returns a receiver that sees each new finality update.
    pub fn subscribe_finality(&self) -> watch::Receiver<Latest> {
        self.finality.subscribe()
    }

    /// Returns a receiver that sees each new optimistic update.
    pub fn subscribe_optimistic(&self) -> watch::Receiver<Latest> {
        self.optimistic.subscribe()
    }

    /// Returns a receiver that sees each change of the checkpoint task's [`Progress`].
    pub fn subscribe_progress(&self) -> watch::Receiver<Progress> {
        self.progress.subscribe()
    }

    /// Makes the checkpoint task run a step now, or right after the step it runs.
    pub fn wake_checkpoint(&self) {
        self.wake.notify_one();
    }

    /// Waits for [`Self::wake_checkpoint`].
    pub(crate) async fn woken(&self) {
        self.wake.notified().await;
    }

    /// Records that a checkpoint step started.
    pub(crate) fn step_started(&self) {
        self.progress.send_modify(|progress| progress.started += 1);
    }

    /// Records that the running step builds `root`.
    pub(crate) fn step_builds(&self, root: B256) {
        self.progress.send_modify(|progress| progress.building = Some(root));
    }

    /// Records that the running step ended.
    pub(crate) fn step_done(&self) {
        self.progress.send_modify(|progress| {
            progress.done = progress.started;
            progress.building = None;
        });
    }

    /// Returns the self-check store.
    #[cfg(test)]
    pub(crate) fn store(&self) -> parking_lot::MutexGuard<'_, LightClientStore> {
        self.store.lock()
    }

    /// Returns the slot of the self-check store's finalized header when a checkpoint at `slot`
    /// can teach the store nothing: it is older, or at it once the store knows the next
    /// committee. `None` otherwise.
    pub(crate) fn passed(&self, slot: u64) -> Option<u64> {
        let store = self.store.lock();
        let finalized = store.finalized_header().beacon.slot;
        let passed = slot < finalized || slot == finalized && store.next_sync_committee().is_some();
        passed.then_some(finalized)
    }

    /// Checks the archive's stored period updates from the pin, the anchor and the self-check
    /// store, once after open, at the wall-clock slot `current_slot`. The store moves forward
    /// through the stored updates it verifies, and is saved. Until the check, the archive
    /// serves no period update.
    pub async fn check_archive(&self, current_slot: u64) -> io::Result<()> {
        let mut archive = self.archive.lock().await;
        if archive.is_verified() {
            return Ok(())
        }
        let store = self.store.lock().clone();
        let store = archive.check(store, current_slot).await?;
        archive.save_store(&store).await?;
        info!(target: "lc_server::answers", period = store.period(), slot = store.finalized_header().beacon.slot, "checked the stored period updates against the self-check store");
        *self.store.lock() = store;
        Ok(())
    }

    /// Checks `bootstrap` against `root`, and that its committee is the one the self-check store
    /// verified for its period. The store is not changed: an upstream root never becomes its
    /// anchor.
    pub(crate) fn check_bootstrap(
        &self,
        root: B256,
        bootstrap: &LightClientBootstrap,
    ) -> Result<(), SelfCheckError> {
        let period = LightClientStore::bootstrap(self.preset, self.pins, root, bootstrap)?.period();
        let store = self.store.lock();
        let store_period = store.period();
        let known = if period == store_period {
            Some(store.current_sync_committee())
        } else if period == store_period + 1 {
            store.next_sync_committee()
        } else {
            None
        };
        match known {
            Some(committee) if *committee == bootstrap.current_sync_committee => Ok(()),
            Some(_) => Err(SelfCheckError::OtherCommittee { period }),
            None => Err(SelfCheckError::NotChained { period, store_period }),
        }
    }

    /// Returns whether `root` is the root of the self-check store's finalized header.
    pub(crate) fn is_finalized(&self, root: B256) -> bool {
        self.store.lock().finalized_header().beacon.hash_tree_root() == root
    }

    /// Checks that a committee the self-check store verified signs `update`, at the wall-clock
    /// slot `current_slot`. The store is not changed.
    pub(crate) fn check_signed(
        &self,
        update: &LightClientUpdate,
        current_slot: u64,
    ) -> Result<(), SelfCheckError> {
        Ok(self.store.lock().validate_update(update, current_slot)?)
    }

    /// Applies the finality or period `update` to the self-check store at the wall-clock slot
    /// `current_slot`, and saves the store.
    ///
    /// The store checks the update first. A period update is stored in the archive before the
    /// store takes it, so that a failed write leaves the store where it was. When the store's
    /// committees change, the stored updates above it that it now verifies move it further.
    pub(crate) async fn accept_update(
        &self,
        update: &LightClientUpdate,
        current_slot: u64,
    ) -> Result<(), AcceptError> {
        let mut archive = self.archive.lock().await;
        self.store.lock().validate_update(update, current_slot).map_err(SelfCheckError::from)?;
        if update.is_sync_committee_update() {
            archive.save_update(update.clone()).await?;
        }
        let (store, moved) = {
            let mut store = self.store.lock();
            let before = (store.period(), store.next_sync_committee().is_some());
            store.process_update(update, current_slot).map_err(SelfCheckError::from)?;
            let moved = before != (store.period(), store.next_sync_committee().is_some());
            (store.clone(), moved)
        };
        let further = if moved { archive.extend(&store, current_slot).await? } else { None };
        let store = match further {
            Some(further) => {
                *self.store.lock() = further.clone();
                further
            }
            None => store,
        };
        archive.save_store(&store).await?;
        if moved {
            info!(target: "lc_server::answers", period = store.period(), next = store.next_sync_committee().is_some(), "the self-check store moved to a new committee");
        }
        Ok(())
    }

    /// Serves `update` as the latest finality update when its attested block is newer than the
    /// served one's. The self-check store has accepted it. Returns whether it serves `update`.
    pub(crate) fn publish_finality(&self, update: LightClientUpdate) -> bool {
        let slot = update.attested_header.beacon.slot;
        let newer = self.finality.send_if_modified(|served| {
            let newer =
                served.as_ref().is_none_or(|served| served.attested_header.beacon.slot < slot);
            if newer {
                *served = Some(Arc::new(update));
            }
            newer
        });
        if newer {
            debug!(target: "lc_server::answers", slot, "new finality update");
        }
        newer
    }

    /// Applies the optimistic `update` to the self-check store and serves it when the store
    /// accepts it. Returns whether it is newer than the update served before.
    pub(crate) fn accept_optimistic(
        &self,
        update: LightClientUpdate,
        current_slot: u64,
    ) -> Result<bool, SelfCheckError> {
        self.store.lock().process_update(&update, current_slot)?;
        let newer = self
            .optimistic
            .borrow()
            .as_ref()
            .is_none_or(|served| served.signature_slot < update.signature_slot);
        if newer {
            debug!(target: "lc_server::answers", slot = update.attested_header.beacon.slot, "new optimistic update");
            self.optimistic.send_replace(Some(Arc::new(update)));
        }
        Ok(newer)
    }
}
