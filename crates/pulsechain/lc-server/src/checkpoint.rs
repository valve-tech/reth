//! The checkpoint task: the bootstrap, finality and period answers at each finalized checkpoint.
//!
//! Each slot it asks the state URL for its finalized root. For a new root it fetches F by root,
//! finds C as the first block in slots S+1 to S+32 after F's slot S, fetches `states/{S}` and
//! hashes it once, and checks that its committee is the one the self-check store verified for
//! its period. It checks C's signature with the state's committee, and asks the beacon URLs for
//! C again when it fails. It stores the bootstrap once the store's committee verifies C's
//! signature over F. Then it fetches G, the block that F's state has finalized, builds the
//! updates, and serves and stores each one that the self-check store accepts. A checkpoint that
//! does not chain to the store is refused. See `DESIGN.md`.
//!
//! An upstream that is down or slow leaves the root to try again while it is still the newest.
//! Each try fetches only what the tries before did not get, and the wait before the next try
//! doubles with each failure, up to [`MAX_RETRY_SLOTS`]. Data that does not check out drops the
//! root.

use crate::{
    answers::{AcceptError, Answers, SelfCheckError},
    archive::MAX_BOOTSTRAPS,
    current_slot,
    upstream::{Beacons, FetchError, Upstream, UpstreamError},
};
use alloy_primitives::B256;
use reth_pulsechain_light_client::derive::{
    optimistic_update, CheckedState, DeriveError, LightClientBlock,
};
use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, warn};

/// A period with no stored update after this many epochs is logged as an error. The update
/// usually comes about 2 epochs into a period, once G is in it too.
pub const MISSING_UPDATE_EPOCHS: u64 = 8;
/// The least time from the start of one step to the start of the next, so that bootstrap
/// requests that wake the task cannot make it ask the state URL without limit.
pub const MIN_STEP_GAP: Duration = Duration::from_secs(1);
/// The longest wait, in slots, before a root that failed is tried again: one epoch. The wait is
/// one slot after the first failure and doubles after each next one.
pub const MAX_RETRY_SLOTS: u64 = 32;

/// Why a checkpoint gave no answers, or only a bootstrap.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// The state URL did not give its finalized root.
    #[error("the state URL's finalized root: {0}")]
    FinalizedRoot(UpstreamError),
    /// A block that the checkpoint needs was not read.
    #[error("block {root}: {source}")]
    Block {
        /// The block root.
        root: B256,
        /// What went wrong.
        source: FetchError,
    },
    /// No beacon URL has a block that the checkpoint needs.
    #[error("no beacon URL has block {0}")]
    MissingBlock(B256),
    /// The state URL did not give the state.
    #[error("the state at slot {slot}: {source}")]
    State {
        /// The state's slot.
        slot: u64,
        /// What went wrong.
        source: UpstreamError,
    },
    /// A block after F was not read.
    #[error("the block at slot {slot}: {source}")]
    Child {
        /// The slot.
        slot: u64,
        /// What went wrong.
        source: FetchError,
    },
    /// No slot after F has a block.
    #[error("no block in slots {from} to {to}")]
    NoChild {
        /// The first slot asked for.
        from: u64,
        /// The last slot asked for.
        to: u64,
    },
    /// F is after the wall-clock slot, so it cannot be finalized.
    #[error("F at slot {slot} is after the wall-clock slot {current}")]
    FutureRoot {
        /// F's slot.
        slot: u64,
        /// The wall-clock slot, with one slot for clock drift.
        current: u64,
    },
    /// F is not newer than the newest checkpoint handled, as from a state URL that syncs again,
    /// or it can teach the self-check store nothing, as after a restart.
    #[error("F at slot {slot} is not newer than the checkpoint at slot {newest}")]
    OlderRoot {
        /// F's slot.
        slot: u64,
        /// The slot of the newest F handled, or of the store's finalized header.
        newest: u64,
    },
    /// The data does not give the answer.
    #[error(transparent)]
    Derive(#[from] DeriveError),
    /// The self-check store did not accept the answer.
    #[error(transparent)]
    SelfCheck(#[from] SelfCheckError),
    /// The archive could not store an answer, or the build thread failed.
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl From<AcceptError> for CheckpointError {
    fn from(err: AcceptError) -> Self {
        match err {
            AcceptError::SelfCheck(err) => Self::SelfCheck(err),
            AcceptError::Io(err) => Self::Io(err),
        }
    }
}

impl CheckpointError {
    /// Returns whether an upstream failure caused the error, so the root may give the answers at
    /// the next try. A block that does not read is one beacon URL's failure too: a hostile URL's
    /// bytes must not drop a root that the next try gets from another URL.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::FinalizedRoot(_) |
                Self::Block { .. } |
                Self::MissingBlock(_) |
                Self::State { .. } |
                Self::Child { .. } |
                Self::Io(_)
        )
    }

    /// A name of the error's cause, so that a cause that repeats each slot is logged once.
    const fn cause(&self) -> &'static str {
        match self {
            Self::FinalizedRoot(_) => "finalized root",
            Self::Block { .. } | Self::MissingBlock(_) => "block",
            Self::State { .. } => "state",
            Self::Child { .. } | Self::NoChild { .. } => "child",
            Self::FutureRoot { .. } => "future root",
            Self::OlderRoot { .. } => "older root",
            Self::Derive(_) => "derive",
            Self::SelfCheck(
                SelfCheckError::OtherCommittee { .. } | SelfCheckError::NotChained { .. },
            ) => "not chained",
            Self::SelfCheck(_) => "self-check",
            Self::Io(_) => "io",
        }
    }
}

/// The checkpoint task of one chain.
#[derive(Debug)]
pub struct CheckpointTask {
    answers: Arc<Answers>,
    state_url: Upstream,
    beacons: Beacons,
    /// The newest root handled to the end, with answers or dropped.
    done: Option<B256>,
    /// The slot of the newest F handled to the end. An older F is skipped before its state.
    newest: Option<u64>,
    /// The root that failed for a cause worth another try, with what its tries got.
    retry: Option<Building>,
    /// The cause of the last failure, logged once until a checkpoint succeeds.
    last_cause: Option<&'static str>,
    /// The period whose missing update was logged.
    missing_logged: Option<u64>,
}

impl CheckpointTask {
    /// A task that builds `answers` from `state_url` and `beacons`.
    pub const fn new(answers: Arc<Answers>, state_url: Upstream, beacons: Beacons) -> Self {
        Self {
            answers,
            state_url,
            beacons,
            done: None,
            newest: None,
            retry: None,
            last_cause: None,
            missing_logged: None,
        }
    }

    /// Runs a step every `poll`, and when [`Answers::wake_checkpoint`] wakes it, at most one
    /// step every [`MIN_STEP_GAP`]. It ends only when the caller aborts it.
    pub async fn run(mut self, poll: Duration) {
        let mut tick = tokio::time::interval(poll);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let answers = self.answers.clone();
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = answers.woken() => {}
            }
            let started = tokio::time::Instant::now();
            let slot = current_slot(self.answers.pins(), SystemTime::now());
            match self.step(slot).await {
                Ok(Some(root)) => {
                    debug!(target: "lc_server::checkpoint", %root, "built the checkpoint answers");
                    self.last_cause = None;
                }
                Ok(None) => {}
                Err(err) => self.log(&err),
            }
            tokio::time::sleep_until(started + MIN_STEP_GAP).await;
        }
    }

    /// Logs `err`: an unknown fork or a self-check failure as an error, and another cause once
    /// until a checkpoint succeeds. A checkpoint that does not chain to the self-check store is
    /// an error too, logged once and counted each time.
    fn log(&mut self, err: &CheckpointError) {
        match err {
            CheckpointError::SelfCheck(
                SelfCheckError::OtherCommittee { .. } | SelfCheckError::NotChained { .. },
            ) => {
                metrics::counter!("lc_server_checkpoints_not_chained_total").increment(1);
                if self.last_cause != Some(err.cause()) {
                    error!(target: "lc_server::checkpoint", %err, "refused a checkpoint that does not chain to the self-check store");
                    self.last_cause = Some(err.cause());
                }
                return
            }
            CheckpointError::Derive(
                DeriveError::UnsupportedFork { .. } | DeriveError::UnknownStateFork { .. },
            ) |
            CheckpointError::Block { source: FetchError::Derive(_), .. } |
            CheckpointError::Child { source: FetchError::Derive(_), .. } |
            CheckpointError::SelfCheck(_) => {
                error!(target: "lc_server::checkpoint", %err, "cannot build the checkpoint answers");
                return
            }
            _ => {}
        }
        if self.last_cause == Some(err.cause()) {
            debug!(target: "lc_server::checkpoint", %err, "no checkpoint answers");
        } else {
            warn!(target: "lc_server::checkpoint", %err, "no checkpoint answers");
            self.last_cause = Some(err.cause());
        }
    }

    /// Handles the state URL's newest finalized root at wall-clock slot `current_slot`.
    /// Returns the root when it built new answers, and `None` when the root was handled before
    /// or waits for its next try.
    ///
    /// A root that fails for a cause [`CheckpointError::is_retryable`] names is tried again,
    /// after a wait that a woken step does not skip. A root that gives only a bootstrap is done.
    /// Each step is recorded in the answers' [`Progress`](crate::answers::Progress).
    pub async fn step(&mut self, current_slot: u64) -> Result<Option<B256>, CheckpointError> {
        self.answers.step_started();
        let result = self.step_inner(current_slot).await;
        self.answers.step_done();
        result
    }

    async fn step_inner(&mut self, current_slot: u64) -> Result<Option<B256>, CheckpointError> {
        self.answers.check_archive(current_slot).await?;
        self.log_missing_update(current_slot).await;
        let root = self.state_url.finalized_root().await.map_err(CheckpointError::FinalizedRoot)?;
        if self.done == Some(root) {
            return Ok(None)
        }
        let mut building = match self.retry.take() {
            Some(building) if building.root == root => building,
            _ => Building::new(root),
        };
        if current_slot < building.next_try {
            self.retry = Some(building);
            return Ok(None)
        }
        self.answers.step_builds(root);
        let result = self.build(&mut building, current_slot).await;
        if result.as_ref().is_err_and(CheckpointError::is_retryable) {
            building.failures += 1;
            building.next_try = current_slot + retry_delay(building.failures);
            self.retry = Some(building);
        } else {
            self.done = Some(root);
            self.newest = self.newest.max(building.f.as_ref().map(LightClientBlock::slot));
        }
        result.map(|()| Some(root))
    }

    /// Builds, checks, serves and stores the answers of the checkpoint at `b.root`, with the
    /// parts that earlier tries got.
    async fn build(&self, b: &mut Building, current_slot: u64) -> Result<(), CheckpointError> {
        let root = b.root;
        let f = match &mut b.f {
            Some(f) => &*f,
            none => {
                let f = self.block(root).await?;
                if f.slot() > current_slot {
                    return Err(CheckpointError::FutureRoot {
                        slot: f.slot(),
                        current: current_slot,
                    })
                }
                if let Some(newest) = self.newest.filter(|&newest| f.slot() <= newest) {
                    return Err(CheckpointError::OlderRoot { slot: f.slot(), newest })
                }
                if let Some(finalized) = self.answers.passed(f.slot()) {
                    return Err(CheckpointError::OlderRoot { slot: f.slot(), newest: finalized })
                }
                &*none.insert(f)
            }
        };
        // C comes before the state, so a checkpoint without a good child costs no state.
        if b.c.is_none() {
            b.c = Some(self.child(f, None).await?);
        }
        let checked = match &mut b.checked {
            Some(checked) => &*checked,
            none => &*none.insert(self.hash_state(f).await?),
        };

        let bootstrap = checked.bootstrap();
        self.answers.check_bootstrap(root, &bootstrap)?;
        // C was fetched by slot, so nothing tied its aggregate to F until the state gave the
        // committee. A bad one is a failed answer: the beacon URLs are asked again.
        let c = match &mut b.c {
            Some(c) if checked.check_signature(self.answers.pins(), c).is_ok() => &*c,
            c => {
                debug!(target: "lc_server::checkpoint", %root, "the child's signature does not verify; asking for it again");
                &*c.insert(self.child(f, Some(checked)).await?)
            }
        };
        // The state's committees are the claim of whoever made F, so F is stored only once a
        // committee that the store verified signs it. The store verified its own header.
        if !self.answers.is_finalized(root) {
            let signed = optimistic_update(self.answers.preset(), f, c)?;
            self.answers.check_signed(&signed, current_slot)?;
        }
        {
            let mut archive = self.answers.archive().lock().await;
            archive.save_bootstrap(bootstrap).await?;
            archive.prune(SystemTime::now(), MAX_BOOTSTRAPS).await?;
        }
        let g = self.block(checked.finalized_root()).await?;
        let finality = checked.finality_update(&g, c)?;
        match checked.period_update(&g, c) {
            Ok(period) => self.answers.accept_update(&period, current_slot).await?,
            // With G in the period before, the finality update alone is served. The period
            // update finalizes the next committee, so it waits for G in the period.
            Err(err @ DeriveError::CrossPeriod { .. }) => {
                debug!(target: "lc_server::checkpoint", %err, "no period update until G is in the period");
                self.answers.accept_update(&finality, current_slot).await?;
            }
            Err(err) => return Err(err.into()),
        }
        self.answers.publish_finality(finality);
        Ok(())
    }

    /// Fetches F's state from the state URL and hashes it on a blocking thread.
    async fn hash_state(&self, f: &LightClientBlock) -> Result<CheckedState, CheckpointError> {
        let slot = f.slot();
        let state = self
            .state_url
            .state(slot)
            .await
            .map_err(|source| CheckpointError::State { slot, source })?;
        let (preset, pins, f) = (self.answers.preset(), *self.answers.pins(), f.clone());
        let checked =
            tokio::task::spawn_blocking(move || CheckedState::new(preset, &pins, &f, &state))
                .await
                .map_err(io::Error::from)??;
        Ok(checked)
    }

    /// Fetches the block with `root` from the beacon URLs.
    async fn block(&self, root: B256) -> Result<LightClientBlock, CheckpointError> {
        self.beacons
            .block_by_root(root)
            .await
            .map_err(|source| CheckpointError::Block { root, source })?
            .ok_or(CheckpointError::MissingBlock(root))
    }

    /// Finds C, the first block after `f` within one epoch. It must have `f` as its parent, and
    /// with `signed`, F's state, an aggregate that the state's committee made: another block
    /// from every beacon URL that has one is a failed answer, tried again.
    async fn child(
        &self,
        f: &LightClientBlock,
        signed: Option<&CheckedState>,
    ) -> Result<LightClientBlock, CheckpointError> {
        let (from, to) = (f.slot() + 1, f.slot() + self.answers.preset().slots_per_epoch());
        let pins = self.answers.pins();
        for slot in from..=to {
            let found = self
                .beacons
                .child_at_slot(slot, f.root(), |c| {
                    signed.is_none_or(|state| state.check_signature(pins, c).is_ok())
                })
                .await
                .map_err(|source| CheckpointError::Child { slot, source })?;
            if let Some(c) = found {
                return Ok(c)
            }
        }
        Err(CheckpointError::NoChild { from, to })
    }

    /// Logs an error, once per period, when the period of `current_slot` is
    /// [`MISSING_UPDATE_EPOCHS`] old and has no stored update. Returns whether it logged. It does
    /// not check while the stored updates wait for the self-check store, which serves none.
    pub async fn log_missing_update(&mut self, current_slot: u64) -> bool {
        let preset = self.answers.preset();
        let epoch = preset.epoch_at_slot(current_slot);
        let period = preset.period_at_slot(current_slot);
        let age = epoch % preset.epochs_per_sync_committee_period();
        if age < MISSING_UPDATE_EPOCHS || self.missing_logged == Some(period) {
            return false
        }
        let archive = self.answers.archive().lock().await;
        if !archive.is_verified() || archive.update(period).is_some() {
            return false
        }
        drop(archive);
        self.missing_logged = Some(period);
        error!(target: "lc_server::checkpoint", period, epochs = age, "no update for the current sync-committee period; clients stop at the next period boundary unless one comes");
        true
    }
}

/// The parts of one root's answers that its tries got, and when it is tried next.
#[derive(Debug)]
struct Building {
    root: B256,
    f: Option<LightClientBlock>,
    c: Option<LightClientBlock>,
    /// F's state, hashed. The bootstrap is built from it.
    checked: Option<CheckedState>,
    /// The tries that failed.
    failures: u32,
    /// The wall-clock slot of the next try.
    next_try: u64,
}

impl Building {
    const fn new(root: B256) -> Self {
        Self { root, f: None, c: None, checked: None, failures: 0, next_try: 0 }
    }
}

/// The slots to wait after the `failures`th failure in a row: 1, 2, 4 and so on, up to
/// [`MAX_RETRY_SLOTS`].
fn retry_delay(failures: u32) -> u64 {
    1u64.checked_shl(failures.saturating_sub(1)).unwrap_or(u64::MAX).min(MAX_RETRY_SLOTS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::{Archive, STORE_FILE},
        fake::{committee, Answer, Rig, TestChain, NOW, PRESET},
        head::HeadTask,
        upstream::Timeouts,
    };
    use reth_pulsechain_forks::network::pulsechain_network;
    use reth_pulsechain_light_client::{
        derive::test_utils::{block_ssz, keys, sign},
        sync_committee::{
            test_utils::{repeated_committee, Real369},
            LightClientStore, LightClientUpdate, Preset, SyncCommitteeError,
        },
    };

    // Period 1 of the minimal preset is slots 64 to 127, 8 slots an epoch. F is at 88 (epoch 11)
    // and has finalized G at 72 (epoch 9).
    const G: u64 = 72;
    const F: u64 = 88;
    const STATE_88: &str = "/eth/v2/debug/beacon/states/88";

    fn task(rig: &Rig) -> CheckpointTask {
        CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), rig.beacons())
    }

    /// Blocks at 64 to 87, the checkpoint at 88, and blocks at `after`.
    fn chain_with(after: impl IntoIterator<Item = u64>) -> TestChain {
        let mut chain = TestChain::new();
        chain.extend(64..F);
        chain.checkpoint(F, G);
        chain.extend(after);
        chain
    }

    async fn stored_bootstrap(rig: &Rig, root: B256) -> bool {
        rig.answers.archive().lock().await.has_bootstrap(&root)
    }

    async fn stored_periods(rig: &Rig) -> Vec<u64> {
        rig.answers.archive().lock().await.periods().collect()
    }

    /// The child slot S+1 has no block, so C is the block at S+2. The checkpoint gives the
    /// bootstrap, the finality update and the period update, and a second step at the same root
    /// fetches nothing again.
    #[tokio::test]
    async fn a_skipped_child_slot_gives_every_answer_from_the_next_block() {
        let chain = chain_with(90..96);
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);

        assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(F)));
        assert!(stored_bootstrap(&rig, chain.root(F)).await);
        let finality = rig.answers.finality_update().unwrap();
        assert_eq!(finality.attested_header, *chain.at(F).header());
        assert_eq!(finality.finalized_header, *chain.at(G).header());
        assert_eq!(finality.signature_slot, 90);
        assert!(!finality.is_sync_committee_update());
        assert_eq!(stored_periods(&rig).await, [1]);
        let archive = rig.answers.archive().lock().await;
        assert_eq!(archive.update(1).unwrap().next_sync_committee, committee(2));
        drop(archive);
        assert_eq!(rig.answers.store().next_sync_committee(), Some(&committee(2)));
        assert_eq!(rig.beacon.calls("/eth/v2/beacon/blocks/89"), 1);

        assert_eq!(task.step(NOW).await.unwrap(), None);
        assert_eq!(rig.state.calls(STATE_88), 1);
    }

    /// A restart goes on from the self-check store the server saved, not from its trust root:
    /// here the store had moved to period 2. The stored updates are served at once.
    #[tokio::test]
    async fn a_restart_continues_from_the_saved_self_check_store() {
        let mut chain = chain_with(89..152);
        chain.checkpoint(152, 136);
        chain.extend(153..155);
        let rig = Rig::start(&chain).await;
        let mut first_run = task(&rig);
        for root in [chain.root(F), chain.root(152)] {
            rig.state.finalize(root);
            assert_eq!(first_run.step(NOW).await.unwrap(), Some(root));
        }
        drop(first_run);
        let saved = rig.answers.store().clone();
        assert_eq!(saved.period(), 2);

        let rig = rig.restart().await;
        rig.answers.check_archive(NOW).await.unwrap();
        let store = rig.answers.store().clone();
        assert_eq!(store.finalized_header(), chain.at(136).header());
        assert_eq!(store.current_sync_committee(), &committee(2));
        assert_eq!(store.next_sync_committee(), Some(&committee(3)));
        assert_eq!(stored_periods(&rig).await, [1, 2]);
        assert!(rig.answers.archive().lock().await.updates_json().keys().eq([&1, &2]));
        // The state URL names the trust root again: it is older than the store, and dropped
        // before its state.
        rig.state.finalize(chain.root(F));
        assert!(matches!(
            task(&rig).step(NOW).await,
            Err(CheckpointError::OlderRoot { slot: F, newest: 136 })
        ));
        assert_eq!(rig.state.calls(STATE_88), 1);
        assert_eq!(rig.answers.store().finalized_header(), chain.at(136).header());
    }

    /// Blocks at 64 to 282, with a checkpoint in each of periods 1 to 4: F at 88, 152, 216 and
    /// 280.
    fn four_periods() -> TestChain {
        let mut chain = chain_with(89..152);
        chain.checkpoint(152, 136);
        chain.extend(153..216);
        chain.checkpoint(216, 200);
        chain.extend(217..280);
        chain.checkpoint(280, 264);
        chain.extend(281..283);
        chain
    }

    /// Steps `task` at each of the checkpoints `fs` of `chain`.
    async fn step_at(rig: &Rig, chain: &TestChain, fs: &[u64]) {
        let mut task = task(rig);
        for &f in fs {
            rig.state.finalize(chain.root(f));
            assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(f)), "F at {f}");
        }
    }

    /// The archive's anchor file in `rig`'s datadir.
    fn anchor_file(rig: &Rig) -> std::path::PathBuf {
        rig.dir().join("anchor.ssz")
    }

    /// `--checkpoint` starts a datadir at 152, in period 2, after the pin's period 1, on a chain
    /// whose pin is `pin`. The server stores the updates of periods 2 to 4, and its store moves
    /// to period 4. After each of two restarts every stored period is served again: the walk
    /// from the anchor, the store that the datadir first bootstrapped, checks them.
    async fn a_restart_serves_every_period_from_the_anchor_up(pin: Option<LightClientStore>) {
        let chain = four_periods();
        let rig = Rig::from_checkpoint(&chain, pin, chain.store_at(152)).await;
        step_at(&rig, &chain, &[152, 216, 280]).await;
        assert_eq!(stored_periods(&rig).await, [2, 3, 4]);
        assert_eq!(rig.answers.store().period(), 4);

        let mut rig = rig;
        for restart in 1..=2 {
            rig = rig.restart().await;
            rig.answers.check_archive(NOW).await.unwrap();
            assert_eq!(stored_periods(&rig).await, [2, 3, 4], "restart {restart}");
            let archive = rig.answers.archive().lock().await;
            assert!(archive.updates_json().keys().eq([&2, &3, &4]), "restart {restart}");
            assert!(archive.unchained().is_empty(), "restart {restart}");
            drop(archive);
            assert_eq!(rig.answers.store().period(), 4);
        }
    }

    /// On a chain with a pin at period 1, a datadir that `--checkpoint` started in period 2
    /// serves its whole history after a restart.
    #[tokio::test]
    async fn a_restart_serves_the_history_of_a_datadir_started_after_the_pin() {
        let chain = four_periods();
        a_restart_serves_every_period_from_the_anchor_up(Some(chain.store_at(F))).await;
    }

    /// On a chain with no pin, as 943, a datadir serves its whole history after a restart.
    #[tokio::test]
    async fn a_restart_serves_the_history_of_a_datadir_on_a_chain_with_no_pin() {
        a_restart_serves_every_period_from_the_anchor_up(None).await;
    }

    /// The anchor file is the store that the datadir first bootstrapped. Later starts never
    /// write it again, though the saved store moves on.
    #[tokio::test]
    async fn the_anchor_file_is_never_overwritten() {
        let chain = four_periods();
        let rig = Rig::from_checkpoint(&chain, Some(chain.store_at(F)), chain.store_at(152)).await;
        let written = std::fs::read(anchor_file(&rig)).expect("the first start writes the anchor");
        assert_eq!(written, std::fs::read(rig.dir().join(STORE_FILE)).unwrap());
        step_at(&rig, &chain, &[152, 216]).await;

        let rig = rig.restart().await;
        rig.answers.check_archive(NOW).await.unwrap();
        step_at(&rig, &chain, &[280]).await;
        let rig = rig.restart().await;
        rig.answers.check_archive(NOW).await.unwrap();
        assert_eq!(rig.answers.store().period(), 4);
        assert_eq!(std::fs::read(anchor_file(&rig)).unwrap(), written);
        assert_ne!(std::fs::read(rig.dir().join(STORE_FILE)).unwrap(), written);
    }

    /// The value of `name` that `recorder` holds.
    fn gauge(
        recorder: &metrics_exporter_prometheus::PrometheusRecorder,
        name: &str,
    ) -> Option<u64> {
        let prefix = format!("{name} ");
        recorder.handle().render().lines().find_map(|line| line.strip_prefix(&prefix)?.parse().ok())
    }

    /// A damaged anchor file stays in place. A restart warns, counts it, and does not write it
    /// again, and the walks from the pin and the saved store still serve: here the pin's walk
    /// serves period 1, below the saved store.
    #[tokio::test]
    async fn a_damaged_anchor_file_is_kept_and_the_other_walks_serve() {
        let chain = four_periods();
        let rig = Rig::start(&chain).await;
        step_at(&rig, &chain, &[F, 152]).await;
        assert_eq!(rig.answers.store().period(), 2);
        let mut damaged = std::fs::read(anchor_file(&rig)).expect("the first start writes it");
        damaged[100] ^= 1;
        std::fs::write(anchor_file(&rig), &damaged).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let logs = crate::fake::Logs::capture();
        let mut rig = rig;
        for restart in 1..=2 {
            rig = rig.restart().await;
            rig.answers.check_archive(NOW).await.unwrap();
            assert_eq!(stored_periods(&rig).await, [1, 2], "restart {restart}");
            assert_eq!(std::fs::read(anchor_file(&rig)).unwrap(), damaged, "restart {restart}");
            assert_eq!(gauge(&recorder, "lc_server_archive_unreadable_anchor"), Some(1));
        }
        let text = logs.text();
        assert_eq!(text.matches("the anchor file does not check out").count(), 2, "{text}");
        assert!(text.contains("checksum"), "{text}");
    }

    /// A datadir from an older build has a saved store and no anchor file. A restart writes
    /// the loaded store as the anchor, so later restarts serve from its period up.
    #[tokio::test]
    async fn an_older_datadir_writes_its_saved_store_as_the_anchor() {
        let chain = four_periods();
        let rig = Rig::from_checkpoint(&chain, None, chain.store_at(152)).await;
        step_at(&rig, &chain, &[152]).await;
        assert_eq!(rig.answers.store().period(), 2);
        // An older build wrote no anchor file.
        let _ = std::fs::remove_file(anchor_file(&rig));
        let saved = std::fs::read(rig.dir().join(STORE_FILE)).unwrap();

        let rig = rig.restart().await;
        assert_eq!(std::fs::read(anchor_file(&rig)).expect("the restart writes it"), saved);
        rig.answers.check_archive(NOW).await.unwrap();
        step_at(&rig, &chain, &[216, 280]).await;
        let rig = rig.restart().await;
        rig.answers.check_archive(NOW).await.unwrap();
        assert_eq!(stored_periods(&rig).await, [2, 3, 4]);
        assert_eq!(std::fs::read(anchor_file(&rig)).unwrap(), saved);
    }

    /// The first block after F names another parent, so the beacon URL and the state URL do not
    /// agree on the chain. Nothing is served, and the root is tried again: another beacon URL,
    /// or this one once it follows the chain, may give the child.
    #[tokio::test]
    async fn a_child_with_another_parent_serves_nothing() {
        let mut chain = chain_with([]);
        let other = chain.root(F - 1);
        chain.push(F + 1, other, 24, B256::repeat_byte(2));
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);

        let err = task.step(NOW).await.unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::Child { slot: 89, source: FetchError::Upstream(UpstreamError::Body) }
        ));
        assert!(err.is_retryable());
        assert!(!stored_bootstrap(&rig, chain.root(F)).await);
        assert_eq!(rig.answers.finality_update(), None);
        assert_eq!(rig.answers.store().finalized_header(), chain.at(F).header());
        assert_eq!(rig.answers.store().next_sync_committee(), None);
        assert_eq!(rig.state.calls(STATE_88), 0);
    }

    /// The first beacon URL is on another fork after F; the second gives C.
    #[tokio::test]
    async fn a_beacon_url_on_another_fork_does_not_hide_the_child() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let forked = crate::fake::Fake::start(&chain.pins).await;
        let mut fork = chain_with([]);
        fork.push(F + 1, chain.root(F - 1), 24, B256::repeat_byte(2));
        forked.answer("/eth/v2/beacon/blocks/89", Answer::ssz(fork.blocks[&(F + 1)].0.clone()));
        rig.state.finalize(chain.root(F));
        let beacons =
            Beacons::new(PRESET, chain.pins, vec![forked.upstream(), rig.beacon.upstream()]);
        let mut task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), beacons);

        assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(F)));
        assert_eq!(rig.answers.finality_update().unwrap().signature_slot, F + 1);
    }

    /// One beacon URL answers F with bytes that do not read, and the other does not have F yet.
    /// The bytes are that URL's failure, not the root's, so the root is tried again and gives
    /// every answer once the other URL has F.
    #[tokio::test]
    async fn a_block_that_does_not_read_from_one_beacon_url_does_not_drop_the_root() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let hostile = crate::fake::Fake::start(&chain.pins).await;
        let f_path = format!("/eth/v2/beacon/blocks/{}", chain.root(F));
        hostile.answer(&f_path, Answer::ssz(vec![0; 8]));
        rig.beacon.answer(&f_path, Answer::status(404));
        rig.state.finalize(chain.root(F));
        let beacons =
            Beacons::new(PRESET, chain.pins, vec![hostile.upstream(), rig.beacon.upstream()]);
        let mut task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), beacons);

        let err = task.step(NOW).await.unwrap_err();
        assert!(
            matches!(err, CheckpointError::Block { source: FetchError::Derive(_), .. }),
            "{err}"
        );
        assert!(err.is_retryable());
        rig.beacon.heal();
        assert_eq!(task.step(NOW + 1).await.unwrap(), Some(chain.root(F)));
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(F).header());
    }

    /// The same holds for C: bytes that do not read at C's slot do not drop the root.
    #[test]
    fn a_child_that_does_not_read_is_retryable() {
        let err = CheckpointError::Child {
            slot: 89,
            source: FetchError::Derive(DeriveError::UnsupportedFork {
                slot: 89,
                fork: reth_pulsechain_forks::network::BeaconFork::Bellatrix,
            }),
        };
        assert!(err.is_retryable());
    }

    /// No block in the epoch after F.
    #[tokio::test]
    async fn no_child_in_an_epoch_drops_the_checkpoint() {
        let chain = chain_with([]);
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(F));
        assert!(matches!(
            task(&rig).step(NOW).await,
            Err(CheckpointError::NoChild { from: 89, to: 96 })
        ));
        assert!(!stored_bootstrap(&rig, chain.root(F)).await);
        assert_eq!(rig.state.calls(STATE_88), 0);
    }

    /// The state URL's state at S is not F's post-state, as when the first slot of an epoch has
    /// no block.
    #[tokio::test]
    async fn a_state_root_mismatch_drops_the_checkpoint() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let other = chain.state_at(F, G - 1, &committee(2));
        rig.state.serve_state(F, other);
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);

        assert!(matches!(
            task.step(NOW).await,
            Err(CheckpointError::Derive(DeriveError::StateRoot { block, .. }))
                if block == chain.at(F).header().beacon.state_root
        ));
        assert!(!stored_bootstrap(&rig, chain.root(F)).await);
        assert_eq!(rig.answers.finality_update(), None);
        assert_eq!(task.step(NOW).await.unwrap(), None);
    }

    /// A block at C's slot on F whose aggregate the committee did not make, from a beacon URL
    /// before the honest one. C is fetched by slot, so the state's committee checks it: the
    /// next beacon URL then gives C, and every answer is built. With no other URL the root is
    /// tried again, and no bootstrap is stored until a good C comes.
    #[tokio::test]
    async fn a_child_with_a_bad_signature_is_asked_of_the_next_beacon_url() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let hostile = crate::fake::Fake::start(&chain.pins).await;
        let aggregate = sign(PRESET, &chain.pins, &keys(77), 24, chain.root(F), F + 1);
        let forged = block_ssz(PRESET, F + 1, chain.root(F), B256::repeat_byte(9), &aggregate);
        hostile.answer("/eth/v2/beacon/blocks/89", Answer::ssz(forged));
        rig.state.finalize(chain.root(F));

        let only_hostile = Beacons::new(PRESET, chain.pins, vec![hostile.upstream()]);
        hostile.serve_blocks(&chain);
        let mut task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), only_hostile);
        let err = task.step(NOW).await.unwrap_err();
        assert!(
            matches!(
                err,
                CheckpointError::Child {
                    slot: 89,
                    source: FetchError::Upstream(UpstreamError::Body)
                }
            ),
            "{err}"
        );
        assert!(err.is_retryable());
        assert!(!stored_bootstrap(&rig, chain.root(F)).await);
        assert_eq!(rig.answers.finality_update(), None);

        let beacons =
            Beacons::new(PRESET, chain.pins, vec![hostile.upstream(), rig.beacon.upstream()]);
        let mut task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), beacons);
        assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(F)));
        assert_eq!(rig.answers.finality_update().unwrap().signature_slot, F + 1);
        assert_eq!(stored_periods(&rig).await, [1]);
        assert!(stored_bootstrap(&rig, chain.root(F)).await);
    }

    /// A hostile state URL and beacon URL name F' at 120, whose state holds the real committee
    /// of period 1 and a next committee whose keys they hold. They sign C' at 128, in period 2,
    /// with those keys, so C' checks out against the state. The self-check store knows the
    /// real period 2 committee, which did not sign C'. So F' is refused before G is fetched,
    /// and its bootstrap is not stored.
    #[tokio::test]
    async fn a_checkpoint_that_the_store_s_committee_did_not_sign_stores_no_bootstrap() {
        let mut chain = chain_with(89..92);
        let forger = keys(77);
        let next = repeated_committee(&forger, PRESET.sync_committee_size());
        chain.checkpoint_with_next(120, F, &next);
        let aggregate = sign(PRESET, &chain.pins, &forger, 24, chain.root(120), 128);
        let c = block_ssz(PRESET, 128, chain.root(120), B256::repeat_byte(9), &aggregate);
        let rig = Rig::start(&chain).await;
        rig.beacon.answer("/eth/v2/beacon/blocks/128", Answer::ssz(c));
        let mut task = task(&rig);
        rig.state.finalize(chain.root(F));
        task.step(NOW).await.unwrap();
        assert_eq!(rig.answers.store().next_sync_committee(), Some(&committee(2)));

        rig.state.finalize(chain.root(120));
        let err = task.step(NOW).await.unwrap_err();
        assert!(
            matches!(
                err,
                CheckpointError::SelfCheck(SelfCheckError::Refused(SyncCommitteeError::Signature(
                    _
                )))
            ),
            "{err}"
        );
        assert!(!err.is_retryable());
        assert!(!stored_bootstrap(&rig, chain.root(120)).await);
        assert_eq!(rig.beacon.calls(&format!("/eth/v2/beacon/blocks/{}", chain.root(F))), 1);
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(F).header());
    }

    /// C has 21 of 32 signers, under two thirds. F is the self-check store's own header, which
    /// the store verified, so its bootstrap is stored; the updates are dropped. At another F
    /// the store's check of C would drop the bootstrap too.
    #[tokio::test]
    async fn low_participation_drops_the_updates() {
        let mut chain = chain_with([]);
        chain.push(F + 1, chain.root(F), 21, B256::repeat_byte(2));
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);

        assert!(matches!(
            task.step(NOW).await,
            Err(CheckpointError::Derive(DeriveError::TooFewParticipants {
                participants: 21,
                size: 32
            }))
        ));
        assert!(stored_bootstrap(&rig, chain.root(F)).await);
        assert_eq!(rig.answers.finality_update(), None);
        assert_eq!(stored_periods(&rig).await, Vec::<u64>::new());
        assert_eq!(task.step(NOW).await.unwrap(), None);
    }

    /// A checkpoint after the self-check store's header whose C has too few signers is dropped
    /// with no bootstrap: no committee the store verified signs F.
    #[tokio::test]
    async fn low_participation_after_the_store_s_header_stores_no_bootstrap() {
        let mut chain = chain_with(89..96);
        chain.checkpoint(96, 80);
        chain.push(97, chain.root(96), 21, B256::repeat_byte(2));
        let rig = Rig::start(&chain).await;
        let mut task = task(&rig);
        rig.state.finalize(chain.root(F));
        task.step(NOW).await.unwrap();

        rig.state.finalize(chain.root(96));
        assert!(matches!(
            task.step(NOW).await,
            Err(CheckpointError::Derive(DeriveError::TooFewParticipants {
                participants: 21,
                size: 32
            }))
        ));
        assert!(!stored_bootstrap(&rig, chain.root(96)).await);
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(F).header());
    }

    /// After a first checkpoint, the state URL answers 404 for the next state and then never
    /// answers. Optimistic updates go on, and the checkpoint is built once the state comes.
    #[tokio::test]
    async fn optimistic_updates_go_on_while_the_state_url_fails() {
        let mut chain = chain_with(89..96);
        chain.checkpoint(96, 80);
        chain.extend(97..101);
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        task.step(NOW).await.unwrap();

        let state_96 = "/eth/v2/debug/beacon/states/96";
        rig.state.answer(state_96, Answer::status(404));
        rig.state.finalize(chain.root(96));
        assert!(matches!(
            task.step(NOW).await,
            Err(CheckpointError::State { slot: 96, source: UpstreamError::Status(404) })
        ));
        assert!(head.on_head(chain.root(99), NOW).await.unwrap());
        assert_eq!(
            rig.answers.optimistic_update().unwrap().attested_header,
            *chain.at(98).header()
        );

        rig.state.heal();
        rig.state.stall(state_96);
        assert!(matches!(
            task.step(NOW + 1).await,
            Err(CheckpointError::State { slot: 96, source: UpstreamError::Timeout })
        ));
        assert!(head.on_head(chain.root(100), NOW).await.unwrap());
        assert_eq!(rig.answers.optimistic_update().unwrap().signature_slot, 100);
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(F).header());

        rig.state.heal();
        assert_eq!(task.step(NOW + 3).await.unwrap(), Some(chain.root(96)));
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(96).header());
        assert_eq!(rig.state.calls(state_96), 3);
    }

    /// G answers 429 at first. The state is fetched and hashed once, and the bootstrap is
    /// stored before G comes. Each failure doubles the wait before the next try, and a woken
    /// step does not skip it.
    #[tokio::test]
    async fn a_failed_g_costs_one_state_and_waits_longer_each_try() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let g_path = format!("/eth/v2/beacon/blocks/{}", chain.root(G));
        rig.beacon.answer(&g_path, Answer::status(429));
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);
        let failed = |result: Result<Option<B256>, CheckpointError>| {
            matches!(
                result,
                Err(CheckpointError::Block {
                    source: FetchError::Upstream(UpstreamError::Status(429)),
                    ..
                })
            )
        };

        assert!(failed(task.step(NOW).await));
        assert!(stored_bootstrap(&rig, chain.root(F)).await);
        assert_eq!(rig.answers.finality_update(), None);
        assert!(failed(task.step(NOW + 1).await));
        // Two failures: the next try is at NOW + 3.
        assert_eq!(task.step(NOW + 2).await.unwrap(), None);
        assert_eq!(rig.beacon.calls(&g_path), 2);
        rig.beacon.heal();
        assert_eq!(task.step(NOW + 3).await.unwrap(), Some(chain.root(F)));
        assert_eq!(rig.state.calls(STATE_88), 1);
        assert_eq!(rig.beacon.calls(&format!("/eth/v2/beacon/blocks/{}", chain.root(F))), 1);
        assert_eq!(rig.beacon.calls("/eth/v2/beacon/blocks/89"), 1);
        assert_eq!(rig.answers.finality_update().unwrap().finalized_header, *chain.at(G).header());
    }

    #[test]
    fn the_retry_wait_doubles_up_to_an_epoch() {
        let waits: Vec<u64> = (1..=8).map(retry_delay).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 32, 32]);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_SLOTS);
    }

    /// Period 2 starts at slot 128. A checkpoint there has G in period 1, so it gives a
    /// bootstrap and a finality update but no period update; an optimistic update signed by the
    /// period 2 committee passes, since the period 1 update proved that committee. The first
    /// checkpoint with G in period 2 rotates the self-check store and stores the period 2 update.
    #[tokio::test]
    async fn the_committees_rotate_at_a_period_boundary() {
        let mut chain = chain_with(89..128);
        chain.checkpoint(128, 112);
        chain.extend(129..152);
        chain.checkpoint(152, 136);
        chain.extend(153..155);
        let rig = Rig::start(&chain).await;
        let mut task = task(&rig);
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());

        rig.state.finalize(chain.root(F));
        task.step(NOW).await.unwrap();
        assert_eq!(rig.answers.store().period(), 1);

        rig.state.finalize(chain.root(128));
        assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(128)));
        assert!(stored_bootstrap(&rig, chain.root(128)).await);
        let finality = rig.answers.finality_update().unwrap();
        assert_eq!(finality.attested_header, *chain.at(128).header());
        assert_eq!(finality.finalized_header, *chain.at(112).header());
        assert_eq!(stored_periods(&rig).await, [1]);
        let store = rig.answers.store().clone();
        assert_eq!((store.period(), store.finalized_header()), (1, chain.at(112).header()));
        assert!(head.on_head(chain.root(131), NOW).await.unwrap());

        rig.state.finalize(chain.root(152));
        assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(152)));
        let store = rig.answers.store().clone();
        assert_eq!(store.period(), 2);
        assert_eq!(store.current_sync_committee(), &committee(2));
        assert_eq!(store.next_sync_committee(), Some(&committee(3)));
        assert_eq!(stored_periods(&rig).await, [1, 2]);
        assert_eq!(
            rig.answers.finality_update().unwrap().finalized_header,
            *chain.at(136).header()
        );
    }

    /// A store that missed a period's update does not know the next committee, so it cannot
    /// check a checkpoint of the next period. The checkpoint is refused and does not become the
    /// store's anchor: nothing is stored or served, and the store stays where it was.
    #[tokio::test]
    async fn a_store_a_period_behind_refuses_the_checkpoint() {
        let mut chain = chain_with(89..152);
        chain.checkpoint(152, 136);
        chain.extend(153..155);
        let rig = Rig::start(&chain).await;
        let mut task = task(&rig);
        rig.state.finalize(chain.root(152));
        let err = task.step(NOW).await.unwrap_err();
        assert!(
            matches!(
                err,
                CheckpointError::SelfCheck(SelfCheckError::NotChained {
                    period: 2,
                    store_period: 1
                })
            ),
            "{err}"
        );
        assert!(!err.is_retryable());
        assert!(!stored_bootstrap(&rig, chain.root(152)).await);
        assert_eq!(rig.answers.finality_update(), None);
        assert!(stored_periods(&rig).await.is_empty());
        let store = rig.answers.store().clone();
        assert_eq!((store.period(), store.finalized_header()), (1, chain.at(F).header()));
        assert_eq!(task.step(NOW).await.unwrap(), None);
    }

    /// A state URL on another chain, with other committees, names its finalized roots. Each
    /// bootstrap's committee is not the one the self-check store verified, so the checkpoint is
    /// refused: nothing is stored or served, the store does not move, and the refusal is logged
    /// once.
    #[tokio::test]
    async fn an_upstream_checkpoint_on_another_chain_is_refused() {
        let ours = chain_with(89..92);
        let mut other = TestChain::with_keys(101);
        other.pins = ours.pins;
        other.extend(64..F);
        other.checkpoint(F, G);
        other.extend(89..96);
        other.checkpoint(96, 80);
        other.extend(97..99);
        let rig = Rig::anchored(&other, ours.store_at(F)).await;
        let mut task = task(&rig);
        let logs = crate::fake::Logs::capture();
        for slot in [F, 96] {
            rig.state.finalize(other.root(slot));
            let err = task.step(NOW).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    CheckpointError::SelfCheck(SelfCheckError::OtherCommittee { period: 1 })
                ),
                "{err}"
            );
            assert!(!err.is_retryable());
            task.log(&err);
            assert!(!stored_bootstrap(&rig, other.root(slot)).await);
        }
        assert_eq!(rig.answers.finality_update(), None);
        assert!(stored_periods(&rig).await.is_empty());
        assert_eq!(rig.answers.store().finalized_header(), ours.at(F).header());
        let saved = rig.answers.archive().lock().await.load_store(SystemTime::now()).await;
        assert_eq!(saved.unwrap().unwrap().finalized_header(), ours.at(F).header());
        let text = logs.text();
        let line = "refused a checkpoint that does not chain to the self-check store";
        assert_eq!(text.matches(line).count(), 1, "{text}");
    }

    /// After the checkpoint at 152 (period 2), the state URL names F at 88 (period 1) again, as
    /// a node that syncs again does. The older root costs no state, the store keeps period 2,
    /// and the served finality update stays at 152. The store also refuses the old period
    /// update itself without starting again.
    #[tokio::test]
    async fn an_older_root_does_not_move_the_answers_back() {
        let mut chain = chain_with(89..152);
        chain.checkpoint(152, 136);
        chain.extend(153..155);
        let rig = Rig::start(&chain).await;
        let mut task = task(&rig);
        rig.state.finalize(chain.root(F));
        task.step(NOW).await.unwrap();
        rig.state.finalize(chain.root(152));
        task.step(NOW).await.unwrap();
        assert_eq!(rig.answers.store().period(), 2);

        rig.state.finalize(chain.root(F));
        assert!(matches!(
            task.step(NOW).await,
            Err(CheckpointError::OlderRoot { slot: F, newest: 152 })
        ));
        assert_eq!(rig.state.calls(STATE_88), 1);
        assert_eq!(rig.answers.store().period(), 2);
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(152).header());

        let old = rig.answers.archive().lock().await.update(1).unwrap().clone();
        assert!(matches!(
            rig.answers.accept_update(&old, NOW).await,
            Err(AcceptError::SelfCheck(SelfCheckError::Refused(
                SyncCommitteeError::SignaturePeriod { signature_period: 1, store_period: 2, .. }
            )))
        ));
        assert_eq!(rig.answers.store().period(), 2);
        assert!(!rig.answers.publish_finality(old));
        assert_eq!(rig.answers.finality_update().unwrap().attested_header, *chain.at(152).header());
    }

    /// F after the wall-clock slot cannot be finalized. It is dropped before its state, and it
    /// does not become the newest checkpoint, which would drop every real root after it.
    #[tokio::test]
    async fn a_root_after_the_wall_clock_is_dropped() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(F));
        let mut task = task(&rig);
        assert!(matches!(
            task.step(F - 1).await,
            Err(CheckpointError::FutureRoot { slot: F, current }) if current == F - 1
        ));
        assert_eq!(rig.state.calls(STATE_88), 0);
        assert_eq!(task.newest, None);
        assert!(!stored_bootstrap(&rig, chain.root(F)).await);
    }

    /// The self-check store starts at the trust root, so an optimistic update of the root's
    /// period is checked and served before the first checkpoint.
    #[tokio::test]
    async fn an_optimistic_update_is_checked_from_the_trust_root_before_any_checkpoint() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        assert!(head.on_head(chain.root(91), NOW).await.unwrap());
        assert_eq!(
            rig.answers.optimistic_update().unwrap().attested_header,
            *chain.at(90).header()
        );
    }

    #[tokio::test]
    async fn a_failed_finalized_root_is_retried() {
        let chain = chain_with(89..92);
        let rig = Rig::start(&chain).await;
        let mut task = task(&rig);
        let err = task.step(NOW).await.unwrap_err();
        assert!(matches!(err, CheckpointError::FinalizedRoot(UpstreamError::Status(404))));
        assert!(err.is_retryable());
        rig.state.finalize(chain.root(F));
        assert_eq!(task.step(NOW).await.unwrap(), Some(chain.root(F)));
    }

    /// The real 369 bootstrap's period, at `epoch` epochs into it.
    fn slot_in_real_period(epoch: u64) -> u64 {
        let preset = Preset::PULSECHAIN;
        let period = preset.period_at_slot(Real369::load().header.slot);
        (period * preset.epochs_per_sync_committee_period() + epoch) * preset.slots_per_epoch()
    }

    /// A task of 369 whose self-check store is the real 369 bootstrap's. The archive is checked
    /// when `checked`.
    async fn task_369(datadir: &std::path::Path, checked: bool) -> CheckpointTask {
        let pins = pulsechain_network(369).unwrap().beacon;
        let archive = Archive::open(datadir, 369, Preset::PULSECHAIN, pins, None).await.unwrap();
        let real = Real369::load();
        let root = reth_pulsechain_light_client::sync_committee::test_utils::hash(
            &real.json["block_root"],
        );
        let store =
            LightClientStore::bootstrap(Preset::PULSECHAIN, pins, root, &real.bootstrap()).unwrap();
        let answers = Arc::new(Answers::new(Preset::PULSECHAIN, pins, archive, store));
        if checked {
            answers.check_archive(real.header.slot + 1).await.unwrap();
        }
        // The check makes no request.
        let unused = Upstream::new("http://127.0.0.1:9".parse().unwrap(), Timeouts::default());
        CheckpointTask::new(
            answers,
            unused.clone(),
            Beacons::new(Preset::PULSECHAIN, pins, vec![unused]),
        )
    }

    /// A period with no update logs an error once at 8 epochs, and not when it has one.
    #[tokio::test]
    async fn a_period_8_epochs_old_with_no_update_logs_an_error_once() {
        let datadir = tempfile::tempdir().unwrap();
        let mut task = task_369(datadir.path(), true).await;
        let logs = crate::fake::Logs::capture();

        assert!(!task.log_missing_update(slot_in_real_period(7)).await);
        assert_eq!(logs.text(), "");
        assert!(task.log_missing_update(slot_in_real_period(8)).await);
        let text = logs.text();
        assert!(text.contains("ERROR"), "{text}");
        assert!(text.contains("no update for the current sync-committee period"), "{text}");
        assert!(!task.log_missing_update(slot_in_real_period(9)).await);
        assert_eq!(logs.text(), text);
        // The next period logs again.
        assert!(task.log_missing_update(slot_in_real_period(256 + 8)).await);

        let datadir = tempfile::tempdir().unwrap();
        let mut task = task_369(datadir.path(), true).await;
        let real = Real369::load();
        let header = real.light_client_header();
        let update = LightClientUpdate {
            attested_header: header.clone(),
            next_sync_committee: real.committee.clone(),
            next_sync_committee_branch: real.branch("current_sync_committee_branch"),
            finalized_header: header,
            finality_branch: vec![B256::repeat_byte(1); 6],
            sync_aggregate: real.aggregate,
            signature_slot: real.header.slot + 1,
        };
        assert!(task.answers.archive().lock().await.save_update(update).await.unwrap());
        assert!(!task.log_missing_update(slot_in_real_period(8)).await);
    }

    /// After a restart the stored updates wait for the self-check store, so the check does not
    /// run: it would miss the stored update of the period and then stay quiet for that period.
    #[tokio::test]
    async fn a_restart_logs_no_missing_update_until_the_archive_is_checked() {
        let datadir = tempfile::tempdir().unwrap();
        let task = task_369(datadir.path(), false).await;
        let real = Real369::load();
        let header = real.light_client_header();
        let update = LightClientUpdate {
            attested_header: header.clone(),
            next_sync_committee: real.committee.clone(),
            next_sync_committee_branch: real.branch("current_sync_committee_branch"),
            finalized_header: header,
            finality_branch: vec![B256::repeat_byte(1); 6],
            sync_aggregate: real.aggregate,
            signature_slot: real.header.slot + 1,
        };
        assert!(task.answers.archive().lock().await.save_update(update).await.unwrap());
        drop(task);

        let mut task = task_369(datadir.path(), false).await;
        assert!(!task.answers.archive().lock().await.is_verified());
        assert!(!task.log_missing_update(slot_in_real_period(8)).await);
        assert_eq!(task.missing_logged, None);
    }
}
