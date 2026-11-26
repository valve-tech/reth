//! The head task: the optimistic update at each new head.
//!
//! It learns heads from each beacon URL's head events and polls each beacon URL's
//! `headers/head` every slot, as reth-lite does. For a new head H it fetches H by root and takes
//! its parent P from the blocks it read last, which usually hold P as the previous head. The
//! committee's signature in H covers P, so the update proves P, one slot behind the beacon head.

use crate::{
    answers::{Answers, SelfCheckError},
    current_slot,
    upstream::{Beacons, FetchError, Upstream},
};
use alloy_primitives::B256;
use reth_pulsechain_forks::network::PulsechainBeacon;
use reth_pulsechain_light_client::derive::{optimistic_update, DeriveError, LightClientBlock};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use tracing::{debug, warn};

/// The most recent blocks kept, by root, to find a head's parent without a request.
pub const RECENT_BLOCKS: usize = 64;
/// The most head events queued from the event streams.
const HEAD_QUEUE: usize = 64;
/// An event stream that sends nothing for this many polls ends, and the task opens it again.
const EVENT_IDLE_POLLS: u32 = 4;
/// The most head events that one stream may send in a poll, a slot. An honest stream sends about
/// one, and a few in a reorg. Each new head costs a block request to every beacon URL, so a
/// stream that sends more ends, and opens again after the poll.
pub const MAX_STREAM_HEADS: usize = 4;
/// The least time between two tries of a head refused for a cause that may pass. A head is the
/// head for one slot, so the limit is by time and not by slot.
pub const HEAD_RETRY_GAP: Duration = Duration::from_secs(1);
/// The most tries of the newest head refused for a cause that may pass, before a beacon URL
/// reports it again. The task makes the tries after the first on its own, [`HEAD_RETRY_GAP`]
/// apart.
pub const HEAD_TRIES: u32 = 4;

/// Why a head gave no optimistic update.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeadError {
    /// A block was not read.
    #[error("block {root}: {source}")]
    Block {
        /// The block root.
        root: B256,
        /// What went wrong.
        source: FetchError,
    },
    /// No beacon URL has the block.
    #[error("no beacon URL has block {0}")]
    MissingBlock(B256),
    /// The blocks do not give the update.
    #[error(transparent)]
    Derive(#[from] DeriveError),
    /// The self-check store did not accept the update.
    #[error(transparent)]
    SelfCheck(#[from] SelfCheckError),
}

impl HeadError {
    /// Returns whether the same blocks give the error again: blocks that hash to their roots
    /// but do not give an update. Another cause may pass, as when a block reaches the beacon
    /// URLs or the self-check store moves on. A block that does not read may pass too: one
    /// beacon URL's bytes, not the block, may be at fault.
    pub const fn is_lasting(&self) -> bool {
        matches!(self, Self::Derive(_))
    }
}

/// The head task of one chain.
#[derive(Debug)]
pub struct HeadTask {
    answers: Arc<Answers>,
    beacons: Beacons,
    /// The last [`RECENT_BLOCKS`] blocks read, newest last, with their roots.
    recent: VecDeque<(B256, LightClientBlock)>,
    /// The last [`RECENT_BLOCKS`] heads whose update the self-check store accepted.
    handled: VecDeque<B256>,
    /// The last [`RECENT_BLOCKS`] heads refused, newest last.
    refused: VecDeque<Refusal>,
    /// The last failure, logged once until a head succeeds.
    last_failure: Option<HeadError>,
}

impl HeadTask {
    /// A task that builds `answers` from the heads of `beacons`.
    pub const fn new(answers: Arc<Answers>, beacons: Beacons) -> Self {
        Self {
            answers,
            beacons,
            recent: VecDeque::new(),
            handled: VecDeque::new(),
            refused: VecDeque::new(),
            last_failure: None,
        }
    }

    /// Follows the heads: each beacon URL's head events, and a poll of the head every `poll`.
    /// It ends only when the caller aborts it, which also stops the event streams.
    pub async fn run(mut self, poll: Duration) {
        let (heads, mut events) = mpsc::channel(HEAD_QUEUE);
        let mut streams = JoinSet::new();
        for upstream in self.beacons.upstreams() {
            let pins = *self.beacons.pins();
            streams.spawn(follow_events(upstream.clone(), pins, poll, heads.clone()));
        }
        let mut tick = tokio::time::interval(poll);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let retry = self.next_retry();
            let at = retry.map_or_else(Instant::now, |(_, at)| at);
            let roots = tokio::select! {
                Some(root) = events.recv() => vec![root],
                _ = tick.tick() => self.beacons.head_roots().await,
                () = tokio::time::sleep_until(at), if retry.is_some() => {
                    retry.into_iter().map(|(root, _)| root).collect()
                }
            };
            for root in roots {
                let slot = current_slot(self.answers.pins(), SystemTime::now());
                match self.on_head(root, slot).await {
                    Ok(_) => self.last_failure = None,
                    Err(err) => self.log(err),
                }
            }
        }
    }

    /// Logs `err` once until a head succeeds.
    fn log(&mut self, err: HeadError) {
        if self.last_failure.as_ref() == Some(&err) {
            debug!(target: "lc_server::head", %err, "no optimistic update");
        } else {
            warn!(target: "lc_server::head", %err, "no optimistic update");
        }
        self.last_failure = Some(err);
    }

    /// Returns the newest refused head that the task tries again on its own, and when: one
    /// refused for a cause that may pass, with fewer than [`HEAD_TRIES`] tries.
    fn next_retry(&self) -> Option<(B256, Instant)> {
        self.refused
            .back()
            .filter(|refusal| !refusal.err.is_lasting() && refusal.tries < HEAD_TRIES)
            .map(|refusal| (refusal.root, refusal.tried + HEAD_RETRY_GAP))
    }

    /// Handles head `root` at wall-clock slot `current_slot`. Returns whether it served a new
    /// optimistic update. A head whose update the store accepted before is skipped. A head
    /// refused before gives the same error again without a try, for good when
    /// [`HeadError::is_lasting`], else for [`HEAD_RETRY_GAP`]; then it is handled again from
    /// the blocks it read.
    pub async fn on_head(&mut self, root: B256, current_slot: u64) -> Result<bool, HeadError> {
        if self.handled.contains(&root) {
            return Ok(false)
        }
        let mut tries = 1;
        if let Some(at) = self.refused.iter().position(|refusal| refusal.root == root) {
            let refusal = &self.refused[at];
            if refusal.err.is_lasting() || refusal.tried.elapsed() < HEAD_RETRY_GAP {
                return Err(refusal.err.clone())
            }
            tries += refusal.tries;
            self.refused.remove(at);
        }
        match self.update_at(root, current_slot).await {
            Ok(newer) => {
                if self.handled.len() == RECENT_BLOCKS {
                    self.handled.pop_front();
                }
                self.handled.push_back(root);
                Ok(newer)
            }
            Err(err) => {
                if self.refused.len() == RECENT_BLOCKS {
                    self.refused.pop_front();
                }
                self.refused.push_back(Refusal {
                    root,
                    err: err.clone(),
                    tried: Instant::now(),
                    tries,
                });
                Err(err)
            }
        }
    }

    /// Builds the optimistic update of head `root` and applies it.
    async fn update_at(&mut self, root: B256, current_slot: u64) -> Result<bool, HeadError> {
        let h = self.block(root).await?;
        let p = self.block(h.header().beacon.parent_root).await?;
        let update = optimistic_update(self.answers.preset(), &p, &h)?;
        Ok(self.answers.accept_optimistic(update, current_slot)?)
    }

    /// Returns the block with `root` from the recent blocks, or fetches it and keeps it there.
    async fn block(&mut self, root: B256) -> Result<LightClientBlock, HeadError> {
        if let Some((_, block)) = self.recent.iter().find(|(cached, _)| *cached == root) {
            return Ok(block.clone())
        }
        let block = self.fetch(root).await?;
        if self.recent.len() == RECENT_BLOCKS {
            self.recent.pop_front();
        }
        self.recent.push_back((root, block.clone()));
        Ok(block)
    }

    async fn fetch(&self, root: B256) -> Result<LightClientBlock, HeadError> {
        self.beacons
            .block_by_root(root)
            .await
            .map_err(|source| HeadError::Block { root, source })?
            .ok_or(HeadError::MissingBlock(root))
    }
}

/// A refused head.
#[derive(Debug)]
struct Refusal {
    root: B256,
    err: HeadError,
    /// When the last try ended.
    tried: Instant,
    /// The tries so far.
    tries: u32,
}

/// Sends the head of each head event of `upstream` to `heads`, and opens the stream again
/// `retry` after it ends. A stream that sends more than [`MAX_STREAM_HEADS`] heads in `retry`
/// ends. It opens no stream while the genesis does not match `pins`. It ends when `heads`
/// closes.
async fn follow_events(
    upstream: Upstream,
    pins: PulsechainBeacon,
    retry: Duration,
    heads: mpsc::Sender<B256>,
) {
    loop {
        if !upstream.genesis_matches(&pins).await {
            tokio::time::sleep(retry).await;
            continue
        }
        match upstream.head_events(retry * EVENT_IDLE_POLLS).await {
            Ok(mut events) => {
                let (mut window, mut sent) = (Instant::now(), 0);
                while let Some(root) = events.next_head().await {
                    if window.elapsed() >= retry {
                        (window, sent) = (Instant::now(), 0);
                    }
                    sent += 1;
                    if sent > MAX_STREAM_HEADS {
                        warn!(target: "lc_server::head", host = upstream.host(), max = MAX_STREAM_HEADS, "the head event stream sends more heads than the chain makes; ending it");
                        break
                    }
                    if heads.send(root).await.is_err() {
                        return
                    }
                }
                debug!(target: "lc_server::head", host = upstream.host(), "the head event stream ended");
            }
            Err(err) => {
                debug!(target: "lc_server::head", host = upstream.host(), %err, "no head event stream");
            }
        }
        tokio::time::sleep(retry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checkpoint::CheckpointTask,
        fake::{Answer, Rig, TestChain, NOW},
    };
    use reth_pulsechain_light_client::sync_committee::SyncCommitteeError;

    /// A rig whose server has built the checkpoint at 88, with blocks up to `last`.
    async fn rig_after_checkpoint(last: u64) -> (TestChain, Rig) {
        let mut chain = TestChain::new();
        chain.extend(64..88);
        chain.checkpoint(88, 72);
        chain.extend(89..=last);
        let rig = Rig::start(&chain).await;
        rig.state.finalize(chain.root(88));
        let mut task =
            CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), rig.beacons());
        task.step(NOW).await.unwrap();
        (chain, rig)
    }

    fn block_path(root: B256) -> String {
        format!("/eth/v2/beacon/blocks/{root}")
    }

    /// Moves each refusal's last try back by [`HEAD_RETRY_GAP`], as if the gap had passed.
    fn age(head: &mut HeadTask) {
        for refusal in &mut head.refused {
            refusal.tried -= HEAD_RETRY_GAP;
        }
    }

    /// Each head's parent is the previous head, so only the first head fetches its parent. A
    /// head read before is skipped.
    #[tokio::test]
    async fn the_parent_comes_from_the_previous_head() {
        let (chain, rig) = rig_after_checkpoint(95).await;
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        for slot in 92..=95 {
            assert!(head.on_head(chain.root(slot), NOW).await.unwrap());
            let update = rig.answers.optimistic_update().unwrap();
            assert_eq!(update.attested_header, *chain.at(slot - 1).header());
            assert_eq!(update.signature_slot, slot);
        }
        assert_eq!(rig.beacon.calls(&block_path(chain.root(91))), 1);
        for slot in 92..95 {
            assert_eq!(rig.beacon.calls(&block_path(chain.root(slot))), 1);
        }
        assert!(!head.on_head(chain.root(95), NOW).await.unwrap());
        assert_eq!(rig.beacon.calls(&block_path(chain.root(95))), 1);
    }

    /// An older head after a newer one passes the store but does not replace the served update.
    #[tokio::test]
    async fn an_older_head_does_not_replace_a_newer_update() {
        let (chain, rig) = rig_after_checkpoint(95).await;
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        assert!(head.on_head(chain.root(95), NOW).await.unwrap());
        assert!(!head.on_head(chain.root(93), NOW).await.unwrap());
        assert_eq!(rig.answers.optimistic_update().unwrap().signature_slot, 95);
    }

    #[tokio::test]
    async fn a_head_with_low_participation_gives_no_update() {
        let (mut chain, rig) = rig_after_checkpoint(92).await;
        chain.push(93, chain.root(92), 21, B256::repeat_byte(2));
        rig.beacon.serve_blocks(&chain);
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        assert_eq!(
            head.on_head(chain.root(93), NOW).await,
            Err(HeadError::Derive(DeriveError::TooFewParticipants { participants: 21, size: 32 }))
        );
        assert_eq!(rig.answers.optimistic_update(), None);
    }

    #[tokio::test]
    async fn an_unknown_head_is_a_missing_block() {
        let (_chain, rig) = rig_after_checkpoint(92).await;
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        let unknown = B256::repeat_byte(9);
        assert_eq!(head.on_head(unknown, NOW).await, Err(HeadError::MissingBlock(unknown)));
    }

    async fn wait_for_update(rig: &Rig, signature_slot: u64) {
        let mut updates = rig.answers.subscribe_optimistic();
        tokio::time::timeout(
            Duration::from_secs(5),
            updates.wait_for(|update| {
                update.as_ref().is_some_and(|update| update.signature_slot == signature_slot)
            }),
        )
        .await
        .expect("the optimistic update comes")
        .unwrap();
    }

    /// The task follows head events, with no poll in between.
    #[tokio::test]
    async fn the_task_follows_head_events() {
        let (chain, rig) = rig_after_checkpoint(95).await;
        rig.beacon.enable_events();
        let task = tokio::spawn(
            HeadTask::new(rig.answers.clone(), rig.beacons()).run(Duration::from_secs(3600)),
        );
        // A stream gets only the events sent after it opened.
        while rig.beacon.calls("/eth/v1/events") == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        rig.beacon.set_head(chain.root(94));
        wait_for_update(&rig, 94).await;
        rig.beacon.set_head(chain.root(95));
        wait_for_update(&rig, 95).await;
        assert_eq!(rig.beacon.calls("/eth/v1/beacon/headers/head"), 1);
        task.abort();
    }

    /// A head event that comes before any beacon URL serves the block, as from a URL that
    /// relays gossip early, refuses the head. No URL reports it again, but the task tries the
    /// newest such head again on its own, so the update comes once the block does.
    #[tokio::test]
    async fn a_head_refused_before_its_block_is_served_is_tried_again_unreported() {
        let (mut chain, rig) = rig_after_checkpoint(94).await;
        chain.extend([95]);
        let root = chain.root(95);
        rig.beacon.enable_events();
        let task = tokio::spawn(
            HeadTask::new(rig.answers.clone(), rig.beacons()).run(Duration::from_secs(3600)),
        );
        while rig.beacon.calls("/eth/v1/events") == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        rig.beacon.set_head(root);
        while rig.beacon.calls(&block_path(root)) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        rig.beacon.serve_blocks(&chain);
        wait_for_update(&rig, 95).await;
        task.abort();
    }

    /// An event stream that sends more heads in one poll than an honest one ends: its heads
    /// would each cost a block request to every beacon URL. The stream opens again after the
    /// poll.
    #[tokio::test]
    async fn an_event_stream_that_sends_too_many_heads_ends() {
        let (chain, rig) = rig_after_checkpoint(89).await;
        rig.beacon.enable_events();
        let (heads, mut events) = mpsc::channel(HEAD_QUEUE);
        let poll = Duration::from_millis(500);
        let stream = tokio::spawn(follow_events(rig.beacon.upstream(), chain.pins, poll, heads));
        while rig.beacon.calls("/eth/v1/events") == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for byte in 0..10 {
            rig.beacon.set_head(B256::repeat_byte(byte));
        }
        let mut got = Vec::new();
        while let Ok(Some(root)) =
            tokio::time::timeout(Duration::from_millis(200), events.recv()).await
        {
            got.push(root);
        }
        assert_eq!(got, (0..MAX_STREAM_HEADS as u8).map(B256::repeat_byte).collect::<Vec<_>>());
        assert_eq!(rig.beacon.calls("/eth/v1/events"), 1);
        tokio::time::sleep(poll * 2).await;
        assert_eq!(rig.beacon.calls("/eth/v1/events"), 2);
        stream.abort();
    }

    /// A head that the store refused for a passing reason, here a head of period 2 before the
    /// store knows period 2's committee, is handled again when a beacon URL reports it again,
    /// from the blocks read the first time.
    #[tokio::test]
    async fn a_head_refused_for_a_passing_reason_is_tried_again() {
        let mut chain = TestChain::new();
        chain.extend(64..88);
        chain.checkpoint(88, 72);
        chain.extend(89..131);
        let rig = Rig::start(&chain).await;
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        assert_eq!(
            head.on_head(chain.root(130), NOW).await,
            Err(HeadError::SelfCheck(SelfCheckError::Refused(
                SyncCommitteeError::SignaturePeriod {
                    signature_period: 2,
                    store_period: 1,
                    next_known: false
                }
            )))
        );
        rig.state.finalize(chain.root(88));
        CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), rig.beacons())
            .step(NOW)
            .await
            .unwrap();
        age(&mut head);
        assert!(head.on_head(chain.root(130), NOW).await.unwrap());
        assert_eq!(rig.beacon.calls(&block_path(chain.root(130))), 1);
        assert!(!head.on_head(chain.root(130), NOW).await.unwrap());
    }

    /// A head refused for a cause that may pass is tried at most once a [`HEAD_RETRY_GAP`].
    /// The task tries the newest one again on its own until it has had [`HEAD_TRIES`], and it
    /// keeps at most [`RECENT_BLOCKS`] refused heads.
    #[tokio::test]
    async fn a_passing_refusal_is_tried_at_most_once_a_gap() {
        let (_chain, rig) = rig_after_checkpoint(92).await;
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        let unknown = B256::repeat_byte(9);
        for aged in [false, false, true, false] {
            if aged {
                age(&mut head);
            }
            assert_eq!(head.on_head(unknown, NOW).await, Err(HeadError::MissingBlock(unknown)));
        }
        assert_eq!(rig.beacon.calls(&block_path(unknown)), 2);
        let tried = head.refused[0].tried;
        assert_eq!(head.next_retry(), Some((unknown, tried + HEAD_RETRY_GAP)));
        for _ in 2..HEAD_TRIES {
            age(&mut head);
            assert!(head.on_head(unknown, NOW).await.is_err());
        }
        assert_eq!(head.refused[0].tries, HEAD_TRIES);
        assert_eq!(head.next_retry(), None);
        for byte in 0..=RECENT_BLOCKS as u8 {
            let root = B256::repeat_byte(byte);
            assert_eq!(head.on_head(root, NOW).await, Err(HeadError::MissingBlock(root)));
        }
        assert_eq!(head.refused.len(), RECENT_BLOCKS);
    }

    /// A block that one beacon URL answers with bytes that do not read is a passing refusal: the
    /// head is tried again after the gap, and a URL that has the block then gives it.
    #[tokio::test]
    async fn a_block_that_does_not_read_is_tried_again_after_the_gap() {
        let (chain, rig) = rig_after_checkpoint(95).await;
        let root = chain.root(95);
        rig.beacon.answer(&block_path(root), Answer::ssz(vec![0; 8]));
        let late = crate::fake::Fake::start(&chain.pins).await;
        let beacons = Beacons::new(
            crate::fake::PRESET,
            chain.pins,
            vec![rig.beacon.upstream(), late.upstream()],
        );
        let mut head = HeadTask::new(rig.answers.clone(), beacons);
        let refused = head.on_head(root, NOW).await;
        assert!(
            matches!(refused, Err(HeadError::Block { source: FetchError::Derive(_), .. })),
            "{refused:?}"
        );
        late.serve_blocks(&chain);
        assert_eq!(head.on_head(root, NOW).await, refused);
        assert_eq!(late.calls(&block_path(root)), 1);
        age(&mut head);
        assert!(head.on_head(root, NOW).await.unwrap());
        assert_eq!(late.calls(&block_path(root)), 2);
        assert_eq!(rig.answers.optimistic_update().unwrap().signature_slot, 95);
    }

    /// A head refused for a cause that the same blocks give again, here too few signers in
    /// blocks that hash to their roots, is not tried again.
    #[tokio::test]
    async fn a_lasting_refusal_is_not_tried_again() {
        let (mut chain, rig) = rig_after_checkpoint(92).await;
        chain.push(93, chain.root(92), 21, B256::repeat_byte(2));
        rig.beacon.serve_blocks(&chain);
        let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
        let refused = head.on_head(chain.root(93), NOW).await;
        assert!(matches!(refused, Err(HeadError::Derive(_))), "{refused:?}");
        for slot in [NOW, NOW + 1, NOW + 40] {
            age(&mut head);
            assert_eq!(head.on_head(chain.root(93), slot).await, refused);
        }
        assert_eq!(head.refused.len(), 1);
        assert_eq!(head.refused[0].tries, 1);
        assert_eq!(head.next_retry(), None);
    }

    /// Without head events, the task polls each beacon URL's head: a URL that lags does not
    /// hide the head of the next one.
    #[tokio::test]
    async fn the_task_polls_every_beacon_url_head() {
        let (chain, rig) = rig_after_checkpoint(95).await;
        let ahead = crate::fake::Fake::start(&chain.pins).await;
        ahead.serve_blocks(&chain);
        rig.beacon.set_head(chain.root(94));
        ahead.set_head(chain.root(95));
        let beacons = Beacons::new(
            crate::fake::PRESET,
            chain.pins,
            vec![rig.beacon.upstream(), ahead.upstream()],
        );
        let task = tokio::spawn(
            HeadTask::new(rig.answers.clone(), beacons).run(Duration::from_millis(50)),
        );
        wait_for_update(&rig, 95).await;
        task.abort();
    }

    /// Without head events, the task polls the head.
    #[tokio::test]
    async fn the_task_polls_the_head_without_events() {
        let (chain, rig) = rig_after_checkpoint(95).await;
        let task = tokio::spawn(
            HeadTask::new(rig.answers.clone(), rig.beacons()).run(Duration::from_millis(50)),
        );
        rig.beacon.set_head(chain.root(94));
        wait_for_update(&rig, 94).await;
        rig.beacon.set_head(chain.root(95));
        wait_for_update(&rig, 95).await;
        assert!(rig.beacon.calls("/eth/v1/events") >= 1);
        task.abort();
    }
}
