//! Shared in-memory msgboard state.
//!
//! [`MsgBoard`] is the central actor. It is `Arc`-shared between the P2P
//! protocol handler (which may run one connection task per peer) and the
//! JSON-RPC handler. A `parking_lot::Mutex` guards the mutable state for
//! low-contention synchronous access; a `tokio::sync::broadcast` channel
//! fans new-message notifications out to all active peer connection tasks.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Instant, SystemTime},
};

use alloy_primitives::B256;
use parking_lot::Mutex;
use reth_libmdbx::Environment;
use tokio::sync::broadcast;

use reth_msgboard_types::{
    CheckedPoWMsg, MsgID, MsgboardConfig, MsgboardError, PoWMsg, VERSION_V1,
};

use crate::{block_filter::BlockFilter, db, index::MsgIndex, metrics::MsgboardMetrics};

/// Capacity of the broadcast channel for new-message notifications.
///
/// If a receiver falls more than this many messages behind it receives
/// `RecvError::Lagged` and should re-sync by announcing all current IDs.
///
/// Sized to 1024 to match the gRPC subscriber buffer in erigon-pulse's
/// `msgboard_grpc_server.go`. A smaller buffer (the previous 64) caused
/// every brief peer-task slowdown to trigger a full-board re-announce
/// storm under sustained ingest, which degenerates with peer count.
const BROADCAST_CAPACITY: usize = 1024;

#[derive(Debug)]
struct BoardState {
    index: MsgIndex,
    block_filter: BlockFilter,
    /// Messages evicted from the index (pending DB deletion or metrics).
    discarded: Vec<Arc<CheckedPoWMsg>>,
}

/// Shared in-memory msgboard.
///
/// All public methods are safe to call from any thread. The internal state is
/// protected by a `Mutex`; `PoW` verification happens *outside* the lock.
#[derive(Debug)]
pub struct MsgBoard {
    cfg: MsgboardConfig,
    state: Mutex<BoardState>,
    /// Broadcasts newly accepted messages to all active peer connection tasks.
    new_msg_tx: broadcast::Sender<Arc<CheckedPoWMsg>>,
    /// Optional MDBX environment for persistent storage.
    db: Option<Environment>,
    /// Whether the node has finished initial sync and the board is accepting
    /// messages. Starts `false`; flips to `true` exactly once when the caller
    /// signals sync completion via [`MsgBoard::set_ready`].
    ready: AtomicBool,
    /// Prometheus metrics. Cloned out of the struct via `metrics()` for
    /// outside-the-lock observation (e.g. by the protocol handler).
    metrics: MsgboardMetrics,
}

impl MsgBoard {
    /// Create a new board with the given configuration (in-memory only).
    pub fn new(cfg: MsgboardConfig) -> Self {
        let (new_msg_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        let state = BoardState {
            index: MsgIndex::default(),
            block_filter: BlockFilter::new(cfg.block_range),
            discarded: Vec::new(),
        };
        Self {
            cfg,
            state: Mutex::new(state),
            new_msg_tx,
            db: None,
            ready: AtomicBool::new(false),
            metrics: MsgboardMetrics::default(),
        }
    }

    /// Create a board backed by an MDBX database for persistence.
    pub fn with_db(cfg: MsgboardConfig, db: Environment) -> Self {
        let (new_msg_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        let state = BoardState {
            index: MsgIndex::default(),
            block_filter: BlockFilter::new(cfg.block_range),
            discarded: Vec::new(),
        };
        Self {
            cfg,
            state: Mutex::new(state),
            new_msg_tx,
            db: Some(db),
            ready: AtomicBool::new(false),
            metrics: MsgboardMetrics::default(),
        }
    }

    /// Returns a clone of the metrics handle so callers (e.g. protocol handler)
    /// can record send-side timings.
    pub fn metrics(&self) -> MsgboardMetrics {
        self.metrics.clone()
    }

    /// Whether the board is accepting messages (node has finished initial sync).
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Signal that the node has finished initial sync. Logs the state change
    /// exactly once. Subsequent calls are no-ops.
    pub fn set_ready(&self) {
        if !self.ready.swap(true, Ordering::Relaxed) {
            tracing::info!(target: "msgboard", "node synced — msgboard is now accepting messages");
        }
    }

    /// Load persisted messages from the database into the index.
    ///
    /// Should be called once after construction and before the board starts
    /// accepting new messages.
    ///
    /// Re-applies the current config's `size_limit` / `is_work_acceptable`
    /// checks (mirrors `loadAndRepairDbLocked` in erigon-pulse), so messages
    /// that were valid under an older config but no longer satisfy a tightened
    /// one are pushed onto `discarded` for the next flush to delete from disk.
    /// Duplicate hashes already present in the index follow the same path.
    pub fn load_from_db(&self) -> eyre::Result<u64> {
        let Some(ref env) = self.db else { return Ok(0) };
        let (msgs, bad) = db::db_load_all(env)?;
        if bad > 0 {
            tracing::warn!(target: "msgboard", bad, "skipped invalid messages during DB load");
        }

        let mut loaded = 0u64;
        let mut dropped_invalid = 0u64;
        let mut dropped_duplicate = 0u64;
        for msg in msgs {
            let arc = Arc::new(msg);
            // Reject rows that no longer satisfy the live config. They land in
            // `discarded` so the next flush deletes them from MDBX.
            let valid = self.cfg.is_size_acceptable(arc.msg.data.len()) &&
                self.cfg.is_work_acceptable(arc.msg.work_multiplier, arc.msg.work_divisor);
            if !valid {
                let mut state = self.state.lock();
                state.discarded.push(arc);
                dropped_invalid += 1;
                continue;
            }

            let mut state = self.state.lock();
            if state.index.insert(Arc::clone(&arc)) {
                loaded += 1;
            } else {
                // Duplicate hash on disk — schedule for deletion to keep the
                // table clean across restarts.
                state.discarded.push(arc);
                dropped_duplicate += 1;
            }
            // Don't broadcast loaded messages — peers will learn about them
            // via the initial ID announcement on connect.
        }

        self.record_index_gauges();
        tracing::debug!(
            target: "msgboard",
            loaded,
            dropped_invalid,
            dropped_duplicate,
            "loaded messages from DB",
        );
        Ok(loaded)
    }

    /// Flush pending changes to the database.
    ///
    /// Writes all current messages and deletes discarded ones. Returns the
    /// number of bytes written.
    pub fn flush_to_db(&self) -> eyre::Result<u64> {
        let Some(ref env) = self.db else { return Ok(0) };

        let start = Instant::now();
        let discarded = self.take_discarded();
        let discarded_hashes: Vec<B256> = discarded.iter().map(|m| m.hash).collect();

        let current: Vec<CheckedPoWMsg> = {
            let state = self.state.lock();
            state.index.all_msgs().iter().map(|m| (**m).clone()).collect()
        };

        let bytes = db::db_flush(env, &current, &discarded_hashes)?;

        self.metrics.write_to_db_duration_seconds.record(start.elapsed().as_secs_f64());
        self.metrics.write_to_db_bytes.set(bytes as f64);

        tracing::debug!(
            target: "msgboard",
            written = current.len(),
            deleted = discarded_hashes.len(),
            bytes,
            "flushed messages to DB"
        );

        Ok(bytes)
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &MsgboardConfig {
        &self.cfg
    }

    /// Advance the chain head. Messages anchored outside the new window are pruned.
    pub fn set_head(&self, height: u64, hash: B256) {
        let start = Instant::now();
        let (count, total_size) = {
            let mut state = self.state.lock();
            state.block_filter.set_head(height, hash);
            let lower = state.block_filter.lower();

            // Collect stale hashes first to avoid borrowing issues.
            let stale: Vec<B256> = state
                .index
                .all_msgs()
                .iter()
                .filter(|m| m.block_number < lower)
                .map(|m| m.hash)
                .collect();

            let mut expired = 0u64;
            for hash in stale {
                if let Some(evicted) = state.index.remove(&hash) {
                    state.discarded.push(evicted);
                    expired += 1;
                }
            }
            self.metrics.expired.increment(expired);
            (state.index.len(), state.index.total_size())
        };

        self.metrics.msg_count.set(count as f64);
        self.metrics.msg_size.set(total_size as f64);
        self.metrics.change_block_duration_seconds.record(start.elapsed().as_secs_f64());
    }

    /// Filter a slice of peer-announced [`MsgID`]s, returning the subset we want to fetch.
    ///
    /// An ID is wanted if we don't already have it, it passes the configured
    /// size and work limits, and the block is not within the stale buffer zone.
    pub fn filter_wanted(&self, ids: &[MsgID]) -> Vec<MsgID> {
        let state = self.state.lock();
        let stale_lower = state.block_filter.lower() + self.cfg.stale_block_buffer;
        ids.iter()
            .filter(|id| {
                // Mirrors erigon's `FilterMessageIDs`: drop announcements with a
                // version we don't speak before requesting the body, instead of
                // wasting an RTT and rejecting at decode time.
                if id.version() != VERSION_V1 {
                    return false;
                }
                if state.index.has(&id.message_hash()) {
                    return false;
                }
                if !self.cfg.is_size_acceptable(id.size() as usize) {
                    return false;
                }
                if !self.cfg.is_work_acceptable(id.work_multiplier(), id.work_divisor()) {
                    return false;
                }
                // Skip messages anchored to blocks about to expire.
                if let Some(block_num) = state.block_filter.block_number(&id.block_hash()) {
                    block_num >= stale_lower
                } else {
                    // Block hash not in our window — skip.
                    false
                }
            })
            .copied()
            .collect()
    }

    /// All current message IDs (for announcing to a newly connected peer).
    pub fn all_message_ids(&self) -> Vec<MsgID> {
        let state = self.state.lock();
        state.index.all_msgs().iter().map(|m| m.msg_id()).collect()
    }

    /// Fetch the raw `PoWMsg`s corresponding to the requested [`MsgID`]s.
    ///
    /// Used to respond to `GetBoardMessages` packets.
    pub fn get_messages_for_ids(&self, ids: &[MsgID]) -> Vec<PoWMsg> {
        let state = self.state.lock();
        ids.iter()
            .filter_map(|id| state.index.get(&id.message_hash()).map(|m| m.msg.clone()))
            .collect()
    }

    /// Add `PoWMsg`s received from a remote peer.
    ///
    /// Inputs **must** already be field-validated — wire-side messages are
    /// validated by [`reth_msgboard_types::decode_pow_msg_list`] (mirrors
    /// erigon's `DecodeRLPMsgList`) and RPC submissions don't reach this
    /// path. Mirrors erigon's `addMsgLocked` which assumes its caller has
    /// already run `Validate()`.
    ///
    /// For each message: applies the live config's size and work-ratio
    /// checks, looks up the block number from the live window, runs `PoW`
    /// verification, then inserts. Returns `(accepted, kickable)`:
    ///
    ///  - `accepted` — number of messages newly inserted into the board.
    ///  - `kickable` — number of messages rejected for *non-circumstantial* reasons (oversized
    ///    payload, undersized work, invalid PoW). Mirrors erigon-pulse `AddRemoteMsgs` returning a
    ///    non-nil error → caller sets `kickPeer=true`.
    ///
    /// Circumstantial rejections (`MessageExists`, `BoardOverflow`,
    /// `BlockTooOld`) do **not** contribute to `kickable`,
    /// matching `addMsgLocked`'s circumstantial branch (`board.go:269-271`).
    ///
    /// When [`MsgboardConfig::gossip_disabled`] is set, messages are dropped
    /// silently (mirrors erigon-pulse `AddRemoteMsgs` returning `nil` on
    /// `cfg.NoGossip`). Returns `(0, 0)` — read-only observers must not
    /// penalise peers for participating in gossip the operator opted out of.
    pub fn add_remote_msgs(&self, msgs: Vec<PoWMsg>) -> (usize, usize) {
        if self.cfg.gossip_disabled {
            return (0, 0);
        }
        if !self.is_ready() {
            return (0, 0);
        }
        let start = Instant::now();
        let timestamp = unix_timestamp();
        let mut added = 0;
        let mut kickable = 0;
        for msg in msgs {
            if !self.cfg.is_size_acceptable(msg.data.len()) {
                self.metrics.rejected_oversized.increment(1);
                kickable += 1;
                continue;
            }
            if !self.cfg.is_work_acceptable(msg.work_multiplier, msg.work_divisor) {
                self.metrics.rejected_insufficient_work.increment(1);
                kickable += 1;
                continue;
            }

            // Look up block number under a brief lock, then release before PoW.
            let block_number = {
                let state = self.state.lock();
                state.block_filter.block_number(&msg.block_hash)
            };
            // Unknown block — circumstantial (peer may be one block ahead),
            // mirrors erigon's `ErrMsgTooOld`/`ErrMsgFromTheFuture` branch.
            let Some(block_number) = block_number else {
                self.metrics.skipped_unknown_block.increment(1);
                continue
            };

            let checked = match msg.to_checked(block_number, timestamp) {
                Ok(checked) => checked,
                Err(err) => {
                    // Split by reason: `InvalidDifficulty` is the §14.1
                    // overflow, where reth and erigon genuinely disagree, and
                    // must not be lumped in with ordinary bad `PoW`.
                    match err {
                        MsgboardError::InvalidDifficulty => {
                            self.metrics.rejected_invalid_difficulty.increment(1)
                        }
                        MsgboardError::InvalidWork => {
                            self.metrics.rejected_invalid_pow.increment(1)
                        }
                        _ => self.metrics.rejected_other.increment(1),
                    }
                    kickable += 1;
                    continue;
                }
            };
            match self.insert_checked(checked) {
                Ok(_) => {
                    self.metrics.accepted_remote.increment(1);
                    added += 1
                }
                // Circumstantial: don't penalise.
                Err(MsgboardError::MessageExists) => self.metrics.skipped_duplicate.increment(1),
                Err(MsgboardError::BoardOverflow) => {
                    self.metrics.skipped_board_overflow.increment(1)
                }
                Err(MsgboardError::BlockTooOld) => self.metrics.skipped_block_too_old.increment(1),
                // Should not happen post-validation, but treat as kickable.
                Err(_) => {
                    self.metrics.rejected_other.increment(1);
                    kickable += 1
                }
            }
        }
        self.metrics.add_remote_msgs_duration_seconds.record(start.elapsed().as_secs_f64());
        (added, kickable)
    }

    /// Add a locally-submitted message (from the RPC handler).
    ///
    /// Inputs **must** already be field-validated — the JSON-RPC
    /// `msgboard_addMessage` handler runs
    /// [`reth_msgboard_types::decode_validated_pow_msg`] (mirrors erigon's
    /// `PoWMsgFromRLP`) before reaching this path. Mirrors erigon's
    /// `addMsgLocked`: validation lives at the decode boundary, not here.
    ///
    /// Returns the inserted message on success, or a specific error describing
    /// why the message was rejected.
    pub fn add_local_msg(&self, msg: PoWMsg) -> Result<Arc<CheckedPoWMsg>, MsgboardError> {
        if !self.is_ready() {
            return Err(MsgboardError::NotReady);
        }

        if !self.cfg.is_size_acceptable(msg.data.len()) {
            return Err(MsgboardError::MessageTooLarge);
        }
        if !self.cfg.is_work_acceptable(msg.work_multiplier, msg.work_divisor) {
            return Err(MsgboardError::WorkTooEasy);
        }

        let timestamp = unix_timestamp();
        let block_number = {
            let state = self.state.lock();
            state.block_filter.block_number(&msg.block_hash)
        };
        let block_number = block_number.ok_or(MsgboardError::BlockTooOld)?;

        let checked = msg.to_checked(block_number, timestamp)?;
        let inserted = self.insert_checked(checked)?;
        // Only the success path is counted here. Local submissions return the
        // specific error to the RPC caller, who sees the reason directly; the
        // per-reason counters exist for peer traffic, which has no such channel.
        self.metrics.accepted_local.increment(1);
        Ok(inserted)
    }

    /// Subscribe to new-message notifications.
    ///
    /// Each accepted message is broadcast to all subscribers. A subscriber that
    /// falls more than `BROADCAST_CAPACITY` messages behind receives
    /// `RecvError::Lagged` and should re-announce all current IDs.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CheckedPoWMsg>> {
        self.new_msg_tx.subscribe()
    }

    /// All messages in a specific category (for `msgboard_content` RPC).
    pub fn category_msgs(&self, category: &B256) -> Vec<Arc<CheckedPoWMsg>> {
        let state = self.state.lock();
        state.index.category_msgs(category).cloned().collect()
    }

    /// Messages in a category filtered by optional block range.
    pub fn category_msgs_filtered(
        &self,
        category: &B256,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<Arc<CheckedPoWMsg>> {
        let state = self.state.lock();
        state.index.category_msgs_filtered(category, from_block, to_block)
    }

    /// All messages filtered by optional block range (all categories).
    pub fn all_msgs_filtered(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Vec<Arc<CheckedPoWMsg>> {
        let state = self.state.lock();
        state.index.all_msgs_filtered(from_block, to_block)
    }

    /// All known category hashes, sorted ascending (for `msgboard_categories` RPC).
    ///
    /// `specs/02-msgboard.md` §9.2 specifies `msgboard_categories` returns a
    /// sorted list. The index stores categories in a `HashMap`, whose key
    /// iteration order is arbitrary and varies between runs, so the sort
    /// happens here.
    pub fn categories(&self) -> Vec<B256> {
        let state = self.state.lock();
        let mut cats: Vec<B256> = state.index.categories().copied().collect();
        drop(state);
        cats.sort_unstable();
        cats
    }

    /// Fetch a single message by its `PoW` hash (for `msgboard_getMessage` RPC).
    pub fn get_message(&self, hash: &B256) -> Option<Arc<CheckedPoWMsg>> {
        let state = self.state.lock();
        state.index.get(hash)
    }

    /// Returns `(head_block, count, total_size, work_multiplier, work_divisor)` for status.
    pub fn status(&self) -> (bool, u64, u64, u64, u64, u64) {
        let state = self.state.lock();
        (
            self.is_ready(),
            state.block_filter.head(),
            state.index.len() as u64,
            state.index.total_size(),
            self.cfg.work_multiplier,
            self.cfg.work_divisor,
        )
    }

    /// Drain discarded messages (for DB deletion during flush).
    pub fn take_discarded(&self) -> Vec<Arc<CheckedPoWMsg>> {
        let mut state = self.state.lock();
        std::mem::take(&mut state.discarded)
    }

    /// Snapshot of all currently indexed messages (for DB flush).
    pub fn all_messages(&self) -> Vec<Arc<CheckedPoWMsg>> {
        let state = self.state.lock();
        state.index.all_msgs().to_vec()
    }

    /// Snapshot the current `(count, total_size)` and emit them on the gauges.
    /// Cheap helper for the few mutation paths that don't already hold the
    /// lock at the moment of update (`load_from_db`).
    fn record_index_gauges(&self) {
        let (count, total_size) = {
            let state = self.state.lock();
            (state.index.len(), state.index.total_size())
        };
        self.metrics.msg_count.set(count as f64);
        self.metrics.msg_size.set(total_size as f64);
    }

    // ── internal ─────────────────────────────────────────────────────────────

    /// Insert a pre-verified `CheckedPoWMsg` into the index.
    ///
    /// Returns the `Arc<CheckedPoWMsg>` if newly inserted, or an error describing
    /// why insertion failed.
    ///
    /// If the board is already at `count_limit` and the new message is itself
    /// the lowest-precedence entry, it is evicted on the same call and
    /// `BoardOverflow` is returned — matching the spec at §5.3 and erigon's
    /// `addMsgLocked` behaviour. The caller therefore knows the message did
    /// not land on the board and the broadcast below is skipped.
    fn insert_checked(&self, msg: CheckedPoWMsg) -> Result<Arc<CheckedPoWMsg>, MsgboardError> {
        let arc = Arc::new(msg);
        let (count, total_size) = {
            let mut state = self.state.lock();

            // Reject if the block has aged out since we looked up the number.
            if state.block_filter.head() > 0 && !state.block_filter.within_bounds(arc.block_number)
            {
                return Err(MsgboardError::BlockTooOld);
            }

            if !state.index.insert(Arc::clone(&arc)) {
                return Err(MsgboardError::MessageExists);
            }

            // Evict oldest messages when the count limit is exceeded.
            // If our own newly-inserted message is the lowest-precedence entry
            // it gets evicted here — that's a board overflow and we report it
            // to the caller instead of broadcasting a message we don't hold.
            while state.index.len() > self.cfg.count_limit {
                let Some(evicted) = state.index.evict_oldest() else { break };
                if evicted.hash == arc.hash {
                    return Err(MsgboardError::BoardOverflow);
                }
                self.metrics.evicted.increment(1);
                state.discarded.push(evicted);
            }
            (state.index.len(), state.index.total_size())
        };

        self.metrics.msg_count.set(count as f64);
        self.metrics.msg_size.set(total_size as f64);

        // Broadcast outside the lock — receivers that are slow will get Lagged.
        let _ = self.new_msg_tx.send(Arc::clone(&arc));
        Ok(arc)
    }

    /// Spawn a background task that flushes the DB every `interval`.
    ///
    /// Returns a `JoinHandle` that can be used to cancel the task. The handle
    /// is `'static` so it outlives the calling scope.
    pub fn spawn_flush_task(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let board = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = board.flush_to_db() {
                    tracing::warn!(target: "msgboard", %e, "DB flush failed");
                }
            }
        })
    }

    /// Spawn a background task that emits a periodic stats line at INFO level.
    ///
    /// Mirrors erigon-pulse's `LogEvery` timer (default 30s). The line includes
    /// `ready`, `head`, `count`, `size`, and the configured min-difficulty pair.
    pub fn spawn_log_task(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let board = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let (ready, head, count, size, mult, div) = board.status();
                tracing::info!(
                    target: "msgboard",
                    ready,
                    head,
                    count,
                    size,
                    work_multiplier = mult,
                    work_divisor = div,
                    "msgboard stats",
                );
            }
        })
    }
}

/// Current Unix timestamp in seconds.
fn unix_timestamp() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{Bytes, B256};
    use reth_msgboard_types::{MsgboardConfig, PoWMsg, VERSION_V1};

    use super::*;

    // ── test helpers ─────────────────────────────────────────────────────────

    fn block_hash_one() -> B256 {
        let mut b = [0u8; 32];
        b[0] = 0x01;
        B256::from(b)
    }

    fn category_hash() -> B256 {
        let mut b = [0u8; 32];
        b[0] = 0xCA;
        B256::from(b)
    }

    /// Config with easy PoW so tests can mine valid messages quickly.
    fn easy_cfg() -> MsgboardConfig {
        MsgboardConfig {
            work_multiplier: 1,
            work_divisor: 1_000_000,
            size_limit: 8 * 1024,
            count_limit: 10_000,
            block_range: 120,
            stale_block_buffer: 3,
            gossip_disabled: false,
        }
    }

    fn make_pow_msg(nonce: u64, data: &[u8]) -> PoWMsg {
        PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: category_hash(),
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Brute-force mine a valid nonce for the given data.
    fn find_nonce(data: &[u8]) -> u64 {
        for n in 1u64..=1_000_000 {
            if make_pow_msg(n, data).to_checked(0, 0).is_ok() {
                return n;
            }
        }
        panic!("no valid nonce found within 1M iterations");
    }

    /// Return a ready board pre-seeded with a known block hash at height `height`.
    fn board_with_block(height: u64) -> MsgBoard {
        let board = MsgBoard::new(easy_cfg());
        board.set_ready();
        board.set_head(height, block_hash_one());
        board
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Regression test for the zero-work exploit — see
    /// `docs/msgboard-parity-gaps.md` §14.1.
    ///
    /// These `work_multiplier`/`work_divisor` values wrap `difficulty()` onto 1
    /// under erigon's `uint64` arithmetic, making every nonce a valid solution.
    /// They also clear `is_work_acceptable` with an enormous declared ratio, so
    /// before the fix all four were accepted with `nonce: 1` and no mining, and
    /// their high ratio sorted them above the honest messages — which is what
    /// `evict_oldest` then dropped.
    ///
    /// Reth now computes the threshold exactly and rejects them at
    /// `to_checked`, which `add_remote_msgs` counts as kickable.
    #[test]
    fn zero_work_messages_are_rejected_and_honest_ones_survive() {
        const EVIL_MULTIPLIER: u64 = 1_014_806_211_241_672_337;
        const EVIL_DIVISOR: u64 = 16;

        // count_limit 4 so the board would fill after a handful of inserts.
        let cfg = MsgboardConfig { count_limit: 4, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        let honest: Vec<B256> = [b"honest-a".as_slice(), b"honest-b".as_slice()]
            .iter()
            .map(|data| {
                let nonce = find_nonce(data);
                board.add_local_msg(make_pow_msg(nonce, data)).expect("honest msg accepted").hash
            })
            .collect();
        assert_eq!(board.all_messages().len(), 2);

        let spam: Vec<PoWMsg> = (0u8..4)
            .map(|i| PoWMsg {
                version: VERSION_V1,
                block_hash: block_hash_one(),
                nonce: 1,
                work_multiplier: EVIL_MULTIPLIER,
                work_divisor: EVIL_DIVISOR,
                category: category_hash(),
                data: Bytes::copy_from_slice(&[i]),
            })
            .collect();
        for msg in &spam {
            assert_eq!(msg.difficulty_checked(), None, "exact threshold exceeds u64::MAX");
            assert!(
                board.config().is_work_acceptable(msg.work_multiplier, msg.work_divisor),
                "the minimum-work gate is not what rejects these",
            );
        }

        let (accepted, kickable) = board.add_remote_msgs(spam);
        assert_eq!(accepted, 0, "no zero-work message may be accepted");
        assert_eq!(kickable, 4, "and the sender is penalised for each");

        // The honest messages are untouched.
        assert_eq!(board.all_messages().len(), 2);
        for hash in honest {
            assert!(board.get_message(&hash).is_some(), "honest message must survive");
        }
    }

    #[test]
    fn new_board_starts_empty() {
        let board = MsgBoard::new(easy_cfg());
        let (_, head, count, total_size, _, _) = board.status();
        assert_eq!(head, 0);
        assert_eq!(count, 0);
        assert_eq!(total_size, 0);
        assert!(board.all_message_ids().is_empty());
        assert!(board.take_discarded().is_empty());
    }

    // Note: tests for `version`/`block_hash`/`nonce`/`work_*`/`data` field
    // validation live next to `PoWMsg::validate` in `msgboard-types/src/pow.rs`
    // (`test_validate_rejects_*`). Mirrors erigon: validation runs at the
    // decode boundary (`PoWMsgFromRLP` / `DecodeRLPMsgList`); `add_local_msg`
    // and `add_remote_msgs` trust their inputs.

    #[test]
    fn add_local_msg_rejects_messages_above_size_limit() {
        let cfg = MsgboardConfig { size_limit: 10, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        // 20 bytes of data exceeds the size_limit of 10
        let big_data = vec![0u8; 20];
        let msg = PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce: 1,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: category_hash(),
            data: Bytes::copy_from_slice(&big_data),
        };
        let err = board.add_local_msg(msg);
        assert!(
            matches!(err, Err(reth_msgboard_types::MsgboardError::MessageTooLarge)),
            "should reject oversized message"
        );
    }

    #[test]
    fn add_local_msg_rejects_insufficient_work() {
        // Board requires multiplier=1_000 / divisor=1_000_000
        // Message provides multiplier=1 / divisor=1_000_000 (too easy)
        let cfg = MsgboardConfig { work_multiplier: 1_000, work_divisor: 1_000_000, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        let msg = make_pow_msg(find_nonce(&[5]), &[5]);
        let err = board.add_local_msg(msg);
        assert!(
            matches!(err, Err(reth_msgboard_types::MsgboardError::WorkTooEasy)),
            "should reject insufficient work"
        );
    }

    #[test]
    fn add_local_msg_rejects_unknown_block() {
        let board = MsgBoard::new(easy_cfg());
        board.set_ready();
        // Do NOT call set_head, so block_hash_one() is unknown
        let msg = make_pow_msg(find_nonce(&[6]), &[6]);
        let err = board.add_local_msg(msg);
        assert!(
            matches!(err, Err(reth_msgboard_types::MsgboardError::BlockTooOld)),
            "should reject message with unknown block"
        );
    }

    #[test]
    fn add_local_msg_succeeds_with_valid_message() {
        let board = board_with_block(100);
        let nonce = find_nonce(&[7]);
        let msg = make_pow_msg(nonce, &[7]);
        let result = board.add_local_msg(msg);
        assert!(result.is_ok(), "valid message should be accepted");

        let (_, _, count, _, _, _) = board.status();
        assert_eq!(count, 1);
    }

    #[test]
    fn set_head_prunes_old_messages_and_adds_to_discarded() {
        let cfg = MsgboardConfig { block_range: 5, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();

        // Register block 1 and add a message anchored to it
        board.set_head(1, block_hash_one());
        let nonce = find_nonce(&[8]);
        let msg = make_pow_msg(nonce, &[8]);
        board.add_local_msg(msg).expect("valid message");

        let (_, _, count, _, _, _) = board.status();
        assert_eq!(count, 1);

        // Advance head to 10: window = [10 - (5-1), 10] = [6, 10]
        // Block 1 is now below the lower bound — message should be pruned
        let new_hash = {
            let mut b = [0u8; 32];
            b[0] = 0x02;
            B256::from(b)
        };
        board.set_head(10, new_hash);

        let (_, _, count_after, _, _, _) = board.status();
        assert_eq!(count_after, 0, "message anchored to pruned block should be removed");

        let discarded = board.take_discarded();
        assert_eq!(discarded.len(), 1, "pruned message should appear in discarded");
    }

    #[test]
    fn take_discarded_drains_the_discard_list() {
        let cfg = MsgboardConfig { block_range: 2, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();

        board.set_head(1, block_hash_one());
        let nonce = find_nonce(&[9]);
        board.add_local_msg(make_pow_msg(nonce, &[9])).expect("valid");

        let new_hash = {
            let mut b = [0u8; 32];
            b[0] = 0x03;
            B256::from(b)
        };
        board.set_head(10, new_hash);

        let discarded_first = board.take_discarded();
        assert!(!discarded_first.is_empty());

        // Second call should return empty
        let discarded_second = board.take_discarded();
        assert!(discarded_second.is_empty(), "take_discarded should drain the list");
    }

    #[test]
    fn add_remote_msgs_skips_invalid_and_counts_accepted() {
        // Configure a 10-byte size limit so an oversized payload is the
        // deterministic kickable case (erigon-equivalent path: size check
        // returns ErrMsgTooLarge, which sets kickPeer=true).
        let cfg = MsgboardConfig { size_limit: 10, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        let nonce = find_nonce(&[10]);
        let valid_msg = make_pow_msg(nonce, &[10]);

        // Oversized data → `is_size_acceptable` rejects → kickable.
        let oversized = PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce: 1,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: category_hash(),
            data: Bytes::copy_from_slice(&[0u8; 100]),
        };

        let (accepted, kickable) = board.add_remote_msgs(vec![valid_msg, oversized]);
        assert_eq!(accepted, 1, "only the valid message should be accepted");
        assert_eq!(kickable, 1, "the oversized message should be flagged kickable");
    }

    #[test]
    fn add_remote_msgs_skips_unknown_blocks() {
        let board = MsgBoard::new(easy_cfg());
        board.set_ready();
        // No set_head called — block_hash_one() is unknown

        let nonce = find_nonce(&[12]);
        let msg = make_pow_msg(nonce, &[12]);

        let (accepted, kickable) = board.add_remote_msgs(vec![msg]);
        assert_eq!(accepted, 0, "message with unknown block should be skipped");
        assert_eq!(kickable, 0, "unknown-block is circumstantial, not kickable");
    }

    /// Mirrors erigon's `AddRemoteMsgs` early-return when `cfg.NoGossip` is set:
    /// observer mode must not validate, persist, broadcast, or penalise.
    #[test]
    fn add_remote_msgs_drops_everything_when_gossip_disabled() {
        let cfg = MsgboardConfig { gossip_disabled: true, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        let nonce = find_nonce(&[42]);
        let valid_msg = make_pow_msg(nonce, &[42]);
        let mut invalid_msg = make_pow_msg(nonce, &[43]);
        invalid_msg.nonce = 0;

        let (accepted, kickable) = board.add_remote_msgs(vec![valid_msg, invalid_msg]);
        assert_eq!(accepted, 0);
        assert_eq!(kickable, 0, "observers must not penalise peers");

        let (_, _, count, _, _, _) = board.status();
        assert_eq!(count, 0);
    }

    #[test]
    fn filter_wanted_filters_known_messages() {
        let board = board_with_block(100);
        let nonce = find_nonce(&[13]);
        let msg = make_pow_msg(nonce, &[13]);
        let checked = board.add_local_msg(msg).expect("valid");

        // The ID for the message we already have should be filtered out
        let id = checked.msg_id();
        let wanted = board.filter_wanted(&[id]);
        assert!(wanted.is_empty(), "already-known message should not be wanted");
    }

    #[test]
    fn filter_wanted_filters_stale_messages() {
        let cfg = MsgboardConfig { block_range: 10, stale_block_buffer: 3, ..easy_cfg() };
        let board = MsgBoard::new(cfg);

        // Set head to 100; lower = 100 - 9 = 91; stale_lower = 91 + 3 = 94
        board.set_head(100, block_hash_one());

        // Register a stale block at height 91 (below stale_lower=94)
        let stale_block_hash = {
            let mut b = [0u8; 32];
            b[0] = 0x50;
            B256::from(b)
        };
        // We need to register this block in the filter while keeping head at 100.
        // Advance to 91 first, then back to 100 so both hashes are in the window.
        board.set_head(91, stale_block_hash);
        board.set_head(100, block_hash_one());

        let msg_hash = {
            let mut b = [0u8; 32];
            b[0] = 0xFF;
            B256::from(b)
        };
        let id = reth_msgboard_types::MsgID::from_checked(
            VERSION_V1,
            &stale_block_hash,
            1,
            1,
            1_000_000,
            &category_hash(),
            &msg_hash,
        );

        let wanted = board.filter_wanted(&[id]);
        assert!(wanted.is_empty(), "stale message should be filtered out");
    }

    #[test]
    fn filter_wanted_rejects_non_v1_announcements() {
        let board = board_with_block(100);

        let msg_hash = {
            let mut b = [0u8; 32];
            b[0] = 0xAA;
            B256::from(b)
        };
        // Same shape as a real announcement, but version 0 (or any non-V1).
        let id = reth_msgboard_types::MsgID::from_checked(
            0,
            &block_hash_one(),
            1,
            1,
            1_000_000,
            &category_hash(),
            &msg_hash,
        );
        let wanted = board.filter_wanted(&[id]);
        assert!(wanted.is_empty(), "non-V1 announcements should never be requested");
    }

    #[test]
    fn filter_wanted_filters_oversized_messages() {
        let cfg = MsgboardConfig { size_limit: 10, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_head(100, block_hash_one());

        let msg_hash = {
            let mut b = [0u8; 32];
            b[0] = 0xFE;
            B256::from(b)
        };
        // size = 100 which exceeds size_limit = 10
        let id = reth_msgboard_types::MsgID::from_checked(
            VERSION_V1,
            &block_hash_one(),
            100,
            1,
            1_000_000,
            &category_hash(),
            &msg_hash,
        );

        let wanted = board.filter_wanted(&[id]);
        assert!(wanted.is_empty(), "oversized message should be filtered out");
    }

    #[test]
    fn subscribe_receives_new_messages() {
        let board = Arc::new(board_with_block(200));
        let mut rx = board.subscribe();

        let nonce = find_nonce(&[20]);
        let msg = make_pow_msg(nonce, &[20]);
        let accepted = board.add_local_msg(msg).expect("valid");

        let received = rx.try_recv().expect("should have received a message");
        assert_eq!(received.hash, accepted.hash);
    }

    #[test]
    fn status_returns_correct_values() {
        let board = MsgBoard::new(easy_cfg());
        board.set_ready();
        board.set_head(50, block_hash_one());

        let nonce = find_nonce(&[21]);
        let msg = make_pow_msg(nonce, &[21]);
        board.add_local_msg(msg).expect("valid");

        let (_, head, count, total_size, work_mult, work_div) = board.status();
        assert_eq!(head, 50);
        assert_eq!(count, 1);
        assert!(total_size > 0);
        // Configured with work_multiplier=1, work_divisor=1_000_000
        assert_eq!(work_mult, 1);
        assert_eq!(work_div, 1_000_000);
    }

    #[test]
    fn count_limit_causes_eviction() {
        let cfg = MsgboardConfig { count_limit: 2, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        let n0 = find_nonce(&[30]);
        let n1 = find_nonce(&[31]);
        let n2 = find_nonce(&[32]);

        board.add_local_msg(make_pow_msg(n0, &[30])).expect("msg 0");
        board.add_local_msg(make_pow_msg(n1, &[31])).expect("msg 1");

        let (_, _, count, _, _, _) = board.status();
        assert_eq!(count, 2, "should have 2 messages before hitting limit");

        // Adding a 3rd message should evict the oldest
        board.add_local_msg(make_pow_msg(n2, &[32])).expect("msg 2");

        let (_, _, count_after, _, _, _) = board.status();
        assert_eq!(count_after, 2, "count should still be 2 after eviction");

        // The evicted message should appear in discarded
        let discarded = board.take_discarded();
        assert_eq!(discarded.len(), 1, "one message should have been evicted");
    }

    /// Spec §5.3: when the board is full and the new message itself has the
    /// lowest precedence, it is the one displaced and the caller gets
    /// `BoardOverflow` — matching erigon's `addMsgLocked`.
    #[test]
    fn lowest_precedence_new_message_returns_board_overflow() {
        let cfg = MsgboardConfig { count_limit: 1, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        // mine two messages anchored to the same block so precedence is by
        // difficulty ratio alone. higher work_multiplier ⇒ higher ratio
        // ⇒ higher precedence.
        let mine = |mult: u64, data: &[u8]| -> PoWMsg {
            for n in 1u64..=1_000_000 {
                let m = PoWMsg {
                    version: VERSION_V1,
                    block_hash: block_hash_one(),
                    nonce: n,
                    work_multiplier: mult,
                    work_divisor: 1_000_000,
                    category: category_hash(),
                    data: Bytes::copy_from_slice(data),
                };
                if m.clone().to_checked(0, 0).is_ok() {
                    return m;
                }
            }
            panic!("no valid nonce found");
        };

        // High-precedence message lands first.
        let high = mine(5, &[1]);
        board.add_local_msg(high).expect("high-precedence msg accepted");

        // Now try to add a lower-precedence message. Board is full at 1, our
        // new msg is sorted to index 0 and evicted on the same call.
        let low = mine(1, &[2]);
        let err = board.add_local_msg(low).expect_err("should overflow");
        assert!(matches!(err, MsgboardError::BoardOverflow), "expected BoardOverflow, got {err:?}",);

        // Board still holds the high-precedence message untouched.
        let (_, _, count, _, _, _) = board.status();
        assert_eq!(count, 1);
    }
}
