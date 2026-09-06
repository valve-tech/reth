//! Shared in-memory msgboard state.
//!
//! [`MsgBoard`] is the central actor. It is `Arc`-shared between the P2P
//! protocol handler (which may run one connection task per peer) and the
//! JSON-RPC handler. A `parking_lot::Mutex` guards the mutable state for
//! low-contention synchronous access; a `tokio::sync::broadcast` channel
//! fans new-message notifications out to all active peer connection tasks.

use std::{
    collections::HashSet,
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
    CheckedPoWMsg, MsgID, MsgboardConfig, MsgboardError, PoWMsg, WirePoWMsg, VERSION_V1,
};

use crate::{
    block_filter::BlockFilter, db, index::MsgIndex, metrics::MsgboardMetrics,
    pending::PendingRequests,
};

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
    /// Messages evicted from the index, waiting for the next flush to delete
    /// their rows. Always empty when `persists` is false.
    discarded: Vec<Arc<CheckedPoWMsg>>,
    /// Hashes inserted since the last successful flush. A flush writes these
    /// rows and no others. Always empty when `persists` is false.
    dirty: HashSet<B256>,
    /// IDs already requested from some peer, so a second peer announcing the
    /// same message does not earn a second request.
    pending: PendingRequests,
    /// Whether a database sits behind the board.
    ///
    /// Both flush sets exist only to describe the next write transaction, so
    /// without a database there is nothing for them to describe.
    persists: bool,
}

impl BoardState {
    /// Record a message that left the index, so the next flush deletes its row.
    ///
    /// A board with no database records nothing. Nothing drains the list in
    /// that configuration — `flush_to_db` returns before it reaches the drain —
    /// so each entry would live as long as the process and hold its message
    /// body alive with it. Dropping the message here bounds the list by
    /// construction rather than by how often a flush happens to run, and it
    /// costs nothing: there is no row on disk to delete.
    fn discard(&mut self, msg: Arc<CheckedPoWMsg>) {
        if self.persists {
            self.discarded.push(msg);
        }
    }

    /// Record a newly inserted message, so the next flush writes its row.
    ///
    /// Messages read back by `load_from_db` are already stored and are not
    /// marked. See [`discard`](Self::discard) for the no-database case.
    fn mark_dirty(&mut self, hash: B256) {
        if self.persists {
            self.dirty.insert(hash);
        }
    }
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
        Self::build(cfg, None)
    }

    /// Create a board backed by an MDBX database for persistence.
    pub fn with_db(cfg: MsgboardConfig, db: Environment) -> Self {
        Self::build(cfg, Some(db))
    }

    fn build(cfg: MsgboardConfig, db: Option<Environment>) -> Self {
        let (new_msg_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        let state = BoardState {
            index: MsgIndex::default(),
            block_filter: BlockFilter::new(cfg.block_range),
            discarded: Vec::new(),
            dirty: HashSet::new(),
            pending: PendingRequests::default(),
            persists: db.is_some(),
        };
        Self {
            cfg,
            state: Mutex::new(state),
            new_msg_tx,
            db,
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
        // `db_load_all` reports the skipped rows itself, with the decode error,
        // the row's RLP shape and an ERROR when the whole table fails. Repeating
        // the bare count here only buried that line under a vaguer one.
        let (msgs, _bad) = db::db_load_all(env)?;

        let mut loaded = 0u64;
        let mut dropped_invalid = 0u64;
        let mut dropped_duplicate = 0u64;
        for msg in msgs {
            let arc = Arc::new(msg);
            // Reject rows that no longer satisfy the live config. They land in
            // `discarded` so the next flush deletes them from MDBX.
            //
            // The `PoW` is re-verified, not trusted. A row on disk was valid
            // under the rules in force when it was written, and those rules can
            // change under it — §21 changed the construction outright. Without
            // this check a construction change leaves the board serving
            // messages no conforming peer can accept, and every one we serve
            // earns us a `BadMessage` hit from that peer. Four is a 12-hour
            // ban, and the ban is global: it costs block sync, not just
            // msgboard.
            //
            // The cost is one scalar multiplication per stored message, paid
            // once at startup — under a second for a full `count_limit` board,
            // against a partition that lasts hours.
            let valid = self.cfg.is_size_acceptable(arc.msg.data.len()) &&
                self.cfg.is_work_acceptable(arc.msg.work_multiplier, arc.msg.work_divisor) &&
                arc.msg.verify().is_ok_and(|hash| hash == arc.hash);
            if !valid {
                let mut state = self.state.lock();
                state.discard(arc);
                dropped_invalid += 1;
                continue;
            }

            let mut state = self.state.lock();
            if state.index.insert(Arc::clone(&arc)) {
                loaded += 1;
            } else {
                // Duplicate hash on disk — schedule for deletion to keep the
                // table clean across restarts.
                state.discard(arc);
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
    /// Writes the messages inserted since the last successful flush and deletes
    /// the discarded ones. Returns the number of bytes written, which is zero
    /// for a board that has not changed.
    ///
    /// **This call blocks.** It opens an MDBX write transaction and commits it,
    /// and the commit fsyncs. Run it on a blocking thread, not on a runtime
    /// worker — [`spawn_flush_task`](Self::spawn_flush_task) does.
    pub fn flush_to_db(&self) -> eyre::Result<u64> {
        let Some(ref env) = self.db else { return Ok(0) };

        let start = Instant::now();
        let batch = self.take_flush_batch();
        let discarded_hashes: Vec<B256> = batch.discarded.iter().map(|m| m.hash).collect();

        let bytes = match db::db_flush(env, &batch.current, &discarded_hashes) {
            Ok(bytes) => bytes,
            Err(err) => {
                // The transaction is all-or-nothing, so a failure leaves every
                // row as it was. Hand the batch back or the deletions never
                // happen and the writes never land: this is the only record
                // that either is outstanding.
                self.restore_flush_batch(batch);
                return Err(err);
            }
        };

        self.metrics.write_to_db_duration_seconds.record(start.elapsed().as_secs_f64());
        self.metrics.write_to_db_bytes.set(bytes as f64);

        tracing::debug!(
            target: "msgboard",
            written = batch.current.len(),
            deleted = discarded_hashes.len(),
            bytes,
            "flushed messages to DB"
        );

        Ok(bytes)
    }

    /// Returns a reference to the configuration.
    pub const fn config(&self) -> &MsgboardConfig {
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
                    state.discard(evicted);
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
    /// An ID is wanted if we don't already have it, no request for it is
    /// already in flight, it passes the configured size and work limits, and
    /// the block is not within the stale buffer zone.
    ///
    /// **This method mutates.** Every returned ID is claimed in
    /// [`PendingRequests`], so calling it twice with the same live ID returns
    /// it only once. The caller owns the request it just claimed: if the frame
    /// does not reach the peer it must hand the IDs back via
    /// [`release_pending`](Self::release_pending), or nothing re-requests them
    /// until the claim expires.
    ///
    /// The name still mirrors erigon's `FilterMessageIDs`, which does the same
    /// filtering minus the in-flight check.
    pub fn filter_wanted(&self, ids: &[MsgID]) -> Vec<MsgID> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let stale_lower = state.block_filter.lower() + self.cfg.stale_block_buffer;

        // Sweeping here rather than on a timer keeps the map bounded without a
        // background task: it can only grow on this path, so it can only need
        // trimming on this path.
        state.pending.sweep(now);

        let BoardState { index, block_filter, pending, .. } = &mut *state;
        let mut suppressed = 0u64;
        let wanted: Vec<MsgID> = ids
            .iter()
            .filter(|id| {
                // Mirrors erigon's `FilterMessageIDs`: drop announcements with a
                // version we don't speak before requesting the body, instead of
                // wasting an RTT and rejecting at decode time.
                //
                if id.version() != VERSION_V1 {
                    return false;
                }
                if index.has(&id.message_hash()) {
                    return false;
                }
                if !self.cfg.is_size_acceptable(id.size() as usize) {
                    return false;
                }
                if !self.cfg.is_work_acceptable(id.work_multiplier(), id.work_divisor()) {
                    return false;
                }
                // Skip messages anchored to blocks about to expire.
                if let Some(block_num) = block_filter.block_number(&id.block_hash()) {
                    if block_num < stale_lower {
                        return false;
                    }
                } else {
                    // Block hash not in our window — skip.
                    return false;
                }
                // Claimed last, so an ID rejected above never occupies a slot.
                if pending.claim(**id, now) {
                    true
                } else {
                    suppressed += 1;
                    false
                }
            })
            .copied()
            .collect();

        let live_claims = pending.len();
        drop(state);

        self.metrics.requests_suppressed.increment(suppressed);
        self.metrics.pending_requests.set(live_claims as f64);
        wanted
    }

    /// Hand back claims taken by [`filter_wanted`](Self::filter_wanted) for a
    /// request that never reached its peer.
    ///
    /// Without this a dropped frame would stall the message until the claim
    /// expired, because the peers still announcing it would all be suppressed.
    pub fn release_pending(&self, ids: &[MsgID]) {
        let mut state = self.state.lock();
        for id in ids {
            state.pending.release(id);
        }
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

    /// Fetch the messages named by these work hashes, each paired with the hash
    /// it is held under.
    ///
    /// Used to respond to a `GetBoardMessages` packet under the
    /// `pulse-v3.4.4` behaviour set, where the request names 32-byte hashes and
    /// the reply carries the hash alongside each body. Mirrors erigon's
    /// `GetMessage(ctx, h)` loop (`msgboard/fetch.go:256-266`): a hash we do
    /// not hold is skipped, not reported.
    pub fn get_wire_messages_for_hashes(&self, hashes: &[B256]) -> Vec<WirePoWMsg> {
        let state = self.state.lock();
        hashes
            .iter()
            .filter_map(|hash| {
                state.index.get(hash).map(|m| WirePoWMsg::new(m.msg.clone(), m.hash))
            })
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
    ///    payload, undersized work, invalid `PoW`). Mirrors erigon-pulse `AddRemoteMsgs` returning
    ///    a non-nil error → caller sets `kickPeer=true`.
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
        // `B256::ZERO` is erigon's absent-claim sentinel (`addMsgLocked`'s
        // `claimedHash != (common.Hash{})` guards), and a real work hash is
        // never zero.
        self.add_remote(msgs.into_iter().map(|msg| (msg, B256::ZERO)))
    }

    /// Add messages delivered with the hash their sender claims for them.
    ///
    /// The `pulse-v3.4.4` entry point. Same rules as
    /// [`add_remote_msgs`](Self::add_remote_msgs), plus the two checks the
    /// claim buys — see [`add_remote`](Self::add_remote). Mirrors erigon's
    /// `AddRemoteWireMsgs` (`msgboard/board.go:271-292`).
    pub fn add_remote_wire_msgs(&self, msgs: Vec<WirePoWMsg>) -> (usize, usize) {
        self.add_remote(msgs.into_iter().map(|m| (m.msg, m.hash)))
    }

    /// The shared body of both remote-ingest entry points.
    ///
    /// Each message arrives with the hash its sender claims for it, or
    /// [`B256::ZERO`] when the wire format carries no claim. A claim is used
    /// twice, straddling the expensive step, exactly as erigon's `addMsgLocked`
    /// uses it (`msgboard/board.go:402-462`):
    ///
    ///  - **Before** `to_checked`, as an index probe. A message we already hold is then free to
    ///    re-receive. Without the claim nothing can look a delivery up first: the index key is
    ///    `sha256(challenge ‖ category ‖ data)` and `challenge` *is* the elliptic curve point, so
    ///    learning which message arrived costs the secp256k1 scalar multiplication we are trying to
    ///    avoid. Gossip re-delivers constantly, so this is the common case, not the corner one.
    ///  - **After** `to_checked`, against the recomputed hash. The claim is never trusted; a
    ///    mismatch is kickable, because a peer that mislabels a body is either broken or probing.
    ///
    /// With no claim both checks are skipped and the duplicate is caught later,
    /// by `insert_checked` returning `MessageExists` — same outcome, paid for
    /// with a verification.
    fn add_remote(&self, msgs: impl IntoIterator<Item = (PoWMsg, B256)>) -> (usize, usize) {
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
        for (msg, claimed) in msgs {
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

            // Ordered as erigon orders it: after the block lookup, before the
            // scalar multiplication.
            if !claimed.is_zero() && self.state.lock().index.has(&claimed) {
                self.metrics.skipped_duplicate.increment(1);
                continue;
            }

            let checked = match msg.to_checked(block_number, timestamp) {
                Ok(checked) => checked,
                Err(err) => {
                    // Split by reason: `InvalidDifficulty` means the message
                    // declares no usable threshold at all, which is a malformed
                    // parameter rather than a failed mining attempt.
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
            if !claimed.is_zero() && checked.hash != claimed {
                // Counted under `rejected_other` rather than its own gauge: a
                // conforming peer never sends one, so the interesting signal is
                // the `BadMessage` hit the caller raises, not the rate.
                self.metrics.rejected_other.increment(1);
                kickable += 1;
                continue;
            }
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

        // The remote path validates on decode (`decode_pow_msg_list`); the local
        // path had no equivalent, so a message the peers would kick us for
        // relaying could still enter the board through the RPC. The version byte
        // makes that concrete: it is hashed into the scalar, so a message mined
        // at the wrong version has genuine work behind it and passes
        // `to_checked` on its own terms.
        msg.validate()?;

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

    /// Drain the messages whose rows are waiting to be deleted.
    ///
    /// A board with no database queues none of them, so it always returns
    /// empty there. `flush_to_db` takes the same list as part of a whole
    /// batch, so that it can hand the batch back when the write fails.
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

    /// Take everything the next write transaction needs, under one short lock.
    ///
    /// The messages come out as `Arc` clones. Collecting a `Vec<CheckedPoWMsg>`
    /// instead copies a whole struct per message and allocates a vector to hold
    /// them, all while holding the mutex that `add_remote_msgs`, `set_head` and
    /// every RPC read need. It is the structs that cost, not the payloads: a
    /// payload is a refcounted `Bytes` and its clone is an atomic increment.
    fn take_flush_batch(&self) -> FlushBatch {
        let mut state = self.state.lock();
        let dirty = std::mem::take(&mut state.dirty);
        // A hash whose message has since left the index has nothing to write.
        // The `discarded` set carries its deletion instead.
        let current: Vec<Arc<CheckedPoWMsg>> =
            dirty.iter().filter_map(|hash| state.index.get(hash)).collect();
        let discarded = std::mem::take(&mut state.discarded);
        FlushBatch { current, dirty, discarded }
    }

    /// Put a failed batch back so the next flush retries it.
    ///
    /// The board keeps running while a flush is in flight, so both sets can
    /// have grown since [`take_flush_batch`](Self::take_flush_batch). The batch
    /// merges into what is there now; replacing it would drop every message
    /// inserted or discarded during the failed attempt.
    fn restore_flush_batch(&self, batch: FlushBatch) {
        let mut state = self.state.lock();
        state.dirty.extend(batch.dirty);
        // Older discards go first, so the list keeps eviction order.
        let mut discarded = batch.discarded;
        discarded.append(&mut state.discarded);
        state.discarded = discarded;
    }

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
                state.discard(evicted);
            }
            // Marked after the eviction loop, so a message displaced on its own
            // insert never enters the write set.
            state.mark_dirty(arc.hash);
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
                // `flush_to_db` writes every dirty row and fsyncs on commit.
                // Run directly, that stalls a runtime worker for the whole
                // transaction, and every task sharing the thread with it.
                let board = Arc::clone(&board);
                match tokio::task::spawn_blocking(move || board.flush_to_db()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::warn!(target: "msgboard", %e, "DB flush failed"),
                    Err(e) => tracing::warn!(target: "msgboard", %e, "DB flush task failed"),
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

/// One flush's worth of work, taken off the board under a single lock.
///
/// Held apart from the board so a failed transaction can be handed back
/// whole — see [`MsgBoard::restore_flush_batch`].
#[derive(Debug)]
struct FlushBatch {
    /// Messages to write, shared with the index rather than copied out of it.
    current: Vec<Arc<CheckedPoWMsg>>,
    /// Every hash taken from the dirty set, including those whose message has
    /// already left the index. Restoring them all is harmless: the next batch
    /// looks each one up again and drops the ones that are gone.
    dirty: HashSet<B256>,
    /// Messages whose rows the transaction deletes.
    discarded: Vec<Arc<CheckedPoWMsg>>,
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

    /// Config with easy `PoW` so tests can mine valid messages quickly.
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

    fn hash_byte(byte: u8) -> B256 {
        let mut b = [0u8; 32];
        b[0] = byte;
        B256::from(b)
    }

    /// A board backed by a real MDBX environment.
    ///
    /// The `TempDir` comes back with it because it has to outlive the board:
    /// dropping it removes the database under the open environment.
    fn board_with_db(cfg: MsgboardConfig) -> (tempfile::TempDir, MsgBoard) {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = crate::db::open_msgboard_db(dir.path()).expect("open db");
        (dir, MsgBoard::with_db(cfg, env))
    }

    /// A work divisor that leaves the exact difficulty in single digits at any
    /// message size, so a test that needs hundreds of messages can mine them.
    ///
    /// `difficulty` is `(2^24 + size * 10_000) * multiplier / divisor`, so a
    /// divisor of `2^24` keeps it near 1 whatever the payload. Under the
    /// default `easy_cfg` divisor an 8 KiB message costs about a hundred
    /// SHA-256 passes over 8 KiB, which is minutes in a debug build.
    const CHEAP_WORK_DIVISOR: u64 = 1 << 24;

    /// Mine a valid message anchored to `block_hash`.
    fn mine_for_block(block_hash: B256, work_divisor: u64, data: &[u8]) -> PoWMsg {
        for nonce in 1u64..=1_000_000 {
            let msg = PoWMsg {
                version: VERSION_V1,
                block_hash,
                nonce,
                work_multiplier: 1,
                work_divisor,
                category: category_hash(),
                data: Bytes::copy_from_slice(data),
            };
            if msg.verify().is_ok() {
                return msg;
            }
        }
        panic!("no valid nonce found within 1M iterations");
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
            let d = msg.difficulty().expect("well-formed parameters");
            assert!(
                d > alloy_primitives::U256::from(u64::MAX),
                "the exact threshold is ~2^80 — the old code wrapped it to 1",
            );
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

    /// The board must hand its behaviour set to the index.
    ///
    /// Without this the flag gates the wire format while eviction quietly
    /// keeps the other ordering — and eviction order is the half that is
    /// wire-observable, so the node would gossip a board its peers disagree
    /// with while appearing to speak their protocol.
    /// The flush must not run on a runtime worker.
    ///
    /// `flush_to_db` is fully synchronous: it opens an MDBX write transaction,
    /// writes every dirty row, and fsyncs on commit. Run directly inside the
    /// async task it would hold a worker thread for the whole transaction, and
    /// every task sharing that thread stops.
    ///
    /// Asserted as **liveness, not duration**. The runtime gets exactly one
    /// worker. A write transaction is held open before the flush fires, so
    /// `begin_rw_txn` spins on `Error::Busy` with a blocking 250 ms sleep —
    /// real contention through the production path, no test hook in the flush.
    /// If that spinning sits on the worker, nothing else on the runtime can
    /// run; the probe task below never completes and the channel times out.
    ///
    /// The test body stays **off** the runtime, on the plain `#[test]` thread,
    /// so a regression fails on the timeout instead of hanging the suite —
    /// which is what would happen if the assertion were itself a runtime task
    /// waiting on a blocked worker.
    ///
    /// The five-second bound is a liveness ceiling, not a budget. A healthy
    /// runtime clears it in well under a second; a regression sits on the
    /// worker until the timeout expires, so pass and fail are an order of
    /// magnitude apart rather than a few percent. **If this ever flakes, do
    /// not raise the ceiling** — a machine that cannot schedule a
    /// `spawn_blocking` thread inside five seconds is not the failure this
    /// guards against, and lifting the number is how a real regression gets
    /// mistaken for one.
    #[test]
    fn the_flush_does_not_occupy_a_runtime_worker() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");

        let dir = tempfile::tempdir().expect("tempdir");
        let env = crate::db::open_msgboard_db(dir.path()).expect("open db");
        // A second handle to the same environment. `Environment` is an `Arc`
        // internally, so both share one writer lock.
        let blocker = env.clone();

        let board = Arc::new(MsgBoard::with_db(easy_cfg(), env));
        board.set_ready();
        board.set_head(1, block_hash_one());
        let nonce = find_nonce(&[7]);
        board.add_local_msg(make_pow_msg(nonce, &[7])).expect("valid message");

        // Take the writer slot. Every flush now blocks until this is dropped.
        let held = blocker.begin_rw_txn().expect("hold the writer lock");

        // `block_on` only supplies the runtime context `spawn_flush_task` needs;
        // the handle it returns is not awaited here, because the point is to
        // leave the flush running while the probe goes in.
        let _guard = rt.enter();
        let _flush = board.spawn_flush_task(std::time::Duration::from_millis(10));

        // Give the interval room to elapse so the flush is genuinely blocked
        // before the probe goes in. This sleep is on the test thread, not the
        // runtime, so it cannot itself starve.
        std::thread::sleep(std::time::Duration::from_millis(500));

        let (probe_tx, probe_rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            let _ = probe_tx.send(());
        });

        let progressed = probe_rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok();

        drop(held);
        rt.shutdown_timeout(std::time::Duration::from_secs(5));

        assert!(
            progressed,
            "a blocked flush held the only runtime worker; \
             `spawn_flush_task` must hand `flush_to_db` to `spawn_blocking`",
        );
    }

    #[test]
    fn the_board_orders_by_ratio_only_within_a_block() {
        fn mined(block_hash: B256, mult: u64, data: &[u8]) -> PoWMsg {
            let base = PoWMsg {
                version: VERSION_V1,
                block_hash,
                nonce: 0,
                work_multiplier: mult,
                work_divisor: 1_000_000,
                category: category_hash(),
                data: Bytes::copy_from_slice(data),
            };
            for n in 1u64..=1_000_000 {
                let mut msg = base.clone();
                msg.nonce = n;
                if msg.clone().to_checked(0, 0).is_ok() {
                    return msg;
                }
            }
            panic!("no valid nonce found within 1M iterations");
        }

        // Two blocks, and a later-block message whose ratio is the lowest.
        // Comparing that ratio across blocks would sort it to the front. The
        // comparator guards on block equality, so it does not.
        let low = block_hash_one();
        let high = B256::from([0x02u8; 32]);

        let front_of_board = || {
            let board = MsgBoard::new(easy_cfg());
            board.set_ready();
            board.set_head(5, low);
            board.set_head(10, high);

            board.add_local_msg(mined(low, 3, b"a")).expect("block 5, highest ratio");
            board.add_local_msg(mined(high, 3, b"b")).expect("block 10, highest ratio");
            board.add_local_msg(mined(high, 1, b"c")).expect("block 10, lowest ratio");

            board.all_messages()[0].msg.data.to_vec()
        };

        assert_eq!(
            front_of_board(),
            b"a",
            "ratios are only compared within a block, so the earliest block sorts first",
        );
    }

    #[test]
    fn set_head_prunes_old_messages_and_adds_to_discarded() {
        // A database-backed board: only that configuration queues discards,
        // because only it has rows to delete.
        let (_dir, board) = board_with_db(MsgboardConfig { block_range: 5, ..easy_cfg() });
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
        let (_dir, board) = board_with_db(MsgboardConfig { block_range: 2, ..easy_cfg() });
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
        let (_dir, board) = board_with_db(MsgboardConfig { count_limit: 2, ..easy_cfg() });
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

    /// Version 1 is the only version the board will take.
    ///
    /// This replaced a test asserting that two constructions coexisted. They no
    /// longer do: the new algorithm took the same version byte, so there is
    /// nothing to tell an old message from a new one and no dual-accept path to
    /// build. Anything but 1 is refused outright.
    #[test]
    fn only_version_one_is_accepted() {
        let board = board_with_block(100);

        let good = make_pow_msg(find_nonce(&[0xA1]), &[0xA1]);
        assert_eq!(good.version, VERSION_V1);
        board.add_local_msg(good.clone()).expect("version 1 must be accepted");

        for bad in [0u8, 2, 3] {
            let mut msg = good.clone();
            msg.version = bad;
            assert!(
                matches!(board.add_local_msg(msg), Err(MsgboardError::InvalidVersion)),
                "version {bad} must be refused",
            );
        }

        // The version byte is hashed into the scalar, so relabelling a valid
        // message breaks its work even when the new label is one we speak.
        // That is what makes the byte load-bearing rather than decorative.
        let mut relabelled = good;
        relabelled.version = 2;
        assert!(relabelled.verify().is_err());
    }

    /// A stored message whose `PoW` no longer verifies must not come back onto
    /// the board at startup.
    ///
    /// A row on disk was valid under the rules in force when it was written,
    /// and §21 changed those rules outright. Before this check `load_from_db`
    /// re-inserted such rows unexamined, so a construction change left the
    /// board announcing and serving messages no conforming peer could accept —
    /// and each one served earns a `BadMessage` hit from that peer, four of
    /// which is a 12-hour ban on *all* protocols, block sync included.
    ///
    /// The stale row here carries a hash that does not match its own work,
    /// which is what a rules change looks like from the loader's side.
    #[test]
    fn a_stored_message_that_no_longer_verifies_is_not_reloaded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = crate::db::open_msgboard_db(dir.path()).expect("open db");

        let good = {
            let msg = make_pow_msg(find_nonce(&[0xB1]), &[0xB1]);
            let hash = msg.verify().expect("mined");
            CheckedPoWMsg { msg, block_number: 100, timestamp: 0, hash }
        };
        // Same fields, but the recorded hash is not the one this construction
        // produces — indistinguishable, on disk, from a row written under rules
        // that have since changed.
        let stale = CheckedPoWMsg { hash: B256::repeat_byte(0xEE), ..good.clone() };

        crate::db::db_flush(&env, std::slice::from_ref(&good), &[]).expect("write good");
        crate::db::db_flush(&env, std::slice::from_ref(&stale), &[]).expect("write stale");

        let board = MsgBoard::with_db(easy_cfg(), env);
        board.set_ready();
        board.set_head(100, block_hash_one());
        let loaded = board.load_from_db().expect("load");

        assert_eq!(loaded, 1, "only the message that still verifies may load");
        assert!(board.get_message(&good.hash).is_some(), "the valid one survives");
        assert!(board.get_message(&stale.hash).is_none(), "the stale one must not");
    }

    /// A board with no database must not queue pruned messages.
    ///
    /// `launch.rs` builds one whenever `open_msgboard_db` fails, and on that
    /// path nothing drains the discard list: `flush_to_db` returns before it
    /// reaches the drain. Every new block would add to the list for the life of
    /// the process, and each entry holds a whole message body alive.
    #[test]
    fn a_board_without_a_database_drops_pruned_messages_instead_of_queueing_them() {
        let cfg = MsgboardConfig { block_range: 3, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();

        board.set_head(1, block_hash_one());
        board.add_local_msg(make_pow_msg(find_nonce(&[0x51]), &[0x51])).expect("valid message");

        // Window becomes [2, 4], so the message anchored to block 1 is pruned.
        board.set_head(4, hash_byte(0x04));
        assert_eq!(board.status().2, 0, "the message leaves the index");

        assert_eq!(board.flush_to_db().expect("no database"), 0);
        assert!(board.take_discarded().is_empty(), "nothing may queue with no rows to delete");
    }

    /// The eviction path has the same problem as the prune path: under sustained
    /// ingest a full board evicts on nearly every insert.
    #[test]
    fn a_board_without_a_database_drops_evicted_messages_instead_of_queueing_them() {
        let cfg = MsgboardConfig { count_limit: 2, ..easy_cfg() };
        let board = MsgBoard::new(cfg);
        board.set_ready();
        board.set_head(100, block_hash_one());

        for data in [&[0x52u8][..], &[0x53][..], &[0x54][..]] {
            board.add_local_msg(make_pow_msg(find_nonce(data), data)).expect("valid message");
        }
        assert_eq!(board.status().2, 2, "the third insert evicts one");

        assert!(board.take_discarded().is_empty(), "nothing may queue with no rows to delete");
    }

    /// A failed flush must keep the hashes it could not delete.
    ///
    /// The deletion set lives nowhere else. Dropping it on the floor leaves the
    /// rows in MDBX for the life of the process, and the caller only logs the
    /// error and tries again on the next tick.
    #[test]
    fn a_failed_flush_keeps_the_deletion_set_for_the_next_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No `BoardMessage` table, so every flush fails when it opens the table.
        let env = crate::db::open_env_without_table(dir.path()).expect("open env");
        let board = MsgBoard::with_db(MsgboardConfig { block_range: 3, ..easy_cfg() }, env);
        board.set_ready();

        board.set_head(1, block_hash_one());
        let hash =
            board.add_local_msg(make_pow_msg(find_nonce(&[0x55]), &[0x55])).expect("valid").hash;
        board.set_head(4, hash_byte(0x04));

        let _ = board.flush_to_db().expect_err("the table is missing");

        let kept: Vec<B256> = board.take_discarded().iter().map(|m| m.hash).collect();
        assert_eq!(kept, vec![hash], "a failed flush must hand its deletion set back");
    }

    /// Restoring a failed batch must merge, not replace.
    ///
    /// The board keeps accepting and pruning while a flush runs, so both sets
    /// can have grown by the time the failure comes back. Overwriting them with
    /// the failed batch loses everything that happened in between.
    #[test]
    fn restoring_a_failed_flush_keeps_what_the_board_discarded_during_it() {
        let (_dir, board) = board_with_db(MsgboardConfig { block_range: 3, ..easy_cfg() });
        board.set_ready();

        board.set_head(1, block_hash_one());
        let first =
            board.add_local_msg(make_pow_msg(find_nonce(&[0x56]), &[0x56])).expect("valid").hash;
        board.set_head(2, hash_byte(0x02));
        let second = board
            .add_local_msg(mine_for_block(hash_byte(0x02), 1_000_000, &[0x57]))
            .expect("valid")
            .hash;

        // Window [2, 4] drops the first message, and the flush takes it.
        board.set_head(4, hash_byte(0x04));
        let batch = board.take_flush_batch();
        assert_eq!(batch.discarded.len(), 1, "the batch carries the first message");

        // The board runs on while the write is in flight: window [3, 5] drops
        // the second message too.
        board.set_head(5, hash_byte(0x05));

        board.restore_flush_batch(batch);

        let kept: Vec<B256> = board.take_discarded().iter().map(|m| m.hash).collect();
        assert_eq!(kept, vec![first, second], "both deletions survive, in eviction order");
    }

    /// A flush writes what changed, not the whole board.
    ///
    /// At the default limits a full rewrite is 81.92 MB every `commit_every`,
    /// about 5.46 MB/s of durable writes for a board that usually changes by a
    /// handful of messages.
    #[test]
    fn a_flush_writes_only_the_messages_added_since_the_last_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stored = {
            let env = crate::db::open_msgboard_db(dir.path()).expect("open db");
            let board = MsgBoard::with_db(easy_cfg(), env);
            board.set_ready();
            board.set_head(100, block_hash_one());

            for data in [&[0x58u8][..], &[0x59][..], &[0x5A][..]] {
                board.add_local_msg(make_pow_msg(find_nonce(data), data)).expect("valid");
            }
            let three = board.flush_to_db().expect("flush");
            assert!(three > 0, "the first flush stores all three messages");

            assert_eq!(
                board.flush_to_db().expect("flush"),
                0,
                "an unchanged board must not rewrite a single row",
            );

            board.add_local_msg(make_pow_msg(find_nonce(&[0x5B]), &[0x5B])).expect("valid");
            let one = board.flush_to_db().expect("flush");
            assert!(one > 0, "the new message is written");
            assert!(one * 2 < three, "only the new message is written: {one} against {three}");
            board.all_messages().len()
        };

        // Reopen from scratch: writing only the delta must still leave every
        // message on disk.
        let env = crate::db::open_msgboard_db(dir.path()).expect("reopen");
        let (loaded, bad) = crate::db::db_load_all(&env).expect("load");
        assert_eq!(bad, 0);
        assert_eq!(loaded.len(), stored, "every message is on disk after the delta flushes");
    }

    /// A failed flush must not mark the board clean.
    ///
    /// The write set is the only record that a message is not yet on disk. If a
    /// failure clears it, the message is never stored, and the next flush
    /// reports success over a board that disagrees with its own database.
    #[test]
    fn a_failed_flush_keeps_the_write_set_for_the_next_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A map too small for a bulk write, but roomy enough for a single
        // message — so the retry can succeed.
        let env = crate::db::open_env_with_map_size(dir.path(), 2 * 1024 * 1024).expect("open env");
        let cfg = MsgboardConfig { block_range: 3, work_divisor: CHEAP_WORK_DIVISOR, ..easy_cfg() };
        let board = MsgBoard::with_db(cfg, env);
        board.set_ready();

        // Block 1 carries far more than the map holds.
        board.set_head(1, block_hash_one());
        for i in 0..200u16 {
            let mut data = vec![0u8; 8_000];
            data[..2].copy_from_slice(&i.to_be_bytes());
            board
                .add_local_msg(mine_for_block(block_hash_one(), CHEAP_WORK_DIVISOR, &data))
                .expect("valid");
        }
        // Block 2 carries one small message.
        board.set_head(2, hash_byte(0x02));
        let small = board
            .add_local_msg(mine_for_block(hash_byte(0x02), CHEAP_WORK_DIVISOR, &[0x5C]))
            .expect("valid")
            .hash;

        let _ = board.flush_to_db().expect_err("the batch exceeds the dirty-page budget");

        // Window [3, 4] drops block 1, leaving a batch that fits.
        board.set_head(4, hash_byte(0x04));
        assert!(board.flush_to_db().expect("the retry fits") > 0, "the retry writes the message");
        drop(board);

        let env = crate::db::open_msgboard_db(dir.path()).expect("reopen");
        let (loaded, bad) = crate::db::db_load_all(&env).expect("load");
        assert_eq!(bad, 0);
        assert_eq!(loaded.len(), 1, "the message survived the failed flush and reached disk");
        assert_eq!(loaded[0].hash, small);
    }

    /// The flush batch shares the index's messages instead of copying them.
    ///
    /// Copying builds a second `CheckedPoWMsg` per message, and a vector to
    /// hold them, under the mutex that `add_remote_msgs`, `set_head` and every
    /// RPC read all need. `tests/flush_cost.rs` measures what that costs.
    #[test]
    fn the_flush_batch_shares_its_messages_with_the_index() {
        let (_dir, board) = board_with_db(easy_cfg());
        board.set_ready();
        board.set_head(100, block_hash_one());
        let inserted =
            board.add_local_msg(make_pow_msg(find_nonce(&[0x5D]), &[0x5D])).expect("valid");

        let batch = board.take_flush_batch();

        assert_eq!(batch.current.len(), 1);
        assert!(
            Arc::ptr_eq(&batch.current[0], &inserted),
            "the flush must borrow the board's messages, not copy them",
        );
    }
}
