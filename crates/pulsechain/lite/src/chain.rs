//! The verified header chain.
//!
//! Every block here came from a beacon execution payload whose rebuilt block hash equals its
//! `block_hash`, and descends from the finalized anchor through held parents. `HeaderChain` holds
//! them in a window around the head and tracks the head, the finalized block and why the node is
//! halted, if it is.
//!
//! Bodies are bounded by bytes as well as by count: past the body budget (at most
//! [`MAX_BODY_BYTES`]) the lowest blocks, on any branch, lose their bodies. Such a block still
//! counts for the chain (descent, `BLOCKHASH`, anchor checks), but it is not served: an accessor
//! answers as if it were not held.

use alloy_consensus::{constants::EMPTY_ROOT_HASH, BlockBody, Header, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{map::B256Map, B256};
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
};

/// Headers (and non-canonical siblings) kept behind the head. At least the 256 `BLOCKHASH` needs
/// and the reorg window. The finalized block itself is kept even when it is older.
pub const HEADERS_WINDOW: u64 = 512;

/// How far the head may run past the finalized block before state is no longer served: past
/// this, finality has stalled (or a source withholds it) and the head is not trusted.
pub const MAX_HELD: u64 = 4 * HEADERS_WINDOW;

/// Blocks held at most: the canonical window, one ancestor walk and room for siblings.
pub const MAX_BLOCKS: usize = 3 * HEADERS_WINDOW as usize;

/// The largest body budget: body bytes held at most, by the estimate of `body_bytes`. The window
/// of typical blocks (about 100 KB) needs a fifth of it. A window of blocks filled with calldata
/// to the gas limit would need gigabytes. The node sizes its budget to the box
/// ([`crate::memory::Memory::body_budget`]).
pub const MAX_BODY_BYTES: u64 = 256 << 20;

/// Heap bytes of one transaction's entry in the hash index: the map slot and its location list.
const TX_INDEX_BYTES: usize = 128;

/// The heap bytes `body` holds, estimated: each transaction's encoded length, the enum that
/// carries it and its index entry, and the withdrawals.
pub(crate) fn body_bytes(body: &BlockBody<TxEnvelope>) -> u64 {
    let txs: usize = body
        .transactions
        .iter()
        .map(|t| t.encode_2718_len() + std::mem::size_of::<TxEnvelope>() + TX_INDEX_BYTES)
        .sum();
    let withdrawals = body
        .withdrawals
        .as_ref()
        .map_or(0, |w| w.len() * std::mem::size_of::<alloy_eips::eip4895::Withdrawal>());
    (txs + withdrawals) as u64
}

/// Whether `block` carries an empty body in place of the one its header names. A catch-up walk
/// over the body budget replaces the bodies of its oldest blocks with `Arc::default()`, and the
/// chain then holds them without a body. An empty body passes only for a header that names no
/// transactions and no withdrawals, so it is never served in place of a real one.
fn lacks_body(block: &HeldBlock) -> bool {
    let (body, header) = (&block.body, &block.header);
    (body.transactions.is_empty() && header.transactions_root != EMPTY_ROOT_HASH) ||
        (body.withdrawals.is_none() && header.withdrawals_root.is_some())
}

/// One verified block.
#[derive(Debug, Clone)]
pub struct HeldBlock {
    /// The block hash.
    pub hash: B256,
    /// The header.
    pub header: Header,
    /// The beacon block root it arrived in.
    pub beacon_root: B256,
    /// The body, checked against the header roots.
    pub body: Arc<BlockBody<TxEnvelope>>,
}

/// Why a block was not inserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The parent is not held.
    #[error("parent block is not held")]
    UnknownParent,
    /// The number is not the parent's plus one.
    #[error("block number does not follow its parent")]
    BadNumber,
    /// The block is older than the window.
    #[error("block is outside the window")]
    TooOld,
    /// No such block is held.
    #[error("block is not held")]
    Unknown,
    /// The block does not descend from the finalized block.
    #[error("block does not descend from the finalized block")]
    NotFromFinalized,
}

/// How the finalized anchor compares with what is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStatus {
    /// The same block is held at that number.
    Agree,
    /// A different block is held at that number.
    Mismatch,
    /// That number is not held (older than the window or not reached yet).
    NotHeld,
}

#[derive(Debug, Default)]
struct Inner {
    /// Every held block. One with no entry in `body_sizes` lost its body to the byte budget.
    by_hash: HashMap<B256, HeldBlock>,
    /// The [`body_bytes`] of each held block that keeps its body.
    body_sizes: HashMap<B256, u64>,
    /// The sum of `body_sizes`.
    body_total: u64,
    /// Transaction hash to the blocks with a body that carry it, and its index there.
    txs: B256Map<Vec<(B256, usize)>>,
    canonical: BTreeMap<u64, B256>,
    head: Option<B256>,
    /// The finalized block's number and hash, kept apart from `by_hash` so the descent check
    /// never depends on the block still being held.
    finalized: Option<(u64, B256)>,
    /// Whether `finalized` was confirmed by a beacon quorum at depth (not only seeded). Changed
    /// only together with `finalized`, under the same lock.
    finality_confirmed: bool,
}

impl Inner {
    /// Holds `block` alone, as head and finalized block.
    fn start_at(&mut self, block: HeldBlock) {
        *self = Self::default();
        let (hash, number) = (block.hash, block.header.number);
        self.add(block);
        self.canonical.insert(number, hash);
        self.head = Some(hash);
        self.finalized = Some((number, hash));
    }

    /// Holds `block` with its body, replacing a copy that lost its body.
    fn add(&mut self, block: HeldBlock) {
        self.drop_body(&block.hash);
        let size = body_bytes(&block.body);
        self.body_sizes.insert(block.hash, size);
        self.body_total += size;
        for (i, tx) in block.body.transactions.iter().enumerate() {
            self.txs.entry(*tx.tx_hash()).or_default().push((block.hash, i));
        }
        self.by_hash.insert(block.hash, block);
    }

    /// Stops counting and indexing the body of `hash`, if it has one. The block keeps its
    /// header; the caller drops or replaces the body.
    fn drop_body(&mut self, hash: &B256) {
        let Some(size) = self.body_sizes.remove(hash) else { return };
        self.body_total -= size;
        let Some(b) = self.by_hash.get(hash) else { return };
        for tx in &b.body.transactions {
            if let Some(at) = self.txs.get_mut(tx.tx_hash()) {
                at.retain(|(h, _)| h != hash);
                if at.is_empty() {
                    self.txs.remove(tx.tx_hash());
                }
            }
        }
    }

    /// Drops every held block that `keep` rejects.
    fn retain(&mut self, keep: impl Fn(&Self, &HeldBlock) -> bool) {
        let gone: Vec<B256> =
            self.by_hash.values().filter(|b| !keep(self, b)).map(|b| b.hash).collect();
        for hash in gone {
            self.drop_body(&hash);
            self.by_hash.remove(&hash);
        }
    }

    /// The held block `hash` if it keeps its body: only such a block is served.
    fn served(&self, hash: &B256) -> Option<&HeldBlock> {
        self.body_sizes.contains_key(hash).then(|| self.by_hash.get(hash)).flatten()
    }

    /// Drops the bodies of the lowest blocks, on any branch and above the head too, until the
    /// bodies held fit in `budget`. The head, the finalized block and `kept` keep theirs. A walk
    /// inserts its target last and keeps it: a block above the head loses its body only after
    /// every lower one did.
    fn enforce_body_budget(&mut self, budget: u64, kept: Option<B256>) {
        if self.body_total <= budget {
            return;
        }
        let keep = [self.head, self.finalized.map(|(_, h)| h), kept];
        let mut oldest: Vec<(u64, B256)> = self
            .body_sizes
            .keys()
            .filter(|h| !keep.contains(&Some(**h)))
            .filter_map(|h| self.by_hash.get(h))
            .map(|b| (b.header.number, b.hash))
            .collect();
        oldest.sort_unstable();
        let mut dropped = 0usize;
        for (_, hash) in oldest {
            if self.body_total <= budget {
                break;
            }
            self.drop_body(&hash);
            if let Some(b) = self.by_hash.get_mut(&hash) {
                b.body = Arc::default();
            }
            dropped += 1;
        }
        tracing::debug!(
            dropped,
            held = self.body_total,
            "held bodies over budget; dropped the oldest"
        );
    }
}

/// Why the node does not serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltReason {
    /// The finalized anchor disagrees with a held block.
    AnchorMismatch,
    /// The finalized anchor is above the head, and no source checks the head against it.
    BehindAnchor,
}

impl HaltReason {
    const fn code(reason: Option<Self>) -> u8 {
        match reason {
            None => 0,
            Some(Self::AnchorMismatch) => 1,
            Some(Self::BehindAnchor) => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => None,
            1 => Some(Self::AnchorMismatch),
            _ => Some(Self::BehindAnchor),
        }
    }
}

/// The header chain.
#[derive(Debug)]
pub struct HeaderChain {
    inner: RwLock<Inner>,
    /// Body bytes held at most.
    body_budget: u64,
    /// [`HaltReason::code`] of the halt.
    halted: AtomicU8,
    /// Whether the head has moved since the last seed: a seeded anchor alone is not served.
    live: AtomicBool,
    /// When the head last moved.
    moved_at: parking_lot::Mutex<Option<std::time::Instant>>,
    /// Bumped by every seed: a request that spans one answers nothing.
    epoch: std::sync::atomic::AtomicU64,
}

impl Default for HeaderChain {
    fn default() -> Self {
        Self::with_body_budget(MAX_BODY_BYTES)
    }
}

impl HeaderChain {
    /// An empty chain with the largest body budget, [`MAX_BODY_BYTES`]: no head until
    /// [`Self::seed`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty chain that holds at most `body_budget` bytes of bodies.
    pub fn with_body_budget(body_budget: u64) -> Self {
        Self {
            inner: RwLock::default(),
            body_budget,
            halted: AtomicU8::default(),
            live: AtomicBool::default(),
            moved_at: parking_lot::Mutex::default(),
            epoch: std::sync::atomic::AtomicU64::default(),
        }
    }

    /// Body bytes held at most.
    pub const fn body_budget(&self) -> u64 {
        self.body_budget
    }

    /// Starts the chain at the verified finalized anchor.
    pub fn seed(&self, block: HeldBlock) {
        let mut g = self.inner.write();
        self.start_epoch();
        let (hash, number) = (block.hash, block.header.number);
        g.add(block);
        g.canonical.insert(number, hash);
        g.head = Some(hash);
        g.finalized = Some((number, hash));
        g.finality_confirmed = false;
        g.enforce_body_budget(self.body_budget, None);
    }

    /// Drops everything held and starts again at `block`, under one write lock.
    pub fn reseed(&self, block: HeldBlock) {
        let mut g = self.inner.write();
        self.start_epoch();
        g.start_at(block);
    }

    /// Bumps the epoch and clears `live`. The caller holds the write lock: `set_head` stores
    /// `live` under it, so a head move cannot mark the new anchor live.
    fn start_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.live.store(false, Ordering::SeqCst);
    }

    /// [`Self::reseed`], unless the chain was re-seeded since `epoch`, `block` is below the
    /// finalized number, or `block` is already canonical. A re-seed waits seconds for its
    /// confirmation: it must not undo a head or a re-seed that landed meanwhile. Returns whether
    /// it re-seeded.
    pub fn reseed_since(&self, epoch: u64, block: HeldBlock) -> bool {
        let mut g = self.inner.write();
        let number = block.header.number;
        if self.epoch() != epoch ||
            g.finalized.is_some_and(|(n, _)| number < n) ||
            g.canonical.get(&number) == Some(&block.hash)
        {
            return false;
        }
        self.start_epoch();
        g.start_at(block);
        true
    }

    /// Marks the verified `block` finalized after a beacon quorum confirmed it at depth. One
    /// write section: the canonical map must hold its hash at its number, and it must not be
    /// below the current finalized number. A block pruned from the window, or one that lost its
    /// body, is held again with `block`'s body, so finality may lag the head as far as the map
    /// reaches ([`MAX_HELD`]) and the finalized block is still served.
    pub fn confirm_finalized(&self, block: &HeldBlock) -> bool {
        let (number, hash) = (block.header.number, block.hash);
        let mut g = self.inner.write();
        if g.canonical.get(&number) != Some(&hash) || g.finalized.is_some_and(|(n, _)| number < n) {
            return false;
        }
        g.finalized = Some((number, hash));
        g.finality_confirmed = true;
        if g.served(&hash).is_none() {
            g.add(block.clone());
            g.enforce_body_budget(self.body_budget, None);
        }
        true
    }

    /// Whether finality has been confirmed since the last seed (the `safe` and `finalized`
    /// tags are served only then).
    pub fn finality_confirmed(&self) -> bool {
        self.inner.read().finality_confirmed
    }

    /// The finalized block's number, held or not.
    pub fn finalized_number(&self) -> Option<u64> {
        self.inner.read().finalized.map(|(n, _)| n)
    }

    /// Whether the chain has been seeded.
    pub fn is_seeded(&self) -> bool {
        self.inner.read().head.is_some()
    }

    /// How many blocks are held.
    pub fn held(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    /// Whether the head is more than [`MAX_HELD`] blocks past the finalized block.
    pub fn finality_stalled(&self) -> bool {
        let g = self.inner.read();
        let head = g.head.and_then(|h| g.by_hash.get(&h)).map(|b| b.header.number);
        matches!((head, g.finalized), (Some(h), Some((f, _))) if h > f.saturating_add(MAX_HELD))
    }

    /// The highest number of any held block, canonical or not.
    pub fn highest(&self) -> Option<u64> {
        self.inner.read().by_hash.values().map(|b| b.header.number).max()
    }

    /// Whether a block with `hash` is held.
    pub fn contains(&self, hash: &B256) -> bool {
        self.inner.read().by_hash.contains_key(hash)
    }

    /// Inserts a verified block whose parent is held. It does not move the head. A block whose
    /// body a walk dropped (see `lacks_body`) is held without one.
    ///
    /// At [`MAX_BLOCKS`] it first drops every block off the canonical chain except the
    /// finalized one, so a walk in progress can lose its parent and fail.
    pub fn insert(&self, block: HeldBlock) -> Result<(), ChainError> {
        let mut g = self.inner.write();
        if g.by_hash.len() >= MAX_BLOCKS {
            g.retain(|i, b| {
                i.canonical.get(&b.header.number) == Some(&b.hash) ||
                    i.finalized.is_some_and(|(_, f)| f == b.hash)
            });
            tracing::debug!(
                held = g.by_hash.len(),
                "held blocks at the cap; dropped side branches"
            );
        }
        let head_number = g.head.and_then(|h| g.by_hash.get(&h)).map_or(0, |b| b.header.number);
        let parent = g.by_hash.get(&block.header.parent_hash).ok_or(ChainError::UnknownParent)?;
        if parent.header.number.checked_add(1) != Some(block.header.number) {
            return Err(ChainError::BadNumber);
        }
        if block.header.number.saturating_add(HEADERS_WINDOW) < head_number {
            return Err(ChainError::TooOld);
        }
        // Nothing new at or below the finalized number: only the finalized block lives there.
        if let Some((fin_number, fin_hash)) = g.finalized &&
            block.header.number <= fin_number &&
            block.hash != fin_hash
        {
            return Err(ChainError::NotFromFinalized);
        }
        let hash = block.hash;
        if lacks_body(&block) {
            // Held without a body; a body already held stays.
            g.by_hash.entry(hash).or_insert(block);
        } else {
            g.add(block);
            g.enforce_body_budget(self.body_budget, Some(hash));
        }
        Ok(())
    }

    /// Makes `hash` the head, re-pointing the canonical chain at its ancestry (a reorg when it
    /// is not a child of the old head). Prunes what fell out of the window.
    ///
    /// The new head must descend from the finalized block: its chain must hold the finalized
    /// hash at the finalized number. Otherwise nothing changes. A block that lost its body is
    /// not a head ([`ChainError::Unknown`]).
    pub fn set_head(&self, hash: B256) -> Result<(), ChainError> {
        let mut g = self.inner.write();
        let new = g.served(&hash).ok_or(ChainError::Unknown)?.header.number;
        // Walk back until the canonical chain already agrees, collecting what changes.
        let mut changed: Vec<(u64, B256)> = Vec::new();
        let mut cur = hash;
        // Whether the walk met the canonical chain (rather than running out of held blocks).
        let mut connected = false;
        while let Some(b) = g.by_hash.get(&cur) {
            let (n, parent) = (b.header.number, b.header.parent_hash);
            if g.canonical.get(&n) == Some(&cur) {
                connected = true;
                break;
            }
            changed.push((n, cur));
            cur = parent;
        }
        if let Some((fin_number, fin_hash)) = g.finalized {
            if new < fin_number {
                return Err(ChainError::NotFromFinalized);
            }
            let at_fin =
                changed.iter().find(|(n, _)| *n == fin_number).map(|(_, h)| *h).or_else(|| {
                    // Below the changed part the canonical chain stays as it is, but only when
                    // the new branch met it: a branch that runs out of held blocks has not
                    // shown where it joins.
                    let lowest_changed = changed.last().map_or(u64::MAX, |(n, _)| *n);
                    (connected && fin_number < lowest_changed)
                        .then(|| g.canonical.get(&fin_number).copied())
                        .flatten()
                });
            // Fails closed: a finalized hash that cannot be resolved rejects the head.
            if at_fin != Some(fin_hash) {
                return Err(ChainError::NotFromFinalized);
            }
        }
        g.canonical.retain(|n, _| *n <= new);
        for (n, h) in changed {
            g.canonical.insert(n, h);
        }
        let old = g.head.and_then(|h| g.by_hash.get(&h)).map(|b| b.header.number);
        g.head = Some(hash);
        self.live.store(true, Ordering::SeqCst);
        // Only a forward move counts as the head moving (a short reorg back does not).
        if old.is_none_or(|o| new > o) {
            *self.moved_at.lock() = Some(std::time::Instant::now());
        }
        // Full blocks: the window plus the finalized block. The canonical number-to-hash map
        // (small) is kept from the finalized number up, so an anchor anywhere in that range is
        // still compared; it is capped at MAX_HELD, where state stops being served anyway.
        let floor = new.saturating_sub(HEADERS_WINDOW);
        let fin = g.finalized;
        let map_floor = fin.map_or(floor, |(n, _)| n.min(floor)).max(new.saturating_sub(MAX_HELD));
        g.retain(|_, b| b.header.number >= floor || fin.is_some_and(|(_, f)| f == b.hash));
        g.canonical.retain(|n, h| *n >= map_floor || fin == Some((*n, *h)));
        g.enforce_body_budget(self.body_budget, None);
        Ok(())
    }

    /// The head, if any.
    pub fn head(&self) -> Option<HeldBlock> {
        let g = self.inner.read();
        g.head.and_then(|h| g.served(&h)).cloned()
    }

    /// The finalized block, if held with its body.
    pub fn finalized(&self) -> Option<HeldBlock> {
        let g = self.inner.read();
        g.finalized.and_then(|(_, h)| g.served(&h)).cloned()
    }

    /// Marks a held block finalized. Finality never moves back to a lower number.
    pub fn set_finalized(&self, hash: B256) {
        let mut g = self.inner.write();
        if let Some(n) = g.by_hash.get(&hash).map(|b| b.header.number) &&
            g.finalized.is_none_or(|(old, _)| n >= old)
        {
            if g.finalized != Some((n, hash)) {
                g.finality_confirmed = false;
            }
            g.finalized = Some((n, hash));
        }
    }

    /// The canonical block at `number`, if held with its body.
    pub fn by_number(&self, number: u64) -> Option<HeldBlock> {
        let g = self.inner.read();
        g.canonical.get(&number).and_then(|h| g.served(h)).cloned()
    }

    /// The canonical block that carries transaction `hash`, with the transaction's index.
    pub fn find_tx(&self, hash: &B256) -> Option<(HeldBlock, usize)> {
        let g = self.inner.read();
        g.txs.get(hash)?.iter().find_map(|(block, i)| {
            let b = g.served(block)?;
            (g.canonical.get(&b.header.number) == Some(block)).then(|| (b.clone(), *i))
        })
    }

    /// Any held block (canonical or not) by hash, if held with its body.
    pub fn by_hash(&self, hash: &B256) -> Option<HeldBlock> {
        self.inner.read().served(hash).cloned()
    }

    /// The hash of the ancestor at `number` of the held block `of`. For a canonical `of` it is
    /// the canonical hash there; otherwise parent hashes are walked, so a block off the canonical
    /// chain gets its own ancestry. `None` when `number` is not below `of` or is not reached.
    pub fn ancestor_hash(&self, of: &B256, number: u64) -> Option<B256> {
        let g = self.inner.read();
        let mut cur = g.by_hash.get(of)?;
        if number >= cur.header.number {
            return None;
        }
        // `BLOCKHASH` asks this once per opcode: a walk of up to 256 parents each time costs a
        // million lookups in one call. The canonical map is one chain, so it answers at once.
        // Below the map, the lowest held block's header still names its parent: walk to it.
        if g.canonical.get(&cur.header.number) == Some(of) &&
            let Some(h) = g.canonical.get(&number)
        {
            return Some(*h);
        }
        while cur.header.number - 1 > number {
            cur = g.by_hash.get(&cur.header.parent_hash)?;
        }
        Some(cur.header.parent_hash)
    }

    /// Whether `hash` is on the canonical chain.
    pub fn is_canonical(&self, hash: &B256) -> bool {
        let g = self.inner.read();
        g.by_hash.get(hash).is_some_and(|b| g.canonical.get(&b.header.number) == Some(hash))
    }

    /// The lowest number from which every canonical block up to the head is held with its body.
    /// The canonical map reaches lower than the held blocks while finality lags, and it always
    /// keeps the finalized number, so its lowest key may name a block that is gone.
    pub fn lowest(&self) -> Option<u64> {
        let g = self.inner.read();
        let head = g.head.and_then(|h| g.by_hash.get(&h))?.header.number;
        let mut lowest = None;
        let mut want = head;
        for (n, h) in g.canonical.range(..=head).rev() {
            if *n != want || g.served(h).is_none() {
                break;
            }
            lowest = Some(*n);
            let Some(below) = n.checked_sub(1) else { break };
            want = below;
        }
        lowest
    }

    /// Compares an anchor block with the canonical chain.
    ///
    /// Fails closed: a number inside the held run above the finalized one, not above the head,
    /// that is missing from the canonical map is a mismatch, never "not held".
    pub fn check_anchor(&self, number: u64, hash: &B256) -> AnchorStatus {
        let g = self.inner.read();
        match g.canonical.get(&number) {
            Some(h) if h == hash => AnchorStatus::Agree,
            Some(_) => AnchorStatus::Mismatch,
            None => {
                let head = g.head.and_then(|h| g.by_hash.get(&h)).map(|b| b.header.number);
                // Past MAX_HELD the run above the finalized number starts higher: what lies
                // between was pruned, so there is nothing to compare.
                let run_floor = g.finalized.and_then(|(f, _)| {
                    g.canonical.range(f.saturating_add(1)..).next().map(|(n, _)| *n)
                });
                match (run_floor, head) {
                    (Some(lo), Some(h)) if number >= lo && number <= h => AnchorStatus::Mismatch,
                    _ => AnchorStatus::NotHeld,
                }
            }
        }
    }

    /// Whether the head has moved past the seeded anchor (the RPC serves nothing before).
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// How long since the head last moved, if it ever did.
    pub fn since_head_moved(&self) -> Option<std::time::Duration> {
        self.moved_at.lock().map(|t| t.elapsed())
    }

    /// The seed epoch (changes on every seed and re-seed).
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Halts the node for `reason`, or clears the halt with `None`.
    pub fn set_halted(&self, reason: Option<HaltReason>) {
        self.halted.store(HaltReason::code(reason), Ordering::SeqCst);
    }

    /// Whether the node is halted.
    pub fn halted(&self) -> bool {
        self.halt_reason().is_some()
    }

    /// Why the node is halted, if it is.
    pub fn halt_reason(&self) -> Option<HaltReason> {
        HaltReason::from_code(self.halted.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
pub(crate) fn test_block(number: u64, parent: B256, salt: u8) -> HeldBlock {
    let header =
        Header { number, parent_hash: parent, extra_data: vec![salt].into(), ..Default::default() };
    HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::repeat_byte(salt),
        body: Arc::new(BlockBody::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extend(c: &HeaderChain, from: &HeldBlock, n: u64, salt: u8) -> Vec<HeldBlock> {
        let mut out = vec![];
        let mut parent = from.clone();
        for _ in 0..n {
            let b = test_block(parent.header.number + 1, parent.hash, salt);
            c.insert(b.clone()).unwrap();
            out.push(b.clone());
            parent = b;
        }
        out
    }

    /// A block whose body carries one transaction with `input` bytes of calldata.
    fn heavy_block(parent: &HeldBlock, body: &Arc<BlockBody<TxEnvelope>>) -> HeldBlock {
        let mut b = test_block(parent.header.number + 1, parent.hash, 1);
        b.body = body.clone();
        b
    }

    fn heavy_body(input: usize) -> Arc<BlockBody<TxEnvelope>> {
        let tx = alloy_consensus::TxLegacy { input: vec![0; input].into(), ..Default::default() };
        let tx = alloy_consensus::Signed::new_unhashed(
            tx,
            alloy_primitives::Signature::test_signature(),
        );
        Arc::new(BlockBody { transactions: vec![TxEnvelope::Legacy(tx)], ..Default::default() })
    }

    /// Calldata bytes in the bodies the chain holds.
    fn held_calldata(c: &HeaderChain) -> u64 {
        use alloy_consensus::Transaction;
        let g = c.inner.read();
        g.by_hash.values().flat_map(|b| &b.body.transactions).map(|t| t.input().len() as u64).sum()
    }

    /// A budget sized to a small box holds that much and no more.
    #[test]
    fn the_body_budget_is_the_one_given() {
        let budget = 32 << 20;
        let c = HeaderChain::with_body_budget(budget);
        assert_eq!((c.body_budget(), HeaderChain::new().body_budget()), (budget, MAX_BODY_BYTES));
        let body = heavy_body(1 << 20);
        let mut last = heavy_block(&test_block(999, B256::ZERO, 0), &body);
        c.seed(last.clone());
        for _ in 0..100 {
            last = heavy_block(&last, &body);
            c.insert(last.clone()).unwrap();
            c.set_head(last.hash).unwrap();
        }
        let total = c.inner.read().body_total;
        assert!(total <= budget && total > budget / 2, "{} MiB held", total >> 20);
        // The default budget would have kept 100 such bodies.
        assert!(100 * body_bytes(&body) < MAX_BODY_BYTES);
    }

    #[test]
    fn calldata_heavy_blocks_stay_within_the_body_budget() {
        let c = HeaderChain::new();
        let body = heavy_body(1 << 20);
        let anchor = heavy_block(&test_block(999, B256::ZERO, 0), &body);
        c.seed(anchor.clone());
        let mut blocks = vec![anchor];
        for _ in 0..600 {
            let b = heavy_block(blocks.last().unwrap(), &body);
            c.insert(b.clone()).unwrap();
            c.set_head(b.hash).unwrap();
            blocks.push(b);
            assert!(held_calldata(&c) <= 256 << 20, "{} MiB held", held_calldata(&c) >> 20);
        }
        let g = c.inner.read();
        assert!(g.body_total <= MAX_BODY_BYTES && g.body_total > MAX_BODY_BYTES / 2);
        assert_eq!(g.body_total, g.by_hash.values().map(|b| body_bytes(&b.body)).sum::<u64>());
        drop(g);
        let head = blocks.last().unwrap();
        assert_eq!(c.head().unwrap().hash, head.hash);
        assert_eq!(c.finalized().unwrap().body, body, "the finalized block keeps its body");
        assert_eq!(c.by_number(head.header.number - 1).unwrap().body, body);
        // An old block lost its body: it is not served, but it still counts for the chain.
        let old = &blocks[200];
        assert!(c.by_number(old.header.number).is_none());
        assert!(c.by_hash(&old.hash).is_none());
        assert!(c.contains(&old.hash) && c.is_canonical(&old.hash));
        assert_eq!(c.ancestor_hash(&head.hash, old.header.number), Some(old.hash));
        assert_eq!(c.check_anchor(old.header.number, &old.hash), AnchorStatus::Agree);
        let lowest = c.lowest().unwrap();
        assert!(lowest > old.header.number && c.by_number(lowest).is_some(), "{lowest}");
        assert!(c.by_number(lowest - 1).is_none());
        assert_eq!(c.set_head(old.hash), Err(ChainError::Unknown), "not a head without a body");
        // Finality may move onto it: the confirmed block gets its body back.
        assert!(c.confirm_finalized(old));
        assert!(c.finalized().is_some_and(|b| b.body == body), "the finalized block is served");
        assert!(c.inner.read().body_total <= MAX_BODY_BYTES);
        // Inserting a block again gives its body back.
        let next = &blocks[201];
        assert!(c.by_hash(&next.hash).is_none());
        c.insert(next.clone()).unwrap();
        assert!(c.by_hash(&next.hash).is_some_and(|b| b.body == body));
    }

    /// Heavy blocks from `parent` up, each inserted as the head.
    fn grow_heavy(c: &HeaderChain, blocks: &mut Vec<HeldBlock>, n: usize) {
        let body = heavy_body(2 << 20);
        for _ in 0..n {
            let b = heavy_block(blocks.last().unwrap(), &body);
            c.insert(b.clone()).unwrap();
            c.set_head(b.hash).unwrap();
            blocks.push(b);
        }
    }

    #[test]
    fn bodies_above_a_head_moved_back_stay_within_the_budget() {
        let c = HeaderChain::new();
        let mut blocks = vec![heavy_block(&test_block(999, B256::ZERO, 0), &heavy_body(2 << 20))];
        c.seed(blocks[0].clone());
        grow_heavy(&c, &mut blocks, 200);
        // Back to the lowest block that keeps its body: every other body is above the head.
        let back = blocks[(c.lowest().unwrap() - 1000) as usize].clone();
        c.set_head(back.hash).unwrap();
        let mut side = test_block(back.header.number + 1, back.hash, 2);
        side.body = heavy_body(2 << 20);
        c.insert(side.clone()).unwrap();
        assert!(
            c.inner.read().body_total <= MAX_BODY_BYTES,
            "{} MiB",
            c.inner.read().body_total >> 20
        );
        assert!(c.by_hash(&side.hash).is_some(), "the block just inserted keeps its body");
        assert_eq!(c.head().unwrap().hash, back.hash);
        assert_eq!(c.finalized().unwrap().hash, blocks[0].hash);
        c.set_head(side.hash).unwrap();
    }

    #[test]
    fn a_walk_above_the_head_stays_within_the_body_budget() {
        let c = HeaderChain::new();
        let body = heavy_body(2 << 20);
        let mut blocks = vec![heavy_block(&test_block(999, B256::ZERO, 0), &body)];
        c.seed(blocks[0].clone());
        grow_heavy(&c, &mut blocks, 100);
        // A catch-up walk inserts every block up to its target before the head moves.
        for _ in 0..300 {
            let b = heavy_block(blocks.last().unwrap(), &body);
            c.insert(b.clone()).unwrap();
            blocks.push(b);
            let total = c.inner.read().body_total;
            assert!(total <= MAX_BODY_BYTES, "{} MiB", total >> 20);
        }
        let target = blocks.last().unwrap();
        c.set_head(target.hash).unwrap();
        assert_eq!(c.head().unwrap().body, body);
        assert_eq!(c.by_number(target.header.number - 1).unwrap().body, body);
    }

    #[test]
    fn a_block_the_walk_left_without_a_body_is_not_served() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        // A beacon block: its header names transactions and withdrawals.
        let mut header = test_block(1001, anchor.hash, 1).header;
        header.transactions_root = B256::repeat_byte(1);
        header.withdrawals_root = Some(alloy_consensus::constants::EMPTY_WITHDRAWALS);
        let body = BlockBody {
            transactions: vec![tx(1)],
            withdrawals: Some(Default::default()),
            ..Default::default()
        };
        let full = HeldBlock {
            hash: header.hash_slow(),
            header,
            beacon_root: B256::ZERO,
            body: Arc::new(body),
        };
        let bare = HeldBlock { body: Arc::default(), ..full.clone() };
        c.insert(bare.clone()).unwrap();
        assert!(c.contains(&bare.hash));
        assert!(c.by_hash(&bare.hash).is_none(), "an empty body is not the block's body");
        assert_eq!(c.set_head(bare.hash), Err(ChainError::Unknown));
        assert_eq!(c.inner.read().body_total, 0);
        // A child still connects to it, and the full block gives the body.
        let child = test_block(1002, bare.hash, 1);
        c.insert(child.clone()).unwrap();
        c.insert(full.clone()).unwrap();
        assert_eq!(c.by_hash(&full.hash).unwrap().body, full.body);
        // A bare copy never replaces a body that is held.
        c.insert(bare).unwrap();
        assert_eq!(c.by_hash(&full.hash).unwrap().body, full.body);
        c.set_head(child.hash).unwrap();
        assert_eq!(c.by_number(1001).unwrap().body, full.body);
    }

    #[test]
    fn the_readme_states_the_body_budget() {
        let readme = include_str!("../README.md").split_whitespace().collect::<Vec<_>>().join(" ");
        // The chain holds up to the budget, and the ancestor walk holds up to it again before it
        // inserts (`Follower::advance`).
        use crate::memory::{BODY_PERCENT, MIN_BODY_BYTES};
        let (min, max) = (MIN_BODY_BYTES >> 20, MAX_BODY_BYTES >> 20);
        let figure = format!(
            "{BODY_PERCENT}% of memory, at least {min} MiB and at most {max} MiB ({max} MiB when \
             memory is not found), by the node's estimate of their size, and up to as much again \
             while the node walks to a new head"
        );
        assert!(readme.contains(&figure), "the README lacks `{figure}`");
    }

    #[test]
    fn body_bytes_counts_calldata_and_each_transaction() {
        let empty = body_bytes(&BlockBody::default());
        assert_eq!(empty, 0);
        let one = body_bytes(&heavy_body(0));
        assert!(one > std::mem::size_of::<TxEnvelope>() as u64, "{one}");
        // The calldata, plus longer RLP length prefixes.
        let extra = body_bytes(&heavy_body(1 << 20)) - one - (1 << 20);
        assert!((1..=8).contains(&extra), "{extra}");
    }

    fn tx(nonce: u64) -> TxEnvelope {
        let tx = alloy_consensus::TxLegacy { nonce, ..Default::default() };
        let sig = alloy_primitives::Signature::test_signature();
        TxEnvelope::Legacy(alloy_consensus::Signed::new_unhashed(tx, sig))
    }

    fn block_with(parent: &HeldBlock, salt: u8, txs: Vec<TxEnvelope>) -> HeldBlock {
        let mut b = test_block(parent.header.number + 1, parent.hash, salt);
        b.body = Arc::new(BlockBody { transactions: txs, ..Default::default() });
        b
    }

    #[test]
    fn a_transaction_is_found_only_in_the_canonical_chain() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let (shared, only_a, only_b) = (tx(1), tx(2), tx(3));
        let a = block_with(&anchor, 1, vec![only_a.clone(), shared.clone()]);
        let b = block_with(&anchor, 2, vec![shared.clone(), only_b.clone()]);
        c.insert(a.clone()).unwrap();
        c.insert(b.clone()).unwrap();
        c.set_head(a.hash).unwrap();
        let found = |t: &TxEnvelope| c.find_tx(t.tx_hash()).map(|(blk, i)| (blk.hash, i));
        assert_eq!(found(&only_a), Some((a.hash, 0)));
        assert_eq!(found(&shared), Some((a.hash, 1)));
        assert_eq!(found(&only_b), None, "a side branch is not served");
        assert_eq!(found(&tx(4)), None);
        // A reorg moves the answer.
        c.set_head(b.hash).unwrap();
        assert_eq!(found(&shared), Some((b.hash, 0)));
        assert_eq!(found(&only_a), None);
        // Pruned out of the window: gone from the index too.
        let mut cur = b;
        for _ in 0..=HEADERS_WINDOW {
            cur = extend(&c, &cur, 1, 3).remove(0);
            c.set_head(cur.hash).unwrap();
        }
        c.set_finalized(cur.hash);
        c.set_head(cur.hash).unwrap();
        assert_eq!(found(&shared), None);
        assert!(c.inner.read().txs.is_empty(), "the index keeps nothing that was pruned");
        // A re-seed starts the index again.
        c.reseed(block_with(&cur, 4, vec![only_b.clone()]));
        assert_eq!(found(&only_b).map(|(_, i)| i), Some(0));
    }

    #[test]
    fn follows_and_rejects_unknown_parents() {
        let c = HeaderChain::new();
        assert!(c.head().is_none());
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        assert_eq!(c.head().unwrap().header.number, 1000);
        let blocks = extend(&c, &anchor, 3, 1);
        c.set_head(blocks[2].hash).unwrap();
        assert_eq!(c.head().unwrap().header.number, 1003);
        assert_eq!(c.by_number(1002).unwrap().hash, blocks[1].hash);
        assert!(c.is_canonical(&blocks[0].hash));
        // An orphan is refused.
        let orphan = test_block(1004, B256::repeat_byte(9), 7);
        assert_eq!(c.insert(orphan), Err(ChainError::UnknownParent));
        // A wrong number is refused.
        let skip = test_block(1010, blocks[2].hash, 7);
        assert_eq!(c.insert(skip), Err(ChainError::BadNumber));
        // Insert alone does not move the head.
        let more = extend(&c, &blocks[2], 1, 1);
        assert_eq!(c.head().unwrap().hash, blocks[2].hash);
        assert!(c.by_number(1004).is_none());
        assert!(c.contains(&more[0].hash));
    }

    #[test]
    fn a_reorg_switches_the_canonical_chain() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 3, 1);
        c.set_head(a[2].hash).unwrap();
        // A competing branch from 1001 that becomes longer.
        let b = extend(&c, &a[0], 3, 2);
        c.set_head(b[2].hash).unwrap();
        assert_eq!(c.head().unwrap().header.number, 1004);
        assert_eq!(c.by_number(1002).unwrap().hash, b[0].hash);
        assert_eq!(c.by_number(1001).unwrap().hash, a[0].hash);
        assert!(!c.is_canonical(&a[1].hash));
        // The old branch is still held for the reorg window.
        assert!(c.contains(&a[2].hash));
        // Switching back to a shorter head drops the numbers above it.
        c.set_head(a[1].hash).unwrap();
        assert!(c.by_number(1004).is_none());
        assert_eq!(c.by_number(1002).unwrap().hash, a[1].hash);
    }

    #[test]
    fn a_head_that_does_not_descend_from_finalized_is_rejected() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 3, 1);
        // A branch from 1001, held before finality moves to 1002.
        let b = extend(&c, &a[0], 4, 2);
        c.set_head(a[2].hash).unwrap();
        c.set_finalized(a[1].hash);
        assert_eq!(c.set_head(b[3].hash), Err(ChainError::NotFromFinalized));
        assert_eq!(c.head().unwrap().hash, a[2].hash, "the head did not move");
        assert_eq!(c.by_number(1002).unwrap().hash, a[1].hash, "canonical is untouched");
        assert!(c.by_number(1005).is_none());
        // A head below the finalized block is rejected too.
        assert_eq!(c.set_head(a[0].hash), Err(ChainError::NotFromFinalized));
        // A head that descends from finalized is fine.
        let more = extend(&c, &a[2], 1, 3);
        c.set_head(more[0].hash).unwrap();
        assert_eq!(c.head().unwrap().header.number, 1004);
    }

    #[test]
    fn a_fork_below_finalized_is_rejected_after_the_window_passes_finalized() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 5, 1);
        // A long fork from 1001, held before finality moves.
        let fork = extend(&c, &a[0], 600, 2);
        c.set_head(a[4].hash).unwrap();
        c.set_finalized(a[4].hash);
        // The head runs far past the finalized 1005 with no new finalized update.
        let mut cur = a[4].clone();
        for _ in 0..(HEADERS_WINDOW + 20) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            cur = b;
        }
        assert_eq!(c.finalized().map(|b| b.hash), Some(a[4].hash), "finalized is kept");
        assert_eq!(
            c.set_head(fork.last().unwrap().hash),
            Err(ChainError::NotFromFinalized),
            "a fork from below finalized"
        );
        assert_eq!(c.head().unwrap().hash, cur.hash);
    }

    #[test]
    fn a_finality_stall_keeps_memory_bounded_and_stops_serving_past_the_cap() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let mut cur = anchor.clone();
        let mut stalled_at = None;
        for _ in 0..(10 * HEADERS_WINDOW) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            cur = b;
            if stalled_at.is_none() && c.finality_stalled() {
                stalled_at = Some(cur.header.number);
            }
        }
        assert!(c.held() as u64 <= HEADERS_WINDOW + 2, "{} blocks held", c.held());
        assert_eq!(c.finalized().unwrap().hash, anchor.hash, "only the finalized block is pinned");
        assert_eq!(stalled_at, Some(1000 + MAX_HELD + 1), "stalled just past the cap");

        // The descent check still holds once the blocks between finalized and the window are
        // gone: a fork from below finalized is refused.
        let c = HeaderChain::new();
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 5, 1);
        // Short enough that the fork and the window stay under the cap on held blocks.
        let fork = extend(&c, &a[0], HEADERS_WINDOW + 400, 2);
        c.set_head(a[4].hash).unwrap();
        c.set_finalized(a[4].hash);
        let mut cur = a[4].clone();
        for _ in 0..(2 * HEADERS_WINDOW) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            cur = b;
        }
        assert_eq!(c.set_head(fork.last().unwrap().hash), Err(ChainError::NotFromFinalized));
        assert_eq!(c.head().unwrap().hash, cur.hash);
    }

    #[test]
    fn blocks_off_the_canonical_chain_are_dropped_at_the_cap() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 10, 1);
        c.set_head(a[9].hash).unwrap();
        // Branches that never become the head: siblings at every height and runs above it.
        let mut refused = 0;
        for salt in 2..8 {
            let mut parent = a[4].clone();
            for _ in 0..400 {
                let b = test_block(parent.header.number + 1, parent.hash, salt);
                match c.insert(b.clone()) {
                    Ok(()) => {}
                    Err(e) => {
                        assert_eq!(e, ChainError::UnknownParent);
                        refused += 1;
                        break;
                    }
                }
                assert!(c.held() <= MAX_BLOCKS, "{} blocks held", c.held());
                parent = b;
            }
        }
        assert_eq!(refused, 1, "the branch whose parent was dropped");
        assert_eq!(c.head().unwrap().hash, a[9].hash);
        assert!((1000..=1010).all(|n| c.by_number(n).is_some()), "canonical blocks are kept");
        assert!(c.finalized().is_some());
        // The chain still follows its head.
        let next = extend(&c, &a[9], 1, 9);
        c.set_head(next[0].hash).unwrap();
        assert_eq!(c.head().unwrap().header.number, 1011);
    }

    #[test]
    fn an_anchor_between_finalized_and_the_block_floor_is_still_checked() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let mut cur = anchor;
        let mut at_1500 = B256::ZERO;
        for _ in 0..(3 * HEADERS_WINDOW) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            if b.header.number == 1500 {
                at_1500 = b.hash;
            }
            cur = b;
        }
        assert!(c.by_hash(&at_1500).is_none(), "the block itself is pruned");
        assert_eq!(c.check_anchor(1500, &B256::repeat_byte(7)), AnchorStatus::Mismatch);
        assert_eq!(c.check_anchor(1500, &at_1500), AnchorStatus::Agree);
        // Above the head is not reached yet; the head itself is held.
        assert_eq!(c.check_anchor(cur.header.number + 1, &B256::ZERO), AnchorStatus::NotHeld);
        assert_eq!(c.check_anchor(cur.header.number, &cur.hash), AnchorStatus::Agree);
    }

    #[test]
    fn an_anchor_in_the_pruned_gap_past_the_held_cap_is_not_held() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let mut cur = anchor.clone();
        let mut hashes = HashMap::new();
        for _ in 0..(MAX_HELD + 600) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            hashes.insert(b.header.number, b.hash);
            cur = b;
        }
        // The map keeps the finalized 1000 and a run from head - MAX_HELD up.
        let low = cur.header.number - MAX_HELD;
        assert_eq!(low, 1600);
        for n in [1001, 1300, low - 1] {
            assert_eq!(c.check_anchor(n, &hashes[&n]), AnchorStatus::NotHeld, "true block {n}");
        }
        assert_eq!(c.check_anchor(low, &hashes[&low]), AnchorStatus::Agree);
        assert_eq!(c.check_anchor(low, &B256::repeat_byte(7)), AnchorStatus::Mismatch);
        assert_eq!(c.check_anchor(1000, &anchor.hash), AnchorStatus::Agree);
        assert_eq!(c.check_anchor(1000, &B256::repeat_byte(7)), AnchorStatus::Mismatch);
        // A number missing inside the run is still a mismatch.
        c.inner.write().canonical.remove(&(low + 10));
        assert_eq!(c.check_anchor(low + 10, &hashes[&(low + 10)]), AnchorStatus::Mismatch);
    }

    #[test]
    fn inserts_at_or_below_finalized_are_refused() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 3, 1);
        c.set_head(a[2].hash).unwrap();
        c.set_finalized(a[1].hash);
        assert_eq!(c.insert(test_block(1002, a[0].hash, 9)), Err(ChainError::NotFromFinalized));
        assert_eq!(c.insert(test_block(1001, anchor.hash, 9)), Err(ChainError::NotFromFinalized));
        assert!(c.insert(test_block(1003, a[1].hash, 9)).is_ok());
    }

    #[test]
    fn the_lowest_number_has_every_block_up_to_the_head_held_while_finality_lags() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        assert_eq!(c.lowest(), Some(1000));
        let mut cur = anchor;
        for _ in 0..700 {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            cur = b;
        }
        let head = cur.header.number;
        // The finalized block 1000 is pinned, but 1001 up to the window are gone.
        assert_eq!(c.lowest(), Some(head - HEADERS_WINDOW));
        assert!((head - HEADERS_WINDOW..=head).all(|n| c.by_number(n).is_some()));
        assert!(c.by_number(head - HEADERS_WINDOW - 1).is_none());
    }

    #[test]
    fn the_window_prunes_old_headers() {
        let c = HeaderChain::new();
        let mut cur = test_block(0, B256::ZERO, 0);
        c.seed(cur.clone());
        for _ in 0..(HEADERS_WINDOW + 40) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            c.set_finalized(b.hash);
            cur = b;
        }
        assert_eq!(c.lowest().unwrap(), 40);
        assert!(c.by_number(10).is_none());
        assert!(c.by_number(cur.header.number).is_some());
    }

    #[test]
    fn a_conditional_reseed_keeps_what_landed_since_its_epoch() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 5, 1);
        c.set_head(a[4].hash).unwrap();
        let epoch = c.epoch();
        // Already canonical: nothing to do.
        assert!(!c.reseed_since(epoch, a[2].clone()));
        assert_eq!(c.head().unwrap().hash, a[4].hash);
        // A newer re-seed landed since the epoch was read.
        c.reseed(a[3].clone());
        assert!(!c.reseed_since(epoch, test_block(1009, B256::repeat_byte(1), 7)));
        assert_eq!(c.head().unwrap().hash, a[3].hash);
        // Below the finalized number.
        assert!(!c.reseed_since(c.epoch(), test_block(1002, a[0].hash, 7)));
        assert_eq!(c.finalized_number(), Some(1004));
        // Otherwise it re-seeds and moves the epoch.
        let other = test_block(1009, B256::repeat_byte(1), 7);
        let epoch = c.epoch();
        assert!(c.reseed_since(epoch, other.clone()));
        assert_eq!(c.head().unwrap().hash, other.hash);
        assert_eq!(c.finalized_number(), Some(1009));
        assert_ne!(c.epoch(), epoch);
    }

    #[test]
    fn a_head_move_during_a_reseed_does_not_leave_the_anchor_live() {
        let c = Arc::new(HeaderChain::new());
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 2, 1);
        c.set_head(a[1].hash).unwrap();
        let epoch = c.epoch();
        // The test holds the write lock as a concurrent `set_head` does.
        let g = c.inner.write();
        let reseed = std::thread::spawn({
            let c = c.clone();
            move || c.reseed(test_block(2000, B256::repeat_byte(3), 4))
        });
        let start = std::time::Instant::now();
        while c.epoch() == epoch && start.elapsed() < std::time::Duration::from_millis(200) {
            std::thread::yield_now();
        }
        // `set_head` stores `live` before it drops the lock.
        c.live.store(true, Ordering::SeqCst);
        drop(g);
        reseed.join().unwrap();
        assert_eq!(c.head().unwrap().header.number, 2000);
        assert!(!c.is_live(), "a bare re-seeded anchor is not live");
        assert_ne!(c.epoch(), epoch);
    }

    #[test]
    fn a_canonical_ancestor_hash_is_looked_up_without_a_parent_walk() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 300, 1);
        let head = a.last().unwrap();
        c.set_head(head.hash).unwrap();
        // A parent walk from the head cannot pass a block that is gone.
        c.inner.write().by_hash.remove(&a[200].hash);
        assert_eq!(c.ancestor_hash(&head.hash, 1044), Some(a[43].hash));
        assert_eq!(c.ancestor_hash(&head.hash, head.header.number), None);
        // A block off the canonical chain still gets its own ancestry.
        let side = extend(&c, &a[250], 3, 2);
        assert_eq!(c.ancestor_hash(&side[2].hash, 1252), Some(side[0].hash));
        assert_eq!(c.ancestor_hash(&side[2].hash, 1251), Some(a[250].hash));
    }

    #[test]
    fn anchor_comparison_and_halt_flag() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        assert_eq!(c.check_anchor(1000, &anchor.hash), AnchorStatus::Agree);
        assert_eq!(c.check_anchor(1000, &B256::repeat_byte(5)), AnchorStatus::Mismatch);
        assert_eq!(c.check_anchor(5, &B256::repeat_byte(5)), AnchorStatus::NotHeld);
        assert!(!c.halted());
        for reason in [HaltReason::AnchorMismatch, HaltReason::BehindAnchor] {
            c.set_halted(Some(reason));
            assert_eq!(c.halt_reason(), Some(reason));
            assert!(c.halted());
        }
        c.set_halted(None);
        assert!(!c.halted());
    }

    #[test]
    fn blocks_at_the_last_numbers_do_not_overflow() {
        let c = HeaderChain::new();
        let anchor = test_block(u64::MAX - 1, B256::ZERO, 0);
        c.seed(anchor.clone());
        let last = test_block(u64::MAX, anchor.hash, 0);
        c.insert(last.clone()).unwrap();
        c.set_head(last.hash).unwrap();
        assert!(!c.finality_stalled());
        assert_eq!(
            c.insert(test_block(0, last.hash, 1)),
            Err(ChainError::BadNumber),
            "no block follows the last number"
        );
    }

    #[test]
    fn confirm_finalized_needs_a_held_canonical_block_not_below_finality() {
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let a = extend(&c, &anchor, 5, 1);
        let side = extend(&c, &a[1], 2, 2);
        c.set_head(a[4].hash).unwrap();
        assert!(!c.finality_confirmed(), "a seed is not confirmed finality");
        // Off the canonical chain, at a number with another hash, or not held at all.
        assert!(!c.confirm_finalized(&side[0]));
        assert!(!c.confirm_finalized(&test_block(1006, a[4].hash, 9)));
        assert_eq!((c.finalized_number(), c.finality_confirmed()), (Some(1000), false));
        assert!(c.confirm_finalized(&a[2]));
        assert_eq!((c.finalized_number(), c.finality_confirmed()), (Some(1003), true));
        assert!(c.confirm_finalized(&a[2]), "the same block again");
        assert!(!c.confirm_finalized(&a[1]), "finality never moves back");
        assert_eq!(c.finalized_number(), Some(1003));
        // The side branch from 1002 no longer descends from the finalized block.
        assert_eq!(c.set_head(side[1].hash), Err(ChainError::NotFromFinalized));
        assert_eq!(c.insert(test_block(1003, a[1].hash, 9)), Err(ChainError::NotFromFinalized));
        assert_eq!(c.set_head(B256::repeat_byte(9)), Err(ChainError::Unknown));
        // A canonical block pruned from the window is held again.
        let mut cur = a[4].clone();
        for _ in 0..(HEADERS_WINDOW + 10) {
            let b = extend(&c, &cur, 1, 1).remove(0);
            c.set_head(b.hash).unwrap();
            cur = b;
        }
        assert!(c.by_hash(&a[3].hash).is_none());
        assert_eq!(c.check_anchor(1004, &a[3].hash), AnchorStatus::Agree);
        assert!(c.confirm_finalized(&a[3]));
        assert_eq!(c.finalized().map(|b| b.hash), Some(a[3].hash));
        // A child of the pinned finalized block is now older than the window.
        assert_eq!(c.insert(test_block(1005, a[3].hash, 9)), Err(ChainError::TooOld));
        // Seeds start without confirmed finality.
        c.reseed(cur.clone());
        assert!(!c.finality_confirmed());
        assert!(c.confirm_finalized(&cur));
        c.seed(test_block(5000, B256::ZERO, 3));
        assert!(!c.finality_confirmed());
    }

    #[test]
    fn finality_confirmed_below_the_window_moves_and_delays_the_stall() {
        // The anchor was out of reach while finality moved, and is back during a finality stall:
        // the beacons' finalized block is now 600 below the head, under the 512-block window.
        let c = HeaderChain::new();
        let anchor = test_block(1000, B256::ZERO, 0);
        c.seed(anchor.clone());
        let grow = |blocks: &mut Vec<HeldBlock>, n: u64| {
            for _ in 0..n {
                let b = extend(&c, blocks.last().unwrap(), 1, 1).remove(0);
                c.set_head(b.hash).unwrap();
                blocks.push(b);
            }
        };
        let mut blocks = vec![anchor];
        grow(&mut blocks, 1700);
        let fin = blocks[1700 - 600].clone();
        assert!(!c.contains(&fin.hash), "pruned from the window");
        assert_eq!(c.check_anchor(fin.header.number, &fin.hash), AnchorStatus::Agree);
        assert!(c.confirm_finalized(&fin));
        assert_eq!(c.finalized_number(), Some(fin.header.number));
        assert_eq!(c.finalized().map(|b| b.hash), Some(fin.hash), "the finalized block is served");
        // Past the old finalized block plus MAX_HELD, but not past the new one.
        grow(&mut blocks, 400);
        assert!(!c.finality_stalled());
    }

    /// The bodies generated blocks share: empty, two transactions, and 2 MiB of calldata. A third
    /// of a 513-block window is 342 MiB of heavy bodies, past [`MAX_BODY_BYTES`].
    static MODEL_BODIES: std::sync::LazyLock<[Arc<BlockBody<TxEnvelope>>; 3]> =
        std::sync::LazyLock::new(|| {
            let two = BlockBody { transactions: vec![tx(1), tx(2)], ..Default::default() };
            [Arc::default(), Arc::new(two), heavy_body(2 << 20)]
        });

    /// A block with a 4-byte id, so a generated tree has distinct siblings.
    fn model_block(number: u64, parent: B256, id: u32) -> HeldBlock {
        let header = Header {
            number,
            parent_hash: parent,
            extra_data: id.to_be_bytes().to_vec().into(),
            ..Default::default()
        };
        HeldBlock {
            hash: header.hash_slow(),
            header,
            beacon_root: B256::ZERO,
            body: MODEL_BODIES[id as usize % 3].clone(),
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert {
            parent: proptest::sample::Index,
            skip: bool,
        },
        /// Inserts a block made earlier again.
        Reinsert(proptest::sample::Index),
        Grow(u16),
        SetHead(proptest::sample::Index),
        Confirm(proptest::sample::Index),
        Reseed(proptest::sample::Index),
        ReseedSince {
            at: proptest::sample::Index,
            stale: bool,
        },
        ReseedFresh(u16),
    }

    fn op() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::{prelude::*, sample::Index};
        prop_oneof![
            8 => (any::<Index>(), proptest::bool::weighted(0.1))
                .prop_map(|(parent, skip)| Op::Insert { parent, skip }),
            3 => any::<Index>().prop_map(Op::Reinsert),
            4 => (1u16..8).prop_map(Op::Grow),
            1 => (500u16..640).prop_map(Op::Grow),
            6 => any::<Index>().prop_map(Op::SetHead),
            3 => any::<Index>().prop_map(Op::Confirm),
            1 => any::<Index>().prop_map(Op::Reseed),
            1 => (any::<Index>(), any::<bool>()).prop_map(|(at, stale)| Op::ReseedSince { at, stale }),
            1 => any::<u16>().prop_map(Op::ReseedFresh),
        ]
    }

    /// Everything a refused change must leave as it was.
    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        canonical: BTreeMap<u64, B256>,
        held: std::collections::BTreeSet<B256>,
        head: Option<B256>,
        finalized: Option<(u64, B256)>,
        confirmed: bool,
        live: bool,
        epoch: u64,
    }

    fn snapshot(c: &HeaderChain) -> Snapshot {
        let g = c.inner.read();
        Snapshot {
            canonical: g.canonical.clone(),
            held: g.by_hash.keys().copied().collect(),
            head: g.head,
            finalized: g.finalized,
            confirmed: g.finality_confirmed,
            live: c.is_live(),
            epoch: c.epoch(),
        }
    }

    /// The hash at `number` on the true ancestry of `hash`, from every block ever made.
    fn true_ancestor(all: &HashMap<B256, (u64, B256)>, hash: B256, number: u64) -> Option<B256> {
        let mut cur = hash;
        loop {
            let (n, parent) = *all.get(&cur)?;
            if n == number {
                return Some(cur);
            }
            if n < number {
                return None;
            }
            cur = parent;
        }
    }

    /// Whether every block from `hash` down to the finalized block is held.
    fn held_down_to(s: &Snapshot, all: &HashMap<B256, (u64, B256)>, hash: B256) -> bool {
        let Some((fin, _)) = s.finalized else { return false };
        let mut cur = hash;
        while let Some(&(n, parent)) = all.get(&cur) {
            if !s.held.contains(&cur) {
                return false;
            }
            if n <= fin {
                return true;
            }
            cur = parent;
        }
        false
    }

    /// The invariants every reachable state keeps.
    fn check_invariants(c: &HeaderChain, all: &HashMap<B256, (u64, B256)>) {
        let s = snapshot(c);
        {
            let g = c.inner.read();
            for (h, b) in &g.by_hash {
                match g.body_sizes.get(h) {
                    Some(size) => assert_eq!(*size, body_bytes(&b.body), "the size of {h}"),
                    None => assert!(b.body.transactions.is_empty(), "{h} kept an uncounted body"),
                }
            }
            assert!(
                g.body_sizes.keys().all(|h| g.by_hash.contains_key(h)),
                "a size outlived its block"
            );
            assert_eq!(g.body_total, g.body_sizes.values().sum::<u64>(), "the body total drifted");
            assert!(g.body_total <= MAX_BODY_BYTES, "{} MiB of bodies held", g.body_total >> 20);
            let mut indexed = 0;
            for (tx, at) in &g.txs {
                for (h, i) in at {
                    assert!(g.body_sizes.contains_key(h), "an index entry outlived its body");
                    assert_eq!(g.by_hash[h].body.transactions[*i].tx_hash(), tx);
                    indexed += 1;
                }
            }
            let carried: usize =
                g.body_sizes.keys().map(|h| g.by_hash[h].body.transactions.len()).sum();
            assert_eq!(indexed, carried, "each transaction of a held body is indexed once");
        }
        let head = c.head().expect("the head is held");
        for tx in &head.body.transactions {
            let (b, i) = c.find_tx(tx.tx_hash()).expect("a head transaction is found");
            assert!(c.is_canonical(&b.hash));
            assert_eq!(b.body.transactions[i].tx_hash(), tx.tx_hash());
        }
        let (fin_number, fin_hash) = s.finalized.expect("finalized is set");
        assert!(s.held.contains(&fin_hash), "finalized is held");
        assert!(c.finalized().is_some(), "the finalized block keeps its body");
        assert!(head.header.number >= fin_number);
        assert_eq!(
            true_ancestor(all, head.hash, fin_number),
            Some(fin_hash),
            "the head descends from finalized"
        );
        assert_eq!(s.canonical.get(&fin_number), Some(&fin_hash), "finalized is canonical");
        assert_eq!(c.check_anchor(fin_number, &fin_hash), AnchorStatus::Agree);
        assert_eq!(c.check_anchor(head.header.number + 1, &head.hash), AnchorStatus::NotHeld);
        assert_eq!(s.canonical.keys().next_back(), Some(&head.header.number), "nothing above");
        // One hash-linked line of held blocks from the lowest number up to the head.
        let lowest = c.lowest().expect("the head is held");
        assert!(lowest <= head.header.number);
        assert!(lowest.checked_sub(1).is_none_or(|n| c.by_number(n).is_none()), "the run is whole");
        let mut child = head.clone();
        for n in (lowest..head.header.number).rev() {
            let b = c.by_number(n).expect("every block from the lowest up is held");
            assert_eq!(child.header.parent_hash, b.hash, "the canonical line is linked at {n}");
            assert_eq!(c.check_anchor(n, &b.hash), AnchorStatus::Agree);
            child = b;
        }
        assert!(c.held() <= MAX_BLOCKS, "{} blocks held", c.held());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        #[test]
        fn any_sequence_of_chain_updates_keeps_the_chain_invariants(
            ops in proptest::collection::vec(op(), 1..40)
        ) {
            let c = HeaderChain::new();
            let anchor = model_block(1000, B256::ZERO, 0);
            let mut all = HashMap::from([(anchor.hash, (1000, B256::ZERO))]);
            let mut pool = vec![anchor.clone()];
            let mut next_id = 0u32;
            let mut make = |number: u64, parent: B256, all: &mut HashMap<_, _>| {
                next_id += 1;
                let b = model_block(number, parent, next_id);
                all.insert(b.hash, (number, parent));
                b
            };
            c.seed(anchor);
            for op in ops {
                let before = snapshot(&c);
                let head = c.head().unwrap();
                let (fin_number, fin_hash) = before.finalized.unwrap();
                match op {
                    Op::Insert { parent, skip } => {
                        let p = parent.get(&pool).clone();
                        let number = p.header.number + 1 + u64::from(skip);
                        let b = make(number, p.hash, &mut all);
                        let want = if !before.held.contains(&p.hash) {
                            Err(ChainError::UnknownParent)
                        } else if skip {
                            Err(ChainError::BadNumber)
                        } else if number + HEADERS_WINDOW < head.header.number {
                            Err(ChainError::TooOld)
                        } else if number <= fin_number {
                            Err(ChainError::NotFromFinalized)
                        } else {
                            Ok(())
                        };
                        let got = c.insert(b.clone());
                        if before.held.len() < MAX_BLOCKS {
                            assert_eq!(got, want, "insert at {number}");
                        }
                        if got.is_ok() {
                            assert!(c.contains(&b.hash));
                        } else {
                            let mut after = snapshot(&c);
                            assert!(after.held.is_subset(&before.held));
                            after.held.clone_from(&before.held);
                            assert_eq!(after, before, "a refused insert changes nothing else");
                        }
                        pool.push(b);
                    }
                    Op::Reinsert(at) => {
                        let b = at.get(&pool).clone();
                        let (number, parent) = all[&b.hash];
                        let want = if !before.held.contains(&parent) {
                            Err(ChainError::UnknownParent)
                        } else if all[&parent].0 + 1 != number {
                            Err(ChainError::BadNumber)
                        } else if number + HEADERS_WINDOW < head.header.number {
                            Err(ChainError::TooOld)
                        } else if number <= fin_number && b.hash != fin_hash {
                            Err(ChainError::NotFromFinalized)
                        } else {
                            Ok(())
                        };
                        let got = c.insert(b.clone());
                        if before.held.len() < MAX_BLOCKS {
                            assert_eq!(got, want, "insert again at {number}");
                        }
                        if got.is_ok() {
                            assert!(c.contains(&b.hash));
                        }
                    }
                    Op::Grow(len) => {
                        let mut cur = head;
                        for _ in 0..len {
                            let b = make(cur.header.number + 1, cur.hash, &mut all);
                            c.insert(b.clone()).unwrap();
                            c.set_head(b.hash).unwrap();
                            pool.push(b.clone());
                            cur = b;
                        }
                        assert!(c.is_live());
                    }
                    Op::SetHead(at) => {
                        let b = at.get(&pool);
                        // A held block that lost its body is not a head.
                        let served = c.by_hash(&b.hash).is_some();
                        let got = c.set_head(b.hash);
                        let safe = true_ancestor(&all, b.hash, fin_number) == Some(fin_hash);
                        if got.is_ok() {
                            assert!(safe, "a head that does not descend from finalized");
                            assert_eq!(c.head().unwrap().hash, b.hash);
                            assert!(c.is_live());
                        } else {
                            assert_eq!(snapshot(&c), before, "a refused head changes nothing");
                            assert!(
                                !(safe && served && held_down_to(&before, &all, b.hash)),
                                "a held head that descends from finalized was refused: {got:?}"
                            );
                            let want = if served {
                                ChainError::NotFromFinalized
                            } else {
                                ChainError::Unknown
                            };
                            assert_eq!(got, Err(want));
                        }
                    }
                    Op::Confirm(at) => {
                        let b = at.get(&pool);
                        let n = b.header.number;
                        let want = before.canonical.get(&n) == Some(&b.hash) && n >= fin_number;
                        assert_eq!(c.confirm_finalized(b), want);
                        if want {
                            // A block not held, or held without its body, is held with its body.
                            assert!(c.by_hash(&b.hash).is_some(), "the finalized block is served");
                            assert_eq!(c.finalized_number(), Some(n));
                            assert!(c.finality_confirmed());
                            assert!(c.contains(&b.hash), "the finalized block is held");
                        } else {
                            assert_eq!(snapshot(&c), before, "a refused confirmation changes nothing");
                        }
                    }
                    Op::Reseed(at) => {
                        let b = at.get(&pool).clone();
                        c.reseed(b.clone());
                        assert_eq!(c.held(), 1);
                        assert_eq!(c.finalized_number(), Some(b.header.number));
                        assert!(!c.is_live() && !c.finality_confirmed());
                        assert_ne!(c.epoch(), before.epoch);
                    }
                    Op::ReseedSince { at, stale } => {
                        let b = at.get(&pool).clone();
                        let n = b.header.number;
                        let epoch = if stale { before.epoch - 1 } else { before.epoch };
                        let want = !stale &&
                            n >= fin_number &&
                            before.canonical.get(&n) != Some(&b.hash);
                        assert_eq!(c.reseed_since(epoch, b.clone()), want);
                        if want {
                            assert_eq!(c.held(), 1);
                            assert!(!c.is_live() && !c.finality_confirmed());
                            assert_ne!(c.epoch(), before.epoch);
                        } else {
                            assert_eq!(snapshot(&c), before, "a refused re-seed changes nothing");
                        }
                    }
                    Op::ReseedFresh(ahead) => {
                        // An unknown parent: a re-seed starts a new line.
                        let parent = B256::repeat_byte(0xee);
                        let b = make(head.header.number + u64::from(ahead) + 1, parent, &mut all);
                        assert!(c.reseed_since(before.epoch, b.clone()));
                        assert!(!c.is_live());
                        pool.push(b);
                    }
                }
                let fin = c.finalized_number().unwrap();
                let reseeded = c.epoch() != before.epoch;
                assert!(reseeded || fin >= fin_number, "finality moved back without a re-seed");
                check_invariants(&c, &all);
            }
        }
    }
}
