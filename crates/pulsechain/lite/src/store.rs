//! A bounded, content-addressed store for verified trie nodes and contract code.
//!
//! Keys are keccak hashes, so a value is its own proof: a read that finds an entry may use it
//! without asking who wrote it (the verifier checked it on the way in). Disk reads hash the
//! bytes again: an entry that no longer matches its key is deleted and read as absent.
//!
//! Two tiers:
//!
//! * a byte-bounded in-memory LRU (`--cache.size`). `put` never takes the tier past its cap; the
//!   least recently used entries are evicted, and an evicted entry that is read again is simply
//!   absent (never wrong), so the caller refetches it.
//! * a two-generation on-disk spill. Evicted entries are queued and written to the current
//!   generation in batches (one transaction per 256 KiB, not one per eviction). Each generation is
//!   capped at half of `--disk.limit`. It rotates when the pages it holds in use reach 90% of that
//!   cap (45% of the limit) or a write finds it full, and the node's disk check also rotates it
//!   once both generations pass 80% of the limit. A rotation starts a new generation and deletes
//!   the generation before the previous one, so disk use stays under the limit. A read that hits
//!   the previous generation promotes the entry into the current one.
//!
//! Disk mechanism: one MDBX environment (`reth-libmdbx`) per generation under
//! `<datadir>/store/gen-<n>`. MDBX keeps its index on disk and memory-maps it, so the resident
//! index of a multi-GiB generation is paged by the OS instead of being held on the heap, which
//! a plain file plus a `HashMap` index would do. Each environment is capped at the generation
//! size, written with `SafeNoSync` (the content is verifiable, a lost tail is a refetch) and a
//! steady sync every 1/32 of the cap (at most 64 MiB) so MDBX can reuse the pages that commits
//! retire.
//!
//! Callers run on the async runtime, so a put or a read does not wait for disk work. A put only
//! queues what it evicts in an inbox; one writer thread moves the inbox to disk. A full inbox
//! drops cold evictions, but never a value over the memory cap (`--cache.size 0`), which has no
//! other copy: that put writes it under the disk lock. Commits and rotations hold the disk lock,
//! which reads take for an MDBX lookup. Syncs, generation closes and deletes run after the lock
//! is released.

use alloy_primitives::{keccak256, Bytes, B256};
use parking_lot::{Condvar, Mutex};
use reth_libmdbx::{DatabaseFlags, Environment, Geometry, Mode, SyncMode, WriteFlags};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

/// Per entry bookkeeping charged against the memory cap on top of the value: the hash slot (up
/// to twice its size just after the map grows), the order-tree slot, and the header a `Bytes`
/// allocates on its first clone. Measured, and pinned by `tests/store_memory.rs`.
const ENTRY_OVERHEAD: u64 = 384;
/// A generation rotates when the pages MDBX holds in use reach this share of its size cap.
const ROTATE_PERCENT: u64 = 90;
const GROWTH_STEP: isize = 256 * 1024;
/// Spilled bytes queued before they are written in one transaction.
const SPILL_BATCH: u64 = 256 * 1024;
/// Queued bytes past which a queue drops what it is given: the inbox while the writer thread is
/// behind, and the flush's queue once the generation is full.
const MAX_PENDING: u64 = 4 * SPILL_BATCH;
/// The longest the writer thread sleeps before it checks the inbox again.
const WRITER_WAKE: Duration = Duration::from_secs(1);
/// The store makes a steady sync of a generation after 1/32 of its cap in written pages, at most
/// this many bytes. Pages retired since the last sync count as free but cannot be reused yet, so
/// this must stay well under the rotation headroom (1/10 of the cap). A spill batch of random keys
/// writes about 60 times its size in pages, so a smaller bound syncs at nearly every commit.
const SYNC_BYTES: u64 = 64 << 20;

/// The smallest disk limit: two generations of 8 MiB. A put-path write into a new generation
/// carries the inbox or the flush's queue (up to [`MAX_PENDING`]) plus a spill batch, about twice
/// that in B-tree pages, and one that does not fit is dropped.
pub const MIN_DISK_LIMIT: u64 = 16 * MAX_PENDING;

/// Why the store or one of its generations could not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The disk limit cannot hold two generations.
    #[error("--disk.limit of {limit} bytes is below the minimum of {MIN_DISK_LIMIT} bytes")]
    DiskLimit {
        /// The limit asked for.
        limit: u64,
    },
    /// The OS refused to create the store or generation directory.
    #[error("could not create a disk generation directory: {0}")]
    Dir(std::io::ErrorKind),
    /// MDBX failed to open a generation.
    #[error(transparent)]
    Mdbx(#[from] reth_libmdbx::Error),
    /// The OS refused to start the disk writer thread.
    #[error("could not start the disk writer thread: {0}")]
    Writer(std::io::ErrorKind),
}

/// Where verified trie nodes and code live.
pub trait NodeStore: Send + Sync {
    /// A trie node by hash.
    fn get(&self, hash: &B256) -> Option<Bytes>;
    /// Stores a trie node. The caller has verified `hash == keccak(node)`.
    fn put(&self, hash: B256, node: Bytes);
    /// Contract code by hash.
    fn code(&self, hash: &B256) -> Option<Bytes>;
    /// Stores contract code the caller has verified.
    fn put_code(&self, hash: B256, code: Bytes);
    /// Bytes held in memory, including writes queued for disk.
    fn bytes(&self) -> u64;
}

#[derive(Debug)]
struct Entry {
    value: Bytes,
    tick: u64,
}

#[derive(Debug, Default)]
struct Mem {
    map: HashMap<B256, Entry>,
    order: BTreeMap<u64, B256>,
    tick: u64,
    bytes: u64,
}

fn charge(value: &Bytes) -> u64 {
    value.len() as u64 + ENTRY_OVERHEAD
}

impl Mem {
    fn touch(&mut self, key: &B256) -> Option<Bytes> {
        self.tick += 1;
        let tick = self.tick;
        let e = self.map.get_mut(key)?;
        self.order.remove(&e.tick);
        e.tick = tick;
        self.order.insert(tick, *key);
        Some(e.value.clone())
    }

    /// Inserts and returns what was evicted to stay within `cap`.
    fn insert(&mut self, key: B256, value: Bytes, cap: u64) -> Vec<(B256, Bytes)> {
        let mut evicted = Vec::new();
        let cost = charge(&value);
        if cost > cap {
            // Does not fit even alone: hand it straight to the next tier.
            evicted.push((key, value));
            return evicted;
        }
        if let Some(old) = self.map.remove(&key) {
            self.order.remove(&old.tick);
            self.bytes -= charge(&old.value);
        }
        while self.bytes + cost > cap {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            if let Some(e) = self.map.remove(&oldest) {
                self.bytes -= charge(&e.value);
                evicted.push((oldest, e.value));
            }
        }
        self.tick += 1;
        self.order.insert(self.tick, key);
        self.bytes += cost;
        self.map.insert(key, Entry { value, tick: self.tick });
        evicted
    }
}

#[derive(Debug)]
struct Generation {
    id: u64,
    path: PathBuf,
    env: Environment,
    /// Written bytes past which [`Self::sync_if_due`] makes a steady sync.
    sync_bytes: u64,
    /// Pages written when the last steady sync ran.
    synced_pages: AtomicU64,
    /// Held for each write transaction and each sync. reth's environments set
    /// `MDBX_NOSTICKYTHREADS`, so MDBX takes a sync made while any thread holds a write
    /// transaction as part of that write: it skips its writer lock, and the two write the same
    /// meta page.
    write: Mutex<()>,
}

impl Generation {
    fn open(root: &Path, id: u64, size_cap: u64) -> Result<Self, StoreError> {
        let path = root.join(format!("gen-{id}"));
        fs::create_dir_all(&path).map_err(|e| StoreError::Dir(e.kind()))?;
        let mut builder = Environment::builder();
        builder.set_geometry(Geometry {
            size: Some(0..size_cap as usize),
            growth_step: Some(GROWTH_STEP),
            shrink_threshold: Some(0),
            page_size: None,
        });
        builder.set_flags(Mode::ReadWrite { sync_mode: SyncMode::SafeNoSync }.into());
        let env = builder.open(&path)?;
        let synced_pages = AtomicU64::new(Self::written_pages(&env));
        Ok(Self {
            id,
            path,
            env,
            sync_bytes: (size_cap / 32).min(SYNC_BYTES),
            synced_pages,
            write: Mutex::new(()),
        })
    }

    /// Pages MDBX has written in this environment (0 when it cannot say).
    fn written_pages(env: &Environment) -> u64 {
        env.info().map_or(0, |i| i.page_ops().newly + i.page_ops().cow)
    }

    /// Makes a steady sync once the pages written since the last one reach `sync_bytes`. MDBX
    /// reuses a retired page only after a steady sync. Without one the file grows by the copied
    /// pages of every commit and reports `MapFull` at a small share of live data. The caller holds
    /// no disk lock: a sync of up to [`SYNC_BYTES`] must not hold up reads. A write into this
    /// generation waits for the sync.
    fn sync_if_due(&self) {
        let (written, Ok(stat)) = (Self::written_pages(&self.env), self.env.stat()) else {
            return;
        };
        let since = written.saturating_sub(self.synced_pages.load(Ordering::Relaxed));
        if since.saturating_mul(u64::from(stat.page_size())) < self.sync_bytes {
            return;
        }
        match self.sync() {
            Ok(_) => self.synced_pages.store(written, Ordering::Relaxed),
            Err(e) => tracing::warn!(%e, "could not sync a disk generation"),
        }
    }

    /// A steady sync, never during a write transaction.
    fn sync(&self) -> Result<bool, reth_libmdbx::Error> {
        let _write = self.write.lock();
        self.env.sync(true)
    }

    fn get(&self, key: &B256) -> Option<Bytes> {
        let txn = self.env.begin_ro_txn().ok()?;
        let db = txn.open_db(None).ok()?;
        let v: Option<Vec<u8>> = txn.get(db.dbi(), key.as_slice()).ok()?;
        v.map(Bytes::from)
    }

    /// The entry under `key` if its bytes still hash to it. Bytes that do not (disk corruption,
    /// a bad write) are deleted and read as absent: the caller refetches.
    fn get_verified(&self, key: &B256) -> Option<Bytes> {
        let v = self.get(key)?;
        if keccak256(&v) == *key {
            return Some(v);
        }
        tracing::warn!("a stored entry does not match its hash; dropping it");
        let _ = self.delete(key);
        None
    }

    fn delete(&self, key: &B256) -> Result<(), reth_libmdbx::Error> {
        let _write = self.write.lock();
        let txn = self.env.begin_rw_txn()?;
        let db = txn.open_db(None)?;
        txn.del(db.dbi(), key.as_slice(), None)?;
        txn.commit()?;
        Ok(())
    }

    /// Writes a batch in one transaction. `Ok(false)` when the generation is full.
    fn put_all<'a>(
        &self,
        items: impl IntoIterator<Item = (&'a B256, &'a Bytes)>,
    ) -> Result<bool, reth_libmdbx::Error> {
        let _write = self.write.lock();
        let txn = self.env.begin_rw_txn()?;
        let db = txn.create_db(None, DatabaseFlags::empty())?;
        for (k, v) in items {
            match txn.put(db.dbi(), k.as_slice(), v.as_ref(), WriteFlags::empty()) {
                Ok(()) => {}
                Err(reth_libmdbx::Error::MapFull) => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        txn.commit()?;
        Ok(true)
    }

    /// Whether the generation holds no entry (an error reads as not empty).
    fn is_empty(&self) -> bool {
        self.env.stat().is_ok_and(|s| s.entries() == 0)
    }

    fn file_bytes(&self) -> u64 {
        fs::metadata(self.path.join("mdbx.dat")).map(|m| m.len()).unwrap_or(0)
    }

    /// Bytes in pages MDBX holds in use (the file only grows, and grows in steps, so its length
    /// says little about how full the generation is).
    fn used_bytes(&self) -> u64 {
        let (Ok(info), Ok(stat), Ok(free)) =
            (self.env.info(), self.env.stat(), self.env.freelist())
        else {
            return self.file_bytes();
        };
        let pages = (info.last_pgno() + 1).saturating_sub(free);
        pages as u64 * u64::from(stat.page_size())
    }
}

/// Whether MDBX refused a generation for its contents: damaged, or written by another format.
const fn is_damaged(e: reth_libmdbx::Error) -> bool {
    use reth_libmdbx::Error;
    matches!(
        e,
        Error::Corrupted |
            Error::Panic |
            Error::VersionMismatch |
            Error::Invalid |
            Error::PageNotFound |
            Error::BadSignature |
            Error::WannaRecovery |
            Error::Incompatible
    )
}

/// Who asked for a write: only the put path may rotate. A read that promotes an entry or spills
/// what its promotion evicted must never delete the generation it is reading from, and once the
/// shutdown flush has had its one rotation every write runs as `Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Writer {
    Put,
    Read,
}

#[derive(Debug)]
struct Disk {
    root: PathBuf,
    limit: u64,
    gen_cap: u64,
    cur: Arc<Generation>,
    prev: Option<Arc<Generation>>,
    /// The id of the next generation: above every one found at open, a damaged one that could
    /// not be deleted included, so a rotation never opens it again.
    next_id: u64,
    /// Spilled entries not yet written: one MDBX transaction per [`SPILL_BATCH`] bytes instead of
    /// one per eviction.
    pending: HashMap<B256, Bytes>,
    pending_bytes: u64,
    /// `cur` refused a read-path write. Read-path writes then only queue, up to [`MAX_PENDING`],
    /// until a put-path write rotates and writes the queue.
    read_blocked: bool,
    /// Generations a rotation retired. [`Spill::with_disk`] closes and deletes them after it
    /// releases the lock, so the close's sync and an unlink of up to half the limit never block
    /// other disk reads.
    dead: Vec<Arc<Generation>>,
    /// Rotations left: `None` until the shutdown flush starts, which allows one. A disk check or
    /// a request still in flight may rotate between two flush batches, and a second rotation
    /// from anyone would delete the generation that holds the flush's newest entries.
    rotations_left: Option<u8>,
}

impl Disk {
    fn open(root: PathBuf, disk_limit: u64) -> Result<Self, StoreError> {
        Self::open_with(root, disk_limit, |path| fs::remove_dir_all(path))
    }

    /// [`Self::open`], deleting old and damaged generations with `remove`.
    fn open_with(
        root: PathBuf,
        disk_limit: u64,
        remove: impl Fn(&Path) -> std::io::Result<()>,
    ) -> Result<Self, StoreError> {
        if disk_limit < MIN_DISK_LIMIT {
            return Err(StoreError::DiskLimit { limit: disk_limit });
        }
        // Each generation is capped at half the limit. At most two are alive: the generation
        // before the previous one is deleted when a new one starts.
        let gen_cap = disk_limit / 2;
        fs::create_dir_all(&root).map_err(|e| StoreError::Dir(e.kind()))?;
        let mut ids: Vec<u64> = fs::read_dir(&root)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_prefix("gen-")?.parse().ok())
            .collect();
        ids.sort_unstable();
        // Keep the two newest, delete the rest.
        while ids.len() > 2 {
            let old = ids.remove(0);
            let _ = remove(&root.join(format!("gen-{old}")));
        }
        // Every entry is re-hashed on read and refetched on a miss, so a generation MDBX finds
        // damaged or of another format holds nothing to keep. Any other error stops the open.
        let mut kept = Vec::new();
        for &id in &ids {
            match Generation::open(&root, id, gen_cap) {
                Ok(g) => kept.push(Arc::new(g)),
                Err(StoreError::Mdbx(e)) if is_damaged(e) => {
                    let path = root.join(format!("gen-{id}"));
                    tracing::warn!(%e, path = %path.display(), "cannot open a disk generation; deleting it");
                    if let Err(e) = remove(&path) {
                        tracing::warn!(%e, path = %path.display(), "could not delete a damaged disk generation");
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let mut next_id = ids.last().map_or(0, |id| id + 1);
        let cur = match kept.pop() {
            Some(cur) => cur,
            None => {
                let g = Generation::open(&root, next_id, gen_cap)?;
                next_id += 1;
                Arc::new(g)
            }
        };
        let prev = kept.pop();
        Ok(Self {
            root,
            limit: disk_limit,
            gen_cap,
            cur,
            prev,
            next_id,
            pending: HashMap::new(),
            pending_bytes: 0,
            read_blocked: false,
            dead: Vec::new(),
            rotations_left: None,
        })
    }

    /// `who`, or `Read` once no rotation is left.
    fn writer(&self, who: Writer) -> Writer {
        if self.rotations_left == Some(0) {
            Writer::Read
        } else {
            who
        }
    }

    /// Starts a new generation. Callers rotate only as [`Writer::Put`] from [`Self::writer`].
    fn rotate(&mut self) -> Result<(), StoreError> {
        let id = self.next_id;
        tracing::debug!(from = self.cur.id, to = id, "starting a new disk generation");
        let next = match Generation::open(&self.root, id, self.gen_cap) {
            Ok(next) => Arc::new(next),
            Err(e) => {
                // The id is above every generation found at open, so its directory holds only
                // what this open left. Once that is gone the next rotation may use the id again;
                // while it is not, the id is spent, so the leftover is never opened.
                match fs::remove_dir_all(self.root.join(format!("gen-{id}"))) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => self.next_id += 1,
                    _ => {}
                }
                return Err(e);
            }
        };
        self.next_id += 1;
        let old_cur = std::mem::replace(&mut self.cur, next);
        if let Some(dead) = self.prev.replace(old_cur) {
            self.dead.push(dead);
        }
        if let Some(left) = &mut self.rotations_left {
            *left = left.saturating_sub(1);
        }
        Ok(())
    }

    /// Writes the queue and rotates, once: the write may already rotate.
    fn rotate_once(&mut self) {
        if !self.write_pending(Writer::Put) &&
            self.writer(Writer::Put) == Writer::Put &&
            let Err(e) = self.rotate()
        {
            tracing::warn!(%e, "could not start a new disk generation");
        }
    }

    /// Queues spilled entries and writes them once a batch is full. Returns whether it rotated.
    fn spill(&mut self, items: Vec<(B256, Bytes)>, who: Writer) -> bool {
        let who = self.writer(who);
        let blocked = who == Writer::Read && self.read_blocked;
        for (k, v) in items {
            if blocked && self.pending_bytes >= MAX_PENDING {
                tracing::debug!("spill queue full while the disk generation is full; dropping");
                break;
            }
            let len = v.len() as u64;
            if let Some(old) = self.pending.insert(k, v) {
                self.pending_bytes -= old.len() as u64;
            }
            self.pending_bytes += len;
        }
        !blocked && self.pending_bytes >= SPILL_BATCH && self.write_pending(who)
    }

    /// Writes the queued entries in one transaction and returns whether it rotated. A read that
    /// finds `cur` full puts them back for the next put-path write; any other failure drops them
    /// with a warning (a later read refetches).
    fn write_pending(&mut self, who: Writer) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let who = self.writer(who);
        let items = std::mem::take(&mut self.pending);
        let bytes = std::mem::take(&mut self.pending_bytes);
        if who == Writer::Put {
            self.read_blocked = false;
        }
        let full = self.cur.used_bytes() >= self.gen_cap / 100 * ROTATE_PERCENT;
        if full && who == Writer::Read {
            self.requeue(items, bytes);
            return false;
        }
        let entries = items.len();
        if full && let Err(e) = self.rotate() {
            tracing::warn!(
                %e,
                entries,
                bytes,
                "could not start a disk generation; dropping a spill batch"
            );
            return false;
        }
        match self.cur.put_all(items.iter()) {
            Ok(true) => return full,
            Ok(false) | Err(reth_libmdbx::Error::MapFull) => {}
            Err(e) => {
                tracing::warn!(%e, entries, bytes, "could not write a spill batch; dropping it");
                return full;
            }
        }
        // Full: rotate and retry once, on the put path only. Rotating away from an empty
        // generation would only delete the previous one: the batch is too big for any generation.
        // The rotation above may have spent the flush's one.
        if self.writer(who) == Writer::Read {
            self.requeue(items, bytes);
            return full;
        }
        if self.cur.is_empty() {
            tracing::warn!(
                entries,
                bytes,
                "spill batch is larger than a disk generation; dropping it"
            );
            return full;
        }
        if let Err(e) = self.rotate() {
            tracing::warn!(
                %e,
                entries,
                bytes,
                "could not start a disk generation; dropping a spill batch"
            );
            return full;
        }
        match self.cur.put_all(items.iter()) {
            Ok(true) => {}
            Ok(false) | Err(reth_libmdbx::Error::MapFull) => tracing::warn!(
                entries,
                bytes,
                "spill batch does not fit in a new disk generation; dropping it"
            ),
            Err(e) => tracing::warn!(
                %e,
                entries,
                bytes,
                "could not write a spill batch; dropping it"
            ),
        }
        true
    }

    /// Puts back a batch a read could not write: it holds put-path evictions too, which are in
    /// neither tier.
    fn requeue(&mut self, items: HashMap<B256, Bytes>, bytes: u64) {
        tracing::debug!(
            entries = items.len(),
            "disk generation full; keeping the spill batch queued"
        );
        self.pending = items;
        self.pending_bytes = bytes;
        self.read_blocked = true;
    }

    /// The entry under `key`, and whether it came from `prev`: the caller then queues it again
    /// so it survives the next rotation.
    fn read(&self, key: &B256) -> Option<(Bytes, bool)> {
        if let Some(v) = self.pending.get(key) {
            return Some((v.clone(), false));
        }
        if let Some(v) = self.cur.get_verified(key) {
            return Some((v, false));
        }
        Some((self.prev.as_ref()?.get_verified(key)?, true))
    }

    fn disk_bytes(&self) -> u64 {
        self.cur.file_bytes() + self.prev.as_ref().map_or(0, |g| g.file_bytes())
    }
}

/// Entries waiting for the writer thread: what puts evict and what reads promote or evict, each
/// with the path that queued it.
#[derive(Debug, Default)]
struct Inbox {
    items: HashMap<B256, (Bytes, Writer)>,
    bytes: u64,
    /// Entries dropped since the last drain, which logs them.
    dropped: usize,
    /// The store is closing: the writer thread stops.
    closed: bool,
}

impl Inbox {
    /// Queues `items` up to [`MAX_PENDING`] and drops the rest (a later read refetches them).
    /// Returns whether a batch is ready.
    fn push(&mut self, items: Vec<(B256, Bytes)>, who: Writer) -> bool {
        let total = items.len();
        for (i, (k, v)) in items.into_iter().enumerate() {
            if self.bytes >= MAX_PENDING {
                self.dropped += total - i;
                break;
            }
            let len = v.len() as u64;
            if let Some((old, _)) = self.items.insert(k, (v, who)) {
                self.bytes -= old.len() as u64;
            }
            self.bytes += len;
        }
        self.bytes >= SPILL_BATCH
    }

    fn charge(&self) -> u64 {
        self.bytes + self.items.len() as u64 * ENTRY_OVERHEAD
    }
}

/// The disk tier and the inbox in front of it, shared with the writer thread.
#[derive(Debug)]
struct Spill {
    disk: Mutex<Disk>,
    /// Its lock is never held across disk work. Lock order: `disk`, then `inbox`.
    inbox: Mutex<Inbox>,
    /// Wakes the writer thread when the inbox holds a batch or the store closes.
    wake: Condvar,
    /// The charge of `Disk::pending`, so [`NodeStore::bytes`] never waits for the disk lock.
    queued: AtomicU64,
}

impl Spill {
    fn queue(&self, items: Vec<(B256, Bytes)>, who: Writer) {
        if !items.is_empty() && self.inbox.lock().push(items, who) {
            self.wake.notify_one();
        }
    }

    /// Queues `entry`, the only copy of a fresh put, or writes it under the disk lock when the
    /// inbox is full: the caller reads it back next, and a drop would end in a refetch loop.
    /// Only then does a put wait for the disk.
    fn keep(&self, entry: (B256, Bytes)) {
        let mut inbox = self.inbox.lock();
        if inbox.bytes < MAX_PENDING {
            if inbox.push(vec![entry], Writer::Put) {
                self.wake.notify_one();
            }
            return;
        }
        drop(inbox);
        self.with_disk(|d| {
            d.spill(vec![entry], Writer::Put);
        });
    }

    /// Moves the inbox to the disk tier, which writes it once it holds a batch. The inbox is
    /// taken under the disk lock, so a read that misses it waits for the lock and then finds the
    /// entries queued or written. What reads queued is spilled as a read, which never rotates:
    /// a run of reads from the previous generation must not delete it.
    fn drain(&self) {
        self.with_disk(|d| {
            let (items, dropped) = {
                let mut inbox = self.inbox.lock();
                inbox.bytes = 0;
                (std::mem::take(&mut inbox.items), std::mem::take(&mut inbox.dropped))
            };
            if dropped > 0 {
                tracing::warn!(
                    entries = dropped,
                    "the disk writer was behind; dropped evicted entries (a later read refetches them)"
                );
            }
            let (mut puts, mut reads) = (Vec::new(), Vec::new());
            for (k, (v, who)) in items {
                match who {
                    Writer::Put => puts.push((k, v)),
                    Writer::Read => reads.push((k, v)),
                }
            }
            // An empty put batch would still write a full read-blocked queue, and rotate.
            for (batch, who) in [(reads, Writer::Read), (puts, Writer::Put)] {
                if !batch.is_empty() {
                    d.spill(batch, who);
                }
            }
        });
    }

    /// Runs `f` on the disk tier. After it releases the lock it closes and deletes the
    /// generations `f` retired and syncs the current one if a sync is due.
    fn with_disk<R>(&self, f: impl FnOnce(&mut Disk) -> R) -> R {
        let (r, dead, cur) = {
            let mut d = self.disk.lock();
            let r = f(&mut d);
            let queued = d.pending_bytes + d.pending.len() as u64 * ENTRY_OVERHEAD;
            self.queued.store(queued, Ordering::Relaxed);
            (r, std::mem::take(&mut d.dead), d.cur.clone())
        };
        for g in dead {
            let path = g.path.clone();
            drop(g);
            if let Err(e) = fs::remove_dir_all(&path) {
                tracing::warn!(%e, path = %path.display(), "could not delete a retired disk generation");
            }
        }
        cur.sync_if_due();
        r
    }

    /// The entry under `key` from the inbox or the disk tier, and whether to promote it.
    fn read(&self, key: &B256) -> Option<(Bytes, bool)> {
        if let Some((v, _)) = self.inbox.lock().items.get(key) {
            return Some((v.clone(), false));
        }
        self.disk.lock().read(key)
    }

    /// The writer thread: writes the inbox each time it holds a batch, until the store closes.
    fn write_loop(&self) {
        loop {
            {
                let mut inbox = self.inbox.lock();
                while !inbox.closed && inbox.bytes < SPILL_BATCH {
                    self.wake.wait_for(&mut inbox, WRITER_WAKE);
                }
                if inbox.closed {
                    return;
                }
            }
            self.drain();
        }
    }
}

/// The disk tier and its writer thread, which stops when this drops.
#[derive(Debug)]
struct DiskTier {
    spill: Arc<Spill>,
    writer: Option<JoinHandle<()>>,
}

impl Drop for DiskTier {
    fn drop(&mut self) {
        self.spill.inbox.lock().closed = true;
        self.spill.wake.notify_one();
        // Waits for at most the batch the writer is on, so the environments close before a
        // reopen of the same directory.
        if let Some(w) = self.writer.take() &&
            w.join().is_err()
        {
            tracing::warn!("the disk writer thread panicked");
        }
    }
}

/// The lite node's [`NodeStore`]: bounded memory LRU over a two-generation disk spill.
#[derive(Debug)]
pub struct Store {
    cap: u64,
    mem: Mutex<Mem>,
    disk: Option<DiskTier>,
}

impl Store {
    /// A memory-only store (an evicted entry is gone).
    pub fn in_memory(cap: u64) -> Self {
        Self { cap, mem: Mutex::default(), disk: None }
    }

    /// Opens the store under `dir`, reusing the two newest generations found there, and starts
    /// its writer thread.
    pub fn open(dir: &Path, cap: u64, disk_limit: u64) -> Result<Self, StoreError> {
        let disk = Disk::open(dir.to_path_buf(), disk_limit)?;
        let spill = Arc::new(Spill {
            disk: Mutex::new(disk),
            inbox: Mutex::default(),
            wake: Condvar::new(),
            queued: AtomicU64::new(0),
        });
        let writer = std::thread::Builder::new()
            .name("lite-store-writer".into())
            .spawn({
                let spill = spill.clone();
                move || spill.write_loop()
            })
            .map_err(|e| StoreError::Writer(e.kind()))?;
        Ok(Self {
            cap,
            mem: Mutex::default(),
            disk: Some(DiskTier { spill, writer: Some(writer) }),
        })
    }

    fn spill(&self) -> Option<&Spill> {
        self.disk.as_ref().map(|t| &*t.spill)
    }

    /// Bytes on disk across live generations.
    pub fn disk_bytes(&self) -> u64 {
        self.spill().map_or(0, |s| s.disk.lock().disk_bytes())
    }

    /// Starts a new generation when the live generations pass 80% of the disk limit, and returns
    /// their bytes. Other files in the data directory do not count: the store cannot shrink them.
    pub fn enforce_disk_limit(&self) -> u64 {
        // One critical section: a put-path rotation between the check and the rotation would
        // make this rotation delete the generation that was current a moment before.
        self.spill().map_or(0, |s| {
            s.with_disk(|d| {
                let used = d.disk_bytes();
                if used > d.limit / 10 * 8 {
                    d.rotate_once();
                }
                used
            })
        })
    }

    /// Starts a new generation now, dropping the one before the previous.
    pub fn rotate_now(&self) {
        if let Some(s) = self.spill() {
            s.with_disk(Disk::rotate_once);
        }
    }

    /// Writes what is held in memory to disk (for shutdown), newest first, one
    /// [`SPILL_BATCH`] per transaction. From its start the store rotates at most once more,
    /// whoever asks: a second rotation would delete the newest entries the flush wrote, so what
    /// does not fit after that is dropped, and one warning gives the count. It also stops before
    /// the next batch once `stop` is set.
    pub fn flush(&self, stop: &AtomicBool) {
        let Some(spill) = self.spill() else { return };
        spill.with_disk(|d| {
            d.rotations_left.get_or_insert(1);
        });
        spill.drain();
        let mut below = u64::MAX;
        loop {
            if stop.load(Ordering::Relaxed) {
                let left =
                    spill.disk.lock().pending.len() + self.mem.lock().order.range(..below).count();
                if left > 0 {
                    tracing::warn!(
                        entries = left,
                        "the shutdown flush stopped; entries are unsaved"
                    );
                }
                return;
            }
            let mut chunk = Vec::new();
            let mut bytes = 0;
            {
                let mem = self.mem.lock();
                for (&tick, key) in mem.order.range(..below).rev() {
                    if bytes >= SPILL_BATCH {
                        break;
                    }
                    below = tick;
                    let Some(e) = mem.map.get(key) else { continue };
                    bytes += e.value.len() as u64;
                    chunk.push((*key, e.value.clone()));
                }
            }
            let chunk_len = chunk.len();
            // Requests still in flight evict into the inbox while the flush runs.
            if chunk.is_empty() {
                spill.drain();
            }
            // `Some(queued)` ends the flush with `queued` entries left in the spill queue.
            let end = spill.with_disk(|d| {
                // After the one rotation every write runs as `Read`, which only queues once the
                // generation is full: nothing more reaches disk.
                if d.writer(Writer::Put) == Writer::Read && d.read_blocked {
                    return Some(d.pending.len());
                }
                if chunk.is_empty() {
                    d.write_pending(Writer::Put);
                    return Some(d.pending.len());
                }
                d.spill(chunk, Writer::Put);
                None
            });
            if let Some(queued) = end {
                let left = queued + chunk_len + self.mem.lock().order.range(..below).count();
                if left > 0 {
                    tracing::warn!(
                        entries = left,
                        "the disk store is full; shutdown leaves entries unsaved"
                    );
                }
                return;
            }
        }
    }

    fn put_any(&self, hash: B256, value: Bytes) {
        let over_cap = charge(&value) > self.cap;
        let evicted = self.mem.lock().insert(hash, value, self.cap);
        let Some(s) = self.spill() else { return };
        if over_cap {
            // `insert` handed the value straight back: it is the only copy.
            for entry in evicted {
                s.keep(entry);
            }
        } else {
            s.queue(evicted, Writer::Put);
        }
    }

    fn get_any(&self, hash: &B256) -> Option<Bytes> {
        if let Some(v) = self.mem.lock().touch(hash) {
            return Some(v);
        }
        let spill = self.spill()?;
        let (v, promote) = spill.read(hash)?;
        let mut evicted = self.mem.lock().insert(*hash, v.clone(), self.cap);
        // A value over the cap comes straight back: only one from `prev` is written again.
        evicted.retain(|(k, _)| k != hash);
        if promote {
            evicted.push((*hash, v.clone()));
        }
        spill.queue(evicted, Writer::Read);
        Some(v)
    }

    /// Moves the inbox to the disk tier now, as the writer thread would.
    #[cfg(test)]
    fn drain(&self) {
        self.spill().unwrap().drain();
    }

    /// The disk tier, locked.
    #[cfg(test)]
    fn disk_lock(&self) -> parking_lot::MutexGuard<'_, Disk> {
        self.spill().unwrap().disk.lock()
    }
}

impl NodeStore for Store {
    fn get(&self, hash: &B256) -> Option<Bytes> {
        self.get_any(hash)
    }
    fn put(&self, hash: B256, node: Bytes) {
        self.put_any(hash, node);
    }
    fn code(&self, hash: &B256) -> Option<Bytes> {
        self.get_any(hash)
    }
    fn put_code(&self, hash: B256, code: Bytes) {
        self.put_any(hash, code);
    }
    fn bytes(&self) -> u64 {
        let queued =
            self.spill().map_or(0, |s| s.inbox.lock().charge() + s.queued.load(Ordering::Relaxed));
        self.mem.lock().bytes + queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::Arc;

    static NO_STOP: AtomicBool = AtomicBool::new(false);

    /// A unique value of `len` bytes (at least 4) keyed by its keccak hash, as real entries are.
    fn item(i: u32, len: usize) -> (B256, Bytes) {
        let mut v = vec![(i % 251) as u8; len.max(4)];
        v[..4].copy_from_slice(&i.to_be_bytes());
        let v = Bytes::from(v);
        (keccak256(&v), v)
    }

    #[test]
    fn cache_size_docs_state_the_charged_overhead() {
        use clap::CommandFactory;
        let overhead = format!("plus {ENTRY_OVERHEAD} bytes");
        let readme = include_str!("../README.md");
        let row = readme.lines().find(|row| row.starts_with("| `--cache.size`")).unwrap();
        assert!(row.contains(&overhead), "README row: {row}");
        let cmd = crate::config::LiteArgs::command();
        let arg = cmd.get_arguments().find(|arg| arg.get_long() == Some("cache.size")).unwrap();
        let help = arg.get_long_help().or_else(|| arg.get_help()).unwrap().to_string();
        assert!(help.contains(&overhead), "--cache.size help: {help}");
    }

    #[test]
    fn corrupted_disk_bytes_are_treated_as_absent_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 1_000, MIN_DISK_LIMIT).unwrap();
        let items: Vec<_> = (0..50).map(|i| item(i, 200)).collect();
        for (k, v) in &items {
            s.put(*k, v.clone());
        }
        s.flush(&NO_STOP);
        // Flip the bytes of one entry on disk.
        let (k, v) = &items[0];
        let mut bad = v.to_vec();
        bad[10] ^= 0xff;
        let bad = Bytes::from(bad);
        assert!(s.disk_lock().cur.put_all([(k, &bad)]).unwrap());
        assert!(!s.mem.lock().map.contains_key(k), "evicted from memory");
        assert_eq!(s.get(k), None, "corrupted bytes are absent, never served");
        assert_eq!(s.disk_lock().cur.get(k), None, "and deleted");
        // An intact entry still reads.
        let (k2, v2) = &items[1];
        assert_eq!(s.get(k2).as_ref(), Some(v2));
    }

    #[test]
    fn put_get_and_code() {
        let s = Store::in_memory(1 << 20);
        let (k, v) = item(1, 100);
        s.put(k, v.clone());
        assert_eq!(s.get(&k), Some(v));
        let (kc, vc) = item(2, 300);
        s.put_code(kc, vc.clone());
        assert_eq!(s.code(&kc), Some(vc));
        assert_eq!(s.get(&B256::ZERO), None);
    }

    #[test]
    fn memory_never_exceeds_the_cap_under_ten_times_load() {
        let cap = 100_000;
        let s = Store::in_memory(cap);
        for i in 0..10_000u32 {
            let (k, v) = item(i, 100);
            s.put(k, v);
            assert!(s.bytes() <= cap, "{} > {cap}", s.bytes());
        }
        assert!(s.bytes() > cap / 2);
    }

    #[test]
    fn eviction_returns_none_never_wrong_data() {
        let s = Store::in_memory(2_000);
        let (first_k, first_v) = item(0, 200);
        s.put(first_k, first_v);
        for i in 1..100u32 {
            let (k, v) = item(i, 200);
            s.put(k, v);
        }
        assert_eq!(s.get(&first_k), None);
        // A recent one is still right.
        let (k, v) = item(99, 200);
        assert_eq!(s.get(&k), Some(v));
    }

    #[test]
    fn lru_keeps_recently_read_entries() {
        let s = Store::in_memory(1_500);
        let (hot_k, hot_v) = item(0, 200);
        s.put(hot_k, hot_v.clone());
        for i in 1..50u32 {
            let (k, v) = item(i, 200);
            s.put(k, v);
            assert_eq!(s.get(&hot_k), Some(hot_v.clone()));
        }
    }

    #[test]
    fn an_oversized_value_does_not_break_the_cap() {
        let s = Store::in_memory(1_000);
        let (k, v) = item(1, 5_000);
        s.put(k, v);
        assert!(s.bytes() <= 1_000);
        assert_eq!(s.get(&k), None);
    }

    #[test]
    fn a_put_over_the_cap_is_kept_while_the_writer_is_behind() {
        let dir = tempfile::tempdir().unwrap();
        // `--cache.size 0`: every put comes straight back from the memory tier.
        let s = Arc::new(Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap());
        // One chunk of 64 codes at the size limit: more than the inbox holds.
        let codes: Vec<_> = (0..64).map(|i| item(i, 24 * 1024)).collect();
        assert!(codes.iter().map(|(_, v)| v.len() as u64).sum::<u64>() > MAX_PENDING);
        // The writer is in a long disk section (a steady sync or a rotation).
        let (locked_tx, locked) = std::sync::mpsc::channel();
        let busy = std::thread::spawn({
            let s = s.clone();
            move || {
                let _disk = s.disk_lock();
                locked_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        locked.recv_timeout(Duration::from_secs(10)).unwrap();
        for (k, v) in &codes {
            s.put_code(*k, v.clone());
        }
        busy.join().unwrap();
        for (i, (k, v)) in codes.iter().enumerate() {
            assert!(s.code(k).is_some_and(|c| c == *v), "code {i} was dropped");
        }
    }

    #[test]
    fn spilled_entries_come_back_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 4_000, MIN_DISK_LIMIT).unwrap();
        let items: Vec<_> = (0..200).map(|i| item(i, 200)).collect();
        for (k, v) in &items {
            s.put(*k, v.clone());
        }
        assert!(s.mem.lock().bytes <= 4_000);
        for (k, v) in &items {
            assert_eq!(s.get(k).as_ref(), Some(v));
        }
    }

    #[test]
    fn read_back_across_a_rotation_keeps_both_generations() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 4_000, MIN_DISK_LIMIT).unwrap();
        let items: Vec<_> = (0..400).map(|i| item(i, 200)).collect();
        // The first half ends up in the previous generation, the second half in the current.
        for (k, v) in &items[..200] {
            s.put(*k, v.clone());
        }
        s.flush(&NO_STOP);
        s.rotate_now();
        for (k, v) in &items[200..] {
            s.put(*k, v.clone());
        }
        s.flush(&NO_STOP);
        // Reading everything back promotes the old half and spills evictions: neither may
        // rotate away the generation being read.
        for (k, v) in &items {
            assert_eq!(s.get(k).as_ref(), Some(v));
        }
        for (k, v) in &items {
            assert_eq!(s.get(k).as_ref(), Some(v));
        }
    }

    #[test]
    fn rotation_deletes_the_old_generation_and_bounds_disk() {
        let dir = tempfile::tempdir().unwrap();
        let limit = MIN_DISK_LIMIT;
        let s = Store::open(dir.path(), 2_000, limit).unwrap();
        // Far more data than the limit.
        for i in 0..40_000u32 {
            let (k, v) = item(i, 1_000);
            s.put(k, v);
            s.drain();
            if i % 1_000 == 0 {
                assert!(s.disk_bytes() <= limit, "{} > {limit}", s.disk_bytes());
            }
        }
        assert!(s.disk_bytes() <= limit);
        let gens: Vec<_> = fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert!(gens.len() <= 2, "{} generations", gens.len());
        assert!(!gens.is_empty());
        // The earliest data is gone, never wrong.
        let (k0, _) = item(0, 1_000);
        assert_eq!(s.get(&k0), None);
        // The latest is there.
        let (k, v) = item(39_999, 1_000);
        assert_eq!(s.get(&k), Some(v));
    }

    #[test]
    fn a_generation_fills_to_a_useful_share_of_its_cap_before_it_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), 32 << 20).unwrap();
        let mut i = 0;
        while d.cur.id == 0 {
            d.spill(vec![item(i, 420)], Writer::Put);
            d.cur.sync_if_due();
            i += 1;
        }
        let first = d.prev.as_ref().unwrap();
        let stored = first.env.stat().unwrap().entries() as u64 * 420;
        // Random keys cost about twice their value bytes in B-tree pages, so 30% is near full.
        assert!(stored * 100 >= d.gen_cap * 30, "{stored} of {} stored", d.gen_cap);
    }

    /// Writes items straight into `cur` until MDBX holds at least `ROTATE_PERCENT` of its cap.
    /// Batches stay small: a commit copies about one page per random key, and the pages the last
    /// commit retired cannot be reused yet, so a big batch would hit `MapFull` below the mark.
    fn fill_cur(d: &Disk) -> Vec<B256> {
        let mut keys = Vec::new();
        let mut i = 1_000_000;
        while d.cur.used_bytes() < d.gen_cap / 100 * ROTATE_PERCENT {
            let batch: Vec<_> = (i..i + 4).map(|j| item(j, 420)).collect();
            assert!(d.cur.put_all(batch.iter().map(|(k, v)| (k, v))).unwrap());
            d.cur.sync_if_due();
            keys.extend(batch.iter().map(|(k, _)| *k));
            i += 4;
        }
        keys
    }

    /// The fsyncs MDBX makes while a `cap`-sized generation takes 16 MiB of written pages, with
    /// a sync check after each commit when `sync` is set.
    fn fsyncs_for_16_mib(cap: u64, sync: bool) -> u64 {
        let dir = tempfile::tempdir().unwrap();
        let g = Generation::open(dir.path(), 0, cap).unwrap();
        let ops = || g.env.info().unwrap().page_ops();
        let (start, page) = (ops().fsync, u64::from(g.env.stat().unwrap().page_size()));
        let mut i = 0;
        while (ops().cow + ops().newly) * page < 16 << 20 {
            let batch: Vec<_> = (i..i + 500).map(|j| item(j, 500)).collect();
            assert!(g.put_all(batch.iter().map(|(k, v)| (k, v))).unwrap());
            if sync {
                g.sync_if_due();
            }
            i += 500;
        }
        ops().fsync - start
    }

    #[test]
    fn a_large_generation_syncs_once_per_thirty_second_of_its_cap() {
        // 1 GiB syncs every 32 MiB.
        assert_eq!(fsyncs_for_16_mib(1 << 30, true), 0);
        // Positive control: 64 MiB syncs every 2 MiB.
        assert!(fsyncs_for_16_mib(64 << 20, true) >= 8);
    }

    #[test]
    fn a_sync_while_another_thread_commits_keeps_the_generation_whole() {
        // `with_disk` syncs after it releases the disk lock, so a sync can meet a commit.
        // Before the fix MDBX took a sync during an open write as part of that write, and the
        // two wrote the same meta page: an MDBX assertion aborted the process.
        let dir = tempfile::tempdir().unwrap();
        let g = Arc::new(Generation::open(dir.path(), 0, 64 << 20).unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let syncer = std::thread::spawn({
            let (g, stop) = (g.clone(), stop.clone());
            move || {
                let mut syncs = 0;
                while !stop.load(Ordering::Relaxed) {
                    if g.sync().is_ok() {
                        syncs += 1;
                    }
                }
                syncs
            }
        });
        let start = std::time::Instant::now();
        let mut i = 0;
        while start.elapsed() < std::time::Duration::from_secs(2) {
            let batch: Vec<_> = (i..i + 20).map(|j| item(j, 300)).collect();
            assert!(g.put_all(batch.iter().map(|(k, v)| (k, v))).unwrap());
            i += 20;
        }
        stop.store(true, Ordering::Relaxed);
        assert!(syncer.join().unwrap() > 0, "the sync thread never synced");
        let (k, v) = item(0, 300);
        assert_eq!(g.get(&k), Some(v));
    }

    #[test]
    fn a_commit_never_fsyncs() {
        // A commit runs under the disk lock. The positive control above syncs this generation.
        assert_eq!(fsyncs_for_16_mib(64 << 20, false), 0);
    }

    #[test]
    fn puts_queued_reads_and_the_byte_gauge_never_wait_for_the_disk_lock() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(Store::open(dir.path(), 4_000, MIN_DISK_LIMIT).unwrap());
        let items: Vec<_> = (0..200).map(|i| item(i, 200)).collect();
        // Stands in for a commit, a sync or a rotation.
        let held = s.disk_lock();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn({
            let (s, items) = (s.clone(), items.clone());
            move || {
                for (k, v) in &items {
                    s.put(*k, v.clone());
                }
                tx.send((s.bytes(), s.get(&items[0].0))).unwrap();
            }
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        let (bytes, first) = got.expect("a put, a read or the gauge waited for the disk lock");
        assert!(bytes > 4_000, "the queue is charged: {bytes}");
        assert_eq!(first.as_ref(), Some(&items[0].1), "an evicted entry reads back from the queue");
    }

    #[test]
    fn the_inbox_drops_what_comes_past_its_bound() {
        let mut inbox = Inbox::default();
        assert!(inbox.push((0..2_000).map(|i| item(i, 1_000)).collect(), Writer::Put));
        assert_eq!(inbox.bytes, MAX_PENDING.div_ceil(1_000) * 1_000);
        assert_eq!(inbox.items.len() as u64, MAX_PENDING.div_ceil(1_000));
    }

    #[test]
    fn the_writer_thread_writes_an_inbox_that_holds_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 1_000, MIN_DISK_LIMIT).unwrap();
        let items: Vec<_> = (0..400).map(|i| item(i, 1_000)).collect();
        for (k, v) in &items {
            s.put(*k, v.clone());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while s.disk_lock().cur.get(&items[0].0).is_none() {
            assert!(std::time::Instant::now() < deadline, "the writer thread wrote nothing");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(s.get(&items[0].0).as_ref(), Some(&items[0].1));
    }

    #[test]
    fn flush_saves_a_memory_tier_larger_than_one_generation_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let (cap, limit) = (8 << 20, MIN_DISK_LIMIT);
        let items: Vec<_> = (0..5_000).map(|i| item(i, 1_000)).collect();
        {
            let s = Store::open(dir.path(), cap, limit).unwrap();
            for (k, v) in &items {
                s.put(*k, v.clone());
            }
            assert_eq!(s.mem.lock().map.len(), items.len(), "nothing evicted before the flush");
            assert_eq!(warnings(|| s.flush(&NO_STOP)), "");
        }
        let s = Store::open(dir.path(), cap, limit).unwrap();
        let lost = items.iter().filter(|(k, v)| s.get(k).as_ref() != Some(v)).count();
        assert_eq!(lost, 0, "of {}", items.len());
    }

    #[test]
    fn flush_rotates_at_most_once() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 4 << 20, MIN_DISK_LIMIT).unwrap();
        let old_cur = fill_cur(&s.disk_lock());
        for i in 0..2_900 {
            let (k, v) = item(i, 1_000);
            s.put(k, v);
        }
        s.flush(&NO_STOP);
        assert_eq!(s.disk_lock().cur.id, 1);
        assert!(s.get(&old_cur[0]).is_some(), "the full generation survives as the previous one");
    }

    /// How many of `items` a fresh store over `dir` reads back from disk.
    fn saved(dir: &Path, items: &[(B256, Bytes)]) -> usize {
        let s = Store::open(dir, 0, MIN_DISK_LIMIT).unwrap();
        items.iter().filter(|(k, v)| s.get(k).as_ref() == Some(v)).count()
    }

    #[test]
    fn a_stopped_flush_saves_nothing_more_and_warns_with_the_count_it_left() {
        let dir = tempfile::tempdir().unwrap();
        let items: Vec<_> = (0..2_000).map(|i| item(i, 1_000)).collect();
        let out = {
            let s = Store::open(dir.path(), 8 << 20, MIN_DISK_LIMIT).unwrap();
            for (k, v) in &items {
                s.put(*k, v.clone());
            }
            warnings(|| s.flush(&AtomicBool::new(true)))
        };
        assert_eq!(saved(dir.path(), &items), 0);
        assert!(
            out.contains("the shutdown flush stopped; entries are unsaved") &&
                out.contains("entries=2000"),
            "logged:\n{out}"
        );
    }

    #[test]
    fn disk_checks_after_the_flush_starts_never_delete_what_it_saved() {
        let dir = tempfile::tempdir().unwrap();
        let items: Vec<_> = (0..2_000).map(|i| item(i, 1_000)).collect();
        {
            let s = Store::open(dir.path(), 8 << 20, MIN_DISK_LIMIT).unwrap();
            for (k, v) in &items {
                s.put(*k, v.clone());
            }
            s.flush(&NO_STOP);
            // A disk check the gauges task started before shutdown runs on its blocking thread.
            s.rotate_now();
            s.rotate_now();
            assert_eq!(s.disk_lock().cur.id, 1, "one rotation after the flush starts");
        }
        assert_eq!(saved(dir.path(), &items), items.len());
    }

    #[test]
    fn a_late_put_after_the_flush_never_deletes_what_it_saved() {
        let dir = tempfile::tempdir().unwrap();
        // Fits the memory tier: nothing is evicted, and so nothing dropped, before the flush.
        let items: Vec<_> = (0..1_500).map(|i| item(i, 1_000)).collect();
        {
            let s = Store::open(dir.path(), 2 << 20, MIN_DISK_LIMIT).unwrap();
            for (k, v) in &items {
                s.put(*k, v.clone());
            }
            s.flush(&NO_STOP);
            s.rotate_now();
            fill_cur(&s.disk_lock());
            // A request still in flight evicts a batch into the full current generation.
            for i in 10_000..13_000 {
                let (k, v) = item(i, 1_000);
                s.put(k, v);
            }
            s.drain();
            assert_eq!(s.disk_lock().cur.id, 1, "one rotation after the flush starts");
        }
        assert_eq!(saved(dir.path(), &items), items.len());
    }

    #[test]
    fn rotate_now_rotates_once_when_the_pending_write_already_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 4_000, MIN_DISK_LIMIT).unwrap();
        let old_cur = {
            let mut d = s.disk_lock();
            let keys = fill_cur(&d);
            assert!(!d.spill(vec![item(0, 420)], Writer::Put), "queued, not written");
            keys
        };
        s.rotate_now();
        assert_eq!(s.disk_lock().cur.id, 1);
        assert!(s.get(&old_cur[0]).is_some(), "the full generation survives as the previous one");
    }

    #[test]
    fn a_read_triggered_write_into_a_full_generation_keeps_the_queue() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        fill_cur(&d);
        let evicted: Vec<_> = (0..600).map(|i| item(i, 420)).collect();
        assert!(!d.spill(evicted.clone(), Writer::Put), "under one batch: queued");
        // Pushes the queue past one batch, so the read path writes.
        let promoted: Vec<_> = (600..700).map(|i| item(i, 420)).collect();
        assert!(!d.spill(promoted.clone(), Writer::Read), "a read never rotates");
        for (k, v) in evicted.iter().chain(&promoted) {
            assert_eq!(d.read(k), Some((v.clone(), false)), "still queued");
        }
        // The next put-path write rotates and writes the whole queue.
        assert!(d.spill(vec![item(700, 420)], Writer::Put));
        assert!(d.pending.is_empty());
        for (k, v) in evicted.iter().chain(&promoted) {
            assert_eq!(d.cur.get_verified(k).as_ref(), Some(v));
        }
    }

    #[test]
    fn the_smallest_generation_holds_a_full_read_blocked_queue() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        fill_cur(&d);
        let mut queued = Vec::new();
        for i in 0.. {
            let it = item(i, 532);
            d.spill(vec![it.clone()], Writer::Read);
            if !d.pending.contains_key(&it.0) {
                break;
            }
            queued.push(it);
        }
        assert!(d.pending_bytes >= MAX_PENDING);
        // The largest put-path batch: one value short of a spill batch, then the one that writes.
        let put: Vec<_> =
            (1_000_000..).map(|i| item(i, 532)).take((SPILL_BATCH / 532) as usize).collect();
        assert!(d.spill(put.clone(), Writer::Put), "rotates");
        let all = queued.len() + put.len();
        let lost =
            queued.iter().chain(&put).filter(|(k, v)| d.cur.get(k).as_ref() != Some(v)).count();
        assert_eq!(lost, 0, "of {all}");
    }

    #[test]
    fn a_read_batch_that_does_not_fit_stays_queued() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        let big: Vec<_> = (0..10_000).map(|i| item(i, 1_000)).collect();
        assert!(!d.spill(big.clone(), Writer::Read));
        assert!(d.read_blocked);
        assert_eq!(d.pending.len(), big.len());
        assert_eq!(d.read(&big[0].0), Some((big[0].1.clone(), false)));
    }

    #[test]
    fn a_blocked_read_path_queues_at_most_max_pending() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        fill_cur(&d);
        for i in 0..10_000 {
            d.spill(vec![item(i, 420)], Writer::Read);
            assert!(d.pending_bytes < MAX_PENDING + 420, "{} queued", d.pending_bytes);
        }
        assert!(d.pending_bytes >= MAX_PENDING);
    }

    #[test]
    fn a_batch_too_big_for_an_empty_generation_never_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        let (k, v) = item(0, 420);
        assert!(d.cur.put_all([(&k, &v)]).unwrap());
        d.rotate().unwrap();
        let big: Vec<_> = (1..10_000).map(|i| item(i, 1_000)).collect();
        d.pending.extend(big);
        assert!(!d.write_pending(Writer::Put));
        assert_eq!(d.cur.id, 1);
        assert_eq!(d.read(&k), Some((v, true)), "the previous generation is kept");
    }

    /// Runs `f` and returns the lines it logged at `WARN` or above.
    fn warnings(f: impl FnOnce()) -> String {
        let logs = crate::testing::logs::capture(tracing::Level::WARN);
        f();
        logs.text()
    }

    #[test]
    fn a_dropped_spill_batch_is_logged_as_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        let big: Vec<_> = (0..10_000).map(|i| item(i, 1_000)).collect();
        d.pending_bytes = 10_000 * 1_000;
        d.pending.extend(big);
        let out = warnings(|| assert!(!d.write_pending(Writer::Put)));
        assert!(
            out.contains("spill batch is larger than a disk generation; dropping it") &&
                out.contains("entries=10000 bytes=10000000"),
            "{out}"
        );
    }

    #[test]
    fn a_flush_that_cannot_save_everything_warns_with_the_count_it_left() {
        let dir = tempfile::tempdir().unwrap();
        let (cap, limit) = (24 << 20, MIN_DISK_LIMIT);
        let items: Vec<_> = (0..12_000).map(|i| item(i, 1_000)).collect();
        let out = {
            let s = Store::open(dir.path(), cap, limit).unwrap();
            for (k, v) in &items {
                s.put(*k, v.clone());
            }
            warnings(|| s.flush(&NO_STOP))
        };
        let s = Store::open(dir.path(), cap, limit).unwrap();
        let lost = items.iter().filter(|(k, v)| s.get(k).as_ref() != Some(v)).count();
        assert!(lost > 0, "the memory tier must not fit in two generations");
        assert!(
            out.contains("the disk store is full; shutdown leaves entries unsaved") &&
                out.contains(&format!("entries={lost}")),
            "{lost} lost, logged:\n{out}"
        );
    }

    /// Overwrites the data file of generation `id` under `dir` with bytes MDBX cannot read.
    fn damage(dir: &Path, id: u64) {
        let file = dir.join(format!("gen-{id}")).join("mdbx.dat");
        assert!(file.exists());
        fs::write(&file, vec![0x5a; 64 << 10]).unwrap();
    }

    #[test]
    fn a_damaged_generation_is_deleted_and_the_other_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (item(1, 300), item(2, 300));
        {
            let s = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap();
            s.put(old.0, old.1.clone());
            s.flush(&NO_STOP);
            s.rotate_now();
            s.put(new.0, new.1.clone());
            s.flush(&NO_STOP);
        }
        damage(dir.path(), 1);
        let out = warnings(|| {
            let s = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap();
            assert_eq!(s.get(&old.0).as_ref(), Some(&old.1), "the sound generation is kept");
            assert_eq!(s.get(&new.0), None);
            assert_eq!(s.disk_lock().cur.id, 0);
            assert!(s.disk_lock().prev.is_none());
        });
        assert!(
            out.contains("cannot open a disk generation; deleting it") && out.contains("gen-1"),
            "logged:\n{out}"
        );
        assert!(!dir.path().join("gen-1").exists());
    }

    #[test]
    fn a_damaged_generation_that_cannot_be_deleted_is_skipped_by_the_next_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let entry = item(1, 300);
        {
            let s = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap();
            s.put(entry.0, entry.1);
            s.flush(&NO_STOP);
            s.rotate_now();
        }
        damage(dir.path(), 1);
        // A delete that fails for any user, root included.
        let refuse = |_: &Path| Err(std::io::Error::other("refused"));
        let mut d = Disk::open_with(dir.path().to_path_buf(), MIN_DISK_LIMIT, refuse).unwrap();
        assert_eq!(d.cur.id, 0);
        d.rotate().expect("the rotation opened the damaged generation");
        assert_eq!(d.cur.id, 2);
        assert!(dir.path().join("gen-1").exists());
    }

    #[test]
    fn a_rotation_whose_open_fails_leaves_no_directory_behind() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        let gen1 = dir.path().join("gen-1");
        // MDBX cannot open a data file that is a directory; the open fails after its mkdir.
        fs::create_dir_all(gen1.join("mdbx.dat")).unwrap();
        for _ in 0..3 {
            assert!(d.rotate().is_err());
            assert!(!gen1.exists(), "a failed open left its directory");
            fs::create_dir_all(gen1.join("mdbx.dat")).unwrap();
        }
        fs::remove_dir_all(&gen1).unwrap();
        d.rotate().unwrap();
        let mut names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!((d.cur.id, names), (1, vec!["gen-0".to_owned(), "gen-1".to_owned()]));
    }

    #[test]
    fn evictions_that_reach_the_inbox_during_the_flush_are_saved() {
        let dir = tempfile::tempdir().unwrap();
        let (early, late) = (item(1, 300), item(2, 300));
        {
            let s = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap();
            let spill = s.spill().unwrap();
            spill.queue(vec![early.clone()], Writer::Put);
            std::thread::scope(|scope| {
                // Holds the flush before its first batch.
                let mem = s.mem.lock();
                let flush = scope.spawn(|| s.flush(&NO_STOP));
                // The flush's first drain has taken the inbox.
                while !spill.inbox.lock().items.is_empty() {
                    std::thread::yield_now();
                }
                // A request still in flight evicts an entry.
                spill.queue(vec![late.clone()], Writer::Put);
                drop(mem);
                flush.join().unwrap();
            });
        }
        assert_eq!(saved(dir.path(), &[early]), 1);
        assert_eq!(saved(dir.path(), &[late]), 1, "an eviction after the first drain is lost");
    }

    #[test]
    fn a_store_whose_only_generations_are_damaged_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let entry = item(1, 300);
        {
            let s = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap();
            s.put(entry.0, entry.1.clone());
            s.flush(&NO_STOP);
            s.rotate_now();
        }
        damage(dir.path(), 0);
        damage(dir.path(), 1);
        let s = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap();
        assert_eq!(s.get(&entry.0), None);
        assert_eq!(s.disk_lock().cur.id, 2);
        s.put(entry.0, entry.1.clone());
        s.flush(&NO_STOP);
        assert_eq!(s.get(&entry.0).as_ref(), Some(&entry.1), "the new generation takes writes");
    }

    #[test]
    fn a_generation_path_that_is_not_a_directory_names_the_os_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("gen-0"), b"not a directory").unwrap();
        let err = Store::open(dir.path(), 0, MIN_DISK_LIMIT).unwrap_err();
        assert_eq!(
            err.to_string(),
            "could not create a disk generation directory: entity already exists"
        );
        assert!(dir.path().join("gen-0").is_file(), "a path MDBX did not refuse is not deleted");
    }

    #[test]
    fn a_disk_limit_below_two_generations_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for limit in [0, 2 << 20, MIN_DISK_LIMIT - 1] {
            let err = Store::open(dir.path(), 4_000, limit).unwrap_err();
            assert_eq!(err, StoreError::DiskLimit { limit });
            assert_eq!(
                err.to_string(),
                format!("--disk.limit of {limit} bytes is below the minimum of 16777216 bytes")
            );
        }
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none(), "nothing created");
        assert!(Store::open(dir.path(), 4_000, MIN_DISK_LIMIT).is_ok());
    }

    #[test]
    fn only_the_store_files_count_toward_the_disk_limit() {
        let datadir = tempfile::tempdir().unwrap();
        let limit = MIN_DISK_LIMIT;
        let s = Store::open(&datadir.path().join("store"), 4_000, limit).unwrap();
        fs::write(datadir.path().join("other"), vec![0u8; 15 << 20]).unwrap();
        assert!(s.enforce_disk_limit() < limit / 10 * 8);
        assert_eq!(s.disk_lock().cur.id, 0, "no rotation");
        // Positive control: the store's own generations past 80% rotate.
        {
            let mut d = s.disk_lock();
            fill_cur(&d);
            d.rotate().unwrap();
            fill_cur(&d);
        }
        assert!(s.enforce_disk_limit() > limit / 10 * 8);
        assert_eq!(s.disk_lock().cur.id, 2);
    }

    #[test]
    fn a_rotation_deletes_the_dead_generation_after_the_lock_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        d.rotate().unwrap();
        d.rotate().unwrap();
        assert!(dir.path().join("gen-0").exists(), "not deleted under the lock");
        assert_eq!(
            d.dead.iter().map(|g| g.path.clone()).collect::<Vec<_>>(),
            [dir.path().join("gen-0")]
        );

        drop(d);
        let s = Store::open(dir.path(), 4_000, MIN_DISK_LIMIT).unwrap();
        s.rotate_now();
        s.rotate_now();
        assert_eq!(names(dir.path()), ["gen-3", "gen-4"], "deleted once the lock is free");
    }

    #[test]
    fn reopen_keeps_the_two_newest_generations() {
        let dir = tempfile::tempdir().unwrap();
        let limit = MIN_DISK_LIMIT;
        {
            let s = Store::open(dir.path(), 2_000, limit).unwrap();
            for i in 0..20_000u32 {
                let (k, v) = item(i, 1_000);
                s.put(k, v);
                s.drain();
            }
            s.flush(&NO_STOP);
        }
        let ids: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(ids.len() <= 2, "{ids:?}");
        let s = Store::open(dir.path(), 2_000, limit).unwrap();
        let (k, v) = item(19_999, 1_000);
        assert_eq!(s.get(&k), Some(v));
        let after: Vec<_> = fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert!(after.len() <= 2);
    }

    /// The names under `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort_unstable();
        names
    }

    /// Entries the disk tier holds, counted without promoting anything.
    fn disk_entries(d: &Disk) -> u64 {
        let entries = |g: &Generation| g.env.stat().unwrap().entries() as u64;
        d.pending.len() as u64 + entries(&d.cur) + d.prev.as_deref().map_or(0, entries)
    }

    /// Whether the disk tier holds `key`, checked without promoting it.
    fn on_disk(d: &Disk, key: &B256) -> bool {
        d.pending.contains_key(key) ||
            d.cur.get(key).is_some() ||
            d.prev.as_ref().is_some_and(|p| p.get(key).is_some())
    }

    #[test]
    fn the_disk_tier_keeps_a_useful_share_of_its_limit_under_load() {
        let dir = tempfile::tempdir().unwrap();
        let limit = MIN_DISK_LIMIT;
        let s = Store::open(dir.path(), 2_000, limit).unwrap();
        let (mut low, mut high) = (u64::MAX, 0);
        for i in 0..u32::try_from(2 * limit / 1_000).unwrap() {
            let (k, v) = item(i, 1_000);
            s.put(k, v);
            s.drain();
            let d = s.disk_lock();
            if i % 100 == 0 && d.cur.id > 0 {
                let percent = disk_entries(&d) * 1_000 * 100 / limit;
                low = low.min(percent);
                high = high.max(percent);
            }
        }
        // Just after a rotation only the previous generation holds data, and random keys cost
        // about twice their value bytes in B-tree pages: about 19% and 34% on a 16 KiB page.
        assert!(low >= 15 && high >= 30, "the disk tier held {low}% to {high}% of its limit");
    }

    #[test]
    fn a_corrupted_entry_in_the_previous_generation_is_absent_deleted_and_not_promoted() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 1 << 20, MIN_DISK_LIMIT).unwrap();
        let (bad_k, good_v) = item(0, 200);
        let (k, v) = item(1, 200);
        {
            let mut d = s.disk_lock();
            assert!(d.cur.put_all([(&bad_k, &good_v), (&k, &v)]).unwrap());
            d.rotate().unwrap();
            let mut bad = good_v.to_vec();
            bad[10] ^= 0xff;
            assert!(d.prev.as_ref().unwrap().put_all([(&bad_k, &Bytes::from(bad))]).unwrap());
        }
        let inbox = |key| s.spill().unwrap().inbox.lock().items.get(key).map(|(v, _)| v.clone());

        assert_eq!(s.get(&bad_k), None, "corrupted bytes are absent, never served");
        assert_eq!(s.disk_lock().prev.as_ref().unwrap().get(&bad_k), None, "and deleted");
        assert_eq!(inbox(&bad_k), None, "and not promoted");
        assert_eq!(s.disk_lock().cur.get(&bad_k), None);
        // Positive control: an intact entry of the previous generation reads and is promoted.
        assert_eq!(s.get(&k), Some(v.clone()));
        assert_eq!(inbox(&k), Some(v));
    }

    #[test]
    fn a_read_into_a_full_generation_neither_rotates_nor_loses_the_previous_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Disk::open(dir.path().to_path_buf(), MIN_DISK_LIMIT).unwrap();
        let (old_k, old_v) = item(10_000, 420);
        assert!(d.cur.put_all([(&old_k, &old_v)]).unwrap());
        d.rotate().unwrap();
        fill_cur(&d);
        let evicted: Vec<_> = (0..600).map(|i| item(i, 420)).collect();
        assert!(!d.spill(evicted.clone(), Writer::Put), "under one batch: queued");
        assert!(!d.spill((600..700).map(|i| item(i, 420)).collect(), Writer::Read));
        assert!(d.read_blocked);
        assert_eq!(d.cur.id, 1, "a read never rotates");
        assert_eq!(
            d.read(&old_k),
            Some((old_v.clone(), true)),
            "the previous generation survives, and its entry is due a promotion"
        );

        // The next put-path write carries the promotion and rotates gen-0 away.
        assert!(d.spill(vec![(old_k, old_v.clone()), item(700, 420)], Writer::Put));
        assert_eq!(d.cur.id, 2);
        for (k, v) in evicted.iter().chain([&(old_k, old_v)]) {
            assert_eq!(d.cur.get_verified(k).as_ref(), Some(v));
        }
    }

    #[test]
    fn code_evicted_to_disk_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path(), 1_000, MIN_DISK_LIMIT).unwrap();
        let codes: Vec<_> = (0..50).map(|i| item(i, 300)).collect();
        for (k, v) in &codes {
            s.put_code(*k, v.clone());
        }
        s.flush(&NO_STOP);
        let (k0, v0) = &codes[0];
        assert!(!s.mem.lock().map.contains_key(k0), "evicted from memory");
        assert_eq!(s.disk_lock().cur.get(k0).as_ref(), Some(v0), "on disk");
        for (k, v) in &codes {
            assert_eq!(s.code(k).as_ref(), Some(v));
        }
    }

    #[test]
    fn a_disk_read_too_big_for_memory_queues_only_a_promotion() {
        let dir = tempfile::tempdir().unwrap();
        // A charge of 1384 bytes: over a cap of 0 (no memory tier) and over a small cap.
        let (k, v) = item(0, 1_000);
        let (old_k, old_v) = item(1, 1_000);
        for cap in [0, 300] {
            let s = Store::open(&dir.path().join(cap.to_string()), cap, MIN_DISK_LIMIT).unwrap();
            {
                let mut d = s.disk_lock();
                assert!(d.cur.put_all([(&old_k, &old_v)]).unwrap());
                d.rotate().unwrap();
                assert!(d.cur.put_all([(&k, &v)]).unwrap());
            }
            let inbox =
                |key| s.spill().unwrap().inbox.lock().items.get(key).map(|(v, _)| v.clone());
            assert_eq!(s.get(&k).as_ref(), Some(&v));
            assert!(
                inbox(&k).is_none(),
                "cap {cap}: an entry of the current generation is rewritten"
            );
            assert_eq!(s.get(&old_k).as_ref(), Some(&old_v));
            assert!(inbox(&old_k) == Some(old_v.clone()), "cap {cap}: no promotion");
            assert_eq!(s.mem.lock().bytes, 0);
        }
    }

    #[test]
    fn open_keeps_the_two_newest_generations_and_ignores_other_names() {
        let dir = tempfile::tempdir().unwrap();
        let limit = MIN_DISK_LIMIT;
        let entries: Vec<_> = [3, 10, 7]
            .into_iter()
            .map(|id| {
                let g = Generation::open(dir.path(), id, limit / 2).unwrap();
                let (k, v) = item(u32::try_from(id).unwrap(), 200);
                assert!(g.put_all([(&k, &v)]).unwrap());
                (id, k, v)
            })
            .collect();
        for other in ["gen-", "gen-x", "gen--1", "other"] {
            fs::create_dir(dir.path().join(other)).unwrap();
        }

        let d = Disk::open(dir.path().to_path_buf(), limit).unwrap();
        assert_eq!((d.prev.as_ref().unwrap().id, d.cur.id), (7, 10));
        assert_eq!(names(dir.path()), ["gen-", "gen--1", "gen-10", "gen-7", "gen-x", "other"]);
        for (id, k, v) in &entries {
            let want = (*id != 3).then(|| v.clone());
            assert_eq!(d.read(k), want.map(|v| (v, *id == 7)), "gen-{id}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn mem_charges_what_it_holds_and_hands_back_what_it_drops(
            cap in 0..20_000u64,
            ops in proptest::collection::vec((any::<bool>(), 0..64u32), 1..200),
        ) {
            let mut m = Mem::default();
            for (insert, i) in ops {
                // One length per key, some larger than any cap.
                let (k, v) = item(i, i as usize * 61 % 2_500);
                if insert {
                    let before: Vec<B256> = m.map.keys().copied().collect();
                    let evicted = m.insert(k, v, cap);
                    for (ek, ev) in &evicted {
                        prop_assert_eq!(keccak256(ev), *ek);
                        prop_assert!(!m.map.contains_key(ek), "evicted and still held");
                    }
                    // Nothing leaves the tier without going to the disk tier.
                    for gone in before.iter().filter(|b| !m.map.contains_key(*b)) {
                        prop_assert!(evicted.iter().any(|(e, _)| e == gone), "dropped silently");
                    }
                    prop_assert!(m.map.contains_key(&k) || evicted.iter().any(|(e, _)| *e == k));
                } else if let Some(got) = m.touch(&k) {
                    prop_assert_eq!(got, v);
                }
                prop_assert!(m.bytes <= cap, "{} > {cap}", m.bytes);
                prop_assert_eq!(m.bytes, m.map.values().map(|e| charge(&e.value)).sum::<u64>());
                prop_assert_eq!(m.map.len(), m.order.len());
                for (tick, key) in &m.order {
                    prop_assert_eq!(m.map[key].tick, *tick);
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        /// Puts `n` keys never put before.
        Put(u32),
        /// Reads `n` keys from the `back`-th newest on: a long run promotes a batch out of `prev`.
        Get {
            back: u32,
            n: u32,
        },
        Flush,
        RotateNow,
        Reopen,
        /// Writes flipped bytes under the `back`-th newest key in `cur` or `prev`.
        Corrupt {
            back: u32,
            prev: bool,
        },
    }

    /// The `i`-th key a model run puts: one length per key, 100 to 1,000 bytes.
    fn nth(i: u32) -> (B256, Bytes) {
        item(i, 100 + (i % 7) as usize * 150)
    }

    fn store_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => Just(Op::Put(1)),
            3 => (1..1_000u32).prop_map(Op::Put),
            3 => (1..4_000u32).prop_map(|back| Op::Get { back, n: 1 }),
            2 => (1..4_000u32, 1..600u32).prop_map(|(back, n)| Op::Get { back, n }),
            1 => Just(Op::Flush),
            2 => Just(Op::RotateNow),
            1 => Just(Op::Reopen),
            2 => (1..4_000u32, any::<bool>()).prop_map(|(back, prev)| Op::Corrupt { back, prev }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn the_disk_store_never_serves_a_wrong_value_or_breaks_its_bounds(
            ops in proptest::collection::vec(store_op(), 1..12),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let (cap, limit) = (8_000, MIN_DISK_LIMIT);
            let mut s = Store::open(dir.path(), cap, limit).unwrap();
            let mut next = 0u32;
            for op in ops {
                match op {
                    Op::Put(n) => {
                        for i in next..next + n {
                            let (k, v) = nth(i);
                            s.put(k, v);
                            s.drain();
                        }
                        next += n;
                    }
                    Op::Get { back, n } => {
                        let queued: Vec<B256> =
                            s.disk_lock().pending.keys().copied().collect();
                        for i in next.saturating_sub(back)..next.saturating_sub(back) + n {
                            let (k, v) = nth(i);
                            let got = s.get(&k);
                            prop_assert!(got.is_none() || got == Some(v), "wrong value for {k}");
                        }
                        // Keys are never put twice, so a queued entry has no other copy.
                        let d = s.disk_lock();
                        for q in &queued {
                            prop_assert!(on_disk(&d, q), "a read dropped a queued entry");
                        }
                    }
                    Op::Flush => s.flush(&NO_STOP),
                    Op::RotateNow => {
                        let held: Vec<B256> = {
                            let d = s.disk_lock();
                            (next.saturating_sub(2_000)..next)
                                .map(|i| nth(i).0)
                                .filter(|k| d.pending.contains_key(k) || d.cur.get(k).is_some())
                                .collect()
                        };
                        s.rotate_now();
                        // One rotation keeps the current generation as the previous one.
                        let d = s.disk_lock();
                        for k in &held {
                            prop_assert!(on_disk(&d, k), "rotate_now lost {k}");
                        }
                    }
                    Op::Reopen => {
                        drop(s);
                        s = Store::open(dir.path(), cap, limit).unwrap();
                    }
                    Op::Corrupt { back, prev } => {
                        let (k, v) = nth(next.saturating_sub(back));
                        let mut bad = v.to_vec();
                        bad[0] ^= 0xff;
                        let bad = Bytes::from(bad);
                        {
                            let d = s.disk_lock();
                            let g = if prev { d.prev.as_ref() } else { Some(&d.cur) };
                            // A full generation refuses the write, which is fine here.
                            if let Some(g) = g {
                                g.put_all([(&k, &bad)]).unwrap();
                            }
                        }
                        let got = s.get(&k);
                        prop_assert!(got.is_none() || got == Some(v), "served corrupted bytes");
                    }
                }
                prop_assert!(s.mem.lock().bytes <= cap, "{} > {cap}", s.mem.lock().bytes);
                prop_assert!(s.disk_bytes() <= limit, "{} > {limit}", s.disk_bytes());
                let gens = names(dir.path()).len();
                prop_assert!((1..=2).contains(&gens), "{gens} generations");
            }
        }
    }
}
