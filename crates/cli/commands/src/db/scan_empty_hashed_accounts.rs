//! `reth db scan-empty-hashed-accounts`: finds `HashedAccounts` rows that EIP-161 deleted.
//!
//! Before upstream reth #27252, the state root task wrote EIP-161-deleted accounts into
//! `HashedAccounts` as all-zero rows, while `PlainAccountState` removed them. Nothing fails until
//! the affected trie branch is fully recomputed. Then the state root diverges.
//!
//! Pre-EIP-161 empty accounts that nothing has touched since are legitimately present as
//! all-zero rows. The command separates them from bug rows in one of two modes:
//!
//! - `v1` (storage v1): a row is legit if its preimage is also an all-zero row in
//!   `PlainAccountState`.
//! - `v2` (storage v2, no plain state): a row is legit if the stored `AccountsTrie` contains it.
//!   The bug rows never reached the trie, because the state root treated them as removals.

use alloy_consensus::BlockHeader;
use alloy_primitives::{keccak256, B256, KECCAK256_EMPTY};
use clap::Parser;
use reth_db_api::{
    cursor::DbCursorRO, database::Database, table::Table, tables, transaction::DbTx,
};
use reth_db_common::DbTool;
use reth_primitives_traits::Account;
use reth_provider::{providers::ProviderNodeTypes, HeaderProvider};
use reth_stages::StageId;
use reth_storage_api::StorageSettingsCache;
use reth_trie::{
    BranchNodeCompact, BranchNodeRef, ExtensionNodeRef, LeafNodeRef, Nibbles, RlpNode, StorageRoot,
    TrieMask,
};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStorageRoot, DatabaseTrieCursorFactory, TrieTableAdapter,
};
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};
use tracing::info;

const PROGRESS_PERIOD: Duration = Duration::from_secs(5);

/// Maximum number of sample hashed addresses kept per class for the report.
const MAX_SAMPLES: usize = 10;

/// Maximum number of `HashedAccounts` rows the v2 mode rehashes to rebuild one trie node.
const MAX_REHASH_ROWS: usize = 4096;

/// Maximum number of empty rows in one rehashed subtree. The check tries every subset of them.
const MAX_EMPTY_IN_SUBTREE: usize = 8;

/// The arguments for the `reth db scan-empty-hashed-accounts` command.
///
/// Read-only. Safe to run against the datadir of a running node.
#[derive(Parser, Debug)]
pub struct Command {
    /// Maximum number of rows to read per second, over all passes. 0 disables the throttle.
    #[arg(long, default_value_t = 200_000)]
    max_rows_per_sec: u64,

    /// Abort if the set of all-zero accounts held in memory grows above this. v1 holds the
    /// all-zero `PlainAccountState` accounts, v2 the all-zero `HashedAccounts` rows. About 32 to
    /// 64 bytes per entry; the default of 20M costs up to about 1.3 GB (640 MB in v2).
    #[arg(long, default_value_t = 20_000_000)]
    max_plain_empty: usize,

    /// Renew the read transaction after this many rows. Short transactions stop a live node's
    /// database from growing while the scan runs.
    #[arg(long, default_value_t = 1_000_000)]
    renew_every_rows: u64,

    /// Renew the read transaction after this many seconds.
    #[arg(long, default_value_t = 5)]
    renew_every_secs: u64,
}

impl Command {
    /// Execute `db scan-empty-hashed-accounts` command
    pub fn execute<N: ProviderNodeTypes>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        let options = ScanOptions {
            max_rows_per_sec: self.max_rows_per_sec,
            max_plain_empty: self.max_plain_empty,
            renew_every_rows: self.renew_every_rows.max(1),
            renew_every: Duration::from_secs(self.renew_every_secs.max(1)),
        };
        let db = tool.provider_factory.db_ref();
        // Storage v2 keeps no `PlainAccountState`, so it needs the trie method.
        let report = if tool.provider_factory.cached_storage_settings().use_hashed_state() {
            info!(target: "reth::cli", "Storage v2: classifying rows against AccountsTrie");
            // The trie in a transaction matches the state at the Finish checkpoint that the same
            // transaction reads, because the node commits both together.
            let state_root = |tx: &<N::DB as Database>::TX| -> eyre::Result<Option<B256>> {
                let Some(block_number) = trie_block_number(tx)? else { return Ok(None) };
                Ok(tool
                    .provider_factory
                    .header_by_number(block_number)?
                    .map(|header| header.state_root()))
            };
            reth_trie_db::with_adapter!(tool.provider_factory, |A| scan_trie::<_, A>(
                db, &options, state_root
            ))?
        } else {
            info!(target: "reth::cli", "Storage v1: classifying rows against PlainAccountState");
            scan(db, &options)?
        };
        println!("{report}");
        Ok(())
    }
}

/// Tuning for [`scan`] and [`scan_trie`].
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum rows read per second. 0 disables the throttle.
    pub max_rows_per_sec: u64,
    /// Maximum size of the set of all-zero accounts held in memory.
    pub max_plain_empty: usize,
    /// Renew the read transaction after this many rows.
    pub renew_every_rows: u64,
    /// Renew the read transaction after this much time.
    pub renew_every: Duration,
}

/// Classification method used by a scan.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Compare against `PlainAccountState`.
    #[default]
    V1,
    /// Compare against the stored `AccountsTrie`.
    V2,
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        })
    }
}

/// Result of [`scan`] or [`scan_trie`].
#[derive(Debug, Default)]
pub struct ScanReport {
    /// Method that classified the rows.
    pub mode: ScanMode,
    /// Rows read from `PlainAccountState` (v1 only).
    pub plain_rows: u64,
    /// All-zero rows in `PlainAccountState` (v1 only).
    pub plain_empty: u64,
    /// Rows read from `HashedAccounts`.
    pub hashed_rows: u64,
    /// All-zero rows in `HashedAccounts`.
    pub hashed_empty: u64,
    /// All-zero hashed rows that the reference (plain state or trie) confirms.
    pub legit: u64,
    /// All-zero hashed rows that the reference proves absent.
    pub suspects: u64,
    /// All-zero hashed rows that the scan could not decide (v2 only).
    pub undetermined: u64,
    /// All-zero rows that the node changed before the trie check (v2 only).
    pub changed: u64,
    /// Suspects that still have `HashedStorages` entries (v2 only).
    pub suspects_with_storage: u64,
    /// Up to [`MAX_SAMPLES`] suspect hashed addresses, with the reason.
    pub suspect_samples: Vec<(B256, &'static str)>,
    /// Up to [`MAX_SAMPLES`] undetermined hashed addresses, with the reason.
    pub undetermined_samples: Vec<(B256, &'static str)>,
    /// Number of read transactions opened.
    pub transactions: u64,
    /// Wall time of all passes.
    pub elapsed: Duration,
}

impl ScanReport {
    fn record(&mut self, hashed_address: B256, verdict: Verdict) {
        match verdict {
            Verdict::Legit => self.legit += 1,
            Verdict::Suspect(reason) => {
                self.suspects += 1;
                if self.suspect_samples.len() < MAX_SAMPLES {
                    self.suspect_samples.push((hashed_address, reason));
                }
            }
            Verdict::Undetermined(reason) => {
                self.undetermined += 1;
                if self.undetermined_samples.len() < MAX_SAMPLES {
                    self.undetermined_samples.push((hashed_address, reason));
                }
            }
        }
    }
}

impl fmt::Display for ScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Mode:                            {}", self.mode)?;
        if self.mode == ScanMode::V1 {
            writeln!(f, "PlainAccountState rows scanned:  {}", self.plain_rows)?;
            writeln!(f, "PlainAccountState empty rows:    {}", self.plain_empty)?;
        }
        writeln!(f, "HashedAccounts rows scanned:     {}", self.hashed_rows)?;
        writeln!(f, "HashedAccounts empty rows:       {}", self.hashed_empty)?;
        writeln!(f, "  legit:                         {}", self.legit)?;
        writeln!(f, "  suspects (EIP-161 leftovers):  {}", self.suspects)?;
        writeln!(f, "  undetermined:                  {}", self.undetermined)?;
        if self.mode == ScanMode::V2 {
            writeln!(f, "  suspects with storage:         {}", self.suspects_with_storage)?;
            writeln!(f, "  changed during scan (skipped): {}", self.changed)?;
        }
        for (hashed_address, reason) in &self.suspect_samples {
            writeln!(f, "  suspect hashed address: {hashed_address} ({reason})")?;
        }
        for (hashed_address, reason) in &self.undetermined_samples {
            writeln!(f, "  undetermined hashed address: {hashed_address} ({reason})")?;
        }
        writeln!(f, "Read transactions:               {}", self.transactions)?;
        writeln!(f, "Elapsed:                         {:.1}s", self.elapsed.as_secs_f64())?;
        write!(
            f,
            "RESULT mode={} suspects={} legit={} undetermined={} changed={} hashed_empty={} plain_empty={} hashed_rows={} plain_rows={} elapsed_secs={:.1}",
            self.mode,
            self.suspects,
            self.legit,
            self.undetermined,
            self.changed,
            self.hashed_empty,
            self.plain_empty,
            self.hashed_rows,
            self.plain_rows,
            self.elapsed.as_secs_f64()
        )
    }
}

/// v1: walks `PlainAccountState`, then `HashedAccounts`, and classifies every all-zero hashed
/// row.
pub fn scan<DB: Database>(db: &DB, options: &ScanOptions) -> eyre::Result<ScanReport> {
    let start = Instant::now();
    let mut report = ScanReport { mode: ScanMode::V1, ..Default::default() };
    let mut throttle = Throttle::new(options.max_rows_per_sec);

    // Pass 1: hashed keys of all-zero plain accounts.
    let mut plain_empty = HashSet::new();
    let mut rows_seen = 0u64;
    let (rows, txs) = walk_table::<DB, tables::PlainAccountState>(
        db,
        options,
        &mut throttle,
        |address, account| {
            rows_seen += 1;
            if is_empty(&account) {
                plain_empty.insert(keccak256(address));
                eyre::ensure!(
                    plain_empty.len() <= options.max_plain_empty,
                    "PlainAccountState holds more than {} empty accounts ({} read so far after {} rows); \
                     raise --max-plain-empty",
                    options.max_plain_empty,
                    plain_empty.len(),
                    rows_seen
                );
            }
            Ok(())
        },
    )?;
    report.plain_rows = rows;
    report.plain_empty = plain_empty.len() as u64;
    report.transactions += txs;
    info!(target: "reth::cli", rows, empty = plain_empty.len(), "Finished PlainAccountState pass");

    // Pass 2: classify all-zero hashed rows.
    let mut empty_rows = Vec::new();
    let (rows, txs) = walk_table::<DB, tables::HashedAccounts>(
        db,
        options,
        &mut throttle,
        |hashed_address, account| {
            if is_empty(&account) {
                empty_rows.push(hashed_address);
            }
            Ok(())
        },
    )?;
    report.hashed_rows = rows;
    report.hashed_empty = empty_rows.len() as u64;
    report.transactions += txs;
    for hashed_address in empty_rows {
        let verdict = if plain_empty.contains(&hashed_address) {
            Verdict::Legit
        } else {
            Verdict::Suspect("no empty PlainAccountState row")
        };
        report.record(hashed_address, verdict);
    }
    report.elapsed = start.elapsed();
    Ok(report)
}

/// v2: walks `HashedAccounts`, then checks every all-zero row against the stored `AccountsTrie`.
///
/// For each row the check finds the deepest stored branch node on the row's nibble path. A
/// missing child at the next nibble proves the row is absent from the trie. Otherwise the check
/// rehashes the smallest subtree whose hash the trie stores, from `HashedAccounts`, and finds
/// which of the subtree's empty rows make the hash match. `hash_mask` in a stored branch node
/// marks only branch children, so a leaf child's hash is never stored and the check rehashes the
/// parent branch instead. Reth does not store the root node; `state_root` returns the root that
/// matches the trie in a transaction.
pub fn scan_trie<DB: Database, A: TrieTableAdapter>(
    db: &DB,
    options: &ScanOptions,
    state_root: impl Fn(&DB::TX) -> eyre::Result<Option<B256>>,
) -> eyre::Result<ScanReport> {
    let start = Instant::now();
    let mut report = ScanReport { mode: ScanMode::V2, ..Default::default() };
    let mut throttle = Throttle::new(options.max_rows_per_sec);

    // Pass 1: all-zero hashed rows.
    let mut rows_seen = 0u64;
    let mut empty_rows = Vec::new();
    let (rows, txs) = walk_table::<DB, tables::HashedAccounts>(
        db,
        options,
        &mut throttle,
        |hashed_address, account| {
            rows_seen += 1;
            if is_empty(&account) {
                empty_rows.push(hashed_address);
                eyre::ensure!(
                    empty_rows.len() <= options.max_plain_empty,
                    "HashedAccounts holds more than {} empty rows ({} read so far after {} rows); raise \
                     --max-plain-empty",
                    options.max_plain_empty,
                    empty_rows.len(),
                    rows_seen
                );
            }
            Ok(())
        },
    )?;
    report.hashed_rows = rows;
    report.hashed_empty = empty_rows.len() as u64;
    report.transactions += txs;
    info!(target: "reth::cli", rows, empty = empty_rows.len(), "Finished HashedAccounts pass");

    // Pass 2 throttles per empty row only. The trie lookups and the rehash reads (at most
    // MAX_REHASH_ROWS rows) for one empty row are not throttled.
    // Pass 2: trie lookups. Each row is checked inside one transaction, so the trie and the
    // hashed state it reads are consistent even while the node writes.
    let mut next = 0;
    while next < empty_rows.len() {
        let tx = db.tx()?;
        report.transactions += 1;
        let root = state_root(&tx)?;
        let tx_start = Instant::now();
        let mut tx_rows = 0u64;
        while next < empty_rows.len() {
            let hashed_address = empty_rows[next];
            let Some(verdict) = classify_row::<_, A>(&tx, hashed_address, root)? else {
                report.changed += 1;
                next += 1;
                continue
            };
            if matches!(verdict, Verdict::Suspect(_)) &&
                tx.cursor_dup_read::<tables::HashedStorages>()?
                    .seek_exact(hashed_address)?
                    .is_some()
            {
                report.suspects_with_storage += 1;
            }
            report.record(hashed_address, verdict);
            next += 1;
            tx_rows += 1;
            throttle.tick();
            if tx_rows >= options.renew_every_rows || tx_start.elapsed() >= options.renew_every {
                break
            }
        }
    }
    report.elapsed = start.elapsed();
    Ok(report)
}

/// Class of one all-zero `HashedAccounts` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Legit,
    Suspect(&'static str),
    Undetermined(&'static str),
}

/// EIP-161 empty: zero nonce, zero balance, no code.
fn is_empty(account: &Account) -> bool {
    account.nonce == 0 &&
        account.balance.is_zero() &&
        account.bytecode_hash.is_none_or(|hash| hash == KECCAK256_EMPTY)
}

/// Returns the block whose state the stored trie holds.
fn trie_block_number<TX: DbTx>(tx: &TX) -> eyre::Result<Option<u64>> {
    // The node can persist the trie behind the Finish block. `partial_state_trie` then names the
    // block the trie holds.
    Ok(tx.get::<tables::StageCheckpoints>(StageId::Finish.to_string())?.map(|checkpoint| {
        checkpoint
            .finish_stage_checkpoint()
            .and_then(|finish| finish.partial_state_trie())
            .unwrap_or(checkpoint.block_number)
    }))
}

/// Classifies one row, or returns `None` if it is no longer all-zero.
fn classify_row<TX: DbTx, A: TrieTableAdapter>(
    tx: &TX,
    hashed_address: B256,
    state_root: Option<B256>,
) -> eyre::Result<Option<Verdict>> {
    // The node can change the row between pass 1 and this transaction.
    if !tx.get::<tables::HashedAccounts>(hashed_address)?.is_some_and(|account| is_empty(&account))
    {
        return Ok(None)
    }
    classify_in_trie::<TX, A>(tx, hashed_address, state_root).map(Some)
}

/// Decides whether the stored `AccountsTrie` contains the all-zero row at `hashed_address`.
///
/// `state_root` is the root of the trie as committed in `tx`. Reth does not store the root
/// branch node, so rows whose nearest stored hash is the root need it.
fn classify_in_trie<TX: DbTx, A: TrieTableAdapter>(
    tx: &TX,
    hashed_address: B256,
    state_root: Option<B256>,
) -> eyre::Result<Verdict> {
    let key = Nibbles::unpack(hashed_address);
    let mut trie = tx.cursor_read::<A::AccountTrieTable>()?;

    // Stored branch nodes on the key's path, shallowest first. At most 63 point lookups.
    let mut on_path = Vec::new();
    for depth in 1..key.len() {
        if let Some((_, node)) = trie.seek_exact(A::AccountKey::from(key.slice(..depth)))? {
            on_path.push((depth, node));
        }
    }

    let Some((depth, node)) = on_path.last().cloned() else {
        // No stored branch below the root: the row lies in an unstored root child.
        return decide_root::<TX, A>(tx, hashed_address, state_root)
    };
    // Masks alone never decide a row: a stale or corrupt mask would turn a legit row into a
    // suspect. Every verdict below comes from a hash match.
    let nibble = key.get_unchecked(depth);
    if node.state_mask.is_bit_set(nibble) && node.hash_mask.is_bit_set(nibble) {
        // The child is an unstored branch whose hash `node` stores. Rehash that branch.
        let Some(rows) = rows_under::<TX, A>(tx, &key.slice(..=depth))? else {
            return Ok(Verdict::Undetermined("subtree too large to rehash"))
        };
        let expected = Some(node.hash_for_nibble(nibble));
        return Ok(decide(&rows, hashed_address, expected, |included| {
            (!included.is_empty()).then(|| subtrie_rlp(depth + 1, included))
        }))
    }

    // No hash is stored for the child: it is a leaf, an extension, or absent. Rehash `node`
    // itself from its stored child hashes and the rows under its other nibbles, and compare with
    // the hash stored above it.
    if depth == 1 {
        return decide_root::<TX, A>(tx, hashed_address, state_root)
    }
    let last = key.get_unchecked(depth - 1);
    let Some(expected) = on_path.iter().find(|(d, _)| *d == depth - 1).and_then(|(_, parent)| {
        parent.hash_mask.is_bit_set(last).then(|| parent.hash_for_nibble(last))
    }) else {
        return Ok(Verdict::Undetermined("branch sits below an extension; no stored hash above it"))
    };
    let Some(rows) = rows_under_branch::<TX, A>(tx, &key.slice(..depth), &node)? else {
        return Ok(Verdict::Undetermined("subtree too large to rehash"))
    };
    Ok(decide(&rows, hashed_address, Some(expected), |included| {
        branch_rlp_mixed(depth, &node, included)
    }))
}

/// Rehashes the root from the stored depth-1 branch nodes and compares it with `state_root`.
fn decide_root<TX: DbTx, A: TrieTableAdapter>(
    tx: &TX,
    hashed_address: B256,
    state_root: Option<B256>,
) -> eyre::Result<Verdict> {
    let mut trie = tx.cursor_read::<A::AccountTrieTable>()?;
    let mut stored = Vec::new();
    let mut rows = Vec::new();
    for nibble in 0..16u8 {
        let prefix = Nibbles::from_nibbles([nibble]);
        let child_rows = match trie.seek_exact(A::AccountKey::from(prefix))? {
            Some((_, node)) => {
                let child_rows = rows_under_branch::<TX, A>(tx, &prefix, &node)?;
                stored.push((nibble, node));
                child_rows
            }
            None => rows_under::<TX, A>(tx, &prefix)?,
        };
        let Some(child_rows) = child_rows else {
            return Ok(Verdict::Undetermined("subtree too large to rehash"))
        };
        rows.extend(child_rows);
        if rows.len() > MAX_REHASH_ROWS {
            return Ok(Verdict::Undetermined("subtree too large to rehash"))
        }
    }
    Ok(decide(&rows, hashed_address, state_root, |included| {
        let mut state_mask = TrieMask::default();
        let mut stack = Vec::new();
        for nibble in 0..16u8 {
            let group: Vec<_> =
                included.iter().filter(|row| row.0.get_unchecked(0) == nibble).cloned().collect();
            let child = match stored.iter().find(|(n, _)| *n == nibble) {
                Some((_, node)) => branch_rlp_mixed(1, node, &group),
                None => (!group.is_empty()).then(|| subtrie_rlp(1, &group)),
            };
            if let Some(child) = child {
                state_mask.set_bit(nibble);
                stack.push(child);
            }
        }
        (stack.len() >= 2).then(|| BranchNodeRef::new(&stack, state_mask).rlp(&mut Vec::new()))
    }))
}

/// Finds which empty rows the stored hash includes.
///
/// Rows with a non-empty account are always in the trie. For the empty rows in the rehashed
/// subtree, the function tries every subset and keeps the one whose hash matches `expected`.
/// Several empty rows in one subtree (two leftovers, or a leftover next to a legit empty
/// account) then still resolve.
fn decide(
    rows: &[Row],
    hashed_address: B256,
    expected: Option<B256>,
    rlp_of: impl Fn(&[Row]) -> Option<RlpNode>,
) -> Verdict {
    let Some(expected) = expected else {
        return Verdict::Undetermined("no state root for the root branch")
    };
    let key = Nibbles::unpack(hashed_address);
    let empties: Vec<_> = rows.iter().filter(|row| row.2).map(|row| row.0).collect();
    if empties.len() > MAX_EMPTY_IN_SUBTREE {
        return Verdict::Undetermined("too many empty rows in the rehashed subtree")
    }
    for subset in 0u32..(1 << empties.len()) {
        let included: Vec<_> = rows
            .iter()
            .filter(|row| {
                !row.2 ||
                    empties
                        .iter()
                        .position(|k| *k == row.0)
                        .is_some_and(|i| (subset >> i) & 1 == 1)
            })
            .cloned()
            .collect();
        if rlp_of(&included).and_then(|rlp| rlp.as_hash()) == Some(expected) {
            return if included.iter().any(|row| row.0 == key) {
                Verdict::Legit
            } else {
                Verdict::Suspect("trie hash matches the subtree without this row (hash-confirmed)")
            }
        }
    }
    // The node wrote between reads, or the stored trie is itself inconsistent.
    Verdict::Undetermined("trie hash matches no variant of the subtree")
}

/// One `HashedAccounts` row as a trie leaf: full key, account RLP, and whether it is all-zero.
type Row = (Nibbles, Vec<u8>, bool);

/// Returns the trie leaves of all `HashedAccounts` rows under `prefix`, or `None` above
/// [`MAX_REHASH_ROWS`].
fn rows_under<TX: DbTx, A: TrieTableAdapter>(
    tx: &TX,
    prefix: &Nibbles,
) -> eyre::Result<Option<Vec<Row>>> {
    let mut cursor = tx.cursor_read::<tables::HashedAccounts>()?;
    let mut rows = Vec::new();
    let mut entry = cursor.seek(lower_bound(prefix))?;
    while let Some((hashed_address, account)) = entry {
        let key = Nibbles::unpack(hashed_address);
        if !key.starts_with(prefix) {
            break
        }
        if rows.len() == MAX_REHASH_ROWS {
            return Ok(None)
        }
        let storage_root = StorageRoot::<
            DatabaseTrieCursorFactory<&TX, A>,
            DatabaseHashedCursorFactory<&TX>,
        >::from_tx_hashed(tx, hashed_address)
        .root()?;
        let empty = is_empty(&account);
        rows.push((key, alloy_rlp::encode(account.into_trie_account(storage_root)), empty));
        entry = cursor.next()?;
    }
    Ok(Some(rows))
}

/// Like [`rows_under`], but skips the children of `node` whose hashes the node stores.
fn rows_under_branch<TX: DbTx, A: TrieTableAdapter>(
    tx: &TX,
    prefix: &Nibbles,
    node: &BranchNodeCompact,
) -> eyre::Result<Option<Vec<Row>>> {
    let mut rows = Vec::new();
    // All nibbles, not only `state_mask`: rows that the masks do not account for must change the
    // hash.
    for nibble in 0..16u8 {
        if node.hash_mask.is_bit_set(nibble) {
            continue
        }
        let mut child = *prefix;
        child.push(nibble);
        let Some(child_rows) = rows_under::<TX, A>(tx, &child)? else { return Ok(None) };
        rows.extend(child_rows);
        if rows.len() > MAX_REHASH_ROWS {
            return Ok(None)
        }
    }
    Ok(Some(rows))
}

/// Builds the branch at `depth` from stored hashes for `hash_mask` children and from `rows` for
/// the others.
fn branch_rlp_mixed(depth: usize, node: &BranchNodeCompact, rows: &[Row]) -> Option<RlpNode> {
    let mut state_mask = TrieMask::default();
    let mut stack = Vec::new();
    for nibble in 0..16u8 {
        let child = if node.hash_mask.is_bit_set(nibble) {
            Some(RlpNode::word_rlp(&node.hash_for_nibble(nibble)))
        } else {
            let group: Vec<_> =
                rows.iter().filter(|row| row.0.get_unchecked(depth) == nibble).cloned().collect();
            (!group.is_empty()).then(|| subtrie_rlp(depth + 1, &group))
        };
        if let Some(child) = child {
            state_mask.set_bit(nibble);
            stack.push(child);
        }
    }
    // A branch with one child would have collapsed into an extension or leaf.
    (stack.len() >= 2).then(|| BranchNodeRef::new(&stack, state_mask).rlp(&mut Vec::new()))
}

/// Builds the trie node that holds `rows` (sorted, non-empty, all sharing the first `depth`
/// nibbles) at `depth`, the same way `HashBuilder` does.
fn subtrie_rlp(depth: usize, rows: &[Row]) -> RlpNode {
    if let [(key, value, _)] = rows {
        let suffix = key.slice(depth..);
        return LeafNodeRef::new(&suffix, value).rlp(&mut Vec::new())
    }
    let first = &rows[0].0;
    let last = &rows[rows.len() - 1].0;
    let shared = first.slice(depth..).common_prefix_length(&last.slice(depth..));
    let branch_depth = depth + shared;
    let mut state_mask = TrieMask::default();
    let mut stack = Vec::new();
    let mut start = 0;
    while start < rows.len() {
        let nibble = rows[start].0.get_unchecked(branch_depth);
        let end = start +
            rows[start..]
                .iter()
                .take_while(|row| row.0.get_unchecked(branch_depth) == nibble)
                .count();
        state_mask.set_bit(nibble);
        stack.push(subtrie_rlp(branch_depth + 1, &rows[start..end]));
        start = end;
    }
    let branch = BranchNodeRef::new(&stack, state_mask).rlp(&mut Vec::new());
    if shared == 0 {
        return branch
    }
    let extension_key = first.slice(depth..branch_depth);
    ExtensionNodeRef::new(&extension_key, &branch).rlp(&mut Vec::new())
}

/// Smallest `B256` whose nibbles start with `prefix`.
fn lower_bound(prefix: &Nibbles) -> B256 {
    let mut bytes = [0u8; 32];
    for i in 0..prefix.len() {
        let nibble = prefix.get_unchecked(i);
        bytes[i / 2] |= if i % 2 == 0 { nibble << 4 } else { nibble };
    }
    B256::from(bytes)
}

/// Walks a whole table in key order with a chain of short read transactions.
///
/// A long MDBX read transaction pins old pages, so a node that writes at the same time makes the
/// file grow. The walk drops the transaction after `renew_every_rows` rows or `renew_every` time,
/// opens a new one and seeks past the last key it read. Rows written between two transactions can
/// be seen or missed; that is acceptable for this diagnostic.
///
/// Returns the number of rows read and the number of transactions opened.
fn walk_table<DB, T>(
    db: &DB,
    options: &ScanOptions,
    throttle: &mut Throttle,
    mut f: impl FnMut(T::Key, T::Value) -> eyre::Result<()>,
) -> eyre::Result<(u64, u64)>
where
    DB: Database,
    T: Table,
{
    let mut rows = 0u64;
    let mut transactions = 0u64;
    let mut last_key: Option<T::Key> = None;
    let mut last_progress = Instant::now();

    loop {
        let tx = db.tx()?;
        transactions += 1;
        let mut cursor = tx.cursor_read::<T>()?;
        let mut entry = match last_key.clone() {
            None => cursor.first()?,
            Some(key) => match cursor.seek(key.clone())? {
                Some((found, _)) if found == key => cursor.next()?,
                other => other,
            },
        };

        let tx_start = Instant::now();
        let mut tx_rows = 0u64;
        let mut finished = true;
        while let Some((key, value)) = entry {
            last_key = Some(key.clone());
            f(key, value)?;
            rows += 1;
            tx_rows += 1;
            throttle.tick();

            if last_progress.elapsed() >= PROGRESS_PERIOD {
                info!(target: "reth::cli", table = T::NAME, rows, "Scanning");
                last_progress = Instant::now();
            }
            if tx_rows >= options.renew_every_rows || tx_start.elapsed() >= options.renew_every {
                finished = false;
                break
            }
            entry = cursor.next()?;
        }

        if finished {
            return Ok((rows, transactions))
        }
    }
}

/// Sleeps so the average read rate stays at or below the limit.
struct Throttle {
    max_rows_per_sec: u64,
    start: Instant,
    rows: u64,
}

impl Throttle {
    fn new(max_rows_per_sec: u64) -> Self {
        Self { max_rows_per_sec, start: Instant::now(), rows: 0 }
    }

    fn tick(&mut self) {
        self.rows += 1;
        // Check once per 1024 rows so the clock read stays off the hot path.
        if self.max_rows_per_sec == 0 || !self.rows.is_multiple_of(1024) {
            return
        }
        let due = Duration::from_secs_f64(self.rows as f64 / self.max_rows_per_sec as f64);
        let elapsed = self.start.elapsed();
        if due > elapsed {
            std::thread::sleep(due - elapsed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_db::{test_utils::create_test_rw_db, DatabaseEnv};
    use reth_db_api::transaction::DbTxMut;
    use reth_primitives_traits::StorageEntry;
    use reth_stages_types::{FinishCheckpoint, StageCheckpoint};
    use reth_trie::StateRoot;
    use reth_trie_db::{DatabaseStateRoot, LegacyKeyAdapter, PackedKeyAdapter};
    use std::sync::Arc;

    type TestDb = Arc<reth_db::test_utils::TempDatabase<DatabaseEnv>>;

    fn options(renew_every_rows: u64) -> ScanOptions {
        ScanOptions {
            max_rows_per_sec: 0,
            max_plain_empty: 100,
            renew_every_rows,
            renew_every: Duration::from_secs(60),
        }
    }

    fn funded(i: u64) -> Account {
        let bytecode_hash = i.is_multiple_of(10).then(|| keccak256(i.to_be_bytes()));
        Account { nonce: i % 5 + 1, balance: U256::from(i + 1), bytecode_hash }
    }

    /// Builds a DB with one legit empty account, one EIP-161 leftover and normal accounts, all in
    /// plain and hashed state. It builds the `AccountsTrie` for adapter `A` from the hashed state
    /// *before* it inserts the leftover, as the buggy node did.
    fn fixture<A: TrieTableAdapter>(normal: u64, leftover: Address) -> (TestDb, B256, B256) {
        let db = create_test_rw_db();
        let legit = Address::repeat_byte(0x01);
        db.update(|tx| {
            // (a) pre-EIP-161 empty account, present in both tables and in the trie
            tx.put::<tables::PlainAccountState>(legit, Account::default())?;
            tx.put::<tables::HashedAccounts>(keccak256(legit), Account::default())?;
            // (c) normal accounts
            for i in 0..normal {
                let address = Address::with_last_byte(0).create(i);
                tx.put::<tables::PlainAccountState>(address, funded(i))?;
                tx.put::<tables::HashedAccounts>(keccak256(address), funded(i))?;
                // Every tenth account is a contract with storage, so leaves carry real storage
                // roots.
                if i.is_multiple_of(10) {
                    for slot in 1..4u64 {
                        let entry = StorageEntry {
                            key: B256::with_last_byte(slot as u8),
                            value: U256::from(slot),
                        };
                        tx.put::<tables::HashedStorages>(keccak256(address), entry)?;
                    }
                }
            }
            Ok::<_, reth_db_api::DatabaseError>(())
        })
        .unwrap()
        .unwrap();
        let root = db
            .update(|tx| {
                let (root, updates) = StateRoot::<
                    DatabaseTrieCursorFactory<_, A>,
                    DatabaseHashedCursorFactory<_>,
                >::from_tx(tx)
                .root_with_updates()
                .unwrap();
                for (path, node) in updates.account_nodes {
                    tx.put::<A::AccountTrieTable>(A::AccountKey::from(path), node)?;
                }
                // (b) EIP-161 deleted it from plain state, the bug kept an all-zero hashed row
                tx.put::<tables::HashedAccounts>(keccak256(leftover), Account::default())?;
                Ok::<_, reth_db_api::DatabaseError>(root)
            })
            .unwrap()
            .unwrap();
        (db, keccak256(leftover), root)
    }

    /// Returns an address whose hash shares its first `nibbles` nibbles with `target`.
    fn colliding(target: B256, nibbles: usize) -> Address {
        let target = Nibbles::unpack(target);
        (0u64..)
            .map(|i| Address::with_last_byte(0xee).create(i))
            .find(|a| Nibbles::unpack(keccak256(a)).common_prefix_length(&target) >= nibbles)
            .unwrap()
    }

    #[test]
    fn finds_eip161_leftover_and_keeps_legit_empty() {
        let (db, leftover, _) = fixture::<LegacyKeyAdapter>(16, Address::repeat_byte(0x02));
        let report = scan(db.as_ref(), &options(1_000)).unwrap();
        assert_eq!(report.plain_rows, 17);
        assert_eq!(report.hashed_rows, 18);
        assert_eq!(report.plain_empty, 1);
        assert_eq!(report.hashed_empty, 2);
        assert_eq!(report.legit, 1);
        assert_eq!(report.suspects, 1);
        assert_eq!(report.suspect_samples[0].0, leftover);
        assert!(report.to_string().contains("RESULT mode=v1 suspects=1 legit=1 undetermined=0 "));
    }

    /// Renewing the transaction after every row must neither skip nor repeat a row.
    #[test]
    fn renewing_every_row_reads_each_row_once() {
        let (db, _, _) = fixture::<LegacyKeyAdapter>(16, Address::repeat_byte(0x02));
        let report = scan(db.as_ref(), &options(1)).unwrap();
        assert_eq!((report.plain_rows, report.hashed_rows), (17, 18));
        assert_eq!((report.legit, report.suspects), (1, 1));
        // One transaction per row, plus the one that finds the end of each table.
        assert_eq!(report.transactions, 17 + 18 + 2);
    }

    #[test]
    fn aborts_above_plain_empty_limit() {
        let (db, _, _) = fixture::<LegacyKeyAdapter>(16, Address::repeat_byte(0x02));
        let mut options = options(1_000);
        options.max_plain_empty = 0;
        assert!(scan(db.as_ref(), &options).is_err());
    }

    /// v2 on a trie big enough for stored branch nodes at several depths.
    fn assert_trie_mode<A: TrieTableAdapter>(normal: u64, leftover: Address) {
        let (db, leftover, root) = fixture::<A>(normal, leftover);
        let report = scan_trie::<_, A>(db.as_ref(), &options(1), |_| Ok(Some(root))).unwrap();
        assert_eq!(report.hashed_empty, 2);
        assert_eq!((report.legit, report.suspects, report.undetermined), (1, 1, 0), "{report}");
        assert_eq!(report.suspect_samples[0].0, leftover);
        assert_eq!(report.suspects_with_storage, 0);
        assert!(report.to_string().contains("RESULT mode=v2 suspects=1 legit=1 undetermined=0 "));
        // The v1 method must agree on the same DB.
        let v1 = scan(db.as_ref(), &options(1_000)).unwrap();
        assert_eq!((v1.legit, v1.suspects), (report.legit, report.suspects));
        assert_eq!(v1.suspect_samples[0].0, report.suspect_samples[0].0);
    }

    #[test]
    fn trie_mode_small_trie() {
        assert_trie_mode::<LegacyKeyAdapter>(16, Address::repeat_byte(0x02));
    }

    #[test]
    fn trie_mode_large_trie() {
        assert_trie_mode::<LegacyKeyAdapter>(3_000, Address::repeat_byte(0x02));
        assert_trie_mode::<PackedKeyAdapter>(3_000, Address::repeat_byte(0x02));
    }

    /// The leftover shares a long prefix with a live account, so it sits deep in the trie next
    /// to a real leaf.
    #[test]
    fn trie_mode_prefix_collision() {
        let neighbour = keccak256(Address::with_last_byte(0).create(7));
        for shared in [2, 3, 4] {
            assert_trie_mode::<LegacyKeyAdapter>(3_000, colliding(neighbour, shared));
        }
        // The legit empty account also gets a close neighbour.
        let legit = keccak256(Address::repeat_byte(0x01));
        assert_trie_mode::<LegacyKeyAdapter>(3_000, colliding(legit, 3));
    }

    /// Returns the deepest stored `AccountsTrie` node on the path of `hashed_address`.
    fn deepest_node<A: TrieTableAdapter>(
        db: &TestDb,
        hashed_address: B256,
    ) -> (Nibbles, BranchNodeCompact) {
        let key = Nibbles::unpack(hashed_address);
        let tx = db.tx().unwrap();
        let mut cursor = tx.cursor_read::<A::AccountTrieTable>().unwrap();
        (1..key.len())
            .filter_map(|depth| {
                let path = key.slice(..depth);
                cursor.seek_exact(A::AccountKey::from(path)).unwrap().map(|(_, node)| (path, node))
            })
            .last()
            .unwrap()
    }

    /// A stale or corrupt mask on a legit row's path must never produce a suspect: every
    /// suspect needs a hash match.
    #[test]
    fn corrupt_masks_never_make_a_legit_row_suspect() {
        let legit = keccak256(Address::repeat_byte(0x01));
        let corruptions: [fn(&mut BranchNodeCompact, u8); 2] = [
            |node, nibble| node.state_mask.unset_bit(nibble),
            |node, nibble| node.tree_mask.set_bit(nibble),
        ];
        for corrupt in corruptions {
            let (db, leftover, root) =
                fixture::<LegacyKeyAdapter>(3_000, Address::repeat_byte(0x02));
            let (path, mut node) = deepest_node::<LegacyKeyAdapter>(&db, legit);
            corrupt(&mut node, Nibbles::unpack(legit).get_unchecked(path.len()));
            db.update(|tx| tx.put::<tables::AccountsTrie>(path.into(), node)).unwrap().unwrap();

            let report =
                scan_trie::<_, LegacyKeyAdapter>(db.as_ref(), &options(1), |_| Ok(Some(root)))
                    .unwrap();
            assert_eq!(report.suspects, 1, "{report}");
            assert_eq!(report.suspect_samples[0].0, leftover);
        }
    }

    /// The trie can lag the Finish block; the root to compare is the partial trie block's.
    #[test]
    fn trie_block_number_prefers_partial_state_trie() {
        let db = create_test_rw_db();
        let tx = db.tx().unwrap();
        assert_eq!(trie_block_number(&tx).unwrap(), None);
        drop(tx);

        db.update(|tx| {
            tx.put::<tables::StageCheckpoints>(
                StageId::Finish.to_string(),
                StageCheckpoint::new(100),
            )
        })
        .unwrap()
        .unwrap();
        assert_eq!(trie_block_number(&db.tx().unwrap()).unwrap(), Some(100));

        db.update(|tx| {
            tx.put::<tables::StageCheckpoints>(
                StageId::Finish.to_string(),
                StageCheckpoint::new(100).with_finish_stage_checkpoint(FinishCheckpoint {
                    partial_state_trie: Some(90),
                }),
            )
        })
        .unwrap()
        .unwrap();
        assert_eq!(trie_block_number(&db.tx().unwrap()).unwrap(), Some(90));
    }

    /// A row the node changed after pass 1 is skipped, not classified.
    #[test]
    fn row_changed_since_pass_one_is_skipped() {
        let (db, _, root) = fixture::<LegacyKeyAdapter>(3_000, Address::repeat_byte(0x02));
        let legit = keccak256(Address::repeat_byte(0x01));
        let tx = db.tx().unwrap();
        assert_eq!(
            classify_row::<_, LegacyKeyAdapter>(&tx, legit, Some(root)).unwrap(),
            Some(Verdict::Legit)
        );
        drop(tx);

        db.update(|tx| tx.put::<tables::HashedAccounts>(legit, funded(1))).unwrap().unwrap();
        let tx = db.tx().unwrap();
        assert_eq!(classify_row::<_, LegacyKeyAdapter>(&tx, legit, Some(root)).unwrap(), None);
    }
}
