//! `reth db scan-empty-hashed-accounts`: finds `HashedAccounts` rows that EIP-161 deleted.
//!
//! Before upstream reth #27252, the state root task wrote EIP-161-deleted accounts into
//! `HashedAccounts` as all-zero rows, while `PlainAccountState` removed them. Nothing fails until
//! the affected trie branch is fully recomputed. Then the state root diverges.
//!
//! Pre-EIP-161 empty accounts that nothing has touched since are legitimately present as
//! all-zero rows in both tables. A row is a suspect only if it is all-zero in `HashedAccounts` and
//! its preimage is not an all-zero row in `PlainAccountState`.

use alloy_primitives::{keccak256, B256, KECCAK256_EMPTY};
use clap::Parser;
use reth_db_api::{
    cursor::DbCursorRO, database::Database, table::Table, tables, transaction::DbTx,
};
use reth_db_common::DbTool;
use reth_node_builder::NodeTypesWithDB;
use reth_primitives_traits::Account;
use reth_storage_api::StorageSettingsCache;
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};
use tracing::info;

const PROGRESS_PERIOD: Duration = Duration::from_secs(5);

/// Maximum number of suspect hashed addresses kept for the report.
const MAX_SAMPLES: usize = 10;

/// The arguments for the `reth db scan-empty-hashed-accounts` command.
///
/// Read-only. Safe to run against the datadir of a running node.
#[derive(Parser, Debug)]
pub struct Command {
    /// Maximum number of rows to read per second, over both passes. 0 disables the throttle.
    #[arg(long, default_value_t = 200_000)]
    max_rows_per_sec: u64,

    /// Abort if `PlainAccountState` holds more all-zero accounts than this. Bounds memory use
    /// (about 64 bytes per entry).
    #[arg(long, default_value_t = 5_000_000)]
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
    pub fn execute<N: NodeTypesWithDB>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        // Storage v2 keeps no `PlainAccountState`, so the scan has nothing to compare against.
        eyre::ensure!(
            !tool.provider_factory.cached_storage_settings().use_hashed_state(),
            "this datadir uses storage v2 (hashed state only); the scan needs PlainAccountState"
        );

        let options = ScanOptions {
            max_rows_per_sec: self.max_rows_per_sec,
            max_plain_empty: self.max_plain_empty,
            renew_every_rows: self.renew_every_rows.max(1),
            renew_every: Duration::from_secs(self.renew_every_secs.max(1)),
        };
        let report = scan(tool.provider_factory.db_ref(), &options)?;
        println!("{report}");
        Ok(())
    }
}

/// Tuning for [`scan`].
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum rows read per second. 0 disables the throttle.
    pub max_rows_per_sec: u64,
    /// Maximum size of the set of all-zero plain accounts.
    pub max_plain_empty: usize,
    /// Renew the read transaction after this many rows.
    pub renew_every_rows: u64,
    /// Renew the read transaction after this much time.
    pub renew_every: Duration,
}

/// Result of [`scan`].
#[derive(Debug, Default)]
pub struct ScanReport {
    /// Rows read from `PlainAccountState`.
    pub plain_rows: u64,
    /// All-zero rows in `PlainAccountState`.
    pub plain_empty: u64,
    /// Rows read from `HashedAccounts`.
    pub hashed_rows: u64,
    /// All-zero rows in `HashedAccounts`.
    pub hashed_empty: u64,
    /// All-zero hashed rows whose preimage is an all-zero plain row.
    pub legit: u64,
    /// All-zero hashed rows with no all-zero plain row behind them.
    pub suspects: u64,
    /// Up to [`MAX_SAMPLES`] suspect hashed addresses.
    pub samples: Vec<B256>,
    /// Number of read transactions opened.
    pub transactions: u64,
    /// Wall time of both passes.
    pub elapsed: Duration,
}

impl fmt::Display for ScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PlainAccountState rows scanned:  {}", self.plain_rows)?;
        writeln!(f, "PlainAccountState empty rows:    {}", self.plain_empty)?;
        writeln!(f, "HashedAccounts rows scanned:     {}", self.hashed_rows)?;
        writeln!(f, "HashedAccounts empty rows:       {}", self.hashed_empty)?;
        writeln!(f, "  legit (also empty in plain):   {}", self.legit)?;
        writeln!(f, "  suspects (EIP-161 leftovers):  {}", self.suspects)?;
        for hashed_address in &self.samples {
            writeln!(f, "  suspect hashed address: {hashed_address}")?;
        }
        writeln!(f, "Read transactions:               {}", self.transactions)?;
        writeln!(f, "Elapsed:                         {:.1}s", self.elapsed.as_secs_f64())?;
        write!(
            f,
            "RESULT suspects={} legit={} hashed_empty={} plain_empty={} hashed_rows={} plain_rows={} elapsed_secs={:.1}",
            self.suspects,
            self.legit,
            self.hashed_empty,
            self.plain_empty,
            self.hashed_rows,
            self.plain_rows,
            self.elapsed.as_secs_f64()
        )
    }
}

/// Walks `PlainAccountState`, then `HashedAccounts`, and classifies every all-zero hashed row.
pub fn scan<DB: Database>(db: &DB, options: &ScanOptions) -> eyre::Result<ScanReport> {
    let start = Instant::now();
    let mut report = ScanReport::default();
    let mut throttle = Throttle::new(options.max_rows_per_sec);

    // Pass 1: hashed keys of all-zero plain accounts.
    let mut plain_empty = HashSet::new();
    let (rows, txs) = walk_table::<DB, tables::PlainAccountState>(
        db,
        options,
        &mut throttle,
        |address, account| {
            if is_empty(&account) {
                plain_empty.insert(keccak256(address));
                eyre::ensure!(
                    plain_empty.len() <= options.max_plain_empty,
                    "PlainAccountState holds more than {} empty accounts; raise --max-plain-empty",
                    options.max_plain_empty
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
    let (rows, txs) = walk_table::<DB, tables::HashedAccounts>(
        db,
        options,
        &mut throttle,
        |hashed_address, account| {
            if is_empty(&account) {
                report.hashed_empty += 1;
                if plain_empty.contains(&hashed_address) {
                    report.legit += 1;
                } else {
                    report.suspects += 1;
                    if report.samples.len() < MAX_SAMPLES {
                        report.samples.push(hashed_address);
                    }
                }
            }
            Ok(())
        },
    )?;
    report.hashed_rows = rows;
    report.transactions += txs;
    report.elapsed = start.elapsed();
    Ok(report)
}

/// EIP-161 empty: zero nonce, zero balance, no code.
fn is_empty(account: &Account) -> bool {
    account.nonce == 0 &&
        account.balance.is_zero() &&
        account.bytecode_hash.is_none_or(|hash| hash == KECCAK256_EMPTY)
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
    use reth_db::test_utils::create_test_rw_db;
    use reth_db_api::transaction::DbTxMut;

    fn options(renew_every_rows: u64) -> ScanOptions {
        ScanOptions {
            max_rows_per_sec: 0,
            max_plain_empty: 100,
            renew_every_rows,
            renew_every: Duration::from_secs(60),
        }
    }

    /// Builds a DB with one legit empty account, one EIP-161 leftover and normal accounts.
    fn fixture() -> (std::sync::Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>, B256)
    {
        let db = create_test_rw_db();
        let legit = Address::repeat_byte(0x01);
        let leftover = Address::repeat_byte(0x02);
        let funded = Account { nonce: 3, balance: U256::from(7), bytecode_hash: None };
        db.update(|tx| {
            // (a) pre-EIP-161 empty account, present in both tables
            tx.put::<tables::PlainAccountState>(legit, Account::default())?;
            tx.put::<tables::HashedAccounts>(keccak256(legit), Account::default())?;
            // (b) EIP-161 deleted it from plain state, the bug kept an all-zero hashed row
            tx.put::<tables::HashedAccounts>(keccak256(leftover), Account::default())?;
            // (c) normal accounts
            for byte in 0x10..0x20u8 {
                let address = Address::repeat_byte(byte);
                tx.put::<tables::PlainAccountState>(address, funded)?;
                tx.put::<tables::HashedAccounts>(keccak256(address), funded)?;
            }
            Ok::<_, reth_db_api::DatabaseError>(())
        })
        .unwrap()
        .unwrap();
        (db, keccak256(leftover))
    }

    #[test]
    fn finds_eip161_leftover_and_keeps_legit_empty() {
        let (db, leftover) = fixture();
        let report = scan(db.as_ref(), &options(1_000)).unwrap();
        assert_eq!(report.plain_rows, 17);
        assert_eq!(report.hashed_rows, 18);
        assert_eq!(report.plain_empty, 1);
        assert_eq!(report.hashed_empty, 2);
        assert_eq!(report.legit, 1);
        assert_eq!(report.suspects, 1);
        assert_eq!(report.samples, vec![leftover]);
        assert!(report.to_string().contains("RESULT suspects=1 legit=1 "));
    }

    /// Renewing the transaction after every row must neither skip nor repeat a row.
    #[test]
    fn renewing_every_row_reads_each_row_once() {
        let (db, _) = fixture();
        let report = scan(db.as_ref(), &options(1)).unwrap();
        assert_eq!((report.plain_rows, report.hashed_rows), (17, 18));
        assert_eq!((report.legit, report.suspects), (1, 1));
        // One transaction per row, plus the one that finds the end of each table.
        assert_eq!(report.transactions, 17 + 18 + 2);
    }

    #[test]
    fn aborts_above_plain_empty_limit() {
        let (db, _) = fixture();
        let mut options = options(1_000);
        options.max_plain_empty = 0;
        assert!(scan(db.as_ref(), &options).is_err());
    }
}
