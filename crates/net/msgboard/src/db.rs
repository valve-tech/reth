//! MDBX persistent storage for msgboard messages.

use std::path::Path;

use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable};
use reth_libmdbx::{
    DatabaseFlags, Environment, EnvironmentFlags, Geometry, Mode, PageSize, SyncMode, WriteFlags,
};
use reth_msgboard_types::CheckedPoWMsg;

const KIBIBYTE: usize = 1024;
const MEBIBYTE: usize = KIBIBYTE * 1024;
const GIBIBYTE: usize = MEBIBYTE * 1024;
const TEBIBYTE: usize = GIBIBYTE * 1024;

/// MDBX named-table holding RLP-encoded `CheckedPoWMsg` values keyed by SHA-256
/// PoW hash. Mirrors `kv.BoardMessage = "BoardMessage"` in erigon-pulse so the
/// on-disk layout is interchangeable between implementations.
const TABLE_NAME: &str = "BoardMessage";

/// MDBX page size. Matches `PageSize = 16 KiB` in erigon-pulse `msgboard/util.go`.
const PAGE_SIZE_BYTES: usize = 16 * KIBIBYTE;

/// File grows in chunks of this size. Matches `GrowthStep = 16 MiB` in erigon.
/// Reth previously used 256 GiB, which made the env file allocate in absurdly
/// large chunks on tiny msgboard databases.
const GROWTH_STEP_BYTES: isize = 16 * MEBIBYTE as isize;

/// Per-transaction dirty page budget, in pages. Matches erigon's
/// `DirtySpace = 128 MiB` (= 8192 pages × 16 KiB).
const TXN_DIRTY_PAGE_LIMIT: u64 = (128 * MEBIBYTE / PAGE_SIZE_BYTES) as u64;

/// Sub-page merge threshold as a 16.16-fixed-point percent. Matches erigon's
/// `WriteMergeThreshold(3 * 8192) = 24576` (≈ 37.5%) — pages emptier than this
/// get merged with a neighbor on the next write transaction. MDBX accepts
/// values in `[8192, 32768]` (≈ 12.5% to 50%).
const MERGE_THRESHOLD_16DOT16_PERCENT: u64 = 3 * 8192;

/// Open (or create) the msgboard MDBX database at `path`.
///
/// Geometry mirrors `private-erigon-pulse/msgboard/util.go` so a reth-built
/// msgboard env opens cleanly under erigon and vice versa.
pub fn open_msgboard_db(path: &Path) -> eyre::Result<Environment> {
    reth_fs_util::create_dir_all(path)?;

    let env = Environment::builder()
        .set_max_dbs(1)
        .set_geometry(Geometry {
            size: Some(0..TEBIBYTE),
            growth_step: Some(GROWTH_STEP_BYTES),
            shrink_threshold: Some(0),
            page_size: Some(PageSize::Set(PAGE_SIZE_BYTES)),
        })
        .set_txn_dp_limit(TXN_DIRTY_PAGE_LIMIT)
        .set_merge_threshold(MERGE_THRESHOLD_16DOT16_PERCENT)
        .set_flags(EnvironmentFlags {
            mode: Mode::ReadWrite { sync_mode: SyncMode::Durable },
            no_sub_dir: false,
            ..Default::default()
        })
        .write_map()
        .open(path)?;

    {
        let tx = env.begin_rw_txn()?;
        tx.create_db(Some(TABLE_NAME), DatabaseFlags::empty())?;
        tx.commit()?;
    }

    Ok(env)
}

/// Load all messages from the database.
pub fn db_load_all(env: &Environment) -> eyre::Result<(Vec<CheckedPoWMsg>, u64)> {
    let tx = env.begin_ro_txn()?;
    let db = tx.open_db(Some(TABLE_NAME))?;
    let cursor = tx.cursor(db.dbi())?;

    let mut msgs = Vec::new();
    let mut bad = 0u64;

    let iter = cursor.iter_slices();
    for item in iter {
        let (_, value) = match item {
            Ok((k, v)) => (k, v),
            Err(_) => {
                bad += 1;
                continue;
            }
        };

        match CheckedPoWMsg::decode(&mut &*value) {
            Ok(checked) => msgs.push(checked),
            Err(_) => {
                bad += 1;
            }
        }
    }

    Ok((msgs, bad))
}

/// Batch flush: write current messages and delete discarded ones.
pub fn db_flush(
    env: &Environment,
    current: &[CheckedPoWMsg],
    discarded_hashes: &[B256],
) -> eyre::Result<u64> {
    let tx = env.begin_rw_txn()?;
    let db = tx.open_db(Some(TABLE_NAME))?;
    let mut bytes_written = 0u64;

    for hash in discarded_hashes {
        let _ = tx.del(db.dbi(), hash.as_slice(), None);
    }

    let mut rlp_buf = Vec::new();
    for msg in current {
        rlp_buf.clear();
        msg.encode(&mut rlp_buf);
        tx.put(db.dbi(), msg.hash.as_slice(), &rlp_buf, WriteFlags::empty())?;
        bytes_written += rlp_buf.len() as u64;
    }

    tx.commit()?;
    Ok(bytes_written)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use reth_msgboard_types::PoWMsg;
    use tempfile::TempDir;

    use super::*;

    fn sample_msg(byte: u8) -> CheckedPoWMsg {
        let mut hash = [0u8; 32];
        hash[0] = byte;
        CheckedPoWMsg {
            msg: PoWMsg {
                version: 1,
                block_hash: B256::from([byte; 32]),
                nonce: 1,
                work_multiplier: 10_000,
                work_divisor: 1_000_000,
                category: B256::from([byte; 32]),
                data: Bytes::from(vec![byte; 4]),
            },
            block_number: u64::from(byte),
            timestamp: 1_700_000_000,
            hash: B256::from(hash),
        }
    }

    #[test]
    fn write_and_reload_roundtrips_through_named_table() {
        let dir = TempDir::new().expect("tempdir");

        let env = open_msgboard_db(dir.path()).expect("open");
        let msgs = vec![sample_msg(1), sample_msg(2), sample_msg(3)];
        let bytes = db_flush(&env, &msgs, &[]).expect("flush");
        assert!(bytes > 0);
        drop(env);

        // Reopen from scratch — proves the named table is what gets persisted.
        let env = open_msgboard_db(dir.path()).expect("reopen");
        let (loaded, bad) = db_load_all(&env).expect("load");
        assert_eq!(bad, 0);
        assert_eq!(loaded.len(), 3);
    }

    /// The MDBX geometry is an erigon-pulse parity contract, not a tuning
    /// preference: a reth-built msgboard env must open cleanly under erigon and
    /// vice versa (`docs/msgboard-parity-gaps.md` §4.1, erigon `msgboard/util.go`).
    /// `GrowthStep` already regressed once — reth shipped 256 GiB against
    /// erigon's 16 MiB — so each value is pinned here against silent drift.
    ///
    /// MDBX exposes no getters for growth step, dirty-page limit, or merge
    /// threshold, so those are asserted at the constant. Page size and map size
    /// are read back from the opened env by
    /// `opened_env_applies_erigons_page_size_and_map_size`.
    #[test]
    fn mdbx_parameters_match_erigon_pulse() {
        assert_eq!(PAGE_SIZE_BYTES, 16 * 1024, "erigon PageSize = 16 KiB");
        assert_eq!(GROWTH_STEP_BYTES, 16 * 1024 * 1024, "erigon GrowthStep = 16 MiB");
        assert_eq!(TXN_DIRTY_PAGE_LIMIT, 8192, "erigon DirtySpace = 128 MiB over 16 KiB pages");
        assert_eq!(MERGE_THRESHOLD_16DOT16_PERCENT, 24576, "erigon WriteMergeThreshold = 3 * 8192",);
        assert_eq!(TEBIBYTE, 1024 * 1024 * 1024 * 1024, "erigon MapSize = 1 TiB");

        // MDBX rejects a merge threshold outside [8192, 32768] at open time, so
        // an out-of-range edit here would break every node's DB open, not just parity.
        assert!(
            (8192..=32768).contains(&MERGE_THRESHOLD_16DOT16_PERCENT),
            "merge threshold must stay inside MDBX's accepted 16.16-percent range",
        );

        // The dirty-page limit is derived from the page size; if one moves
        // without the other, the effective DirtySpace silently stops being 128 MiB.
        assert_eq!(
            TXN_DIRTY_PAGE_LIMIT as usize * PAGE_SIZE_BYTES,
            128 * MEBIBYTE,
            "dirty-page limit and page size must still multiply out to erigon's 128 MiB",
        );
    }

    /// The on-disk table name is what makes the env interchangeable with erigon
    /// (`kv.BoardMessage`). Renaming it orphans every persisted message.
    #[test]
    fn table_name_matches_erigon_kv_board_message() {
        assert_eq!(TABLE_NAME, "BoardMessage");
    }

    /// Proves MDBX actually *applied* erigon's geometry rather than silently
    /// falling back to its own defaults (4 KiB pages).
    ///
    /// Asserted against erigon's literal values, not against `PAGE_SIZE_BYTES` /
    /// `TEBIBYTE` — comparing a read-back to the same constant that produced it
    /// is a tautology that passes under any value, which is precisely how the
    /// M1 guard test slipped through (§11.3).
    #[test]
    fn opened_env_applies_erigons_page_size_and_map_size() {
        let dir = TempDir::new().expect("tempdir");
        let env = open_msgboard_db(dir.path()).expect("open");

        assert_eq!(
            env.stat().expect("stat").page_size(),
            16 * 1024,
            "MDBX did not apply erigon's 16 KiB page size",
        );
        assert_eq!(
            env.info().expect("info").map_size(),
            1024 * 1024 * 1024 * 1024,
            "MDBX did not apply erigon's 1 TiB map size",
        );
    }

    /// A single corrupt record must not cost us the rest of the board. Erigon
    /// tolerates undecodable rows the same way; `db_load_all` counts them into
    /// `bad` and keeps going, and that counter is what surfaces the corruption
    /// to the operator.
    #[test]
    fn undecodable_records_are_counted_as_bad_and_skipped() {
        let dir = TempDir::new().expect("tempdir");
        let env = open_msgboard_db(dir.path()).expect("open");

        let good = sample_msg(1);
        db_flush(&env, std::slice::from_ref(&good), &[]).expect("flush");

        // Write two rows that decode to nothing useful: outright garbage, and a
        // truncated prefix of a real RLP encoding (the likelier on-disk failure).
        let mut valid_rlp = Vec::new();
        sample_msg(2).encode(&mut valid_rlp);
        let truncated = &valid_rlp[..valid_rlp.len() / 2];
        {
            let tx = env.begin_rw_txn().expect("rw txn");
            let db = tx.open_db(Some(TABLE_NAME)).expect("open table");
            tx.put(db.dbi(), B256::from([0xAAu8; 32]).as_slice(), b"not rlp", WriteFlags::empty())
                .expect("put garbage");
            tx.put(db.dbi(), B256::from([0xBBu8; 32]).as_slice(), truncated, WriteFlags::empty())
                .expect("put truncated");
            tx.commit().expect("commit");
        }

        let (loaded, bad) = db_load_all(&env).expect("load");
        assert_eq!(bad, 2, "both undecodable rows should be counted");
        assert_eq!(loaded.len(), 1, "the good message should still load");
        assert_eq!(loaded[0].hash, good.hash);
    }

    #[test]
    fn discarded_hashes_are_deleted_on_flush() {
        let dir = TempDir::new().expect("tempdir");
        let env = open_msgboard_db(dir.path()).expect("open");

        let m1 = sample_msg(1);
        let m2 = sample_msg(2);
        db_flush(&env, &[m1.clone(), m2.clone()], &[]).expect("flush");

        // Drop m1, keep m2.
        db_flush(&env, &[m2.clone()], &[m1.hash]).expect("flush2");

        let (loaded, bad) = db_load_all(&env).expect("load");
        assert_eq!(bad, 0);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].hash, m2.hash);
    }
}
