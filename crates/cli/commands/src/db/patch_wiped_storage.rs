//! `reth db patch-wiped-storage`: offline repair of storage changesets that miss wiped slots.
//!
//! Input is one JSON object per line: `{"block": N, "address": "0x..", "slot": "0x..", "value":
//! "0x.."}`. Each line is a slot that a self-destruct in `block` wiped, with its non-zero value
//! just before the block, taken from an independent client. `scan-wiped-storage` lists the slots.
//!
//! Without `--apply`, the command rewrites each affected storage changeset file into
//! `<staging>/work` and checks every block of it against the original plus the patch. The node's
//! files are not touched, so this is safe while the node runs.
//!
//! With `--apply`, the node must be stopped. The command repeats the dry run, copies the original
//! files to `<staging>/backup`, writes the undo record for the history index, swaps the rewritten
//! files in, and adds each patched block to the slot's `StoragesHistory` entry. `--undo` reverses
//! an applied patch from the same staging directory.

use alloy_primitives::{keccak256, Address, B256, U256};
use clap::Parser;
use eyre::{ensure, eyre, WrapErr};
use reth_db_api::{
    cursor::DbDupCursorRO,
    models::{storage_sharded_key::StorageShardedKey, StorageBeforeTx},
    tables,
    transaction::DbTx,
};
use reth_db_common::DbTool;
use reth_provider::{
    providers::{
        rewrite_storage_changeset_file, verify_storage_changeset_file, ProviderNodeTypes,
        StorageChangesetPatch, StorageChangesetRewrite,
    },
    RocksDBProviderFactory, StaticFileProviderFactory,
};
use reth_static_file_types::StaticFileSegment;
use reth_storage_api::StorageChangeSetReader;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use tracing::info;

/// The arguments for the `reth db patch-wiped-storage` command.
#[derive(Parser, Debug)]
pub struct Command {
    /// JSON-lines file of the rows to add.
    #[arg(long)]
    rows: PathBuf,

    /// Directory for rewritten files, backups and the undo record. Use a new one per patch.
    #[arg(long)]
    staging: PathBuf,

    /// Swap the rewritten files in and update the history index. The node must be stopped.
    #[arg(long, conflicts_with = "undo")]
    apply: bool,

    /// Restore the backed-up files and history index entries of an applied patch.
    #[arg(long)]
    undo: bool,
}

/// One input line.
#[derive(Debug, Deserialize)]
struct InputRow {
    block: u64,
    address: Address,
    slot: String,
    value: String,
}

/// Undo record for one slot's history index entries.
#[derive(Debug, Serialize, Deserialize)]
struct HistoryUndo {
    address: Address,
    slot: B256,
    /// The shards before the patch: `(highest block number, block numbers)`.
    shards: Vec<(u64, Vec<u64>)>,
}

impl Command {
    /// Returns true if this command needs write access to the database.
    pub const fn writes(&self) -> bool {
        self.apply || self.undo
    }

    /// Execute `db patch-wiped-storage` command
    pub fn execute<N: ProviderNodeTypes>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        if self.undo {
            return undo(tool, &self.staging)
        }

        let patch = read_patch(&self.rows)?;
        let rows: usize = patch.values().map(Vec::len).sum();
        info!(target: "reth::cli", blocks = patch.len(), rows, "Read patch");
        check_wiped_at_block(tool, &patch)?;

        let original = tool.provider_factory.static_file_provider();
        let mut ranges = BTreeMap::new();
        for block in patch.keys() {
            let range = original.find_fixed_range(StaticFileSegment::StorageChangeSets, *block);
            ranges.insert((range.start(), range.end()), range);
        }

        let mut rewrites = Vec::new();
        for range in ranges.values() {
            let work_dir =
                self.staging.join("work").join(format!("{}_{}", range.start(), range.end()));
            let rewrite = rewrite_storage_changeset_file(&original, &work_dir, *range, &patch)
                .wrap_err_with(|| format!("rewriting {}..={}", range.start(), range.end()))?;
            let checked = verify_storage_changeset_file(&original, &rewrite, &patch)
                .wrap_err_with(|| format!("verifying {}..={}", range.start(), range.end()))?;
            info!(
                target: "reth::cli",
                start = range.start(),
                end = range.end(),
                added_rows = rewrite.added_rows,
                checked_blocks = checked,
                "Rewrote and verified storage changeset file"
            );
            rewrites.push(rewrite);
        }
        println!(
            "{}",
            serde_json::json!({
                "kind": "verified",
                "files": rewrites.len(),
                "blocks": patch.len(),
                "rows": rows,
                "applied": self.apply,
            })
        );

        if self.apply {
            apply(tool, &self.staging, &rewrites, &patch)?;
        }
        Ok(())
    }
}

/// Reads and checks the input rows.
fn read_patch(path: &Path) -> eyre::Result<StorageChangesetPatch> {
    let file = std::fs::File::open(path).wrap_err_with(|| format!("opening {}", path.display()))?;
    let mut patch = StorageChangesetPatch::new();
    for (number, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue
        }
        let row: InputRow = serde_json::from_str(&line)
            .wrap_err_with(|| format!("line {}: not a patch row", number + 1))?;
        let slot = U256::from_str(&row.slot)
            .map_err(|err| eyre!("line {}: bad slot: {err}", number + 1))?;
        let value = U256::from_str(&row.value)
            .map_err(|err| eyre!("line {}: bad value: {err}", number + 1))?;
        ensure!(!value.is_zero(), "line {}: a zero value needs no row", number + 1);
        patch.entry(row.block).or_default().push(StorageBeforeTx {
            address: row.address,
            key: B256::from(slot),
            value,
        });
    }
    for (block, rows) in &mut patch {
        rows.sort_by_key(|row| (row.address, row.key));
        let before = rows.len();
        rows.dedup_by_key(|row| (row.address, row.key));
        ensure!(rows.len() == before, "block {block}: the input repeats a slot");
    }
    ensure!(!patch.is_empty(), "the input has no rows");
    Ok(patch)
}

/// Refuses rows whose slot is not zero right after its block.
///
/// A self-destruct leaves every slot of the account at zero after the block. A non-zero value
/// there means the slot was not wiped in that block, so the row would be wrong. The value after
/// block B is the `before` of the slot's next changeset row above B, or the current value if no
/// later row exists. Neither depends on the missing row, so this check works on a damaged node.
fn check_wiped_at_block<N: ProviderNodeTypes>(
    tool: &DbTool<N>,
    patch: &StorageChangesetPatch,
) -> eyre::Result<()> {
    let provider = tool.provider_factory.provider()?;
    let rocksdb = tool.provider_factory.rocksdb_provider();
    let mut hashed = provider.tx_ref().cursor_dup_read::<tables::HashedStorages>()?;
    for (block, rows) in patch {
        for row in rows {
            let next_change = rocksdb
                .storage_history_shards(row.address, row.key)?
                .into_iter()
                .flat_map(|(_, list)| list.iter().collect::<Vec<_>>())
                .find(|changed| changed > block);
            let after = match next_change {
                Some(next) => provider
                    .storage_changeset(next)?
                    .into_iter()
                    .find(|(key, entry)| key.address() == row.address && entry.key == row.key)
                    .map(|(_, entry)| entry.value)
                    .ok_or_else(|| {
                        eyre!(
                            "history lists block {next} for {} slot {}, but its changeset has no row",
                            row.address,
                            row.key
                        )
                    })?,
                None => {
                    let (hashed_address, hashed_slot) = (keccak256(row.address), keccak256(row.key));
                    hashed
                        .seek_by_key_subkey(hashed_address, hashed_slot)?
                        .filter(|entry| entry.key == hashed_slot)
                        .map(|entry| entry.value)
                        .unwrap_or_default()
                }
            };
            ensure!(
                after.is_zero(),
                "block {block}: {} slot {} reads {after} after the block, so it was not wiped there",
                row.address,
                row.key
            );
        }
    }
    Ok(())
}

/// Swaps the rewritten files in and updates the history index. The node must be stopped.
fn apply<N: ProviderNodeTypes>(
    tool: &DbTool<N>,
    staging: &Path,
    rewrites: &[StorageChangesetRewrite],
    patch: &StorageChangesetPatch,
) -> eyre::Result<()> {
    let rocksdb = tool.provider_factory.rocksdb_provider();

    // 1. Undo record for the history index, written before anything changes.
    let mut slots = BTreeMap::<(Address, B256), Vec<u64>>::new();
    for (block, rows) in patch {
        for row in rows {
            slots.entry((row.address, row.key)).or_default().push(*block);
        }
    }
    let undo_path = staging.join("history-undo.jsonl");
    ensure!(!undo_path.exists(), "{} exists; use a new staging directory", undo_path.display());
    let mut undo_file = std::io::BufWriter::new(std::fs::File::create(&undo_path)?);
    for (address, slot) in slots.keys() {
        let shards = rocksdb
            .storage_history_shards(*address, *slot)?
            .into_iter()
            .map(|(key, list)| (key.sharded_key.highest_block_number, list.iter().collect()))
            .collect();
        let record = HistoryUndo { address: *address, slot: *slot, shards };
        writeln!(undo_file, "{}", serde_json::to_string(&record)?)?;
    }
    undo_file.flush()?;
    undo_file.get_ref().sync_all()?;

    // 2. Back up the original files, then copy each rewritten file over its original.
    let backup_dir = staging.join("backup");
    reth_fs_util::create_dir_all(&backup_dir)?;
    for rewrite in rewrites {
        for original in &rewrite.original_files {
            let name = original.file_name().expect("listed files have names");
            std::fs::copy(original, backup_dir.join(name))?;
        }
    }
    for rewrite in rewrites {
        for (work, original) in rewrite.work_files.iter().zip(&rewrite.original_files) {
            ensure!(
                work.file_name() == original.file_name(),
                "work and original file lists differ"
            );
            let temporary = original.with_extension("patching");
            std::fs::copy(work, &temporary)?;
            std::fs::rename(&temporary, original)?;
        }
        info!(target: "reth::cli", start = rewrite.range.start(), "Swapped in rewritten file");
    }

    // 3. Add each patched block to its slot's history, so old reads find the new rows.
    for ((address, slot), blocks) in &slots {
        rocksdb.insert_storage_history_blocks(*address, *slot, blocks)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "applied",
            "files": rewrites.len(),
            "history_slots": slots.len(),
            "backup": backup_dir,
            "undo": undo_path,
        })
    );
    Ok(())
}

/// Restores the backed-up files and the history index entries of an applied patch.
fn undo<N: ProviderNodeTypes>(tool: &DbTool<N>, staging: &Path) -> eyre::Result<()> {
    let static_dir = tool.provider_factory.static_file_provider().directory().to_path_buf();
    let backup_dir = staging.join("backup");
    let mut restored = 0;
    for entry in std::fs::read_dir(&backup_dir)? {
        let entry = entry?;
        let target = static_dir.join(entry.file_name());
        let temporary = target.with_extension("undoing");
        std::fs::copy(entry.path(), &temporary)?;
        std::fs::rename(&temporary, &target)?;
        restored += 1;
    }

    let rocksdb = tool.provider_factory.rocksdb_provider();
    let undo_file = std::fs::File::open(staging.join("history-undo.jsonl"))?;
    let mut slots = 0;
    for line in std::io::BufReader::new(undo_file).lines() {
        let record: HistoryUndo = serde_json::from_str(&line?)?;
        let shards: Vec<_> = record
            .shards
            .into_iter()
            .map(|(highest, blocks)| {
                (
                    StorageShardedKey::new(record.address, record.slot, highest),
                    reth_db_api::BlockNumberList::new_pre_sorted(blocks),
                )
            })
            .collect();
        rocksdb.replace_storage_history_shards(record.address, record.slot, &shards)?;
        slots += 1;
    }
    println!(
        "{}",
        serde_json::json!({"kind": "undone", "files": restored, "history_slots": slots})
    );
    Ok(())
}
