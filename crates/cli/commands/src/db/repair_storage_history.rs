//! `reth db repair-storage-history`: adds history index entries for storage changeset rows.
//!
//! Builds before the history index fix wrote the changeset rows of slots that a self-destruct
//! wiped, but not their history index entries. Old reads of those slots then skip the row and
//! return zero. This command reads every storage changeset row in a block range and lists each
//! row whose block the slot's history index lacks. Everything comes from the node's own
//! changesets, so the command needs no outside values and is safe to run more than once.
//!
//! Without `--apply`, it only reports and is safe on a running node. With `--apply`, the node must
//! be stopped. It writes an undo record to `--staging` and then adds the missing blocks.
//! `--undo` restores the recorded index entries.

use super::patch_wiped_storage::{record_history, restore_history};
use alloy_primitives::{Address, B256};
use clap::Parser;
use eyre::ensure;
use reth_db_common::DbTool;
use reth_provider::{
    providers::{ProviderNodeTypes, RocksDBProvider},
    BlockNumReader, RocksDBProviderFactory, StorageSettingsCache,
};
use reth_storage_api::StorageChangeSetReader;
use std::{collections::BTreeMap, path::PathBuf};
use tracing::info;

/// The arguments for the `reth db repair-storage-history` command.
#[derive(Parser, Debug)]
pub struct Command {
    /// First block to check.
    #[arg(long, required_unless_present = "undo")]
    from: Option<u64>,

    /// Last block to check. Defaults to the database tip.
    #[arg(long)]
    to: Option<u64>,

    /// Directory for the undo record. Required with `--apply` and `--undo`. Use a new one per
    /// apply.
    #[arg(long, required_if_eq_any = [("apply", "true"), ("undo", "true")])]
    staging: Option<PathBuf>,

    /// Add the missing history index entries. The node must be stopped.
    #[arg(long, conflicts_with = "undo")]
    apply: bool,

    /// Restore the history index entries recorded by an earlier `--apply`.
    #[arg(long)]
    undo: bool,
}

impl Command {
    /// Returns true if this command needs write access to the database.
    pub const fn writes(&self) -> bool {
        self.apply || self.undo
    }

    /// Execute `db repair-storage-history` command
    pub fn execute<N: ProviderNodeTypes>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        let rocksdb = tool.provider_factory.rocksdb_provider();
        if self.undo {
            let staging = self.staging.expect("clap requires --staging with --undo");
            let slots = restore_history(&rocksdb, &staging)?;
            println!("{}", serde_json::json!({"kind": "undone", "history_slots": slots}));
            return Ok(())
        }

        let provider = tool.provider_factory.provider()?;
        ensure!(
            provider.cached_storage_settings().storage_v2,
            "this command repairs the RocksDB history index of storage v2 only"
        );
        let from = self.from.expect("clap requires --from without --undo");
        let to = match self.to {
            Some(to) => to,
            None => provider.best_block_number()?,
        };
        ensure!(from <= to, "--from {from} is above --to {to}");

        let (rows, missing) =
            find_missing(&provider, &rocksdb, from, to, |block, address, slot| {
                println!(
                    "{}",
                    serde_json::json!({
                        "kind": "missing",
                        "block": block,
                        "address": address,
                        "slot": slot,
                    })
                );
            })?;
        let missing_rows: usize = missing.values().map(Vec::len).sum();
        println!(
            "{}",
            serde_json::json!({
                "kind": "summary",
                "from": from,
                "to": to,
                "rows": rows,
                "missing_rows": missing_rows,
                "slots": missing.len(),
                "applied": self.apply,
            })
        );

        if self.apply && !missing.is_empty() {
            let staging = self.staging.expect("clap requires --staging with --apply");
            let undo = record_history(&rocksdb, &staging, missing.keys().copied())?;
            add_missing(&rocksdb, &missing)?;
            println!(
                "{}",
                serde_json::json!({"kind": "applied", "history_slots": missing.len(), "undo": undo})
            );
        }
        Ok(())
    }
}

/// Missing history index entries, by slot: the blocks whose changeset has a row for the slot but
/// whose block the slot's index lacks.
type MissingHistory = BTreeMap<(Address, B256), Vec<u64>>;

/// Checks every storage changeset row in `from..=to` against the history index. Calls `report`
/// for each missing entry. Returns the number of rows checked and the missing entries.
fn find_missing(
    provider: &impl StorageChangeSetReader,
    rocksdb: &RocksDBProvider,
    from: u64,
    to: u64,
    mut report: impl FnMut(u64, Address, B256),
) -> eyre::Result<(usize, MissingHistory)> {
    let mut missing = MissingHistory::new();
    let mut rows = 0usize;
    for block in from..=to {
        for (key, entry) in provider.storage_changeset(block)? {
            rows += 1;
            let address = key.address();
            if !rocksdb.storage_history_contains(address, entry.key, block)? {
                report(block, address, entry.key);
                missing.entry((address, entry.key)).or_default().push(block);
            }
        }
        if block % 100_000 == 0 {
            info!(target: "reth::cli", block, rows, missing = missing.len(), "Checked");
        }
    }
    Ok((rows, missing))
}

/// Adds the missing blocks to each slot's history index.
fn add_missing(rocksdb: &RocksDBProvider, missing: &MissingHistory) -> eyre::Result<()> {
    for ((address, slot), blocks) in missing {
        rocksdb.insert_storage_history_blocks(*address, *slot, blocks)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_db_api::models::StorageBeforeTx;
    use reth_provider::{
        providers::StaticFileWriter, test_utils::create_test_provider_factory,
        StaticFileProviderFactory,
    };
    use reth_static_file_types::StaticFileSegment;
    use reth_storage_api::StorageSettings;

    /// Block 1 changes slot A, which the index lists. Block 2 holds a row for slot B that the
    /// index lacks, as the engine wrote for wiped slots before the fix. Only B is reported, and
    /// a second check after the repair finds nothing.
    #[test]
    fn reports_and_adds_rows_missing_from_the_history_index() {
        let factory = create_test_provider_factory();
        factory.set_storage_settings_cache(StorageSettings::v2());
        let address = Address::with_last_byte(1);
        let (slot_a, slot_b) = (B256::with_last_byte(10), B256::with_last_byte(11));
        let row = |key| StorageBeforeTx { address, key, value: U256::from(7) };

        let sf = factory.static_file_provider();
        let mut writer = sf.latest_writer(StaticFileSegment::StorageChangeSets).unwrap();
        writer.append_storage_changeset(vec![], 0).unwrap();
        writer.append_storage_changeset(vec![row(slot_a)], 1).unwrap();
        writer.append_storage_changeset(vec![row(slot_b)], 2).unwrap();
        writer.commit().unwrap();
        drop(writer);

        let rocksdb = factory.rocksdb_provider();
        rocksdb.insert_storage_history_blocks(address, slot_a, &[1]).unwrap();

        let provider = factory.provider().unwrap();
        let mut reported = Vec::new();
        let (rows, missing) = find_missing(&provider, &rocksdb, 0, 2, |block, address, slot| {
            reported.push((block, address, slot))
        })
        .unwrap();
        assert_eq!(rows, 2);
        assert_eq!(reported, vec![(2, address, slot_b)]);
        assert_eq!(missing, MissingHistory::from([((address, slot_b), vec![2])]));

        add_missing(&rocksdb, &missing).unwrap();
        let (_, missing) = find_missing(&provider, &rocksdb, 0, 2, |_, _, _| {}).unwrap();
        assert!(missing.is_empty(), "a repaired index has nothing missing");
    }
}
