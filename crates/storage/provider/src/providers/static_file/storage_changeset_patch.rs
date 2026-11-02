//! Offline repair of storage changeset static files: adds missing rows to past blocks.
//!
//! Static files are append-only, and a block's rows sit between offset sidecars, so a row cannot
//! be inserted in place. [`rewrite_storage_changeset_file`] copies one fixed-range file into a work
//! directory, truncates the copy to the block before the first patched block with the normal
//! writer, and appends every later block again from the original, with the extra rows merged in.
//! [`verify_storage_changeset_file`] then reads the copy back and checks every block against the
//! original plus the patch. The original file is never written.

use super::{StaticFileProvider, StaticFileProviderBuilder, StaticFileWriter};
use alloy_primitives::{Address, BlockNumber, B256, U256};
use reth_db_api::models::StorageBeforeTx;
use reth_primitives_traits::NodePrimitives;
use reth_static_file_types::{SegmentRangeInclusive, StaticFileSegment};
use reth_storage_api::StorageChangeSetReader;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

/// Extra rows to add, by block number.
pub type StorageChangesetPatch = BTreeMap<BlockNumber, Vec<StorageBeforeTx>>;

/// What [`rewrite_storage_changeset_file`] wrote.
#[derive(Debug, Clone)]
pub struct StorageChangesetRewrite {
    /// The fixed block range of the rewritten file.
    pub range: SegmentRangeInclusive,
    /// The files of the range in the work directory, data file first.
    pub work_files: Vec<PathBuf>,
    /// The original files of the range, in the same order.
    pub original_files: Vec<PathBuf>,
    /// The first block that was appended again.
    pub first_rewritten_block: BlockNumber,
    /// The last block the original file holds.
    pub last_block: BlockNumber,
    /// Rows added.
    pub added_rows: usize,
}

/// Lists the data file and sidecars of one storage changeset range, sorted.
pub fn storage_changeset_files(
    directory: &Path,
    range: SegmentRangeInclusive,
) -> ProviderResult<Vec<PathBuf>> {
    let prefix = format!(
        "static_file_{}_{}_{}",
        StaticFileSegment::StorageChangeSets.as_str(),
        range.start(),
        range.end()
    );
    let mut files = Vec::new();
    for entry in reth_fs_util::read_dir(directory).map_err(ProviderError::other)? {
        let entry = entry.map_err(ProviderError::other)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix(&prefix) &&
            (rest.is_empty() || rest.starts_with('.'))
        {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Rewrites one storage changeset file with the patch rows of its range added.
///
/// `original` reads the node's static files and is only read. `work_dir` must be empty or absent;
/// it receives a copy of the range's files, which this function then rewrites.
///
/// Fails if a patch row duplicates an existing row, or if a patched block is the first block of
/// the range, because truncating before it would delete the file.
pub fn rewrite_storage_changeset_file<N: NodePrimitives>(
    original: &StaticFileProvider<N>,
    work_dir: &Path,
    range: SegmentRangeInclusive,
    patch: &StorageChangesetPatch,
) -> ProviderResult<StorageChangesetRewrite> {
    let patched: BTreeMap<_, _> =
        patch.range(range.start()..=range.end()).map(|(block, rows)| (*block, rows)).collect();
    let Some(first) = patched.keys().next().copied() else {
        return Err(ProviderError::other(std::io::Error::other("no patched block in range")))
    };
    if first == range.start() {
        return Err(ProviderError::other(std::io::Error::other(format!(
            "block {first} is the first block of its file; patching it is not supported"
        ))))
    }
    let last_block = original
        .get_highest_static_file_block(StaticFileSegment::StorageChangeSets)
        .ok_or_else(|| ProviderError::other(std::io::Error::other("no storage changesets")))?
        .min(range.end());
    if first > last_block {
        return Err(ProviderError::other(std::io::Error::other(format!(
            "block {first} is above the last stored block {last_block}"
        ))))
    }

    // Copy the range's files. The writer edits only these copies.
    let original_files = storage_changeset_files(original.directory(), range)?;
    if original_files.is_empty() {
        return Err(ProviderError::other(std::io::Error::other(format!(
            "no storage changeset files for {}..={}",
            range.start(),
            range.end()
        ))))
    }
    reth_fs_util::create_dir_all(work_dir).map_err(ProviderError::other)?;
    if reth_fs_util::read_dir(work_dir).map_err(ProviderError::other)?.next().is_some() {
        return Err(ProviderError::other(std::io::Error::other(format!(
            "work directory {} is not empty",
            work_dir.display()
        ))))
    }
    let mut work_files = Vec::with_capacity(original_files.len());
    for file in &original_files {
        let target = work_dir.join(file.file_name().expect("listed files have names"));
        std::fs::copy(file, &target).map_err(ProviderError::other)?;
        work_files.push(target);
    }

    // The work directory holds one file, so give the writer that file's span.
    let work = StaticFileProviderBuilder::read_write(work_dir)
        .with_blocks_per_file(range.end() - range.start() + 1)
        .build::<N>()?;
    let mut added_rows = 0;
    {
        let mut writer = work.latest_writer(StaticFileSegment::StorageChangeSets)?;
        writer.prune_storage_changesets(first - 1)?;
        writer.commit()?;
        for block in first..=last_block {
            let mut rows: Vec<StorageBeforeTx> = original
                .storage_changeset(block)?
                .into_iter()
                .map(|(key, entry)| StorageBeforeTx {
                    address: key.address(),
                    key: entry.key,
                    value: entry.value,
                })
                .collect();
            if let Some(extra) = patched.get(&block) {
                let existing: BTreeSet<(Address, B256)> =
                    rows.iter().map(|row| (row.address, row.key)).collect();
                for row in *extra {
                    if existing.contains(&(row.address, row.key)) {
                        return Err(ProviderError::other(std::io::Error::other(format!(
                            "block {block} already has a row for {} slot {}",
                            row.address, row.key
                        ))))
                    }
                    rows.push(*row);
                    added_rows += 1;
                }
            }
            writer.append_storage_changeset(rows, block)?;
        }
        writer.commit()?;
    }

    Ok(StorageChangesetRewrite {
        range,
        work_files,
        original_files,
        first_rewritten_block: first,
        last_block,
        added_rows,
    })
}

/// Checks a rewritten file against the original plus the patch, for every block of the range.
///
/// Returns the number of blocks checked.
pub fn verify_storage_changeset_file<N: NodePrimitives>(
    original: &StaticFileProvider<N>,
    rewrite: &StorageChangesetRewrite,
    patch: &StorageChangesetPatch,
) -> ProviderResult<u64> {
    let work_dir = rewrite.work_files[0].parent().expect("work files have a directory");
    let work = StaticFileProvider::<N>::read_only(work_dir)?;
    let rows_of = |provider: &StaticFileProvider<N>, block| -> ProviderResult<Vec<_>> {
        let mut rows: Vec<(Address, B256, U256)> = provider
            .storage_changeset(block)?
            .into_iter()
            .map(|(key, entry)| (key.address(), entry.key, entry.value))
            .collect();
        rows.sort_unstable();
        Ok(rows)
    };

    let mut checked = 0;
    for block in rewrite.range.start()..=rewrite.last_block {
        let mut expected = rows_of(original, block)?;
        if let Some(extra) = patch.get(&block) {
            expected.extend(extra.iter().map(|row| (row.address, row.key, row.value)));
            expected.sort_unstable();
        }
        let got = rows_of(&work, block)?;
        if got != expected {
            return Err(ProviderError::other(std::io::Error::other(format!(
                "rewritten block {block} has {} rows, expected {}",
                got.len(),
                expected.len()
            ))))
        }
        checked += 1;
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_ethereum_primitives::EthPrimitives;

    fn row(address: u8, slot: u8, value: u64) -> StorageBeforeTx {
        StorageBeforeTx {
            address: Address::with_last_byte(address),
            key: B256::with_last_byte(slot),
            value: U256::from(value),
        }
    }

    /// Writes blocks 0..=24 in files of 10 blocks, each block with one row.
    fn write_segment(dir: &Path) -> StaticFileProvider<EthPrimitives> {
        let provider = StaticFileProviderBuilder::read_write(dir)
            .with_blocks_per_file(10)
            .build::<EthPrimitives>()
            .unwrap();
        {
            let mut writer = provider.latest_writer(StaticFileSegment::StorageChangeSets).unwrap();
            for block in 0..=24u64 {
                writer.append_storage_changeset(vec![row(1, block as u8, block)], block).unwrap();
            }
            writer.commit().unwrap();
        }
        provider
    }

    fn rows(
        provider: &StaticFileProvider<EthPrimitives>,
        block: u64,
    ) -> Vec<(Address, B256, U256)> {
        let mut rows: Vec<_> = provider
            .storage_changeset(block)
            .unwrap()
            .into_iter()
            .map(|(key, entry)| (key.address(), entry.key, entry.value))
            .collect();
        rows.sort_unstable();
        rows
    }

    #[test]
    fn rewrite_adds_rows_and_keeps_every_other_block() {
        let dir = tempfile::tempdir().unwrap();
        let static_dir = dir.path().join("static_files");
        let original = write_segment(&static_dir);
        let range = original.find_fixed_range(StaticFileSegment::StorageChangeSets, 14);
        assert_eq!((range.start(), range.end()), (10, 19));

        let before: Vec<_> = (0..=24).map(|block| rows(&original, block)).collect();
        let patch = StorageChangesetPatch::from([(14, vec![row(2, 0, 7), row(2, 1, 9)])]);
        let rewrite =
            rewrite_storage_changeset_file(&original, &dir.path().join("work"), range, &patch)
                .unwrap();
        assert_eq!(rewrite.added_rows, 2);
        assert_eq!(rewrite.last_block, 19);
        assert_eq!(verify_storage_changeset_file(&original, &rewrite, &patch).unwrap(), 10);

        // The work file has the extra rows at block 14 and nothing else changed.
        let work =
            StaticFileProvider::<EthPrimitives>::read_only(rewrite.work_files[0].parent().unwrap())
                .unwrap();
        for block in 10..=19u64 {
            let mut expected = before[block as usize].clone();
            if block == 14 {
                expected.extend([row(2, 0, 7), row(2, 1, 9)].map(|r| (r.address, r.key, r.value)));
                expected.sort_unstable();
            }
            assert_eq!(rows(&work, block), expected, "block {block}");
        }

        // The original files were not touched.
        for block in 0..=24u64 {
            assert_eq!(rows(&original, block), before[block as usize], "original block {block}");
        }
    }

    #[test]
    fn verify_rejects_a_rewrite_that_lost_a_row() {
        let dir = tempfile::tempdir().unwrap();
        let static_dir = dir.path().join("static_files");
        let original = write_segment(&static_dir);
        let range = original.find_fixed_range(StaticFileSegment::StorageChangeSets, 14);
        let patch = StorageChangesetPatch::from([(14, vec![row(2, 0, 7)])]);
        let rewrite =
            rewrite_storage_changeset_file(&original, &dir.path().join("work"), range, &patch)
                .unwrap();

        // Expecting one more row than was written must fail the check.
        let wrong = StorageChangesetPatch::from([(14, vec![row(2, 0, 7), row(2, 1, 9)])]);
        assert!(verify_storage_changeset_file(&original, &rewrite, &wrong).is_err());
    }

    #[test]
    fn rewrite_rejects_a_duplicate_row() {
        let dir = tempfile::tempdir().unwrap();
        let static_dir = dir.path().join("static_files");
        let original = write_segment(&static_dir);
        let range = original.find_fixed_range(StaticFileSegment::StorageChangeSets, 14);
        let patch = StorageChangesetPatch::from([(14, vec![row(1, 14, 3)])]);
        assert!(rewrite_storage_changeset_file(&original, &dir.path().join("work"), range, &patch)
            .is_err());
    }
}
