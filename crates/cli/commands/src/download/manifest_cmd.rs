use crate::download::manifest::generate_manifest;
use clap::Parser;
use eyre::{Result, WrapErr};
use reth_db::{mdbx::DatabaseArguments, open_db_read_only, tables, Database};
use reth_db_api::transaction::DbTx;
use reth_primitives_traits::FastInstant as Instant;
use reth_stages_types::StageId;
use reth_static_file_types::DEFAULT_BLOCKS_PER_STATIC_FILE;
use std::path::PathBuf;
use tracing::{info, warn};

/// Generate modular chunk archives and a snapshot manifest from a source datadir.
///
/// Archive naming convention:
///   - Chunked: `{component}-{start}-{end}.tar.zst` (e.g. `transactions-0-499999.tar.zst`)
#[derive(Debug, Parser)]
pub struct SnapshotManifestCommand {
    /// Source datadir containing static files.
    #[arg(long, short = 'd')]
    source_datadir: PathBuf,

    /// Optional base URL where archives will be hosted.
    #[arg(long)]
    base_url: Option<String>,

    /// Output directory where chunk archives and manifest.json are written.
    #[arg(long, short = 'o')]
    output_dir: PathBuf,

    /// Block number this snapshot was taken at.
    ///
    /// If omitted, this is inferred from the source datadir's `Finish` stage checkpoint.
    #[arg(long)]
    block: Option<u64>,

    /// Chain ID.
    #[arg(long, default_value = "1")]
    chain_id: u64,

    /// Forward block-span written into the downloaded node's config (the span
    /// it will use for NEW static files). Does NOT control how this manifest is
    /// chunked — archives are packaged from the real on-disk segment ranges.
    ///
    /// If omitted, inferred as the span of the newest existing static file
    /// (falling back to the reth default when the datadir has none).
    #[arg(long)]
    blocks_per_file: Option<u64>,
}

impl SnapshotManifestCommand {
    /// Packages snapshot archives and writes the manifest file.
    pub fn execute(self) -> Result<()> {
        let block = match self.block {
            Some(block) => block,
            None => infer_snapshot_block(&self.source_datadir)?,
        };
        let blocks_per_file = match self.blocks_per_file {
            Some(blocks_per_file) => blocks_per_file,
            None => infer_blocks_per_file(&self.source_datadir)?,
        };

        info!(target: "reth::cli",
            dir = ?self.source_datadir,
            output = ?self.output_dir,
            block,
            blocks_per_file,
            "Packaging modular snapshot archives"
        );
        let start = Instant::now();
        let manifest = generate_manifest(
            &self.source_datadir,
            &self.output_dir,
            self.base_url.as_deref(),
            block,
            self.chain_id,
            blocks_per_file,
        )?;

        let num_components = manifest.components.len();
        let json = serde_json::to_string_pretty(&manifest)?;
        let output = self.output_dir.join("manifest.json");
        reth_fs_util::write(&output, &json)?;
        info!(target: "reth::cli",
            path = ?output,
            components = num_components,
            block = manifest.block,
            elapsed = ?start.elapsed(),
            "Manifest written"
        );

        Ok(())
    }
}

/// Infers the snapshot block from the source datadir.
fn infer_snapshot_block(source_datadir: &std::path::Path) -> Result<u64> {
    if let Ok(block) = infer_snapshot_block_from_db(source_datadir) {
        return Ok(block);
    }

    let block = infer_snapshot_block_from_headers(source_datadir)?;
    warn!(
        target: "reth::cli",
        block,
        "Could not read Finish stage checkpoint from source DB, using header static-file tip"
    );
    Ok(block)
}

/// Reads the snapshot block from the source database Finish stage checkpoint.
fn infer_snapshot_block_from_db(source_datadir: &std::path::Path) -> Result<u64> {
    let candidates = [source_datadir.join("db"), source_datadir.to_path_buf()];

    for db_path in candidates {
        if !db_path.exists() {
            continue;
        }

        let db = match open_db_read_only(&db_path, DatabaseArguments::default()) {
            Ok(db) => db,
            Err(_) => continue,
        };

        let tx = db.tx()?;
        if let Some(checkpoint) = tx.get::<tables::StageCheckpoints>(StageId::Finish.to_string())? {
            return Ok(checkpoint.block_number);
        }
    }

    eyre::bail!(
        "Could not infer --block from source DB (Finish checkpoint missing); pass --block manually"
    )
}

/// Infers the snapshot block from the highest header static-file range.
fn infer_snapshot_block_from_headers(source_datadir: &std::path::Path) -> Result<u64> {
    let max_end = header_ranges(source_datadir)?
        .into_iter()
        .map(|(_, end)| end)
        .max()
        .ok_or_else(|| eyre::eyre!("No header static files found to infer --block"))?;
    Ok(max_end)
}

/// Infers the going-forward static-file block span from header file ranges.
///
/// Unlike the previous inference this does NOT bail on mixed spans — a datadir with mixed
/// block-spans (e.g. 50k-span seed segments below default-500k tip segments) is valid reth data.
/// It returns the span of the NEWEST (highest-start) header segment — the span the node keeps
/// writing with — and falls back to [`DEFAULT_BLOCKS_PER_STATIC_FILE`] when no header static
/// files are present. This value now only sets the downloaded node's forward write span
/// (`config.toml`); it no longer drives chunk packaging (which enumerates the real on-disk
/// ranges instead).
fn infer_blocks_per_file(source_datadir: &std::path::Path) -> Result<u64> {
    let ranges = header_ranges(source_datadir)?;
    let Some(&(start, end)) = ranges.last() else {
        return Ok(DEFAULT_BLOCKS_PER_STATIC_FILE);
    };
    let span = end.saturating_sub(start).saturating_add(1);
    Ok(if span == 0 { DEFAULT_BLOCKS_PER_STATIC_FILE } else { span })
}

/// Collects header static-file ranges from the source datadir, sorted and deduplicated.
fn header_ranges(source_datadir: &std::path::Path) -> Result<Vec<(u64, u64)>> {
    segment_ranges(source_datadir, "headers")
}

/// Collects the deduplicated, sorted set of on-disk static-file ranges for `segment`.
///
/// Reads `static_files/` (falling back to the datadir root), matches the
/// `static_file_{segment}_` prefix, parses `_{start}_{end}` while ignoring any
/// `.jar`/`.conf`/`.off` sidecar suffix, and dedupes the three sidecars of a single range to one
/// entry. Filesystem parse only — no DB/provider init. Result is sorted by `(start, end)`.
pub(crate) fn segment_ranges(
    source_datadir: &std::path::Path,
    segment: &str,
) -> Result<Vec<(u64, u64)>> {
    let static_files_dir = source_datadir.join("static_files");
    let static_files_dir =
        if static_files_dir.exists() { static_files_dir } else { source_datadir.to_path_buf() };

    let entries = std::fs::read_dir(&static_files_dir).wrap_err_with(|| {
        format!("Failed to read static files directory: {}", static_files_dir.display())
    })?;

    let mut ranges = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if let Some(range) = parse_segment_range(&file_name, segment) {
            ranges.insert(range);
        }
    }

    Ok(ranges.into_iter().collect())
}

/// Parses the inclusive `(start, end)` block range from a static-file name for `segment`.
///
/// Handles hyphenated segment names (`transaction-senders`, `account-change-sets`,
/// `storage-change-sets`) and strips any `.jar`/`.conf`/`.off` suffix trailing the end block.
fn parse_segment_range(file_name: &str, segment: &str) -> Option<(u64, u64)> {
    let prefix = format!("static_file_{segment}_");
    let remainder = file_name.strip_prefix(&prefix)?;
    let (start, end_with_suffix) = remainder.split_once('_')?;

    let start = start.parse::<u64>().ok()?;
    let end_digits: String = end_with_suffix.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    let end = end_digits.parse::<u64>().ok()?;

    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_segment_range_works_with_suffixes() {
        assert_eq!(
            parse_segment_range("static_file_headers_0_499999", "headers"),
            Some((0, 499_999))
        );
        // Strips `.jar`, `.jar.conf`, `.jar.off` sidecar suffixes.
        assert_eq!(
            parse_segment_range("static_file_headers_500000_999999.jar", "headers"),
            Some((500_000, 999_999))
        );
        assert_eq!(
            parse_segment_range("static_file_headers_500000_999999.jar.conf", "headers"),
            Some((500_000, 999_999))
        );
        assert_eq!(
            parse_segment_range("static_file_headers_500000_999999.jar.off", "headers"),
            Some((500_000, 999_999))
        );
        // Segment name mismatch → None (no cross-segment false positives).
        assert_eq!(parse_segment_range("static_file_transactions_0_499999", "headers"), None);
        assert_eq!(
            parse_segment_range("static_file_transaction-senders_0_499999", "transactions"),
            None
        );
    }

    #[test]
    fn parse_segment_range_handles_all_six_segments() {
        for segment in [
            "headers",
            "transactions",
            "receipts",
            "transaction-senders",
            "account-change-sets",
            "storage-change-sets",
        ] {
            let name = format!("static_file_{segment}_100000_599999.jar");
            assert_eq!(
                parse_segment_range(&name, segment),
                Some((100_000, 599_999)),
                "segment {segment} should parse"
            );
        }
    }

    #[test]
    fn segment_ranges_dedupes_sidecars_and_sorts() {
        let dir = tempdir().unwrap();
        let sf = dir.path().join("static_files");
        std::fs::create_dir_all(&sf).unwrap();
        // Three sidecars of the same range must collapse to one entry.
        std::fs::write(sf.join("static_file_headers_50000_99999.jar"), []).unwrap();
        std::fs::write(sf.join("static_file_headers_50000_99999.jar.conf"), []).unwrap();
        std::fs::write(sf.join("static_file_headers_50000_99999.jar.off"), []).unwrap();
        // A lower range written after → must sort ahead.
        std::fs::write(sf.join("static_file_headers_0_49999.jar"), []).unwrap();

        assert_eq!(
            segment_ranges(dir.path(), "headers").unwrap(),
            vec![(0, 49_999), (50_000, 99_999)]
        );
    }

    #[test]
    fn infer_blocks_per_file_from_header_ranges() {
        let dir = tempdir().unwrap();
        let sf = dir.path().join("static_files");
        std::fs::create_dir_all(&sf).unwrap();
        std::fs::write(sf.join("static_file_headers_0_499999"), []).unwrap();
        std::fs::write(sf.join("static_file_headers_500000_999999.jar"), []).unwrap();

        assert_eq!(infer_blocks_per_file(dir.path()).unwrap(), 500_000);
    }

    #[test]
    fn infer_blocks_per_file_on_mixed_ranges_returns_newest_span() {
        let dir = tempdir().unwrap();
        let sf = dir.path().join("static_files");
        std::fs::create_dir_all(&sf).unwrap();
        // 50k-span seed segments...
        std::fs::write(sf.join("static_file_headers_0_49999.jar"), []).unwrap();
        std::fs::write(sf.join("static_file_headers_50000_99999.jar"), []).unwrap();
        // ...then a 500k-span tip segment. Must NOT bail; returns the newest (500k) span.
        std::fs::write(sf.join("static_file_headers_100000_599999.jar"), []).unwrap();

        assert_eq!(infer_blocks_per_file(dir.path()).unwrap(), 500_000);
    }

    #[test]
    fn infer_blocks_per_file_defaults_when_no_headers() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("static_files")).unwrap();
        assert_eq!(infer_blocks_per_file(dir.path()).unwrap(), DEFAULT_BLOCKS_PER_STATIC_FILE);
    }

    #[test]
    fn infer_snapshot_block_from_headers_uses_max_end() {
        let dir = tempdir().unwrap();
        let sf = dir.path().join("static_files");
        std::fs::create_dir_all(&sf).unwrap();
        std::fs::write(sf.join("static_file_headers_0_499999"), []).unwrap();
        std::fs::write(sf.join("static_file_headers_500000_999999"), []).unwrap();

        assert_eq!(infer_snapshot_block_from_headers(dir.path()).unwrap(), 999_999);
    }
}
