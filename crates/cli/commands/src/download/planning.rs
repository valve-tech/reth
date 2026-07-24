use super::{manifest::*, verify::OutputVerifier};
use eyre::Result;
use std::{collections::BTreeMap, path::Path};
use tracing::info;

/// One archive selected from the manifest, along with its component name.
#[derive(Debug, Clone)]
pub(crate) struct PlannedArchive {
    /// Snapshot component type this archive belongs to.
    pub(crate) ty: SnapshotComponentType,
    /// User-facing component name used in logs.
    pub(crate) component: String,
    /// Concrete snapshot archive metadata resolved from the manifest.
    pub(crate) archive: SnapshotArchive,
}

/// The archive list for a modular snapshot download.
#[derive(Debug)]
pub(crate) struct PlannedDownloads {
    /// Concrete archives that still need reuse checks or processing.
    pub(crate) archives: Vec<PlannedArchive>,
    /// Total compressed download size of all planned archives.
    pub(crate) total_download_size: u64,
    /// Total extracted plain-output size of all planned archives.
    pub(crate) total_output_size: u64,
}

impl PlannedDownloads {
    /// Returns the number of concrete archives queued for this snapshot selection.
    pub(crate) const fn total_archives(&self) -> usize {
        self.archives.len()
    }
}

/// Returns the sort priority used to schedule archives.
pub(crate) const fn archive_priority_rank(ty: SnapshotComponentType) -> u8 {
    match ty {
        SnapshotComponentType::State => 0,
        SnapshotComponentType::RocksdbIndices => 1,
        _ => 2,
    }
}

/// Startup summary showing how much of the selected work can be reused.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DownloadStartupSummary {
    /// Archives whose declared outputs already verify on disk.
    pub(crate) reusable: usize,
    /// Archives that still need to be downloaded or retried.
    pub(crate) needs_download: usize,
}

/// Checks selected archives against existing output files before work begins.
pub(crate) fn summarize_download_startup(
    all_downloads: &[PlannedArchive],
    target_dir: &Path,
) -> Result<DownloadStartupSummary> {
    let mut summary = DownloadStartupSummary::default();
    let verifier = OutputVerifier::new(target_dir);

    for planned in all_downloads {
        if verifier.verify(&planned.archive.output_files)? {
            summary.reusable += 1;
        } else {
            summary.needs_download += 1;
        }
    }

    Ok(summary)
}

/// Converts a selection into the manifest distance form used for archive lookup.
fn selection_archive_distance(
    selection: &ComponentSelection,
    snapshot_block: u64,
) -> Option<Option<u64>> {
    match selection {
        ComponentSelection::All => Some(None),
        ComponentSelection::Distance(distance) => Some(Some(*distance)),
        ComponentSelection::Since(block) => Some(Some(snapshot_block.saturating_sub(*block) + 1)),
        ComponentSelection::None => None,
    }
}

/// Sorts planned archives into a stable processing order.
fn sort_planned_archives(all_downloads: &mut [PlannedArchive]) {
    all_downloads.sort_by(|a, b| {
        archive_priority_rank(a.ty)
            .cmp(&archive_priority_rank(b.ty))
            .then_with(|| a.component.cmp(&b.component))
            .then_with(|| a.archive.file_name.cmp(&b.archive.file_name))
    });
}

/// Expands component selections into the archives that need to be processed.
pub(crate) fn collect_planned_archives(
    manifest: &SnapshotManifest,
    selections: &BTreeMap<SnapshotComponentType, ComponentSelection>,
) -> Result<PlannedDownloads> {
    let mut archives = Vec::new();
    let mut total_download_size = 0;
    let mut total_output_size = 0;

    for (ty, selection) in selections {
        let Some(distance) = selection_archive_distance(selection, manifest.block) else {
            continue;
        };
        total_download_size += manifest.size_for_distance(*ty, distance);
        total_output_size += manifest.output_size_for_distance(*ty, distance);

        let snapshot_archives = manifest.snapshot_archives_for_distance(*ty, distance);
        let component = ty.display_name().to_string();
        if !snapshot_archives.is_empty() {
            info!(target: "reth::cli",
                component = %component,
                archives = snapshot_archives.len(),
                selection = %selection,
                "Queued component for download"
            );
        }

        for archive in snapshot_archives {
            if archive.output_files.is_empty() {
                eyre::bail!(
                    "Invalid modular manifest: {} is missing plain output checksum metadata",
                    archive.file_name
                );
            }

            archives.push(PlannedArchive { ty: *ty, component: component.clone(), archive });
        }
    }

    sort_planned_archives(&mut archives);
    Ok(PlannedDownloads { archives, total_download_size, total_output_size })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn summarize_download_startup_counts_reusable_and_needs_download() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path();
        let ok_file = target_dir.join("ok.bin");
        std::fs::write(&ok_file, vec![1_u8; 4]).unwrap();
        let ok_hash = blake3::hash(&[1_u8; 4]).to_hex().to_string();

        let planned = vec![
            PlannedArchive {
                ty: SnapshotComponentType::State,
                component: "State".to_string(),
                archive: SnapshotArchive {
                    url: "https://example.com/ok.tar.zst".to_string(),
                    file_name: "ok.tar.zst".to_string(),
                    size: 10,
                    blake3: None,
                    output_files: vec![OutputFileChecksum {
                        path: "ok.bin".to_string(),
                        size: 4,
                        blake3: ok_hash,
                    }],
                },
            },
            PlannedArchive {
                ty: SnapshotComponentType::Headers,
                component: "Headers".to_string(),
                archive: SnapshotArchive {
                    url: "https://example.com/missing.tar.zst".to_string(),
                    file_name: "missing.tar.zst".to_string(),
                    size: 10,
                    blake3: None,
                    output_files: vec![OutputFileChecksum {
                        path: "missing.bin".to_string(),
                        size: 1,
                        blake3: "deadbeef".to_string(),
                    }],
                },
            },
            PlannedArchive {
                ty: SnapshotComponentType::Transactions,
                component: "Transactions".to_string(),
                archive: SnapshotArchive {
                    url: "https://example.com/bad-size.tar.zst".to_string(),
                    file_name: "bad-size.tar.zst".to_string(),
                    size: 10,
                    blake3: None,
                    output_files: vec![],
                },
            },
        ];

        let summary = summarize_download_startup(&planned, target_dir).unwrap();
        assert_eq!(summary.reusable, 1);
        assert_eq!(summary.needs_download, 2);
    }

    #[test]
    fn archive_priority_prefers_state_then_rocksdb() {
        let mut planned = [
            PlannedArchive {
                ty: SnapshotComponentType::Transactions,
                component: "Transactions".to_string(),
                archive: SnapshotArchive {
                    url: "u3".to_string(),
                    file_name: "t.tar.zst".to_string(),
                    size: 1,
                    blake3: None,
                    output_files: vec![OutputFileChecksum {
                        path: "a".to_string(),
                        size: 1,
                        blake3: "x".to_string(),
                    }],
                },
            },
            PlannedArchive {
                ty: SnapshotComponentType::RocksdbIndices,
                component: "RocksDB Indices".to_string(),
                archive: SnapshotArchive {
                    url: "u2".to_string(),
                    file_name: "rocksdb_indices.tar.zst".to_string(),
                    size: 1,
                    blake3: None,
                    output_files: vec![OutputFileChecksum {
                        path: "b".to_string(),
                        size: 1,
                        blake3: "y".to_string(),
                    }],
                },
            },
            PlannedArchive {
                ty: SnapshotComponentType::State,
                component: "State (mdbx)".to_string(),
                archive: SnapshotArchive {
                    url: "u1".to_string(),
                    file_name: "state.tar.zst".to_string(),
                    size: 1,
                    blake3: None,
                    output_files: vec![OutputFileChecksum {
                        path: "c".to_string(),
                        size: 1,
                        blake3: "z".to_string(),
                    }],
                },
            },
        ];

        planned.sort_by(|a, b| {
            archive_priority_rank(a.ty)
                .cmp(&archive_priority_rank(b.ty))
                .then_with(|| a.component.cmp(&b.component))
                .then_with(|| a.archive.file_name.cmp(&b.archive.file_name))
        });

        assert_eq!(planned[0].ty, SnapshotComponentType::State);
        assert_eq!(planned[1].ty, SnapshotComponentType::RocksdbIndices);
        assert_eq!(planned[2].ty, SnapshotComponentType::Transactions);
    }

    #[test]
    fn collect_planned_archives_tracks_download_and_output_totals() {
        let mut components = BTreeMap::new();
        components.insert(
            "state".to_string(),
            ComponentManifest::Single(SingleArchive {
                file: "state.tar.zst".to_string(),
                size: 10,
                decompressed_size: 100,
                blake3: None,
                output_files: vec![OutputFileChecksum {
                    path: "db/mdbx.dat".to_string(),
                    size: 100,
                    blake3: "h0".to_string(),
                }],
            }),
        );
        components.insert(
            "transactions".to_string(),
            ComponentManifest::Chunked(ChunkedArchive {
                blocks_per_file: 500_000,
                total_blocks: 1_000_000,
                chunk_sizes: vec![20, 30],
                chunk_decompressed_sizes: vec![200, 300],
                chunk_output_files: vec![
                    vec![OutputFileChecksum {
                        path: "static_files/tx-0".to_string(),
                        size: 200,
                        blake3: "h1".to_string(),
                    }],
                    vec![OutputFileChecksum {
                        path: "static_files/tx-1".to_string(),
                        size: 300,
                        blake3: "h2".to_string(),
                    }],
                ],
                chunk_ranges: vec![],
            }),
        );

        let manifest = SnapshotManifest {
            block: 1_000_000,
            chain_id: 1,
            storage_version: 2,
            timestamp: 0,
            base_url: Some("https://example.com".to_string()),
            reth_version: None,
            components,
        };

        let selections = BTreeMap::from([
            (SnapshotComponentType::State, ComponentSelection::All),
            (SnapshotComponentType::Transactions, ComponentSelection::Distance(500_000)),
        ]);

        let planned = collect_planned_archives(&manifest, &selections).unwrap();

        assert_eq!(planned.total_download_size, 40);
        assert_eq!(planned.total_output_size, 400);
        assert_eq!(planned.archives.len(), 2);
    }

    /// CRITICAL regression for the default receipts path: `mod.rs` auto-selects
    /// `Since(paris)` for receipts, which planning converts to a distance
    /// (`snapshot_block - since + 1`). Over a mixed manifest whose tip chunk is a partially
    /// filled fixed bucket (`total_blocks` 150_000 < nominal tip end 599_999), a
    /// `Since(0)`-derived distance spans the whole chain and MUST select every chunk — the
    /// naive nominal-span walk selected only the tip chunk.
    #[test]
    fn since_selection_over_partial_tip_mixed_manifest_selects_full_set() {
        let chunk_ranges = [(0u64, 49_999u64), (50_000, 99_999), (100_000, 599_999)];
        let mut components = BTreeMap::new();
        components.insert(
            "receipts".to_string(),
            ComponentManifest::Chunked(ChunkedArchive {
                blocks_per_file: 500_000,
                total_blocks: 150_000,
                chunk_sizes: vec![10, 20, 30],
                chunk_decompressed_sizes: vec![100, 200, 300],
                chunk_output_files: chunk_ranges
                    .iter()
                    .map(|(start, end)| {
                        vec![OutputFileChecksum {
                            path: format!("static_files/static_file_receipts_{start}_{end}.jar"),
                            size: 1,
                            blake3: "h".to_string(),
                        }]
                    })
                    .collect(),
                chunk_ranges: chunk_ranges
                    .iter()
                    .map(|(start, end)| ChunkRange { start: *start, end: *end })
                    .collect(),
            }),
        );
        let manifest = SnapshotManifest {
            block: 150_000,
            chain_id: 1,
            storage_version: 2,
            timestamp: 0,
            base_url: Some("https://example.com".to_string()),
            reth_version: None,
            components,
        };

        let selections =
            BTreeMap::from([(SnapshotComponentType::Receipts, ComponentSelection::Since(0))]);
        let planned = collect_planned_archives(&manifest, &selections).unwrap();

        assert_eq!(planned.archives.len(), 3, "Since(0) must select every chunk");
        let mut names: Vec<_> =
            planned.archives.iter().map(|p| p.archive.file_name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "receipts-0-49999.tar.zst".to_string(),
                "receipts-100000-599999.tar.zst".to_string(),
                "receipts-50000-99999.tar.zst".to_string(),
            ]
        );
        assert_eq!(planned.total_download_size, 60);
    }

    /// Seeds `static_files/` under `source` with the three real reth sidecars for each `(start,
    /// end)` header range, plus a minimal state DB so `generate_manifest` succeeds.
    fn seed_header_datadir(source: &Path, ranges: &[(u64, u64)]) {
        let sf = source.join("static_files");
        std::fs::create_dir_all(&sf).unwrap();
        for (start, end) in ranges {
            std::fs::write(sf.join(format!("static_file_headers_{start}_{end}.jar")), b"h").unwrap();
            std::fs::write(sf.join(format!("static_file_headers_{start}_{end}.jar.conf")), b"c")
                .unwrap();
            std::fs::write(sf.join(format!("static_file_headers_{start}_{end}.jar.off")), b"o")
                .unwrap();
        }
        let db = source.join("db");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("mdbx.dat"), b"state").unwrap();
    }

    /// Highest-value regression: a full producer→consumer round trip over a MIXED-span datadir.
    /// Every archive the planner selects must EXACTLY match a `{key}-{start}-{end}.tar.zst` file
    /// the producer actually wrote — proving producer and consumer agree on names via
    /// `chunk_ranges`.
    #[test]
    fn round_trip_mixed_span_planned_names_match_written_archives() {
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        seed_header_datadir(source.path(), &[(0, 49_999), (50_000, 99_999), (100_000, 599_999)]);

        let manifest = generate_manifest(
            source.path(),
            output.path(),
            Some("https://x"),
            599_999,
            1,
            500_000,
        )
        .unwrap();

        let selections =
            BTreeMap::from([(SnapshotComponentType::Headers, ComponentSelection::All)]);
        let planned = collect_planned_archives(&manifest, &selections).unwrap();

        assert_eq!(planned.archives.len(), 3);
        for p in &planned.archives {
            assert!(
                output.path().join(&p.archive.file_name).exists(),
                "planner selected {} but producer never wrote it",
                p.archive.file_name
            );
        }
        let mut names: Vec<_> =
            planned.archives.iter().map(|p| p.archive.file_name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "headers-0-49999.tar.zst".to_string(),
                "headers-100000-599999.tar.zst".to_string(),
                "headers-50000-99999.tar.zst".to_string(),
            ]
        );
    }

    /// Guards the working 369a/943b producers: on a UNIFORM datadir the new producer must emit
    /// the exact same archive names as the pre-change stride loop, and clearing `chunk_ranges`
    /// (legacy manifest) must derive identical URLs.
    #[test]
    fn round_trip_uniform_datadir_matches_stride_naming() {
        let source = tempdir().unwrap();
        let output = tempdir().unwrap();
        seed_header_datadir(
            source.path(),
            &[(0, 499_999), (500_000, 999_999), (1_000_000, 1_499_999)],
        );

        let manifest = generate_manifest(
            source.path(),
            output.path(),
            Some("https://x"),
            1_499_999,
            1,
            500_000,
        )
        .unwrap();

        let ComponentManifest::Chunked(chunked) =
            manifest.component(SnapshotComponentType::Headers).unwrap()
        else {
            panic!("headers should be chunked")
        };
        assert_eq!(
            chunked.chunk_ranges,
            vec![
                ChunkRange { start: 0, end: 499_999 },
                ChunkRange { start: 500_000, end: 999_999 },
                ChunkRange { start: 1_000_000, end: 1_499_999 },
            ]
        );

        let selections =
            BTreeMap::from([(SnapshotComponentType::Headers, ComponentSelection::All)]);
        let planned = collect_planned_archives(&manifest, &selections).unwrap();
        let mut names: Vec<_> =
            planned.archives.iter().map(|p| p.archive.file_name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "headers-0-499999.tar.zst".to_string(),
                "headers-1000000-1499999.tar.zst".to_string(),
                "headers-500000-999999.tar.zst".to_string(),
            ]
        );
        for p in &planned.archives {
            assert!(output.path().join(&p.archive.file_name).exists());
        }

        // Clearing chunk_ranges (a legacy manifest) must derive byte-identical URLs via the
        // uniform stride fallback.
        let mut legacy = manifest.clone();
        if let Some(ComponentManifest::Chunked(c)) = legacy.components.get_mut("headers") {
            c.chunk_ranges.clear();
        }
        assert_eq!(
            manifest.archive_urls(SnapshotComponentType::Headers),
            legacy.archive_urls(SnapshotComponentType::Headers),
        );
    }
}
