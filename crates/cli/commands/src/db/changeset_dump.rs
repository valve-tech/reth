//! `reth db changeset-dump`: prints the stored account and storage changesets of a block range.
//!
//! Each row is the value a key had before the block changed it. The output is one JSON object per
//! line, for comparison against another node or an independent client. It opens no write
//! transaction.

use clap::Parser;
use reth_db_common::DbTool;
use reth_provider::providers::ProviderNodeTypes;
use reth_storage_api::{ChangeSetReader, StorageChangeSetReader, StorageSettingsCache};
use serde_json::json;
use std::io::{BufWriter, Write};

/// The arguments for the `reth db changeset-dump` command.
///
/// Read-only. Safe to run against the datadir of a running node.
#[derive(Parser, Debug)]
pub struct Command {
    /// First block to dump.
    #[arg(long)]
    from: u64,

    /// Last block to dump, inclusive. Defaults to `--from`.
    #[arg(long)]
    to: Option<u64>,
}

impl Command {
    /// Execute `db changeset-dump` command
    pub fn execute<N: ProviderNodeTypes>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        let to = self.to.unwrap_or(self.from);
        eyre::ensure!(to >= self.from, "--to must not be below --from");

        let settings = tool.provider_factory.cached_storage_settings();
        let provider = tool.provider_factory.provider()?;
        let mut out = BufWriter::new(std::io::stdout().lock());

        // Storage v2 may store hashed slot keys, so the reader must know which form it sees.
        writeln!(
            out,
            "{}",
            json!({
                "kind": "settings",
                "from": self.from,
                "to": to,
                "use_hashed_state": settings.use_hashed_state(),
                "storage_settings": format!("{settings:?}"),
            })
        )?;

        for block in self.from..=to {
            let accounts = provider.account_block_changeset(block)?;
            let storage = provider.storage_changeset(block)?;
            for row in &accounts {
                let info = row.info.map(|account| {
                    json!({
                        "nonce": account.nonce,
                        "balance": account.balance.to_string(),
                        "bytecode_hash": account.bytecode_hash,
                    })
                });
                writeln!(
                    out,
                    "{}",
                    json!({"kind": "account", "block": block, "address": row.address, "before": info})
                )?;
            }
            for (key, entry) in &storage {
                writeln!(
                    out,
                    "{}",
                    json!({
                        "kind": "storage",
                        "block": block,
                        "address": key.address(),
                        "slot": entry.key,
                        "before": entry.value.to_string(),
                    })
                )?;
            }
            writeln!(
                out,
                "{}",
                json!({
                    "kind": "block",
                    "block": block,
                    "account_rows": accounts.len(),
                    "storage_rows": storage.len(),
                })
            )?;
        }
        out.flush()?;
        Ok(())
    }
}
