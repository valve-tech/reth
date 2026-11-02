//! `reth db scan-wiped-storage`: finds self-destructs whose wiped storage has no changeset rows.
//!
//! Before Cancun, `SELFDESTRUCT` deletes an account and all of its storage. The block's storage
//! changeset must then hold a row for every slot the account had, so that history and unwinds can
//! restore them. The pipeline adds those rows. The engine's static-file writer does not, so blocks
//! written live on a chain without Cancun can miss them.
//!
//! Pass 1 reads the account changesets and finds blocks where a contract stopped existing, or came
//! back with a lower nonce (destroyed and re-created in one block). Pass 2 reads the storage
//! changesets and lists, for each such block, the slots the contract wrote earlier that the
//! block's own changeset does not cover. Those slots are suspects. A suspect is a missing row only
//! if the slot was non-zero just before the block, which an independent client must confirm.
//!
//! Read-only. Safe to run against the datadir of a running node.

use alloy_primitives::{map::HashMap, Address, B256, KECCAK256_EMPTY};
use clap::Parser;
use reth_db_common::DbTool;
use reth_primitives_traits::Account;
use reth_provider::{providers::ProviderNodeTypes, LatestStateProviderRef};
use reth_stages::StageId;
use reth_storage_api::{
    AccountReader, ChangeSetReader, StageCheckpointReader, StorageChangeSetReader,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    time::Instant,
};
use tracing::info;

/// The arguments for the `reth db scan-wiped-storage` command.
#[derive(Parser, Debug)]
pub struct Command {
    /// First block to scan.
    #[arg(long, default_value_t = 0)]
    from: u64,

    /// Last block to report, inclusive. Defaults to the Finish checkpoint.
    ///
    /// Pass 1 still reads account changesets up to the tip, because a destruction is only known
    /// from the account's next row.
    #[arg(long)]
    to: Option<u64>,

    /// First block of storage changesets that pass 2 reads. Slots a contract wrote before this
    /// block are not seen, so keep the default of 0 unless no contract in the range is older.
    #[arg(long, default_value_t = 0)]
    storage_from: u64,

    /// Blocks read per changeset batch.
    #[arg(long, default_value_t = 10_000)]
    chunk_blocks: u64,
}

/// A block in which a contract was destroyed, and what the scan learned about its storage.
#[derive(Debug, Default)]
struct Destruction {
    /// The account was re-created in the same block (its nonce went down), not left empty.
    recreated: bool,
    /// Slots the contract wrote in earlier blocks, since its previous destruction.
    written_before: BTreeSet<B256>,
    /// Slots the destroying block's own changeset covers.
    covered: BTreeSet<B256>,
}

/// Destruction blocks by contract address.
type Destructions = HashMap<Address, BTreeMap<u64, Destruction>>;

impl Command {
    /// Execute `db scan-wiped-storage` command
    pub fn execute<N: ProviderNodeTypes>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        eyre::ensure!(self.chunk_blocks > 0, "--chunk-blocks must be greater than zero");
        let provider = tool.provider_factory.provider()?;
        let tip = provider
            .get_stage_checkpoint(StageId::Finish)?
            .map(|c| c.block_number)
            .ok_or_else(|| eyre::eyre!("no Finish checkpoint"))?;
        let to = self.to.unwrap_or(tip).min(tip);
        eyre::ensure!(to >= self.from, "--to must not be below --from");
        eyre::ensure!(self.storage_from <= self.from, "--storage-from must not be above --from");
        let start = Instant::now();

        let mut destructions = find_destructions(&provider, self.from, to, tip, self.chunk_blocks)?;
        let latest = LatestStateProviderRef::new(&provider);
        let destroyed = destructions.values().map(BTreeMap::len).sum::<usize>();
        info!(target: "reth::cli", destroyed, elapsed = ?start.elapsed(), "Pass 1 done");

        collect_storage(&provider, &mut destructions, self.storage_from, to, self.chunk_blocks)?;
        info!(target: "reth::cli", elapsed = ?start.elapsed(), "Pass 2 done");

        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        let mut affected = 0usize;
        let mut suspect_slots = 0usize;
        let mut rows: Vec<_> = destructions
            .iter()
            .flat_map(|(address, blocks)| {
                blocks.iter().map(move |(block, d)| (*block, *address, d))
            })
            .collect();
        rows.sort_unstable_by_key(|(block, address, _)| (*block, *address));
        for (block, address, destruction) in rows {
            let suspects: Vec<_> =
                destruction.written_before.difference(&destruction.covered).collect();
            if suspects.is_empty() {
                continue
            }
            affected += 1;
            suspect_slots += suspects.len();
            writeln!(
                out,
                "{}",
                json!({
                    "kind": "suspect",
                    "block": block,
                    "address": address,
                    "recreated": destruction.recreated,
                    "exists_at_tip": latest.basic_account(&address)?.is_some(),
                    "written_before": destruction.written_before.len(),
                    "covered": destruction.covered.len(),
                    "suspect_slots": suspects,
                })
            )?;
        }
        writeln!(
            out,
            "{}",
            json!({
                "kind": "summary",
                "from": self.from,
                "to": to,
                "storage_from": self.storage_from,
                "destructions": destroyed,
                "affected": affected,
                "suspect_slots": suspect_slots,
                "elapsed_secs": start.elapsed().as_secs_f64(),
            })
        )?;
        out.flush()?;
        Ok(())
    }
}

/// Returns true if the account holds code, so it can hold storage that a self-destruct wipes.
fn is_contract(account: &Account) -> bool {
    account.bytecode_hash.is_some_and(|hash| hash != KECCAK256_EMPTY)
}

/// Pass 1: finds blocks in `from..=to` in which a contract was destroyed.
///
/// A changeset row holds the value before its block, so the value after block `b` is the `before`
/// of the account's next row, or the tip state if no later row exists. The next row can be above
/// `to`, so this reads account changesets up to `tip`. Reading only to `to` and taking the tip
/// state for the last row would report a later destruction at that row instead.
fn find_destructions<P>(
    provider: &P,
    from: u64,
    to: u64,
    tip: u64,
    chunk: u64,
) -> eyre::Result<Destructions>
where
    P: ChangeSetReader + AccountReader,
{
    // The last row seen for each contract: its block and the contract's nonce before that block.
    let mut open = HashMap::<Address, (u64, u64)>::default();
    let mut destructions = Destructions::default();
    let mut record = |address: Address, block: u64, nonce: u64, after: Option<&Account>| {
        let recreated = after.is_some_and(|after| after.nonce < nonce);
        if (after.is_none() || recreated) && block <= to {
            destructions
                .entry(address)
                .or_default()
                .insert(block, Destruction { recreated, ..Default::default() });
        }
    };

    let mut start = from;
    while start <= tip {
        let end = start.saturating_add(chunk - 1).min(tip);
        for (block, row) in provider.account_changesets_range(start..=end)? {
            if let Some((open_block, nonce)) = open.remove(&row.address) {
                record(row.address, open_block, nonce, row.info.as_ref());
            }
            // Only rows in the report range can start a destruction.
            if block <= to &&
                let Some(before) = row.info.filter(is_contract)
            {
                open.insert(row.address, (block, before.nonce));
            }
        }
        info!(target: "reth::cli", block = end, open = open.len(), "Pass 1: account changesets");
        start = end + 1;
        if end >= to && open.is_empty() {
            break
        }
    }

    // Contracts with no later row: the value after their last row is the tip state.
    for (address, (block, nonce)) in open {
        let after = provider.basic_account(&address)?;
        record(address, block, nonce, after.as_ref());
    }
    Ok(destructions)
}

/// Pass 2: for each destruction, collects the slots written before it and the slots it covers.
fn collect_storage<P>(
    provider: &P,
    destructions: &mut Destructions,
    from: u64,
    to: u64,
    chunk: u64,
) -> eyre::Result<()>
where
    P: StorageChangeSetReader,
{
    let mut start = from;
    while start <= to {
        let end = start.saturating_add(chunk - 1).min(to);
        for (key, entry) in provider.storage_changesets_range(start..=end)? {
            let Some(blocks) = destructions.get_mut(&key.address()) else { continue };
            let block = key.block_number();
            // The row belongs to the first destruction at or after its block.
            let Some((destroyed_at, destruction)) = blocks.range_mut(block..).next() else {
                continue
            };
            if *destroyed_at == block {
                destruction.covered.insert(entry.key);
            } else {
                destruction.written_before.insert(entry.key);
            }
        }
        info!(target: "reth::cli", block = end, "Pass 2: storage changesets");
        start = end + 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_db_api::{
        models::{AccountBeforeTx, BlockNumberAddress},
        tables,
        transaction::DbTxMut,
    };
    use reth_primitives_traits::StorageEntry;
    use reth_provider::test_utils::create_test_provider_factory;

    fn contract(nonce: u64) -> Account {
        Account { nonce, balance: U256::ZERO, bytecode_hash: Some(B256::with_last_byte(9)) }
    }

    /// A contract writes two slots, then self-destructs in block 4. The pipeline would cover
    /// both slots in block 4. Here block 4 covers only one, as the engine writer does.
    #[test]
    fn reports_wiped_slots_missing_from_the_destroying_block() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let tx = provider.tx_ref();
        let clone = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let (slot_a, slot_b) = (B256::with_last_byte(10), B256::with_last_byte(11));

        // Block 1 creates the contract, block 3 touches it, block 4 destroys it.
        tx.put::<tables::AccountChangeSets>(1, AccountBeforeTx { address: clone, info: None })
            .unwrap();
        tx.put::<tables::AccountChangeSets>(
            3,
            AccountBeforeTx { address: clone, info: Some(contract(1)) },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            4,
            AccountBeforeTx { address: clone, info: Some(contract(1)) },
        )
        .unwrap();
        // A contract that is touched but never destroyed is not reported.
        tx.put::<tables::AccountChangeSets>(
            4,
            AccountBeforeTx { address: other, info: Some(contract(1)) },
        )
        .unwrap();
        tx.put::<tables::PlainAccountState>(other, contract(2)).unwrap();
        for (block, slot) in [(1, slot_a), (1, slot_b), (4, slot_a)] {
            tx.put::<tables::StorageChangeSets>(
                BlockNumberAddress((block, clone)),
                StorageEntry { key: slot, value: U256::ZERO },
            )
            .unwrap();
        }

        let mut destructions = find_destructions(&*provider, 0, 5, 5, 2).unwrap();
        collect_storage(&*provider, &mut destructions, 0, 5, 2).unwrap();

        assert_eq!(destructions.len(), 1, "only the destroyed contract is a candidate");
        let destruction = &destructions[&clone][&4];
        assert!(!destruction.recreated);
        assert_eq!(destruction.written_before, BTreeSet::from([slot_a, slot_b]));
        assert_eq!(destruction.covered, BTreeSet::from([slot_a]));
        let suspects: Vec<_> =
            destruction.written_before.difference(&destruction.covered).copied().collect();
        assert_eq!(suspects, vec![slot_b]);
    }

    /// A report range that ends below the tip must not move a later destruction into the range.
    #[test]
    fn a_destruction_above_to_is_not_reported_at_the_last_row_in_range() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let tx = provider.tx_ref();
        let address = Address::with_last_byte(4);
        // Touched in block 2, destroyed in block 8. The account is gone at the tip.
        for block in [2, 8] {
            tx.put::<tables::AccountChangeSets>(
                block,
                AccountBeforeTx { address, info: Some(contract(1)) },
            )
            .unwrap();
        }

        let in_range = find_destructions(&*provider, 0, 5, 10, 3).unwrap();
        assert!(in_range.is_empty(), "the destruction at block 8 is above --to 5");

        let full = find_destructions(&*provider, 0, 10, 10, 3).unwrap();
        assert_eq!(full[&address].keys().copied().collect::<Vec<_>>(), vec![8]);
    }

    /// A destruction followed by re-creation in the same block shows as a lower nonce.
    #[test]
    fn a_lower_nonce_marks_a_recreated_contract() {
        let factory = create_test_provider_factory();
        let provider = factory.provider_rw().unwrap();
        let tx = provider.tx_ref();
        let address = Address::with_last_byte(3);
        tx.put::<tables::AccountChangeSets>(
            2,
            AccountBeforeTx { address, info: Some(contract(5)) },
        )
        .unwrap();
        tx.put::<tables::PlainAccountState>(address, contract(1)).unwrap();

        let destructions = find_destructions(&*provider, 0, 3, 3, 10).unwrap();
        assert!(destructions[&address][&2].recreated);
    }
}
