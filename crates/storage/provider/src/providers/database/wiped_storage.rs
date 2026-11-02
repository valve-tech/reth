//! Storage changeset rows for accounts that a self-destruct wiped.
//!
//! Before Cancun, `SELFDESTRUCT` deletes all storage of an account. The block's storage changeset
//! must then hold the value before the block of every slot the account had, not only the slots
//! the block touched. The pipeline adds these slots in `ExecutionStage`. The engine persists
//! through `save_blocks`, which before this module wrote only the touched slots. History reads,
//! historical proofs and unwinds across such a block then lost the wiped values.
//!
//! The hashed state of an executed block already lists every slot of a destroyed account with a
//! zero value. This module takes those slots, finds each slot's value before the block, and finds
//! its plain key, which the changeset needs.

use crate::providers::rocksdb::RocksDBProvider;
use alloy_primitives::{keccak256, map::HashMap, Address, BlockNumber, B256, U256};
use reth_chain_state::ExecutedBlock;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    models::{storage_sharded_key::StorageShardedKey, StorageBeforeTx},
    tables,
    transaction::DbTx,
};
use reth_primitives_traits::{AlloyBlockHeader as _, NodePrimitives};
use reth_storage_errors::provider::ProviderResult;
use std::collections::BTreeMap;
use tracing::{debug, error};

/// Complete storage changeset rows for wiped accounts, by block number and address.
///
/// The static-file writer uses these rows instead of the touched-slot rows for the same account.
pub type StorageWipeRows = HashMap<(BlockNumber, Address), Vec<StorageBeforeTx>>;

/// Where the plain keys of an account's storage slots can be found.
pub(crate) enum SlotHistory<'a, TX> {
    /// `StoragesHistory` in `RocksDB` (storage v2).
    RocksDB(&'a RocksDBProvider),
    /// `StoragesHistory` in MDBX.
    Database(&'a TX),
}

/// Builds the storage changeset rows for every wiped account in `blocks`.
///
/// `overlay` must hold every block above the hashed-state frontier of the database up to the end
/// of `blocks`. `tx` must read the database before this batch writes. A wiped slot whose plain key
/// cannot be found is logged and left out, which is the behaviour before this fix.
pub(crate) fn wiped_storage_rows<N, TX>(
    tx: &TX,
    history: SlotHistory<'_, TX>,
    hashed_frontier: BlockNumber,
    blocks: &[ExecutedBlock<N>],
    overlay: &[&ExecutedBlock<N>],
) -> ProviderResult<StorageWipeRows>
where
    N: NodePrimitives,
    TX: DbTx,
{
    let mut rows = StorageWipeRows::default();
    let wipes_any = blocks.iter().any(|block| {
        block.execution_outcome().state.reverts.iter().flatten().any(|(_, r)| r.wipe_storage)
    });
    if !wipes_any {
        return Ok(rows)
    }

    // Blocks whose hashed state is not in the database yet, by number.
    let overlay: BTreeMap<BlockNumber, &ExecutedBlock<N>> = overlay
        .iter()
        .map(|block| (block.recovered_block().number(), *block))
        .filter(|(number, _)| *number > hashed_frontier)
        .collect();
    let first_wipe_block = blocks.first().map(|block| block.recovered_block().number());
    if let Some(first) = first_wipe_block &&
        (hashed_frontier + 1..first).any(|number| !overlay.contains_key(&number))
    {
        error!(
            target: "providers::db",
            hashed_frontier,
            first_block = first,
            "Cannot restore wiped storage: the batch lacks blocks above the hashed-state frontier"
        );
        return Ok(rows)
    }

    let mut hashed_storage = tx.cursor_dup_read::<tables::HashedStorages>()?;
    let mut plain_keys = HashMap::<Address, HashMap<B256, B256>>::default();

    for block in blocks {
        let number = block.recovered_block().number();
        let hashed_state = block.hashed_state();
        for (address, revert) in block.execution_outcome().state.reverts.iter().flatten() {
            if !revert.wipe_storage {
                continue
            }
            let hashed_address = keccak256(address);

            // Slots the block touched, with their plain keys.
            let touched: HashMap<B256, (B256, U256)> = revert
                .storage
                .iter()
                .map(|(slot, revert_to)| {
                    let plain = B256::from(*slot);
                    (keccak256(plain), (plain, revert_to.to_previous_value()))
                })
                .collect();

            let mut account_rows = Vec::new();
            let mut unknown_keys = 0usize;
            let mut seen = std::collections::HashSet::new();
            let slots = hashed_state
                .storages
                .get(&hashed_address)
                .map(|storage| storage.storage_slots_ref().iter().map(|(slot, _)| *slot))
                .into_iter()
                .flatten();
            for hashed_slot in slots.chain(touched.keys().copied()) {
                if !seen.insert(hashed_slot) {
                    continue
                }
                let before = value_before_block(
                    &mut hashed_storage,
                    &overlay,
                    number,
                    hashed_address,
                    hashed_slot,
                )?;
                let plain = match touched.get(&hashed_slot) {
                    Some((plain, _)) => Some(*plain),
                    None => plain_key(
                        &history,
                        &mut plain_keys,
                        &overlay,
                        number,
                        *address,
                        hashed_slot,
                    )?,
                };
                match plain {
                    // A touched slot always gets a row. An untouched slot only if it held a value.
                    Some(key) if touched.contains_key(&hashed_slot) || !before.is_zero() => {
                        account_rows.push(StorageBeforeTx { address: *address, key, value: before })
                    }
                    Some(_) => {}
                    None if before.is_zero() => {}
                    None => unknown_keys += 1,
                }
            }
            if unknown_keys > 0 {
                error!(
                    target: "providers::db",
                    block = number,
                    %address,
                    unknown_keys,
                    "Wiped storage slots have no known plain key; their changeset rows are missing"
                );
            }
            debug!(
                target: "providers::db",
                block = number,
                %address,
                rows = account_rows.len(),
                "Restored storage changeset rows for a wiped account"
            );
            rows.insert((number, *address), account_rows);
        }
    }
    Ok(rows)
}

/// Returns the value of a hashed slot just before `block`.
///
/// The newest block below `block` in the overlay that changed the slot wins. Otherwise the
/// database holds the value, as of the hashed-state frontier.
fn value_before_block<N, C>(
    hashed_storage: &mut C,
    overlay: &BTreeMap<BlockNumber, &ExecutedBlock<N>>,
    block: BlockNumber,
    hashed_address: B256,
    hashed_slot: B256,
) -> ProviderResult<U256>
where
    N: NodePrimitives,
    C: DbDupCursorRO<tables::HashedStorages>,
{
    for (_, earlier) in overlay.range(..block).rev() {
        if let Some(storage) = earlier.hashed_state().storages.get(&hashed_address) &&
            let Ok(index) =
                storage.storage_slots_ref().binary_search_by_key(&hashed_slot, |(slot, _)| *slot)
        {
            return Ok(storage.storage_slots_ref()[index].1)
        }
    }
    Ok(hashed_storage
        .seek_by_key_subkey(hashed_address, hashed_slot)?
        .filter(|entry| entry.key == hashed_slot)
        .map(|entry| entry.value)
        .unwrap_or_default())
}

/// Returns the plain key of a hashed slot of `address`, or `None` if no source knows it.
///
/// Sources, in order: the plain keys in the overlay's bundles up to `block`, then every slot the
/// storage history index lists for the address.
fn plain_key<N, TX>(
    history: &SlotHistory<'_, TX>,
    cache: &mut HashMap<Address, HashMap<B256, B256>>,
    overlay: &BTreeMap<BlockNumber, &ExecutedBlock<N>>,
    block: BlockNumber,
    address: Address,
    hashed_slot: B256,
) -> ProviderResult<Option<B256>>
where
    N: NodePrimitives,
    TX: DbTx,
{
    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(address) {
        let mut keys = HashMap::<B256, B256>::default();
        let mut add = |plain: B256| {
            keys.insert(keccak256(plain), plain);
        };
        for (_, earlier) in overlay.range(..=block) {
            let state = &earlier.execution_outcome().state;
            if let Some(account) = state.state.get(&address) {
                account.storage.keys().for_each(|slot| add(B256::from(*slot)));
            }
            for (reverted, revert) in state.reverts.iter().flatten() {
                if *reverted == address {
                    revert.storage.keys().for_each(|slot| add(B256::from(*slot)));
                }
            }
        }
        for plain in history_slots(history, address)? {
            add(plain);
        }
        entry.insert(keys);
    }
    Ok(cache.get(&address).and_then(|keys| keys.get(&hashed_slot)).copied())
}

/// Lists every plain slot key the storage history index holds for `address`.
fn history_slots<TX: DbTx>(
    history: &SlotHistory<'_, TX>,
    address: Address,
) -> ProviderResult<Vec<B256>> {
    let start = StorageShardedKey::new(address, B256::ZERO, 0);
    let mut slots = Vec::new();
    match history {
        SlotHistory::RocksDB(rocksdb) => {
            slots = rocksdb.storage_history_slots(address)?;
        }
        SlotHistory::Database(tx) => {
            let mut cursor = tx.cursor_read::<tables::StoragesHistory>()?;
            let mut entry = cursor.seek(start)?;
            while let Some((key, _)) = entry {
                if key.address != address {
                    break
                }
                if slots.last() != Some(&key.sharded_key.key) {
                    slots.push(key.sharded_key.key);
                }
                entry = cursor.next()?;
            }
        }
    }
    Ok(slots)
}
