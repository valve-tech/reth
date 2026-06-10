use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use alloy_primitives::{Address, BlockNumber};
use auto_impl::auto_impl;
use core::ops::{RangeBounds, RangeInclusive};
use reth_db_models::AccountBeforeTx;
use reth_primitives_traits::Account;
use reth_storage_errors::provider::ProviderResult;

/// Account reader
#[auto_impl(&, Arc, Box)]
pub trait AccountReader {
    /// Get basic account information.
    ///
    /// Returns `None` if the account doesn't exist.
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>>;
}

/// Account reader
#[auto_impl(&, Arc, Box)]
pub trait AccountExtReader {
    /// Iterate over account changesets and return all account address that were changed.
    fn changed_accounts_with_range(
        &self,
        _range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<BTreeSet<Address>>;

    /// Get basic account information for multiple accounts. A more efficient version than calling
    /// [`AccountReader::basic_account`] repeatedly.
    ///
    /// Returns `None` if the account doesn't exist.
    fn basic_accounts(
        &self,
        _iter: impl IntoIterator<Item = Address>,
    ) -> ProviderResult<Vec<(Address, Option<Account>)>>;

    /// Iterate over account changesets and return all account addresses that were changed alongside
    /// each specific set of blocks.
    ///
    /// NOTE: Get inclusive range of blocks.
    fn changed_accounts_and_blocks_with_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<BTreeMap<Address, Vec<BlockNumber>>>;
}

/// Read access to the account-history index (`tables::AccountsHistory`): for a given address,
/// the block numbers at which the account's state changed.
///
/// The index is populated from account changesets, i.e. it contains the blocks where the
/// account's info (balance / nonce / code) changed. Note that blocks where only the account's
/// *storage* changed are tracked in the separate storage-history index and are NOT guaranteed to
/// appear here.
#[auto_impl(&, Arc, Box)]
pub trait AccountHistoryReader: Send + Sync {
    /// Returns up to `limit` block numbers strictly BELOW `before`, in descending order,
    /// at which `address` changed. An empty result means there are no recorded changes
    /// below `before`.
    fn account_changed_blocks_before(
        &self,
        address: Address,
        before: BlockNumber,
        limit: usize,
    ) -> ProviderResult<Vec<BlockNumber>>;

    /// Returns up to `limit` block numbers strictly ABOVE `after`, in ascending order,
    /// at which `address` changed. An empty result means there are no recorded changes
    /// above `after`.
    fn account_changed_blocks_after(
        &self,
        address: Address,
        after: BlockNumber,
        limit: usize,
    ) -> ProviderResult<Vec<BlockNumber>>;
}

/// `AccountChange` reader
#[auto_impl(&, Arc, Box)]
pub trait ChangeSetReader {
    /// Iterate over account changesets and return the account state from before this block.
    fn account_block_changeset(
        &self,
        block_number: BlockNumber,
    ) -> ProviderResult<Vec<AccountBeforeTx>>;

    /// Search the block's changesets for the given address, and return the result.
    ///
    /// Returns `None` if the account was not changed in this block.
    fn get_account_before_block(
        &self,
        block_number: BlockNumber,
        address: Address,
    ) -> ProviderResult<Option<AccountBeforeTx>>;

    /// Get all account changesets in a range of blocks.
    ///
    /// Accepts any range type that implements `RangeBounds<BlockNumber>`, including:
    /// - `Range<BlockNumber>` (e.g., `0..100`)
    /// - `RangeInclusive<BlockNumber>` (e.g., `0..=99`)
    /// - `RangeFrom<BlockNumber>` (e.g., `0..`) - iterates until exhausted
    ///
    /// If there is no start bound, 0 is used as the start block.
    ///
    /// Returns a vector of (`block_number`, changeset) pairs.
    fn account_changesets_range(
        &self,
        range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<(BlockNumber, AccountBeforeTx)>>;
}
