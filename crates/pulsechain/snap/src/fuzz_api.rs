//! Hooks for the cargo-fuzz targets in `fuzz/`, behind the `fuzzing` feature.
//!
//! These are thin wrappers over the crate's in-memory test state and private helpers. They are
//! not a stable API.

use crate::{message::Snap1Message, test_utils};
use alloy_primitives::{Bytes, B256, U256};
use alloy_trie::{
    proof::{verify_proof, ProofVerificationError},
    Nibbles, TrieAccount,
};
use reth_storage_api::{
    errors::provider::ProviderResult, StateRangeProviderFactory, StateRangeView,
};
use std::collections::BTreeMap;

pub use reth_primitives_traits::Account;

/// An in-memory state whose roots and proofs come from `alloy_trie`'s `HashBuilder`.
#[derive(Debug, Clone, Default)]
pub struct FuzzState(test_utils::FakeState);

impl FuzzState {
    /// Inserts or replaces the account at `hash`, keeping its storage.
    pub fn set_account(&mut self, hash: B256, account: Account) {
        self.0
            .accounts
            .entry(hash)
            .and_modify(|a| a.account = account)
            .or_insert(test_utils::FakeAccount { account, storage: BTreeMap::new() });
    }

    /// Sets a storage slot of an existing account. A zero value removes the slot. Returns
    /// `false` when the account does not exist.
    pub fn set_slot(&mut self, account: B256, slot: B256, value: U256) -> bool {
        let Some(acc) = self.0.accounts.get_mut(&account) else { return false };
        if value.is_zero() {
            acc.storage.remove(&slot);
        } else {
            acc.storage.insert(slot, value);
        }
        true
    }

    /// The account trie root.
    pub fn root(&self) -> B256 {
        self.0.root()
    }

    /// The account at `hash` as its trie leaf commits to it.
    pub fn trie_account(&self, hash: B256) -> Option<TrieAccount> {
        self.0.accounts.get(&hash).map(test_utils::FakeAccount::trie_account)
    }

    /// The hashes of all accounts, ascending.
    pub fn account_hashes(&self) -> Vec<B256> {
        self.0.accounts.keys().copied().collect()
    }

    /// The slots of the account at `hash`, ascending, or `None` when it does not exist.
    pub fn slots(&self, hash: B256) -> Option<Vec<(B256, U256)>> {
        self.0.accounts.get(&hash).map(|a| a.storage.iter().map(|(k, v)| (*k, *v)).collect())
    }

    /// The storage root of the account at `hash`, or `None` when it does not exist.
    pub fn storage_root(&self, hash: B256) -> Option<B256> {
        self.0.accounts.get(&hash).map(test_utils::FakeAccount::storage_root)
    }

    /// Every node of the account trie by path, embedded nodes included.
    pub fn account_trie_nodes(&self) -> Vec<(Nibbles, Bytes)> {
        test_utils::all_nodes(&self.0.account_trie_leaves())
    }

    /// Every node of the storage trie of the account at `hash` by path, embedded nodes included.
    pub fn storage_trie_nodes(&self, hash: B256) -> Vec<(Nibbles, Bytes)> {
        self.0
            .accounts
            .get(&hash)
            .map(|a| test_utils::all_nodes(&a.storage_trie_leaves()))
            .unwrap_or_default()
    }

    /// Wraps the state in a factory that serves it at its root, and returns the root.
    pub fn into_factory(self) -> (FuzzFactory, B256) {
        let mut factory = test_utils::FakeFactory::default();
        let root = factory.add(self.0);
        (FuzzFactory(factory), root)
    }
}

/// Serves the [`FuzzState`] it was made from at its root; any other root is unknown.
#[derive(Debug)]
pub struct FuzzFactory(test_utils::FakeFactory);

impl StateRangeProviderFactory for FuzzFactory {
    fn state_range_provider(&self, root: B256) -> ProviderResult<Option<StateRangeView>> {
        self.0.state_range_provider(root)
    }
}

/// Picks, out of a multiproof, the nodes on the path to `key`, in order from the root.
pub fn path_nodes(root: B256, key: B256, proof: &[Bytes]) -> Vec<Bytes> {
    test_utils::path_nodes(root, key, proof)
}

/// Verifies `key` against `root` with `alloy_trie`'s verifier, selecting its nodes first.
pub fn verify_key(
    root: B256,
    key: B256,
    expected: Option<Vec<u8>>,
    proof: &[Bytes],
) -> Result<(), ProofVerificationError> {
    test_utils::verify_key(root, key, expected, proof)
}

/// Verifies `key` against `root` with `alloy_trie`'s verifier over exactly `nodes`, in order.
pub fn verify_path(
    root: B256,
    key: B256,
    expected: Option<Vec<u8>>,
    nodes: &[Bytes],
) -> Result<(), ProofVerificationError> {
    verify_proof(root, Nibbles::unpack(key), expected, nodes)
}

/// The reply bytes a request asks for, capped at the soft response limit.
pub fn reply_budget(msg: &Snap1Message) -> usize {
    crate::server::reply_budget(msg)
}

/// Answers a `GetAccountRange` request with an injectable clock, as
/// [`serve_account_range`](crate::serve_account_range) does with the system clock.
pub fn serve_account_range_with_clock<F: StateRangeProviderFactory>(
    factory: &F,
    req: &reth_eth_wire_types::snap::GetAccountRangeMessage,
    elapsed: impl FnMut() -> std::time::Duration,
) -> ProviderResult<reth_eth_wire_types::snap::AccountRangeMessage> {
    crate::ranges::serve_account_range_with_clock(factory, req, elapsed)
}
