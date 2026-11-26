//! A small in-memory state with real trie proofs, for the serving tests.
//!
//! [`FakeState`] implements [`StateRangeProvider`] over generated accounts and storage. Roots
//! and proofs come from `alloy_trie`'s `HashBuilder` and `ProofRetainer`, the same primitives the
//! real provider builds on, and the tests check results with `alloy_trie`'s own verifier.

use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::TrieNode,
    proof::{verify_proof, ProofRetainer, ProofVerificationError},
    HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH,
};
use reth_primitives_traits::Account;
use reth_storage_api::{
    errors::provider::ProviderResult, RangeEnd, RangeResponse, RangeResult, StateRangeProvider,
    StateRangeProviderFactory, StateRangeView, StorageRangeResult,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// One generated account.
#[derive(Debug, Clone)]
pub(crate) struct FakeAccount {
    pub(crate) account: Account,
    /// Slots keyed by their hashed key.
    pub(crate) storage: BTreeMap<B256, U256>,
}

/// Accounts keyed by hashed address.
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeState {
    pub(crate) accounts: BTreeMap<B256, FakeAccount>,
}

/// Builds a trie over sorted `leaves`, retaining proofs for `targets`.
fn build(leaves: &[(B256, Vec<u8>)], targets: &[B256]) -> (B256, Vec<Bytes>) {
    let retainer = ProofRetainer::new(targets.iter().map(|k| Nibbles::unpack(k)).collect());
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);
    for (key, value) in leaves {
        hb.add_leaf(Nibbles::unpack(key), value);
    }
    let root = hb.root();
    let nodes = hb.take_proof_nodes().into_nodes_sorted().into_iter().map(|(_, b)| b).collect();
    (root, nodes)
}

fn storage_leaves(storage: &BTreeMap<B256, U256>) -> Vec<(B256, Vec<u8>)> {
    storage.iter().map(|(k, v)| (*k, alloy_rlp::encode(v))).collect()
}

impl FakeAccount {
    pub(crate) fn storage_root(&self) -> B256 {
        build(&storage_leaves(&self.storage), &[]).0
    }

    pub(crate) fn trie_account(&self) -> TrieAccount {
        self.account.into_trie_account(self.storage_root())
    }
}

impl FakeState {
    /// `accounts` accounts with distinct balances, and `slots` storage slots on every 10th.
    pub(crate) fn generated(accounts: u64, slots: u64) -> Self {
        let mut state = Self::default();
        for i in 0..accounts {
            let hash = keccak256(i.to_be_bytes());
            let mut storage = BTreeMap::new();
            if i % 10 == 0 {
                for s in 0..slots {
                    storage.insert(
                        keccak256([i.to_be_bytes(), s.to_be_bytes()].concat()),
                        U256::from(s + 1),
                    );
                }
            }
            let account = Account {
                nonce: i,
                balance: U256::from(1000 + i),
                bytecode_hash: (i % 3 == 0).then(|| keccak256([i as u8])),
            };
            state.accounts.insert(hash, FakeAccount { account, storage });
        }
        state
    }

    fn account_leaves(&self) -> Vec<(B256, Vec<u8>)> {
        self.accounts.iter().map(|(h, a)| (*h, alloy_rlp::encode(a.trie_account()))).collect()
    }

    pub(crate) fn root(&self) -> B256 {
        build(&self.account_leaves(), &[]).0
    }
}

impl StateRangeProvider for FakeState {
    fn account_range(
        &self,
        start: B256,
        limit: B256,
        response_bytes: usize,
    ) -> RangeResult<(B256, Account)> {
        let mut items = Vec::new();
        let mut total = 0usize;
        let mut end = RangeEnd::Exhausted;
        for (hash, acc) in self.accounts.range(start..) {
            total += 32 + 4 * 32;
            items.push((*hash, acc.account));
            if *hash >= limit {
                end = RangeEnd::HashLimit;
                break
            }
            if total > response_bytes {
                end = RangeEnd::ByteLimit;
                break
            }
        }
        Ok(RangeResponse { items, end })
    }

    fn storage_root_by_hash(&self, hashed_address: B256) -> ProviderResult<B256> {
        Ok(self.accounts.get(&hashed_address).map_or(EMPTY_ROOT_HASH, FakeAccount::storage_root))
    }

    fn storage_range(
        &self,
        hashed_address: B256,
        start: B256,
        limit: B256,
        response_bytes: usize,
    ) -> StorageRangeResult {
        let Some(acc) = self.accounts.get(&hashed_address) else { return Ok(None) };
        let mut items = Vec::new();
        let mut total = 0usize;
        let mut end = RangeEnd::Exhausted;
        for (hash, value) in acc.storage.range(start..) {
            total += 64;
            items.push((*hash, *value));
            if *hash >= limit {
                end = RangeEnd::HashLimit;
                break
            }
            if total > response_bytes {
                end = RangeEnd::ByteLimit;
                break
            }
        }
        Ok(Some(RangeResponse { items, end }))
    }

    fn account_range_proof(&self, keys: &[B256]) -> ProviderResult<Vec<Bytes>> {
        Ok(build(&self.account_leaves(), keys).1)
    }

    fn storage_range_proof(
        &self,
        hashed_address: B256,
        keys: &[B256],
    ) -> ProviderResult<Vec<Bytes>> {
        let leaves = self.accounts.get(&hashed_address).map(|a| storage_leaves(&a.storage));
        Ok(build(&leaves.unwrap_or_default(), keys).1)
    }
}

/// Serves views for the roots it was given; any other root is unknown.
#[derive(Debug, Default)]
pub(crate) struct FakeFactory {
    states: HashMap<B256, Arc<FakeState>>,
}

impl FakeFactory {
    /// Registers `state` and returns its root.
    pub(crate) fn add(&mut self, state: FakeState) -> B256 {
        let root = state.root();
        self.states.insert(root, Arc::new(state));
        root
    }
}

struct View(Arc<FakeState>);

impl StateRangeProvider for View {
    fn account_range(&self, s: B256, l: B256, b: usize) -> RangeResult<(B256, Account)> {
        self.0.account_range(s, l, b)
    }
    fn storage_root_by_hash(&self, a: B256) -> ProviderResult<B256> {
        self.0.storage_root_by_hash(a)
    }
    fn storage_range(&self, a: B256, s: B256, l: B256, b: usize) -> StorageRangeResult {
        self.0.storage_range(a, s, l, b)
    }
    fn account_range_proof(&self, k: &[B256]) -> ProviderResult<Vec<Bytes>> {
        self.0.account_range_proof(k)
    }
    fn storage_range_proof(&self, a: B256, k: &[B256]) -> ProviderResult<Vec<Bytes>> {
        self.0.storage_range_proof(a, k)
    }
}

impl StateRangeProviderFactory for FakeFactory {
    fn state_range_provider(&self, root: B256) -> ProviderResult<Option<StateRangeView>> {
        Ok(self.states.get(&root).map(|s| Box::new(View(s.clone())) as StateRangeView))
    }
}

/// Picks, out of a multiproof, the nodes on the path to `key`, in order from the root.
///
/// This only selects; the verdict is `alloy_trie`'s [`verify_proof`]. Selection stops at the
/// first node it cannot find by hash, so a tampered node ends the path early.
pub(crate) fn path_nodes(root: B256, key: B256, proof: &[Bytes]) -> Vec<Bytes> {
    let by_hash: HashMap<B256, &Bytes> = proof.iter().map(|n| (keccak256(n), n)).collect();
    let nibbles = Nibbles::unpack(key);
    let mut out = Vec::new();
    let mut want = Some(root);
    let mut depth = 0usize;
    while let Some(hash) = want.take() {
        let Some(node) = by_hash.get(&hash) else { break };
        out.push((*node).clone());
        match TrieNode::decode(&mut &node[..]) {
            Ok(TrieNode::Branch(b)) => {
                let idx = nibbles.get(depth).unwrap_or(0);
                depth += 1;
                let mut stack = b.stack.iter();
                for i in 0..16u8 {
                    if b.state_mask.is_bit_set(i) {
                        let child = stack.next().expect("mask matches stack");
                        if i == idx && child.len() == 33 {
                            want = Some(B256::from_slice(&child[1..]));
                        }
                    }
                }
            }
            Ok(TrieNode::Extension(e)) => {
                depth += e.key.len();
                if e.child.len() == 33 {
                    want = Some(B256::from_slice(&e.child[1..]));
                }
            }
            _ => {}
        }
    }
    out
}

/// Verifies `key` against `root` with `alloy_trie`'s verifier, selecting its nodes first.
pub(crate) fn verify_key(
    root: B256,
    key: B256,
    expected: Option<Vec<u8>>,
    proof: &[Bytes],
) -> Result<(), ProofVerificationError> {
    let nodes = path_nodes(root, key, proof);
    verify_proof(root, Nibbles::unpack(key), expected, &nodes)
}

/// Every node of the trie over `leaves`, by position. Nodes shorter than 32 bytes are embedded in
/// their parent but are listed here too.
pub(crate) fn all_nodes(leaves: &[(B256, Vec<u8>)]) -> Vec<(Nibbles, Bytes)> {
    let keys: Vec<B256> = leaves.iter().map(|(k, _)| *k).collect();
    let retainer = ProofRetainer::new(keys.iter().map(|k| Nibbles::unpack(k)).collect());
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);
    for (key, value) in leaves {
        hb.add_leaf(Nibbles::unpack(key), value);
    }
    hb.root();
    hb.take_proof_nodes().into_nodes_sorted()
}

impl FakeState {
    pub(crate) fn account_trie_leaves(&self) -> Vec<(B256, Vec<u8>)> {
        self.account_leaves()
    }
}

impl FakeAccount {
    pub(crate) fn storage_trie_leaves(&self) -> Vec<(B256, Vec<u8>)> {
        storage_leaves(&self.storage)
    }
}

/// How often a [`CountingFactory`]'s views did costly work.
#[derive(Debug, Default)]
pub(crate) struct Counts {
    pub(crate) storage_roots: std::sync::atomic::AtomicUsize,
    pub(crate) proofs: std::sync::atomic::AtomicUsize,
    /// Keys passed to all proofs together.
    pub(crate) proof_keys: std::sync::atomic::AtomicUsize,
}

/// A [`FakeFactory`] whose views count storage root and proof computations.
#[derive(Debug, Default)]
pub(crate) struct CountingFactory {
    pub(crate) inner: FakeFactory,
    pub(crate) counts: Arc<Counts>,
}

struct CountingView {
    inner: StateRangeView,
    counts: Arc<Counts>,
}

impl CountingView {
    fn count(counter: &std::sync::atomic::AtomicUsize) {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl StateRangeProvider for CountingView {
    fn account_range(&self, s: B256, l: B256, b: usize) -> RangeResult<(B256, Account)> {
        self.inner.account_range(s, l, b)
    }
    fn storage_root_by_hash(&self, a: B256) -> ProviderResult<B256> {
        Self::count(&self.counts.storage_roots);
        self.inner.storage_root_by_hash(a)
    }
    fn storage_range(&self, a: B256, s: B256, l: B256, b: usize) -> StorageRangeResult {
        self.inner.storage_range(a, s, l, b)
    }
    fn account_range_proof(&self, k: &[B256]) -> ProviderResult<Vec<Bytes>> {
        Self::count(&self.counts.proofs);
        self.counts.proof_keys.fetch_add(k.len(), std::sync::atomic::Ordering::SeqCst);
        self.inner.account_range_proof(k)
    }
    fn storage_range_proof(&self, a: B256, k: &[B256]) -> ProviderResult<Vec<Bytes>> {
        Self::count(&self.counts.proofs);
        self.counts.proof_keys.fetch_add(k.len(), std::sync::atomic::Ordering::SeqCst);
        self.inner.storage_range_proof(a, k)
    }
}

impl StateRangeProviderFactory for CountingFactory {
    fn state_range_provider(&self, root: B256) -> ProviderResult<Option<StateRangeView>> {
        Ok(self.inner.state_range_provider(root)?.map(|inner| {
            Box::new(CountingView { inner, counts: self.counts.clone() }) as StateRangeView
        }))
    }
}
