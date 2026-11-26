//! Shared support for the `reth-pulsechain-lite` fuzz targets: a paused tokio runtime and small
//! state tries built here, independent of the crate's own test fixtures.

use alloy_consensus::{
    constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY},
    TrieAccount,
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use std::collections::HashMap;

/// Runs `f` to completion on this thread's runtime. Time is paused: a sleep returns as soon as
/// nothing else can run, so retry pauses and timeouts cost no wall time.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    thread_local! {
        static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("runtime");
    }
    RT.with(|rt| rt.block_on(f))
}

/// A Merkle-Patricia trie with every node an honest full node holds.
#[derive(Debug, Clone)]
pub struct Trie {
    /// The root hash.
    pub root: B256,
    /// Every hashed node, by hash.
    pub nodes: HashMap<B256, Bytes>,
}

impl Trie {
    /// The trie of `(hashed key, value)` leaves.
    pub fn build(mut leaves: Vec<(B256, Vec<u8>)>) -> Self {
        leaves.sort_by_key(|(k, _)| *k);
        leaves.dedup_by_key(|(k, _)| *k);
        if leaves.is_empty() {
            return Self { root: EMPTY_ROOT_HASH, nodes: HashMap::new() };
        }
        let targets = leaves.iter().map(|(k, _)| Nibbles::unpack(*k)).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(*k), v);
        }
        let root = hb.root();
        let nodes =
            hb.take_proof_nodes().into_inner().into_values().map(|b| (keccak256(&b), b)).collect();
        Self { root, nodes }
    }

    /// The proof of `key` (hashed): the hashed nodes on its path, root first.
    pub fn proof(&self, key: B256) -> Vec<Bytes> {
        let walk = reth_pulsechain_lite::verify::walk_path(self.root, &Nibbles::unpack(key), |h| {
            self.nodes.get(h).cloned()
        })
        .expect("an honest trie has every node");
        walk.nodes.into_iter().map(|(_, n)| n).collect()
    }
}

/// One account of a test world.
#[derive(Debug, Clone, Default)]
pub struct Acct {
    pub balance: U256,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: Vec<(B256, U256)>,
}

/// A state trie, its storage tries, and the code an honest full node holds.
#[derive(Debug, Clone)]
pub struct World {
    pub accounts: Vec<(Address, Acct)>,
    pub state: Trie,
    pub storage: HashMap<Address, Trie>,
    pub trie_accounts: HashMap<Address, TrieAccount>,
    pub codes: HashMap<B256, Bytes>,
}

/// RLP of a slot value as a storage leaf holds it.
pub fn slot_rlp(v: U256) -> Vec<u8> {
    alloy_rlp::encode(v)
}

impl World {
    /// The world of `accounts`. Zero storage values are left out, as a trie does.
    pub fn build(accounts: Vec<(Address, Acct)>) -> Self {
        let mut leaves = Vec::new();
        let mut storage = HashMap::new();
        let mut trie_accounts = HashMap::new();
        let mut codes = HashMap::new();
        for (addr, a) in &accounts {
            let slots = a
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (keccak256(k), slot_rlp(*v)))
                .collect();
            let st = Trie::build(slots);
            let code_hash = if a.code.is_empty() {
                KECCAK_EMPTY
            } else {
                let h = keccak256(&a.code);
                codes.insert(h, Bytes::from(a.code.clone()));
                h
            };
            let t = TrieAccount {
                nonce: a.nonce,
                balance: a.balance,
                storage_root: st.root,
                code_hash,
            };
            leaves.push((keccak256(addr), alloy_rlp::encode(t)));
            storage.insert(*addr, st);
            trie_accounts.insert(*addr, t);
        }
        Self { state: Trie::build(leaves), accounts, storage, trie_accounts, codes }
    }

    /// A small fixed world: a few accounts, one with code and several slots.
    pub fn small() -> Self {
        let a = |n: u8| Address::repeat_byte(n);
        let slots = (0u8..12)
            .map(|i| (B256::with_last_byte(i), U256::from(u64::from(i) * 1000 + 7)))
            .collect();
        Self::build(vec![
            (
                a(1),
                Acct {
                    balance: U256::from(10u64).pow(U256::from(18)),
                    nonce: 3,
                    ..Default::default()
                },
            ),
            (
                a(2),
                Acct {
                    code: vec![0x60, 0x2a, 0x60, 0, 0x55, 0x00],
                    storage: slots,
                    ..Default::default()
                },
            ),
            (a(3), Acct { balance: U256::from(1), ..Default::default() }),
            (
                a(4),
                Acct {
                    code: vec![0x5b, 0x60, 0, 0x56],
                    storage: vec![(B256::ZERO, U256::MAX)],
                    ..Default::default()
                },
            ),
            (a(5), Acct { nonce: 1, ..Default::default() }),
        ])
    }

    /// The true storage value of `slot` of `addr`.
    pub fn slot(&self, addr: &Address, slot: &B256) -> U256 {
        self.accounts
            .iter()
            .find(|(a, _)| a == addr)
            .and_then(|(_, acct)| acct.storage.iter().find(|(k, _)| k == slot))
            .map_or(U256::ZERO, |(_, v)| *v)
    }

    /// Every hashed node of the state trie and all storage tries.
    pub fn all_nodes(&self) -> HashMap<B256, Bytes> {
        let mut out = self.state.nodes.clone();
        for st in self.storage.values() {
            out.extend(st.nodes.iter().map(|(k, v)| (*k, v.clone())));
        }
        out
    }
}
