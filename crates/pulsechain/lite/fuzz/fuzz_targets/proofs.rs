//! Account and storage proof verification against the real root of a small trie built here.
//!
//! A valid proof (of a present or an absent key) is mutated: bytes flipped, nodes dropped,
//! duplicated, reordered or replaced, extra nodes added (other nodes of the same trie included),
//! and the claim changed. Whatever the mutation, verification may only ever accept the true
//! value. The full-storage rebuild is checked the same way.
#![no_main]

use alloy_consensus::constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use reth_pulsechain_lite::verify::{
    verify_account, verify_full_storage, verify_storage, AccountProof, ProvenAccount, StorageEntry,
};
use reth_pulsechain_lite_fuzz::{slot_rlp, World};
use std::sync::LazyLock;

static WORLD: LazyLock<World> = LazyLock::new(World::small);

#[derive(Debug, Arbitrary)]
enum Edit {
    Flip {
        node: u8,
        at: u16,
        xor: u8,
    },
    Drop {
        node: u8,
    },
    Dup {
        node: u8,
    },
    Swap {
        a: u8,
        b: u8,
    },
    Truncate {
        node: u8,
        len: u16,
    },
    Replace {
        node: u8,
        bytes: Vec<u8>,
    },
    Push {
        bytes: Vec<u8>,
    },
    /// Adds a node of the same trie, possibly from another path.
    Foreign {
        pick: u16,
    },
    Clear,
}

fn apply(proof: &mut Vec<Bytes>, e: &Edit, pool: &[Bytes]) {
    let pick = |n: u8, len: usize| usize::from(n) % len;
    match e {
        Edit::Flip { node, at, xor } if !proof.is_empty() => {
            let i = pick(*node, proof.len());
            let mut v = proof[i].to_vec();
            if !v.is_empty() {
                let j = usize::from(*at) % v.len();
                v[j] ^= xor.max(&1);
                proof[i] = v.into();
            }
        }
        Edit::Drop { node } if !proof.is_empty() => {
            let i = pick(*node, proof.len());
            proof.remove(i);
        }
        Edit::Dup { node } if !proof.is_empty() => {
            let i = pick(*node, proof.len());
            proof.push(proof[i].clone());
        }
        Edit::Swap { a, b } if !proof.is_empty() => {
            let (i, j) = (pick(*a, proof.len()), pick(*b, proof.len()));
            proof.swap(i, j);
        }
        Edit::Truncate { node, len } if !proof.is_empty() => {
            let i = pick(*node, proof.len());
            let n = usize::from(*len) % (proof[i].len() + 1);
            proof[i] = proof[i].slice(..n);
        }
        Edit::Replace { node, bytes } if !proof.is_empty() => {
            let i = pick(*node, proof.len());
            proof[i] = Bytes::from(bytes.clone());
        }
        Edit::Push { bytes } => proof.push(Bytes::from(bytes.clone())),
        Edit::Foreign { pick } if !pool.is_empty() => {
            proof.push(pool[usize::from(*pick) % pool.len()].clone());
        }
        Edit::Clear => proof.clear(),
        _ => {}
    }
}

#[derive(Debug, Arbitrary)]
enum Claim {
    True,
    Nonce(u64),
    Balance([u8; 32]),
    StorageRoot([u8; 32]),
    CodeHash([u8; 32]),
    /// The claim of an absent account (all zero).
    Absent,
}

#[derive(Debug, Arbitrary)]
enum Case {
    Account {
        /// An index into the world, or past it for an absent address.
        who: u8,
        absent_seed: [u8; 20],
        claim: Claim,
        edits: Vec<Edit>,
        /// Slots checked with the account, each with its claimed value (None: the true one).
        slots: Vec<(u8, Option<[u8; 32]>, Vec<Edit>)>,
    },
    Storage {
        slot: u8,
        claimed: Option<[u8; 32]>,
        edits: Vec<Edit>,
        /// Verify against the empty root instead.
        empty_root: bool,
    },
    /// Arbitrary node lists against the real state root.
    Raw { addr: [u8; 20], nodes: Vec<Vec<u8>> },
    FullStorage {
        edits: Vec<(u8, Option<[u8; 32]>)>,
        drop: Vec<u8>,
        extra: Vec<([u8; 32], [u8; 32])>,
    },
}

/// The contract with storage in the small world.
fn storage_owner() -> Address {
    Address::repeat_byte(2)
}

fn slot_key(n: u8) -> B256 {
    // Slots 0..12 exist; others are absent.
    B256::with_last_byte(n % 24)
}

fn word(b: &[u8; 32]) -> U256 {
    U256::from_be_bytes(*b)
}

fn run(case: &Case) {
    let w = &*WORLD;
    let pool: Vec<Bytes> = w.all_nodes().into_values().collect();
    match case {
        Case::Account { who, absent_seed, claim, edits, slots } => {
            let addr = w
                .accounts
                .get(usize::from(*who))
                .map(|(a, _)| *a)
                .unwrap_or_else(|| Address::from(*absent_seed));
            let truth = w.trie_accounts.get(&addr).copied().map(ProvenAccount::from);
            let mut proof = w.state.proof(keccak256(addr));
            for e in edits.iter().take(6) {
                apply(&mut proof, e, &pool);
            }
            let t = truth.unwrap_or(ProvenAccount {
                nonce: 0,
                balance: U256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
                code_hash: KECCAK_EMPTY,
            });
            let mut claimed = (t.nonce, t.balance, t.storage_root, t.code_hash);
            match claim {
                Claim::True => {}
                Claim::Nonce(n) => claimed.0 = *n,
                Claim::Balance(b) => claimed.1 = word(b),
                Claim::StorageRoot(r) => claimed.2 = B256::from(*r),
                Claim::CodeHash(h) => claimed.3 = B256::from(*h),
                Claim::Absent => claimed = (0, U256::ZERO, B256::ZERO, B256::ZERO),
            }
            let storage_root = truth.map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
            let st = w.storage.get(&addr);
            let mut entries = Vec::new();
            for (n, value, edits) in slots.iter().take(3) {
                let key = slot_key(*n);
                let true_value = w.slot(&addr, &key);
                let mut p = st.map(|t| t.proof(keccak256(key))).unwrap_or_default();
                for e in edits.iter().take(4) {
                    apply(&mut p, e, &pool);
                }
                let value = value.as_ref().map_or(true_value, word);
                entries.push((StorageEntry { key, value, proof: p }, true_value));
            }
            let proof = AccountProof {
                address: addr,
                nonce: claimed.0,
                balance: claimed.1,
                storage_hash: claimed.2,
                code_hash: claimed.3,
                account_proof: proof,
                storage_proof: entries.iter().map(|(e, _)| e.clone()).collect(),
            };
            if let Ok((proven, nodes)) = verify_account(w.state.root, addr, &proof) {
                assert_eq!(proven, truth, "an account proof was accepted for a wrong account");
                for (e, true_value) in &entries {
                    assert_eq!(e.value, *true_value, "a slot was accepted with a wrong value");
                }
                if let Some(a) = proven {
                    assert_eq!(a.storage_root, storage_root);
                }
                for (h, n) in nodes {
                    assert_eq!(keccak256(&n), h, "a returned node is not keyed by its hash");
                    assert!(w.all_nodes().contains_key(&h), "a returned node is not in the trie");
                }
            }
        }
        Case::Storage { slot, claimed, edits, empty_root } => {
            let st = &w.storage[&storage_owner()];
            let key = slot_key(*slot);
            let (root, truth) = if *empty_root {
                (EMPTY_ROOT_HASH, U256::ZERO)
            } else {
                (st.root, w.slot(&storage_owner(), &key))
            };
            let mut proof = st.proof(keccak256(key));
            for e in edits.iter().take(6) {
                apply(&mut proof, e, &pool);
            }
            let claim = claimed.as_ref().map_or(truth, word);
            if let Ok((proven, nodes)) = verify_storage(root, key, claim, &proof) {
                assert_eq!(proven, truth, "a storage proof was accepted for a wrong value");
                assert_eq!(claim, truth);
                for (h, n) in nodes {
                    assert_eq!(keccak256(&n), h);
                    assert!(st.nodes.contains_key(&h));
                }
            }
        }
        Case::Raw { addr, nodes } => {
            let addr = Address::from(*addr);
            let proof = AccountProof {
                address: addr,
                nonce: 0,
                balance: U256::ZERO,
                storage_hash: B256::ZERO,
                code_hash: B256::ZERO,
                account_proof: nodes.iter().take(16).map(|n| Bytes::from(n.clone())).collect(),
                storage_proof: Vec::new(),
            };
            if let Ok((proven, _)) = verify_account(w.state.root, addr, &proof) {
                let truth = w.trie_accounts.get(&addr).copied().map(ProvenAccount::from);
                assert_eq!(proven, truth);
            }
        }
        Case::FullStorage { edits, drop, extra } => {
            let owner = storage_owner();
            let (_, acct) = w.accounts.iter().find(|(a, _)| *a == owner).unwrap();
            let truth: Vec<(B256, U256)> = acct.storage.clone();
            let mut slots: Vec<(B256, U256)> = truth.clone();
            for (i, v) in edits.iter().take(4) {
                if slots.is_empty() {
                    break;
                }
                let i = usize::from(*i) % slots.len();
                if let Some(v) = v {
                    slots[i].1 = word(v);
                } else {
                    slots[i].0 = B256::from(keccak256(slots[i].0));
                }
            }
            for d in drop.iter().take(2) {
                if !slots.is_empty() {
                    let i = usize::from(*d) % slots.len();
                    slots.remove(i);
                }
            }
            for (k, v) in extra.iter().take(2) {
                slots.push((B256::from(*k), word(v)));
            }
            let hashed: Vec<(B256, Bytes)> =
                slots.iter().map(|(k, v)| (keccak256(k), Bytes::from(slot_rlp(*v)))).collect();
            if verify_full_storage(w.storage[&owner].root, &hashed).is_ok() {
                let mut got = slots.clone();
                got.sort();
                let mut want = truth;
                want.sort();
                assert_eq!(got, want, "a wrong full storage set was accepted");
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(case) = Case::arbitrary(&mut Unstructured::new(data)) {
        run(&case);
    }
});
