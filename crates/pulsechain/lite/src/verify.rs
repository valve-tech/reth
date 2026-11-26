//! The one verifier: everything the lite node serves is checked here first.
//!
//! * accounts and storage by Merkle proof against a trusted state root (address mismatch,
//!   absent-account fields empty, claimed equals proven, empty storage root means zero, a
//!   proof-less full slot set is rebuilt and compared);
//! * code by hash;
//! * block bodies by transactions root, uncles hash and withdrawals root;
//! * receipts by receipts root.
//!
//! The same walker ([`walk_path`]) also reads the partial trie out of the store, so a "proof"
//! and the state the EVM reads share one code path.

use alloy_consensus::{
    constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY},
    proofs::{
        calculate_ommers_root, calculate_receipt_root, calculate_transaction_root,
        calculate_withdrawals_root,
    },
    BlockBody, Header, TrieAccount,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::{
    nodes::{RlpNode, TrieNode},
    HashBuilder, Nibbles,
};
use reth_eth_wire_types::snap::{AccountRangeMessage, StorageRangesMessage};
use std::collections::HashMap;

/// Why data was rejected, or a walk could not finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The response is for a different address.
    #[error("proof is for a different address")]
    AddressMismatch,
    /// The claimed account does not match the proven one.
    #[error("claimed account does not match the proof")]
    AccountMismatch,
    /// The claimed storage value does not match the proof.
    #[error("claimed storage value does not match the proof")]
    StorageMismatch,
    /// A proof node is missing, so the path cannot be walked.
    #[error("proof is missing a node")]
    Incomplete,
    /// A node is not valid RLP trie data.
    #[error("malformed trie node")]
    Malformed,
    /// Code does not hash to the expected code hash.
    #[error("code does not match its hash")]
    CodeMismatch,
    /// A body root does not match the header.
    #[error("body does not match the header ({0})")]
    BodyMismatch(&'static str),
    /// The receipts root does not match the header.
    #[error("receipts do not match the header")]
    ReceiptsMismatch,
    /// A rebuilt storage trie does not hash to the storage root.
    #[error("storage set does not rebuild the storage root")]
    StorageRootMismatch,
    /// A full storage set holds the same slot more than once.
    #[error("storage set holds a slot more than once")]
    DuplicateSlot,
}

/// An account whose fields are proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenAccount {
    /// Transaction count.
    pub nonce: u64,
    /// Balance in wei.
    pub balance: U256,
    /// Root of the account's storage trie.
    pub storage_root: B256,
    /// Hash of the account's code.
    pub code_hash: B256,
}

impl From<TrieAccount> for ProvenAccount {
    fn from(a: TrieAccount) -> Self {
        Self {
            nonce: a.nonce,
            balance: a.balance,
            storage_root: a.storage_root,
            code_hash: a.code_hash,
        }
    }
}

/// One storage slot of an [`AccountProof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEntry {
    /// The slot key.
    pub key: B256,
    /// The claimed value.
    pub value: U256,
    /// Proof nodes from the storage root.
    pub proof: Vec<Bytes>,
}

/// An EIP-1186 shaped account proof: the claim plus the nodes that prove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProof {
    /// The address asked about.
    pub address: Address,
    /// Claimed balance.
    pub balance: U256,
    /// Claimed code hash.
    pub code_hash: B256,
    /// Claimed nonce.
    pub nonce: u64,
    /// Claimed storage root.
    pub storage_hash: B256,
    /// Account trie proof nodes.
    pub account_proof: Vec<Bytes>,
    /// Slots with proofs.
    pub storage_proof: Vec<StorageEntry>,
}

impl AccountProof {
    /// Builds the claim from a one-key `AccountRange` response for `address`.
    ///
    /// If the first returned account is not the one asked about, the claim is "absent": the
    /// range's neighbour plus the proof show the gap, and the verifier checks that.
    pub fn from_account_range(address: Address, msg: &AccountRangeMessage) -> Self {
        let hashed = keccak256(address);
        let claim = msg.accounts.first().filter(|a| a.hash == hashed).map(|a| a.trie_account());
        let (nonce, balance, storage_hash, code_hash) = claim
            .map_or((0, U256::ZERO, B256::ZERO, B256::ZERO), |a| {
                (a.nonce, a.balance, a.storage_root, a.code_hash)
            });
        Self {
            address,
            balance,
            code_hash,
            nonce,
            storage_hash,
            account_proof: msg.proof.clone(),
            storage_proof: Vec::new(),
        }
    }

    /// Adds the one-slot `StorageRanges` response for `slot` (a single account, one key).
    ///
    /// A slot that is not the first returned is claimed zero.
    pub fn with_storage_range(mut self, slot: B256, msg: &StorageRangesMessage) -> Self {
        let hashed = keccak256(slot);
        let value = msg
            .slots
            .first()
            .and_then(|s| s.first())
            .filter(|d| d.hash == hashed)
            .and_then(|d| U256::decode(&mut d.data.as_ref()).ok())
            .unwrap_or(U256::ZERO);
        self.storage_proof.push(StorageEntry { key: slot, value, proof: msg.proof.clone() });
        self
    }
}

impl From<alloy_rpc_types_eth::EIP1186AccountProofResponse> for AccountProof {
    fn from(r: alloy_rpc_types_eth::EIP1186AccountProofResponse) -> Self {
        Self {
            address: r.address,
            balance: r.balance,
            code_hash: r.code_hash,
            nonce: r.nonce,
            storage_hash: r.storage_hash,
            account_proof: r.account_proof,
            storage_proof: r
                .storage_proof
                .into_iter()
                .map(|s| StorageEntry { key: s.key.as_b256(), value: s.value, proof: s.proof })
                .collect(),
        }
    }
}

/// A node read on a verified path, keyed by its hash, ready for the store.
pub type NodeRead = (B256, Bytes);

/// Where a walk stopped for lack of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stop {
    /// The hash of the node that was needed.
    pub hash: B256,
    /// The path already walked (nibbles) when the node was needed.
    pub prefix: Nibbles,
}

/// What a walk found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    /// The leaf value, or `None` when the path is proven absent.
    pub value: Option<Vec<u8>>,
    /// Every hashed node read on the way.
    pub nodes: Vec<NodeRead>,
}

/// Why a walk did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// A node was not available.
    Missing(Stop),
    /// A node did not decode.
    Malformed,
}

/// Walks `path` (nibbles of the hashed key) from `root`, fetching nodes by hash from `get`.
///
/// Returns the leaf value or a proof of absence, and the hashed nodes read.
pub fn walk_path(
    root: B256,
    path: &Nibbles,
    get: impl Fn(&B256) -> Option<Bytes>,
) -> Result<Walk, WalkError> {
    if root == EMPTY_ROOT_HASH {
        return Ok(Walk { value: None, nodes: Vec::new() });
    }
    let mut nodes = Vec::new();
    let mut walked = 0usize;
    let mut next = RlpNode::word_rlp(&root);
    loop {
        // Resolve `next` into node bytes: either a hash reference or an embedded node.
        let owned;
        let raw: &[u8] = if let Some(hash) = next.as_hash() {
            let Some(bytes) = get(&hash) else {
                return Err(WalkError::Missing(Stop { hash, prefix: path.slice(..walked) }));
            };
            nodes.push((hash, bytes.clone()));
            owned = bytes;
            owned.as_ref()
        } else {
            next.as_slice()
        };
        let node = TrieNode::decode(&mut &raw[..]).map_err(|_| WalkError::Malformed)?;
        let rest = path.slice(walked..);
        match node {
            TrieNode::EmptyRoot => return Ok(Walk { value: None, nodes }),
            TrieNode::Leaf(leaf) => {
                let value = (leaf.key == rest).then_some(leaf.value);
                return Ok(Walk { value, nodes });
            }
            TrieNode::Extension(ext) => {
                if rest.len() < ext.key.len() || rest.slice(..ext.key.len()) != ext.key {
                    return Ok(Walk { value: None, nodes });
                }
                walked += ext.key.len();
                next = ext.child;
            }
            TrieNode::Branch(branch) => {
                if rest.is_empty() {
                    // Fixed-length keys: a branch has no value at a full-length path.
                    return Ok(Walk { value: None, nodes });
                }
                let nib = rest.get(0).expect("not empty");
                let branch_ref = branch.as_ref();
                let child = branch_ref.children().find(|(i, _)| *i == nib).and_then(|(_, c)| c);
                let Some(child) = child else { return Ok(Walk { value: None, nodes }) };
                next = child.clone();
                walked += 1;
            }
        }
    }
}

fn node_map(proof: &[Bytes]) -> HashMap<B256, Bytes> {
    proof.iter().map(|n| (keccak256(n), n.clone())).collect()
}

fn walk_proof(root: B256, key_hash: B256, proof: &[Bytes]) -> Result<Walk, VerifyError> {
    let map = node_map(proof);
    walk_path(root, &Nibbles::unpack(key_hash), |h| map.get(h).cloned()).map_err(|e| match e {
        WalkError::Missing(_) => VerifyError::Incomplete,
        WalkError::Malformed => VerifyError::Malformed,
    })
}

/// Verifies one slot against `storage_root`. Returns the proven value and the nodes read.
pub fn verify_storage(
    storage_root: B256,
    slot: B256,
    claimed: U256,
    proof: &[Bytes],
) -> Result<(U256, Vec<NodeRead>), VerifyError> {
    if storage_root == EMPTY_ROOT_HASH {
        // No proof needed: the trie is empty, so the value is zero.
        return if claimed.is_zero() {
            Ok((U256::ZERO, Vec::new()))
        } else {
            Err(VerifyError::StorageMismatch)
        };
    }
    let walk = walk_proof(storage_root, keccak256(slot), proof)?;
    let proven = match walk.value {
        None => U256::ZERO,
        Some(v) => U256::decode(&mut v.as_slice()).map_err(|_| VerifyError::Malformed)?,
    };
    if proven != claimed {
        return Err(VerifyError::StorageMismatch);
    }
    Ok((proven, walk.nodes))
}

/// Verifies an account (and any slots in the proof) against a trusted state `root`.
///
/// `Ok((None, _))` is a proven absent account. The returned nodes are everything read on the
/// verified paths, ready for the store.
pub fn verify_account(
    root: B256,
    address: Address,
    proof: &AccountProof,
) -> Result<(Option<ProvenAccount>, Vec<NodeRead>), VerifyError> {
    if proof.address != address {
        return Err(VerifyError::AddressMismatch);
    }
    let walk = walk_proof(root, keccak256(address), &proof.account_proof)?;
    let mut nodes = walk.nodes;
    let proven = match walk.value {
        None => {
            let empty = proof.balance.is_zero() &&
                proof.nonce == 0 &&
                (proof.code_hash.is_zero() || proof.code_hash == KECCAK_EMPTY) &&
                (proof.storage_hash.is_zero() || proof.storage_hash == EMPTY_ROOT_HASH);
            if !empty {
                return Err(VerifyError::AccountMismatch);
            }
            // Every slot of an absent account is zero.
            if proof.storage_proof.iter().any(|s| !s.value.is_zero()) {
                return Err(VerifyError::StorageMismatch);
            }
            return Ok((None, nodes));
        }
        Some(leaf) => {
            let acct =
                TrieAccount::decode(&mut leaf.as_slice()).map_err(|_| VerifyError::Malformed)?;
            ProvenAccount::from(acct)
        }
    };
    let claimed = ProvenAccount {
        nonce: proof.nonce,
        balance: proof.balance,
        storage_root: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    if proven != claimed {
        return Err(VerifyError::AccountMismatch);
    }
    for s in &proof.storage_proof {
        let (_, more) = verify_storage(proven.storage_root, s.key, s.value, &s.proof)?;
        nodes.extend(more);
    }
    Ok((Some(proven), nodes))
}

/// Verifies code against the hash an account commits to.
pub fn verify_code(hash: B256, code: &Bytes) -> Result<(), VerifyError> {
    if keccak256(code) == hash {
        Ok(())
    } else {
        Err(VerifyError::CodeMismatch)
    }
}

/// Rebuilds a storage trie from a complete, proof-less slot set and compares it to
/// `storage_root`. `slots` are `(keccak(slot), rlp(value))`, in any order, each slot once.
pub fn verify_full_storage(storage_root: B256, slots: &[(B256, Bytes)]) -> Result<(), VerifyError> {
    let mut sorted: Vec<_> = slots.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(VerifyError::DuplicateSlot);
    }
    let mut hb = HashBuilder::default();
    for (k, v) in sorted {
        hb.add_leaf(Nibbles::unpack(k), v);
    }
    if hb.root() == storage_root {
        Ok(())
    } else {
        Err(VerifyError::StorageRootMismatch)
    }
}

/// Verifies a block body against its header: transactions root, uncles hash, withdrawals root.
pub fn verify_body<T: Encodable2718>(
    header: &Header,
    body: &BlockBody<T>,
) -> Result<(), VerifyError> {
    if calculate_transaction_root(&body.transactions) != header.transactions_root {
        return Err(VerifyError::BodyMismatch("transactions root"));
    }
    if calculate_ommers_root(&body.ommers) != header.ommers_hash {
        return Err(VerifyError::BodyMismatch("uncles hash"));
    }
    match (&body.withdrawals, header.withdrawals_root) {
        (None, None) => {}
        (Some(w), Some(root)) if calculate_withdrawals_root(w) == root => {}
        _ => return Err(VerifyError::BodyMismatch("withdrawals root")),
    }
    Ok(())
}

/// Verifies receipts against the header's receipts root.
pub fn verify_receipts<R: Encodable2718>(
    header: &Header,
    receipts: &[R],
) -> Result<(), VerifyError> {
    if calculate_receipt_root(receipts) == header.receipts_root {
        Ok(())
    } else {
        Err(VerifyError::ReceiptsMismatch)
    }
}

/// RLP of a slot value as a storage leaf holds it.
pub fn slot_rlp(value: U256) -> Bytes {
    let mut out = Vec::new();
    value.encode(&mut out);
    out.into()
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Generated tries with proofs, shared by the verifier, state and execution tests.

    use super::*;
    use alloy_trie::proof::ProofRetainer;

    /// A trie of `(hashed key, value)` pairs with proof nodes retained for `targets`.
    pub(crate) struct Built {
        pub(crate) root: B256,
        pub(crate) proofs: HashMap<B256, Vec<Bytes>>,
        /// Every node of the trie by hash (what an honest full node can serve).
        #[allow(dead_code)] // read by the state tests
        pub(crate) all_nodes: HashMap<B256, Bytes>,
    }

    pub(crate) fn build(mut leaves: Vec<(B256, Vec<u8>)>, targets: &[B256]) -> Built {
        leaves.sort_by_key(|(k, _)| *k);
        let retainer = ProofRetainer::new(targets.iter().map(|k| Nibbles::unpack(*k)).collect());
        let mut hb = HashBuilder::default().with_proof_retainer(retainer);
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(*k), v);
        }
        let root = hb.root();
        let nodes = hb.take_proof_nodes();
        let mut proofs = HashMap::new();
        for t in targets {
            let p = nodes.matching_nodes_sorted(&Nibbles::unpack(*t));
            proofs.insert(*t, p.into_iter().map(|(_, b)| b).collect());
        }
        // Retain every node: rebuild with all leaf paths as targets.
        let all_targets = leaves.iter().map(|(k, _)| Nibbles::unpack(*k)).collect();
        let mut hb2 = HashBuilder::default().with_proof_retainer(ProofRetainer::new(all_targets));
        for (k, v) in &leaves {
            hb2.add_leaf(Nibbles::unpack(*k), v);
        }
        let _ = hb2.root();
        let mut all_nodes = HashMap::new();
        for (_, b) in hb2.take_proof_nodes().into_inner() {
            all_nodes.insert(keccak256(&b), b);
        }
        Built { root, proofs, all_nodes }
    }

    pub(crate) fn account_leaf(a: &TrieAccount) -> Vec<u8> {
        alloy_rlp::encode(a)
    }
}

#[cfg(test)]
mod tests {
    use super::{fixtures::*, *};
    use alloy_consensus::{
        Eip658Value, Receipt, ReceiptEnvelope, ReceiptWithBloom, Signed, TxEnvelope, TxLegacy,
    };
    use alloy_eips::eip4895::{Withdrawal, Withdrawals};
    use alloy_primitives::Signature;
    use reth_eth_wire_types::snap::{AccountData, StorageData};

    fn addr(n: u8) -> Address {
        Address::repeat_byte(n)
    }

    fn acct(n: u64, bal: u64, storage_root: B256, code: B256) -> TrieAccount {
        TrieAccount { nonce: n, balance: U256::from(bal), storage_root, code_hash: code }
    }

    struct World {
        root: B256,
        proofs: HashMap<B256, Vec<Bytes>>,
        storage_root: B256,
        storage_proofs: HashMap<B256, Vec<Bytes>>,
    }

    fn world() -> World {
        let slots: Vec<(B256, Vec<u8>)> = (1u64..=6)
            .map(|i| (keccak256(B256::from(U256::from(i))), alloy_rlp::encode(U256::from(i * 100))))
            .collect();
        let slot_targets: Vec<B256> = slots.iter().map(|(k, _)| *k).collect();
        let st = build(slots, &slot_targets);
        let mut accounts = Vec::new();
        for i in 1u8..=9 {
            let storage_root = if i == 1 { st.root } else { EMPTY_ROOT_HASH };
            accounts.push((
                keccak256(addr(i)),
                account_leaf(&acct(i as u64, 1000 * i as u64, storage_root, KECCAK_EMPTY)),
            ));
        }
        let targets: Vec<B256> =
            (1u8..=9).map(|i| keccak256(addr(i))).chain([keccak256(addr(200))]).collect();
        let t = build(accounts, &targets);
        World { root: t.root, proofs: t.proofs, storage_root: st.root, storage_proofs: st.proofs }
    }

    fn claim(w: &World, i: u8) -> AccountProof {
        AccountProof {
            address: addr(i),
            balance: U256::from(1000 * i as u64),
            code_hash: KECCAK_EMPTY,
            nonce: i as u64,
            storage_hash: if i == 1 { w.storage_root } else { EMPTY_ROOT_HASH },
            account_proof: w.proofs[&keccak256(addr(i))].clone(),
            storage_proof: vec![],
        }
    }

    #[test]
    fn valid_account_and_its_nodes() {
        let w = world();
        let (acct, nodes) = verify_account(w.root, addr(3), &claim(&w, 3)).unwrap();
        let acct = acct.unwrap();
        assert_eq!((acct.nonce, acct.balance), (3, U256::from(3000)));
        assert!(!nodes.is_empty());
        for (h, n) in nodes {
            assert_eq!(h, keccak256(&n));
        }
    }

    #[test]
    fn absent_account() {
        let w = world();
        let proof = AccountProof {
            address: addr(200),
            balance: U256::ZERO,
            code_hash: B256::ZERO,
            nonce: 0,
            storage_hash: B256::ZERO,
            account_proof: w.proofs[&keccak256(addr(200))].clone(),
            storage_proof: vec![],
        };
        assert_eq!(verify_account(w.root, addr(200), &proof).unwrap().0, None);
        // An absent account may not claim a balance.
        let mut bad = proof;
        bad.balance = U256::from(1);
        assert_eq!(verify_account(w.root, addr(200), &bad), Err(VerifyError::AccountMismatch));
        // A present account cannot be claimed absent with another account's proof. The claim
        // is empty, so only the proof can fail it.
        let lie = AccountProof {
            address: addr(4),
            balance: U256::ZERO,
            code_hash: B256::ZERO,
            nonce: 0,
            storage_hash: B256::ZERO,
            account_proof: w.proofs[&keccak256(addr(3))].clone(),
            storage_proof: vec![],
        };
        // The proof leaves the path of addr(4) where it splits from addr(3)'s.
        assert_eq!(verify_account(w.root, addr(4), &lie), Err(VerifyError::Incomplete));
        // The same proof can prove a really absent address absent, when the paths split at a
        // node it holds: that is a valid proof, not a lie.
        let real = AccountProof { address: addr(200), ..lie.clone() };
        assert_eq!(verify_account(w.root, addr(200), &real).map(|r| r.0), Ok(None));
        // With every node on its own path, the proof reaches the leaf that refutes the claim.
        let full_path =
            AccountProof { account_proof: w.proofs[&keccak256(addr(4))].clone(), ..lie };
        assert_eq!(verify_account(w.root, addr(4), &full_path), Err(VerifyError::AccountMismatch));
    }

    #[test]
    fn an_absent_account_proves_every_field_empty_and_every_slot_zero() {
        let w = world();
        let empty = AccountProof {
            address: addr(200),
            balance: U256::ZERO,
            code_hash: B256::ZERO,
            nonce: 0,
            storage_hash: B256::ZERO,
            account_proof: w.proofs[&keccak256(addr(200))].clone(),
            storage_proof: vec![StorageEntry { key: B256::ZERO, value: U256::ZERO, proof: vec![] }],
        };
        // eth_getProof writes the empty hashes instead of zero.
        let rpc = AccountProof {
            code_hash: KECCAK_EMPTY,
            storage_hash: EMPTY_ROOT_HASH,
            ..empty.clone()
        };
        for p in [&empty, &rpc] {
            assert_eq!(verify_account(w.root, addr(200), p).map(|r| r.0), Ok(None));
        }
        for bad in [
            AccountProof { nonce: 1, ..empty.clone() },
            AccountProof { code_hash: B256::repeat_byte(1), ..empty.clone() },
            AccountProof { storage_hash: B256::repeat_byte(1), ..empty.clone() },
        ] {
            assert_eq!(verify_account(w.root, addr(200), &bad), Err(VerifyError::AccountMismatch));
        }
        let mut slot = empty;
        slot.storage_proof[0].value = U256::from(1);
        assert_eq!(verify_account(w.root, addr(200), &slot), Err(VerifyError::StorageMismatch));
    }

    #[test]
    fn a_slot_proof_under_another_storage_root_is_refused() {
        let w = world();
        let slot = B256::from(U256::from(2));
        let entry = StorageEntry {
            key: slot,
            value: U256::from(200),
            proof: w.storage_proofs[&keccak256(slot)].clone(),
        };
        // Account 2 has no storage, so its slots are zero whatever the proof says.
        let mut p = claim(&w, 2);
        p.storage_proof.push(entry.clone());
        assert_eq!(verify_account(w.root, addr(2), &p), Err(VerifyError::StorageMismatch));
        // A proof from another storage trie lacks the root node of account 1's.
        let other =
            build(vec![(keccak256(slot), alloy_rlp::encode(U256::from(200)))], &[keccak256(slot)]);
        let mut p = claim(&w, 1);
        p.storage_proof
            .push(StorageEntry { proof: other.proofs[&keccak256(slot)].clone(), ..entry });
        assert_eq!(verify_account(w.root, addr(1), &p), Err(VerifyError::Incomplete));
    }

    #[test]
    fn a_node_that_hashes_right_but_is_not_a_trie_node_is_malformed() {
        // Valid RLP, but no trie node is a list of three items.
        let garbage = Bytes::from_static(&[0xc3, 0x80, 0x80, 0x80]);
        let root = keccak256(&garbage);
        let proof = AccountProof {
            address: addr(1),
            balance: U256::ZERO,
            code_hash: B256::ZERO,
            nonce: 0,
            storage_hash: B256::ZERO,
            account_proof: vec![garbage.clone()],
            storage_proof: vec![],
        };
        assert_eq!(verify_account(root, addr(1), &proof), Err(VerifyError::Malformed));
        assert_eq!(
            verify_storage(root, B256::ZERO, U256::ZERO, &[garbage]),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn a_leaf_that_is_not_an_account_or_a_slot_value_is_malformed() {
        // An empty list, and a 33-byte string that overflows a slot.
        for bad in [vec![0xc0], alloy_rlp::encode(&[0xffu8; 33][..])] {
            let a = build(vec![(keccak256(addr(1)), bad.clone())], &[keccak256(addr(1))]);
            let proof = AccountProof {
                address: addr(1),
                balance: U256::ZERO,
                code_hash: B256::ZERO,
                nonce: 0,
                storage_hash: B256::ZERO,
                account_proof: a.proofs[&keccak256(addr(1))].clone(),
                storage_proof: vec![],
            };
            assert_eq!(verify_account(a.root, addr(1), &proof), Err(VerifyError::Malformed));
            let key = keccak256(B256::ZERO);
            let s = build(vec![(key, bad)], &[key]);
            assert_eq!(
                verify_storage(s.root, B256::ZERO, U256::ZERO, &s.proofs[&key]),
                Err(VerifyError::Malformed)
            );
        }
    }

    #[test]
    fn wrong_balance_rejected() {
        let w = world();
        let mut p = claim(&w, 3);
        p.balance += U256::from(1);
        assert_eq!(verify_account(w.root, addr(3), &p), Err(VerifyError::AccountMismatch));
    }

    #[test]
    fn wrong_address_rejected() {
        let w = world();
        assert_eq!(
            verify_account(w.root, addr(4), &claim(&w, 3)),
            Err(VerifyError::AddressMismatch)
        );
    }

    #[test]
    fn tampered_node_rejected() {
        let w = world();
        let mut p = claim(&w, 3);
        let last = p.account_proof.len() - 1;
        let mut raw = p.account_proof[last].to_vec();
        let n = raw.len() - 1;
        raw[n] ^= 1;
        p.account_proof[last] = raw.into();
        // The changed node no longer hashes to the reference its parent holds.
        assert_eq!(verify_account(w.root, addr(3), &p), Err(VerifyError::Incomplete));
        // Dropping a node leaves the path incomplete.
        let mut short = claim(&w, 3);
        short.account_proof.pop();
        assert_eq!(verify_account(w.root, addr(3), &short), Err(VerifyError::Incomplete));
    }

    #[test]
    fn storage_proofs() {
        let w = world();
        let slot = B256::from(U256::from(2));
        let mut p = claim(&w, 1);
        p.storage_proof.push(StorageEntry {
            key: slot,
            value: U256::from(200),
            proof: w.storage_proofs[&keccak256(slot)].clone(),
        });
        let (_, nodes) = verify_account(w.root, addr(1), &p).unwrap();
        assert!(nodes.len() > 2);
        // Wrong value.
        p.storage_proof[0].value = U256::from(201);
        assert_eq!(verify_account(w.root, addr(1), &p), Err(VerifyError::StorageMismatch));
        // Empty storage root: zero needs no proof, non-zero is rejected.
        assert_eq!(
            verify_storage(EMPTY_ROOT_HASH, slot, U256::ZERO, &[]),
            Ok((U256::ZERO, vec![]))
        );
        assert_eq!(
            verify_storage(EMPTY_ROOT_HASH, slot, U256::from(1), &[]),
            Err(VerifyError::StorageMismatch)
        );
        // A slot not in the trie is zero, proven by its path.
        let absent = B256::from(U256::from(77));
        let proof_of_absent = {
            let leaves: Vec<_> = (1u64..=6)
                .map(|i| {
                    (keccak256(B256::from(U256::from(i))), alloy_rlp::encode(U256::from(i * 100)))
                })
                .collect();
            build(leaves, &[keccak256(absent)]).proofs.remove(&keccak256(absent)).unwrap()
        };
        assert_eq!(
            verify_storage(w.storage_root, absent, U256::ZERO, &proof_of_absent).unwrap().0,
            U256::ZERO
        );
        assert_eq!(
            verify_storage(w.storage_root, absent, U256::from(5), &proof_of_absent),
            Err(VerifyError::StorageMismatch)
        );
    }

    #[test]
    fn full_storage_set_rebuilds_the_root() {
        let w = world();
        let mut slots: Vec<(B256, Bytes)> = (1u64..=6)
            .map(|i| (keccak256(B256::from(U256::from(i))), slot_rlp(U256::from(i * 100))))
            .collect();
        assert!(verify_full_storage(w.storage_root, &slots).is_ok());
        slots[2].1 = slot_rlp(U256::from(1));
        assert_eq!(
            verify_full_storage(w.storage_root, &slots),
            Err(VerifyError::StorageRootMismatch)
        );
        assert_eq!(verify_full_storage(EMPTY_ROOT_HASH, &[]), Ok(()));
        assert_eq!(verify_full_storage(w.storage_root, &[]), Err(VerifyError::StorageRootMismatch));
        // A stored zero (RLP 0x80) is a leaf like any other, so it changes the root.
        slots[2].1 = slot_rlp(U256::from(300));
        assert_eq!(verify_full_storage(w.storage_root, &slots), Ok(()));
        slots.push((keccak256(B256::from(U256::from(9))), slot_rlp(U256::ZERO)));
        assert_eq!(
            verify_full_storage(w.storage_root, &slots),
            Err(VerifyError::StorageRootMismatch)
        );
    }

    #[test]
    fn full_storage_set_rejects_a_duplicate_slot() {
        let w = world();
        let mut slots: Vec<(B256, Bytes)> = (1u64..=6)
            .map(|i| (keccak256(B256::from(U256::from(i))), slot_rlp(U256::from(i * 100))))
            .collect();
        // The real pair comes first, so a first-wins dedup would rebuild the true root.
        slots.push((slots[2].0, slot_rlp(U256::from(1))));
        assert_eq!(verify_full_storage(w.storage_root, &slots), Err(VerifyError::DuplicateSlot));
    }

    #[test]
    fn snap_range_shape_equals_eth_get_proof_shape() {
        let w = world();
        let a = addr(5);
        let acct5 = acct(5, 5000, EMPTY_ROOT_HASH, KECCAK_EMPTY);
        let msg = AccountRangeMessage {
            request_id: 1,
            accounts: vec![AccountData::from_trie_account(keccak256(a), &acct5)],
            proof: w.proofs[&keccak256(a)].clone(),
        };
        let from_snap = AccountProof::from_account_range(a, &msg);
        let from_rpc = claim(&w, 5);
        assert_eq!(from_snap, from_rpc);
        assert_eq!(verify_account(w.root, a, &from_snap), verify_account(w.root, a, &from_rpc));
        // A neighbour returned instead of the account is the "absent" claim, which a present
        // account's proof refutes.
        let other = AccountRangeMessage {
            request_id: 1,
            accounts: vec![AccountData::from_trie_account(
                keccak256(addr(6)),
                &acct(6, 6000, EMPTY_ROOT_HASH, KECCAK_EMPTY),
            )],
            proof: w.proofs[&keccak256(a)].clone(),
        };
        let lie = AccountProof::from_account_range(a, &other);
        assert_eq!(verify_account(w.root, a, &lie), Err(VerifyError::AccountMismatch));
    }

    #[test]
    fn snap_storage_shape() {
        let w = world();
        let slot = B256::from(U256::from(3));
        let msg = StorageRangesMessage {
            request_id: 1,
            slots: vec![vec![StorageData::from_value(keccak256(slot), U256::from(300))]],
            proof: w.storage_proofs[&keccak256(slot)].clone(),
        };
        let p = claim(&w, 1).with_storage_range(slot, &msg);
        assert!(verify_account(w.root, addr(1), &p).is_ok());
    }

    #[test]
    fn code_hash() {
        let code = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00]);
        assert!(verify_code(keccak256(&code), &code).is_ok());
        assert_eq!(verify_code(B256::ZERO, &code), Err(VerifyError::CodeMismatch));
    }

    fn legacy_tx(nonce: u64) -> TxEnvelope {
        let tx = TxLegacy { nonce, ..Default::default() };
        TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn header_for(body: &BlockBody<TxEnvelope>) -> Header {
        Header {
            transactions_root: calculate_transaction_root(&body.transactions),
            ommers_hash: calculate_ommers_root(&body.ommers),
            withdrawals_root: body.withdrawals.as_ref().map(|w| calculate_withdrawals_root(w)),
            ..Default::default()
        }
    }

    #[test]
    fn body_roots() {
        let body = BlockBody {
            transactions: vec![legacy_tx(0), legacy_tx(1)],
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(vec![Withdrawal {
                index: 1,
                validator_index: 2,
                address: addr(1),
                amount: 5,
            }])),
        };
        let header = header_for(&body);
        assert!(verify_body(&header, &body).is_ok());

        let mut tx_bad = body.clone();
        tx_bad.transactions.pop();
        assert_eq!(
            verify_body(&header, &tx_bad),
            Err(VerifyError::BodyMismatch("transactions root"))
        );

        let mut uncle_bad = body.clone();
        uncle_bad.ommers.push(Header::default());
        assert_eq!(verify_body(&header, &uncle_bad), Err(VerifyError::BodyMismatch("uncles hash")));

        let mut w_bad = body.clone();
        w_bad.withdrawals = Some(Withdrawals::new(vec![]));
        assert_eq!(
            verify_body(&header, &w_bad),
            Err(VerifyError::BodyMismatch("withdrawals root"))
        );
        let mut w_none = body.clone();
        w_none.withdrawals = None;
        assert_eq!(
            verify_body(&header, &w_none),
            Err(VerifyError::BodyMismatch("withdrawals root"))
        );
        // A pre-Shanghai header holds no withdrawals root, so a body with withdrawals is wrong.
        let pre_shanghai = Header { withdrawals_root: None, ..header };
        assert_eq!(
            verify_body(&pre_shanghai, &body),
            Err(VerifyError::BodyMismatch("withdrawals root"))
        );
    }

    #[test]
    fn receipts_root() {
        let r = |gas: u64| {
            ReceiptEnvelope::Legacy(ReceiptWithBloom {
                receipt: Receipt {
                    status: Eip658Value::Eip658(true),
                    cumulative_gas_used: gas,
                    logs: vec![],
                },
                logs_bloom: Default::default(),
            })
        };
        let good = vec![r(21_000), r(42_000)];
        let header = Header { receipts_root: calculate_receipt_root(&good), ..Default::default() };
        assert!(verify_receipts(&header, &good).is_ok());
        assert_eq!(
            verify_receipts(&header, &[r(21_000), r(42_001)]),
            Err(VerifyError::ReceiptsMismatch)
        );
    }
}

#[cfg(test)]
mod props {
    use super::{fixtures::build, *};
    use alloy_trie::proof::ProofRetainer;
    use proptest::{prelude::*, sample::Index};
    use std::{cell::Cell, collections::BTreeMap};

    /// A key that keeps the first `shared` bytes of a base key, so keys share long prefixes and
    /// the trie gets extension nodes and children small enough to embed in their parent.
    fn key_spec() -> impl Strategy<Value = (usize, [u8; 32])> {
        (prop_oneof![Just(31usize), Just(30), Just(16), 0usize..32], any::<[u8; 32]>())
    }

    fn key(base: &[u8; 32], (shared, tail): &(usize, [u8; 32])) -> B256 {
        let mut k = *base;
        k[*shared..].copy_from_slice(&tail[*shared..]);
        B256::from(k)
    }

    /// Proof nodes, with the path of each, for every target.
    fn prove(
        leaves: &BTreeMap<B256, Vec<u8>>,
        targets: &[B256],
    ) -> (B256, HashMap<B256, Vec<(Nibbles, Bytes)>>) {
        let retainer = ProofRetainer::new(targets.iter().map(|k| Nibbles::unpack(*k)).collect());
        let mut hb = HashBuilder::default().with_proof_retainer(retainer);
        for (k, v) in leaves {
            hb.add_leaf(Nibbles::unpack(*k), v);
        }
        let root = hb.root();
        let nodes = hb.take_proof_nodes();
        let proofs = targets
            .iter()
            .map(|t| (*t, nodes.matching_nodes_sorted(&Nibbles::unpack(*t))))
            .collect();
        (root, proofs)
    }

    fn walk(root: B256, key: B256, proof: &[Bytes]) -> Result<Walk, WalkError> {
        let map = node_map(proof);
        walk_path(root, &Nibbles::unpack(key), |h| map.get(h).cloned())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// An honest inclusion or absence proof gives exactly the model's value; one dropped or
        /// changed node gives the exact miss at that node's path, never another value.
        #[test]
        fn proofs_give_the_model_value_and_a_broken_proof_an_exact_miss(
            base in any::<[u8; 32]>(),
            present in prop::collection::vec(
                (key_spec(), prop::collection::vec(any::<u8>(), 1..40)), 1..16),
            absent in prop::collection::vec(key_spec(), 0..8),
            pick in any::<Index>(),
            at in any::<Index>(),
            flip in 1u8..=255,
        ) {
            let leaves: BTreeMap<B256, Vec<u8>> =
                present.iter().map(|(k, v)| (key(&base, k), v.clone())).collect();
            let targets: Vec<B256> = leaves
                .keys()
                .copied()
                .chain(absent.iter().map(|k| key(&base, k)))
                .collect();
            let (root, proofs) = prove(&leaves, &targets);
            let every_node: Vec<Bytes> =
                proofs.values().flatten().map(|(_, n)| n.clone()).collect();
            for t in &targets {
                let proof: Vec<Bytes> = proofs[t].iter().map(|(_, n)| n.clone()).collect();
                let w = walk(root, *t, &proof).unwrap();
                prop_assert_eq!(&w.value, &leaves.get(t).cloned());
                prop_assert_eq!(w.nodes[0].0, root);
                for (h, n) in &w.nodes {
                    prop_assert_eq!(*h, keccak256(n));
                }
                // Order and nodes off the path do not matter.
                let mut noisy: Vec<Bytes> = every_node.iter().rev().cloned().collect();
                noisy.extend(proof.iter().cloned());
                prop_assert_eq!(&walk(root, *t, &noisy).unwrap().value, &w.value);

                let (hash, node) = w.nodes[pick.index(w.nodes.len())].clone();
                let prefix = proofs[t].iter().find(|(_, n)| *n == node).unwrap().0;
                let want = Err(WalkError::Missing(Stop { hash, prefix }));
                let dropped: Vec<Bytes> = proof.iter().filter(|n| **n != node).cloned().collect();
                prop_assert_eq!(&walk(root, *t, &dropped), &want);
                let mut raw = node.to_vec();
                let i = at.index(raw.len());
                raw[i] ^= flip;
                let changed: Vec<Bytes> = proof
                    .iter()
                    .map(|n| if *n == node { Bytes::from(raw.clone()) } else { n.clone() })
                    .collect();
                prop_assert_eq!(&walk(root, *t, &changed), &want);
            }
        }

        /// A storage claim verifies only at its proven value.
        #[test]
        fn a_storage_claim_verifies_only_at_its_value(
            slots in prop::collection::btree_map(any::<[u8; 32]>(), 1..=u128::MAX, 1..12),
            absent in any::<[u8; 32]>(),
            delta in 1..=u128::MAX,
        ) {
            let leaves: Vec<_> = slots
                .iter()
                .map(|(s, v)| (keccak256(s), slot_rlp(U256::from(*v)).to_vec()))
                .collect();
            let mut targets: Vec<B256> = slots.keys().map(keccak256).collect();
            targets.push(keccak256(absent));
            let t = build(leaves, &targets);
            for (s, v) in &slots {
                let (slot, value) = (B256::from(*s), U256::from(*v));
                let proof = &t.proofs[&keccak256(slot)];
                prop_assert_eq!(verify_storage(t.root, slot, value, proof).map(|r| r.0), Ok(value));
                let lie = value.wrapping_add(U256::from(delta));
                prop_assert_eq!(
                    verify_storage(t.root, slot, lie, proof),
                    Err(VerifyError::StorageMismatch)
                );
            }
            if !slots.contains_key(&absent) {
                let (slot, proof) = (B256::from(absent), &t.proofs[&keccak256(absent)]);
                prop_assert_eq!(
                    verify_storage(t.root, slot, U256::ZERO, proof).map(|r| r.0),
                    Ok(U256::ZERO)
                );
                prop_assert_eq!(
                    verify_storage(t.root, slot, U256::from(delta), proof),
                    Err(VerifyError::StorageMismatch)
                );
            }
        }

        /// A full slot set rebuilds the root in any order, and any one insert, delete, changed
        /// value or repeated slot is refused.
        #[test]
        fn a_full_storage_set_is_exact(
            slots in prop::collection::btree_map(any::<[u8; 32]>(), any::<u128>(), 1..24),
            extra in (any::<[u8; 32]>(), any::<u128>()),
            pick in any::<Index>(),
            turn in any::<Index>(),
        ) {
            let mut set: Vec<(B256, Bytes)> = slots
                .iter()
                .map(|(k, v)| (B256::from(*k), slot_rlp(U256::from(*v))))
                .collect();
            let root = build(set.iter().map(|(k, v)| (*k, v.to_vec())).collect(), &[]).root;
            set.reverse();
            let n = turn.index(set.len());
            set.rotate_left(n);
            prop_assert_eq!(verify_full_storage(root, &set), Ok(()));

            let i = pick.index(set.len());
            if !slots.contains_key(&extra.0) {
                let mut more = set.clone();
                more.push((B256::from(extra.0), slot_rlp(U256::from(extra.1))));
                prop_assert_eq!(verify_full_storage(root, &more), Err(VerifyError::StorageRootMismatch));
            }
            let mut fewer = set.clone();
            fewer.remove(i);
            prop_assert_eq!(verify_full_storage(root, &fewer), Err(VerifyError::StorageRootMismatch));
            let mut changed = set.clone();
            let old = U256::decode(&mut changed[i].1.as_ref()).unwrap();
            changed[i].1 = slot_rlp(old ^ U256::from(1));
            prop_assert_eq!(verify_full_storage(root, &changed), Err(VerifyError::StorageRootMismatch));
            for value in [set[i].1.clone(), slot_rlp(old ^ U256::from(1))] {
                let mut twice = set.clone();
                twice.push((set[i].0, value));
                prop_assert_eq!(verify_full_storage(root, &twice), Err(VerifyError::DuplicateSlot));
            }
        }
    }

    /// A trie root, the leaf a range answer returns, and its proof nodes.
    type RangeAnswer = (B256, Option<(B256, Vec<u8>)>, Vec<Bytes>);

    /// What a go-ethereum snap server answers to a one-key range request at `origin` (limit
    /// `origin`, one byte): the first leaf at or after `origin`, with the proofs of `origin` and
    /// of that leaf, or past the last leaf no leaf and the proof of `origin`.
    fn geth_range(leaves: &BTreeMap<B256, Vec<u8>>, origin: B256) -> RangeAnswer {
        let next = leaves.range(origin..).next().map(|(k, v)| (*k, v.clone()));
        let targets: Vec<B256> = next.iter().map(|(k, _)| *k).chain([origin]).collect();
        let (root, proofs) = prove(leaves, &targets);
        // The leaf's proof comes first, so the answer does not lean on the order of the nodes.
        let mut proof: Vec<Bytes> = Vec::new();
        for (_, node) in targets.iter().flat_map(|t| &proofs[t]) {
            if !proof.contains(node) {
                proof.push(node.clone());
            }
        }
        (root, next, proof)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// A go-ethereum shaped `AccountRange` answer verifies to the model account: the account
        /// itself, or for an absent key the neighbour past it (or nothing past the last leaf)
        /// with the boundary proofs.
        #[test]
        fn a_geth_account_range_answer_verifies_to_the_model_account(
            accounts in prop::collection::btree_map(
                any::<[u8; 20]>(), (any::<u64>(), any::<u128>(), any::<bool>()), 1..16),
            asked in prop_oneof![
                any::<Index>().prop_map(Ok),
                any::<[u8; 20]>().prop_map(Err),
            ],
        ) {
            let model: BTreeMap<Address, TrieAccount> = accounts
                .iter()
                .map(|(a, (nonce, balance, code))| {
                    let code_hash = if *code { keccak256(a) } else { KECCAK_EMPTY };
                    let acct = TrieAccount {
                        nonce: *nonce,
                        balance: U256::from(*balance),
                        storage_root: EMPTY_ROOT_HASH,
                        code_hash,
                    };
                    (Address::from(*a), acct)
                })
                .collect();
            let leaves: BTreeMap<B256, Vec<u8>> =
                model.iter().map(|(a, acct)| (keccak256(a), alloy_rlp::encode(acct))).collect();
            let address = match asked {
                Ok(i) => *model.keys().nth(i.index(model.len())).unwrap(),
                Err(a) => Address::from(a),
            };
            let (root, next, proof) = geth_range(&leaves, keccak256(address));
            let accounts = next
                .iter()
                .map(|(k, v)| {
                    let acct = TrieAccount::decode(&mut v.as_slice()).unwrap();
                    reth_eth_wire_types::snap::AccountData::from_trie_account(*k, &acct)
                })
                .collect();
            let msg = AccountRangeMessage { request_id: 1, accounts, proof };
            let claim = AccountProof::from_account_range(address, &msg);
            prop_assert_eq!(
                verify_account(root, address, &claim).map(|r| r.0),
                Ok(model.get(&address).map(|a| ProvenAccount::from(*a)))
            );
        }

        /// A go-ethereum shaped `StorageRanges` answer verifies to the model value, as the
        /// client reads it: the slot itself, or for an absent slot the neighbour past it (or an
        /// empty slot list past the last leaf) with the boundary proofs.
        #[test]
        fn a_geth_storage_range_answer_verifies_to_the_model_value(
            slots in prop::collection::btree_map(any::<[u8; 32]>(), 1..=u128::MAX, 1..16),
            asked in prop_oneof![
                any::<Index>().prop_map(Ok),
                any::<[u8; 32]>().prop_map(Err),
            ],
        ) {
            let leaves: BTreeMap<B256, Vec<u8>> = slots
                .iter()
                .map(|(s, v)| (keccak256(s), slot_rlp(U256::from(*v)).to_vec()))
                .collect();
            let slot = B256::from(match asked {
                Ok(i) => *slots.keys().nth(i.index(slots.len())).unwrap(),
                Err(s) => s,
            });
            let (root, next, proof) = geth_range(&leaves, keccak256(slot));
            let found: Vec<_> = next
                .iter()
                .map(|(k, v)| {
                    let value = U256::decode(&mut v.as_slice()).unwrap();
                    reth_eth_wire_types::snap::StorageData::from_value(*k, value)
                })
                .collect();
            // geth leaves out the list of an account with no slot in the range.
            let msg = StorageRangesMessage {
                request_id: 1,
                slots: if found.is_empty() { vec![] } else { vec![found] },
                proof,
            };
            let absent = AccountProof {
                address: Address::ZERO,
                balance: U256::ZERO,
                code_hash: B256::ZERO,
                nonce: 0,
                storage_hash: B256::ZERO,
                account_proof: vec![],
                storage_proof: vec![],
            };
            let claimed = absent.with_storage_range(slot, &msg);
            let entry = &claimed.storage_proof[0];
            let want = slots.get(&slot.0).map_or(U256::ZERO, |v| U256::from(*v));
            prop_assert_eq!(
                verify_storage(root, slot, entry.value, &entry.proof).map(|r| r.0),
                Ok(want)
            );
        }
    }

    /// A child of a generated node: empty, a reference to (or the embedding of) an earlier node,
    /// or an arbitrary string.
    #[derive(Debug, Clone)]
    enum Child {
        Empty,
        Earlier(Index),
        Raw(Vec<u8>),
    }

    /// A node shape the decoder must survive, valid or not.
    #[derive(Debug, Clone)]
    enum Shape {
        /// A leaf or extension: compact key prefix byte, key bytes, child or value.
        Short(u8, Vec<u8>, Child),
        /// A branch: children (any count, 16 is valid) and a value.
        Branch(Vec<Child>, Vec<u8>),
        /// An earlier node cut short.
        Truncated(Index, Index),
        /// Arbitrary bytes.
        Bytes(Vec<u8>),
    }

    // Weighted toward what decodes, so walks get past the first node.
    fn child() -> impl Strategy<Value = Child> {
        prop_oneof![
            3 => Just(Child::Empty),
            4 => any::<Index>().prop_map(Child::Earlier),
            2 => prop::collection::vec(any::<u8>(), 32).prop_map(Child::Raw),
            1 => prop::collection::vec(any::<u8>(), 0..34).prop_map(Child::Raw),
        ]
    }

    fn shape() -> impl Strategy<Value = Shape> {
        let prefix = prop_oneof![(0u8..4, 0u8..16).prop_map(|(f, n)| (f << 4) | n), any::<u8>()];
        prop_oneof![
            (prefix, prop::collection::vec(any::<u8>(), 0..33), child())
                .prop_map(|(p, k, c)| Shape::Short(p, k, c)),
            (
                prop_oneof![
                    8 => prop::collection::vec(child(), 16),
                    1 => prop::collection::vec(child(), 15..=17),
                ],
                prop_oneof![4 => Just(Vec::new()), 1 => prop::collection::vec(any::<u8>(), 1..3)],
            )
                .prop_map(|(c, v)| Shape::Branch(c, v)),
            (any::<Index>(), any::<Index>()).prop_map(|(n, at)| Shape::Truncated(n, at)),
            prop::collection::vec(any::<u8>(), 0..80).prop_map(Shape::Bytes),
        ]
    }

    fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
        out.extend(payload);
        out
    }

    fn encode_child(c: &Child, earlier: &[Vec<u8>]) -> Vec<u8> {
        match c {
            Child::Empty => vec![alloy_rlp::EMPTY_STRING_CODE],
            Child::Earlier(_) if earlier.is_empty() => vec![alloy_rlp::EMPTY_STRING_CODE],
            Child::Earlier(i) => {
                let node = &earlier[i.index(earlier.len())];
                if node.len() < 32 {
                    node.clone()
                } else {
                    alloy_rlp::encode(keccak256(node))
                }
            }
            Child::Raw(b) => alloy_rlp::encode(&b[..]),
        }
    }

    /// Encodes the shapes in order; each may point at the ones before it.
    fn encode_nodes(shapes: &[Shape]) -> Vec<Vec<u8>> {
        let mut nodes: Vec<Vec<u8>> = Vec::new();
        for s in shapes {
            let node = match s {
                Shape::Short(prefix, key, c) => {
                    let compact = [&[*prefix][..], key].concat();
                    encode_list(&[alloy_rlp::encode(&compact[..]), encode_child(c, &nodes)])
                }
                Shape::Branch(children, value) => {
                    let mut items: Vec<_> =
                        children.iter().map(|c| encode_child(c, &nodes)).collect();
                    items.push(alloy_rlp::encode(&value[..]));
                    encode_list(&items)
                }
                Shape::Truncated(_, _) if nodes.is_empty() => Vec::new(),
                Shape::Truncated(n, at) => {
                    let node = &nodes[n.index(nodes.len())];
                    node[..at.index(node.len() + 1)].to_vec()
                }
                Shape::Bytes(b) => b.clone(),
            };
            nodes.push(node);
        }
        nodes
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Arbitrary node bytes never panic the walker, each node is fetched at most once, and an
        /// answer only ever rests on nodes that hash to the references that led to them.
        #[test]
        fn a_walk_over_arbitrary_nodes_never_panics_and_stays_hash_bound(
            shapes in prop::collection::vec(shape(), 1..12),
            path in prop::collection::vec(0u8..16, 0..=64),
            other_root in any::<[u8; 32]>(),
            known_root in any::<bool>(),
        ) {
            let nodes = encode_nodes(&shapes);
            let root = if known_root {
                keccak256(nodes.last().unwrap())
            } else {
                B256::from(other_root)
            };
            let map: HashMap<B256, Bytes> =
                nodes.iter().map(|n| (keccak256(n), Bytes::from(n.clone()))).collect();
            let gets = Cell::new(0usize);
            let res = walk_path(root, &Nibbles::from_nibbles(&path), |h| {
                gets.set(gets.get() + 1);
                map.get(h).cloned()
            });
            prop_assert!(gets.get() <= map.len() + 1, "{} gets over {} nodes", gets.get(), map.len());
            if let Ok(w) = res {
                if root != EMPTY_ROOT_HASH {
                    prop_assert_eq!(w.nodes.first().map(|n| n.0), Some(root));
                }
                for (h, n) in &w.nodes {
                    prop_assert_eq!(*h, keccak256(n));
                }
            }
            // The same nodes as an account or slot proof: an error, or an answer, never a panic.
            let proof: Vec<Bytes> = map.values().cloned().collect();
            let claim = AccountProof {
                address: Address::from_slice(&other_root[..20]),
                balance: U256::ZERO,
                code_hash: B256::ZERO,
                nonce: 0,
                storage_hash: B256::ZERO,
                account_proof: proof.clone(),
                storage_proof: vec![StorageEntry {
                    key: B256::from(other_root),
                    value: U256::ZERO,
                    proof: proof.clone(),
                }],
            };
            let _ = verify_account(root, claim.address, &claim);
            let _ = verify_storage(root, B256::from(other_root), U256::ZERO, &proof);
        }
    }
}
