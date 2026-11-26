//! Serving `GetTrieNodes` (`0x06`).
//!
//! reth keeps no RLP trie nodes addressable by path, so the nodes are rebuilt from proofs. For
//! each owner (the account trie, or one account's storage trie) multiproofs are taken whose
//! targets are the paths padded with zero nibbles up to a full key. The multiproof holds every
//! node on the way to each target, so it holds the node at any path `P` for which a node exists,
//! because that node lies on the way to every key with prefix `P`. The server then walks from the
//! root through hash links along each path and returns the node that sits exactly at that path.
//! An entry whose path no proof covers yet starts a multiproof over the next [`PROOF_BATCH`]
//! unproven paths of its owner in request order, so the work stays near what the budget serves.
//!
//! The reply is a prefix of the request: entry `i` answers path `i`. Serving can stop early at
//! the byte budget or the time limit (see below), and an unknown root gets no entries. An empty
//! entry means no node is served at that path. That is the case for a path that ends inside an
//! extension or a leaf, for a node embedded in its parent (shorter than 32 bytes), for a path
//! longer than a key, and for an account that does not exist. go-ethereum skips some of these
//! entries instead. Its healer matches each entry to the requested node hashes in order, and an
//! entry that matches none, such as an empty one, fails the whole reply ("unexpected healing
//! trienode") and drops the peer. Empty entries are safe only because a healer asks for nodes
//! that its parents reference by hash, so it never asks for such a path. Do not add placeholder
//! entries for any other case. reth-lite sends no `GetTrieNodes`.
//!
//! Limits follow go-ethereum: [`MAX_TRIE_NODE_LOOKUPS`] entries, the requested byte count
//! (capped at [`SOFT_RESPONSE_LIMIT`]) and [`MAX_TRIE_NODE_TIME`]. The lookup cap applies to the
//! request before any work, and covers placeholder entries too. Serving stops after the entry
//! that crosses the byte budget. The time limit is checked before each entry and after each
//! storage root, so no proof starts once it has passed. An unknown root answers empty.

use crate::bytecodes::SOFT_RESPONSE_LIMIT;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::{BranchNode, TrieNode},
    EMPTY_ROOT_HASH,
};
use reth_storage_api::{errors::provider::ProviderResult, StateRangeProviderFactory};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::message::{GetTrieNodesMessage, TrieNodesMessage};

/// The most trie node paths one request looks up, as in go-ethereum.
pub const MAX_TRIE_NODE_LOOKUPS: usize = 1024;

/// The longest one request spends before it stops, as in go-ethereum.
pub const MAX_TRIE_NODE_TIME: Duration = Duration::from_secs(5);

/// The most paths one multiproof covers. A small byte budget then pays for at most this many
/// targets, not for every path of the request.
pub const PROOF_BATCH: usize = 32;

/// Decodes a hex-prefix (compact) path into nibbles, without the terminator.
///
/// The high nibble of the first byte holds flags: bit 0 set means an odd number of nibbles, of
/// which the first is the low nibble of that byte; bit 1 is the leaf terminator and is ignored.
/// An empty input is the empty path.
pub fn compact_to_nibbles(compact: &[u8]) -> Vec<u8> {
    let Some((&first, rest)) = compact.split_first() else { return Vec::new() };
    let mut out = Vec::with_capacity(rest.len() * 2 + 1);
    if first & 0x10 != 0 {
        out.push(first & 0x0f);
    }
    for byte in rest {
        out.push(byte >> 4);
        out.push(byte & 0x0f);
    }
    out
}

/// Answers a `GetTrieNodes` request, timing the 5 s limit with the system clock.
pub fn serve_trie_nodes<F: StateRangeProviderFactory>(
    factory: &F,
    req: &GetTrieNodesMessage,
) -> ProviderResult<TrieNodesMessage> {
    let start = Instant::now();
    serve_trie_nodes_with_clock(factory, req, || start.elapsed())
}

/// Like [`serve_trie_nodes`], with an injectable clock that returns the time spent so far. It is
/// read before each entry is served and after each storage root is computed.
pub fn serve_trie_nodes_with_clock<F: StateRangeProviderFactory>(
    factory: &F,
    req: &GetTrieNodesMessage,
    mut elapsed: impl FnMut() -> Duration,
) -> ProviderResult<TrieNodesMessage> {
    let mut resp = TrieNodesMessage { request_id: req.request_id, nodes: Vec::new() };
    let Some(state) = factory.state_range_provider(req.root_hash)? else { return Ok(resp) };

    // Flatten the path sets into one list of lookups, in request order.
    struct Lookup {
        owner: Option<B256>,
        /// `None` when the owner hash or path cannot name a node.
        nibbles: Option<Vec<u8>>,
    }
    // Every entry of the response comes from one lookup, so capping the lookups caps the
    // response. Each non-empty set adds at least one lookup, so the sets past the cap are never
    // read.
    let mut lookups = Vec::new();
    for set in req.paths.iter().take(MAX_TRIE_NODE_LOOKUPS) {
        let Some((first, rest)) = set.split_first() else { continue };
        let (owner, paths) = if rest.is_empty() {
            (None, std::slice::from_ref(first))
        } else {
            ((first.len() == 32).then(|| B256::from_slice(first)), rest)
        };
        for path in paths.iter().take(MAX_TRIE_NODE_LOOKUPS - lookups.len()) {
            // A set whose first element is not an account hash keeps its positions and serves
            // nothing.
            let nibbles = if rest.is_empty() || owner.is_some() {
                Some(compact_to_nibbles(path)).filter(|n| n.len() <= 64)
            } else {
                None
            };
            lookups.push(Lookup { owner, nibbles });
        }
        if lookups.len() >= MAX_TRIE_NODE_LOOKUPS {
            break
        }
    }

    // owner -> (trie root, nodes by hash); `None` when the owner has no trie to read.
    let mut proofs: HashMap<Option<B256>, Option<ProofNodes>> = HashMap::new();
    let mut proven = vec![false; lookups.len()];

    let budget = usize::try_from(req.response_bytes).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT);
    let mut bytes = 0usize;
    let mut over_time = || elapsed() > MAX_TRIE_NODE_TIME;
    for (i, l) in lookups.iter().enumerate() {
        if over_time() {
            break
        }
        let node = match &l.nibbles {
            None => None,
            Some(nibbles) => {
                if let std::collections::hash_map::Entry::Vacant(slot) = proofs.entry(l.owner) {
                    let root = match l.owner {
                        None => Some(req.root_hash),
                        Some(owner) => {
                            let root = state.storage_root_by_hash(owner)?;
                            // A storage root can take long; build no proof past the limit.
                            if over_time() {
                                break
                            }
                            (root != EMPTY_ROOT_HASH).then_some(root)
                        }
                    };
                    slot.insert(root.map(|root| (root, HashMap::new())));
                }
                if let Some((_, nodes)) = proofs.get_mut(&l.owner).and_then(Option::as_mut) &&
                    !proven[i]
                {
                    let mut keys = Vec::with_capacity(PROOF_BATCH);
                    for (j, other) in lookups.iter().enumerate().skip(i) {
                        if keys.len() == PROOF_BATCH {
                            break
                        }
                        if let Some(n) = &other.nibbles &&
                            other.owner == l.owner &&
                            !proven[j]
                        {
                            proven[j] = true;
                            keys.push(pad_to_key(n));
                        }
                    }
                    let proof = match l.owner {
                        None => state.account_range_proof(&keys)?,
                        Some(owner) => state.storage_range_proof(owner, &keys)?,
                    };
                    nodes.extend(proof.into_iter().map(|n| (keccak256(&n), n)));
                }
                proofs[&l.owner].as_ref().and_then(|(root, nodes)| node_at(*root, nodes, nibbles))
            }
        };
        let node = node.unwrap_or_default();
        bytes += node.len();
        resp.nodes.push(node);
        if bytes > budget {
            break
        }
    }
    Ok(resp)
}

/// A trie root and the nodes of a multiproof by hash.
type ProofNodes = (B256, HashMap<B256, Bytes>);

/// Packs `nibbles` into a 32-byte key, padded with zero nibbles.
fn pad_to_key(nibbles: &[u8]) -> B256 {
    let mut key = B256::ZERO;
    for (i, n) in nibbles.iter().enumerate() {
        key.0[i / 2] |= if i % 2 == 0 { n << 4 } else { *n };
    }
    key
}

/// The hash a child reference links to, or `None` for a node embedded in its parent.
fn child_hash(child: &[u8]) -> Option<B256> {
    (child.len() == 33 && child[0] == 0xa0).then(|| B256::from_slice(&child[1..]))
}

fn branch_child(branch: &BranchNode, nibble: u8) -> Option<&[u8]> {
    if !branch.state_mask.is_bit_set(nibble) {
        return None
    }
    let below = (0..nibble).filter(|i| branch.state_mask.is_bit_set(*i)).count();
    branch.stack.get(below).map(|c| &c[..])
}

/// Walks from `root` through hash links and returns the node at exactly `path`.
fn node_at(root: B256, nodes: &HashMap<B256, Bytes>, path: &[u8]) -> Option<Bytes> {
    let mut hash = root;
    let mut depth = 0;
    loop {
        let node = nodes.get(&hash)?;
        if depth == path.len() {
            return Some(node.clone())
        }
        match TrieNode::decode(&mut &node[..]).ok()? {
            TrieNode::Branch(branch) => {
                hash = child_hash(branch_child(&branch, path[depth])?)?;
                depth += 1;
            }
            TrieNode::Extension(ext) => {
                let rest = &path[depth..];
                if rest.len() < ext.key.len() ||
                    !(0..ext.key.len()).all(|i| ext.key.get(i) == Some(rest[i]))
                {
                    return None
                }
                depth += ext.key.len();
                hash = child_hash(&ext.child)?;
            }
            TrieNode::Leaf(_) | TrieNode::EmptyRoot => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{all_nodes, FakeFactory, FakeState};
    use alloy_trie::Nibbles;
    use std::collections::HashSet;

    fn compact(nibbles: &[u8]) -> Bytes {
        let mut out = Vec::new();
        let rest = if nibbles.len() % 2 == 1 {
            out.push(0x10 | nibbles[0]);
            &nibbles[1..]
        } else {
            out.push(0x00);
            nibbles
        };
        out.extend(rest.chunks(2).map(|c| (c[0] << 4) | c[1]));
        out.into()
    }

    fn nibbles_of(p: &Nibbles) -> Vec<u8> {
        (0..p.len()).map(|i| p.get(i).unwrap()).collect()
    }

    fn req(root: B256, paths: Vec<Vec<Bytes>>, bytes: u64) -> GetTrieNodesMessage {
        GetTrieNodesMessage { request_id: 3, root_hash: root, paths, response_bytes: bytes }
    }

    /// Hashes a trie links to, plus its root: the only hashes a served node may have.
    fn linked_hashes(root: B256, nodes: &[(Nibbles, Bytes)]) -> HashSet<B256> {
        let mut set = HashSet::from([root]);
        for (_, n) in nodes {
            match TrieNode::decode(&mut &n[..]).unwrap() {
                TrieNode::Branch(b) => {
                    set.extend(b.stack.iter().filter_map(|c| child_hash(c)));
                }
                TrieNode::Extension(e) => set.extend(child_hash(&e.child)),
                _ => {}
            }
        }
        set
    }

    /// What a request must return under an unlimited budget, from the full tries `alloy_trie`
    /// builds: per lookup, the node at the path when it is a root or linked by hash, else an
    /// empty entry. It reads the request the way serving does: the first
    /// [`MAX_TRIE_NODE_LOOKUPS`] sets and lookups.
    fn expected_nodes(state: &FakeState, paths: &[Vec<Bytes>]) -> Vec<Bytes> {
        let served_by_path = |leaves: &[(B256, Vec<u8>)]| -> HashMap<Vec<u8>, Bytes> {
            all_nodes(leaves)
                .into_iter()
                .filter(|(p, n)| p.is_empty() || n.len() >= 32)
                .map(|(p, n)| (nibbles_of(&p), n))
                .collect()
        };
        let account = served_by_path(&state.account_trie_leaves());
        let mut storage: HashMap<B256, HashMap<Vec<u8>, Bytes>> = HashMap::new();
        let mut out = Vec::new();
        for set in paths.iter().take(MAX_TRIE_NODE_LOOKUPS) {
            let Some((first, rest)) = set.split_first() else { continue };
            let (trie, lookups) = if rest.is_empty() {
                (Some(&account), std::slice::from_ref(first))
            } else {
                let owner = (first.len() == 32).then(|| B256::from_slice(first));
                let trie = owner
                    .and_then(|o| state.accounts.get(&o).map(|a| (o, a)))
                    .filter(|(_, a)| !a.storage.is_empty())
                    .map(|(o, a)| {
                        &*storage
                            .entry(o)
                            .or_insert_with(|| served_by_path(&a.storage_trie_leaves()))
                    });
                (trie, rest)
            };
            for path in lookups {
                if out.len() == MAX_TRIE_NODE_LOOKUPS {
                    return out
                }
                let node = trie.and_then(|t| t.get(&compact_to_nibbles(path)));
                out.push(node.cloned().unwrap_or_default());
            }
        }
        out
    }

    struct Fixture {
        factory: FakeFactory,
        root: B256,
        state: FakeState,
    }

    fn fixture(accounts: u64, slots: u64) -> Fixture {
        let state = FakeState::generated(accounts, slots);
        let mut factory = FakeFactory::default();
        let root = factory.add(state.clone());
        Fixture { factory, root, state }
    }

    /// Checks every node of a trie against the response for its path. Callers serve with a clock
    /// that never runs out: the time budget has its own test, and a loaded CI runner can spend
    /// more than `MAX_TRIE_NODE_TIME` on one 200-path request.
    fn check_trie(
        root: B256,
        leaves: &[(B256, Vec<u8>)],
        serve: impl Fn(Vec<Bytes>) -> Vec<Bytes>,
    ) {
        let nodes = all_nodes(leaves);
        let links = linked_hashes(root, &nodes);
        let by_path: HashSet<Vec<u8>> = nodes.iter().map(|(p, _)| nibbles_of(p)).collect();
        let mut served = 0;
        for chunk in nodes.chunks(200) {
            let paths: Vec<Bytes> = chunk.iter().map(|(p, _)| compact(&nibbles_of(p))).collect();
            let got = serve(paths);
            assert_eq!(got.len(), chunk.len(), "positions preserved");
            for ((path, node), entry) in chunk.iter().zip(&got) {
                if path.is_empty() || node.len() >= 32 {
                    assert_eq!(entry, node, "node at {path:?}");
                    assert!(links.contains(&keccak256(entry)), "hash link at {path:?}");
                    served += 1;
                } else {
                    assert!(entry.is_empty(), "inline node at {path:?} must be empty");
                }
            }
        }
        assert!(served > 3);
        // A path one nibble below any position that holds no node is empty: it ends inside an
        // extension or leaf, or has no child.
        let mut probes = Vec::new();
        for (p, _) in nodes.iter().take(300) {
            for n in 0..16u8 {
                let mut q = nibbles_of(p);
                q.push(n);
                if !by_path.contains(&q) {
                    probes.push(compact(&q));
                }
            }
        }
        for chunk in probes.chunks(200) {
            assert!(serve(chunk.to_vec()).iter().all(|b| b.is_empty()));
        }
    }

    #[test]
    fn compact_paths_decode() {
        assert_eq!(compact_to_nibbles(&[]), Vec::<u8>::new());
        assert_eq!(compact_to_nibbles(&[0x00]), Vec::<u8>::new());
        assert_eq!(compact_to_nibbles(&[0x1a]), vec![0xa]);
        assert_eq!(compact_to_nibbles(&[0x00, 0xab, 0xcd]), vec![0xa, 0xb, 0xc, 0xd]);
        assert_eq!(compact_to_nibbles(&[0x3f, 0x12]), vec![0xf, 1, 2]);
        // The leaf flag is ignored.
        assert_eq!(compact_to_nibbles(&[0x20, 0x12]), vec![1, 2]);
        for len in 0..9u8 {
            let n: Vec<u8> = (0..len).map(|i| (i * 5 + 1) % 16).collect();
            assert_eq!(compact_to_nibbles(&compact(&n)), n);
        }
    }

    #[test]
    fn every_account_trie_node_is_served_and_hash_linked() {
        let fx = fixture(300, 0);
        let leaves = fx.state.account_trie_leaves();
        check_trie(fx.root, &leaves, |paths| {
            let paths = paths.into_iter().map(|p| vec![p]).collect();
            serve_trie_nodes_with_clock(&fx.factory, &req(fx.root, paths, 1 << 30), || {
                Duration::ZERO
            })
            .unwrap()
            .nodes
        });
    }

    #[test]
    fn every_deep_storage_trie_node_is_served_and_hash_linked() {
        let fx = fixture(11, 4000);
        let (owner, acct) =
            fx.state.accounts.iter().find(|(_, a)| a.storage.len() == 4000).unwrap();
        let leaves = acct.storage_trie_leaves();
        let sroot = acct.storage_root();
        check_trie(sroot, &leaves, |paths| {
            let mut set = vec![Bytes::copy_from_slice(owner.as_slice())];
            set.extend(paths);
            serve_trie_nodes_with_clock(&fx.factory, &req(fx.root, vec![set], 1 << 30), || {
                Duration::ZERO
            })
            .unwrap()
            .nodes
        });
    }

    /// SNAP1-DESIGN 4.1 item 4: one multiproof for keys with prefix `P` holds the node at `P`.
    #[test]
    fn multiproof_for_a_prefix_holds_the_node_at_that_prefix() {
        use reth_storage_api::StateRangeProvider;
        let fx = fixture(11, 1200);
        let (owner, acct) =
            fx.state.accounts.iter().find(|(_, a)| a.storage.len() == 1200).unwrap();
        let view = fx.factory.state_range_provider(fx.root).unwrap().unwrap();
        let storage_nodes = all_nodes(&acct.storage_trie_leaves());
        let account_nodes = all_nodes(&fx.state.account_trie_leaves());
        let mut checked = 0;
        let tagged =
            storage_nodes.iter().map(|n| (true, n)).chain(account_nodes.iter().map(|n| (false, n)));
        for (in_storage, (p, node)) in tagged.step_by(25) {
            if node.len() < 32 && !p.is_empty() {
                continue
            }
            let key = pad_to_key(&nibbles_of(p));
            let proof = if in_storage {
                view.storage_range_proof(*owner, &[key]).unwrap()
            } else {
                view.account_range_proof(&[key]).unwrap()
            };
            assert!(proof.contains(node), "multiproof lacks node at {p:?}");
            checked += 1;
        }
        assert!(checked > 40, "{checked}");
    }

    #[test]
    fn storage_set_with_missing_owner_keeps_positions() {
        let fx = fixture(20, 50);
        let paths = vec![vec![
            Bytes::copy_from_slice(keccak256("nobody").as_slice()),
            compact(&[]),
            compact(&[1]),
        ]];
        let resp = serve_trie_nodes(&fx.factory, &req(fx.root, paths, 1 << 20)).unwrap();
        assert_eq!(resp.nodes, vec![Bytes::new(), Bytes::new()]);
        assert_eq!(resp.request_id, 3);
    }

    #[test]
    fn unknown_root_answers_empty() {
        let fx = fixture(20, 0);
        let resp =
            serve_trie_nodes(&fx.factory, &req(keccak256("x"), vec![vec![compact(&[])]], 1 << 20))
                .unwrap();
        assert!(resp.nodes.is_empty());
    }

    #[test]
    fn lookups_are_capped() {
        let fx = fixture(20, 0);
        let paths = (0..1500).map(|_| vec![compact(&[])]).collect();
        let resp = serve_trie_nodes(&fx.factory, &req(fx.root, paths, 1 << 30)).unwrap();
        assert_eq!(resp.nodes.len(), MAX_TRIE_NODE_LOOKUPS);
    }

    #[test]
    fn a_set_with_a_bad_owner_and_a_huge_rest_is_capped() {
        let fx = fixture(20, 0);
        // The first element is not 32 bytes, so no path in the set can name a node.
        let mut set = vec![Bytes::from_static(&[0x01])];
        set.extend((0..MAX_TRIE_NODE_LOOKUPS * 4).map(|_| compact(&[])));
        let resp = serve_trie_nodes(&fx.factory, &req(fx.root, vec![set], 1 << 30)).unwrap();
        assert_eq!(resp.nodes.len(), MAX_TRIE_NODE_LOOKUPS);
    }

    #[test]
    fn bad_sets_and_good_sets_share_one_cap() {
        let fx = fixture(20, 0);
        let mut bad = vec![Bytes::from_static(&[0x01])];
        bad.extend((0..1000).map(|_| compact(&[])));
        let good: Vec<Vec<Bytes>> = (0..1000).map(|_| vec![compact(&[])]).collect();
        let paths = [vec![bad.clone()], good, vec![bad]].concat();
        let resp = serve_trie_nodes(&fx.factory, &req(fx.root, paths, 1 << 30)).unwrap();
        assert_eq!(resp.nodes.len(), MAX_TRIE_NODE_LOOKUPS);
        // The first 1000 entries are the bad set's placeholders, then the root node.
        assert!(resp.nodes[..1000].iter().all(|n| n.is_empty()));
        assert_eq!(keccak256(&resp.nodes[1000]), fx.root);
    }

    #[test]
    fn byte_budget_stops_after_the_crossing_entry() {
        let fx = fixture(300, 0);
        let paths: Vec<_> = (0..16u8).map(|n| vec![compact(&[n])]).collect();
        let all = serve_trie_nodes(&fx.factory, &req(fx.root, paths.clone(), 1 << 30)).unwrap();
        assert_eq!(all.nodes.len(), 16);
        let one = serve_trie_nodes(&fx.factory, &req(fx.root, paths.clone(), 1)).unwrap();
        assert_eq!(one.nodes.len(), 1, "an entry is always served");
        let some = serve_trie_nodes(&fx.factory, &req(fx.root, paths, 600)).unwrap();
        assert!(some.nodes.len() > 1 && some.nodes.len() < 16);
        assert!(some.nodes[..some.nodes.len() - 1].iter().map(|b| b.len()).sum::<usize>() <= 600);
    }

    #[test]
    fn time_limit_uses_the_injected_clock() {
        let fx = fixture(20, 0);
        let paths = (0..50).map(|_| vec![compact(&[])]).collect();
        let mut calls = 0;
        let resp = serve_trie_nodes_with_clock(&fx.factory, &req(fx.root, paths, 1 << 30), || {
            calls += 1;
            Duration::from_secs(calls - 1)
        })
        .unwrap();
        // Reads 0..=5 s are within the limit, the read of 6 s stops serving.
        assert_eq!(resp.nodes.len(), 6);
    }

    #[test]
    fn no_proof_is_built_once_a_storage_root_passes_the_time_limit() {
        use crate::test_utils::CountingFactory;
        use std::sync::atomic::Ordering;
        let state = FakeState::generated(60, 30);
        let owners: Vec<B256> = state
            .accounts
            .iter()
            .filter(|(_, a)| !a.storage.is_empty())
            .map(|(hash, _)| *hash)
            .collect();
        let mut factory = CountingFactory::default();
        let root = factory.inner.add(state);
        let paths = owners
            .iter()
            .map(|owner| vec![Bytes::copy_from_slice(owner.as_slice()), compact(&[])])
            .collect();
        let counts = factory.counts.clone();
        // The first storage root takes the request past the limit.
        let resp = serve_trie_nodes_with_clock(&factory, &req(root, paths, 1 << 30), || {
            if counts.storage_roots.load(Ordering::SeqCst) > 0 {
                MAX_TRIE_NODE_TIME + Duration::from_secs(1)
            } else {
                Duration::ZERO
            }
        })
        .unwrap();
        assert_eq!(factory.counts.storage_roots.load(Ordering::SeqCst), 1);
        assert_eq!(factory.counts.proofs.load(Ordering::SeqCst), 0, "no proof after the limit");
        assert!(resp.nodes.is_empty());
    }

    #[test]
    fn proofs_cover_only_the_entries_the_byte_budget_serves() {
        use crate::test_utils::CountingFactory;
        use std::sync::atomic::Ordering;
        let mut factory = CountingFactory::default();
        let root = factory.inner.add(FakeState::generated(300, 0));
        // The root node first, so the first entry crosses the budget, then 6-nibble paths.
        let paths: Vec<Vec<Bytes>> = std::iter::once(vec![compact(&[])])
            .chain((1..MAX_TRIE_NODE_LOOKUPS).map(|i| {
                let n: Vec<u8> = (0..6).map(|d| ((i >> (4 * d)) & 0xf) as u8).collect();
                vec![compact(&n)]
            }))
            .collect();
        let one = serve_trie_nodes(&factory, &req(root, paths.clone(), 1)).unwrap();
        assert_eq!(one.nodes.len(), 1);
        assert_eq!(factory.counts.proof_keys.load(Ordering::SeqCst), PROOF_BATCH);

        // A full budget proves every key once.
        factory.counts.proof_keys.store(0, Ordering::SeqCst);
        let all = serve_trie_nodes(&factory, &req(root, paths, 1 << 30)).unwrap();
        assert_eq!(all.nodes.len(), MAX_TRIE_NODE_LOOKUPS);
        assert_eq!(factory.counts.proof_keys.load(Ordering::SeqCst), MAX_TRIE_NODE_LOOKUPS);
    }

    #[test]
    fn tampered_node_fails_the_hash_check() {
        let fx = fixture(300, 0);
        let nodes = all_nodes(&fx.state.account_trie_leaves());
        let links = linked_hashes(fx.root, &nodes);
        let resp = serve_trie_nodes(&fx.factory, &req(fx.root, vec![vec![compact(&[])]], 1 << 20))
            .unwrap();
        assert!(links.contains(&keccak256(&resp.nodes[0])));
        for i in 0..resp.nodes[0].len() {
            let mut bad = resp.nodes[0].to_vec();
            bad[i] ^= 1;
            assert!(!links.contains(&keccak256(&bad)), "flip at {i} accepted");
        }
    }

    /// go-ethereum's heal requests mix account sets and the storage sets of many owners. Each
    /// owner's proof batch must take only its own paths, or the other owners' paths get no proof
    /// and answer empty.
    #[test]
    fn interleaved_owners_each_get_the_nodes_of_their_own_trie() {
        let fx = fixture(11, 1200);
        let tries: Vec<_> = std::iter::once((None, all_nodes(&fx.state.account_trie_leaves())))
            .chain(
                fx.state
                    .accounts
                    .iter()
                    .filter(|(_, a)| !a.storage.is_empty())
                    .map(|(owner, a)| (Some(*owner), all_nodes(&a.storage_trie_leaves()))),
            )
            .collect();
        assert_eq!(tries.len(), 3, "the account trie and two storage tries");
        let mut paths = Vec::new();
        for i in 0..3 * PROOF_BATCH {
            for (owner, nodes) in &tries {
                let path = compact(&nibbles_of(&nodes[i % nodes.len()].0));
                paths.push(match owner {
                    None => vec![path],
                    Some(owner) => vec![Bytes::copy_from_slice(owner.as_slice()), path],
                });
            }
        }
        let expected = expected_nodes(&fx.state, &paths);
        assert_eq!(expected.len(), 9 * PROOF_BATCH);
        assert!(expected.iter().filter(|n| !n.is_empty()).count() > 4 * PROOF_BATCH);
        let resp = serve_trie_nodes(&fx.factory, &req(fx.root, paths, 1 << 30)).unwrap();
        assert_eq!(resp.nodes, expected);
    }

    /// A path set: empty, one account path, or an owner with storage paths. The owner is a real
    /// account, an unknown hash or a malformed one.
    fn path_set(owners: Vec<B256>) -> impl proptest::strategy::Strategy<Value = Vec<Bytes>> {
        use proptest::prelude::*;
        let path = prop::collection::vec(0u8..16, 0..4).prop_map(|n| compact(&n));
        let owner = prop_oneof![
            prop::sample::select(owners).prop_map(|o| Bytes::copy_from_slice(o.as_slice())),
            Just(Bytes::copy_from_slice(keccak256("nobody").as_slice())),
            Just(Bytes::from_static(&[0x01])),
        ];
        prop_oneof![
            1 => Just(Vec::new()),
            8 => path.clone().prop_map(|p| vec![p]),
            2 => (owner.clone(), prop::collection::vec(path.clone(), 1..4))
                .prop_map(|(o, ps)| [vec![o], ps].concat()),
            1 => (owner, prop::collection::vec(path, 0..1200))
                .prop_map(|(o, ps)| [vec![o], ps].concat()),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Any path up to a full key decodes back from its compact form, with or without the
        /// leaf flag, and packs into a key that reads back as the path then zero nibbles.
        #[test]
        fn compact_paths_and_padded_keys_read_back(
            nibbles in proptest::collection::vec(0u8..16, 0..=64),
            leaf in proptest::bool::ANY,
        ) {
            let mut path = compact(&nibbles).to_vec();
            if leaf {
                path[0] |= 0x20;
            }
            proptest::prop_assert_eq!(compact_to_nibbles(&path), nibbles.as_slice());
            let key = Nibbles::unpack(pad_to_key(&nibbles));
            let mut expected = nibbles;
            expected.resize(64, 0);
            proptest::prop_assert_eq!(nibbles_of(&key), expected);
        }

        /// Any bytes decode to nibbles, two per byte after the first and one more when the odd
        /// flag is set.
        #[test]
        fn any_bytes_decode_to_nibbles(path in proptest::collection::vec(proptest::num::u8::ANY, 0..80)) {
            let nibbles = compact_to_nibbles(&path);
            let expected = path.first().map_or(0, |first| {
                (path.len() - 1) * 2 + usize::from(first & 0x10 != 0)
            });
            proptest::prop_assert_eq!(nibbles.len(), expected);
            proptest::prop_assert!(nibbles.iter().all(|n| *n < 16), "{:?}", nibbles);
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Every entry is the node the full trie holds at its path, for the sent request and for
        /// the one a peer decodes from it. Account and storage sets interleave, so one owner's
        /// proof batch must not take another owner's paths.
        #[test]
        fn every_entry_is_the_node_at_its_path(
            paths in proptest::collection::vec(
                path_set(fixture(20, 30).state.accounts.keys().copied().collect()),
                0..1300,
            )
        ) {
            let fx = fixture(20, 30);
            let sent = req(fx.root, paths, 1 << 30);
            let served = serve_trie_nodes(&fx.factory, &sent).unwrap();
            proptest::prop_assert_eq!(&served.nodes, &expected_nodes(&fx.state, &sent.paths));
            let crate::Snap1Message::GetTrieNodes(decoded) = crate::Snap1Message::decode(
                &crate::Snap1Message::GetTrieNodes(sent).encode().unwrap(),
            )
            .unwrap() else {
                panic!("not a GetTrieNodes")
            };
            proptest::prop_assert_eq!(serve_trie_nodes(&fx.factory, &decoded).unwrap(), served);
        }
    }
}
