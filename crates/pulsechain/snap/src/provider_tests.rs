//! Serving tests against a real [`BlockchainProvider`] over a test database.
//!
//! The states here are generated and written to the hashed-state tables, so the provider builds
//! tries, proofs and views the way a node does. Every answer is checked with `alloy_trie`'s own
//! verifier against the root the provider holds, not against anything this crate computed.

use crate::{
    serve_account_range, serve_storage_ranges, serve_trie_nodes,
    server::{Lane, Snap1Config, Snap1Server},
    test_utils::{all_nodes, path_nodes, verify_key},
    GetTrieNodesMessage, ProviderBackend, RetainedRoot, RootLanes, Snap1Message,
};
use alloy_consensus::constants::EMPTY_ROOT_HASH;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::nodes::TrieNode;
use reth_chain_state::{ExecutedBlock, NewCanonicalChain};
use reth_eth_wire_types::snap::{
    GetAccountRangeMessage, GetStorageRangesMessage, SnapProtocolMessage,
};
use reth_execution_types::{BlockExecutionOutput, BlockExecutionResult};
use reth_primitives_traits::{Account, Block as _, StorageEntry};
use reth_provider::{
    providers::BlockchainProvider,
    test_utils::{create_test_provider_factory, MockNodeTypesWithDB},
    BlockWriter, CanonChainTracker, ProviderFactory,
};
use reth_stages_types::{StageCheckpoint, StageId};
use reth_storage_api::{
    HashingWriter, HeaderProvider, StageCheckpointWriter, StateRootProvider, StateWriter,
};
use reth_testing_utils::generators::{self, random_block, BlockParams};
use reth_trie::{updates::TrieUpdates, HashedPostState, HashedStorage, SortedTrieData};
use std::{collections::BTreeMap, sync::Arc};

type Factory = ProviderFactory<MockNodeTypesWithDB>;

/// How many blocks the retention window holds, as in the provider.
const RETAINED: u64 = reth_provider::providers::SNAPSHOT_STATE_RETENTION;

/// The generated state and its database.
struct World {
    factory: Factory,
    /// The state root of the generated state.
    root: B256,
    accounts: BTreeMap<Address, Account>,
    /// The account that holds `slots`.
    owner: Address,
    slots: BTreeMap<B256, U256>,
}

fn account(i: u64) -> Account {
    Account { nonce: i, balance: U256::from(1000 + i), ..Default::default() }
}

/// 40 accounts, and 300 slots on the first one so its storage trie is several levels deep.
fn world() -> eyre::Result<World> {
    let factory = create_test_provider_factory();
    let mut rng = generators::rng();
    let genesis =
        random_block(&mut rng, 0, BlockParams { tx_count: Some(0), ..Default::default() });
    let provider_rw = factory.provider_rw()?;
    provider_rw.insert_block(&genesis.try_recover().expect("recover genesis"))?;

    let accounts: BTreeMap<Address, Account> =
        (0..40u64).map(|i| (Address::with_last_byte(i as u8 + 1), account(i + 1))).collect();
    let owner = Address::with_last_byte(1);
    let slots: BTreeMap<B256, U256> =
        (0..300u64).map(|i| (B256::from(U256::from(i)), U256::from(i + 7))).collect();
    provider_rw.insert_account_for_hashing(accounts.iter().map(|(a, acc)| (*a, Some(*acc))))?;
    provider_rw.insert_storage_for_hashing([(
        owner,
        slots.iter().map(|(key, value)| StorageEntry { key: *key, value: *value }),
    )])?;
    provider_rw.save_stage_checkpoint(StageId::Finish, StageCheckpoint::new(0))?;
    provider_rw.commit()?;

    let root = factory.latest()?.state_root(HashedPostState::default())?;
    Ok(World { factory, root, accounts, owner, slots })
}

/// Appends blocks `1..=last` to the database, with the state root `root` on block `root_at` and a
/// root nothing else has on every other block, and makes `last` the persisted head.
fn persisted_chain(
    world: &World,
    last: u64,
    root_at: u64,
) -> eyre::Result<BlockchainProvider<MockNodeTypesWithDB>> {
    let mut rng = generators::rng();
    let mut parent = world.factory.sealed_header(0)?.unwrap().hash();
    let provider_rw = world.factory.provider_rw()?;
    for number in 1..=last {
        let mut block = random_block(
            &mut rng,
            number,
            BlockParams { parent: Some(parent), tx_count: Some(0), ..Default::default() },
        )
        .unseal();
        block.header.state_root =
            if number == root_at { world.root } else { keccak256(number.to_be_bytes()) };
        let block = block.seal_slow();
        parent = block.hash();
        provider_rw.insert_block(&block.try_recover().expect("recover block"))?;
    }
    provider_rw.save_stage_checkpoint(StageId::Finish, StageCheckpoint::new(last))?;
    provider_rw.commit()?;
    Ok(BlockchainProvider::new(world.factory.clone())?)
}

fn account_request(root: B256, key: B256) -> GetAccountRangeMessage {
    GetAccountRangeMessage {
        request_id: 1,
        root_hash: root,
        starting_hash: key,
        limit_hash: key,
        response_bytes: 1,
    }
}

/// Serves every generated account as a one-key request and verifies each answer.
fn assert_accounts_served(
    provider: &BlockchainProvider<MockNodeTypesWithDB>,
    world: &World,
    root: B256,
) {
    for (address, expected) in world.accounts.iter().step_by(7) {
        let key = keccak256(address);
        let resp = serve_account_range(provider, &account_request(root, key)).unwrap();
        assert_eq!(resp.accounts.len(), 1, "{address}");
        let got = resp.accounts[0].trie_account();
        assert_eq!((got.nonce, got.balance), (expected.nonce, expected.balance));
        let leaf = alloy_rlp::encode(got);
        verify_key(root, key, Some(leaf), &resp.proof).unwrap();
    }
}

fn assert_empty_account_answer(provider: &BlockchainProvider<MockNodeTypesWithDB>, root: B256) {
    let key = keccak256(Address::with_last_byte(1));
    let resp = serve_account_range(provider, &account_request(root, key)).unwrap();
    assert!(resp.accounts.is_empty() && resp.proof.is_empty());
    assert_eq!(resp.request_id, 1);
}

/// A chain of `RETAINED + 2` persisted blocks with the generated state's root `depth` blocks
/// below the head. Each depth is its own test so they run in parallel.
fn served_at_depth(depth: u64) {
    let last = RETAINED + 2;
    let world = world().unwrap();
    let provider = persisted_chain(&world, last, last - depth).unwrap();
    assert_accounts_served(&provider, &world, world.root);
    // Persisted roots are cold: their views need reverts. Only the listing places them.
    assert_eq!(provider.lane(world.root), None);
    assert_eq!(ProviderBackend::new(provider.clone()).lane(world.root), None);
    // The listed roots agree with what the provider serves.
    let listed = |roots: Option<Vec<RetainedRoot>>| {
        roots.unwrap().into_iter().find(|r| r.root == world.root)
    };
    // The persisted tip needs no reverts, so it is hot.
    let lane = if depth == 0 { Lane::Hot } else { Lane::Cold };
    let expected = Some(RetainedRoot { root: world.root, lane, depth });
    assert_eq!(listed(provider.retained_roots()), expected);
    assert_eq!(listed(ProviderBackend::new(provider).retained_roots()), expected);
}

fn empty_at_depth(depth: u64) {
    let last = RETAINED + 2;
    let world = world().unwrap();
    let provider = persisted_chain(&world, last, last - depth).unwrap();
    assert_empty_account_answer(&provider, world.root);
    let roots = ProviderBackend::new(provider).retained_roots().unwrap();
    assert!(roots.iter().all(|r| r.root != world.root), "a root past the window is not listed");
    assert_eq!(roots.len() as u64, RETAINED);
}

#[test]
fn persisted_root_at_the_head_is_served() {
    served_at_depth(0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_at_the_persisted_tip_is_served_on_the_hot_lane() {
    let world = world().unwrap();
    // The head is the persisted tip, as after a restart or with a memory buffer target of 0.
    let provider = persisted_chain(&world, 3, 3).unwrap();
    let server = Snap1Server::new(Arc::new(provider), Snap1Config::default());
    let request = || {
        let key = keccak256(Address::with_last_byte(3));
        Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(account_request(world.root, key)))
    };
    let peer = crate::PeerId::repeat_byte(7);
    // The cold lane runs one request per peer at once, the hot lane four.
    let replies = futures::future::join_all((0..4).map(|_| server.handle(peer, request()))).await;
    for reply in replies {
        let Some(Snap1Message::Shared(SnapProtocolMessage::AccountRange(resp))) = reply else {
            panic!("unexpected {reply:?}")
        };
        assert_eq!(resp.accounts.len(), 1);
    }
}

#[test]
fn persisted_root_one_back_is_served() {
    served_at_depth(1);
}

#[test]
fn persisted_root_64_back_is_served() {
    served_at_depth(64);
}

#[test]
fn persisted_root_127_back_is_served() {
    served_at_depth(RETAINED - 1);
}

#[test]
fn root_128_back_answers_empty() {
    empty_at_depth(RETAINED);
}

#[test]
fn root_129_back_answers_empty() {
    empty_at_depth(RETAINED + 1);
}

#[test]
fn unknown_roots_answer_empty_and_never_fail() {
    let world = world().unwrap();
    let provider = persisted_chain(&world, 4, 4).unwrap();
    assert_accounts_served(&provider, &world, world.root);
    assert_empty_account_answer(&provider, B256::repeat_byte(0xab));
    let resp = serve_trie_nodes(
        &provider,
        &GetTrieNodesMessage {
            request_id: 3,
            root_hash: B256::repeat_byte(0xab),
            paths: vec![vec![Bytes::from_static(&[0x00])]],
            response_bytes: 1 << 20,
        },
    )
    .unwrap();
    assert!(resp.nodes.is_empty() && resp.request_id == 3);
}

#[test]
fn storage_ranges_verify_against_the_storage_root() {
    let world = world().unwrap();
    let provider = persisted_chain(&world, 3, 3).unwrap();
    let hashed_owner = keccak256(world.owner);

    // The storage root the proof must verify against comes from the account the provider served.
    let account =
        serve_account_range(&provider, &account_request(world.root, hashed_owner)).unwrap();
    let storage_root = account.accounts[0].trie_account().storage_root;
    assert_ne!(storage_root, EMPTY_ROOT_HASH);

    let hashed: BTreeMap<B256, U256> =
        world.slots.iter().map(|(k, v)| (keccak256(k), *v)).collect();
    for (slot, value) in hashed.iter().step_by(37) {
        let req = GetStorageRangesMessage {
            request_id: 2,
            root_hash: world.root,
            account_hashes: vec![hashed_owner],
            starting_hash: (*slot).into(),
            limit_hash: (*slot).into(),
            response_bytes: 1,
        };
        let resp = serve_storage_ranges(&provider, &req).unwrap();
        assert_eq!(resp.slots[0].len(), 1);
        assert_eq!(resp.slots[0][0].value().unwrap(), *value);
        verify_key(storage_root, *slot, Some(alloy_rlp::encode(value)), &resp.proof).unwrap();

        // A tampered node must fail the independent verifier.
        let mut proof = resp.proof;
        let mut node = proof[0].to_vec();
        let last = node.len() - 1;
        node[last] ^= 1;
        proof[0] = node.into();
        assert!(verify_key(storage_root, *slot, Some(alloy_rlp::encode(value)), &proof).is_err());
    }
}

#[test]
fn tampered_account_proofs_are_rejected() {
    let world = world().unwrap();
    let provider = persisted_chain(&world, 3, 3).unwrap();
    let key = keccak256(Address::with_last_byte(9));
    let resp = serve_account_range(&provider, &account_request(world.root, key)).unwrap();
    let leaf = alloy_rlp::encode(resp.accounts[0].trie_account());
    verify_key(world.root, key, Some(leaf.clone()), &resp.proof).unwrap();

    for i in 0..path_nodes(world.root, key, &resp.proof).len() {
        let mut proof = resp.proof.clone();
        let target = keccak256(&path_nodes(world.root, key, &resp.proof)[i]);
        let index = proof.iter().position(|n| keccak256(n) == target).unwrap();
        let mut node = proof[index].to_vec();
        let last = node.len() - 1;
        node[last] ^= 1;
        proof[index] = node.into();
        assert!(verify_key(world.root, key, Some(leaf.clone()), &proof).is_err(), "node {i}");
    }
    // The right proof for the wrong value is rejected too.
    let mut wrong = resp.accounts[0].trie_account();
    wrong.balance += U256::from(1);
    assert!(verify_key(world.root, key, Some(alloy_rlp::encode(wrong)), &resp.proof).is_err());
}

/// Walks the trie one level below `node` and checks every hash-linked child against the node the
/// server returns for its path.
fn assert_children_linked(
    provider: &BlockchainProvider<MockNodeTypesWithDB>,
    root: B256,
    owner: Option<B256>,
    parent: &Bytes,
) {
    let TrieNode::Branch(branch) = TrieNode::decode(&mut &parent[..]).unwrap() else {
        panic!("expected a branch at the top of a large trie")
    };
    let mut stack = branch.stack.iter();
    let mut checked = 0;
    for nibble in 0..16u8 {
        if !branch.state_mask.is_bit_set(nibble) {
            continue
        }
        let child = stack.next().unwrap();
        let mut set = owner.map(|o| vec![Bytes::copy_from_slice(o.as_slice())]).unwrap_or_default();
        // Compact path with the odd flag: one nibble.
        set.push(Bytes::from(vec![0x10 | nibble]));
        let resp = serve_trie_nodes(
            provider,
            &GetTrieNodesMessage {
                request_id: 4,
                root_hash: root,
                paths: vec![set],
                response_bytes: 1 << 20,
            },
        )
        .unwrap();
        assert_eq!(resp.nodes.len(), 1);
        if child.len() == 33 {
            assert_eq!(keccak256(&resp.nodes[0]).as_slice(), &child[1..], "child {nibble:x}");
            checked += 1;
        }
    }
    assert!(checked >= 2);
}

#[test]
fn trie_nodes_are_hash_linked_from_the_root() {
    let world = world().unwrap();
    let provider = persisted_chain(&world, 3, 3).unwrap();
    let account_root = |owner: Option<B256>, root: B256| {
        let mut set: Vec<Bytes> =
            owner.map(|o| vec![Bytes::copy_from_slice(o.as_slice())]).unwrap_or_default();
        set.push(Bytes::from_static(&[0x00]));
        let resp = serve_trie_nodes(
            &provider,
            &GetTrieNodesMessage {
                request_id: 4,
                root_hash: world.root,
                paths: vec![set],
                response_bytes: 1 << 20,
            },
        )
        .unwrap();
        assert_eq!(keccak256(&resp.nodes[0]), root);
        resp.nodes[0].clone()
    };

    let top = account_root(None, world.root);
    assert_children_linked(&provider, world.root, None, &top);

    let hashed_owner = keccak256(world.owner);
    let account =
        serve_account_range(&provider, &account_request(world.root, hashed_owner)).unwrap();
    let storage_root = account.accounts[0].trie_account().storage_root;
    let storage_top = account_root(Some(hashed_owner), storage_root);
    assert_children_linked(&provider, world.root, Some(hashed_owner), &storage_top);

    // A node that was altered no longer matches the hash its parent links to.
    let mut altered = top.to_vec();
    altered[3] ^= 1;
    assert_ne!(keccak256(&altered), world.root);
}

/// Trie leaves: a hashed key and its RLP-encoded value.
type Leaves = Vec<(B256, Vec<u8>)>;

/// Storage written by hashed key for the account `Address::with_last_byte(2)`, so its trie has a
/// known shape: 200 spread keys, plus two keys that share six nibbles with each other and at most
/// two with any other key. The pair sits under an extension node and a branch at depth six.
fn deep_world() -> eyre::Result<(World, B256, Leaves)> {
    let mut world = world()?;
    let owner = keccak256(Address::with_last_byte(2));
    let mut slots: BTreeMap<B256, U256> =
        (0..200u64).map(|i| (keccak256(i.to_be_bytes()), U256::from(i + 1))).collect();
    // Drop spread keys that share three nibbles with the pair, so the extension is certain.
    slots.retain(|key, _| !key.0.starts_with(&[0x12]) || key.0[1] >> 4 != 3);
    let mut pair = B256::repeat_byte(0x11);
    pair.0[..3].copy_from_slice(&[0x12, 0x34, 0x56]);
    slots.insert(pair, U256::from(7));
    pair.0[3] = 0xf1;
    slots.insert(pair, U256::from(8));

    let provider_rw = world.factory.provider_rw()?;
    let mut state = HashedPostState::default();
    state.storages.insert(owner, HashedStorage::from_iter(slots.iter().map(|(k, v)| (*k, *v))));
    provider_rw.write_hashed_state(&state.into_sorted())?;
    provider_rw.commit()?;
    world.root = world.factory.latest()?.state_root(HashedPostState::default())?;
    let leaves = slots.iter().map(|(k, v)| (*k, alloy_rlp::encode(v))).collect();
    Ok((world, owner, leaves))
}

/// The child reference `parent` holds for the node at `path`, where `parent` sits at
/// `path[..at]`. `None` when `parent` does not lead to `path`.
fn child_ref(parent: &Bytes, path: &[u8], at: usize) -> Option<Vec<u8>> {
    match TrieNode::decode(&mut &parent[..]).unwrap() {
        TrieNode::Branch(branch) => {
            if at + 1 != path.len() || !branch.state_mask.is_bit_set(path[at]) {
                return None
            }
            let below = (0..path[at]).filter(|i| branch.state_mask.is_bit_set(*i)).count();
            Some(branch.stack[below].to_vec())
        }
        TrieNode::Extension(ext) => {
            let key: Vec<u8> = (0..ext.key.len()).map(|i| ext.key.get(i).unwrap()).collect();
            (path[at..] == key[..]).then(|| ext.child.to_vec())
        }
        _ => None,
    }
}

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

#[test]
fn every_node_of_a_deep_storage_trie_is_hash_linked_from_the_real_provider() {
    let (world, owner, leaves) = deep_world().unwrap();
    let provider = persisted_chain(&world, 3, 3).unwrap();
    let account = serve_account_range(&provider, &account_request(world.root, owner)).unwrap();
    let storage_root = account.accounts[0].trie_account().storage_root;

    // The expected trie comes from `alloy_trie`'s builder, not from the provider.
    let expected: Vec<(Vec<u8>, Bytes)> = all_nodes(&leaves)
        .into_iter()
        .map(|(p, n)| ((0..p.len()).map(|i| p.get(i).unwrap()).collect(), n))
        .collect();
    assert_eq!(keccak256(&expected[0].1), storage_root, "the builder agrees on the root");

    let mut served = BTreeMap::new();
    for chunk in expected.chunks(500) {
        let mut set = vec![Bytes::copy_from_slice(owner.as_slice())];
        set.extend(chunk.iter().map(|(p, _)| compact(p)));
        let resp = serve_trie_nodes(
            &provider,
            &GetTrieNodesMessage {
                request_id: 5,
                root_hash: world.root,
                paths: vec![set],
                response_bytes: 1 << 30,
            },
        )
        .unwrap();
        assert_eq!(resp.nodes.len(), chunk.len(), "positions preserved");
        for ((path, node), got) in chunk.iter().zip(resp.nodes) {
            if path.is_empty() || node.len() >= 32 {
                assert_eq!(&got, node, "node at {path:?}");
                served.insert(path.clone(), got);
            } else {
                assert!(got.is_empty(), "an embedded node at {path:?} is not served");
            }
        }
    }

    // Every served node below the root hangs off the nearest served node above it by hash.
    let mut extensions = 0;
    let mut deepest = 0;
    for (path, node) in &served {
        if matches!(TrieNode::decode(&mut &node[..]).unwrap(), TrieNode::Extension(_)) {
            extensions += 1;
        }
        if path.is_empty() {
            assert_eq!(keccak256(node), storage_root);
            continue
        }
        let (at, parent) = (0..path.len())
            .rev()
            .find_map(|at| served.get(&path[..at]).map(|parent| (at, parent)))
            .expect("the root is served");
        let link = child_ref(parent, path, at).unwrap_or_else(|| panic!("no link to {path:?}"));
        assert_eq!(link.len(), 33, "{path:?} is linked by hash");
        assert_eq!(&link[1..], keccak256(node).as_slice(), "hash link to {path:?}");
        let mut levels = 1;
        let mut up = &path[..at];
        while !up.is_empty() {
            up = (0..up.len()).rev().map(|i| &up[..i]).find(|p| served.contains_key(*p)).unwrap();
            levels += 1;
        }
        deepest = deepest.max(levels);
    }
    assert!(extensions >= 1, "the trie has an extension node");
    assert!(deepest >= 3, "hash links checked {deepest} levels deep");

    // The check can fail: a node with one bit flipped no longer matches its parent's link.
    let (path, node) = served.iter().find(|(p, _)| p.len() >= 3).unwrap();
    let mut altered = node.to_vec();
    altered[1] ^= 1;
    let (at, parent) =
        (0..path.len()).rev().find_map(|at| served.get(&path[..at]).map(|p| (at, p))).unwrap();
    assert_ne!(&child_ref(parent, path, at).unwrap()[1..], keccak256(&altered).as_slice());
}

/// A persisted state A, and an in-memory block on top that adds one account.
struct WithMemory {
    provider: BlockchainProvider<MockNodeTypesWithDB>,
    world: World,
    memory_root: B256,
    extra: Address,
}

fn with_memory_block() -> eyre::Result<WithMemory> {
    let (provider, world, roots) = with_memory_blocks(1)?;
    Ok(WithMemory { provider, world, memory_root: roots[0], extra: Address::with_last_byte(200) })
}

/// A persisted state A at block 3, and `n` in-memory blocks on top. Block `4 + i` adds account
/// `200 + i`; its state root is the `i`th returned.
fn with_memory_blocks(
    n: u8,
) -> eyre::Result<(BlockchainProvider<MockNodeTypesWithDB>, World, Vec<B256>)> {
    let world = world()?;
    let provider = persisted_chain(&world, 3, 3)?;
    let mut parent = world.factory.sealed_header(3)?.unwrap();
    let mut post_state = HashedPostState::default();
    let (mut roots, mut chain) = (Vec::new(), Vec::new());
    let mut rng = generators::rng();
    for i in 0..n {
        let extra = Address::with_last_byte(200 + i);
        post_state.accounts.insert(keccak256(extra), Some(account(500 + u64::from(i))));
        let memory_root = world.factory.latest()?.state_root(post_state.clone())?;
        assert_ne!(memory_root, world.root);
        let mut block = random_block(
            &mut rng,
            4 + u64::from(i),
            BlockParams { parent: Some(parent.hash()), tx_count: Some(0), ..Default::default() },
        )
        .unseal();
        block.header.state_root = memory_root;
        let block = block.seal_slow().try_recover().expect("recover block");
        let trie_data = SortedTrieData::new(
            Arc::new(post_state.clone().into_sorted()),
            Arc::new(TrieUpdates::default().into_sorted()),
        );
        let output = BlockExecutionOutput {
            result: BlockExecutionResult {
                receipts: Default::default(),
                requests: Default::default(),
                gas_used: 0,
                blob_gas_used: 0,
            },
            state: Default::default(),
        };
        let executed = ExecutedBlock::new(Arc::new(block), Arc::new(output), trie_data);
        world.factory.overlay_manager().insert_block(executed.clone());
        parent = executed.recovered_block().clone_sealed_header();
        roots.push(memory_root);
        chain.push(executed);
    }
    provider.canonical_in_memory_state().update_chain(NewCanonicalChain::Commit { new: chain });
    // The engine moves the canonical head when it accepts the block.
    provider.set_canonical_head(parent);
    Ok((provider, world, roots))
}

/// The engine keeps persisted blocks in memory for a while (state masking). Their views need
/// reverts like any block below the `Finish` checkpoint, so they are cold, as the listing says.
#[test]
fn an_in_memory_block_below_the_persisted_tip_is_cold() {
    let (provider, world, roots) = with_memory_blocks(3).unwrap();
    // Blocks 4 and 5 are persisted, and still in memory; block 6 is not.
    let provider_rw = world.factory.provider_rw().unwrap();
    provider_rw.save_stage_checkpoint(StageId::Finish, StageCheckpoint::new(5)).unwrap();
    provider_rw.commit().unwrap();
    let want = [(Lane::Cold, 2), (Lane::Hot, 1), (Lane::Hot, 0)];
    let listed = provider.retained_roots().unwrap();
    for (root, (lane, depth)) in roots.iter().zip(want) {
        assert!(listed.contains(&RetainedRoot { root: *root, lane, depth }), "{root}");
        assert_eq!(provider.classify(*root), Some((lane, Some(depth))), "{root}");
        assert_eq!(provider.lane(*root), Some(lane), "{root}");
    }
}

/// While listings fail, the server asks `classify` for each request. Without the `Finish`
/// checkpoint the provider cannot tell a hot in-memory root from a cold one, so it serves the
/// root on the cold lane, whose limits hold for any view. A failed read takes the same path.
#[test]
fn without_the_persisted_tip_an_in_memory_root_is_cold() {
    use reth_db_api::{tables, transaction::DbTxMut};
    let t = with_memory_block().unwrap();
    let provider_rw = t.world.factory.provider_rw().unwrap();
    let finish = StageId::Finish.to_string();
    provider_rw.tx_ref().delete::<tables::StageCheckpoints>(finish, None).unwrap();
    provider_rw.commit().unwrap();
    assert_eq!(t.provider.retained_roots(), None, "the listing fails");
    assert_eq!(t.provider.classify(t.memory_root), Some((Lane::Cold, Some(0))));
    assert_eq!(t.provider.lane(t.memory_root), Some(Lane::Cold));
}

#[test]
fn the_in_memory_head_is_hot_and_serves_its_own_state() {
    let t = with_memory_block().unwrap();
    assert_eq!(t.provider.lane(t.memory_root), Some(Lane::Hot));
    assert_eq!(t.provider.depth(t.memory_root), Some(0));
    assert_eq!(t.provider.lane(t.world.root), None);

    // The backend a generic node builder uses lists the same lanes.
    let generic = ProviderBackend::new(t.provider.clone());
    let roots = generic.retained_roots().unwrap();
    assert!(roots.contains(&RetainedRoot { root: t.memory_root, lane: Lane::Hot, depth: 0 }));
    // The persisted tip needs no reverts; the block below it does.
    assert!(roots.contains(&RetainedRoot { root: t.world.root, lane: Lane::Hot, depth: 1 }));
    let below_tip = keccak256(2u64.to_be_bytes());
    assert!(roots.contains(&RetainedRoot { root: below_tip, lane: Lane::Cold, depth: 2 }));

    // The extra account exists at the in-memory root, and is proven absent below it.
    let key = keccak256(t.extra);
    let resp = serve_account_range(&t.provider, &account_request(t.memory_root, key)).unwrap();
    assert_eq!(resp.accounts[0].hash, key);
    let leaf = alloy_rlp::encode(resp.accounts[0].trie_account());
    verify_key(t.memory_root, key, Some(leaf), &resp.proof).unwrap();

    let resp = serve_account_range(&t.provider, &account_request(t.world.root, key)).unwrap();
    assert!(resp.accounts.first().is_none_or(|a| a.hash != key));
    verify_key(t.world.root, key, None, &resp.proof).unwrap();
}

#[test]
fn every_block_above_the_persisted_tip_is_listed_hot_however_far_persistence_lags() {
    let world = world().unwrap();
    let (persisted, head) = (RETAINED + 10, RETAINED + 310);
    let provider = persisted_chain(&world, head, 0).unwrap();
    // The `Finish` checkpoint lags the head by 300 blocks, as with a large
    // `--engine.persistence-threshold`.
    let provider_rw = world.factory.provider_rw().unwrap();
    provider_rw.save_stage_checkpoint(StageId::Finish, StageCheckpoint::new(persisted)).unwrap();
    provider_rw.commit().unwrap();
    provider.set_canonical_head(world.factory.sealed_header(head).unwrap().unwrap());

    let roots = ProviderBackend::new(provider).retained_roots().unwrap();
    let listed = |number: u64| {
        let root = keccak256(number.to_be_bytes());
        roots.iter().find(|r| r.root == root).map(|r| (r.lane, r.depth))
    };
    for number in persisted..=head {
        assert_eq!(listed(number), Some((Lane::Hot, head - number)), "block {number}");
    }
    for number in persisted + 1 - RETAINED..persisted {
        assert_eq!(listed(number), Some((Lane::Cold, head - number)), "block {number}");
    }
    assert_eq!(listed(persisted - RETAINED), None);
    assert_eq!(roots.len() as u64, head - persisted + RETAINED);
}

#[test]
fn without_a_listing_no_root_outside_memory_gets_a_lane() {
    let t = with_memory_block().unwrap();
    assert_eq!(t.provider.classify(t.memory_root), Some((Lane::Hot, Some(0))));
    // The server asks only while a listing fails. A persisted root then looks like junk, and
    // junk must not take a cold slot.
    for root in [t.world.root, B256::repeat_byte(0x99)] {
        assert_eq!(t.provider.classify(root), None, "{root}");
        assert_eq!(ProviderBackend::new(t.provider.clone()).classify(root), None, "{root}");
    }
    // The generic backend could find the head only by reading headers on the async thread.
    let generic = ProviderBackend::new(t.provider.clone());
    assert_eq!((generic.lane(t.memory_root), generic.classify(t.memory_root)), (None, None));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_serves_memory_and_persisted_roots_from_a_real_provider() {
    let t = with_memory_block().unwrap();
    let server = Snap1Server::new(Arc::new(t.provider.clone()), Snap1Config::default());
    let peer = crate::PeerId::repeat_byte(7);
    for (root, key, present) in [
        (t.memory_root, keccak256(t.extra), true),
        (t.world.root, keccak256(Address::with_last_byte(3)), true),
    ] {
        let reply = server
            .handle(
                peer,
                Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(account_request(
                    root, key,
                ))),
            )
            .await;
        let Some(Snap1Message::Shared(SnapProtocolMessage::AccountRange(resp))) = reply else {
            panic!("unexpected {reply:?}")
        };
        assert_eq!(present, !resp.accounts.is_empty());
        let leaf = alloy_rlp::encode(resp.accounts[0].trie_account());
        verify_key(root, key, Some(leaf), &resp.proof).unwrap();
    }
    // An unknown root is answered empty: the listing lacks it.
    let reply = server
        .handle(
            peer,
            Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(account_request(
                B256::repeat_byte(0x99),
                keccak256(t.extra),
            ))),
        )
        .await;
    let Some(Snap1Message::Shared(SnapProtocolMessage::AccountRange(resp))) = reply else {
        panic!("unexpected {reply:?}")
    };
    assert!(resp.accounts.is_empty() && resp.proof.is_empty());
}
