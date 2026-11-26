//! Structured `snap/1` requests against a small in-memory state with real trie proofs.
//!
//! The input builds a state (accounts, storage, code) and a few requests with arbitrary roots,
//! origins, limits, path sets and byte budgets. Each reply is checked against the state:
//!
//! - A reply body never exceeds the request's reply budget plus `REPLY_SLACK`, and the items before
//!   the last one fit in the serving budget. Item caps hold.
//! - Ranges are the contiguous run of the state from the origin. A range that is not the whole trie
//!   from the zero origin carries a proof, and the proof verifies the origin and the last key
//!   against the root. The verifier rejects the proof's path with any one byte changed.
//! - Trie nodes are the nodes at exactly the requested paths, empty where no hashed node sits.
//!   Serving the decoded wire request gives the same reply as serving the request in full.
//! - Byte codes are the known codes in request order, unknown hashes skipped.
//!
//! The time limits read a clock that never advances, so a reply stops only at a byte budget.

#![no_main]

use alloy_primitives::{keccak256, Address, Bytes, B256, KECCAK256_EMPTY, U256};
use alloy_rlp::Encodable;
use alloy_trie::EMPTY_ROOT_HASH;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use reth_eth_wire_types::snap::{
    AccountData, GetAccountRangeMessage, GetByteCodesMessage, GetStorageRangesMessage,
    SnapProtocolMessage, StorageData,
};
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_pulsechain_snap::{
    compact_to_nibbles,
    fuzz_api::{
        path_nodes, reply_budget, serve_account_range_with_clock, verify_key, verify_path, Account,
        FuzzFactory, FuzzState,
    },
    protocol::REPLY_SLACK,
    serve_byte_codes, serve_storage_ranges, serve_trie_nodes_with_clock, GetTrieNodesMessage,
    Snap1Message, TrieNodePathSet, MAX_BYTE_CODES_SERVE, MAX_STORAGE_RANGE_ACCOUNTS_SERVE,
    MAX_TRIE_NODE_LOOKUPS, PROOF_RESERVE, SOFT_RESPONSE_LIMIT,
};
use std::{collections::HashMap, time::Duration};

const MAX_ACCOUNTS: usize = 48;
const MAX_SLOTS: usize = 48;
const MAX_REQUESTS: usize = 4;

/// The most path elements one `GetTrieNodes` request is built with: four times the lookup cap.
const MAX_PATH_ELEMENTS: usize = 4 * MAX_TRIE_NODE_LOOKUPS;

/// The bytes the in-memory provider counts for one account.
const PROVIDER_ACCOUNT_BYTES: usize = 32 + 4 * 32;

/// A trie key. The short forms make keys that share long prefixes, so tries get extensions.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Key {
    Full([u8; 32]),
    Head(u8, u8),
    Tail(u16, u8),
}

impl Key {
    fn hash(self) -> B256 {
        let mut key = B256::ZERO;
        match self {
            Self::Full(bytes) => key = B256::from(bytes),
            Self::Head(a, b) => (key.0[0], key.0[1]) = (a, b),
            Self::Tail(prefix, tail) => {
                key.0[..2].copy_from_slice(&prefix.to_be_bytes());
                key.0[31] = tail;
            }
        }
        key
    }
}

#[derive(Arbitrary, Debug)]
enum Value {
    Small(u8),
    Full([u8; 32]),
}

impl Value {
    fn get(&self) -> U256 {
        match self {
            Self::Small(v) => U256::from(*v),
            Self::Full(b) => U256::from_be_bytes(*b),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Code {
    None,
    Raw(Vec<u8>),
    Delegation([u8; 20]),
}

impl Code {
    fn bytes(&self) -> Option<Bytes> {
        match self {
            Self::None => None,
            // The mock stores code as a `Bytecode`, which rejects a malformed EIP-7702 designator.
            Self::Raw(code) if code.starts_with(&[0xef, 0x01]) => None,
            Self::Raw(code) => Some(code.clone().into()),
            Self::Delegation(addr) => Some([&[0xef, 0x01, 0x00][..], addr].concat().into()),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct AccountSpec {
    key: Key,
    nonce: u64,
    balance: u128,
    code: Code,
    slots: Vec<(Key, Value)>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Root {
    Served,
    Empty,
    Other([u8; 32]),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Step {
    At,
    Above,
    Below,
}

/// A range bound: an end of the key space, near a key the state has, or any key.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Bound {
    Zero,
    Max,
    Near(u8, Step),
    Raw(Key),
}

impl Bound {
    fn resolve(self, keys: &[B256]) -> B256 {
        match self {
            Self::Zero => B256::ZERO,
            Self::Max => B256::repeat_byte(0xff),
            Self::Raw(key) => key.hash(),
            Self::Near(_, _) if keys.is_empty() => B256::ZERO,
            Self::Near(i, step) => {
                let key = U256::from_be_bytes(keys[i as usize % keys.len()].0);
                let key = match step {
                    Step::At => key,
                    Step::Above => key.wrapping_add(U256::from(1)),
                    Step::Below => key.wrapping_sub(U256::from(1)),
                };
                B256::from(key.to_be_bytes())
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Budget {
    Zero,
    Small(u16),
    Large(u32),
    Huge(u64),
}

impl Budget {
    const fn bytes(self) -> u64 {
        match self {
            Self::Zero => 0,
            Self::Small(n) => n as u64,
            Self::Large(n) => n as u64,
            Self::Huge(n) => n,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum AccountRef {
    Known(u8),
    Raw(Key),
}

/// A trie path: a node the trie has, a prefix of a key it has, or any bytes.
#[derive(Arbitrary, Debug)]
enum PathSpec {
    Node(u16, bool),
    KeyPrefix(u8, u8, bool),
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum SetSpec {
    Empty,
    Account(PathSpec),
    Storage(AccountRef, Vec<PathSpec>),
    BadOwner(Vec<u8>, Vec<PathSpec>),
    /// One storage path many times, to cross the lookup cap.
    Many(AccountRef, PathSpec, u16),
}

#[derive(Arbitrary, Debug)]
enum CodeRef {
    Known(u8),
    Empty,
    Raw([u8; 32]),
}

#[derive(Arbitrary, Debug)]
enum Request {
    AccountRange {
        root: Root,
        origin: Bound,
        limit: Bound,
        budget: Budget,
    },
    StorageRanges {
        root: Root,
        accounts: Vec<AccountRef>,
        origin: Option<Bound>,
        limit: Option<Bound>,
        budget: Budget,
    },
    TrieNodes {
        root: Root,
        sets: Vec<SetSpec>,
        /// Copies of the last set to append, to cross the set cap.
        repeat_last: u16,
        budget: Budget,
    },
    ByteCodes {
        hashes: Vec<CodeRef>,
        budget: Budget,
    },
}

/// Which proof byte to change: node index, byte index, and the xor mask.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct Mutation(u16, u16, u8);

#[derive(Arbitrary, Debug)]
struct Input {
    accounts: Vec<AccountSpec>,
    requests: Vec<Request>,
    mutation: Mutation,
}

struct World {
    state: FuzzState,
    factory: FuzzFactory,
    root: B256,
    accounts: Vec<B256>,
    codes: Vec<Bytes>,
    mutation: Mutation,
}

impl World {
    fn new(input: &Input) -> Self {
        let mut state = FuzzState::default();
        let mut codes = Vec::new();
        for spec in input.accounts.iter().take(MAX_ACCOUNTS) {
            let hash = spec.key.hash();
            let code = spec.code.bytes();
            let account = Account {
                nonce: spec.nonce,
                balance: U256::from(spec.balance),
                bytecode_hash: code.as_ref().map(keccak256),
            };
            state.set_account(hash, account);
            for (slot, value) in spec.slots.iter().take(MAX_SLOTS) {
                state.set_slot(hash, slot.hash(), value.get());
            }
            codes.extend(code);
        }
        let accounts = state.account_hashes();
        let (factory, root) = state.clone().into_factory();
        Self { state, factory, root, accounts, codes, mutation: input.mutation }
    }

    fn root(&self, root: Root) -> B256 {
        match root {
            Root::Served => self.root,
            Root::Empty => EMPTY_ROOT_HASH,
            Root::Other(bytes) => B256::from(bytes),
        }
    }

    fn account(&self, r: AccountRef) -> B256 {
        match r {
            AccountRef::Known(i) if !self.accounts.is_empty() => {
                self.accounts[i as usize % self.accounts.len()]
            }
            AccountRef::Known(_) => B256::ZERO,
            AccountRef::Raw(key) => key.hash(),
        }
    }

    /// The keys of the trie a path set reads: the account trie, or `owner`'s storage trie.
    fn keys(&self, owner: Option<B256>) -> Vec<B256> {
        match owner {
            None => self.accounts.clone(),
            Some(owner) => {
                self.state.slots(owner).unwrap_or_default().into_iter().map(|(k, _)| k).collect()
            }
        }
    }

    fn path(&self, owner: Option<B256>, spec: &PathSpec) -> Bytes {
        match spec {
            PathSpec::Raw(bytes) => bytes.clone().into(),
            PathSpec::Node(i, leaf) => {
                let nodes = match owner {
                    None => self.state.account_trie_nodes(),
                    Some(owner) => self.state.storage_trie_nodes(owner),
                };
                let path = nodes
                    .get(*i as usize % nodes.len().max(1))
                    .map(|(p, _)| (0..p.len()).map(|j| p.get(j).unwrap()).collect::<Vec<u8>>())
                    .unwrap_or_default();
                compact(&path, *leaf)
            }
            PathSpec::KeyPrefix(i, len, leaf) => {
                let keys = self.keys(owner);
                let key = keys.get(*i as usize % keys.len().max(1)).copied().unwrap_or_default();
                let nibbles: Vec<u8> = key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect();
                compact(&nibbles[..(*len as usize).min(64)], *leaf)
            }
        }
    }

    fn path_set(&self, spec: &SetSpec, out: &mut Vec<TrieNodePathSet>) {
        match spec {
            SetSpec::Empty => out.push(Vec::new()),
            SetSpec::Account(path) => out.push(vec![self.path(None, path)]),
            SetSpec::Storage(owner, paths) => {
                let owner = self.account(*owner);
                let mut set = vec![Bytes::copy_from_slice(owner.as_slice())];
                set.extend(paths.iter().map(|p| self.path(Some(owner), p)));
                out.push(set);
            }
            SetSpec::BadOwner(owner, paths) => {
                let mut set = vec![Bytes::from(owner.clone())];
                set.extend(paths.iter().map(|p| self.path(None, p)));
                out.push(set);
            }
            SetSpec::Many(owner, path, count) => {
                let owner = self.account(*owner);
                let path = self.path(Some(owner), path);
                let mut set = vec![Bytes::copy_from_slice(owner.as_slice())];
                set.extend(std::iter::repeat_n(path, *count as usize % 1200));
                out.push(set);
            }
        }
    }
}

/// Hex-prefix encodes `nibbles`, with the leaf flag when `leaf`.
fn compact(nibbles: &[u8], leaf: bool) -> Bytes {
    let flag = if leaf { 0x20 } else { 0x00 };
    let mut out = Vec::with_capacity(nibbles.len() / 2 + 1);
    let rest = if nibbles.len() % 2 == 1 {
        out.push(flag | 0x10 | nibbles[0]);
        &nibbles[1..]
    } else {
        out.push(flag);
        nibbles
    };
    out.extend(rest.chunks(2).map(|c| (c[0] << 4) | c[1]));
    let encoded = Bytes::from(out);
    assert_eq!(compact_to_nibbles(&encoded), nibbles, "hex-prefix round trip");
    encoded
}

/// Serving stops after the item that crosses `budget`, so the items before the last fit in it.
/// A reply that is not `complete` stopped at the budget, so it crossed it.
fn check_cut(what: &str, sizes: &[usize], budget: usize, complete: bool) {
    let before_last: usize = sizes[..sizes.len().saturating_sub(1)].iter().sum();
    assert!(
        before_last <= budget,
        "{what}: {before_last} bytes before the last item, budget {budget}"
    );
    let total: usize = sizes.iter().sum();
    assert!(complete || total > budget, "{what}: stopped at {total} bytes, budget {budget}");
}

fn check_body(what: &str, req: &Snap1Message, body_len: usize) {
    let limit = reply_budget(req) + REPLY_SLACK;
    assert!(body_len <= limit, "{what}: {body_len}-byte reply, limit {limit}");
}

/// The serving budget for a range request: the asked bytes, less the proof reserve.
fn range_budget(asked: u64) -> usize {
    usize::try_from(asked).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT - PROOF_RESERVE)
}

/// Checks that `proof` proves `key` holds `expected` under `root`, and that changing one byte
/// of a node on its path makes the verifier reject it.
fn check_proof(world: &World, root: B256, key: B256, expected: Option<Vec<u8>>, proof: &[Bytes]) {
    if let Err(err) = verify_key(root, key, expected.clone(), proof) {
        panic!("proof of {key} under {root} rejected: {err:?}");
    }
    let mut nodes = path_nodes(root, key, proof);
    if nodes.is_empty() {
        return
    }
    assert!(verify_path(root, key, expected.clone(), &nodes).is_ok());
    let Mutation(n, b, x) = world.mutation;
    let n = n as usize % nodes.len();
    let mut node = nodes[n].to_vec();
    let b = b as usize % node.len();
    node[b] ^= x.max(1);
    nodes[n] = node.into();
    assert!(
        verify_path(root, key, expected, &nodes).is_err(),
        "a proof with node {n} byte {b} changed verifies"
    );
}

fn account_range(world: &World, root: Root, origin: Bound, limit: Bound, budget: Budget) {
    let req = GetAccountRangeMessage {
        request_id: 1,
        root_hash: world.root(root),
        starting_hash: origin.resolve(&world.accounts),
        limit_hash: limit.resolve(&world.accounts),
        response_bytes: budget.bytes(),
    };
    let resp = serve_account_range_with_clock(&world.factory, &req, || Duration::ZERO).unwrap();
    assert_eq!(resp.request_id, req.request_id);
    let msg = Snap1Message::Shared(SnapProtocolMessage::GetAccountRange(req.clone()));
    check_body("account range", &msg, resp.length());
    if req.root_hash != world.root {
        assert!(resp.accounts.is_empty() && resp.proof.is_empty(), "unknown root served");
        return
    }

    let from: Vec<AccountData> = world
        .accounts
        .iter()
        .filter(|h| **h >= req.starting_hash)
        .map(|h| AccountData::from_trie_account(*h, &world.state.trie_account(*h).unwrap()))
        .collect();
    assert!(from.starts_with(&resp.accounts), "accounts are not the run from the origin");
    assert_eq!(from.is_empty(), resp.accounts.is_empty(), "the first account was not served");
    let n = resp.accounts.len();
    assert!(
        resp.accounts.iter().take(n.saturating_sub(1)).all(|a| a.hash < req.limit_hash),
        "accounts served past the limit"
    );
    let budget = range_budget(req.response_bytes);
    let last = resp.accounts.last();
    let complete = n == from.len() || last.is_some_and(|a| a.hash >= req.limit_hash);
    assert!(complete || n * PROVIDER_ACCOUNT_BYTES > budget, "account range stopped early");
    let sizes: Vec<usize> = resp.accounts.iter().map(Encodable::length).collect();
    assert!(sizes.iter().take(n.saturating_sub(1)).sum::<usize>() <= budget);

    // The whole trie from the zero origin needs no proof; any other range does.
    let whole = req.starting_hash.is_zero() && n == from.len();
    if resp.proof.is_empty() {
        assert!(whole || world.root == EMPTY_ROOT_HASH, "a partial account range has no proof");
    }
    if !whole || !resp.proof.is_empty() {
        let at_origin = world.state.trie_account(req.starting_hash).map(alloy_rlp::encode);
        check_proof(world, world.root, req.starting_hash, at_origin, &resp.proof);
        if let Some(last) = last {
            let leaf = alloy_rlp::encode(last.trie_account());
            check_proof(world, world.root, last.hash, Some(leaf), &resp.proof);
        }
    }
}

fn storage_ranges(
    world: &World,
    root: Root,
    accounts: &[AccountRef],
    bounds: (Option<Bound>, Option<Bound>),
    budget: Budget,
) {
    let account_hashes: Vec<B256> = accounts.iter().map(|a| world.account(*a)).collect();
    let first_keys = account_hashes.first().map(|a| world.keys(Some(*a))).unwrap_or_default();
    let req = GetStorageRangesMessage {
        request_id: 2,
        root_hash: world.root(root),
        account_hashes,
        starting_hash: bounds.0.map(|b| b.resolve(&first_keys).into()).unwrap_or_default(),
        limit_hash: bounds.1.map(|b| b.resolve(&first_keys).into()).unwrap_or_default(),
        response_bytes: budget.bytes(),
    };
    let resp = serve_storage_ranges(&world.factory, &req).unwrap();
    assert_eq!(resp.request_id, req.request_id);
    let msg = Snap1Message::Shared(SnapProtocolMessage::GetStorageRanges(req.clone()));
    check_body("storage ranges", &msg, resp.length());
    let walked: Vec<B256> =
        req.account_hashes.iter().take(MAX_STORAGE_RANGE_ACCOUNTS_SERVE).copied().collect();
    assert!(resp.slots.len() <= walked.len(), "more ranges than accounts");
    if req.root_hash != world.root || resp.slots.is_empty() {
        assert!(resp.slots.is_empty() && resp.proof.is_empty(), "unknown root served");
        assert!(
            req.root_hash != world.root ||
                walked.is_empty() ||
                walked.iter().any(|a| world.state.slots(*a).is_none()),
            "a request for known accounts got no ranges"
        );
        return
    }

    let budget = range_budget(req.response_bytes);
    let mut sizes = Vec::new();
    let mut last_complete = true;
    for (i, range) in resp.slots.iter().enumerate() {
        let account = walked[i];
        let slots = world.state.slots(account).expect("a range served for a missing account");
        let (origin, limit) = if i == 0 {
            (
                req.starting_hash.unwrap_or(B256::ZERO),
                req.limit_hash.unwrap_or(B256::repeat_byte(0xff)),
            )
        } else {
            (B256::ZERO, B256::repeat_byte(0xff))
        };
        let from: Vec<StorageData> = slots
            .iter()
            .filter(|(k, _)| *k >= origin)
            .map(|(k, v)| StorageData::from_value(*k, *v))
            .collect();
        assert!(from.starts_with(range), "range {i} is not the run from its origin");
        assert_eq!(from.is_empty(), range.is_empty(), "range {i}: its first slot not served");
        let n = range.len();
        assert!(
            range.iter().take(n.saturating_sub(1)).all(|s| s.hash < limit),
            "range {i}: slots served past the limit"
        );
        let complete =
            origin.is_zero() && n == from.len() && range.last().is_none_or(|s| s.hash < limit);
        if i + 1 < resp.slots.len() {
            assert!(complete, "range {i} is partial but not the last");
        } else {
            last_complete = complete;
        }
        sizes.extend(range.iter().map(Encodable::length));
    }
    let before_last: usize = sizes[..sizes.len().saturating_sub(1)].iter().sum();
    assert!(before_last <= budget, "{before_last} slot bytes before the last, budget {budget}");
    if resp.slots.len() < walked.len() && resp.proof.is_empty() {
        let total: usize = sizes.iter().sum();
        assert!(total >= budget, "storage ranges stopped early at {total} of {budget} bytes");
    }

    let i = resp.slots.len() - 1;
    let account = walked[i];
    let storage_root = world.state.storage_root(account).unwrap();
    if resp.proof.is_empty() {
        assert!(
            last_complete || storage_root == EMPTY_ROOT_HASH,
            "a partial storage range has no proof"
        );
    }
    if !last_complete || !resp.proof.is_empty() {
        let origin = if i == 0 { req.starting_hash.unwrap_or(B256::ZERO) } else { B256::ZERO };
        let slots: HashMap<B256, U256> = world.state.slots(account).unwrap().into_iter().collect();
        let at_origin = slots.get(&origin).map(alloy_rlp::encode);
        check_proof(world, storage_root, origin, at_origin, &resp.proof);
        if let Some(last) = resp.slots[i].last() {
            check_proof(world, storage_root, last.hash, Some(last.data.to_vec()), &resp.proof);
        }
    }
}

/// The nodes of the trie `owner` names by path: the account trie, or a storage trie.
type NodesByPath = HashMap<Vec<u8>, Bytes>;

fn nodes_by_path(world: &World, owner: Option<B256>) -> NodesByPath {
    let nodes = match owner {
        None => world.state.account_trie_nodes(),
        Some(owner) => world.state.storage_trie_nodes(owner),
    };
    nodes
        .into_iter()
        .map(|(p, node)| ((0..p.len()).map(|i| p.get(i).unwrap()).collect(), node))
        .collect()
}

/// The node `serve_trie_nodes` must return for one lookup: the node at exactly `path` when it
/// is the root or is linked by hash, else nothing. An owner without storage has no trie.
fn expected_node(
    world: &World,
    owner: Option<B256>,
    path: &[u8],
    cache: &mut HashMap<Option<B256>, NodesByPath>,
) -> Bytes {
    if let Some(owner) = owner &&
        world.state.storage_root(owner).is_none_or(|r| r == EMPTY_ROOT_HASH)
    {
        return Bytes::new()
    }
    let nodes = cache.entry(owner).or_insert_with(|| nodes_by_path(world, owner));
    nodes.get(path).filter(|node| path.is_empty() || node.len() >= 32).cloned().unwrap_or_default()
}

fn trie_nodes(world: &World, root: Root, sets: &[SetSpec], repeat_last: u16, budget: Budget) {
    let mut paths = Vec::new();
    for set in sets {
        world.path_set(set, &mut paths);
    }
    // Enough copies to cross the set cap, but not of a set that already crosses the lookup
    // cap: a million paths a run only grows the allocator's footprint.
    let elements: usize = paths.iter().map(Vec::len).sum();
    if let Some(last) = paths.last().cloned() {
        let room = MAX_PATH_ELEMENTS.saturating_sub(elements) / last.len().max(1);
        paths.extend(std::iter::repeat_n(last, (repeat_last as usize % 1200).min(room)));
    }
    let req = GetTrieNodesMessage {
        request_id: 3,
        root_hash: world.root(root),
        paths,
        response_bytes: budget.bytes(),
    };
    let never = || Duration::ZERO;
    let resp = serve_trie_nodes_with_clock(&world.factory, &req, never).unwrap();
    assert_eq!(resp.request_id, req.request_id);
    let msg = Snap1Message::GetTrieNodes(req.clone());
    check_body("trie nodes", &msg, resp.length());

    // What the wire decoder keeps of the request serves the same reply.
    let wire = Snap1Message::decode(&msg.encode().unwrap()).unwrap();
    let Snap1Message::GetTrieNodes(decoded) = &wire else { panic!("decoded {wire:?}") };
    let again = serve_trie_nodes_with_clock(&world.factory, decoded, never).unwrap();
    assert_eq!(again, resp, "the decoded request serves a different reply");

    // The lookups in request order, capped.
    let mut lookups: Vec<(Option<Option<B256>>, &Bytes)> = Vec::new();
    for set in req.paths.iter().take(MAX_TRIE_NODE_LOOKUPS) {
        match set.as_slice() {
            [] => {}
            [path] => lookups.push((Some(None), path)),
            [owner, rest @ ..] => {
                let owner = (owner.len() == 32).then(|| Some(B256::from_slice(owner)));
                lookups.extend(rest.iter().map(|p| (owner, p)));
            }
        }
    }
    lookups.truncate(MAX_TRIE_NODE_LOOKUPS);
    assert!(resp.nodes.len() <= lookups.len(), "more nodes than lookups");
    if req.root_hash != world.root {
        assert!(resp.nodes.is_empty(), "unknown root served");
        return
    }
    let mut cache = HashMap::new();
    for (i, (node, (owner, path))) in resp.nodes.iter().zip(&lookups).enumerate() {
        let nibbles = compact_to_nibbles(path);
        let want = match owner {
            Some(owner) if nibbles.len() <= 64 => {
                expected_node(world, *owner, &nibbles, &mut cache)
            }
            _ => Bytes::new(),
        };
        assert_eq!(node, &want, "entry {i}: owner {owner:?} path {nibbles:?}");
    }
    let budget = usize::try_from(req.response_bytes).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT);
    let sizes: Vec<usize> = resp.nodes.iter().map(|b| b.len()).collect();
    check_cut("trie nodes", &sizes, budget, resp.nodes.len() == lookups.len());
}

thread_local! {
    /// Building a mock provider builds a mainnet chain spec, so one is kept and cleared per run.
    static PROVIDER: MockEthProvider = MockEthProvider::default();
}

fn byte_codes(world: &World, hashes: &[CodeRef], budget: Budget) {
    PROVIDER.with(|provider| byte_codes_from(provider, world, hashes, budget))
}

fn byte_codes_from(provider: &MockEthProvider, world: &World, hashes: &[CodeRef], budget: Budget) {
    provider.accounts.lock().clear();
    for (i, code) in world.codes.iter().enumerate() {
        provider.add_account(
            Address::with_last_byte(i as u8),
            ExtendedAccount::new(0, U256::ZERO).with_bytecode(code.clone()),
        );
    }
    let known: HashMap<B256, Bytes> =
        world.codes.iter().map(|c| (keccak256(c), c.clone())).collect();
    let hashes: Vec<B256> = hashes
        .iter()
        .map(|h| match h {
            CodeRef::Known(i) if !world.codes.is_empty() => {
                keccak256(&world.codes[*i as usize % world.codes.len()])
            }
            CodeRef::Known(_) | CodeRef::Empty => KECCAK256_EMPTY,
            CodeRef::Raw(bytes) => B256::from(*bytes),
        })
        .collect();
    let req = GetByteCodesMessage { request_id: 4, hashes, response_bytes: budget.bytes() };
    let resp = serve_byte_codes(provider, &req).unwrap();
    assert_eq!(resp.request_id, req.request_id);
    let msg = Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(req.clone()));
    check_body("byte codes", &msg, resp.length());
    let expected: Vec<Bytes> = req
        .hashes
        .iter()
        .take(MAX_BYTE_CODES_SERVE)
        .filter_map(
            |h| if *h == KECCAK256_EMPTY { Some(Bytes::new()) } else { known.get(h).cloned() },
        )
        .collect();
    assert!(expected.starts_with(&resp.codes), "codes are not the known ones in order");
    let budget = usize::try_from(req.response_bytes).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT);
    let sizes: Vec<usize> = resp.codes.iter().map(|b| b.len()).collect();
    check_cut("byte codes", &sizes, budget, resp.codes.len() == expected.len());
}

fuzz_target!(|input: Input| {
    let world = World::new(&input);
    for request in input.requests.iter().take(MAX_REQUESTS) {
        match request {
            Request::AccountRange { root, origin, limit, budget } => {
                account_range(&world, *root, *origin, *limit, *budget)
            }
            Request::StorageRanges { root, accounts, origin, limit, budget } => {
                storage_ranges(&world, *root, accounts, (*origin, *limit), *budget)
            }
            Request::TrieNodes { root, sets, repeat_last, budget } => {
                trie_nodes(&world, *root, sets, *repeat_last, *budget)
            }
            Request::ByteCodes { hashes, budget } => byte_codes(&world, hashes, *budget),
        }
    }
});
