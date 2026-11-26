//! Partial state: the trie nodes this node has verified, read as an EVM database.
//!
//! A read walks the state trie from a verified root through the [`NodeStore`]. If a node on the
//! path is not held, the read is a [`Lookup::Miss`] naming the thing to fetch. [`MissingDb`]
//! wraps a [`PartialState`] as an `evm2` [`Database`]: a miss is recorded and a default (absent
//! account, zero slot, empty code) is returned so the EVM can keep going. The result of such a
//! run is never used; [`crate::exec::run_rounds`] fetches the recorded misses and runs again
//! until a run has none.

use crate::{
    store::NodeStore,
    verify::{walk_path, ProvenAccount, Stop, WalkError},
};
use alloy_consensus::constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use alloy_primitives::{keccak256, map::B256Map, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::Nibbles;
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Database},
};
use std::{
    convert::Infallible,
    sync::{Arc, Weak},
};

/// Something a read needed and did not have.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MissKey {
    /// An account leaf, with where the walk stopped (`None` when a held node on the path or the
    /// account leaf does not decode).
    Account(Address, Option<Stop>),
    /// A storage slot of an account whose leaf is held.
    Slot(Address, B256),
    /// Contract code by hash.
    Code(B256),
    /// The hash of block `n` (for `BLOCKHASH`).
    Header(u64),
}

impl std::hash::Hash for Stop {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

/// The outcome of a partial-state read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// The value, verified.
    Hit(T),
    /// The read needs this first.
    Miss(MissKey),
}

/// The verified nodes of one state root.
#[derive(Clone)]
pub struct PartialState {
    store: Arc<dyn NodeStore>,
    root: B256,
}

impl std::fmt::Debug for PartialState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialState").field("root", &self.root).finish_non_exhaustive()
    }
}

impl PartialState {
    /// Reads `root` out of `store`.
    pub fn new(store: Arc<dyn NodeStore>, root: B256) -> Self {
        Self { store, root }
    }

    /// The state root.
    pub const fn root(&self) -> B256 {
        self.root
    }

    /// The backing store.
    pub fn store(&self) -> &Arc<dyn NodeStore> {
        &self.store
    }

    /// An account: `Hit(None)` is a proven absent account.
    pub fn account(&self, address: &Address) -> Lookup<Option<ProvenAccount>> {
        let path = Nibbles::unpack(keccak256(address));
        match walk_path(self.root, &path, |h| self.store.get(h)) {
            Ok(walk) => match walk.value {
                None => Lookup::Hit(None),
                Some(leaf) => match alloy_consensus::TrieAccount::decode(&mut leaf.as_slice()) {
                    Ok(a) => Lookup::Hit(Some(a.into())),
                    Err(_) => Lookup::Miss(MissKey::Account(*address, None)),
                },
            },
            Err(WalkError::Missing(stop)) => Lookup::Miss(MissKey::Account(*address, Some(stop))),
            Err(WalkError::Malformed) => Lookup::Miss(MissKey::Account(*address, None)),
        }
    }

    /// A storage slot. The account leaf must be held first, else the miss is the account's.
    pub fn storage(&self, address: &Address, slot: U256) -> Lookup<U256> {
        let acct = match self.account(address) {
            Lookup::Hit(Some(a)) => a,
            Lookup::Hit(None) => return Lookup::Hit(U256::ZERO),
            Lookup::Miss(k) => return Lookup::Miss(k),
        };
        if acct.storage_root == EMPTY_ROOT_HASH {
            return Lookup::Hit(U256::ZERO);
        }
        let key = B256::from(slot);
        let path = Nibbles::unpack(keccak256(key));
        match walk_path(acct.storage_root, &path, |h| self.store.get(h)) {
            Ok(walk) => match walk.value {
                None => Lookup::Hit(U256::ZERO),
                Some(v) => U256::decode(&mut v.as_slice())
                    .map_or(Lookup::Miss(MissKey::Slot(*address, key)), Lookup::Hit),
            },
            Err(_) => Lookup::Miss(MissKey::Slot(*address, key)),
        }
    }

    /// Contract code by hash. The empty hash is always held.
    pub fn code(&self, hash: &B256) -> Lookup<Bytes> {
        if *hash == KECCAK_EMPTY || hash.is_zero() {
            return Lookup::Hit(Bytes::new());
        }
        self.store.code(hash).map_or(Lookup::Miss(MissKey::Code(*hash)), Lookup::Hit)
    }
}

/// Looks up a historical block hash for `BLOCKHASH`.
pub type BlockHashes = Arc<dyn Fn(u64) -> Option<B256> + Send + Sync>;

/// The `evm2` database over a [`PartialState`] that records what it could not answer.
pub struct MissingDb {
    state: PartialState,
    hashes: BlockHashes,
    misses: Vec<MissKey>,
    caller: Option<Weak<()>>,
    /// The analysed code this run has read. The EVM asks for the code again on each
    /// `EXTCODESIZE`, `EXTCODECOPY` and `CALL`, and a clone shares the padded bytes and the jump
    /// table.
    codes: B256Map<Bytecode>,
}

impl std::fmt::Debug for MissingDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MissingDb")
            .field("state", &self.state)
            .field("misses", &self.misses.len())
            .finish_non_exhaustive()
    }
}

impl MissingDb {
    /// A database over `state` with a `BLOCKHASH` source.
    pub fn new(state: PartialState, hashes: BlockHashes) -> Self {
        Self { state, hashes, misses: Vec::new(), caller: None, codes: B256Map::default() }
    }

    /// The same database for a caller that holds the `Arc` behind `caller` while it waits.
    pub fn watching(mut self, caller: Weak<()>) -> Self {
        self.caller = Some(caller);
        self
    }

    /// Whether the caller has stopped waiting (a request timeout dropped it), so no one reads
    /// the result.
    pub fn caller_gone(&self) -> bool {
        self.caller.as_ref().is_some_and(|c| c.strong_count() == 0)
    }

    /// The handle [`Self::caller_gone`] reads, for a check made while the EVM holds the database.
    pub const fn caller(&self) -> Option<&Weak<()>> {
        self.caller.as_ref()
    }

    /// Takes the distinct misses recorded so far, in first-seen order.
    pub fn take_misses(&mut self) -> Vec<MissKey> {
        let mut seen = std::collections::HashSet::new();
        std::mem::take(&mut self.misses).into_iter().filter(|k| seen.insert(k.clone())).collect()
    }

    /// Whether any read has missed since the last [`Self::take_misses`].
    pub const fn has_misses(&self) -> bool {
        !self.misses.is_empty()
    }

    /// Raw code by hash (not the padded analysed form `get_code_by_hash` returns). A miss is
    /// recorded and the empty code returned.
    pub fn code_bytes(&mut self, hash: &B256) -> Bytes {
        match self.state.code(hash) {
            Lookup::Hit(code) => code,
            Lookup::Miss(k) => self.miss(k),
        }
    }

    fn miss<T: Default>(&mut self, key: MissKey) -> T {
        self.misses.push(key);
        T::default()
    }
}

impl Database for MissingDb {
    type Error = Infallible;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Infallible> {
        Ok(match self.state.account(address) {
            Lookup::Hit(a) => a.map(|a| AccountInfo::new(a.balance, a.nonce, a.code_hash, None)),
            Lookup::Miss(k) => self.miss(k),
        })
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Infallible> {
        if let Some(code) = self.codes.get(code_hash) {
            return Ok(code.clone());
        }
        Ok(match self.state.code(code_hash) {
            Lookup::Hit(code) => {
                let code = Bytecode::from_stored(code);
                self.codes.insert(*code_hash, code.clone());
                code
            }
            Lookup::Miss(k) => {
                self.misses.push(k);
                Bytecode::default()
            }
        })
    }

    fn get_storage(&mut self, address: &Address, key: &U256) -> Result<U256, Infallible> {
        Ok(match self.state.storage(address, *key) {
            Lookup::Hit(v) => v,
            Lookup::Miss(k) => self.miss(k),
        })
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, Infallible> {
        let n: u64 = number.saturating_to();
        Ok((self.hashes)(n).unwrap_or_else(|| self.miss(MissKey::Header(n))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        store::Store,
        verify::fixtures::{account_leaf, build},
    };
    use alloy_consensus::TrieAccount;

    struct Fx {
        root: B256,
        nodes: std::collections::HashMap<B256, Bytes>,
        storage_root: B256,
    }

    fn fx() -> Fx {
        let slots: Vec<_> = (1u64..=5)
            .map(|i| (keccak256(B256::from(U256::from(i))), alloy_rlp::encode(U256::from(i * 7))))
            .collect();
        let st = build(slots, &[]);
        let accts: Vec<_> = (1u8..=8)
            .map(|i| {
                let root = if i == 1 { st.root } else { EMPTY_ROOT_HASH };
                let a = TrieAccount {
                    nonce: i as u64,
                    balance: U256::from(i as u64 * 10),
                    storage_root: root,
                    code_hash: KECCAK_EMPTY,
                };
                (keccak256(Address::repeat_byte(i)), account_leaf(&a))
            })
            .collect();
        let t = build(accts, &[]);
        let mut nodes = t.all_nodes;
        nodes.extend(st.all_nodes);
        Fx { root: t.root, nodes, storage_root: st.root }
    }

    #[test]
    fn miss_then_hit_after_the_nodes_arrive() {
        let f = fx();
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
        let st = PartialState::new(store.clone(), f.root);
        let a = Address::repeat_byte(3);
        match st.account(&a) {
            Lookup::Miss(MissKey::Account(addr, Some(stop))) => {
                assert_eq!(addr, a);
                assert_eq!(stop.hash, f.root);
            }
            other => panic!("{other:?}"),
        }
        for (h, n) in &f.nodes {
            store.put(*h, n.clone());
        }
        let Lookup::Hit(Some(acct)) = st.account(&a) else { panic!() };
        assert_eq!((acct.nonce, acct.balance), (3, U256::from(30)));
        // Absent account is a hit, not a miss.
        assert_eq!(st.account(&Address::repeat_byte(99)), Lookup::Hit(None));
        // Slots.
        assert_eq!(
            st.storage(&Address::repeat_byte(1), U256::from(2)),
            Lookup::Hit(U256::from(14))
        );
        assert_eq!(st.storage(&Address::repeat_byte(1), U256::from(50)), Lookup::Hit(U256::ZERO));
        assert_eq!(st.storage(&Address::repeat_byte(2), U256::from(1)), Lookup::Hit(U256::ZERO));
        assert_ne!(f.storage_root, EMPTY_ROOT_HASH);
    }

    #[test]
    fn stored_code_keeps_its_kind() {
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
        let designator = Bytes::from([&[0xef, 0x01, 0x00][..], &[0x22; 20]].concat());
        // Code deployed before EIP-3541 may start with 0xEF without being a designator.
        let old_ef = Bytes::from_static(&[0xef, 0x01, 0x00, 0x01]);
        for code in [&designator, &old_ef] {
            store.put_code(keccak256(code), code.clone());
        }
        let mut db = MissingDb::new(PartialState::new(store, B256::ZERO), Arc::new(|_| None));
        let got = db.get_code_by_hash(&keccak256(&designator)).unwrap();
        assert_eq!(got.eip7702_address(), Some(Address::repeat_byte(0x22)));
        assert!(db.get_code_by_hash(&keccak256(&old_ef)).unwrap().is_legacy());
        assert!(!db.has_misses());
    }

    /// A store that counts its code reads.
    struct CountingCode(Store, std::sync::atomic::AtomicUsize);

    impl NodeStore for CountingCode {
        fn get(&self, hash: &B256) -> Option<Bytes> {
            self.0.get(hash)
        }
        fn put(&self, hash: B256, node: Bytes) {
            self.0.put(hash, node);
        }
        fn code(&self, hash: &B256) -> Option<Bytes> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0.code(hash)
        }
        fn put_code(&self, hash: B256, code: Bytes) {
            self.0.put_code(hash, code);
        }
        fn bytes(&self) -> u64 {
            self.0.bytes()
        }
    }

    #[test]
    fn a_run_reads_and_analyses_each_code_once() {
        let store = Arc::new(CountingCode(Store::in_memory(1 << 20), Default::default()));
        let code = Bytes::from_static(&[0x5b, 0x60, 0x00, 0x56]);
        let hash = keccak256(&code);
        store.put_code(hash, code);
        let mut db =
            MissingDb::new(PartialState::new(store.clone(), B256::ZERO), Arc::new(|_| None));
        // As a loop of EXTCODESIZE on one contract.
        let first = db.get_code_by_hash(&hash).unwrap();
        for _ in 0..10 {
            assert_eq!(db.get_code_by_hash(&hash).unwrap(), first);
        }
        assert_eq!(store.1.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!db.has_misses());
    }

    #[test]
    fn slot_miss_after_account_hit_and_db_records_it() {
        let f = fx();
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
        // Hold only the account trie nodes, not the storage trie.
        let acct_only = {
            let path = Nibbles::unpack(keccak256(Address::repeat_byte(1)));
            walk_path(f.root, &path, |h| f.nodes.get(h).cloned()).unwrap().nodes
        };
        for (h, n) in acct_only {
            store.put(h, n);
        }
        let st = PartialState::new(store, f.root);
        let hashes: BlockHashes = Arc::new(|n| (n == 5).then_some(B256::repeat_byte(5)));
        let mut db = MissingDb::new(st, hashes);
        let a = Address::repeat_byte(1);
        assert!(db.get_account(&a).unwrap().is_some());
        assert!(!db.has_misses());
        assert_eq!(db.get_storage(&a, &U256::from(2)).unwrap(), U256::ZERO);
        assert_eq!(db.get_block_hash(&U256::from(5)).unwrap(), B256::repeat_byte(5));
        assert_eq!(db.get_block_hash(&U256::from(6)).unwrap(), B256::ZERO);
        let code = db.get_code_by_hash(&B256::repeat_byte(9)).unwrap();
        assert!(code.is_empty());
        let misses = db.take_misses();
        assert_eq!(
            misses,
            vec![
                MissKey::Slot(a, B256::from(U256::from(2))),
                MissKey::Header(6),
                MissKey::Code(B256::repeat_byte(9)),
            ]
        );
        assert!(!db.has_misses());
    }

    #[test]
    fn take_misses_keeps_each_key_once_in_first_seen_order() {
        let f = fx();
        let mut db = MissingDb::new(
            PartialState::new(Arc::new(Store::in_memory(1 << 20)), f.root),
            Arc::new(|_| None),
        );
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let stop = Some(Stop { hash: f.root, prefix: Nibbles::default() });
        for addr in [a, b, a] {
            assert_eq!(db.get_account(&addr).unwrap(), None);
            // A slot of an unheld account misses on the account.
            assert_eq!(db.get_storage(&addr, &U256::from(1)).unwrap(), U256::ZERO);
        }
        for _ in 0..2 {
            assert_eq!(db.get_block_hash(&U256::from(7)).unwrap(), B256::ZERO);
        }
        assert_eq!(
            db.take_misses(),
            vec![MissKey::Account(a, stop.clone()), MissKey::Account(b, stop), MissKey::Header(7),]
        );
        assert_eq!(db.take_misses(), vec![]);
    }

    #[test]
    fn code_is_held_for_the_empty_hashes_and_missed_otherwise() {
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
        let code = Bytes::from_static(&[0x60, 0x00]);
        store.put_code(keccak256(&code), code.clone());
        let st = PartialState::new(store, B256::ZERO);
        assert_eq!(st.code(&KECCAK_EMPTY), Lookup::Hit(Bytes::new()));
        assert_eq!(st.code(&B256::ZERO), Lookup::Hit(Bytes::new()));
        assert_eq!(st.code(&keccak256(&code)), Lookup::Hit(code));
        let unheld = B256::repeat_byte(9);
        assert_eq!(st.code(&unheld), Lookup::Miss(MissKey::Code(unheld)));
    }

    #[test]
    fn a_proven_absent_account_has_zero_slots_without_a_miss() {
        let f = fx();
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
        for (h, n) in &f.nodes {
            store.put(*h, n.clone());
        }
        let absent = Address::repeat_byte(99);
        let st = PartialState::new(store, f.root);
        assert_eq!(st.storage(&absent, U256::from(1)), Lookup::Hit(U256::ZERO));
        let mut db = MissingDb::new(st, Arc::new(|_| None));
        assert_eq!(db.get_storage(&absent, &U256::from(1)).unwrap(), U256::ZERO);
        assert!(!db.has_misses());
    }

    #[test]
    fn a_node_or_leaf_that_does_not_decode_is_a_miss_not_a_default() {
        let a = Address::repeat_byte(1);
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
        // A root that hashes right but is no trie node.
        let garbage = Bytes::from_static(&[0xc3, 0x80, 0x80, 0x80]);
        store.put(keccak256(&garbage), garbage.clone());
        let st = PartialState::new(store.clone(), keccak256(&garbage));
        assert_eq!(st.account(&a), Lookup::Miss(MissKey::Account(a, None)));
        // An account leaf that is not an account.
        let t = build(vec![(keccak256(a), vec![0xc0])], &[]);
        for (h, n) in t.all_nodes {
            store.put(h, n);
        }
        let st = PartialState::new(store.clone(), t.root);
        assert_eq!(st.account(&a), Lookup::Miss(MissKey::Account(a, None)));
        // A slot leaf that is not a slot value.
        let slot = B256::from(U256::from(1));
        let s = build(vec![(keccak256(slot), vec![0xc0])], &[]);
        let acct = TrieAccount {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: s.root,
            code_hash: KECCAK_EMPTY,
        };
        let t = build(vec![(keccak256(a), account_leaf(&acct))], &[]);
        for (h, n) in t.all_nodes.into_iter().chain(s.all_nodes) {
            store.put(h, n);
        }
        let st = PartialState::new(store, t.root);
        assert_eq!(st.storage(&a, U256::from(1)), Lookup::Miss(MissKey::Slot(a, slot)));
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use crate::{
        store::Store,
        testing::{world, Acct},
    };
    use proptest::{prelude::*, sample::Index};

    /// Blocks `0..HELD` have hashes in the complete view.
    const HELD: u64 = 16;

    #[derive(Debug, Clone)]
    enum Read {
        Account(u8),
        Storage(u8, u8),
        Code(u8),
        BlockHash(u64),
    }

    fn read() -> impl Strategy<Value = Read> {
        // Addresses past the world's accounts are absent.
        prop_oneof![
            (0u8..10).prop_map(Read::Account),
            (0u8..10, 0u8..6).prop_map(|(a, s)| Read::Storage(a, s)),
            (0u8..10).prop_map(Read::Code),
            (0..HELD + 4).prop_map(Read::BlockHash),
        ]
    }

    /// Balance, nonce, code and slots of one account.
    type AcctParts = (u64, u64, Vec<u8>, std::collections::BTreeMap<u8, u64>);

    fn acct() -> impl Strategy<Value = AcctParts> {
        (
            any::<u64>(),
            0u64..4,
            prop_oneof![Just(Vec::new()), prop::collection::vec(any::<u8>(), 1..40)],
            prop::collection::btree_map(0u8..6, 1u64.., 0..5),
        )
    }

    fn hash_of(n: u64) -> B256 {
        keccak256(n.to_be_bytes())
    }

    /// Runs `r` and returns what it read, with the misses it recorded.
    fn run(db: &mut MissingDb, r: &Read, codes: &[B256]) -> (String, Vec<MissKey>) {
        let addr = |i: &u8| Address::repeat_byte(i + 1);
        let out = match r {
            Read::Account(i) => format!("{:?}", db.get_account(&addr(i)).unwrap()),
            Read::Storage(i, s) => {
                format!("{}", db.get_storage(&addr(i), &U256::from(*s)).unwrap())
            }
            Read::Code(i) => {
                let hash = codes.get(*i as usize).copied().unwrap_or(KECCAK_EMPTY);
                let code = db.get_code_by_hash(&hash).unwrap();
                format!("{} {:?}", db.code_bytes(&hash), code.original_bytes())
            }
            Read::BlockHash(n) => format!("{}", db.get_block_hash(&U256::from(*n)).unwrap()),
        };
        (out, db.take_misses())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Over any subset of the nodes, under eviction, a read either records a miss for what
        /// it read or returns exactly what complete state returns.
        #[test]
        fn a_read_is_exact_or_a_miss_for_what_it_read(
            accts in prop::collection::vec(acct(), 1..8),
            held in prop::collection::vec(any::<bool>(), 64),
            held_hashes in any::<u16>(),
            cap in prop_oneof![Just(400u64), Just(2_000), Just(1 << 20)],
            reads in prop::collection::vec(read(), 1..40),
            skip in any::<Index>(),
        ) {
            let entries: Vec<(Address, Acct)> = accts
                .into_iter()
                .enumerate()
                .map(|(i, (balance, nonce, code, slots))| {
                    let storage =
                        slots.into_iter().map(|(k, v)| (U256::from(k), U256::from(v))).collect();
                    (Address::repeat_byte(i as u8 + 1), Acct { balance, nonce, code, storage })
                })
                .collect();
            let w = world(&entries);
            let codes: Vec<B256> = entries
                .iter()
                .map(|(_, a)| if a.code.is_empty() { KECCAK_EMPTY } else { keccak256(&a.code) })
                .collect();

            let full: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
            let part: Arc<dyn NodeStore> = Arc::new(Store::in_memory(cap));
            let mut all: Vec<(&B256, &Bytes)> = w.nodes.iter().chain(w.codes.iter()).collect();
            all.sort();
            let offset = skip.index(held.len());
            for (i, (h, n)) in all.into_iter().enumerate() {
                full.put(*h, n.clone());
                if held[(i + offset) % held.len()] {
                    part.put(*h, n.clone());
                }
            }
            let mut reference =
                MissingDb::new(PartialState::new(full, w.root), Arc::new(|n| (n < HELD).then(|| hash_of(n))));
            let mut db = MissingDb::new(
                PartialState::new(part, w.root),
                Arc::new(move |n| (n < HELD && held_hashes >> n & 1 == 1).then(|| hash_of(n))),
            );

            for r in &reads {
                let (want, ref_misses) = run(&mut reference, r, &codes);
                let (got, misses) = run(&mut db, r, &codes);
                if let Read::BlockHash(n) = r && *n >= HELD {
                    prop_assert_eq!(&ref_misses, &vec![MissKey::Header(*n)]);
                } else {
                    prop_assert_eq!(&ref_misses, &vec![], "{:?}", r);
                }
                if misses.is_empty() {
                    prop_assert_eq!(&got, &want, "{:?}", r);
                }
                for m in &misses {
                    let ok = match (r, m) {
                        (Read::Account(i) | Read::Storage(i, _), MissKey::Account(a, _)) => {
                            *a == Address::repeat_byte(i + 1)
                        }
                        (Read::Storage(i, s), MissKey::Slot(a, k)) => {
                            *a == Address::repeat_byte(i + 1) && *k == B256::from(U256::from(*s))
                        }
                        (Read::Code(i), MissKey::Code(h)) => {
                            Some(h) == codes.get(*i as usize)
                        }
                        (Read::BlockHash(n), MissKey::Header(k)) => n == k,
                        _ => false,
                    };
                    prop_assert!(ok, "{:?} recorded {:?}", r, m);
                }
            }
        }
    }
}
