//! The miss-and-retry round driver.
//!
//! A closure runs against a [`MissingDb`]. A run with misses is thrown away; the misses are
//! fetched through the verifier and the closure runs again. A result is accepted only from a run
//! with no misses, so an answer never depends on a default that stood in for missing state.

use crate::{
    config::OnMiss,
    state::{BlockHashes, Lookup, MissKey, MissingDb, PartialState},
};
use alloy_primitives::B256;
use async_trait::async_trait;

/// Why fetching state failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// No peer could serve it (all failed or none connected).
    #[error("no source could serve the request")]
    NoSource,
    /// Every attempt returned data that failed verification.
    #[error("every source returned data that failed verification")]
    Unverifiable,
}

/// Fills the store, through the verifier, with what a round missed.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Fetches and verifies `misses` at state root `root`.
    async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError>;
}

/// Receives misses to fetch in the background (`error-and-warm`).
pub trait WarmSink: Send + Sync {
    /// Queues `misses` at `root`. Must not block.
    fn warm(&self, root: B256, misses: Vec<MissKey>);
}

/// Why the rounds did not produce a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoundsError {
    /// `error` or `error-and-warm`: the first run needed this many pieces. Nothing was fetched
    /// inline.
    #[error("{0} pieces of state are not verified locally")]
    Missing(u64),
    /// Fetching failed.
    #[error("fetch failed: {0}")]
    Fetch(#[from] FetchError),
    /// A run with complete state read the hash of a block outside the held header chain.
    #[error("the hash of block {0} is outside the held header chain")]
    BlockHashUnavailable(u64),
    /// A run missed exactly what the run before it missed, so the fetch made nothing readable.
    #[error("round {0} missed the same state after it was fetched")]
    NoProgress(u32),
    /// The closure still had misses after `max_rounds` runs.
    #[error("state kept changing the set of misses after {0} rounds")]
    TooManyRounds(u32),
    /// The blocking run did not finish (it panicked or the runtime is shutting down).
    #[error("execution aborted")]
    Aborted,
}

/// A result and how many runs it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rounds<T> {
    /// The result of the run that had no misses.
    pub value: T,
    /// How many runs it took (1 when state was complete).
    pub rounds: u32,
}

/// Runs `f` until it completes with no misses.
pub async fn run_rounds<T>(
    state: &PartialState,
    hashes: &BlockHashes,
    fetcher: &dyn Fetcher,
    warm: Option<&dyn WarmSink>,
    mode: OnMiss,
    max_rounds: u32,
    mut f: impl FnMut(&mut MissingDb) -> T,
) -> Result<Rounds<T>, RoundsError> {
    let mut stuck = Stuck::default();
    for round in 1..=max_rounds {
        let mut db = MissingDb::new(state.clone(), hashes.clone());
        let value = f(&mut db);
        let misses = db.take_misses();
        if misses.is_empty() {
            return Ok(Rounds { value, rounds: round });
        }
        handle_misses(state, fetcher, warm, mode, misses, round, &mut stuck).await?;
    }
    Err(RoundsError::TooManyRounds(max_rounds))
}

/// Like [`run_rounds`], for heavy closures (EVM runs): each run goes to a blocking thread, at most
/// as many at once as `permits` allows, so the async workers keep answering other requests.
///
/// A run reads the code of nearly every account it loads, so a round also fetches the code of the
/// accounts it fetched, and a nested contract costs one round instead of two.
#[expect(clippy::too_many_arguments)]
pub async fn run_rounds_blocking<T, F>(
    state: &PartialState,
    hashes: &BlockHashes,
    fetcher: &dyn Fetcher,
    warm: Option<&dyn WarmSink>,
    mode: OnMiss,
    max_rounds: u32,
    permits: &std::sync::Arc<tokio::sync::Semaphore>,
    f: F,
) -> Result<Rounds<T>, RoundsError>
where
    T: Send + 'static,
    F: FnMut(&mut MissingDb) -> T + Send + 'static,
{
    let mut f = f;
    let mut stuck = Stuck::default();
    for round in 1..=max_rounds {
        // Dropped with this future, so the closure can see that no one waits for it.
        let caller = std::sync::Arc::new(());
        let mut db = MissingDb::new(state.clone(), hashes.clone())
            .watching(std::sync::Arc::downgrade(&caller));
        // The permit moves into the blocking task: a caller that gives up (a request timeout)
        // does not free the slot while the run is still going.
        let permit = permits.clone().acquire_owned().await.map_err(|_| RoundsError::Aborted)?;
        let (back, value, misses) = tokio::task::spawn_blocking(move || {
            let value = f(&mut db);
            drop(permit);
            (f, value, db.take_misses())
        })
        .await
        .map_err(|_| RoundsError::Aborted)?;
        drop(caller);
        f = back;
        if misses.is_empty() {
            return Ok(Rounds { value, rounds: round });
        }
        let got = handle_misses(state, fetcher, warm, mode, misses, round, &mut stuck).await?;
        let codes = unheld_code(state, &got);
        // Best effort: a run that needs the code misses it, and that fetch reports its error.
        if !codes.is_empty() &&
            let Err(e) = fetcher.fetch(state.root(), &codes).await
        {
            tracing::debug!(%e, codes = codes.len(), "code prefetch failed");
        }
    }
    Err(RoundsError::TooManyRounds(max_rounds))
}

/// The code misses of the accounts among `fetched` that now resolve, each once.
fn unheld_code(state: &PartialState, fetched: &[MissKey]) -> Vec<MissKey> {
    let mut codes = Vec::new();
    for key in fetched {
        if let MissKey::Account(address, _) = key &&
            let Lookup::Hit(Some(account)) = state.account(address) &&
            let Lookup::Miss(code) = state.code(&account.code_hash) &&
            !codes.contains(&code)
        {
            codes.push(code);
        }
    }
    codes
}

/// Fetches in a row that leave the same misses unreadable before the rounds end. One is not
/// enough: the shared cache may evict the fetched nodes before the check reads them.
const STUCK_FETCHES: u32 = 2;

/// The misses of the last fetch if any of them still missed right after it, and how many fetches
/// in a row left those same misses so.
#[derive(Debug, Default)]
struct Stuck {
    misses: Vec<MissKey>,
    fetches: u32,
}

/// Fetches `misses` in `fetch` mode and returns them, and records in `stuck` whether the fetch
/// left any of them unreadable.
async fn handle_misses(
    state: &PartialState,
    fetcher: &dyn Fetcher,
    warm: Option<&dyn WarmSink>,
    mode: OnMiss,
    misses: Vec<MissKey>,
    round: u32,
    stuck: &mut Stuck,
) -> Result<Vec<MissKey>, RoundsError> {
    // No fetch extends the header chain, so a hash miss in a run with complete state is final.
    // With state misses too, a default may have named the block, so those are fetched first.
    if let Some(MissKey::Header(n)) = misses.first() &&
        misses.iter().all(|k| matches!(k, MissKey::Header(_)))
    {
        return Err(RoundsError::BlockHashUnavailable(*n));
    }
    // The same misses after fetches that each left one of them unreadable mean the fetches
    // stored nothing they can use (an unserved or malformed node), and another run is waste.
    if stuck.fetches >= STUCK_FETCHES && misses == stuck.misses {
        return Err(RoundsError::NoProgress(round));
    }
    match mode {
        OnMiss::Error => Err(RoundsError::Missing(misses.len() as u64)),
        OnMiss::ErrorAndWarm => {
            let n = misses.len() as u64;
            if let Some(w) = warm {
                w.warm(state.root(), misses);
            }
            Err(RoundsError::Missing(n))
        }
        OnMiss::Fetch => {
            fetcher.fetch(state.root(), &misses).await?;
            // When every miss resolved, the same misses next round mean the shared cache dropped
            // the nodes in between, and fetching them again helps.
            if !misses.iter().any(|k| still_missing(state, k)) {
                *stuck = Stuck::default();
            } else if misses == stuck.misses {
                stuck.fetches += 1;
            } else {
                *stuck = Stuck { misses: misses.clone(), fetches: 1 };
            }
            Ok(misses)
        }
    }
}

/// Whether reading `key` again gives the same miss.
fn still_missing(state: &PartialState, key: &MissKey) -> bool {
    match key {
        MissKey::Account(address, _) => {
            matches!(state.account(address), Lookup::Miss(k) if k == *key)
        }
        MissKey::Slot(address, slot) => {
            matches!(state.storage(address, (*slot).into()), Lookup::Miss(k) if k == *key)
        }
        MissKey::Code(hash) => matches!(state.code(hash), Lookup::Miss(_)),
        // No fetch serves a block hash, so it says nothing about what the fetch stored.
        MissKey::Header(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::{Lookup, PartialState},
        store::{NodeStore, Store},
        verify::{
            fixtures::{account_leaf, build},
            slot_rlp, walk_path,
        },
    };
    use alloy_consensus::{
        constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY},
        TrieAccount,
    };
    use alloy_primitives::{keccak256, Address, Bytes, U256};
    use alloy_trie::Nibbles;
    use evm2::evm::Database;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    const PROXY: Address = Address::repeat_byte(0x11);
    const IMPL: Address = Address::repeat_byte(0x22);

    /// proxy slot 0 holds the impl address; impl's mapping slot `MAP` holds 4242.
    const MAP: u64 = 7;

    struct World {
        root: B256,
        nodes: HashMap<B256, Bytes>,
    }

    fn world() -> World {
        let proxy_slots =
            vec![(keccak256(B256::ZERO), alloy_rlp::encode(U256::from_be_slice(IMPL.as_slice())))];
        let pst = build(proxy_slots, &[]);
        let impl_slots = vec![
            (keccak256(B256::from(U256::from(MAP))), slot_rlp(U256::from(4242)).to_vec()),
            (keccak256(B256::from(U256::from(8))), slot_rlp(U256::from(1)).to_vec()),
        ];
        let ist = build(impl_slots, &[]);
        let mk = |root| TrieAccount {
            nonce: 1,
            balance: U256::from(5),
            storage_root: root,
            code_hash: KECCAK_EMPTY,
        };
        let mut leaves = vec![
            (keccak256(PROXY), account_leaf(&mk(pst.root))),
            (keccak256(IMPL), account_leaf(&mk(ist.root))),
        ];
        for i in 0u8..6 {
            leaves.push((
                keccak256(Address::repeat_byte(0x40 + i)),
                account_leaf(&mk(EMPTY_ROOT_HASH)),
            ));
        }
        let t = build(leaves, &[]);
        let mut nodes = t.all_nodes;
        nodes.extend(pst.all_nodes);
        nodes.extend(ist.all_nodes);
        World { root: t.root, nodes }
    }

    /// An honest full node: serves the nodes on the path of each miss, and counts calls.
    struct Honest {
        world: HashMap<B256, Bytes>,
        store: Arc<dyn NodeStore>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Fetcher for Honest {
        async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let get = |h: &B256| self.world.get(h).cloned();
            for m in misses {
                let nodes = match m {
                    MissKey::Account(a, _) => {
                        walk_path(root, &Nibbles::unpack(keccak256(a)), get).unwrap().nodes
                    }
                    MissKey::Slot(a, slot) => {
                        let st = PartialState::new(self.store.clone(), root);
                        let Lookup::Hit(Some(acct)) = st.account(a) else { continue };
                        walk_path(acct.storage_root, &Nibbles::unpack(keccak256(slot)), get)
                            .unwrap()
                            .nodes
                    }
                    MissKey::Code(_) | MissKey::Header(_) => continue,
                };
                for (h, n) in nodes {
                    self.store.put(h, n);
                }
            }
            Ok(())
        }
    }

    fn setup() -> (PartialState, Honest, BlockHashes) {
        let w = world();
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
        let st = PartialState::new(store.clone(), w.root);
        let honest = Honest { world: w.nodes, store, calls: AtomicUsize::new(0) };
        (st, honest, Arc::new(|_| None))
    }

    /// proxy -> impl -> mapping slot.
    fn read_through_proxy(db: &mut MissingDb) -> U256 {
        let _ = db.get_account(&PROXY).unwrap();
        let word = db.get_storage(&PROXY, &U256::ZERO).unwrap();
        let target = Address::from_word(B256::from(word));
        let _ = db.get_account(&target).unwrap();
        db.get_storage(&target, &U256::from(MAP)).unwrap()
    }

    #[tokio::test]
    async fn proxy_impl_mapping_converges_and_never_returns_a_partial_result() {
        let (st, honest, hashes) = setup();
        let seen = Mutex::new(Vec::new());
        let out = run_rounds(&st, &hashes, &honest, None, OnMiss::Fetch, 40, |db| {
            let v = read_through_proxy(db);
            seen.lock().unwrap().push(v);
            v
        })
        .await
        .unwrap();
        assert_eq!(out.value, U256::from(4242));
        // Each dependent read costs a round: proxy leaf, proxy slot, impl leaf, impl slot, then
        // the run with complete state.
        assert_eq!(out.rounds, 5);
        assert_eq!(honest.calls.load(Ordering::SeqCst), 4);
        // Earlier rounds saw defaults (zero), the accepted one did not.
        let seen = seen.into_inner().unwrap();
        assert_eq!(seen.len(), 5);
        assert!(seen[..4].iter().all(|v| v.is_zero()));
    }

    #[tokio::test]
    async fn error_mode_counts_misses_and_fetches_nothing() {
        let (st, honest, hashes) = setup();
        let err = run_rounds(&st, &hashes, &honest, None, OnMiss::Error, 40, read_through_proxy)
            .await
            .unwrap_err();
        // Account(proxy) is the only distinct miss of the first run: the storage read dedups to
        // it, and impl resolves to the zero address, whose account is a second miss.
        assert_eq!(err, RoundsError::Missing(2));
        assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
    }

    struct Queue(Mutex<Vec<(B256, Vec<MissKey>)>>);
    impl WarmSink for Queue {
        fn warm(&self, root: B256, misses: Vec<MissKey>) {
            self.0.lock().unwrap().push((root, misses));
        }
    }

    #[tokio::test]
    async fn error_and_warm_queues_then_the_second_call_hits() {
        let (st, honest, hashes) = setup();
        let q = Queue(Mutex::default());
        let err = run_rounds(
            &st,
            &hashes,
            &honest,
            Some(&q),
            OnMiss::ErrorAndWarm,
            40,
            read_through_proxy,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RoundsError::Missing(_)));
        assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
        // The warm worker (here: the test) fetches what was queued, until nothing is left.
        for _ in 0..6 {
            let batch: Vec<_> = std::mem::take(&mut *q.0.lock().unwrap());
            if batch.is_empty() {
                break;
            }
            for (root, misses) in batch {
                honest.fetch(root, &misses).await.unwrap();
            }
            let _ = run_rounds(
                &st,
                &hashes,
                &honest,
                Some(&q),
                OnMiss::ErrorAndWarm,
                40,
                read_through_proxy,
            )
            .await;
        }
        let out = run_rounds(
            &st,
            &hashes,
            &honest,
            Some(&q),
            OnMiss::ErrorAndWarm,
            40,
            read_through_proxy,
        )
        .await
        .unwrap();
        assert_eq!((out.value, out.rounds), (U256::from(4242), 1));
    }

    /// Contracts 1 to `n` in a chain: the code of each names the next, and `n` names an absent
    /// `ABSENT`.
    fn contract_chain(n: u8) -> (PartialState, crate::testing::Honest) {
        let accts: Vec<_> = (1u8..=n)
            .map(|i| {
                let next = if i == n { ABSENT } else { i + 1 };
                (
                    Address::repeat_byte(i),
                    crate::testing::Acct { code: vec![next], ..Default::default() },
                )
            })
            .collect();
        let w = Arc::new(crate::testing::world(&accts));
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 22));
        let st = PartialState::new(store.clone(), w.root);
        (st, crate::testing::Honest::new(w, store))
    }

    const ABSENT: u8 = 0x99;

    /// Follows a [`contract_chain`] from contract 1 and returns the addresses it named.
    fn walk_chain(db: &mut MissingDb) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut at = Address::repeat_byte(1);
        while let Ok(Some(acct)) = db.get_account(&at) {
            let Ok(code) = db.get_code_by_hash(&acct.code_hash);
            let Some(next) = code.original_bytes().first().copied() else { break };
            seen.push(next);
            at = Address::repeat_byte(next);
        }
        seen
    }

    #[tokio::test]
    async fn the_code_of_a_fetched_account_comes_in_the_same_round() {
        let (st, honest) = contract_chain(5);
        let hashes: BlockHashes = Arc::new(|_| None);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let out = run_rounds_blocking(
            &st,
            &hashes,
            &honest,
            None,
            OnMiss::Fetch,
            40,
            &permits,
            walk_chain,
        )
        .await
        .unwrap();
        assert_eq!(out.value, vec![2, 3, 4, 5, ABSENT]);
        // One round per contract, then the complete run. The nodes already held prove the last
        // name absent.
        assert_eq!(out.rounds, 6);
        // Each contract round fetches its account, then its code.
        assert_eq!(honest.calls.load(Ordering::SeqCst), 10);
    }

    /// Serves accounts and slots honestly, and fails every code fetch.
    struct NoCode(crate::testing::Honest);

    #[async_trait]
    impl Fetcher for NoCode {
        async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
            if misses.iter().any(|k| matches!(k, MissKey::Code(_))) {
                return Err(FetchError::NoSource);
            }
            self.0.fetch(root, misses).await
        }
    }

    #[tokio::test]
    async fn a_failed_code_prefetch_does_not_fail_a_run_that_never_reads_the_code() {
        let (st, honest) = contract_chain(1);
        let hashes: BlockHashes = Arc::new(|_| None);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        // Reads the balance of a contract, as `address(token).balance`, and never its code.
        let out = run_rounds_blocking(
            &st,
            &hashes,
            &NoCode(honest),
            None,
            OnMiss::Fetch,
            40,
            &permits,
            |db: &mut MissingDb| db.get_account(&Address::repeat_byte(1)).unwrap().is_some(),
        )
        .await
        .unwrap();
        assert_eq!((out.value, out.rounds), (true, 2));
    }

    /// An honest fetcher whose first fetch the shared cache loses before the driver checks it.
    struct LostAtOnce {
        honest: Honest,
        store: Arc<Forgetful>,
    }

    #[async_trait]
    impl Fetcher for LostAtOnce {
        async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
            let first = self.honest.calls.load(Ordering::SeqCst) == 0;
            self.honest.fetch(root, misses).await?;
            if first {
                self.store.forget();
            }
            Ok(())
        }
    }

    /// A memory store that other requests can empty at once.
    #[derive(Default)]
    struct Forgetful(Mutex<HashMap<B256, Bytes>>);

    impl Forgetful {
        fn forget(&self) {
            self.0.lock().unwrap().clear();
        }
    }

    impl NodeStore for Forgetful {
        fn get(&self, hash: &B256) -> Option<Bytes> {
            self.0.lock().unwrap().get(hash).cloned()
        }
        fn put(&self, hash: B256, node: Bytes) {
            self.0.lock().unwrap().insert(hash, node);
        }
        fn code(&self, hash: &B256) -> Option<Bytes> {
            self.get(hash)
        }
        fn put_code(&self, hash: B256, code: Bytes) {
            self.put(hash, code);
        }
        fn bytes(&self) -> u64 {
            0
        }
    }

    #[tokio::test]
    async fn a_fetch_the_cache_lost_before_it_was_checked_is_fetched_again() {
        let w = world();
        let store = Arc::new(Forgetful::default());
        let st = PartialState::new(store.clone(), w.root);
        let honest = Honest { world: w.nodes, store: store.clone(), calls: AtomicUsize::new(0) };
        let fetcher = LostAtOnce { honest, store };
        let hashes: BlockHashes = Arc::new(|_| None);
        let out = run_rounds(&st, &hashes, &fetcher, None, OnMiss::Fetch, 40, read_through_proxy)
            .await
            .unwrap();
        // The lost fetch costs one more fetch and run than `proxy_impl_mapping_converges`.
        assert_eq!((out.value, out.rounds), (U256::from(4242), 6));
        assert_eq!(fetcher.honest.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn too_many_rounds() {
        let (st, honest, hashes) = setup();
        let runs = AtomicUsize::new(0);
        let err = run_rounds(&st, &hashes, &honest, None, OnMiss::Fetch, 2, |db| {
            runs.fetch_add(1, Ordering::SeqCst);
            read_through_proxy(db)
        })
        .await
        .unwrap_err();
        assert_eq!(err, RoundsError::TooManyRounds(2));
        assert_eq!(runs.into_inner(), 2);
    }

    #[tokio::test]
    async fn a_chain_longer_than_the_round_limit_goes_on_from_the_held_nodes() {
        // One round per contract, so 45 contracts need more than the default 40 rounds.
        let (st, honest) = contract_chain(45);
        let hashes: BlockHashes = Arc::new(|_| None);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = |runs: Arc<AtomicUsize>| {
            move |db: &mut MissingDb| {
                runs.fetch_add(1, Ordering::SeqCst);
                walk_chain(db)
            }
        };
        let max = crate::config::LiteConfig::default().max_rounds;
        let first = run_rounds_blocking(
            &st,
            &hashes,
            &honest,
            None,
            OnMiss::Fetch,
            max,
            &permits,
            counted(runs.clone()),
        )
        .await;
        assert_eq!(first.unwrap_err(), RoundsError::TooManyRounds(max));
        assert_eq!(runs.swap(0, Ordering::SeqCst), max as usize);
        // Every round stored what it fetched, so the next call starts at contract 41.
        let out = run_rounds_blocking(
            &st,
            &hashes,
            &honest,
            None,
            OnMiss::Fetch,
            max,
            &permits,
            counted(runs.clone()),
        )
        .await
        .unwrap();
        assert_eq!(out.value, (2..=45).chain([ABSENT]).collect::<Vec<u8>>());
        assert_eq!(out.rounds, 6);
        assert_eq!(runs.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn an_unheld_block_hash_ends_the_rounds_at_once_in_every_mode() {
        let (st, honest, hashes) = setup();
        let q = Queue(Mutex::default());
        for mode in [OnMiss::Fetch, OnMiss::Error, OnMiss::ErrorAndWarm] {
            let runs = AtomicUsize::new(0);
            let err = run_rounds(&st, &hashes, &honest, Some(&q), mode, 40, |db| {
                runs.fetch_add(1, Ordering::SeqCst);
                db.get_block_hash(&U256::from(100)).unwrap()
            })
            .await
            .unwrap_err();
            assert_eq!(err, RoundsError::BlockHashUnavailable(100), "{mode:?}");
            assert_eq!(runs.load(Ordering::SeqCst), 1, "{mode:?}");
        }
        assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
        assert!(q.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn state_misses_are_fetched_before_an_unheld_block_hash_ends_the_rounds() {
        // The block number comes from storage, so the default of a missed slot names the wrong
        // block: the state must be complete before the hash miss is final.
        let (st, honest, hashes) = setup();
        let err = run_rounds(&st, &hashes, &honest, None, OnMiss::Fetch, 40, |db| {
            let n = read_through_proxy(db);
            db.get_block_hash(&n).unwrap()
        })
        .await
        .unwrap_err();
        assert_eq!(err, RoundsError::BlockHashUnavailable(4242));
        assert_eq!(honest.calls.load(Ordering::SeqCst), 4);
    }

    /// Reports success and stores nothing, like a fetcher whose peers serve no usable node.
    struct Idle(AtomicUsize);

    #[async_trait]
    impl Fetcher for Idle {
        async fn fetch(&self, _: B256, _: &[MissKey]) -> Result<(), FetchError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_fetch_that_stores_nothing_ends_the_rounds_after_the_third_run() {
        let (st, _, hashes) = setup();
        let idle = Idle(AtomicUsize::new(0));
        let runs = AtomicUsize::new(0);
        let err = run_rounds(&st, &hashes, &idle, None, OnMiss::Fetch, 40, |db| {
            runs.fetch_add(1, Ordering::SeqCst);
            read_through_proxy(db)
        })
        .await
        .unwrap_err();
        assert_eq!(err, RoundsError::NoProgress(3));
        assert_eq!((runs.into_inner(), idle.0.into_inner()), (3, 2));
    }

    #[tokio::test]
    async fn a_blocking_run_whose_fetch_stores_nothing_ends_after_the_third_run() {
        let (st, _, hashes) = setup();
        let idle = Idle(AtomicUsize::new(0));
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let err = run_rounds_blocking(
            &st,
            &hashes,
            &idle,
            None,
            OnMiss::Fetch,
            40,
            &permits,
            read_through_proxy,
        )
        .await
        .unwrap_err();
        assert_eq!(err, RoundsError::NoProgress(3));
        assert_eq!(idle.0.into_inner(), 2);
    }

    #[tokio::test]
    async fn a_fetch_the_cache_lost_before_the_next_run_is_fetched_again() {
        let w = world();
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 14));
        let st = PartialState::new(store.clone(), w.root);
        let honest = Honest { world: w.nodes, store: store.clone(), calls: AtomicUsize::new(0) };
        let hashes: BlockHashes = Arc::new(|_| None);
        let runs = AtomicUsize::new(0);
        let out = run_rounds(&st, &hashes, &honest, None, OnMiss::Fetch, 40, |db| {
            // Before the second run, other requests push the first fetch out of the cache.
            if runs.fetch_add(1, Ordering::SeqCst) == 1 {
                for i in 0u64..64 {
                    store.put(keccak256(i.to_be_bytes()), Bytes::from(vec![0; 1024]));
                }
            }
            read_through_proxy(db)
        })
        .await
        .unwrap();
        // The lost fetch costs one more fetch and run than `proxy_impl_mapping_converges`.
        assert_eq!((out.value, out.rounds), (U256::from(4242), 6));
        assert_eq!(honest.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn a_failing_fetch_is_reported() {
        struct Down;
        #[async_trait]
        impl Fetcher for Down {
            async fn fetch(&self, _: B256, _: &[MissKey]) -> Result<(), FetchError> {
                Err(FetchError::NoSource)
            }
        }
        let (st, _, hashes) = setup();
        let err = run_rounds(&st, &hashes, &Down, None, OnMiss::Fetch, 5, read_through_proxy)
            .await
            .unwrap_err();
        assert_eq!(err, RoundsError::Fetch(FetchError::NoSource));
    }

    #[tokio::test]
    async fn a_run_that_completes_with_a_real_zero_is_a_result() {
        // A slot that is genuinely zero in complete state is an answer, not a miss.
        let (st, honest, hashes) = setup();
        let out = run_rounds(&st, &hashes, &honest, None, OnMiss::Fetch, 40, |db| {
            let _ = db.get_account(&IMPL).unwrap();
            db.get_storage(&IMPL, &U256::from(999)).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(out.value, U256::ZERO);
        assert!(out.rounds >= 2);
    }

    #[tokio::test]
    async fn a_panicking_blocking_run_is_aborted_and_frees_its_permit() {
        let (st, honest, hashes) = setup();
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let err = run_rounds_blocking(
            &st,
            &hashes,
            &honest,
            None,
            OnMiss::Fetch,
            40,
            &permits,
            |_: &mut MissingDb| -> U256 { panic!("the run panics") },
        )
        .await
        .unwrap_err();
        assert_eq!(err, RoundsError::Aborted);
        assert_eq!(permits.available_permits(), 1);
        assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_closed_semaphore_aborts_before_any_run() {
        let (st, honest, hashes) = setup();
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        permits.close();
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = runs.clone();
        let err = run_rounds_blocking(
            &st,
            &hashes,
            &honest,
            None,
            OnMiss::Fetch,
            40,
            &permits,
            move |db| {
                counter.fetch_add(1, Ordering::SeqCst);
                read_through_proxy(db)
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err, RoundsError::Aborted);
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use crate::{
        state::PartialState,
        store::{NodeStore, Store},
        testing::{world, Acct, World},
        verify::walk_path,
    };
    use alloy_consensus::{constants::KECCAK_EMPTY, TrieAccount};
    use alloy_primitives::{keccak256, Address, Bytes, U256};
    use alloy_rlp::Decodable;
    use alloy_trie::Nibbles;
    use evm2::evm::Database;
    use proptest::prelude::*;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    const ACCOUNTS: u8 = 6;

    /// An honest source that loses every `drop_every`-th node it would store.
    struct Lossy {
        world: Arc<World>,
        store: Arc<dyn NodeStore>,
        drop_every: Option<usize>,
        sent: AtomicUsize,
    }

    #[async_trait]
    impl Fetcher for Lossy {
        async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
            let get = |h: &B256| self.world.nodes.get(h).cloned();
            for m in misses {
                let nodes = match m {
                    MissKey::Account(a, _) => {
                        walk_path(root, &Nibbles::unpack(keccak256(a)), get).unwrap().nodes
                    }
                    MissKey::Slot(a, slot) => {
                        let leaf = walk_path(root, &Nibbles::unpack(keccak256(a)), get)
                            .unwrap()
                            .value
                            .unwrap();
                        let acct = TrieAccount::decode(&mut leaf.as_slice()).unwrap();
                        walk_path(acct.storage_root, &Nibbles::unpack(keccak256(slot)), get)
                            .unwrap()
                            .nodes
                    }
                    MissKey::Code(h) => vec![(*h, self.world.codes[h].clone())],
                    MissKey::Header(_) => continue,
                };
                for (h, n) in nodes {
                    let i = self.sent.fetch_add(1, Ordering::SeqCst);
                    if self.drop_every.is_none_or(|d| i % d != d - 1) {
                        self.store.put(h, n);
                    }
                }
            }
            Ok(())
        }
    }

    /// Reads where each address depends on the slot read before it, as through a proxy.
    fn chained_reads(plan: &[(u8, u8)], db: &mut MissingDb) -> Vec<String> {
        let mut next = 0u8;
        let mut out = Vec::new();
        for (a, s) in plan {
            let addr = Address::repeat_byte(1 + (a ^ next) % (ACCOUNTS + 2));
            let Ok(acct) = db.get_account(&addr);
            let code_hash = acct.as_ref().map_or(KECCAK_EMPTY, |a| a.code_hash);
            let Ok(code) = db.get_code_by_hash(&code_hash);
            let Ok(value) = db.get_storage(&addr, &U256::from(*s));
            let Ok(hash) = db.get_block_hash(&U256::from(value.byte(0) % 4));
            next = value.byte(0);
            out.push(format!("{acct:?} {:?} {value} {hash}", code.original_bytes()));
        }
        out
    }

    /// A store that other work can empty at once, as a burst of requests empties the cache.
    /// Nodes and code share one map, as in [`Store`].
    #[derive(Default)]
    struct Forgetful(Mutex<HashMap<B256, Bytes>>);

    impl Forgetful {
        fn forget(&self) {
            self.0.lock().unwrap().clear();
        }
    }

    impl NodeStore for Forgetful {
        fn get(&self, hash: &B256) -> Option<Bytes> {
            self.0.lock().unwrap().get(hash).cloned()
        }
        fn put(&self, hash: B256, node: Bytes) {
            self.0.lock().unwrap().insert(hash, node);
        }
        fn code(&self, hash: &B256) -> Option<Bytes> {
            self.get(hash)
        }
        fn put_code(&self, hash: B256, code: Bytes) {
            self.put(hash, code);
        }
        fn bytes(&self) -> u64 {
            0
        }
    }

    /// Balance, code and slots of one account.
    type AcctParts = (u64, Vec<u8>, Vec<(u8, u8)>);

    /// The accounts of a generated world, at addresses 1 to `parts.len()`.
    fn entries(parts: Vec<AcctParts>) -> Vec<(Address, Acct)> {
        parts
            .into_iter()
            .enumerate()
            .map(|(i, (balance, code, slots))| {
                let storage = slots
                    .into_iter()
                    .map(|(k, v)| (U256::from(k), U256::from(v)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect();
                let a = Acct { balance, nonce: 0, code, storage };
                (Address::repeat_byte(i as u8 + 1), a)
            })
            .collect()
    }

    fn acct_parts() -> impl Strategy<Value = AcctParts> {
        (
            any::<u64>(),
            prop_oneof![Just(Vec::new()), prop::collection::vec(any::<u8>(), 1..20)],
            prop::collection::vec((0u8..4, 1u8..), 0..4),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// With a source that loses nodes and a cache that evicts, both drivers return the value
        /// complete state gives, or an error; never the value of a run that missed.
        #[test]
        fn the_drivers_return_the_complete_state_value_or_an_error(
            accts in prop::collection::vec(acct_parts(), ACCOUNTS as usize),
            plan in prop::collection::vec((any::<u8>(), 0u8..4), 1..6),
            drop_every in prop_oneof![Just(None), (2usize..5).prop_map(Some)],
            cap in prop_oneof![Just(600u64), Just(1 << 22)],
            max_rounds in 1u32..12,
        ) {
            let w = Arc::new(world(&entries(accts)));
            let hashes: BlockHashes = Arc::new(|n| (n < 2).then(|| keccak256(n.to_be_bytes())));

            let full: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
            for (h, n) in w.nodes.iter().chain(w.codes.iter()) {
                full.put(*h, n.clone());
            }
            let mut complete = MissingDb::new(PartialState::new(full, w.root), hashes.clone());
            let want = chained_reads(&plan, &mut complete);
            let complete_misses = complete.take_misses();
            prop_assert!(
                complete_misses.iter().all(|k| matches!(k, MissKey::Header(_))),
                "{:?}",
                complete_misses
            );

            let plan_len = plan.len();
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            for blocking in [false, true] {
                let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(cap));
                let st = PartialState::new(store.clone(), w.root);
                let lossy =
                    Lossy { world: w.clone(), store, drop_every, sent: AtomicUsize::new(0) };
                let permits = Arc::new(tokio::sync::Semaphore::new(1));
                let plan = plan.clone();
                let got = rt.block_on(async {
                    if blocking {
                        run_rounds_blocking(
                            &st, &hashes, &lossy, None, OnMiss::Fetch, max_rounds, &permits,
                            move |db| chained_reads(&plan, db),
                        )
                        .await
                    } else {
                        run_rounds(&st, &hashes, &lossy, None, OnMiss::Fetch, max_rounds, |db| {
                            chained_reads(&plan, db)
                        })
                        .await
                    }
                });
                // Each step costs at most an account round and a slot and code round.
                let enough = u32::try_from(2 * plan_len + 1).unwrap();
                if drop_every.is_none() && cap > 600 && max_rounds >= enough &&
                    complete_misses.is_empty()
                {
                    prop_assert!(got.is_ok(), "{:?}", got);
                }
                match got {
                    Ok(r) => {
                        prop_assert!(complete_misses.is_empty());
                        prop_assert_eq!(&r.value, &want);
                    }
                    Err(RoundsError::BlockHashUnavailable(_)) => {
                        prop_assert!(!complete_misses.is_empty());
                    }
                    Err(RoundsError::NoProgress(_) | RoundsError::TooManyRounds(_)) => {}
                    Err(e) => prop_assert!(false, "unexpected {:?}", e),
                }
            }
        }

        /// An honest source whose fetches the cache loses before the next run never ends the
        /// rounds with `NoProgress`: the driver fetches again, and any result is the value
        /// complete state gives.
        #[test]
        fn a_fetch_lost_between_rounds_is_fetched_again(
            accts in prop::collection::vec(acct_parts(), ACCOUNTS as usize),
            plan in prop::collection::vec((any::<u8>(), 0u8..4), 1..6),
            forget in prop::collection::vec(any::<bool>(), 12),
        ) {
            let w = Arc::new(world(&entries(accts)));
            let hashes: BlockHashes = Arc::new(|n| (n < 2).then(|| keccak256(n.to_be_bytes())));
            let full: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
            for (h, n) in w.nodes.iter().chain(w.codes.iter()) {
                full.put(*h, n.clone());
            }
            let mut complete = MissingDb::new(PartialState::new(full, w.root), hashes.clone());
            let want = chained_reads(&plan, &mut complete);
            let complete_misses = complete.take_misses();

            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            for blocking in [false, true] {
                let store = Arc::new(Forgetful::default());
                let st = PartialState::new(store.clone(), w.root);
                let honest =
                    Lossy { world: w.clone(), store: store.clone(), drop_every: None, sent: AtomicUsize::new(0) };
                let permits = Arc::new(tokio::sync::Semaphore::new(1));
                let runs = AtomicUsize::new(0);
                let (plan, forget) = (plan.clone(), forget.clone());
                // Before some runs, other work empties the cache.
                let run = move |db: &mut MissingDb| {
                    if forget.get(runs.fetch_add(1, Ordering::SeqCst)).copied().unwrap_or(false) {
                        store.forget();
                    }
                    chained_reads(&plan, db)
                };
                let got = rt.block_on(async {
                    if blocking {
                        run_rounds_blocking(&st, &hashes, &honest, None, OnMiss::Fetch, 40, &permits, run)
                            .await
                    } else {
                        run_rounds(&st, &hashes, &honest, None, OnMiss::Fetch, 40, run).await
                    }
                });
                match got {
                    Ok(r) => {
                        prop_assert!(complete_misses.is_empty());
                        prop_assert_eq!(&r.value, &want);
                    }
                    Err(RoundsError::BlockHashUnavailable(_)) => {
                        prop_assert!(!complete_misses.is_empty());
                    }
                    Err(e) => prop_assert!(false, "unexpected {:?} (blocking: {})", e, blocking),
                }
            }
        }
    }
}
