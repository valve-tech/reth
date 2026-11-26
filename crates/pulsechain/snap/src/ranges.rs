//! Serving `GetAccountRange` (`0x00`) and `GetStorageRanges` (`0x02`).
//!
//! A port of upstream's private `StateRangeRequest::serve_*` (`reth-network`'s `eth_requests`)
//! onto the public [`StateRangeProviderFactory`] trait, with go-pulse's limits:
//!
//! - The response budget is the requested byte count, capped at [`SOFT_RESPONSE_LIMIT`] minus
//!   [`PROOF_RESERVE`]. The reserve keeps the whole encoded response, proof included, under the 2
//!   MiB limit even when a client asks for more.
//! - At most [`MAX_STORAGE_RANGE_ACCOUNTS_SERVE`] accounts are looked up for storage.
//! - An account range stops once it has spent [`MAX_RANGE_TIME`], checked after each storage root,
//!   and proves the accounts it served.
//! - An unknown root answers empty. It never fails the request.
//! - The first account at or after `origin` is always returned, even past `limit`, so the empty
//!   range `[origin, limit]` is proven by the neighbour. The provider's range scan does this; the
//!   proof then covers `origin` and the last returned key.

use crate::bytecodes::SOFT_RESPONSE_LIMIT;
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use reth_eth_wire_types::snap::{
    AccountData, AccountRangeMessage, GetAccountRangeMessage, GetStorageRangesMessage, StorageData,
    StorageRangesMessage,
};
use reth_storage_api::{
    errors::provider::ProviderResult, RangeEnd, RangeResponse, StateRangeProviderFactory,
};
use std::time::{Duration, Instant};

/// The most accounts one `GetStorageRanges` request reads storage for, as in go-ethereum.
pub const MAX_STORAGE_RANGE_ACCOUNTS_SERVE: usize = 1024;

/// Bytes of the 2 MiB limit kept back for proof nodes.
pub const PROOF_RESERVE: usize = 64 * 1024;

/// The bytes the provider counts for one storage slot.
const PROVIDER_SLOT_BYTES: usize = 64;

/// The most bytes one storage slot encodes to: a list header (2), the hash (33), and the
/// RLP-encoded value (33 for a full 32-byte value) as a byte string (34).
const MAX_SLOT_ENCODED_BYTES: usize = 69;

fn budget(requested: u64) -> usize {
    usize::try_from(requested).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT - PROOF_RESERVE)
}

/// Answers a `GetAccountRange` request.
///
/// A zero-origin range that exhausts the trie carries no proof; every other range proves `origin`
/// and the last returned key.
pub fn serve_account_range<F: StateRangeProviderFactory>(
    factory: &F,
    req: &GetAccountRangeMessage,
) -> ProviderResult<AccountRangeMessage> {
    let start = Instant::now();
    serve_account_range_with_clock(factory, req, || start.elapsed())
}

/// The longest one `GetAccountRange` request spends before it stops, as for trie nodes.
pub const MAX_RANGE_TIME: Duration = Duration::from_secs(5);

/// Like [`serve_account_range`], with an injectable clock that returns the time spent so far. It
/// is read after each storage root is computed.
pub(crate) fn serve_account_range_with_clock<F: StateRangeProviderFactory>(
    factory: &F,
    req: &GetAccountRangeMessage,
    mut elapsed: impl FnMut() -> Duration,
) -> ProviderResult<AccountRangeMessage> {
    let empty =
        AccountRangeMessage { request_id: req.request_id, accounts: Vec::new(), proof: Vec::new() };
    let Some(state) = factory.state_range_provider(req.root_hash)? else { return Ok(empty) };
    let RangeResponse { items: accounts, mut end } =
        state.account_range(req.starting_hash, req.limit_hash, budget(req.response_bytes))?;

    // A storage root can take long, so the range is cut once the time limit passes. The proof
    // is built after the cut, for the accounts actually served.
    let total = accounts.len();
    let mut data = Vec::with_capacity(total);
    for (hash, account) in accounts {
        let storage_root = state.storage_root_by_hash(hash)?;
        data.push(AccountData::from_trie_account(hash, &account.into_trie_account(storage_root)));
        if elapsed() > MAX_RANGE_TIME {
            break
        }
    }
    if data.len() < total {
        end = RangeEnd::ByteLimit;
    }

    let proof = if req.starting_hash.is_zero() && end == RangeEnd::Exhausted {
        Vec::new()
    } else {
        state.account_range_proof(&boundary_keys(req.starting_hash, data.last().map(|a| a.hash)))?
    };
    Ok(AccountRangeMessage { request_id: req.request_id, accounts: data, proof })
}

/// Answers a `GetStorageRanges` request.
///
/// `origin` and `limit` apply to the first account only. An account missing at this root makes
/// the whole response empty rather than shifting later accounts' positions. The response stops at
/// the first account whose range is not complete from the zero origin, and proves that range.
pub fn serve_storage_ranges<F: StateRangeProviderFactory>(
    factory: &F,
    req: &GetStorageRangesMessage,
) -> ProviderResult<StorageRangesMessage> {
    let empty =
        StorageRangesMessage { request_id: req.request_id, slots: Vec::new(), proof: Vec::new() };
    let Some(state) = factory.state_range_provider(req.root_hash)? else { return Ok(empty) };
    let mut slots: Vec<Vec<StorageData>> = Vec::new();
    let mut proof = Vec::new();
    let mut remaining = budget(req.response_bytes);

    for (i, &account) in
        req.account_hashes.iter().take(MAX_STORAGE_RANGE_ACCOUNTS_SERVE).enumerate()
    {
        // Storage-empty accounts are still walked under a zero budget, so a real slot gets
        // served; the take() above bounds the lookups.
        if remaining == 0 && slots.iter().any(|range| !range.is_empty()) {
            break
        }
        let (origin, limit) = if i == 0 {
            (
                req.starting_hash.unwrap_or(B256::ZERO),
                req.limit_hash.unwrap_or(B256::repeat_byte(0xff)),
            )
        } else {
            (B256::ZERO, B256::repeat_byte(0xff))
        };
        // The provider counts 64 bytes a slot, but a slot encodes to up to
        // `MAX_SLOT_ENCODED_BYTES`. Scale its budget so it returns no more slots than fit, then
        // count the real sizes.
        let scan = remaining / MAX_SLOT_ENCODED_BYTES * PROVIDER_SLOT_BYTES;
        let Some(RangeResponse { items, mut end }) =
            state.storage_range(account, origin, limit, scan)?
        else {
            return Ok(empty)
        };

        let mut range = Vec::with_capacity(items.len());
        for (hash, value) in items {
            let slot = StorageData::from_value(hash, value);
            let len = slot.length();
            // Stop after the slot that crosses the budget, as the provider does. One slot is
            // always served, so a zero budget still makes progress.
            if remaining == 0 && (!range.is_empty() || slots.iter().any(|r| !r.is_empty())) {
                end = RangeEnd::ByteLimit;
                break
            }
            remaining = remaining.saturating_sub(len);
            range.push(slot);
        }
        let last = range.last().map(|slot| slot.hash);
        let needs_proof = !origin.is_zero() || end != RangeEnd::Exhausted;
        slots.push(range);
        if needs_proof {
            proof = state.storage_range_proof(account, &boundary_keys(origin, last))?;
            break
        }
    }
    Ok(StorageRangesMessage { request_id: req.request_id, slots, proof })
}

fn boundary_keys(origin: B256, last: Option<B256>) -> Vec<B256> {
    last.map_or_else(|| vec![origin], |last| vec![origin, last])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{verify_key, FakeFactory, FakeState};
    use alloy_primitives::{keccak256, Bytes, U256};
    use alloy_trie::EMPTY_ROOT_HASH;
    use reth_eth_wire_types::snap::RangeBound;

    const MIB2: usize = 2 * 1024 * 1024;

    fn setup() -> (FakeFactory, B256, FakeState) {
        let state = FakeState::generated(200, 300);
        let mut f = FakeFactory::default();
        let root = f.add(state.clone());
        (f, root, state)
    }

    fn account_req(root: B256, origin: B256, limit: B256, bytes: u64) -> GetAccountRangeMessage {
        GetAccountRangeMessage {
            request_id: 7,
            root_hash: root,
            starting_hash: origin,
            limit_hash: limit,
            response_bytes: bytes,
        }
    }

    #[test]
    fn single_key_account_with_verifiable_proof() {
        let (f, root, state) = setup();
        let (key, acc) = state.accounts.iter().nth(50).unwrap();
        let resp = serve_account_range(&f, &account_req(root, *key, *key, 1)).unwrap();
        assert_eq!(resp.request_id, 7);
        assert_eq!(resp.accounts.len(), 1);
        assert_eq!(resp.accounts[0].hash, *key);
        assert_eq!(resp.accounts[0].trie_account(), acc.trie_account());
        let leaf = alloy_rlp::encode(resp.accounts[0].trie_account());
        verify_key(root, *key, Some(leaf), &resp.proof).unwrap();
    }

    #[test]
    fn absent_key_returns_neighbour_and_proof_of_absence() {
        let (f, root, state) = setup();
        let mut absent = *state.accounts.keys().nth(80).unwrap();
        absent.0[31] ^= 1;
        assert!(!state.accounts.contains_key(&absent));
        let resp = serve_account_range(&f, &account_req(root, absent, absent, 1)).unwrap();
        // The first account past the key comes back even though it is beyond the limit.
        assert_eq!(resp.accounts.len(), 1);
        assert!(resp.accounts[0].hash > absent);
        verify_key(root, absent, None, &resp.proof).unwrap();
        let neighbour = resp.accounts[0].hash;
        let leaf = alloy_rlp::encode(resp.accounts[0].trie_account());
        verify_key(root, neighbour, Some(leaf), &resp.proof).unwrap();
    }

    #[test]
    fn unknown_root_answers_empty() {
        let (f, _, _) = setup();
        let resp = serve_account_range(&f, &account_req(keccak256("x"), B256::ZERO, B256::ZERO, 1))
            .unwrap();
        assert!(resp.accounts.is_empty() && resp.proof.is_empty());
        let req = GetStorageRangesMessage {
            request_id: 1,
            root_hash: keccak256("x"),
            account_hashes: vec![B256::ZERO],
            starting_hash: RangeBound::default(),
            limit_hash: RangeBound::default(),
            response_bytes: 1,
        };
        let resp = serve_storage_ranges(&f, &req).unwrap();
        assert!(resp.slots.is_empty() && resp.proof.is_empty());
    }

    #[test]
    fn tampered_proof_fails_the_independent_verifier() {
        let (f, root, state) = setup();
        let key = *state.accounts.keys().nth(20).unwrap();
        let resp = serve_account_range(&f, &account_req(root, key, key, 1)).unwrap();
        let leaf = alloy_rlp::encode(resp.accounts[0].trie_account());
        verify_key(root, key, Some(leaf.clone()), &resp.proof).unwrap();

        // Flip one byte in each node in turn: every variant must be rejected.
        for i in 0..resp.proof.len() {
            let mut proof = resp.proof.clone();
            let mut node = proof[i].to_vec();
            let last = node.len() - 1;
            node[last] ^= 1;
            proof[i] = Bytes::from(node);
            assert!(
                verify_key(root, key, Some(leaf.clone()), &proof).is_err(),
                "tampered node {i} accepted"
            );
        }
        // A wrong value is rejected too.
        let mut other = state.accounts[&key].trie_account();
        other.balance += U256::from(1);
        assert!(verify_key(root, key, Some(alloy_rlp::encode(other)), &resp.proof).is_err());
    }

    #[test]
    fn account_response_never_exceeds_two_mib() {
        // Enough accounts that an uncapped request would need well over 2 MiB.
        let state = FakeState::generated(20_000, 0);
        let mut f = FakeFactory::default();
        let root = f.add(state);
        let req = account_req(root, B256::ZERO, B256::repeat_byte(0xff), u64::MAX);
        let resp = serve_account_range(&f, &req).unwrap();
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        assert!(buf.len() <= MIB2, "{} bytes", buf.len());
        assert!(resp.accounts.len() > 1000, "served too little: {}", resp.accounts.len());
        assert!(!resp.proof.is_empty(), "a cut range carries a proof");
    }

    #[test]
    fn complete_zero_origin_account_range_has_no_proof() {
        let state = FakeState::generated(30, 0);
        let n = state.accounts.len();
        let mut f = FakeFactory::default();
        let root = f.add(state);
        let resp = serve_account_range(
            &f,
            &account_req(root, B256::ZERO, B256::repeat_byte(0xff), 1 << 20),
        )
        .unwrap();
        assert_eq!(resp.accounts.len(), n);
        assert!(resp.proof.is_empty());
    }

    fn storage_req(root: B256, acct: B256, origin: B256, limit: B256) -> GetStorageRangesMessage {
        GetStorageRangesMessage {
            request_id: 9,
            root_hash: root,
            account_hashes: vec![acct],
            starting_hash: origin.into(),
            limit_hash: limit.into(),
            response_bytes: 1,
        }
    }

    #[test]
    fn single_slot_with_verifiable_proof() {
        let (f, root, state) = setup();
        let (acct, fa) = state.accounts.iter().find(|(_, a)| a.storage.len() > 100).unwrap();
        let storage_root = fa.storage_root();
        let (slot, value) = fa.storage.iter().nth(40).unwrap();
        let resp = serve_storage_ranges(&f, &storage_req(root, *acct, *slot, *slot)).unwrap();
        assert_eq!(resp.slots.len(), 1);
        assert_eq!(resp.slots[0][0].hash, *slot);
        assert_eq!(resp.slots[0][0].value().unwrap(), *value);
        verify_key(storage_root, *slot, Some(alloy_rlp::encode(value)), &resp.proof).unwrap();

        let mut proof = resp.proof;
        let mut node = proof[0].to_vec();
        node[5] ^= 1;
        proof[0] = node.into();
        assert!(verify_key(storage_root, *slot, Some(alloy_rlp::encode(value)), &proof).is_err());
    }

    #[test]
    fn absent_slot_returns_neighbour_and_proof_of_absence() {
        let (f, root, state) = setup();
        let (acct, fa) = state.accounts.iter().find(|(_, a)| a.storage.len() > 100).unwrap();
        let mut absent = *fa.storage.keys().nth(60).unwrap();
        absent.0[31] ^= 1;
        assert!(!fa.storage.contains_key(&absent));
        let resp = serve_storage_ranges(&f, &storage_req(root, *acct, absent, absent)).unwrap();
        assert_eq!(resp.slots[0].len(), 1);
        assert!(resp.slots[0][0].hash > absent);
        verify_key(fa.storage_root(), absent, None, &resp.proof).unwrap();
    }

    #[test]
    fn missing_account_makes_storage_response_empty() {
        let (f, root, _) = setup();
        let resp = serve_storage_ranges(
            &f,
            &storage_req(root, keccak256("none"), B256::ZERO, B256::repeat_byte(0xff)),
        )
        .unwrap();
        assert!(resp.slots.is_empty() && resp.proof.is_empty());
    }

    #[test]
    fn complete_zero_origin_storage_has_no_proof() {
        let (f, root, state) = setup();
        let (acct, fa) = state.accounts.iter().find(|(_, a)| !a.storage.is_empty()).unwrap();
        let mut req = storage_req(root, *acct, B256::ZERO, B256::repeat_byte(0xff));
        req.response_bytes = 1 << 20;
        let resp = serve_storage_ranges(&f, &req).unwrap();
        assert_eq!(resp.slots[0].len(), fa.storage.len());
        assert!(resp.proof.is_empty());
    }

    #[test]
    fn storage_response_never_exceeds_two_mib() {
        let state = FakeState::generated(1, 60_000);
        let acct = *state.accounts.keys().next().unwrap();
        let mut f = FakeFactory::default();
        let root = f.add(state);
        let mut req = storage_req(root, acct, B256::ZERO, B256::repeat_byte(0xff));
        req.response_bytes = u64::MAX;
        let resp = serve_storage_ranges(&f, &req).unwrap();
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        assert!(buf.len() <= MIB2, "{} bytes", buf.len());
        assert!(resp.slots[0].len() > 1000);
        assert!(!resp.proof.is_empty(), "a cut range carries a proof");
    }

    #[test]
    fn account_range_stops_at_the_time_limit_and_proves_what_it_served() {
        use crate::test_utils::CountingFactory;
        use std::sync::atomic::Ordering;
        let state = FakeState::generated(200, 0);
        let mut factory = CountingFactory::default();
        let root = factory.inner.add(state.clone());
        let counts = factory.counts.clone();
        let req = account_req(root, B256::ZERO, B256::repeat_byte(0xff), 1 << 20);
        // The third storage root takes the request past the limit.
        let resp = serve_account_range_with_clock(&factory, &req, || {
            if counts.storage_roots.load(Ordering::SeqCst) >= 3 {
                MAX_RANGE_TIME + Duration::from_secs(1)
            } else {
                Duration::ZERO
            }
        })
        .unwrap();
        assert_eq!(resp.accounts.len(), 3);
        assert_eq!(factory.counts.storage_roots.load(Ordering::SeqCst), 3);
        let last = resp.accounts.last().unwrap();
        let leaf = alloy_rlp::encode(last.trie_account());
        verify_key(root, last.hash, Some(leaf), &resp.proof).unwrap();
        assert_eq!(last.trie_account(), state.accounts[&last.hash].trie_account());
    }

    /// Full 32-byte values encode to 69 bytes a slot, more than the 64 the provider counts.
    fn full_width(accounts: u64, slots: u64) -> FakeState {
        let mut state = FakeState::generated(accounts, slots);
        for account in state.accounts.values_mut() {
            for value in account.storage.values_mut() {
                *value = U256::MAX - *value;
            }
        }
        state
    }

    #[test]
    fn full_width_storage_response_never_exceeds_two_mib() {
        let state = full_width(1, 60_000);
        let acct = *state.accounts.keys().next().unwrap();
        let storage_root = state.accounts[&acct].storage_root();
        let mut f = FakeFactory::default();
        let root = f.add(state);
        let mut req = storage_req(root, acct, B256::ZERO, B256::repeat_byte(0xff));
        req.response_bytes = u64::MAX;
        let resp = serve_storage_ranges(&f, &req).unwrap();
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        assert!(buf.len() <= MIB2, "{} bytes", buf.len());
        assert!(resp.slots[0].len() > 25_000, "served too little: {}", resp.slots[0].len());
        // The cut range is proven up to the last slot served.
        let (last, value) = resp.slots[0].last().map(|s| (s.hash, s.value().unwrap())).unwrap();
        verify_key(storage_root, last, Some(alloy_rlp::encode(value)), &resp.proof).unwrap();
    }

    #[test]
    fn full_width_storage_over_many_accounts_never_exceeds_two_mib() {
        // 30 accounts with storage, 2000 full-width slots each: about 4 MiB in all.
        let state = full_width(300, 2000);
        let accounts: Vec<B256> = state
            .accounts
            .iter()
            .filter(|(_, a)| !a.storage.is_empty())
            .map(|(hash, _)| *hash)
            .collect();
        let mut f = FakeFactory::default();
        let root = f.add(state);
        let req = GetStorageRangesMessage {
            request_id: 9,
            root_hash: root,
            account_hashes: accounts,
            starting_hash: RangeBound::default(),
            limit_hash: RangeBound::default(),
            response_bytes: u64::MAX,
        };
        let resp = serve_storage_ranges(&f, &req).unwrap();
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        assert!(buf.len() <= MIB2, "{} bytes", buf.len());
        assert!(resp.slots.len() > 10, "served too little: {}", resp.slots.len());
    }

    /// A hash relative to a sorted key list: zero, the largest hash, a key, a hash next to a
    /// key, or any hash.
    #[derive(Debug, Clone, Copy)]
    enum Pick {
        Zero,
        Max,
        Key(proptest::sample::Index),
        NextTo(proptest::sample::Index),
        Any(B256),
    }

    impl Pick {
        fn strategy() -> impl proptest::strategy::Strategy<Value = Self> {
            use proptest::prelude::*;
            prop_oneof![
                Just(Self::Zero),
                Just(Self::Max),
                any::<proptest::sample::Index>().prop_map(Self::Key),
                any::<proptest::sample::Index>().prop_map(Self::NextTo),
                any::<[u8; 32]>().prop_map(|b| Self::Any(B256::from(b))),
            ]
        }

        fn resolve(self, keys: &[B256]) -> B256 {
            match self {
                Self::Max => B256::repeat_byte(0xff),
                Self::Key(i) if !keys.is_empty() => keys[i.index(keys.len())],
                Self::NextTo(i) if !keys.is_empty() => {
                    let mut key = keys[i.index(keys.len())];
                    key.0[31] ^= 1;
                    key
                }
                // With no keys to pick from, a key pick is zero.
                Self::Zero | Self::Key(_) | Self::NextTo(_) => B256::ZERO,
                Self::Any(hash) => hash,
            }
        }
    }

    fn budget_strategy() -> impl proptest::strategy::Strategy<Value = u64> {
        use proptest::prelude::*;
        prop_oneof![Just(0u64), 1u64..20_000, Just(u64::MAX)]
    }

    /// Flips one byte of one proof node, picked by `node`, `at` and the non-zero `xor`.
    fn tamper(
        proof: &[Bytes],
        node: proptest::sample::Index,
        at: proptest::sample::Index,
        xor: u8,
    ) -> Vec<Bytes> {
        let mut proof = proof.to_vec();
        let i = node.index(proof.len());
        let mut bytes = proof[i].to_vec();
        let j = at.index(bytes.len());
        bytes[j] ^= xor;
        proof[i] = bytes.into();
        proof
    }

    /// Every account range answer is the ordered run of accounts from `origin`, cut only after
    /// the first account past `limit`, under 2 MiB. It has no proof only when it is the whole
    /// trie from zero; otherwise its proof proves `origin` and the last account, and fails once
    /// any one byte of it changes.
    #[test]
    fn account_ranges_are_proven_runs_from_the_origin() {
        use proptest::prelude::*;
        let state = FakeState::generated(200, 30);
        let mut f = FakeFactory::default();
        let root = f.add(state.clone());
        let keys: Vec<B256> = state.accounts.keys().copied().collect();
        let leaf =
            |hash: &B256| state.accounts.get(hash).map(|a| alloy_rlp::encode(a.trie_account()));
        let input = (
            Pick::strategy(),
            Pick::strategy(),
            budget_strategy(),
            (any::<proptest::sample::Index>(), any::<proptest::sample::Index>(), 1u8..=255),
        );
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(128));
        runner
            .run(&input, |(origin, limit, bytes, (node, at, xor))| {
                let (origin, limit) = (origin.resolve(&keys), limit.resolve(&keys));
                let resp = serve_account_range(&f, &account_req(root, origin, limit, bytes))?;
                prop_assert!(resp.length() <= MIB2, "{} bytes", resp.length());
                let from_origin: Vec<_> = state.accounts.range(origin..).collect();
                prop_assert_eq!(resp.accounts.is_empty(), from_origin.is_empty());
                for (got, (hash, account)) in resp.accounts.iter().zip(&from_origin) {
                    prop_assert_eq!(got.hash, **hash);
                    prop_assert_eq!(got.trie_account(), account.trie_account());
                }
                if let Some((_, before_last)) = resp.accounts.split_last() {
                    prop_assert!(
                        before_last.iter().all(|a| a.hash < limit),
                        "served past the limit"
                    );
                }
                if resp.proof.is_empty() {
                    prop_assert!(origin.is_zero() && resp.accounts.len() == keys.len());
                    return Ok(())
                }
                let last = resp.accounts.last().map(|a| a.hash);
                let verify = |proof: &[Bytes]| {
                    verify_key(root, origin, leaf(&origin), proof).is_ok() &&
                        last.is_none_or(|last| {
                            verify_key(root, last, leaf(&last), proof).is_ok()
                        })
                };
                prop_assert!(verify(&resp.proof), "proof does not verify");
                prop_assert!(
                    !verify(&tamper(&resp.proof, node, at, xor)),
                    "tampered proof verifies"
                );
                Ok(())
            })
            .unwrap();
    }

    /// An account hash for a storage request: one with storage, one without, or one missing.
    #[derive(Debug, Clone, Copy)]
    enum Owner {
        WithStorage(proptest::sample::Index),
        Empty(proptest::sample::Index),
        Missing,
    }

    /// Every storage ranges answer gives, for each served position, the run of slots of the
    /// requested account; `origin` and `limit` bind the first account only. Every range but the
    /// last is complete from zero. The last range has no proof only when it is complete from
    /// zero; otherwise its proof proves `origin` and its last slot, and fails once any one byte
    /// changes. An answer never serves a position of a missing account.
    #[test]
    fn storage_ranges_are_proven_runs_from_the_origin() {
        use proptest::prelude::*;
        let state = FakeState::generated(200, 30);
        let mut f = FakeFactory::default();
        let root = f.add(state.clone());
        let (with, without): (Vec<B256>, Vec<B256>) =
            state.accounts.keys().partition(|hash| !state.accounts[*hash].storage.is_empty());
        let owner = prop_oneof![
            4 => any::<proptest::sample::Index>().prop_map(Owner::WithStorage),
            4 => any::<proptest::sample::Index>().prop_map(Owner::Empty),
            1 => Just(Owner::Missing),
        ];
        let owners = prop_oneof![
            8 => proptest::collection::vec(owner, 0..12),
            1 => proptest::collection::vec(any::<proptest::sample::Index>().prop_map(Owner::Empty), 1000..1100),
        ];
        // A limit above every slot of a first account lets later accounts be served.
        let limit = prop_oneof![
            Pick::strategy(),
            any::<[u8; 32]>().prop_map(|b| Pick::Any(B256::from(b))),
        ];
        let input = (
            owners,
            proptest::option::of(Pick::strategy()),
            proptest::option::of(limit),
            budget_strategy(),
            (any::<proptest::sample::Index>(), any::<proptest::sample::Index>(), 1u8..=255),
        );
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
        runner
            .run(&input, |(owners, origin, limit, bytes, (node, at, xor))| {
                let account_hashes: Vec<B256> = owners
                    .iter()
                    .map(|o| match *o {
                        Owner::WithStorage(i) => with[i.index(with.len())],
                        Owner::Empty(i) => without[i.index(without.len())],
                        Owner::Missing => keccak256("missing"),
                    })
                    .collect();
                // Bounds are picked among the slots of the first account.
                let first_slots: Vec<B256> = account_hashes
                    .first()
                    .and_then(|h| state.accounts.get(h))
                    .map(|a| a.storage.keys().copied().collect())
                    .unwrap_or_default();
                let origin = origin.map(|p| p.resolve(&first_slots));
                let limit = limit.map(|p| p.resolve(&first_slots));
                let req = GetStorageRangesMessage {
                    request_id: 9,
                    root_hash: root,
                    account_hashes: account_hashes.clone(),
                    starting_hash: origin.map(RangeBound::from).unwrap_or_default(),
                    limit_hash: limit.map(RangeBound::from).unwrap_or_default(),
                    response_bytes: bytes,
                };
                let resp = serve_storage_ranges(&f, &req)?;
                prop_assert!(resp.length() <= MIB2, "{} bytes", resp.length());
                let looked_up = account_hashes.len().min(MAX_STORAGE_RANGE_ACCOUNTS_SERVE);
                prop_assert!(resp.slots.len() <= looked_up);
                let missing =
                    account_hashes[..looked_up].iter().any(|h| !state.accounts.contains_key(h));
                // Serving stops at a cut range, so only a missing account it reaches empties it.
                prop_assert!(!resp.slots.is_empty() || missing || looked_up == 0);
                prop_assert!(account_hashes[..resp.slots.len()]
                    .iter()
                    .all(|h| state.accounts.contains_key(h)));
                let Some(last_index) = resp.slots.len().checked_sub(1) else {
                    prop_assert!(resp.proof.is_empty());
                    return Ok(())
                };

                for (i, range) in resp.slots.iter().enumerate() {
                    let storage = &state.accounts[&account_hashes[i]].storage;
                    let (origin, limit) = if i == 0 {
                        (origin.unwrap_or(B256::ZERO), limit.unwrap_or(B256::repeat_byte(0xff)))
                    } else {
                        (B256::ZERO, B256::repeat_byte(0xff))
                    };
                    let from_origin: Vec<_> = storage.range(origin..).collect();
                    prop_assert!(range.len() <= from_origin.len());
                    for (got, (hash, value)) in range.iter().zip(&from_origin) {
                        prop_assert_eq!(got.hash, **hash);
                        prop_assert_eq!(got.value().unwrap(), **value);
                    }
                    if let Some((_, before_last)) = range.split_last() {
                        prop_assert!(
                            before_last.iter().all(|s| s.hash < limit),
                            "served past the limit"
                        );
                    }
                    let complete = origin.is_zero() && range.len() == storage.len();
                    // All the fixture's storage fits a 1 MiB budget, and later accounts have no
                    // limit, so only the first range can be cut.
                    if i > 0 && bytes >= 1 << 20 {
                        prop_assert!(complete, "range {} is cut", i);
                    }
                    if i < last_index {
                        prop_assert!(complete, "range {} is cut but not last", i);
                    } else if resp.proof.is_empty() {
                        prop_assert!(complete, "the last range is cut but carries no proof");
                    } else {
                        let account = &state.accounts[&account_hashes[i]];
                        let storage_root = account.storage_root();
                        let leaf = |hash: &B256| storage.get(hash).map(alloy_rlp::encode);
                        let last = range.last().map(|s| s.hash);
                        let verify = |proof: &[Bytes]| {
                            verify_key(storage_root, origin, leaf(&origin), proof).is_ok() &&
                                last.is_none_or(|last| {
                                    verify_key(storage_root, last, leaf(&last), proof).is_ok()
                                })
                        };
                        prop_assert!(verify(&resp.proof), "proof does not verify");
                        // The empty trie verifies with no node, so its proof has none to tamper.
                        prop_assert!(
                            storage_root == EMPTY_ROOT_HASH ||
                                !verify(&tamper(&resp.proof, node, at, xor)),
                            "tampered proof verifies"
                        );
                    }
                }
                Ok(())
            })
            .unwrap();
    }

    fn storage_request(account_hashes: Vec<B256>, root: B256) -> GetStorageRangesMessage {
        GetStorageRangesMessage {
            request_id: 9,
            root_hash: root,
            account_hashes,
            starting_hash: RangeBound::default(),
            limit_hash: RangeBound::default(),
            response_bytes: u64::MAX,
        }
    }

    #[test]
    fn storage_ranges_look_up_at_most_the_account_cap() {
        let state = FakeState::generated(1200, 0);
        let hashes: Vec<B256> = state.accounts.keys().copied().collect();
        let mut f = FakeFactory::default();
        let root = f.add(state);
        let resp = serve_storage_ranges(&f, &storage_request(hashes, root)).unwrap();
        assert_eq!(resp.slots.len(), MAX_STORAGE_RANGE_ACCOUNTS_SERVE);
        assert!(resp.slots.iter().all(Vec::is_empty) && resp.proof.is_empty());
    }

    #[test]
    fn a_missing_account_after_served_ranges_empties_the_answer() {
        let (f, root, state) = setup();
        let present: Vec<B256> = state.accounts.keys().copied().take(5).collect();
        for at in [2, 5] {
            let mut hashes = present.clone();
            hashes.insert(at, keccak256("none"));
            let resp = serve_storage_ranges(&f, &storage_request(hashes, root)).unwrap();
            assert!(resp.slots.is_empty() && resp.proof.is_empty(), "missing at {at}");
        }
        // Without the missing account the same request is served.
        let resp = serve_storage_ranges(&f, &storage_request(present, root)).unwrap();
        assert_eq!(resp.slots.len(), 5);
    }
}
