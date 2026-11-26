//! `--state.hot-set=N`: count the accounts and slots reads hit most, and after each new verified
//! head re-fetch their proofs in bounded batches so the next reads at the new head are local.
//! Counts halve at each head, so recent hits outrank old ones and a key no longer read leaves.

use crate::{chain::HeaderChain, exec::Fetcher, state::MissKey};
use alloy_primitives::{map::AddressSet, Address, B256};
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc, time::Duration};

/// The largest hot set. The map counts up to eight times this many keys, and each new head
/// refetches up to twice this many proofs.
pub const MAX_HOT_SET: usize = 65_536;
/// Misses the refresh sends to peers in one fetch.
const REFRESH_CHUNK: usize = 1_024;

/// What reads hit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hot {
    /// An account.
    Account(Address),
    /// A storage slot.
    Slot(Address, B256),
}

/// A bounded hit counter.
#[derive(Debug)]
pub struct HotSet {
    size: usize,
    counts: Mutex<HashMap<Hot, u64>>,
}

impl HotSet {
    /// A hot set of `size` entries (0 = off), at most [`MAX_HOT_SET`].
    pub fn new(size: usize) -> Self {
        if size > MAX_HOT_SET {
            tracing::warn!(
                size,
                max = MAX_HOT_SET,
                "--state.hot-set is above the maximum; capping it"
            );
        }
        Self { size: size.min(MAX_HOT_SET), counts: Mutex::new(HashMap::new()) }
    }

    /// Whether the hot set is on.
    pub const fn enabled(&self) -> bool {
        self.size > 0
    }

    /// Counts a hit.
    pub fn record(&self, item: Hot) {
        if !self.enabled() {
            return;
        }
        let mut c = self.counts.lock();
        *c.entry(item).or_default() += 1;
        // Bounded: past eight times the size, keep only the leaders.
        if c.len() > self.size.max(16) * 8 {
            *c = leaders(&c, self.size).into_iter().collect();
        }
    }

    /// Halves every count, rounding down, and forgets the keys that reach zero. Called once per
    /// head, so a key that stops being read leaves the set instead of holding its place on an old
    /// count (ties rank by key, so a count of 1 would outlast every later key above it).
    fn decay(&self) {
        self.counts.lock().retain(|_, n| {
            *n /= 2;
            *n > 0
        });
    }

    /// The `size` most hit items, most first.
    pub fn top(&self) -> Vec<Hot> {
        leaders(&self.counts.lock(), self.size).into_iter().map(|(k, _)| k).collect()
    }

    /// How many distinct items are counted.
    pub fn len(&self) -> usize {
        self.counts.lock().len()
    }

    /// Whether nothing is counted.
    pub fn is_empty(&self) -> bool {
        self.counts.lock().is_empty()
    }
}

/// The misses that fetch `items` at a new root: each account not in `seen`, then the slots. A
/// slot fetch that misses its account fetches the account proof itself, so the accounts must land
/// first or a contract with K hot slots costs K extra account proofs.
fn refresh_misses(items: &[Hot], seen: &mut AddressSet) -> [Vec<MissKey>; 2] {
    let (mut accounts, mut slots) = (Vec::new(), Vec::new());
    for h in items {
        let a = match h {
            Hot::Account(a) => *a,
            Hot::Slot(a, s) => {
                slots.push(MissKey::Slot(*a, *s));
                *a
            }
        };
        if seen.insert(a) {
            accounts.push(MissKey::Account(a, None));
        }
    }
    [accounts, slots]
}

/// The `size` entries with the most hits, most first, ties by key. Selection is linear in the
/// map and only the leaders are sorted, so a trim under the lock stays cheap.
fn leaders(c: &HashMap<Hot, u64>, size: usize) -> Vec<(Hot, u64)> {
    let rank = |a: &(&Hot, &u64), b: &(&Hot, &u64)| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0));
    let mut v: Vec<_> = c.iter().collect();
    if v.len() > size {
        v.select_nth_unstable_by(size, rank);
        v.truncate(size);
    }
    v.sort_unstable_by(rank);
    v.into_iter().map(|(k, n)| (k.clone(), *n)).collect()
}

/// After each new head, fetches the top items' proofs, most hit first, [`REFRESH_CHUNK`] items at
/// a time with each chunk's accounts before its slots. A pass stops when the head moves, so a set
/// too large for one block refreshes only its leaders. Runs until dropped.
pub async fn refresh_loop(chain: Arc<HeaderChain>, hot: Arc<HotSet>, fetcher: Arc<dyn Fetcher>) {
    if !hot.enabled() {
        return;
    }
    let mut last: Option<B256> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let Some(head) = chain.head() else { continue };
        if chain.halted() || last == Some(head.hash) {
            continue;
        }
        last = Some(head.hash);
        let mut seen = AddressSet::default();
        'pass: for items in hot.top().chunks(REFRESH_CHUNK) {
            for misses in refresh_misses(items, &mut seen) {
                if misses.is_empty() {
                    continue;
                }
                if chain.head().is_none_or(|h| h.hash != head.hash) {
                    tracing::debug!("new head during the hot-set refresh; starting over");
                    break 'pass;
                }
                if let Err(e) = fetcher.fetch(head.header.state_root, &misses).await {
                    tracing::debug!(%e, "hot-set refresh fetch failed");
                }
            }
        }
        hot.decay();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{test_block, HeldBlock},
        exec::FetchError,
        state::MissKey,
    };
    use async_trait::async_trait;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn a(n: u8) -> Address {
        Address::repeat_byte(n)
    }

    #[test]
    fn counts_the_top_n_and_stays_bounded() {
        let h = HotSet::new(2);
        for _ in 0..5 {
            h.record(Hot::Account(a(1)));
        }
        for _ in 0..3 {
            h.record(Hot::Slot(a(2), B256::ZERO));
        }
        h.record(Hot::Account(a(3)));
        assert_eq!(h.top(), vec![Hot::Account(a(1)), Hot::Slot(a(2), B256::ZERO)]);
        for i in 0..2000u32 {
            let mut b = [0u8; 20];
            b[..4].copy_from_slice(&i.to_be_bytes());
            h.record(Hot::Account(Address::from(b)));
        }
        assert!(h.len() <= 16 * 8);
        // The leaders survive the trimming.
        assert_eq!(h.top()[0], Hot::Account(a(1)));
        assert!(!HotSet::new(0).enabled());
        let off = HotSet::new(0);
        off.record(Hot::Account(a(1)));
        assert!(off.is_empty());
    }

    fn account(i: u32) -> Hot {
        let mut b = [0u8; 20];
        b[..4].copy_from_slice(&i.to_be_bytes());
        Hot::Account(Address::from(b))
    }

    /// How long one trim at `size` takes: the record that takes the map past eight times the size.
    fn trim_time(size: usize) -> Duration {
        let h = HotSet::new(size);
        let bound = u32::try_from(size * 8).unwrap();
        for i in 0..bound {
            h.record(account(i));
        }
        assert_eq!(h.len(), size * 8);
        let start = std::time::Instant::now();
        h.record(account(bound));
        let took = start.elapsed();
        assert_eq!(h.len(), size);
        took
    }

    #[test]
    fn a_trim_is_not_quadratic_in_the_size() {
        // A ratio, not a wall-clock limit, so a slow or loaded runner does not decide it. At
        // sixteen times the size a linear or n log n trim takes 16 to about 25 times as long, a
        // quadratic one 256; a 4x step left too little room, as cache effects alone reached 16x.
        // The fastest of three runs at each size drops one-off stalls.
        let fastest = |size| (0..3).map(|_| trim_time(size)).min().unwrap();
        let (small, large) = (fastest(1_000), fastest(16_000));
        let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-6);
        assert!(ratio < 64.0, "a trim took {small:?} at 1000 and {large:?} at 16000 ({ratio:.1}x)");
    }

    #[test]
    fn a_huge_size_is_capped() {
        let h = HotSet::new(usize::MAX);
        h.record(Hot::Account(a(1)));
        assert_eq!(h.size, MAX_HOT_SET);
        assert_eq!(h.top(), vec![Hot::Account(a(1))]);
    }

    struct Rec(Mutex<Vec<(B256, Vec<MissKey>)>>);
    #[async_trait]
    impl Fetcher for Rec {
        async fn fetch(&self, root: B256, m: &[MissKey]) -> Result<(), FetchError> {
            self.0.lock().push((root, m.to_vec()));
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_top_entry_is_refetched_after_each_head() {
        let chain = Arc::new(HeaderChain::new());
        let anchor = test_block(10, B256::ZERO, 0);
        chain.seed(anchor.clone());
        let hot = Arc::new(HotSet::new(1));
        // Two hits last two heads: 2, then 1, then gone.
        hot.record(Hot::Account(a(9)));
        hot.record(Hot::Account(a(9)));
        let rec = Arc::new(Rec(Mutex::default()));
        let task = tokio::spawn(refresh_loop(chain.clone(), hot, rec.clone()));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let next = test_block(11, anchor.hash, 1);
        chain.insert(next.clone()).unwrap();
        chain.set_head(next.hash).unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        task.abort();
        let calls = rec.0.lock().clone();
        assert_eq!(calls.len(), 2, "once per head: {calls:?}");
        assert_eq!(calls[1].0, next.header.state_root);
        assert_eq!(calls[1].1, vec![MissKey::Account(a(9), None)]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_old_leader_decays_so_a_new_hot_key_takes_its_place() {
        let chain = Arc::new(HeaderChain::new());
        let mut parent = test_block(10, B256::ZERO, 0);
        chain.seed(parent.clone());
        let hot = Arc::new(HotSet::new(1));
        for _ in 0..100_000 {
            hot.record(Hot::Account(a(1)));
        }
        let rec = Arc::new(Rec(Mutex::default()));
        let task = tokio::spawn(refresh_loop(chain.clone(), hot.clone(), rec));
        // 20 heads at 10 hits each: 200 lifetime hits, far fewer than the old leader's.
        for n in 1..=20u8 {
            for _ in 0..10 {
                hot.record(Hot::Account(a(2)));
            }
            let next = test_block(10 + u64::from(n), parent.hash, n);
            chain.insert(next.clone()).unwrap();
            chain.set_head(next.hash).unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
            parent = next;
        }
        task.abort();
        assert_eq!(hot.top(), vec![Hot::Account(a(2))]);
    }

    #[test]
    fn a_key_read_once_gives_its_place_to_a_later_key_read_once() {
        let h = HotSet::new(1);
        // The lowest key wins a tie, so the old key must be gone, not just outranked.
        h.record(Hot::Account(a(1)));
        h.decay();
        h.record(Hot::Account(a(2)));
        assert_eq!(h.top(), vec![Hot::Account(a(2))]);
        h.decay();
        assert!(h.is_empty(), "{:?}", h.counts.lock());
    }

    #[tokio::test(start_paused = true)]
    async fn the_refresh_fetches_each_account_once_before_its_slots() {
        let chain = Arc::new(HeaderChain::new());
        let anchor = test_block(10, B256::ZERO, 0);
        chain.seed(anchor.clone());
        let hot = Arc::new(HotSet::new(4));
        let slot = |n: u8| Hot::Slot(a(1), B256::repeat_byte(n));
        for (n, hits) in [(1, 3), (2, 2), (3, 1)] {
            for _ in 0..hits {
                hot.record(slot(n));
            }
        }
        let rec = Arc::new(Rec(Mutex::default()));
        let task = tokio::spawn(refresh_loop(chain, hot, rec.clone()));
        tokio::time::sleep(Duration::from_millis(250)).await;
        task.abort();
        let root = anchor.header.state_root;
        let slots = (1..=3).map(|n| MissKey::Slot(a(1), B256::repeat_byte(n))).collect();
        assert_eq!(
            rec.0.lock().clone(),
            vec![(root, vec![MissKey::Account(a(1), None)]), (root, slots)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_refresh_fetches_in_bounded_chunks() {
        let chain = Arc::new(HeaderChain::new());
        let anchor = test_block(10, B256::ZERO, 0);
        chain.seed(anchor);
        let n = 1_500;
        let hot = Arc::new(HotSet::new(n));
        for i in 0..u32::try_from(n).unwrap() {
            let Hot::Account(addr) = account(i) else { unreachable!() };
            hot.record(Hot::Slot(addr, B256::ZERO));
        }
        let rec = Arc::new(Rec(Mutex::default()));
        let task = tokio::spawn(refresh_loop(chain, hot, rec.clone()));
        tokio::time::sleep(Duration::from_millis(250)).await;
        task.abort();
        let sizes: Vec<_> = rec.0.lock().iter().map(|(_, m)| m.len()).collect();
        let rest = n - REFRESH_CHUNK;
        // The leaders' slots come before the next chunk's accounts: a cut pass keeps the hottest.
        assert_eq!(sizes, vec![REFRESH_CHUNK, REFRESH_CHUNK, rest, rest], "accounts, then slots");
    }

    /// Records each fetch and moves the head to `next` during the first one.
    struct NewHeadMidPass {
        chain: Arc<HeaderChain>,
        next: Mutex<Option<HeldBlock>>,
        calls: Mutex<Vec<(B256, usize)>>,
    }
    #[async_trait]
    impl Fetcher for NewHeadMidPass {
        async fn fetch(&self, root: B256, m: &[MissKey]) -> Result<(), FetchError> {
            self.calls.lock().push((root, m.len()));
            if let Some(next) = self.next.lock().take() {
                self.chain.insert(next.clone()).unwrap();
                self.chain.set_head(next.hash).unwrap();
            }
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_head_ends_the_refresh_at_the_old_root() {
        let chain = Arc::new(HeaderChain::new());
        let anchor = test_block(10, B256::ZERO, 0);
        chain.seed(anchor.clone());
        let mut next = test_block(11, anchor.hash, 1);
        next.header.state_root = B256::repeat_byte(7);
        next.hash = next.header.hash_slow();
        let n = 3 * REFRESH_CHUNK;
        let hot = Arc::new(HotSet::new(n));
        for i in 0..u32::try_from(n).unwrap() {
            // Two hits outlast the first pass's decay.
            hot.record(account(i));
            hot.record(account(i));
        }
        let rec = Arc::new(NewHeadMidPass {
            chain: chain.clone(),
            next: Mutex::new(Some(next.clone())),
            calls: Mutex::default(),
        });
        let task = tokio::spawn(refresh_loop(chain, hot, rec.clone()));
        tokio::time::sleep(Duration::from_millis(250)).await;
        task.abort();
        let (old, new) = (anchor.header.state_root, next.header.state_root);
        let full = (new, REFRESH_CHUNK);
        assert_eq!(rec.calls.lock().clone(), vec![(old, REFRESH_CHUNK), full, full, full]);
    }

    #[test]
    fn refresh_misses_lists_each_account_once_then_the_slots() {
        let h = HotSet::new(8);
        let (s1, s2) = (B256::repeat_byte(1), B256::repeat_byte(2));
        for (hot, hits) in [
            (Hot::Slot(a(1), s1), 4),
            (Hot::Account(a(2)), 3),
            (Hot::Slot(a(2), s2), 2),
            (Hot::Account(a(1)), 1),
        ] {
            for _ in 0..hits {
                h.record(hot.clone());
            }
        }
        let mut seen = AddressSet::default();
        assert_eq!(
            refresh_misses(&h.top(), &mut seen),
            [
                vec![MissKey::Account(a(1), None), MissKey::Account(a(2), None)],
                vec![MissKey::Slot(a(1), s1), MissKey::Slot(a(2), s2)],
            ]
        );
        // A later chunk of the same pass does not fetch those accounts again.
        let (s3, s4) = (B256::repeat_byte(3), B256::repeat_byte(4));
        assert_eq!(
            refresh_misses(&[Hot::Slot(a(1), s3), Hot::Slot(a(4), s4)], &mut seen),
            [
                vec![MissKey::Account(a(4), None)],
                vec![MissKey::Slot(a(1), s3), MissKey::Slot(a(4), s4)]
            ]
        );
    }

    fn hot_key() -> impl Strategy<Value = Hot> {
        prop_oneof![
            (0..200u32).prop_map(account),
            (0..20u8, 0..10u8).prop_map(|(x, s)| Hot::Slot(a(x), B256::repeat_byte(s))),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `None` is a new head (a decay), `Some` a hit.
        #[test]
        fn the_hot_set_stays_bounded_and_ranks_its_leaders(
            size in 0..40usize,
            ops in proptest::collection::vec(proptest::option::weighted(0.98, hot_key()), 1..600),
        ) {
            let h = HotSet::new(size);
            let mut recorded = HashSet::new();
            let last_op = ops.len() - 1;
            for (i, op) in ops.into_iter().enumerate() {
                if let Some(key) = op {
                    recorded.insert(key.clone());
                    h.record(key);
                } else {
                    let before = h.counts.lock().clone();
                    h.decay();
                    let after = h.counts.lock().clone();
                    let halved: HashMap<_, _> =
                        before.into_iter().map(|(k, n)| (k, n / 2)).filter(|(_, n)| *n > 0).collect();
                    prop_assert_eq!(after, halved);
                }
                prop_assert!(h.len() <= size.max(16) * 8, "{} keys for size {size}", h.len());
                // The ranking is checked every eighth op to keep the run fast: a bad trim stays.
                if i % 8 != 0 && i != last_op {
                    continue;
                }
                let counts = h.counts.lock().clone();
                let top = h.top();
                prop_assert_eq!(top.len(), size.min(counts.len()));
                prop_assert!(top.iter().all(|k| recorded.contains(k)));
                // Most hits first, ties by key, and no key left out outranks the last leader.
                let rank = |k: &Hot| (std::cmp::Reverse(counts[k]), k.clone());
                for w in top.windows(2) {
                    prop_assert!(rank(&w[0]) < rank(&w[1]), "{w:?} out of order");
                }
                if let Some(last) = top.last() {
                    let leaders: HashSet<_> = top.iter().collect();
                    for k in counts.keys().filter(|k| !leaders.contains(k)) {
                        prop_assert!(rank(k) > rank(last), "{k:?} outranks {last:?}");
                    }
                }
            }
        }
    }
}
