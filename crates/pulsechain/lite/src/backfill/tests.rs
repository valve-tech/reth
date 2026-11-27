use super::*;
use crate::chain::ChainError;
use alloy_consensus::{proofs::calculate_transaction_root, Signed, TxLegacy};
use alloy_primitives::{Signature, TxKind};
use parking_lot::Mutex;
use std::collections::HashMap;

/// A canonical chain of blocks `0..=top`, each with one transaction, by hash and by number.
struct Truth {
    by_hash: HashMap<B256, HeldBlock>,
    by_number: Vec<HeldBlock>,
}

fn tx(n: u64) -> TxEnvelope {
    let tx = TxLegacy { nonce: n, gas_limit: 21_000, to: TxKind::Create, ..Default::default() };
    TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
}

impl Truth {
    fn new(top: u64) -> Self {
        let mut by_number: Vec<HeldBlock> = Vec::new();
        for n in 0..=top {
            let body = BlockBody { transactions: vec![tx(n)], ommers: vec![], withdrawals: None };
            let header = Header {
                number: n,
                parent_hash: by_number.last().map_or(B256::ZERO, |b| b.hash),
                transactions_root: calculate_transaction_root(&body.transactions),
                ..Default::default()
            };
            by_number.push(HeldBlock {
                hash: header.hash_slow(),
                header,
                beacon_root: B256::ZERO,
                body: Arc::new(body),
            });
        }
        let by_hash = by_number.iter().map(|b| (b.hash, b.clone())).collect();
        Self { by_hash, by_number }
    }

    fn at(&self, n: u64) -> &HeldBlock {
        &self.by_number[n as usize]
    }

    /// A chain seeded at block `seed`, with the head at `head`.
    fn chain(&self, seed: u64, head: u64) -> HeaderChain {
        let chain = HeaderChain::new();
        chain.seed(self.at(seed).clone());
        for n in seed + 1..=head {
            chain.insert(self.at(n).clone()).unwrap();
            chain.set_head(self.at(n).hash).unwrap();
        }
        chain
    }
}

/// Serves [`Truth`], at most `per_call` headers at a time, with the header at `forged` (if any)
/// altered and the body at `bad_body` (if any) not its own. Counts its header requests.
struct Peers {
    truth: Arc<Truth>,
    per_call: u64,
    forged: Option<u64>,
    bad_body: Mutex<Option<u64>>,
    silent: std::sync::atomic::AtomicBool,
    asked: Mutex<Vec<(B256, u64)>>,
    /// Run before each header answer.
    on_ask: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Peers {
    fn honest(truth: &Arc<Truth>) -> Self {
        Self {
            truth: truth.clone(),
            per_call: u64::MAX,
            forged: None,
            bad_body: Mutex::new(None),
            silent: false.into(),
            asked: Mutex::default(),
            on_ask: None,
        }
    }
}

#[async_trait]
impl History for Peers {
    async fn headers_down(&self, hash: B256, limit: u64) -> Vec<Header> {
        self.asked.lock().push((hash, limit));
        if let Some(f) = &self.on_ask {
            f();
        }
        let Some(start) = self
            .truth
            .by_hash
            .get(&hash)
            .filter(|_| !self.silent.load(std::sync::atomic::Ordering::SeqCst))
        else {
            return Vec::new()
        };
        let n = start.header.number;
        (0..=n)
            .rev()
            .take(limit.min(self.per_call) as usize)
            .map(|i| {
                let mut h = self.truth.at(i).header.clone();
                if self.forged == Some(i) {
                    h.extra_data = vec![0xff].into();
                }
                h
            })
            .collect()
    }

    async fn bodies(&self, hashes: &[B256]) -> Vec<BlockBody<TxEnvelope>> {
        hashes
            .iter()
            .filter_map(|h| self.truth.by_hash.get(h))
            .map(|b| {
                if *self.bad_body.lock() == Some(b.header.number) {
                    BlockBody { transactions: vec![tx(u64::MAX)], ..BlockBody::default() }
                } else {
                    (*b.body).clone()
                }
            })
            .collect()
    }
}

#[tokio::test(start_paused = true)]
async fn a_backfill_holds_the_256_blocks_below_the_seed_each_linked_to_it() {
    let truth = Arc::new(Truth::new(1100));
    let chain = truth.chain(1000, 1003);
    let seed = truth.at(1000).hash;
    // Before: BLOCKHASH reaches only the seed's parent, and no block below the seed is held.
    assert_eq!(chain.ancestor_hash(&seed, 999), Some(truth.at(999).hash));
    assert_eq!(chain.ancestor_hash(&seed, 998), None);
    assert!(chain.by_number(999).is_none());
    assert_eq!(chain.lowest(), Some(1000));
    let peers = Peers::honest(&truth);
    assert_eq!(backfill(&chain, &peers).await, 256);
    assert_eq!(*peers.asked.lock(), vec![(truth.at(999).hash, 256)]);
    let head = truth.at(1003).hash;
    for n in [999, 900, 744] {
        assert_eq!(chain.ancestor_hash(&head, n), Some(truth.at(n).hash), "{n}");
        assert_eq!(chain.by_number(n).map(|b| b.hash), Some(truth.at(n).hash), "{n}");
    }
    // The lowest held header names its parent, so BLOCKHASH reaches one block further.
    assert_eq!(chain.ancestor_hash(&head, 743), Some(truth.at(743).hash));
    assert_eq!(chain.ancestor_hash(&head, 742), None);
    assert_eq!(chain.lowest(), Some(744));
    assert!(chain.find_tx(truth.at(800).body.transactions[0].tx_hash()).is_some());
    // A second backfill goes on below the lowest block, down to the header window. The loop
    // runs one backfill per seed.
    assert_eq!(backfill(&chain, &peers).await, 253);
    assert_eq!(chain.lowest(), Some(1003 - crate::chain::HEADERS_WINDOW));
}

#[tokio::test(start_paused = true)]
async fn a_header_that_does_not_link_ends_the_run_there() {
    let truth = Arc::new(Truth::new(1100));
    let chain = truth.chain(1000, 1001);
    let peers = Peers { forged: Some(990), ..Peers::honest(&truth) };
    assert_eq!(backfill(&chain, &peers).await, 9);
    assert_eq!(chain.lowest_canonical().unwrap().1.hash, truth.at(991).hash);
    assert_eq!(chain.ancestor_hash(&truth.at(1001).hash, 989), None);
    // Every try asked again below the last linked block, and none could pass the forgery.
    assert_eq!(peers.asked.lock().len(), TRIES);
}

#[tokio::test(start_paused = true)]
async fn a_body_that_does_not_match_its_header_is_not_held() {
    let truth = Arc::new(Truth::new(1100));
    let chain = truth.chain(1000, 1001);
    let peers = Peers { bad_body: Mutex::new(Some(950)), ..Peers::honest(&truth) };
    assert_eq!(backfill(&chain, &peers).await, 256);
    let head = truth.at(1001).hash;
    // The block is held for BLOCKHASH, without the body. The rest of its request's bodies
    // (999 down to 936) are not read, so they are held without theirs too; the blocks of the
    // other requests keep them.
    assert_eq!(chain.ancestor_hash(&head, 950), Some(truth.at(950).hash));
    assert!(chain.by_number(950).is_none());
    assert_eq!(chain.by_number(951).map(|b| b.hash), Some(truth.at(951).hash));
    assert!(chain.by_number(936).is_none());
    assert_eq!(chain.by_number(935).map(|b| b.hash), Some(truth.at(935).hash));
    assert_eq!(chain.lowest(), Some(951));
}

#[tokio::test(start_paused = true)]
async fn short_answers_are_asked_for_again_below_what_they_gave() {
    let truth = Arc::new(Truth::new(1100));
    let chain = truth.chain(1000, 1000);
    let peers = Peers { per_call: 100, ..Peers::honest(&truth) };
    let start = tokio::time::Instant::now();
    assert_eq!(backfill(&chain, &peers).await, 256);
    let asked: Vec<u64> = peers.asked.lock().iter().map(|(_, limit)| *limit).collect();
    assert_eq!(asked, [256, 156, 56]);
    // A try that held blocks starts the next at once.
    assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn with_no_answers_a_backfill_tries_a_few_times_and_stops() {
    let truth = Arc::new(Truth::new(1100));
    let chain = truth.chain(1000, 1000);
    let peers = Peers { silent: true.into(), ..Peers::honest(&truth) };
    let start = tokio::time::Instant::now();
    assert_eq!(backfill(&chain, &peers).await, 0);
    assert_eq!(peers.asked.lock().len(), TRIES);
    assert_eq!(start.elapsed(), PAUSE * TRIES as u32);
    assert_eq!(chain.lowest(), Some(1000));
}

#[tokio::test(start_paused = true)]
async fn a_backfill_stops_at_genesis_and_at_the_header_window() {
    let truth = Arc::new(Truth::new(1500));
    let chain = truth.chain(100, 100);
    assert_eq!(backfill(&chain, &Peers::honest(&truth)).await, 100);
    assert_eq!(chain.lowest(), Some(0));
    // With the head 400 blocks past the seed, blocks more than the 512-block window below the
    // head would be pruned at the next head: they are not held.
    let chain = truth.chain(1000, 1400);
    assert_eq!(backfill(&chain, &Peers::honest(&truth)).await, 112);
    assert_eq!(chain.lowest(), Some(1400 - crate::chain::HEADERS_WINDOW));
}

#[tokio::test(start_paused = true)]
async fn a_backfill_across_a_reseed_holds_nothing() {
    let truth = Arc::new(Truth::new(1100));
    let chain = Arc::new(truth.chain(1000, 1001));
    let reseed = (chain.clone(), truth.at(1050).clone());
    let peers = Peers {
        on_ask: Some(Box::new(move || reseed.0.reseed(reseed.1.clone()))),
        ..Peers::honest(&truth)
    };
    assert_eq!(backfill(&chain, &peers).await, 0);
    assert_eq!(chain.lowest_canonical().unwrap().1.hash, truth.at(1050).hash);
    let (epoch, top) = chain.lowest_canonical().unwrap();
    let below = vec![truth.at(1049).clone()];
    assert_eq!(chain.backfill(epoch + 1, top.hash, below), Err(ChainError::Reseeded));
}

#[tokio::test(start_paused = true)]
async fn the_bodies_backfilled_stay_within_the_body_budget() {
    let truth = Arc::new(Truth::new(1100));
    let one = crate::chain::body_bytes(&truth.at(950).body);
    let chain = HeaderChain::with_body_budget(one * 100);
    chain.seed(truth.at(1000).clone());
    assert_eq!(backfill(&chain, &Peers::honest(&truth)).await, 256);
    // The lowest blocks lost their bodies first; every block is still held for BLOCKHASH.
    assert_eq!(chain.lowest(), Some(901));
    assert!(chain.by_number(900).is_none());
    assert_eq!(chain.ancestor_hash(&truth.at(1000).hash, 744), Some(truth.at(744).hash));
}

#[tokio::test(start_paused = true)]
async fn the_loop_backfills_once_after_each_seed() {
    let truth = Arc::new(Truth::new(1300));
    let chain = Arc::new(truth.chain(1000, 1000));
    let peers = Arc::new(Peers::honest(&truth));
    let task = tokio::spawn(backfill_loop(chain.clone(), peers.clone()));
    tokio::time::sleep(PAUSE * 3).await;
    assert_eq!(peers.asked.lock().len(), 1);
    assert_eq!(chain.lowest(), Some(744));
    chain.reseed(truth.at(1200).clone());
    tokio::time::sleep(PAUSE * 3).await;
    assert_eq!(peers.asked.lock().len(), 2);
    assert_eq!(chain.lowest(), Some(944));
    task.abort();
}

/// A header that names uncles is never served with an empty body in place of them.
#[test]
fn an_empty_body_is_not_served_for_a_header_that_names_uncles() {
    let uncles = Header {
        number: 9,
        ommers_hash: B256::repeat_byte(1),
        transactions_root: alloy_consensus::constants::EMPTY_ROOT_HASH,
        ..Default::default()
    };
    let nine = HeldBlock {
        hash: uncles.hash_slow(),
        header: uncles,
        beacon_root: B256::ZERO,
        body: Arc::default(),
    };
    let header = Header { number: 10, parent_hash: nine.hash, ..Default::default() };
    let ten = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::default(),
    };
    let chain = HeaderChain::new();
    chain.seed(ten.clone());
    assert_eq!(chain.backfill(chain.epoch(), ten.hash, vec![nine.clone()]), Ok(1));
    assert_eq!(chain.ancestor_hash(&ten.hash, 9), Some(nine.hash));
    assert!(chain.by_number(9).is_none(), "an empty body was served for a header with uncles");
    assert!(chain.by_hash(&nine.hash).is_none());
}

/// A backfill that holds nothing, because no peer answers yet, is tried again with a backoff
/// that doubles from 30 s, and finishes once a peer answers.
#[tokio::test(start_paused = true)]
async fn the_loop_tries_an_unfinished_backfill_again_with_backoff() {
    use std::sync::atomic::Ordering::SeqCst;
    let truth = Arc::new(Truth::new(1100));
    let chain = Arc::new(truth.chain(1000, 1000));
    let peers = Arc::new(Peers { silent: true.into(), ..Peers::honest(&truth) });
    let task = tokio::spawn(backfill_loop(chain.clone(), peers.clone()));
    let asked = || peers.asked.lock().len();
    // One round: three tries 5 s apart.
    tokio::time::sleep(PAUSE * 3 + Duration::from_millis(1)).await;
    assert_eq!(asked(), TRIES);
    // The next round waits 30 s, the one after 60 s.
    tokio::time::sleep(RETRY_FIRST - Duration::from_secs(1)).await;
    assert_eq!(asked(), TRIES);
    tokio::time::sleep(Duration::from_secs(1) + PAUSE * 3).await;
    assert_eq!(asked(), 2 * TRIES);
    tokio::time::sleep(2 * RETRY_FIRST - Duration::from_secs(1)).await;
    assert_eq!(asked(), 2 * TRIES);
    peers.silent.store(false, SeqCst);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(chain.lowest(), Some(744));
    // Finished: no more rounds for this seed.
    let n = asked();
    tokio::time::sleep(RETRY_MAX * 2).await;
    assert_eq!(asked(), n);
    task.abort();
}

/// Bodies a peer did not serve are fetched again later, and their blocks served then.
#[tokio::test(start_paused = true)]
async fn the_loop_fetches_again_the_bodies_a_peer_did_not_serve() {
    let truth = Arc::new(Truth::new(1100));
    let chain = Arc::new(truth.chain(1000, 1000));
    let peers = Arc::new(Peers { bad_body: Mutex::new(Some(950)), ..Peers::honest(&truth) });
    let task = tokio::spawn(backfill_loop(chain.clone(), peers.clone()));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(chain.by_number(950).is_none());
    assert_eq!(chain.lowest(), Some(951));
    *peers.bad_body.lock() = None;
    tokio::time::sleep(RETRY_FIRST + Duration::from_secs(1)).await;
    assert_eq!(chain.by_number(950).map(|b| b.hash), Some(truth.at(950).hash));
    assert_eq!(chain.lowest(), Some(744));
    assert!(chain.backfill_bodiless(10).1.is_empty());
    task.abort();
}

/// A body is given only to a block a backfill listed without one, and not across a re-seed.
#[test]
fn a_backfilled_block_takes_only_its_listed_missing_body() {
    let truth = Truth::new(1100);
    let chain = truth.chain(1000, 1000);
    let (epoch, top) = chain.lowest_canonical().unwrap();
    let bare = |n: u64| HeldBlock { body: Arc::default(), ..truth.at(n).clone() };
    assert_eq!(chain.backfill(epoch, top.hash, vec![bare(999), bare(998)]), Ok(2));
    let (at, listed) = chain.backfill_bodiless(10);
    assert_eq!((at, listed.len()), (epoch, 2));
    assert!(!chain.backfill_body(epoch + 1, truth.at(999).clone()), "taken across a re-seed");
    assert!(!chain.backfill_body(epoch, bare(999)), "an empty body was taken");
    assert!(chain.backfill_body(epoch, truth.at(999).clone()));
    assert!(!chain.backfill_body(epoch, truth.at(999).clone()), "taken twice");
    assert!(!chain.backfill_body(epoch, truth.at(1000).clone()), "a block not listed");
    assert_eq!(chain.by_number(999).map(|b| b.hash), Some(truth.at(999).hash));
    assert_eq!(chain.backfill_bodiless(10).1.len(), 1);
}

/// A backfill hangs only below a canonical block: a held side block is no anchor, and the chain
/// holds nothing below it.
#[test]
fn a_backfill_from_a_side_block_is_refused() {
    let truth = Truth::new(1100);
    let chain = truth.chain(1000, 1001);
    let side = HeldBlock {
        header: Header { extra_data: vec![0xee].into(), ..truth.at(1001).header.clone() },
        ..truth.at(1001).clone()
    };
    let side = HeldBlock { hash: side.header.hash_slow(), ..side };
    chain.insert(side.clone()).unwrap();
    let epoch = chain.epoch();
    assert_eq!(
        chain.backfill(epoch, side.hash, vec![truth.at(1000).clone()]),
        Err(ChainError::Unknown)
    );
    assert_eq!(chain.lowest_canonical().map(|(_, b)| b.hash), Some(truth.at(1000).hash));
    assert_eq!(chain.head().map(|b| b.hash), Some(truth.at(1001).hash));
}
