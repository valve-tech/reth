//! The response budget bounds the heap that answers waiting to be written really hold. This needs
//! its own test binary: it swaps the global allocator to count live heap bytes.

use alloy_consensus::{
    BlockBody, EthereumReceipt, Header, ReceiptWithBloom, Signed, TxEnvelope, TxLegacy, TxType,
};
use alloy_primitives::{Address, Bytes, Log, Signature, TxKind, B256};
use async_trait::async_trait;
use reth_pulsechain_lite::{
    chain::{HeaderChain, HeldBlock},
    config::{LiteConfig, OnMiss},
    exec::{FetchError, Fetcher},
    hot_set::HotSet,
    metrics::LiteMetrics,
    net::client::WireReceipt,
    rpc::{handle_body, Api, ApiParts, NoPeers, ReceiptSource},
    state::MissKey,
    store::{NodeStore, Store},
};
use serde_json::{json, Value};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        atomic::{AtomicIsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Semaphore, time::Instant};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Logs in each receipt: small logs, whose parsed form is several times their text.
const LOGS: usize = 3000;

/// Serves no state: the test reads blocks and receipts only.
struct NoState;

#[async_trait]
impl Fetcher for NoState {
    async fn fetch(&self, _: B256, _: &[MissKey]) -> Result<(), FetchError> {
        Err(FetchError::NoSource)
    }
}

/// Two receipts of [`LOGS`] logs each, as a log-spam block holds.
struct LogSpam;

#[async_trait]
impl ReceiptSource for LogSpam {
    async fn receipts(&self, _: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        let log = Log::new_unchecked(
            Address::repeat_byte(7),
            vec![B256::repeat_byte(1)],
            Bytes::from_static(&[1, 2]),
        );
        let receipt = |cumulative_gas_used| ReceiptWithBloom {
            receipt: EthereumReceipt {
                tx_type: TxType::Legacy,
                success: true,
                cumulative_gas_used,
                logs: vec![log.clone(); LOGS],
            },
            logs_bloom: Default::default(),
        };
        Ok(vec![receipt(21_000), receipt(42_000)])
    }
}

fn legacy_tx(nonce: u64) -> TxEnvelope {
    let tx = TxLegacy {
        nonce,
        gas_price: 2_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(1)),
        ..Default::default()
    };
    TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
}

/// An API over a short live chain whose head holds two transactions.
fn api() -> Arc<Api> {
    let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
    let chain = Arc::new(HeaderChain::new());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut parent = B256::repeat_byte(0xcc);
    for n in 0..3u64 {
        let txs = if n == 2 { vec![legacy_tx(0), legacy_tx(1)] } else { vec![] };
        let header = Header {
            number: 1000 + n,
            parent_hash: parent,
            base_fee_per_gas: Some(1_000_000_000),
            gas_limit: 30_000_000,
            gas_used: if n == 2 { 42_000 } else { 0 },
            timestamp: now - (2 - n) * 10,
            ..Default::default()
        };
        let b = HeldBlock {
            hash: header.hash_slow(),
            header,
            beacon_root: B256::repeat_byte(n as u8),
            body: Arc::new(BlockBody { transactions: txs, ommers: vec![], withdrawals: None }),
        };
        parent = b.hash;
        if n == 0 {
            chain.seed(b);
        } else {
            chain.insert(b.clone()).unwrap();
            chain.set_head(b.hash).unwrap();
        }
    }
    let cfg = LiteConfig {
        chain_id: 943,
        on_miss: OnMiss::Fetch,
        head_max_age: Duration::from_secs(1 << 40),
        ..LiteConfig::default()
    };
    Api::new(ApiParts {
        cfg,
        chain,
        store,
        fetcher: Arc::new(NoState),
        receipts: Arc::new(LogSpam),
        metrics: LiteMetrics::new(),
        hot: Arc::new(HotSet::new(0)),
        net: Arc::new(NoPeers),
        trust_label: "follows test".into(),
    })
    .expect("api")
}

fn receipts_request(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "eth_getBlockReceipts", "params": ["latest"]})
}

/// Sends `bodies` one after another and keeps every reply, as stalled clients that read nothing
/// do. Returns the heap the replies hold, the budget they hold, and how many receipt sets they
/// carry.
async fn held_by_replies(
    api: &Arc<Api>,
    budget: &Arc<Semaphore>,
    bodies: &[Vec<u8>],
) -> [isize; 3] {
    let far = Instant::now() + Duration::from_secs(600);
    let before = LIVE.load(Ordering::Relaxed);
    let mut replies = Vec::new();
    for body in bodies {
        replies.push(handle_body(api, body, far, budget).await.expect("a reply"));
    }
    let heap = LIVE.load(Ordering::Relaxed) - before;
    let charged: usize =
        replies.iter().filter_map(|(_, p)| p.as_ref()).map(|p| p.num_permits()).sum();
    let text: Vec<Value> =
        replies.iter().map(|(r, _)| serde_json::from_str(&r.to_string()).unwrap()).collect();
    let sets = text
        .iter()
        .flat_map(|v| v.as_array().cloned().unwrap_or_else(|| vec![v.clone()]))
        .filter(|v| v["result"].is_array())
        .count();
    drop(replies);
    [heap, isize::try_from(charged).unwrap(), isize::try_from(sets).unwrap()]
}

#[tokio::test]
async fn answers_waiting_to_be_written_hold_no_more_heap_than_the_response_budget() {
    let api = api();
    let far = Instant::now() + Duration::from_secs(600);
    let unbounded = Arc::new(Semaphore::new(Semaphore::MAX_PERMITS));
    // The first read fetches the receipts and caches them, outside the response budget.
    let warm = receipts_request(0).to_string();
    let (reply, _) = handle_body(&api, warm.as_bytes(), far, &unbounded).await.unwrap();
    let one = reply.to_string().len();
    drop(reply);
    assert!(one > 2 << 20, "an answer of {one} bytes is too small to measure");

    // Room for about four answers: many more are asked for, singly and in batches of two.
    let total = 4 * one;
    let singles: Vec<Vec<u8>> = (1..=12).map(|i| receipts_request(i).to_string().into()).collect();
    let pairs: Vec<Vec<u8>> = (1..=6)
        .map(|i| json!([receipts_request(2 * i), receipts_request(2 * i + 1)]).to_string().into())
        .collect();
    for bodies in [singles, pairs] {
        let budget = Arc::new(Semaphore::new(total));
        let [heap, charged, sets] = held_by_replies(&api, &budget, &bodies).await;
        // The check measures something only when the budget holds several answers.
        assert!(sets >= 3, "only {sets} answers were served");
        assert!(charged > 0 && charged as usize <= total, "{charged} charged of {total}");
        // Each reply holds its free part uncharged, and a refusal is a few hundred bytes. The
        // slack is for the runtime and the blocking threads, not for the answers.
        let bound = (total + bodies.len() * (64 << 10) + (2 << 20)) as isize;
        assert!(
            heap <= bound,
            "{sets} answers of {one} bytes hold {heap} heap bytes; the budget is {total} bytes \
             and the bound {bound}"
        );
    }
}

/// A request whose id is a string of `len` bytes. Every answer repeats its id.
fn long_id_request(method: &str, i: u64, len: usize) -> Value {
    let id = format!("{i:x}{}", "a".repeat(len));
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": []})
}

#[tokio::test]
async fn error_answers_and_result_heads_hold_no_more_heap_than_their_text() {
    let api = api();
    let far = Instant::now() + Duration::from_secs(600);
    let unbounded = Arc::new(Semaphore::new(Semaphore::MAX_PERMITS));
    // An error answer (the method is not served) and a result answer, each about 1 MiB long:
    // most of the text is the id, in the error text or in the head before the result.
    let methods = ["eth_notServed", "eth_chainId"];
    for method in methods {
        let warm = long_id_request(method, 0, 8).to_string();
        let (reply, _) = handle_body(&api, warm.as_bytes(), far, &unbounded).await.unwrap();
        drop(reply);
    }
    let singles: Vec<Vec<u8>> = (1..=8)
        .map(|i| long_id_request(methods[i as usize % 2], i, 1 << 20).to_string().into())
        .collect();
    let pairs: Vec<Vec<u8>> = (1..=4)
        .map(|i| {
            let [a, b] = methods.map(|m| long_id_request(m, i, 1 << 20));
            json!([a, b]).to_string().into()
        })
        .collect();
    for bodies in [singles, pairs] {
        let before = LIVE.load(Ordering::Relaxed);
        let mut replies = Vec::new();
        for body in &bodies {
            replies.push(handle_body(&api, body, far, &unbounded).await.expect("a reply"));
        }
        let heap = LIVE.load(Ordering::Relaxed) - before;
        let text: usize = replies.iter().map(|(r, _)| r.len()).sum();
        let errors = replies
            .iter()
            .flat_map(|(r, _)| {
                let v: Value = serde_json::from_slice(&r.to_vec()).unwrap();
                v.as_array().cloned().unwrap_or_else(|| vec![v])
            })
            .filter(|v| v["error"]["code"] == -32601)
            .count();
        drop(replies);
        assert_eq!(errors, 4, "every not-served request gets an error answer");
        assert!(text >= 8 << 20, "answers of {text} bytes are too short to measure");
        // The slack is for the runtime and the blocking threads, not for the answers.
        let bound = (text + (2 << 20)) as isize;
        assert!(
            heap <= bound,
            "answers of {text} bytes hold {heap} heap bytes; the bound is {bound}"
        );
    }
}
