use super::*;
use crate::{
    chain::{HeaderChain, HeldBlock},
    exec::Fetcher,
    metrics::LiteMetrics,
    store::Store,
    testing::{world, Acct, Honest, World},
};
use alloy_consensus::{transaction::SignerRecoverable, BlockBody, Signed, TxLegacy};
use alloy_primitives::{address, Signature};
use proptest::{collection::vec, prelude::*};
use std::time::Duration;

const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
const VIEW: Address = address!("00000000000000000000000000000000000c0de1");
const REVERTER: Address = address!("00000000000000000000000000000000000c0de2");
const COLD: Address = address!("00000000000000000000000000000000000c01d0");
/// Returns `BLOCKHASH(NUMBER - 1)`.
const PARENT_HASH: Address = address!("00000000000000000000000000000000000c0de4");
/// `JUMPDEST PUSH1 0 JUMP`: loops until the gas runs out.
const LOOPER: Address = address!("00000000000000000000000000000000000c0de3");
/// Jumps over `BLOCKHASH(NUMBER - 5)` when slot 0 (1) is set.
const BRANCHER: Address = address!("00000000000000000000000000000000000c0de5");

struct Receipts(Vec<WireReceipt>);

#[async_trait]
impl ReceiptSource for Receipts {
    async fn receipts(&self, _: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        Ok(self.0.clone())
    }
}

fn legacy_tx(nonce: u64, gas_price: u128) -> TxEnvelope {
    let tx = TxLegacy {
        nonce,
        gas_price,
        gas_limit: 21_000,
        to: TxKind::Call(ALICE),
        ..Default::default()
    };
    TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
}

fn wire_receipt(cumulative: u64) -> WireReceipt {
    ReceiptWithBloom {
        receipt: alloy_consensus::EthereumReceipt {
            tx_type: alloy_consensus::TxType::Legacy,
            success: true,
            cumulative_gas_used: cumulative,
            logs: vec![alloy_primitives::Log::new_unchecked(
                ALICE,
                vec![B256::repeat_byte(1)],
                Bytes::from_static(&[1, 2]),
            )],
        },
        logs_bloom: Default::default(),
    }
}

struct Rig {
    api: Arc<Api>,
    chain: Arc<HeaderChain>,
    honest: Arc<Honest>,
    blocks: Vec<HeldBlock>,
    metrics: LiteMetrics,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn rig(mode: OnMiss, seed: bool) -> Rig {
    let w: Arc<World> = Arc::new(world(&[
        (ALICE, Acct { balance: 1_000_000_000_000_000_000, nonce: 3, ..Default::default() }),
        (
            VIEW,
            Acct {
                code: vec![0x60, 7, 0x54, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3],
                storage: vec![(U256::from(7), U256::from(1234))],
                ..Default::default()
            },
        ),
        (
            REVERTER,
            Acct {
                code: vec![0x60, 0xde, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xfd],
                ..Default::default()
            },
        ),
        (LOOPER, Acct { code: vec![0x5b, 0x60, 0, 0x56], ..Default::default() }),
        (
            BRANCHER,
            Acct {
                code: vec![
                    0x60, 0, 0x54, 0x60, 12, 0x57, 0x60, 5, 0x43, 0x03, 0x40, 0x50, 0x5b, 0x00,
                ],
                storage: vec![(U256::ZERO, U256::from(1))],
                ..Default::default()
            },
        ),
        (
            PARENT_HASH,
            Acct {
                code: vec![0x60, 1, 0x43, 0x03, 0x40, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3],
                ..Default::default()
            },
        ),
    ]));
    let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
    let honest = Arc::new(Honest::new(w.clone(), store.clone()));
    let chain = Arc::new(HeaderChain::new());
    let mut blocks = Vec::new();
    if seed {
        let mut parent = B256::repeat_byte(0xcc);
        for n in 0..4u64 {
            let txs = if n == 3 {
                vec![legacy_tx(0, 3_000_000_000), legacy_tx(1, 2_000_000_000)]
            } else {
                vec![]
            };
            let header = Header {
                number: 1000 + n,
                parent_hash: parent,
                state_root: w.root,
                base_fee_per_gas: Some(1_000_000_000),
                gas_limit: 30_000_000,
                gas_used: if n == 3 { 42_000 } else { 0 },
                timestamp: now() - (3 - n) * 10,
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
                chain.seed(b.clone());
            } else {
                chain.insert(b.clone()).unwrap();
                chain.set_head(b.hash).unwrap();
            }
            blocks.push(b);
        }
    }
    let cfg = LiteConfig { chain_id: 943, on_miss: mode, ..LiteConfig::default() };
    let metrics = LiteMetrics::new();
    let api = Api::new(ApiParts {
        cfg,
        chain: chain.clone(),
        store,
        fetcher: honest.clone(),
        receipts: Arc::new(Receipts(vec![wire_receipt(21_000), wire_receipt(42_000)])),
        metrics: metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: "follows test; finalized checked against test".into(),
    })
    .unwrap();
    Rig { api, chain, honest, blocks, metrics }
}

async fn call(api: &Arc<Api>, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    handle(api, body.as_bytes()).await
}

/// [`handle_body`] with a deadline no test reaches and a response budget no test fills.
async fn handle(api: &Arc<Api>, body: &[u8]) -> Value {
    let budget = Arc::new(tokio::sync::Semaphore::new(tokio::sync::Semaphore::MAX_PERMITS));
    let far = Instant::now() + Duration::from_secs(600);
    handle_value(api, body, far, &budget).await.expect("a reply").0
}

/// [`handle_body`], with the reply parsed. The reply text must be what writing the parsed form
/// gives, byte for byte: compact, with the keys in order.
async fn handle_value(
    api: &Arc<Api>,
    body: &[u8],
    deadline: Instant,
    budget: &Arc<tokio::sync::Semaphore>,
) -> Option<(Value, Option<tokio::sync::OwnedSemaphorePermit>)> {
    let (reply, permit) = handle_body(api, body, deadline, budget).await?;
    Some((parsed(&reply), permit))
}

/// `reply` parsed, once checked to be what writing its parsed form gives.
fn parsed(reply: &ReplyBody) -> Value {
    let text = reply.to_vec();
    assert_eq!((reply.len(), reply.to_string().into_bytes()), (text.len(), text.clone()));
    let v: Value = serde_json::from_slice(&text).expect("a JSON reply");
    assert_eq!(serde_json::to_vec(&v).unwrap(), text, "the reply text is not in the usual form");
    v
}

fn result(v: &Value) -> &Value {
    assert!(v.get("error").is_none(), "unexpected error: {v}");
    &v["result"]
}

fn error(v: &Value) -> (i64, &str) {
    let e = &v["error"];
    assert!(e.is_object(), "expected an error: {v}");
    (e["code"].as_i64().unwrap(), e["message"].as_str().unwrap())
}

fn h(a: Address) -> String {
    format!("{a:#x}")
}

#[tokio::test]
async fn every_served_method_answers_in_fetch_mode() {
    let r = rig(OnMiss::Fetch, true);
    let api = &r.api;
    let head = r.blocks.last().unwrap();
    let tx_hash = format!("{:#x}", r.blocks[3].body.transactions[0].tx_hash());
    let hash = format!("{:#x}", head.hash);
    assert_eq!(result(&call(api, "eth_chainId", json!([])).await), "0x3af");
    assert_eq!(result(&call(api, "net_version", json!([])).await), "943");
    assert_eq!(result(&call(api, "eth_blockNumber", json!([])).await), "0x3eb");
    assert_eq!(result(&call(api, "eth_syncing", json!([])).await), &json!(false));
    assert_eq!(
        result(&call(api, "eth_getBalance", json!([h(ALICE), "latest"])).await),
        "0xde0b6b3a7640000"
    );
    assert_eq!(
        result(&call(api, "eth_getTransactionCount", json!([h(ALICE), "latest"])).await),
        "0x3"
    );
    assert_eq!(
        result(&call(api, "eth_getCode", json!([h(VIEW), "latest"])).await),
        "0x60075460005260206000f3"
    );
    assert_eq!(
        result(&call(api, "eth_getStorageAt", json!([h(VIEW), "0x7", "latest"])).await),
        "0x00000000000000000000000000000000000000000000000000000000000004d2"
    );
    assert_eq!(
        result(&call(api, "eth_call", json!([{"to": h(VIEW), "data": "0x"}, "latest"])).await),
        "0x00000000000000000000000000000000000000000000000000000000000004d2"
    );
    let est = call(api, "eth_estimateGas", json!([{"to": h(VIEW)}, "latest"])).await;
    // The call uses 21,000 + PUSH1 3 + cold SLOAD 2,100 + PUSH1 3 + MSTORE 6 + PUSH1 3 + PUSH1 3
    // = 23,118. geth's search over that ends at 23,455, and go-pulse's fifth makes it 28,146.
    assert_eq!(result(&est), &json!(hex_u64(28_146)));
    let blk = call(api, "eth_getBlockByNumber", json!(["latest", false])).await;
    assert_eq!(result(&blk)["hash"], hash);
    assert_eq!(result(&blk)["transactions"].as_array().unwrap().len(), 2);
    let full = call(api, "eth_getBlockByHash", json!([hash, true])).await;
    assert_eq!(result(&full)["transactions"][0]["hash"], tx_hash);
    assert_eq!(
        result(&call(api, "eth_getBlockTransactionCountByNumber", json!(["latest"])).await),
        "0x2"
    );
    assert_eq!(
        result(&call(api, "eth_getBlockTransactionCountByHash", json!([hash])).await),
        "0x2"
    );
    assert_eq!(
        result(&call(api, "eth_getTransactionByHash", json!([tx_hash])).await)["blockNumber"],
        "0x3eb"
    );
    assert_eq!(
        result(&call(api, "eth_getTransactionByBlockHashAndIndex", json!([hash, "0x1"])).await)
            ["transactionIndex"],
        "0x1"
    );
    assert_eq!(
        result(
            &call(api, "eth_getTransactionByBlockNumberAndIndex", json!(["latest", "0x0"])).await
        )["hash"],
        tx_hash
    );
    let rcpt = call(api, "eth_getTransactionReceipt", json!([tx_hash])).await;
    assert_eq!(result(&rcpt)["status"], "0x1");
    assert_eq!(result(&rcpt)["gasUsed"], "0x5208");
    assert_eq!(result(&rcpt)["logs"][0]["logIndex"], "0x0");
    let all = call(api, "eth_getBlockReceipts", json!(["latest"])).await;
    assert_eq!(result(&all).as_array().unwrap().len(), 2);
    assert_eq!(result(&all)[1]["cumulativeGasUsed"], "0xa410");
    assert_eq!(result(&all)[1]["logs"][0]["logIndex"], "0x1");
    // The block of the last tx is the head; an empty block has no receipts to fetch.
    let none = call(api, "eth_getBlockReceipts", json!(["0x3e9"])).await;
    assert_eq!(result(&none), &json!([]));
    let fee = call(api, "eth_feeHistory", json!(["0x2", "latest", []])).await;
    assert_eq!(result(&fee)["baseFeePerGas"].as_array().unwrap().len(), 3);
    assert_eq!(result(&fee)["oldestBlock"], "0x3ea");
}

#[tokio::test]
async fn gas_price_and_tips_come_from_the_window_bodies() {
    let r = rig(OnMiss::Fetch, true);
    // Tips: 2 gwei and 1 gwei over a 1 gwei base fee, sorted [1, 2]; 60th percentile index 0.
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), "0x3b9aca00");
    let price = call(&r.api, "eth_gasPrice", json!([])).await;
    assert_eq!(result(&price), "0x77359400");
    // The next base fee follows EIP-1559 from the head block: 42,000 gas used of a 15M target
    // at 1 gwei gives 1e9 - 1e9 * 14,958,000 / 15M / 8 = 875,350,000.
    let fee = call(&r.api, "eth_feeHistory", json!(["0x1", "latest", []])).await;
    assert_eq!(result(&fee)["baseFeePerGas"], json!(["0x3b9aca00", hex_u64(875_350_000)]));
    assert!(result(&fee).get("reward").is_none());
}

#[tokio::test]
async fn the_miss_error_has_the_exact_shape_in_error_mode() {
    let r = rig(OnMiss::Error, true);
    for (m, p) in [
        ("eth_getBalance", json!([h(COLD), "latest"])),
        ("eth_call", json!([{"to": h(COLD), "data": "0x"}, "latest"])),
    ] {
        let v = call(&r.api, m, p).await;
        let e = &v["error"];
        assert_eq!(e["code"], -32046, "{m}: {v}");
        assert_eq!(e["message"], "state not verified locally");
        assert!(e["data"]["missing"].as_u64().unwrap() >= 1);
        assert_eq!(e["data"].as_object().unwrap().len(), 1);
    }
    assert_eq!(
        r.honest.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "error mode fetches nothing"
    );
}

#[tokio::test]
async fn only_answers_checked_against_a_root_count_as_verified() {
    let mut r = rig(OnMiss::Fetch, true);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    r.metrics = metrics::with_local_recorder(&recorder, LiteMetrics::new);
    let api = api_with(&r, cfg_943(), r.honest.clone(), Arc::new(Receipts(vec![])));
    for (m, p) in [
        // Checked against the head's roots.
        ("eth_getBalance", json!([h(ALICE), "latest"])),
        ("eth_getBlockByNumber", json!(["latest", false])),
        // The head choice, a clock check and fee estimates: no root checks them.
        ("eth_blockNumber", json!([])),
        ("eth_syncing", json!([])),
        ("eth_gasPrice", json!([])),
        ("eth_maxPriorityFeePerGas", json!([])),
        ("eth_feeHistory", json!(["0x1", "latest", []])),
        // Configuration: not counted.
        ("eth_chainId", json!([])),
    ] {
        result(&call(&api, m, p).await);
    }
    let out = handle.render();
    for line in
        ["lite_answers_total{verified=\"true\"} 2", "lite_answers_total{verified=\"false\"} 5"]
    {
        assert!(out.lines().any(|l| l == line), "{line} missing from {out}");
    }
}

#[tokio::test]
async fn error_and_warm_misses_then_answers_locally_on_the_second_call() {
    let r = rig(OnMiss::ErrorAndWarm, true);
    let first = call(&r.api, "eth_call", json!([{"to": h(VIEW), "data": "0x"}, "latest"])).await;
    assert_eq!(error(&first).0, -32046);
    let mut ok = false;
    for _ in 0..200 {
        let v = call(&r.api, "eth_call", json!([{"to": h(VIEW), "data": "0x"}, "latest"])).await;
        if v.get("result").is_some() {
            assert_eq!(
                v["result"],
                "0x00000000000000000000000000000000000000000000000000000000000004d2"
            );
            ok = true;
            break;
        }
        assert_eq!(error(&v).0, -32046);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ok, "the warm-up never completed");
    // The queue drains.
    for _ in 0..100 {
        if r.api.warming.lock().keys.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(r.api.warming.lock().keys.is_empty());
    let _ = &r.metrics;
}

#[tokio::test]
async fn a_revert_with_complete_state_is_not_a_miss() {
    let r = rig(OnMiss::Fetch, true);
    let v = call(&r.api, "eth_call", json!([{"to": h(REVERTER), "data": "0x"}, "latest"])).await;
    let e = &v["error"];
    assert_eq!(e["code"], 3);
    assert_eq!(e["message"], "execution reverted");
    assert_eq!(e["data"], "0xde");
    // Now with state held, error mode gives the same answer.
    let mut again = r;
    again.api = Api::new(ApiParts {
        cfg: LiteConfig { chain_id: 943, on_miss: OnMiss::Error, ..LiteConfig::default() },
        chain: again.chain.clone(),
        store: again.honest.store.clone(),
        fetcher: again.honest.clone(),
        receipts: Arc::new(Receipts(vec![])),
        metrics: again.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    let v =
        call(&again.api, "eth_call", json!([{"to": h(REVERTER), "data": "0x"}, "latest"])).await;
    assert_eq!(v["error"]["code"], 3, "{v}");
}

#[tokio::test]
async fn revert_reasons_decode() {
    // Error("nope")
    let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
    data.extend(U256::from(32).to_be_bytes::<32>());
    data.extend(U256::from(4).to_be_bytes::<32>());
    data.extend(b"nope");
    data.extend([0u8; 28]);
    let e = revert_error(&Bytes::from(data));
    assert_eq!((e.code, e.message.as_str()), (3, "execution reverted: nope"));
    assert_eq!(revert_error(&Bytes::new()).message, "execution reverted");
}

#[test]
fn revert_offsets_and_lengths_near_usize_max_do_not_overflow() {
    let error_string = |off: usize, len: usize| {
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
        data.extend(U256::from(off).to_be_bytes::<32>());
        data.extend(U256::from(len).to_be_bytes::<32>());
        Bytes::from(data)
    };
    for (off, len) in [(usize::MAX - 31, 0), (usize::MAX, 0), (32, usize::MAX - 63)] {
        let e = revert_error(&error_string(off, len));
        assert_eq!((e.code, e.message.as_str()), (3, "execution reverted"), "{off} {len}");
    }
}

#[tokio::test]
async fn a_state_window_near_u64_max_does_not_overflow() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig { chain_id: 943, state_window: u64::MAX, ..LiteConfig::default() },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher: r.honest.clone(),
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"])).await;
    assert_eq!(result(&v), "0xde0b6b3a7640000");
}

#[tokio::test]
async fn overrides_are_rejected_but_null_and_empty_are_fine() {
    let r = rig(OnMiss::Fetch, true);
    let ok = call(&r.api, "eth_call", json!([{"to": h(VIEW)}, "latest", {}, null])).await;
    assert!(ok.get("result").is_some(), "{ok}");
    let bad =
        call(&r.api, "eth_call", json!([{"to": h(VIEW)}, "latest", {h(VIEW): {"balance": "0x1"}}]))
            .await;
    assert_eq!(error(&bad).0, -32602);
    assert!(error(&bad).1.contains("overrides"));
}

#[tokio::test]
async fn call_fields_that_change_the_answer_but_are_not_modelled_are_refused() {
    let r = rig(OnMiss::Fetch, true);
    let auth = json!({"chainId": "0x3af", "address": h(VIEW), "nonce": "0x0",
        "yParity": "0x0", "r": "0x1", "s": "0x1"});
    for m in ["eth_call", "eth_estimateGas"] {
        // Empty lists, the node's own chain ID and a blob fee without blobs change nothing.
        let ok = json!([{"to": h(VIEW), "accessList": [], "blobVersionedHashes": [],
            "authorizationList": [], "chainId": "0x3af", "maxFeePerBlobGas": "0x1"}, "latest"]);
        result(&call(&r.api, m, ok).await);
        // An access list is modelled: the call runs as an EIP-2930 transaction.
        let listed = json!([{"to": h(VIEW), "accessList": [{"address": h(VIEW), "storageKeys": []}]},
            "latest"]);
        result(&call(&r.api, m, listed).await);
        for (field, value, msg) in [
            (
                "blobVersionedHashes",
                json!([format!("{:#x}", B256::repeat_byte(1))]),
                "blob transactions are not supported by the lite node",
            ),
            (
                "authorizationList",
                json!([auth]),
                "authorizationList is not supported by the lite node",
            ),
            ("chainId", json!("0x171"), "chainId does not match node's (have=369, want=943)"),
        ] {
            let mut req = json!({"to": h(VIEW)});
            req[field] = value;
            let v = call(&r.api, m, json!([req, "latest"])).await;
            assert_eq!(error(&v), (-32602, msg), "{m} {field}");
        }
    }
}

#[tokio::test]
async fn send_raw_transaction_and_unlisted_methods_are_refused() {
    let r = rig(OnMiss::Fetch, true);
    for m in [
        "eth_sendRawTransaction",
        "eth_getLogs",
        "eth_getProof",
        "debug_traceTransaction",
        "eth_newFilter",
        "eth_subscribe",
        "eth_accounts",
        "no_such_method",
    ] {
        let v = call(&r.api, m, json!(["0x02f8"])).await;
        assert_eq!(error(&v), (-32601, "method not served"), "{m}");
    }
    // Even with no head and when halted: a refusal never depends on state.
    let empty = rig(OnMiss::Fetch, false);
    assert_eq!(error(&call(&empty.api, "eth_sendRawTransaction", json!([])).await).0, -32601);
}

#[tokio::test]
async fn no_head_yet_and_halted() {
    let r = rig(OnMiss::Fetch, false);
    assert_eq!(error(&call(&r.api, "eth_blockNumber", json!([])).await), (-32000, NO_HEAD));
    assert_eq!(result(&call(&r.api, "eth_chainId", json!([])).await), "0x3af");

    let r = rig(OnMiss::Fetch, true);
    r.chain.set_halted(Some(HaltReason::AnchorMismatch));
    for (m, p) in [
        ("eth_blockNumber", json!([])),
        ("eth_getBlockByNumber", json!(["latest", false])),
        ("eth_getBalance", json!([h(ALICE), "latest"])),
        ("eth_gasPrice", json!([])),
    ] {
        assert_eq!(error(&call(&r.api, m, p).await), (-32000, HALTED_MESSAGE), "{m}");
    }
    assert_eq!(result(&call(&r.api, "eth_chainId", json!([])).await), "0x3af");
    assert_eq!(result(&call(&r.api, "net_version", json!([])).await), "943");
    r.chain.set_halted(Some(HaltReason::BehindAnchor));
    assert_eq!(error(&call(&r.api, "eth_blockNumber", json!([])).await), (-32000, BEHIND_ANCHOR));
    r.chain.set_halted(None);
    assert!(call(&r.api, "eth_blockNumber", json!([])).await.get("result").is_some());
}

#[tokio::test]
async fn unknown_blocks_are_null_and_state_above_the_head_is_not_in_window() {
    let r = rig(OnMiss::Error, true);
    let unknown = format!("{:#x}", B256::repeat_byte(0xee));
    for (m, p) in [
        ("eth_getBlockByNumber", json!(["0xfffffff", false])),
        ("eth_getBlockByNumber", json!(["0x3ec", false])),
        ("eth_getBlockByHash", json!([unknown, true])),
        ("eth_getBlockTransactionCountByNumber", json!(["0xfffffff"])),
        ("eth_getTransactionByBlockNumberAndIndex", json!(["0xfffffff", "0x0"])),
        ("eth_getBlockReceipts", json!(["0xfffffff"])),
        ("eth_getBlockReceipts", json!([{"blockHash": unknown}])),
        ("eth_getTransactionReceipt", json!([unknown])),
        ("eth_getTransactionByHash", json!([unknown])),
    ] {
        assert_eq!(result(&call(&r.api, m, p.clone()).await), &Value::Null, "{m} {p}");
    }
    for at in [json!("0xfffffff"), json!({"blockHash": unknown})] {
        let v = call(&r.api, "eth_getBalance", json!([h(ALICE), at])).await;
        assert_eq!(error(&v), (-32000, NOT_IN_WINDOW), "{at}");
    }
    let v = call(&r.api, "eth_feeHistory", json!(["0x1", "0x3ec", []])).await;
    assert_eq!(error(&v), (-32000, NOT_IN_WINDOW));
    // Held block whose receipts are not held: the miss error in error modes.
    let miss = json!({"code": MISS_CODE, "message": MISS_MESSAGE, "data": {"missing": 1}});
    let rc = call(&r.api, "eth_getBlockReceipts", json!(["latest"])).await;
    assert_eq!(rc["error"], miss);
    let rcpt = call(
        &r.api,
        "eth_getTransactionReceipt",
        json!([format!("{:#x}", r.blocks[3].body.transactions[0].tx_hash())]),
    )
    .await;
    assert_eq!(rcpt["error"], miss);
}

/// reth's answer for a block below its earliest available one: 4444 and no data.
fn pruned(requested: u64, earliest: u64) -> Value {
    let message =
        format!("pruned history unavailable: requested {requested}, earliest available {earliest}");
    json!({"code": 4444, "message": message})
}

#[tokio::test]
async fn blocks_below_the_lowest_held_answer_reths_pruned_history_error() {
    let r = rig(OnMiss::Fetch, true);
    // The rig holds 1000 to 1003.
    for (n, at) in [(999, json!("0x3e7")), (0, json!("0x0"))] {
        for (m, p) in [
            ("eth_getBlockByNumber", json!([at, false])),
            ("eth_getBlockTransactionCountByNumber", json!([at])),
            ("eth_getTransactionByBlockNumberAndIndex", json!([at, "0x0"])),
            ("eth_getBlockReceipts", json!([at])),
            ("eth_getBlockReceipts", json!([{"blockNumber": at}])),
            ("eth_feeHistory", json!(["0x1", at, []])),
            ("eth_getBalance", json!([h(ALICE), at])),
            ("eth_getCode", json!([h(VIEW), at])),
            ("eth_call", json!([{"to": h(VIEW)}, at])),
        ] {
            assert_eq!(call(&r.api, m, p).await["error"], pruned(n, 1000), "{m} {at}");
        }
    }
    // As reth, `earliest` is the earliest available block.
    let v = call(&r.api, "eth_getBlockByNumber", json!(["earliest", false])).await;
    assert_eq!(result(&v)["hash"], format!("{:#x}", r.blocks[0].hash));
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), "earliest"])).await;
    assert_eq!(result(&v), "0xde0b6b3a7640000");
    let v = call(&r.api, "eth_feeHistory", json!(["0x2", "earliest", []])).await;
    assert_eq!(result(&v)["oldestBlock"], "0x3e8");

    // The finalized block stays held below the run; the blocks between are pruned.
    extend_head(&r, crate::chain::HEADERS_WINDOW + 10);
    let lowest = r.chain.lowest().unwrap();
    assert!(lowest > 1001, "{lowest}");
    let v = call(&r.api, "eth_getBlockByNumber", json!(["0x3e8", false])).await;
    assert_eq!(result(&v)["hash"], format!("{:#x}", r.blocks[0].hash));
    let v = call(&r.api, "eth_getBlockByNumber", json!(["0x3e9", false])).await;
    assert_eq!(v["error"], pruned(1001, lowest));
    let v = call(&r.api, "eth_getBlockByNumber", json!(["earliest", false])).await;
    assert_eq!(result(&v)["number"], hex_u64(lowest));
}

#[tokio::test]
async fn error_and_warm_fetches_the_receipts_a_read_missed_once() {
    let tx_hash = |r: &Rig| format!("{:#x}", r.blocks[3].body.transactions[0].tx_hash());
    for method in ["eth_getTransactionReceipt", "eth_getBlockReceipts"] {
        let r = rig(OnMiss::ErrorAndWarm, true);
        let p =
            if method == "eth_getBlockReceipts" { json!(["latest"]) } else { json!([tx_hash(&r)]) };
        let source = Arc::new(CountingReceipts(
            Receipts(vec![wire_receipt(21_000), wire_receipt(42_000)]),
            Default::default(),
        ));
        let cfg = LiteConfig { on_miss: OnMiss::ErrorAndWarm, ..cfg_943() };
        let api = api_with(&r, cfg, r.honest.clone(), source.clone());
        assert_eq!(error(&call(&api, method, p.clone()).await), (MISS_CODE, MISS_MESSAGE));
        let mut answered = None;
        for _ in 0..100 {
            let v = call(&api, method, p.clone()).await;
            if v.get("result").is_some() {
                answered = Some(v);
                break;
            }
            assert_eq!(error(&v), (MISS_CODE, MISS_MESSAGE), "{method}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let v = answered.unwrap_or_else(|| panic!("{method}: the warm job never fetched"));
        let first = if method == "eth_getBlockReceipts" { &result(&v)[0] } else { result(&v) };
        assert_eq!(first["transactionHash"], tx_hash(&r), "{method}");
        assert_eq!(source.1.load(std::sync::atomic::Ordering::SeqCst), 1, "{method}");
    }
}

#[tokio::test]
async fn batches_and_malformed_requests() {
    let r = rig(OnMiss::Fetch, true);
    let body = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber"},
    ]);
    let v = handle(&r.api, body.to_string().as_bytes()).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[1]["id"], 2);
    assert_eq!(handle(&r.api, b"{nope").await["error"]["code"], -32700);
    assert_eq!(handle(&r.api, b"{\"id\":1}").await["error"]["code"], -32600);
    assert_eq!(handle(&r.api, b"[]").await["error"]["code"], -32600);
}

#[tokio::test]
async fn batches_take_geths_1000_items_and_a_larger_one_is_refused_in_an_array() {
    let r = rig(OnMiss::Fetch, true);
    let item = |id: Value| json!({"jsonrpc": "2.0", "id": id, "method": "eth_chainId"});
    let v = handle(&r.api, Value::Array(vec![item(json!(1)); 1000]).to_string().as_bytes()).await;
    assert_eq!(v.as_array().unwrap().len(), 1000);
    assert_eq!(result(&v[999]), "0x3af");
    // As geth: one error, with the id of the first call (not of a notification or a bad id).
    let note = json!({"jsonrpc": "2.0", "method": "eth_chainId"});
    let mut batch = vec![note, item(json!({"a": 1})), item(json!("first"))];
    batch.resize(1001, item(json!(2)));
    let v = handle(&r.api, Value::Array(batch).to_string().as_bytes()).await;
    assert_eq!(
        v,
        json!([{"jsonrpc": "2.0", "id": "first",
            "error": {"code": -32600, "message": "batch too large"}}])
    );
}

#[tokio::test]
async fn the_http_server_serves_post_and_nothing_else() {
    let r = rig(OnMiss::Fetch, true);
    let (addr, task) = serve(r.api.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}"))
        .header("content-type", "application/json")
        .body(
            json!({"jsonrpc": "2.0", "id": 7, "method": "eth_blockNumber", "params": []})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!((v["id"].clone(), v["result"].clone()), (json!(7), json!("0x3eb")));
    // As geth: a GET with no body and no query is a health check, answered 200 and empty.
    let health = client.get(format!("http://{addr}")).send().await.unwrap();
    assert_eq!(health.status(), 200);
    assert!(health.bytes().await.unwrap().is_empty());
    let url = format!("http://{addr}");
    for req in [
        client.get(format!("{url}/?x=1")),
        client.get(&url).body("x"),
        client.put(&url),
        client.delete(&url),
    ] {
        assert_eq!(req.send().await.unwrap().status(), 405);
    }
    // The host check comes first.
    let other = client.get(&url).header("host", "evil.example").send().await.unwrap();
    assert_eq!(other.status(), 403);
    task.abort();
}

#[tokio::test]
async fn a_web_page_cannot_drive_the_server_by_content_type_or_host_name() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let (addr, task) = serve(r.api.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let ask = async |headers: String| {
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST / HTTP/1.1\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        tokio::time::timeout(Duration::from_secs(5), sock.read_to_string(&mut resp))
            .await
            .unwrap()
            .unwrap();
        resp
    };
    let json = "content-type: application/json\r\n";
    for host in ["localhost", "LocalHost:8545", "127.0.0.1", &addr.to_string(), "[::1]:8545"] {
        let resp = ask(format!("host: {host}\r\n{json}")).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{host}: {resp}");
        assert!(!resp.to_ascii_lowercase().contains("access-control-allow-origin"), "{resp}");
    }
    // A browser sends a cross-origin text/plain POST without a preflight.
    for ctype in ["", "content-type: text/plain\r\n", "content-type: application/jsonx\r\n"] {
        let resp = ask(format!("host: localhost\r\n{ctype}")).await;
        assert!(resp.starts_with("HTTP/1.1 415"), "{ctype}: {resp}");
    }
    let resp = ask("host: localhost\r\ncontent-type: Application/JSON; charset=utf-8\r\n".into());
    assert!(resp.await.starts_with("HTTP/1.1 200"));
    // A DNS-rebound name reaches the loopback address with its own Host. A loopback alias and the
    // public name a reverse proxy passes on are refused the same way, as geth's default vhosts: a
    // proxy must send a local Host (README).
    for host in [
        "evil.example",
        "evil.example:8545",
        "localhost.evil.example",
        "ip6-localhost",
        "localhost.localdomain",
        "rpc.example.com:443",
    ] {
        let resp = ask(format!("host: {host}\r\n{json}")).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{host}: {resp}");
    }
    task.abort();
}

#[test]
fn trust_label_is_kept() {
    let r = rig(OnMiss::Fetch, true);
    assert!(r.api.trust_label().starts_with("follows"));
}

/// Extends the rig's chain by `n` blocks on the head, with the same state and fresh timestamps.
fn extend_head(r: &Rig, n: u64) {
    let mut parent = r.chain.head().unwrap();
    for _ in 0..n {
        let header = Header {
            number: parent.header.number + 1,
            parent_hash: parent.hash,
            timestamp: now(),
            ..parent.header.clone()
        };
        let b = HeldBlock {
            hash: header.hash_slow(),
            header,
            beacon_root: B256::ZERO,
            body: Arc::new(BlockBody::default()),
        };
        r.chain.insert(b.clone()).unwrap();
        r.chain.set_head(b.hash).unwrap();
        parent = b;
    }
}

#[tokio::test]
async fn state_is_refused_once_the_head_runs_past_the_finality_cap() {
    let r = rig(OnMiss::Fetch, true);
    // The rig's finalized block is its first; the head is three past it.
    extend_head(&r, crate::chain::MAX_HELD - 3);
    assert!(call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"]))
        .await
        .get("result")
        .is_some());
    extend_head(&r, 1);
    for (m, p) in [
        ("eth_getBalance", json!([h(ALICE), "latest"])),
        ("eth_call", json!([{"to": h(VIEW), "data": "0x"}, "latest"])),
    ] {
        assert_eq!(error(&call(&r.api, m, p).await), (-32000, FINALITY_STALLED), "{m}");
    }
    // Latest blocks and the head number are refused too.
    for (m, p) in
        [("eth_blockNumber", json!([])), ("eth_getBlockByNumber", json!(["latest", false]))]
    {
        assert_eq!(error(&call(&r.api, m, p).await), (-32000, FINALITY_STALLED), "{m}");
    }
}

#[tokio::test]
async fn a_heavy_eth_call_does_not_block_eth_block_number() {
    // One runtime thread: an EVM run on it would stall every other request.
    let r = rig(OnMiss::Fetch, true);
    // Warm the state first so the timed call does no fetching.
    let _ = call(&r.api, "eth_call", json!([{"to": h(LOOPER), "gas": "0x5208"}, "latest"])).await;
    let api = r.api.clone();
    let heavy = tokio::spawn(async move {
        call(&api, "eth_call", json!([{"to": h(LOOPER), "data": "0x"}, "latest"])).await
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    let n = call(&r.api, "eth_blockNumber", json!([])).await;
    assert_eq!(result(&n), "0x3eb");
    assert!(!heavy.is_finished(), "eth_blockNumber waited for the EVM");
    let out = heavy.await.unwrap();
    assert_eq!(error(&out), (-32000, "out of gas"));
}

#[tokio::test]
async fn the_server_caps_connections_and_times_out_slow_headers_and_requests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits {
        max_connections: 2,
        header_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_millis(100),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let post = |body: Value| {
        let body = body.to_string();
        format!(
            "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let block_number = post(json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}));
    async fn ask(sock: &mut tokio::net::TcpStream, req: &str) -> Option<String> {
        sock.write_all(req.as_bytes()).await.ok()?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_millis(300), sock.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
    }
    // Two kept-alive connections fill the cap; a third is not served meanwhile.
    let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert!(ask(&mut a, &block_number).await.unwrap().contains("0x3eb"));
    assert!(ask(&mut b, &block_number).await.unwrap().contains("0x3eb"));
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(ask(&mut c, &block_number).await, None, "over the connection cap");
    drop(a);
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("0x3eb"), "served once a slot frees");
    drop((b, c));
    // Headers that never finish: the connection is closed.
    let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
    slow.write_all(b"POST / HTTP/1.1\r\nhost: localhost\r\n").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), slow.read(&mut buf)).await.unwrap();
    assert!(matches!(n, Ok(0) | Err(_)) || String::from_utf8_lossy(&buf).contains("408"));
    // A request that runs past the request timeout gets the timeout error.
    let mut d = tokio::net::TcpStream::connect(addr).await.unwrap();
    let heavy = post(json!({"jsonrpc": "2.0", "id": 2, "method": "eth_call",
        "params": [{"to": h(LOOPER)}, "latest"]}));
    d.write_all(heavy.as_bytes()).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), d.read(&mut buf)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains(REQUEST_TIMED_OUT));
    task.abort();
}

#[tokio::test]
async fn a_kept_alive_connection_waits_the_idle_timeout_and_a_begun_head_the_header_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits {
        header_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_secs(2),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let post = format!(
        "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut buf = vec![0u8; 4096];
    // `Ok(0)` or an error once the server closes the connection.
    async fn read(sock: &mut tokio::net::TcpStream, buf: &mut [u8], wait: Duration) -> String {
        match tokio::time::timeout(wait, sock.read(buf)).await {
            Ok(Ok(n)) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            Ok(Err(_)) => String::new(),
            Err(_) => "no reply and not closed".into(),
        }
    }
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    for _ in 0..2 {
        sock.write_all(post.as_bytes()).await.unwrap();
        assert!(read(&mut sock, &mut buf, Duration::from_secs(1)).await.contains("0x3eb"));
        // Past the header timeout: a client that polls once per slot finds the connection open.
        tokio::time::sleep(Duration::from_millis(800)).await;
    }
    // A head begun on a kept-alive connection still has the header timeout, not the idle one.
    sock.write_all(b"POST / HTTP/1.1\r\nhost: localhost\r\n").await.unwrap();
    assert_eq!(read(&mut sock, &mut buf, Duration::from_secs(1)).await, "");
    // An idle connection closes at the idle timeout.
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(post.as_bytes()).await.unwrap();
    assert!(read(&mut sock, &mut buf, Duration::from_secs(1)).await.contains("0x3eb"));
    let idle = Instant::now();
    assert_eq!(read(&mut sock, &mut buf, Duration::from_secs(4)).await, "");
    assert!(idle.elapsed() >= Duration::from_millis(1800), "{:?}", idle.elapsed());
    task.abort();
}

/// An HTTP/1.1 POST of `body` to the local server, read for up to `wait`.
async fn post_raw(addr: SocketAddr, head: &str, body: &[u8], wait: Duration) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n{head}\r\n"
    );
    sock.write_all(head.as_bytes()).await.unwrap();
    // The server may answer and close before it reads the whole body. The writer keeps its half
    // open: hyper drops a connection whose read side ends.
    let (mut rd, mut wr) = sock.into_split();
    let body = body.to_vec();
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(&body).await;
        std::future::pending::<()>().await;
    });
    let mut out = Vec::new();
    let read = tokio::time::timeout(wait, rd.read_to_end(&mut out)).await;
    writer.abort();
    assert!(read.is_ok() || !out.is_empty(), "no response in {wait:?}");
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn a_timed_out_batch_is_an_array_that_keeps_its_finished_answers() {
    let r = rig(OnMiss::Fetch, true);
    let limits =
        ServerLimits { request_timeout: Duration::from_millis(100), ..ServerLimits::default() };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let batch = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"},
        {"jsonrpc": "2.0", "id": 2, "method": "eth_call", "params": [{"to": h(LOOPER)}, "latest"]},
        {"jsonrpc": "2.0", "id": "three", "method": "eth_chainId"},
    ])
    .to_string();
    let head = format!("content-length: {}\r\nconnection: close\r\n", batch.len());
    let resp = post_raw(addr, &head, batch.as_bytes(), Duration::from_secs(5)).await;
    let body: Value = serde_json::from_str(resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let items = body.as_array().unwrap_or_else(|| panic!("not an array: {body}"));
    assert_eq!(items.len(), 3);
    assert_eq!((items[0]["id"].clone(), result(&items[0]).clone()), (json!(1), json!("0x3eb")));
    for (it, id) in items[1..].iter().zip([json!(2), json!("three")]) {
        assert_eq!((it["id"].clone(), error(it)), (id, (-32002, REQUEST_TIMED_OUT)));
    }
    // A single request that times out keeps its id.
    let one = json!({"jsonrpc": "2.0", "id": 7, "method": "eth_call",
        "params": [{"to": h(LOOPER)}, "latest"]})
    .to_string();
    let head = format!("content-length: {}\r\nconnection: close\r\n", one.len());
    let resp = post_raw(addr, &head, one.as_bytes(), Duration::from_secs(5)).await;
    let body: Value = serde_json::from_str(resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!((body["id"].clone(), error(&body)), (json!(7), (-32002, REQUEST_TIMED_OUT)));
    // A body that never arrives in full: its shape and id are unknown.
    let resp = post_raw(addr, "content-length: 100\r\n", b"[", Duration::from_secs(5)).await;
    let body: Value = serde_json::from_str(resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!((body["id"].clone(), error(&body)), (Value::Null, (-32002, REQUEST_TIMED_OUT)));
    task.abort();
}

#[tokio::test]
async fn notifications_get_no_reply_and_the_version_must_be_2_0() {
    let r = rig(OnMiss::Fetch, true);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) =
        serve_listener_with(r.api.clone(), listener, ServerLimits::default()).unwrap();
    let send = |body: Value| async move {
        let body = body.to_string();
        let head = format!("content-length: {}\r\nconnection: close\r\n", body.len());
        let resp = post_raw(addr, &head, body.as_bytes(), Duration::from_secs(5)).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        resp.split("\r\n\r\n").nth(1).unwrap().to_owned()
    };
    let note = json!({"jsonrpc": "2.0", "method": "eth_chainId"});
    assert_eq!(send(note.clone()).await, "", "a notification");
    assert_eq!(send(json!([note, note])).await, "", "a batch of notifications");
    let parse = |s: String| serde_json::from_str::<Value>(&s).unwrap();
    let mixed = send(json!([note, {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"}, note]));
    assert_eq!(parse(mixed.await), json!([{"jsonrpc": "2.0", "id": 1, "result": "0x3af"}]));
    // A request with an id of null is not a notification.
    let null_id = json!({"jsonrpc": "2.0", "id": null, "method": "eth_chainId"});
    assert_eq!(
        parse(send(null_id).await),
        json!({"jsonrpc": "2.0", "id": null, "result": "0x3af"})
    );
    // Without a valid version it is not a request, nor a notification.
    for version in [Some(json!("1.0")), Some(json!(2.0)), None] {
        let mut req = json!({"id": 5, "method": "eth_chainId"});
        let mut note = json!({"method": "eth_chainId"});
        if let Some(v) = &version {
            req["jsonrpc"] = v.clone();
            note["jsonrpc"] = v.clone();
        }
        let v = parse(send(req).await);
        assert_eq!(
            (v["id"].clone(), error(&v)),
            (json!(5), (-32600, "invalid request")),
            "{version:?}"
        );
        let v = parse(send(note).await);
        assert_eq!(
            (v["id"].clone(), error(&v)),
            (Value::Null, (-32600, "invalid request")),
            "{version:?}"
        );
    }
    task.abort();
}

#[tokio::test]
async fn only_an_oversized_body_is_answered_413() {
    let r = rig(OnMiss::Fetch, true);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // A timeout past `Instant`'s range does not panic the request.
    let limits = ServerLimits { request_timeout: Duration::MAX, ..ServerLimits::default() };
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let ok = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let head = format!("content-length: {}\r\nconnection: close\r\n", ok.len());
    let resp = post_raw(addr, &head, ok.as_bytes(), Duration::from_secs(5)).await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("0x3eb"), "{resp}");
    let chunked = "transfer-encoding: chunked\r\n";
    // A chunk size that is not hex is a malformed body, not a large one.
    let resp = post_raw(addr, chunked, b"zz\r\n{}\r\n0\r\n\r\n", Duration::from_secs(5)).await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    assert!(resp.ends_with("{\"error\":\"invalid request body\"}"), "{resp}");
    // A chunked body with no declared length that grows past the cap.
    let chunk = vec![b' '; 1 << 20];
    let mut body = Vec::new();
    for _ in 0..=MAX_BODY / chunk.len() {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(&chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    let resp = post_raw(addr, chunked, &body, Duration::from_secs(5)).await;
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert!(resp.ends_with("{\"error\":\"body too large\"}"), "{resp}");
    task.abort();
}

#[tokio::test]
async fn fee_history_rewards_are_refused_not_zeros() {
    let r = rig(OnMiss::Fetch, true);
    let v = call(&r.api, "eth_feeHistory", json!(["0x2", "latest", [25, 75]])).await;
    let (code, msg) = error(&v);
    assert_eq!(code, -32000);
    assert!(msg.contains("rewardPercentiles"), "{msg}");
    // No percentiles: no rewards asked, an answer.
    let v = call(&r.api, "eth_feeHistory", json!(["0x2", "latest", []])).await;
    assert!(result(&v).get("reward").is_none());
}

#[tokio::test]
async fn a_transaction_whose_sender_cannot_be_recovered_is_an_error_not_the_zero_address() {
    let r = rig(OnMiss::Fetch, true);
    let tx =
        TxLegacy { nonce: 9, gas_limit: 21_000, to: TxKind::Call(ALICE), ..Default::default() };
    let bad =
        TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::new(U256::ZERO, U256::ZERO, false)));
    let tx_hash = format!("{:#x}", bad.tx_hash());
    let parent = r.chain.head().unwrap();
    let header = Header {
        number: parent.header.number + 1,
        parent_hash: parent.hash,
        timestamp: now(),
        ..parent.header.clone()
    };
    let b = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody { transactions: vec![bad], ommers: vec![], withdrawals: None }),
    };
    r.chain.insert(b.clone()).unwrap();
    r.chain.set_head(b.hash).unwrap();
    for (m, p) in [
        ("eth_getTransactionByHash", json!([tx_hash])),
        ("eth_getTransactionByBlockNumberAndIndex", json!(["latest", "0x0"])),
        ("eth_getBlockByNumber", json!(["latest", true])),
    ] {
        let v = call(&r.api, m, p).await;
        let (code, msg) = error(&v);
        assert_eq!(code, -32000, "{m}");
        assert!(msg.contains("sender"), "{m}: {msg}");
    }
    // Hashes only: no sender needed.
    assert!(call(&r.api, "eth_getBlockByNumber", json!(["latest", false]))
        .await
        .get("result")
        .is_some());
}

#[tokio::test]
async fn blockhash_follows_the_call_blocks_own_ancestry() {
    let r = rig(OnMiss::Fetch, true);
    let sibling = |parent: &HeldBlock, salt: u8| {
        let header = Header {
            number: parent.header.number + 1,
            parent_hash: parent.hash,
            extra_data: vec![salt].into(),
            ..r.blocks[2].header.clone()
        };
        HeldBlock {
            hash: header.hash_slow(),
            header,
            beacon_root: B256::ZERO,
            body: Arc::new(BlockBody::default()),
        }
    };
    // A side branch from 1001: 1002' and 1003', not canonical.
    let s2 = sibling(&r.blocks[1], 7);
    let s3 = sibling(&s2, 7);
    r.chain.insert(s2.clone()).unwrap();
    r.chain.insert(s3.clone()).unwrap();
    let at =
        |b: &HeldBlock| json!([{"to": h(PARENT_HASH)}, {"blockHash": format!("{:#x}", b.hash)}]);
    let word = |b: B256| format!("{b:#x}");
    assert_eq!(result(&call(&r.api, "eth_call", at(&s3)).await), &json!(word(s2.hash)));
    // On the canonical block the canonical parent.
    assert_eq!(
        result(&call(&r.api, "eth_call", at(&r.blocks[3])).await),
        &json!(word(r.blocks[2].hash))
    );
}

#[tokio::test]
async fn a_seeded_anchor_alone_is_not_served() {
    let r = rig(OnMiss::Fetch, false);
    r.chain.seed(HeldBlock {
        hash: B256::repeat_byte(1),
        header: Header { number: 7, timestamp: now(), ..Default::default() },
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody::default()),
    });
    assert_eq!(error(&call(&r.api, "eth_blockNumber", json!([])).await), (-32000, NO_HEAD));
    assert_eq!(
        error(&call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"])).await).1,
        NO_HEAD
    );
    // Blocks by number or hash are not served either.
    let by_number = call(&r.api, "eth_getBlockByNumber", json!(["0x7", false])).await;
    assert_eq!(error(&by_number), (-32000, NO_HEAD));
    let hash = format!("{:#x}", B256::repeat_byte(1));
    let by_hash = call(&r.api, "eth_getBlockByHash", json!([hash, false])).await;
    assert_eq!(error(&by_hash), (-32000, NO_HEAD));
}

#[tokio::test]
async fn a_stale_head_is_refused_for_latest_and_state_reads() {
    // A head whose timestamp is two minutes old.
    let r = rig(OnMiss::Fetch, true);
    let parent = r.chain.head().unwrap();
    let header = Header {
        number: parent.header.number + 1,
        parent_hash: parent.hash,
        timestamp: now() - 120,
        ..parent.header.clone()
    };
    let b = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody::default()),
    };
    r.chain.insert(b.clone()).unwrap();
    r.chain.set_head(b.hash).unwrap();
    for (m, p) in [
        ("eth_blockNumber", json!([])),
        ("eth_getBalance", json!([h(ALICE), "latest"])),
        ("eth_call", json!([{"to": h(VIEW)}, "latest"])),
        ("eth_getBlockByNumber", json!(["latest", false])),
    ] {
        let v = call(&r.api, m, p).await;
        let (code, msg) = error(&v);
        assert_eq!(code, -32000, "{m}");
        assert!(msg.contains("head is stale"), "{m}: {msg}");
    }
    // A block named by hash is still served: it was verified.
    let by_hash =
        call(&r.api, "eth_getBlockByHash", json!([format!("{:#x}", r.blocks[1].hash), false]));
    assert!(by_hash.await.get("result").is_some());
}

#[tokio::test]
async fn a_head_not_moved_within_the_bound_is_stale() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig {
            chain_id: 943,
            // Wide enough that a slow CI setup does not make the head stale before the first check.
            head_max_age: Duration::from_secs(6),
            ..LiteConfig::default()
        },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher: r.honest.clone(),
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    assert!(call(&r.api, "eth_blockNumber", json!([])).await.get("result").is_some());
    tokio::time::sleep(Duration::from_millis(6300)).await;
    let v = call(&r.api, "eth_blockNumber", json!([])).await;
    assert!(error(&v).1.contains("head is stale"), "{v}");
}

#[tokio::test]
async fn eth_syncing_reports_a_sync_whenever_the_head_is_stale() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig {
            chain_id: 943,
            // Wide enough that a slow CI setup does not make the head stale before the first check.
            head_max_age: Duration::from_secs(6),
            ..LiteConfig::default()
        },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher: r.honest.clone(),
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    assert_eq!(result(&call(&r.api, "eth_syncing", json!([])).await), &json!(false));
    tokio::time::sleep(Duration::from_millis(6300)).await;
    // The head has not moved for 6 s: reads are refused as stale, so a health check must not see
    // `false`.
    let v = call(&r.api, "eth_blockNumber", json!([])).await;
    assert!(error(&v).1.contains(STALE_HEAD), "{v}");
    let v = call(&r.api, "eth_syncing", json!([])).await;
    assert_eq!(
        result(&v),
        &json!({"startingBlock": "0x3e8", "currentBlock": "0x3eb", "highestBlock": "0x3eb"})
    );
}

/// Halts the chain while it fetches, as an anchor check could mid-request.
struct HaltingFetcher {
    chain: Arc<HeaderChain>,
    inner: Arc<Honest>,
}

#[async_trait]
impl Fetcher for HaltingFetcher {
    async fn fetch(&self, root: B256, misses: &[crate::state::MissKey]) -> Result<(), FetchError> {
        self.chain.set_halted(Some(HaltReason::AnchorMismatch));
        self.inner.fetch(root, misses).await
    }
}

#[tokio::test]
async fn a_halt_during_a_request_is_seen_before_the_answer_goes_out() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig { chain_id: 943, ..LiteConfig::default() },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher: Arc::new(HaltingFetcher { chain: r.chain.clone(), inner: r.honest.clone() }),
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"])).await;
    assert_eq!(error(&v), (-32000, HALTED_MESSAGE));
}

#[tokio::test]
async fn a_halt_or_reseed_during_a_batch_drops_the_answers_computed_before_it() {
    for halt in [true, false] {
        let mut r = rig(OnMiss::Fetch, true);
        let (fetcher, message): (Arc<dyn Fetcher>, _) = if halt {
            (
                Arc::new(HaltingFetcher { chain: r.chain.clone(), inner: r.honest.clone() }),
                HALTED_MESSAGE,
            )
        } else {
            let to = r.blocks[3].clone();
            (
                Arc::new(ReseedingFetcher { chain: r.chain.clone(), to, inner: r.honest.clone() }),
                RESEEDED,
            )
        };
        r.api = Api::new(ApiParts {
            cfg: LiteConfig { chain_id: 943, ..LiteConfig::default() },
            chain: r.chain.clone(),
            store: r.honest.store.clone(),
            fetcher,
            receipts: Arc::new(Receipts(vec![])),
            metrics: r.metrics.clone(),
            hot: Arc::new(HotSet::new(0)),
            trust_label: String::new(),
        })
        .unwrap();
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
            {"jsonrpc": "2.0", "id": 2, "method": "eth_chainId", "params": []},
            {"jsonrpc": "2.0", "id": 3, "method": "eth_getBalance", "params": [h(ALICE), "latest"]},
        ]);
        let v = handle(&r.api, batch.to_string().as_bytes()).await;
        assert_eq!(error(&v[0]), (-32000, message));
        assert_eq!(v[0]["id"], 1);
        assert_eq!(result(&v[1]), "0x3af");
        assert_eq!(error(&v[2]), (-32000, message));
    }
}

#[tokio::test]
async fn a_revert_or_evm_error_computed_before_a_halt_or_reseed_is_not_sent() {
    // No gas past the intrinsic cost: LOOPER runs out of gas at its first opcode.
    let out_of_gas = json!([{"to": h(LOOPER), "gas": "0x5208"}, "latest"]);
    for halt in [true, false] {
        let mut r = rig(OnMiss::Fetch, true);
        let revert = json!([{"to": h(REVERTER)}, "latest"]);
        // The callees' state is held before the chain changes, so the batch's calls fetch nothing.
        assert_eq!(call(&r.api, "eth_call", revert.clone()).await["error"]["code"], 3);
        let v = call(&r.api, "eth_call", out_of_gas.clone()).await;
        assert_eq!(error(&v), (-32000, "out of gas"));
        let (fetcher, message): (Arc<dyn Fetcher>, _) = if halt {
            (
                Arc::new(HaltingFetcher { chain: r.chain.clone(), inner: r.honest.clone() }),
                HALTED_MESSAGE,
            )
        } else {
            let to = r.blocks[3].clone();
            (
                Arc::new(ReseedingFetcher { chain: r.chain.clone(), to, inner: r.honest.clone() }),
                RESEEDED,
            )
        };
        r.api = Api::new(ApiParts {
            cfg: LiteConfig { chain_id: 943, ..LiteConfig::default() },
            chain: r.chain.clone(),
            store: r.honest.store.clone(),
            fetcher,
            receipts: Arc::new(Receipts(vec![])),
            metrics: r.metrics.clone(),
            hot: Arc::new(HotSet::new(0)),
            trust_label: String::new(),
        })
        .unwrap();
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": ["0x12", "latest"]},
            {"jsonrpc": "2.0", "id": 2, "method": "eth_call", "params": revert},
            {"jsonrpc": "2.0", "id": 3, "method": "eth_call", "params": out_of_gas},
            {"jsonrpc": "2.0", "id": 4, "method": "eth_getBalance", "params": [h(ALICE), "latest"]},
        ]);
        let v = handle(&r.api, batch.to_string().as_bytes()).await;
        // A refused request is not an answer from the chain: it stays.
        assert_eq!(error(&v[0]), (-32602, "invalid address"), "{halt}");
        for (i, it) in v.as_array().unwrap().iter().enumerate().skip(1) {
            assert_eq!(it["error"], json!({"code": -32000, "message": message}), "{halt} {i}");
        }
    }
    // A revert or an EVM error on state fetched while the chain halts.
    for p in [json!([{"to": h(REVERTER)}, "latest"]), out_of_gas] {
        let r = rig(OnMiss::Fetch, true);
        let halting = Arc::new(HaltingFetcher { chain: r.chain.clone(), inner: r.honest.clone() });
        let api = api_with(&r, cfg_943(), halting, Arc::new(Receipts(vec![])));
        let v = call(&api, "eth_call", p.clone()).await;
        assert_eq!(v["error"], json!({"code": -32000, "message": HALTED_MESSAGE}), "{p}");
    }
}

#[tokio::test]
async fn require_canonical_refuses_a_block_off_the_canonical_chain() {
    let r = rig(OnMiss::Fetch, true);
    let header = Header { extra_data: vec![9].into(), ..r.blocks[3].header.clone() };
    let side = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody::default()),
    };
    r.chain.insert(side.clone()).unwrap();
    let at = |canon: bool| json!([h(ALICE), {"blockHash": format!("{:#x}", side.hash), "requireCanonical": canon}]);
    assert!(call(&r.api, "eth_getBalance", at(false)).await.get("result").is_some());
    let v = call(&r.api, "eth_getBalance", at(true)).await;
    let (code, msg) = error(&v);
    assert_eq!(code, -32000);
    assert!(msg.contains("canonical"), "{msg}");
}

#[tokio::test]
async fn safe_and_finalized_are_refused_until_finality_is_confirmed() {
    let r = rig(OnMiss::Fetch, true);
    for tag in ["safe", "finalized"] {
        let v = call(&r.api, "eth_getBlockByNumber", json!([tag, false])).await;
        assert_eq!(error(&v), (-32000, FINALITY_UNCONFIRMED), "{tag}");
    }
    assert!(r.chain.confirm_finalized(&r.blocks[0]));
    let v = call(&r.api, "eth_getBlockByNumber", json!(["finalized", false])).await;
    assert_eq!(result(&v)["hash"], format!("{:#x}", r.blocks[0].hash));
}

/// Re-seeds the chain while it fetches, as a confirmed anchor re-seed could mid-request.
struct ReseedingFetcher {
    chain: Arc<HeaderChain>,
    to: HeldBlock,
    inner: Arc<Honest>,
}

#[async_trait]
impl Fetcher for ReseedingFetcher {
    async fn fetch(&self, root: B256, misses: &[crate::state::MissKey]) -> Result<(), FetchError> {
        self.chain.reseed(self.to.clone());
        self.inner.fetch(root, misses).await
    }
}

#[tokio::test]
async fn a_reseed_during_a_request_is_seen_before_the_answer_goes_out() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig { chain_id: 943, ..LiteConfig::default() },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher: Arc::new(ReseedingFetcher {
            chain: r.chain.clone(),
            to: r.blocks[3].clone(),
            inner: r.honest.clone(),
        }),
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"])).await;
    assert_eq!(error(&v), (-32000, RESEEDED));
}

#[tokio::test]
async fn fee_history_entries_line_up_with_oldest_block_when_finality_lags_the_window() {
    let r = rig(OnMiss::Fetch, true);
    // The finalized block stays at 1000 while the head runs 600 past it: blocks between 1000
    // and the window floor are no longer held. Each base fee is its block number.
    let mut parent = r.chain.head().unwrap();
    for _ in 0..600 {
        let number = parent.header.number + 1;
        let header = Header {
            number,
            parent_hash: parent.hash,
            timestamp: now(),
            base_fee_per_gas: Some(number),
            ..parent.header.clone()
        };
        let b = HeldBlock {
            hash: header.hash_slow(),
            header,
            beacon_root: B256::ZERO,
            body: Arc::new(BlockBody::default()),
        };
        r.chain.insert(b.clone()).unwrap();
        r.chain.set_head(b.hash).unwrap();
        parent = b;
    }
    let floor = 1603 - crate::chain::HEADERS_WINDOW;
    for (count, newest, oldest, len) in
        [("0x400", "latest", floor, 513), ("0xa", "0x447", floor, 5), ("0x1", "0x3e8", 1000, 1)]
    {
        let v = call(&r.api, "eth_feeHistory", json!([count, newest, []])).await;
        let v = result(&v);
        assert_eq!(v["oldestBlock"], hex_u64(oldest), "{count} {newest}");
        let ratios = v["gasUsedRatio"].as_array().unwrap();
        let fees = v["baseFeePerGas"].as_array().unwrap();
        assert_eq!((ratios.len(), fees.len()), (len, len + 1), "{count} {newest}");
        for (i, fee) in fees[..len].iter().enumerate() {
            let n = oldest + i as u64;
            let want = if n == 1000 { 1_000_000_000 } else { n };
            assert_eq!(fee, &json!(hex_u64(want)), "entry {i} of {count} {newest}");
        }
    }
}

#[tokio::test]
async fn fee_history_at_a_side_block_reads_only_that_blocks_fork() {
    let r = rig(OnMiss::Fetch, true);
    // A held sibling of the canonical head, with its own base fee and gas used.
    let header =
        Header { base_fee_per_gas: Some(7), gas_used: 15_000_000, ..r.blocks[3].header.clone() };
    let side = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody::default()),
    };
    r.chain.insert(side.clone()).unwrap();
    assert!(!r.chain.is_canonical(&side.hash));
    let v = call(&r.api, "eth_feeHistory", json!(["0x2", format!("{:#x}", side.hash), []])).await;
    let next = calc_next_block_base_fee(15_000_000, 30_000_000, 7, BaseFeeParams::ethereum());
    assert_eq!(
        result(&v),
        &json!({
            "oldestBlock": hex_u64(1002),
            "baseFeePerGas": [hex_u64(1_000_000_000), hex_u64(7), hex_u64(next)],
            "gasUsedRatio": [0.0, 0.5],
        })
    );
}

#[tokio::test]
async fn request_bodies_are_capped_and_share_one_byte_budget() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let budget = 300 << 10;
    let limits = ServerLimits {
        body_budget: budget,
        body_idle_timeout: Duration::from_millis(400),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let head = |len: usize| {
        format!("POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {len}\r\n\r\n")
    };
    async fn read(sock: &mut tokio::net::TcpStream, wait: Duration) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(wait, sock.read(&mut buf)).await.ok()?.ok()?;
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
    }
    let connect = || tokio::net::TcpStream::connect(addr);
    // A body over the cap is refused from its declared length, before it is read.
    let mut big = connect().await.unwrap();
    big.write_all(head(MAX_BODY + 1).as_bytes()).await.unwrap();
    let resp = read(&mut big, Duration::from_secs(2)).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert_eq!(MAX_BODY, 5 << 20);

    // A body padded to `len` bytes.
    let small = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let padded = |len: usize| format!("{small}{}", " ".repeat(len - small.len()));
    // A declared length that no byte has followed holds nothing.
    let mut silent = connect().await.unwrap();
    silent.write_all(head(4 << 20).as_bytes()).await.unwrap();
    // Two bodies 110 KiB past the free part, then a stall: they hold 220 KiB of the 300 KiB.
    let mut stalled = Vec::new();
    for _ in 0..2 {
        let mut sock = connect().await.unwrap();
        let body = padded(FREE_BODY + (110 << 10));
        sock.write_all(format!("{}{}", head(body.len()), &body[..FREE_BODY + 1]).as_bytes())
            .await
            .unwrap();
        stalled.push(sock);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut waiting = connect().await.unwrap();
    let body = padded(FREE_BODY + (100 << 10));
    waiting.write_all(format!("{}{body}", head(body.len())).as_bytes()).await.unwrap();
    assert_eq!(read(&mut waiting, Duration::from_millis(200)).await, None, "over the byte budget");
    // A body within the free part does not wait for the budget.
    let mut next = connect().await.unwrap();
    next.write_all(format!("{}{small}", head(small.len())).as_bytes()).await.unwrap();
    assert!(read(&mut next, Duration::from_millis(200)).await.unwrap().contains("0x3eb"));
    // The stalled bodies time out at the idle timeout; their bytes are freed, within the second
    // the waiting body may wait for them.
    for sock in std::iter::once(&mut silent).chain(&mut stalled) {
        let resp = read(sock, Duration::from_secs(2)).await.unwrap();
        assert!(resp.contains(REQUEST_TIMED_OUT), "{resp}");
    }
    assert!(read(&mut waiting, Duration::from_secs(2)).await.unwrap().contains("0x3eb"));
    // A body past the free part by more than the whole budget is refused, never charged.
    let mut over = connect().await.unwrap();
    let body = padded(FREE_BODY + budget + 1);
    over.write_all(format!("{}{body}", head(body.len())).as_bytes()).await.unwrap();
    let resp = read(&mut over, Duration::from_secs(2)).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    task.abort();
}

#[tokio::test]
async fn params_past_a_methods_arguments_are_refused_as_geth_does() {
    let r = rig(OnMiss::Fetch, true);
    for (method, params, want) in [
        ("eth_chainId", json!([1]), 0),
        ("eth_blockNumber", json!([0]), 0),
        ("eth_getBalance", json!([h(ALICE), "latest", 0]), 2),
        ("eth_getStorageAt", json!([h(VIEW), "0x7", "latest", 0]), 3),
        ("eth_call", json!([{"to": h(VIEW)}, "latest", null, {}, 0]), 4),
        ("eth_estimateGas", json!([{"to": h(VIEW)}, "latest", null, {}, 0]), 4),
        ("eth_getTransactionReceipt", json!([format!("{:#x}", B256::ZERO), 0]), 1),
        ("eth_feeHistory", json!(["0x1", "latest", [], 0]), 3),
    ] {
        let v = call(&r.api, method, params).await;
        let msg = format!("too many arguments, want at most {want}");
        assert_eq!(error(&v), (-32602, msg.as_str()), "{method}");
    }
    assert_eq!(result(&call(&r.api, "eth_chainId", json!([])).await), "0x3af");
    let v = call(&r.api, "eth_call", json!([{"to": h(VIEW)}, "latest", null, {}])).await;
    assert!(v.get("result").is_some(), "{v}");
}

#[tokio::test]
async fn a_body_of_many_small_values_is_charged_for_its_parsed_form() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut r = rig(OnMiss::Fetch, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig { chain_id: 943, ..LiteConfig::default() },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher: Arc::new(Stuck::default()),
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    let limits = ServerLimits {
        body_budget: 4 << 20,
        request_timeout: Duration::from_secs(2),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let post = |body: String| {
        format!(
            "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    async fn read(sock: &mut (impl AsyncRead + Unpin), wait: Duration) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(wait, sock.read(&mut buf)).await.ok()?.ok()?;
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
    }
    // A body within the free part, but about 30k values: about 4 MiB parsed. It waits on a peer.
    let zeros = vec![0u8; 30_000];
    let pad = json!({"blockNumber": "latest", "pad": zeros});
    let junk = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
        "params": [h(ALICE), pad]})
    .to_string();
    assert!(junk.len() <= FREE_BODY);
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    first.write_all(post(junk).as_bytes()).await.unwrap();
    assert_eq!(read(&mut first, Duration::from_millis(200)).await, None);
    // 1 MiB of body does not fit beside it: within a second it is answered busy, and the rest of
    // it is read and dropped.
    let small = json!({"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber"}).to_string();
    let padded = post(format!("{small}{}", " ".repeat(1 << 20)));
    let send = async |padded: String| {
        let (mut rd, mut wr) = tokio::net::TcpStream::connect(addr).await.unwrap().into_split();
        let sent = tokio::spawn(async move { wr.write_all(padded.as_bytes()).await.map(|()| wr) });
        let resp = read(&mut rd, Duration::from_secs(5)).await;
        drop(sent.await.unwrap().unwrap());
        resp.unwrap()
    };
    let resp = send(padded.clone()).await;
    assert!(resp.contains(r#""code":-32005"#) && resp.contains(BODY_BUDGET_FULL), "{resp}");
    assert!(read(&mut first, Duration::from_secs(5)).await.unwrap().contains(REQUEST_TIMED_OUT));
    assert!(send(padded).await.contains("0x3eb"));
    task.abort();
}

#[tokio::test]
async fn bodies_whose_parsed_charges_overlap_do_not_wait_on_each_other() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits {
        body_budget: 1 << 20,
        request_timeout: Duration::from_secs(10),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    async fn read(sock: &mut tokio::net::TcpStream, wait: Duration) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(wait, sock.read(&mut buf)).await.ok()?.ok()?;
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
    }
    // 400 KiB past the free part is read under the read charge; its parsed form takes it to
    // nearly the whole 1 MiB budget. Two read charges fit, but not one read charge and one whole
    // charge.
    let req =
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "pad": vec![0u8; 1000]});
    let text = req.to_string();
    let body = format!("{text}{}", " ".repeat(FREE_BODY + (400 << 10) - text.len()));
    let mut cost = JsonCost::default();
    cost.feed(body.as_bytes());
    let (read_charge, total) = (body.len() - FREE_BODY, body.len() + cost.cost() - FREE_BODY);
    assert!(2 * read_charge <= 1 << 20 && total <= 1 << 20 && read_charge + total > 1 << 20);
    let post = format!(
        "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let split = post.len() - body.len() + FREE_BODY + 1;
    let (mut first, mut second) = (
        tokio::net::TcpStream::connect(addr).await.unwrap(),
        tokio::net::TcpStream::connect(addr).await.unwrap(),
    );
    // Both take their read charge, then each sends the rest of its body.
    for sock in [&mut first, &mut second] {
        sock.write_all(&post.as_bytes()[..split]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    first.write_all(&post.as_bytes()[split..]).await.unwrap();
    // The first waits up to a second for its parsed charge; the second waits from here.
    tokio::time::sleep(Duration::from_millis(600)).await;
    second.write_all(&post.as_bytes()[split..]).await.unwrap();
    // The first gives up its read charge with the retryable code, and the second is served.
    let resp = read(&mut first, Duration::from_secs(3)).await.expect("bodies wait on each other");
    assert!(resp.contains(r#""code":-32005"#) && resp.contains(BODY_BUDGET_FULL), "{resp}");
    let resp = read(&mut second, Duration::from_secs(3)).await.expect("the second is not served");
    assert!(resp.contains("0x3eb"), "{resp}");
    // Every charge is freed.
    let mut third = tokio::net::TcpStream::connect(addr).await.unwrap();
    third.write_all(post.as_bytes()).await.unwrap();
    assert!(read(&mut third, Duration::from_secs(3)).await.unwrap().contains("0x3eb"));
    task.abort();
}

#[test]
fn json_cost_counts_values_outside_strings_fed_in_any_pieces() {
    let text = br#"{"a":[0,"x,:[{\",{}"],"b":{}}"#;
    for split in 0..=text.len() {
        let mut c = JsonCost::default();
        c.feed(&text[..split]);
        c.feed(&text[split..]);
        // `{ : [ ,` and `, : {` outside the string, and the first value.
        assert_eq!((c.values, c.bytes), (7, text.len()), "{split}");
        assert_eq!(c.cost(), 8 * PARSED_VALUE_COST + text.len());
    }
}

#[tokio::test]
async fn a_body_that_drips_in_slower_than_the_minimum_rate_frees_the_budget() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits {
        body_budget: 300 << 10,
        body_idle_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(8),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let head = |len: usize| {
        format!("POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {len}\r\n\r\n")
    };
    let small = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let padded = |len: usize| format!("{small}{}", " ".repeat(len - small.len()));
    // Past the free part, then one byte each half second: within the idle timeout, it holds 250
    // KiB of the 300 KiB budget.
    let body = padded(FREE_BODY + (250 << 10));
    let (mut drip_read, mut drip) =
        tokio::net::TcpStream::connect(addr).await.unwrap().into_split();
    drip.write_all(format!("{}{}", head(body.len()), &body[..FREE_BODY + 1]).as_bytes())
        .await
        .unwrap();
    let dripping = tokio::spawn(async move {
        while drip.write_all(b" ").await.is_ok() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
    // The drip is cut at the idle timeout plus its length at the minimum rate (about 2 s), not at
    // the request timeout.
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(4), drip_read.read(&mut buf))
        .await
        .expect("a dripping body holds the budget until its request timeout")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains(REQUEST_TIMED_OUT));
    dripping.abort();
    // Its charge is freed: a body that needs most of the budget is served at once.
    let mut honest = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = padded(FREE_BODY + (100 << 10));
    honest.write_all(format!("{}{body}", head(body.len())).as_bytes()).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), honest.read(&mut buf)).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n.unwrap()]).contains("0x3eb"));
    task.abort();
}

/// Initcode that reverts with `len` zero bytes (`PUSH3 len PUSH1 0 REVERT`).
fn revert_with(len: u32) -> String {
    let l = len.to_be_bytes();
    format!("0x62{:02x}{:02x}{:02x}6000fd", l[1], l[2], l[3])
}

#[tokio::test]
async fn a_batch_stops_at_the_response_cap_and_ids_must_be_scalars() {
    let r = rig(OnMiss::Fetch, true);
    // Each item is about 2 MiB of hex revert data: 12 of them pass geth's cap of 25,000,000
    // bytes, but not 25 MiB.
    let item = |id: u64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "eth_call",
            "params": [{"data": revert_with(1 << 20)}, "latest"]})
    };
    let batch = Value::Array((0..15).map(item).collect());
    let v = handle(&r.api, batch.to_string().as_bytes()).await;
    let items = v.as_array().unwrap();
    assert_eq!(items.len(), 15);
    assert_eq!(items[0]["error"]["code"], 3, "a revert with its data");
    assert_eq!(items[10]["error"]["code"], 3);
    let twelve = 12 * serde_json::to_vec(&items[0]).unwrap().len();
    assert!(twelve > 25_000_000 && twelve < 25 << 20, "{twelve}");
    for (i, it) in items.iter().enumerate().skip(11) {
        assert_eq!(it["id"], i, "{i}");
        assert_eq!(error(it), (-32003, RESPONSE_TOO_LARGE), "{i}");
    }
    assert!(serde_json::to_vec(&v).unwrap().len() <= MAX_RESPONSE);
    // An id that is not a string, number or null is an invalid request, not echoed.
    for id in [json!({"a": 1}), json!([1]), json!(true)] {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "eth_chainId"});
        let v = handle(&r.api, req.to_string().as_bytes()).await;
        assert_eq!((v["id"].clone(), error(&v)), (Value::Null, (-32600, "invalid request")));
    }
    for id in [json!("x"), json!(1), Value::Null] {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "eth_chainId"});
        assert_eq!(handle(&r.api, req.to_string().as_bytes()).await["id"], id);
    }
}

#[tokio::test]
async fn answers_are_charged_to_one_response_budget() {
    let r = rig(OnMiss::Fetch, true);
    let budget = Arc::new(tokio::sync::Semaphore::new(5 << 20));
    let far = Instant::now() + Duration::from_secs(600);
    // Each answer is about 2 MiB of hex revert data: two fit, the third does not.
    let item = |id: u64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "eth_call",
            "params": [{"data": revert_with(1 << 20)}, "latest"]})
    };
    let batch = Value::Array((0..4).map(item).collect()).to_string();
    let (v, held) = handle_value(&r.api, batch.as_bytes(), far, &budget).await.unwrap();
    let items = v.as_array().unwrap();
    assert_eq!(
        (items[0]["error"]["code"].clone(), items[1]["error"]["code"].clone()),
        (json!(3), json!(3))
    );
    for it in &items[2..] {
        assert_eq!(error(it), (-32005, RESPONSE_BUDGET_FULL));
    }
    let charged = json_len(&items[0]) + json_len(&items[1]) - FREE_RESPONSE;
    assert_eq!(budget.available_permits(), (5 << 20) - charged);
    // Until the reply is written, the next one finds no room.
    let one = item(9).to_string();
    let (v, _) = handle_value(&r.api, one.as_bytes(), far, &budget).await.unwrap();
    assert_eq!(error(&v), (-32005, RESPONSE_BUDGET_FULL));
    drop(held);
    let (v, _) = handle_value(&r.api, one.as_bytes(), far, &budget).await.unwrap();
    assert_eq!(v["error"]["code"], 3);
}

#[tokio::test]
async fn a_batch_answers_nothing_after_the_response_budget_refuses_an_item() {
    let r = rig(OnMiss::Fetch, true);
    // Room for one answer of about 2 MiB and a small one, not for two large ones.
    let budget = Arc::new(tokio::sync::Semaphore::new(3 << 20));
    let far = Instant::now() + Duration::from_secs(600);
    let large = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"data": revert_with(1 << 20)}, "latest"]});
    let small = json!({"jsonrpc": "2.0", "id": 3, "method": "eth_blockNumber"});
    let batch = json!([large, large, small]).to_string();
    let (v, held) = handle_value(&r.api, batch.as_bytes(), far, &budget).await.unwrap();
    assert_eq!(v[0]["error"]["code"], 3);
    // The small answer would fit, but a batch item that follows a refusal is not run.
    for it in &v.as_array().unwrap()[1..] {
        assert_eq!(error(it), (-32005, RESPONSE_BUDGET_FULL), "{}", it["id"]);
    }
    let charged = json_len(&v[0]) - FREE_RESPONSE;
    assert_eq!(held.as_ref().map(|p| p.num_permits()), Some(charged));
    assert_eq!(budget.available_permits(), (3 << 20) - charged);
}

#[tokio::test]
async fn a_render_holds_its_permit_until_it_ends_after_its_request_has_left() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let render = move || {
        wait.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(Value::Null)
    };
    // The request times out and leaves while its render still runs on a blocking thread.
    let left = tokio::time::timeout(Duration::from_millis(50), render_blocking(&permits, render));
    assert!(left.await.is_err());
    assert_eq!(permits.available_permits(), 0, "a render that still runs freed its permit");
    go.send(()).unwrap();
    let freed = tokio::time::timeout(Duration::from_secs(5), permits.acquire()).await;
    assert!(freed.is_ok(), "a render that ended kept its permit");
}

#[tokio::test]
async fn a_single_answer_may_pass_the_batch_cap_up_to_its_own() {
    let r = rig(OnMiss::Fetch, true);
    // Two receipts with one log of `data` bytes each, which render as twice as many hex digits.
    let receipts_api = |data: usize| {
        let mut one = wire_receipt(21_000);
        one.receipt.logs[0].data =
            alloy_primitives::LogData::new_unchecked(vec![], vec![0; data].into());
        let set = Receipts(vec![one.clone(), one]);
        api_with(&r, cfg_943(), r.honest.clone(), Arc::new(set))
    };
    // As a log-spam block of a 45M gas limit, past the batch cap.
    let api = receipts_api(MAX_RESPONSE / 3);
    let v = call(&api, "eth_getBlockReceipts", json!(["latest"])).await;
    assert!(json_len(&v) > MAX_RESPONSE, "{}", json_len(&v));
    assert_eq!(result(&v).as_array().unwrap().len(), 2);
    let api = receipts_api(MAX_SINGLE_RESPONSE / 4 + 1);
    let v = call(&api, "eth_getBlockReceipts", json!(["latest"])).await;
    assert_eq!(error(&v), (-32003, RESPONSE_TOO_LARGE));
}

#[tokio::test]
async fn small_answers_are_served_while_large_ones_fill_the_response_budget() {
    let r = rig(OnMiss::Fetch, true);
    // Stalled readers hold the whole budget.
    let budget = Arc::new(tokio::sync::Semaphore::new(0));
    let far = Instant::now() + Duration::from_secs(600);
    // An id of 1000 bytes: about 60 answers fill the free part.
    let id = "i".repeat(1000);
    let small = json!({"jsonrpc": "2.0", "id": id, "method": "eth_blockNumber"}).to_string();
    let (v, held) = handle_value(&r.api, small.as_bytes(), far, &budget).await.unwrap();
    assert_eq!((result(&v), held.is_none()), (&json!("0x3eb"), true));
    // A batch is free up to `FREE_RESPONSE` in all; the answer that crosses it is charged.
    let one = json_len(&rpc_response(&json!(id), Ok(json!("0x3eb"))));
    let fit = FREE_RESPONSE / one;
    let batch = Value::Array(vec![serde_json::from_str(&small).unwrap(); fit + 1]).to_string();
    let (v, held) = handle_value(&r.api, batch.as_bytes(), far, &budget).await.unwrap();
    let items = v.as_array().unwrap();
    assert!(held.is_none());
    for it in &items[..fit] {
        assert_eq!(result(it), "0x3eb");
    }
    assert_eq!(error(&items[fit]), (-32005, RESPONSE_BUDGET_FULL));
    // A large answer still needs room.
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "eth_call",
        "params": [{"data": revert_with(1 << 20)}, "latest"]});
    let (v, _) = handle_value(&r.api, call.to_string().as_bytes(), far, &budget).await.unwrap();
    assert_eq!(error(&v), (-32005, RESPONSE_BUDGET_FULL));
    budget.add_permits(2 << 20);
    let (v, held) = handle_value(&r.api, call.to_string().as_bytes(), far, &budget).await.unwrap();
    assert_eq!(v["error"]["code"], 3);
    let charged = json_len(&v) - FREE_RESPONSE;
    assert_eq!(held.as_ref().map(|p| p.num_permits()), Some(charged));
    assert_eq!(budget.available_permits(), (2 << 20) - charged);
}

#[tokio::test]
async fn a_response_holds_its_budget_until_the_client_has_read_it() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits { response_budget: 20 << 20, ..ServerLimits::default() };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let post = |body: String| {
        format!(
            "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let call = |id: u64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "eth_call",
            "params": [{"data": revert_with(4 << 20)}, "latest"]})
    };
    // About 16 MiB of response, more than the socket buffers hold; not read yet.
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    first.write_all(post(json!([call(1), call(2)]).to_string()).as_bytes()).await.unwrap();
    // The first bytes show the response is charged; the rest stays unread.
    let mut head = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(10), first.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    let ask = || async {
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(post(call(3).to_string()).as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 1 << 10];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await.unwrap();
        String::from_utf8_lossy(&buf[..n.unwrap()]).into_owned()
    };
    // About 8 MiB more does not fit in the 20 MiB budget.
    let resp = ask().await;
    assert!(resp.contains(RESPONSE_BUDGET_FULL), "{resp}");
    // Once the first response is read, its bytes are free.
    let (mut buf, mut all) = (vec![0u8; 1 << 20], Vec::new());
    while !all.ends_with(b"}]") {
        let n = tokio::time::timeout(Duration::from_secs(5), first.read(&mut buf)).await;
        let n = n.unwrap().unwrap();
        assert!(n > 0, "the first response ended early");
        all.extend_from_slice(&buf[..n]);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = ask().await;
    assert!(resp.contains("\"code\":3"), "{resp}");
    task.abort();
}

#[tokio::test]
async fn a_client_that_stops_reading_loses_its_connection_after_the_write_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits {
        max_connections: 1,
        write_timeout: Duration::from_millis(300),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let post = |body: String| {
        format!(
            "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    // About 16 MiB of response, far more than the socket buffers hold; never read.
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"data": revert_with(4 << 20)}, "latest"]});
    let big = json!([call, call]);
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled.write_all(post(big.to_string()).as_bytes()).await.unwrap();
    // The one connection slot frees once the stalled write times out.
    let small = json!({"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber"}).to_string();
    let mut next = tokio::net::TcpStream::connect(addr).await.unwrap();
    next.write_all(post(small).as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), next.read(&mut buf))
        .await
        .expect("the stalled connection still holds the only slot")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("0x3eb"));
    drop(stalled);
    task.abort();
}

#[tokio::test]
async fn a_client_that_reads_too_slowly_loses_its_connection_at_the_response_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rig(OnMiss::Fetch, true);
    // About 16 MiB of response must be written within 2 s + 1 s.
    let limits = ServerLimits {
        max_connections: 1,
        write_timeout: Duration::from_secs(2),
        min_write_rate: 16 << 20,
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    let post = |body: String| {
        format!(
            "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"data": revert_with(4 << 20)}, "latest"]});
    let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
    slow.write_all(post(json!([call, call]).to_string()).as_bytes()).await.unwrap();
    // 64 KiB every 100 ms: progress well within the write timeout, 25 s for the whole response.
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 << 10];
        while matches!(slow.read(&mut buf).await, Ok(n) if n > 0) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let small = json!({"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber"}).to_string();
    let mut next = tokio::net::TcpStream::connect(addr).await.unwrap();
    next.write_all(post(small).as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(8), next.read(&mut buf))
        .await
        .expect("the slow reader still holds the only slot")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("0x3eb"));
    reader.abort();
    task.abort();
}

/// Counts how often a task on the test's single runtime thread gets polled.
fn ticker() -> Arc<std::sync::atomic::AtomicUsize> {
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticks = n.clone();
    tokio::spawn(async move {
        loop {
            ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::task::yield_now().await;
        }
    });
    n
}

#[tokio::test]
async fn batches_and_block_rendering_let_other_tasks_run() {
    let r = rig(OnMiss::Fetch, true);
    let ticks = ticker();
    let ran = |before: usize| ticks.load(std::sync::atomic::Ordering::SeqCst) > before;
    let item = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"});
    let batch = Value::Array(vec![item; MAX_BATCH]);
    let before = ticks.load(std::sync::atomic::Ordering::SeqCst);
    let v = handle(&r.api, batch.to_string().as_bytes()).await;
    assert_eq!(v.as_array().unwrap().len(), MAX_BATCH);
    assert!(ran(before), "a batch ran in one poll");
    for (m, p) in [
        ("eth_getBlockByNumber", json!(["latest", true])),
        ("eth_getBlockReceipts", json!(["latest"])),
    ] {
        let before = ticks.load(std::sync::atomic::Ordering::SeqCst);
        assert!(call(&r.api, m, p).await.get("result").is_some(), "{m}");
        assert!(ran(before), "{m} recovered every sender in one poll");
    }
}

#[tokio::test]
async fn block_rendering_waits_for_a_render_permit_not_an_execution_permit() {
    let r = rig(OnMiss::Fetch, true);
    let n = u32::try_from(crate::call::MAX_CONCURRENT_EXECUTIONS).unwrap();
    let evm = r.api.exec.exec_permits.clone().acquire_many_owned(n).await.unwrap();
    let calls = [
        ("eth_getBlockByNumber", json!(["latest", true])),
        ("eth_getBlockReceipts", json!(["latest"])),
    ];
    // Busy EVM runs do not hold up rendering.
    for (m, p) in calls.clone() {
        let v = tokio::time::timeout(Duration::from_secs(5), call(&r.api, m, p)).await;
        assert!(v.is_ok_and(|v| v.get("result").is_some()), "{m} waited for an EVM permit");
    }
    drop(evm);
    let n = u32::try_from(MAX_CONCURRENT_RENDERS).unwrap();
    let all = r.api.render_permits.clone().acquire_many_owned(n).await.unwrap();
    for (m, p) in calls {
        let wait = tokio::time::timeout(Duration::from_millis(200), call(&r.api, m, p)).await;
        assert!(wait.is_err(), "{m} rendered with every render permit taken");
    }
    drop(all);
    let v = call(&r.api, "eth_getBlockByNumber", json!(["latest", true])).await;
    assert_eq!(result(&v)["transactions"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_transaction_receipt_needs_only_its_own_sender() {
    let r = rig(OnMiss::Fetch, true);
    let tx =
        TxLegacy { nonce: 9, gas_limit: 21_000, to: TxKind::Call(ALICE), ..Default::default() };
    let bad =
        TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::new(U256::ZERO, U256::ZERO, false)));
    let good = legacy_tx(4, 1_000_000_000);
    let (good_hash, from) = (format!("{:#x}", good.tx_hash()), recover(&good).unwrap());
    let parent = r.chain.head().unwrap();
    let header = Header {
        number: parent.header.number + 1,
        parent_hash: parent.hash,
        timestamp: now(),
        ..parent.header.clone()
    };
    let b = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody {
            transactions: vec![bad, good],
            ommers: vec![],
            withdrawals: None,
        }),
    };
    r.chain.insert(b.clone()).unwrap();
    r.chain.set_head(b.hash).unwrap();
    let v = call(&r.api, "eth_getTransactionReceipt", json!([good_hash])).await;
    let rcpt = result(&v);
    assert_eq!(rcpt["transactionIndex"], "0x1");
    assert_eq!(rcpt["gasUsed"], "0x5208");
    assert_eq!(rcpt["cumulativeGasUsed"], "0xa410");
    assert_eq!(rcpt["logs"][0]["logIndex"], "0x1");
    assert_eq!(rcpt["from"], format!("{from:#x}"));
    // The whole block still needs every sender.
    let all = call(&r.api, "eth_getBlockReceipts", json!(["latest"])).await;
    assert_eq!(error(&all), (-32000, BAD_SENDER));
}

#[tokio::test]
async fn blockhash_of_an_unheld_ancestor_fails_at_once_with_its_own_error() {
    // Initcode `PUSH1 5 NUMBER SUB BLOCKHASH POP STOP`: block 998 at the head 1003, below the
    // seeded anchor 1000, so never held.
    let call_998 = json!([{"data": "0x6005430340500000"}, "latest"]);
    for mode in [OnMiss::Fetch, OnMiss::Error, OnMiss::ErrorAndWarm] {
        let r = rig(mode, true);
        // Hold the caller, so the hash is the round's only miss.
        let fetching = api_with(&r, cfg_943(), r.honest.clone(), Arc::new(Receipts(vec![])));
        result(&call(&fetching, "eth_getBalance", json!([h(Address::ZERO), "latest"])).await);
        let fetched = r.honest.calls.load(std::sync::atomic::Ordering::SeqCst);
        for m in ["eth_call", "eth_estimateGas"] {
            let v = call(&r.api, m, call_998.clone()).await;
            assert_eq!(error(&v), (-32000, BLOCKHASH_NOT_HELD), "{m} {mode:?}");
        }
        assert_eq!(r.honest.calls.load(std::sync::atomic::Ordering::SeqCst), fetched, "{mode:?}");
        assert!(r.api.warming.lock().keys.is_empty(), "no warm job for {mode:?}");
    }
    // A held ancestor still answers.
    let r = rig(OnMiss::Fetch, true);
    let held = json!([{"data": "0x6001430340500000"}, "latest"]);
    assert_eq!(result(&call(&r.api, "eth_call", held).await), "0x");
}

#[tokio::test]
async fn blockhash_of_an_unheld_ancestor_fails_after_the_state_it_missed_with_is_fetched() {
    // The first round misses the caller and the hash of block 998: the state is fetched, and the
    // next round, whose only miss is the hash, ends the call.
    let call_998 = json!([{"data": "0x6005430340500000"}, "latest"]);
    for m in ["eth_call", "eth_estimateGas"] {
        let r = rig(OnMiss::Fetch, true);
        let v = call(&r.api, m, call_998.clone()).await;
        assert_eq!(error(&v), (-32000, BLOCKHASH_NOT_HELD), "{m}");
        assert_eq!(r.honest.calls.load(std::sync::atomic::Ordering::SeqCst), 1, "{m}");
    }
}

#[tokio::test]
async fn blockhash_on_a_path_only_a_default_took_does_not_end_the_call() {
    // A round that reads slot 0 as the default zero takes the `BLOCKHASH(998)` path.
    let p = json!([{"to": h(BRANCHER)}, "latest"]);
    let r = rig(OnMiss::Fetch, true);
    assert_eq!(result(&call(&r.api, "eth_call", p.clone()).await), "0x");
    for mode in [OnMiss::Error, OnMiss::ErrorAndWarm] {
        let r = rig(mode, true);
        // Hold the caller and BRANCHER's code, not its slot.
        let fetching = api_with(&r, cfg_943(), r.honest.clone(), Arc::new(Receipts(vec![])));
        for a in [Address::ZERO, BRANCHER] {
            result(&call(&fetching, "eth_getCode", json!([h(a), "latest"])).await);
        }
        let v = call(&r.api, "eth_call", p.clone()).await;
        assert_eq!(
            v["error"],
            json!({"code": MISS_CODE, "message": MISS_MESSAGE, "data": {"missing": 2}}),
            "{mode:?}"
        );
    }
    // The warm job fetches the slot; the next call answers.
    let r = rig(OnMiss::ErrorAndWarm, true);
    call(&r.api, "eth_call", p.clone()).await;
    for _ in 0..100 {
        let v = call(&r.api, "eth_call", p.clone()).await;
        if v.get("result").is_some() {
            assert_eq!(result(&v), "0x");
            return;
        }
        assert_eq!(error(&v), (MISS_CODE, MISS_MESSAGE));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the warm job never made the call servable");
}

/// A fetcher that never answers, counting the fetches started.
#[derive(Default)]
struct Stuck(std::sync::atomic::AtomicUsize);

#[async_trait]
impl Fetcher for Stuck {
    async fn fetch(&self, _: B256, _: &[crate::state::MissKey]) -> Result<(), FetchError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        futures::future::pending().await
    }
}

fn warm_rig(fetcher: Arc<dyn Fetcher>) -> Rig {
    let mut r = rig(OnMiss::ErrorAndWarm, true);
    r.api = Api::new(ApiParts {
        cfg: LiteConfig { chain_id: 943, on_miss: OnMiss::ErrorAndWarm, ..LiteConfig::default() },
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher,
        receipts: Arc::new(Receipts(vec![])),
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap();
    r
}

#[tokio::test(start_paused = true)]
async fn warm_jobs_hold_at_most_max_warm_bytes_of_params() {
    let r = warm_rig(Arc::new(Stuck::default()));
    let balance =
        |a: Address, pad: usize| json!([h(a), {"blockNumber": "latest", "pad": "a".repeat(pad)}]);
    // A multicall's 100 KiB of calldata is warmed.
    let v = call(&r.api, "eth_getBalance", balance(ALICE, 100 << 10)).await;
    assert_eq!(error(&v).0, MISS_CODE);
    assert_eq!(r.api.warming.lock().keys.len(), 1);
    // Params that take the bytes held past the bound are not.
    let big = balance(VIEW, MAX_WARM_BYTES - (100 << 10));
    assert_eq!(error(&call(&r.api, "eth_getBalance", big.clone()).await).0, MISS_CODE);
    assert_eq!(r.api.warming.lock().keys.len(), 1, "over the byte bound");
    // Once the first job ends, they fit.
    tokio::time::sleep(WARM_TIMEOUT + Duration::from_secs(1)).await;
    assert_eq!(r.api.warming.lock().bytes, 0);
    call(&r.api, "eth_getBalance", big.clone()).await;
    let w = r.api.warming.lock();
    assert_eq!((w.keys.len(), w.bytes), (1, warm_key("eth_getBalance", &big).1));
    // Params of many small values count what their clone takes, not their serialized length.
    let many = json!([h(COLD), {"blockNumber": "latest", "pad": vec![0u8; 1000]}]);
    assert!(warm_key("eth_getBalance", &many).1 > 1000 * PARSED_VALUE_COST);
}

struct Panics;

#[async_trait]
impl Fetcher for Panics {
    async fn fetch(&self, _: B256, _: &[crate::state::MissKey]) -> Result<(), FetchError> {
        panic!("fetch panicked")
    }
}

#[tokio::test]
async fn a_warm_job_that_panics_frees_its_key() {
    let r = warm_rig(Arc::new(Panics));
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"])).await;
    assert_eq!(error(&v).0, MISS_CODE);
    for _ in 0..100 {
        if r.api.warming.lock().keys.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("a panicked warm job keeps its key");
}

#[tokio::test(start_paused = true)]
async fn warm_jobs_run_a_few_at_once_and_wait_for_a_slot_at_most_the_timeout() {
    let stuck = Arc::new(Stuck::default());
    let r = warm_rig(stuck.clone());
    let started = || stuck.0.load(std::sync::atomic::Ordering::SeqCst);
    let balance = |i: usize| json!([h(Address::with_last_byte(i as u8)), "latest"]);
    let warm_call = |a: Address| call(&r.api, "eth_call", json!([{"to": h(a)}, "latest"]));
    for i in 0..WARM_READS_RUNNING {
        assert_eq!(error(&call(&r.api, "eth_getBalance", balance(i)).await).0, MISS_CODE, "{i}");
    }
    for a in [VIEW, REVERTER] {
        assert_eq!(error(&warm_call(a).await).0, MISS_CODE, "{a}");
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    let running = WARM_READS_RUNNING + WARM_CALLS_RUNNING;
    assert_eq!(started(), running);
    // Jobs past the slots wait: one read more than the slots that free at the first timeout,
    // and a third call.
    tokio::time::sleep(Duration::from_secs(1)).await;
    for i in WARM_READS_RUNNING..=2 * WARM_READS_RUNNING {
        assert_eq!(error(&call(&r.api, "eth_getBalance", balance(i)).await).0, MISS_CODE, "{i}");
    }
    assert_eq!(error(&warm_call(COLD).await).0, MISS_CODE);
    assert_eq!(started(), running);
    assert_eq!(r.api.warming.lock().keys.len(), running + WARM_READS_RUNNING + 2, "not queued");
    // The first jobs time out; the waiting jobs start and each has its own full timeout.
    tokio::time::sleep(WARM_TIMEOUT - Duration::from_millis(500)).await;
    assert_eq!(started(), running + WARM_READS_RUNNING + 1);
    // The last read's wait ends at its timeout, before any slot frees.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(r.api.warming.lock().keys.len(), WARM_READS_RUNNING + 1, "a read waits forever");
    tokio::time::sleep(WARM_TIMEOUT).await;
    assert!(r.api.warming.lock().keys.is_empty(), "a stuck warm job never ends");
    assert_eq!(started(), running + WARM_READS_RUNNING + 1);
}

#[tokio::test(start_paused = true)]
async fn warm_calls_hold_at_most_their_share_of_the_warm_keys() {
    let stuck = Arc::new(Stuck::default());
    let r = warm_rig(stuck.clone());
    for i in 0..MAX_WARM {
        let req = json!([{"to": h(VIEW), "data": format!("0x{i:04x}")}, "latest"]);
        assert_eq!(error(&call(&r.api, "eth_call", req).await).0, MISS_CODE, "{i}");
    }
    assert_eq!(r.api.warming.lock().keys.len(), WARM_CALLS_HELD);
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), "latest"])).await;
    assert_eq!(error(&v).0, MISS_CODE);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(stuck.0.load(std::sync::atomic::Ordering::SeqCst), WARM_CALLS_RUNNING + 1);
    assert_eq!(r.api.warming.lock().keys.len(), WARM_CALLS_HELD + 1);
    // Once the calls end, a call is warmed again.
    tokio::time::sleep(WARM_TIMEOUT * 9).await;
    assert!(r.api.warming.lock().keys.is_empty());
    let req = json!([{"to": h(VIEW), "data": "0xffff"}, "latest"]);
    assert_eq!(error(&call(&r.api, "eth_call", req).await).0, MISS_CODE);
    assert_eq!(r.api.warming.lock().keys.len(), 1);
}

#[test]
fn the_accept_loop_pauses_after_errors_that_repeat_at_once() {
    use io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset};
    for kind in [ConnectionAborted, ConnectionReset, ConnectionRefused] {
        assert_eq!(accept_pause(&io::Error::from(kind)), None, "{kind}");
    }
    // EMFILE and ENFILE, the same numbers on Linux and macOS.
    for errno in [24, 23] {
        assert_eq!(accept_pause(&io::Error::from_raw_os_error(errno)), Some(ACCEPT_ERROR_PAUSE));
    }
}

#[tokio::test]
async fn the_accept_loop_waits_between_descriptor_errors_and_then_serves() {
    let r = rig(OnMiss::Fetch, true);
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let addr = listener.local_addr().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let accept = {
        let attempts = attempts.clone();
        move || {
            let (attempts, listener) = (attempts.clone(), listener.clone());
            async move {
                let n = {
                    let mut a = attempts.lock();
                    a.push(Instant::now());
                    a.len()
                };
                if n <= 2 {
                    // EMFILE.
                    return Err(io::Error::from_raw_os_error(24));
                }
                listener.accept().await.map(|(sock, _)| sock)
            }
        }
    };
    let task = tokio::spawn(accept_loop(r.api.clone(), ServerLimits::default(), accept));
    let one = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let head = format!("content-length: {}\r\nconnection: close\r\n", one.len());
    let resp = post_raw(addr, &head, one.as_bytes(), Duration::from_secs(5)).await;
    assert!(resp.contains("0x3eb"), "{resp}");
    let a = attempts.lock().clone();
    assert_eq!(a.len(), 4, "two errors, the served connection, the next accept");
    for i in 1..3 {
        assert!(a[i] - a[i - 1] >= ACCEPT_ERROR_PAUSE, "attempt {i} came at once");
    }
    task.abort();
}

#[tokio::test]
async fn a_null_block_parameter_is_latest_for_state_reads() {
    let r = rig(OnMiss::Fetch, true);
    let v = call(&r.api, "eth_getBalance", json!([h(ALICE), null])).await;
    assert_eq!(result(&v), "0xde0b6b3a7640000");
    let v = call(&r.api, "eth_getStorageAt", json!([h(VIEW), "0x7", null])).await;
    assert_eq!(*result(&v), format!("{:#066x}", 1234));
    let v = call(&r.api, "eth_call", json!([{"to": h(VIEW), "data": "0x"}, null])).await;
    assert_eq!(*result(&v), format!("{:#066x}", 1234));
}

#[tokio::test]
async fn blocks_omit_the_total_difficulty_the_node_cannot_know() {
    let r = rig(OnMiss::Fetch, true);
    for full in [false, true] {
        let v = call(&r.api, "eth_getBlockByNumber", json!(["latest", full])).await;
        let block = result(&v).as_object().unwrap();
        assert!(block.contains_key("hash"), "{v}");
        assert!(!block.contains_key("totalDifficulty"), "{v}");
    }
}

// --- parsers of request values ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn quantities_round_trip_and_only_hex_digits_parse(
        n: u64,
        s in "(0x)?[0-9a-fA-F+_ g-]{0,20}",
    ) {
        for text in [format!("{n:#x}"), format!("0x{n:X}"), format!("0x000{n:x}")] {
            prop_assert_eq!(parse_quantity(&text), Some(n), "{}", text);
        }
        prop_assert_eq!(index_param(&json!([format!("{n:#x}")]), 0), Ok(usize::try_from(n).unwrap()));
        let h = s.strip_prefix("0x");
        let hex = h.filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()));
        match parse_quantity(&s) {
            // The value is what the digits spell.
            Some(v) => prop_assert_eq!(Some(v), hex.map(|h| u64::from_str_radix(h, 16).unwrap())),
            // Refused only when not `0x` and hex digits, or when too large.
            None => prop_assert!(hex.is_none_or(|h| h.trim_start_matches('0').len() > 16), "{}", s),
        }
    }

    #[test]
    fn storage_keys_round_trip_and_only_hex_digits_parse(
        key: [u8; 32],
        s in "(0x)?[0-9a-fA-F+_ g-]{0,70}",
    ) {
        let x = U256::from_be_bytes(key);
        let padded = alloy_primitives::hex::encode(key);
        for text in [format!("{x:#x}"), format!("0x{padded}"), padded.clone()] {
            prop_assert_eq!(parse_slot(&json!(text)), Ok(x), "{}", text);
        }
        let invalid = || Err(RpcError::params("invalid storage key"));
        prop_assert_eq!(parse_slot(&json!(format!("0x0{padded}"))), invalid());
        let h = s.strip_prefix("0x").unwrap_or(&s);
        let hex = (1..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit());
        let want = if hex { Ok(U256::from_str_radix(h, 16).unwrap()) } else { invalid() };
        prop_assert_eq!(parse_slot(&json!(s)), want, "{}", s);
    }
}

// --- revert data ---

/// A word near the bounds an ABI offset or length must survive. Offset 32 points at the
/// generated length word, so it is drawn often.
fn abi_word() -> impl Strategy<Value = U256> {
    prop_oneof![
        Just(U256::from(32)),
        (0u64..200).prop_map(U256::from),
        (0u64..64).prop_map(|d| U256::from(u64::MAX - d)),
        (0u64..64).prop_map(|d| U256::from(usize::MAX) - U256::from(d)),
        any::<[u8; 32]>().prop_map(U256::from_be_bytes),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn revert_data_never_panics_and_a_decoded_reason_lies_inside_it(
        raw in vec(any::<u8>(), 0..300),
        off in abi_word(),
        len in abi_word(),
        tail in vec(any::<u8>(), 0..200),
    ) {
        let mut abi = vec![0x08, 0xc3, 0x79, 0xa0];
        abi.extend(off.to_be_bytes::<32>());
        abi.extend(len.to_be_bytes::<32>());
        abi.extend(tail);
        for data in [raw, abi] {
            let e = revert_error(&Bytes::from(data.clone()));
            prop_assert_eq!(e.code, 3);
            prop_assert_eq!(e.data, Some(json!(Bytes::from(data.clone()))));
            match decode_revert_reason(&data) {
                Some(r) => {
                    prop_assert!(r.is_empty() || data.windows(r.len()).any(|w| w == r.as_bytes()));
                    prop_assert_eq!(e.message, format!("execution reverted: {r}"));
                }
                None => prop_assert_eq!(e.message, "execution reverted"),
            }
        }
    }

    #[test]
    fn error_strings_round_trip(
        reason in any::<String>(),
        gap in vec(any::<u8>(), 0..64),
        after in vec(any::<u8>(), 0..64),
    ) {
        // The offset may skip `gap` bytes, and bytes after the string are padding.
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
        data.extend(U256::from(32 + gap.len()).to_be_bytes::<32>());
        data.extend(gap);
        data.extend(U256::from(reason.len()).to_be_bytes::<32>());
        data.extend(reason.as_bytes());
        data.extend(after);
        prop_assert_eq!(decode_revert_reason(&data), Some(reason.clone()));
        prop_assert_eq!(revert_error(&Bytes::from(data)).message, format!("execution reverted: {reason}"));
    }
}

// --- request bodies ---

/// Call-object and EIP-1898 keys, so generated objects reach the parsers behind them.
const FIELDS: &[&str] = &[
    "to",
    "from",
    "data",
    "input",
    "gas",
    "value",
    "blockHash",
    "blockNumber",
    "requireCanonical",
];

fn json_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>().prop_map(Value::from),
        "0x[0-9a-f]{0,66}".prop_map(Value::from),
        prop::sample::select(&["latest", "pending", "safe", "finalized", "earliest", "0x3eb"][..])
            .prop_map(Value::from),
        prop::sample::select(vec![ALICE, VIEW, REVERTER, COLD]).prop_map(|a| json!(h(a))),
        "\\PC{0,8}".prop_map(Value::from),
    ]
}

fn json_value() -> impl Strategy<Value = Value> {
    json_leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            vec((prop::sample::select(FIELDS), inner), 0..4).prop_map(|kv| {
                Value::Object(kv.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
            }),
        ]
    })
}

/// A batch entry: mostly a request, with every shape of id, version and params.
fn rpc_request() -> impl Strategy<Value = Value> {
    let methods: Vec<&str> =
        SERVED.iter().copied().chain(["eth_sendRawTransaction", "eth_getLogs", ""]).collect();
    let id = prop_oneof![
        Just(None),
        Just(Some(Value::Null)),
        any::<u64>().prop_map(|n| Some(json!(n))),
        "\\PC{0,6}".prop_map(|s| Some(json!(s))),
        Just(Some(json!({"a": 1}))),
        Just(Some(json!([1]))),
    ];
    let version = prop_oneof![
        4 => Just(Some(json!("2.0"))),
        1 => Just(None),
        1 => Just(Some(json!("1.0"))),
        1 => Just(Some(json!(2.0))),
    ];
    let params = prop_oneof![
        4 => vec(json_value(), 0..4).prop_map(|p| Some(Value::Array(p))),
        1 => Just(None),
        1 => json_value().prop_map(Some),
    ];
    prop_oneof![
        9 => (prop::sample::select(methods), params, id, version).prop_map(
            |(method, params, id, version)| {
                let mut req = json!({"method": method});
                for (k, v) in [("params", params), ("id", id), ("jsonrpc", version)] {
                    if let Some(v) = v {
                        req[k] = v;
                    }
                }
                req
            }
        ),
        1 => json_value(),
    ]
}

/// JSON-RPC 2.0: a request with no id gets no reply.
fn is_spec_notification(req: &Value) -> bool {
    req.get("jsonrpc") == Some(&json!("2.0")) &&
        req.get("id").is_none() &&
        req.get("method").is_some_and(Value::is_string)
}

/// `resp` is a JSON-RPC 2.0 response to `req`: the version, `req`'s id when it is a scalar (else
/// null), and exactly one of result or error.
fn check_reply(req: &Value, resp: &Value) -> Result<(), TestCaseError> {
    let o =
        resp.as_object().ok_or_else(|| TestCaseError::fail(format!("not an object: {resp}")))?;
    prop_assert_eq!(o.get("jsonrpc"), Some(&json!("2.0")), "{}", resp);
    let id = match req.get("id") {
        Some(id @ (Value::Null | Value::Number(_) | Value::String(_))) => id.clone(),
        _ => Value::Null,
    };
    prop_assert_eq!(o.get("id"), Some(&id), "{}", resp);
    prop_assert_eq!(o.len(), 3, "{}", resp);
    match (o.get("result"), o.get("error")) {
        (Some(_), None) => {}
        (None, Some(e)) => prop_assert!(e["code"].is_i64() && e["message"].is_string(), "{}", resp),
        _ => prop_assert!(false, "not one of result or error: {}", resp),
    }
    Ok(())
}

/// The reply `resp` that [`handle_body`] gave to `body` has the shape the body asks for.
fn check_body(body: &[u8], resp: Option<Value>) -> Result<(), TestCaseError> {
    match serde_json::from_slice::<Value>(body) {
        Err(_) => {
            let resp = resp.ok_or_else(|| TestCaseError::fail("no reply to a parse error"))?;
            check_reply(&Value::Null, &resp)?;
            prop_assert_eq!(&resp["error"]["code"], &json!(-32700));
        }
        Ok(Value::Array(batch)) if batch.is_empty() => {
            let resp = resp.ok_or_else(|| TestCaseError::fail("no reply to an empty batch"))?;
            check_reply(&Value::Null, &resp)?;
            prop_assert_eq!(&resp["error"], &json!({"code": -32600, "message": "empty batch"}));
        }
        Ok(Value::Array(batch)) if batch.len() > MAX_BATCH => {
            let resp = resp.ok_or_else(|| TestCaseError::fail("no reply to a large batch"))?;
            let out = resp.as_array().ok_or_else(|| TestCaseError::fail("not an array"))?;
            prop_assert_eq!(out.len(), 1);
            prop_assert_eq!(&out[0]["error"], &json!({"code": -32600, "message": BATCH_TOO_LARGE}));
        }
        Ok(Value::Array(batch)) => {
            let asked: Vec<&Value> = batch.iter().filter(|r| !is_spec_notification(r)).collect();
            let Some(resp) = resp else {
                prop_assert!(asked.is_empty(), "no reply to {} requests", asked.len());
                return Ok(())
            };
            let out = resp
                .as_array()
                .ok_or_else(|| TestCaseError::fail("a batch reply is not an array"))?;
            prop_assert_eq!(out.len(), asked.len());
            for (req, resp) in asked.into_iter().zip(out) {
                check_reply(req, resp)?;
            }
        }
        Ok(single) if is_spec_notification(&single) => prop_assert_eq!(resp, None),
        Ok(single) => {
            let resp = resp.ok_or_else(|| TestCaseError::fail("no reply to a request"))?;
            check_reply(&single, &resp)?;
        }
    }
    Ok(())
}

#[test]
fn every_body_gets_well_formed_replies_in_request_order() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let r = rig(OnMiss::Error, true);
    let answer = |body: &[u8]| {
        let deadline = Instant::now() + Duration::from_secs(600);
        let budget = Arc::new(tokio::sync::Semaphore::new(tokio::sync::Semaphore::MAX_PERMITS));
        rt.block_on(handle_value(&r.api, body, deadline, &budget)).map(|(v, _)| v)
    };
    let bodies = prop_oneof![
        vec(rpc_request(), 0..=8).prop_map(|b| Value::Array(b).to_string().into_bytes()),
        vec(rpc_request(), MAX_BATCH..=MAX_BATCH + 1)
            .prop_map(|b| Value::Array(b).to_string().into_bytes()),
        rpc_request().prop_map(|v| v.to_string().into_bytes()),
        vec(any::<u8>(), 0..200),
        // A request with one byte changed: mostly a parse error, sometimes another request.
        (rpc_request(), any::<prop::sample::Index>(), any::<u8>()).prop_map(|(v, i, b)| {
            let mut s = v.to_string().into_bytes();
            let at = i.index(s.len());
            s[at] = b;
            s
        }),
    ];
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(128));
    runner.run(&bodies, |body| check_body(&body, answer(&body))).unwrap();
}

// --- BLOCKHASH ancestry ---

/// `BLOCKHASH(n)` for a call at `blk`, by walking parent links through `held`.
fn walk_ancestor(held: &HashMap<B256, HeldBlock>, blk: &HeldBlock, n: u64) -> Option<B256> {
    let number = blk.header.number;
    if n >= number || number - n > 256 {
        return None;
    }
    let mut cur = blk;
    while cur.header.number > n + 1 {
        cur = held.get(&cur.header.parent_hash)?;
    }
    Some(cur.header.parent_hash)
}

/// A chain seeded at `seed`, `len` canonical blocks on it, and a side branch of `side` blocks
/// from the canonical block at index `fork`. Returns every block inserted.
fn branching_chain(
    seed: u64,
    len: u64,
    fork: usize,
    side: u64,
) -> (Arc<HeaderChain>, Vec<HeldBlock>) {
    let chain = Arc::new(HeaderChain::new());
    let anchor = crate::chain::test_block(seed, B256::repeat_byte(0xcc), 0);
    chain.seed(anchor.clone());
    let mut held = vec![anchor];
    for salt in [0, 1] {
        let (count, mut parent) =
            if salt == 0 { (len, held[0].clone()) } else { (side, held[fork].clone()) };
        for _ in 0..count {
            let b = crate::chain::test_block(parent.header.number + 1, parent.hash, salt);
            chain.insert(b.clone()).unwrap();
            held.push(b.clone());
            parent = b;
        }
        if salt == 0 {
            chain.set_head(parent.hash).unwrap();
        }
    }
    (chain, held)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn call_block_hashes_match_a_walk_of_parent_links(
        seed in prop_oneof![0u64..300, 10_000u64..10_300],
        len in 1u64..320,
        fork: prop::sample::Index,
        side in 0u64..20,
        pick: prop::sample::Index,
        // How far below the call block `n` is; negative is above it.
        depth in prop_oneof![-2i64..300, 255i64..=258],
    ) {
        let (chain, held) = branching_chain(seed, len, fork.index(len as usize + 1), side);
        let blk = &held[pick.index(held.len())];
        let n = blk.header.number.saturating_add_signed(-depth);
        let by_hash: HashMap<B256, HeldBlock> = held.iter().map(|b| (b.hash, b.clone())).collect();
        let want = walk_ancestor(&by_hash, blk, n);
        let unheld = Arc::new(Unheld::default());
        prop_assert_eq!(call_block_hashes(chain, blk, unheld.clone())(n), want);
        let in_range = n < blk.header.number && blk.header.number - n <= 256;
        let asked = unheld.asked.lock().clone();
        prop_assert_eq!(asked, HashSet::from_iter((in_range && want.is_none()).then_some(n)));
    }
}

#[test]
fn blockhash_reaches_exactly_256_blocks_back() {
    let (chain, held) = branching_chain(0, 300, 0, 0);
    let blk = &held[300];
    let hashes = call_block_hashes(chain, blk, Arc::new(Unheld::default()));
    assert_eq!(hashes(300 - 256), Some(held[300 - 256].hash));
    assert_eq!(hashes(299), Some(held[299].hash));
    for n in [300 - 257, 300, 301] {
        assert_eq!(hashes(n), None, "{n}");
    }
}

#[test]
fn blockhash_walks_each_ancestor_of_a_side_block_once() {
    // A side branch of 20 blocks from block 250: its ancestors are found by walking parents.
    let (chain, held) = branching_chain(0, 300, 250, 20);
    let blk = held.last().unwrap();
    assert!(!chain.is_canonical(&blk.hash));
    let hashes = call_block_hashes(chain.clone(), blk, Arc::new(Unheld::default()));
    assert_eq!(hashes(100), Some(held[100].hash));
    // With the chain gone, only an answer kept from the first walk is left.
    chain.reseed(crate::chain::test_block(1000, B256::repeat_byte(0xdd), 0));
    assert_eq!(hashes(100), Some(held[100].hash));
    assert_eq!(hashes(101), None);
}

// --- receipts ---

/// A block of legacy transactions, `true` for a create, with recoverable senders.
fn block_of(creates: &[bool]) -> HeldBlock {
    let transactions = creates
        .iter()
        .enumerate()
        .map(|(i, create)| {
            let to = if *create { TxKind::Create } else { TxKind::Call(ALICE) };
            let tx = TxLegacy {
                nonce: i as u64,
                gas_price: 1,
                gas_limit: 100_000,
                to,
                ..Default::default()
            };
            TxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
        })
        .collect();
    let header = Header { number: 7, base_fee_per_gas: Some(0), ..Default::default() };
    HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody { transactions, ommers: vec![], withdrawals: None }),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn block_receipts_number_logs_and_split_gas_by_transaction(
        txs in vec((any::<bool>(), 0usize..4, 21_000u64..100_000), 0..8),
    ) {
        let creates: Vec<bool> = txs.iter().map(|t| t.0).collect();
        let b = block_of(&creates);
        let mut cumulative = 0;
        let receipts: Vec<WireReceipt> = txs
            .iter()
            .map(|(_, logs, gas)| {
                cumulative += gas;
                let mut r = wire_receipt(cumulative);
                r.receipt.logs = vec![r.receipt.logs[0].clone(); *logs];
                r
            })
            .collect();
        let out = rpc_receipts(&b, &receipts).unwrap();
        let total: usize = txs.iter().map(|t| t.1).sum();
        let indexes: Vec<u64> =
            out.iter().flat_map(|r| r.inner.logs().iter().map(|l| l.log_index.unwrap())).collect();
        prop_assert_eq!(indexes, (0..total as u64).collect::<Vec<_>>());
        prop_assert_eq!(out.iter().map(|r| r.gas_used).sum::<u64>(), cumulative);
        for (i, (r, (create, _, gas))) in out.iter().zip(&txs).enumerate() {
            prop_assert_eq!(r.gas_used, *gas);
            prop_assert_eq!(r.transaction_index, Some(i as u64));
            prop_assert!(r.inner.logs().iter().all(|l| l.transaction_index == Some(i as u64)));
            prop_assert_eq!(r.to.is_none(), *create);
            prop_assert_eq!(r.contract_address, create.then(|| r.from.create(i as u64)));
        }
        // A receipt list of any other length is refused.
        let mismatch = || Err(RpcError::other("receipts do not match the block"));
        let mut longer = receipts.clone();
        longer.push(wire_receipt(cumulative));
        prop_assert_eq!(rpc_receipts(&b, &longer), mismatch());
        if let Some((_, shorter)) = receipts.split_last() {
            prop_assert_eq!(rpc_receipts(&b, shorter), mismatch());
        }
    }
}

// --- fixtures for single-path tests ---

/// A new API over the rig's chain and store.
fn api_with(
    r: &Rig,
    cfg: LiteConfig,
    fetcher: Arc<dyn Fetcher>,
    receipts: Arc<dyn ReceiptSource>,
) -> Arc<Api> {
    Api::new(ApiParts {
        cfg,
        chain: r.chain.clone(),
        store: r.honest.store.clone(),
        fetcher,
        receipts,
        metrics: r.metrics.clone(),
        hot: Arc::new(HotSet::new(0)),
        trust_label: String::new(),
    })
    .unwrap()
}

fn cfg_943() -> LiteConfig {
    LiteConfig { chain_id: 943, ..LiteConfig::default() }
}

/// Puts a block of `transactions` on the rig's head, with the same state and a fresh timestamp.
fn push_head(r: &Rig, transactions: Vec<TxEnvelope>) -> HeldBlock {
    let beneficiary = r.chain.head().unwrap().header.beneficiary;
    push_head_by(r, transactions, beneficiary)
}

fn push_head_by(r: &Rig, transactions: Vec<TxEnvelope>, beneficiary: Address) -> HeldBlock {
    let parent = r.chain.head().unwrap();
    let header = Header {
        number: parent.header.number + 1,
        parent_hash: parent.hash,
        timestamp: now(),
        beneficiary,
        ..parent.header
    };
    let b = HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::new(BlockBody { transactions, ommers: vec![], withdrawals: None }),
    };
    r.chain.insert(b.clone()).unwrap();
    r.chain.set_head(b.hash).unwrap();
    b
}

#[tokio::test]
async fn state_older_than_the_state_window_answers_reths_pruned_history_error() {
    let r = rig(OnMiss::Fetch, true);
    let cfg = LiteConfig { state_window: 1, ..cfg_943() };
    let api = api_with(&r, cfg, r.honest.clone(), Arc::new(Receipts(vec![])));
    // The head is 1003: 1002 is in the window, 1001 is held but older, 999 is not held.
    let old = format!("{:#x}", r.blocks[1].hash);
    let blk = call(&api, "eth_getBlockByNumber", json!(["0x3e9", false])).await;
    assert_eq!(result(&blk)["hash"], old);
    let v = call(&api, "eth_getBalance", json!([h(ALICE), "0x3ea"])).await;
    assert_eq!(result(&v), "0xde0b6b3a7640000");
    for (n, at) in [
        (1001, json!("0x3e9")),
        (1001, json!({"blockHash": old})),
        (1000, json!("earliest")),
        (999, json!("0x3e7")),
    ] {
        for (m, p) in [
            ("eth_getBalance", json!([h(ALICE), at])),
            ("eth_getTransactionCount", json!([h(ALICE), at])),
            ("eth_getCode", json!([h(VIEW), at])),
            ("eth_getStorageAt", json!([h(VIEW), "0x7", at])),
            ("eth_call", json!([{"to": h(VIEW)}, at])),
            ("eth_estimateGas", json!([{"to": h(VIEW)}, at])),
        ] {
            assert_eq!(call(&api, m, p).await["error"], pruned(n, 1002), "{m} {at}");
        }
    }
}

#[tokio::test]
async fn block_parameters_resolve_or_are_refused_with_their_reason() {
    let r = rig(OnMiss::Fetch, true);
    let hash_of = |i: usize| json!(format!("{:#x}", r.blocks[i].hash));
    for (at, want) in [
        (json!("pending"), 3),
        (json!("0x3e8"), 0),
        (json!("0x03e8"), 0),
        (json!({"blockNumber": "0x3ea"}), 2),
        (json!({"blockHash": hash_of(1), "requireCanonical": true}), 1),
    ] {
        let v = call(&r.api, "eth_getBlockByNumber", json!([at, false])).await;
        assert_eq!(result(&v)["hash"], hash_of(want), "{at}");
    }
    for (at, want) in [
        (json!(format!("0x{}", "z".repeat(64))), "invalid block hash"),
        (json!("1".repeat(66)), "invalid block hash"),
        (json!({"blockHash": "0x1234"}), "invalid block hash"),
        (json!("newest"), "invalid block number"),
        (json!("0x+3e8"), "invalid block number"),
        (json!("0x"), "invalid block number"),
        (json!({"blockNumber": "nope"}), "invalid block number"),
        (Value::Null, "invalid block parameter"),
        (json!(true), "invalid block parameter"),
        (json!(-1), "invalid block parameter"),
        // As geth and reth: a block number is a quantity string.
        (json!(1001), "invalid block parameter"),
        (json!({}), "invalid block parameter"),
    ] {
        let v = call(&r.api, "eth_getBlockByNumber", json!([at, false])).await;
        assert_eq!(error(&v), (-32602, want), "{at}");
    }
    let v = call(&r.api, "eth_getBlockByNumber", json!([])).await;
    assert_eq!(error(&v), (-32602, "missing block parameter"));
}

/// Fails every fetch with its error.
struct Failing(FetchError);

#[async_trait]
impl Fetcher for Failing {
    async fn fetch(&self, _: B256, _: &[crate::state::MissKey]) -> Result<(), FetchError> {
        Err(self.0.clone())
    }
}

#[async_trait]
impl ReceiptSource for Failing {
    async fn receipts(&self, _: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        Err(self.0.clone())
    }
}

#[tokio::test]
async fn an_evm_run_past_the_evm_timeout_answers_geths_text() {
    let r = rig(OnMiss::Fetch, true);
    assert_eq!(r.api.exec.evm_timeout, Duration::from_secs(5));
    assert_eq!(
        r.api.map_call_error(CallError::Timeout(Duration::from_secs(5))),
        RpcError::other("execution aborted (timeout = 5s)")
    );
    // LOOPER spins until the 50M gas cap runs out: millions of jumps, far more than 1 ms.
    let cfg = LiteConfig { evm_timeout: Duration::from_millis(1), ..cfg_943() };
    let api = api_with(&r, cfg, r.honest.clone(), Arc::new(Receipts(Vec::new())));
    assert_eq!(api.exec.evm_timeout, Duration::from_millis(1));
    for method in ["eth_call", "eth_estimateGas"] {
        let v = call(&api, method, json!([{"to": h(LOOPER)}, "latest"])).await;
        assert_eq!(error(&v), (-32000, "execution aborted (timeout = 1ms)"), "{method}");
    }
}

#[tokio::test]
async fn fetch_failures_and_receipts_that_do_not_match_have_their_own_texts() {
    let r = rig(OnMiss::Fetch, true);
    for (e, msg) in [
        (FetchError::NoSource, "no source could serve the request"),
        (FetchError::Unverifiable, "every source returned data that failed verification"),
    ] {
        let want = RpcError::other(format!("state unavailable: {msg}"));
        assert_eq!(r.api.map_rounds(RoundsError::Fetch(e)), want);
    }
    assert_eq!(
        r.api.map_rounds(RoundsError::TooManyRounds(40)),
        RpcError::other("state discovery did not converge after 40 rounds")
    );
    assert_eq!(r.api.map_rounds(RoundsError::Aborted), RpcError::other("execution aborted"));
    // A miss of zero pieces still reports one.
    assert_eq!(r.api.map_rounds(RoundsError::Missing(0)), RpcError::miss(1));

    let failing = Arc::new(Failing(FetchError::Unverifiable));
    let api = api_with(&r, cfg_943(), failing.clone(), failing);
    let unverifiable = "every source returned data that failed verification";
    let v = call(&api, "eth_getBalance", json!([h(ALICE), "latest"])).await;
    assert_eq!(error(&v), (-32000, format!("state unavailable: {unverifiable}").as_str()));
    let tx_hash = format!("{:#x}", r.blocks[3].body.transactions[0].tx_hash());
    let reads = [
        ("eth_getBlockReceipts", json!(["latest"])),
        ("eth_getTransactionReceipt", json!([tx_hash])),
    ];
    for (m, p) in reads.clone() {
        let v = call(&api, m, p).await;
        assert_eq!(error(&v), (-32000, format!("receipts unavailable: {unverifiable}").as_str()));
    }
    // One receipt for a block of two transactions.
    let short = Arc::new(Receipts(vec![wire_receipt(21_000)]));
    let api = api_with(&r, cfg_943(), r.honest.clone(), short);
    for (m, p) in reads {
        assert_eq!(error(&call(&api, m, p).await), (-32000, "receipts do not match the block"));
    }
}

/// Counts the receipt fetches it answers.
struct CountingReceipts(Receipts, std::sync::atomic::AtomicUsize);

#[async_trait]
impl ReceiptSource for CountingReceipts {
    async fn receipts(&self, header: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.receipts(header).await
    }
}

/// Counts the receipt fetches it starts, and answers each once the gate gives it a permit.
struct GatedReceipts {
    answer: Result<Vec<WireReceipt>, FetchError>,
    gate: tokio::sync::Semaphore,
    started: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl ReceiptSource for GatedReceipts {
    async fn receipts(&self, _: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        self.started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _permit = self.gate.acquire().await.unwrap();
        self.answer.clone()
    }
}

#[tokio::test]
async fn concurrent_reads_of_one_blocks_receipts_share_one_fetch() {
    let r = rig(OnMiss::Fetch, true);
    let txs: Vec<String> =
        r.blocks[3].body.transactions.iter().map(|t| format!("{:#x}", t.tx_hash())).collect();
    for answer in [Err(FetchError::NoSource), Ok(vec![wire_receipt(21_000), wire_receipt(42_000)])]
    {
        let source = Arc::new(GatedReceipts {
            answer: answer.clone(),
            gate: tokio::sync::Semaphore::new(0),
            started: Default::default(),
        });
        let api = api_with(&r, cfg_943(), r.honest.clone(), source.clone());
        let reads = (0..20).map(|i| {
            let api = api.clone();
            let tx = txs[i % 2].clone();
            async move {
                if i % 3 == 0 {
                    call(&api, "eth_getBlockReceipts", json!(["latest"])).await
                } else {
                    call(&api, "eth_getTransactionReceipt", json!([tx])).await
                }
            }
        });
        let release = async {
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            source.gate.add_permits(1000);
        };
        let (answers, ()) = tokio::join!(futures::future::join_all(reads), release);
        assert_eq!(source.started.load(std::sync::atomic::Ordering::SeqCst), 1, "{answer:?}");
        for v in &answers {
            match &answer {
                Ok(_) => assert!(result(v).is_object() || result(v).is_array(), "{v}"),
                Err(e) => {
                    assert_eq!(error(v), (-32000, format!("receipts unavailable: {e}").as_str()))
                }
            }
        }
        assert!(api.receipt_fetches.lock().is_empty(), "a finished fetch is still listed");
    }
}

#[tokio::test]
async fn receipts_are_fetched_once_and_the_least_recently_used_set_leaves_first() {
    let r = rig(OnMiss::Fetch, true);
    let source = Arc::new(CountingReceipts(
        Receipts(vec![wire_receipt(21_000), wire_receipt(42_000)]),
        Default::default(),
    ));
    let api = api_with(&r, cfg_943(), r.honest.clone(), source.clone());
    let fetches = || source.1.load(std::sync::atomic::Ordering::SeqCst);
    let receipts_of = |n: u64| call(&api, "eth_getBlockReceipts", json!([hex_u64(n)]));
    for _ in 0..2 {
        assert_eq!(result(&receipts_of(1003).await).as_array().unwrap().len(), 2);
    }
    assert_eq!(fetches(), 1, "the second read fetched again");
    let two = || vec![legacy_tx(0, 2_000_000_000), legacy_tx(1, 2_000_000_000)];
    for _ in 0..RECEIPT_CACHE {
        push_head(&r, two());
    }
    for n in 1004..1003 + RECEIPT_CACHE as u64 {
        result(&receipts_of(n).await);
    }
    assert_eq!((fetches(), api.receipts.lock().sets.len()), (RECEIPT_CACHE, RECEIPT_CACHE));
    // A read makes 1003 the most recently used, so one more set pushes out 1004 alone.
    result(&receipts_of(1003).await);
    result(&receipts_of(1003 + RECEIPT_CACHE as u64).await);
    assert_eq!((fetches(), api.receipts.lock().sets.len()), (RECEIPT_CACHE + 1, RECEIPT_CACHE));
    result(&receipts_of(1003).await);
    assert_eq!(fetches(), RECEIPT_CACHE + 1, "1003 was pushed out");
    result(&receipts_of(1004).await);
    assert_eq!(fetches(), RECEIPT_CACHE + 2, "1004 was kept");
}

#[tokio::test]
async fn the_receipt_cache_holds_at_most_its_byte_bound() {
    let r = rig(OnMiss::Fetch, true);
    // One receipt with a log of a third of the bound: two sets fit, three do not.
    let mut big = wire_receipt(21_000);
    big.receipt.logs[0].data =
        alloy_primitives::LogData::new_unchecked(vec![], vec![0; RECEIPT_CACHE_BYTES / 3].into());
    let set = vec![big];
    let bytes = receipt_set_bytes(&set);
    assert!(2 * bytes <= RECEIPT_CACHE_BYTES && 3 * bytes > RECEIPT_CACHE_BYTES, "{bytes}");
    let source = Arc::new(CountingReceipts(Receipts(set), Default::default()));
    let api = api_with(&r, cfg_943(), r.honest.clone(), source.clone());
    let fetches = || source.1.load(std::sync::atomic::Ordering::SeqCst);
    let blocks: Vec<_> = (0..3).map(|i| push_head(&r, vec![legacy_tx(i, 2_000_000_000)])).collect();
    for b in [&blocks[0], &blocks[1], &blocks[0], &blocks[2]] {
        api.receipts_for(b, OnMiss::Fetch).await.unwrap();
    }
    let held = |api: &Api| {
        let cache = api.receipts.lock();
        (cache.sets.len(), cache.bytes)
    };
    assert_eq!((fetches(), held(&api)), (3, (2, 2 * bytes)));
    api.receipts_for(&blocks[0], OnMiss::Fetch).await.unwrap();
    assert_eq!(fetches(), 3, "the most recently used set was pushed out");
    api.receipts_for(&blocks[1], OnMiss::Fetch).await.unwrap();
    assert_eq!(fetches(), 4, "the least recently used set was kept");
}

#[test]
fn the_receipt_cache_skips_a_set_over_its_bound_and_a_set_it_holds() {
    let mut cache = ReceiptCache::default();
    let small = Arc::new(vec![wire_receipt(21_000)]);
    let (a, b) = (B256::repeat_byte(1), B256::repeat_byte(2));
    cache.insert(a, small.clone());
    cache.insert(a, small.clone());
    assert_eq!((cache.sets.len(), cache.bytes), (1, receipt_set_bytes(&small)));
    let mut over = wire_receipt(21_000);
    over.receipt.logs[0].data =
        alloy_primitives::LogData::new_unchecked(vec![], vec![0; RECEIPT_CACHE_BYTES].into());
    cache.insert(b, Arc::new(vec![over]));
    assert!(cache.get(&b).is_none());
    assert_eq!((cache.sets.len(), cache.bytes), (1, receipt_set_bytes(&small)));
}

#[tokio::test]
async fn the_suggested_tip_is_the_60th_percentile_of_each_blocks_three_lowest() {
    let r = rig(OnMiss::Fetch, true);
    let gwei = 1_000_000_000u128;
    let block = |tips: &[u128]| {
        tips.iter().enumerate().map(|(i, t)| legacy_tx(i as u64, gwei + t * gwei)).collect()
    };
    // Tips in gwei over the 1 gwei base fee. The head already holds 1 and 2; of this block only
    // 4, 5 and 6 count.
    push_head(&r, block(&[13, 4, 12, 5, 11, 6, 10]));
    push_head(&r, block(&[9]));
    // [1, 2, 4, 5, 6, 9]: index 5 * 60 / 100 = 3.
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), &json!(hex_u128(5 * gwei)));
    let price = call(&r.api, "eth_gasPrice", json!([])).await;
    assert_eq!(result(&price), &json!(hex_u128(6 * gwei)));
}

#[tokio::test]
async fn the_suggested_tip_skips_dust_and_the_beneficiarys_own_transactions() {
    let r = rig(OnMiss::Fetch, true);
    let gwei = 1_000_000_000u128;
    // The producer's own zero-tip transaction and a 1 wei tip would be two of the three lowest.
    let own = legacy_tx(0, gwei);
    let producer = own.recover_signer().unwrap();
    let mut txs = vec![own, legacy_tx(1, gwei + 1)];
    txs.extend((2..6).map(|i| legacy_tx(i, gwei + 7 * gwei)));
    for _ in 0..20 {
        push_head_by(&r, txs.clone(), producer);
    }
    // Only the 7 gwei tips count: the zero tip is the producer's own and the 1 wei tip is dust.
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), &json!(hex_u128(7 * gwei)));
}

#[tokio::test]
async fn the_suggested_tip_is_never_below_the_943_minimum() {
    let r = rig(OnMiss::Fetch, true);
    let gwei = 1_000_000_000u128;
    for _ in 0..20 {
        push_head(&r, (0..3).map(|i| legacy_tx(i, gwei + 1_000)).collect());
    }
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), &json!(hex_u128(1_000_000)));
}

#[tokio::test]
async fn a_window_of_empty_blocks_suggests_the_943_minimum() {
    let r = rig(OnMiss::Fetch, true);
    for _ in 0..20 {
        push_head(&r, vec![]);
    }
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), &json!(hex_u128(1_000_000)));
}

thread_local! {
    /// Senders [`recover`] recovered on this thread.
    pub(super) static RECOVERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The tip is computed once per head: later fee estimates at the same head recover no sender.
#[tokio::test]
async fn the_suggested_tip_is_computed_once_per_head() {
    let r = rig(OnMiss::Fetch, true);
    for i in 0..20 {
        push_head(&r, (0..3).map(|j| legacy_tx(10 * i + j, 3_000_000_000)).collect());
    }
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), &json!(hex_u128(2_000_000_000)));
    assert!(RECOVERIES.with(|n| n.get()) > 0);
    RECOVERIES.with(|n| n.set(0));
    let batch: Vec<Value> = (0..1000)
        .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "eth_gasPrice", "params": []}))
        .collect();
    let answers = handle(&r.api, &serde_json::to_vec(&batch).unwrap()).await;
    assert!(answers
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["result"] == json!(hex_u128(3_000_000_000))));
    assert_eq!(result(&call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await), result(&tip));
    assert_eq!(
        RECOVERIES.with(|n| n.get()),
        0,
        "a fee estimate at the same head recovered senders"
    );
    // A new head computes it again.
    push_head(&r, vec![legacy_tx(999, 2_500_000_000)]);
    result(&call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await);
    assert!(RECOVERIES.with(|n| n.get()) > 0);
}

/// As reth's oracle, the suggested tip is at most 500 gwei.
#[tokio::test]
async fn the_suggested_tip_is_at_most_500_gwei() {
    let r = rig(OnMiss::Fetch, true);
    for i in 0..3 {
        push_head(&r, vec![legacy_tx(i, 2_000 * GWEI_TIP)]);
    }
    let tip = call(&r.api, "eth_maxPriorityFeePerGas", json!([])).await;
    assert_eq!(result(&tip), &json!(hex_u128(MAX_TIP)));
    let price = call(&r.api, "eth_gasPrice", json!([])).await;
    assert_eq!(result(&price), &json!(hex_u128(MAX_TIP + 1_000_000_000)));
    assert_eq!(MAX_TIP, 500 * GWEI_TIP);
}

const GWEI_TIP: u128 = 1_000_000_000;

// --- fee history ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn fee_history_entries_are_the_newest_blocks_own_ancestry(
        lag in prop_oneof![0u64..40, 500u64..700],
        fork: prop::sample::Index,
        side_len in 1u64..4,
        count in 1u64..1100,
        newest in 0u8..4,
        pick: prop::sample::Index,
    ) {
        let r = rig(OnMiss::Fetch, true);
        let mut all: HashMap<B256, HeldBlock> =
            r.blocks.iter().map(|b| (b.hash, b.clone())).collect();
        // Each base fee is its block number, plus a million off the canonical chain.
        let mut add = |parent: &HeldBlock, salt: u8, canonical: bool| {
            let number = parent.header.number + 1;
            let header = Header {
                number,
                parent_hash: parent.hash,
                timestamp: now(),
                base_fee_per_gas: Some(number + u64::from(salt) * 1_000_000),
                gas_used: number % 7 * 1_000_000,
                extra_data: vec![salt].into(),
                ..parent.header.clone()
            };
            let b = HeldBlock {
                hash: header.hash_slow(),
                header,
                beacon_root: B256::ZERO,
                body: Arc::new(BlockBody::default()),
            };
            r.chain.insert(b.clone()).unwrap();
            if canonical {
                r.chain.set_head(b.hash).unwrap();
            }
            all.insert(b.hash, b.clone());
            b
        };
        let mut head = r.blocks[3].clone();
        for _ in 0..lag {
            head = add(&head, 0, true);
        }
        let number = head.header.number;
        let floor = number - crate::chain::HEADERS_WINDOW;
        let held = |b: &HeldBlock| b.header.number >= floor || b.hash == r.blocks[0].hash;
        // A side branch from a canonical block recent enough to take children.
        let canonical: Vec<HeldBlock> = (floor.max(1000)..=number)
            .filter_map(|n| r.chain.by_number(n))
            .collect();
        let mut tip = canonical[fork.index(canonical.len())].clone();
        let mut side = Vec::new();
        for _ in 0..side_len {
            tip = add(&tip, 1, false);
            side.push(tip.clone());
        }
        let (newest_param, newest_block) = match newest {
            0 => (json!("latest"), head.clone()),
            1 => {
                let b = canonical[pick.index(canonical.len())].clone();
                (json!(hex_u64(b.header.number)), b)
            }
            2 => {
                let b = side[pick.index(side.len())].clone();
                (json!(format!("{:#x}", b.hash)), b)
            }
            _ => {
                let b = canonical[pick.index(canonical.len())].clone();
                (json!({"blockHash": format!("{:#x}", b.hash)}), b)
            }
        };
        let v = r.api.fee_history(&json!([hex_u64(count), newest_param, []])).unwrap();
        // The model: walk parent links from the newest block while the blocks are held.
        let mut want = vec![newest_block.clone()];
        while (want.len() as u64) < count.min(1024) &&
            let Some(parent) = all.get(&want.last().unwrap().header.parent_hash).filter(|b| held(b))
        {
            want.push(parent.clone());
        }
        want.reverse();
        let next = calc_next_block_base_fee(
            newest_block.header.gas_used,
            newest_block.header.gas_limit,
            newest_block.header.base_fee_per_gas.unwrap(),
            BaseFeeParams::ethereum(),
        );
        let fees: Vec<String> = want
            .iter()
            .map(|b| hex_u64(b.header.base_fee_per_gas.unwrap()))
            .chain([hex_u64(next)])
            .collect();
        prop_assert_eq!(&v["oldestBlock"], &json!(hex_u64(want[0].header.number)));
        prop_assert_eq!(&v["baseFeePerGas"], &json!(fees));
        prop_assert_eq!(v["gasUsedRatio"].as_array().unwrap().len(), want.len());
        for (i, b) in want.iter().enumerate() {
            prop_assert_eq!(b.header.number, want[0].header.number + i as u64);
        }
    }
}

#[tokio::test]
async fn a_halt_keeps_the_timeout_and_size_refusals_of_a_batch() {
    let r = rig(OnMiss::Fetch, true);
    let epoch = r.chain.epoch();
    let req = |id: u64| json!({"jsonrpc": "2.0", "id": id, "method": "eth_getBalance"});
    let batch: Vec<Value> = (1..=4).map(req).collect();
    let refused =
        |id: u64, code: i64, msg: &str| Answer::new(&json!(id), Err(RpcError::new(code, msg)));
    let mut out = vec![
        Answer::new(&json!(1), Rendered::of(&json!("0x1"))),
        refused(2, -32002, REQUEST_TIMED_OUT),
        refused(3, -32003, RESPONSE_TOO_LARGE),
        refused(4, -32005, RESPONSE_BUDGET_FULL),
    ];
    let text = |out: &[Answer]| out.iter().map(Answer::to_vec).collect::<Vec<_>>();
    let kept = text(&out[1..]);
    r.chain.set_halted(Some(HaltReason::AnchorMismatch));
    drop_stale_answers(&r.api, epoch, &batch, &mut out);
    let first: Value = serde_json::from_slice(&out[0].to_vec()).unwrap();
    assert_eq!((first["id"].clone(), error(&first)), (json!(1), (-32000, HALTED_MESSAGE)));
    // They never read the chain, and the client needs them to know what to send again.
    assert_eq!(text(&out[1..]), kept);
}

#[tokio::test]
async fn an_empty_batch_gets_geths_error() {
    let r = rig(OnMiss::Fetch, true);
    let v = handle(&r.api, b"[]").await;
    assert_eq!(
        v,
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "empty batch"}})
    );
}

#[tokio::test]
async fn fee_history_reads_the_block_count_as_geth_does() {
    let r = rig(OnMiss::Fetch, true);
    // `math.HexOrDecimal64`: a decimal string, a 0x quantity or a number.
    for count in [json!("2"), json!("0x2"), json!(2)] {
        let v = call(&r.api, "eth_feeHistory", json!([count, "latest", []])).await;
        assert_eq!(result(&v)["oldestBlock"], "0x3ea", "{count}");
    }
    // A zero count is an empty result, before the newest block is read.
    for newest in [json!("latest"), json!("0xffffff")] {
        let v = call(&r.api, "eth_feeHistory", json!(["0x0", newest, []])).await;
        assert_eq!(result(&v), &json!({"oldestBlock": "0x0", "gasUsedRatio": null}));
    }
    for bad in [json!("0x"), json!("ten"), json!("-1"), json!("+2"), json!(null)] {
        let v = call(&r.api, "eth_feeHistory", json!([bad, "latest", []])).await;
        assert_eq!(error(&v), (-32602, "invalid block count"), "{bad}");
    }
    // geth decodes the newest block before it reads the count: a malformed one is refused even
    // for no blocks.
    for (newest, want) in [
        (json!("bogus"), "invalid block number"),
        (json!(5), "invalid block parameter"),
        (json!(null), "invalid block parameter"),
    ] {
        let v = call(&r.api, "eth_feeHistory", json!(["0x0", newest, []])).await;
        assert_eq!(error(&v), (-32602, want), "{newest}");
    }
    let v = call(&r.api, "eth_feeHistory", json!(["0x0"])).await;
    assert_eq!(error(&v).0, -32602);
}

#[tokio::test]
async fn params_of_the_wrong_shape_are_refused_as_geth_does() {
    let r = rig(OnMiss::Fetch, true);
    let req = |method: &str, params: Value| {
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()
    };
    for (body, want) in [
        (req("eth_blockNumber", json!({})), "non-array args"),
        (req("eth_getBalance", json!({"address": h(ALICE)})), "non-array args"),
        (req("eth_chainId", json!(1)), "non-array args"),
        (req("eth_getBlockByNumber", json!(["latest", 1])), "invalid full transactions flag"),
        (
            req("eth_getBlockByHash", json!([format!("{:#x}", r.blocks[3].hash), "true"])),
            "invalid full transactions flag",
        ),
        (req("eth_feeHistory", json!(["0x1", "latest", 50])), "invalid reward percentiles"),
        (req("eth_getBlockByNumber", json!([1003, false])), "invalid block parameter"),
        (req("eth_getBalance", json!([h(ALICE), 1003])), "invalid block parameter"),
        (
            req("eth_getBalance", json!([h(ALICE), {"blockNumber": 1003}])),
            "invalid block parameter",
        ),
    ] {
        let v = handle(&r.api, body.as_bytes()).await;
        assert_eq!(error(&v), (-32602, want), "{body}");
    }
    // Absent and null params, a null flag and null percentiles are still taken, as geth does.
    for body in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string(),
        req("eth_blockNumber", Value::Null),
        req("eth_getBlockByNumber", json!(["latest", null])),
        req("eth_getBlockByNumber", json!(["0x3eb"])),
        req("eth_feeHistory", json!(["0x1", "latest", null])),
        req("eth_feeHistory", json!(["0x1", "latest"])),
    ] {
        let v = handle(&r.api, body.as_bytes()).await;
        assert!(v.get("result").is_some(), "{body}: {v}");
    }
    // geth looks the method up before it reads the params: an unserved method is refused as
    // unserved, whatever its params.
    for params in [json!({"tx": "0x00"}), json!(1), json!(["0x00"])] {
        let body = req("eth_sendRawTransaction", params);
        let v = handle(&r.api, body.as_bytes()).await;
        assert_eq!(error(&v), (-32601, REFUSED_MESSAGE), "{body}");
    }
}

#[test]
fn every_reply_is_counted_with_the_outcome_the_client_gets() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // `counter!` reads the thread's recorder, and this runtime runs every task on this thread.
    let served = metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let r = rig(OnMiss::Fetch, true);
            let api =
                api_with(&r, cfg_943(), Arc::new(Stuck::default()), Arc::new(Receipts(vec![])));
            // A state read that waits on a stuck peer until the deadline.
            let soon = Instant::now() + Duration::from_millis(200);
            let budget = Arc::new(tokio::sync::Semaphore::new(0));
            let read = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                "params": [h(ALICE), "latest"]});
            let (v, _) =
                handle_value(&api, read.to_string().as_bytes(), soon, &budget).await.unwrap();
            assert_eq!(error(&v), (-32002, REQUEST_TIMED_OUT));
            // A batch whose answers pass the free part of an empty response budget.
            let far = Instant::now() + Duration::from_secs(600);
            let item = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                "params": ["latest", false]});
            let batch = Value::Array(vec![item; 200]).to_string();
            let (v, _) = handle_value(&api, batch.as_bytes(), far, &budget).await.unwrap();
            let out = v.as_array().unwrap();
            let served = out.iter().filter(|v| v.get("result").is_some()).count();
            assert!(served > 0 && served < 200, "{served}");
            assert!(out[served..].iter().all(|v| error(v) == (-32005, RESPONSE_BUDGET_FULL)));
            // Not JSON.
            let (v, _) = handle_value(&api, b"{", far, &budget).await.unwrap();
            assert_eq!(error(&v).0, -32700);
            served
        })
    });
    let out = handle.render();
    for line in [
        "lite_requests_total{method=\"eth_getBalance\",outcome=\"error\"} 1".to_owned(),
        format!(
            "lite_requests_total{{method=\"eth_getBlockByNumber\",outcome=\"local\"}} {served}"
        ),
        format!(
            "lite_requests_total{{method=\"eth_getBlockByNumber\",outcome=\"error\"}} {}",
            200 - served
        ),
        "lite_requests_total{method=\"other\",outcome=\"error\"} 1".to_owned(),
        format!("lite_answers_total{{verified=\"true\"}} {served}"),
    ] {
        assert!(out.lines().any(|l| l == line), "{line} missing from {out}");
    }
}

#[test]
fn a_batch_answer_a_halt_replaced_is_counted_as_the_error_sent() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // `counter!` reads the thread's recorder, and this runtime runs every task on this thread.
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let r = rig(OnMiss::Fetch, true);
            let fetcher = HaltingFetcher { chain: r.chain.clone(), inner: r.honest.clone() };
            let api = api_with(&r, cfg_943(), Arc::new(fetcher), Arc::new(Receipts(vec![])));
            // A block answered from the chain, then a state read that halts it.
            let batch = json!([
                {"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                    "params": ["latest", false]},
                {"jsonrpc": "2.0", "id": 2, "method": "eth_getBalance",
                    "params": [h(ALICE), "latest"]},
            ]);
            let far = Instant::now() + Duration::from_secs(600);
            let budget = Arc::new(tokio::sync::Semaphore::new(0));
            let (v, _) =
                handle_value(&api, batch.to_string().as_bytes(), far, &budget).await.unwrap();
            assert_eq!(error(&v[0]), (-32000, HALTED_MESSAGE));
            assert_eq!(error(&v[1]), (-32000, HALTED_MESSAGE));
        })
    });
    let out = handle.render();
    for line in [
        "lite_requests_total{method=\"eth_getBlockByNumber\",outcome=\"error\"} 1",
        "lite_requests_total{method=\"eth_getBalance\",outcome=\"error\"} 1",
    ] {
        assert!(out.lines().any(|l| l == line), "{line} missing from {out}");
    }
    // Nothing counted as served.
    let served = |l: &&str| l.contains("outcome=\"local\"") || l.starts_with("lite_answers_total{");
    assert!(out.lines().filter(served).all(|l| l.ends_with(" 0")), "{out}");
}

/// A POST of `body` on a new connection, sent whole, and the reply read for up to `wait`.
async fn post_whole(addr: SocketAddr, body: &str, wait: Duration) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let (mut rd, mut wr) = sock.split();
    let send = async { wr.write_all(req.as_bytes()).await.unwrap() };
    let mut buf = vec![0u8; 4096];
    let read = async { tokio::time::timeout(wait, rd.read(&mut buf)).await.ok()?.ok() };
    let ((), n) = tokio::join!(send, read);
    n.filter(|n| *n > 0).map(|n| String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test]
async fn a_body_whose_parsed_form_passes_the_whole_budget_is_refused_before_it_is_parsed() {
    let r = rig(OnMiss::Fetch, true);
    let limits = ServerLimits { body_budget: 1 << 20, ..ServerLimits::default() };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    // About 40 KB of text, about 2.5 MiB parsed.
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber",
        "params": vec![0u8; 20_000]})
    .to_string();
    assert!(body.len() <= FREE_BODY);
    let resp = post_whole(addr, &body, Duration::from_secs(5)).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 413") && resp.contains("body too large"), "{resp}");
    // The same values within the budget are parsed and answered.
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber",
        "params": vec![0u8; 2_000]})
    .to_string();
    let resp = post_whole(addr, &body, Duration::from_secs(5)).await.unwrap();
    assert!(resp.contains("too many arguments"), "{resp}");
    task.abort();
}

#[tokio::test]
async fn a_body_that_finds_no_room_in_the_budget_is_answered_busy_within_a_second() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = api_with(&r, cfg_943(), Arc::new(Stuck::default()), Arc::new(Receipts(vec![])));
    let limits = ServerLimits {
        body_budget: 1 << 20,
        request_timeout: Duration::from_secs(10),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    // What a body takes of the budget once it is read and its parsed form charged.
    let charge = |body: &str| {
        let mut cost = JsonCost::default();
        cost.feed(body.as_bytes());
        body.len() + cost.cost() - FREE_BODY
    };
    // About 850 KiB, held until the request timeout: it waits on a stuck peer.
    let pad = json!({"blockNumber": "latest", "pad": vec![0u8; 7_000]});
    let holder = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
        "params": [h(ALICE), pad]})
    .to_string();
    let left = (1 << 20) - charge(&holder);
    let held =
        tokio::spawn(async move { post_whole(addr, &holder, Duration::from_secs(15)).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // No read charge, but a parsed form past what is left.
    let values =
        json!({"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber", "pad": vec![0u8; 2_500]})
            .to_string();
    assert!(values.len() <= FREE_BODY && charge(&values) > left);
    // A read charge past what is left.
    let small = json!({"jsonrpc": "2.0", "id": 3, "method": "eth_blockNumber"}).to_string();
    let long = format!("{small}{}", " ".repeat(400 << 10));
    assert!(long.len() - FREE_BODY > left);
    for body in [values, long] {
        let start = std::time::Instant::now();
        let resp = post_whole(addr, &body, Duration::from_secs(5)).await.expect("no reply in 5 s");
        assert!(resp.contains(r#""code":-32005"#) && resp.contains(BODY_BUDGET_FULL), "{resp}");
        assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
    }
    assert!(held.await.unwrap().unwrap().contains(REQUEST_TIMED_OUT));
    task.abort();
}

/// What a body takes of the body budget once it is read and its parsed form charged.
fn body_charge(body: &str) -> usize {
    let mut cost = JsonCost::default();
    cost.feed(body.as_bytes());
    (body.len() + cost.cost()).saturating_sub(FREE_BODY)
}

#[tokio::test]
async fn one_body_cannot_hold_the_whole_body_budget() {
    let mut r = rig(OnMiss::Fetch, true);
    r.api = api_with(&r, cfg_943(), Arc::new(Stuck::default()), Arc::new(Receipts(vec![])));
    let (budget, cap) = (1 << 20, 256 << 10);
    let limits = ServerLimits {
        body_budget: budget,
        max_body_charge: cap,
        request_timeout: Duration::from_secs(10),
        ..ServerLimits::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, limits).unwrap();
    // A body that waits on the stuck peer until the request timeout, `values` values long.
    let holder = |id: u64, values: usize| {
        let pad = json!({"blockNumber": "latest", "pad": vec![0u8; values]});
        json!({"jsonrpc": "2.0", "id": id, "method": "eth_getBalance", "params": [h(ALICE), pad]})
            .to_string()
    };
    // Charged just under the whole budget.
    let near = holder(1, 7_000);
    let near_charge = body_charge(&near);
    assert!(near_charge > cap && near_charge < budget);
    let near = tokio::spawn(async move { post_whole(addr, &near, Duration::from_secs(15)).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    // A small body sent meanwhile, that would not fit beside it.
    let small = json!({"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber"}).to_string();
    let concurrent = format!("{small}{}", " ".repeat(130 << 10));
    assert!(body_charge(&concurrent) > budget - near_charge && body_charge(&concurrent) <= cap);
    let resp = post_whole(addr, &concurrent, Duration::from_secs(5)).await.expect("no reply");
    assert!(resp.contains("0x3eb"), "the near-budget body blocked a small one: {resp}");
    let resp = near.await.unwrap().expect("the near-budget body was held");
    assert!(resp.starts_with("HTTP/1.1 413") && resp.contains("body too large"), "{resp}");
    // Three bodies charged just under the cap wait on the stuck peer; a fourth still fits.
    let values = (1..).take_while(|v| body_charge(&holder(9, *v)) <= cap).last().unwrap();
    let held: Vec<_> = (3..6)
        .map(|id| {
            let body = holder(id, values);
            tokio::spawn(async move { post_whole(addr, &body, Duration::from_secs(15)).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let fourth =
        json!({"jsonrpc": "2.0", "id": 6, "method": "eth_blockNumber", "pad": vec![0u8; values]})
            .to_string();
    assert!(3 * body_charge(&holder(3, values)) + body_charge(&fourth) <= budget);
    let resp = post_whole(addr, &fourth, Duration::from_secs(5)).await.expect("no reply");
    assert!(resp.contains("0x3eb"), "{resp}");
    for h in held {
        h.abort();
    }
    task.abort();
}

#[tokio::test]
async fn the_default_limits_take_a_whole_body_of_hex_data_and_four_at_the_cap() {
    let d = ServerLimits::default();
    assert!(4 * d.max_body_charge <= d.body_budget);
    let r = rig(OnMiss::Fetch, true);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (addr, task) = serve_listener_with(r.api.clone(), listener, d).unwrap();
    let text = |n: usize| {
        let pad = format!("0x{}", "ab".repeat(n));
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "pad": pad}).to_string()
    };
    let short = text(0).len();
    let body = text((MAX_BODY - short) / 2);
    assert!(body.len() <= MAX_BODY && body.len() > MAX_BODY - 2);
    let resp = post_whole(addr, &body, Duration::from_secs(10)).await.expect("no reply");
    assert!(resp.contains("0x3eb"), "{resp}");
    task.abort();
}

#[tokio::test]
async fn a_request_head_past_the_connection_buffer_is_not_read() {
    let r = rig(OnMiss::Fetch, true);
    let (addr, task) = serve(r.api.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"}).to_string();
    let ask = async |pad: usize| {
        let head = format!("x-pad: {}\r\ncontent-length: {}\r\n", "a".repeat(pad), body.len());
        post_raw(addr, &head, body.as_bytes(), Duration::from_secs(5)).await
    };
    assert!(ask(16 << 10).await.contains("0x3eb"));
    // hyper checks the bound after each read, so a head may pass it by one read. Its default
    // buffer of about 400 KiB a connection would hold this head.
    let resp = ask(2 * CONN_BUF + 1).await;
    assert!(!resp.contains("0x3eb"), "{resp}");
    task.abort();
}

#[tokio::test]
async fn a_receipt_with_many_logs_is_rendered_under_a_render_permit() {
    let r = rig(OnMiss::Fetch, true);
    let tx_hash = format!("{:#x}", r.chain.head().unwrap().body.transactions[0].tx_hash());
    let receipts_api = |logs: usize| {
        let mut one = wire_receipt(21_000);
        one.receipt.logs = vec![one.receipt.logs[0].clone(); logs];
        let set = Receipts(vec![one.clone(), one]);
        api_with(&r, cfg_943(), r.honest.clone(), Arc::new(set))
    };
    let (few, many) = (receipts_api(INLINE_RECEIPT_LOGS), receipts_api(INLINE_RECEIPT_LOGS + 1));
    let n = u32::try_from(MAX_CONCURRENT_RENDERS).unwrap();
    // The rig's APIs share no render permits: each test API takes its own.
    let (few_held, many_held) = (
        few.render_permits.clone().acquire_many_owned(n).await.unwrap(),
        many.render_permits.clone().acquire_many_owned(n).await.unwrap(),
    );
    let read = |api: Arc<Api>| {
        let p = json!([tx_hash]);
        async move { call(&api, "eth_getTransactionReceipt", p).await }
    };
    // A small receipt does not wait for the renders of blocks.
    let v = tokio::time::timeout(Duration::from_secs(30), read(few.clone())).await.unwrap();
    assert_eq!(result(&v)["logs"].as_array().unwrap().len(), INLINE_RECEIPT_LOGS);
    // A large one waits: its `Value` form is several times its text.
    let wait = tokio::time::timeout(Duration::from_millis(200), read(many.clone())).await;
    assert!(wait.is_err(), "a receipt of many logs rendered with every render permit taken");
    drop((few_held, many_held));
    let v = tokio::time::timeout(Duration::from_secs(30), read(many)).await.unwrap();
    assert_eq!(result(&v)["logs"].as_array().unwrap().len(), INLINE_RECEIPT_LOGS + 1);
}

#[test]
fn answers_are_the_text_of_their_value_form_byte_for_byte() {
    let ids = [json!(1), json!("a\"b\\u{1}"), Value::Null, json!(u64::MAX), json!(-7)];
    let results = [json!("0x1"), Value::Null, json!({"b": [1, {"z": 0, "a": null}], "a": true})];
    let mut with_data = RpcError::new(3, "execution reverted");
    with_data.data = Some(json!("0x08c3"));
    let errors = [with_data, RpcError::new(-32005, RESPONSE_BUDGET_FULL)];
    let mut answers = Vec::new();
    for id in &ids {
        for res in results.iter().map(|v| Ok(v.clone())).chain(errors.iter().cloned().map(Err)) {
            let want = rpc_response(id, res.clone());
            let answer = Answer::new(id, res.and_then(|v| Rendered::of(&v)));
            assert_eq!(answer.to_vec(), serde_json::to_vec(&want).unwrap(), "{want}");
            assert_eq!(answer.len, answer.to_vec().len());
            answers.push(want);
        }
    }
    let as_answers = |vs: &[Value]| {
        vs.iter()
            .map(|v| match v.get("error") {
                None => Answer::new(&v["id"], Rendered::of(&v["result"])),
                Some(e) => Answer::new(
                    &v["id"],
                    Err(RpcError {
                        code: e["code"].as_i64().unwrap(),
                        message: e["message"].as_str().unwrap().into(),
                        data: e.get("data").cloned(),
                    }),
                ),
            })
            .collect::<Vec<_>>()
    };
    let body = ReplyBody::batch(as_answers(&answers));
    assert_eq!(body.to_vec(), serde_json::to_vec(&Value::Array(answers.clone())).unwrap());
    let body = ReplyBody::one(as_answers(&answers[..1]).pop().unwrap());
    assert_eq!(body.to_vec(), serde_json::to_vec(&answers[0]).unwrap());
}

#[test]
fn a_reply_body_writes_its_pieces_in_order_and_frees_each_once_copied() {
    let piece = |n: usize, b: u8| vec![b; n];
    let pieces = [
        piece(1, b'['),
        piece(RESPONSE_CHUNK - 1, b'a'),
        piece(0, b'-'),
        piece(2 * RESPONSE_CHUNK + 5, b'b'),
        piece(3, b'c'),
    ];
    let mut body = ReplyBody::default();
    for p in &pieces {
        body.len += p.len();
        body.pieces.push(p.clone().into());
    }
    let want = pieces.concat();
    assert_eq!((body.len(), body.to_vec()), (want.len(), want.clone()));
    let mut body = std::pin::pin!(ChargedBody::new(body, None));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut got = Vec::new();
    while let Poll::Ready(Some(Ok(frame))) = body.as_mut().poll_frame(&mut cx) {
        let chunk = frame.into_data().unwrap();
        assert!(!chunk.is_empty() && chunk.len() <= RESPONSE_CHUNK, "{}", chunk.len());
        got.extend_from_slice(&chunk);
        // Each piece wholly copied is freed: only the one being copied, and those after it, stay.
        let held: usize = body.pieces.iter().map(|p| p.len()).sum();
        assert!(held <= want.len() - got.len() + body.offset, "{held} held");
        assert_eq!(body.size_hint().exact(), Some((want.len() - got.len()) as u64));
    }
    assert!(body.is_end_stream());
    assert_eq!(got, want);
    assert!(body.pieces.iter().all(|p| p.is_empty()));
}

#[test]
fn the_readme_states_the_render_bounds() {
    let readme = include_str!("../../README.md").split_whitespace().collect::<Vec<_>>().join(" ");
    let large = format!("a receipt with more than {INLINE_RECEIPT_LOGS} logs");
    assert!(readme.contains(&large), "{large} not in the README");
    assert_eq!(MAX_CONCURRENT_RENDERS, 2, "the README says two renders");
    assert!(readme.contains("At most two renders run at once"));
}
