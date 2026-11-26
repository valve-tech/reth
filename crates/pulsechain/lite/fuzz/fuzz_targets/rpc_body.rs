//! JSON-RPC request bodies through `handle_body` on an `Api` over an empty or a tiny chain.
//!
//! The body is either raw bytes or requests built from fuzz input (a served or unknown method,
//! params made of block tags, addresses, numbers, hashes, objects and lists). Every reply must
//! be JSON-RPC 2.0 of the shape the body asks for: one reply per non-notification request, in
//! order, each with the request's id and exactly one of result or error. The response budget
//! the reply holds must match what is left of it.
#![no_main]

use alloy_consensus::{BlockBody, Header, ReceiptWithBloom, Signed, TxEnvelope, TxLegacy};
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use alloy_trie::Nibbles;
use arbitrary::Unstructured;
use async_trait::async_trait;
use libfuzzer_sys::fuzz_target;
use reth_pulsechain_lite::{
    chain::{HeaderChain, HeldBlock},
    config::{LiteConfig, OnMiss},
    exec::{FetchError, Fetcher},
    hot_set::HotSet,
    metrics::LiteMetrics,
    net::client::WireReceipt,
    rpc::{handle_body, Api, ApiParts, NoPeers, ReceiptSource, SERVED},
    state::{Lookup, MissKey, PartialState},
    store::{NodeStore, Store},
    verify::walk_path,
};
use reth_pulsechain_lite_fuzz::{block_on, World};
use serde_json::{json, Map, Value};
use std::{
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static WORLD: LazyLock<World> = LazyLock::new(World::small);
const MAX_BATCH: usize = 1000;

/// Serves the world's nodes and code, as an honest peer set would.
struct Honest {
    store: Arc<dyn NodeStore>,
}

#[async_trait]
impl Fetcher for Honest {
    async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
        let w = &*WORLD;
        let nodes = w.all_nodes();
        let get = |h: &B256| nodes.get(h).cloned();
        for m in misses {
            let path_root = match m {
                MissKey::Account(a, _) => (root, keccak256(a)),
                MissKey::Slot(a, slot) => {
                    let st = PartialState::new(self.store.clone(), root);
                    let Lookup::Hit(Some(acct)) = st.account(a) else { continue };
                    (acct.storage_root, keccak256(slot))
                }
                MissKey::Code(h) => {
                    if let Some(c) = w.codes.get(h) {
                        self.store.put_code(*h, c.clone());
                    }
                    continue;
                }
                MissKey::Header(_) => continue,
            };
            let Ok(walk) = walk_path(path_root.0, &Nibbles::unpack(path_root.1), get) else {
                return Err(FetchError::NoSource);
            };
            for (h, n) in walk.nodes {
                self.store.put(h, n);
            }
        }
        Ok(())
    }
}

struct Receipts;

#[async_trait]
impl ReceiptSource for Receipts {
    async fn receipts(&self, header: &Header) -> Result<Vec<WireReceipt>, FetchError> {
        if header.gas_used == 0 {
            return Ok(vec![]);
        }
        Ok([21_000, 42_000]
            .into_iter()
            .map(|g| ReceiptWithBloom {
                receipt: alloy_consensus::EthereumReceipt {
                    tx_type: alloy_consensus::TxType::Legacy,
                    success: true,
                    cumulative_gas_used: g,
                    logs: vec![],
                },
                logs_bloom: Default::default(),
            })
            .collect())
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

fn api(seed: bool, on_miss: OnMiss) -> Arc<Api> {
    let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
    let chain = Arc::new(HeaderChain::new());
    if seed {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut parent = B256::repeat_byte(0xcc);
        for n in 0..4u64 {
            let txs = if n == 3 { vec![legacy_tx(0), legacy_tx(1)] } else { vec![] };
            let header = Header {
                number: 1000 + n,
                parent_hash: parent,
                state_root: WORLD.state.root,
                base_fee_per_gas: Some(1_000_000_000),
                gas_limit: 30_000_000,
                gas_used: if n == 3 { 42_000 } else { 0 },
                timestamp: now - (3 - n) * 10,
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
    }
    let cfg = LiteConfig {
        chain_id: 943,
        on_miss,
        head_max_age: Duration::from_secs(1 << 40),
        ..LiteConfig::default()
    };
    Api::new(ApiParts {
        cfg,
        chain,
        store: store.clone(),
        fetcher: Arc::new(Honest { store }),
        receipts: Arc::new(Receipts),
        metrics: LiteMetrics::new(),
        hot: Arc::new(HotSet::new(0)),
        net: Arc::new(NoPeers),
        trust_label: "follows test".into(),
    })
    .expect("api")
}

/// A JSON value from fuzz input, biased toward what the methods read.
fn value(u: &mut Unstructured<'_>, depth: u8) -> arbitrary::Result<Value> {
    let w = &*WORLD;
    Ok(match u.int_in_range(0..=13)? {
        0 => Value::Null,
        1 => Value::Bool(u.arbitrary()?),
        2 => json!(u.arbitrary::<i64>()?),
        3 => json!(format!("0x{:x}", u.int_in_range(995u64..=1006)?)),
        4 => json!(*u.choose(&[
            "latest",
            "pending",
            "earliest",
            "safe",
            "finalized",
            "0x",
            "0x0"
        ])?),
        5 => {
            let a = u.choose(&w.accounts)?.0;
            json!(a)
        }
        6 => json!(Address::from(u.arbitrary::<[u8; 20]>()?)),
        7 => json!(B256::from(u.arbitrary::<[u8; 32]>()?)),
        8 => json!(format!("0x{:x}", u.arbitrary::<u128>()?)),
        9 => json!(Bytes::from(u.arbitrary::<Vec<u8>>()?)),
        10 => Value::String(u.arbitrary()?),
        11 if depth < 3 => {
            let n = u.int_in_range(0..=4)?;
            Value::Array((0..n).map(|_| value(u, depth + 1)).collect::<Result<_, _>>()?)
        }
        12 if depth < 3 => {
            let keys = [
                "from",
                "to",
                "gas",
                "gasPrice",
                "value",
                "data",
                "input",
                "nonce",
                "blockHash",
                "blockNumber",
                "requireCanonical",
                "maxFeePerGas",
                "maxPriorityFeePerGas",
                "accessList",
                "type",
                "chainId",
            ];
            let n = u.int_in_range(0..=5)?;
            let mut m = Map::new();
            for _ in 0..n {
                m.insert((*u.choose(&keys)?).to_owned(), value(u, depth + 1)?);
            }
            Value::Object(m)
        }
        _ => json!(U256::from_be_bytes(u.arbitrary::<[u8; 32]>()?)),
    })
}

fn request(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    let mut req = Map::new();
    if u.ratio(15, 16)? {
        req.insert("jsonrpc".into(), json!("2.0"));
    }
    match u.int_in_range(0..=5)? {
        0 => {}
        1 => {
            req.insert("id".into(), Value::Null);
        }
        2 => {
            req.insert("id".into(), json!(u.arbitrary::<String>()?));
        }
        3 => {
            req.insert("id".into(), value(u, 2)?);
        }
        _ => {
            req.insert("id".into(), json!(u.arbitrary::<u32>()?));
        }
    }
    let method = if u.ratio(7, 8)? {
        json!(*u.choose(SERVED)?)
    } else if u.ratio(1, 2)? {
        json!(*u.choose(&[
            "eth_sendRawTransaction",
            "eth_getLogs",
            "eth_getProof",
            "debug_x",
            ""
        ])?)
    } else {
        value(u, 2)?
    };
    req.insert("method".into(), method);
    if u.ratio(7, 8)? {
        let n = u.int_in_range(0..=4)?;
        let params: Vec<Value> = (0..n).map(|_| value(u, 0)).collect::<Result<_, _>>()?;
        req.insert("params".into(), Value::Array(params));
    } else {
        req.insert("params".into(), value(u, 1)?);
    }
    Ok(Value::Object(req))
}

fn is_notification(req: &Value) -> bool {
    req.get("jsonrpc") == Some(&json!("2.0")) &&
        req.get("id").is_none() &&
        req.get("method").is_some_and(Value::is_string)
}

fn check_reply(req: &Value, resp: &Value) {
    let o = resp.as_object().unwrap_or_else(|| panic!("not an object: {resp}"));
    assert_eq!(o.get("jsonrpc"), Some(&json!("2.0")), "{resp}");
    let id = match req.get("id") {
        Some(id @ (Value::Null | Value::Number(_) | Value::String(_))) => id.clone(),
        _ => Value::Null,
    };
    assert_eq!(o.get("id"), Some(&id), "{resp}");
    assert_eq!(o.len(), 3, "{resp}");
    match (o.get("result"), o.get("error")) {
        (Some(_), None) => {}
        (None, Some(e)) => {
            assert!(e["code"].is_i64() && e["message"].is_string(), "{resp}");
            let extra: Vec<&String> = e
                .as_object()
                .unwrap()
                .keys()
                .filter(|k| !matches!(k.as_str(), "code" | "message" | "data"))
                .collect();
            assert!(extra.is_empty(), "{resp}");
        }
        _ => panic!("not one of result or error: {resp}"),
    }
}

fn check_body(body: &[u8], resp: Option<&Value>) {
    match serde_json::from_slice::<Value>(body) {
        Err(_) => {
            let resp = resp.expect("no reply to a parse error");
            check_reply(&Value::Null, resp);
            assert_eq!(resp["error"]["code"], json!(-32700));
        }
        Ok(Value::Array(batch)) if batch.is_empty() => {
            let resp = resp.expect("no reply to an empty batch");
            check_reply(&Value::Null, resp);
            assert_eq!(resp["error"]["code"], json!(-32600));
        }
        Ok(Value::Array(batch)) if batch.len() > MAX_BATCH => {
            let out = resp.expect("no reply to a large batch").as_array().expect("an array");
            assert_eq!(out.len(), 1);
            assert_eq!(out[0]["error"]["code"], json!(-32600));
        }
        Ok(Value::Array(batch)) => {
            let asked: Vec<&Value> = batch.iter().filter(|r| !is_notification(r)).collect();
            let Some(resp) = resp else {
                assert!(asked.is_empty(), "no reply to {} requests", asked.len());
                return;
            };
            let out = resp.as_array().expect("a batch reply is an array");
            assert_eq!(out.len(), asked.len());
            for (req, resp) in asked.into_iter().zip(out) {
                check_reply(req, resp);
            }
        }
        Ok(single) if is_notification(&single) => assert_eq!(resp, None),
        Ok(single) => check_reply(&single, resp.expect("no reply to a request")),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(flags) = u.arbitrary::<u8>() else { return };
    let on_miss = [OnMiss::Fetch, OnMiss::Error, OnMiss::ErrorAndWarm][usize::from(flags >> 2) % 3];
    let api = api(flags & 1 == 1, on_miss);
    let body: Vec<u8> = if flags & 2 == 0 {
        u.take_rest().to_vec()
    } else {
        let built = (|| -> arbitrary::Result<Value> {
            if u.ratio(1, 3)? {
                let n = u.int_in_range(0..=8)?;
                Ok(Value::Array((0..n).map(|_| request(&mut u)).collect::<Result<_, _>>()?))
            } else {
                request(&mut u)
            }
        })();
        let Ok(v) = built else { return };
        v.to_string().into_bytes()
    };
    if std::env::var_os("LITE_FUZZ_DEBUG").is_some() {
        eprintln!("flags {flags:#04x} body {}", String::from_utf8_lossy(&body));
    }
    // A budget the size of a few small answers, or one no reply fills.
    let total = if flags & 0x40 == 0 {
        tokio::sync::Semaphore::MAX_PERMITS
    } else {
        64 + usize::from(flags & 0x3f) * 16
    };
    let budget = Arc::new(tokio::sync::Semaphore::new(total));
    let reply = block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        handle_body(&api, &body, deadline, &budget).await
    });
    let (resp, permit) = match reply {
        Some((body, p)) => {
            let text = body.to_vec();
            let v: Value = serde_json::from_slice(&text).expect("a JSON reply");
            assert_eq!(serde_json::to_vec(&v).unwrap(), text, "the reply text is not compact");
            (Some(v), p)
        }
        None => (None, None),
    };
    check_body(&body, resp.as_ref());
    let held = permit.as_ref().map_or(0, |p| p.num_permits());
    assert_eq!(budget.available_permits() + held, total, "the response budget leaked");
    drop(permit);
    assert_eq!(budget.available_permits(), total);
});
