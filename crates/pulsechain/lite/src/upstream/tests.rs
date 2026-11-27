use super::*;
use crate::{
    chain::HeldBlock,
    state::{Lookup, PartialState},
    store::Store,
    testing::{world, Acct, World},
    verify::walk_path,
};
use alloy_consensus::{
    constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY},
    Header, TrieAccount,
};
use alloy_primitives::{address, U256};
use alloy_trie::Nibbles;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
const VIEW: Address = address!("00000000000000000000000000000000000c0de1");
const NOBODY: Address = address!("00000000000000000000000000000000000b0b00");
const VIEW_CODE: [u8; 11] = [0x60, 7, 0x54, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3];
/// The path of every fake endpoint: a key, which no log line may show.
const KEY_PATH: &str = "/rpc/vk_secret_key_123456";

fn test_world() -> Arc<World> {
    Arc::new(world(&[
        (ALICE, Acct { balance: 1_000_000, nonce: 3, ..Default::default() }),
        (
            VIEW,
            Acct {
                code: VIEW_CODE.to_vec(),
                storage: vec![(U256::from(7), U256::from(1234))],
                ..Default::default()
            },
        ),
    ]))
}

/// How a fake endpoint answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Honest,
    /// Proofs claim a balance one wei above the real one.
    Liar,
    /// Every call is a JSON-RPC error.
    Errors,
    /// HTTP 500.
    Down,
    /// `eth_blockNumber` below the block asked about.
    Behind,
    /// An answer over the body cap.
    Huge,
    /// An honest answer padded past the body cap, sent without a length.
    Unsized,
    /// Proofs with more nodes than any honest proof.
    Padded,
    /// Proofs that leave out the slots asked for.
    NoSlots,
    /// `eth_getCode` answers other code.
    OtherCode,
    /// Never answers.
    Silent,
    /// Every result is `null`.
    Null,
}

/// A fake JSON-RPC endpoint over `world`, at [`KEY_PATH`]. Records each call and each path.
struct FakeRpc {
    url: Url,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    paths: Arc<Mutex<Vec<String>>>,
}

impl FakeRpc {
    async fn start(world: Arc<World>, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}{KEY_PATH}", listener.local_addr().unwrap()).parse().unwrap();
        let (calls, paths) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
        let (c, ps) = (calls.clone(), paths.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let (world, c, ps) = (world.clone(), c.clone(), ps.clone());
                tokio::spawn(async move {
                    let Some((path, body)) = read_request(&mut sock).await else { return };
                    ps.lock().push(path);
                    if mode == Mode::Silent {
                        std::future::pending::<()>().await;
                    }
                    let (status, mut reply) = match mode {
                        Mode::Down => ("500 Internal Server Error", b"oops".to_vec()),
                        Mode::Huge => ("200 OK", vec![b' '; MAX_UPSTREAM_BODY + 1]),
                        _ => {
                            let batch: Vec<Value> = serde_json::from_slice(&body).unwrap();
                            let replies: Vec<Value> = batch
                                .iter()
                                .map(|req| {
                                    let method = req["method"].as_str().unwrap().to_owned();
                                    c.lock().push((method.clone(), req["params"].clone()));
                                    let id = req["id"].clone();
                                    match answer(&world, mode, &method, &req["params"]) {
                                        Some(result) => {
                                            json!({"jsonrpc": "2.0", "id": id, "result": result})
                                        }
                                        None => json!({"jsonrpc": "2.0", "id": id, "error": {
                                            "code": -32000,
                                            "message": format!("no {KEY_PATH}")
                                        }}),
                                    }
                                })
                                .collect();
                            ("200 OK", serde_json::to_vec(&replies).unwrap())
                        }
                    };
                    let length = if mode == Mode::Unsized {
                        reply.resize(MAX_UPSTREAM_BODY + 1, b' ');
                        String::new()
                    } else {
                        format!("content-length: {}\r\n", reply.len())
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n{length}\
                         connection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&reply).await;
                });
            }
        });
        Self { url, calls, paths }
    }

    fn methods(&self) -> Vec<String> {
        self.calls.lock().iter().map(|(m, _)| m.clone()).collect()
    }
}

/// The path and body of one HTTP request.
async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let path = head.split_whitespace().nth(1)?.to_owned();
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_owned())
        })?
        .parse()
        .ok()?;
    while buf.len() < head_end + len {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some((path, buf[head_end..head_end + len].to_vec()))
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(b))
}

/// The answer an endpoint in `mode` gives, or `None` for an error.
fn answer(world: &World, mode: Mode, method: &str, params: &Value) -> Option<Value> {
    if mode == Mode::Errors {
        return None;
    }
    let get = |h: &B256| world.nodes.get(h).cloned();
    match method {
        "eth_blockNumber" => Some(json!(if mode == Mode::Behind { "0x3e7" } else { "0x3e8" })),
        _ if mode == Mode::Null && method != "eth_blockNumber" => Some(Value::Null),
        "eth_getProof" => {
            let address: Address = serde_json::from_value(params[0].clone()).unwrap();
            let slots: Vec<B256> = serde_json::from_value(params[1].clone()).unwrap();
            let walk = walk_path(world.root, &Nibbles::unpack(keccak256(address)), get).unwrap();
            let account = walk.value.map(|leaf| {
                <TrieAccount as alloy_rlp::Decodable>::decode(&mut leaf.as_slice()).unwrap()
            });
            let (nonce, mut balance, storage_root, code_hash) = account
                .map_or((0, U256::ZERO, EMPTY_ROOT_HASH, KECCAK_EMPTY), |a| {
                    (a.nonce, a.balance, a.storage_root, a.code_hash)
                });
            if mode == Mode::Liar {
                balance += U256::from(1);
            }
            let mut proof: Vec<String> = walk.nodes.iter().map(|(_, n)| hex(n)).collect();
            if mode == Mode::Padded {
                proof.extend((0..MAX_PROOF_NODES).map(|_| hex(&[0x80])));
            }
            let storage: Vec<Value> = slots
                .iter()
                .filter(|_| mode != Mode::NoSlots)
                .map(|s| {
                    let walk =
                        walk_path(storage_root, &Nibbles::unpack(keccak256(s)), get).unwrap();
                    let value = walk.value.map_or(U256::ZERO, |v| {
                        <U256 as alloy_rlp::Decodable>::decode(&mut v.as_slice()).unwrap()
                    });
                    let proof: Vec<String> = walk.nodes.iter().map(|(_, n)| hex(n)).collect();
                    json!({"key": s, "value": value, "proof": proof})
                })
                .collect();
            Some(json!({
                "address": address,
                "balance": balance,
                "codeHash": code_hash,
                "nonce": format!("{nonce:#x}"),
                "storageHash": storage_root,
                "accountProof": proof,
                "storageProof": storage,
            }))
        }
        "eth_getCode" => {
            let address: Address = serde_json::from_value(params[0].clone()).unwrap();
            if mode == Mode::OtherCode {
                return Some(json!("0x6001"));
            }
            Some(json!(if address == VIEW { hex(&VIEW_CODE) } else { "0x".to_owned() }))
        }
        _ => None,
    }
}

/// A chain whose head and only block, 1000, has `world`'s state root.
fn chain_at(world: &World) -> Arc<HeaderChain> {
    let header = Header { number: 1000, state_root: world.root, ..Default::default() };
    let chain = Arc::new(HeaderChain::new());
    chain.seed(HeldBlock {
        hash: header.hash_slow(),
        header,
        beacon_root: B256::ZERO,
        body: Arc::default(),
    });
    chain
}

struct Rig {
    world: Arc<World>,
    chain: Arc<HeaderChain>,
    store: Arc<dyn NodeStore>,
    fetcher: UpstreamFetcher,
    servers: Vec<FakeRpc>,
}

async fn rig(modes: &[Mode]) -> Rig {
    let world = test_world();
    let mut servers = Vec::new();
    for mode in modes {
        servers.push(FakeRpc::start(world.clone(), *mode).await);
    }
    let chain = chain_at(&world);
    let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
    let upstreams = Upstreams::new(servers.iter().map(|s| s.url.clone()).collect());
    let fetcher = UpstreamFetcher::new(upstreams, chain.clone(), store.clone(), LiteMetrics::new());
    Rig { world, chain, store, fetcher, servers }
}

impl Rig {
    fn state(&self) -> PartialState {
        PartialState::new(self.store.clone(), self.world.root)
    }

    fn block_hash(&self) -> B256 {
        self.chain.head().unwrap().hash
    }
}

fn view_code_hash() -> B256 {
    keccak256(VIEW_CODE)
}

#[tokio::test]
async fn an_upstream_serves_accounts_slots_and_code_at_the_block_by_hash() {
    let r = rig(&[Mode::Honest]).await;
    let slot = B256::from(U256::from(7));
    let misses =
        [MissKey::Account(ALICE, None), MissKey::Slot(VIEW, slot), MissKey::Account(NOBODY, None)];
    assert!(matches!(r.state().account(&ALICE), Lookup::Miss(_)));
    r.fetcher.fetch(r.world.root, &misses).await.unwrap();
    let st = r.state();
    let Lookup::Hit(Some(alice)) = st.account(&ALICE) else { panic!("ALICE not held") };
    assert_eq!((alice.balance, alice.nonce), (U256::from(1_000_000), 3));
    assert_eq!(st.storage(&VIEW, U256::from(7)), Lookup::Hit(U256::from(1234)));
    assert_eq!(st.account(&NOBODY), Lookup::Hit(None));
    // One batch: the endpoint's head, then one proof per account with its slots, each at the
    // block named by hash. The slot key is the full 32 bytes.
    let at = json!({"blockHash": r.block_hash()});
    let calls = r.servers[0].calls.lock().clone();
    assert_eq!(
        calls,
        vec![
            ("eth_blockNumber".to_owned(), json!([])),
            ("eth_getProof".to_owned(), json!([ALICE, [], at])),
            ("eth_getProof".to_owned(), json!([VIEW, [slot], at])),
            ("eth_getProof".to_owned(), json!([NOBODY, [], at])),
        ]
    );
    assert_eq!(*r.servers[0].paths.lock(), vec![KEY_PATH.to_owned()]);
    // Code is fetched from an account that holds it.
    let code = [MissKey::Code(view_code_hash())];
    let owners: B256Map<Address> = std::iter::once((view_code_hash(), VIEW)).collect();
    r.fetcher.fetch_with_owners(r.world.root, &code, &owners).await.unwrap();
    assert_eq!(r.state().code(&view_code_hash()), Lookup::Hit(Bytes::from(VIEW_CODE.to_vec())));
    assert_eq!(r.servers[0].methods().last().unwrap(), "eth_getCode");
}

/// Runs on one thread inside the test recorder, so the counters the fetch bumps land in it.
#[test]
fn a_bad_proof_moves_to_the_next_upstream_and_rests_the_one_that_sent_it() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let prometheus = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let r = rig(&[Mode::Liar, Mode::Honest]).await;
            r.fetcher.fetch(r.world.root, &[MissKey::Account(ALICE, None)]).await.unwrap();
            let Lookup::Hit(Some(alice)) = r.state().account(&ALICE) else {
                panic!("ALICE not held")
            };
            assert_eq!(alice.balance, U256::from(1_000_000));
            assert_eq!(r.servers[0].methods(), ["eth_blockNumber", "eth_getProof"]);
            assert_eq!(r.servers[1].methods(), ["eth_blockNumber", "eth_getProof"]);
            // The liar rests: the next fetch asks the honest endpoint first, and is served
            // there.
            r.fetcher.fetch(r.world.root, &[MissKey::Account(VIEW, None)]).await.unwrap();
            assert_eq!(r.servers[0].methods().len(), 2, "the resting liar was asked");
            assert_eq!(r.servers[1].methods().len(), 4);
        })
    });
    let rendered = prometheus.render();
    assert!(
        rendered.lines().any(|l| l == "lite_proof_failures_total{source=\"upstream\"} 1"),
        "{rendered}"
    );
}

#[tokio::test]
async fn a_fetch_no_upstream_serves_is_unverifiable_after_a_bad_answer_and_no_source_otherwise() {
    let alice = [MissKey::Account(ALICE, None)];
    let slot = [MissKey::Slot(VIEW, B256::from(U256::from(7)))];
    for (mode, misses, want) in [
        (Mode::Liar, &alice[..], FetchError::Unverifiable),
        (Mode::Padded, &alice[..], FetchError::Unverifiable),
        (Mode::NoSlots, &slot[..], FetchError::Unverifiable),
        (Mode::Errors, &alice[..], FetchError::NoSource),
        (Mode::Down, &alice[..], FetchError::NoSource),
        (Mode::Behind, &alice[..], FetchError::NoSource),
        (Mode::Huge, &alice[..], FetchError::NoSource),
        (Mode::Unsized, &alice[..], FetchError::NoSource),
    ] {
        let r = rig(&[mode]).await;
        assert_eq!(r.fetcher.fetch(r.world.root, misses).await, Err(want), "{mode:?}");
        assert!(matches!(r.state().account(&ALICE), Lookup::Miss(_)), "{mode:?}");
        assert!(!r.servers[0].paths.lock().is_empty(), "{mode:?}: not asked");
    }
    // A root no held block has: no block to name, nothing asked.
    let r = rig(&[Mode::Honest]).await;
    let other = B256::repeat_byte(7);
    assert_eq!(r.fetcher.fetch(other, &alice).await, Err(FetchError::NoSource));
    assert!(r.servers[0].paths.lock().is_empty());
}

#[tokio::test]
async fn an_upstream_that_does_not_answer_is_cut_off_at_the_timeout() {
    let r = rig(&[Mode::Silent]).await;
    let start = std::time::Instant::now();
    let res = r.fetcher.fetch(r.world.root, &[MissKey::Account(ALICE, None)]).await;
    assert_eq!(res, Err(FetchError::NoSource));
    let took = start.elapsed();
    assert!(took >= UPSTREAM_TIMEOUT && took < UPSTREAM_TIMEOUT * 2, "{took:?}");
}

#[tokio::test]
async fn a_code_miss_is_fetched_from_an_account_that_holds_the_code() {
    let r = rig(&[Mode::Honest]).await;
    let code = [MissKey::Code(view_code_hash())];
    // No account is known for the hash: nothing to ask.
    assert_eq!(r.fetcher.fetch(r.world.root, &code).await, Err(FetchError::NoSource));
    assert!(r.servers[0].calls.lock().is_empty());
    // An account this source proved names its code hash.
    r.fetcher.fetch(r.world.root, &[MissKey::Account(VIEW, None)]).await.unwrap();
    r.fetcher.fetch(r.world.root, &code).await.unwrap();
    assert_eq!(r.state().code(&view_code_hash()), Lookup::Hit(Bytes::from(VIEW_CODE.to_vec())));
    let at = json!({"blockHash": r.block_hash()});
    assert_eq!(
        r.servers[0].calls.lock().last().unwrap(),
        &("eth_getCode".to_owned(), json!([VIEW, at]))
    );
}

#[tokio::test]
async fn other_code_from_the_account_asked_is_not_stored_and_rests_no_one() {
    let r = rig(&[Mode::OtherCode]).await;
    let code = [MissKey::Code(view_code_hash())];
    let owners: B256Map<Address> = std::iter::once((view_code_hash(), VIEW)).collect();
    for _ in 0..2 {
        let res = r.fetcher.fetch_with_owners(r.world.root, &code, &owners).await;
        assert_eq!(res, Err(FetchError::NoSource));
    }
    assert!(matches!(r.state().code(&view_code_hash()), Lookup::Miss(_)));
    // Asked both times: the account may hold other code at this block, which is no lie.
    assert_eq!(r.servers[0].paths.lock().len(), 2);
}

#[tokio::test]
async fn an_upstream_url_never_reaches_a_log_line_an_error_or_a_debug_form() {
    let logs = crate::testing::logs::capture(tracing::Level::DEBUG);
    let r = rig(&[Mode::Errors, Mode::Liar, Mode::Down]).await;
    let misses = [MissKey::Account(ALICE, None), MissKey::Code(view_code_hash())];
    let owners: B256Map<Address> = std::iter::once((view_code_hash(), VIEW)).collect();
    let err = r.fetcher.fetch_with_owners(r.world.root, &misses, &owners).await.unwrap_err();
    r.fetcher.upstreams().probe().await;
    // A closed port: a connect error, whose reqwest text holds the whole URL.
    let gone = Upstreams::new(vec![format!("http://127.0.0.1:1{KEY_PATH}").parse().unwrap()]);
    gone.probe().await;
    let text = logs.text();
    drop(logs);
    for shown in [text.clone(), err.to_string(), format!("{:?}", r.fetcher), format!("{gone:?}")] {
        assert!(!shown.contains("vk_secret"), "a key leaked: {shown}");
        assert!(!shown.contains("/rpc"), "a path leaked: {shown}");
    }
    assert!(text.contains("http://127.0.0.1"), "{text}");
    assert!(text.contains("upstream state source does not answer"), "{text}");
    assert!(text.contains("could not connect"), "{text}");
    assert!(text.contains("failed verification"), "{text}");
    // The key is sent: it is the endpoint's.
    assert!(r.servers.iter().all(|s| s.paths.lock().iter().all(|p| p == KEY_PATH)));
}

/// A resting endpoint is not asked while another is not resting; when every one rests, they
/// are all asked.
#[tokio::test]
async fn a_resting_endpoint_is_not_asked_while_another_is_awake() {
    let r = rig(&[Mode::Down, Mode::Honest]).await;
    let ups = r.fetcher.upstreams();
    for _ in 0..DOWN_AFTER {
        let calls = vec![Call::Proof { address: ALICE, slots: vec![] }];
        let (left, bad) =
            r.fetcher.ask(&ups.endpoints[0], r.world.root, (r.block_hash(), 1000), calls).await;
        assert_eq!((left.len(), bad), (1, false));
    }
    let asked = r.servers[0].paths.lock().len();
    let now = Instant::now();
    for _ in 0..4 {
        let order = ups.order(now);
        assert_eq!(order.len(), 1);
        assert!(std::ptr::eq(order[0], &raw const ups.endpoints[1]));
    }
    r.fetcher.fetch(r.world.root, &[MissKey::Account(ALICE, None)]).await.unwrap();
    assert_eq!(r.servers[0].paths.lock().len(), asked, "a resting endpoint was asked");
    // Every endpoint resting: all are asked.
    ups.endpoints[1].health.lock().resting_until = Some(now + DOWN_FOR);
    assert_eq!(ups.order(now).len(), 2);
    // After the rest it takes its turn again.
    let later = now + DOWN_FOR + Duration::from_secs(1);
    assert_eq!(ups.order(later).len(), 2);
}

/// A `null` result is no answer: it moves the call on and rests no one.
#[tokio::test]
async fn a_null_result_is_unavailable_not_a_lie() {
    let r = rig(&[Mode::Null]).await;
    for _ in 0..2 {
        let res = r.fetcher.fetch(r.world.root, &[MissKey::Account(ALICE, None)]).await;
        assert_eq!(res, Err(FetchError::NoSource));
    }
    assert_eq!(r.servers[0].paths.lock().len(), 2, "the endpoint was rested");
    let code = [MissKey::Code(view_code_hash())];
    let owners: B256Map<Address> = std::iter::once((view_code_hash(), VIEW)).collect();
    let res = r.fetcher.fetch_with_owners(r.world.root, &code, &owners).await;
    assert_eq!(res, Err(FetchError::NoSource));
}

/// An answer whose parsed form would take many times its size is refused before it is parsed.
#[test]
fn an_answer_of_many_small_values_is_refused_before_it_is_parsed() {
    let honest =
        serde_json::to_vec(&json!([{"jsonrpc": "2.0", "id": 0, "result": "0x3e8"}])).unwrap();
    assert_eq!(parse_replies(&honest).unwrap().len(), 1);
    // Under the body cap, and about 64 times it once parsed.
    let mut many = b"[".to_vec();
    many.extend(std::iter::repeat_n(&b"0,"[..], MAX_UPSTREAM_BODY / 4).flatten());
    many.extend_from_slice(b"0]");
    assert!(many.len() <= MAX_UPSTREAM_BODY);
    assert_eq!(parse_replies(&many), Err(SourceError::TooLarge));
    assert_eq!(parse_replies(b"[{"), Err(SourceError::Body));
}

/// The verification warning is logged once per rest, not once per fetch.
#[tokio::test]
async fn a_lying_upstream_is_warned_about_once_per_rest() {
    let logs = crate::testing::logs::capture(tracing::Level::WARN);
    let r = rig(&[Mode::Liar]).await;
    for _ in 0..3 {
        let res = r.fetcher.fetch(r.world.root, &[MissKey::Account(ALICE, None)]).await;
        assert_eq!(res, Err(FetchError::Unverifiable));
    }
    let text = logs.text();
    drop(logs);
    assert_eq!(text.matches("failed verification").count(), 1, "{text}");
    assert!(text.contains("while another upstream is not resting"), "{text}");
}

#[test]
fn calls_group_slots_by_account_in_chunks_and_skip_code_with_no_account() {
    let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 20));
    let f = UpstreamFetcher::new(
        Upstreams::new(Vec::new()),
        Arc::new(HeaderChain::new()),
        store,
        LiteMetrics::new(),
    );
    let slots: Vec<B256> =
        (0..SLOTS_PER_PROOF as u64 + 1).map(|i| B256::from(U256::from(i))).collect();
    let mut misses: Vec<MissKey> = slots.iter().map(|s| MissKey::Slot(VIEW, *s)).collect();
    misses.extend([
        MissKey::Account(ALICE, None),
        MissKey::Slot(VIEW, slots[0]),
        MissKey::Code(B256::repeat_byte(1)),
        MissKey::Code(B256::repeat_byte(2)),
        MissKey::Header(5),
    ]);
    let owners: B256Map<Address> = std::iter::once((B256::repeat_byte(1), ALICE)).collect();
    let (calls, unservable) = f.calls(&misses, &owners);
    let shape: Vec<String> = calls
        .iter()
        .map(|c| match c {
            Call::Proof { address, slots } => format!("{address:#x}/{}", slots.len()),
            Call::Code { hash, owner } => format!("code {hash:#x} at {owner:#x}"),
        })
        .collect();
    assert_eq!(
        shape,
        [
            format!("{VIEW:#x}/{SLOTS_PER_PROOF}"),
            format!("{VIEW:#x}/1"),
            format!("{ALICE:#x}/0"),
            format!("code {:#x} at {ALICE:#x}", B256::repeat_byte(1)),
        ]
    );
    assert_eq!(unservable, 1);
}

/// A fetcher that answers `answer` and counts its calls.
struct Fixed(Result<(), FetchError>, std::sync::atomic::AtomicUsize);

#[async_trait]
impl Fetcher for Fixed {
    async fn fetch(&self, _: B256, _: &[MissKey]) -> Result<(), FetchError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.clone()
    }
}

#[tokio::test]
async fn the_fallback_asks_the_upstreams_when_the_peers_do_not_serve_the_state() {
    let alice = [MissKey::Account(ALICE, None)];
    for (primary, peers, mode, want, primary_asked, upstream_asked) in [
        (Ok(()), 1, Mode::Honest, Ok(()), 1, false),
        (Err(FetchError::NoSource), 1, Mode::Honest, Ok(()), 1, true),
        (Err(FetchError::Unverifiable), 1, Mode::Honest, Ok(()), 1, true),
        // No state peer: the upstreams at once.
        (Ok(()), 0, Mode::Honest, Ok(()), 0, true),
        // Both fail: the worse of the two.
        (Err(FetchError::Unverifiable), 1, Mode::Down, Err(FetchError::Unverifiable), 1, true),
        (Err(FetchError::NoSource), 1, Mode::Liar, Err(FetchError::Unverifiable), 1, true),
        (Err(FetchError::NoSource), 1, Mode::Down, Err(FetchError::NoSource), 1, true),
    ] {
        let case = format!("{primary:?} {peers} {mode:?}");
        let r = rig(&[mode]).await;
        let p2p = Arc::new(Fixed(primary, Default::default()));
        let fallback = FallbackFetcher {
            primary: p2p.clone(),
            upstream: Arc::new(r.fetcher),
            state_peers: Arc::new(move || peers),
        };
        assert_eq!(fallback.fetch(r.world.root, &alice).await, want, "{case}");
        assert_eq!(p2p.1.load(Ordering::SeqCst), primary_asked, "{case}");
        assert_eq!(!r.servers[0].paths.lock().is_empty(), upstream_asked, "{case}");
    }
}

/// Records the code owners each fetch gets, and serves nothing.
#[derive(Default)]
struct RecordsOwners(Mutex<Vec<B256Map<Address>>>);

#[async_trait]
impl Fetcher for RecordsOwners {
    async fn fetch(&self, _: B256, _: &[MissKey]) -> Result<(), FetchError> {
        Err(FetchError::NoSource)
    }
    async fn fetch_with_owners(
        &self,
        _: B256,
        _: &[MissKey],
        owners: &B256Map<Address>,
    ) -> Result<(), FetchError> {
        self.0.lock().push(owners.clone());
        Err(FetchError::NoSource)
    }
}

/// A run that reads an account and misses its code hands the fetcher that account for the
/// hash, in both round drivers.
#[tokio::test]
async fn the_rounds_hand_the_fetcher_the_account_of_each_missing_code() {
    use crate::{
        exec::{run_rounds, run_rounds_blocking, RoundsError},
        metrics::RoundMetrics,
    };
    use evm2::evm::Database;
    let r = rig(&[Mode::Honest]).await;
    r.fetcher.fetch(r.world.root, &[MissKey::Account(VIEW, None)]).await.unwrap();
    let hashes: crate::state::BlockHashes = Arc::new(|_| None);
    let read = |db: &mut crate::state::MissingDb| {
        let code_hash = db.get_account(&VIEW).unwrap().unwrap().code_hash;
        db.code_bytes(&code_hash).len()
    };
    let want: B256Map<Address> = std::iter::once((view_code_hash(), VIEW)).collect();
    let rec = RecordsOwners::default();
    let res = run_rounds(
        &r.state(),
        &hashes,
        &rec,
        None,
        crate::config::OnMiss::Fetch,
        3,
        &RoundMetrics::default(),
        read,
    )
    .await;
    assert_eq!(res.unwrap_err(), RoundsError::Fetch(FetchError::NoSource));
    assert_eq!(*rec.0.lock(), vec![want.clone()]);
    let rec = RecordsOwners::default();
    let permits = Arc::new(Semaphore::new(1));
    let res = run_rounds_blocking(
        &r.state(),
        &hashes,
        &rec,
        None,
        crate::config::OnMiss::Fetch,
        3,
        &permits,
        &RoundMetrics::default(),
        read,
    )
    .await;
    assert_eq!(res.unwrap_err(), RoundsError::Fetch(FetchError::NoSource));
    assert_eq!(*rec.0.lock(), vec![want]);
}
