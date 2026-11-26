//! The `snap/1` and eth/68 responses the lite client reads, from arbitrary bytes and from honest
//! answers a peer edits.
//!
//! * The decoders: a `snap/1` frame (`Snap1Message::decode`, what each peer connection runs) and an
//!   eth/68 message must re-encode to bytes that decode to the same message.
//! * The fetcher: `P2pFetcher` asks a mock peer set for accounts, slots, code and receipts of a
//!   small world built here. Each answer is taken from the fuzz input: raw frame bytes, an honest
//!   answer with edits, a timeout or a disconnect; once the input runs out, peers answer honestly.
//!   Whatever they send, a returned account or receipt list is the true one, and the store only
//!   ever receives nodes of the true trie and code that hashes to a requested hash.
#![no_main]

use alloy_consensus::{proofs::calculate_receipt_root, Header, ReceiptWithBloom, TrieAccount};
use alloy_primitives::{keccak256, Address, Bloom, Bytes, Log, B256, U256};
use arbitrary::{Arbitrary, Unstructured};
use async_trait::async_trait;
use libfuzzer_sys::fuzz_target;
use reth_eth_wire_types::{
    message::{EthMessage, ProtocolMessage},
    snap::{
        AccountData, AccountRangeMessage, ByteCodesMessage, SnapProtocolMessage as M, StorageData,
        StorageRangesMessage,
    },
    EthNetworkPrimitives, EthVersion,
};
use reth_network_peers::PeerId;
use reth_pulsechain_lite::{
    exec::FetchError,
    metrics::LiteMetrics,
    net::client::{P2pFetcher, Transport, TransportError, WireReceipt},
    store::NodeStore,
    verify::ProvenAccount,
};
use reth_pulsechain_lite_fuzz::{block_on, World};
use reth_pulsechain_snap::Snap1Message;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, LazyLock, Mutex},
};

static WORLD: LazyLock<World> = LazyLock::new(World::small);
static ALL_NODES: LazyLock<HashMap<B256, Bytes>> = LazyLock::new(|| WORLD.all_nodes());

/// The honest receipts of one block, and its header.
static RECEIPTS: LazyLock<(Vec<WireReceipt>, Header)> = LazyLock::new(|| {
    let receipts: Vec<WireReceipt> = (1..=3u64)
        .map(|i| {
            let receipt = alloy_consensus::EthereumReceipt {
                tx_type: alloy_consensus::TxType::Legacy,
                success: i != 2,
                cumulative_gas_used: 21_000 * i,
                logs: vec![Log::new_unchecked(
                    Address::repeat_byte(i as u8),
                    vec![B256::repeat_byte(i as u8)],
                    Bytes::from(vec![i as u8; 3]),
                )],
            };
            let logs_bloom = alloy_consensus::TxReceipt::bloom(&receipt);
            ReceiptWithBloom { receipt, logs_bloom }
        })
        .collect();
    let header = Header {
        number: 7,
        receipts_root: calculate_receipt_root(&receipts),
        ..Default::default()
    };
    (receipts, header)
});

/// A store that checks every write against the true world.
#[derive(Default)]
struct CheckedStore {
    nodes: Mutex<HashMap<B256, Bytes>>,
    codes: Mutex<HashMap<B256, Bytes>>,
    asked_codes: Mutex<HashSet<B256>>,
}

impl NodeStore for CheckedStore {
    fn get(&self, hash: &B256) -> Option<Bytes> {
        self.nodes.lock().unwrap().get(hash).cloned()
    }
    fn put(&self, hash: B256, node: Bytes) {
        assert_eq!(keccak256(&node), hash, "a node was stored under another hash");
        assert!(ALL_NODES.contains_key(&hash), "a node outside the true trie was stored");
        self.nodes.lock().unwrap().insert(hash, node);
    }
    fn code(&self, hash: &B256) -> Option<Bytes> {
        self.codes.lock().unwrap().get(hash).cloned()
    }
    fn put_code(&self, hash: B256, code: Bytes) {
        assert_eq!(keccak256(&code), hash, "code was stored under another hash");
        assert!(self.asked_codes.lock().unwrap().contains(&hash), "unrequested code was stored");
        self.codes.lock().unwrap().insert(hash, code);
    }
    fn bytes(&self) -> u64 {
        0
    }
}

#[derive(Debug, Arbitrary, Clone)]
enum Edit {
    /// Flips a byte of a proof node.
    Flip {
        node: u8,
        at: u16,
        xor: u8,
    },
    DropNode {
        node: u8,
    },
    DupNode {
        node: u8,
    },
    SwapNodes {
        a: u8,
        b: u8,
    },
    AddNode {
        bytes: Vec<u8>,
    },
    /// Adds a real node of the world, possibly from another path.
    AddForeign {
        pick: u16,
    },
    ClearProof,
    /// Changes the first account's fields, or its hash.
    Account {
        nonce: Option<u64>,
        balance: Option<[u8; 32]>,
        storage_root: Option<[u8; 32]>,
        code_hash: Option<[u8; 32]>,
        hash: Option<[u8; 32]>,
    },
    DropItems,
    AddAccount {
        hash: [u8; 32],
        nonce: u64,
    },
    /// Changes the first slot's value or hash.
    Slot {
        value: Option<Vec<u8>>,
        hash: Option<[u8; 32]>,
    },
    AddSlotList,
    /// Changes, drops, duplicates or adds code blobs.
    Code {
        pick: u8,
        flip: u16,
    },
    DropCode {
        pick: u8,
    },
    DupCode {
        pick: u8,
    },
    AddCode {
        bytes: Vec<u8>,
    },
    /// Receipt edits.
    ReceiptGas {
        pick: u8,
        gas: u64,
    },
    ReceiptStatus {
        pick: u8,
    },
    ReceiptBloom {
        pick: u8,
        byte: u8,
    },
    ReceiptDrop {
        pick: u8,
    },
    ReceiptDup {
        pick: u8,
    },
    ReceiptSwap {
        a: u8,
        b: u8,
    },
}

#[derive(Debug, Arbitrary, Clone)]
enum Reply {
    Honest,
    Edited(Vec<Edit>),
    /// Raw bytes: a `snap/1` frame, or an eth/68 message for a receipts request. With `fix_id`
    /// the request id is set to the one asked, so the answer reaches verification.
    Raw {
        bytes: Vec<u8>,
        fix_id: bool,
    },
    /// An honest answer under another request id.
    WrongId(u64),
    Timeout,
    Disconnected,
}

#[derive(Debug, Arbitrary)]
enum Op {
    Account { who: u8, absent: [u8; 20] },
    Slots { who: u8, slots: Vec<u8> },
    Codes { which: Vec<u8>, unknown: Option<[u8; 32]> },
    Receipts,
}

#[derive(Debug, Arbitrary)]
struct Input {
    raw_snap: Vec<u8>,
    raw_eth: Vec<u8>,
    ops: Vec<Op>,
    replies: Vec<Reply>,
}

struct Mock {
    replies: Mutex<VecDeque<Reply>>,
}

fn pick<T>(v: &[T], n: impl Into<usize>) -> Option<usize> {
    (!v.is_empty()).then(|| n.into() % v.len())
}

fn edit_proof(proof: &mut Vec<Bytes>, e: &Edit) {
    let pool: Vec<&Bytes> = ALL_NODES.values().collect();
    match e {
        Edit::Flip { node, at, xor } => {
            if let Some(i) = pick(proof, *node) {
                let mut v = proof[i].to_vec();
                if let Some(j) = pick(&v, *at) {
                    v[j] ^= (*xor).max(1);
                }
                proof[i] = v.into();
            }
        }
        Edit::DropNode { node } => {
            if let Some(i) = pick(proof, *node) {
                proof.remove(i);
            }
        }
        Edit::DupNode { node } => {
            if let Some(i) = pick(proof, *node) {
                proof.push(proof[i].clone());
            }
        }
        Edit::SwapNodes { a, b } => {
            if let (Some(i), Some(j)) = (pick(proof, *a), pick(proof, *b)) {
                proof.swap(i, j);
            }
        }
        Edit::AddNode { bytes } => proof.push(Bytes::from(bytes.clone())),
        Edit::AddForeign { pick: p } => {
            if let Some(i) = pick(&pool, *p) {
                proof.push(pool[i].clone());
            }
        }
        Edit::ClearProof => proof.clear(),
        _ => {}
    }
}

fn edit(msg: &mut Snap1Message, e: &Edit) {
    match msg {
        Snap1Message::Shared(M::AccountRange(r)) => {
            edit_proof(&mut r.proof, e);
            match e {
                Edit::Account { nonce, balance, storage_root, code_hash, hash } => {
                    if let Some(a) = r.accounts.first_mut() {
                        let mut t = a.trie_account();
                        if let Some(n) = nonce {
                            t.nonce = *n;
                        }
                        if let Some(b) = balance {
                            t.balance = U256::from_be_bytes(*b);
                        }
                        if let Some(s) = storage_root {
                            t.storage_root = B256::from(*s);
                        }
                        if let Some(c) = code_hash {
                            t.code_hash = B256::from(*c);
                        }
                        let h = hash.map_or(a.hash, B256::from);
                        *a = AccountData::from_trie_account(h, &t);
                    }
                }
                Edit::DropItems => r.accounts.clear(),
                Edit::AddAccount { hash, nonce } => {
                    r.accounts.push(AccountData::from_trie_account(
                        B256::from(*hash),
                        &TrieAccount { nonce: *nonce, ..Default::default() },
                    ))
                }
                _ => {}
            }
        }
        Snap1Message::Shared(M::StorageRanges(r)) => {
            edit_proof(&mut r.proof, e);
            match e {
                Edit::Slot { value, hash } => {
                    if let Some(d) = r.slots.first_mut().and_then(|s| s.first_mut()) {
                        if let Some(v) = value {
                            d.data = Bytes::from(v.clone());
                        }
                        if let Some(h) = hash {
                            d.hash = B256::from(*h);
                        }
                    }
                }
                Edit::DropItems => r.slots.clear(),
                Edit::AddSlotList => r.slots.push(vec![]),
                _ => {}
            }
        }
        Snap1Message::Shared(M::ByteCodes(r)) => match e {
            Edit::Code { pick: p, flip } => {
                if let Some(i) = pick(&r.codes, *p) {
                    let mut v = r.codes[i].to_vec();
                    if let Some(j) = pick(&v, *flip) {
                        v[j] ^= 0x01;
                    } else {
                        v.push(0);
                    }
                    r.codes[i] = v.into();
                }
            }
            Edit::DropCode { pick: p } => {
                if let Some(i) = pick(&r.codes, *p) {
                    r.codes.remove(i);
                }
            }
            Edit::DupCode { pick: p } => {
                if let Some(i) = pick(&r.codes, *p) {
                    r.codes.push(r.codes[i].clone());
                }
            }
            Edit::AddCode { bytes } => r.codes.push(Bytes::from(bytes.clone())),
            _ => {}
        },
        _ => {}
    }
}

fn edit_receipts(r: &mut Vec<WireReceipt>, e: &Edit) {
    match e {
        Edit::ReceiptGas { pick: p, gas } => {
            if let Some(i) = pick(r, *p) {
                r[i].receipt.cumulative_gas_used = *gas;
            }
        }
        Edit::ReceiptStatus { pick: p } => {
            if let Some(i) = pick(r, *p) {
                r[i].receipt.success = !r[i].receipt.success;
            }
        }
        Edit::ReceiptBloom { pick: p, byte } => {
            if let Some(i) = pick(r, *p) {
                r[i].logs_bloom = Bloom::repeat_byte(*byte);
            }
        }
        Edit::ReceiptDrop { pick: p } => {
            if let Some(i) = pick(r, *p) {
                r.remove(i);
            }
        }
        Edit::ReceiptDup { pick: p } => {
            if let Some(i) = pick(r, *p) {
                r.push(r[i].clone());
            }
        }
        Edit::ReceiptSwap { a, b } => {
            if let (Some(i), Some(j)) = (pick(r, *a), pick(r, *b)) {
                r.swap(i, j);
            }
        }
        _ => {}
    }
}

/// What an honest full node answers.
fn honest(msg: &Snap1Message) -> Snap1Message {
    let w = &*WORLD;
    match msg {
        Snap1Message::Shared(M::GetAccountRange(r)) => {
            let hashed = r.starting_hash;
            let accounts = w
                .trie_accounts
                .iter()
                .find(|(a, _)| keccak256(a) == hashed)
                .map(|(_, t)| vec![AccountData::from_trie_account(hashed, t)])
                .unwrap_or_default();
            Snap1Message::Shared(M::AccountRange(AccountRangeMessage {
                request_id: r.request_id,
                accounts,
                proof: w.state.proof(hashed),
            }))
        }
        Snap1Message::Shared(M::GetStorageRanges(r)) => {
            let owner =
                w.accounts.iter().map(|(a, _)| *a).find(|a| keccak256(a) == r.account_hashes[0]);
            let Some(owner) = owner else {
                return Snap1Message::Shared(M::StorageRanges(StorageRangesMessage {
                    request_id: r.request_id,
                    slots: vec![],
                    proof: vec![],
                }));
            };
            let st = &w.storage[&owner];
            let hashed = r.starting_hash.unwrap_or(B256::ZERO);
            let slot = w
                .accounts
                .iter()
                .find(|(a, _)| *a == owner)
                .and_then(|(_, acct)| acct.storage.iter().find(|(k, _)| keccak256(k) == hashed))
                .map(|(_, v)| StorageData::from_value(hashed, *v));
            Snap1Message::Shared(M::StorageRanges(StorageRangesMessage {
                request_id: r.request_id,
                slots: vec![slot.into_iter().collect()],
                proof: st.proof(hashed),
            }))
        }
        Snap1Message::Shared(M::GetByteCodes(r)) => {
            let codes = r.hashes.iter().filter_map(|h| w.codes.get(h).cloned()).collect();
            Snap1Message::Shared(M::ByteCodes(ByteCodesMessage { request_id: r.request_id, codes }))
        }
        other => panic!("the fetcher sent an unexpected request: {other:?}"),
    }
}

fn set_id(msg: &mut Snap1Message, id: u64) {
    match msg {
        Snap1Message::Shared(M::AccountRange(r)) => r.request_id = id,
        Snap1Message::Shared(M::StorageRanges(r)) => r.request_id = id,
        Snap1Message::Shared(M::ByteCodes(r)) => r.request_id = id,
        Snap1Message::TrieNodes(r) => r.request_id = id,
        _ => {}
    }
}

/// `msg` as it arrives after a trip over the wire.
fn over_wire(msg: &Snap1Message) -> Result<Snap1Message, TransportError> {
    let bytes = msg.encode().map_err(|_| TransportError::Unexpected)?;
    let back = Snap1Message::decode(&bytes).expect("an encoded message decodes");
    assert_eq!(&back, msg, "a snap/1 message did not survive encode and decode");
    Ok(back)
}

fn request_id(msg: &Snap1Message) -> u64 {
    reth_pulsechain_lite::net::wire::request_id(msg).expect("a request")
}

#[async_trait]
impl Transport for Mock {
    fn peers(&self) -> Vec<PeerId> {
        (1..=3u8).map(PeerId::repeat_byte).collect()
    }

    fn drop_peer(&self, _peer: PeerId) {}

    async fn snap(&self, _peer: PeerId, msg: Snap1Message) -> Result<Snap1Message, TransportError> {
        let reply = self.replies.lock().unwrap().pop_front().unwrap_or(Reply::Honest);
        let id = request_id(&msg);
        match reply {
            Reply::Honest => over_wire(&honest(&msg)),
            Reply::Edited(edits) => {
                let mut r = honest(&msg);
                for e in edits.iter().take(6) {
                    edit(&mut r, e);
                }
                over_wire(&r)
            }
            Reply::Raw { bytes, fix_id } => {
                let mut r =
                    Snap1Message::decode(&bytes).map_err(|_| TransportError::Disconnected)?;
                if fix_id {
                    set_id(&mut r, id);
                }
                Ok(r)
            }
            Reply::WrongId(other) => {
                let mut r = honest(&msg);
                set_id(&mut r, if other == id { other.wrapping_add(1) } else { other });
                Ok(r)
            }
            Reply::Timeout => std::future::pending().await,
            Reply::Disconnected => Err(TransportError::Disconnected),
        }
    }

    async fn receipts(
        &self,
        _peer: PeerId,
        block_hash: B256,
    ) -> Result<Option<Vec<WireReceipt>>, TransportError> {
        assert_eq!(block_hash, RECEIPTS.1.hash_slow());
        let reply = self.replies.lock().unwrap().pop_front().unwrap_or(Reply::Honest);
        match reply {
            Reply::Honest | Reply::WrongId(_) => Ok(Some(RECEIPTS.0.clone())),
            Reply::Edited(edits) => {
                let mut r = RECEIPTS.0.clone();
                for e in edits.iter().take(6) {
                    edit_receipts(&mut r, e);
                }
                Ok(Some(r))
            }
            Reply::Raw { bytes, .. } => {
                let msg = ProtocolMessage::<EthNetworkPrimitives>::decode_message(
                    EthVersion::Eth68,
                    &mut bytes.as_slice(),
                )
                .map_err(|_| TransportError::Disconnected)?;
                match msg.message {
                    // As the real transport: an empty list is a peer without the block.
                    EthMessage::Receipts(pair) => Ok(pair.message.0.into_iter().next()),
                    _ => Err(TransportError::Unexpected),
                }
            }
            Reply::Timeout => std::future::pending().await,
            Reply::Disconnected => Err(TransportError::Disconnected),
        }
    }
}

fn decoders(input: &Input) {
    if let Ok(msg) = Snap1Message::decode(&input.raw_snap) {
        // A message that decodes re-encodes to bytes that decode to it again.
        if let Ok(bytes) = msg.encode() {
            assert_eq!(Snap1Message::decode(&bytes).unwrap(), msg);
        }
        let ids = (
            reth_pulsechain_lite::net::wire::request_id(&msg),
            reth_pulsechain_lite::net::wire::response_id(&msg),
        );
        assert!(ids.0.is_none() || ids.1.is_none(), "a message is both a request and a response");
    }
    let mut buf = input.raw_eth.as_slice();
    if let Ok(msg) =
        ProtocolMessage::<EthNetworkPrimitives>::decode_message(EthVersion::Eth68, &mut buf)
    {
        let bytes = alloy_rlp::encode(&msg);
        let back = ProtocolMessage::<EthNetworkPrimitives>::decode_message(
            EthVersion::Eth68,
            &mut bytes.as_slice(),
        )
        .expect("a decoded eth/68 message re-encodes to one that decodes");
        assert_eq!(back.message, msg.message);
    }
}

fn fetches(input: &Input) {
    let w = &*WORLD;
    let store = Arc::new(CheckedStore::default());
    let mock =
        Arc::new(Mock { replies: Mutex::new(input.replies.iter().take(24).cloned().collect()) });
    let fetcher = P2pFetcher::new(mock, store.clone(), LiteMetrics::new());
    let root = w.state.root;
    block_on(async {
        for op in input.ops.iter().take(4) {
            match op {
                Op::Account { who, absent } => {
                    let addr = w
                        .accounts
                        .get(usize::from(*who))
                        .map_or(Address::from(*absent), |(a, _)| *a);
                    let truth = w.trie_accounts.get(&addr).copied().map(ProvenAccount::from);
                    match fetcher.fetch_account(root, addr).await {
                        Ok(got) => assert_eq!(got, truth, "a wrong account was returned"),
                        Err(FetchError::NoSource | FetchError::Unverifiable) => {}
                    }
                }
                Op::Slots { who, slots } => {
                    let addr = w.accounts[usize::from(*who) % w.accounts.len()].0;
                    let slots: Vec<B256> =
                        slots.iter().take(3).map(|s| B256::with_last_byte(s % 16)).collect();
                    let _ = fetcher.fetch_slots(root, addr, &slots).await;
                }
                Op::Codes { which, unknown } => {
                    let known: Vec<B256> = w.codes.keys().copied().collect();
                    let mut hashes: Vec<B256> = which
                        .iter()
                        .take(3)
                        .map(|i| known[usize::from(*i) % known.len()])
                        .collect();
                    hashes.extend(unknown.map(B256::from));
                    hashes.sort_unstable();
                    hashes.dedup();
                    store.asked_codes.lock().unwrap().extend(hashes.iter().copied());
                    if fetcher.fetch_codes(&hashes).await.is_ok() {
                        for h in &hashes {
                            assert!(
                                store.code(h).is_some(),
                                "a code fetch passed without the code"
                            );
                        }
                    }
                }
                Op::Receipts => {
                    if let Ok(r) = fetcher.fetch_receipts(&RECEIPTS.1).await {
                        assert_eq!(r, RECEIPTS.0, "wrong receipts were returned");
                    }
                }
            }
        }
    });
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = Input::arbitrary(&mut Unstructured::new(data)) else { return };
    decoders(&input);
    fetches(&input);
});
