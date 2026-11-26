//! A beacon block response body through the client's bounded `Shape` parse and
//! `parse_beacon_block`.
//!
//! Two modes, chosen by the first byte:
//! * raw: the bytes are the body. A parsed block must be self-consistent (its hash is its header's
//!   hash and the payload's `block_hash`, its body matches the header), and the bounded parse must
//!   give the same outcome as a full `serde_json` parse wherever that succeeds.
//! * built: a valid block is built here from fuzz input (its own hash, roots and requests hash,
//!   computed with alloy), then byte edits may be applied to its JSON. Unedited, it must parse to
//!   exactly the header and body built; edited, it may only parse to that same block.
#![no_main]

use alloy_consensus::{
    constants::EMPTY_OMMER_ROOT_HASH,
    proofs::{calculate_transaction_root, calculate_withdrawals_root},
    BlockBody, Header, Signed, TxEip1559, TxEnvelope, TxLegacy,
};
use alloy_eips::{
    eip2718::Encodable2718,
    eip4895::{Withdrawal, Withdrawals},
    eip7685::Requests,
};
use alloy_primitives::{hex, Address, Bloom, Bytes, Signature, TxKind, B256, U256};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use reth_pulsechain_lite::{
    fuzz_api::{parse_beacon_body, BeaconShape},
    payload::{parse_beacon_block, ForkSchedule, ParsedBlock, PayloadError, Profile},
    verify::verify_body,
};
use serde_json::{json, Value};

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum Fork {
    Shanghai,
    Cancun,
    Prague,
}

impl From<Fork> for Profile {
    fn from(f: Fork) -> Self {
        match f {
            Fork::Shanghai => Self::Shanghai,
            Fork::Cancun => Self::Cancun,
            Fork::Prague => Self::Prague,
        }
    }
}

#[derive(Debug, Arbitrary)]
enum Tx {
    Legacy {
        nonce: u64,
        gas_price: u64,
        gas: u64,
        to: Option<[u8; 20]>,
        value: u64,
        input: Vec<u8>,
    },
    Eip1559 {
        nonce: u64,
        max_fee: u64,
        tip: u64,
        gas: u64,
        to: [u8; 20],
        input: Vec<u8>,
    },
}

impl Tx {
    fn envelope(&self) -> TxEnvelope {
        let sig = Signature::test_signature();
        match self {
            Self::Legacy { nonce, gas_price, gas, to, value, input } => {
                let tx = TxLegacy {
                    chain_id: Some(943),
                    nonce: *nonce,
                    gas_price: u128::from(*gas_price),
                    gas_limit: *gas,
                    to: to.map_or(TxKind::Create, |a| TxKind::Call(Address::from(a))),
                    value: U256::from(*value),
                    input: Bytes::from(input.clone()),
                };
                TxEnvelope::Legacy(Signed::new_unhashed(tx, sig))
            }
            Self::Eip1559 { nonce, max_fee, tip, gas, to, input } => {
                let tx = TxEip1559 {
                    chain_id: 943,
                    nonce: *nonce,
                    gas_limit: *gas,
                    max_fee_per_gas: u128::from(*max_fee),
                    max_priority_fee_per_gas: u128::from(*tip),
                    to: TxKind::Call(Address::from(*to)),
                    input: Bytes::from(input.clone()),
                    ..Default::default()
                };
                TxEnvelope::Eip1559(Signed::new_unhashed(tx, sig))
            }
        }
    }
}

#[derive(Debug, Arbitrary)]
struct Deposit {
    pubkey: [u8; 48],
    creds: [u8; 32],
    amount: u64,
    sig_head: [u8; 32],
    index: u64,
}

#[derive(Debug, Arbitrary)]
struct WithdrawalRequest {
    source: [u8; 20],
    pubkey: [u8; 48],
    amount: u64,
}

#[derive(Debug, Arbitrary)]
struct Consolidation {
    source: [u8; 20],
    from: [u8; 48],
    to: [u8; 48],
}

#[derive(Debug, Arbitrary)]
struct Built {
    fork: Fork,
    /// The fork the schedule names; a different one must be refused.
    schedule: Option<Fork>,
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    bloom_byte: u8,
    prev_randao: [u8; 32],
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra: Vec<u8>,
    base_fee: u64,
    parent_root: [u8; 32],
    blob_gas_used: u64,
    excess_blob_gas: u64,
    txs: Vec<Tx>,
    withdrawals: Vec<(u64, u64, [u8; 20], u64)>,
    deposits: Vec<Deposit>,
    withdrawal_requests: Vec<WithdrawalRequest>,
    consolidations: Vec<Consolidation>,
    /// Byte overwrites applied to the JSON text: (position, byte).
    edits: Vec<(u16, u8)>,
}

/// The header, body and JSON of a valid beacon block of `b`.
fn build(b: &Built) -> (Header, BlockBody<TxEnvelope>, Vec<u8>) {
    let txs: Vec<TxEnvelope> = b.txs.iter().take(4).map(Tx::envelope).collect();
    let withdrawals: Vec<Withdrawal> = b
        .withdrawals
        .iter()
        .take(4)
        .map(|(index, validator_index, address, amount)| Withdrawal {
            index: *index,
            validator_index: *validator_index,
            address: Address::from(*address),
            amount: *amount,
        })
        .collect();
    let mut header = Header {
        parent_hash: B256::from(b.parent_hash),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: Address::from(b.fee_recipient),
        state_root: B256::from(b.state_root),
        transactions_root: calculate_transaction_root(&txs),
        receipts_root: B256::from(b.receipts_root),
        logs_bloom: Bloom::repeat_byte(b.bloom_byte),
        number: b.number,
        gas_limit: b.gas_limit,
        gas_used: b.gas_used,
        timestamp: b.timestamp,
        extra_data: Bytes::from(b.extra.iter().take(32).copied().collect::<Vec<u8>>()),
        mix_hash: B256::from(b.prev_randao),
        base_fee_per_gas: Some(b.base_fee),
        withdrawals_root: Some(calculate_withdrawals_root(&withdrawals)),
        ..Default::default()
    };
    let mut payload = json!({
        "parent_hash": hx(&b.parent_hash),
        "fee_recipient": hx(&b.fee_recipient),
        "state_root": hx(&b.state_root),
        "receipts_root": hx(&b.receipts_root),
        "logs_bloom": hx(header.logs_bloom.as_slice()),
        "prev_randao": hx(&b.prev_randao),
        "block_number": b.number.to_string(),
        "gas_limit": b.gas_limit.to_string(),
        "gas_used": b.gas_used.to_string(),
        "timestamp": b.timestamp.to_string(),
        "extra_data": hx(&header.extra_data),
        "base_fee_per_gas": b.base_fee.to_string(),
        "transactions": txs.iter().map(|t| hx(&t.encoded_2718())).collect::<Vec<_>>(),
        "withdrawals": withdrawals.iter().map(|w| json!({
            "index": w.index.to_string(),
            "validator_index": w.validator_index.to_string(),
            "address": hx(w.address.as_slice()),
            "amount": w.amount.to_string(),
        })).collect::<Vec<_>>(),
    });
    let mut body = json!({"randao_reveal": "0x00", "graffiti": "0x00"});
    if !matches!(b.fork, Fork::Shanghai) {
        header.blob_gas_used = Some(b.blob_gas_used);
        header.excess_blob_gas = Some(b.excess_blob_gas);
        header.parent_beacon_block_root = Some(B256::from(b.parent_root));
        payload["blob_gas_used"] = json!(b.blob_gas_used.to_string());
        payload["excess_blob_gas"] = json!(b.excess_blob_gas.to_string());
    }
    if matches!(b.fork, Fork::Prague) {
        let deposits: Vec<&Deposit> = b.deposits.iter().take(2).collect();
        let wreqs: Vec<&WithdrawalRequest> = b.withdrawal_requests.iter().take(2).collect();
        let cons: Vec<&Consolidation> = b.consolidations.iter().take(2).collect();
        let mut data = [vec![0u8], vec![1u8], vec![2u8]];
        for d in &deposits {
            let mut sig = [0u8; 96];
            sig[..32].copy_from_slice(&d.sig_head);
            data[0].extend(d.pubkey);
            data[0].extend(d.creds);
            data[0].extend(d.amount.to_le_bytes());
            data[0].extend(sig);
            data[0].extend(d.index.to_le_bytes());
        }
        for w in &wreqs {
            data[1].extend(w.source);
            data[1].extend(w.pubkey);
            data[1].extend(w.amount.to_le_bytes());
        }
        for c in &cons {
            data[2].extend(c.source);
            data[2].extend(c.from);
            data[2].extend(c.to);
        }
        header.requests_hash =
            Some(Requests::new(data.into_iter().map(Bytes::from).collect()).requests_hash());
        body["execution_requests"] = json!({
            "deposits": deposits.iter().map(|d| {
                let mut sig = [0u8; 96];
                sig[..32].copy_from_slice(&d.sig_head);
                json!({
                    "pubkey": hx(&d.pubkey),
                    "withdrawal_credentials": hx(&d.creds),
                    "amount": d.amount.to_string(),
                    "signature": hx(&sig),
                    "index": d.index.to_string(),
                })
            }).collect::<Vec<_>>(),
            "withdrawals": wreqs.iter().map(|w| json!({
                "source_address": hx(&w.source),
                "validator_pubkey": hx(&w.pubkey),
                "amount": w.amount.to_string(),
            })).collect::<Vec<_>>(),
            "consolidations": cons.iter().map(|c| json!({
                "source_address": hx(&c.source),
                "source_pubkey": hx(&c.from),
                "target_pubkey": hx(&c.to),
            })).collect::<Vec<_>>(),
        });
    }
    payload["block_hash"] = json!(hx(header.hash_slow().as_slice()));
    body["execution_payload"] = payload;
    let resp = json!({
        "version": "capella",
        "execution_optimistic": false,
        "finalized": true,
        "data": {"message": {
            "slot": "1",
            "parent_root": hx(&b.parent_root),
            "state_root": hx(&[0u8; 32]),
            "body": body,
        }, "signature": "0x00"},
    });
    let block_body = BlockBody {
        transactions: txs,
        ommers: vec![],
        withdrawals: Some(Withdrawals::new(withdrawals)),
    };
    (header, block_body, serde_json::to_vec(&resp).unwrap())
}

/// What any block that parsed must satisfy, whatever the input.
fn check_parsed(v: &Value, p: &ParsedBlock) {
    let h = &p.block.header;
    assert_eq!(p.block.hash, h.hash_slow(), "the reported hash is not the header's");
    let payload = &v["data"]["message"]["body"]["execution_payload"];
    let claimed: B256 = payload["block_hash"].as_str().unwrap().parse().unwrap();
    assert_eq!(p.block.hash, claimed, "the hash is not the payload's block_hash");
    let parent: B256 = v["data"]["message"]["parent_root"].as_str().unwrap().parse().unwrap();
    assert_eq!(p.parent_root, parent);
    assert_eq!(h.ommers_hash, EMPTY_OMMER_ROOT_HASH);
    verify_body(h, &p.block.body).expect("a parsed body matches its header");
    assert_ne!(v.get("execution_optimistic"), Some(&Value::Bool(true)));
}

fn outcome(r: &Result<ParsedBlock, PayloadError>) -> Result<B256, PayloadError> {
    r.as_ref().map(|p| p.block.hash).map_err(Clone::clone)
}

fn run_raw(bytes: &[u8], profile: Profile) {
    let forks = ForkSchedule::fixed(profile);
    if std::env::var_os("LITE_FUZZ_DEBUG").is_some() {
        eprintln!("body {}", String::from_utf8_lossy(bytes));
    }
    let Ok(v) = parse_beacon_body(BeaconShape::Block, bytes) else { return };
    let got = parse_beacon_block(&v, B256::ZERO, &forks);
    // The bounded parse drops nothing the block needs. It skips the fields it does not name
    // without validating them (invalid UTF-8 or a lone surrogate escape there is accepted), so
    // the comparison runs only where a full parse also succeeds.
    if let Ok(full) = serde_json::from_slice::<Value>(bytes) {
        assert_eq!(outcome(&got), outcome(&parse_beacon_block(&full, B256::ZERO, &forks)));
    }
    if let Ok(p) = &got {
        check_parsed(&v, p);
    }
}

fn run_built(b: &Built) {
    let (header, body, mut text) = build(b);
    let profile = Profile::from(b.schedule.unwrap_or(b.fork));
    let forks = ForkSchedule::fixed(profile);
    let original = text.clone();
    for (at, byte) in b.edits.iter().take(4) {
        let i = usize::from(*at) % text.len();
        text[i] = *byte;
    }
    let edited = text != original;
    let parsed = parse_beacon_body(BeaconShape::Block, &text);
    if !edited {
        let v = parsed.expect("a valid block body parses");
        let got = parse_beacon_block(&v, B256::ZERO, &forks);
        if profile != Profile::from(b.fork) {
            assert_eq!(got.unwrap_err(), PayloadError::ForkMismatch);
            return;
        }
        let p = got.unwrap_or_else(|e| panic!("a valid block was refused: {e}"));
        check_parsed(&v, &p);
        assert_eq!(p.block.header, header);
        assert_eq!(*p.block.body, body);
        return;
    }
    run_raw(&text, profile);
    if let Ok(v) = parsed &&
        let Ok(p) = parse_beacon_block(&v, B256::ZERO, &forks)
    {
        // An edit can only respell the same block: any other block needs a hash collision.
        assert_eq!(p.block.header, header, "an edited body parsed to another header");
        assert_eq!(*p.block.body, body, "an edited body parsed to another body");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    if mode & 1 == 0 {
        let profile = [Profile::Paris, Profile::Shanghai, Profile::Cancun, Profile::Prague]
            [usize::from(mode >> 1) % 4];
        run_raw(rest, profile);
    } else if let Ok(b) = Built::arbitrary(&mut Unstructured::new(rest)) {
        run_built(&b);
    }
});
