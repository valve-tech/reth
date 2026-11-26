//! Rebuilding an execution block from a beacon block (`GET /eth/v2/beacon/blocks/{id}`).
//!
//! The header is rebuilt from the execution payload and the beacon block (the parent beacon
//! block root is the beacon block's `parent_root`; the Prague requests hash is derived from
//! `execution_requests`). Its keccak hash must equal the payload's `block_hash`; the transaction
//! and withdrawal roots are computed from the lists in the payload, so a payload that lies about
//! its body cannot hash to its own `block_hash`.

use crate::{
    chain::HeldBlock,
    verify::{verify_body, VerifyError},
};
use alloy_consensus::{
    constants::EMPTY_OMMER_ROOT_HASH,
    proofs::{calculate_withdrawals_root, ordered_trie_root_encoded},
    BlockBody, Header, TxEnvelope,
};
use alloy_eips::{
    eip2718::Decodable2718,
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Why a beacon block was not accepted. The messages never carry source data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// A field is missing or malformed.
    #[error("malformed beacon block: {0}")]
    Malformed(&'static str),
    /// The rebuilt block hash differs from the payload's `block_hash`.
    #[error("rebuilt block hash does not match block_hash")]
    HashMismatch,
    /// The decoded body does not re-encode to the roots the matching header carries.
    #[error(transparent)]
    Body(#[from] VerifyError),
    /// The source has not validated the payload's execution (`execution_optimistic`), so the
    /// state root is unchecked.
    #[error("the source has not validated the execution payload")]
    Optimistic,
    /// The payload's fields are not those of the fork the chain runs at its timestamp.
    #[error("payload fields do not match the fork active at its timestamp")]
    ForkMismatch,
}

/// The execution payload shape of a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Before Shanghai: no withdrawals. Not served by the lite node.
    Paris,
    /// Withdrawals.
    Shanghai,
    /// Blob gas fields and the parent beacon block root.
    Cancun,
    /// EIP-7685 execution requests.
    Prague,
}

/// The fork a payload must follow, by timestamp, from the chain's fork schedule.
#[derive(Clone)]
pub struct ForkSchedule(Arc<dyn Fn(u64) -> Profile + Send + Sync>);

impl std::fmt::Debug for ForkSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkSchedule").finish_non_exhaustive()
    }
}

impl ForkSchedule {
    /// The schedule of chain `chain_id` (369 or 943), from `reth_pulsechain_forks`.
    pub fn for_chain(chain_id: u64) -> Option<Self> {
        use reth_chainspec::EthereumHardforks;
        use reth_pulsechain_forks::chainspec as cs;
        let spec = match chain_id {
            cs::PULSECHAIN_MAINNET_CHAIN_ID => cs::PULSECHAIN.clone(),
            cs::PULSECHAIN_TESTNET_V4_CHAIN_ID => cs::PULSECHAIN_TESTNET_V4.clone(),
            _ => return None,
        };
        Some(Self(Arc::new(move |ts| {
            if spec.is_prague_active_at_timestamp(ts) {
                Profile::Prague
            } else if spec.is_cancun_active_at_timestamp(ts) {
                Profile::Cancun
            } else if spec.is_shanghai_active_at_timestamp(ts) {
                Profile::Shanghai
            } else {
                Profile::Paris
            }
        })))
    }

    /// One profile at every timestamp.
    pub fn fixed(p: Profile) -> Self {
        Self(Arc::new(move |_| p))
    }

    /// The profile at `timestamp`.
    pub fn at(&self, timestamp: u64) -> Profile {
        (self.0)(timestamp)
    }
}

/// A beacon block turned into a verified execution block.
#[derive(Debug, Clone)]
pub struct ParsedBlock {
    /// The block, ready for the header chain.
    pub block: HeldBlock,
    /// The beacon block's `parent_root`.
    pub parent_root: B256,
}

fn field<'a>(v: &'a Value, key: &'static str) -> Result<&'a Value, PayloadError> {
    v.get(key).ok_or(PayloadError::Malformed(key))
}

fn string<'a>(v: &'a Value, key: &'static str) -> Result<&'a str, PayloadError> {
    field(v, key)?.as_str().ok_or(PayloadError::Malformed(key))
}

fn dec(v: &Value, key: &'static str) -> Result<u64, PayloadError> {
    string(v, key)?.parse().map_err(|_| PayloadError::Malformed(key))
}

fn hexbytes(v: &Value, key: &'static str) -> Result<Vec<u8>, PayloadError> {
    let s = string(v, key)?;
    alloy_primitives::hex::decode(s).map_err(|_| PayloadError::Malformed(key))
}

fn fixed<const N: usize>(v: &Value, key: &'static str) -> Result<[u8; N], PayloadError> {
    hexbytes(v, key)?.try_into().map_err(|_| PayloadError::Malformed(key))
}

fn list<'a>(v: &'a Value, key: &'static str) -> Result<&'a Vec<Value>, PayloadError> {
    field(v, key)?.as_array().ok_or(PayloadError::Malformed(key))
}

/// The EIP-7685 requests hash of `execution_requests`.
fn requests_hash(requests: &Value) -> Result<B256, PayloadError> {
    // Request type bytes: deposits 0, withdrawals 1, consolidations 2.
    let mut outer = Sha256::new();
    for (ty, key) in [(0u8, "deposits"), (1, "withdrawals"), (2, "consolidations")] {
        let items = list(requests, key)?;
        if items.is_empty() {
            continue;
        }
        let mut data = vec![ty];
        for it in items {
            match ty {
                0 => {
                    data.extend(fixed::<48>(it, "pubkey")?);
                    data.extend(fixed::<32>(it, "withdrawal_credentials")?);
                    data.extend(dec(it, "amount")?.to_le_bytes());
                    data.extend(fixed::<96>(it, "signature")?);
                    data.extend(dec(it, "index")?.to_le_bytes());
                }
                1 => {
                    data.extend(fixed::<20>(it, "source_address")?);
                    data.extend(fixed::<48>(it, "validator_pubkey")?);
                    data.extend(dec(it, "amount")?.to_le_bytes());
                }
                _ => {
                    data.extend(fixed::<20>(it, "source_address")?);
                    data.extend(fixed::<48>(it, "source_pubkey")?);
                    data.extend(fixed::<48>(it, "target_pubkey")?);
                }
            }
        }
        outer.update(Sha256::digest(&data));
    }
    Ok(B256::from_slice(&outer.finalize()))
}

/// The consensus limit on a header's `extra_data` (`MAX_EXTRA_DATA_BYTES`).
const MAX_EXTRA_DATA: usize = 32;

/// Parses a beacon block response into a verified execution block.
///
/// `beacon_root` is the root the block was requested by (kept so the node can tell which beacon
/// block a held block came from).
/// The payload's fields must be those of the fork `forks` names at its timestamp; the profile is
/// never inferred from the payload. A response marked `execution_optimistic` is refused.
pub fn parse_beacon_block(
    resp: &Value,
    beacon_root: B256,
    forks: &ForkSchedule,
) -> Result<ParsedBlock, PayloadError> {
    // The checks below prove the payload consistent, not its state root executed: only the
    // source's own validation does that.
    match resp.get("execution_optimistic") {
        None | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => return Err(PayloadError::Optimistic),
        Some(_) => return Err(PayloadError::Malformed("execution_optimistic")),
    }
    let message = field(field(resp, "data")?, "message")?;
    let parent_root = B256::from(fixed::<32>(message, "parent_root")?);
    let body = field(message, "body")?;
    let p = field(body, "execution_payload")?;

    let raw_txs: Vec<Vec<u8>> = list(p, "transactions")?
        .iter()
        .map(|t| {
            t.as_str()
                .and_then(|s| alloy_primitives::hex::decode(s).ok())
                .ok_or(PayloadError::Malformed("transactions"))
        })
        .collect::<Result<_, _>>()?;
    let transactions = raw_txs
        .iter()
        .map(|raw| TxEnvelope::decode_2718_exact(raw))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PayloadError::Malformed("transactions"))?;

    let withdrawals: Vec<Withdrawal> = list(p, "withdrawals")?
        .iter()
        .map(|w| {
            Ok(Withdrawal {
                index: dec(w, "index")?,
                validator_index: dec(w, "validator_index")?,
                address: Address::from(fixed::<20>(w, "address")?),
                amount: dec(w, "amount")?,
            })
        })
        .collect::<Result<_, PayloadError>>()?;

    let mut header = Header {
        parent_hash: B256::from(fixed::<32>(p, "parent_hash")?),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: Address::from(fixed::<20>(p, "fee_recipient")?),
        state_root: B256::from(fixed::<32>(p, "state_root")?),
        transactions_root: ordered_trie_root_encoded(&raw_txs),
        receipts_root: B256::from(fixed::<32>(p, "receipts_root")?),
        logs_bloom: Bloom::from(fixed::<256>(p, "logs_bloom")?),
        difficulty: U256::ZERO,
        number: dec(p, "block_number")?,
        gas_limit: dec(p, "gas_limit")?,
        gas_used: dec(p, "gas_used")?,
        timestamp: dec(p, "timestamp")?,
        // The chain's body budget does not count header bytes, so the limit bounds them.
        extra_data: Bytes::from(
            Some(hexbytes(p, "extra_data")?)
                .filter(|e| e.len() <= MAX_EXTRA_DATA)
                .ok_or(PayloadError::Malformed("extra_data"))?,
        ),
        mix_hash: B256::from(fixed::<32>(p, "prev_randao")?),
        nonce: B64::ZERO,
        base_fee_per_gas: Some(dec(p, "base_fee_per_gas")?),
        withdrawals_root: Some(calculate_withdrawals_root(&withdrawals)),
        ..Default::default()
    };
    let profile = forks.at(header.timestamp);
    let has_blobs = p.get("blob_gas_used").is_some() || p.get("excess_blob_gas").is_some();
    let has_requests = body.get("execution_requests").is_some();
    let ok = match profile {
        Profile::Paris => false,
        Profile::Shanghai => !has_blobs && !has_requests,
        Profile::Cancun => has_blobs && !has_requests,
        Profile::Prague => has_blobs && has_requests,
    };
    if !ok {
        return Err(PayloadError::ForkMismatch);
    }
    if has_blobs {
        header.blob_gas_used = Some(dec(p, "blob_gas_used")?);
        header.excess_blob_gas = Some(dec(p, "excess_blob_gas")?);
        header.parent_beacon_block_root = Some(parent_root);
    }
    if let Some(requests) = body.get("execution_requests") {
        header.requests_hash = Some(requests_hash(requests)?);
    }

    let claimed = B256::from(fixed::<32>(p, "block_hash")?);
    let hash = header.hash_slow();
    if hash != claimed {
        return Err(PayloadError::HashMismatch);
    }
    let block_body = BlockBody {
        transactions,
        ommers: vec![],
        withdrawals: Some(Withdrawals::new(withdrawals)),
    };
    verify_body(&header, &block_body)?;
    Ok(ParsedBlock {
        block: HeldBlock { hash, header, beacon_root, body: Arc::new(block_body) },
        parent_root,
    })
}

/// Builds beacon block JSON like a real beacon would serve, for tests.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use serde_json::json;

    /// Fork profile of a fake block.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Fork {
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

    /// The schedule a fake chain of fork `f` follows.
    pub(crate) fn forks(f: Fork) -> ForkSchedule {
        ForkSchedule::fixed(f.into())
    }

    #[derive(Debug, Clone)]
    pub(crate) struct FakeBlock {
        pub(crate) header: Header,
        pub(crate) hash: B256,
        pub(crate) root: B256,
        pub(crate) parent_root: B256,
        pub(crate) json: Value,
    }

    pub(crate) fn hx(b: &[u8]) -> String {
        format!("0x{}", alloy_primitives::hex::encode(b))
    }

    pub(crate) fn make(
        fork: Fork,
        number: u64,
        parent_hash: B256,
        parent_root: B256,
        salt: &str,
    ) -> FakeBlock {
        let state_root = alloy_primitives::keccak256(format!("state-{number}{salt}"));
        let mut header = Header {
            parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: Address::repeat_byte(7),
            state_root,
            transactions_root: alloy_consensus::constants::EMPTY_ROOT_HASH,
            receipts_root: alloy_consensus::constants::EMPTY_ROOT_HASH,
            number,
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000 + number * 10,
            extra_data: Bytes::from(format!("lite{salt}").into_bytes()),
            mix_hash: alloy_primitives::keccak256(format!("randao{number}{salt}")),
            base_fee_per_gas: Some(1_000_000_000),
            withdrawals_root: Some(alloy_consensus::constants::EMPTY_ROOT_HASH),
            ..Default::default()
        };
        if fork != Fork::Shanghai {
            header.blob_gas_used = Some(0);
            header.excess_blob_gas = Some(0);
            header.parent_beacon_block_root = Some(parent_root);
        }
        let mut body = json!({});
        if fork == Fork::Prague {
            header.requests_hash = Some(B256::from_slice(&Sha256::digest([])));
            body["execution_requests"] =
                json!({"deposits": [], "withdrawals": [], "consolidations": []});
        }
        let hash = header.hash_slow();
        let mut payload = json!({
            "parent_hash": hx(parent_hash.as_slice()),
            "fee_recipient": hx(header.beneficiary.as_slice()),
            "state_root": hx(state_root.as_slice()),
            "receipts_root": hx(header.receipts_root.as_slice()),
            "logs_bloom": hx(&[0u8; 256]),
            "prev_randao": hx(header.mix_hash.as_slice()),
            "block_number": number.to_string(),
            "gas_limit": header.gas_limit.to_string(),
            "gas_used": "0",
            "timestamp": header.timestamp.to_string(),
            "extra_data": hx(&header.extra_data),
            "base_fee_per_gas": "1000000000",
            "block_hash": hx(hash.as_slice()),
            "transactions": [],
            "withdrawals": [],
        });
        if fork != Fork::Shanghai {
            payload["blob_gas_used"] = json!("0");
            payload["excess_blob_gas"] = json!("0");
        }
        body["execution_payload"] = payload;
        let root = alloy_primitives::keccak256(format!("root-{}", hx(hash.as_slice())));
        let version = match fork {
            Fork::Shanghai => "capella",
            Fork::Cancun => "deneb",
            Fork::Prague => "electra",
        };
        let json = json!({
            "version": version,
            "execution_optimistic": false,
            "data": {"message": {
                "slot": number.to_string(),
                "parent_root": hx(parent_root.as_slice()),
                "state_root": hx(&[0u8; 32]),
                "body": body,
            }, "signature": "0x00"},
        });
        FakeBlock { header, hash, root, parent_root, json }
    }
}

#[cfg(test)]
mod tests {
    use super::{fake::*, *};

    #[test]
    fn rebuilds_every_fork_profile() {
        for fork in [Fork::Shanghai, Fork::Cancun, Fork::Prague] {
            let b = make(fork, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
            let parsed = parse_beacon_block(&b.json, b.root, &forks(fork)).unwrap();
            assert_eq!(parsed.block.hash, b.hash, "{fork:?}");
            assert_eq!(parsed.parent_root, B256::repeat_byte(2));
            assert_eq!(parsed.block.header.number, 5);
        }
    }

    #[test]
    fn the_fork_profile_comes_from_the_schedule_not_the_payload() {
        // A Cancun-shaped payload where the chain runs Shanghai, and the other way round.
        let c = make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        assert_eq!(
            parse_beacon_block(&c.json, c.root, &forks(Fork::Shanghai)).unwrap_err(),
            PayloadError::ForkMismatch
        );
        let sh = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        assert_eq!(
            parse_beacon_block(&sh.json, sh.root, &forks(Fork::Cancun)).unwrap_err(),
            PayloadError::ForkMismatch
        );
        let p = make(Fork::Prague, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        assert_eq!(
            parse_beacon_block(&p.json, p.root, &forks(Fork::Cancun)).unwrap_err(),
            PayloadError::ForkMismatch
        );
        // PulseChain runs Shanghai, with no Cancun: its schedule refuses the blob fields.
        for id in [369, 943] {
            let s = ForkSchedule::for_chain(id).unwrap();
            assert_eq!(s.at(c.header.timestamp), Profile::Shanghai);
            assert_eq!(s.at(1_600_000_000), Profile::Paris);
            assert!(parse_beacon_block(&sh.json, sh.root, &s).is_ok());
            assert_eq!(
                parse_beacon_block(&c.json, c.root, &s).unwrap_err(),
                PayloadError::ForkMismatch
            );
        }
        assert!(ForkSchedule::for_chain(1).is_none());
    }

    #[test]
    fn a_wrong_block_hash_is_rejected() {
        let mut b = make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        b.json["data"]["message"]["body"]["execution_payload"]["block_hash"] =
            serde_json::json!(hx(&[9u8; 32]));
        assert_eq!(
            parse_beacon_block(&b.json, b.root, &forks(Fork::Cancun)).unwrap_err(),
            PayloadError::HashMismatch
        );
    }

    #[test]
    fn a_tampered_field_changes_the_hash() {
        let mut b = make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        b.json["data"]["message"]["body"]["execution_payload"]["gas_used"] = serde_json::json!("1");
        assert_eq!(
            parse_beacon_block(&b.json, b.root, &forks(Fork::Cancun)).unwrap_err(),
            PayloadError::HashMismatch
        );
        // The parent beacon root is part of the Cancun header.
        let mut c = make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        c.json["data"]["message"]["parent_root"] = serde_json::json!(hx(&[3u8; 32]));
        assert_eq!(
            parse_beacon_block(&c.json, c.root, &forks(Fork::Cancun)).unwrap_err(),
            PayloadError::HashMismatch
        );
    }

    #[test]
    fn withdrawals_and_transactions_feed_the_roots() {
        let mut b = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        // A withdrawal that the header's root does not cover.
        b.json["data"]["message"]["body"]["execution_payload"]["withdrawals"] = serde_json::json!(
            [{"index": "1", "validator_index": "2", "address": hx(&[1u8; 20]), "amount": "5"}]
        );
        assert_eq!(
            parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap_err(),
            PayloadError::HashMismatch
        );
        // Garbage transactions are malformed, not a panic.
        let mut c = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        c.json["data"]["message"]["body"]["execution_payload"]["transactions"] =
            serde_json::json!(["0x01"]);
        assert!(matches!(
            parse_beacon_block(&c.json, c.root, &forks(Fork::Shanghai)),
            Err(PayloadError::Malformed(_))
        ));
        let d = serde_json::json!({"data": {}});
        assert!(matches!(
            parse_beacon_block(&d, B256::ZERO, &forks(Fork::Shanghai)),
            Err(PayloadError::Malformed(_))
        ));
    }

    #[test]
    fn a_transaction_with_trailing_bytes_is_malformed() {
        use alloy_consensus::{Signed, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        let tx = TxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy { gas_limit: 21_000, ..Default::default() },
            alloy_primitives::Signature::test_signature(),
        ));
        let mut b = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        // The header covers the raw bytes, so only the trailing byte is wrong.
        let mut raw = tx.encoded_2718();
        raw.push(0);
        b.header.transactions_root = ordered_trie_root_encoded(&[raw.clone()]);
        let p = &mut b.json["data"]["message"]["body"]["execution_payload"];
        p["block_hash"] = serde_json::json!(hx(b.header.hash_slow().as_slice()));
        p["transactions"] = serde_json::json!([hx(&raw)]);
        assert_eq!(
            parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap_err(),
            PayloadError::Malformed("transactions")
        );
    }

    #[test]
    fn an_optimistic_block_is_refused() {
        let mut b = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        assert!(parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).is_ok());
        b.json["execution_optimistic"] = serde_json::json!(true);
        assert_eq!(
            parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap_err(),
            PayloadError::Optimistic
        );
        b.json["execution_optimistic"] = serde_json::json!("false");
        assert_eq!(
            parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap_err(),
            PayloadError::Malformed("execution_optimistic")
        );
        // A response without the field is taken as validated: only an explicit `true` refuses.
        b.json.as_object_mut().unwrap().remove("execution_optimistic");
        let parsed = parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap();
        assert_eq!(parsed.block.hash, b.hash);
    }

    #[test]
    fn a_shanghai_header_does_not_bind_the_parent_root() {
        // Before Cancun the header has no parent beacon root, so a changed `parent_root` parses
        // to the same block: only the beacon walk can check it.
        let mut b = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        b.json["data"]["message"]["parent_root"] = serde_json::json!(hx(&[3u8; 32]));
        let parsed = parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap();
        assert_eq!((parsed.block.hash, parsed.parent_root), (b.hash, B256::repeat_byte(3)));
        assert_eq!(parsed.block.header.parent_beacon_block_root, None);
    }

    #[test]
    fn a_non_empty_request_list_changes_the_requests_hash() {
        let empty = requests_hash(&serde_json::json!(
            {"deposits": [], "withdrawals": [], "consolidations": []}
        ))
        .unwrap();
        assert_eq!(empty, B256::from_slice(&Sha256::digest([])));
        let one = requests_hash(&serde_json::json!({
            "deposits": [], "consolidations": [],
            "withdrawals": [{"source_address": hx(&[1u8; 20]), "validator_pubkey": hx(&[2u8; 48]), "amount": "9"}]
        }))
        .unwrap();
        assert_ne!(one, empty);
    }

    #[test]
    fn the_requests_hash_follows_eip_7685_byte_for_byte() {
        use alloy_eips::{
            eip6110::DepositRequest, eip7002::WithdrawalRequest, eip7251::ConsolidationRequest,
            eip7685::Requests,
        };
        use alloy_primitives::FixedBytes;
        let deposit = |n: u8| DepositRequest {
            pubkey: FixedBytes::repeat_byte(n),
            withdrawal_credentials: B256::repeat_byte(n + 1),
            amount: 0x0102_0304_0506_0708,
            signature: FixedBytes::repeat_byte(n + 2),
            index: 0x1112_1314_1516_1718,
        };
        let withdrawal = WithdrawalRequest {
            source_address: Address::repeat_byte(0x44),
            validator_pubkey: FixedBytes::repeat_byte(0x55),
            amount: 0x2122_2324_2526_2728,
        };
        let consolidation = ConsolidationRequest {
            source_address: Address::repeat_byte(0x66),
            source_pubkey: FixedBytes::repeat_byte(0x77),
            target_pubkey: FixedBytes::repeat_byte(0x88),
        };
        // Type byte, then each request's fields in order, integers little-endian.
        let deposit_bytes = |n: u8| -> Vec<u8> {
            [
                &[n; 48][..],
                &[n + 1; 32],
                &[8, 7, 6, 5, 4, 3, 2, 1],
                &[n + 2; 96],
                &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11],
            ]
            .concat()
        };
        let deposits = [&[0u8][..], &deposit_bytes(0x10), &deposit_bytes(0x20)].concat();
        let withdrawals = [
            &[1u8][..],
            &[0x44; 20],
            &[0x55; 48],
            &[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21],
        ]
        .concat();
        let consolidations = [&[2u8][..], &[0x66; 20], &[0x77; 48], &[0x88; 48]].concat();
        let json = serde_json::json!({
            "deposits": [deposit(0x10), deposit(0x20)],
            "withdrawals": [withdrawal],
            "consolidations": [consolidation],
        });
        let want = Requests::new(vec![
            deposits.clone().into(),
            withdrawals.into(),
            consolidations.clone().into(),
        ]);
        assert_eq!(requests_hash(&json).unwrap(), want.requests_hash());
        // An empty list is left out of the hash, not hashed as its type byte.
        let json = serde_json::json!({
            "deposits": [deposit(0x10), deposit(0x20)],
            "withdrawals": [],
            "consolidations": [consolidation],
        });
        let want = Requests::new(vec![deposits.into(), consolidations.into()]);
        assert_eq!(requests_hash(&json).unwrap(), want.requests_hash());
    }

    #[test]
    fn a_malformed_request_list_names_the_bad_field() {
        let ok = serde_json::json!({"deposits": [], "withdrawals": [], "consolidations": []});
        let mut no_list = ok.clone();
        no_list["deposits"] = serde_json::json!({});
        assert_eq!(requests_hash(&no_list), Err(PayloadError::Malformed("deposits")));
        let mut missing = ok.clone();
        missing.as_object_mut().unwrap().remove("consolidations");
        assert_eq!(requests_hash(&missing), Err(PayloadError::Malformed("consolidations")));
        let mut short_key = ok;
        short_key["withdrawals"] = serde_json::json!([
            {"source_address": hx(&[1u8; 20]), "validator_pubkey": hx(&[2u8; 47]), "amount": "9"}
        ]);
        assert_eq!(requests_hash(&short_key), Err(PayloadError::Malformed("validator_pubkey")));
    }

    #[test]
    fn a_malformed_payload_field_names_the_field() {
        let cases: [(&str, serde_json::Value, &str); 7] = [
            ("base_fee_per_gas", serde_json::json!("18446744073709551616"), "base_fee_per_gas"),
            ("base_fee_per_gas", serde_json::json!("0x3b9aca00"), "base_fee_per_gas"),
            ("block_number", serde_json::json!(5), "block_number"),
            ("fee_recipient", serde_json::json!(hx(&[7u8; 19])), "fee_recipient"),
            ("state_root", serde_json::json!("0xzz"), "state_root"),
            ("withdrawals", serde_json::json!({}), "withdrawals"),
            ("withdrawals", serde_json::json!([{"index": "1"}]), "validator_index"),
        ];
        for (key, value, want) in cases {
            let mut b = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
            b.json["data"]["message"]["body"]["execution_payload"][key] = value;
            assert_eq!(
                parse_beacon_block(&b.json, b.root, &forks(Fork::Shanghai)).unwrap_err(),
                PayloadError::Malformed(want),
                "{key}"
            );
        }
    }

    #[test]
    fn extra_data_past_the_consensus_limit_is_malformed() {
        // `make` writes `lite` and the salt: 32 bytes are allowed, 33 are not, even when the
        // block hash covers them.
        let at = make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), &"a".repeat(28));
        assert_eq!(at.header.extra_data.len(), 32);
        assert!(parse_beacon_block(&at.json, at.root, &forks(Fork::Cancun)).is_ok());
        let over =
            make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), &"a".repeat(29));
        assert_eq!(
            parse_beacon_block(&over.json, over.root, &forks(Fork::Cancun)).unwrap_err(),
            PayloadError::Malformed("extra_data")
        );
    }

    #[test]
    fn a_payload_must_carry_every_field_of_its_fork() {
        // The lite node does not serve pre-Shanghai blocks.
        let sh = make(Fork::Shanghai, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        assert_eq!(
            parse_beacon_block(&sh.json, sh.root, &ForkSchedule::fixed(Profile::Paris))
                .unwrap_err(),
            PayloadError::ForkMismatch
        );
        // Cancun with one of its two blob fields.
        for (gone, left) in
            [("excess_blob_gas", "excess_blob_gas"), ("blob_gas_used", "blob_gas_used")]
        {
            let mut c = make(Fork::Cancun, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
            let p = c.json["data"]["message"]["body"]["execution_payload"].as_object_mut().unwrap();
            p.remove(gone);
            assert_eq!(
                parse_beacon_block(&c.json, c.root, &forks(Fork::Cancun)).unwrap_err(),
                PayloadError::Malformed(left)
            );
        }
        // Prague without its execution requests is a Cancun payload.
        let mut pr = make(Fork::Prague, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        pr.json["data"]["message"]["body"].as_object_mut().unwrap().remove("execution_requests");
        assert_eq!(
            parse_beacon_block(&pr.json, pr.root, &forks(Fork::Prague)).unwrap_err(),
            PayloadError::ForkMismatch
        );
    }
}

#[cfg(test)]
mod props {
    use super::{fake::*, *};
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_eips::eip2718::Encodable2718;
    use proptest::{prelude::*, sample::Index};
    use serde_json::json;

    /// A fake block with two transactions and a withdrawal, its header and hash updated.
    fn with_body(fork: Fork) -> FakeBlock {
        let mut b = make(fork, 5, B256::repeat_byte(1), B256::repeat_byte(2), "");
        let raw: Vec<Vec<u8>> = (0..2)
            .map(|nonce| {
                TxEnvelope::Legacy(Signed::new_unhashed(
                    TxLegacy { nonce, gas_limit: 21_000, ..Default::default() },
                    alloy_primitives::Signature::test_signature(),
                ))
                .encoded_2718()
            })
            .collect();
        let w = Withdrawal {
            index: 1,
            validator_index: 2,
            address: Address::repeat_byte(3),
            amount: 4,
        };
        b.header.transactions_root = ordered_trie_root_encoded(&raw);
        b.header.withdrawals_root = Some(calculate_withdrawals_root(&[w]));
        b.hash = b.header.hash_slow();
        let p = &mut b.json["data"]["message"]["body"]["execution_payload"];
        p["transactions"] = json!(raw.iter().map(|t| hx(t)).collect::<Vec<_>>());
        p["withdrawals"] = json!([
            {"index": "1", "validator_index": "2", "address": hx(&[3u8; 20]), "amount": "4"}
        ]);
        p["block_hash"] = json!(hx(b.hash.as_slice()));
        b
    }

    /// Paths to every leaf of `v`.
    fn leaves(v: &Value, at: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        match v {
            Value::Object(m) => {
                for (k, c) in m {
                    at.push(k.clone());
                    leaves(c, at, out);
                    at.pop();
                }
            }
            Value::Array(a) if !a.is_empty() => {
                for (i, c) in a.iter().enumerate() {
                    at.push(i.to_string());
                    leaves(c, at, out);
                    at.pop();
                }
            }
            _ => out.push(at.clone()),
        }
    }

    fn at_path<'a>(v: &'a mut Value, path: &[String]) -> &'a mut Value {
        path.iter().fold(v, |v, k| match v {
            Value::Array(a) => &mut a[k.parse::<usize>().unwrap()],
            _ => &mut v[k.as_str()],
        })
    }

    #[derive(Debug, Clone)]
    enum Change {
        /// Flip one character of a string (hex digits stay hex digits).
        Char(Index, u8),
        /// Cut a string short.
        Cut(Index),
        /// Replace the value.
        With(Value),
        /// Remove the key.
        Remove,
    }

    fn change() -> impl Strategy<Value = Change> {
        prop_oneof![
            4 => (any::<Index>(), 1u8..16).prop_map(|(i, d)| Change::Char(i, d)),
            1 => any::<Index>().prop_map(Change::Cut),
            1 => prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::Bool),
                any::<u64>().prop_map(|n| json!(n)),
                any::<u64>().prop_map(|n| json!(n.to_string())),
                "[0-9a-fx]{0,70}".prop_map(Value::String),
                Just(json!([])),
                Just(json!({})),
            ]
            .prop_map(Change::With),
            1 => Just(Change::Remove),
        ]
    }

    fn apply(json: &mut Value, path: &[String], c: &Change) {
        let target = at_path(json, path);
        match c {
            Change::Char(i, d) => {
                if let Value::String(s) = target &&
                    !s.is_empty()
                {
                    let mut b = s.clone().into_bytes();
                    let i = i.index(b.len());
                    b[i] = match b[i] {
                        c @ (b'0'..=b'9' | b'a'..=b'f') => {
                            let n = (char::from(c).to_digit(16).unwrap() as u8 + d) % 16;
                            char::from_digit(n.into(), 16).unwrap() as u8
                        }
                        c => c ^ d,
                    };
                    *s = String::from_utf8_lossy(&b).into_owned();
                }
            }
            Change::Cut(i) => {
                if let Value::String(s) = target {
                    s.truncate(i.index(s.len() + 1));
                }
            }
            Change::With(v) => *target = v.clone(),
            Change::Remove => {
                let (last, parent) = path.split_last().unwrap();
                match at_path(json, parent) {
                    Value::Object(m) => {
                        m.remove(last);
                    }
                    Value::Array(a) => {
                        a.remove(last.parse::<usize>().unwrap());
                    }
                    _ => {}
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any change to a beacon block response is refused, or leaves the block exactly as it was.
        #[test]
        fn a_changed_beacon_block_is_refused_or_unchanged(
            fork in prop_oneof![Just(Fork::Shanghai), Just(Fork::Cancun), Just(Fork::Prague)],
            changes in prop::collection::vec((any::<Index>(), change()), 1..4),
        ) {
            let b = with_body(fork);
            let original = parse_beacon_block(&b.json, b.root, &forks(fork)).unwrap();
            prop_assert_eq!(original.block.hash, b.hash);
            let mut json = b.json.clone();
            for (pick, c) in &changes {
                let mut paths = Vec::new();
                leaves(&json, &mut Vec::new(), &mut paths);
                if paths.is_empty() {
                    break;
                }
                let path = paths[pick.index(paths.len())].clone();
                apply(&mut json, &path, c);
            }
            if let Ok(parsed) = parse_beacon_block(&json, b.root, &forks(fork)) {
                prop_assert_eq!(parsed.block.hash, b.hash);
                prop_assert_eq!(&parsed.block.header, &b.header);
                prop_assert_eq!(&parsed.block.body, &original.block.body);
                if fork != Fork::Shanghai {
                    prop_assert_eq!(parsed.parent_root, b.parent_root);
                }
            }
        }
    }
}
