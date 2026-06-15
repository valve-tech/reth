//! Prestate-driven block runner.
//!
//! Layout of a test case folder (mirrors the upstream Go harness):
//!
//! ```text
//! testdata/TestFirehosePrestate/<case>/
//!   prestate.json              # genesis + context + RLP-encoded signed tx
//!   fh3.0/block.<num>.golden.bin  # expected Firehose Block (binary protobuf)
//! ```

use std::{path::Path, sync::Arc};

use alloy_consensus::{
    constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH},
    proofs::calculate_transaction_root,
    Header,
};
use alloy_eips::{eip2718::Decodable2718, eip4895::Withdrawals};
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use base64::{engine::general_purpose, Engine as _};
use eyre::{Context, ContextCompat};
use firehose_tracer::pb::sf::ethereum::r#type::v2::Block as FirehoseBlock;
use prost::Message;
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives, TransactionSigned};
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose::{run_wrapped_block, FirehoseBlockTracer, NoPostTxExtras, NoPreTxAdjust};
use reth_primitives_traits::{Block as _, RecoveredBlock};
use reth_revm::State;
use revm::{
    database::{CacheDB, EmptyDB},
    state::{AccountInfo, Bytecode},
};
use serde::Deserialize;

/// Captured outcome of a prestate run.
///
/// `block` is the protobuf `Block` parsed from the single `FIRE BLOCK` line emitted for the
/// executed block. Genesis lines, if any, are stripped.
#[derive(Debug)]
pub struct RunOutcome {
    /// The decoded Firehose `Block` for the executed test block.
    pub block: FirehoseBlock,
    /// Raw captured tracer output (all `FIRE BLOCK` lines), useful for debugging.
    pub raw: Vec<u8>,
}

/// JSON shape of `prestate.json` (matches Go's `prestateData`).
#[derive(Debug, Deserialize)]
pub struct Prestate {
    /// The genesis configuration, including the `alloc` used to seed the state DB.
    pub genesis: Genesis,
    /// The block context fields supplied by the test fixture (number, timestamp, miner, …).
    pub context: TraceContext,
    /// Hex-encoded RLP-serialized signed transaction (with or without `0x` prefix).
    /// For typed (EIP-2718) transactions this is the RLP-byte-string-wrapped form, exactly
    /// matching `geth`'s `rlp.EncodeToBytes(types.Transaction)`.
    pub input: String,
}

/// Block context fields from the JSON fixture (mirrors Geth's `context` sub-object).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceContext {
    /// Block number.
    #[serde(deserialize_with = "deser_u64_str")]
    pub number: u64,
    /// Block timestamp (Unix seconds).
    #[serde(deserialize_with = "deser_u64_str")]
    pub timestamp: u64,
    /// Block gas limit.
    #[serde(deserialize_with = "deser_u64_str")]
    pub gas_limit: u64,
    /// Block beneficiary (coinbase).
    pub miner: Address,
    /// EIP-1559 base fee per gas (absent on pre-London blocks).
    #[serde(default, deserialize_with = "deser_opt_u128_str")]
    pub base_fee_per_gas: Option<u128>,
    /// Block difficulty (absent on post-Merge blocks).
    #[serde(default, deserialize_with = "deser_opt_u256_str")]
    pub difficulty: Option<U256>,
}

/// Run the prestate-driven Firehose harness against `case_folder` and return the captured Block.
///
/// `case_folder` must contain `prestate.json` (Geth-style genesis + block context + RLP-encoded
/// signed transaction). The captured `Block` is the protobuf parsed from the single
/// `FIRE BLOCK` line emitted for the executed block; assert against a `.binpb` golden via
/// [`assert_block_equals_golden`].
pub fn run_prestate(case_folder: &Path) -> eyre::Result<RunOutcome> {
    let prestate_path = case_folder.join("prestate.json");
    let prestate: Prestate = serde_json::from_slice(&std::fs::read(&prestate_path)?)
        .with_context(|| format!("reading prestate.json at {}", prestate_path.display()))?;

    let chain_spec = Arc::new(ChainSpec::from(prestate.genesis.clone()));
    let parent_hash = chain_spec.genesis_hash();

    let tx_bytes = decode_hex(&prestate.input).context("decoding prestate.input hex")?;
    let signed_tx = TransactionSigned::network_decode(&mut tx_bytes.as_slice())
        .context("RLP-decoding prestate.input as a signed transaction")?;

    let transactions = vec![signed_tx];
    let header = build_header(&prestate.context, parent_hash, &transactions);

    // Match Geth's `extblock` RLP shape on Shanghai+ chains: 4-element list
    // [header, txs, uncles, withdrawals] where the withdrawals slot is always present (empty
    // list when the block has no withdrawals). Reth's encoder elides the slot entirely when
    // `withdrawals: None`, producing a 3-element list and a 1-byte-shorter `block.size`.
    let block = Block {
        header,
        body: BlockBody { transactions, ommers: vec![], withdrawals: Some(Withdrawals::default()) },
    };
    let recovered: RecoveredBlock<Block> =
        block.try_into_recovered().map_err(|_| eyre::eyre!("recovering tx senders"))?;

    let mut db = CacheDB::new(EmptyDB::default());
    seed_cache_db(&mut db, &prestate.genesis)?;
    let mut state = State::builder().with_database(db).with_bundle_update().build();

    let evm_config = EthEvmConfig::new(chain_spec.clone());

    // Bundles `new_with_writer` + `on_blockchain_init`: the Tracer guards mid-block events behind
    // a one-shot init so any captured output is preceded by a `FIRE INIT` line declaring the
    // chain. Fork timings are derived from the prestate's genesis config.
    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: prestate.genesis.config.chain_id,
            shanghai_time: prestate.genesis.config.shanghai_time,
            cancun_time: prestate.genesis.config.cancun_time,
            prague_time: prestate.genesis.config.prague_time,
            verkle_time: None,
        },
        "reth-firehose-tests",
        env!("CARGO_PKG_VERSION"),
    );

    let block_number = recovered.header().number;
    let block_hash = recovered.hash();
    let finalized = Some(firehose_tracer::types::FinalizedBlockRef {
        number: block_number,
        hash: Some(block_hash),
    });

    let mut block_tracer = FirehoseBlockTracer::start_local::<EthPrimitives>(
        &mut tracer,
        recovered.sealed_block(),
        finalized,
    );

    let exec_result = run_wrapped_block::<_, _, _, _, _>(
        &evm_config,
        &mut state,
        &recovered,
        &mut block_tracer,
        NoPreTxAdjust,
        NoPostTxExtras,
    );

    match exec_result {
        Ok(_) => block_tracer.mark_verified(),
        Err(e) => {
            let msg = e.to_string();
            block_tracer.mark_failed(&std::io::Error::other(msg.clone()));
            return Err(eyre::eyre!("block execution failed: {msg}"));
        }
    }

    drop(tracer);

    let raw = buffer.get_bytes();
    let block = parse_fire_block_for(&raw, block_number)?;
    Ok(RunOutcome { block, raw })
}

/// Compare a captured Firehose `Block` against the binary protobuf golden at `golden_path`.
///
/// On mismatch, returns an error containing pretty-printed `{:#?}` debug dumps of both the
/// captured and the expected `Block`, written to neighbouring `.actual.txt` / `.expected.txt`
/// files next to the golden so a normal `diff` shows the difference at a glance.
pub fn assert_block_equals_golden(
    captured: &FirehoseBlock,
    golden_path: &Path,
) -> eyre::Result<()> {
    let bytes = std::fs::read(golden_path)
        .with_context(|| format!("reading golden file {}", golden_path.display()))?;
    let expected = FirehoseBlock::decode(bytes.as_slice())
        .with_context(|| format!("decoding golden Block from {}", golden_path.display()))?;
    if captured != &expected {
        let actual_path = golden_path.with_extension("actual.txt");
        let expected_path = golden_path.with_extension("expected.txt");
        let actual_bin = golden_path.with_extension("actual.binpb");
        let _ = std::fs::write(&actual_path, format!("{captured:#?}"));
        let _ = std::fs::write(&expected_path, format!("{expected:#?}"));
        let _ = std::fs::write(&actual_bin, captured.encode_to_vec());
        return Err(eyre::eyre!(
            "captured Firehose Block does not match golden at {}\n\
             diff with: diff -u {} {}\n\
             raw protobuf bytes also written to {}",
            golden_path.display(),
            expected_path.display(),
            actual_path.display(),
            actual_bin.display(),
        ));
    }
    Ok(())
}

fn build_header(
    ctx: &TraceContext,
    parent_hash: B256,
    transactions: &[TransactionSigned],
) -> Header {
    // The upstream Go harness builds the test block via `types.NewBlock(header, body, nil, ...)`,
    // which:
    //   * recomputes ommers_hash and transactions_root from `body`,
    //   * pins receipts_root to EMPTY_ROOT_HASH (the receipts list passed to `NewBlock` is nil),
    //   * leaves state_root at zero (no trie computation),
    //   * leaves withdrawals_root unset because `body.Withdrawals` is nil,
    //   * does not populate blob_gas_used / excess_blob_gas.
    //
    // Mirror those choices so the captured `FIRE BLOCK` header bytes line up with the goldens.
    // The Cancun-required field `parent_beacon_block_root` cannot be left unset on reth (the EVM
    // rejects the header), so it is pinned to zero, matching what the corresponding Go
    // fixture-generator now sets explicitly. `blob_gas_used` / `excess_blob_gas` are forced to
    // `Some(0)` for the same reason; [`normalize_for_upstream_geth_fixture`] later strips them
    // from the captured Block so it lines up with Geth's narrower header representation.
    Header {
        parent_hash,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        state_root: B256::ZERO,
        transactions_root: calculate_transaction_root(transactions),
        receipts_root: EMPTY_ROOT_HASH,
        // Real Shanghai+ blocks always have `withdrawals_root` populated. The upstream Go
        // fixture must construct the body with a non-nil (possibly empty) `Withdrawals` slice
        // so `types.NewBlock` fills `WithdrawalsHash = EmptyWithdrawalsHash`; we mirror that
        // here. Leaving it `None` is incompatible with reth's RLP encoder, which elides the
        // field entirely (vs Geth's `0x80` placeholder for nil-with-following-fields), so the
        // header keccak would diverge.
        withdrawals_root: Some(EMPTY_ROOT_HASH),
        number: ctx.number,
        timestamp: ctx.timestamp,
        gas_limit: ctx.gas_limit,
        gas_used: 0,
        beneficiary: ctx.miner,
        base_fee_per_gas: ctx.base_fee_per_gas.map(|v| v as u64),
        difficulty: ctx.difficulty.unwrap_or(U256::ZERO),
        parent_beacon_block_root: Some(B256::ZERO),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        requests_hash: None,
        ..Default::default()
    }
}

/// Seed a [`CacheDB`] from a genesis `alloc` map, inserting account info and storage slots.
pub fn seed_cache_db(db: &mut CacheDB<EmptyDB>, genesis: &Genesis) -> eyre::Result<()> {
    for (addr, account) in &genesis.alloc {
        let info = build_account_info(account);
        db.insert_account_info(*addr, info);

        if let Some(storage) = &account.storage {
            for (slot, value) in storage {
                let slot_u = U256::from_be_bytes(slot.0);
                let value_u = U256::from_be_bytes(value.0);
                db.insert_account_storage(*addr, slot_u, value_u)
                    .with_context(|| format!("seeding storage for {addr:?}"))?;
            }
        }
    }
    Ok(())
}

/// Convert a [`GenesisAccount`] into a revm [`AccountInfo`].
pub fn build_account_info(account: &GenesisAccount) -> AccountInfo {
    let code = account.code.as_ref().map(|c| Bytecode::new_raw(Bytes::copy_from_slice(c)));
    let code_hash = code.as_ref().map(|c| keccak256(c.original_byte_slice()));
    AccountInfo {
        balance: account.balance,
        nonce: account.nonce.unwrap_or_default(),
        code_hash: code_hash.unwrap_or(revm::primitives::KECCAK_EMPTY),
        code,
        account_id: None,
    }
}

/// Parse the captured tracer output and return the `Block` whose number matches `block_number`.
///
/// `FIRE BLOCK` line format: `FIRE BLOCK <num> <flash_idx> <hash> <prev_num> <prev_hash> <lib_num>
/// <ts_ns> <payload_b64>\n`.
pub fn parse_fire_block_for(raw: &[u8], block_number: u64) -> eyre::Result<FirehoseBlock> {
    let text = std::str::from_utf8(raw).context("captured tracer output is not UTF-8")?;
    for line in text.lines() {
        let mut parts = line.split(' ');
        let Some(p0) = parts.next() else { continue };
        let Some(p1) = parts.next() else { continue };
        if p0 != "FIRE" || p1 != "BLOCK" {
            continue;
        }
        let Some(num_str) = parts.next() else { continue };
        let num: u64 = num_str.parse().context("parsing FIRE BLOCK number")?;
        if num != block_number {
            continue;
        }
        // Skip flash_idx, hash, prev_num, prev_hash, lib_num, ts_ns to reach payload (8th token,
        // 0-indexed token #8 from the start of the line — i.e. the last token).
        let payload =
            parts.last().context("FIRE BLOCK line missing base64 payload (last token)")?;
        let bytes = general_purpose::STANDARD
            .decode(payload)
            .context("base64-decoding FIRE BLOCK payload")?;
        return FirehoseBlock::decode(bytes.as_slice())
            .context("protobuf-decoding FIRE BLOCK payload as Block");
    }
    Err(eyre::eyre!("no FIRE BLOCK line found for block #{block_number}"))
}

/// Decode a hex string (with or without `0x` prefix) into raw bytes.
pub fn decode_hex(s: &str) -> eyre::Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context("hex-decoding")
}

// ---- Serde helpers for the JSON formats Geth emits in `context` ----

mod private {
    use super::*;
    use serde::de::Error as _;

    pub(super) fn parse_decimal_or_hex_u128(s: &str) -> Result<u128, String> {
        if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u128::from_str_radix(stripped, 16).map_err(|e| e.to_string())
        } else {
            s.parse().map_err(|e: std::num::ParseIntError| e.to_string())
        }
    }

    pub(super) fn de_u64<'de, D>(d: D) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(d)?;
        let v = parse_decimal_or_hex_u128(&s).map_err(D::Error::custom)?;
        u64::try_from(v).map_err(D::Error::custom)
    }

    pub(super) fn de_opt_u128<'de, D>(d: D) -> Result<Option<u128>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: Option<String> = serde::Deserialize::deserialize(d)?;
        match s {
            None => Ok(None),
            Some(s) => parse_decimal_or_hex_u128(&s).map(Some).map_err(D::Error::custom),
        }
    }

    pub(super) fn de_opt_u256<'de, D>(d: D) -> Result<Option<U256>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: Option<String> = serde::Deserialize::deserialize(d)?;
        match s {
            None => Ok(None),
            Some(s) => {
                if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Ok(Some(U256::from_str_radix(stripped, 16).map_err(D::Error::custom)?))
                } else {
                    Ok(Some(U256::from_str_radix(&s, 10).map_err(D::Error::custom)?))
                }
            }
        }
    }
}

/// Deserialise a decimal-or-hex string as `u64` (for use with `#[serde(deserialize_with = …)]`).
pub fn deser_u64_str<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    private::de_u64(d)
}

/// Deserialise an optional decimal-or-hex string as `Option<u128>` (for `#[serde(deserialize_with =
/// …)]`).
pub fn deser_opt_u128_str<'de, D>(d: D) -> Result<Option<u128>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    private::de_opt_u128(d)
}

/// Deserialise an optional decimal-or-hex string as `Option<U256>` (for `#[serde(deserialize_with =
/// …)]`).
pub fn deser_opt_u256_str<'de, D>(d: D) -> Result<Option<U256>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    private::de_opt_u256(d)
}
