use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
};

use crate::prelude::*;
use alloy_consensus::{
    transaction::{RlpEcdsaEncodableTx, TxHashRef},
    BlockHeader as ConsensusBlockHeader, EthereumTxEnvelope,
};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, Bytes, Sealable, B256, U256};
use alloy_rlp::Encodable;
use firehose_tracer::types::{
    AccessTuple, BlockData, GenesisAlloc, SetCodeAuthorization, TxEvent, UncleData, WithdrawalData,
};
use reth_primitives_traits::{Block as BlockTrait, BlockBody};
use reth_provider::{AccountReader, ProviderResult};

pub(crate) fn to_genesis_alloc(genesis: &Genesis) -> GenesisAlloc {
    genesis
        .alloc
        .iter()
        .map(|(address, account)| {
            (
                *address,
                firehose_tracer::types::GenesisAccount {
                    code: account.code.clone(),
                    balance: Some(account.balance.clone()),
                    nonce: account.nonce.unwrap_or_default(),
                    storage: map_genesis_storage(&account.storage),
                },
            )
        })
        .collect()
}

fn map_genesis_storage(storage: &Option<BTreeMap<B256, B256>>) -> HashMap<B256, B256> {
    match storage {
        Some(storage_map) => storage_map.iter().map(|(k, v)| (*k, *v)).collect(),
        None => HashMap::new(),
    }
}

/// Returns block data from a `SealedBlock<B>`.
///
/// Signer-free: reads header fields, ommers, withdrawals, and RLP-encoded length only. Callers
/// holding a `RecoveredBlock` pass `block.sealed_block()`.
pub fn to_block_data<B>(block: &reth_primitives_traits::SealedBlock<B>) -> BlockData
where
    B: BlockTrait,
    B::Header: ConsensusBlockHeader + Sealable,
    B::Body: BlockBody,
    <<B as BlockTrait>::Body as BlockBody>::OmmerHeader: ConsensusBlockHeader + Sealable,
{
    let header = block.header();

    BlockData {
        number: header.number(),
        hash: block.hash(),
        parent_hash: header.parent_hash(),
        uncle_hash: header.ommers_hash(),
        coinbase: header.beneficiary(),
        root: header.state_root(),
        tx_hash: header.transactions_root(),
        receipt_hash: header.receipts_root(),
        bloom: header.logs_bloom(),
        difficulty: header.difficulty(),
        gas_limit: header.gas_limit(),
        gas_used: header.gas_used(),
        time: header.timestamp(),
        extra: header.extra_data().clone(),
        mix_digest: header.mix_hash().unwrap_or_default(),
        nonce: header.nonce().map(|n| u64::from_be_bytes(n.into())).unwrap_or_default(),
        base_fee: header.base_fee_per_gas().map(U256::from),
        // RLP-encoded length of the sealed block.
        size: block.length() as u64,
        uncles: map_uncles(block),
        withdrawals: map_withdrawals(block),
        withdrawals_root: header.withdrawals_root(),
        blob_gas_used: header.blob_gas_used(),
        excess_blob_gas: header.excess_blob_gas(),
        parent_beacon_root: header.parent_beacon_block_root(),
        requests_hash: header.requests_hash(),
        tx_dependency: None,
        // EIP-7843: Amsterdam slot number — not yet exposed by reth Header trait
        slot_number: None,
    }
}

fn map_uncles<B>(block: &reth_primitives_traits::SealedBlock<B>) -> Vec<UncleData>
where
    B: BlockTrait,
    B::Body: BlockBody,
    <<B as BlockTrait>::Body as BlockBody>::OmmerHeader: ConsensusBlockHeader + Sealable,
{
    let Some(ommers) = block.body().ommers() else {
        return Vec::new();
    };
    ommers.iter().map(to_uncle_data).collect()
}

fn map_withdrawals<B>(block: &reth_primitives_traits::SealedBlock<B>) -> Vec<WithdrawalData>
where
    B: BlockTrait,
    B::Body: BlockBody,
{
    block
        .body()
        .withdrawals()
        .map(|ws| ws.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|w| WithdrawalData {
            index: w.index,
            validator_index: w.validator_index,
            address: w.address,
            amount: w.amount,
        })
        .collect()
}

pub(crate) fn to_finalized_ref(
    block_ref: ProviderResult<Option<alloy_eips::BlockNumHash>>,
) -> Option<firehose_tracer::types::FinalizedBlockRef> {
    block_ref.ok().flatten().map(|num_hash| firehose_tracer::types::FinalizedBlockRef {
        number: num_hash.number,
        hash: Some(num_hash.hash),
    })
}

fn to_uncle_data<H>(uncle: &H) -> UncleData
where
    H: ConsensusBlockHeader + Sealable,
{
    UncleData {
        // hash_slow() recomputes the hash via RLP encoding (no cached hash for ommer headers)
        hash: uncle.hash_slow(),
        parent_hash: uncle.parent_hash(),
        uncle_hash: uncle.ommers_hash(),
        coinbase: uncle.beneficiary(),
        root: uncle.state_root(),
        tx_hash: uncle.transactions_root(),
        receipt_hash: uncle.receipts_root(),
        bloom: uncle.logs_bloom(),
        difficulty: uncle.difficulty(),
        number: uncle.number(),
        gas_limit: uncle.gas_limit(),
        gas_used: uncle.gas_used(),
        time: uncle.timestamp(),
        extra: uncle.extra_data().clone(),
        mix_digest: uncle.mix_hash().unwrap_or_default(),
        nonce: uncle.nonce().map(|n| u64::from_be_bytes(n.into())).unwrap_or_default(),
        base_fee: uncle.base_fee_per_gas().map(U256::from),
    }
}

/// SignatureFields provides generic access to transaction signature (r, s, v) bytes.
///
/// This trait is needed because reth's `SignedTransaction` does not expose a generic
/// `signature()` method — only concrete types like `EthereumTxEnvelope` have it.
pub trait SignatureFields {
    /// Returns (r, s, v) where v is trimmed big-endian bytes (no leading zeros), matching
    /// go-ethereum's `big.Int.Bytes()` encoding used in the Firehose protocol.
    fn signature_fields(&self) -> (B256, B256, Bytes);
}

impl<Eip4844> SignatureFields for EthereumTxEnvelope<Eip4844>
where
    Eip4844: RlpEcdsaEncodableTx,
{
    fn signature_fields(&self) -> (B256, B256, Bytes) {
        let sig = self.signature();
        let y_parity = sig.v() as u64;
        let v = match self {
            // Legacy without EIP-155: V = 27 or 28
            // Legacy with EIP-155: V = chain_id * 2 + 35 + y_parity
            EthereumTxEnvelope::Legacy(signed) => {
                if let Some(chain_id) = signed.tx().chain_id {
                    chain_id * 2 + 35 + y_parity
                } else {
                    27 + y_parity
                }
            }
            // Typed transactions (EIP-2930, EIP-1559, EIP-4844, EIP-7702): V = 0 or 1
            _ => y_parity,
        };
        (
            B256::new(sig.r().to_be_bytes::<32>()),
            B256::new(sig.s().to_be_bytes::<32>()),
            u64_to_trimmed_bytes(v),
        )
    }
}

/// Encodes a u64 as big-endian bytes with no leading zeros (matching go-ethereum big.Int.Bytes()).
pub fn u64_to_trimmed_bytes(v: u64) -> Bytes {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    Bytes::copy_from_slice(&bytes[start..])
}

/// Converts a signed transaction to a firehose TxEvent.
pub fn signed_tx_to_tx_event<Tx>(
    tx: &Tx,
    signer: Address,
    tx_index: usize,
    r: B256,
    s: B256,
    v: Bytes,
) -> TxEvent
where
    Tx: alloy_consensus::Transaction + TxHashRef,
{
    TxEvent {
        // FIXME: That is not true, what about Optimism specialized transaction types? We might
        // to have a special mapper that knows the chain and as such is aware of some types
        // that could not exists anywhere else. We will need to deal with this.
        tx_type: tx.ty().try_into().expect("All transaction types handled for now"),
        hash: *tx.tx_hash(),
        from: signer,
        to: tx.to(),
        input: tx.input().clone(),
        value: tx.value(),
        gas: tx.gas_limit(),
        gas_price: U256::from(tx.gas_price().unwrap_or(0)),
        nonce: tx.nonce(),
        index: tx_index as u32,
        r,
        s,
        v: Some(v),
        max_fee_per_gas: if tx.is_dynamic_fee() {
            Some(U256::from(tx.max_fee_per_gas()))
        } else {
            None
        },
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas().map(U256::from),
        access_list: tx
            .access_list()
            .map(|al| {
                al.iter()
                    .map(|item| AccessTuple {
                        address: item.address,
                        storage_keys: item.storage_keys.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        blob_gas_fee_cap: tx.max_fee_per_blob_gas().map(U256::from),
        blob_hashes: tx.blob_versioned_hashes().map(|h| h.to_vec()).unwrap_or_default(),
        set_code_authorizations: tx
            .authorization_list()
            .map(|auths| auths.iter().map(map_signed_authorization).collect())
            .unwrap_or_default(),
    }
}

/// Wraps a StateProviderBox to implement the firehose StateReader trait.
///
/// StateProviderBox is Box<dyn StateProvider + Send + 'static>, so StateReaderAdapter
/// is automatically Send + 'static, satisfying the Box<dyn StateReader + Send> bound.
pub struct StateReaderAdapter(pub StateProviderBox);

impl Debug for StateReaderAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StateReaderAdapter").finish()
    }
}

impl firehose_tracer::types::StateReader for StateReaderAdapter {
    fn get_nonce(&self, address: Address) -> u64 {
        self.0.account_nonce(&address).ok().flatten().unwrap_or(0)
    }

    fn get_code(&self, address: Address) -> Bytes {
        self.0
            .account_code(&address)
            .ok()
            .flatten()
            .map(|bytecode| bytecode.0.original_bytes())
            .unwrap_or_default()
    }

    fn exists(&self, address: Address) -> bool {
        self.0.basic_account(&address).ok().flatten().is_some()
    }
}

/// Builds a [`firehose_tracer::types::ReceiptData`] from raw execution components,
/// for use in the historical execution path where a `TxReceipt` is not yet available.
///
/// - `tx_index`: 0-based index of this transaction in the block
/// - `gas_used`: gas consumed by this transaction alone
/// - `cumulative_gas`: running total of gas used up to and including this tx
/// - `status`: 1 = success, 0 = failure/revert
/// - `logs`: logs emitted by this transaction
/// - `log_index_start`: block-wide log index of the first log in this receipt
pub fn receipt_data_from_parts(
    tx_index: u32,
    gas_used: u64,
    cumulative_gas: u64,
    status: u64,
    logs: &[alloy_primitives::Log],
    log_index_start: u32,
) -> firehose_tracer::types::ReceiptData {
    let mut receipt_data =
        firehose_tracer::types::ReceiptData::new(tx_index, gas_used, status, cumulative_gas);
    for (i, log) in logs.iter().enumerate() {
        receipt_data.add_log(firehose_tracer::types::LogData::new(
            log.address,
            log.data.topics().to_vec(),
            log.data.data.clone(),
            log_index_start + i as u32,
        ));
    }
    receipt_data
}

/// Converts a receipt to a firehose ReceiptData.
///
/// - `tx_index`: 0-based index of this transaction in the block
/// - `gas_used`: gas consumed by this transaction alone (cumulative_gas - prev_cumulative_gas)
/// - `log_index_start`: block-wide log index of the first log in this receipt
/// - `blob_gas_used`: total blob gas consumed by this tx (0 for non-EIP-4844 transactions)
/// - `blob_gas_price`: per-unit blob gas price from the block (None pre-Cancun)
pub fn to_receipt_data<R>(
    receipt: &R,
    tx_index: u32,
    gas_used: u64,
    log_index_start: u32,
    blob_gas_used: u64,
    blob_gas_price: Option<U256>,
) -> firehose_tracer::types::ReceiptData
where
    R: alloy_consensus::TxReceipt<Log = alloy_primitives::Log>,
{
    let mut receipt_data = firehose_tracer::types::ReceiptData::new(
        tx_index,
        gas_used,
        receipt.status() as u64,
        receipt.cumulative_gas_used(),
    );
    receipt_data.logs_bloom = *receipt.bloom().data();
    receipt_data.blob_gas_used = blob_gas_used;
    receipt_data.blob_gas_price = blob_gas_price;
    for (i, log) in receipt.logs().iter().enumerate() {
        receipt_data.add_log(firehose_tracer::types::LogData::new(
            log.address,
            log.data.topics().to_vec(),
            log.data.data.clone(),
            log_index_start + i as u32,
        ));
    }
    receipt_data
}

fn map_signed_authorization(
    auth: &alloy_eips::eip7702::SignedAuthorization,
) -> SetCodeAuthorization {
    SetCodeAuthorization {
        chain_id: B256::new(auth.inner().chain_id().to_be_bytes::<32>()),
        address: *auth.inner().address(),
        nonce: auth.inner().nonce(),
        v: auth.y_parity() as u32,
        r: B256::new(auth.r().to_be_bytes::<32>()),
        s: B256::new(auth.s().to_be_bytes::<32>()),
    }
}
