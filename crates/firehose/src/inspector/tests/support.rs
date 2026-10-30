//! Shared fixtures for the [`crate::inspector`] tests: well-known addresses, account and
//! opcode builders, the block driver every EVM-level test runs through, and the FIRE output
//! decoder.

use crate::{
    inspector::*, run_wrapped_block, FirehoseBlockTracer, NoPostTxExtras, NoPreTxAdjust,
    PreTxAdjust,
};
use alloy_consensus::{
    constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH},
    proofs::calculate_transaction_root,
    Header, SignableTransaction, TxEip4844, TxEip7702, TxLegacy,
};
use alloy_eips::{eip4895::Withdrawals, eip7702::SignedAuthorization};
use alloy_primitives::{Signature, TxKind};
use base64::Engine as _;
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
    SpecId,
};
use firehose_tracer::pb;
use prost::Message as _;
use reth_chainspec::{ChainSpec, ChainSpecBuilder};
use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, EvmFor};
use reth_evm_ethereum::{EthEvmConfig, EvmFactory, RethEvmFactory};
use reth_primitives_traits::RecoveredBlock;
use std::{collections::HashMap, sync::Arc};

/// Address of the B-20 activation registry precompile, used here as a stand-in for any
/// native precompile that writes storage / emits logs directly on the journal.
pub(super) const PRECOMPILE: Address =
    Address::new([0x84, 0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
pub(super) const SENDER: Address = Address::repeat_byte(0xaa);

/// Recipient of a plain value transfer, holding no code.
pub(super) const RECIPIENT: Address = Address::repeat_byte(0xcc);

/// Chain id of the driven block, and of the transactions and authorizations in it.
pub(super) const CHAIN_ID: u64 = 1;

/// Gas limit of the driven block, above the sum of what any scenario sends.
const BLOCK_GAS_LIMIT: u64 = 100_000_000;

pub(super) fn code_account(code: &[u8], balance: u64) -> AccountInfo {
    AccountInfo::default()
        .with_balance(U256::from(balance))
        .with_code(Bytecode::new_raw(Bytes::copy_from_slice(code)))
}

pub(super) fn balance_account(balance: u64) -> AccountInfo {
    AccountInfo::default().with_balance(U256::from(balance))
}

/// `PUSHn <bytes>`. `PUSH0` is `0x5f`, so `PUSHn` is `0x5f + n`.
pub(super) fn push(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x5f + bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

/// `CALL(gas = all remaining, target, value, in = none, out = none)` then `POP`.
pub(super) fn op_call_with_value(target: Address, value: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(&[0])); // retLength
    code.extend(push(&[0])); // retOffset
    code.extend(push(&[0])); // argsLength
    code.extend(push(&[0])); // argsOffset
    code.extend(push(&value.to_be_bytes())); // value
    code.extend(push(target.as_slice())); // address
    code.push(0x5a); // GAS
    code.push(0xf1); // CALL
    code.push(0x50); // POP
    code
}

/// `LOG0` over an empty data range.
pub(super) fn op_log0() -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(&[0])); // size
    code.extend(push(&[0])); // offset
    code.push(0xa0); // LOG0
    code
}

/// Writes `initcode` into memory via `PUSHn` + `MSTORE` and returns the bytecode plus the
/// `(offset, size)` pair a CREATE/CREATE2 should read it back from. `MSTORE` left-pads its
/// 32-byte word, so `initcode` lands at the tail of the word: offset `32 - len`.
///
/// Empty `initcode` needs no memory write at all; `(0, 0)` alone reads as an empty range.
pub(super) fn op_store_initcode(initcode: &[u8]) -> (Vec<u8>, u8, u8) {
    if initcode.is_empty() {
        return (Vec::new(), 0, 0);
    }
    let mut code = Vec::new();
    code.extend(push(initcode));
    code.extend(push(&[0])); // mstore offset
    code.push(0x52); // MSTORE
    (code, 32 - initcode.len() as u8, initcode.len() as u8)
}

/// `CREATE(value, offset, size)` then `POP` the created address.
pub(super) fn op_create(value: u64, offset: u8, size: u8) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(&[size]));
    code.extend(push(&[offset]));
    code.extend(push(&value.to_be_bytes()));
    code.push(0xf0); // CREATE
    code.push(0x50); // POP
    code
}

/// `CREATE2(value, offset, size, salt)` then `POP` the created address.
pub(super) fn op_create2(value: u64, offset: u8, size: u8, salt: u8) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(&[salt]));
    code.extend(push(&[size]));
    code.extend(push(&[offset]));
    code.extend(push(&value.to_be_bytes()));
    code.push(0xf5); // CREATE2
    code.push(0x50); // POP
    code
}

/// Runs `txs` as separate transactions of one block at `spec`, through the production
/// Firehose block executor, and returns the decoded FIRE block.
///
/// See [`BlockDriver`] for what this exercises; this is [`BlockDriver::run`] with the default
/// coinbase, EVM factory and hooks.
pub(super) fn drive_txs(
    spec: SpecId,
    accounts: &[(Address, AccountInfo)],
    txs: &[DriveTx],
) -> pb::sf::ethereum::r#type::v2::Block {
    BlockDriver::new(spec, accounts).run(txs)
}

/// Runs one real transaction calling `to` with `value` at `spec`. See [`drive_txs`].
pub(super) fn drive_tx(
    spec: SpecId,
    accounts: &[(Address, AccountInfo)],
    to: Address,
    value: u64,
) -> pb::sf::ethereum::r#type::v2::Block {
    drive_txs(spec, accounts, &[DriveTx::call(to, value)])
}

/// Executes one block of transactions with the production inspector attached and returns the
/// decoded FIRE block.
///
/// The block goes through [`run_wrapped_block`] on an [`EthEvmConfig`], the path staged sync
/// traces blocks with: the EVM is built from the chain spec exactly as the node builds it, the
/// [`crate::FirehoseWrappedExecutor`] drives the transaction lifecycle (`on_tx_start`,
/// post-transaction gas accounting, `on_tx_end` with the real receipt), and the block's system
/// calls run around the transactions. Going through genuine execution rather than hand-driven
/// hooks is the point: where evm2 journals a change, appends a log or settles gas is the thing
/// under test, so a fixture that fabricated those would only re-assert this file's own
/// assumptions. `on_tx_end` runs `assign_ordinal_and_index_to_receipt_logs`, which panics when
/// the logs collected off the call tree do not match the receipt one-for-one.
///
/// `spec` selects the hardforks active in the block, so a test can pin behaviour on both sides
/// of a fork boundary.
pub(super) struct BlockDriver<'a, F = RethEvmFactory, A = NoPreTxAdjust> {
    spec: SpecId,
    accounts: &'a [(Address, AccountInfo)],
    coinbase: Address,
    evm_factory: F,
    adjust: A,
}

impl<'a> BlockDriver<'a> {
    pub(super) fn new(spec: SpecId, accounts: &'a [(Address, AccountInfo)]) -> Self {
        Self {
            spec,
            accounts,
            coinbase: Address::ZERO,
            evm_factory: RethEvmFactory::default(),
            adjust: NoPreTxAdjust,
        }
    }
}

impl<'a, F, A> BlockDriver<'a, F, A> {
    /// Sets the block beneficiary, credited the priority fee of every transaction.
    pub(super) const fn with_coinbase(mut self, coinbase: Address) -> Self {
        self.coinbase = coinbase;
        self
    }

    /// Builds the block's EVM with `evm_factory` instead of the node's default one.
    pub(super) fn with_evm_factory<F2>(self, evm_factory: F2) -> BlockDriver<'a, F2, A> {
        let Self { spec, accounts, coinbase, adjust, .. } = self;
        BlockDriver { spec, accounts, coinbase, evm_factory, adjust }
    }

    /// Installs a chain-specific [`PreTxAdjust`] hook on the executor.
    pub(super) fn with_pre_tx_adjust<A2>(self, adjust: A2) -> BlockDriver<'a, F, A2> {
        let Self { spec, accounts, coinbase, evm_factory, .. } = self;
        BlockDriver { spec, accounts, coinbase, evm_factory, adjust }
    }

    pub(super) fn run(self, txs: &[DriveTx]) -> pb::sf::ethereum::r#type::v2::Block
    where
        F: EvmFactory,
        EthEvmConfig<ChainSpec, F>: ConfigureEvm<Primitives = EthPrimitives>,
        for<'e> A: PreTxAdjust<EvmFor<'e, EthEvmConfig<ChainSpec, F>>>,
    {
        let evm_config =
            EthEvmConfig::new_with_evm_factory(chain_spec(self.spec), self.evm_factory);

        let mut db = InMemoryDB::default();
        let mut nonces = HashMap::new();
        for (address, info) in self.accounts {
            db.insert_account_info(address, info.clone());
            nonces.insert(*address, info.nonce);
        }

        let (transactions, senders): (Vec<_>, Vec<_>) = txs
            .iter()
            .map(|tx| {
                let nonce = nonces.entry(tx.sender).or_default();
                let signed = tx.sign(*nonce);
                *nonce += 1;
                (signed, tx.sender)
            })
            .unzip();

        let header = Header {
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            transactions_root: calculate_transaction_root(&transactions),
            receipts_root: EMPTY_ROOT_HASH,
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            number: 2,
            timestamp: 24,
            gas_limit: BLOCK_GAS_LIMIT,
            beneficiary: self.coinbase,
            base_fee_per_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            slot_number: self.spec.enables(SpecId::AMSTERDAM).then_some(0),
            ..Default::default()
        };
        let block = Block {
            header,
            body: BlockBody {
                transactions,
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals::default()),
            },
        };
        let block = RecoveredBlock::new_unhashed(block, senders);

        let (tracer, buffer) = firehose_tracer::Tracer::with_buffer(
            firehose_tracer::config::Config::default(),
            firehose_tracer::config::ChainConfig {
                chain_id: CHAIN_ID,
                shanghai_time: Some(0),
                cancun_time: Some(0),
                prague_time: Some(0),
                verkle_time: None,
            },
            "reth-firehose-test",
            "0",
        );
        let mut block_tracer = FirehoseBlockTracer::start_local::<EthPrimitives>(
            Box::new(tracer),
            block.sealed_block(),
            None,
        );

        run_wrapped_block(
            &evm_config,
            &mut db,
            &block,
            &mut block_tracer,
            self.adjust,
            NoPostTxExtras,
        )
        .expect("block executes");
        block_tracer.mark_verified();

        decode_fire_block(&buffer.get_bytes())
    }
}

/// Chain spec with every hardfork up to `spec` active at genesis, and none after it.
fn chain_spec(spec: SpecId) -> Arc<ChainSpec> {
    let builder = ChainSpecBuilder::mainnet();
    let builder = match spec {
        SpecId::PRAGUE => builder.prague_activated(),
        SpecId::OSAKA => builder.osaka_activated(),
        SpecId::AMSTERDAM => builder.amsterdam_activated(),
        other => panic!("no chain spec for {other:?}"),
    };
    Arc::new(builder.build())
}

/// One transaction for [`drive_txs`]: a legacy transaction from [`SENDER`] paying no gas,
/// with [`DriveTx::AMPLE_GAS`], unless a scenario changes it.
///
/// Transactions of the same sender take consecutive nonces, starting from the sender's account
/// nonce.
pub(super) struct DriveTx {
    sender: Address,
    to: Option<Address>,
    input: Bytes,
    value: u64,
    gas_limit: u64,
    gas_price: u128,
    envelope: Envelope,
}

/// Transaction type of a [`DriveTx`].
enum Envelope {
    Legacy,
    Blob { versioned_hashes: Vec<B256>, max_fee_per_blob_gas: u128 },
    SetCode { authorizations: Vec<SignedAuthorization> },
}

impl DriveTx {
    pub(super) const AMPLE_GAS: u64 = 1_000_000;

    /// A call to `to` carrying `value`.
    pub(super) fn call(to: Address, value: u64) -> Self {
        Self {
            sender: SENDER,
            to: Some(to),
            input: Bytes::new(),
            value,
            gas_limit: Self::AMPLE_GAS,
            gas_price: 0,
            envelope: Envelope::Legacy,
        }
    }

    /// A contract creation running `initcode`.
    pub(super) fn create(initcode: impl Into<Bytes>) -> Self {
        Self { to: None, input: initcode.into(), ..Self::call(Address::ZERO, 0) }
    }

    /// Sets the calldata (ignored by a creation, whose calldata is its init code).
    pub(super) fn with_input(mut self, input: impl Into<Bytes>) -> Self {
        self.input = input.into();
        self
    }

    /// Sets the value the transaction transfers.
    pub(super) const fn with_value(mut self, value: u64) -> Self {
        self.value = value;
        self
    }

    /// Sets the gas limit, so a scenario can starve a frame instead of always running to
    /// completion.
    pub(super) const fn with_gas(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Sets the gas price. The block's base fee is zero, so all of it is priority fee.
    pub(super) const fn with_gas_price(mut self, gas_price: u128) -> Self {
        self.gas_price = gas_price;
        self
    }

    /// Sends the transaction from `sender` instead of [`SENDER`].
    pub(super) const fn with_sender(mut self, sender: Address) -> Self {
        self.sender = sender;
        self
    }

    /// Makes the transaction an EIP-4844 blob transaction carrying `blobs` blobs, paying
    /// `max_fee_per_blob_gas` per blob gas.
    pub(super) fn with_blobs(mut self, blobs: u8, max_fee_per_blob_gas: u128) -> Self {
        let versioned_hashes = (0..blobs)
            .map(|index| {
                let mut hash = B256::repeat_byte(index);
                hash[0] = alloy_eips::eip4844::VERSIONED_HASH_VERSION_KZG;
                hash
            })
            .collect();
        self.envelope = Envelope::Blob { versioned_hashes, max_fee_per_blob_gas };
        self
    }

    /// Makes the transaction an EIP-7702 set-code transaction carrying `authorizations`.
    pub(super) fn with_authorizations(mut self, authorizations: Vec<SignedAuthorization>) -> Self {
        self.envelope = Envelope::SetCode { authorizations };
        self
    }

    /// Builds the signed transaction at `nonce`. The signature is a placeholder: the driver
    /// hands the executor the sender directly.
    fn sign(&self, nonce: u64) -> TransactionSigned {
        let signature = Signature::test_signature();
        let value = U256::from(self.value);
        let input = self.input.clone();
        let to = || self.to.expect("only a legacy transaction can create a contract");
        match &self.envelope {
            Envelope::Legacy => TxLegacy {
                chain_id: Some(CHAIN_ID),
                nonce,
                gas_price: self.gas_price,
                gas_limit: self.gas_limit,
                to: self.to.map_or(TxKind::Create, TxKind::Call),
                value,
                input,
            }
            .into_signed(signature)
            .into(),
            Envelope::Blob { versioned_hashes, max_fee_per_blob_gas } => TxEip4844 {
                chain_id: CHAIN_ID,
                nonce,
                gas_limit: self.gas_limit,
                max_fee_per_gas: self.gas_price,
                max_priority_fee_per_gas: self.gas_price,
                to: to(),
                value,
                access_list: Default::default(),
                blob_versioned_hashes: versioned_hashes.clone(),
                max_fee_per_blob_gas: *max_fee_per_blob_gas,
                input,
            }
            .into_signed(signature)
            .into(),
            Envelope::SetCode { authorizations } => TxEip7702 {
                chain_id: CHAIN_ID,
                nonce,
                gas_limit: self.gas_limit,
                max_fee_per_gas: self.gas_price,
                max_priority_fee_per_gas: self.gas_price,
                to: to(),
                value,
                access_list: Default::default(),
                authorization_list: authorizations.clone(),
                input,
            }
            .into_signed(signature)
            .into(),
        }
    }
}

pub(super) fn legacy_tx_event() -> firehose_tracer::types::TxEvent {
    firehose_tracer::types::TxEvent {
        tx_type: firehose_tracer::types::TxType::Legacy,
        hash: B256::repeat_byte(0x11),
        from: SENDER,
        to: Some(PRECOMPILE),
        input: Bytes::new(),
        value: U256::ZERO,
        gas: 100_000,
        gas_price: U256::from(7u64),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        blob_gas_fee_cap: None,
        blob_hashes: Vec::new(),
        set_code_authorizations: Vec::new(),
        account_abstraction_trx_input: None,
    }
}

/// firehose-tracer exposes no FIRE BLOCK parser (only `InMemoryBuffer::get_bytes`), so
/// pull the base64 protobuf payload off the single FIRE BLOCK line and decode it here.
pub(super) fn decode_fire_block(raw: &[u8]) -> pb::sf::ethereum::r#type::v2::Block {
    let text = std::str::from_utf8(raw).expect("FIRE output is UTF-8");
    let line = text.lines().find(|l| l.starts_with("FIRE BLOCK ")).expect("a FIRE BLOCK line");
    let payload = line.split(' ').next_back().expect("payload token");
    let bytes = base64::engine::general_purpose::STANDARD.decode(payload).expect("base64 payload");
    pb::sf::ethereum::r#type::v2::Block::decode(bytes.as_slice()).expect("protobuf Block")
}
