//! Shared fixtures for the [`crate::inspector`] tests: well-known addresses, account and
//! opcode builders, the revm drivers every EVM-level test runs through, and the FIRE output
//! decoder.

use crate::inspector::*;
use reth_revm::revm::primitives::hardfork::SpecId;

/// Address of the B-20 activation registry precompile, used here as a stand-in for any
/// native precompile that writes storage / emits logs directly on the journal.
pub(super) const PRECOMPILE: Address =
    Address::new([0x84, 0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
pub(super) const SENDER: Address = Address::repeat_byte(0xaa);

/// Recipient of a plain value transfer, holding no code.
pub(super) const RECIPIENT: Address = Address::repeat_byte(0xcc);

pub(super) fn code_account(code: &[u8], balance: u64) -> revm::state::AccountInfo {
    use reth_revm::bytecode::Bytecode;

    let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
    revm::state::AccountInfo {
        balance: U256::from(balance),
        nonce: 0,
        code_hash: alloy_primitives::keccak256(bytecode.original_byte_slice()),
        code: Some(bytecode),
        account_id: None,
    }
}

pub(super) fn balance_account(balance: u64) -> revm::state::AccountInfo {
    revm::state::AccountInfo { balance: U256::from(balance), ..Default::default() }
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

/// Runs `txs` as separate transactions in one block through revm at `spec`, with the
/// production inspector attached, then replays each resulting receipt through `on_tx_end`.
///
/// `spec` is a parameter rather than a constant so a test can pin behaviour on both sides of
/// a fork boundary — EIP-7708 only emits below `SpecId::AMSTERDAM`, and the absence of a log
/// before it is as much a property worth testing as its presence after.
///
/// Going through a genuine `inspect_tx_commit` rather than hand-driven hooks is the point:
/// EIP-7708 logs are appended by revm's journal outside any opcode, and where revm appends
/// them is the thing under test, so a fixture that fabricated them would only re-assert this
/// file's own assumptions. `on_tx_end`
/// runs `assign_ordinal_and_index_to_receipt_logs`, which panics when the logs collected off
/// the call tree do not match the receipt one-for-one, in count and in `block_index` order.
///
/// A single inspector is built once and shared across every tx, exactly as the production
/// executor holds one inspector for the whole block: `process_post_tx_balance_changes` is
/// called after each tx to advance its block-wide log counter, so a second tx's logs
/// continue numbering after the first's rather than restarting at `block_index` 0.
pub(super) fn drive_txs(
    spec: SpecId,
    accounts: &[(Address, revm::state::AccountInfo)],
    txs: &[DriveTx],
) -> pb::sf::ethereum::r#type::v2::Block {
    use reth_revm::revm::{
        context::{Context, TxEnv},
        database::{CacheDB, EmptyDB},
        primitives::TxKind,
        InspectCommitEvm, MainBuilder, MainContext,
    };

    let mut db = CacheDB::new(EmptyDB::default());
    for (address, info) in accounts {
        db.insert_account_info(*address, info.clone());
    }

    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 1,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            verkle_time: None,
        },
        "reth-firehose-test",
        "0",
    );

    tracer.on_block_start(firehose_tracer::types::BlockEvent {
        block: firehose_tracer::types::BlockData { number: 2, ..Default::default() },
        finalized: None,
        flash_block: None,
    });

    // Scoped so the EVM (which owns the inspector, which borrows the tracer) is dropped
    // before the tracer is used again for `on_block_end`.
    {
        let insp = FirehoseInspector::new(&mut tracer);
        let mut evm = Context::mainnet()
            .with_db(db)
            // Matches how the node builds its config (`EthEvmConfig::evm_env`): assigning
            // `spec` alone leaves the Amsterdam gas params and the EIP-8037/EIP-2780
            // switches off, so the EVM under test would not be the one that runs in
            // production.
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(spec))
            .build_mainnet_with_inspector(insp);

        // Block-wide log count seen so far, mirroring `log_block_index`: a receipt log's
        // `block_index` is the block-wide position the call tree reports, not the index
        // within this tx's own `ExecutionResult::logs()`.
        let mut block_log_offset = 0u32;

        for (tx_index, drive_tx) in txs.iter().enumerate() {
            let DriveTx { to, ref input, value, gas_limit } = *drive_tx;
            let tx = TxEnv {
                caller: SENDER,
                gas_limit,
                gas_price: 0,
                kind: to.map_or(TxKind::Create, TxKind::Call),
                value: U256::from(value),
                data: input.clone(),
                nonce: tx_index as u64,
                ..Default::default()
            };

            evm.inspector.tracer_mut().on_tx_start(
                firehose_tracer::types::TxEvent {
                    to,
                    input: input.clone(),
                    value: U256::from(value),
                    gas: gas_limit,
                    gas_price: U256::ZERO,
                    nonce: tx_index as u64,
                    ..legacy_tx_event()
                },
                None,
            );

            let result = evm.inspect_tx_commit(tx).expect("transaction executes");

            let gas_used = result.tx_gas_used();
            let committed_log_count = result.logs().len() as u32;
            let mut receipt = firehose_tracer::types::ReceiptData::new(
                tx_index as u32,
                gas_used,
                u64::from(result.is_success()),
                gas_used,
            );
            for (log_index, log) in result.logs().iter().enumerate() {
                receipt.add_log(firehose_tracer::types::LogData::new(
                    log.address,
                    log.topics().to_vec(),
                    log.data.data.clone(),
                    block_log_offset + log_index as u32,
                ));
            }
            // Mirrors the production executor, which runs post-tx accounting before
            // closing the transaction: the gas-refund and coinbase-reward events, and the
            // nonce/code cleanup of self-destructed accounts, all belong to the
            // transaction the tracer is still inside. It also advances the block-wide log
            // counter (`self.log_block_index += committed_log_count`).
            evm.inspector.process_post_tx_balance_changes(
                SENDER,
                Address::ZERO,
                gas_limit,
                gas_used,
                0,
                0,
                committed_log_count,
                |_| U256::ZERO,
            );

            evm.inspector.tracer_mut().on_tx_end(Some(&receipt), None);
            block_log_offset += committed_log_count;
        }

        evm.inspector.tracer_mut().on_block_end(None);
    }

    decode_fire_block(&buffer.get_bytes())
}

/// One transaction for [`drive_txs`]. Runs with [`DriveTx::AMPLE_GAS`] unless a scenario
/// starves it on purpose with [`DriveTx::with_gas`].
pub(super) struct DriveTx {
    to: Option<Address>,
    input: Bytes,
    value: u64,
    gas_limit: u64,
}

impl DriveTx {
    pub(super) const AMPLE_GAS: u64 = 1_000_000;

    /// A call to `to` carrying `value`.
    pub(super) fn call(to: Address, value: u64) -> Self {
        Self { to: Some(to), input: Bytes::new(), value, gas_limit: Self::AMPLE_GAS }
    }

    /// A contract creation running `initcode`.
    pub(super) fn create(initcode: impl Into<Bytes>) -> Self {
        Self { to: None, input: initcode.into(), value: 0, gas_limit: Self::AMPLE_GAS }
    }

    /// Sets the calldata (ignored by a creation, whose calldata is its init code).
    pub(super) fn with_input(mut self, input: impl Into<Bytes>) -> Self {
        self.input = input.into();
        self
    }

    /// Sets the gas limit, so a scenario can starve a frame instead of always running to
    /// completion.
    pub(super) fn with_gas(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }
}

/// Runs one real transaction through revm at `spec`, with the production inspector
/// attached, then replays the resulting receipt through `on_tx_end`. See [`drive_txs`] for
/// what this exercises and why.
pub(super) fn drive_tx(
    spec: SpecId,
    accounts: &[(Address, revm::state::AccountInfo)],
    to: Address,
    value: u64,
) -> pb::sf::ethereum::r#type::v2::Block {
    drive_txs(spec, accounts, &[DriveTx::call(to, value)])
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
    }
}

/// firehose-tracer exposes no FIRE BLOCK parser (only `InMemoryBuffer::get_bytes`), so
/// pull the base64 protobuf payload off the single FIRE BLOCK line and decode it here.
pub(super) fn decode_fire_block(raw: &[u8]) -> pb::sf::ethereum::r#type::v2::Block {
    use base64::Engine as _;
    use prost::Message as _;

    let text = std::str::from_utf8(raw).expect("FIRE output is UTF-8");
    let line = text.lines().find(|l| l.starts_with("FIRE BLOCK ")).expect("a FIRE BLOCK line");
    let payload = line.split(' ').next_back().expect("payload token");
    let bytes = base64::engine::general_purpose::STANDARD.decode(payload).expect("base64 payload");
    pb::sf::ethereum::r#type::v2::Block::decode(bytes.as_slice()).expect("protobuf Block")
}
