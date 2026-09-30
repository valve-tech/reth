//! State changes a native precompile writes directly on the journal, with no SSTORE or LOG
//! opcode in between.

use super::support::*;
use crate::inspector::*;

/// A native precompile writes one storage slot and emits one log directly on the journal
/// (no SSTORE/LOG opcode). Driving the inspector's real `call` / `call_end` hooks around
/// those writes must attach both to the precompile's call frame: the log so the call-log
/// count matches the receipt (otherwise the tracer panics), and the storage change so it
/// is not silently dropped.
#[test]
fn precompile_journal_storage_and_logs_are_captured() {
    let block = decode_fire_block(&drive_precompile_call());

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("one call");

    assert_eq!(call.logs.len(), 1, "precompile log must be attached to the call");
    assert_eq!(call.logs[0].address, PRECOMPILE.to_vec());
    assert_eq!(call.logs[0].block_index, 0);

    assert_eq!(
        call.storage_changes.len(),
        1,
        "precompile storage write must be attached to the call"
    );
    let change = &call.storage_changes[0];
    assert_eq!(change.address, PRECOMPILE.to_vec());
    assert_eq!(change.key, B256::from(U256::from(7u64)).to_vec());
    assert_eq!(change.new_value, B256::from(U256::from(42u64)).to_vec());
    assert_eq!(change.old_value, B256::ZERO.to_vec());
}

#[test]
fn reverted_precompile_value_transfer_emits_balance_changes() {
    let block = decode_fire_block(&drive_reverted_precompile_value_transfer());

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("one call");
    assert!(call.state_reverted, "precompile call must be reverted");

    let transfers: Vec<_> = call
        .balance_changes
        .iter()
        .filter(|b| {
            b.reason == pb::sf::ethereum::r#type::v2::balance_change::Reason::Transfer as i32
        })
        .collect();

    assert_eq!(
        transfers.len(),
        2,
        "reverted precompile value transfer must emit sender-debit + precompile-credit"
    );
    assert_eq!(transfers[0].address, SENDER.to_vec(), "first transfer is the sender debit");
    assert_eq!(
        transfers[1].address,
        PRECOMPILE.to_vec(),
        "second transfer is the precompile credit"
    );
}

/// Drives one transaction whose only call targets a native precompile, going through the
/// inspector's real `call` / `call_end` hooks (which run the precompile gathers). The
/// precompile body is simulated by writing the storage slot and log directly on the
/// journal between the two hooks — exactly what `EvmInternals` does for a real precompile,
/// with no SSTORE/LOG opcode in between. Write order mirrors a B-20 transfer: mutate
/// state, then emit the event. Returns the raw FIRE output buffer.
fn drive_precompile_call() -> Vec<u8> {
    use reth_revm::{
        bytecode::Bytecode,
        revm::{
            context::Context,
            database::{CacheDB, EmptyDB},
            interpreter::{
                interpreter_action::CallScheme, CallInput, CallValue, Gas, InstructionResult,
                InterpreterResult,
            },
            state::AccountInfo,
            MainContext,
        },
    };

    let storage_key = U256::from(7u64);
    let storage_value = U256::from(42u64);
    let log_topic = B256::repeat_byte(0xcc);
    let log_data = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);

    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(PRECOMPILE, AccountInfo::default());
    let mut ctx = Context::mainnet().with_db(db);

    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 8453,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: None,
            verkle_time: None,
        },
        "reth-firehose-test",
        "0",
    );

    {
        // `with_buffer` already performed `on_blockchain_init`.
        let mut insp = FirehoseInspector::new(&mut tracer);
        insp.tracer_mut().on_block_start(firehose_tracer::types::BlockEvent {
            block: firehose_tracer::types::BlockData { number: 2, ..Default::default() },
            finalized: None,
            flash_block: None,
        });
        insp.tracer_mut().on_tx_start(legacy_tx_event(), None);

        let mut inputs = CallInputs {
            input: CallInput::Bytes(Bytes::new()),
            return_memory_offset: 0..0,
            gas_limit: 100_000,
            reservoir: 0,
            bytecode_address: PRECOMPILE,
            known_bytecode: (KECCAK_EMPTY, Bytecode::default()),
            target_address: PRECOMPILE,
            caller: SENDER,
            value: CallValue::Transfer(U256::ZERO),
            scheme: CallScheme::Call,
            is_static: false,
            charged_new_account_state_gas: false,
        };

        // Enter the precompile frame through the production hook.
        let _ = insp.call(&mut ctx, &mut inputs);

        // The precompile body: SSTORE-equivalent then a log, both straight on the journal
        // with no opcode. Warm the account and slot first so `sstore` does not attempt a
        // cold DB load against the empty test DB.
        ctx.journal_mut().load_account(PRECOMPILE).expect("load account");
        ctx.journal_mut().sload(PRECOMPILE, storage_key).expect("sload");
        ctx.journal_mut().sstore(PRECOMPILE, storage_key, storage_value).expect("sstore");
        ctx.journal_mut().log(AlloyLog {
            address: PRECOMPILE,
            data: alloy_primitives::LogData::new_unchecked(vec![log_topic], log_data.clone()),
        });

        // Exit through the production hook — this is where the precompile gathers run.
        let mut outcome = CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Return,
                output: Bytes::new(),
                gas: Gas::new(100_000),
            },
            memory_offset: 0..0,
            was_precompile_called: true,
            precompile_call_logs: Vec::new(),
            charged_new_account_state_gas: false,
        };
        insp.call_end(&mut ctx, &inputs, &mut outcome);

        let mut receipt = firehose_tracer::types::ReceiptData::new(0, 21_000, 1, 21_000);
        receipt.add_log(firehose_tracer::types::LogData::new(
            PRECOMPILE,
            vec![log_topic],
            log_data,
            0,
        ));
        // Panics ("mismatch between call logs and receipt logs") if the call carries fewer
        // logs than the receipt — i.e. if the log gather in `call_end` regressed.
        insp.tracer_mut().on_tx_end(Some(&receipt), None);
    }

    tracer.on_block_end(None);
    drop(tracer);

    buffer.get_bytes()
}

/// Drives one transaction sending value to a native precompile whose frame then fails
/// (out of gas) after the value transfer, so revm truncated the BalanceTransfer journal
/// entry on rollback. Mirrors Hoodi 3171397: geth still reports the transfer, so the
/// inspector must re-emit it from `pending_value_transfer` in call_end. Returns the raw
/// FIRE output buffer.
fn drive_reverted_precompile_value_transfer() -> Vec<u8> {
    use reth_revm::{
        bytecode::Bytecode,
        revm::{
            context::Context,
            database::{CacheDB, EmptyDB},
            interpreter::{
                interpreter_action::CallScheme, CallInput, CallValue, Gas, InstructionResult,
                InterpreterResult,
            },
            state::AccountInfo,
            MainContext,
        },
    };

    let value = U256::from(1000u64);

    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        SENDER,
        AccountInfo { balance: U256::from(1_000_000u64), ..Default::default() },
    );
    db.insert_account_info(
        PRECOMPILE,
        AccountInfo { balance: U256::from(500u64), ..Default::default() },
    );
    let mut ctx = Context::mainnet().with_db(db);

    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 8453,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: None,
            verkle_time: None,
        },
        "reth-firehose-test",
        "0",
    );

    {
        let mut insp = FirehoseInspector::new(&mut tracer);
        insp.tracer_mut().on_block_start(firehose_tracer::types::BlockEvent {
            block: firehose_tracer::types::BlockData { number: 2, ..Default::default() },
            finalized: None,
            flash_block: None,
        });
        insp.tracer_mut().on_tx_start(legacy_tx_event(), None);

        let mut inputs = CallInputs {
            input: CallInput::Bytes(Bytes::new()),
            return_memory_offset: 0..0,
            gas_limit: 0,
            reservoir: 0,
            bytecode_address: PRECOMPILE,
            known_bytecode: (KECCAK_EMPTY, Bytecode::default()),
            target_address: PRECOMPILE,
            caller: SENDER,
            value: CallValue::Transfer(value),
            scheme: CallScheme::Call,
            is_static: false,
            charged_new_account_state_gas: false,
        };

        // Enter the precompile frame through the production hook (records the pending
        // value transfer).
        let _ = insp.call(&mut ctx, &mut inputs);

        // Simulate the post-rollback state: revm did the transfer then the precompile ran
        // out of gas and the checkpoint was reverted, truncating the BalanceTransfer. The
        // accounts are loaded at their pre-transfer balances and no BalanceTransfer entry
        // remains in the journal for call_end to find.
        ctx.journal_mut().load_account(SENDER).expect("load sender");
        ctx.journal_mut().load_account(PRECOMPILE).expect("load precompile");

        let mut outcome = CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::OutOfGas,
                output: Bytes::new(),
                gas: Gas::new(0),
            },
            memory_offset: 0..0,
            was_precompile_called: true,
            precompile_call_logs: Vec::new(),
            charged_new_account_state_gas: false,
        };
        insp.call_end(&mut ctx, &inputs, &mut outcome);

        let receipt = firehose_tracer::types::ReceiptData::new(0, 21_000, 0, 21_000);
        insp.tracer_mut().on_tx_end(Some(&receipt), None);
    }

    tracer.on_block_end(None);
    drop(tracer);

    buffer.get_bytes()
}

#[test]
fn precompile_log_after_reverted_opcode_log_is_captured() {
    let block = decode_fire_block(&drive_precompile_log_after_reverted_opcode_log());

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("one call");

    assert_eq!(
        call.logs.len(),
        1,
        "precompile log reusing a reverted log's journal index must still be captured"
    );
    assert_eq!(call.logs[0].address, PRECOMPILE.to_vec());
    assert_eq!(call.logs[0].block_index, 0);
}

/// Regression for the Base mainnet block 48387796 panic (tx 0xc2cf3e23…): a Uniswap V4
/// revert-based quote emitted a `Swap` *opcode* log inside a sub-call that then reverted.
/// `log_full` had advanced `trx_logs_count`; revm truncated the log on revert but left the
/// watermark stale-high. A B-20 token's committed precompile log then reused the freed
/// journal index, so `drain_journal_logs` skipped it as "already emitted" — the call
/// carried one fewer log than the receipt and `assign_ordinal_and_index_to_receipt_logs`
/// panicked ("6 call logs but 7 receipt logs").
///
/// Drives the real hooks: emit an opcode log and revert it (with a manual
/// `drain_journal_logs` standing in for the reverting child frame's `call_end`, which
/// is where the watermark must be re-clamped to the live log count), then emit a native
/// precompile log at the reused index — it must still be gathered.
fn drive_precompile_log_after_reverted_opcode_log() -> Vec<u8> {
    use reth_revm::{
        bytecode::Bytecode,
        revm::{
            context::Context,
            database::{CacheDB, EmptyDB},
            interpreter::{
                interpreter_action::CallScheme, CallInput, CallValue, Gas, InstructionResult,
                InterpreterResult,
            },
            state::AccountInfo,
            MainContext,
        },
    };

    let reverted_topic = B256::repeat_byte(0xab);
    let precompile_topic = B256::repeat_byte(0xcc);
    let precompile_data = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);

    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(PRECOMPILE, AccountInfo::default());
    let mut ctx = Context::mainnet().with_db(db);

    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 8453,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: None,
            verkle_time: None,
        },
        "reth-firehose-test",
        "0",
    );

    {
        let mut insp = FirehoseInspector::new(&mut tracer);
        insp.tracer_mut().on_block_start(firehose_tracer::types::BlockEvent {
            block: firehose_tracer::types::BlockData { number: 2, ..Default::default() },
            finalized: None,
            flash_block: None,
        });
        insp.tracer_mut().on_tx_start(legacy_tx_event(), None);

        let mut inputs = CallInputs {
            input: CallInput::Bytes(Bytes::new()),
            return_memory_offset: 0..0,
            gas_limit: 100_000,
            reservoir: 0,
            bytecode_address: PRECOMPILE,
            known_bytecode: (KECCAK_EMPTY, Bytecode::default()),
            target_address: PRECOMPILE,
            caller: SENDER,
            value: CallValue::Transfer(U256::ZERO),
            scheme: CallScheme::Call,
            is_static: false,
            charged_new_account_state_gas: false,
        };

        // Enter the precompile frame through the production hook.
        let _ = insp.call(&mut ctx, &mut inputs);

        // A sub-call emits a LOG opcode, then reverts. Replicate `log_full`'s side effect
        // (advance the watermark to the journal log count), then revert the checkpoint so
        // revm truncates the log back off the journal — leaving the watermark stale-high.
        let checkpoint = ctx.journal_mut().checkpoint();
        ctx.journal_mut().log(AlloyLog {
            address: SENDER,
            data: alloy_primitives::LogData::new_unchecked(vec![reverted_topic], Bytes::new()),
        });
        insp.trx_logs_count = ctx.journal().logs().len() as u32; // == 1, what log_full sets
        ctx.journal_mut().checkpoint_revert(checkpoint);

        // The reverting child frame's `call_end` runs the gather against the truncated
        // journal — this is where the watermark must be re-clamped down to the live count.
        insp.drain_journal_logs(&mut ctx);

        // The B-20 precompile body: a log straight on the journal (no LOG opcode), landing
        // at the index the reverted log just freed.
        ctx.journal_mut().log(AlloyLog {
            address: PRECOMPILE,
            data: alloy_primitives::LogData::new_unchecked(
                vec![precompile_topic],
                precompile_data.clone(),
            ),
        });

        // Exit through the production hook — gather must now emit the precompile log.
        let mut outcome = CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Return,
                output: Bytes::new(),
                gas: Gas::new(100_000),
            },
            memory_offset: 0..0,
            was_precompile_called: true,
            precompile_call_logs: Vec::new(),
            charged_new_account_state_gas: false,
        };
        insp.call_end(&mut ctx, &inputs, &mut outcome);

        let mut receipt = firehose_tracer::types::ReceiptData::new(0, 21_000, 1, 21_000);
        receipt.add_log(firehose_tracer::types::LogData::new(
            PRECOMPILE,
            vec![precompile_topic],
            precompile_data,
            0,
        ));
        // Panics ("mismatch between call logs and receipt logs") if the precompile log was
        // skipped — the pre-fix behaviour.
        insp.tracer_mut().on_tx_end(Some(&receipt), None);
    }

    tracer.on_block_end(None);
    drop(tracer);

    buffer.get_bytes()
}
