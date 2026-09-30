//! Post-transaction gas accounting (refund and fee reward) and the `gas_consumed` a call
//! reports once EIP-8037 state gas is in play.

use super::support::*;
use crate::inspector::*;
use reth_revm::revm::primitives::hardfork::SpecId;

const COINBASE: Address = Address::repeat_byte(0xcb);

/// Drives one transaction whose root call targets an empty account, then applies the given
/// post-tx gas accounting through the production method and returns the decoded block.
/// The sender's live balance is captured by the depth-0 hook, as on a real transaction.
fn drive_gas_accounting(
    gas_limit: u64,
    gas_used: u64,
    accounting: PostTxGasAccounting,
) -> pb::sf::ethereum::r#type::v2::Block {
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

    let sender_balance = U256::from(1_000_000u64);
    let coinbase_balance = U256::from(50u64);
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(SENDER, AccountInfo { balance: sender_balance, ..Default::default() });
    db.insert_account_info(
        COINBASE,
        AccountInfo { balance: coinbase_balance, ..Default::default() },
    );
    db.insert_account_info(PRECOMPILE, AccountInfo::default());
    let mut ctx = Context::mainnet().with_db(db);
    ctx.journal_mut().load_account(SENDER).expect("load sender");

    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 2818,
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
            gas_limit,
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
        let _ = insp.call(&mut ctx, &mut inputs);
        let mut outcome = CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Stop,
                output: Bytes::new(),
                gas: Gas::new(gas_limit),
            },
            memory_offset: 0..0,
            was_precompile_called: false,
            precompile_call_logs: Vec::new(),
            charged_new_account_state_gas: false,
        };
        insp.call_end(&mut ctx, &inputs, &mut outcome);

        insp.process_post_tx_gas_accounting(
            SENDER,
            COINBASE,
            gas_limit,
            gas_used,
            accounting,
            0,
            |address| if address == COINBASE { coinbase_balance } else { sender_balance },
        );

        let receipt = firehose_tracer::types::ReceiptData::new(0, gas_used, 1, gas_used);
        insp.tracer_mut().on_tx_end(Some(&receipt), None);
    }

    tracer.on_block_end(None);
    drop(tracer);

    decode_fire_block(&buffer.get_bytes())
}

fn fee_changes(
    block: &pb::sf::ethereum::r#type::v2::Block,
) -> Vec<(Address, pb::sf::ethereum::r#type::v2::balance_change::Reason, U256, U256)> {
    use pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let big = |value: &Option<pb::sf::ethereum::r#type::v2::BigInt>| {
        value.as_ref().map(|v| U256::from_be_slice(&v.bytes)).unwrap_or_default()
    };
    block.transaction_traces[0].calls[0]
        .balance_changes
        .iter()
        .filter_map(|change| {
            let reason = Reason::try_from(change.reason).ok()?;
            matches!(reason, Reason::GasRefund | Reason::RewardTransactionFee).then(|| {
                (
                    Address::from_slice(&change.address),
                    reason,
                    big(&change.old_value),
                    big(&change.new_value),
                )
            })
        })
        .collect()
}

/// The Ethereum accounting refunds unused gas at the effective price and credits only the
/// priority fee, exactly as `process_post_tx_balance_changes` always did.
#[test]
fn gas_accounting_ethereum_matches_legacy_method() {
    use pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let block = drive_gas_accounting(100, 60, PostTxGasAccounting::ethereum(10, 4));
    assert_eq!(
        fee_changes(&block),
        vec![
            (SENDER, Reason::GasRefund, U256::from(1_000_000u64), U256::from(1_000_400u64)),
            (COINBASE, Reason::RewardTransactionFee, U256::from(50u64), U256::from(410u64)),
        ]
    );
}

/// A chain that does not burn the base fee and charges an extra data fee credits both in a
/// single `RewardTransactionFee` change.
#[test]
fn gas_accounting_extra_reward_is_one_change() {
    use pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let accounting = PostTxGasAccounting {
        refund_gas_price: 10,
        reward_gas_price: 10,
        extra_reward: U256::from(7u64),
    };
    let block = drive_gas_accounting(100, 60, accounting);
    assert_eq!(
        fee_changes(&block),
        vec![
            (SENDER, Reason::GasRefund, U256::from(1_000_000u64), U256::from(1_000_400u64)),
            (COINBASE, Reason::RewardTransactionFee, U256::from(50u64), U256::from(657u64)),
        ]
    );
}

/// Gas not paid from the native balance produces neither a refund nor a reward.
#[test]
fn gas_accounting_none_emits_no_fee_changes() {
    let block = drive_gas_accounting(100, 60, PostTxGasAccounting::none());
    assert!(fee_changes(&block).is_empty());
}

/// EIP-8037: a call's `gas_consumed` must not depend on where the state gas it charged
/// happened to come from.
///
/// State gas is drawn from the transaction's reservoir first and only spills into regular
/// gas once the reservoir is empty. The reservoir exists only when the gas limit exceeds
/// `TX_GAS_LIMIT_CAP`, so the same `SSTORE` charges the same 64 state bytes either way —
/// paid out of regular gas under the cap, out of the reservoir above it. Reporting the
/// regular component alone would make the identical call look cheaper purely because it was
/// sent with a larger limit.
#[test]
fn call_gas_consumed_is_independent_of_the_eip8037_reservoir() {
    use reth_revm::revm::primitives::eip7825::TX_GAS_LIMIT_CAP;

    // PUSH1 0x01, PUSH1 0x00, SSTORE, STOP: one 0->non-zero store, 64 state bytes.
    const SSTORE_ONE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

    let accounts = [(SENDER, balance_account(u64::MAX)), (RECIPIENT, code_account(SSTORE_ONE, 0))];

    let root_call_gas = |gas_limit: u64| {
        let block = drive_txs(
            SpecId::AMSTERDAM,
            &accounts,
            &[DriveTx::call(RECIPIENT, 0).with_gas(gas_limit)],
        );
        let trx = block.transaction_traces.first().expect("one transaction").clone();
        let root = trx.calls.first().expect("a root call");
        (root.gas_consumed, trx.gas_used)
    };

    let (under_cap, under_cap_tx) = root_call_gas(TX_GAS_LIMIT_CAP);
    let (over_cap, over_cap_tx) = root_call_gas(TX_GAS_LIMIT_CAP + 200_000);

    // Control: the work done is identical, so the receipt agrees across both limits. If this
    // ever fails the fixture changed, not the reporting.
    assert_eq!(under_cap_tx, over_cap_tx, "the same store costs the same either way");

    assert_eq!(
        over_cap, under_cap,
        "reservoir-paid state gas is missing from the call's gas_consumed"
    );
}

/// EIP-8037: a revert returns the state gas the frame charged, so `gas_consumed` must not
/// keep it.
///
/// Pre-Amsterdam a reverted `SSTORE` was still paid for in full. Under EIP-8037 the state
/// component is handed back to the reservoir instead, and unlike the reservoir itself this
/// applies at any gas limit — an ordinary transaction whose call reverts after storing hits
/// it. Checked against the receipt rather than a constant: the root call plus the intrinsic
/// gas is what the transaction is charged, and the intrinsic part is read off a transaction
/// that does nothing but revert.
#[test]
fn call_gas_consumed_excludes_state_gas_returned_on_revert() {
    // PUSH1 0x00, PUSH1 0x00, REVERT.
    const REVERT: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];
    // PUSH1 0x01, PUSH1 0x00, SSTORE, then the same revert: 64 state bytes, all returned.
    const SSTORE_THEN_REVERT: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xfd];

    let charged = |code: &[u8]| {
        let accounts = [(SENDER, balance_account(u64::MAX)), (RECIPIENT, code_account(code, 0))];
        let block = drive_tx(SpecId::AMSTERDAM, &accounts, RECIPIENT, 0);
        let trx = block.transaction_traces.first().expect("one transaction").clone();
        let root = trx.calls.first().expect("a root call");
        (root.gas_consumed, trx.gas_used)
    };

    let (bare_root, bare_tx) = charged(REVERT);
    let intrinsic = bare_tx - bare_root;

    let (root, tx) = charged(SSTORE_THEN_REVERT);
    assert_eq!(
        root + intrinsic,
        tx,
        "the reverted store's state gas is reported as consumed but the receipt gave it back"
    );
}
