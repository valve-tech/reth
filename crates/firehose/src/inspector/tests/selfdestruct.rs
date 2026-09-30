//! SELFDESTRUCT: the `suicide` flag on the call that executed it, and the balance and state
//! events EIP-8246 changes.

use super::{scenario::*, support::*};
use crate::inspector::*;
use reth_revm::revm::primitives::hardfork::SpecId;

#[test]
fn executed_selfdestruct_marks_call_as_suicide() {
    use reth_revm::revm::interpreter::InstructionResult;

    let block = decode_fire_block(&drive_lone_selfdestruct(InstructionResult::SelfDestruct));
    let call = block.transaction_traces[0].calls.first().expect("one call");

    assert!(call.suicide, "an executed SELFDESTRUCT must mark the call as self-destructed");
    assert!(!call.status_failed, "an executed SELFDESTRUCT succeeds");
}

/// A chain can replace SELFDESTRUCT with an undefined instruction. The frame then halts on
/// `OpcodeNotFound` without self-destructing, so the call must not be reported as a suicide.
#[test]
fn undefined_selfdestruct_does_not_mark_call_as_suicide() {
    use reth_revm::revm::interpreter::InstructionResult;

    let block = decode_fire_block(&drive_lone_selfdestruct(InstructionResult::OpcodeNotFound));
    let call = block.transaction_traces[0].calls.first().expect("one call");

    assert!(!call.suicide, "an undefined SELFDESTRUCT must not mark the call as self-destructed");
    assert!(call.status_failed, "a frame halting on an undefined opcode fails");
}

/// Contract whose code is a lone `0xff` byte.
const SELFDESTRUCT_CONTRACT: Address = Address::repeat_byte(0xdd);

/// Drives one transaction calling [`SELFDESTRUCT_CONTRACT`] through the inspector's `call`,
/// `step`, `step_end` and `call_end` hooks, with the `0xff` instruction halting the frame on
/// `result`: `SelfDestruct` when the instruction table defines SELFDESTRUCT, `OpcodeNotFound`
/// when a chain replaced it with an undefined instruction. Returns the raw FIRE output buffer.
fn drive_lone_selfdestruct(result: reth_revm::revm::interpreter::InstructionResult) -> Vec<u8> {
    use reth_revm::{
        bytecode::Bytecode,
        revm::{
            context::Context,
            database::{CacheDB, EmptyDB},
            interpreter::{
                interpreter::ExtBytecode, interpreter_action::CallScheme, CallInput, CallValue,
                Gas, Interpreter, InterpreterResult,
            },
            state::AccountInfo,
            MainContext,
        },
    };

    let gas_limit = 100_000;
    let code = Bytecode::new_raw(Bytes::from_static(&[0xff]));
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        SELFDESTRUCT_CONTRACT,
        AccountInfo { code_hash: code.hash_slow(), code: Some(code.clone()), ..Default::default() },
    );
    let mut ctx = Context::mainnet().with_db(db);

    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 1,
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
            block: firehose_tracer::types::BlockData { number: 1, ..Default::default() },
            finalized: None,
            flash_block: None,
        });
        insp.tracer_mut().on_tx_start(
            firehose_tracer::types::TxEvent {
                to: Some(SELFDESTRUCT_CONTRACT),
                ..legacy_tx_event()
            },
            None,
        );

        let mut inputs = CallInputs {
            input: CallInput::Bytes(Bytes::new()),
            return_memory_offset: 0..0,
            gas_limit,
            reservoir: 0,
            bytecode_address: SELFDESTRUCT_CONTRACT,
            known_bytecode: (code.hash_slow(), code.clone()),
            target_address: SELFDESTRUCT_CONTRACT,
            caller: SENDER,
            value: CallValue::Transfer(U256::ZERO),
            scheme: CallScheme::Call,
            is_static: false,
            charged_new_account_state_gas: false,
        };
        let _ = insp.call(&mut ctx, &mut inputs);

        // Stand-in for the interpreter loop running the lone instruction: `step`, the
        // instruction halting the frame, then `step_end`.
        let mut interp = Interpreter { bytecode: ExtBytecode::new(code), ..Default::default() };
        insp.step(&mut interp, &mut ctx);
        interp.halt(result);
        insp.step_end(&mut interp, &mut ctx);

        let mut outcome = CallOutcome {
            result: InterpreterResult { result, output: Bytes::new(), gas: Gas::new(gas_limit) },
            memory_offset: 0..0,
            was_precompile_called: false,
            precompile_call_logs: Vec::new(),
            charged_new_account_state_gas: false,
        };
        insp.call_end(&mut ctx, &inputs, &mut outcome);

        let status = if result.is_ok() { 1 } else { 0 };
        let receipt = firehose_tracer::types::ReceiptData::new(0, gas_limit, status, gas_limit);
        insp.tracer_mut().on_tx_end(Some(&receipt), None);
    }

    tracer.on_block_end(None);
    drop(tracer);

    buffer.get_bytes()
}

// ---- EIP-8246 SELFDESTRUCT burn removal ----------------------------------------------
//
// [EIP-8246] stops `SELFDESTRUCT` from burning ETH: a self-beneficiary `SELFDESTRUCT`
// leaves the balance on the account, and at transaction finalization a self-destructed
// account that still holds a balance keeps it, losing only its nonce, code and storage.
//
// revm implements the rule (`JournalInner::selfdestruct` and
// `eip8246_clear_selfdestructed_accounts`); what the tests below pin is the Firehose side:
// which balance changes the inspector reports on each side of the fork. Every case from the
// EIP's own test-case list is driven at `PRAGUE` and at `AMSTERDAM` from the same scenario,
// so a difference in the reported events is attributable to the fork and nothing else.
//
// No new event kind is introduced. In particular the storage that revm wipes at
// finalization is not reported: nothing reported it before the fork and the Firehose
// protocol has no account-clearing event to hang it on.
//
// [EIP-8246]: https://eips.ethereum.org/EIPS/eip-8246

/// EIP test case, instruction level 1: same-transaction `selfdestruct-to-self`.
///
/// The burn this EIP removes, in its simplest form. Before Amsterdam the endowment leaves
/// the account as a `SuicideWithdraw` to nowhere; at Amsterdam the account keeps it and the
/// Firehose trace says nothing about the SELFDESTRUCT beyond marking the call.
#[test]
fn selfdestruct_to_self() {
    Scenario { ops: vec![op_call_selector(subject(), 0, SD_SELF)], ..Default::default() }
        .assert_balance_logs(
            &[
                "factory 1000000→999000 Transfer",
                "subject 0→1000 Transfer",
                "subject 1000→0 SuicideWithdraw",
            ],
            &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
        );
}

/// EIP test case, instruction level 2: `selfdestruct-to-self`, then `selfdestruct-to-self`
/// again.
///
/// The second SELFDESTRUCT is a no-op on both sides of the fork, for different reasons:
/// before Amsterdam the first one already emptied the account, at Amsterdam a
/// self-beneficiary SELFDESTRUCT moves nothing in the first place.
#[test]
fn selfdestruct_to_self_then_to_self() {
    Scenario {
        ops: vec![op_call_selector(subject(), 0, SD_SELF), op_call_selector(subject(), 0, SD_SELF)],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
        ],
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
    );
}

/// EIP test case, instruction level 3: `selfdestruct-to-self`, then
/// `selfdestruct-to-other`.
///
/// The clearest consequence of removing the burn: the balance the first SELFDESTRUCT used to
/// destroy is still there for the second one to pay out, so Amsterdam reports a refund where
/// Prague reported a withdrawal into nothing.
#[test]
fn selfdestruct_to_self_then_to_other() {
    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_SELF),
            op_call_selector(subject(), 0, SD_OTHER),
        ],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
        ],
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "beneficiary 0→1000 SuicideRefund",
        ],
    );
}

/// EIP test case, instruction level 4: `selfdestruct-to-other`, then
/// `selfdestruct-to-self`.
///
/// Unchanged by the fork: the first SELFDESTRUCT pays the beneficiary and the second finds
/// an empty account, so there is no burn to remove.
#[test]
fn selfdestruct_to_other_then_to_self() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
    ];

    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_OTHER),
            op_call_selector(subject(), 0, SD_SELF),
        ],
        ..Default::default()
    }
    .assert_balance_logs(&expected, &expected);
}

/// EIP test case, finalization 1: `selfdestruct-to-other`, then a CALL with value to the
/// self-destructed account.
///
/// Unchanged by the fork on the reporting side. What the fork changes is invisible here: the
/// 500 wei the account receives after its own destruction is burned at finalization before
/// Amsterdam and kept after it, and neither Geth nor reth has ever reported that burn.
#[test]
fn selfdestruct_to_other_then_call_with_value() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
        "factory 999000→998500 Transfer",
        "subject 0→500 Transfer",
    ];

    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_OTHER),
            op_call_selector(subject(), 500, RECEIVE),
        ],
        ..Default::default()
    }
    .assert_balance_logs(&expected, &expected);
}

/// EIP test case, finalization 2: `selfdestruct-to-other`, then several CALLs with value to
/// the self-destructed account.
#[test]
fn selfdestruct_to_other_then_multiple_calls_with_value() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
        "factory 999000→998500 Transfer",
        "subject 0→500 Transfer",
        "factory 998500→998200 Transfer",
        "subject 500→800 Transfer",
    ];

    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_OTHER),
            op_call_selector(subject(), 500, RECEIVE),
            op_call_selector(subject(), 300, RECEIVE),
        ],
        ..Default::default()
    }
    .assert_balance_logs(&expected, &expected);
}

/// EIP test case, finalization 3: `selfdestruct-to-other`, CALL with value, then
/// `selfdestruct-to-other` again.
///
/// The repeat SELFDESTRUCT pays out what arrived after the first one, on both sides of the
/// fork — an already-destroyed account is not a dead end for value.
#[test]
fn selfdestruct_to_other_then_call_with_value_then_to_other() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
        "factory 999000→998500 Transfer",
        "subject 0→500 Transfer",
        "subject 500→0 SuicideWithdraw",
        "beneficiary 1000→1500 SuicideRefund",
    ];

    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_OTHER),
            op_call_selector(subject(), 500, RECEIVE),
            op_call_selector(subject(), 0, SD_OTHER),
        ],
        ..Default::default()
    }
    .assert_balance_logs(&expected, &expected);
}

/// EIP test case, finalization 4: `selfdestruct-to-other`, CALL with value, then
/// `selfdestruct-to-self`.
///
/// The value that arrived after the first destruction is burned by the second SELFDESTRUCT
/// before Amsterdam and kept after it.
#[test]
fn selfdestruct_to_other_then_call_with_value_then_to_self() {
    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_OTHER),
            op_call_selector(subject(), 500, RECEIVE),
            op_call_selector(subject(), 0, SD_SELF),
        ],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "beneficiary 0→1000 SuicideRefund",
            "factory 999000→998500 Transfer",
            "subject 0→500 Transfer",
            "subject 500→0 SuicideWithdraw",
        ],
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "beneficiary 0→1000 SuicideRefund",
            "factory 999000→998500 Transfer",
            "subject 0→500 Transfer",
        ],
    );
}

/// EIP test case, finalization 5: `selfdestruct-to-self`, then a CALL with value to the
/// self-destructed account.
///
/// The `old_balance` of the incoming transfer is where the fork shows: at Amsterdam the
/// account still holds its endowment, so the CALL credits 1000 → 1500 rather than 0 → 500.
#[test]
fn selfdestruct_to_self_then_call_with_value() {
    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_SELF),
            op_call_selector(subject(), 500, RECEIVE),
        ],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "factory 999000→998500 Transfer",
            "subject 0→500 Transfer",
        ],
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "factory 999000→998500 Transfer",
            "subject 1000→1500 Transfer",
        ],
    );
}

/// EIP test case, finalization 6: `selfdestruct-to-self`, then several CALLs with value to
/// the self-destructed account.
#[test]
fn selfdestruct_to_self_then_multiple_calls_with_value() {
    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_SELF),
            op_call_selector(subject(), 500, RECEIVE),
            op_call_selector(subject(), 300, RECEIVE),
        ],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "factory 999000→998500 Transfer",
            "subject 0→500 Transfer",
            "factory 998500→998200 Transfer",
            "subject 500→800 Transfer",
        ],
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "factory 999000→998500 Transfer",
            "subject 1000→1500 Transfer",
            "factory 998500→998200 Transfer",
            "subject 1500→1800 Transfer",
        ],
    );
}

/// EIP test case, finalization 7: `selfdestruct-to-self`, CALL with value, then
/// `selfdestruct-to-other`.
///
/// The beneficiary collects the endowment as well as the later transfer at Amsterdam, and
/// only the later transfer before it.
#[test]
fn selfdestruct_to_self_then_call_with_value_then_to_other() {
    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_SELF),
            op_call_selector(subject(), 500, RECEIVE),
            op_call_selector(subject(), 0, SD_OTHER),
        ],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "factory 999000→998500 Transfer",
            "subject 0→500 Transfer",
            "subject 500→0 SuicideWithdraw",
            "beneficiary 0→500 SuicideRefund",
        ],
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "factory 999000→998500 Transfer",
            "subject 1000→1500 Transfer",
            "subject 1500→0 SuicideWithdraw",
            "beneficiary 0→1500 SuicideRefund",
        ],
    );
}

/// EIP test case, finalization 8: `selfdestruct-to-self`, CALL with value, then
/// `selfdestruct-to-self`.
///
/// Amsterdam reports no SELFDESTRUCT balance change at all: nothing ever leaves the account.
#[test]
fn selfdestruct_to_self_then_call_with_value_then_to_self() {
    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SD_SELF),
            op_call_selector(subject(), 500, RECEIVE),
            op_call_selector(subject(), 0, SD_SELF),
        ],
        ..Default::default()
    }
    .assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
            "factory 999000→998500 Transfer",
            "subject 0→500 Transfer",
            "subject 500→0 SuicideWithdraw",
        ],
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "factory 999000→998500 Transfer",
            "subject 1000→1500 Transfer",
        ],
    );
}

/// EIP test case, finalization 9: a created account raises its own nonce by creating other
/// accounts, then `selfdestruct-to-self`.
///
/// The nonce reset the EIP specifies is the pre-fork cleanup unchanged: the inspector
/// already reported `nonce → 0` for a destroyed account, and at Amsterdam the same event
/// describes an account that survives with a balance instead of one that disappears.
#[test]
fn nonce_bumped_then_selfdestruct_to_self() {
    let scenario = Scenario {
        ops: vec![
            op_call_selector(subject(), 0, BUMP_NONCE),
            op_call_selector(subject(), 0, SD_SELF),
        ],
        ..Default::default()
    };

    scenario.assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
        ],
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
    );

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block = scenario.run(spec);
        let cleanup: Vec<_> = state_change_log(&block, &scenario.labels())
            .into_iter()
            .filter(|line| line.starts_with("subject"))
            .collect();

        assert_eq!(
            cleanup,
            [
                "subject nonce 0→1",
                "subject code 0B→94B",
                "subject nonce 1→2",
                "subject nonce 2→3",
                "subject nonce 3→0",
                "subject code 94B→0B",
            ],
            "nonce and code cleanup at {spec:?}"
        );
    }
}

/// EIP test case, finalization 10: a created account raises its own nonce by creating other
/// accounts, then `selfdestruct-to-other`.
#[test]
fn nonce_bumped_then_selfdestruct_to_other() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
    ];

    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, BUMP_NONCE),
            op_call_selector(subject(), 0, SD_OTHER),
        ],
        ..Default::default()
    }
    .assert_balance_logs(&expected, &expected);
}

/// EIP test case, finalization 11: a created account writes storage, then
/// `selfdestruct-to-self`.
///
/// revm wipes the storage of a surviving balance-only account at finalization, and that wipe
/// is deliberately not reported: no event described it before the fork either, and the
/// Firehose protocol has no account-clearing event to carry it. A consumer learns the
/// account was cleared from the call's `suicide` marker, as it always has.
#[test]
fn storage_written_then_selfdestruct_to_self() {
    let scenario = Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SSTORE_SLOT),
            op_call_selector(subject(), 0, SD_SELF),
        ],
        ..Default::default()
    };

    scenario.assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
        ],
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
    );

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block = scenario.run(spec);
        let storage: Vec<_> = state_change_log(&block, &scenario.labels())
            .into_iter()
            .filter(|line| line.contains("storage"))
            .collect();

        assert_eq!(
            storage,
            ["subject storage 1: 0→1"],
            "only the SSTORE itself is reported at {spec:?}, not the finalization wipe"
        );
    }
}

/// EIP test case, finalization 12: a created account writes storage, then
/// `selfdestruct-to-other`.
#[test]
fn storage_written_then_selfdestruct_to_other() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
    ];

    Scenario {
        ops: vec![
            op_call_selector(subject(), 0, SSTORE_SLOT),
            op_call_selector(subject(), 0, SD_OTHER),
        ],
        ..Default::default()
    }
    .assert_balance_logs(&expected, &expected);
}

/// EIP test case, multi-transaction 1: two identical transactions, each CREATE2-ing the
/// same account with a non-zero balance and having it `selfdestruct-to-self`.
///
/// The second CREATE2 lands on the address again either way — before Amsterdam because the
/// account was deleted, at Amsterdam because what survives has nonce 0 and no code — but
/// the balance it starts from differs, and the endowment transfer says so.
#[test]
fn selfdestruct_to_self_repeated_in_a_second_transaction() {
    let scenario = Scenario {
        ops: vec![op_call_selector(subject(), 0, SD_SELF)],
        transactions: 2,
        ..Default::default()
    };
    let labels = scenario.labels();

    let prague: Vec<Vec<String>> = scenario
        .run(SpecId::PRAGUE)
        .transaction_traces
        .iter()
        .map(|trx| balance_change_log_of(trx, &labels))
        .collect();
    assert_eq!(
        prague,
        [
            vec![
                "factory 1000000→999000 Transfer".to_string(),
                "subject 0→1000 Transfer".to_string(),
                "subject 1000→0 SuicideWithdraw".to_string(),
            ],
            vec![
                "factory 999000→998000 Transfer".to_string(),
                "subject 0→1000 Transfer".to_string(),
                "subject 1000→0 SuicideWithdraw".to_string(),
            ],
        ]
    );

    let amsterdam: Vec<Vec<String>> = scenario
        .run(SpecId::AMSTERDAM)
        .transaction_traces
        .iter()
        .map(|trx| balance_change_log_of(trx, &labels))
        .collect();
    assert_eq!(
        amsterdam,
        [
            vec![
                "factory 1000000→999000 Transfer".to_string(),
                "subject 0→1000 Transfer".to_string(),
            ],
            vec![
                "factory 999000→998000 Transfer".to_string(),
                // The endowment lands on the balance the first transaction left behind.
                "subject 1000→2000 Transfer".to_string(),
            ],
        ]
    );
}

/// `SELFDESTRUCT` in initcode with the account under construction as beneficiary: no code is
/// ever deployed, so the only cleanup is the nonce.
#[test]
fn selfdestruct_to_self_in_initcode() {
    let scenario =
        Scenario { initcode: op_selfdestruct_self(), ops: Vec::new(), ..Default::default() };

    scenario.assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            "subject 1000→0 SuicideWithdraw",
        ],
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
    );
}

/// `SELFDESTRUCT` in initcode to another account: unchanged by the fork, the endowment is
/// forwarded rather than burned in both cases.
#[test]
fn selfdestruct_to_other_in_initcode() {
    let expected = [
        "factory 1000000→999000 Transfer",
        "subject 0→1000 Transfer",
        "subject 1000→0 SuicideWithdraw",
        "beneficiary 0→1000 SuicideRefund",
    ];

    Scenario { initcode: op_selfdestruct_to(BENEFICIARY), ops: Vec::new(), ..Default::default() }
        .assert_balance_logs(&expected, &expected);
}

/// A zero-balance `selfdestruct-to-self` reports nothing on either side of the fork: there
/// is no burn to remove, and EIP-161 deletes the empty account at Amsterdam just as before.
#[test]
fn zero_balance_selfdestruct_to_self() {
    Scenario {
        endowment: 0,
        ops: vec![op_call_selector(subject(), 0, SD_SELF)],
        ..Default::default()
    }
    .assert_balance_logs(&[], &[]);
}

/// A `SELFDESTRUCT` that runs out of gas destroys nothing: no balance change, no nonce/code
/// cleanup, and the call is not marked as self-destructed.
///
/// revm mutates the journal inside `Journal::selfdestruct` and charges the dynamic cost
/// afterwards, so the `AccountDestroyed` entry is already written when the instruction halts
/// on gas. Geth charges before running the opcode body, so its tracer never sees a suicide
/// here; the inspector matches that by reporting the opcode as failed for every instruction
/// result other than `SelfDestruct`.
#[test]
fn out_of_gas_selfdestruct_reports_nothing() {
    let scenario = Scenario {
        ops: vec![op_call_selector_with_gas(subject(), 0, SD_SELF, 100)],
        ..Default::default()
    };

    scenario.assert_balance_logs(
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
    );

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block = scenario.run(spec);
        let labels = scenario.labels();

        assert!(
            !state_change_log(&block, &labels).iter().any(|line| line.contains("nonce 1→0")),
            "nothing was destroyed at {spec:?}, so no finalization cleanup is reported"
        );
        assert!(
            suicided_calls(&block, &labels).is_empty(),
            "the SELFDESTRUCT never took effect at {spec:?}, so no call is a suicide"
        );
    }
}

/// A `SELFDESTRUCT` inside a frame that later reverts destroys nothing: revm rolls the
/// journal entry back, the balance change the inspector emitted stays flagged as reverted,
/// and no finalization cleanup follows.
///
/// The cleanup is the part worth pinning. `selfdestruct_addresses` is filled when the opcode
/// runs and revm truncates the journal entry without telling the inspector, so the set still
/// holds an account that kept its nonce and code; `capture_selfdestruct_cleanup` drops it by
/// checking the committed journal. Geth's journal reverts its own self-destruct set.
#[test]
fn reverted_selfdestruct_reports_no_cleanup() {
    let scenario = Scenario {
        ops: vec![op_call_selector(REVERTER, 0, RECEIVE)],
        extra_accounts: vec![(
            REVERTER,
            code_account(&[op_call_selector(subject(), 0, SD_SELF), op_revert()].concat(), 0),
        )],
        ..Default::default()
    };

    scenario.assert_balance_logs(
        &[
            "factory 1000000→999000 Transfer",
            "subject 0→1000 Transfer",
            // Reported, but flagged: the frame it belongs to reverted.
            "[reverted] subject 1000→0 SuicideWithdraw",
        ],
        &["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
    );

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block = scenario.run(spec);
        let cleanup: Vec<_> = state_change_log(&block, &scenario.labels())
            .into_iter()
            .filter(|line| line.starts_with("subject nonce") || line.starts_with("subject code"))
            .collect();

        assert_eq!(
            cleanup,
            ["subject nonce 0→1", "subject code 0B→94B"],
            "the account survived the revert at {spec:?}, so only its creation is reported"
        );
    }
}

/// The same rollback one frame up: the root call itself reverts after a nested
/// `SELFDESTRUCT` committed. The filter has to hold here too, because `call_end` at depth 0
/// is where the cleanup is captured — if revm had not truncated the journal by then, a
/// whole-transaction revert would still report the account as cleared.
#[test]
fn root_reverted_selfdestruct_reports_no_cleanup() {
    let scenario = Scenario {
        ops: vec![op_call_selector(subject(), 0, SD_SELF), op_revert()],
        ..Default::default()
    };

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block = scenario.run(spec);
        let balances = balance_change_log(&block, &scenario.labels());
        assert!(
            balances.iter().all(|line| line.starts_with("[reverted]")),
            "every change belongs to the reverted root call at {spec:?}: {balances:?}"
        );
        let state = state_change_log(&block, &scenario.labels());
        assert!(
            !state.iter().any(|line| line.contains("nonce 1→0")),
            "no finalization cleanup at {spec:?}: {state:?}"
        );
    }
}
