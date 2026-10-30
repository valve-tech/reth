//! SELFDESTRUCT: the `suicide` flag on the call that executed it, and the balance and state
//! events EIP-8246 changes.

use super::{scenario::*, support::*};
use crate::inspector::*;
use evm2::SpecId;
use firehose_tracer::pb;

/// Contract that self-destructs, its code being `code`.
const SELFDESTRUCT_CONTRACT: Address = Address::repeat_byte(0xdd);

/// Runs one transaction calling [`SELFDESTRUCT_CONTRACT`] holding `code` and returns its root
/// call.
fn lone_selfdestruct_call(code: &[u8]) -> pb::sf::ethereum::r#type::v2::Call {
    let block = drive_tx(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(1_000_000)), (SELFDESTRUCT_CONTRACT, code_account(code, 0))],
        SELFDESTRUCT_CONTRACT,
        0,
    );
    block.transaction_traces[0].calls.first().expect("one call").clone()
}

#[test]
fn executed_selfdestruct_marks_call_as_suicide() {
    // PUSH0 SELFDESTRUCT: self-destruct to the zero address.
    let call = lone_selfdestruct_call(&[0x5f, 0xff]);

    assert!(call.suicide, "an executed SELFDESTRUCT must mark the call as self-destructed");
    assert!(!call.status_failed, "an executed SELFDESTRUCT succeeds");
}

/// A SELFDESTRUCT that halts the frame without self-destructing, as an undefined instruction
/// does on a chain that replaced it, must not mark the call as a suicide. A lone `0xff` byte
/// halts on its empty stack before destroying anything.
#[test]
fn halted_selfdestruct_does_not_mark_call_as_suicide() {
    let call = lone_selfdestruct_call(&[0xff]);

    assert!(!call.suicide, "a halted SELFDESTRUCT must not mark the call as self-destructed");
    assert!(call.status_failed, "a frame halting on SELFDESTRUCT fails");
}

// ---- EIP-8246 SELFDESTRUCT burn removal ----------------------------------------------
//
// [EIP-8246] stops `SELFDESTRUCT` from burning ETH: a self-beneficiary `SELFDESTRUCT`
// leaves the balance on the account, and at transaction finalization a self-destructed
// account that still holds a balance keeps it, losing only its nonce, code and storage.
//
// evm2 implements the rule; what the tests below pin is the Firehose side:
// which balance changes the inspector reports on each side of the fork. Every case from the
// EIP's own test-case list is driven at `PRAGUE` and at `AMSTERDAM` from the same scenario,
// so a difference in the reported events is attributable to the fork and nothing else.
//
// No new event kind is introduced. In particular the storage that evm2 wipes at
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
/// evm2 wipes the storage of a surviving balance-only account at finalization, and that wipe
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
/// evm2 applies the SELFDESTRUCT to the state and charges the dynamic cost afterwards, so the
/// account is already marked destroyed in the journal when the instruction halts
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

/// A `SELFDESTRUCT` inside a frame that later reverts destroys nothing: evm2 rolls the
/// journal entry back, the balance change the inspector emitted stays flagged as reverted,
/// and no finalization cleanup follows.
///
/// The cleanup is the part worth pinning. `selfdestruct_candidates` is filled when the opcode
/// runs and evm2 rolls the destruction back without telling the inspector, so the set still
/// holds an account that kept its nonce and code; `capture_selfdestruct_cleanup` drops it by
/// checking whether the account is still destroyed. Geth's journal reverts its own
/// self-destruct set.
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
/// is where the cleanup is captured — if evm2 had not rolled the destruction back by then, a
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
