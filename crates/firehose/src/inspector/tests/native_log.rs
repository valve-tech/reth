//! EIP-7708 native ETH transfer logs: which call frame each one attaches to, and how they
//! order against the balance changes they describe.

use super::support::*;
use crate::inspector::*;
use evm2::SpecId;
use firehose_tracer::pb;

/// `SYSTEM_ADDRESS`, the emitter evm2 stamps on every [EIP-7708] log.
///
/// [EIP-7708]: https://eips.ethereum.org/EIPS/eip-7708
const NATIVE_LOG_ADDRESS: Address = Address::new([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
]);

const CONTRACT_A: Address = Address::repeat_byte(0xa1);
const CONTRACT_B: Address = Address::repeat_byte(0xb1);

/// The `identity` precompile, used as a stand-in for any real mainnet precompile — as
/// opposed to [`PRECOMPILE`], a made-up address the precompile tests install a custom
/// precompile at.
const IDENTITY_PRECOMPILE: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);

/// `keccak256("Transfer(address,address,uint256)")`, pinned rather than imported: consumers
/// index native transfers off this exact topic, so a change upstream must break a test here.
fn native_transfer_topic() -> B256 {
    B256::from(alloy_primitives::hex!(
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    ))
}

/// Asserts a captured log is the EIP-7708 transfer log for `from -> to` of `value`.
fn assert_native_transfer(
    log: &pb::sf::ethereum::r#type::v2::Log,
    from: Address,
    to: Address,
    value: u64,
) {
    assert_eq!(log.address, NATIVE_LOG_ADDRESS.to_vec(), "emitter must be SYSTEM_ADDRESS");
    assert_eq!(
        log.topics,
        vec![
            native_transfer_topic().to_vec(),
            B256::left_padding_from(from.as_slice()).to_vec(),
            B256::left_padding_from(to.as_slice()).to_vec(),
        ]
    );
    assert_eq!(log.data, U256::from(value).to_be_bytes::<32>().to_vec());
}

/// A plain value transfer between two EOAs produces one call, and the EIP-7708 log lands
/// on it. There is no other frame it could belong to.
#[test]
fn native_transfer_log_attaches_to_root_call() {
    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (RECIPIENT, balance_account(0))],
        RECIPIENT,
        1_000,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert_eq!(trx.calls.len(), 1, "a value transfer to an EOA is a single call");

    let call = &trx.calls[0];
    assert_eq!(call.logs.len(), 1);
    assert_native_transfer(&call.logs[0], SENDER, RECIPIENT, 1_000);
}

/// The log belongs to the callee, not the caller: evm2 appends it after taking the callee's
/// checkpoint, so that is the frame it reverts with. Here the root call moves no value and
/// must stay empty while the inner call carries the transfer.
#[test]
fn native_transfer_log_attaches_to_callee_not_caller() {
    let a = code_account(&op_call_with_value(RECIPIENT, 1_000), 10_000);
    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a), (RECIPIENT, balance_account(0))],
        CONTRACT_A,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert_eq!(trx.calls.len(), 2, "root call plus the inner value call");

    assert!(trx.calls[0].logs.is_empty(), "the caller frame transfers nothing");
    assert_eq!(trx.calls[1].logs.len(), 1);
    assert_native_transfer(&trx.calls[1].logs[0], CONTRACT_A, RECIPIENT, 1_000);
}

/// A native transfer log and an opcode log in the same frame both land on it, in emission
/// order: the transfer log, appended before the frame's first opcode, takes block index 0 and
/// the `LOG0` after it index 1. Missing either leaves the call tree one log short of the
/// receipt.
#[test]
fn native_transfer_log_survives_an_opcode_log_in_the_same_frame() {
    let a = code_account(&op_log0(), 0);
    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a)],
        CONTRACT_A,
        1_000,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("the root call");

    assert_eq!(call.logs.len(), 2, "the native transfer log and the LOG0");
    assert_native_transfer(&call.logs[0], SENDER, CONTRACT_A, 1_000);
    assert_eq!(call.logs[0].block_index, 0, "the transfer log precedes EVM-emitted logs");
    assert_eq!(call.logs[1].address, CONTRACT_A.to_vec());
    assert_eq!(call.logs[1].block_index, 1);
}

/// The native transfer log must take an ordinal AFTER the balance changes for the very
/// transfer it describes. evm2 calls the inspector's `log` hook before the frame's first
/// opcode, ahead of the hook that would otherwise report the transfer, so the hook flushes the
/// journal first: forwarding the log straight away would announce the transfer ahead of the
/// money moving. A consumer replaying the call by ordinal would see the event before its
/// effect.
#[test]
fn native_transfer_log_is_ordered_after_its_balance_changes() {
    // A contract target, so the frame executes opcodes and the transfer balance changes are
    // not left for the frame's exit to report.
    let a = code_account(&op_log0(), 0);
    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a)],
        CONTRACT_A,
        1_000,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("the root call");

    let transfer_ordinals: Vec<u64> = call
        .balance_changes
        .iter()
        .filter(|change| change.reason == Reason::Transfer as i32)
        .map(|change| change.ordinal)
        .collect();
    assert_eq!(transfer_ordinals.len(), 2, "sender debit and recipient credit");

    let native_log = &call.logs[0];
    assert_native_transfer(native_log, SENDER, CONTRACT_A, 1_000);

    for ordinal in transfer_ordinals {
        assert!(
            ordinal < native_log.ordinal,
            "balance change at ordinal {ordinal} must precede the native transfer log at \
             ordinal {}",
            native_log.ordinal,
        );
    }
}

/// An outer frame's log must not be parked on whichever inner frame exits first. The tracer drops
/// the logs of reverted calls, so a log that actually survived would vanish from the call tree
/// while staying in the receipt.
///
/// Here the root call receives value (log survives) and then calls a reverting contract
/// with value (log reverts with it). The two must end up on different frames.
#[test]
fn native_transfer_log_is_not_parked_on_a_reverting_inner_call() {
    // CONTRACT_A forwards value to CONTRACT_B, which reverts immediately.
    let a = code_account(&op_call_with_value(CONTRACT_B, 500), 0);
    let revert = {
        let mut code = Vec::new();
        code.extend(push(&[0])); // size
        code.extend(push(&[0])); // offset
        code.push(0xfd); // REVERT
        code
    };
    let b = code_account(&revert, 0);

    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a), (CONTRACT_B, b)],
        CONTRACT_A,
        1_000,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert_eq!(trx.calls.len(), 2, "root call plus the reverting inner call");

    assert_eq!(trx.calls[0].logs.len(), 1, "the incoming transfer survives on the root call");
    assert_native_transfer(&trx.calls[0].logs[0], SENDER, CONTRACT_A, 1_000);

    assert!(trx.calls[1].state_reverted, "the inner call reverted");
    assert_eq!(
        trx.calls[1].logs.len(),
        1,
        "the reverted frame still records the log it produced; the tracer filters it out \
         because the call is marked reverted"
    );
}

/// `SELFDESTRUCT` is the one case where the log is emitter-side: the beneficiary has no
/// frame of its own, so it attaches to the destructing call.
#[test]
fn native_transfer_log_on_selfdestruct_attaches_to_the_destructing_call() {
    let mut code = Vec::new();
    code.extend(push(RECIPIENT.as_slice()));
    code.push(0xff); // SELFDESTRUCT
    let a = code_account(&code, 750);

    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a), (RECIPIENT, balance_account(0))],
        CONTRACT_A,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("the root call");

    assert_eq!(call.logs.len(), 1);
    assert_native_transfer(&call.logs[0], CONTRACT_A, RECIPIENT, 750);
}

/// Geth's SELFDESTRUCT emits its EIP-7708 transfer log before moving the balance, the reverse of
/// a call's value transfer.
#[test]
fn native_transfer_log_on_selfdestruct_precedes_its_balance_changes() {
    let mut code = Vec::new();
    code.extend(push(RECIPIENT.as_slice()));
    code.push(0xff); // SELFDESTRUCT
    let a = code_account(&code, 750);

    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a), (RECIPIENT, balance_account(0))],
        CONTRACT_A,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("the root call");
    let native_log = &call.logs[0];
    assert_native_transfer(native_log, CONTRACT_A, RECIPIENT, 750);

    let suicide_ordinals: Vec<u64> = call
        .balance_changes
        .iter()
        .filter(|change| {
            change.reason == Reason::SuicideWithdraw as i32 ||
                change.reason == Reason::SuicideRefund as i32
        })
        .map(|change| change.ordinal)
        .collect();
    assert_eq!(suicide_ordinals.len(), 2, "contract withdraw and beneficiary refund");
    for ordinal in suicide_ordinals {
        assert!(
            native_log.ordinal < ordinal,
            "native transfer log at ordinal {} must precede the balance change at ordinal \
             {ordinal}",
            native_log.ordinal,
        );
    }
}

/// CREATE with value and non-empty initcode: the endowment log is emitted with no opcode
/// behind it (same as any value transfer), and the frame that follows executes at least one
/// opcode (the initcode's `STOP`), so this covers a CREATE frame that runs code rather than
/// the zero-opcode one the empty-initcode case below covers.
#[test]
fn native_transfer_log_on_create_attaches_to_the_create_call() {
    let value = 1_000u64;
    let (store, offset, size) = op_store_initcode(&[0x00]); // initcode: STOP
    let mut code = store;
    code.extend(op_create(value, offset, size));
    let a = code_account(&code, 10_000);

    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a)],
        CONTRACT_A,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert_eq!(trx.calls.len(), 2, "root call plus the CREATE");

    assert!(trx.calls[0].logs.is_empty(), "the root call transfers no value itself");
    let create_call = &trx.calls[1];
    assert_eq!(create_call.logs.len(), 1);
    let created = Address::from_slice(&create_call.address);
    assert_native_transfer(&create_call.logs[0], CONTRACT_A, created, value);
}

/// Same as the CREATE case above, but for CREATE2 — its created address is derived
/// differently (salt + init code hash rather than caller nonce), so this pins that the log
/// still attaches to the CREATE2 frame regardless of how the address was computed.
#[test]
fn native_transfer_log_on_create2_attaches_to_the_create_call() {
    let value = 1_000u64;
    let (store, offset, size) = op_store_initcode(&[0x00]); // initcode: STOP
    let mut code = store;
    code.extend(op_create2(value, offset, size, 0x07));
    let a = code_account(&code, 10_000);

    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT_A, a)],
        CONTRACT_A,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert_eq!(trx.calls.len(), 2, "root call plus the CREATE2");

    assert!(trx.calls[0].logs.is_empty(), "the root call transfers no value itself");
    let create_call = &trx.calls[1];
    assert_eq!(create_call.logs.len(), 1);
    let created = Address::from_slice(&create_call.address);
    assert_native_transfer(&create_call.logs[0], CONTRACT_A, created, value);
}

/// A root CREATE with value and empty init code: the endowment log is the only log of the
/// transaction and there is no outer frame to pick it up, so it must land on the CREATE call
/// itself, whether or not the frame runs an opcode.
#[test]
fn native_transfer_log_on_empty_initcode_create_attaches_to_the_create_call() {
    let block = drive_txs(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000))],
        &[DriveTx::create(Bytes::new()).with_value(1_000)],
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("the root CREATE call");
    assert_eq!(
        call.call_type,
        pb::sf::ethereum::r#type::v2::CallType::Create as i32,
        "root call is the CREATE"
    );

    assert_eq!(call.logs.len(), 1);
    assert_native_transfer(&call.logs[0], SENDER, SENDER.create(0), 1_000);
}

/// A CALL with value to a real precompile (`identity`, address `0x…04`) is still a no-code
/// target from the EVM's perspective — no opcode ever runs in that frame — so this pins that
/// the precompile call gets the same log attachment as any other no-code callee, not the root
/// that dispatched it.
#[test]
fn native_transfer_log_to_precompile_attaches_to_the_precompile_call() {
    let a = code_account(&op_call_with_value(IDENTITY_PRECOMPILE, 1_000), 10_000);
    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[
            (SENDER, balance_account(1_000_000)),
            (CONTRACT_A, a),
            (IDENTITY_PRECOMPILE, balance_account(0)),
        ],
        CONTRACT_A,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert_eq!(trx.calls.len(), 2, "root call plus the precompile call");

    assert!(trx.calls[0].logs.is_empty(), "the root call transfers no value itself");
    assert_eq!(trx.calls[1].logs.len(), 1);
    assert_native_transfer(&trx.calls[1].logs[0], CONTRACT_A, IDENTITY_PRECOMPILE, 1_000);
}

/// Two transactions in one block: the inspector is shared across both (as it is in
/// production), so the second tx's native log must carry a `block_index` continuing after
/// the first tx's, not restart at 0.
#[test]
fn native_transfer_log_second_tx_continues_block_index() {
    let block = drive_txs(
        SpecId::AMSTERDAM,
        &[
            (SENDER, balance_account(1_000_000)),
            (CONTRACT_A, balance_account(0)),
            (CONTRACT_B, balance_account(0)),
        ],
        &[DriveTx::call(CONTRACT_A, 1_000), DriveTx::call(CONTRACT_B, 2_000)],
    );

    assert_eq!(block.transaction_traces.len(), 2, "two transactions in the block");

    let first = block.transaction_traces[0].calls.first().expect("first tx's root call");
    assert_eq!(first.logs.len(), 1);
    assert_native_transfer(&first.logs[0], SENDER, CONTRACT_A, 1_000);
    assert_eq!(first.logs[0].block_index, 0);

    let second = block.transaction_traces[1].calls.first().expect("second tx's root call");
    assert_eq!(second.logs.len(), 1);
    assert_native_transfer(&second.logs[0], SENDER, CONTRACT_B, 2_000);
    assert_eq!(
        second.logs[0].block_index, 1,
        "block index must continue after the first tx's logs, not restart at 0"
    );
}

/// A zero-value call must not produce a log: evm2 short-circuits on a zero value, and a
/// spurious entry here would desync every log index in the block.
#[test]
fn zero_value_transfer_emits_no_native_log() {
    let block = drive_tx(
        SpecId::AMSTERDAM,
        &[(SENDER, balance_account(1_000_000)), (RECIPIENT, balance_account(0))],
        RECIPIENT,
        0,
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    assert!(trx.calls.iter().all(|call| call.logs.is_empty()));
}

/// The fork gate: the exact transfer that produces a native log at Amsterdam must produce
/// none at Prague. Pins that the inspector reports the logs evm2 emits rather than synthesising
/// logs of its own, so pre-Amsterdam chains keep byte-identical Firehose output.
#[test]
fn value_transfer_emits_no_native_log_before_amsterdam() {
    let accounts = [(SENDER, balance_account(1_000_000)), (RECIPIENT, balance_account(0))];

    let prague = drive_tx(SpecId::PRAGUE, &accounts, RECIPIENT, 1_000);
    let trx = prague.transaction_traces.first().expect("one transaction");
    assert!(
        trx.calls.iter().all(|call| call.logs.is_empty()),
        "EIP-7708 is not active before Amsterdam"
    );

    // Same transfer one fork later, to show the assertion above is about the fork and not
    // about the transfer being unremarkable.
    let amsterdam = drive_tx(SpecId::AMSTERDAM, &accounts, RECIPIENT, 1_000);
    let trx = amsterdam.transaction_traces.first().expect("one transaction");
    let logs: Vec<_> = trx.calls.iter().flat_map(|call| call.logs.iter()).collect();
    assert_eq!(logs.len(), 1);
    assert_native_transfer(logs[0], SENDER, RECIPIENT, 1_000);
}
