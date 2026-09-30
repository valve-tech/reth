//! Transactions and frames that run out of gas right at a boundary: a frame that starts with
//! no gas at all, and value transfers whose frame is starved before it can finish. Each is
//! driven through a real revm transaction so the gas figures are the ones the EVM produces,
//! not ones the fixture asserts about itself.

use super::support::*;
use crate::inspector::*;
use reth_revm::revm::primitives::hardfork::SpecId;

type Reason = pb::sf::ethereum::r#type::v2::balance_change::Reason;

/// Contract that runs `to.transfer(1)` the way Solidity compiles it: `CALL` with a zero gas
/// argument (the 2300 stipend is added by the EVM because value is non-zero), reverting when
/// the call reports failure.
fn transfer_or_revert(to: Address) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(&[0])); // retLength
    code.extend(push(&[0])); // retOffset
    code.extend(push(&[0])); // argsLength
    code.extend(push(&[0])); // argsOffset
    code.extend(push(&[1])); // value
    code.extend(push(to.as_slice())); // address
    code.extend(push(&[0])); // gas: none, so only the stipend
    code.push(0xf1); // CALL
    code.push(0x15); // ISZERO
                     // Jump target is right after `PUSH1 <dest>`, `JUMPI`, `STOP`.
    let revert_dest = code.len() + 2 + 1 + 1;
    code.extend(push(&[revert_dest as u8]));
    code.push(0x57); // JUMPI
    code.push(0x00); // STOP
    code.push(0x5b); // JUMPDEST
    code.extend(push(&[0]));
    code.extend(push(&[0]));
    code.push(0xfd); // REVERT
    code
}

fn transfers(
    call: &pb::sf::ethereum::r#type::v2::Call,
) -> Vec<&pb::sf::ethereum::r#type::v2::BalanceChange> {
    call.balance_changes.iter().filter(|b| b.reason == Reason::Transfer as i32).collect()
}

/// A value-transferring CALL whose callee is handed only the 2300 stipend and burns all of
/// it: the callee frame is entered (`executed_code`) and reports its whole gas limit as
/// consumed, the caller reverts, and the attempted transfer still shows up as a debit and a
/// credit even though revm rolled the journal back.
#[test]
fn starved_value_call_consumes_all_its_gas_and_keeps_transfer_changes() {
    const CALLER_CONTRACT: Address = Address::repeat_byte(0xdd);
    // JUMPDEST, PUSH0, JUMP: spins until the gas is gone.
    const BURN_GAS: &[u8] = &[0x5b, 0x5f, 0x56];
    const STIPEND: u64 = 2300;

    let accounts = [
        (SENDER, balance_account(u64::MAX)),
        (CALLER_CONTRACT, code_account(&transfer_or_revert(RECIPIENT), 1_000)),
        (RECIPIENT, code_account(BURN_GAS, 0)),
    ];

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block =
            drive_txs(spec, &accounts, &[DriveTx::call(CALLER_CONTRACT, 0).with_gas(100_000)]);
        let trx = block.transaction_traces.first().expect("one transaction");
        assert_eq!(trx.calls.len(), 2, "{spec:?}: root call plus the starved inner call");

        let root = &trx.calls[0];
        assert!(root.status_failed, "{spec:?}: the contract reverts when its transfer fails");

        let inner = &trx.calls[1];
        assert_eq!(inner.address, RECIPIENT.to_vec());
        assert!(inner.executed_code, "{spec:?}: the callee frame was entered and ran code");
        assert!(inner.status_failed, "{spec:?}: the callee ran out of gas");
        assert_eq!(inner.gas_limit, STIPEND);
        assert_eq!(
            inner.gas_consumed, inner.gas_limit,
            "{spec:?}: a frame that runs out of gas spends it all"
        );

        let changes = transfers(inner);
        assert_eq!(changes.len(), 2, "{spec:?}: attempted transfer must keep debit and credit");
        assert_eq!(changes[0].address, CALLER_CONTRACT.to_vec(), "first change is the debit");
        assert_eq!(changes[1].address, RECIPIENT.to_vec(), "second change is the credit");
    }
}

/// Base cost of a contract-creation transaction before any calldata.
const TX_BASE_GAS: u64 = 21_000;
/// Extra intrinsic cost of a creation transaction (EIP-2).
const TX_CREATE_GAS: u64 = 32_000;

/// Intrinsic gas of a creation transaction under Prague (Amsterdam prices creation
/// differently, so this floor does not carry over): base, creation surcharge, calldata
/// (4 gas per zero byte, 16 per non-zero) and EIP-3860's 2 gas per init code word. Written out
/// by hand so it is an independent check on what revm charges rather than a call into it.
fn create_intrinsic_gas(initcode: &[u8]) -> u64 {
    let zeros = initcode.iter().filter(|b| **b == 0).count() as u64;
    let non_zeros = initcode.len() as u64 - zeros;
    TX_BASE_GAS +
        TX_CREATE_GAS +
        zeros * 4 +
        non_zeros * 16 +
        2 * (initcode.len() as u64).div_ceil(32)
}

/// A creation transaction (Prague only) sent with exactly its intrinsic gas: the transaction is
/// accepted, but the root `CREATE` frame starts with no gas, never runs a single constructor
/// opcode, and reports a zero gas limit and zero gas consumed.
#[test]
fn create_at_intrinsic_gas_floor_gets_a_zero_gas_frame() {
    // PUSH1 0, PUSH1 0, RETURN: a constructor that would deploy empty code if it ever ran.
    let initcode = [0x60, 0x00, 0x60, 0x00, 0xf3];
    let gas_limit = create_intrinsic_gas(&initcode);
    assert_eq!(gas_limit, 53_058, "hand-computed floor for this init code");

    let accounts = [(SENDER, balance_account(u64::MAX))];
    let tx = DriveTx::create(initcode.to_vec()).with_gas(gas_limit);
    let block = drive_txs(SpecId::PRAGUE, &accounts, &[tx]);

    let trx = block.transaction_traces.first().expect("the transaction is included");
    assert_eq!(trx.gas_used, gas_limit, "the whole intrinsic floor is charged");
    assert_eq!(
        trx.status,
        pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Failed as i32,
        "no gas left for the constructor"
    );

    let root = trx.calls.first().expect("a root call");
    assert_eq!(
        root.call_type,
        pb::sf::ethereum::r#type::v2::CallType::Create as i32,
        "root call is the CREATE"
    );
    assert!(root.status_failed);
    assert_eq!(root.gas_limit, 0, "nothing is left after the intrinsic floor");
    assert_eq!(root.gas_consumed, 0, "the constructor never ran an opcode");
}

/// Hoodi block 3171397: value sent straight to a precompile that is then starved of gas.
/// The frame fails, revm rolls the transfer back, and geth still reports the debit and the
/// credit — so must we. Unlike the hook-level test in [`super::precompile`], this runs a real
/// transaction: a MODEXP call carries a minimum cost above the gas left after the 21000
/// intrinsic, so the precompile itself runs out of gas.
#[test]
fn value_sent_to_starved_precompile_keeps_transfer_changes() {
    const MODEXP: Address =
        Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
    // Well below MODEXP's minimum charge, whichever fork's pricing applies.
    const HEADROOM: u64 = 100;

    // The precompile already holds a balance, as on a live chain. Sending value to a missing
    // account would, from Amsterdam on, price EIP-8037 new-account state gas into the
    // intrinsic cost and the 100 gas of headroom below would no longer be enough to get in.
    let accounts = [(SENDER, balance_account(u64::MAX)), (MODEXP, balance_account(1))];

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block = drive_txs(
            spec,
            &accounts,
            &[DriveTx::call(MODEXP, 1_000).with_gas(TX_BASE_GAS + HEADROOM)],
        );
        let trx = block.transaction_traces.first().expect("the transaction is included");

        let root = trx.calls.first().expect("a root call");
        assert_eq!(root.address, MODEXP.to_vec());
        assert!(root.state_reverted, "{spec:?}: the precompile ran out of gas");
        assert!(root.status_failed);

        let changes = transfers(root);
        assert_eq!(changes.len(), 2, "{spec:?}: reverted transfer must keep debit and credit");
        assert_eq!(changes[0].address, SENDER.to_vec(), "first change is the sender debit");
        assert_eq!(changes[1].address, MODEXP.to_vec(), "second change is the precompile credit");
    }
}

/// Regression for Sepolia block 8784485 (tx 0x1af75e60…), which made the Firehose-instrumented
/// node panic with a Rust "capacity overflow" while tracing a call that burns its entire gas
/// limit and reverts out of gas.
///
/// Reproduced the way the block came about: deploy the exact runtime with `slot0` (its
/// `owner`) set to the deployer — otherwise the `onlyOwner` guard on `0xb757c638` reverts
/// cheaply with `Unauthorized()` and never reaches the out-of-gas path — then call it from that
/// deployer with the original calldata and gas limit.
#[test]
fn out_of_gas_revert_of_sepolia_8784485_traces_without_panicking() {
    const CALL_GAS_LIMIT: u64 = 20_979_492;

    let initcode = alloy_primitives::hex::decode(
        include_str!("fixtures/capacity_overflow_initcode.hex").trim(),
    )
    .expect("init code is hex");
    let calldata = alloy_primitives::hex::decode(
        include_str!("fixtures/capacity_overflow_calldata.hex").trim(),
    )
    .expect("calldata is hex");

    // The deployer sends the deployment at nonce 0, so the contract lands at this address.
    let contract = SENDER.create(0);
    let accounts = [(SENDER, balance_account(u64::MAX))];
    let txs = [
        DriveTx::create(initcode).with_gas(5_000_000),
        DriveTx::call(contract, 0).with_input(calldata).with_gas(CALL_GAS_LIMIT),
    ];

    let block = drive_txs(SpecId::PRAGUE, &accounts, &txs);

    let [deploy, call] = block.transaction_traces.as_slice() else {
        panic!(
            "expected the deployment and the call, got {} traces",
            block.transaction_traces.len()
        );
    };
    assert_eq!(
        deploy.status,
        pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Succeeded as i32,
        "the deployment must succeed for the caller to be the owner"
    );

    let root = call.calls.first().expect("a root call");
    assert_eq!(root.address, contract.to_vec());
    assert!(root.status_failed);
    assert!(
        root.failure_reason.contains("out of gas"),
        "expected an out-of-gas failure, got {:?}",
        root.failure_reason
    );
    assert_eq!(root.gas_consumed, root.gas_limit, "the call burns all of its gas");
}
