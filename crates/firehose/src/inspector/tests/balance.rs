//! Transaction-level accounting: the sender nonce bump of the pre-execution changes, the
//! balances the post-transaction gas refund and fee reward start from, and the one-shot root
//! balance reason override.

use super::{scenario::*, support::*};
use crate::{inspector::*, PreTxAdjust};
use alloy_eips::eip7702::SignedAuthorization;
use alloy_rlp::Decodable;
use evm2::{ethereum::LazyAuthorization, SpecId};
use firehose_tracer::pb;

/// Block beneficiary of the priced transactions below.
const COINBASE: Address = Address::repeat_byte(0xcb);

/// Gas price of the priced transactions below. The block's base fee is zero, so the coinbase is
/// credited all of it.
const GAS_PRICE: u128 = 10;

/// Gas limit of the priced transactions below.
const GAS_LIMIT: u64 = 100_000;

const SENDER_BALANCE: u64 = 1_000_000_000;

/// Address of private key `0x…01`, the signer of [`SELF_AUTHORIZATIONS`].
const AUTHORITY: Address = alloy_primitives::address!("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");

/// Contract [`SELF_AUTHORIZATIONS`] delegate [`AUTHORITY`] to.
const DELEGATE: Address = Address::repeat_byte(0xde);

/// RLP of [`AUTHORITY`]'s authorizations delegating to [`DELEGATE`] on chain 1, at nonces 1, 2
/// and 3: the nonces a transaction [`AUTHORITY`] sends at nonce 0 finds when it processes them.
/// Generated with `cast wallet sign-auth <DELEGATE> --private-key 0x…01 --chain 1 --nonce <n>`.
const SELF_AUTHORIZATIONS: [&str; 3] = [
    "f85a0194dededededededededededededededededededede0180a0eea53161d8453096f789de127ba417217a45ae5dd4b48789935e63e9de9ccadaa010aa69a6d613d44abe1bceb491bb1152e506570f41daff08541b8c539e21bd8a",
    "f85a0194dededededededededededededededededededede0280a019ccf26acd440b6d26fd85de87c5d211f82c73ab09985f67c362b6545dc22870a03a5a99cab36e1b5d02967174f022a9f165be1f399a73715c143154711d7c4e7d",
    "f85a0194dededededededededededededededededededede0301a05ca99385e51f1eca8c17362aab311bd1480f3f2ee2e81aa56ed01e264c0ddf81a05529e9bd075fa3f3191804b02f574f5dab7e01752e3a9b5ead4a5ebbba7a8b9e",
];

/// The first `count` of [`SELF_AUTHORIZATIONS`].
fn self_authorizations(count: usize) -> Vec<SignedAuthorization> {
    SELF_AUTHORIZATIONS[..count]
        .iter()
        .map(|rlp| {
            let rlp = alloy_primitives::hex::decode(rlp).expect("authorization is hex");
            let authorization =
                SignedAuthorization::decode(&mut rlp.as_slice()).expect("authorization is RLP");
            assert_eq!(
                LazyAuthorization::from(authorization.clone()).authority(),
                Some(AUTHORITY),
                "fixture signed by the wrong key"
            );
            authorization
        })
        .collect()
}

/// Runs `txs` with [`COINBASE`] as the block beneficiary.
fn drive_with_coinbase(
    spec: SpecId,
    accounts: &[(Address, AccountInfo)],
    txs: &[DriveTx],
) -> pb::sf::ethereum::r#type::v2::Block {
    BlockDriver::new(spec, accounts).with_coinbase(COINBASE).run(txs)
}

/// A transaction calling `to` with `value`, paying [`GAS_PRICE`] for [`GAS_LIMIT`] gas.
fn priced_call(to: Address, value: u64) -> DriveTx {
    DriveTx::call(to, value).with_gas(GAS_LIMIT).with_gas_price(GAS_PRICE)
}

/// The one balance change of `address` for `reason` in `trx`, as `(old, new)`.
fn only_change(
    trx: &pb::sf::ethereum::r#type::v2::TransactionTrace,
    address: Address,
    reason: Reason,
) -> (U256, U256) {
    let changes: Vec<_> = trx
        .calls
        .iter()
        .flat_map(|call| &call.balance_changes)
        .filter(|change| change.address == address.to_vec() && change.reason == reason as i32)
        .map(|change| (big(&change.old_value), big(&change.new_value)))
        .collect();
    let [change] = changes.as_slice() else {
        panic!("expected one {reason:?} change of {address}, got {changes:?}");
    };
    *change
}

/// Wei a transaction of [`GAS_LIMIT`] gas at [`GAS_PRICE`] pays upfront.
fn gas_buy_cost() -> U256 {
    U256::from(GAS_LIMIT) * U256::from(GAS_PRICE)
}

/// Wei refunded to the sender of `trx`, which paid [`GAS_PRICE`] for [`GAS_LIMIT`] gas.
fn refund(trx: &pb::sf::ethereum::r#type::v2::TransactionTrace) -> U256 {
    U256::from(GAS_LIMIT - trx.gas_used) * U256::from(GAS_PRICE)
}

/// Wei credited to the coinbase for `trx`, which paid [`GAS_PRICE`].
fn reward(trx: &pb::sf::ethereum::r#type::v2::TransactionTrace) -> U256 {
    U256::from(trx.gas_used) * U256::from(GAS_PRICE)
}

/// Nonce changes of `trx`, all calls together, in ordinal order.
fn nonce_changes(trx: &pb::sf::ethereum::r#type::v2::TransactionTrace) -> Vec<(Address, u64, u64)> {
    let mut changes: Vec<_> = trx.calls.iter().flat_map(|call| &call.nonce_changes).collect();
    changes.sort_by_key(|change| change.ordinal);
    changes
        .into_iter()
        .map(|change| (Address::from_slice(&change.address), change.old_value, change.new_value))
        .collect()
}

/// A plain call bumps the sender nonce once.
#[test]
fn call_bumps_the_sender_nonce_once() {
    let block = drive_tx(SpecId::PRAGUE, &[(SENDER, balance_account(1_000_000))], RECIPIENT, 0);

    assert_eq!(nonce_changes(&block.transaction_traces[0]), [(SENDER, 0, 1)]);
}

/// EIP-7702 transaction whose sender is also the authority of its own authorization. The
/// sender nonce is bumped for the transaction (`0 → 1`), then again by the authorization
/// (`1 → 2`), and each bump is reported once with its own running nonce.
///
/// Live-block regression: the trace once carried `(0, 2)` for the transaction bump, folding
/// the authorization's bump into it, followed by `(1, 2)` for the authorization.
#[test]
fn self_authorized_sender_nonce_bumps_are_reported_separately() {
    let accounts = [(AUTHORITY, balance_account(1_000_000)), (DELEGATE, code_account(&[0x00], 0))];
    let tx = DriveTx::call(RECIPIENT, 0)
        .with_sender(AUTHORITY)
        .with_authorizations(self_authorizations(1));
    let block = drive_txs(SpecId::PRAGUE, &accounts, &[tx]);

    assert_eq!(nonce_changes(&block.transaction_traces[0]), [(AUTHORITY, 0, 1), (AUTHORITY, 1, 2)]);
}

/// Like [`self_authorized_sender_nonce_bumps_are_reported_separately`], with three
/// authorizations of the sender: one bump for the transaction, then one per authorization.
#[test]
fn several_self_authorizations_bump_the_sender_nonce_once_each() {
    let accounts = [(AUTHORITY, balance_account(1_000_000)), (DELEGATE, code_account(&[0x00], 0))];
    let tx = DriveTx::call(RECIPIENT, 0)
        .with_sender(AUTHORITY)
        .with_authorizations(self_authorizations(3));
    let block = drive_txs(SpecId::PRAGUE, &accounts, &[tx]);

    assert_eq!(
        nonce_changes(&block.transaction_traces[0]),
        [(AUTHORITY, 0, 1), (AUTHORITY, 1, 2), (AUTHORITY, 2, 3), (AUTHORITY, 3, 4)]
    );
}

/// A CREATE transaction bumps the sender nonce once, inside the root call as Geth's `create`
/// does. The created contract's own EIP-161 nonce bump is reported next to it.
#[test]
fn create_bumps_the_sender_nonce_once_in_the_root_call() {
    let block = drive_txs(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(1_000_000))],
        &[DriveTx::create(vec![0x00])],
    );

    let root = block.transaction_traces[0].calls.first().expect("a root call");
    let sender_nonces: Vec<_> = root
        .nonce_changes
        .iter()
        .filter(|change| change.address == SENDER.to_vec())
        .map(|change| (change.old_value, change.new_value))
        .collect();
    assert_eq!(sender_nonces, [(0, 1)], "the bump belongs to the root CREATE");
}

/// Mainnet shape: the gas buy debits `gas_limit * gas_price`, and the gas refund starts from
/// the balance the gas buy left.
#[test]
fn gas_refund_starts_from_the_gas_buy_balance() {
    let block = drive_with_coinbase(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(SENDER_BALANCE))],
        &[priced_call(RECIPIENT, 0)],
    );
    let trx = &block.transaction_traces[0];

    let pre = U256::from(SENDER_BALANCE);
    let after_gas_buy = pre - gas_buy_cost();
    assert_eq!(only_change(trx, SENDER, Reason::GasBuy), (pre, after_gas_buy));
    assert_eq!(
        only_change(trx, SENDER, Reason::GasRefund),
        (after_gas_buy, after_gas_buy + refund(trx))
    );
}

/// A gas buy that charges more than `gas_limit * gas_price` in one deduction — the blob fee
/// of an EIP-4844 transaction here, the L1 data fee and operator fee folded into the OP Stack
/// gas buy — must still be what the gas refund starts from when the sender's balance does not
/// otherwise move. Deriving the refund's `old_balance` as `pre_tx - gas_limit * gas_price`
/// over-counts by the extra charge and reports a refund starting above the balance the gas buy
/// left (base-mainnet: gas buy `0xfa → 0xea`, gas refund from `0xf5`).
#[test]
fn gas_refund_starts_from_a_gas_buy_with_extra_charges() {
    // EIP-4844: 2^17 blob gas per blob, at the minimum blob base fee of 1 wei.
    const BLOB_FEE: u64 = 131_072;

    let block = drive_with_coinbase(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(SENDER_BALANCE))],
        &[priced_call(RECIPIENT, 0).with_blobs(1, 1)],
    );
    let trx = &block.transaction_traces[0];

    let pre = U256::from(SENDER_BALANCE);
    let after_gas_buy = pre - gas_buy_cost() - U256::from(BLOB_FEE);
    assert_eq!(
        only_change(trx, SENDER, Reason::GasBuy),
        (pre, after_gas_buy),
        "the blob fee is part of the gas buy"
    );
    assert_eq!(
        only_change(trx, SENDER, Reason::GasRefund),
        (after_gas_buy, after_gas_buy + refund(trx))
    );
}

/// Value transfers of the sender during execution move the balance the gas refund starts
/// from: `old_balance = after gas buy - value out + value in`.
#[test]
fn gas_refund_starts_from_the_balance_after_value_transfers() {
    const CONTRACT: Address = Address::repeat_byte(0xc1);

    // The sender pays CONTRACT 20, which sends 5 back.
    let block = drive_with_coinbase(
        SpecId::PRAGUE,
        &[
            (SENDER, balance_account(SENDER_BALANCE)),
            (CONTRACT, code_account(&op_call_with_value(SENDER, 5), 0)),
        ],
        &[priced_call(CONTRACT, 20)],
    );
    let trx = &block.transaction_traces[0];

    let after_execution =
        U256::from(SENDER_BALANCE) - gas_buy_cost() - U256::from(20) + U256::from(5);
    assert_eq!(
        only_change(trx, SENDER, Reason::GasRefund),
        (after_execution, after_execution + refund(trx))
    );
}

/// A root call that reverts rolls its value transfer back, so the gas refund starts from the
/// balance the gas buy left, as if nothing had moved.
#[test]
fn gas_refund_after_a_reverted_root_call_starts_from_the_gas_buy_balance() {
    const CONTRACT: Address = Address::repeat_byte(0xc1);

    let block = drive_with_coinbase(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(SENDER_BALANCE)), (CONTRACT, code_account(&op_revert(), 0))],
        &[priced_call(CONTRACT, 500)],
    );
    let trx = &block.transaction_traces[0];
    assert!(trx.calls[0].state_reverted, "the root call reverted");

    let after_gas_buy = U256::from(SENDER_BALANCE) - gas_buy_cost();
    assert_eq!(
        only_change(trx, SENDER, Reason::GasRefund),
        (after_gas_buy, after_gas_buy + refund(trx))
    );
}

/// A sender whose delegated code self-destructs to another account is drained during
/// execution, so the gas refund starts from zero.
#[test]
fn gas_refund_of_a_sender_drained_by_selfdestruct_starts_from_zero() {
    let accounts = [
        (AUTHORITY, balance_account(SENDER_BALANCE)),
        (DELEGATE, code_account(&op_selfdestruct_to(BENEFICIARY), 0)),
    ];
    // The transaction calls the sender itself, running the code it delegates to.
    let tx = priced_call(AUTHORITY, 0)
        .with_sender(AUTHORITY)
        .with_authorizations(self_authorizations(1));
    let block = drive_with_coinbase(SpecId::PRAGUE, &accounts, &[tx]);
    let trx = &block.transaction_traces[0];

    let after_gas_buy = U256::from(SENDER_BALANCE) - gas_buy_cost();
    assert_eq!(only_change(trx, AUTHORITY, Reason::SuicideWithdraw), (after_gas_buy, U256::ZERO));
    assert_eq!(only_change(trx, AUTHORITY, Reason::GasRefund), (U256::ZERO, refund(trx)));
}

/// The coinbase reward of a transaction that does not touch the coinbase starts from its
/// pre-transaction balance.
#[test]
fn coinbase_reward_starts_from_its_pre_transaction_balance() {
    let block = drive_with_coinbase(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(SENDER_BALANCE)), (COINBASE, balance_account(7))],
        &[priced_call(RECIPIENT, 0)],
    );
    let trx = &block.transaction_traces[0];

    assert_eq!(
        only_change(trx, COINBASE, Reason::RewardTransactionFee),
        (U256::from(7), U256::from(7) + reward(trx))
    );
}

/// A coinbase drained during execution is credited its reward from the drained balance, not
/// its pre-transaction one. Chain-specific credits read the same root-exit balance through
/// [`FirehoseInspector::post_exec_balance`].
///
/// Live-block regression (base-mainnet block 52115535, tx c7febd63): `BaseFeeVault` held
/// 0x74500df8c2f300, was fully withdrawn during the tx, then credited the tx fee reward. Reth
/// reported old=0x74500df8c2f300 / new=pre+reward; Geth reported old=0 / new=reward.
#[test]
fn coinbase_reward_starts_from_its_balance_after_being_drained() {
    const BRIDGE: Address = Address::repeat_byte(0x16);
    const VAULT_BALANCE: u64 = 0x74500df8c2f300;

    // CALL(gas, BRIDGE, SELFBALANCE, 0, 0, 0, 0): send the whole balance to BRIDGE.
    let withdraw = [
        push(&[0]),
        push(&[0]),
        push(&[0]),
        push(&[0]),
        vec![0x47], // SELFBALANCE
        push(BRIDGE.as_slice()),
        vec![0x5a, 0xf1, 0x50], // GAS CALL POP
    ]
    .concat();
    let block = drive_with_coinbase(
        SpecId::PRAGUE,
        &[
            (SENDER, balance_account(SENDER_BALANCE)),
            (COINBASE, code_account(&withdraw, VAULT_BALANCE)),
            (BRIDGE, balance_account(1)),
        ],
        &[priced_call(COINBASE, 0)],
    );
    let trx = &block.transaction_traces[0];

    assert_eq!(
        only_change(trx, COINBASE, Reason::Transfer),
        (U256::from(VAULT_BALANCE), U256::ZERO),
        "the coinbase is drained during execution"
    );
    assert_eq!(
        only_change(trx, COINBASE, Reason::RewardTransactionFee),
        (U256::ZERO, reward(trx)),
        "the reward starts from the drained balance, not the pre-transaction one"
    );
}

/// Drives the SELFDESTRUCT scenario `ops` (see [`Scenario`]) as one transaction paying
/// [`GAS_PRICE`], with `coinbase` as the block beneficiary.
fn drive_selfdestruct_with_coinbase(
    spec: SpecId,
    ops: Vec<Vec<u8>>,
    coinbase: Address,
) -> pb::sf::ethereum::r#type::v2::TransactionTrace {
    let scenario = Scenario { ops, ..Default::default() };
    let factory = factory_code(&scenario.initcode, scenario.endowment, &scenario.ops);
    let accounts = [
        (SENDER, balance_account(SENDER_BALANCE)),
        (FACTORY, code_account(&factory, 1_000_000)),
        (BENEFICIARY, balance_account(0)),
    ];
    let block = BlockDriver::new(spec, &accounts)
        .with_coinbase(coinbase)
        .run(&[DriveTx::call(FACTORY, 0).with_gas_price(GAS_PRICE)]);

    let trx = block.transaction_traces.into_iter().next().expect("one transaction");
    assert_eq!(
        balance_change_log_of(&trx, &scenario.labels())[1..3],
        ["factory 1000000→999000 Transfer", "subject 0→1000 Transfer"],
        "{spec:?}: the account under test is created with its endowment"
    );
    trx
}

/// A SELFDESTRUCT that refunds the coinbase: the fee reward starts from the balance the refund
/// left.
///
/// Live-block regression (mainnet block 25690108): 0x8707c2bd… selfdestructed to the coinbase
/// 0x4838b106… for 0x690f7d1c42ce88. Geth reported
/// `SuicideRefund 0x46e9d5e2f034f0bb → 0x4752e5600c77bf43` followed by
/// `RewardTransactionFee old=0x4752e5600c77bf43`; reth once resolved the reward's
/// `old_balance` back to 0x46e9d5e2f034f0bb, dropping the refund.
#[test]
fn coinbase_reward_starts_from_its_balance_after_a_selfdestruct_refund() {
    let trx = &drive_selfdestruct_with_coinbase(
        SpecId::PRAGUE,
        vec![op_call_selector(subject(), 0, SD_OTHER)],
        BENEFICIARY,
    );

    assert_eq!(
        only_change(trx, BENEFICIARY, Reason::SuicideRefund),
        (U256::ZERO, U256::from(1_000))
    );
    assert_eq!(
        only_change(trx, BENEFICIARY, Reason::RewardTransactionFee),
        (U256::from(1_000), U256::from(1_000) + reward(trx))
    );
}

/// A coinbase created and self-destructed to itself in the transaction. Before Amsterdam the
/// SELFDESTRUCT burns its balance, so the reward starts from zero; at Amsterdam [EIP-8246]
/// keeps the balance on the account, and the reward starts from it. Reporting zero there would
/// say the coinbase lost ether it still holds.
///
/// [EIP-8246]: https://eips.ethereum.org/EIPS/eip-8246
#[test]
fn self_destructed_coinbase_reward_starts_from_the_balance_it_kept() {
    for (spec, kept) in [(SpecId::PRAGUE, 0), (SpecId::AMSTERDAM, 1_000)] {
        let trx = &drive_selfdestruct_with_coinbase(
            spec,
            vec![op_call_selector(subject(), 0, SD_SELF)],
            subject(),
        );

        assert_eq!(
            only_change(trx, subject(), Reason::RewardTransactionFee),
            (U256::from(kept), U256::from(kept) + reward(trx)),
            "{spec:?}"
        );
    }
}

/// [`PreTxAdjust`] flagging the root balance change of the block's first transaction as a
/// mint, the way the OP Stack flags deposit transactions.
struct MintFirstTransaction;

impl<E: reth_evm::Evm> PreTxAdjust<E> for MintFirstTransaction {
    fn adjust_tx_event<G: std::ops::DerefMut<Target = firehose_tracer::Tracer>>(
        &self,
        _evm: &mut E,
        inspector: &FirehoseInspector<G>,
        tx_event: &mut firehose_tracer::types::TxEvent,
        _sender: Address,
    ) {
        if tx_event.index == 0 {
            inspector.set_root_balance_reason(Reason::IncreaseMint);
        }
    }
}

/// [`FirehoseInspector::set_root_balance_reason`] is single-shot: the override applies to the
/// next transaction's root balance change only, so the transaction after it is back to
/// `GasBuy` even though no hook installed a reason for it.
#[test]
fn root_balance_reason_override_is_single_shot() {
    let block = BlockDriver::new(SpecId::PRAGUE, &[(SENDER, balance_account(SENDER_BALANCE))])
        .with_coinbase(COINBASE)
        .with_pre_tx_adjust(MintFirstTransaction)
        .run(&[priced_call(RECIPIENT, 0), priced_call(RECIPIENT, 0)]);

    let root_reasons: Vec<_> = block
        .transaction_traces
        .iter()
        .map(|trx| {
            let first = trx
                .calls
                .iter()
                .flat_map(|call| &call.balance_changes)
                .min_by_key(|change| change.ordinal)
                .expect("a root balance change");
            Reason::try_from(first.reason).expect("a known reason")
        })
        .collect();
    assert_eq!(root_reasons, [Reason::IncreaseMint, Reason::GasBuy]);
}
