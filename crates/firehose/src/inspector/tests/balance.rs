//! Journal-level accounting: the nonce bump [`Inspector::call`] attributes to `deduct_caller`,
//! the post-transaction balance resolution the gas-refund and fee-vault events are built on,
//! and the one-shot root balance reason override.

use crate::inspector::*;
use reth_revm::revm::context::JournalEntry;

fn addr(b: u8) -> Address {
    Address::repeat_byte(b)
}

/// Build a `BalanceChange` entry for `address` with `old_balance` (the only field revm
/// records on the journal — the new balance is whatever the live account holds).
fn balance_change(address: Address, old_balance: U256) -> JournalEntry {
    JournalEntry::BalanceChange { address, old_balance }
}

fn balance_transfer(from: Address, to: Address, amount: U256) -> JournalEntry {
    JournalEntry::BalanceTransfer { from, to, balance: amount }
}

/// Vanilla CALL: deduct_caller bumps by 1, no EIP-7702 auths affect the
/// sender, so `original` and `current` differ by exactly 1. Emits the
/// observed bump as-is.
#[test]
fn deduct_caller_nonce_emission_vanilla_call() {
    assert_eq!(Some((219, 220)), deduct_caller_nonce_emission(219, 220));
}

/// EIP-7702 CALL where the sender is also an authority in its own auth list.
/// deduct_caller bumps `219 → 220`, then revm's `apply_auth_list` bumps
/// `220 → 221` for the matching auth — both before our `call` hook fires.
/// `current = 221` here, but we must emit only the deduct_caller portion
/// (`+1`). The auth bump is owned by `process_eip7702_auth_list` and emits
/// separately as `220 → 221`. Live-block regression: pre-fix the trace
/// carried `(219, 221)` followed by `(220, 221)` — this test pins the fix.
#[test]
fn deduct_caller_nonce_emission_eip7702_self_authorized() {
    assert_eq!(Some((219, 220)), deduct_caller_nonce_emission(219, 221));
}

/// EIP-7702 CALL where the sender is also an authority AND there are
/// multiple matching auths in the list. apply_auth_list applies several
/// per-authority bumps; `current` is `original + 1 (deduct_caller) + N (auths)`.
/// We still emit only the +1 from deduct_caller; each of the N auth bumps
/// is emitted independently by `process_eip7702_auth_list` with its own
/// per-authority running nonce.
#[test]
fn deduct_caller_nonce_emission_eip7702_multiple_self_authorizations() {
    // current = 219 + 1 (deduct_caller) + 3 (three auths bumping the sender)
    assert_eq!(Some((219, 220)), deduct_caller_nonce_emission(219, 223));
}

/// CREATE: deduct_caller does NOT bump the caller nonce — that happens
/// later in `create_account_checkpoint`. At our depth-0 `call` hook the
/// nonce hasn't moved yet, so we must emit nothing. (For CREATE the depth-0
/// hook in question is the `create` hook; this case still validates that the
/// helper returns None when `original == current`, guarding against a future
/// path that might call this helper outside the CALL flow.)
#[test]
fn deduct_caller_nonce_emission_no_bump_yields_none() {
    assert_eq!(None, deduct_caller_nonce_emission(219, 219));
}

/// Defensive: if the live nonce ever appears to have *gone backwards* we
/// emit nothing rather than producing a `(old, old+1)` event that
/// contradicts state. Should never happen in practice (revm's nonces are
/// monotonic per tx) — this just locks the contract.
#[test]
fn deduct_caller_nonce_emission_decreasing_yields_none() {
    assert_eq!(None, deduct_caller_nonce_emission(220, 219));
}

/// Mainnet shape: `validate_against_state_and_deduct_caller` records exactly one
/// `BalanceChange` for the sender whose implicit new balance is `old − gas_buy_cost`.
/// With `initial_balance = None`, the journal-walk fallback recovers the right value.
#[test]
fn resolve_post_tx_balance_mainnet_gas_buy_only() {
    let sender = addr(0xAA);
    let pre_tx = U256::from(0xfa_u64);
    let gas_buy_cost = U256::from(0x10_u64);

    let journal = vec![balance_change(sender, pre_tx)];
    let mut get_pre = |_: Address| pre_tx;

    let resolved = FirehoseInspector::resolve_post_tx_balance(
        sender,
        None,
        gas_buy_cost,
        &journal,
        &mut get_pre,
    );
    assert_eq!(resolved, U256::from(0xea_u64), "mainnet: pre - gas_buy");
}

/// OP Stack shape: `validate_against_state_and_deduct_caller` folds gas_buy + L1 cost
/// (+ operator fee under Isthmus) into a single `set_balance` call, so the journal
/// records ONE `BalanceChange { old = pre_tx }` whose implicit new balance is
/// `pre_tx − (gas_buy + additional_op_cost)`.
///
/// The pre-fix algorithm computed `pre_tx − gas_buy_cost`, over-counting by
/// `additional_op_cost` and producing an `old_balance` for the gas-refund event that
/// was higher than the gas-buy `new_balance` the user actually saw. The fix passes
/// the live post-pre-exec balance via `initial_balance` so the journal walk seeds
/// correctly.
///
/// This test reproduces the bug observed on base-mainnet:
/// gas-buy event:    old=0xfa  new=0xea  (Δ = 0x10 = gas_buy + L1)
/// gas-refund event: old=0xea  new=0xff  (Δ = 0x15 = remaining gas + …)
/// The pre-fix code would have given gas-refund old=0xef (= 0xfa − gas_buy(0x05) +
/// transfer-in(…)), which is the user's reported wrong value.
#[test]
fn resolve_post_tx_balance_op_combined_pre_exec_deduction() {
    let sender = addr(0xAA);
    let pre_tx = U256::from(0xfa_u64);
    let gas_buy_cost = U256::from(0x05_u64);
    let post_pre_exec = U256::from(0xea_u64); // observed on the live account at depth 0

    // Single combined journal entry: validate_against_state_and_deduct_caller's
    // `set_balance(pre_tx − gas_buy − l1)`.
    let journal = vec![balance_change(sender, pre_tx)];
    let mut get_pre = |_: Address| pre_tx;

    // Pre-fix behaviour: ignore `initial_balance`, use journal walk only.
    let pre_fix = FirehoseInspector::resolve_post_tx_balance(
        sender,
        None,
        gas_buy_cost,
        &journal,
        &mut get_pre,
    );
    assert_eq!(
        pre_fix,
        U256::from(0xf5_u64),
        "pre-fix derives pre_tx − gas_buy_cost = 0xfa − 0x05 = 0xf5 (wrong on OP)"
    );

    // Post-fix behaviour: `initial_balance = Some(post_pre_exec)` short-circuits the
    // BalanceChange match, returning the live captured balance.
    let post_fix = FirehoseInspector::resolve_post_tx_balance(
        sender,
        Some(post_pre_exec),
        gas_buy_cost,
        &journal,
        &mut get_pre,
    );
    assert_eq!(post_fix, post_pre_exec, "post-fix uses captured live balance");
}

/// `BalanceTransfer` entries from execution (e.g. value transfers from sender during
/// CALL) must still apply on top of the seeded balance. This guards the formula
/// `gas-refund old = post_pre_exec − value_out + value_in`.
#[test]
fn resolve_post_tx_balance_op_with_value_transfers() {
    let sender = addr(0xAA);
    let other = addr(0xBB);
    let post_pre_exec = U256::from(100_u64);

    let journal = vec![
        balance_change(sender, U256::from(150_u64)), // pre_tx; new = post_pre_exec
        balance_transfer(sender, other, U256::from(20_u64)), // sender pays 20
        balance_transfer(other, sender, U256::from(5_u64)), // sender receives 5
    ];
    let mut get_pre = |_: Address| U256::ZERO;

    let resolved = FirehoseInspector::resolve_post_tx_balance(
        sender,
        Some(post_pre_exec),
        U256::ZERO, // unused on this path
        &journal,
        &mut get_pre,
    );
    assert_eq!(
        resolved,
        U256::from(85_u64),
        "100 − 20 + 5 = 85 (transfers applied on top of seeded post-pre-exec balance)"
    );
}

/// Coinbase path: no pre-exec deduction, no seeded balance — the journal walk falls
/// back to `get_pre_tx_balance` when no entries reference the address. This must keep
/// working (sender ≠ coinbase coinbase-reward emission relies on it).
#[test]
fn resolve_post_tx_balance_coinbase_falls_back_to_pre_tx() {
    let coinbase = addr(0xCC);
    let pre_tx_coinbase = U256::from(7_u64);
    let journal: Vec<JournalEntry> = vec![];
    let mut get_pre = |_: Address| pre_tx_coinbase;

    let resolved = FirehoseInspector::resolve_post_tx_balance(
        coinbase,
        None,
        U256::ZERO,
        &journal,
        &mut get_pre,
    );
    assert_eq!(resolved, pre_tx_coinbase);
}

/// Fee-vault credit path (`post_tx_balance`): the OP Stack post-tx extras hook resolves
/// a fee vault's `old_balance` via the same `initial_balance = None, gas_buy_cost = 0`
/// derivation the coinbase reward uses. On a FeeVault-withdrawal tx the vault is drained
/// mid-execution (a `BalanceTransfer` from the vault), so the resolved balance must be the
/// post-drain value — NOT the pre-tx balance a `db.basic` read would return.
///
/// Live-block regression (base-mainnet block 52115535, tx c7febd63): BaseFeeVault
/// (0x…19) held 0x74500df8c2f300, was fully withdrawn during the tx, then credited the
/// tx fee reward. Pre-fix reth reported old=0x74500df8c2f300 / new=pre+reward; geth
/// reported old=0 / new=reward. This pins the resolver to geth's behaviour.
#[test]
fn resolve_post_tx_balance_fee_vault_drained_before_reward() {
    let vault = addr(0x19);
    let bridge = addr(0x16);
    let pre_tx = U256::from(0x74500df8c2f300_u64); // vault balance entering the tx

    // FeeVault.withdraw() sends the entire balance out during execution.
    let journal = vec![balance_transfer(vault, bridge, pre_tx)];
    let mut get_pre = |_: Address| pre_tx;

    let resolved =
        FirehoseInspector::resolve_post_tx_balance(vault, None, U256::ZERO, &journal, &mut get_pre);
    assert_eq!(
        resolved,
        U256::ZERO,
        "vault drained to 0 during execution → reward old_balance must be 0, not pre-tx"
    );

    // Sanity: with no withdrawal (untouched vault) it falls back to the pre-tx balance,
    // preserving the common-case behaviour for every non-withdrawal tx.
    let untouched: Vec<JournalEntry> = vec![];
    assert_eq!(
        FirehoseInspector::resolve_post_tx_balance(
            vault,
            None,
            U256::ZERO,
            &untouched,
            &mut get_pre,
        ),
        pre_tx,
    );
}

/// SELFDESTRUCT refund into the coinbase (or the sender): on the truly-destroyed path
/// revm credits `target` in place and pushes only `AccountDestroyed` — no
/// `BalanceTransfer`. The resolver must replay that credit, otherwise the
/// `RewardTransactionFee` event that follows carries a stale `old_balance`.
///
/// Live-block regression (mainnet block 25690108): 0x8707c2bd… selfdestructed to the
/// coinbase 0x4838b106… for 0x690f7d1c42ce88. Geth reported
/// `SuicideRefund 0x46e9d5e2f034f0bb → 0x4752e5600c77bf43` followed by
/// `RewardTransactionFee old=0x4752e5600c77bf43`; pre-fix reth resolved the reward's
/// `old_balance` back to 0x46e9d5e2f034f0bb, silently dropping the refund.
#[test]
fn resolve_post_tx_balance_credits_selfdestruct_beneficiary() {
    use reth_revm::revm::context_interface::journaled_state::entry::SelfdestructionRevertStatus;

    let coinbase = addr(0x48);
    let destroyed = addr(0x87);
    let pre_tx = U256::from(0x46e9d5e2f034f0bb_u64);
    let refund = U256::from(0x690f7d1c42ce88_u64);

    let journal = vec![JournalEntry::AccountDestroyed {
        had_balance: refund,
        address: destroyed,
        target: coinbase,
        destroyed_status: SelfdestructionRevertStatus::GloballySelfdestroyed,
    }];
    let mut get_pre = |_: Address| pre_tx;

    assert_eq!(
        FirehoseInspector::resolve_post_tx_balance(
            coinbase,
            None,
            U256::ZERO,
            &journal,
            &mut get_pre,
        ),
        U256::from(0x4752e5600c77bf43_u64),
        "coinbase reward old_balance must include the suicide refund"
    );

    // The destroyed account itself still resolves to zero.
    assert_eq!(
        FirehoseInspector::resolve_post_tx_balance(
            destroyed,
            None,
            U256::ZERO,
            &journal,
            &mut get_pre,
        ),
        U256::ZERO,
    );
}

/// Self-beneficiary SELFDESTRUCT (`target == address`) before Amsterdam: the balance is
/// burned, not credited. The beneficiary arm must not fire and re-add it.
#[test]
fn resolve_post_tx_balance_selfdestruct_to_self_burns() {
    use reth_revm::revm::context_interface::journaled_state::entry::SelfdestructionRevertStatus;

    let account = addr(0x87);
    let pre_tx = U256::from(0x1000_u64);

    let journal = vec![JournalEntry::AccountDestroyed {
        had_balance: pre_tx,
        address: account,
        target: account,
        destroyed_status: SelfdestructionRevertStatus::GloballySelfdestroyed,
    }];
    let mut get_pre = |_: Address| pre_tx;

    assert_eq!(
        FirehoseInspector::resolve_post_tx_balance(
            account,
            None,
            U256::ZERO,
            &journal,
            &mut get_pre,
        ),
        U256::ZERO,
    );
}

/// Self-beneficiary SELFDESTRUCT at Amsterdam: [EIP-8246] keeps the balance on the account
/// and revm records `had_balance = 0` to say so. The resolver must leave the running balance
/// alone — an account that is also the coinbase would otherwise report
/// `RewardTransactionFee old_balance = 0` while still holding its ether.
///
/// [EIP-8246]: https://eips.ethereum.org/EIPS/eip-8246
#[test]
fn resolve_post_tx_balance_selfdestruct_to_self_keeps_balance_at_amsterdam() {
    use reth_revm::revm::context_interface::journaled_state::entry::SelfdestructionRevertStatus;

    let account = addr(0x87);
    let pre_tx = U256::from(0x1000_u64);

    let journal = vec![JournalEntry::AccountDestroyed {
        had_balance: U256::ZERO,
        address: account,
        target: account,
        destroyed_status: SelfdestructionRevertStatus::GloballySelfdestroyed,
    }];
    let mut get_pre = |_: Address| pre_tx;

    assert_eq!(
        FirehoseInspector::resolve_post_tx_balance(
            account,
            None,
            U256::ZERO,
            &journal,
            &mut get_pre,
        ),
        pre_tx,
    );
}

// ----------------------------------------------------------------------
// Regression guards for the `tx_post_pre_exec_sender_balance` snapshot
// path (`enter_frame_pre_hook` → `resolve_post_tx_balance`).
//
// Background: commit `e23632b3` introduced the `initial_balance: Option<U256>`
// parameter and the `tx_post_pre_exec_sender_balance` field to fix an OP Stack
// bug where the gas-refund event's `old_balance` was higher than the gas-buy
// event's `new_balance`. A subsequent refactor (`59843d61c`) extracted the
// depth-0 root-entry block into `enter_frame_pre_hook` and silently dropped
// the snapshot assignment, regressing the fix. The tests below pin both the
// function-level contract and the user-visible invariant so future refactors
// surface the regression immediately.
// ----------------------------------------------------------------------

/// When the seed is `Some(..)` and the sender has NO journal entries (e.g. a
/// reverted root call that touched no other accounts), the seed must flow
/// through unchanged. Guards against a "fix" that requires a journal entry to
/// produce a result on the seeded path.
#[test]
fn resolve_post_tx_balance_seeded_with_no_sender_journal_entries_returns_seed() {
    let sender = addr(0xAA);
    let other = addr(0xBB);
    let post_pre_exec = U256::from(0xea_u64);

    // Journal entries exist but none reference the sender.
    let journal = vec![balance_change(other, U256::from(0x100_u64))];
    let mut get_pre = |_: Address| panic!("must not fall back to get_pre_tx_balance");

    let resolved = FirehoseInspector::resolve_post_tx_balance(
        sender,
        Some(post_pre_exec),
        U256::from(0x05_u64), // gas_buy_cost ignored on the seeded path
        &journal,
        &mut get_pre,
    );
    assert_eq!(resolved, post_pre_exec);
}

/// `AccountDestroyed` for the sender (degenerate case — sender SELFDESTRUCTs
/// itself within the tx) must dominate the seed: balance becomes zero.
#[test]
fn resolve_post_tx_balance_seeded_then_account_destroyed_yields_zero() {
    let sender = addr(0xAA);
    let post_pre_exec = U256::from(0xea_u64);

    let journal = vec![JournalEntry::AccountDestroyed {
        had_balance: post_pre_exec,
        address: sender,
        target: addr(0xBB),
        destroyed_status:
            reth_revm::revm::context_interface::journaled_state::entry::SelfdestructionRevertStatus::LocallySelfdestroyed,
    }];
    let mut get_pre = |_: Address| panic!("must not fall back to get_pre_tx_balance");

    let resolved = FirehoseInspector::resolve_post_tx_balance(
        sender,
        Some(post_pre_exec),
        U256::ZERO,
        &journal,
        &mut get_pre,
    );
    assert_eq!(resolved, U256::ZERO);
}

/// Pins the OP-stack bug from the report: when the sender has no balance
/// activity between pre-exec deduction and post-exec refund (no transfers,
/// no precompile-driven BalanceChange), the gas-refund event's `old_balance`
/// must equal the gas-buy event's `new_balance`. Any deviation in that
/// scenario means `additional_op_cost` (L1 fee + operator fee on Isthmus)
/// was double-counted somewhere.
///
/// (When the sender does see transfers mid-tx, the two values legitimately
/// diverge — `resolve_post_tx_balance` replays `BalanceTransfer` entries
/// to track that, and the gas-refund `old_balance` reflects the live
/// post-execution balance, not the post-pre-exec snapshot.)
///
/// Reproduces the exact `0xfa / 0xea` numbers from the base-mainnet bug
/// report. Without seeding (`initial_balance = None`), the journal-walk
/// fallback computes `0xfa - 0x05 = 0xf5` — a value strictly greater than
/// `0xea` and visibly broken in the trace. With seeding, the contract holds.
#[test]
fn resolve_post_tx_balance_op_invariant_gas_refund_old_equals_gas_buy_new() {
    let sender = addr(0xAA);
    let pre_tx = U256::from(0xfa_u64);
    let gas_buy_cost = U256::from(0x05_u64);
    let l1_plus_operator_fee = U256::from(0x0b_u64);
    // What the OP handler actually wrote to the live account balance:
    // `pre_tx − gas_buy − (L1 + operator)`.
    let live_post_pre_exec = pre_tx - gas_buy_cost - l1_plus_operator_fee;
    assert_eq!(live_post_pre_exec, U256::from(0xea_u64));

    // Single combined journal entry recorded by
    // `validate_against_state_and_deduct_caller`.
    let journal = vec![balance_change(sender, pre_tx)];
    let mut get_pre = |_: Address| pre_tx;

    // Invariant under test: gas-buy `new_balance` (= live post-pre-exec balance)
    // must equal gas-refund `old_balance` (= what the consumer reads back).
    let gas_buy_new = live_post_pre_exec;
    let gas_refund_old = FirehoseInspector::resolve_post_tx_balance(
        sender,
        Some(live_post_pre_exec), // what `enter_frame_pre_hook` snapshots
        gas_buy_cost,
        &journal,
        &mut get_pre,
    );
    assert_eq!(
        gas_refund_old, gas_buy_new,
        "OP gas-refund old_balance must equal gas-buy new_balance — \
         if this fails, the call site likely stopped seeding \
         tx_post_pre_exec_sender_balance"
    );

    // Negative control: confirm the un-seeded path still produces the wrong
    // value. If this assertion ever flips, the broken-derivation test below
    // is no longer load-bearing and the OP-fold semantics have changed
    // upstream — re-evaluate the seeded path then.
    let unseeded = FirehoseInspector::resolve_post_tx_balance(
        sender,
        None,
        gas_buy_cost,
        &journal,
        &mut get_pre,
    );
    assert_ne!(
        unseeded, gas_buy_new,
        "un-seeded path must still produce the broken (over-counted) value — \
         this is the negative control that justifies the seeded path"
    );
    assert_eq!(unseeded, U256::from(0xf5_u64));
}

/// Pins the `set_root_balance_reason` contract: the override defaults to `None`, gets
/// set by the public setter, and is single-shot (consumed via `.take()` by the depth-0
/// hook). A future refactor that drops the `.take()` would let the previous tx's reason
/// leak into the next tx — this test is the canary for that.
#[test]
fn root_balance_reason_override_is_single_shot() {
    use pb::sf::ethereum::r#type::v2::balance_change::Reason;
    let mut tracer = firehose_tracer::Tracer::new_with_writer(
        firehose_tracer::config::Config::default(),
        Box::new(Vec::<u8>::new()),
    );
    let mut inspector = FirehoseInspector::new(&mut tracer);

    // Default: no override.
    assert_eq!(inspector.root_balance_reason_override, None);

    // Setter installs the override.
    inspector.set_root_balance_reason(Reason::IncreaseMint);
    assert_eq!(inspector.root_balance_reason_override, Some(Reason::IncreaseMint));

    // The depth-0 hook reads it via `.take()`. Simulating that here pins the consumption
    // contract: after one read the override is cleared, so the next tx starts clean even
    // if its `PreTxAdjust` impl decides not to install one.
    let consumed = inspector.root_balance_reason_override.take();
    assert_eq!(consumed, Some(Reason::IncreaseMint));
    assert_eq!(inspector.root_balance_reason_override, None);
}
