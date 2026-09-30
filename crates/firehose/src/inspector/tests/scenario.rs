//! The SELFDESTRUCT scenario harness: a factory contract CREATE2s the account under test and
//! drives it through a scripted sequence of operations, and the whole scenario is then run at
//! two spec ids so a fork difference is attributable to the fork alone.

use super::support::*;
use crate::inspector::*;
use reth_revm::revm::primitives::hardfork::SpecId;

/// Beneficiary of every `selfdestruct-to-other` below, distinct from [`RECIPIENT`] so a
/// suicide refund cannot be confused with a plain transfer.
pub(super) const BENEFICIARY: Address = Address::repeat_byte(0xbe);

/// Contract the transaction calls: it CREATE2s the account under test and then drives it.
pub(super) const FACTORY: Address = Address::repeat_byte(0xf1);

/// Contract that calls the account under test and then reverts, so the `SELFDESTRUCT` it
/// triggered is rolled back with the frame.
pub(super) const REVERTER: Address = Address::repeat_byte(0x5e);

/// Salt [`FACTORY`] CREATE2s the account under test with.
pub(super) const SUBJECT_SALT: u8 = 1;

/// `CALLDATASIZE` selectors of the account under test, see [`subject_runtime`].
pub(super) const SD_SELF: u8 = 0;
pub(super) const SD_OTHER: u8 = 1;
pub(super) const RECEIVE: u8 = 2;
pub(super) const SSTORE_SLOT: u8 = 3;
pub(super) const BUMP_NONCE: u8 = 4;

/// One SELFDESTRUCT scenario: [`FACTORY`] CREATE2s `initcode` with `endowment` wei and then
/// runs `ops`, and the transaction calls [`FACTORY`] with no value of its own.
///
/// Scenarios are declared once and run at two spec ids, which is what makes a "before and
/// after the fork" assertion a comparison of the same execution rather than of two
/// hand-written fixtures.
pub(super) struct Scenario {
    pub(super) initcode: Vec<u8>,
    pub(super) endowment: u64,
    pub(super) ops: Vec<Vec<u8>>,
    pub(super) extra_accounts: Vec<(Address, revm::state::AccountInfo)>,
    pub(super) gas_limit: u64,
    pub(super) transactions: usize,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            initcode: subject_initcode(),
            endowment: 1_000,
            ops: Vec::new(),
            extra_accounts: Vec::new(),
            gas_limit: 1_000_000,
            transactions: 1,
        }
    }
}

impl Scenario {
    /// Address [`FACTORY`]'s CREATE2 lands this scenario's account on. Precomputed so a
    /// scenario can bake calls to the account into code deployed before it exists.
    pub(super) fn subject(&self) -> Address {
        create2_address(&self.initcode)
    }

    pub(super) fn run(&self, spec: SpecId) -> pb::sf::ethereum::r#type::v2::Block {
        let mut accounts = vec![
            (SENDER, balance_account(1_000_000)),
            (
                FACTORY,
                code_account(&factory_code(&self.initcode, self.endowment, &self.ops), 1_000_000),
            ),
            (BENEFICIARY, balance_account(0)),
        ];
        accounts.extend(self.extra_accounts.iter().cloned());

        let txs: Vec<_> = (0..self.transactions)
            .map(|_| DriveTx::call(FACTORY, 0).with_gas(self.gas_limit))
            .collect();
        drive_txs(spec, &accounts, &txs)
    }

    /// Address labels for [`balance_change_log`] and [`state_change_log`].
    pub(super) fn labels(&self) -> Vec<(Address, &'static str)> {
        vec![
            (SENDER, "sender"),
            (FACTORY, "factory"),
            (self.subject(), "subject"),
            (BENEFICIARY, "beneficiary"),
            (REVERTER, "reverter"),
        ]
    }

    /// The balance changes of the scenario's first transaction at `spec`.
    pub(super) fn balance_log(&self, spec: SpecId) -> Vec<String> {
        balance_change_log(&self.run(spec), &self.labels())
    }

    /// Asserts the scenario's balance changes on both sides of the fork: `before` at
    /// `PRAGUE`, `after` at `AMSTERDAM`.
    pub(super) fn assert_balance_logs(&self, before: &[&str], after: &[&str]) {
        assert_eq!(self.balance_log(SpecId::PRAGUE), before, "before Amsterdam");
        assert_eq!(self.balance_log(SpecId::AMSTERDAM), after, "at Amsterdam");
    }
}

/// Address of the account under test in every scenario that keeps the default initcode.
/// Precomputed rather than derived from a running scenario: the factory's own code has to
/// contain calls to it.
pub(super) fn subject() -> Address {
    create2_address(&subject_initcode())
}

/// Runtime code of the account under test, dispatching on the number of calldata bytes:
///
/// * [`SD_SELF`] — `SELFDESTRUCT` with itself as beneficiary
/// * [`SD_OTHER`] — `SELFDESTRUCT` to [`BENEFICIARY`]
/// * [`RECEIVE`] — `STOP`, so a caller can fund the account without destroying it again
/// * [`SSTORE_SLOT`] — write storage slot 1, then `STOP`
/// * [`BUMP_NONCE`] — `CREATE` two empty accounts to raise its own nonce, then `STOP`
///
/// One contract covers every case because `SELFDESTRUCT` halts its frame: "selfdestruct,
/// then receive value, then selfdestruct again" can only be expressed as separate calls
/// into the same account, and the account has to behave differently in each.
pub(super) fn subject_runtime() -> Vec<u8> {
    let bump = [op_create(0, 0, 0), op_create(0, 0, 0), vec![0x00]].concat();

    op_dispatch(&[
        op_selfdestruct_self(),
        op_selfdestruct_to(BENEFICIARY),
        vec![0x00], // STOP
        [op_sstore(1, 1), vec![0x00]].concat(),
        bump,
    ])
}

pub(super) fn subject_initcode() -> Vec<u8> {
    op_deploy(&subject_runtime())
}

pub(super) fn create2_address(initcode: &[u8]) -> Address {
    FACTORY.create2_from_code(B256::left_padding_from(&[SUBJECT_SALT]), initcode)
}

/// Code for [`FACTORY`]: CREATE2 `initcode` with `endowment` wei, then run `ops`.
pub(super) fn factory_code(initcode: &[u8], endowment: u64, ops: &[Vec<u8>]) -> Vec<u8> {
    let (mut code, offset, size) = op_store_bytes(initcode);
    code.extend(op_create2(endowment, offset, size, SUBJECT_SALT));
    for op in ops {
        code.extend_from_slice(op);
    }
    code
}

/// `ADDRESS SELFDESTRUCT` — the executing account is its own beneficiary.
pub(super) fn op_selfdestruct_self() -> Vec<u8> {
    vec![0x30, 0xff]
}

/// `PUSH20 <beneficiary> SELFDESTRUCT`.
pub(super) fn op_selfdestruct_to(beneficiary: Address) -> Vec<u8> {
    let mut code = push(beneficiary.as_slice());
    code.push(0xff); // SELFDESTRUCT
    code
}

/// `SSTORE` a single-byte `value` into a single-byte `slot`.
pub(super) fn op_sstore(slot: u8, value: u8) -> Vec<u8> {
    let mut code = push(&[value]);
    code.extend(push(&[slot]));
    code.push(0x55); // SSTORE
    code
}

/// `REVERT` over an empty data range.
pub(super) fn op_revert() -> Vec<u8> {
    let mut code = push(&[0]); // size
    code.extend(push(&[0])); // offset
    code.push(0xfd); // REVERT
    code
}

/// `CALL(gas = all remaining, target, value, in = `selector` bytes, out = none)` then `POP`.
///
/// The callee dispatches on `CALLDATASIZE`, so the argument *length* is the selector and the
/// bytes themselves are whatever the caller's memory happens to hold.
pub(super) fn op_call_selector(target: Address, value: u64, selector: u8) -> Vec<u8> {
    op_call_selector_forwarding(target, value, selector, None)
}

/// [`op_call_selector`] forwarding exactly `gas`, so the callee can be starved of it.
pub(super) fn op_call_selector_with_gas(
    target: Address,
    value: u64,
    selector: u8,
    gas: u16,
) -> Vec<u8> {
    op_call_selector_forwarding(target, value, selector, Some(gas))
}

pub(super) fn op_call_selector_forwarding(
    target: Address,
    value: u64,
    selector: u8,
    gas: Option<u16>,
) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(&[0])); // retLength
    code.extend(push(&[0])); // retOffset
    code.extend(push(&[selector])); // argsLength
    code.extend(push(&[0])); // argsOffset
    code.extend(push(&value.to_be_bytes())); // value
    code.extend(push(target.as_slice())); // address
    match gas {
        Some(gas) => code.extend(push(&gas.to_be_bytes())),
        None => code.push(0x5a), // GAS
    }
    code.push(0xf1); // CALL
    code.push(0x50); // POP
    code
}

/// Initcode returning `runtime` as the deployed code.
pub(super) fn op_deploy(runtime: &[u8]) -> Vec<u8> {
    let (mut code, offset, size) = op_store_bytes(runtime);
    code.extend(push(&[size]));
    code.extend(push(&[offset]));
    code.push(0xf3); // RETURN
    code
}

/// Writes `data` into memory at offset 0, one `MSTORE` per 32-byte word with the last word
/// zero-padded, and returns the bytecode plus the `(offset, size)` pair a CREATE, CREATE2 or
/// RETURN reads it back from.
///
/// [`op_store_initcode`] left-pads a single word instead, which caps it at 32 bytes; the
/// dispatch runtime is larger than that.
pub(super) fn op_store_bytes(data: &[u8]) -> (Vec<u8>, u8, u8) {
    assert!(data.len() <= 255, "memory offsets and sizes are pushed as a single byte");

    let mut code = Vec::new();
    for (index, chunk) in data.chunks(32).enumerate() {
        let mut word = [0u8; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        code.extend(push(&word));
        code.extend(push(&[(index * 32) as u8]));
        code.push(0x52); // MSTORE
    }
    (code, 0, data.len() as u8)
}

/// Builds runtime code that dispatches on `CALLDATASIZE`: `bodies[i]` runs for a call
/// carrying `i` bytes of calldata. Every body must halt its own frame.
///
/// Keying on the argument length rather than a calldata word keeps the prologue at seven
/// bytes per selector and the callers free of ABI encoding.
pub(super) fn op_dispatch(bodies: &[Vec<u8>]) -> Vec<u8> {
    // Per selector above zero: CALLDATASIZE, PUSH1 selector, EQ, PUSH1 dest, JUMPI.
    const PROLOGUE_PER_SELECTOR: usize = 7;

    let prologue_len = PROLOGUE_PER_SELECTOR * (bodies.len() - 1);

    // Body 0 falls out of the prologue; every other body is entered through a JUMPDEST.
    let mut starts = Vec::with_capacity(bodies.len());
    let mut cursor = prologue_len;
    for (index, body) in bodies.iter().enumerate() {
        starts.push(cursor);
        cursor += body.len() + usize::from(index > 0);
    }
    assert!(cursor <= 255, "jump destinations are pushed as a single byte");

    let mut code = Vec::with_capacity(cursor);
    for (index, start) in starts.iter().enumerate().skip(1) {
        code.push(0x36); // CALLDATASIZE
        code.extend(push(&[index as u8]));
        code.push(0x14); // EQ
        code.extend(push(&[*start as u8]));
        code.push(0x57); // JUMPI
    }
    assert_eq!(code.len(), prologue_len);

    for (index, body) in bodies.iter().enumerate() {
        if index > 0 {
            code.push(0x5b); // JUMPDEST
        }
        code.extend_from_slice(body);
    }
    code
}

/// Renders the first transaction's balance changes as ordinal-ordered
/// `"<address> <old>→<new> <REASON>"` lines, prefixed with `[reverted]` when the call
/// carrying them was rolled back.
///
/// `GasRefund` and `RewardTransactionFee` are left out: the harness runs at `gas_price = 0`,
/// so both are zero-amount events that say nothing about SELFDESTRUCT.
pub(super) fn balance_change_log(
    block: &pb::sf::ethereum::r#type::v2::Block,
    labels: &[(Address, &str)],
) -> Vec<String> {
    balance_change_log_of(block.transaction_traces.first().expect("one transaction"), labels)
}

pub(super) fn balance_change_log_of(
    trx: &pb::sf::ethereum::r#type::v2::TransactionTrace,
    labels: &[(Address, &str)],
) -> Vec<String> {
    use pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let mut entries: Vec<_> = trx
        .calls
        .iter()
        .flat_map(|call| call.balance_changes.iter().map(move |change| (call, change)))
        .filter(|(_, change)| {
            !matches!(
                Reason::try_from(change.reason),
                Ok(Reason::GasRefund | Reason::RewardTransactionFee)
            )
        })
        .collect();
    entries.sort_by_key(|(_, change)| change.ordinal);

    entries
        .iter()
        .map(|(call, change)| {
            format!(
                "{}{} {}→{} {:?}",
                if call.state_reverted { "[reverted] " } else { "" },
                label(labels, &change.address),
                big(&change.old_value),
                big(&change.new_value),
                Reason::try_from(change.reason).expect("a known reason"),
            )
        })
        .collect()
}

/// Renders the first transaction's nonce, code and storage changes as ordinal-ordered lines.
/// Code is rendered by length: the scenarios deploy the same runtime everywhere, so its
/// bytes carry no information a test would assert on.
pub(super) fn state_change_log(
    block: &pb::sf::ethereum::r#type::v2::Block,
    labels: &[(Address, &str)],
) -> Vec<String> {
    let trx = block.transaction_traces.first().expect("one transaction");

    let mut entries: Vec<(u64, String)> = Vec::new();
    for call in &trx.calls {
        let reverted = if call.state_reverted { "[reverted] " } else { "" };
        for change in &call.nonce_changes {
            entries.push((
                change.ordinal,
                format!(
                    "{reverted}{} nonce {}→{}",
                    label(labels, &change.address),
                    change.old_value,
                    change.new_value
                ),
            ));
        }
        for change in &call.code_changes {
            entries.push((
                change.ordinal,
                format!(
                    "{reverted}{} code {}B→{}B",
                    label(labels, &change.address),
                    change.old_code.len(),
                    change.new_code.len()
                ),
            ));
        }
        for change in &call.storage_changes {
            entries.push((
                change.ordinal,
                format!(
                    "{reverted}{} storage {}: {}→{}",
                    label(labels, &change.address),
                    U256::from_be_slice(&change.key),
                    U256::from_be_slice(&change.old_value),
                    U256::from_be_slice(&change.new_value)
                ),
            ));
        }
    }
    entries.sort_by_key(|(ordinal, _)| *ordinal);
    entries.into_iter().map(|(_, line)| line).collect()
}

/// Labels of the calls the trace reports as self-destructed.
pub(super) fn suicided_calls(
    block: &pb::sf::ethereum::r#type::v2::Block,
    labels: &[(Address, &str)],
) -> Vec<String> {
    let trx = block.transaction_traces.first().expect("one transaction");
    trx.calls.iter().filter(|call| call.suicide).map(|call| label(labels, &call.address)).collect()
}

pub(super) fn label(labels: &[(Address, &str)], raw: &[u8]) -> String {
    let address = Address::from_slice(raw);
    labels
        .iter()
        .find(|(candidate, _)| *candidate == address)
        .map_or_else(|| address.to_string(), |(_, name)| (*name).to_string())
}

pub(super) fn big(value: &Option<pb::sf::ethereum::r#type::v2::BigInt>) -> U256 {
    value.as_ref().map_or(U256::ZERO, |value| U256::from_be_slice(&value.bytes))
}
