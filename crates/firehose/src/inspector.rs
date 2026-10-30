use alloy_primitives::{Address, Bytes, Log as AlloyLog, B256, KECCAK256_EMPTY, U256};
use evm2::{
    evm::{AccountInfo, DynDatabase as _, JournalEntry, SYSTEM_MAX_SSTORES_PER_CALL},
    interpreter::{InstrStop, Interpreter, Message, MessageKind, MessageResult, Word},
    version::GasId,
    Evm, EvmTypes, Inspector,
};
use firehose_tracer::{
    pb::sf::ethereum::r#type::v2::balance_change::Reason,
    types::{Opcode, StringError},
};
use std::{
    cell::{RefCell, RefMut},
    collections::{HashMap, HashSet},
    fmt::Debug,
    ops::DerefMut,
    rc::Rc,
    sync::LazyLock,
};

use crate::block_tracer::GlobalTracerGuard;

/// The largest preimage, in bytes, recorded in `Call.keccak_preimages`. The map exists so a
/// consumer can walk a storage slot back to the expression that produced it, and Solidity's slot
/// derivations are all small: 32 bytes for a dynamic array or a long `bytes`/`string`, 64 bytes
/// for a mapping with a value-type key (one level per nesting), and 32 bytes plus the key for a
/// `mapping(string => V)` or `mapping(bytes => V)`. 256 bytes covers those with room for a
/// 224-byte dynamic key. Anything larger is contract-level hashing, not slot derivation, and is
/// dropped rather than truncated: a truncated preimage does not hash back to its key and would be
/// worse than no entry at all.
const MAX_KECCAK_PREIMAGE_SIZE: usize = 256;

/// The EIP-8037 state-gas reservoir of a system call, sized for
/// [`SYSTEM_MAX_SSTORES_PER_CALL`] new slots at Amsterdam's state gas price.
///
/// Geth reports a system call's gas as its regular limit plus this reservoir in every fork. evm2
/// keeps the reservoir out of the message's regular gas, and only grants it from Amsterdam on.
static SYSTEM_CALL_STATE_GAS_RESERVOIR: LazyLock<u64> = LazyLock::new(|| {
    let params = &evm2::Version::new(evm2::SpecId::AMSTERDAM).gas_params;
    params.get(GasId::SstoreSetState) * SYSTEM_MAX_SSTORES_PER_CALL
});

/// Gas-fee parameters for the post-transaction `GasRefund` and `RewardTransactionFee` balance
/// changes of one transaction.
///
/// [`PostTxGasAccounting::ethereum`] reproduces Ethereum: unused gas is refunded at the effective
/// gas price and the beneficiary is credited the priority fee of every consumed gas unit, the base
/// fee being burned. Chains that price gas differently (a base fee that is not burned, a data fee
/// credited to the beneficiary, gas paid in something other than the native balance) return their
/// own values from [`crate::PostTxExtras::gas_accounting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostTxGasAccounting {
    /// Wei refunded to the sender per unit of unused gas.
    pub refund_gas_price: u128,
    /// Wei credited to the beneficiary per unit of consumed gas.
    pub reward_gas_price: u128,
    /// Wei credited to the beneficiary on top of `reward_gas_price * gas_used`, in the same
    /// `RewardTransactionFee` change.
    pub extra_reward: U256,
}

impl PostTxGasAccounting {
    /// Ethereum accounting for a transaction paying `effective_gas_price` in a block whose base
    /// fee is `base_fee` (0 before London).
    pub const fn ethereum(effective_gas_price: u128, base_fee: u64) -> Self {
        Self {
            refund_gas_price: effective_gas_price,
            reward_gas_price: effective_gas_price.saturating_sub(base_fee as u128),
            extra_reward: U256::ZERO,
        }
    }

    /// Accounting for a transaction that moves no native balance for gas.
    pub const fn none() -> Self {
        Self { refund_gas_price: 0, reward_gas_price: 0, extra_reward: U256::ZERO }
    }
}

/// The transaction fields [`FirehoseInspector::trace_frameless_root_call`] needs to trace the
/// root call evm2 never opened.
#[derive(Debug, Clone)]
pub struct FramelessTx {
    /// Whether the transaction is a call (and to whom) or a contract creation.
    pub kind: alloy_primitives::TxKind,
    /// Value the transaction would have transferred.
    pub value: U256,
    /// Calldata, or the init code of a creation.
    pub input: Bytes,
    /// Nonce the transaction was sent with.
    pub nonce: u64,
    /// Regular gas the root frame would have been handed: the transaction gas limit less its
    /// intrinsic cost, capped at the transaction gas limit cap (the part above it goes to the
    /// EIP-8037 state gas reservoir instead).
    pub root_gas_limit: u64,
}

/// Captures execution traces for the Firehose format.
///
/// It is installed on the evm2 EVM as its [`Inspector`] and builds the call tree, state changes
/// and logs of each transaction and system call. The block tracer and the block executor wrapper
/// keep clones to drive the block and transaction lifecycle (`on_tx_start`, post-transaction
/// balance changes, `on_tx_end`, `on_block_end`): all clones share one state, because evm2 cannot
/// hand back an installed inspector by type.
///
/// The inspector owns the tracer handle `G`, so it is `'static` whenever `G` is, as the global
/// tracer's [`GlobalTracerGuard`] is. The handle is released when the last clone is dropped.
pub struct FirehoseInspector<G = GlobalTracerGuard>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    state: Rc<RefCell<InspectorState<G>>>,
}

impl<G: DerefMut<Target = firehose_tracer::Tracer>> Clone for FirehoseInspector<G> {
    fn clone(&self) -> Self {
        Self { state: Rc::clone(&self.state) }
    }
}

impl<G: DerefMut<Target = firehose_tracer::Tracer>> Debug for FirehoseInspector<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.borrow();
        f.debug_struct("FirehoseInspector")
            .field("journal_processed_up_to", &state.journal_processed_up_to)
            .field("pending_value_transfer", &state.pending_value_transfer)
            .field("selfdestruct_candidates", &state.selfdestruct_candidates)
            .finish()
    }
}

struct StepContext {
    gas: u64,
    opcode: u8,
    /// For KECCAK256: preimage captured in `step` (where the stack still holds offset/size),
    /// emitted from `step_end` only when the opcode did not halt. Mirrors Geth's firehose
    /// tracer, which hooks the opcode body after the gas charge and so emits no preimage
    /// when KECCAK256 fails (e.g. OOG on memory expansion).
    keccak_preimage: Option<(B256, Vec<u8>)>,
}

/// Pre-destruction state for a self-destructed account, captured at root call exit.
struct SelfdestructCleanupEntry {
    address: Address,
    nonce: u64,
    code_hash: B256,
    code: Bytes,
}

/// How balance changes found in the journal are attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Window {
    /// Value transfers of a call or create.
    Transfer,
    /// The account creation of a CREATE frame: Geth emits the creator and created-contract nonce
    /// changes before the endowment transfer.
    Create,
    /// The balance moves of a SELFDESTRUCT.
    Selfdestruct,
}

struct InspectorState<G> {
    tracer: G,

    /// The opcode running between `step` and `step_end`.
    last_step: Option<StepContext>,

    /// Index into the transaction journal up to which entries have been emitted.
    ///
    /// evm2 truncates the journal when a frame fails, so this is clamped down to the journal
    /// length at every scan.
    journal_processed_up_to: usize,

    /// Attribution of the entries the next scan finds.
    window: Window,

    /// Set by `call` for a self-transfer (CALL with caller == target and value > 0). evm2's
    /// `transfer` journals no balance change for it, but Geth reports the debit-then-credit pair,
    /// so it is synthesized when the frame starts or completes without running code.
    pending_self_transfer: Option<(Address, U256)>,

    /// Value transfer `(from, to, value)` of the current non-self call, captured at call enter
    /// and cleared once the scan emitted it. If it survives to `call_end`, the call failed and
    /// evm2 rolled the transfer back before any hook saw it (a precompile that failed); Geth
    /// records the transfer that happened before the revert, so `call_end` re-emits it.
    pending_value_transfer: Option<(Address, Address, U256)>,

    /// Contracts that executed SELFDESTRUCT this transaction. A candidate whose frame reverted
    /// is still in the set; [`InspectorState::capture_selfdestruct_cleanup`] keeps only the
    /// accounts still marked destroyed at root exit.
    selfdestruct_candidates: HashSet<Address>,

    /// Nonce/code state of self-destructed accounts, emitted after the post-transaction balance
    /// changes to match Geth's `Finalise` ordering.
    pending_selfdestruct_cleanups: Vec<SelfdestructCleanupEntry>,

    /// Balances at the end of the root frame (after its rollback, before gas refund and
    /// beneficiary reward) of every account the transaction touched. Read by the post-transaction
    /// balance changes and by chain-specific extras.
    post_exec_balances: HashMap<Address, U256>,

    /// Creation nonce bump of the sender of a CREATE transaction. evm2 bumps it with the other
    /// pre-execution changes, Geth inside the root call, so it is held until `on_call_enter`.
    deferred_creator_nonce: Option<(Address, u64)>,

    /// Override for the reason of the depth-0 sender balance change, see
    /// [`FirehoseInspector::set_root_balance_reason`].
    root_balance_reason_override: Option<Reason>,

    /// Logs emitted by earlier transactions of the block, to derive each log's block index.
    log_block_index: u32,

    /// Whether the current transaction opened its root frame. Cleared by
    /// [`FirehoseInspector::start_transaction`], set by the depth-0 frame hook and consumed by
    /// [`FirehoseInspector::trace_frameless_root_call`].
    root_frame_entered: bool,
}

impl<G: DerefMut<Target = firehose_tracer::Tracer>> FirehoseInspector<G> {
    /// Creates an inspector emitting into `tracer`.
    pub fn new(tracer: G) -> Self {
        Self {
            state: Rc::new(RefCell::new(InspectorState {
                tracer,
                last_step: None,
                journal_processed_up_to: 0,
                window: Window::Transfer,
                pending_self_transfer: None,
                pending_value_transfer: None,
                selfdestruct_candidates: HashSet::new(),
                pending_selfdestruct_cleanups: Vec::new(),
                post_exec_balances: HashMap::new(),
                deferred_creator_nonce: None,
                root_balance_reason_override: None,
                log_block_index: 0,
                root_frame_entered: false,
            })),
        }
    }

    /// Returns the tracer, for the lifecycle events the executor emits itself (`on_tx_start`,
    /// `on_tx_end`, system call boundaries).
    ///
    /// Panics when called from inside an inspector hook.
    pub fn tracer_mut(&self) -> RefMut<'_, firehose_tracer::Tracer> {
        RefMut::map(self.state.borrow_mut(), |state| &mut *state.tracer)
    }

    /// Override the reason for the depth-0 root-call sender balance change of the next
    /// transaction. Single-shot: the override is consumed when the depth-0 hook fires.
    ///
    /// Defaults to `GasBuy`. The OP Stack flags deposit transactions as `IncreaseMint`: their
    /// depth-0 change is the minted credit, not a gas buy.
    pub fn set_root_balance_reason(&self, reason: Reason) {
        self.state.borrow_mut().root_balance_reason_override = Some(reason);
    }

    /// Resets the per-transaction state that must not carry over from whatever ran before in the
    /// block, a system call included. Call right before a transaction executes.
    pub fn start_transaction(&self) {
        let mut state = self.state.borrow_mut();
        state.root_frame_entered = false;
        state.post_exec_balances.clear();
    }

    /// Whether the current transaction opened its root frame, see
    /// [`Self::trace_frameless_root_call`].
    pub fn root_frame_entered(&self) -> bool {
        self.state.borrow().root_frame_entered
    }

    /// Balance of `address` at the end of the current transaction's root frame, before gas refund
    /// and beneficiary reward, or `None` when the transaction did not touch it.
    ///
    /// Chain-specific post-transaction extras use it as the `old_balance` of their credits, so an
    /// account drained during execution (an OP Stack fee vault withdrawal) reports the drained
    /// balance rather than the stale pre-transaction one.
    pub fn post_exec_balance(&self, address: Address) -> Option<U256> {
        self.state.borrow().post_exec_balances.get(&address).copied()
    }

    /// Traces the root call of a transaction evm2 included without ever opening a frame, and
    /// returns whether it did. A no-op for a transaction whose root frame ran.
    ///
    /// Under Amsterdam, EIP-2780 moves the state-dependent charges (EIP-8037 state gas for a
    /// created or newly funded account, the cold load of a delegation target) to a runtime phase
    /// that runs after the intrinsic check but before the first frame. When that phase runs out
    /// of gas, evm2 includes the transaction as an out-of-gas halt without entering execution and
    /// no inspector hook fires: the gas buy stands and the sender nonce is bumped. Left alone, the
    /// tracer would see a transaction with no call, which it treats as a bad block.
    ///
    /// The root call is traced as if the frame had been entered with `tx.root_gas_limit` and run
    /// out of gas at once: the gas buy and the nonce bump, then a failed call that consumed all of
    /// its gas. `gas_buy_cost` is what the sender was charged upfront, blob fee included, and
    /// `pre_tx_balance` the sender's balance before it.
    pub fn trace_frameless_root_call(
        &self,
        sender: Address,
        gas_buy_cost: U256,
        tx: FramelessTx,
        pre_tx_balance: U256,
    ) -> bool {
        let mut state = self.state.borrow_mut();
        if std::mem::take(&mut state.root_frame_entered) {
            return false;
        }

        let post_gas_buy_balance = pre_tx_balance.saturating_sub(gas_buy_cost);
        state.post_exec_balances.insert(sender, post_gas_buy_balance);
        let reason = state.root_balance_reason_override.take().unwrap_or(Reason::GasBuy);
        state.tracer.on_balance_change(sender, pre_tx_balance, post_gas_buy_balance, reason);
        state.tracer.on_nonce_change(sender, tx.nonce, tx.nonce + 1);

        let (call_type, target) = match tx.kind {
            alloy_primitives::TxKind::Create => (Opcode::Create as u8, sender.create(tx.nonce)),
            alloy_primitives::TxKind::Call(to) => (Opcode::Call as u8, to),
        };
        state.tracer.on_call_enter(
            0,
            call_type,
            sender,
            target,
            &tx.input,
            tx.root_gas_limit,
            tx.value,
        );
        let err = failure_reason(InstrStop::OutOfGas, tx.kind.is_create());
        state.tracer.on_call_exit(
            0,
            &[],
            tx.root_gas_limit,
            Some(&err as &dyn std::error::Error),
            true,
        );

        true
    }

    /// Emits the post-execution balance changes of a transaction: the gas refund to the sender and
    /// the fee reward to the beneficiary, then the nonce and code cleanup of the accounts it
    /// self-destructed.
    ///
    /// evm2 settles gas after the root frame returned, with no inspector hook, so the changes are
    /// derived here from the gas accounting rules. The refund is `(gas_limit - gas_used) *
    /// accounting.refund_gas_price` and the reward `gas_used * accounting.reward_gas_price +
    /// accounting.extra_reward`; each is only emitted when non-zero. The starting balances are the
    /// root-exit balances captured by the inspector, falling back to `pre_tx_balance` for an
    /// account the transaction did not touch.
    ///
    /// Must be called after the transaction executed and before it is committed.
    #[expect(clippy::too_many_arguments)]
    pub fn process_post_tx_gas_accounting(
        &self,
        sender: Address,
        coinbase: Address,
        gas_limit: u64,
        gas_used: u64,
        accounting: PostTxGasAccounting,
        committed_log_count: u32,
        mut pre_tx_balance: impl FnMut(Address) -> U256,
    ) {
        let mut state = self.state.borrow_mut();
        let remaining_gas = gas_limit.saturating_sub(gas_used);
        let refund_amount = U256::from(remaining_gas) * U256::from(accounting.refund_gas_price);

        let sender_balance = state
            .post_exec_balances
            .get(&sender)
            .copied()
            .unwrap_or_else(|| pre_tx_balance(sender));
        if remaining_gas > 0 {
            state.tracer.on_balance_change(
                sender,
                sender_balance,
                sender_balance + refund_amount,
                Reason::GasRefund,
            );
        }

        let reward_amount = (U256::from(gas_used) * U256::from(accounting.reward_gas_price))
            .saturating_add(accounting.extra_reward);
        if !reward_amount.is_zero() {
            let coinbase_balance = if sender == coinbase {
                sender_balance + refund_amount
            } else {
                state
                    .post_exec_balances
                    .get(&coinbase)
                    .copied()
                    .unwrap_or_else(|| pre_tx_balance(coinbase))
            };
            state.tracer.on_balance_change(
                coinbase,
                coinbase_balance,
                coinbase_balance + reward_amount,
                Reason::RewardTransactionFee,
            );
        }

        // Geth's `Finalise` resets destroyed accounts after the gas refund and the reward.
        let cleanups = std::mem::take(&mut state.pending_selfdestruct_cleanups);
        for entry in cleanups {
            if entry.nonce > 0 {
                state.tracer.on_nonce_change(entry.address, entry.nonce, 0);
            }
            if entry.code_hash != KECCAK256_EMPTY {
                state.tracer.on_code_change(
                    entry.address,
                    entry.code_hash,
                    KECCAK256_EMPTY,
                    entry.code.as_ref(),
                    &[],
                );
            }
        }

        state.selfdestruct_candidates.clear();
        state.journal_processed_up_to = 0;
        // Only logs that survived reverts count towards the next transaction's log indexes.
        state.log_block_index += committed_log_count;
    }
}

impl<G: DerefMut<Target = firehose_tracer::Tracer>> InspectorState<G> {
    /// Emits the journal entries appended since the last scan, attributing balance changes per
    /// [`Self::window`].
    fn process_journal<T: EvmTypes>(&mut self, host: &mut Evm<'_, T>) {
        let len = host.state().journal().len();
        if self.journal_processed_up_to > len {
            self.journal_processed_up_to = len;
        }
        if self.journal_processed_up_to == len {
            return;
        }
        let entries = host.state().journal()[self.journal_processed_up_to..len].to_vec();
        self.journal_processed_up_to = len;

        let changes = resolve_changes(host, &entries);
        let changes = if self.window == Window::Create {
            // Nonce changes first, then the rest in journal order.
            let (nonces, rest): (Vec<_>, Vec<_>) =
                changes.into_iter().partition(|change| matches!(change, Change::Nonce { .. }));
            nonces.into_iter().chain(rest).collect()
        } else {
            changes
        };

        for change in changes {
            self.emit(change);
        }
    }

    /// Drops the journal entries appended since the last scan without emitting them.
    fn skip_journal<T: EvmTypes>(&mut self, host: &Evm<'_, T>) {
        self.journal_processed_up_to = host.state().journal().len();
    }

    fn emit(&mut self, change: Change) {
        match change {
            Change::Balance { address, old, new } => {
                let reason = match self.window {
                    Window::Transfer | Window::Create => Reason::Transfer,
                    Window::Selfdestruct if new < old => Reason::SuicideWithdraw,
                    Window::Selfdestruct => Reason::SuicideRefund,
                };
                // The credit is the second half of the pending transfer: once it is emitted, the
                // transfer no longer needs synthesizing at call exit.
                if self.window == Window::Transfer &&
                    let Some((_, to, value)) = self.pending_value_transfer &&
                    address == to &&
                    new.saturating_sub(old) == value
                {
                    self.pending_value_transfer = None;
                }
                self.tracer.on_balance_change(address, old, new, reason);
            }
            Change::Nonce { address, old, new } => self.tracer.on_nonce_change(address, old, new),
            Change::Code { address, old_hash, new_hash, old_code, new_code } => {
                self.tracer.on_code_change(address, old_hash, new_hash, &old_code, &new_code)
            }
            Change::Storage { address, key, old, new } => self.tracer.on_storage_change(
                address,
                B256::from(key.to_be_bytes::<32>()),
                B256::from(old.to_be_bytes::<32>()),
                B256::from(new.to_be_bytes::<32>()),
            ),
        }
    }

    /// Emits the pre-execution changes of a transaction before its root call opens: the gas buy
    /// and the sender nonce bump, then the EIP-7702 authorizations.
    ///
    /// evm2 journals them in its own order (nonce bump, gas buy, authorizations); Geth emits the
    /// gas buy first. For a CREATE transaction the sender nonce bump is held until the root call
    /// opened, where Geth's `create` emits it.
    fn process_pre_execution<T: EvmTypes>(
        &mut self,
        host: &mut Evm<'_, T>,
        sender: Address,
        is_create: bool,
    ) {
        let entries = host.state().journal().to_vec();
        self.journal_processed_up_to = entries.len();
        let changes = resolve_changes(host, &entries);

        let gas_buy = changes.iter().position(
            |change| matches!(change, Change::Balance { address, .. } if *address == sender),
        );
        let sender_nonce = changes.iter().position(
            |change| matches!(change, Change::Nonce { address, .. } if *address == sender),
        );

        let reason = self.root_balance_reason_override.take().unwrap_or(Reason::GasBuy);
        if let Some(Change::Balance { address, old, new }) = gas_buy.map(|index| &changes[index]) {
            self.tracer.on_balance_change(*address, *old, *new, reason);
        }
        if let Some(Change::Nonce { address, old, .. }) = sender_nonce.map(|index| &changes[index])
        {
            if is_create {
                self.deferred_creator_nonce = Some((*address, *old));
            } else {
                self.tracer.on_nonce_change(*address, *old, *old + 1);
            }
        }
        for (index, change) in changes.into_iter().enumerate() {
            if Some(index) != gas_buy && Some(index) != sender_nonce {
                self.emit(change);
            }
        }
    }

    /// Snapshots, at root frame exit, the balances the post-transaction changes start from and the
    /// destroyed accounts to clean up.
    fn capture_root_exit<T: EvmTypes>(&mut self, host: &mut Evm<'_, T>, sender: Address) {
        let mut addresses: Vec<Address> = host
            .state()
            .journal()
            .iter()
            .filter_map(|entry| match entry {
                JournalEntry::AccountChange { address, .. } => Some(*address),
                _ => None,
            })
            .collect();
        addresses.push(sender);
        addresses.push(host.block().beneficiary);
        for address in addresses {
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.post_exec_balances.entry(address)
            {
                let balance = account_info(host, &address).balance;
                entry.insert(balance);
            }
        }

        self.capture_selfdestruct_cleanup(host);
    }

    /// Records the nonce and code of the accounts still destroyed at root exit, in ascending
    /// address order like Geth's `Finalise`. A candidate whose SELFDESTRUCT was reverted is no
    /// longer destroyed and is skipped.
    fn capture_selfdestruct_cleanup<T: EvmTypes>(&mut self, host: &mut Evm<'_, T>) {
        let mut candidates: Vec<Address> = self.selfdestruct_candidates.iter().copied().collect();
        candidates.sort_unstable();
        for address in candidates {
            let destroyed =
                host.state_mut().account(&address).is_ok_and(|account| account.is_destructed());
            if !destroyed {
                continue;
            }
            let info = account_info(host, &address);
            let code = load_code(host, &info);
            self.pending_selfdestruct_cleanups.push(SelfdestructCleanupEntry {
                address,
                nonce: info.nonce,
                code_hash: info.code_hash,
                code,
            });
        }
    }

    /// Emits the debit-then-credit pair Geth reports for a self-transfer, which leaves the balance
    /// unchanged.
    fn emit_self_transfer<T: EvmTypes>(
        &mut self,
        host: &mut Evm<'_, T>,
        address: Address,
        value: U256,
    ) {
        let current = account_info(host, &address).balance;
        let intermediate = current.saturating_sub(value);
        self.tracer.on_balance_change(address, current, intermediate, Reason::Transfer);
        self.tracer.on_balance_change(address, intermediate, current, Reason::Transfer);
    }

    fn enter_frame<T: EvmTypes>(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &Message<T>,
    ) {
        let host = interp.host();
        let depth = frame_depth(host, message);
        let is_create = matches!(message.kind, MessageKind::Create | MessageKind::Create2);

        if depth == 0 {
            // The journal belongs to the transaction or system call this root frame opens, so it
            // holds only its pre-execution changes.
            self.root_frame_entered = true;
            self.window = Window::Transfer;
            self.process_pre_execution(host, message.caller, is_create);
        } else {
            self.process_journal(host);
        }

        let (call_type, from, to) = match message.kind {
            MessageKind::StaticCall => (Opcode::StaticCall, message.caller, message.call_target),
            // The issuing contract calls into the requested callee.
            MessageKind::DelegateCall => {
                (Opcode::DelegateCall, message.destination, message.call_target)
            }
            MessageKind::CallCode => (Opcode::CallCode, message.caller, message.call_target),
            MessageKind::Create => (Opcode::Create, message.caller, message.destination),
            MessageKind::Create2 => (Opcode::Create2, message.caller, message.destination),
            // `MessageKind::Call`, and any call kind evm2 adds later.
            _ => (Opcode::Call, message.caller, message.call_target),
        };
        let gas_limit = if depth == 0 && self.tracer.is_in_system_call() {
            message.gas_limit + *SYSTEM_CALL_STATE_GAS_RESERVOIR
        } else {
            message.gas_limit
        };
        self.tracer.on_call_enter(
            depth,
            call_type as u8,
            from,
            to,
            &message.input,
            gas_limit,
            message.value,
        );

        // EIP-7702: the code of a delegated callee is resolved from its delegation target.
        if !is_create && message.code_address != message.call_target {
            self.tracer.set_current_call_address_delegates_to(message.code_address);
        }

        if let Some((address, old)) = self.deferred_creator_nonce.take() {
            self.tracer.on_nonce_change(address, old, old + 1);
        }

        self.window = if is_create { Window::Create } else { Window::Transfer };
        // CALLCODE and DELEGATECALL move no value, and STATICCALL carries none.
        if message.kind == MessageKind::Call && !message.value.is_zero() {
            if message.caller == message.destination {
                self.pending_self_transfer = Some((message.caller, message.value));
            } else {
                self.pending_value_transfer =
                    Some((message.caller, message.destination, message.value));
            }
        }
    }

    fn exit_frame<T: EvmTypes>(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &Message<T>,
        result: &MessageResult<T>,
    ) {
        let host = interp.host();
        let depth = frame_depth(host, message);
        let is_create = matches!(message.kind, MessageKind::Create | MessageKind::Create2);

        // Changes of a frame that ran no opcode (a precompile, an account without code), and the
        // code deposit of a successful create.
        self.process_journal(host);
        self.window = Window::Transfer;

        if let Some((address, value)) = self.pending_self_transfer.take() &&
            result.stop.is_success()
        {
            self.emit_self_transfer(host, address, value);
        }

        // A transfer still pending was rolled back before any hook could see it. It happened
        // unless the call aborted before transferring.
        if let Some((from, to, value)) = self.pending_value_transfer.take() &&
            !matches!(result.stop, InstrStop::OutOfFunds | InstrStop::CallTooDeep)
        {
            let from_balance = account_info(host, &from).balance;
            let to_balance = account_info(host, &to).balance;
            self.tracer.on_balance_change(
                from,
                from_balance,
                from_balance.saturating_sub(value),
                Reason::Transfer,
            );
            self.tracer.on_balance_change(
                to,
                to_balance,
                to_balance.saturating_add(value),
                Reason::Transfer,
            );
        }

        let failed = !result.stop.is_success();
        let is_revert = result.stop.is_revert();
        let err = failed.then(|| failure_reason(result.stop, is_create));
        let gas_used = frame_gas_consumed(message.gas_limit, &result.gas, failed, is_revert);

        if depth == 0 {
            self.capture_root_exit(host, message.caller);
        }

        self.tracer.on_call_exit(
            depth,
            result.output.as_ref(),
            gas_used,
            err.as_ref().map(|e| e as &dyn std::error::Error),
            failed,
        );
    }
}

impl<T: EvmTypes, G: DerefMut<Target = firehose_tracer::Tracer>> Inspector<T>
    for FirehoseInspector<G>
{
    fn initialize_interp(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        let mut state = self.state.borrow_mut();
        // The frame's value transfer and account creation happened after `call`/`create` and
        // before the first opcode.
        state.process_journal(interp.host());
        state.window = Window::Transfer;
        if let Some((address, value)) = state.pending_self_transfer.take() {
            state.emit_self_transfer(interp.host(), address, value);
        }
    }

    fn step(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        let mut state = self.state.borrow_mut();
        let opcode = interp.opcode();
        let gas = interp.gas().remaining();

        // SELFDESTRUCT is reported from `step_end`, once it is known whether it ran: the tracer
        // marks the call as self-destructed as soon as it is told the opcode runs.
        if opcode == Opcode::SelfDestruct as u8 {
            state.window = Window::Selfdestruct;
        } else {
            state.tracer.on_opcode(interp.pc() as u64, opcode, gas, 0, &[], 0, None);
        }

        let keccak_preimage =
            (opcode == Opcode::Keccak256 as u8).then(|| keccak256_preimage(interp)).flatten();
        state.last_step = Some(StepContext { gas, opcode, keccak_preimage });
    }

    fn step_end(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        let mut state = self.state.borrow_mut();
        let Some(step) = state.last_step.take() else { return };
        let halted = matches!(interp.result(), Err(stop) if !stop.is_success());

        // A halted opcode's writes are rolled back with its frame, and Geth, which charges gas
        // before running the opcode body, never reports them. evm2's SSTORE journals the write
        // before charging its dynamic gas.
        if halted {
            state.skip_journal(interp.host());
        } else {
            state.process_journal(interp.host());
        }

        if let Some((hash, preimage)) = step.keccak_preimage &&
            !halted
        {
            state.tracer.on_keccak_preimage(hash, &preimage);
        }

        if step.opcode == Opcode::SelfDestruct as u8 {
            state.window = Window::Transfer;
            // Only `SelfDestruct` means the account was destroyed: a chain may replace the opcode
            // with an undefined instruction, and an out-of-gas halt must not mark the call.
            match interp.result() {
                Err(InstrStop::SelfDestruct) => {
                    state.tracer.on_opcode(0, step.opcode, step.gas, 0, &[], 0, None);
                }
                result => {
                    let err = match result {
                        Err(stop) => failure_reason(stop, false),
                        Ok(()) => StringError("selfdestruct did not run".to_string()),
                    };
                    state.tracer.on_opcode(0, step.opcode, step.gas, 0, &[], 0, Some(&err));
                }
            }
        }
    }

    fn log(&mut self, log: &AlloyLog, host: &mut Evm<'_, T>) {
        let mut state = self.state.borrow_mut();
        // The state change a log describes (an EIP-7708 transfer) comes before it, except for
        // SELFDESTRUCT: Geth emits its transfer log before moving the balance, which the
        // `selfdestruct` hook then reports.
        if state.window != Window::Selfdestruct {
            state.process_journal(host);
        }
        // evm2 notifies the inspector before recording the log, and truncates the recorded logs
        // when a frame fails, so the count is this log's index in the transaction.
        let block_index = host.logs().len() as u32 + state.log_block_index;
        state.tracer.on_log(log.address, log.topics(), &log.data.data, block_index);
    }

    fn call(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &mut Message<T>,
    ) -> Option<MessageResult<T>> {
        self.state.borrow_mut().enter_frame(interp, message);
        None
    }

    fn call_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &Message<T>,
        result: &mut MessageResult<T>,
    ) {
        self.state.borrow_mut().exit_frame(interp, message, result);
    }

    fn create(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &mut Message<T>,
    ) -> Option<MessageResult<T>> {
        self.state.borrow_mut().enter_frame(interp, message);
        None
    }

    fn create_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, T>,
        message: &Message<T>,
        result: &mut MessageResult<T>,
    ) {
        self.state.borrow_mut().exit_frame(interp, message, result);
    }

    fn selfdestruct(
        &mut self,
        contract: &Address,
        target: &Address,
        value: &U256,
        host: &mut Evm<'_, T>,
    ) {
        let mut state = self.state.borrow_mut();
        state.selfdestruct_candidates.insert(*contract);
        state.process_journal(host);
        // Geth models SELFDESTRUCT as a nested call. on_call_enter with SELFDESTRUCT sets the
        // tracer's suicide flag and on_call_exit clears it; the depth is not used.
        state.tracer.on_call_enter(
            1,
            Opcode::SelfDestruct as u8,
            *contract,
            *target,
            &[],
            0,
            *value,
        );
        state.tracer.on_call_exit(1, &[], 0, None, false);
    }
}

/// A state change resolved from the journal.
enum Change {
    Balance { address: Address, old: U256, new: U256 },
    Nonce { address: Address, old: u64, new: u64 },
    Code { address: Address, old_hash: B256, new_hash: B256, old_code: Bytes, new_code: Bytes },
    Storage { address: Address, key: Word, old: Word, new: Word },
}

/// Resolves journal entries into state changes, in journal order.
///
/// An entry only records the previous value. The new value is the previous value of the next entry
/// for the same account or slot, or the transaction overlay when there is none. An account entry
/// yields its nonce change, then its code change, then its balance change: the order Geth emits an
/// EIP-7702 authorization in.
fn resolve_changes<T: EvmTypes>(host: &mut Evm<'_, T>, entries: &[JournalEntry]) -> Vec<Change> {
    let mut changes = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            JournalEntry::AccountChange { address, previous, .. } => {
                let next = entries[index + 1..].iter().find_map(|later| match later {
                    JournalEntry::AccountChange { address: a, previous, .. } if a == address => {
                        Some(previous.clone().unwrap_or_default())
                    }
                    _ => None,
                });
                let new = next.unwrap_or_else(|| account_info(host, address));
                let old = previous.clone().unwrap_or_default();

                if old.nonce != new.nonce {
                    changes.push(Change::Nonce {
                        address: *address,
                        old: old.nonce,
                        new: new.nonce,
                    });
                }
                if old.code_hash != new.code_hash {
                    changes.push(Change::Code {
                        address: *address,
                        old_hash: old.code_hash,
                        new_hash: new.code_hash,
                        old_code: load_code(host, &old),
                        new_code: load_code(host, &new),
                    });
                }
                if old.balance != new.balance {
                    changes.push(Change::Balance {
                        address: *address,
                        old: old.balance,
                        new: new.balance,
                    });
                }
            }
            JournalEntry::StorageChange { address, key, previous } => {
                let next = entries[index + 1..].iter().find_map(|later| match later {
                    JournalEntry::StorageChange { address: a, key: k, previous }
                        if a == address && k == key =>
                    {
                        Some(*previous)
                    }
                    _ => None,
                });
                let new = next.unwrap_or_else(|| {
                    host.state_mut().storage_slot_untracked(address, key).unwrap_or_default()
                });
                changes.push(Change::Storage { address: *address, key: *key, old: *previous, new });
            }
            _ => {}
        }
    }
    changes
}

/// The account as the transaction overlay currently holds it, an absent account reading as empty.
fn account_info<T: EvmTypes>(host: &mut Evm<'_, T>, address: &Address) -> AccountInfo {
    host.state_mut().account_info_untracked(address).ok().flatten().unwrap_or_default()
}

fn load_code<T: EvmTypes>(host: &mut Evm<'_, T>, info: &AccountInfo) -> Bytes {
    if info.code_hash == KECCAK256_EMPTY {
        return Bytes::new();
    }
    if let Some(code) = &info.code &&
        !code.is_empty()
    {
        return code.original_bytes();
    }
    host.state_mut()
        .overlay_db_mut()
        .get_code_by_hash(&info.code_hash)
        .map(|code| code.original_bytes())
        .unwrap_or_default()
}

/// Call depth of a message as Firehose counts it, 0 for the root call.
fn frame_depth<T: EvmTypes>(host: &Evm<'_, T>, message: &Message<T>) -> i32 {
    i32::from(message.depth) - i32::from(host.version().initial_call_depth)
}

/// Captures the KECCAK256 input from the interpreter before the opcode runs.
///
/// `step` fires before memory is resized, so the region may not be allocated yet. Like Geth's
/// `Memory.GetPtr`, bytes beyond the current memory are zero.
fn keccak256_preimage<T: EvmTypes>(interp: &Interpreter<'_, '_, T>) -> Option<(B256, Vec<u8>)> {
    let stack = interp.stack();
    let (Some(offset), Some(size)) = (stack.peek(0), stack.peek(1)) else { return None };

    let len = size.saturating_to::<usize>();
    if len > MAX_KECCAK_PREIMAGE_SIZE {
        return None;
    }
    if len == 0 {
        return Some((KECCAK256_EMPTY, Vec::new()));
    }

    let offset = offset.saturating_to::<usize>();
    let memory = interp.memory();
    let mem_len = memory.len();
    if offset.checked_add(len).is_some_and(|end| end <= mem_len) {
        let preimage = memory.slice(offset, len).to_vec();
        return Some((alloy_primitives::keccak256(&preimage), preimage));
    }

    // Growing memory costs 3*w + w^2/512 gas for w words, so a region the remaining gas cannot pay
    // for halts before the opcode runs and step_end never emits it. w <= sqrt(512 * gas) bounds
    // what can execute without hashing a region that never existed.
    let gas = interp.gas().remaining() as u128;
    let max_words = (512u128.saturating_mul(gas)).isqrt();
    let max_len = max_words.saturating_mul(32).min(usize::MAX as u128) as usize;
    if len > max_len {
        return None;
    }
    let mut buf = vec![0u8; len];
    if offset < mem_len {
        let copy_len = (mem_len - offset).min(len);
        buf[..copy_len].copy_from_slice(memory.slice(offset, copy_len));
    }
    Some((alloy_primitives::keccak256(&buf), buf))
}

/// Gas charged to a frame, as its caller sees it.
///
/// evm2 settles a frame's gas before `call_end`: a halt consumed the whole regular limit, and a
/// failure already refilled the state gas it spent. Under [EIP-8037] the state gas a successful
/// frame paid from the transaction's reservoir is not part of its spent regular gas, but its
/// caller's accounting counts it, so it is added back. Before Amsterdam every state-gas term is
/// zero.
///
/// [EIP-8037]: https://eips.ethereum.org/EIPS/eip-8037
fn frame_gas_consumed(
    gas_limit: u64,
    gas: &evm2::interpreter::GasTracker,
    failed: bool,
    is_revert: bool,
) -> u64 {
    if failed && !is_revert {
        return gas_limit;
    }
    if failed {
        return gas.spent();
    }
    let from_reservoir = gas.state_gas_spent().saturating_sub_unsigned(gas.state_gas_spilled());
    gas.spent().saturating_add(from_reservoir.max(0) as u64)
}

/// Geth's error string for a failed frame.
///
/// `is_create` distinguishes the CREATE context, where an out-of-gas reads "contract creation code
/// storage out of gas", from the CALL context ("out of gas").
///
/// Geth reference: go-ethereum/core/vm/errors.go
fn failure_reason(stop: InstrStop, is_create: bool) -> StringError {
    StringError(match stop {
        InstrStop::Revert => "execution reverted".to_string(),
        InstrStop::CallTooDeep => "max call depth exceeded".to_string(),
        InstrStop::OutOfFunds => "insufficient balance for transfer".to_string(),
        InstrStop::OutOfGas |
        InstrStop::MemoryOOG |
        InstrStop::MemoryLimitOOG |
        InstrStop::PrecompileOOG |
        InstrStop::InvalidOperandOOG |
        InstrStop::ReentrancySentryOOG => {
            if is_create {
                "contract creation code storage out of gas".to_string()
            } else {
                "out of gas".to_string()
            }
        }
        InstrStop::InvalidFEOpcode => "invalid opcode: INVALID".to_string(),
        InstrStop::InvalidJump => "invalid jump destination".to_string(),
        InstrStop::StackOverflow => "stack limit reached 1024 (1023)".to_string(),
        InstrStop::StackUnderflow => "stack underflow".to_string(),
        InstrStop::CallNotAllowedInsideStatic | InstrStop::StateChangeDuringStaticCall => {
            "write protection".to_string()
        }
        InstrStop::CreateCollision => "contract address collision".to_string(),
        InstrStop::CreateContractSizeLimit => "max code size exceeded".to_string(),
        InstrStop::CreateContractStartingWithEF => {
            "invalid code: must not begin with 0xef".to_string()
        }
        InstrStop::CreateInitCodeSizeLimit => "max initcode size exceeded".to_string(),
        InstrStop::NonceOverflow => "nonce uint64 overflow".to_string(),
        // The precompile's own message is not carried by the stop reason.
        InstrStop::PrecompileError => "precompile error".to_string(),
        other => humanize_stop(other),
    })
}

/// Converts a `CamelCase` stop reason into lowercase words, e.g. `NotActivated` → `"not
/// activated"`.
fn humanize_stop(stop: InstrStop) -> String {
    let name = format!("{stop:?}");
    let mut words = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            words.push(' ');
        }
        words.push(ch.to_ascii_lowercase());
    }
    words
}

#[cfg(test)]
mod tests;
