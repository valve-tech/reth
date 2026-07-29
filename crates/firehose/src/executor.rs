//! Firehose block executor wrappers and EVM config.
//!
//! This module provides:
//!
//! * [`FirehoseWrappedExecutor`] — a thin [`BlockExecutor`] wrapper that fires Firehose tracer
//!   hooks (`on_system_call_start/end`, `on_tx_start/end`, post-tx balance changes, withdrawal
//!   balance changes) around a delegate executor. The inner executor's EVM must carry a
//!   [`FirehoseInspectorApi`]-capable inspector (i.e. a [`crate::inspector::FirehoseInspector`]).
//!
//! * [`FirehoseBlockExecutor`] — the pipeline [`Executor`] used by staged sync. It constructs a
//!   [`FirehoseWrappedExecutor`] per block and defers the end-of-block flush until the caller
//!   confirms post-execution validation succeeded.
//!
//! * [`FirehoseEvmConfig`] — a [`ConfigureEvm`] wrapper that routes `batch_executor` through
//!   [`FirehoseBlockExecutor`] while leaving every other method untouched (live path wraps the
//!   executor explicitly at its call site).
//!
//! ## Post-validation flush deferral (pipeline path)
//!
//! [`FirehoseBlockExecutor::execute_and_trace_one`] emits `on_block_start` and all mid-block
//! events, but **does not flush** (`on_block_end(None)`) until one of:
//!  * The next call to `execute_and_trace_one` — the previous block's validation already succeeded,
//!    since an error between calls would have short-circuited the batch.
//!  * [`Executor::into_state`] — the batch completed without error, so the last block is safe.
//!
//! If the executor is dropped before either, the stashed [`FirehoseBlockTracer`] is dropped,
//! which emits `on_block_end(Some(err))` and discards the block.

use std::{collections::HashMap, fmt::Debug};

use crate::{
    block_tracer::FirehoseBlockTracer, inspector::FirehoseInspectorApi, mapper,
    mapper::SignatureFields,
};
use alloy_consensus::{transaction::TxHashRef, BlockHeader, Transaction, TxReceipt};
use alloy_eip7928::BlockAccessList;
use alloy_eips::eip4895::Withdrawals;
use alloy_evm::{
    block::{BlockExecutor, CommitChanges, ExecutableTx, GasOutput},
    RecoveredTx,
};
use alloy_primitives::{Address, Log, Sealable, U256};
use reth_evm::{
    execute::{BlockExecutionError, Executor},
    ConfigureEvm, Evm as _, OnStateHook,
};
use reth_execution_types::BlockExecutionResult;
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{Block as BlockTrait, BlockBody, BlockTy, RecoveredBlock, TxTy};
use reth_revm::{
    db::states::bundle_state::BundleRetention, revm::context::Block as RevmBlock, Database as _,
    State,
};

/// Chain-specific hook that emits additional post-tx balance changes after the generic
/// gas-refund-to-sender and priority-tip-to-coinbase emissions done by the inspector.
///
/// Fired by [`FirehoseWrappedExecutor`] once per transaction, immediately after
/// [`FirehoseInspectorApi::process_post_tx_balance_changes_erased`] and before the transaction
/// is committed to the state DB. The EVM context at that point still holds the current
/// transaction in `ctx.tx()`, so implementations can read per-tx data (envelope, caller,
/// etc.) via `evm.ctx()`.
///
/// The primary use case is OP Stack: `OpHandler::reward_beneficiary` credits the BaseFeeVault,
/// L1FeeVault, and OperatorFeeVault predeploys via `Journal::balance_incr` during revm's
/// post_execution phase, which fires no inspector hooks — so those vault credits are invisible
/// to the tracer unless the chain integrator re-emits them via this hook.
///
/// Implementations typically call `evm.inspector_mut().tracer_mut().on_balance_change(...)`
/// with `Reason::RewardTransactionFee` for each crediting.
pub trait PostTxExtras<E>
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
{
    /// Emit chain-specific post-tx balance changes. `gas_used` is the post-refund gas
    /// charged to the sender; `base_fee` is the block's EIP-1559 base fee (0 pre-London).
    fn emit_post_tx_extras(&self, evm: &mut E, gas_used: u64, base_fee: u64);
}

/// No-op [`PostTxExtras`] used on Ethereum mainnet (and any chain whose fee distribution is
/// already covered by the generic sender-refund + coinbase-tip emissions).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPostTxExtras;

impl<E> PostTxExtras<E> for NoPostTxExtras
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
{
    #[inline]
    fn emit_post_tx_extras(&self, _evm: &mut E, _gas_used: u64, _base_fee: u64) {}
}

/// Chain-specific hook that patches the per-tx [`firehose_tracer::types::TxEvent`] produced by
/// the generic envelope-derived mapper before it is handed to the tracer via `on_tx_start`.
///
/// Parallel to [`PostTxExtras`] but running at a different point in the tx lifecycle: after
/// [`mapper::signed_tx_to_tx_event`] builds the event from the envelope, but before the event is
/// consumed by the tracer. At this point the DB reflects pre-tx state, so implementations can
/// read account data (nonce, code, balance) to fill in fields the envelope itself does not
/// carry.
///
/// The primary use case is OP Stack deposit transactions: [`alloy_op_consensus::TxDeposit`]
/// carries no `nonce` field on the envelope — its `Transaction::nonce()` impl returns a literal
/// `0` — so the event reaches the tracer with nonce 0. The real nonce is the sender account's
/// pre-execution nonce (post-Regolith the state transition increments it as part of the deposit).
/// Implementations fetch it via `evm.db_mut().basic(sender).nonce`.
pub trait PreTxAdjust<E>
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
{
    /// Mutate `tx_event` in place. `sender` is the recovered signer; `evm` exposes pre-tx state
    /// for DB reads. Implementations should leave the event untouched for tx types they do not
    /// care about.
    fn adjust_tx_event(
        &self,
        evm: &mut E,
        tx_event: &mut firehose_tracer::types::TxEvent,
        sender: Address,
    );
}

/// No-op [`PreTxAdjust`] used on Ethereum mainnet (and any chain whose envelope already carries
/// every field the tracer needs).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPreTxAdjust;

impl<E> PreTxAdjust<E> for NoPreTxAdjust
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
{
    #[inline]
    fn adjust_tx_event(
        &self,
        _evm: &mut E,
        _tx_event: &mut firehose_tracer::types::TxEvent,
        _sender: Address,
    ) {
    }
}

/// A [`BlockExecutor`] wrapper that fires Firehose tracer hooks around a delegate executor.
///
/// The inner executor's EVM must have been configured with a [`FirehoseInspectorApi`]-capable
/// inspector (see [`crate::inspector::FirehoseInspector`]) via `evm_with_env_and_inspector`. The
/// wrapper drives the tracer through the inspector's `tracer_mut()` handle at the following
/// points:
///
/// | Hook                               | When                                               |
/// |------------------------------------|----------------------------------------------------|
/// | `on_system_call_start/end`         | Around [`Self::apply_pre_execution_changes`] and   |
/// |                                    | around the post-execution window inside            |
/// |                                    | [`Self::finish`].                                  |
/// | `on_tx_start`                      | Before executing each transaction (in              |
/// |                                    | [`Self::execute_transaction_with_commit_condition`]).|
/// | `process_post_tx_balance_changes`  | After `execute_transaction_without_commit`,        |
/// |                                    | before `commit_transaction`.                       |
/// | `on_tx_end(Some(receipt_data))`    | After `commit_transaction`.                        |
/// | withdrawal balance changes         | After `finish()` returns, inside the wrapper's     |
/// |                                    | `finish`, so they land in `block.balance_changes`. |
///
/// The wrapper does **not** emit `on_block_start` / `on_block_end`; those are owned by the caller
/// via [`FirehoseBlockTracer::start`] / [`FirehoseBlockTracer::mark_verified`] /
/// [`FirehoseBlockTracer::mark_failed`] so they can be deferred past post-execution validation.
///
/// The `Extras` type parameter plugs in a chain-specific [`PostTxExtras`] hook that fires after
/// the generic post-tx balance accounting, used by OP Stack variants to emit `RewardTransactionFee`
/// entries for the BaseFeeVault / L1FeeVault / OperatorFeeVault predeploys. Defaults to
/// [`NoPostTxExtras`] so the wrapper remains a pure mainnet Ethereum executor by default.
///
/// The `Adjust` type parameter plugs in a chain-specific [`PreTxAdjust`] hook that can patch the
/// per-tx [`firehose_tracer::types::TxEvent`] before it is handed to the tracer, used by OP Stack
/// variants to overwrite the deposit-tx nonce (deposit envelopes carry no nonce — the effective
/// value lives on the sender account). Defaults to [`NoPreTxAdjust`].
pub struct FirehoseWrappedExecutor<Inner, Extras = NoPostTxExtras, Adjust = NoPreTxAdjust> {
    inner: Inner,
    withdrawals: Option<Withdrawals>,
    /// Beneficiary addresses for any ommer (uncle) headers in this block. Pre-merge only —
    /// empty on post-merge / post-Shanghai blocks. Used by [`Self::finish`] to emit
    /// `RewardMineUncle` balance-change events that `db.increment_balances()` otherwise
    /// applies invisibly to the inspector.
    ommer_beneficiaries: Vec<Address>,
    /// Running count of logs emitted so far in this block, used to derive each receipt's
    /// block-wide `log_index_start` when building `on_tx_end` receipt data.
    log_index: u32,
    extras: Extras,
    adjust: Adjust,
}

impl Debug for FirehoseWrappedExecutor<()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirehoseWrappedExecutor").finish()
    }
}

impl<Inner> FirehoseWrappedExecutor<Inner, NoPostTxExtras, NoPreTxAdjust> {
    /// Wraps `inner` with Firehose tracer hooks. `withdrawals` is consumed inside
    /// [`Self::finish`] to emit per-address balance changes for EIP-4895 validator withdrawals.
    /// `ommer_beneficiaries` is consumed in the same place to emit `RewardMineUncle` events.
    pub const fn new(
        inner: Inner,
        withdrawals: Option<Withdrawals>,
        ommer_beneficiaries: Vec<Address>,
    ) -> Self {
        Self {
            inner,
            withdrawals,
            ommer_beneficiaries,
            log_index: 0,
            extras: NoPostTxExtras,
            adjust: NoPreTxAdjust,
        }
    }
}

impl<Inner, Extras> FirehoseWrappedExecutor<Inner, Extras, NoPreTxAdjust> {
    /// Same as [`Self::new`] but lets the caller supply a [`PostTxExtras`] hook that fires after
    /// the generic per-tx balance accounting. Used by OP Stack variants to emit the three fee
    /// vault balance changes that are otherwise invisible to the tracer (they originate from
    /// `Journal::balance_incr` calls inside the OP handler's `reward_beneficiary`, which revm
    /// runs during post_execution with no inspector hooks).
    pub const fn with_extras(
        inner: Inner,
        withdrawals: Option<Withdrawals>,
        ommer_beneficiaries: Vec<Address>,
        extras: Extras,
    ) -> Self {
        Self {
            inner,
            withdrawals,
            ommer_beneficiaries,
            log_index: 0,
            extras,
            adjust: NoPreTxAdjust,
        }
    }
}

impl<Inner, Extras, Adjust> FirehoseWrappedExecutor<Inner, Extras, Adjust> {
    /// Like [`Self::with_extras`] but additionally installs a [`PreTxAdjust`] hook that can patch
    /// each [`firehose_tracer::types::TxEvent`] before it reaches the tracer. Used by OP Stack
    /// variants to fix up the deposit-tx nonce (see [`PreTxAdjust`]).
    pub const fn with_hooks(
        inner: Inner,
        withdrawals: Option<Withdrawals>,
        ommer_beneficiaries: Vec<Address>,
        adjust: Adjust,
        extras: Extras,
    ) -> Self {
        Self { inner, withdrawals, ommer_beneficiaries, log_index: 0, extras, adjust }
    }
}

impl<Inner, Extras, Adjust> BlockExecutor for FirehoseWrappedExecutor<Inner, Extras, Adjust>
where
    Inner: BlockExecutor,
    Inner::Transaction: Transaction + TxHashRef + SignatureFields,
    <Inner::Evm as reth_evm::Evm>::Inspector: FirehoseInspectorApi,
    <Inner::Evm as reth_evm::Evm>::DB: reth_revm::Database,
    Inner::Receipt: TxReceipt<Log = Log>,
    Extras: PostTxExtras<Inner::Evm>,
    Adjust: PreTxAdjust<Inner::Evm>,
{
    type Transaction = Inner::Transaction;
    type Receipt = Inner::Receipt;
    type Evm = Inner::Evm;
    type Result = Inner::Result;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.evm_mut().inspector_mut().tracer_mut().on_system_call_start();
        let res = self.inner.apply_pre_execution_changes();
        self.inner.evm_mut().inspector_mut().tracer_mut().on_system_call_end();
        res
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&Self::Result) -> CommitChanges,
    ) -> Result<Option<GasOutput>, BlockExecutionError> {
        use alloy_evm::block::TxResult as _;

        let (tx_env, recovered) = tx.into_parts();

        let sender: Address = *recovered.signer();
        let tx_index = self.inner.receipts().len();

        let (
            is_dynamic_fee,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas_price_opt,
            gas_limit,
            blob_gas_used,
            mut tx_event,
        ) = {
            let inner_tx: &Inner::Transaction = recovered.tx();
            let (r, s, v) = inner_tx.signature_fields();
            let tx_event = mapper::signed_tx_to_tx_event(inner_tx, sender, tx_index, r, s, v);
            (
                inner_tx.is_dynamic_fee(),
                inner_tx.max_fee_per_gas(),
                inner_tx.max_priority_fee_per_gas().unwrap_or(0),
                inner_tx.gas_price(),
                inner_tx.gas_limit(),
                // EIP-4844: total blob gas consumed by this tx (num_blobs × GAS_PER_BLOB); 0 for
                // non-blob tx types. Geth populates `receipt.BlobGasUsed` from this value.
                inner_tx.blob_gas_used().unwrap_or(0),
                tx_event,
            )
        };

        let base_fee = self.inner.evm().block().basefee();
        let coinbase = self.inner.evm().block().beneficiary();
        // EIP-4844 blob gas price is a block-level property (derived from `excess_blob_gas`).
        // `blob_gasprice()` returns `None` for pre-Cancun blocks, matching Geth's omission of
        // the field on pre-Cancun receipts.
        let blob_gas_price = self.inner.evm().block().blob_gasprice().map(U256::from);

        // Chain-specific pre-tx patching of the event (e.g. OP Stack deposit nonce override).
        // Runs after the envelope-derived mapper and before `on_tx_start` so the tracer sees the
        // final, chain-consistent event.
        self.adjust.adjust_tx_event(self.inner.evm_mut(), &mut tx_event, sender);

        self.inner.evm_mut().inspector_mut().tracer_mut().on_tx_start(tx_event, None);

        // Split execute_transaction into without_commit + commit so post-tx balance accounting
        // can run in between.
        let result = self.inner.execute_transaction_without_commit((tx_env, recovered))?;

        let gas_used = result.result().result.tx_gas_used();
        // Committed log count: logs that survived after revert rollback; used to advance
        // the block-wide log counter inside `process_post_tx_balance_changes`.
        let committed_log_count = result.result().result.logs().len() as u32;

        let effective_gas_price: u128 = if is_dynamic_fee {
            std::cmp::min(max_fee_per_gas, base_fee as u128 + max_priority_fee_per_gas)
        } else {
            gas_price_opt.unwrap_or(0)
        };

        // Post-tx balance changes (gas refund to sender, priority fee to coinbase). The DB at
        // this point reflects state up to but not including this transaction's commit, so
        // db.basic(addr) reads the pre-tx balance.
        {
            let (evm_db, inspector, _) = self.inner.evm_mut().components_mut();
            let mut get_pre = |addr: Address| -> U256 {
                evm_db.basic(addr).ok().flatten().map(|i| i.balance).unwrap_or(U256::ZERO)
            };
            inspector.process_post_tx_balance_changes_erased(
                sender,
                coinbase,
                gas_limit,
                gas_used,
                effective_gas_price,
                base_fee,
                committed_log_count,
                &mut get_pre,
            );
        }

        // Chain-specific post-tx balance emissions (e.g. OP Stack fee vault credits). Runs after
        // the generic gas-refund / coinbase-tip emissions so ordinal ordering matches the handler
        // order: mainnet `reward_beneficiary` (coinbase) → OP `balance_incr` (fee vaults).
        self.extras.emit_post_tx_extras(self.inner.evm_mut(), gas_used, base_fee);

        if !f(&result).should_commit() {
            // Preserve the invariant that every on_tx_start is paired with on_tx_end.
            let err = std::io::Error::other("transaction not committed");
            self.inner.evm_mut().inspector_mut().tracer_mut().on_tx_end(None, Some(&err));
            return Ok(None);
        }

        let gas_output = self.inner.commit_transaction(result);

        let log_index_start = self.log_index;
        let receipt_data = {
            let committed =
                self.inner.receipts().last().expect("commit_transaction pushed a receipt");
            self.log_index += committed.logs().len() as u32;
            mapper::to_receipt_data(
                committed,
                tx_index as u32,
                gas_used,
                log_index_start,
                blob_gas_used,
                blob_gas_price,
            )
        };
        self.inner.evm_mut().inspector_mut().tracer_mut().on_tx_end(Some(&receipt_data), None);

        Ok(Some(gas_output))
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        // Capture pre-`inner.finish()` balances for any address that the upstream
        // `post_block_balance_increments` path will touch via `db.increment_balances()` —
        // namely the coinbase (block reward) and each ommer beneficiary (uncle reward).
        // These increments bypass the EVM journal so the inspector never sees them; we
        // sample here and emit explicit `BalanceChange` events after the inner finishes.
        // Pre-merge only: when `withdrawals.is_some()` (post-Shanghai) the static block
        // reward is zero and we skip the sampling entirely.
        let prereward_state = if self.withdrawals.is_none() {
            let coinbase = self.inner.evm().block().beneficiary();
            let (db, _, _) = self.inner.evm_mut().components_mut();
            Some(BlockRewardPreState::capture(db, coinbase, &self.ommer_beneficiaries))
        } else {
            None
        };

        // PulseChain PrimordialPulse: capture pre-state for every address the
        // `apply_primordial_pulse` call inside `inner.finish()` will mutate
        // (~thousands of sacrifice-credit recipients + treasury + ETH and PULSE
        // deposit contracts). Chain ID is read directly from the inner EVM:
        // `primordial_pulse::fork_block_for` returns `None` for non-PulseChain
        // chains, and the block-number check below filters non-fork blocks on
        // PulseChain itself, so a single unconditional probe is correct here
        // and lets us avoid a `Some(chain_id)` parameter that every wrapper
        // construction site would otherwise have to set.
        let pp_pre_state = {
            let chain_id = self.inner.evm().chain_id();
            crate::primordial_pulse::fork_block_for(chain_id).and_then(|fork_block| {
                let block_number = self.inner.evm().block().number().saturating_to::<u64>();
                if block_number != fork_block {
                    return None;
                }
                let (db, _, _) = self.inner.evm_mut().components_mut();
                crate::primordial_pulse::PrimordialPulsePreState::capture(
                    db,
                    chain_id,
                    block_number,
                )
            })
        };

        // Open the post-execution system-call window (EIP-4895 withdrawals, EIP-7251 consolidation
        // requests, etc.). Close it AFTER the inner finish so inner post-execution work lands
        // inside the window.
        self.inner.evm_mut().inspector_mut().tracer_mut().on_system_call_start();

        let (mut evm, exec_result) = self.inner.finish()?;

        // Close the window before emitting withdrawal balance changes so that on_balance_change
        // routes them to `block.balance_changes` (not `deferred_call_state`, which would be
        // discarded).
        evm.inspector_mut().tracer_mut().on_system_call_end();

        // EIP-4895 validator withdrawals are applied via db.increment_balances() inside the
        // inner finish(), bypassing the EVM journal — the inspector never sees them.
        emit_withdrawal_balance_changes(&mut evm, self.withdrawals.as_ref());

        // Pre-merge static block reward + per-ommer uncle reward — same db.increment_balances()
        // invisibility as withdrawals. Geth-firehose emits these as `REASON_REWARD_MINE_BLOCK`
        // (coinbase) and `REASON_REWARD_MINE_UNCLE` (per ommer beneficiary); we mirror that.
        if let Some(pre) = prereward_state {
            emit_block_reward_balance_changes(&mut evm, &pre);
        }

        // PulseChain PrimordialPulse: emit the captured diffs as FIRE BLOCK events
        // (balance changes for sacrifice credits + treasury, plus account-level
        // diffs for the two deposit contracts). Same invisibility problem as
        // withdrawals — `apply_primordial_pulse` writes the new state directly
        // into the journal via plain `db` calls that the inspector never sees.
        // Emits its own system-call window internally so the events attach to a
        // dedicated PrimordialPulse system call rather than the block reward.
        if let Some(pre) = pp_pre_state {
            crate::primordial_pulse::emit_primordial_pulse_changes(&mut evm, &pre);
        }

        Ok((evm, exec_result))
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
}

// ---------------------------------------------------------------------------
// FirehoseBlockExecutor (pipeline Executor)
// ---------------------------------------------------------------------------

/// Per-block Firehose tracing strategy bound to a [`ConfigureEvm`] flavour.
///
/// Exists so chain integrators (OP Stack, mainnet, ...) can plug chain-specific
/// [`PostTxExtras`] / [`PreTxAdjust`] hooks into the pipeline without forcing
/// [`FirehoseBlockExecutor`]'s `Executor<DB>` impl to carry
/// `for<'a> Extras: PostTxExtras<..Evm<&'a mut State<DB>, _>..>` HRTB bounds. That HRTB
/// cannot be discharged generically when the hook impl is narrow (e.g.
/// `impl<DB,I,P> PostTxExtras<OpEvm<DB,I,P>>`) because the method-level `DB` is forced
/// to `'static` by the universally quantified `'a`. By moving all hook invocation into
/// this trait's method body — where `DB` and the tracer-bound `'a` are both method-local
/// concrete types — the HRTB disappears from the executor's where clause and bound
/// checks happen at a call site where Rust can verify them for a specific (non-`'static`)
/// `DB`.
///
/// An implementation must:
///  1. build the inspector-capable EVM via [`ConfigureEvm::evm_with_env_and_inspector`],
///  2. wrap the resulting executor in [`FirehoseWrappedExecutor::with_hooks`] with whatever
///     chain-specific hooks are desired,
///  3. call `.execute_block(..)` and return the result.
///
/// The implementation must NOT emit `on_block_start` / `on_block_end` — those are owned
/// by [`FirehoseBlockExecutor`] via the [`FirehoseBlockTracer`] lifecycle.
pub trait ChainHooks<F: ConfigureEvm>: Send + Sync + Clone + Unpin + 'static {
    /// Run one traced block against `db`, using `tracer`'s inspector for mid-block events.
    fn execute_one_traced<DB: reth_evm::Database>(
        &self,
        evm_config: &F,
        db: &mut State<DB>,
        block: &RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
        tracer: &mut FirehoseBlockTracer,
    ) -> Result<BlockExecutionResult<<F::Primitives as NodePrimitives>::Receipt>, BlockExecutionError>;
}

/// No-op [`ChainHooks`] for mainnet Ethereum — installs [`NoPostTxExtras`] / [`NoPreTxAdjust`].
#[derive(Default, Debug, Clone, Copy)]
pub struct NoChainHooks;

impl<F> ChainHooks<F> for NoChainHooks
where
    F: ConfigureEvm,
    BlockTy<F::Primitives>: BlockTrait,
    <BlockTy<F::Primitives> as BlockTrait>::Header: BlockHeader + Sealable,
    <BlockTy<F::Primitives> as BlockTrait>::Body: BlockBody,
    <<BlockTy<F::Primitives> as BlockTrait>::Body as BlockBody>::OmmerHeader:
        BlockHeader + Sealable,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
{
    fn execute_one_traced<DB: reth_evm::Database>(
        &self,
        evm_config: &F,
        db: &mut State<DB>,
        block: &RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
        tracer: &mut FirehoseBlockTracer,
    ) -> Result<BlockExecutionResult<<F::Primitives as NodePrimitives>::Receipt>, BlockExecutionError>
    {
        // Safe to use `run_wrapped_block` here: its `for<'a> NoPostTxExtras: PostTxExtras<..>`
        // HRTB is trivially satisfied by [`NoPostTxExtras`]'s blanket `impl<E: Evm>`.
        run_wrapped_block::<F, DB, NoPostTxExtras, NoPreTxAdjust, _>(
            evm_config,
            db,
            block,
            tracer,
            NoPreTxAdjust,
            NoPostTxExtras,
        )
    }
}

/// Pipeline [`Executor`] that runs each block through a per-block wrapping strategy
/// ([`ChainHooks`]) and defers the end-of-block flush until post-execution validation
/// succeeds. See the module-level docs.
///
/// By default `H` resolves to [`NoChainHooks`] (mainnet Ethereum). OP Stack integrators
/// supply their own `ChainHooks` impl via [`FirehoseBlockExecutor::new_with_chain_hooks`]
/// to install `OpPostTxExtras` / `OpPreTxAdjust`.
pub struct FirehoseBlockExecutor<F, DB, H = NoChainHooks> {
    /// The underlying EVM configuration used to create block executors.
    pub strategy_factory: F,
    /// Revm state holding all accumulated changes across the batch.
    pub db: State<DB>,
    /// Tracer guard for the most recently executed block. Finalized by the next
    /// `execute_and_trace_one` call or by `into_state` — see the module-level docs.
    pending_tracer: Option<FirehoseBlockTracer>,
    /// Chain-specific per-block wrapping strategy.
    hooks: H,
}

impl Debug for FirehoseBlockExecutor<(), ()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirehoseBlockExecutor").finish()
    }
}

impl<F, DB: reth_evm::Database> FirehoseBlockExecutor<F, DB, NoChainHooks> {
    /// Creates a new `FirehoseBlockExecutor` with the default [`NoChainHooks`] (mainnet).
    pub fn new(strategy_factory: F, db: DB) -> Self {
        Self::new_with_chain_hooks(strategy_factory, db, NoChainHooks)
    }
}

impl<F, DB: reth_evm::Database, H> FirehoseBlockExecutor<F, DB, H> {
    /// Creates a new `FirehoseBlockExecutor` with a caller-supplied [`ChainHooks`].
    pub fn new_with_chain_hooks(strategy_factory: F, db: DB, hooks: H) -> Self {
        let db = State::builder().with_database(db).with_bundle_update().build();
        Self { strategy_factory, db, pending_tracer: None, hooks }
    }
}

impl<F, DB, H> Executor<DB> for FirehoseBlockExecutor<F, DB, H>
where
    F: ConfigureEvm,
    DB: reth_evm::Database,
    H: ChainHooks<F>,
    BlockTy<F::Primitives>: BlockTrait,
    <BlockTy<F::Primitives> as BlockTrait>::Header: BlockHeader + Sealable,
    <BlockTy<F::Primitives> as BlockTrait>::Body: BlockBody,
    <<BlockTy<F::Primitives> as BlockTrait>::Body as BlockBody>::OmmerHeader:
        BlockHeader + Sealable,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
{
    type Primitives = F::Primitives;
    type Error = BlockExecutionError;

    fn execute_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        let result = self
            .strategy_factory
            .executor_for_block(&mut self.db, block)
            .map_err(BlockExecutionError::other)?
            .execute_block(block.transactions_recovered())?;
        self.db.merge_transitions(BundleRetention::Reverts);
        Ok(result)
    }

    /// Traces a block with Firehose hooks and defers `on_block_end(None)` until the caller has
    /// validated the result. See the module-level docs for the deferral contract.
    fn execute_and_trace_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        if !crate::is_tracer_initialized() {
            return Err(BlockExecutionError::msg(
                "FirehoseBlockExecutor requires the global tracer to be initialized for execute_and_trace_one",
            ));
        }

        // The previous block has reached a point where the caller would have returned early on
        // validation failure; since we've been called again, it passed and can be flushed.
        if let Some(prev) = self.pending_tracer.take() {
            prev.mark_verified();
        }

        // In the pipeline / staged sync path, the block we're about to trace is by definition
        // already finalized — staged sync only replays blocks up to the finalized head — so
        // advertise it as the finalized ref in the block event.
        let finalized = Some(firehose_tracer::types::FinalizedBlockRef {
            number: block.header().number(),
            hash: Some(block.hash()),
        });
        let mut tracer =
            FirehoseBlockTracer::start::<F::Primitives>(block.sealed_block(), finalized);

        let block_result =
            self.hooks.execute_one_traced(&self.strategy_factory, &mut self.db, block, &mut tracer);

        match block_result {
            Ok(result) => {
                self.db.merge_transitions(BundleRetention::Reverts);
                self.pending_tracer = Some(tracer);
                Ok(result)
            }
            Err(e) => {
                tracer.mark_failed(&e);
                Err(e)
            }
        }
    }

    fn execute_one_with_state_hook<S>(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
        state_hook: S,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    where
        S: OnStateHook + 'static,
    {
        // v2.3.0 removed `with_state_hook`/`set_state_hook` from `BlockExecutor`; state hooks are
        // now installed on the EVM's underlying `State` db. Mirror upstream `BasicBlockExecutor`:
        // set the hook on the db, execute, then clear it before merging transitions.
        let mut executor = self
            .strategy_factory
            .executor_for_block(&mut self.db, block)
            .map_err(BlockExecutionError::other)?;
        executor.evm_mut().db_mut().set_state_hook(Some(Box::new(state_hook)));
        let result = executor.execute_block(block.transactions_recovered());
        self.db.set_state_hook(None);
        self.db.merge_transitions(BundleRetention::Reverts);
        result
    }

    fn into_state(mut self) -> State<DB> {
        // Reaching `into_state` without an error means the batch completed successfully —
        // including post-execution validation on the most recent block — so finalize any
        // pending tracer as verified rather than letting Drop discard it.
        if let Some(pending) = self.pending_tracer.take() {
            pending.mark_verified();
        }
        self.db
    }

    fn size_hint(&self) -> usize {
        self.db.bundle_state.size_hint()
    }

    fn take_bal(&mut self) -> Option<BlockAccessList> {
        self.db.take_built_alloy_bal()
    }
}

/// Runs a single block through a [`FirehoseWrappedExecutor`] using the existing tracer guard for
/// mid-block event emission. Does not emit `on_block_start`/`on_block_end` — those are owned by
/// the caller via the [`FirehoseBlockTracer`] lifecycle.
/// Builds a [`FirehoseWrappedExecutor`] around `evm_config`'s per-block executor with the tracer
/// held by `tracer_guard` wired into the EVM as a [`crate::inspector::FirehoseInspector`], then
/// runs the block.
///
/// The function is generic over the tracer-handle type `G`, so it works equally with the
/// process-wide global guard ([`crate::block_tracer::GlobalTracerGuard`], the default) and with a
/// caller-owned `&'a mut firehose_tracer::Tracer` produced by
/// [`FirehoseBlockTracer::start_local`]. The latter form is used by the integration test harness
/// to capture a single block's Firehose output into an in-memory buffer.
///
/// Does **not** emit `on_block_start` / `on_block_end` — those are owned by the
/// [`FirehoseBlockTracer`] lifecycle (see [`FirehoseBlockTracer::start`] and
/// [`FirehoseBlockTracer::mark_verified`]).
pub fn run_wrapped_block<F, DB, Extras, Adjust, G>(
    evm_config: &F,
    db: &mut State<DB>,
    block: &RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
    tracer_guard: &mut FirehoseBlockTracer<G>,
    adjust: Adjust,
    extras: Extras,
) -> Result<BlockExecutionResult<<F::Primitives as NodePrimitives>::Receipt>, BlockExecutionError>
where
    F: ConfigureEvm,
    DB: reth_evm::Database,
    G: std::ops::DerefMut<Target = firehose_tracer::Tracer>,
    BlockTy<F::Primitives>: BlockTrait,
    <BlockTy<F::Primitives> as BlockTrait>::Header: BlockHeader + Sealable,
    <BlockTy<F::Primitives> as BlockTrait>::Body: BlockBody,
    <<BlockTy<F::Primitives> as BlockTrait>::Body as BlockBody>::OmmerHeader:
        BlockHeader + Sealable,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
    for<'a> Extras: PostTxExtras<
        <<F::BlockExecutorFactory as alloy_evm::block::BlockExecutorFactory>::EvmFactory
            as alloy_evm::EvmFactory>::Evm<
            &'a mut State<DB>,
            crate::inspector::FirehoseInspector<'a>,
        >,
    >,
    for<'a> Adjust: PreTxAdjust<
        <<F::BlockExecutorFactory as alloy_evm::block::BlockExecutorFactory>::EvmFactory
            as alloy_evm::EvmFactory>::Evm<
            &'a mut State<DB>,
            crate::inspector::FirehoseInspector<'a>,
        >,
    >,
{
    let evm_env = evm_config.evm_env(block.header()).map_err(BlockExecutionError::other)?;
    let exec_ctx =
        evm_config.context_for_block(block.sealed_block()).map_err(BlockExecutionError::other)?;

    let inspector = tracer_guard.inspector();
    let evm = evm_config.evm_with_env_and_inspector(db, evm_env, inspector);
    let inner = evm_config.create_executor(evm, exec_ctx);

    let withdrawals = block.body().withdrawals().cloned();
    let ommer_beneficiaries: Vec<Address> = block
        .body()
        .ommers()
        .map(|o| o.iter().map(|h| h.beneficiary()).collect())
        .unwrap_or_default();
    let wrapped = FirehoseWrappedExecutor::with_hooks(
        inner,
        withdrawals,
        ommer_beneficiaries,
        adjust,
        extras,
    );

    wrapped.execute_block(block.transactions_recovered())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Emits EIP-4895 withdrawal balance changes to the tracer after the post-execution system-call
/// window has closed.
///
/// Validator withdrawals are applied via `db.increment_balances()` inside the executor's
/// `finish()`, bypassing the EVM journal entirely — the [`crate::inspector::FirehoseInspector`]
/// never sees them. This function bridges the gap by walking the withdrawal list in reverse
/// from the known post-all-withdrawals DB balance, reconstructing per-step pre/post pairs (see
/// [`withdrawal_balance_events`]) so each event gets a distinct monotonically increasing ordinal.
///
/// Must be called with `tracer.transaction == None` (i.e. outside any system-call window) so
/// that `on_balance_change` routes the events to `block.balance_changes` directly.
fn emit_withdrawal_balance_changes<E>(evm: &mut E, withdrawals: Option<&Withdrawals>)
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
    E::DB: reth_revm::Database,
{
    use firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let Some(withdrawals) = withdrawals else { return };
    let withdrawals = withdrawals.as_slice();
    if withdrawals.is_empty() {
        return;
    }

    let (db, inspector, _) = evm.components_mut();
    let events = withdrawal_balance_events(withdrawals, |addr| {
        db.basic(addr).ok().flatten().map(|i| i.balance).unwrap_or_default()
    });

    for (addr, pre, post) in events {
        inspector.tracer_mut().on_balance_change(addr, pre, post, Reason::Withdrawal);
    }
}

/// Pre-`inner.finish()` balance snapshot for addresses that the upstream Ethereum executor's
/// `post_block_balance_increments` path will mutate via `db.increment_balances()` — namely the
/// block coinbase and each ommer beneficiary.
///
/// Sampled BEFORE `inner.finish()` runs so we can compute the static block reward + uncle reward
/// deltas after the inner has applied them, and emit the corresponding `RewardMineBlock` /
/// `RewardMineUncle` balance-change events that would otherwise be invisible to the inspector.
///
/// Ommers are stored as a `Vec<(Address, U256)>` rather than a map so the emission order matches
/// the canonical block-body ordering — geth-firehose emits one `RewardMineUncle` event per uncle
/// in the order they appear in the block, and consumers may depend on that ordering.
#[derive(Debug)]
struct BlockRewardPreState {
    coinbase: Address,
    coinbase_pre: U256,
    /// `(beneficiary, pre_balance)` pairs in the order of the block's ommer list.
    ommer_pre: Vec<(Address, U256)>,
}

impl BlockRewardPreState {
    fn capture<DB: reth_revm::Database>(
        db: &mut DB,
        coinbase: Address,
        ommer_beneficiaries: &[Address],
    ) -> Self {
        let read = |db: &mut DB, addr: Address| -> U256 {
            db.basic(addr).ok().flatten().map(|i| i.balance).unwrap_or_default()
        };
        let coinbase_pre = read(db, coinbase);
        let ommer_pre = ommer_beneficiaries.iter().map(|&addr| (addr, read(db, addr))).collect();
        Self { coinbase, coinbase_pre, ommer_pre }
    }
}

/// Emits the pre-merge static block reward and per-uncle balance changes that
/// `db.increment_balances()` applied invisibly inside `inner.finish()`.
///
/// Must be called with `tracer.transaction == None` (i.e. outside any system-call window) so
/// that `on_balance_change` routes the events to `block.balance_changes` directly — same
/// constraint as [`emit_withdrawal_balance_changes`].
///
/// Emission shape mirrors geth-firehose for the common case:
///  - coinbase: one `RewardMineBlock` event with `pre = coinbase_pre`, `post = coinbase_post`
///  - each ommer beneficiary: one `RewardMineUncle` event with the per-uncle pre/post, in canonical
///    block-body order
///
/// **Known edge case**: if `coinbase` also appears as an ommer beneficiary (self-mined uncle)
/// the two events would share identical `pre`/`post` values rather than the sequential deltas
/// geth emits, since this helper observes only the final post-`inner.finish()` balance for
/// each address rather than reconstructing per-reward amounts. The trace's net balance is still
/// consistent (post-finish() balance), but a consumer that sums the deltas per reason would
/// see double-counting. No Ethereum mainnet or PulseChain block currently hits this — block 1
/// (the bug-3 trigger) has no ommers — and it would require splitting
/// `post_block_balance_increments` into per-reason chunks to fix. Revisit if a downstream consumer
/// surfaces the divergence.
fn emit_block_reward_balance_changes<E>(evm: &mut E, pre: &BlockRewardPreState)
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
    E::DB: reth_revm::Database,
{
    use firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let (db, inspector, _) = evm.components_mut();
    let read = |db: &mut <E as reth_evm::Evm>::DB, addr: Address| -> U256 {
        db.basic(addr).ok().flatten().map(|i| i.balance).unwrap_or_default()
    };

    // Tracer::on_balance_change drops no-op (pre == post) emissions internally, so we don't
    // pre-filter here — saves a branch per address and keeps the call shape parallel to
    // emit_withdrawal_balance_changes.
    let coinbase_post = read(db, pre.coinbase);
    inspector.tracer_mut().on_balance_change(
        pre.coinbase,
        pre.coinbase_pre,
        coinbase_post,
        Reason::RewardMineBlock,
    );

    for &(addr, pre_bal) in &pre.ommer_pre {
        let post_bal = read(db, addr);
        inspector.tracer_mut().on_balance_change(addr, pre_bal, post_bal, Reason::RewardMineUncle);
    }
}

/// Computes per-withdrawal balance change events in forward order by replaying backwards
/// from the known final balances.
///
/// Starting from the post-all-withdrawals balance for each address (fetched via
/// `get_final_balance`), the function walks the withdrawal list in reverse to reconstruct
/// the pre/post values for each individual withdrawal, then returns the events in the
/// original forward order so callers emit them with monotonically increasing ordinals.
///
/// Withdrawals with `amount == 0` are skipped (they produce no balance change).
fn withdrawal_balance_events(
    withdrawals: &[alloy_eips::eip4895::Withdrawal],
    mut get_final_balance: impl FnMut(Address) -> U256,
) -> Vec<(Address, U256, U256)> {
    let mut current: HashMap<Address, U256> = HashMap::new();
    for w in withdrawals {
        if w.amount > 0 {
            current.entry(w.address).or_insert_with(|| get_final_balance(w.address));
        }
    }

    let mut events: Vec<(Address, U256, U256)> = Vec::with_capacity(withdrawals.len());
    for w in withdrawals.iter().rev() {
        if w.amount == 0 {
            continue;
        }
        let post = *current.get(&w.address).unwrap_or(&U256::ZERO);
        let pre = post.saturating_sub(w.amount_wei());
        events.push((w.address, pre, post));
        current.insert(w.address, pre);
    }

    events.reverse();
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip4895::Withdrawal;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn gwei(n: u64) -> u64 {
        n
    }

    fn wei(gwei: u64) -> U256 {
        U256::from(gwei) * U256::from(1_000_000_000u64)
    }

    fn make_withdrawal(
        index: u64,
        validator: u64,
        address: Address,
        amount_gwei: u64,
    ) -> Withdrawal {
        Withdrawal { index, validator_index: validator, address, amount: amount_gwei }
    }

    fn events_with_balances(
        withdrawals: &[Withdrawal],
        final_balances: &HashMap<Address, U256>,
    ) -> Vec<(Address, U256, U256)> {
        withdrawal_balance_events(withdrawals, |addr| {
            final_balances.get(&addr).copied().unwrap_or_default()
        })
    }

    #[test]
    fn test_single_withdrawal() {
        let a = addr(0xAA);
        let ws = [make_withdrawal(0, 0, a, gwei(100))];
        let mut finals = HashMap::new();
        finals.insert(a, wei(1100));

        let events = events_with_balances(&ws, &finals);

        assert_eq!(events, vec![(a, wei(1000), wei(1100))]);
    }

    #[test]
    fn test_two_withdrawals_same_address_ordering() {
        let a = addr(0xAA);
        let ws = [make_withdrawal(0, 0, a, gwei(50)), make_withdrawal(1, 0, a, gwei(150))];
        let mut finals = HashMap::new();
        finals.insert(a, wei(1200));

        let events = events_with_balances(&ws, &finals);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0], (a, wei(1000), wei(1050)));
        assert_eq!(events[1], (a, wei(1050), wei(1200)));
    }

    #[test]
    fn test_interleaved_different_addresses() {
        let a = addr(0xAA);
        let b = addr(0xBB);
        let ws = [
            make_withdrawal(0, 0, a, gwei(50)),
            make_withdrawal(1, 1, b, gwei(20)),
            make_withdrawal(2, 0, a, gwei(150)),
        ];
        let mut finals = HashMap::new();
        finals.insert(a, wei(1200));
        finals.insert(b, wei(220));

        let events = events_with_balances(&ws, &finals);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0], (a, wei(1000), wei(1050)));
        assert_eq!(events[1], (b, wei(200), wei(220)));
        assert_eq!(events[2], (a, wei(1050), wei(1200)));
    }

    #[test]
    fn test_zero_amount_withdrawals_skipped() {
        let a = addr(0xAA);
        let ws = [make_withdrawal(0, 0, a, 0), make_withdrawal(1, 0, a, gwei(100))];
        let mut finals = HashMap::new();
        finals.insert(a, wei(1100));

        let events = events_with_balances(&ws, &finals);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0], (a, wei(1000), wei(1100)));
    }

    #[test]
    fn test_empty_withdrawals() {
        let events = withdrawal_balance_events(&[], |_| U256::ZERO);
        assert!(events.is_empty());
    }
}

// ---------------------------------------------------------------------------
// FirehoseEvmConfig
// ---------------------------------------------------------------------------

/// A thin wrapper around any [`ConfigureEvm`] that overrides [`ConfigureEvm::batch_executor`]
/// to return a [`FirehoseBlockExecutor`] instead of the default `BasicBlockExecutor`.
///
/// All other methods delegate directly to the inner config. The live engine path (payload
/// validator) constructs its wrapped executor explicitly, since `create_executor` cannot tighten
/// its inspector bound via a trait override.
///
/// This wrapper always installs [`NoPostTxExtras`] / [`NoPreTxAdjust`] — suitable for mainnet
/// Ethereum out of the box. Chains that need chain-specific tracer hooks (OP Stack fee vaults,
/// deposit-nonce fixups, ...) must provide their own [`ConfigureEvm`] wrapper whose
/// `batch_executor` constructs [`FirehoseBlockExecutor::new_with_hooks`] with concrete hook
/// types — the `for<'a> Extras: PostTxExtras<Evm<&'a mut State<DB>, ...>>` bound cannot be
/// written on a generic [`ConfigureEvm`] impl because `DB` is a method-level generic on
/// `batch_executor<DB>`, but it *is* expressible for fixed `F`/`Extras`/`Adjust`.
#[derive(Clone, Debug)]
pub struct FirehoseEvmConfig<F> {
    /// The wrapped EVM configuration.
    pub inner: F,
}

impl<F: ConfigureEvm> FirehoseEvmConfig<F> {
    /// Wraps an existing EVM configuration.
    pub const fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F> ConfigureEvm for FirehoseEvmConfig<F>
where
    F: ConfigureEvm,
    BlockTy<F::Primitives>: BlockTrait,
    <BlockTy<F::Primitives> as BlockTrait>::Header: BlockHeader + Sealable,
    <BlockTy<F::Primitives> as BlockTrait>::Body: BlockBody,
    <<BlockTy<F::Primitives> as BlockTrait>::Body as BlockBody>::OmmerHeader:
        BlockHeader + Sealable,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
{
    type Primitives = F::Primitives;
    type Error = F::Error;
    type NextBlockEnvCtx = F::NextBlockEnvCtx;
    type BlockExecutorFactory = F::BlockExecutorFactory;
    type BlockAssembler = F::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self.inner.block_executor_factory()
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(
        &self,
        header: &reth_primitives_traits::HeaderTy<Self::Primitives>,
    ) -> Result<reth_evm::EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &reth_primitives_traits::HeaderTy<Self::Primitives>,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<reth_evm::EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a reth_primitives_traits::SealedBlock<
            reth_primitives_traits::BlockTy<Self::Primitives>,
        >,
    ) -> Result<reth_evm::ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &reth_primitives_traits::SealedHeader<
            reth_primitives_traits::HeaderTy<Self::Primitives>,
        >,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<reth_evm::ExecutionCtxFor<'_, Self>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }

    fn batch_executor<DB: reth_evm::Database>(
        &self,
        db: DB,
    ) -> impl Executor<DB, Primitives = Self::Primitives, Error = BlockExecutionError> {
        FirehoseBlockExecutor::new(self.inner.clone(), db)
    }
}

impl<F, ExecutionData> reth_evm::ConfigureEngineEvm<ExecutionData> for FirehoseEvmConfig<F>
where
    F: reth_evm::ConfigureEngineEvm<ExecutionData>,
    BlockTy<F::Primitives>: BlockTrait,
    <BlockTy<F::Primitives> as BlockTrait>::Header: BlockHeader + Sealable,
    <BlockTy<F::Primitives> as BlockTrait>::Body: BlockBody,
    <<BlockTy<F::Primitives> as BlockTrait>::Body as BlockBody>::OmmerHeader:
        BlockHeader + Sealable,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
{
    fn evm_env_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<reth_evm::EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<reth_evm::ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl reth_evm::ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload)
    }
}
