//! Firehose block executor wrappers and EVM config.
//!
//! This module provides:
//!
//! * [`FirehoseWrappedExecutor`] — a thin [`BlockExecutor`] wrapper that fires Firehose tracer
//!   hooks (`on_system_call_start/end`, `on_tx_start/end`, post-tx balance changes, withdrawal
//!   balance changes) around a delegate executor, and installs a [`FirehoseInspector`] on the
//!   delegate's EVM for everything that happens inside the EVM.
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
//!
//! Only `execute_and_trace_one` traces. Every other [`Executor`] method, `execute` included, runs
//! untraced: callers other than staged sync use them to re-execute blocks for other purposes
//! (single-block ExEx backfill, for example), often blocks that were already emitted, and
//! `execute` would flush a block before its caller validated it.

use std::{collections::HashMap, fmt::Debug, ops::DerefMut, sync::Arc};

use crate::{
    block_tracer::{FirehoseBlockTracer, GlobalTracerGuard},
    inspector::{FirehoseInspector, FramelessTx, PostTxGasAccounting},
    mapper,
    mapper::SignatureFields,
};
use alloy_consensus::{transaction::TxHashRef, BlockHeader, Transaction, TxReceipt};
use alloy_eip7928::{BlockAccessIndex, BlockAccessList};
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::{Address, Log, Sealable, TxKind, U256};
use evm2::evm::{CacheDB, Db};
use reth_evm::{
    execute::{
        BlockExecutionError, BlockExecutionOutput, BlockExecutor, BlockExecutorFactory,
        BlockTransactionResult, CommitChanges, Executor, ExecutorTx, GasOutput, RecoveredTx,
    },
    ConfigureEvm, Database, DynDatabase, Evm as _, EvmEnv, EvmEnvFor, EvmFor,
};
use reth_execution_types::{BlockExecutionResult, BundleSource, StateUpdate};
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{Block as BlockTrait, BlockBody, BlockTy, RecoveredBlock, TxTy};
use reth_trie_common::bundle_state::BundleState;

/// Chain-specific hook that emits additional post-tx balance changes after the generic
/// gas-refund-to-sender and priority-tip-to-coinbase emissions done by the inspector.
///
/// Fired by [`FirehoseWrappedExecutor`] once per transaction, immediately after
/// [`FirehoseInspector::process_post_tx_gas_accounting`] and before the transaction is committed,
/// so `evm` still reads the state before the transaction.
///
/// The primary use case is OP Stack: the fee vault predeploys are credited during gas settlement,
/// after the root frame, where no inspector hook fires — so those credits are invisible to the
/// tracer unless the chain integrator re-emits them via this hook. Implementations typically call
/// `inspector.tracer_mut().on_balance_change(...)` with `Reason::RewardTransactionFee`, starting
/// from [`FirehoseInspector::post_exec_balance`].
pub trait PostTxExtras<E: reth_evm::Evm> {
    /// Emit chain-specific post-tx balance changes. `gas_used` is the post-refund gas
    /// charged to the sender; `base_fee` is the block's EIP-1559 base fee (0 pre-London).
    fn emit_post_tx_extras<G: DerefMut<Target = firehose_tracer::Tracer>>(
        &self,
        evm: &mut E,
        inspector: &FirehoseInspector<G>,
        gas_used: u64,
        base_fee: u64,
    );

    /// Gas-fee parameters for the generic `GasRefund` / `RewardTransactionFee` changes of the
    /// current transaction.
    ///
    /// `ethereum` holds the Ethereum parameters derived from the transaction envelope and the
    /// block base fee; the default returns it unchanged. Runs before those changes are emitted
    /// and before [`Self::emit_post_tx_extras`].
    fn gas_accounting(&self, _evm: &mut E, ethereum: PostTxGasAccounting) -> PostTxGasAccounting {
        ethereum
    }
}

/// No-op [`PostTxExtras`] used on Ethereum mainnet (and any chain whose fee distribution is
/// already covered by the generic sender-refund + coinbase-tip emissions).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPostTxExtras;

impl<E: reth_evm::Evm> PostTxExtras<E> for NoPostTxExtras {
    #[inline]
    fn emit_post_tx_extras<G: DerefMut<Target = firehose_tracer::Tracer>>(
        &self,
        _evm: &mut E,
        _inspector: &FirehoseInspector<G>,
        _gas_used: u64,
        _base_fee: u64,
    ) {
    }
}

/// Chain-specific hook that patches the per-tx [`firehose_tracer::types::TxEvent`] produced by
/// the generic envelope-derived mapper before it is handed to the tracer via `on_tx_start`.
///
/// At this point `evm` reads the state before the transaction, so implementations can read
/// account data (nonce, code, balance) to fill in fields the envelope itself does not carry.
///
/// The primary use case is OP Stack deposit transactions, whose envelope carries no nonce: the
/// real nonce is the sender account's pre-execution nonce, read via `evm.account_info(sender)`.
/// Such implementations also flag the depth-0 balance change as a mint via
/// [`FirehoseInspector::set_root_balance_reason`].
pub trait PreTxAdjust<E: reth_evm::Evm> {
    /// Mutate `tx_event` in place. `sender` is the recovered signer. Implementations should
    /// leave the event untouched for tx types they do not care about.
    fn adjust_tx_event<G: DerefMut<Target = firehose_tracer::Tracer>>(
        &self,
        evm: &mut E,
        inspector: &FirehoseInspector<G>,
        tx_event: &mut firehose_tracer::types::TxEvent,
        sender: Address,
    );
}

/// No-op [`PreTxAdjust`] used on Ethereum mainnet (and any chain whose envelope already carries
/// every field the tracer needs).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPreTxAdjust;

impl<E: reth_evm::Evm> PreTxAdjust<E> for NoPreTxAdjust {
    #[inline]
    fn adjust_tx_event<G: DerefMut<Target = firehose_tracer::Tracer>>(
        &self,
        _evm: &mut E,
        _inspector: &FirehoseInspector<G>,
        _tx_event: &mut firehose_tracer::types::TxEvent,
        _sender: Address,
    ) {
    }
}

/// Block-level values the per-transaction accounting needs, read once from the EVM environment.
#[derive(Debug, Clone)]
pub struct BlockFees {
    coinbase: Address,
    /// Number of the block, used to find the `PrimordialPulse` fork block.
    block_number: u64,
    base_fee: u64,
    /// EIP-4844 blob gas price, `None` before Cancun, matching Geth's omission of the field on
    /// pre-Cancun receipts.
    blob_gas_price: Option<U256>,
    version: evm2::Version,
}

impl BlockFees {
    /// Reads the block fees from the environment the block executes in.
    pub fn new(evm_env: &impl EvmEnv) -> Self {
        let block = evm_env.block_env();
        let version = *evm_env.version();
        let spec: evm2::SpecId = evm_env.spec_id().into();
        let blob_gas_price = spec.enables(evm2::SpecId::CANCUN).then_some(block.blob_basefee);
        Self {
            coinbase: block.beneficiary,
            block_number: block.number.saturating_to(),
            base_fee: evm_env.block_base_fee(),
            blob_gas_price,
            version,
        }
    }
}

/// A [`BlockExecutor`] wrapper that fires Firehose tracer hooks around a delegate executor.
///
/// The constructor installs the [`FirehoseInspector`] on the inner executor's EVM, system calls
/// included. The wrapper drives the tracer through its own clone of the inspector at the following
/// points:
///
/// | Hook                               | When                                               |
/// |------------------------------------|----------------------------------------------------|
/// | `on_system_call_start/end`         | Around [`Self::apply_pre_execution_changes`] and   |
/// |                                    | around the post-execution window inside            |
/// |                                    | [`Self::finish_with_block_access_list`].           |
/// | `on_tx_start`                      | Before executing each transaction (in              |
/// |                                    | [`Self::execute_transaction_with_commit_condition`]).|
/// | post-tx gas accounting             | After `execute_transaction_without_commit`,        |
/// |                                    | before `commit_transaction`.                       |
/// | `on_tx_end(Some(receipt_data))`    | After `commit_transaction`.                        |
/// | withdrawal balance changes         | After the inner finish, so they land in            |
/// |                                    | `block.balance_changes`.                           |
///
/// The wrapper does **not** emit `on_block_start` / `on_block_end`; those are owned by the caller
/// via [`FirehoseBlockTracer::start`] / [`FirehoseBlockTracer::mark_verified`] /
/// [`FirehoseBlockTracer::mark_failed`] so they can be deferred past post-execution validation.
///
/// Only [`Self::execute_transaction_with_commit_condition`] (and the methods defaulting to it)
/// traces a transaction. [`Self::execute_transaction_without_commit`] and
/// [`Self::commit_transaction`] forward untraced: the engine only calls them to commit prewarmed
/// results, which the traced path never does.
///
/// `Extras` plugs in a chain-specific [`PostTxExtras`] hook, `Adjust` a chain-specific
/// [`PreTxAdjust`] hook. Both default to no-ops for mainnet Ethereum.
pub struct FirehoseWrappedExecutor<
    Inner,
    G = GlobalTracerGuard,
    Extras = NoPostTxExtras,
    Adjust = NoPreTxAdjust,
> where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    inner: Inner,
    inspector: FirehoseInspector<G>,
    fees: BlockFees,
    withdrawals: Option<Withdrawals>,
    /// Beneficiaries of the block's ommer (uncle) headers, in block-body order. Empty after the
    /// Merge. See [`Self::with_ommer_beneficiaries`].
    ommer_beneficiaries: Vec<Address>,
    /// Running count of logs emitted so far in this block, used to derive each receipt's
    /// block-wide `log_index_start` when building `on_tx_end` receipt data.
    log_index: u32,
    extras: Extras,
    adjust: Adjust,
}

impl<Inner, G, Extras, Adjust> Debug for FirehoseWrappedExecutor<Inner, G, Extras, Adjust>
where
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirehoseWrappedExecutor").field("log_index", &self.log_index).finish()
    }
}

impl<Inner, G> FirehoseWrappedExecutor<Inner, G>
where
    Inner: BlockExecutor,
    G: DerefMut<Target = firehose_tracer::Tracer> + 'static,
{
    /// Wraps `inner` with Firehose tracer hooks and installs `inspector` on its EVM. `withdrawals`
    /// is consumed at finish to emit per-address balance changes for EIP-4895 validator
    /// withdrawals.
    pub fn new(
        inner: Inner,
        inspector: FirehoseInspector<G>,
        fees: BlockFees,
        withdrawals: Option<Withdrawals>,
    ) -> Self {
        Self::with_hooks(inner, inspector, fees, withdrawals, NoPreTxAdjust, NoPostTxExtras)
    }
}

impl<Inner, G, Extras, Adjust> FirehoseWrappedExecutor<Inner, G, Extras, Adjust>
where
    Inner: BlockExecutor,
    G: DerefMut<Target = firehose_tracer::Tracer> + 'static,
{
    /// Like [`Self::new`] with chain-specific [`PreTxAdjust`] and [`PostTxExtras`] hooks.
    pub fn with_hooks(
        mut inner: Inner,
        inspector: FirehoseInspector<G>,
        fees: BlockFees,
        withdrawals: Option<Withdrawals>,
        adjust: Adjust,
        extras: Extras,
    ) -> Self {
        inner.evm_mut().set_inspector(inspector.clone());
        inner.evm_mut().set_inspect_system_calls(true);
        Self {
            inner,
            inspector,
            fees,
            withdrawals,
            ommer_beneficiaries: Vec::new(),
            log_index: 0,
            extras,
            adjust,
        }
    }

    /// Sets the block's ommer beneficiaries, for the `RewardMineUncle` changes emitted at finish.
    ///
    /// Only pre-Merge blocks have ommers. Without this the wrapper still emits the coinbase's
    /// `RewardMineBlock` change, but no uncle rewards.
    pub fn with_ommer_beneficiaries(mut self, ommer_beneficiaries: Vec<Address>) -> Self {
        self.ommer_beneficiaries = ommer_beneficiaries;
        self
    }

}

impl<Inner, G, Extras, Adjust> FirehoseWrappedExecutor<Inner, G, Extras, Adjust>
where
    Inner: BlockExecutor,
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    /// Snapshots, before the inner finish, the accounts whose post-block changes bypass the
    /// inspector: the pre-Merge block and uncle reward recipients, and the accounts the
    /// `PrimordialPulse` transition writes at its fork block.
    fn capture_post_block_pre_state(&mut self) -> PostBlockPreState {
        // The static block reward exists only before the Merge, and every post-Shanghai block
        // carries withdrawals, so a block with withdrawals has no reward to sample.
        let reward = self.withdrawals.is_none().then(|| {
            let evm = self.inner.evm_mut();
            BlockRewardPreState {
                coinbase: self.fees.coinbase,
                coinbase_pre: account_balance(evm, self.fees.coinbase),
                ommer_pre: self
                    .ommer_beneficiaries
                    .iter()
                    .map(|&address| (address, account_balance(evm, address)))
                    .collect(),
            }
        });
        let chain_id = self.fees.version.chain_id;
        let block_number = self.fees.block_number;
        let primordial_pulse = crate::primordial_pulse::fork_block_for(chain_id)
            .filter(|&fork_block| fork_block == block_number)
            .and_then(|_| {
                crate::primordial_pulse::PrimordialPulsePreState::capture(
                    self.inner.evm_mut().state_db_mut(),
                    chain_id,
                    block_number,
                )
            });
        PostBlockPreState { reward, primordial_pulse }
    }
}

/// Accounts snapshot by [`FirehoseWrappedExecutor::capture_post_block_pre_state`].
#[derive(Debug)]
struct PostBlockPreState {
    reward: Option<BlockRewardPreState>,
    primordial_pulse: Option<crate::primordial_pulse::PrimordialPulsePreState>,
}

/// Emits the post-block changes that bypass the inspector, after the withdrawals, in this order:
/// the block reward, the uncle rewards, then the `PrimordialPulse` transition.
fn emit_post_block_changes<G: DerefMut<Target = firehose_tracer::Tracer>>(
    inspector: &FirehoseInspector<G>,
    pre: &PostBlockPreState,
    state: &BundleState,
) {
    if let Some(reward) = &pre.reward {
        emit_block_reward_balance_changes(inspector, reward, state);
    }
    if let Some(primordial_pulse) = &pre.primordial_pulse {
        crate::primordial_pulse::emit_primordial_pulse_changes(
            &mut inspector.tracer_mut(),
            primordial_pulse,
            state,
        );
    }
}

/// Pre-finish balances of the accounts the pre-Merge block reward credits: the coinbase, and each
/// ommer beneficiary in block-body order (Geth's firehose emits one `RewardMineUncle` change per
/// uncle, in that order).
#[derive(Debug)]
struct BlockRewardPreState {
    coinbase: Address,
    coinbase_pre: U256,
    ommer_pre: Vec<(Address, U256)>,
}

/// Returns an account's balance in the block's final state, or `pre` when the block left the
/// account unchanged.
fn final_balance(state: &BundleState, address: Address, pre: U256) -> U256 {
    match state.account(&address) {
        Some(account) => account.info.as_ref().map(|info| info.balance).unwrap_or_default(),
        None => pre,
    }
}

/// Emits the pre-Merge block reward (`RewardMineBlock`) and uncle rewards (`RewardMineUncle`).
///
/// The inner executor credits them during finish, outside the EVM, so the inspector never sees
/// them. Each change is the account's pre-finish balance against its final balance.
///
/// Known edge case: if the coinbase is also an ommer beneficiary, both changes span the account's
/// whole increase instead of Geth's sequential deltas. No Ethereum mainnet or `PulseChain` block is
/// known to hit this.
fn emit_block_reward_balance_changes<G: DerefMut<Target = firehose_tracer::Tracer>>(
    inspector: &FirehoseInspector<G>,
    pre: &BlockRewardPreState,
    state: &BundleState,
) {
    use firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let mut tracer = inspector.tracer_mut();
    // `on_balance_change` drops no-op changes itself.
    let coinbase_post = final_balance(state, pre.coinbase, pre.coinbase_pre);
    tracer.on_balance_change(pre.coinbase, pre.coinbase_pre, coinbase_post, Reason::RewardMineBlock);
    for &(address, pre_balance) in &pre.ommer_pre {
        let post_balance = final_balance(state, address, pre_balance);
        tracer.on_balance_change(address, pre_balance, post_balance, Reason::RewardMineUncle);
    }
}

impl<Inner, G, Extras, Adjust> BlockExecutor for FirehoseWrappedExecutor<Inner, G, Extras, Adjust>
where
    Inner: BlockExecutor,
    Inner::Transaction: Transaction + TxHashRef + SignatureFields,
    Inner::Receipt: TxReceipt<Log = Log>,
    G: DerefMut<Target = firehose_tracer::Tracer>,
    Extras: PostTxExtras<Inner::Evm>,
    Adjust: PreTxAdjust<Inner::Evm>,
{
    type Transaction = Inner::Transaction;
    type Receipt = Inner::Receipt;
    type Evm = Inner::Evm;
    type TransactionResultWithState = Inner::TransactionResultWithState;
    type BlockAccessList = Inner::BlockAccessList;

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn set_state_hook(&mut self, hook: impl FnMut(StateUpdate) + Send + 'static) -> bool {
        self.inner.set_state_hook(hook)
    }

    fn convert_block_access_list(
        block_access_list: &BlockAccessList,
    ) -> Result<Self::BlockAccessList, BlockExecutionError> {
        Inner::convert_block_access_list(block_access_list)
    }

    fn set_block_access_list(&mut self, block_access_list: Arc<Self::BlockAccessList>) {
        self.inner.set_block_access_list(block_access_list);
    }

    fn set_block_access_index(&mut self, index: BlockAccessIndex) {
        self.inner.set_block_access_index(index);
    }

    fn enable_block_access_list_builder(&mut self) {
        self.inner.enable_block_access_list_builder();
    }

    fn take_block_access_list(&mut self) -> Option<BlockAccessList> {
        self.inner.take_block_access_list()
    }

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inspector.tracer_mut().on_system_call_start();
        let res = self.inner.apply_pre_execution_changes();
        self.inspector.tracer_mut().on_system_call_end();
        res
    }

    fn into_state(self) -> BundleState {
        self.inner.into_state()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        transaction: impl ExecutorTx<Self>,
        f: impl FnOnce(&evm2::TxResult<<Self::Evm as reth_evm::Evm>::EvmTypes>) -> CommitChanges,
    ) -> Result<Option<GasOutput>, BlockExecutionError> {
        let (tx_env, recovered) = transaction.into_parts();
        let sender = *recovered.signer();
        let tx_index = self.inner.receipts().len();

        let tx = recovered.tx();
        let (r, s, v) = tx.signature_fields();
        let mut tx_event = mapper::signed_tx_to_tx_event(tx, sender, tx_index, r, s, v);
        let effective_gas_price = tx.effective_gas_price(Some(self.fees.base_fee));
        let gas_limit = tx.gas_limit();
        // EIP-4844: total blob gas consumed by this tx (num_blobs × GAS_PER_BLOB); 0 for
        // non-blob tx types. Geth populates `receipt.BlobGasUsed` from this value.
        let blob_gas_used = tx.blob_gas_used().unwrap_or(0);
        let frameless = FramelessParts::of(tx);

        // Chain-specific pre-tx patching of the event (e.g. OP Stack deposit nonce override).
        self.adjust.adjust_tx_event(self.inner.evm_mut(), &self.inspector, &mut tx_event, sender);
        self.inspector.tracer_mut().on_tx_start(tx_event, None);

        // The transaction is executed and committed in two steps so the post-transaction balance
        // changes are emitted while the EVM still reads the state before the transaction.
        self.inspector.start_transaction();
        let result = self.inner.execute_transaction_without_commit((tx_env, &recovered))?;
        let tx_result = &result.result().result;
        let gas_used = tx_result.tx_gas_used();
        // Logs that survived reverts, which advance the block-wide log counter.
        let committed_log_count = tx_result.logs.len() as u32;

        let accounting = self.extras.gas_accounting(
            self.inner.evm_mut(),
            PostTxGasAccounting::ethereum(effective_gas_price, self.fees.base_fee),
        );

        // An Amsterdam transaction whose EIP-2780 runtime gas phase ran out of gas is included
        // without its root frame ever opening, see `trace_frameless_root_call`.
        if !self.inspector.root_frame_entered() {
            let tx = frameless.into_tx(&self.fees.version, sender, gas_limit);
            let gas_buy_cost = U256::from(gas_limit) * U256::from(effective_gas_price) +
                U256::from(blob_gas_used) * self.fees.blob_gas_price.unwrap_or_default();
            let pre_tx_balance = account_balance(self.inner.evm_mut(), sender);
            self.inspector.trace_frameless_root_call(sender, gas_buy_cost, tx, pre_tx_balance);
        }

        // Gas refund to the sender and fee reward to the coinbase.
        let evm = self.inner.evm_mut();
        self.inspector.process_post_tx_gas_accounting(
            sender,
            self.fees.coinbase,
            gas_limit,
            gas_used,
            accounting,
            committed_log_count,
            |address| account_balance(evm, address),
        );

        // Chain-specific post-tx balance emissions (e.g. OP Stack fee vault credits), after the
        // generic ones so ordinals follow the handler order.
        self.extras.emit_post_tx_extras(
            self.inner.evm_mut(),
            &self.inspector,
            gas_used,
            self.fees.base_fee,
        );

        if !f(&result.result().result).should_commit() {
            // Preserve the invariant that every on_tx_start is paired with on_tx_end.
            let err = std::io::Error::other("transaction not committed");
            self.inspector.tracer_mut().on_tx_end(None, Some(&err));
            return Ok(None);
        }

        let gas_output = self.inner.commit_transaction(result)?;

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
                self.fees.blob_gas_price,
            )
        };
        self.inspector.tracer_mut().on_tx_end(Some(&receipt_data), None);

        Ok(Some(gas_output))
    }

    fn validate_transaction_gas_limit(
        &mut self,
        gas_limit: u64,
    ) -> Result<(), BlockExecutionError> {
        self.inner.validate_transaction_gas_limit(gas_limit)
    }

    fn execute_transaction_without_commit(
        &mut self,
        transaction: impl ExecutorTx<Self>,
    ) -> Result<Self::TransactionResultWithState, BlockExecutionError> {
        let (tx_env, recovered) = transaction.into_parts();
        self.inner.execute_transaction_without_commit((tx_env, &recovered))
    }

    fn commit_transaction(
        &mut self,
        output: Self::TransactionResultWithState,
    ) -> Result<GasOutput, BlockExecutionError> {
        self.inner.commit_transaction(output)
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }

    fn finish_with_block_access_list(
        mut self,
    ) -> Result<(BlockExecutionOutput<Self::Receipt>, Option<BlockAccessList>), BlockExecutionError>
    {
        let post_block_pre = self.capture_post_block_pre_state();
        let Self { inner, inspector, withdrawals, .. } = self;
        // The post-execution system calls (EIP-7002 withdrawal requests, EIP-7251 consolidation
        // requests) run inside the window; withdrawals are emitted after it closes.
        inspector.tracer_mut().on_system_call_start();
        let finished = inner.finish_with_block_access_list();
        inspector.tracer_mut().on_system_call_end();
        let (output, bal) = finished?;
        emit_withdrawal_balance_changes(&inspector, withdrawals.as_ref(), &output.state);
        emit_post_block_changes(&inspector, &post_block_pre, &output.state);
        Ok((output, bal))
    }

    fn finish_with_prepared_block_access_list(
        mut self,
    ) -> Result<(BlockExecutionOutput<Self::Receipt>, Option<evm2::evm::Bal>), BlockExecutionError>
    {
        let post_block_pre = self.capture_post_block_pre_state();
        let Self { inner, inspector, withdrawals, .. } = self;
        inspector.tracer_mut().on_system_call_start();
        let finished = inner.finish_with_prepared_block_access_list();
        inspector.tracer_mut().on_system_call_end();
        let (output, bal) = finished?;
        emit_withdrawal_balance_changes(&inspector, withdrawals.as_ref(), &output.state);
        emit_post_block_changes(&inspector, &post_block_pre, &output.state);
        Ok((output, bal))
    }
}

/// Emits EIP-4895 withdrawal balance changes once the post-execution system-call window has
/// closed, so they land in `block.balance_changes`.
///
/// Withdrawals are credited during the inner finish, outside the EVM, so the inspector never sees
/// them. Each event is reconstructed by walking the withdrawal list backwards from the final
/// balance in `state` (see [`withdrawal_balance_events`]), so each gets its own ordinal.
fn emit_withdrawal_balance_changes<G: DerefMut<Target = firehose_tracer::Tracer>>(
    inspector: &FirehoseInspector<G>,
    withdrawals: Option<&Withdrawals>,
    state: &BundleState,
) {
    use firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason;

    let Some(withdrawals) = withdrawals else { return };
    let events = withdrawal_balance_events(withdrawals.as_slice(), |address| {
        state
            .account(&address)
            .and_then(|account| account.info.as_ref())
            .map(|info| info.balance)
            .unwrap_or_default()
    });
    let mut tracer = inspector.tracer_mut();
    for (address, pre, post) in events {
        tracer.on_balance_change(address, pre, post, Reason::Withdrawal);
    }
}

fn account_balance(evm: &mut impl reth_evm::Evm, address: Address) -> U256 {
    evm.account_info(&address).ok().flatten().map(|info| info.balance).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// FirehoseBlockExecutor (pipeline Executor)
// ---------------------------------------------------------------------------

/// Per-block Firehose tracing strategy bound to a [`ConfigureEvm`] flavour.
///
/// Exists so chain integrators (OP Stack, mainnet, ...) can plug chain-specific
/// [`PostTxExtras`] / [`PreTxAdjust`] hooks into the pipeline. An implementation typically calls
/// [`run_wrapped_block`] with its hooks.
///
/// The implementation must NOT emit `on_block_start` / `on_block_end` — those are owned
/// by [`FirehoseBlockExecutor`] via the [`FirehoseBlockTracer`] lifecycle.
pub trait ChainHooks<F: ConfigureEvm>: Send + Sync + Clone + Unpin + 'static {
    /// Run one traced block against `database`, using `tracer`'s inspector for mid-block events.
    /// Returns the block access list rebuilt by the execution when the header declares one.
    #[expect(clippy::type_complexity)]
    fn execute_one_traced(
        &self,
        evm_config: &F,
        database: impl DynDatabase,
        block: &RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
        tracer: &mut FirehoseBlockTracer,
    ) -> Result<
        (BlockExecutionOutput<<F::Primitives as NodePrimitives>::Receipt>, Option<BlockAccessList>),
        BlockExecutionError,
    >;
}

/// No-op [`ChainHooks`] for mainnet Ethereum — installs [`NoPostTxExtras`] / [`NoPreTxAdjust`].
#[derive(Default, Debug, Clone, Copy)]
pub struct NoChainHooks;

impl<F> ChainHooks<F> for NoChainHooks
where
    F: ConfigureEvm,
    BlockTy<F::Primitives>: BlockTrait,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
    <F::Primitives as NodePrimitives>::Receipt: TxReceipt<Log = Log>,
{
    fn execute_one_traced(
        &self,
        evm_config: &F,
        database: impl DynDatabase,
        block: &RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
        tracer: &mut FirehoseBlockTracer,
    ) -> Result<
        (BlockExecutionOutput<<F::Primitives as NodePrimitives>::Receipt>, Option<BlockAccessList>),
        BlockExecutionError,
    > {
        run_wrapped_block(evm_config, database, block, tracer, NoPreTxAdjust, NoPostTxExtras)
    }
}

/// Chain-specific hooks the live engine-API path installs on its traced block executor.
///
/// The engine tree's block validator wraps the traced executor in
/// [`FirehoseWrappedExecutor::with_hooks`] with the hook types selected here by the node's EVM
/// configuration. This is the live-path counterpart of [`ChainHooks`], which serves the pipeline.
///
/// Every EVM configuration used with the engine tree's block validator must implement this trait,
/// so a chain cannot silently trace live blocks without its hooks.
pub trait FirehoseLiveHooks: ConfigureEvm {
    /// Hook that patches each transaction event before it reaches the tracer.
    type PreTxAdjust: for<'a> PreTxAdjust<EvmFor<'a, Self>> + Default;
    /// Hook that emits chain-specific balance changes after each transaction.
    type PostTxExtras: for<'a> PostTxExtras<EvmFor<'a, Self>> + Default;
}

impl<F> FirehoseLiveHooks for FirehoseEvmConfig<F>
where
    Self: ConfigureEvm,
{
    type PreTxAdjust = NoPreTxAdjust;
    type PostTxExtras = NoPostTxExtras;
}

impl<ChainSpec, EvmF> FirehoseLiveHooks for reth_evm_ethereum::EthEvmConfig<ChainSpec, EvmF>
where
    EvmF: reth_evm_ethereum::EvmFactory,
    Self: ConfigureEvm,
{
    type PreTxAdjust = NoPreTxAdjust;
    type PostTxExtras = NoPostTxExtras;
}

impl<Inner> FirehoseLiveHooks for reth_evm::noop::NoopEvmConfig<Inner>
where
    Inner: FirehoseLiveHooks,
    Self: ConfigureEvm<BlockExecutorFactory = Inner::BlockExecutorFactory>,
{
    type PreTxAdjust = Inner::PreTxAdjust;
    type PostTxExtras = Inner::PostTxExtras;
}

/// Pipeline [`Executor`] that runs each block through a per-block wrapping strategy
/// ([`ChainHooks`]) and defers the end-of-block flush until post-execution validation
/// succeeds. See the module-level docs.
///
/// Its batch state handling mirrors [`reth_evm::execute::BasicBlockExecutor`]. By default `H`
/// resolves to [`NoChainHooks`] (mainnet Ethereum).
pub struct FirehoseBlockExecutor<F, DB: Database, H = NoChainHooks> {
    evm_config: F,
    batch_database: CacheDB<Db<DB>>,
    batch_state: BundleState,
    block_access_list: Option<BlockAccessList>,
    /// Tracer guard for the most recently executed block. Finalized by the next
    /// `execute_and_trace_one` call or by `into_state` — see the module-level docs.
    pending_tracer: Option<FirehoseBlockTracer>,
    /// Chain-specific per-block wrapping strategy.
    hooks: H,
}

impl<F, DB: Database, H> Debug for FirehoseBlockExecutor<F, DB, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirehoseBlockExecutor").finish()
    }
}

impl<F, DB: Database> FirehoseBlockExecutor<F, DB, NoChainHooks> {
    /// Creates a new `FirehoseBlockExecutor` with the default [`NoChainHooks`] (mainnet).
    pub fn new(evm_config: F, database: DB) -> Self {
        Self::new_with_chain_hooks(evm_config, database, NoChainHooks)
    }
}

impl<F, DB: Database, H> FirehoseBlockExecutor<F, DB, H> {
    /// Creates a new `FirehoseBlockExecutor` with a caller-supplied [`ChainHooks`].
    pub fn new_with_chain_hooks(evm_config: F, database: DB, hooks: H) -> Self {
        Self {
            evm_config,
            batch_database: CacheDB::new(Db::new(database)),
            batch_state: BundleState::default(),
            block_access_list: None,
            pending_tracer: None,
            hooks,
        }
    }
}

impl<F, DB, H> FirehoseBlockExecutor<F, DB, H>
where
    F: ConfigureEvm,
    DB: Database,
{
    /// Executes `block` untraced, exactly like [`reth_evm::execute::BasicBlockExecutor`].
    fn execute_untraced(
        &mut self,
        block: &RecoveredBlock<BlockTy<F::Primitives>>,
        state_hook: Option<Box<dyn FnMut(StateUpdate) + Send>>,
    ) -> Result<BlockExecutionResult<<F::Primitives as NodePrimitives>::Receipt>, BlockExecutionError>
    {
        let evm_env =
            self.evm_config.evm_env(block.header()).map_err(BlockExecutionError::other)?;
        let evm = self
            .evm_config
            .block_executor_factory()
            .evm_with_env(&mut self.batch_database, evm_env);
        let ctx = self
            .evm_config
            .context_for_block(block.sealed_block())
            .map_err(BlockExecutionError::other)?;
        let mut executor = self.evm_config.block_executor_factory().create_executor(evm, ctx);
        if block.header().block_access_list_hash().is_some() {
            executor.enable_block_access_list_builder();
        }
        if let Some(hook) = state_hook &&
            !executor.set_state_hook(hook)
        {
            return Err(BlockExecutionError::msg("block executor does not support state hooks"))
        }
        executor.apply_pre_execution_changes()?;
        for transaction in block.transactions_recovered() {
            executor.execute_transaction(transaction)?;
        }
        let (output, block_access_list) = executor.finish_with_block_access_list()?;
        Ok(self.commit_block(output, block_access_list))
    }

    fn commit_block(
        &mut self,
        output: BlockExecutionOutput<<F::Primitives as NodePrimitives>::Receipt>,
        block_access_list: Option<BlockAccessList>,
    ) -> BlockExecutionResult<<F::Primitives as NodePrimitives>::Receipt> {
        self.block_access_list = block_access_list;
        self.batch_database.commit_source(&BundleSource(&output.state));
        self.batch_state.extend(output.state);
        output.result
    }
}

impl<F, DB, H> Executor<DB> for FirehoseBlockExecutor<F, DB, H>
where
    F: ConfigureEvm,
    DB: Database,
    H: ChainHooks<F>,
    BlockTy<F::Primitives>: BlockTrait,
    <BlockTy<F::Primitives> as BlockTrait>::Header: BlockHeader + Sealable,
    <BlockTy<F::Primitives> as BlockTrait>::Body: BlockBody,
    <<BlockTy<F::Primitives> as BlockTrait>::Body as BlockBody>::OmmerHeader:
        BlockHeader + Sealable,
{
    type Primitives = F::Primitives;
    type Error = BlockExecutionError;

    fn execute_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        self.execute_untraced(block, None)
    }

    /// Traces a block with Firehose hooks and defers `on_block_end(None)` until the caller has
    /// validated the result. See the module-level docs for the deferral contract.
    fn execute_and_trace_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        if !crate::is_tracer_initialized() {
            // Tracing disabled (e.g. FIREHOSE_DISABLED kill-switch): run the plain untraced
            // executor so the node behaves exactly like the un-instrumented upstream.
            return self.execute_one(block);
        }

        // The previous block has reached a point where the caller would have returned early on
        // validation failure; since we've been called again, it passed and can be flushed.
        if let Some(prev) = self.pending_tracer.take() {
            prev.mark_verified();
        }

        // Staged sync only replays blocks up to the finalized head, so the block is finalized.
        let finalized = Some(firehose_tracer::types::FinalizedBlockRef {
            number: block.header().number(),
            hash: Some(block.hash()),
        });
        let mut tracer =
            FirehoseBlockTracer::start::<F::Primitives>(block.sealed_block(), finalized);

        let traced = self
            .hooks
            .execute_one_traced(&self.evm_config, &mut self.batch_database, block, &mut tracer)
            .and_then(|(output, bal)| {
                record_block_access_list(block, bal.as_ref(), &mut tracer)?;
                Ok((output, bal))
            });

        match traced {
            Ok((output, bal)) => {
                self.pending_tracer = Some(tracer);
                Ok(self.commit_block(output, bal))
            }
            Err(err) => {
                tracer.mark_failed(&err);
                Err(err)
            }
        }
    }

    fn execute_one_with_state_hook<S>(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
        state_hook: S,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    where
        S: FnMut(StateUpdate) + Send + 'static,
    {
        self.execute_untraced(block, Some(Box::new(state_hook)))
    }

    fn size_hint(&self) -> usize {
        self.batch_state.size_hint()
    }

    fn into_state(mut self) -> BundleState {
        // Reaching `into_state` without an error means the batch completed successfully —
        // including post-execution validation on the most recent block — so finalize any
        // pending tracer as verified rather than letting Drop discard it.
        if let Some(pending) = self.pending_tracer.take() {
            pending.mark_verified();
        }
        std::mem::take(&mut self.batch_state)
    }

    fn take_bal(&mut self) -> Option<BlockAccessList> {
        self.block_access_list.take()
    }
}

/// Runs a single block through a [`FirehoseWrappedExecutor`] with the tracer held by
/// `tracer_guard` installed on the EVM as a [`FirehoseInspector`], and returns its output and the
/// block access list it rebuilt when the header declares one.
///
/// Generic over the tracer handle `G`, so it works with the process-wide global guard
/// ([`GlobalTracerGuard`], the default) and with a caller-owned tracer (the test harness captures
/// a block's Firehose output into an in-memory buffer this way).
///
/// Does **not** emit `on_block_start` / `on_block_end` — those are owned by the
/// [`FirehoseBlockTracer`] lifecycle. Use [`record_block_access_list`] to check the rebuilt
/// block access list against the header and record it on the traced block.
#[expect(clippy::type_complexity)]
pub fn run_wrapped_block<F, Extras, Adjust, G>(
    evm_config: &F,
    database: impl DynDatabase,
    block: &RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
    tracer_guard: &mut FirehoseBlockTracer<G>,
    adjust: Adjust,
    extras: Extras,
) -> Result<
    (BlockExecutionOutput<<F::Primitives as NodePrimitives>::Receipt>, Option<BlockAccessList>),
    BlockExecutionError,
>
where
    F: ConfigureEvm,
    G: DerefMut<Target = firehose_tracer::Tracer> + 'static,
    TxTy<F::Primitives>: Transaction + TxHashRef + SignatureFields,
    <F::Primitives as NodePrimitives>::Receipt: TxReceipt<Log = Log>,
    for<'a> Extras: PostTxExtras<EvmFor<'a, F>>,
    for<'a> Adjust: PreTxAdjust<EvmFor<'a, F>>,
{
    let evm_env: EvmEnvFor<F> =
        evm_config.evm_env(block.header()).map_err(BlockExecutionError::other)?;
    let fees = BlockFees::new(&evm_env);
    let evm = evm_config.block_executor_factory().evm_with_env(database, evm_env);
    let ctx =
        evm_config.context_for_block(block.sealed_block()).map_err(BlockExecutionError::other)?;
    let mut inner = evm_config.block_executor_factory().create_executor(evm, ctx);
    // EIP-7928: the pipeline has no payload sidecar to source the block access list from, unlike
    // the live engine path, so it is rebuilt from the execution whenever the header declares one.
    if block.header().block_access_list_hash().is_some() {
        inner.enable_block_access_list_builder();
    }

    let withdrawals = block.body().withdrawals().cloned();
    let ommer_beneficiaries = block
        .body()
        .ommers()
        .map(|ommers| ommers.iter().map(|header| header.beneficiary()).collect())
        .unwrap_or_default();
    let mut executor = FirehoseWrappedExecutor::with_hooks(
        inner,
        tracer_guard.inspector(),
        fees,
        withdrawals,
        adjust,
        extras,
    )
    .with_ommer_beneficiaries(ommer_beneficiaries);
    executor.apply_pre_execution_changes()?;
    for transaction in block.transactions_recovered() {
        executor.execute_transaction(transaction)?;
    }
    executor.finish_with_block_access_list()
}

/// Checks the block access list rebuilt for `block` against the header's
/// `block_access_list_hash` and records its RLP on the traced block. A no-op when the header
/// declares no block access list.
pub fn record_block_access_list<B, G>(
    block: &RecoveredBlock<B>,
    bal: Option<&BlockAccessList>,
    tracer_guard: &mut FirehoseBlockTracer<G>,
) -> Result<(), BlockExecutionError>
where
    B: BlockTrait,
    G: DerefMut<Target = firehose_tracer::Tracer>,
{
    let Some(expected_hash) = block.header().block_access_list_hash() else { return Ok(()) };
    let Some(bal) = bal else {
        return Err(BlockExecutionError::msg(format!(
            "no block access list rebuilt for block {}, whose header declares one",
            block.header().number(),
        )));
    };

    let computed_hash = alloy_eip7928::compute_block_access_list_hash(bal.as_slice());
    // A mismatch means the reconstruction is wrong, not that the block is invalid: the hash was
    // already validated by the node.
    if computed_hash != expected_hash {
        return Err(BlockExecutionError::msg(format!(
            "reconstructed block access list hash mismatch for block {}: expected {expected_hash}, computed {computed_hash}",
            block.header().number(),
        )));
    }
    if let Some(header) = tracer_guard.tracer_mut().block_mut().and_then(|b| b.header.as_mut()) {
        header.block_access_list_rlp = Some(alloy_rlp::encode(bal));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The fields of a transaction [`FramelessTx`] is built from, captured before the transaction is
/// handed to the EVM. Only turned into a [`FramelessTx`] for the rare transaction whose root frame
/// never opened.
struct FramelessParts {
    kind: TxKind,
    value: U256,
    input: alloy_primitives::Bytes,
    nonce: u64,
    access_list_accounts: u64,
    access_list_storages: u64,
    authorization_count: usize,
}

impl FramelessParts {
    fn of(tx: &impl Transaction) -> Self {
        let (access_list_accounts, access_list_storages) =
            tx.access_list().map_or((0, 0), |list| {
                list.iter().fold((0, 0), |(accounts, storages), item| {
                    (accounts + 1, storages + item.storage_keys.len() as u64)
                })
            });
        Self {
            kind: tx.kind(),
            value: tx.value(),
            input: tx.input().clone(),
            nonce: tx.nonce(),
            access_list_accounts,
            access_list_storages,
            authorization_count: tx.authorization_list().map_or(0, |list| list.len()),
        }
    }

    /// Computes the regular gas the root frame would have been handed, as evm2's transaction
    /// handlers do. Under EIP-2780, the only fork with frameless transactions, no state gas is
    /// charged at the intrinsic phase.
    fn into_tx(self, version: &evm2::Version, sender: Address, gas_limit: u64) -> FramelessTx {
        let (intrinsic, _) = evm2::ethereum::intrinsic_and_floor_gas(
            version,
            sender,
            self.kind,
            &self.input,
            self.access_list_accounts,
            self.access_list_storages,
            self.value,
        );
        let intrinsic = intrinsic +
            evm2::ethereum::eip7702::eip7702_authorization_gas(version, self.authorization_count);
        let (root_gas_limit, _) =
            evm2::ethereum::initial_gas_and_reservoir(version, gas_limit, intrinsic, 0);
        FramelessTx {
            kind: self.kind,
            value: self.value,
            input: self.input,
            nonce: self.nonce,
            root_gas_limit,
        }
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

/// A [`ConfigureEvm`] wrapper that routes `batch_executor` through [`FirehoseBlockExecutor`].
///
/// Every other method forwards to the wrapped config, except
/// [`ConfigureEvm::reuses_prewarm_results`], which keeps its `false` default: committing a
/// prewarmed result skips execution, so the tracer would not see that transaction.
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
    <F::Primitives as NodePrimitives>::Receipt: TxReceipt<Log = Log>,
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
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &reth_primitives_traits::HeaderTy<Self::Primitives>,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a reth_primitives_traits::SealedBlock<BlockTy<Self::Primitives>>,
    ) -> Result<reth_evm::ExecutionCtxFor<'a, Self>, Self::Error>
    where
        Self: 'a,
    {
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

    fn with_jit_support_enabled(self, enabled: bool) -> Self {
        Self { inner: self.inner.with_jit_support_enabled(enabled) }
    }

    fn evm_with_precompile_cache<'a, DB>(
        &self,
        db: DB,
        evm_env: EvmEnvFor<Self>,
        cache_map: reth_evm::precompile_cache::PrecompileCacheMap<reth_evm::SpecFor<Self>>,
        metrics_enabled: bool,
    ) -> EvmFor<'a, Self>
    where
        DB: Database + 'a,
    {
        self.inner.evm_with_precompile_cache(db, evm_env, cache_map, metrics_enabled)
    }

    fn jit_backend(&self) -> Option<&dyn reth_evm::JitBackend> {
        self.inner.jit_backend()
    }

    fn batch_executor<DB: Database>(
        &self,
        db: DB,
    ) -> impl Executor<DB, Primitives = Self::Primitives, Error = BlockExecutionError> {
        FirehoseBlockExecutor::new(self.inner.clone(), db)
    }
}

impl<F, ExecutionData> reth_evm::ConfigureEngineEvm<ExecutionData> for FirehoseEvmConfig<F>
where
    F: reth_evm::ConfigureEngineEvm<ExecutionData>,
    Self: ConfigureEvm<
        Primitives = F::Primitives,
        Error = F::Error,
        BlockExecutorFactory = F::BlockExecutorFactory,
    >,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
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
