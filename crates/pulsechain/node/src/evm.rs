//! `PulseChain` EVM configuration and block executor.
//!
//! Provides:
//! - [`PulsechainEvmConfig`]: Wraps [`EthEvmConfig`], overriding the CHAINID opcode so that blocks
//!   *before* `PrimordialPulse` return `chain_id = 1` (Ethereum mainnet) and blocks *at or after*
//!   the fork return the `PulseChain` chain ID (369 mainnet / 943 testnet v4).
//! - [`PulsechainBlockExecutorFactory`]: Wraps [`EthBlockExecutorFactory`], calling
//!   [`apply_primordial_pulse`] exactly once at the fork block after all transactions execute but
//!   before state commitment.
//! - [`PulsechainExecutorBuilder`]: Integrates the above into the reth node builder.

use std::{borrow::Cow, convert::Infallible, fmt::Debug, sync::Arc};

use alloy_consensus::{
    transaction::TransactionEnvelope, Header, Transaction as AlloyTransaction, TxReceipt,
};
use alloy_eips::{eip7685::Requests, Decodable2718, Encodable2718};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockValidationError, ExecutableTx, GasOutput, OnStateHook, StateDB,
    },
    eth::{
        receipt_builder::ReceiptBuilder, spec::EthExecutorSpec, EthBlockExecutionCtx,
        EthBlockExecutor, EthBlockExecutorFactory, EthEvmFactory, EthTxResult,
    },
    precompiles::PrecompilesMap,
    Evm, EvmEnv, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Bytes, Log, B256, U256};
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_ethereum_primitives::{Block, EthPrimitives, TransactionSigned};
use reth_evm::{
    ConfigureEngineEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor, NextBlockEnvAttributes,
    TransactionEnvMut,
};
use reth_evm_ethereum::{
    revm_spec_by_timestamp_and_block_number, EthBlockAssembler, EthEvmConfig, RethReceiptBuilder,
};
use reth_node_builder::{components::ExecutorBuilder, BuilderContext, FullNodeTypes, NodeTypes};
use reth_primitives_traits::{
    constants::MAX_TX_GAS_LIMIT_OSAKA, SealedBlock, SealedHeader, SignedTransaction,
};
use reth_storage_errors::any::AnyError;
use revm::{
    context::{BlockEnv, CfgEnv},
    // Block trait provides `.number()`, `.timestamp()`, etc. on `BlockEnv`.
    context_interface::block::{BlobExcessGasAndPrice, Block as RevmBlock},
    database::DatabaseCommitExt,
    primitives::hardfork::SpecId,
    state::{Account, AccountInfo, Bytecode, EvmStorageSlot},
};

use crate::fork::{apply_primordial_pulse, PrimordialPulseStateWriter};
use reth_pulsechain_forks::{
    chainspec::{
        chain_id_at_block_mainnet, chain_id_at_block_testnet_v4, PULSECHAIN_MAINNET_CHAIN_ID,
        PULSECHAIN_TESTNET_V4_CHAIN_ID,
    },
    hardfork::{
        ETH_MAINNET_MERGE_BLOCK, ETH_MAINNET_SHANGHAI_TIMESTAMP, PRIMORDIAL_PULSE_MAINNET_BLOCK,
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
    },
};

// ── Chain-ID helpers ─────────────────────────────────────────────────────────

/// Returns the effective CHAINID at `block_number` for the given `PulseChain` chain.
///
/// Before `PrimordialPulse`: returns `1` (Ethereum mainnet).
/// At or after `PrimordialPulse`: returns `base_chain_id` (369 or 943).
const fn chain_id_for_block(base_chain_id: u64, block_number: u64) -> u64 {
    match base_chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => chain_id_at_block_mainnet(block_number),
        PULSECHAIN_TESTNET_V4_CHAIN_ID => chain_id_at_block_testnet_v4(block_number),
        other => other,
    }
}

/// Returns the `PrimordialPulse` fork block for the given `PulseChain` chain ID.
const fn primordial_pulse_block_for_chain(chain_id: u64) -> u64 {
    match chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => PRIMORDIAL_PULSE_MAINNET_BLOCK,
        PULSECHAIN_TESTNET_V4_CHAIN_ID => PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        // Non-PulseChain chain: use u64::MAX so the hook never fires.
        _ => u64::MAX,
    }
}

// ── PrimordialPulseStateWriter blanket impl for any StateDB ──────────────────

/// Implements [`PrimordialPulseStateWriter`] for any type implementing [`StateDB`].
///
/// This provides the revm-level state mutations needed by [`apply_primordial_pulse`]:
/// `increment_balance`, `set_code`, `set_nonce`, `set_storage`, and `selfdestruct`.
///
/// # Cache preloading
///
/// Every method calls `self.basic(address)` before `commit()` to preload the account
/// into revm's cache. Without this, `State<DB>::commit` panics with:
/// `"All accounts should be present inside cache"`.
impl<T: StateDB> PrimordialPulseStateWriter for T {
    fn increment_balance(&mut self, address: alloy_primitives::Address, amount: U256) {
        // DatabaseCommitExt::increment_balances calls basic() internally, so no
        // explicit preload is needed here.
        let _ = self.increment_balances([(address, amount.saturating_to::<u128>())]);
    }

    fn selfdestruct(&mut self, address: alloy_primitives::Address) {
        // Preload account into cache.
        let existing = self.basic(address).ok().flatten().unwrap_or_default();
        let mut account = Account::from(existing);
        account.mark_selfdestruct();
        account.mark_touch();
        self.commit(std::iter::once((address, account)).collect());
    }

    fn set_code(&mut self, address: alloy_primitives::Address, code: &[u8]) {
        // Preload account into cache. After selfdestruct(), basic() returns None;
        // unwrap_or_default() gives an empty AccountInfo, which is correct for a
        // newly-deployed contract.
        let existing = self.basic(address).ok().flatten().unwrap_or_default();
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
        let code_hash = bytecode.hash_slow();
        let info = AccountInfo { code: Some(bytecode), code_hash, ..existing };
        let mut account = Account::from(info);
        // mark_created() transitions a Destroyed cache entry → DestroyedNew, which
        // is required when code is deployed at an address that was just selfdestructed.
        account.mark_created();
        account.mark_touch();
        self.commit(std::iter::once((address, account)).collect());
    }

    fn set_nonce(&mut self, address: alloy_primitives::Address, nonce: u64) {
        let existing = self.basic(address).ok().flatten().unwrap_or_default();
        let info = AccountInfo { nonce, ..existing };
        let mut account = Account::from(info);
        account.mark_touch();
        self.commit(std::iter::once((address, account)).collect());
    }

    fn set_storage(&mut self, address: alloy_primitives::Address, slot: B256, value: B256) {
        // Preload account into cache.
        let existing = self.basic(address).ok().flatten().unwrap_or_default();
        let mut account = Account::from(existing);
        account.mark_touch();
        // EvmStorageSlot::new_changed(original, present, tx_id): original=ZERO means this
        // is a fresh write. is_changed() returns true when original != present, which
        // passes the filter inside State<DB>::commit.
        account.storage.insert(
            U256::from_be_bytes(slot.0),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from_be_bytes(value.0), 0),
        );
        // Successive set_storage commits accumulate: CacheAccount::change() extends
        // the existing cache storage with the new slot via extend().
        self.commit(std::iter::once((address, account)).collect());
    }
}

// ── Firehose tracing for the PrimordialPulse system call ────────────────────

/// Wraps a [`PrimordialPulseStateWriter`] to additionally emit firehose tracer
/// events for each balance / code / nonce / storage change. Used at the
/// `PrimordialPulse` call site so the firehose stream sees the fork-block
/// transition (the writes go through `evm.db_mut()` directly, bypassing
/// revm's opcode dispatch and therefore the inspector hooks).
///
/// Each method:
///   1. Reads the prior value via [`StateDB::basic`] / [`StateDB::storage`].
///   2. Forwards the call to the inner writer (the existing `T: StateDB` impl
///      handles the actual revm cache + commit dance).
///   3. Emits the corresponding tracer event.
///
/// Mirrors the `BalanceIncreaseGenesisBalance` / `BalanceDecreaseSelfdestruct`
/// reasons used by erigon-pulse / firehose-go-pulse.
struct TracingPrimordialPulseStateWriter<'a, T: StateDB> {
    inner: &'a mut T,
    tracer: &'a mut firehose_tracer::Tracer,
}

impl<'a, T: StateDB> PrimordialPulseStateWriter for TracingPrimordialPulseStateWriter<'a, T> {
    fn increment_balance(&mut self, address: alloy_primitives::Address, amount: U256) {
        let old_balance = self
            .inner
            .basic(address)
            .ok()
            .flatten()
            .map(|info| info.balance)
            .unwrap_or(U256::ZERO);
        <T as PrimordialPulseStateWriter>::increment_balance(self.inner, address, amount);
        let new_balance = old_balance.saturating_add(amount);
        self.tracer.on_balance_change(
            address,
            old_balance,
            new_balance,
            firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason::GenesisBalance,
        );
    }

    fn selfdestruct(&mut self, address: alloy_primitives::Address) {
        // Snapshot prior account state for event emission.
        let info = self.inner.basic(address).ok().flatten().unwrap_or_default();
        let old_balance = info.balance;
        let old_code_hash = info.code_hash;
        <T as PrimordialPulseStateWriter>::selfdestruct(self.inner, address);
        if !old_balance.is_zero() {
            self.tracer.on_balance_change(
                address,
                old_balance,
                U256::ZERO,
                firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason::SuicideWithdraw,
            );
        }
        // Code goes to empty after selfdestruct; old_code/new_code byte slices
        // are best-effort empty (consumers can fetch by hash if needed). The
        // KECCAK_EMPTY hash for new_code_hash is what revm sets after destruct.
        self.tracer.on_code_change(
            address,
            old_code_hash,
            alloy_primitives::KECCAK256_EMPTY,
            &[],
            &[],
        );
    }

    fn set_code(&mut self, address: alloy_primitives::Address, code: &[u8]) {
        let old_code_hash = self
            .inner
            .basic(address)
            .ok()
            .flatten()
            .map(|info| info.code_hash)
            .unwrap_or(alloy_primitives::KECCAK256_EMPTY);
        let new_code_hash = Bytecode::new_raw(Bytes::copy_from_slice(code)).hash_slow();
        <T as PrimordialPulseStateWriter>::set_code(self.inner, address, code);
        // For PrimordialPulse, set_code follows selfdestruct on the same address,
        // so old_code is empty in practice. Emit empty old_code rather than
        // chasing it via code_by_hash — the hash itself is the canonical signal.
        self.tracer.on_code_change(address, old_code_hash, new_code_hash, &[], code);
    }

    fn set_nonce(&mut self, address: alloy_primitives::Address, nonce: u64) {
        let old_nonce = self
            .inner
            .basic(address)
            .ok()
            .flatten()
            .map(|info| info.nonce)
            .unwrap_or(0);
        <T as PrimordialPulseStateWriter>::set_nonce(self.inner, address, nonce);
        self.tracer.on_nonce_change(address, old_nonce, nonce);
    }

    fn set_storage(&mut self, address: alloy_primitives::Address, slot: B256, value: B256) {
        let old_value = self
            .inner
            .storage(address, U256::from_be_bytes(slot.0))
            .ok()
            .map(|v| B256::from(v.to_be_bytes()))
            .unwrap_or(B256::ZERO);
        <T as PrimordialPulseStateWriter>::set_storage(self.inner, address, slot, value);
        self.tracer.on_storage_change(address, slot, old_value, value);
    }
}

// ── PulsechainBlockExecutor ───────────────────────────────────────────────────

/// Block executor for `PulseChain`.
///
/// Delegates all execution to [`EthBlockExecutor`] and adds a single post-execution
/// hook in [`finish`][BlockExecutor::finish]: if the block number matches the
/// `PrimordialPulse` fork block, [`apply_primordial_pulse`] is called on the state DB.
pub struct PulsechainBlockExecutor<'a, E, Spec, R: ReceiptBuilder> {
    inner: EthBlockExecutor<'a, E, &'a Spec, &'a R>,
    block_number: u64,
    primordial_pulse_block: u64,
    chain_id: u64,
}

impl<'a, E, Spec, R: ReceiptBuilder> std::fmt::Debug for PulsechainBlockExecutor<'a, E, Spec, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PulsechainBlockExecutor")
            .field("block_number", &self.block_number)
            .field("primordial_pulse_block", &self.primordial_pulse_block)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl<'a, E, Spec, R> BlockExecutor for PulsechainBlockExecutor<'a, E, Spec, R>
where
    R: ReceiptBuilder,
    EthBlockExecutor<'a, E, &'a Spec, &'a R>:
        BlockExecutor<Receipt = R::Receipt, Evm = E, Transaction = R::Transaction>,
    E: Evm<DB: StateDB, Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>>,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;
    type Result = <EthBlockExecutor<'a, E, &'a Spec, &'a R> as BlockExecutor>::Result;

    fn apply_pre_execution_changes(&mut self) -> std::result::Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> std::result::Result<Self::Result, BlockExecutionError> {
        // ExecutableTx<PulsechainBlockExecutor> ≡ ExecutableTxParts<E::Tx, R::Transaction>
        //                                       ≡ ExecutableTx<EthBlockExecutor<'a, E, &'a Spec, &'a R>>
        // because both executors declare the same Evm and Transaction associated types.
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn finish(
        self,
    ) -> std::result::Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError>
    {
        // For post-ETH-Merge pre-PrimordialPulse blocks, bypass the inner
        // executor's finish(). The PulseChain chain spec has Paris activating at
        // block 17,233,001, so the inner EthBlockExecutor would incorrectly add
        // 2 ETH PoW block rewards for Ethereum post-Merge blocks (15,537,394+).
        //
        // The previous add-then-subtract approach caused state divergence: it
        // created/touched coinbase accounts that shouldn't exist on Ethereum,
        // corrupting the state trie over ~140K blocks and causing gas mismatches
        // when transactions interacted with those phantom accounts.
        //
        // Instead, we handle finish() directly with correct post-Merge semantics:
        // no block rewards, and withdrawal processing gated on ETH's actual
        // Shanghai timestamp (not PulseChain's later activation).
        if self.block_number >= ETH_MAINNET_MERGE_BLOCK &&
            self.block_number < self.primordial_pulse_block
        {
            let mut inner = self.inner;

            // No Prague requests — all blocks in this range are pre-Cancun.
            let requests = Requests::default();

            // No block rewards (post-Merge). No DAO fork (block 1,920,000).

            // Process withdrawals for blocks after ETH Shanghai activation.
            // PulseChain's chain spec has Shanghai at a later timestamp, but
            // we must match Ethereum's actual behavior for pre-fork replay.
            let timestamp: u64 = inner.evm.block().timestamp().saturating_to();
            if timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP {
                if let Some(ref withdrawals) = inner.ctx.withdrawals {
                    // Merge amounts per address — multiple validators can share a
                    // withdrawal address. revm's increment_balances reads the
                    // original balance for each entry independently (before commit),
                    // so duplicate addresses would lose all but the last increment.
                    let mut merged: std::collections::HashMap<alloy_primitives::Address, u128> =
                        std::collections::HashMap::new();
                    for w in withdrawals.iter().filter(|w| w.amount > 0) {
                        *merged.entry(w.address).or_default() += w.amount_wei().to::<u128>();
                    }
                    if !merged.is_empty() {
                        inner
                            .evm
                            .db_mut()
                            .increment_balances(merged)
                            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;
                    }
                }
            }

            // PulseChain post-Merge pre-PrimordialPulse blocks predate Amsterdam
            // (EIP-8037), so cumulative_tx_gas_used (with refunds) is the correct
            // block gas total — matching upstream's pre-Amsterdam branch.
            let gas_used = inner.cumulative_tx_gas_used;

            Ok((
                inner.evm,
                BlockExecutionResult {
                    receipts: inner.receipts,
                    requests,
                    gas_used,
                    blob_gas_used: inner.blob_gas_used,
                },
            ))
        } else {
            let (mut evm, result) = self.inner.finish()?;

            // PrimordialPulse fires exactly once at the fork block.
            // Uses == (not >=) so the transition never re-applies.
            //
            // When the firehose tracer is initialized, wrap the transition with
            // system-call hooks and route per-write events through a tracing
            // adapter. The transition mutates state via `evm.db_mut()` (revm
            // State<DB>) without going through opcode dispatch, so the firehose
            // inspector never sees those writes — same problem as EIP-4895
            // withdrawals, same shape of solution. The tracer locks are short
            // (acquired three times: start, run, end) and there's no contention
            // because block executor `finish` is single-threaded.
            if self.block_number == self.primordial_pulse_block {
                if reth_firehose::is_tracer_initialized() {
                    reth_firehose::tracer().on_system_call_start();
                    {
                        let mut tracer = reth_firehose::tracer();
                        let mut tracing_writer = TracingPrimordialPulseStateWriter {
                            inner: evm.db_mut(),
                            tracer: &mut *tracer,
                        };
                        apply_primordial_pulse(&mut tracing_writer, self.chain_id);
                    }
                    reth_firehose::tracer().on_system_call_end();
                } else {
                    apply_primordial_pulse(evm.db_mut(), self.chain_id);
                }
            }

            Ok((evm, result))
        }
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook);
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

// ── PulsechainBlockExecutorFactory ───────────────────────────────────────────

/// Block executor factory for `PulseChain`.
///
/// Wraps [`EthBlockExecutorFactory`] and constructs [`PulsechainBlockExecutor`] instances
/// that inject the `PrimordialPulse` hook into [`BlockExecutor::finish`].
#[derive(Debug, Clone)]
pub struct PulsechainBlockExecutorFactory<R, Spec, EvmF> {
    inner: EthBlockExecutorFactory<R, Spec, EvmF>,
    primordial_pulse_block: u64,
    chain_id: u64,
}

impl<R, Spec, EvmF> BlockExecutorFactory for PulsechainBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: AlloyTransaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    <R::Transaction as TransactionEnvelope>::TxType: Send + 'static,
    Spec: EthExecutorSpec,
    EvmF: EvmFactory<
        Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
        Precompiles = PrecompilesMap,
    >,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type TxExecutionResult =
        EthTxResult<EvmF::HaltReason, <R::Transaction as TransactionEnvelope>::TxType>;
    type Executor<'a, DB: StateDB, I: revm::Inspector<EvmF::Context<DB>>> =
        PulsechainBlockExecutor<'a, EvmF::Evm<DB, I>, Spec, R>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmF::Evm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: revm::Inspector<EvmF::Context<DB>>,
    {
        // Read block number from the EVM's block environment before consuming it.
        let block_number = evm.block().number().saturating_to::<u64>();

        // Build the inner EthBlockExecutor directly using EthBlockExecutorFactory's
        // public accessors. This avoids calling inner.create_executor() which returns
        // RPIT (unnameable type) that we cannot wrap.
        let inner =
            EthBlockExecutor::new(evm, ctx, self.inner.spec(), self.inner.receipt_builder());

        PulsechainBlockExecutor {
            inner,
            block_number,
            primordial_pulse_block: self.primordial_pulse_block,
            chain_id: self.chain_id,
        }
    }
}

// ── PulsechainEvmConfig ───────────────────────────────────────────────────────

/// EVM configuration for `PulseChain`.
///
/// Wraps [`EthEvmConfig`] and overrides:
/// - **CHAINID opcode**: Returns `1` for blocks before `PrimordialPulse` (replaying Ethereum
///   mainnet history), then `369`/`943` for `PulseChain` blocks.
/// - **Block executor factory**: Uses [`PulsechainBlockExecutorFactory`] which fires the
///   `PrimordialPulse` state transition at the fork block.
#[derive(Debug, Clone)]
pub struct PulsechainEvmConfig<C = ChainSpec, EvmF = EthEvmFactory> {
    /// Inner Ethereum config — reused for block assembler and context methods.
    inner: EthEvmConfig<C, EvmF>,
    /// PulseChain-aware executor factory (wraps the inner factory with fork hook).
    pulse_factory: PulsechainBlockExecutorFactory<RethReceiptBuilder, Arc<C>, EvmF>,
}

impl<C> PulsechainEvmConfig<C>
where
    C: EthChainSpec + EthereumHardforks + EthExecutorSpec + 'static,
{
    /// Creates a new `PulseChain` EVM configuration from the given chain spec.
    pub fn new(chain_spec: Arc<C>) -> Self {
        let inner = EthEvmConfig::new(chain_spec.clone());
        let base_chain_id = chain_spec.chain().id();
        let primordial_pulse_block = primordial_pulse_block_for_chain(base_chain_id);
        let pulse_factory = PulsechainBlockExecutorFactory {
            inner: inner.executor_factory.clone(),
            primordial_pulse_block,
            chain_id: base_chain_id,
        };
        Self { inner, pulse_factory }
    }
}

impl<C, EvmF> reth_evm::ConfigureEvm for PulsechainEvmConfig<C, EvmF>
where
    C: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut
                    + FromRecoveredTx<TransactionSigned>
                    + FromTxWithEncoded<TransactionSigned>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = PulsechainBlockExecutorFactory<RethReceiptBuilder, Arc<C>, EvmF>;
    type BlockAssembler = EthBlockAssembler<C>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.pulse_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> std::result::Result<EvmEnv<SpecId>, Self::Error> {
        let mut env = self.inner.evm_env(header)?;
        let base_chain_id = self.inner.chain_spec().chain().id();
        env.cfg_env.chain_id = chain_id_for_block(base_chain_id, header.number);

        // PulseChain replays Ethereum history verbatim. Blocks >= ETH_MAINNET_MERGE_BLOCK
        // (15,537,394) are post-Merge Ethereum blocks that need post-Merge EVM rules, even
        // though PulseChain's own Paris activation is at block 17,233,001.
        //
        // Within this range, we must also distinguish Shanghai-era blocks: Ethereum's Shanghai
        // activated at timestamp 1,681,338,455 (~block 17,034,870), enabling PUSH0 (EIP-3855),
        // warm COINBASE (EIP-3651), and initcode metering (EIP-3860). PulseChain's own
        // Shanghai timestamp is later (1,683,786,515), so without this override blocks in the
        // gap would use MERGE rules and PUSH0 would be treated as an invalid opcode.
        //
        // This mirrors the Erigon-Pulse override:
        //   if c.PrimordialPulseAhead(num) { return 1681338455 <= time }
        let primordial_block = primordial_pulse_block_for_chain(base_chain_id);
        if header.number >= ETH_MAINNET_MERGE_BLOCK && header.number < primordial_block {
            let spec = if header.timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP {
                SpecId::SHANGHAI
            } else {
                SpecId::MERGE
            };
            env.cfg_env.set_spec_and_mainnet_gas_params(spec);
            env.block_env.difficulty = U256::ZERO;
            env.block_env.prevrandao = Some(header.mix_hash);
        }

        Ok(env)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> std::result::Result<EvmEnv<SpecId>, Self::Error> {
        let mut env = self.inner.next_evm_env(parent, attributes)?;
        let next_block_number = parent.number.saturating_add(1);
        let base_chain_id = self.inner.chain_spec().chain().id();
        env.cfg_env.chain_id = chain_id_for_block(base_chain_id, next_block_number);

        // Apply Ethereum post-Merge/Shanghai rules for history replay blocks.
        let primordial_block = primordial_pulse_block_for_chain(base_chain_id);
        if next_block_number >= ETH_MAINNET_MERGE_BLOCK && next_block_number < primordial_block {
            let spec = if attributes.timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP {
                SpecId::SHANGHAI
            } else {
                SpecId::MERGE
            };
            env.cfg_env.set_spec_and_mainnet_gas_params(spec);
            env.block_env.difficulty = U256::ZERO;
            env.block_env.prevrandao = Some(attributes.prev_randao);
        }

        Ok(env)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> std::result::Result<EthBlockExecutionCtx<'a>, Self::Error> {
        // Delegate directly to inner — EthBlockExecutionCtx construction is chain-agnostic.
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: NextBlockEnvAttributes,
    ) -> std::result::Result<EthBlockExecutionCtx<'_>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

#[cfg(feature = "std")]
impl<C, EvmF> ConfigureEngineEvm<ExecutionData> for PulsechainEvmConfig<C, EvmF>
where
    C: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut
                    + FromRecoveredTx<TransactionSigned>
                    + FromTxWithEncoded<TransactionSigned>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    fn evm_env_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> std::result::Result<EvmEnvFor<Self>, Self::Error> {
        // Implemented directly (not delegated to inner) because Rust cannot normalize
        // EvmEnvFor<EthEvmConfig<C, EvmF>> to EvmEnvFor<PulsechainEvmConfig<C, EvmF>>
        // without additional where-clause machinery.
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();
        let chain_spec = self.inner.chain_spec();

        let blob_params = chain_spec.blob_params_at_timestamp(timestamp);
        let base_chain_id = chain_spec.chain().id();
        let primordial_block = primordial_pulse_block_for_chain(base_chain_id);

        // Use Ethereum post-Merge/Shanghai rules for history replay blocks.
        let spec = if block_number >= ETH_MAINNET_MERGE_BLOCK && block_number < primordial_block {
            if timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP {
                SpecId::SHANGHAI
            } else {
                SpecId::MERGE
            }
        } else {
            revm_spec_by_timestamp_and_block_number(chain_spec, timestamp, block_number)
        };

        // Set PulseChain chain ID: 1 before PrimordialPulse, 369/943 after.
        let mut cfg_env = CfgEnv::new()
            .with_chain_id(chain_id_for_block(base_chain_id, block_number))
            .with_spec_and_mainnet_gas_params(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }
        if chain_spec.is_osaka_active_at_timestamp(timestamp) {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        let blob_excess_gas_and_price =
            payload.payload.excess_blob_gas().zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let block_env = BlockEnv {
            number: U256::from(block_number),
            beneficiary: payload.payload.fee_recipient(),
            timestamp: U256::from(timestamp),
            difficulty: if spec >= SpecId::MERGE {
                U256::ZERO
            } else {
                payload.payload.as_v1().prev_randao.into()
            },
            prevrandao: (spec >= SpecId::MERGE).then(|| payload.payload.as_v1().prev_randao),
            gas_limit: payload.payload.gas_limit(),
            basefee: payload.payload.saturated_base_fee_per_gas(),
            blob_excess_gas_and_price,
            slot_num: 0,
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> std::result::Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        // Implemented directly (not delegated to inner) because Rust cannot normalize
        // ExecutionCtxFor<EthEvmConfig<C, EvmF>> to ExecutionCtxFor<PulsechainEvmConfig<C, EvmF>>
        // without proof that both factories share the same ExecutionCtx<'a> =
        // EthBlockExecutionCtx<'a>.
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: payload.payload.as_v1().extra_data.clone(),
            slot_number: None,
        })
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> std::result::Result<impl ExecutableTxIterator<Self>, Self::Error> {
        // Decode each raw transaction in the payload and recover the signer.
        // This mirrors EthEvmConfig::tx_iterator_for_payload exactly so that
        // Rust can see the concrete return type and verify ExecutableTxFor<Self>.
        let txs = payload.payload.transactions().clone();
        let convert = |tx: Bytes| {
            let tx = TransactionSigned::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = tx.try_recover().map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };
        Ok((txs, convert))
    }
}

// ── PulsechainExecutorBuilder ─────────────────────────────────────────────────

/// Node builder component that provides the `PulseChain` EVM configuration.
///
/// Returns a [`PulsechainEvmConfig`] with CHAINID override and `PrimordialPulse` hook wired in.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PulsechainExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for PulsechainExecutorBuilder
where
    Types: NodeTypes<
        ChainSpec: EthExecutorSpec
                       + EthChainSpec<Header = Header>
                       + EthereumHardforks
                       + Hardforks
                       + 'static,
        Primitives = EthPrimitives,
    >,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = PulsechainEvmConfig<Types::ChainSpec>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(PulsechainEvmConfig::new(ctx.chain_spec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_evm::ConfigureEvm;
    use reth_pulsechain_forks::{
        chainspec::PULSECHAIN,
        hardfork::{
            ETH_MAINNET_MERGE_BLOCK, ETH_MAINNET_SHANGHAI_TIMESTAMP, PRIMORDIAL_PULSE_MAINNET_BLOCK,
        },
    };

    /// Helper: build a PulsechainEvmConfig from the mainnet chain spec.
    fn mainnet_evm_config() -> PulsechainEvmConfig {
        PulsechainEvmConfig::new(PULSECHAIN.clone())
    }

    /// Helper: build a Header at the given block number with the given difficulty and mix_hash.
    fn header_at(block_number: u64, difficulty: u128, mix_hash: B256) -> Header {
        Header {
            number: block_number,
            difficulty: U256::from(difficulty),
            mix_hash,
            // London-era headers need a base fee
            base_fee_per_gas: Some(1_000_000_000),
            ..Default::default()
        }
    }

    /// Helper: build a Header with a specific timestamp (for Shanghai tests).
    fn header_at_with_timestamp(
        block_number: u64,
        difficulty: u128,
        mix_hash: B256,
        timestamp: u64,
    ) -> Header {
        Header {
            number: block_number,
            difficulty: U256::from(difficulty),
            mix_hash,
            base_fee_per_gas: Some(1_000_000_000),
            timestamp,
            ..Default::default()
        }
    }

    // ── SpecId tests ────────────────────────────────────────────────────

    #[test]
    fn pre_merge_block_gets_london_or_gray_glacier_spec() {
        let config = mainnet_evm_config();
        // Block 15,050,001 is after GrayGlacier (15,050,000) but before ETH Merge (15,537,394)
        let header = header_at(15_050_001, 100, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        // Should NOT be MERGE — should be GRAY_GLACIER or LONDON range
        assert!(
            env.cfg_env.spec < SpecId::MERGE,
            "block before ETH Merge should use pre-MERGE spec, got {:?}",
            env.cfg_env.spec
        );
    }

    #[test]
    fn eth_merge_block_gets_merge_spec() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xaa);
        // Block 15,537,394 — first post-Merge Ethereum block
        let header = header_at(ETH_MAINNET_MERGE_BLOCK, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.cfg_env.spec, SpecId::MERGE, "ETH Merge block must use MERGE spec");
    }

    #[test]
    fn post_merge_mid_range_gets_merge_spec() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xbb);
        // Block 16,000,000 — well after ETH Merge, before PrimordialPulse
        let header = header_at(16_000_000, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.cfg_env.spec, SpecId::MERGE, "post-Merge replay block must use MERGE spec");
    }

    // ── Shanghai SpecId tests ────────────────────────────────────────

    #[test]
    fn post_merge_pre_shanghai_gets_merge_spec() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xbb);
        // Block 16,000,000 with a timestamp before ETH Shanghai (1,681,338,455)
        // Jan 2023 — well before Shanghai (April 2023)
        let header = header_at_with_timestamp(16_000_000, 0, randao, 1_674_000_000);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(
            env.cfg_env.spec,
            SpecId::MERGE,
            "post-Merge pre-Shanghai block must use MERGE spec"
        );
    }

    #[test]
    fn post_shanghai_block_gets_shanghai_spec() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xee);
        // Block 17,100,000 with a timestamp at or after ETH Shanghai
        let header =
            header_at_with_timestamp(17_100_000, 0, randao, ETH_MAINNET_SHANGHAI_TIMESTAMP);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(
            env.cfg_env.spec,
            SpecId::SHANGHAI,
            "post-Shanghai block before PrimordialPulse must use SHANGHAI spec"
        );
    }

    #[test]
    fn post_shanghai_block_has_zero_difficulty_and_prevrandao() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xf1);
        let header =
            header_at_with_timestamp(17_100_000, 0, randao, ETH_MAINNET_SHANGHAI_TIMESTAMP + 1000);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.block_env.difficulty, U256::ZERO);
        assert_eq!(env.block_env.prevrandao, Some(randao));
    }

    #[test]
    fn shanghai_boundary_exact_timestamp() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xf2);
        // Exactly at the Shanghai timestamp boundary
        let header =
            header_at_with_timestamp(17_050_000, 0, randao, ETH_MAINNET_SHANGHAI_TIMESTAMP);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(
            env.cfg_env.spec,
            SpecId::SHANGHAI,
            "block at exact Shanghai timestamp must use SHANGHAI spec"
        );
    }

    #[test]
    fn one_second_before_shanghai_gets_merge() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xf3);
        let header =
            header_at_with_timestamp(17_034_869, 0, randao, ETH_MAINNET_SHANGHAI_TIMESTAMP - 1);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(
            env.cfg_env.spec,
            SpecId::MERGE,
            "block 1 second before Shanghai must use MERGE spec"
        );
    }

    #[test]
    fn block_just_before_eth_merge_is_not_merge() {
        let config = mainnet_evm_config();
        let header = header_at(ETH_MAINNET_MERGE_BLOCK - 1, 100, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        assert!(
            env.cfg_env.spec < SpecId::MERGE,
            "block right before ETH Merge should not use MERGE spec, got {:?}",
            env.cfg_env.spec
        );
    }

    // ── Difficulty / prevrandao tests ───────────────────────────────────

    #[test]
    fn pre_merge_block_has_nonzero_difficulty_and_no_prevrandao() {
        let config = mainnet_evm_config();
        let header = header_at(15_050_001, 12_345_678, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        assert_ne!(
            env.block_env.difficulty,
            U256::ZERO,
            "pre-Merge block should preserve difficulty"
        );
        assert_eq!(env.block_env.prevrandao, None, "pre-Merge block should not have prevrandao");
    }

    #[test]
    fn post_merge_block_has_zero_difficulty_and_prevrandao() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xcc);
        let header = header_at(ETH_MAINNET_MERGE_BLOCK, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(
            env.block_env.difficulty,
            U256::ZERO,
            "post-Merge block must have zero difficulty"
        );
        assert_eq!(
            env.block_env.prevrandao,
            Some(randao),
            "post-Merge block must set prevrandao from header.mix_hash"
        );
    }

    #[test]
    fn post_merge_block_prevrandao_carries_through() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xdd);
        // Arbitrary post-Merge, pre-PrimordialPulse block
        let header = header_at(17_000_000, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.block_env.prevrandao, Some(randao));
        assert_eq!(env.block_env.difficulty, U256::ZERO);
    }

    // ── Chain ID tests ─────────────────────────────────────────────────

    #[test]
    fn chain_id_is_1_before_primordial_pulse() {
        let config = mainnet_evm_config();
        let header = header_at(ETH_MAINNET_MERGE_BLOCK, 0, B256::repeat_byte(0xaa));
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.cfg_env.chain_id, 1, "chain ID must be 1 during Ethereum history replay");
    }

    #[test]
    fn chain_id_is_369_at_primordial_pulse() {
        let config = mainnet_evm_config();
        let header = header_at(PRIMORDIAL_PULSE_MAINNET_BLOCK, 100, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.cfg_env.chain_id, 369, "chain ID must be 369 at PrimordialPulse");
    }

    // ── Boundary: PrimordialPulse block itself ─────────────────────────

    #[test]
    fn primordial_pulse_block_is_not_merge_spec() {
        let config = mainnet_evm_config();
        // PrimordialPulse (17,233,000) is the last PoW block — NOT post-Merge.
        // Paris activates at 17,233,001.
        let header = header_at(PRIMORDIAL_PULSE_MAINNET_BLOCK, 100, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        // The override range is [ETH_MERGE_BLOCK, PRIMORDIAL_PULSE_BLOCK).
        // PrimordialPulse itself is NOT in range, so spec comes from chain spec's
        // hardfork schedule (GrayGlacier, since Paris is at 17,233,001).
        assert!(
            env.cfg_env.spec < SpecId::MERGE,
            "PrimordialPulse block should not use MERGE spec (Paris is at +1), got {:?}",
            env.cfg_env.spec
        );
    }

    #[test]
    fn block_after_primordial_pulse_gets_merge_from_chainspec() {
        let config = mainnet_evm_config();
        // Block 17,233,001 — Paris activates here per PulseChain's own hardfork schedule
        let header = header_at(PRIMORDIAL_PULSE_MAINNET_BLOCK + 1, 0, B256::repeat_byte(0xff));
        let env = config.evm_env(&header).unwrap();

        // This block is past the override range AND past PulseChain's Paris activation,
        // so it should get MERGE from the chain spec (not from our override).
        assert_eq!(
            env.cfg_env.spec,
            SpecId::MERGE,
            "first PulseChain PoS block must use MERGE spec"
        );
    }
}
