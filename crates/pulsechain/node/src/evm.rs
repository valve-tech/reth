//! `PulseChain` EVM configuration on evm2.
//!
//! [`PulsechainEvmConfig`] wraps [`EthEvmConfig`] and changes three things:
//!
//! - **Chain ID**: the CHAINID opcode returns `1` for blocks before `PrimordialPulse` (Ethereum
//!   history replay), then `369`/`943`.
//! - **Spec for Ethereum post-Merge history**: blocks in `[ETH_MAINNET_MERGE_BLOCK,
//!   PrimordialPulse)` run with Ethereum's post-Merge rules (MERGE, then SHANGHAI from Ethereum's
//!   Shanghai timestamp), although `PulseChain`'s own Paris and Shanghai come later.
//! - **Block executor**: [`PulsechainBlockExecutor`] pays no proof-of-work reward in that Ethereum
//!   post-Merge range and applies the `PrimordialPulse` state transition at the fork block.

use std::{borrow::Cow, convert::Infallible, fmt::Debug, sync::Arc};

use alloy_consensus::Header;
use alloy_eips::{eip7685::Requests, Decodable2718};
use alloy_primitives::{map::AddressMap, Address, Bytes, B256, U256};
use alloy_rpc_types_engine::ExecutionData;
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, DynDatabase, PendingState},
    SpecId,
};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks, MAINNET};
use reth_ethereum_primitives::{Block, EthPrimitives, TransactionSigned};
use reth_evm::{
    precompile_cache::PrecompileCacheMap, BlockExecutionError, BlockExecutionOutput, BlockExecutor,
    BlockExecutorFactory, ConfigureEngineEvm, ConfigureEvm, Database, EvmEnv, EvmEnvFor, EvmFor,
    ExecutableTxIterator, ExecutionCtxFor, ExecutorTx, GasOutput, NextBlockEnvAttributes,
    ReceiptBuilder, SpecFor,
};
use reth_evm_ethereum::{
    EthBlockAssembler, EthBlockExecutionCtx, EthBlockExecutor, EthBlockExecutorFactory,
    EthEvmConfig, EthEvmEnv, EvmFactory, ExecutableRecoveredTx, RethEvmFactory, RethReceiptBuilder,
};
use reth_execution_types::StateUpdate;
use reth_node_builder::{components::ExecutorBuilder, BuilderContext, FullNodeTypes, NodeTypes};
use reth_primitives_traits::{SealedBlock, SealedHeader, SignedTransaction};
use reth_storage_errors::any::AnyError;
use reth_trie_common::bundle_state::BundleState;

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

// ── Chain helpers ─────────────────────────────────────────────────────────────

/// Returns the CHAINID value for `block_number` on the chain `base_chain_id`.
const fn chain_id_for_block(base_chain_id: u64, block_number: u64) -> u64 {
    match base_chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => chain_id_at_block_mainnet(block_number),
        PULSECHAIN_TESTNET_V4_CHAIN_ID => chain_id_at_block_testnet_v4(block_number),
        other => other,
    }
}

/// Returns the `PrimordialPulse` block of `chain_id`, or `u64::MAX` on another chain.
const fn primordial_pulse_block_for_chain(chain_id: u64) -> u64 {
    match chain_id {
        PULSECHAIN_MAINNET_CHAIN_ID => PRIMORDIAL_PULSE_MAINNET_BLOCK,
        PULSECHAIN_TESTNET_V4_CHAIN_ID => PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        _ => u64::MAX,
    }
}

/// Returns whether `block_number` replays Ethereum mainnet after its Merge.
const fn is_eth_post_merge_replay(block_number: u64, primordial_pulse_block: u64) -> bool {
    block_number >= ETH_MAINNET_MERGE_BLOCK && block_number < primordial_pulse_block
}

/// Returns the Ethereum spec for a block in the Ethereum post-Merge replay range, or `None`
/// outside it.
///
/// `PulseChain`'s own Paris (one block after `PrimordialPulse`) and Shanghai come later than
/// Ethereum's. Without this, replay blocks after Ethereum's Merge would run pre-Merge rules, and
/// blocks after Ethereum's Shanghai would treat PUSH0 as invalid. This mirrors erigon-pulse:
/// `if c.PrimordialPulseAhead(num) { return 1681338455 <= time }`.
const fn eth_replay_spec(
    block_number: u64,
    timestamp: u64,
    primordial_pulse_block: u64,
) -> Option<SpecId> {
    if !is_eth_post_merge_replay(block_number, primordial_pulse_block) {
        return None
    }
    Some(if timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP { SpecId::SHANGHAI } else { SpecId::MERGE })
}

// ── PrimordialPulse state writer ──────────────────────────────────────────────

/// Collects the `PrimordialPulse` writes as one [`PendingState`].
///
/// Every account is read once from the executor's overlay, so a write sees the result of the
/// writes before it. A selfdestructed account becomes absent; the block state then records it
/// as destroyed, which wipes its storage.
struct PrimordialPulseChanges<'e, 'a, T: evm2::EvmTypes> {
    evm: &'e mut evm2::Evm<'a, T>,
    /// Original and current account, in first-write order.
    accounts: AddressMap<(Option<AccountInfo>, Option<AccountInfo>)>,
    /// Original and current storage values per written slot.
    storage: Vec<(Address, U256, U256, U256)>,
    order: Vec<Address>,
    destroyed: Vec<Address>,
}

impl<'e, 'a, T: evm2::EvmTypes> PrimordialPulseChanges<'e, 'a, T> {
    fn new(evm: &'e mut evm2::Evm<'a, T>) -> Self {
        Self {
            evm,
            accounts: AddressMap::default(),
            storage: Vec::new(),
            order: Vec::new(),
            destroyed: Vec::new(),
        }
    }

    /// Returns the current value of `address`, reading it from the overlay on first use.
    fn current(&mut self, address: Address) -> &mut Option<AccountInfo> {
        assert!(
            !self.destroyed.contains(&address),
            "PrimordialPulse writes to {address} after destroying it; PendingState cannot \
             express a wiped and recreated account"
        );
        if !self.accounts.contains_key(&address) {
            let original = self
                .evm
                .read_account_info(&address)
                .expect("PrimordialPulse: database read of an account failed");
            self.accounts.insert(address, (original.clone(), original));
            self.order.push(address);
        }
        &mut self.accounts.get_mut(&address).expect("inserted above").1
    }

    fn current_or_empty(&mut self, address: Address) -> &mut AccountInfo {
        self.current(address).get_or_insert_with(AccountInfo::default)
    }

    fn into_pending_state(self) -> PendingState {
        let mut pending = PendingState::default();
        for address in &self.order {
            let (original, current) = self.accounts[address].clone();
            pending.insert_account(*address, original, current);
        }
        for (address, key, original, current) in self.storage {
            pending.insert_storage(address, key, original, current);
        }
        pending
    }
}

impl<T: evm2::EvmTypes> PrimordialPulseStateWriter for PrimordialPulseChanges<'_, '_, T> {
    fn increment_balance(&mut self, address: Address, amount: U256) {
        let account = self.current_or_empty(address);
        account.balance = account.balance.saturating_add(amount);
    }

    fn selfdestruct(&mut self, address: Address) {
        *self.current(address) = None;
        self.destroyed.push(address);
    }

    fn set_code(&mut self, address: Address, code: &[u8]) {
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
        let account = self.current_or_empty(address);
        account.code_hash = bytecode.hash_slow();
        account.code = Some(bytecode);
    }

    fn set_nonce(&mut self, address: Address, nonce: u64) {
        self.current_or_empty(address).nonce = nonce;
    }

    fn set_storage(&mut self, address: Address, slot: B256, value: B256) {
        self.current_or_empty(address);
        let key = U256::from_be_bytes(slot.0);
        let original = DynDatabase::get_storage(self.evm.overlay_db_mut(), &address, &key)
            .expect("PrimordialPulse: database read of a storage slot failed");
        self.storage.push((address, key, original, U256::from_be_bytes(value.0)));
    }
}

// ── PulsechainBlockExecutor ───────────────────────────────────────────────────

/// Block executor for `PulseChain`.
///
/// Delegates execution to [`EthBlockExecutor`]. At the `PrimordialPulse` block it commits the
/// fork's state transition after the last transaction and before the inner executor finishes.
///
/// The inner executor then applies the block reward and withdrawals. In v2.8 the transition ran
/// after them. The order does not change the state: the reward and withdrawals only add to
/// balances, and the transition adds to balances, replaces the Ethereum deposit contract and
/// deploys the `PulseChain` one. A test checks that the fork blocks' beneficiaries are not
/// accounts the transition destroys or rewrites.
pub struct PulsechainBlockExecutor<'a, T, R>
where
    T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>,
    R: ReceiptBuilder,
{
    inner: EthBlockExecutor<'a, T, R>,
    block_number: u64,
    primordial_pulse_block: u64,
    chain_id: u64,
}

impl<T, R> Debug for PulsechainBlockExecutor<'_, T, R>
where
    T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>,
    R: ReceiptBuilder,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PulsechainBlockExecutor")
            .field("block_number", &self.block_number)
            .field("primordial_pulse_block", &self.primordial_pulse_block)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl<'a, T, R> PulsechainBlockExecutor<'a, T, R>
where
    T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>,
    R: ReceiptBuilder,
{
    /// Commits the `PrimordialPulse` transition when this is the fork block.
    ///
    /// The transition fires exactly once, at `==` the fork block. Firehose does not see these
    /// writes through the inspector; `FirehoseWrappedExecutor` emits them from a state diff.
    fn apply_fork_transition(&mut self) {
        if self.block_number != self.primordial_pulse_block {
            return
        }
        let mut changes = PrimordialPulseChanges::new(&mut self.inner.evm);
        apply_primordial_pulse(&mut changes, self.chain_id);
        let pending = changes.into_pending_state();
        self.inner.commit_pending_state(&pending);
    }
}

impl<'a, T, R> BlockExecutor for PulsechainBlockExecutor<'a, T, R>
where
    T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync>,
    R: ReceiptBuilder,
    EthBlockExecutor<'a, T, R>: BlockExecutor<Evm = evm2::Evm<'a, T>>,
{
    type Transaction = <EthBlockExecutor<'a, T, R> as BlockExecutor>::Transaction;
    type Receipt = <EthBlockExecutor<'a, T, R> as BlockExecutor>::Receipt;
    type Evm = evm2::Evm<'a, T>;
    type TransactionResultWithState =
        <EthBlockExecutor<'a, T, R> as BlockExecutor>::TransactionResultWithState;
    type BlockAccessList = <EthBlockExecutor<'a, T, R> as BlockExecutor>::BlockAccessList;

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
        block_access_list: &alloy_eip7928::BlockAccessList,
    ) -> Result<Self::BlockAccessList, BlockExecutionError> {
        <EthBlockExecutor<'a, T, R> as BlockExecutor>::convert_block_access_list(block_access_list)
    }

    fn set_block_access_list(&mut self, block_access_list: Arc<Self::BlockAccessList>) {
        self.inner.set_block_access_list(block_access_list)
    }

    fn set_block_access_index(&mut self, index: alloy_eip7928::BlockAccessIndex) {
        self.inner.set_block_access_index(index)
    }

    fn enable_block_access_list_builder(&mut self) {
        self.inner.enable_block_access_list_builder()
    }

    fn take_block_access_list(&mut self) -> Option<alloy_eip7928::BlockAccessList> {
        self.inner.take_block_access_list()
    }

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn into_state(self) -> BundleState {
        self.inner.into_state()
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
        self.inner.execute_transaction_without_commit(transaction)
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
    ) -> Result<
        (BlockExecutionOutput<Self::Receipt>, Option<alloy_eip7928::BlockAccessList>),
        BlockExecutionError,
    > {
        self.apply_fork_transition();
        self.inner.finish_with_block_access_list()
    }

    fn finish_with_prepared_block_access_list(
        mut self,
    ) -> Result<(BlockExecutionOutput<Self::Receipt>, Option<evm2::evm::Bal>), BlockExecutionError>
    {
        self.apply_fork_transition();
        self.inner.finish_with_prepared_block_access_list()
    }
}

// ── PulsechainBlockExecutorFactory ───────────────────────────────────────────

/// Block executor factory for `PulseChain`.
///
/// Wraps [`EthBlockExecutorFactory`]. For a block that replays Ethereum after its Merge, the
/// inner executor gets Ethereum mainnet's chain spec: there `PulseChain`'s spec still has
/// proof-of-work rewards (its Paris is one block after `PrimordialPulse`), but Ethereum paid
/// none. Withdrawals follow the block's EVM spec, which [`eth_replay_spec`] already sets.
#[derive(Debug, Clone)]
pub struct PulsechainBlockExecutorFactory<C = ChainSpec, F: EvmFactory = RethEvmFactory> {
    inner: EthBlockExecutorFactory<RethReceiptBuilder, C, F>,
    primordial_pulse_block: u64,
    chain_id: u64,
}

impl<C, F> BlockExecutorFactory for PulsechainBlockExecutorFactory<C, F>
where
    C: EthChainSpec<Header = Header> + EthereumHardforks,
    F: EvmFactory,
    <F::Types as evm2::EvmTypesHost>::Tx: alloy_eips::eip2718::Typed2718,
{
    type EvmFactory = F;
    type EvmTypes = F::Types;
    type Transaction = TransactionSigned;
    type Receipt = reth_ethereum_primitives::Receipt;
    type Evm<'a> = evm2::Evm<'a, F::Types>;
    type EvmEnv = EthEvmEnv<F::Types>;
    type ExecutionCtx<'a>
        = EthBlockExecutionCtx<'a>
    where
        Self: 'a;
    type Executor<'a>
        = PulsechainBlockExecutor<'a, F::Types, &'a RethReceiptBuilder>
    where
        Self: 'a;

    fn create_executor<'a>(
        &'a self,
        evm: Self::Evm<'a>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a>
    where
        Self: 'a,
    {
        let block_number = evm.block().number.saturating_to::<u64>();
        let receipt_builder = self.inner.receipt_builder();
        let inner = if is_eth_post_merge_replay(block_number, self.primordial_pulse_block) {
            EthBlockExecutor::new(evm, ctx, MAINNET.as_ref(), receipt_builder)
        } else {
            EthBlockExecutor::new(evm, ctx, self.inner.chain_spec().as_ref(), receipt_builder)
        };
        PulsechainBlockExecutor {
            inner,
            block_number,
            primordial_pulse_block: self.primordial_pulse_block,
            chain_id: self.chain_id,
        }
    }

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn evm_with_env<'a, DB>(&self, db: DB, evm_env: Self::EvmEnv) -> Self::Evm<'a>
    where
        DB: DynDatabase + 'a,
    {
        <EthBlockExecutorFactory<RethReceiptBuilder, C, F> as BlockExecutorFactory>::evm_with_env(
            &self.inner,
            db,
            evm_env,
        )
    }
}

// ── PulsechainEvmConfig ───────────────────────────────────────────────────────

/// `PulseChain` EVM configuration. See the module docs.
#[derive(Debug, Clone)]
pub struct PulsechainEvmConfig<C = ChainSpec, F: EvmFactory = RethEvmFactory> {
    /// Inner Ethereum config, used for the block assembler, contexts and environments.
    inner: EthEvmConfig<C, F>,
    /// `PulseChain` executor factory.
    pulse_factory: PulsechainBlockExecutorFactory<C, F>,
}

impl<C> PulsechainEvmConfig<C>
where
    C: EthChainSpec + EthereumHardforks + 'static,
{
    /// Creates a `PulseChain` EVM configuration with the default EVM factory.
    pub fn new(chain_spec: Arc<C>) -> Self {
        Self::from_eth(EthEvmConfig::new(chain_spec))
    }
}

impl<C, F> PulsechainEvmConfig<C, F>
where
    C: EthChainSpec + 'static,
    F: EvmFactory,
{
    /// Wraps an Ethereum EVM configuration, keeping its EVM factory and sender recovery cache.
    pub fn from_eth(inner: EthEvmConfig<C, F>) -> Self {
        let chain_id = inner.chain_spec().chain().id();
        let pulse_factory = PulsechainBlockExecutorFactory {
            inner: inner.executor_factory.clone(),
            primordial_pulse_block: primordial_pulse_block_for_chain(chain_id),
            chain_id,
        };
        Self { inner, pulse_factory }
    }

    /// Applies the `PulseChain` chain ID and the Ethereum replay spec to an environment.
    fn adjust_env(
        &self,
        mut env: EthEvmEnv<F::Types>,
        number: u64,
        timestamp: u64,
    ) -> EthEvmEnv<F::Types> {
        let chain_id = chain_id_for_block(self.pulse_factory.chain_id, number);
        if let Some(spec) =
            eth_replay_spec(number, timestamp, self.pulse_factory.primordial_pulse_block)
        {
            let factory = self.inner.executor_factory.evm_factory();
            let mut version = factory.version(spec, chain_id);
            version.max_blobs_per_tx = env.version.max_blobs_per_tx;
            env = EthEvmEnv::new_with_version(factory.spec_id(spec), env.block, version);
        }
        env.version.chain_id = chain_id;
        env
    }
}

impl<C, F> reth_firehose::FirehoseLiveHooks for PulsechainEvmConfig<C, F>
where
    F: EvmFactory,
    Self: ConfigureEvm,
{
    type PreTxAdjust = reth_firehose::NoPreTxAdjust;
    type PostTxExtras = reth_firehose::NoPostTxExtras;
}

impl<C, F> ConfigureEvm for PulsechainEvmConfig<C, F>
where
    C: EthChainSpec<Header = Header> + EthereumHardforks + Hardforks + 'static,
    F: EvmFactory,
    <F::Types as evm2::EvmTypesHost>::Tx: alloy_eips::eip2718::Typed2718
        + reth_evm::FromTxWithEncoded<TransactionSigned>
        + reth_evm::TransactionEnvMut,
{
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = PulsechainBlockExecutorFactory<C, F>;
    type BlockAssembler = EthBlockAssembler<C>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.pulse_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn with_jit_support_enabled(self, enabled: bool) -> Self {
        Self::from_eth(self.inner.with_jit_support_enabled(enabled))
    }

    fn evm_with_precompile_cache<'a, DB>(
        &self,
        db: DB,
        evm_env: EvmEnvFor<Self>,
        cache_map: PrecompileCacheMap<SpecFor<Self>>,
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

    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        let env = self.inner.evm_env(header)?;
        Ok(self.adjust_env(env, header.number, header.timestamp))
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        let env = self.inner.next_evm_env(parent, attributes)?;
        Ok(self.adjust_env(env, parent.number.saturating_add(1), attributes.timestamp))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error>
    where
        Self: 'a,
    {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }

    fn reuses_prewarm_results(&self) -> bool {
        self.inner.reuses_prewarm_results()
    }

    fn prewarm_tx_result<'a>(
        &self,
        tx: &TransactionSigned,
        result: reth_evm::TxResultWithStateFor<Self>,
    ) -> Option<reth_evm::TxExecutionResultFor<'a, Self>>
    where
        Self: 'a,
    {
        self.inner.prewarm_tx_result(tx, result)
    }
}

impl<C, F> ConfigureEngineEvm<ExecutionData> for PulsechainEvmConfig<C, F>
where
    C: EthChainSpec<Header = Header> + EthereumHardforks + Hardforks + 'static,
    F: EvmFactory,
    F::Types: evm2::EvmTypes<Tx = evm2::ethereum::TxEnvelope>,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let env = self.inner.evm_env_for_payload(payload)?;
        Ok(self.adjust_env(env, payload.payload.block_number(), payload.payload.timestamp()))
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: payload.payload.as_v1().extra_data.clone(),
            slot_number: payload.payload.as_v4().map(|v4| v4.slot_number),
        })
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        // Same as `EthEvmConfig::tx_iterator_for_payload`; restated so the compiler can see that
        // the iterator satisfies `ExecutableTxIterator<Self>`.
        let txs = payload.payload.transactions().clone();
        let sender_recovery_cache = self.inner.sender_recovery_cache.clone();
        let convert = move |tx: Bytes| {
            let tx = TransactionSigned::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = if let Some(cache) = &sender_recovery_cache {
                cache.recover(&tx)
            } else {
                tx.try_recover()
            }
            .map_err(AnyError::new)?;
            Ok::<_, AnyError>(ExecutableRecoveredTx::new(tx.with_signer(signer)))
        };
        Ok((txs, convert))
    }
}

// ── PulsechainExecutorBuilder ─────────────────────────────────────────────────

/// Node builder component that provides the `PulseChain` EVM configuration.
///
/// Builds the Ethereum config the same way as `EthereumExecutorBuilder` (JIT settings and the
/// shared sender recovery cache), then wraps it in [`PulsechainEvmConfig`].
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PulsechainExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for PulsechainExecutorBuilder
where
    Types: NodeTypes<
        ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + Hardforks + 'static,
        Primitives = EthPrimitives,
    >,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = PulsechainEvmConfig<Types::ChainSpec, RethEvmFactory>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let jit = &ctx.config().jit;
        let dump_dir = jit.debug.then(|| ctx.config().datadir().data_dir().join("jit"));
        let (mut evm_config, _jit_metrics) =
            reth_node_ethereum::node::build_evm_config(ctx.chain_spec(), jit, dump_dir)?;
        if let Some(cache) = ctx.sender_recovery_cache() {
            evm_config = evm_config.with_sender_recovery_cache(cache.clone());
        }
        Ok(PulsechainEvmConfig::from_eth(evm_config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            env.spec < SpecId::MERGE,
            "block before ETH Merge should use pre-MERGE spec, got {:?}",
            env.spec
        );
    }

    #[test]
    fn eth_merge_block_gets_merge_spec() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xaa);
        // Block 15,537,394 — first post-Merge Ethereum block
        let header = header_at(ETH_MAINNET_MERGE_BLOCK, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.spec, SpecId::MERGE, "ETH Merge block must use MERGE spec");
    }

    #[test]
    fn post_merge_mid_range_gets_merge_spec() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xbb);
        // Block 16,000,000 — well after ETH Merge, before PrimordialPulse
        let header = header_at(16_000_000, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.spec, SpecId::MERGE, "post-Merge replay block must use MERGE spec");
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

        assert_eq!(env.spec, SpecId::MERGE, "post-Merge pre-Shanghai block must use MERGE spec");
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
            env.spec,
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

        assert_eq!(env.block.difficulty, U256::ZERO);
        assert_eq!(env.block.prevrandao, U256::from_be_bytes(randao.0));
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
            env.spec,
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

        assert_eq!(env.spec, SpecId::MERGE, "block 1 second before Shanghai must use MERGE spec");
    }

    #[test]
    fn block_just_before_eth_merge_is_not_merge() {
        let config = mainnet_evm_config();
        let header = header_at(ETH_MAINNET_MERGE_BLOCK - 1, 100, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        assert!(
            env.spec < SpecId::MERGE,
            "block right before ETH Merge should not use MERGE spec, got {:?}",
            env.spec
        );
    }

    // ── Difficulty / prevrandao tests ───────────────────────────────────

    #[test]
    fn pre_merge_block_has_nonzero_difficulty_and_no_prevrandao() {
        let config = mainnet_evm_config();
        let header = header_at(15_050_001, 12_345_678, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        assert_ne!(env.block.difficulty, U256::ZERO, "pre-Merge block should preserve difficulty");
        // evm2 always fills `prevrandao` from `mix_hash`; the pre-Merge spec makes DIFFICULTY
        // return `difficulty`, so there is no separate "no prevrandao" state to check.
        assert!(env.spec < SpecId::MERGE);
    }

    #[test]
    fn post_merge_block_has_zero_difficulty_and_prevrandao() {
        let config = mainnet_evm_config();
        let randao = B256::repeat_byte(0xcc);
        let header = header_at(ETH_MAINNET_MERGE_BLOCK, 0, randao);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.block.difficulty, U256::ZERO, "post-Merge block must have zero difficulty");
        assert_eq!(
            env.block.prevrandao,
            U256::from_be_bytes(randao.0),
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

        assert_eq!(env.block.prevrandao, U256::from_be_bytes(randao.0));
        assert_eq!(env.block.difficulty, U256::ZERO);
    }

    // ── Chain ID tests ─────────────────────────────────────────────────

    #[test]
    fn chain_id_is_1_before_primordial_pulse() {
        let config = mainnet_evm_config();
        let header = header_at(ETH_MAINNET_MERGE_BLOCK, 0, B256::repeat_byte(0xaa));
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.version.chain_id, 1, "chain ID must be 1 during Ethereum history replay");
    }

    #[test]
    fn chain_id_is_369_at_primordial_pulse() {
        let config = mainnet_evm_config();
        let header = header_at(PRIMORDIAL_PULSE_MAINNET_BLOCK, 100, B256::ZERO);
        let env = config.evm_env(&header).unwrap();

        assert_eq!(env.version.chain_id, 369, "chain ID must be 369 at PrimordialPulse");
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
            env.spec < SpecId::MERGE,
            "PrimordialPulse block should not use MERGE spec (Paris is at +1), got {:?}",
            env.spec
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
        assert_eq!(env.spec, SpecId::MERGE, "first PulseChain PoS block must use MERGE spec");
    }

    // ── Block execution through PulsechainBlockExecutor ────────────────────────

    use crate::fork::{
        decode_sacrifice_credits, DEPOSIT_CONTRACT_BYTECODE, DEPOSIT_CONTRACT_INITIAL_STORAGE,
        ETH_DEPOSIT_CONTRACT, PULSE_DEPOSIT_CONTRACT, SACRIFICE_CREDITS_TESTNET_V4,
        TESTNET_V4_TREASURY, TESTNET_V4_TREASURY_BALANCE,
    };
    use alloy_primitives::keccak256;
    use evm2::evm::InMemoryDB;
    use reth_evm::execute::{BasicBlockExecutor, Executor};
    use reth_primitives_traits::Block as _;
    use reth_pulsechain_forks::{
        chainspec::PULSECHAIN_TESTNET_V4,
        hardfork::{PRIMORDIAL_PULSE_TESTNET_V4_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP},
    };

    const BENEFICIARY: alloy_primitives::Address = alloy_primitives::Address::repeat_byte(0xbe);

    /// Executes an empty block `number` on testnet v4 on top of `db` and returns the final state.
    fn execute_empty_block(db: InMemoryDB, number: u64, timestamp: u64) -> BundleState {
        let header = Header {
            number,
            timestamp,
            beneficiary: BENEFICIARY,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            difficulty: U256::from(1),
            ..Default::default()
        };
        let block = Block { header, body: Default::default() }
            .try_into_recovered()
            .expect("an empty block recovers");
        let mut executor =
            BasicBlockExecutor::new(PulsechainEvmConfig::new(PULSECHAIN_TESTNET_V4.clone()), db);
        executor.execute_one(&block).expect("the block executes");
        executor.into_state()
    }

    fn balance(state: &BundleState, address: alloy_primitives::Address) -> Option<U256> {
        state.account(&address).and_then(|account| account.info.as_ref()).map(|info| info.balance)
    }

    /// The fork block applies the whole transition: the treasury and every sacrifice credit, the
    /// destroyed Ethereum deposit contract (storage wiped), and the deployed `PulseChain` one. The
    /// block's proof-of-work reward is still paid, because Paris activates one block later.
    #[test]
    fn primordial_pulse_block_applies_the_transition_and_the_block_reward() {
        let mut db = InMemoryDB::default();
        let eth_code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00]));
        let mut eth_deposit =
            AccountInfo::new(U256::from(1_000), 1, eth_code.hash_slow(), Some(eth_code));
        db.insert_contract(&mut eth_deposit);
        db.insert_account_info(&ETH_DEPOSIT_CONTRACT, eth_deposit);
        db.insert_account_storage(&ETH_DEPOSIT_CONTRACT, &U256::from(7), &U256::from(42));

        let state = execute_empty_block(
            db,
            PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
            PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP,
        );

        let credits = decode_sacrifice_credits(SACRIFICE_CREDITS_TESTNET_V4);
        assert!(!credits.is_empty());
        let mut expected: std::collections::HashMap<_, U256> = Default::default();
        expected.insert(TESTNET_V4_TREASURY, TESTNET_V4_TREASURY_BALANCE);
        for (address, amount) in &credits {
            *expected.entry(*address).or_default() += *amount;
        }
        for (address, amount) in &expected {
            if *address == BENEFICIARY {
                continue
            }
            assert_eq!(balance(&state, *address), Some(*amount), "credit to {address}");
        }

        let eth_deposit =
            state.account(&ETH_DEPOSIT_CONTRACT).expect("ETH deposit is in the state");
        assert!(eth_deposit.info.is_none(), "the ETH deposit contract is destroyed");
        assert!(eth_deposit.was_destroyed(), "its storage is wiped");

        let pulse = state
            .account(&PULSE_DEPOSIT_CONTRACT)
            .and_then(|account| account.info.as_ref())
            .expect("the PulseChain deposit contract is deployed");
        assert_eq!(pulse.code_hash, keccak256(DEPOSIT_CONTRACT_BYTECODE));
        let pulse_storage = &state.account(&PULSE_DEPOSIT_CONTRACT).unwrap().storage;
        for (slot, value) in DEPOSIT_CONTRACT_INITIAL_STORAGE {
            let slot = pulse_storage
                .get(&U256::from_be_bytes(slot.0))
                .unwrap_or_else(|| panic!("deposit contract slot {slot} is written"));
            assert_eq!(slot.present_value, U256::from_be_bytes(value.0));
        }

        // 2 ETH proof-of-work reward (Constantinople onward), plus any credit to the
        // beneficiary.
        let reward = U256::from(2_000_000_000_000_000_000u128);
        let credit = expected.get(&BENEFICIARY).copied().unwrap_or_default();
        assert_eq!(balance(&state, BENEFICIARY), Some(reward + credit));
    }

    /// No transition account is one the fork block's beneficiary reward would also touch in a
    /// way the order of the two could change: the transition destroys or rewrites only the two
    /// deposit contracts, and only adds to every other balance.
    #[test]
    fn primordial_pulse_rewrites_only_the_deposit_contracts() {
        for (address, _) in decode_sacrifice_credits(SACRIFICE_CREDITS_TESTNET_V4) {
            assert_ne!(address, ETH_DEPOSIT_CONTRACT);
            assert_ne!(address, PULSE_DEPOSIT_CONTRACT);
        }
        assert_ne!(ETH_DEPOSIT_CONTRACT, PULSE_DEPOSIT_CONTRACT);
    }

    /// A block that replays Ethereum after its Merge pays no proof-of-work reward, although
    /// `PulseChain`'s own spec has Paris only after `PrimordialPulse`.
    #[test]
    fn eth_post_merge_replay_block_pays_no_block_reward() {
        let state =
            execute_empty_block(InMemoryDB::default(), ETH_MAINNET_MERGE_BLOCK + 1, 1_663_300_000);
        assert_eq!(balance(&state, BENEFICIARY), None, "the beneficiary must not be credited");
    }

    /// Negative control for the test above: the block just before Ethereum's Merge still pays
    /// the proof-of-work reward.
    #[test]
    fn eth_pre_merge_block_pays_the_block_reward() {
        let state =
            execute_empty_block(InMemoryDB::default(), ETH_MAINNET_MERGE_BLOCK - 1, 1_663_200_000);
        assert_eq!(balance(&state, BENEFICIARY), Some(U256::from(2_000_000_000_000_000_000u128)));
    }
}
