// ---------------------------------------------------------------------------
// FirehoseExecutorBuilder + PulsechainFirehoseExecutorBuilder
// ---------------------------------------------------------------------------

use alloy_consensus::Header;
use reth_chainspec::EthChainSpec;
use reth_ethereum_forks::{EthereumHardforks, Hardforks};
use reth_ethereum_primitives::EthPrimitives;
use reth_firehose::{prelude::eyre, FirehoseEvmConfig};
use reth_node_builder::{
    components::ExecutorBuilder,
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_node_ethereum::EthEvmConfig;
use reth_pulsechain_node::evm::PulsechainEvmConfig;

/// Node-builder executor builder that wraps [`EthEvmConfig`] in a [`FirehoseEvmConfig`].
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FirehoseExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for FirehoseExecutorBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<ChainSpec: Hardforks + EthereumHardforks, Primitives = EthPrimitives>,
    >,
{
    type EVM = FirehoseEvmConfig<EthEvmConfig<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        // A JIT-compiled frame only calls `log`/`selfdestruct`/`frame_end` on the Inspector —
        // `step`/`step_end` never fire, so per-opcode storage writes and gas-reason data silently
        // vanish from Firehose output while producing no error. This builder never wires JIT
        // support into the resulting `EthEvmConfig` in the first place (unlike
        // `EthereumExecutorBuilder::build_evm`, which honors `--jit` via `build_evm_config`), but
        // refuse to start outright if `--jit` was passed so a misconfigured node fails loudly
        // instead of silently ignoring the flag. The `reth_jit` RPC method is guarded separately
        // (crates/rpc/rpc/src/reth.rs) since JIT can still be toggled at runtime regardless of how
        // the node started.
        if ctx.config().jit.enabled {
            eyre::bail!(
                "refusing to start with --jit while the Firehose tracer is active: JIT-compiled \
                 execution does not fire the Inspector step/step_end hooks Firehose relies on \
                 for per-opcode tracing"
            );
        }

        let mut evm_config = EthEvmConfig::new(ctx.chain_spec());
        if let Some(cache) = ctx.sender_recovery_cache() {
            evm_config = evm_config.with_sender_recovery_cache(cache.clone());
        }
        Ok(FirehoseEvmConfig::new(evm_config))
    }
}

/// `PulseChain` analogue of [`FirehoseExecutorBuilder`] — wraps
/// [`PulsechainEvmConfig`] in [`FirehoseEvmConfig`] so the firehose tracer sees
/// `PulseChain`'s executor (`CHAINID` override, custom Shanghai gap, `PrimordialPulse`
/// transition) the same way it sees the upstream Ethereum executor.
///
/// The trait bounds mirror [`PulsechainExecutorBuilder`] in
/// `crates/pulsechain/node/src/evm.rs`: any chain spec that satisfies the
/// `EthExecutor` trait stack with `Header`-typed headers is acceptable, which
/// covers both `PulsechainChainSpec` and the pulsechain testnet variant.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PulsechainFirehoseExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for PulsechainFirehoseExecutorBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + Hardforks + 'static,
            Primitives = EthPrimitives,
        >,
    >,
{
    type EVM = FirehoseEvmConfig<PulsechainEvmConfig<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        // Same refusal as the Ethereum builder above: Firehose needs the interpreter's
        // Inspector hooks.
        if ctx.config().jit.enabled {
            eyre::bail!(
                "refusing to start with --jit while the Firehose tracer is active: JIT-compiled \
                 execution does not fire the Inspector step/step_end hooks Firehose relies on \
                 for per-opcode tracing"
            );
        }

        let mut evm_config = EthEvmConfig::new(ctx.chain_spec());
        if let Some(cache) = ctx.sender_recovery_cache() {
            evm_config = evm_config.with_sender_recovery_cache(cache.clone());
        }
        Ok(FirehoseEvmConfig::new(PulsechainEvmConfig::from_eth(evm_config)))
    }
}
