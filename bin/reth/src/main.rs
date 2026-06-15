#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

// Required for "override_allocator_on_supported_platforms".
#[cfg(all(feature = "jemalloc", unix))]
use reth_cli_util::allocator::tikv_jemalloc_sys as _;

#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "malloc_conf")]
static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

use std::sync::Arc;

use clap::Parser;
use reth::{cli::Cli, PulsechainFirehoseExecutorBuilder};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_msgboard::{args::MsgboardArgs, MsgboardLauncher};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_pulsechain_node::{
    consensus::PulsechainConsensus, evm::PulsechainEvmConfig, gas::install_gas_estimation_margin,
    launch::inject_pulsechain_bootnodes_if_unset, spec::PulsechainChainSpec,
    PulsechainChainSpecParser, PulsechainNode,
};
use tracing::info;

/// Chain names that route to upstream `EthereumNode` (full Pectra / EIP-7702
/// support). Anything else falls through to [`PulsechainNode`].
///
/// `PulsechainNode`'s block executor uses PulseChain's hardfork schedule which
/// does not activate Pectra; running it on `--chain mainnet` rejects EIP-7702
/// transactions post-block 22,431,084 with `Eip7702NotSupported`. Routing on
/// chain name (rather than chain id of an already-parsed spec) is necessary
/// because the chosen `Cli<ChainSpecParser, _>` type — and therefore the
/// produced chain spec — is fixed at parse time.
const ETHEREUM_CHAIN_NAMES: &[&str] = &["mainnet", "sepolia", "holesky", "hoodi"];

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    // Firehose tracer init is gated inside `run_pulsechain_node` only — see
    // the comment there for the lifecycle-contract reason this can't run
    // unconditionally before chain dispatch.
    let result =
        if requested_ethereum_chain() { run_ethereum_node() } else { run_pulsechain_node() };

    if let Err(err) = result {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

/// Peek `--chain X` / `--chain=X` from argv and decide whether the user is
/// requesting an Ethereum chain. We have to dispatch before `Cli::parse()`
/// because the chain spec parser type is part of `Cli`'s type signature.
fn requested_ethereum_chain() -> bool {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let name = if let Some(stripped) = arg.strip_prefix("--chain=") {
            Some(stripped.to_string())
        } else if arg == "--chain" {
            args.next()
        } else {
            None
        };

        if let Some(name) = name {
            return ETHEREUM_CHAIN_NAMES.contains(&name.as_str());
        }
    }
    false
}

/// Launch path for Ethereum chains (mainnet/sepolia/holesky/hoodi).
///
/// Uses upstream [`EthereumNode`] with stock components. Msgboard is wired
/// identically to the PulseChain path so the same binary serves both.
fn run_ethereum_node() -> eyre::Result<()> {
    Cli::<EthereumChainSpecParser, MsgboardArgs>::parse().run(
        async move |builder, msgboard_args: MsgboardArgs| {
            info!(target: "reth::cli", "Launching Ethereum node");

            let launcher = MsgboardLauncher::new(msgboard_args);
            let launcher_for_rpc = launcher.clone();

            let node = builder.node(EthereumNode::default()).extend_rpc_modules(move |ctx| {
                let datadir = ctx.config().datadir().data_dir().to_path_buf();
                launcher_for_rpc.install(ctx.modules, ctx.network().clone(), datadir)?;
                Ok(())
            });

            let handle = node.launch().await?;
            launcher.install_post_launch_tasks(
                handle.node.network.clone(),
                handle.node.provider.clone(),
            );
            let exit = handle.wait_for_node_exit().await;
            launcher.final_flush();
            exit
        },
    )
}

/// Launch path for PulseChain chains (pulsechain mainnet/testnet) and any
/// other chain not handled by [`run_ethereum_node`].
///
/// Uses [`PulsechainNode`] with [`PulsechainFirehoseExecutorBuilder`] swapped in
/// for the default executor — the executor wraps [`PulsechainEvmConfig`] in
/// `FirehoseEvmConfig` so PulseChain block execution fires the firehose tracer
/// hooks (CHAINID override, Shanghai-gap consensus, PrimordialPulse transition
/// all preserved). The "firehose" ExEx drives downstream block streaming.
///
/// PrimordialPulse fork-block tracing is wired separately in
/// `crates/pulsechain/node/src/evm.rs` (see NOTES-firehose.md).
fn run_pulsechain_node() -> eyre::Result<()> {
    // Initialise the firehose tracer ONLY on the PulseChain dispatch path.
    //
    // The tracer's `on_block_execution_start` hook asserts that
    // `on_blockchain_init` was fired earlier in the node lifecycle. The
    // PulseChain path satisfies that contract via the firehose ExEx wired
    // into `PulsechainFirehoseExecutorBuilder` below — it fires
    // `on_blockchain_init` during the executor's chain-init pass.
    //
    // Upstream `EthereumNode` (used by `run_ethereum_node`) has no
    // equivalent ExEx and never fires that hook. Installing the tracer
    // before chain dispatch therefore panicked on `--chain mainnet` at the
    // first block-execution call with:
    //   "the OnBlockchainInit hook should have been called at this point"
    // (firehose-tracer-5.0.0/src/tracer.rs:1739). Gating the init here so
    // the tracer never enters the Ethereum lifecycle in the first place.
    reth_firehose::init_tracer(firehose_tracer::Tracer::new(firehose_tracer::config::Config {
        chain_client: firehose_tracer::config::ChainClient::Reth,
        ..Default::default()
    }));

    // We use `run_with_components` (instead of the convenience `run`) because our chain
    // spec is `PulsechainChainSpec` (a wrapper that overrides Shanghai detection for the
    // pre-PrimordialPulse Ethereum-replay range). `Cli::run` is hard-bound to upstream
    // `ChainSpec`, so we pass the components closure ourselves. The closure provides
    // (EvmConfig, Consensus) for non-launch CLI commands; the actual launch path below
    // uses the components-builder API to swap in firehose-instrumented components.
    let components = |spec: Arc<PulsechainChainSpec>| {
        (PulsechainEvmConfig::new(spec.clone()), Arc::new(PulsechainConsensus::new(spec)))
    };

    Cli::<PulsechainChainSpecParser, MsgboardArgs>::parse().run_with_components::<PulsechainNode>(
        components,
        async move |mut builder, msgboard_args: MsgboardArgs| {
            info!(target: "reth::cli", "Launching PulseChain node");

            let chain_id = builder.config().chain.chain().id();
            inject_pulsechain_bootnodes_if_unset(
                &mut builder.config_mut().network.bootnodes,
                chain_id,
            );

            let launcher = MsgboardLauncher::new(msgboard_args);
            let launcher_for_rpc = launcher.clone();

            // Build via the components fluent API so we can swap in
            // PulsechainFirehoseExecutorBuilder + install the firehose ExEx.
            // Mirrors the run_ethereum_node path but with PulseChain's
            // pool/network/consensus/payload builders.
            let handle = builder
                .with_types::<PulsechainNode>()
                .with_components(
                    PulsechainNode::components()
                        .executor(PulsechainFirehoseExecutorBuilder::default()),
                )
                .with_add_ons(EthereumAddOns::default())
                .extend_rpc_modules(move |ctx| {
                    let datadir = ctx.config().datadir().data_dir().to_path_buf();
                    launcher_for_rpc.install(ctx.modules, ctx.network().clone(), datadir)?;

                    // Replace eth_estimateGas with a version that adds a 20% margin.
                    let eth_api = ctx.registry.eth_api().clone();
                    install_gas_estimation_margin(ctx.modules, eth_api)?;

                    Ok(())
                })
                .install_exex("firehose", |ctx| async move {
                    Ok(async move { reth_firehose::run_exex(ctx).await })
                })
                .launch()
                .await?;

            launcher.install_post_launch_tasks(
                handle.node.network.clone(),
                handle.node.provider.clone(),
            );
            let exit = handle.wait_for_node_exit().await;
            launcher.final_flush();
            exit
        },
    )
}
