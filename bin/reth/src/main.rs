#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

#[cfg(all(feature = "jemalloc", unix))]
use reth_cli_util::allocator::tikv_jemalloc_sys as _;

#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "malloc_conf")]
static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

use std::{str::FromStr, sync::Arc};

use clap::Parser;
use reth::{
    cli::Cli, FirehoseExecutorBuilder, MsgboardNetworkBuilder, PulsechainFirehoseExecutorBuilder,
};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_msgboard::{args::MsgboardArgs, launch::MSGBOARD_RPC_NAMESPACE, MsgboardLauncher};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_pulsechain_node::{
    consensus::PulsechainConsensus, evm::PulsechainEvmConfig, gas::install_gas_estimation_margin,
    launch::inject_pulsechain_bootnodes_if_unset, spec::PulsechainChainSpec,
    PulsechainChainSpecParser, PulsechainNode,
};
use reth_rpc_server_types::{RethRpcModule, RpcModuleSelection, RpcModuleValidator};
use tracing::info;

#[derive(Debug, Clone, Copy)]
pub struct ValveRpcModuleValidator;

impl RpcModuleValidator for ValveRpcModuleValidator {
    fn parse_selection(s: &str) -> Result<RpcModuleSelection, String> {
        let selection = RpcModuleSelection::from_str(s)
            .map_err(|e| format!("Failed to parse RPC modules: {e}"))?;

        if let RpcModuleSelection::Selection(modules) = &selection {
            for module in modules {
                if let RethRpcModule::Other(name) = module {
                    if name != MSGBOARD_RPC_NAMESPACE {
                        return Err(format!("Unknown RPC module: '{name}'"));
                    }
                }
            }
        }

        Ok(selection)
    }
}

const ETHEREUM_CHAIN_NAMES: &[&str] = &["mainnet", "sepolia", "holesky", "hoodi"];

#[derive(Debug, Clone, clap::Args)]
struct EthereumExtArgs {
    #[command(flatten)]
    msgboard: MsgboardArgs,

    #[arg(long = "firehose.enabled", env = "RETH_FIREHOSE_ENABLED", default_value_t = false)]
    firehose_enabled: bool,

    #[arg(long = "firehose.replica", env = "FIREHOSE_REPLICA", default_value = "a")]
    firehose_replica: String,
}

#[derive(Debug, Clone, clap::Args)]
struct PulsechainExtArgs {
    #[command(flatten)]
    msgboard: MsgboardArgs,

    #[arg(long = "firehose.replica", env = "FIREHOSE_REPLICA", default_value = "a")]
    firehose_replica: String,
}

fn sync_firehose_replica_env(replica: &str) {
    if std::env::var_os("VALVE_REPLICA").is_some() {
        return;
    }
    unsafe { std::env::set_var("FIREHOSE_REPLICA", replica) };
}

fn main() {
    #[cfg(feature = "jit")]
    {
        match reth_node_ethereum::node::maybe_run_jit_helper() {
            Ok(std::ops::ControlFlow::Break(())) => return,
            Ok(std::ops::ControlFlow::Continue(())) => {}
            Err(err) => {
                eprintln!("Error: {err:?}");
                std::process::exit(1);
            }
        }
    }

    reth_cli_util::sigsegv_handler::install();

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let result =
        if requested_ethereum_chain() { run_ethereum_node() } else { run_pulsechain_node() };

    if let Err(err) = result {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

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

fn run_ethereum_node() -> eyre::Result<()> {
    Cli::<EthereumChainSpecParser, EthereumExtArgs, ValveRpcModuleValidator>::parse().run(
        async move |builder, ext: EthereumExtArgs| {
            let EthereumExtArgs {
                msgboard: msgboard_args,
                firehose_enabled,
                firehose_replica,
            } = ext;
            sync_firehose_replica_env(&firehose_replica);
            let launcher = MsgboardLauncher::new(msgboard_args);

            if firehose_enabled {
                info!(target: "reth::cli", "Launching Ethereum node (firehose-instrumented)");
                warn_if_jit_requested_with_firehose(builder.config().jit.enabled);

                reth_firehose::init_tracer(firehose_tracer::Tracer::new(
                    firehose_tracer::config::Config {
                        chain_client: firehose_tracer::config::ChainClient::Reth,
                        ..Default::default()
                    },
                ));

                let launcher_for_rpc = launcher.clone();
                let handle = builder
                    .with_types::<EthereumNode>()
                    .with_components(
                        EthereumNode::components()
                            .executor(FirehoseExecutorBuilder::default())
                            .network(MsgboardNetworkBuilder::new(launcher.clone())),
                    )
                    .with_add_ons(EthereumAddOns::default())
                    .extend_rpc_modules(move |ctx| {
                        launcher_for_rpc.install_rpc(ctx.modules)?;
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
            } else {
                info!(target: "reth::cli", "Launching Ethereum node (stock, firehose disabled)");

                let launcher_for_rpc = launcher.clone();
                let handle = builder
                    .with_types::<EthereumNode>()
                    .with_components(
                        EthereumNode::components()
                            .network(MsgboardNetworkBuilder::new(launcher.clone())),
                    )
                    .with_add_ons(EthereumAddOns::default())
                    .extend_rpc_modules(move |ctx| {
                        launcher_for_rpc.install_rpc(ctx.modules)?;
                        Ok(())
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
            }
        },
    )
}

fn run_pulsechain_node() -> eyre::Result<()> {
    reth_firehose::init_tracer(firehose_tracer::Tracer::new(firehose_tracer::config::Config {
        chain_client: firehose_tracer::config::ChainClient::Reth,
        ..Default::default()
    }));

    let components = |spec: Arc<PulsechainChainSpec>| {
        (PulsechainEvmConfig::new(spec.clone()), Arc::new(PulsechainConsensus::new(spec)))
    };

    Cli::<PulsechainChainSpecParser, PulsechainExtArgs, ValveRpcModuleValidator>::parse()
        .run_with_components::<PulsechainNode>(
            components,
            async move |mut builder, ext: PulsechainExtArgs| {
                let PulsechainExtArgs { msgboard: msgboard_args, firehose_replica } = ext;
                sync_firehose_replica_env(&firehose_replica);
                info!(target: "reth::cli", "Launching PulseChain node");
                warn_if_jit_requested_with_firehose(builder.config().jit.enabled);

                let chain_id = builder.config().chain.chain().id();
                inject_pulsechain_bootnodes_if_unset(
                    &mut builder.config_mut().network.bootnodes,
                    chain_id,
                );

                let launcher = MsgboardLauncher::new(msgboard_args);
                let launcher_for_rpc = launcher.clone();

                let handle = builder
                    .with_types::<PulsechainNode>()
                    .with_components(
                        PulsechainNode::components()
                            .executor(PulsechainFirehoseExecutorBuilder::default())
                            .network(MsgboardNetworkBuilder::new(launcher.clone())),
                    )
                    .with_add_ons(EthereumAddOns::default())
                    .extend_rpc_modules(move |ctx| {
                        launcher_for_rpc.install_rpc(ctx.modules)?;

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

fn warn_if_jit_requested_with_firehose(jit_enabled: bool) {
    if jit_enabled {
        tracing::warn!(
            target: "reth::cli",
            "--jit has no effect on a firehose node and is being ignored. Firehose and the revmc \
             JIT are mutually exclusive: the JIT's compiled path does not fire the Inspector \
             hooks firehose reads from. Drop the flag to silence this warning."
        );
    }
}

#[cfg(test)]
mod validator_tests {
    use super::*;

    #[test]
    fn accepts_the_msgboard_namespace() {
        let selection = ValveRpcModuleValidator::parse_selection(
            "eth,net,web3,debug,trace,txpool,rpc,reth,ots,msgboard",
        )
        .expect("msgboard must be accepted");

        let RpcModuleSelection::Selection(modules) = selection else {
            panic!("expected an explicit selection");
        };
        assert!(modules.contains(&RethRpcModule::Other(MSGBOARD_RPC_NAMESPACE.to_string())));
        assert!(modules.contains(&RethRpcModule::Eth));
    }

    #[test]
    fn still_rejects_a_typo() {
        let err = ValveRpcModuleValidator::parse_selection("eth,mssgboard")
            .expect_err("a misspelled namespace must be rejected");
        assert!(err.contains("mssgboard"), "the error must name the offending module: {err}");
    }

    #[test]
    fn rejects_an_unrelated_unknown_namespace() {
        assert!(ValveRpcModuleValidator::parse_selection("eth,definitely_not_a_module").is_err());
    }

    #[test]
    fn leaves_standard_selections_alone() {
        for s in ["eth", "eth,net,web3", "all", "none"] {
            assert!(
                ValveRpcModuleValidator::parse_selection(s).is_ok(),
                "standard selection {s} must stay valid"
            );
        }
    }

    #[test]
    fn validate_selection_accepts_msgboard_and_rejects_a_typo() {
        let parsed = RpcModuleSelection::from_str("eth,msgboard").unwrap();
        assert!(ValveRpcModuleValidator::validate_selection(&parsed, "http.api").is_ok());

        let typo = RpcModuleSelection::from_str("eth,mssgboard").unwrap();
        let err = ValveRpcModuleValidator::validate_selection(&typo, "http.api")
            .expect_err("validate_selection must reject a typo too");
        assert!(err.contains("http.api"), "the error must name the argument: {err}");
    }
}
