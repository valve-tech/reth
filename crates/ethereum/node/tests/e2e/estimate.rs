//! Accuracy tests for `eth_estimateGas`.
//!
//! Every test runs against a local node built from the fixed genesis below, so an
//! estimate is an exact number rather than a range. The genesis stops at Shanghai
//! because that is the fork PulseChain runs, and because EIP-7623 (Prague) changes
//! the calldata floor and would make the constants here fork-dependent.
//!
//! The contract accounts hold hand-written runtime code so the gas each one costs
//! is arithmetic a reader can check:
//!
//! | account          | runtime code       | cost above the 21000 intrinsic |
//! |------------------|--------------------|--------------------------------|
//! | `STOP_CONTRACT`  | `STOP`             | 0                              |
//! | `SSTORE_CONTRACT`| `PUSH1 1 PUSH1 0 SSTORE STOP` | 3 + 3 + 20000 + 2100 |

use alloy_eips::BlockId;
use alloy_genesis::Genesis;
use alloy_primitives::{address, bytes, Address, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::TransactionRequest;
use eyre::Result;
use reth_chainspec::ChainSpec;
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::EthereumNode;
use reth_rpc_server_types::{constants::gas_oracle::ESTIMATE_GAS_ERROR_RATIO, RpcModuleSelection};
use reth_tasks::Runtime;
use std::{any::Any, sync::Arc};

/// Account 0 of the standard test mnemonic, funded by the genesis below.
const SENDER: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// A plain account. It holds no code, so a call to it is a basic transfer.
const EOA: Address = address!("0x0000000000000000000000000000000000001000");

/// Holds the single byte `STOP`. A call runs no work but is not a basic transfer,
/// so it takes the binary search rather than the transfer shortcut.
const STOP_CONTRACT: Address = address!("0x0000000000000000000000000000000000002000");

/// Writes 1 to storage slot 0, which is both cold and zero, so the write costs
/// the full 20000 plus the 2100 cold-slot surcharge.
const SSTORE_CONTRACT: Address = address!("0x0000000000000000000000000000000000003000");

/// The intrinsic cost of a transaction that carries no calldata.
const INTRINSIC: u64 = 21_000;

/// `PUSH1 1` + `PUSH1 0` + `SSTORE` + `STOP`, over the intrinsic cost.
const SSTORE_EXECUTION: u64 = 3 + 3 + 20_000 + 2_100;

/// A plain transfer between two accounts with no code costs exactly the intrinsic gas.
#[tokio::test]
async fn plain_transfer_estimates_the_intrinsic_cost() -> Result<()> {
    let (_handle, provider) = spawn_node().await?;

    let request = TransactionRequest::default().from(SENDER).to(EOA);
    let estimate = provider.estimate_gas(request).block(BlockId::latest()).await?;

    assert_eq!(estimate, INTRINSIC, "a transfer with no calldata costs exactly {INTRINSIC}");
    Ok(())
}

/// Moving value does not change the cost of a transfer.
#[tokio::test]
async fn transfer_with_value_estimates_the_intrinsic_cost() -> Result<()> {
    let (_handle, provider) = spawn_node().await?;

    let request =
        TransactionRequest::default().from(SENDER).to(EOA).value(U256::from(1_000_000_000u64));
    let estimate = provider.estimate_gas(request).block(BlockId::latest()).await?;

    assert_eq!(estimate, INTRINSIC, "value transfer costs no more than an empty transfer");
    Ok(())
}

/// Calldata is charged per byte on top of the intrinsic cost: 16 gas for a non-zero
/// byte and 4 for a zero byte. This request carries three of each.
#[tokio::test]
async fn calldata_is_charged_per_byte() -> Result<()> {
    let (_handle, provider) = spawn_node().await?;

    let request =
        TransactionRequest::default().from(SENDER).to(EOA).input(bytes!("0x010203000000").into());
    let estimate = provider.estimate_gas(request).block(BlockId::latest()).await?;

    assert_no_margin(estimate, INTRINSIC + 3 * 16 + 3 * 4, "three non-zero and three zero bytes");
    Ok(())
}

/// A call to a contract whose code does nothing still costs only the intrinsic gas.
///
/// The destination holds code, so the transfer shortcut does not apply and the
/// estimate comes from the binary search. The search must still land on the exact
/// figure rather than somewhere above it.
#[tokio::test]
async fn call_to_a_contract_that_does_nothing_estimates_the_intrinsic_cost() -> Result<()> {
    let (_handle, provider) = spawn_node().await?;

    let request = TransactionRequest::default().from(SENDER).to(STOP_CONTRACT);
    let estimate = provider.estimate_gas(request).block(BlockId::latest()).await?;

    assert_no_margin(estimate, INTRINSIC, "a call that runs only STOP");
    Ok(())
}

/// A storage write costs the intrinsic gas plus the work the code does, and nothing more.
///
/// This is the case that exposes a blanket safety margin: the destination holds code,
/// so the estimate comes from the binary search and passes through the tail of
/// `EstimateCall::estimate_gas_with`.
#[tokio::test]
async fn storage_write_estimates_the_execution_cost() -> Result<()> {
    let (_handle, provider) = spawn_node().await?;

    let request = TransactionRequest::default().from(SENDER).to(SSTORE_CONTRACT);
    let estimate = provider.estimate_gas(request).block(BlockId::latest()).await?;

    assert_no_margin(estimate, INTRINSIC + SSTORE_EXECUTION, "a cold zero-to-non-zero write");
    Ok(())
}

/// Asserts an estimate covers the transaction and carries no safety margin.
///
/// The binary search stops once the remaining bracket is within
/// [`ESTIMATE_GAS_ERROR_RATIO`] of its top, so it may return slightly more than the
/// exact cost. That slack is the only excess allowed. A blanket margin applied after
/// the search — of the kind this fork carried until the estimator was cleaned up —
/// lands far outside it.
fn assert_no_margin(estimate: u64, exact: u64, what: &str) {
    let ceiling = exact + (exact as f64 * ESTIMATE_GAS_ERROR_RATIO).ceil() as u64;

    assert!(estimate >= exact, "{what}: estimate {estimate} is below the true cost {exact}");
    assert!(
        estimate <= ceiling,
        "{what}: estimate {estimate} exceeds {ceiling}, the most the search may return for a \
         true cost of {exact}. A margin has been added somewhere after the search."
    );
}

/// Every estimate this suite makes must be reproducible.
///
/// The estimator runs a binary search, so a change that makes its exit depend on
/// anything other than the request and the state would show up here.
#[tokio::test]
async fn estimates_are_reproducible() -> Result<()> {
    let (_handle, provider) = spawn_node().await?;

    let request = TransactionRequest::default().from(SENDER).to(SSTORE_CONTRACT);

    let first = provider.estimate_gas(request.clone()).block(BlockId::latest()).await?;
    for _ in 0..4 {
        let again = provider.estimate_gas(request.clone()).block(BlockId::latest()).await?;
        assert_eq!(again, first, "the same request against the same state must give one answer");
    }
    Ok(())
}

/// Starts a node on the fixed genesis and returns an HTTP provider for it.
///
/// The node handle comes back alongside the provider because dropping it shuts the
/// node down. Its type is erased so callers do not have to name the full component
/// stack; they only ever hold it.
async fn spawn_node() -> Result<(Box<dyn Any>, DynProvider)> {
    reth_tracing::init_test_tracing();

    // Estimation reads only local state, so the node runs with discovery off. That keeps
    // the tests hermetic and off the host's resolver configuration.
    let config = NodeConfig::test().with_chain(chain_spec()).with_disabled_discovery().with_rpc(
        RpcServerArgs::default()
            .with_unused_ports()
            .with_http()
            .with_http_api(RpcModuleSelection::all_modules().into()),
    );

    let NodeHandle { node, node_exit_future } = NodeBuilder::new(config)
        .testing_node(Runtime::test())
        .node(EthereumNode::default())
        .launch()
        .await?;

    let provider = node.rpc_server_handle().eth_http_provider().expect("http rpc enabled").erased();

    Ok((Box::new((node, node_exit_future)), provider))
}

/// The genesis every test in this file runs against.
fn chain_spec() -> Arc<ChainSpec> {
    let genesis = r#"
{
    "nonce": "0x0",
    "timestamp": "0x0",
    "extraData": "0x",
    "gasLimit": "0x1c9c380",
    "difficulty": "0x0",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266": {
            "balance": "0x21e19e0c9bab2400000"
        },
        "0x0000000000000000000000000000000000001000": {
            "balance": "0x0"
        },
        "0x0000000000000000000000000000000000002000": {
            "balance": "0x0",
            "code": "0x00"
        },
        "0x0000000000000000000000000000000000003000": {
            "balance": "0x0",
            "code": "0x600160005500"
        }
    },
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "config": {
        "chainId": 2600,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": true,
        "shanghaiTime": 0
    }
}
"#;
    let genesis: Genesis = serde_json::from_str(genesis).unwrap();
    Arc::new(genesis.into())
}
