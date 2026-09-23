//! A trace larger than the RPC response limit must be refused before it is built, and the
//! refusal must name the transaction responsible.
//!
//! The case comes from Sepolia block 6,747,896. One transaction there makes 1,000 calls, each
//! passing the same 100,000-byte memory buffer as input. Memory expansion is paid once and each
//! call costs about 200 gas, so the transaction costs 270k gas. But a parity trace writes every
//! call's input in full, as hex, so its trace is ~200 MB — past reth's 160 MB default. An
//! indexer that scrapes with `trace_block` then stalls on that block indefinitely.
//!
//! The contract below is the same shape at test scale: 100 calls with a 10,000-byte buffer, which
//! is ~2 MB of trace for ~16k gas, against a 1 MB response limit.

use alloy_eips::BlockNumberOrTag;
use alloy_genesis::Genesis;
use alloy_primitives::{address, Address, U256};
use alloy_provider::{network::EthereumWallet, Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use eyre::Result;
use reth_chainspec::ChainSpec;
use reth_e2e_test_utils::wallet::Wallet;
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::{DevArgs, RpcServerArgs},
    node_config::NodeConfig,
};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_provider::providers::BlockchainProvider;
use reth_rpc_server_types::RpcModuleSelection;
use reth_tasks::Runtime;
use std::{any::Any, sync::Arc};

/// Holds the trace bomb: 100 `CALL`s to `0x…0123`, each passing memory `[0, 10_000)` as input.
const BOMB: Address = address!("0x0000000000000000000000000000000000004000");

/// A plain account, so a call to it is an ordinary transfer.
const EOA: Address = address!("0x0000000000000000000000000000000000001000");

/// jsonrpsee's code for a response over the configured limit.
const OVERSIZED_RESPONSE_CODE: i64 = -32008;

#[tokio::test]
async fn trace_refusal_names_the_transaction_that_overflows_the_response() -> Result<()> {
    reth_tracing::init_test_tracing();
    let (_node, url) = spawn_dev_node_with_response_limit_mb(1).await?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::new(
            Wallet::default().with_chain_id(2601).wallet_gen().swap_remove(0),
        ))
        .connect_http(url);

    // Control: an ordinary block traces fine under the same limit, so a node that refused
    // every trace could not pass this test.
    let transfer = provider
        .send_transaction(TransactionRequest::default().to(EOA).value(U256::from(1)))
        .await?
        .get_receipt()
        .await?;
    let traces: serde_json::Value = provider
        .raw_request(
            "trace_block".into(),
            (BlockNumberOrTag::Number(transfer.block_number.expect("mined")),),
        )
        .await?;
    assert!(traces.as_array().is_some_and(|t| !t.is_empty()), "an ordinary block traces");

    let bomb = provider
        .send_transaction(TransactionRequest::default().to(BOMB).gas_limit(1_000_000))
        .await?
        .get_receipt()
        .await?;
    assert!(bomb.status(), "the bomb transaction itself succeeds");
    let bomb_hash = bomb.transaction_hash.to_string();

    for (method, params) in [
        (
            "trace_block",
            serde_json::json!([BlockNumberOrTag::Number(bomb.block_number.expect("mined"))]),
        ),
        ("trace_transaction", serde_json::json!([bomb.transaction_hash])),
    ] {
        let err = provider
            .raw_request::<_, serde_json::Value>(method.into(), params)
            .await
            .expect_err("a trace over the response limit is refused");
        let payload = err.as_error_resp().expect("a JSON-RPC error, not a transport failure");

        assert_eq!(payload.code, OVERSIZED_RESPONSE_CODE, "{method}: jsonrpsee's own code");
        assert!(payload.message.contains("is too big"), "{method}: eRPC matches on this text");
        let data = payload.data.as_ref().expect("the refusal explains itself").get();
        assert!(data.contains(&bomb_hash), "{method}: names the transaction responsible: {data}");
    }
    Ok(())
}

/// Starts a dev node that mines on each transaction, with an RPC response limit of `limit_mb`.
///
/// The node handle comes back alongside the URL because dropping it shuts the node down.
async fn spawn_dev_node_with_response_limit_mb(
    limit_mb: u32,
) -> Result<(Box<dyn Any>, reqwest::Url)> {
    let mut rpc = RpcServerArgs::default()
        .with_unused_ports()
        .with_http()
        .with_http_api(RpcModuleSelection::all_modules().into());
    rpc.rpc_max_response_size = limit_mb.into();

    let config = NodeConfig::test()
        .with_chain(chain_spec())
        .with_disabled_discovery()
        .with_dev(DevArgs { dev: true, ..Default::default() })
        .with_rpc(rpc);

    let NodeHandle { node, node_exit_future } = NodeBuilder::new(config)
        .testing_node(Runtime::test())
        .with_types_and_provider::<EthereumNode, BlockchainProvider<_>>()
        .with_components(EthereumNode::components())
        .with_add_ons(EthereumAddOns::default())
        .launch_with_debug_capabilities()
        .await?;

    let url = node.rpc_server_handle().http_url().expect("http rpc enabled").parse()?;
    Ok((Box::new((node, node_exit_future)), url))
}

/// Shanghai genesis funding the test mnemonic's first account and holding the bomb contract.
fn chain_spec() -> Arc<ChainSpec> {
    // Runtime code for BOMB, 29 bytes:
    //   PUSH1 100                       ; loop counter
    //   JUMPDEST                        ; offset 2
    //   PUSH1 0  PUSH1 0                ; retSize, retOffset
    //   PUSH2 10000  PUSH1 0            ; argsSize, argsOffset
    //   PUSH1 0  PUSH2 0x0123  GAS      ; value, target, gas
    //   CALL  POP
    //   PUSH1 1  SWAP1  SUB             ; counter - 1
    //   DUP1  PUSH1 2  JUMPI            ; loop while non-zero
    //   STOP
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
        "0x0000000000000000000000000000000000004000": {
            "balance": "0x0",
            "code": "0x60645b60006000612710600060006101235af150600190038060025700"
        }
    },
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "config": {
        "chainId": 2601,
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
