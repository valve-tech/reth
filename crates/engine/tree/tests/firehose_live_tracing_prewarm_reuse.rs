//! Regression test for Firehose tracing on the engine-tree live-block path with prewarm result
//! reuse enabled.
//!
//! With `--engine.prewarm-reuse`, upstream `execute_block` commits a transaction's speculative
//! prewarm result instead of executing it when the result's reads are still valid. A committed
//! result never runs through the EVM, so the Firehose inspector would not see the transaction. The
//! traced twin (`execute_and_trace_block`) must execute every transaction even when reuse is on.
//!
//! The node runs the stock `EthEvmConfig`, which opts into reuse, and the traced block carries
//! independent transfers from distinct senders, whose prewarm results stay valid.
//!
//! Like `firehose_live_tracing`, it lives in its own integration-test binary because it installs
//! a process-wide tracer.

use alloy_primitives::Address;
use eyre::Result;
use reth_chainspec::{EthChainSpec, EthereumHardfork};
use reth_e2e_test_utils::{
    transaction::TransactionTestContext, wallet::test_signer, E2ETestSetupExt,
};
use reth_node_ethereum::EthereumNode;

/// Block that carries the transfers.
const TRANSFER_BLOCK: u64 = 2;

/// Number of distinct funded senders in the transfer block.
const SENDER_COUNT: u32 = 16;

/// Gas used by a plain value transfer.
const TRANSFER_GAS: u64 = 21_000;

#[tokio::test]
async fn live_payload_validation_traces_reused_prewarm_results() -> Result<()> {
    reth_tracing::init_test_tracing();

    let (mut node, _) = EthereumNode::test_setup_for(EthereumHardfork::Prague)
        .with_tree_config_modifier(|config| {
            config.with_has_enough_parallelism(true).with_prewarm_reuse(true)
        })
        .build_single()
        .await?;

    // Installed after node startup so the genesis block isn't emitted, only the live blocks.
    let buffer = reth_firehose::init_tracer_with_buffer(
        node.inner.chain_spec().chain().id(),
        Some(0), // shanghai
        Some(0), // cancun
        Some(0), // prague
    );

    let chain_id = node.inner.chain_spec().chain().id();
    let mut senders = Vec::with_capacity(SENDER_COUNT as usize);
    for number in 1..=TRANSFER_BLOCK {
        if number == TRANSFER_BLOCK {
            for index in 0..SENDER_COUNT {
                let signer = test_signer(index);
                senders.push(signer.address());
                let transfer =
                    TransactionTestContext::transfer_tx_bytes_with_nonce(chain_id, signer, 0).await;
                node.rpc.inject_tx(transfer).await?;
            }
        }
        node.advance_block().await?;
    }

    let block = reth_firehose_tests::parse_fire_block_for(&buffer.get_bytes(), TRANSFER_BLOCK)?;
    let mut traced_senders = block
        .transaction_traces
        .iter()
        .map(|trx| Address::from_slice(&trx.from))
        .collect::<Vec<_>>();
    traced_senders.sort_unstable();
    senders.sort_unstable();
    assert_eq!(traced_senders, senders, "every transfer is traced");

    for trx in &block.transaction_traces {
        assert_eq!(trx.gas_used, TRANSFER_GAS);
        assert!(!trx.calls.is_empty(), "transaction {:?} was traced without executing", trx.hash);
    }

    Ok(())
}
