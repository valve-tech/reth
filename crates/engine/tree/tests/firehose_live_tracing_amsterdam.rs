//! Regression test for Firehose tracing of Amsterdam blocks on the engine-tree live-block path.
//!
//! Amsterdam blocks commit to an EIP-7928 block access list, and post-execution consensus rejects
//! a block whose execution produced no BAL (`BlockAccessListHashMissing`). The Firehose twin of
//! `execute_block` (`execute_and_trace_block`) must therefore build the BAL exactly like upstream
//! does; if it doesn't, every Amsterdam block arriving through `engine_newPayload` is rejected
//! while tracing is on and no `FIRE BLOCK` line is emitted for it.
//!
//! The middle block also carries a creation transaction starved of its EIP-8037 creation state
//! gas: revm includes it without opening its root frame, and the live path must trace that root
//! call the same way the pipeline path does (see the `amsterdam_create_runtime_out_of_gas`
//! prestate case in `reth-firehose-tests`).
//!
//! The last block carries enough transactions from a single sender for the payload processor to
//! convert them in parallel. The traced execution is sequential, so it must still receive them in
//! block order or the sender's later nonces are rejected as too high.
//!
//! Like `firehose_live_tracing`, it lives in its own integration-test binary because it installs
//! a process-wide tracer.

use alloy_primitives::{Bytes, TxKind};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use eyre::Result;
use firehose_tracer::pb::sf::ethereum::r#type::v2::{CallType, TransactionTraceStatus};
use reth_chainspec::{EthChainSpec, EthereumHardfork};
use reth_e2e_test_utils::{
    transaction::TransactionTestContext,
    wallet::{test_signer, Wallet},
    E2ETestSetupExt,
};
use reth_node_ethereum::EthereumNode;
use reth_provider::BalProvider;

/// Number of blocks to produce, all of them validated through `execute_and_trace_block`.
const PRODUCED_BLOCKS: u64 = 3;

/// Block that carries the starved creation transaction.
const FRAMELESS_BLOCK: u64 = 2;

/// Above Amsterdam's intrinsic cost for the init code below, far below its creation state gas.
const FRAMELESS_GAS_LIMIT: u64 = 30_000;

/// Block that carries the same-sender batch.
const BATCH_BLOCK: u64 = 3;

/// Above the payload processor's sequential conversion threshold of 30 transactions.
const BATCH_TX_COUNT: u64 = 40;

#[tokio::test]
async fn live_payload_validation_traces_amsterdam_blocks() -> Result<()> {
    reth_tracing::init_test_tracing();

    let (mut node, _) =
        EthereumNode::test_setup_for(EthereumHardfork::Amsterdam).build_single().await?;

    // Installed after node startup so the genesis block isn't emitted, only the live blocks.
    let buffer = reth_firehose::init_tracer_with_buffer(
        node.inner.chain_spec().chain().id(),
        Some(0), // shanghai
        Some(0), // cancun
        Some(0), // prague
    );

    let chain_id = node.inner.chain_spec().chain().id();
    let mut hashes = Vec::with_capacity(PRODUCED_BLOCKS as usize);
    for number in 1..=PRODUCED_BLOCKS {
        if number == FRAMELESS_BLOCK {
            // PUSH1 0, PUSH1 0, RETURN: a constructor that would deploy empty code if it ran.
            let deploy = TransactionRequest {
                nonce: Some(0),
                to: Some(TxKind::Create),
                gas: Some(FRAMELESS_GAS_LIMIT),
                max_fee_per_gas: Some(20e9 as u128),
                max_priority_fee_per_gas: Some(20e9 as u128),
                chain_id: Some(chain_id),
                input: TransactionInput::new(Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xf3])),
                ..Default::default()
            };
            let deploy =
                TransactionTestContext::sign_tx_bytes(Wallet::default().inner, deploy).await;
            node.rpc.inject_tx(deploy).await?;
        }
        if number == BATCH_BLOCK {
            for nonce in 0..BATCH_TX_COUNT {
                let transfer = TransactionTestContext::transfer_tx_bytes_with_nonce(
                    chain_id,
                    test_signer(1),
                    nonce,
                )
                .await;
                node.rpc.inject_tx(transfer).await?;
            }
        }
        let payload = node.advance_block().await?;
        hashes.push(payload.block().hash());
    }

    let raw = buffer.get_bytes();
    let text = String::from_utf8(raw).expect("captured tracer output is UTF-8");
    let traced: Vec<u64> = text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(' ');
            if parts.next()? != "FIRE" || parts.next()? != "BLOCK" {
                return None;
            }
            parts.next()?.parse::<u64>().ok()
        })
        .collect();

    for number in 1..=PRODUCED_BLOCKS {
        assert!(
            traced.contains(&number),
            "expected a FIRE BLOCK line for live Amsterdam block #{number}, got traced blocks \
             {traced:?}"
        );
    }

    let block = reth_firehose_tests::parse_fire_block_for(&buffer.get_bytes(), FRAMELESS_BLOCK)?;
    let trx = block.transaction_traces.first().expect("the starved creation is included");
    assert_eq!(trx.status, TransactionTraceStatus::Failed as i32);
    assert_eq!(trx.gas_used, FRAMELESS_GAS_LIMIT, "an out-of-gas halt charges the whole gas limit");
    assert!(trx.receipt.is_some(), "the receipt is kept");
    let root = trx.calls.first().expect("the live path traces the root call revm never opened");
    assert_eq!(root.call_type, CallType::Create as i32);
    assert!(root.status_failed);

    let block = reth_firehose_tests::parse_fire_block_for(&buffer.get_bytes(), BATCH_BLOCK)?;
    let nonces = block.transaction_traces.iter().map(|trx| trx.nonce).collect::<Vec<_>>();
    assert_eq!(nonces, (0..BATCH_TX_COUNT).collect::<Vec<_>>());

    // The BAL built by the traced execution is what the node stores for the block.
    for hash in hashes {
        let bal = node.inner.provider.get_bal_by_hash(hash)?;
        assert!(bal.is_some(), "no BAL stored for live Amsterdam block {hash}");
    }

    Ok(())
}
