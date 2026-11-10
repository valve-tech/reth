//! Regression test for Firehose tracing of Amsterdam blocks on the engine-tree live-block path.
//!
//! Amsterdam blocks commit to an EIP-7928 block access list, and the engine executes a block
//! carrying one on the BAL path: workers execute the transactions in parallel, in whatever order
//! the payload processor converts them, and a canonical executor commits the results in block
//! order. The Firehose twin of that path traces each transaction on the worker that executes it
//! and attaches the traces to the block in order. If it does not, every Amsterdam block arriving
//! through `engine_newPayload` is either rejected while tracing is on (no `FIRE BLOCK` line) or
//! traced out of order.
//!
//! The middle block carries a creation transaction starved of its EIP-8037 creation state gas:
//! evm2 includes it without opening its root frame, and the live path must trace that root call
//! the same way the pipeline path does (see the `amsterdam_create_runtime_out_of_gas` prestate
//! case in `reth-firehose-tests`).
//!
//! The third block carries enough transactions from a single sender for the payload processor to
//! convert them in parallel, so the traces must still be attached in block order or the sender's
//! nonces come out of order.
//!
//! The last block carries calls from several senders to a contract that writes storage and emits
//! a log, so the traces have ordinals, log indexes and cumulative gas to rebase. They are checked
//! against the receipts the node serves over RPC and against the block invariants.
//!
//! The spans the payload validator opens are recorded, so the test fails if a block is executed
//! on another path than the traced BAL path. A second node started with
//! `--engine.disable-bal-parallel-execution`, the switch that sends Amsterdam blocks back to the
//! serial traced path, produces the same blocks and must trace them all without that path.
//!
//! Like `firehose_live_tracing`, it lives in its own integration-test binary because it installs
//! a process-wide tracer.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Bytes, TxKind, B256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use eyre::Result;
use firehose_tracer::pb::sf::ethereum::r#type::v2::{CallType, TransactionTraceStatus};
use firehose_tracer_test::BlockInvariants;
use reth_chainspec::{EthChainSpec, EthereumHardfork};
use reth_e2e_test_utils::{
    transaction::TransactionTestContext,
    wallet::{test_signer, Wallet},
    E2ETestSetupExt, NodeHelperType,
};
use reth_node_ethereum::EthereumNode;
use reth_provider::BalProvider;
use tracing::{
    span::{Attributes, Id},
    Subscriber,
};
use tracing_subscriber::{
    layer::{Context, SubscriberExt},
    EnvFilter, Layer,
};

/// Number of blocks to produce, all of them validated through the traced BAL path.
const PRODUCED_BLOCKS: u64 = 4;

/// Block that deploys the counter contract.
const DEPLOY_BLOCK: u64 = 1;

/// Block that carries the starved creation transaction.
const FRAMELESS_BLOCK: u64 = 2;

/// Above Amsterdam's intrinsic cost for the init code below, far below its creation state gas.
const FRAMELESS_GAS_LIMIT: u64 = 30_000;

/// Block that carries the same-sender batch.
const BATCH_BLOCK: u64 = 3;

/// Above the payload processor's sequential conversion threshold of 30 transactions.
const BATCH_TX_COUNT: u64 = 40;

/// Block that carries the calls to the counter contract.
const LOGS_BLOCK: u64 = 4;

/// Wallet accounts that call the counter contract, and calls per account. Together above the
/// payload processor's sequential conversion threshold of 30 transactions.
const LOG_SENDERS: std::ops::RangeInclusive<u32> = 2..=5;
const CALLS_PER_SENDER: u64 = 8;

/// Wallet account that deploys the counter contract.
const DEPLOYER: u32 = 6;

/// Init code of a contract that increments storage slot 0 and emits `LOG1` with topic `0xaa`.
const COUNTER_INIT_CODE: &[u8] = &[
    0x60, 0x11, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x11, 0x60, 0x00, 0xf3, 0x60, 0x00, 0x54, 0x60,
    0x01, 0x01, 0x60, 0x00, 0x55, 0x60, 0xaa, 0x60, 0x00, 0x60, 0x00, 0xa1, 0x00,
];

/// Tracing target of the payload validator's spans.
const VALIDATOR_TARGET: &str = "engine::tree::payload_validator";

/// Span of the validator function that executes a block on the traced BAL path.
const TRACED_BAL_PATH: &str = "execute_and_trace_block_bal";

/// Span of the validator function that executes a block on the untraced BAL path.
const UNTRACED_BAL_PATH: &str = "execute_block_bal";

#[tokio::test]
async fn live_payload_validation_traces_amsterdam_blocks() -> Result<()> {
    let spans = SpanRecorder::install();

    let (mut node, wallet) =
        EthereumNode::test_setup_for(EthereumHardfork::Amsterdam).build_single().await?;

    // Installed after node startup so the genesis block isn't emitted, only the live blocks.
    let buffer = reth_firehose::init_tracer_with_buffer(
        node.inner.chain_spec().chain().id(),
        Some(0), // shanghai
        Some(0), // cancun
        Some(0), // prague
    );

    let hashes = produce_blocks(&mut node, &wallet).await?;
    let output = buffer.get_bytes();
    assert_traced_blocks(&node, &output, &hashes).await?;
    assert_eq!(
        spans.take(TRACED_BAL_PATH),
        PRODUCED_BLOCKS as usize,
        "every live Amsterdam block is executed on the traced BAL path"
    );
    assert_eq!(spans.take(UNTRACED_BAL_PATH), 0, "no live block skips the tracer");
    drop(node);

    // The escape hatch: `--engine.disable-bal-parallel-execution` sends Amsterdam blocks back to
    // the serial traced path, which must still trace them all.
    let (mut node, wallet) = EthereumNode::test_setup_for(EthereumHardfork::Amsterdam)
        .with_tree_config_modifier(|config| config.without_bal_parallel_execution(true))
        .build_single()
        .await?;
    let hashes = produce_blocks(&mut node, &wallet).await?;
    let serial_output = &buffer.get_bytes()[output.len()..];
    assert_traced_blocks(&node, serial_output, &hashes).await?;
    assert_eq!(
        spans.take(TRACED_BAL_PATH),
        0,
        "with parallel BAL execution disabled, no block is executed on the traced BAL path"
    );
    assert_eq!(spans.take(UNTRACED_BAL_PATH), 0, "no live block skips the tracer");

    Ok(())
}

/// Produces the blocks described in the module documentation and returns their hashes.
async fn produce_blocks(
    node: &mut NodeHelperType<EthereumNode>,
    wallet: &Wallet,
) -> Result<Vec<B256>> {
    let chain_id = node.inner.chain_spec().chain().id();
    let mut deployer = wallet.account(DEPLOYER);
    let counter = deployer.next_contract_address();
    let mut hashes = Vec::with_capacity(PRODUCED_BLOCKS as usize);
    for number in 1..=PRODUCED_BLOCKS {
        if number == DEPLOY_BLOCK {
            let deploy = deployer.deploy(Bytes::from_static(COUNTER_INIT_CODE)).await;
            node.rpc.inject_tx(deploy).await?;
        }
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
        if number == LOGS_BLOCK {
            for index in LOG_SENDERS {
                // Covers the Amsterdam state gas of the counter's new storage slot.
                let mut account = wallet.account(index).with_gas_limit(300_000);
                for _ in 0..CALLS_PER_SENDER {
                    let call = account.call(counter, Bytes::new()).await;
                    node.rpc.inject_tx(call).await?;
                }
            }
        }
        let payload = node.advance_block().await?;
        hashes.push(payload.block().hash());
    }
    Ok(hashes)
}

/// Checks the `FIRE BLOCK` lines in `output` against the blocks `node` produced.
async fn assert_traced_blocks(
    node: &NodeHelperType<EthereumNode>,
    output: &[u8],
    hashes: &[B256],
) -> Result<()> {
    let text = std::str::from_utf8(output).expect("captured tracer output is UTF-8");
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
        let block = reth_firehose_tests::parse_fire_block_for(output, number)?;
        BlockInvariants::assert(&block)?;
    }

    let block = reth_firehose_tests::parse_fire_block_for(output, FRAMELESS_BLOCK)?;
    let trx = block.transaction_traces.first().expect("the starved creation is included");
    assert_eq!(trx.status, TransactionTraceStatus::Failed as i32);
    assert_eq!(trx.gas_used, FRAMELESS_GAS_LIMIT, "an out-of-gas halt charges the whole gas limit");
    assert!(trx.receipt.is_some(), "the receipt is kept");
    let root = trx.calls.first().expect("the live path traces the root call revm never opened");
    assert_eq!(root.call_type, CallType::Create as i32);
    assert!(root.status_failed);

    let block = reth_firehose_tests::parse_fire_block_for(output, BATCH_BLOCK)?;
    let nonces = block.transaction_traces.iter().map(|trx| trx.nonce).collect::<Vec<_>>();
    assert_eq!(nonces, (0..BATCH_TX_COUNT).collect::<Vec<_>>());

    // The traced receipts of the calls carry the block-wide values the node serves over RPC.
    let block = reth_firehose_tests::parse_fire_block_for(output, LOGS_BLOCK)?;
    let receipts = node
        .rpc_provider()
        .get_block_receipts(BlockNumberOrTag::Number(LOGS_BLOCK).into())
        .await?
        .expect("the block has receipts");
    let expected_count = LOG_SENDERS.count() as u64 * CALLS_PER_SENDER;
    assert_eq!(receipts.len() as u64, expected_count);
    assert_eq!(block.transaction_traces.len(), receipts.len());
    for (trx, rpc) in block.transaction_traces.iter().zip(&receipts) {
        assert_eq!(trx.hash, rpc.transaction_hash.as_slice());
        assert_eq!(trx.index as u64, rpc.transaction_index.expect("a mined receipt has an index"));
        let receipt = trx.receipt.as_ref().expect("the receipt is kept");
        assert_eq!(receipt.cumulative_gas_used, rpc.inner.cumulative_gas_used());
        let rpc_logs = rpc.inner.logs();
        assert_eq!(receipt.logs.len(), rpc_logs.len());
        assert_eq!(receipt.logs.len(), 1, "each call emits one log");
        for (log, rpc_log) in receipt.logs.iter().zip(rpc_logs) {
            assert_eq!(
                log.block_index as u64,
                rpc_log.log_index.expect("a mined log has an index")
            );
        }
        let call = trx.calls.first().expect("the call has a root call");
        assert_eq!(call.storage_changes.len(), 1, "each call increments the counter");
        assert_eq!(call.logs[0].block_index, receipt.logs[0].block_index);
    }

    // The BAL built by the traced execution is what the node stores for the block.
    for hash in hashes {
        let bal = node.inner.provider.get_bal_by_hash(*hash)?;
        assert!(bal.is_some(), "no BAL stored for live Amsterdam block {hash}");
    }

    Ok(())
}

/// Counts the spans the payload validator opens, by function name.
#[derive(Clone, Default)]
struct SpanRecorder(Arc<Mutex<HashMap<&'static str, usize>>>);

impl SpanRecorder {
    /// Installs the recorder as the process-wide subscriber, next to the usual test log output
    /// filtered by `RUST_LOG`.
    fn install() -> Self {
        let recorder = Self::default();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_filter(EnvFilter::from_default_env()),
            )
            .with(recorder.clone());
        tracing::subscriber::set_global_default(subscriber)
            .expect("the test installs the only subscriber");
        recorder
    }

    /// Returns how many times the validator opened `name` since the last call and forgets them.
    fn take(&self, name: &'static str) -> usize {
        self.0.lock().expect("recorder lock").remove(name).unwrap_or(0)
    }
}

impl<S: Subscriber> Layer<S> for SpanRecorder {
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        if metadata.target() == VALIDATOR_TARGET {
            *self.0.lock().expect("recorder lock").entry(metadata.name()).or_default() += 1;
        }
    }
}
