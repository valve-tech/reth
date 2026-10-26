//! A firehose node must emit the block it proposed.
//!
//! Firehose emits a block's `FIRE BLOCK` line while the engine validates it,
//! on the traced path in `payload_validator.rs`. The payload builder never
//! traces. So a proposed block reaches the stream only if the proposer
//! re-executes it on `newPayload`.
//!
//! It does today, but only because `EthBuiltPayload` does not implement
//! `BuiltPayload::executed_block`. If it ever did, the node builder would
//! hand the built block to the tree as `InsertExecutedBlock`
//! (`crates/node/builder/src/launch/engine.rs`), `newPayload` would find it
//! already known, and every block a firehose box proposes would be missing
//! from its stream. This test fails if that happens.
//!
//! This lives in its own test binary because it installs the process-wide
//! tracer.

mod common;

use std::time::Duration;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    ExecutionPayloadFieldV2, ExecutionPayloadInputV2, ForkchoiceState, PayloadStatusEnum,
};
use common::*;
use jsonrpsee_core::{client::ClientT, rpc_params};
use reth_chainspec::EthChainSpec;
use reth_node_builder::NodeHandle;
use reth_node_ethereum::EthEngineTypes;
use reth_provider::BlockNumReader;
use reth_pulsechain_forks::{chainspec::PULSECHAIN, hardfork::SHANGHAI_MAINNET_TIMESTAMP};
use reth_rpc_api::EngineApiClient;

/// Counts the `FIRE BLOCK` lines for `number` in the tracer output.
///
/// The line is `FIRE BLOCK <block_num> <flash_block_idx> <block_hash> ...`.
fn fire_block_lines(output: &[u8], number: u64) -> usize {
    let prefix = format!("FIRE BLOCK {number} ");
    String::from_utf8_lossy(output).lines().filter(|line| line.starts_with(&prefix)).count()
}

#[tokio::test(flavor = "multi_thread")]
async fn firehose_node_emits_the_block_it_proposed() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let buffer =
        reth_firehose::init_tracer_with_buffer(369, Some(SHANGHAI_MAINNET_TIMESTAMP), None, None);

    let chain_spec = pulse_spec(&PULSECHAIN, 45_000_000, sender(369).address());
    let genesis_hash = chain_spec.genesis_hash();
    let NodeHandle { node, node_exit_future: _exit } =
        launch_node!(node_config(chain_spec, Some(45_000_000)));
    let engine = node.auth_server_handle().http_client();
    let rpc = node.rpc_server_handle().http_client().expect("http rpc is enabled");

    let raw = signed_transfer(369).await;
    let _: B256 = rpc.request("eth_sendRawTransaction", rpc_params![raw]).await?;

    let updated = EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(
        &engine,
        forkchoice_at(genesis_hash),
        Some(attributes()),
    )
    .await?;
    let payload_id = updated.payload_id.expect("FCUv2 with attributes must start a build");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let envelope = EngineApiClient::<EthEngineTypes>::get_payload_v2(&engine, payload_id).await?;
    let ExecutionPayloadFieldV2::V2(payload) = envelope.execution_payload else {
        panic!("a post-Shanghai payload must be the V2 variant");
    };
    let hash = payload.payload_inner.block_hash;
    let number = payload.payload_inner.block_number;

    // Give the built-payload event time to reach the tree, as it would in the
    // gap while the validator signs and publishes the block.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Control: building the block emitted nothing.
    assert_eq!(fire_block_lines(&buffer.get_bytes(), number), 0, "the builder must not trace");

    let status = EngineApiClient::<EthEngineTypes>::new_payload_v2(
        &engine,
        ExecutionPayloadInputV2 {
            execution_payload: payload.payload_inner,
            withdrawals: Some(payload.withdrawals),
        },
    )
    .await?;
    assert_eq!(status.status, PayloadStatusEnum::Valid);

    let new_head = ForkchoiceState {
        head_block_hash: hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };
    let updated =
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(&engine, new_head, None).await?;
    assert_eq!(updated.payload_status.status, PayloadStatusEnum::Valid);

    let mut tries = 0;
    while node.provider.best_block_number()? != number {
        tries += 1;
        assert!(tries < 50, "the built block never became canonical");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        fire_block_lines(&buffer.get_bytes(), number),
        1,
        "the firehose stream must carry the block this node proposed, exactly once"
    );
    Ok(())
}
