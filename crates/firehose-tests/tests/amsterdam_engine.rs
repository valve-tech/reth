//! Regression test: the Firehose-traced engine path accepts Amsterdam blocks.
//!
//! While the tracer is installed, the engine validates every payload on the traced path. On an
//! Amsterdam block that path must build the block access list, so post-execution validation can
//! check it against the header's `block_access_list_hash`. The check passes only when the traced
//! path builds the same access list as the block builder did.
//!
//! It lives in its own integration-test binary because it installs the process-wide tracer.

use alloy_rpc_types_engine::PayloadStatusEnum;
use base64::{engine::general_purpose, Engine as _};
use firehose_tracer::pb::sf::ethereum::r#type::v2::Block as FirehoseBlock;
use prost::Message as _;
use reth_chainspec::EthereumHardfork;
use reth_e2e_test_utils::{transaction::TransactionTestContext, E2ETestSetupExt};
use reth_firehose::init_tracer;
use reth_node_ethereum::EthereumNode;

#[tokio::test(flavor = "multi_thread")]
async fn traced_engine_path_accepts_amsterdam_block() -> eyre::Result<()> {
    let (tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: 1,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            verkle_time: None,
        },
        "reth-firehose-tests",
        env!("CARGO_PKG_VERSION"),
    );
    init_tracer(tracer);

    let (mut nodes, wallet) =
        EthereumNode::test_setup_for(EthereumHardfork::Amsterdam).with_num_nodes(2).build().await?;
    let validator = nodes.pop().unwrap();
    let mut builder = nodes.pop().unwrap();

    // The builder only builds the block. The validator executes it on the traced path, because it
    // has not seen the block before.
    let raw_tx = TransactionTestContext::transfer_tx_bytes(1, wallet.inner).await;
    builder.rpc.inject_tx(raw_tx).await?;
    let payload = builder.new_payload().await?;
    let header = payload.block().header().clone();
    assert!(header.block_access_list_hash.is_some(), "builder made a pre-Amsterdam block");

    let status =
        validator.inner.add_ons_handle.beacon_engine_handle.new_payload(payload.into()).await?;
    assert_eq!(status.status, PayloadStatusEnum::Valid, "traced path rejected the block");
    let output = buffer.get_bytes();
    assert_eq!(fire_blocks(&output), 1, "traced path did not emit the block");
    assert!(emitted_bal_hash(&output), "emitted block has no block access list hash");

    Ok(())
}

/// Counts the `FIRE BLOCK` lines in the tracer output.
fn fire_blocks(output: &[u8]) -> usize {
    String::from_utf8_lossy(output).lines().filter(|line| line.starts_with("FIRE BLOCK ")).count()
}

/// Returns whether the emitted block carries a block access list hash.
fn emitted_bal_hash(output: &[u8]) -> bool {
    let text = String::from_utf8_lossy(output);
    let line = text.lines().find(|line| line.starts_with("FIRE BLOCK ")).expect("no FIRE BLOCK");
    let payload = line.rsplit(' ').next().expect("FIRE BLOCK line has no payload");
    let bytes = general_purpose::STANDARD.decode(payload).expect("base64 payload");
    let block = FirehoseBlock::decode(bytes.as_slice()).expect("protobuf block");
    block.header.and_then(|header| header.block_access_list_hash).is_some()
}
