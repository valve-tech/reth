//! Regression test: the tracer emits the block access list of a downloaded Amsterdam block that
//! arrives without its BAL sidecar.
//!
//! A peer serves the block body but no BAL, so the engine downloads the block, executes it, builds
//! its access list, and checks that list against the header's `block_access_list_hash`. The
//! emitted Firehose header must then carry the RLP of the built list. Without the fix, the
//! validator passes only a sidecar's BAL to the tracer, and the header has no BAL RLP.
//!
//! It lives in its own integration-test binary because it installs the process-wide tracer.

use std::{sync::Arc, time::Duration};

use alloy_primitives::keccak256;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use futures::StreamExt;
use reth_chainspec::EthereumHardfork;
use reth_e2e_test_utils::{test_chain_spec, transaction::TransactionTestContext, E2ETestSetupExt};
use reth_engine_primitives::ConsensusEngineEvent;
use reth_ethereum_primitives::EthPrimitives;
use reth_firehose::init_tracer_with_buffer;
use reth_firehose_tests::parse_fire_block_for;
use reth_network::{test_utils::Testnet, Peers};
use reth_node_ethereum::EthereumNode;
use reth_payload_primitives::BuiltPayload;
use reth_provider::test_utils::MockEthProvider;

#[tokio::test(flavor = "multi_thread")]
async fn emits_the_built_bal_of_a_block_downloaded_without_a_sidecar() -> eyre::Result<()> {
    let buffer = init_tracer_with_buffer(1, Some(0), Some(0), Some(0));
    let chain_spec = test_chain_spec(EthereumHardfork::Amsterdam);

    let (mut node, wallet) = EthereumNode::test_setup(1, chain_spec.clone()).build_single().await?;

    // Build a valid Amsterdam block without submitting it to the engine.
    let raw_tx = TransactionTestContext::transfer_tx_bytes(1, wallet.inner).await;
    node.rpc.inject_tx(raw_tx).await?;
    let payload = node.new_payload().await?;
    let bal = payload.block_access_list().cloned().expect("an Amsterdam payload has a BAL");
    let block = payload.block().clone();
    let block_number = block.header().number;
    let block_hash = block.hash();
    let bal_hash = block.header().block_access_list_hash.expect("an Amsterdam header has one");
    let genesis_hash = node.block_hash(0);

    // The peer serves the block but not its BAL, so the node downloads it without a sidecar.
    let peer_provider = Arc::new(
        MockEthProvider::<EthPrimitives>::new()
            .with_chain_spec((*chain_spec).clone())
            .with_genesis_block(),
    );
    peer_provider.add_block(block_hash, block.into_block());

    let testnet = Testnet::create_with(1, peer_provider).await.with_request_handlers().spawn();
    let [peer] = testnet.peers_array();

    node.inner.network.add_peer(*peer.peer_id(), peer.local_addr());
    assert_eq!(node.network.next_session_established().await, Some(*peer.peer_id()));

    let mut engine_events = node.inner.add_ons_handle.consensus_engine_events().new_listener();
    let state = ForkchoiceState {
        head_block_hash: block_hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };
    let response =
        node.inner.add_ons_handle.beacon_engine_handle.fork_choice_updated(state, None).await?;
    assert_eq!(response.payload_status.status, PayloadStatusEnum::Syncing);

    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(event) = engine_events.next().await {
            match event {
                ConsensusEngineEvent::CanonicalBlockAdded(block, _)
                    if block.recovered_block().hash() == block_hash =>
                {
                    return
                }
                ConsensusEngineEvent::InvalidBlock { block, error }
                    if block.hash() == block_hash =>
                {
                    panic!("downloaded block is invalid: {error}")
                }
                _ => {}
            }
        }
        panic!("consensus engine event stream ended")
    })
    .await?;

    let emitted = parse_fire_block_for(&buffer.get_bytes(), block_number)?;
    assert_eq!(emitted.hash, block_hash.to_vec(), "emitted another block");
    let header = emitted.header.as_ref().expect("emitted block has a header");
    let bal_rlp = header.block_access_list_rlp.as_deref().expect("emitted no BAL RLP");
    assert_eq!(bal_rlp, bal.as_ref(), "emitted another BAL");
    assert_eq!(keccak256(bal_rlp), bal_hash, "BAL RLP does not hash to the header's");

    Ok(())
}
