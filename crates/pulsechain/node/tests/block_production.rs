//! PulseChain block production through the Engine API, end to end.
//!
//! Our fleet has only ever followed PulseChain. These tests run the proposer
//! path a Lighthouse beacon node drives on a Capella (Shanghai) chain:
//!
//! 1. `engine_forkchoiceUpdatedV2` with payload attributes (withdrawals, fee recipient, no parent
//!    beacon block root).
//! 2. `engine_getPayloadV2`.
//! 3. `engine_newPayloadV2` with the built payload, then a forkchoice update onto it.
//!
//! Each test also starts a second node, a follower with the same genesis, and
//! imports the payload there. The follower has never seen the block, so it
//! executes it in full and checks the state root and receipts, as every
//! PulseChain peer would. The built block is also checked against
//! `PulsechainConsensus` directly.

mod common;

use std::time::Duration;

use alloy_consensus::{proofs::calculate_withdrawals_root, BlockHeader};
use alloy_eips::eip1559::calculate_block_gas_limit;
use alloy_primitives::{Address, Bytes, B256, B64, U256};
use alloy_rpc_types_engine::{
    ExecutionPayload, ExecutionPayloadFieldV2, ExecutionPayloadInputV2, ForkchoiceState,
    PayloadAttributes, PayloadStatusEnum,
};
use common::*;
use jsonrpsee_core::{client::ClientT, rpc_params};
use reth_chainspec::{Chain, ChainSpec, EthChainSpec};
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_primitives::{Block, TransactionSigned};
use reth_node_builder::NodeHandle;
use reth_node_core::{
    args::PayloadBuilderArgs, cli::config::PayloadBuilderConfig, version::default_extra_data_bytes,
};
use reth_node_ethereum::EthEngineTypes;
use reth_primitives_traits::{Block as _, SealedHeader};
use reth_provider::{BlockNumReader, BlockReaderIdExt, StateProviderFactory};
use reth_pulsechain_forks::chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4};
use reth_pulsechain_node::consensus::PulsechainConsensus;
use reth_rpc_api::EngineApiClient;

/// What one proposal run returns for the per-chain assertions.
struct Proposal {
    gas_limit: u64,
    extra_data: Bytes,
}

/// Runs one full proposal on `base`'s schedule and checks it.
///
/// `builder_gas_limit` is what `--builder.gaslimit` would be set to. `None`
/// keeps reth's default.
async fn propose_one_block(
    base: &ChainSpec,
    parent_gas_limit: u64,
    builder_gas_limit: Option<u64>,
) -> eyre::Result<Proposal> {
    reth_tracing::init_test_tracing();

    let chain_id = base.chain().id();
    let sender_address = sender(chain_id).address();
    let chain_spec = pulse_spec(base, parent_gas_limit, sender_address);
    let consensus = PulsechainConsensus::new(chain_spec.clone());
    let genesis_hash = chain_spec.genesis_hash();

    let NodeHandle { node: proposer, node_exit_future: _proposer_exit } =
        launch_node!(node_config(chain_spec.clone(), builder_gas_limit));
    let NodeHandle { node: follower, node_exit_future: _follower_exit } =
        launch_node!(node_config(chain_spec.clone(), builder_gas_limit));

    let engine = proposer.auth_server_handle().http_client();
    let follower_engine = follower.auth_server_handle().http_client();
    let rpc = proposer.rpc_server_handle().http_client().expect("http rpc is enabled");
    let follower_rpc = follower.rpc_server_handle().http_client().expect("http rpc is enabled");

    let raw = signed_transfer(chain_id).await;
    let tx_hash: B256 = rpc.request("eth_sendRawTransaction", rpc_params![raw]).await?;

    let head = forkchoice_at(genesis_hash);
    let attributes = attributes();

    // --- the Engine API refuses the shapes a Shanghai-only chain must refuse ---

    // A V2 forkchoice update on a Shanghai chain must carry withdrawals.
    let no_withdrawals = PayloadAttributes { withdrawals: None, ..attributes.clone() };
    assert!(
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(
            &engine,
            head,
            Some(no_withdrawals)
        )
        .await
        .is_err(),
        "FCUv2 without withdrawals must be rejected after Shanghai"
    );

    // A parent beacon block root is a Cancun field.
    let with_beacon_root =
        PayloadAttributes { parent_beacon_block_root: Some(B256::ZERO), ..attributes.clone() };
    assert!(
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(
            &engine,
            head,
            Some(with_beacon_root.clone())
        )
        .await
        .is_err(),
        "FCUv2 with a parent beacon block root must be rejected without Cancun"
    );

    // V3 is the Cancun method, and Cancun is not scheduled.
    assert!(
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v3(
            &engine,
            head,
            Some(with_beacon_root)
        )
        .await
        .is_err(),
        "FCUv3 must be rejected: cancun_time is None"
    );

    // --- the proposer path ---

    let started = std::time::Instant::now();
    let updated =
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(&engine, head, Some(attributes))
            .await?;
    assert_eq!(updated.payload_status.status, PayloadStatusEnum::Valid);
    let payload_id = updated.payload_id.expect("FCUv2 with attributes must start a build");

    // getPayloadV3 is the Cancun method, so it must refuse this payload.
    assert!(
        EngineApiClient::<EthEngineTypes>::get_payload_v3(&engine, payload_id).await.is_err(),
        "getPayloadV3 must be rejected: cancun_time is None"
    );

    // Lighthouse asks for the payload about a third of a slot after the FCU.
    // One second is enough for the first build, which starts at once.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let envelope = EngineApiClient::<EthEngineTypes>::get_payload_v2(&engine, payload_id).await?;
    eprintln!("chain {chain_id}: FCUv2 -> getPayloadV2 took {:?}", started.elapsed());

    let ExecutionPayloadFieldV2::V2(payload) = envelope.execution_payload.clone() else {
        panic!("a post-Shanghai payload must be the V2 variant, with withdrawals");
    };
    let inner = &payload.payload_inner;

    assert_eq!(inner.parent_hash, genesis_hash);
    assert_eq!(inner.block_number, PARENT_NUMBER + 1);
    assert_eq!(inner.timestamp, PARENT_TIMESTAMP + SECONDS_PER_SLOT);
    assert_eq!(inner.fee_recipient, FEE_RECIPIENT, "fee recipient comes from the attributes");
    assert_eq!(inner.prev_randao, PREV_RANDAO);
    assert_eq!(inner.extra_data.as_ref(), EXTRA_DATA, "extraData comes from --builder.extradata");
    assert_eq!(payload.withdrawals, withdrawals(), "withdrawals are included in order");
    assert_eq!(inner.transactions.len(), 1, "the pending transfer is included");

    let expected_gas_limit = calculate_block_gas_limit(
        parent_gas_limit,
        builder_gas_limit.unwrap_or_else(|| {
            PayloadBuilderArgs::default().gas_limit_for(Chain::from_id(chain_id))
        }),
    );
    assert_eq!(inner.gas_limit, expected_gas_limit);
    assert_eq!(inner.gas_used, 21_000);

    // EIP-1559 base fee from the parent. The follower import below checks the
    // same rule independently.
    let expected_base_fee = chain_spec
        .next_block_base_fee(chain_spec.genesis_header(), inner.timestamp)
        .expect("london is active");
    assert_eq!(inner.base_fee_per_gas, U256::from(expected_base_fee));

    // The block value is the tip on the transfer.
    let effective_tip = TIP.min(2 * PULSECHAIN_BASE_FEE as u128 - expected_base_fee as u128);
    assert_eq!(envelope.block_value, U256::from(effective_tip * 21_000));

    // --- the block, as a PulseChain header ---

    let block: Block =
        ExecutionPayload::V2(payload.clone()).try_into_block::<TransactionSigned>()?;
    let header = &block.header;
    assert_eq!(header.withdrawals_root, Some(calculate_withdrawals_root(&withdrawals())));
    assert_eq!(header.parent_beacon_block_root, None, "no Cancun field");
    assert_eq!(header.blob_gas_used, None, "no Cancun field");
    assert_eq!(header.excess_blob_gas, None, "no Cancun field");
    assert_eq!(header.requests_hash, None, "no Prague field");
    assert_eq!(header.difficulty, U256::ZERO);
    assert_eq!(header.nonce, B64::ZERO);
    assert_eq!(header.ommers_hash, alloy_consensus::EMPTY_OMMER_ROOT_HASH);
    assert_eq!(header.number(), PARENT_NUMBER + 1);

    let sealed = block.clone().seal_slow();
    assert_eq!(sealed.hash(), inner.block_hash, "the payload's block hash matches its contents");

    // PulseChain consensus, called directly.
    let parent = SealedHeader::seal_slow(chain_spec.genesis_header().clone());
    HeaderValidator::validate_header(&consensus, sealed.sealed_header())?;
    HeaderValidator::validate_header_against_parent(&consensus, sealed.sealed_header(), &parent)?;
    Consensus::<Block>::validate_block_pre_execution(&consensus, &sealed)?;

    // --- import on both nodes, as the beacon nodes do after the proposal ---

    let input = ExecutionPayloadInputV2 {
        execution_payload: payload.payload_inner.clone(),
        withdrawals: Some(payload.withdrawals.clone()),
    };
    let new_head = ForkchoiceState {
        head_block_hash: inner.block_hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };

    // The follower executes the block from scratch: PulseChain executor,
    // PulsechainConsensus, receipts root and state root.
    let status =
        EngineApiClient::<EthEngineTypes>::new_payload_v2(&follower_engine, input.clone()).await?;
    assert_eq!(status.status, PayloadStatusEnum::Valid, "a follower accepts our block");
    let updated =
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(&follower_engine, new_head, None)
            .await?;
    assert_eq!(updated.payload_status.status, PayloadStatusEnum::Valid);

    // The proposer re-executes its own block here too. `EthBuiltPayload`
    // carries no executed block, so reth never takes the `InsertExecutedBlock`
    // shortcut for it (see block_production_firehose.rs).
    let status = EngineApiClient::<EthEngineTypes>::new_payload_v2(&engine, input).await?;
    assert_eq!(status.status, PayloadStatusEnum::Valid);
    let updated =
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(&engine, new_head, None).await?;
    assert_eq!(updated.payload_status.status, PayloadStatusEnum::Valid);

    // Wait for both canonical heads to move. The forkchoice update returns
    // before the in-memory canonical state is published.
    for node_provider in [&proposer.provider, &follower.provider] {
        let mut tries = 0;
        while node_provider.best_block_number()? != PARENT_NUMBER + 1 {
            tries += 1;
            assert!(tries < 50, "the built block never became canonical");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // --- the state the block produced, as the follower computed it ---

    let state = follower.provider.latest()?;
    let balance = |address: Address| -> eyre::Result<U256> {
        Ok(state.account_balance(&address)?.unwrap_or_default())
    };

    // Withdrawal amounts are gwei; the EVM credits wei.
    assert_eq!(
        balance(WITHDRAWAL_A)?,
        U256::from((32_000_000u128 * 1_000_000_000 + 12_345_678) * GWEI),
        "both withdrawals to one address are credited"
    );
    assert_eq!(balance(WITHDRAWAL_B)?, U256::from(GWEI));
    assert_eq!(balance(TRANSFER_TO)?, U256::from(PLS));
    assert_eq!(balance(FEE_RECIPIENT)?, envelope.block_value, "the fee recipient gets the tips");
    assert_eq!(state.account_nonce(&sender_address)?, Some(1));

    // Both nodes agree on the state root.
    assert_eq!(
        proposer.provider.latest_header()?.expect("head").state_root(),
        follower.provider.latest_header()?.expect("head").state_root(),
    );

    let receipt: serde_json::Value =
        follower_rpc.request("eth_getTransactionReceipt", rpc_params![tx_hash]).await?;
    assert_eq!(receipt["status"], "0x1");

    Ok(Proposal { gas_limit: inner.gas_limit, extra_data: inner.extra_data.clone() })
}

/// Chain 369 with `--builder.gaslimit 45000000`, the live target.
#[tokio::test(flavor = "multi_thread")]
async fn pulsechain_369_builds_and_imports_a_block() -> eyre::Result<()> {
    let proposal = propose_one_block(&PULSECHAIN, 45_000_000, Some(45_000_000)).await?;
    assert_eq!(proposal.gas_limit, 45_000_000, "the gas limit holds at the network target");
    assert_eq!(proposal.extra_data.as_ref(), EXTRA_DATA);
    Ok(())
}

/// Chain 943 with `--builder.gaslimit 30000000`, the live target.
#[tokio::test(flavor = "multi_thread")]
async fn pulsechain_943_builds_and_imports_a_block() -> eyre::Result<()> {
    let proposal = propose_one_block(&PULSECHAIN_TESTNET_V4, 30_000_000, Some(30_000_000)).await?;
    assert_eq!(proposal.gas_limit, 30_000_000, "the gas limit holds at the network target");
    Ok(())
}

/// Chain 369 with no `--builder.gaslimit`, as the fleet runs today.
///
/// reth's default target for a chain it does not name is 36M. The live 369
/// target is 45M, so every block we propose without the flag votes the gas
/// limit DOWN by parent/1024. The block is still valid; the vote is the
/// problem.
#[tokio::test(flavor = "multi_thread")]
async fn pulsechain_369_without_builder_gaslimit_votes_the_limit_down() -> eyre::Result<()> {
    let proposal = propose_one_block(&PULSECHAIN, 45_000_000, None).await?;
    assert!(proposal.gas_limit < 45_000_000, "the default target pulls the limit down");
    assert_eq!(proposal.gas_limit, 45_000_000 - 45_000_000 / 1024 + 1);
    Ok(())
}

/// The default target reth applies when `--builder.gaslimit` is unset.
///
/// 369 and 943 are not in reth's 60M list, so both get 36M. Neither matches
/// the live chain: 369 runs at 45M and 943 at 30M.
#[test]
fn default_builder_gas_limit_matches_neither_pulsechain_network() {
    let args = PayloadBuilderArgs::default();
    assert_eq!(args.gas_limit_for(Chain::from_id(369)), 36_000_000);
    assert_eq!(args.gas_limit_for(Chain::from_id(943)), 36_000_000);
}

/// The default extraData (`reth/v<version>/<os>`) fits the 32-byte limit, so a
/// node that never sets `--builder.extradata` still builds valid headers.
#[test]
fn default_extra_data_fits_the_header_limit() {
    assert!(
        default_extra_data_bytes().len() <= alloy_consensus::constants::MAXIMUM_EXTRA_DATA_SIZE
    );
}
