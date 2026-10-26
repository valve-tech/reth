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
//! Each test launches a real `PulsechainNode` on the real 369 or 943 hardfork
//! schedule. The genesis sits above the `PrimordialPulse` block and after
//! PulseChain's Shanghai, so every PulseChain override runs in its post-fork
//! branch, as it does at the live head. The built block is then checked
//! against `PulsechainConsensus` directly and re-imported through
//! `newPayloadV2`, which re-executes it and checks the state root.
//!
//! The network component is the plain Ethereum one, so the test never dials
//! the real PulseChain bootnodes. The network takes no part in building or
//! validating a block.

use std::{sync::Arc, time::Duration};

use alloy_consensus::{proofs::calculate_withdrawals_root, BlockHeader};
use alloy_eips::{eip1559::calculate_block_gas_limit, eip4895::Withdrawal};
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{address, b256, Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayload, ExecutionPayloadFieldV2, ExecutionPayloadInputV2, ForkchoiceState,
    PayloadAttributes, PayloadStatusEnum,
};
use alloy_rpc_types_eth::TransactionRequest;
use jsonrpsee_core::{client::ClientT, rpc_params};
use reth_chainspec::{make_genesis_header, Chain, ChainSpec, EthChainSpec};
use reth_consensus::{Consensus, HeaderValidator};
use reth_e2e_test_utils::{transaction::TransactionTestContext, wallet::Wallet};
use reth_ethereum_primitives::{Block, TransactionSigned};
use reth_node_builder::{NodeBuilder, NodeHandle};
use reth_node_core::{
    args::PayloadBuilderArgs, cli::config::PayloadBuilderConfig, node_config::NodeConfig,
    version::default_extra_data_bytes,
};
use reth_node_ethereum::{EthEngineTypes, EthereumAddOns, EthereumNetworkBuilder};
use reth_primitives_traits::{Block as _, SealedHeader};
use reth_provider::{BlockNumReader, StateProviderFactory};
use reth_pulsechain_forks::chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4};
use reth_pulsechain_node::{
    consensus::PulsechainConsensus, spec::PulsechainChainSpec, PulsechainNode,
};
use reth_rpc_api::EngineApiClient;
use reth_tasks::Runtime;

/// One PLS in wei.
const PLS: u128 = 1_000_000_000_000_000_000;

/// One gwei in wei. Consensus-layer withdrawal amounts are in gwei.
const GWEI: u128 = 1_000_000_000;

/// The live 369 base fee on 2026-10-26 (block 27,897,284), in wei.
const PULSECHAIN_BASE_FEE: u64 = 352_156_972_705_304;

/// The block every built block extends. It is above both `PrimordialPulse`
/// blocks (17,233,000 and 16,492,700), so the executor takes its post-fork path.
const PARENT_NUMBER: u64 = 27_900_000;

/// A parent timestamp after both PulseChain Shanghai activations.
const PARENT_TIMESTAMP: u64 = 1_761_000_000;

/// PulseChain's slot length, from the live beacon spec.
const SECONDS_PER_SLOT: u64 = 10;

/// The fee recipient the validator client would set.
const FEE_RECIPIENT: Address = address!("0x000000000000000000000000000000000000fee5");

/// Two withdrawal addresses. The first gets two withdrawals in one block.
const WITHDRAWAL_A: Address = address!("0x00000000000000000000000000000000000a0a0a");
const WITHDRAWAL_B: Address = address!("0x00000000000000000000000000000000000b0b0b");

/// Extra data the test proposer stamps into its blocks.
const EXTRA_DATA: &[u8] = b"valve/block-production-test";

/// The recipient of the test transfer.
const TRANSFER_TO: Address = address!("0x0000000000000000000000000000000000c0ffee");

/// Builds a PulseChain chain spec whose genesis is a post-fork, post-Shanghai
/// block, on the real hardfork schedule of `base` (369 or 943).
///
/// `make_genesis_header` decides the base fee from London's activation at
/// block 0. On the real PulseChain schedule London starts at 12,965,000, so
/// the header it returns has no base fee. A block at 27,900,000 must carry one,
/// so the base fee is set on the header by hand.
fn pulse_spec(base: &ChainSpec, gas_limit: u64, funded: Address) -> Arc<PulsechainChainSpec> {
    let genesis = Genesis {
        number: Some(PARENT_NUMBER),
        parent_hash: Some(b256!(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        )),
        timestamp: PARENT_TIMESTAMP,
        gas_limit,
        base_fee_per_gas: Some(PULSECHAIN_BASE_FEE as u128),
        difficulty: U256::ZERO,
        alloc: [(funded, GenesisAccount::default().with_balance(U256::from(1_000_000_000 * PLS)))]
            .into(),
        config: base.genesis.config.clone(),
        ..Default::default()
    };

    let mut header = make_genesis_header(&genesis, &base.hardforks);
    header.base_fee_per_gas = Some(PULSECHAIN_BASE_FEE);

    let spec =
        ChainSpec { genesis, genesis_header: SealedHeader::seal_slow(header), ..base.clone() };
    Arc::new(PulsechainChainSpec::new(Arc::new(spec)))
}

/// Withdrawals as the beacon node sends them, in gwei.
///
/// The first is a full 32,000,000 PLS validator exit, `MAX_EFFECTIVE_BALANCE`
/// on PulseChain. A second withdrawal to the same address checks that two
/// credits to one address both land.
fn withdrawals() -> Vec<Withdrawal> {
    vec![
        Withdrawal {
            index: 1_000,
            validator_index: 7,
            address: WITHDRAWAL_A,
            amount: 32_000_000 * 1_000_000_000,
        },
        Withdrawal { index: 1_001, validator_index: 8, address: WITHDRAWAL_A, amount: 12_345_678 },
        Withdrawal { index: 1_002, validator_index: 9, address: WITHDRAWAL_B, amount: 1 },
    ]
}

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
    let signer = Wallet::new(1).with_chain_id(chain_id).wallet_gen().remove(0);
    let sender = signer.address();
    let chain_spec = pulse_spec(base, parent_gas_limit, sender);
    let consensus = PulsechainConsensus::new(chain_spec.clone());

    let mut config = NodeConfig::new(chain_spec.clone()).with_unused_ports();
    config.network.discovery.disable_discovery = true;
    config.rpc = config.rpc.with_http();
    // reth's default cap is 1 PLS, which rejects every ordinary PulseChain
    // transaction submitted over RPC. The fleet runs 1,000,000.
    config.rpc.rpc_tx_fee_cap = 1_000_000 * PLS;
    config.builder.extra_data = Bytes::from_static(EXTRA_DATA);
    config.builder.gas_limit = builder_gas_limit;

    let NodeHandle { node, node_exit_future: _exit } = NodeBuilder::new(config)
        .testing_node(Runtime::test())
        .with_types::<PulsechainNode>()
        .with_components(PulsechainNode::components().network(EthereumNetworkBuilder::default()))
        .with_add_ons(EthereumAddOns::default())
        .launch()
        .await?;

    let genesis_hash = chain_spec.genesis_hash();
    let engine = node.auth_server_handle().http_client();
    let rpc = node.rpc_server_handle().http_client().expect("http rpc is enabled");

    // A transfer signed for this chain id. The tip is what lands with the fee
    // recipient; the base fee is burned.
    let tip: u128 = 2 * GWEI;
    let transfer = TransactionRequest {
        from: Some(sender),
        to: Some(TxKind::Call(TRANSFER_TO)),
        value: Some(U256::from(PLS)),
        nonce: Some(0),
        gas: Some(21_000),
        max_fee_per_gas: Some(2 * PULSECHAIN_BASE_FEE as u128),
        max_priority_fee_per_gas: Some(tip),
        chain_id: Some(chain_id),
        ..Default::default()
    };
    let raw = TransactionTestContext::sign_tx_bytes(signer, transfer).await;
    let tx_hash: B256 = rpc.request("eth_sendRawTransaction", rpc_params![raw]).await?;

    let head = ForkchoiceState {
        head_block_hash: genesis_hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };
    let attributes = PayloadAttributes {
        timestamp: PARENT_TIMESTAMP + SECONDS_PER_SLOT,
        prev_randao: b256!("0x2222222222222222222222222222222222222222222222222222222222222222"),
        suggested_fee_recipient: FEE_RECIPIENT,
        withdrawals: Some(withdrawals()),
        parent_beacon_block_root: None,
        ..Default::default()
    };

    // --- the Engine API rejects the shapes a Shanghai-only chain must refuse ---

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

    // Lighthouse asks for the payload one prepare-lookahead later. One second
    // is enough for the first build, which starts at once on the FCU.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let envelope = EngineApiClient::<EthEngineTypes>::get_payload_v2(&engine, payload_id).await?;
    let elapsed = started.elapsed();
    eprintln!("chain {chain_id}: FCUv2 -> getPayloadV2 took {elapsed:?}");

    let ExecutionPayloadFieldV2::V2(payload) = envelope.execution_payload.clone() else {
        panic!("a post-Shanghai payload must be the V2 variant, with withdrawals");
    };
    let inner = &payload.payload_inner;

    assert_eq!(inner.parent_hash, genesis_hash);
    assert_eq!(inner.block_number, PARENT_NUMBER + 1);
    assert_eq!(inner.timestamp, PARENT_TIMESTAMP + SECONDS_PER_SLOT);
    assert_eq!(inner.fee_recipient, FEE_RECIPIENT, "fee recipient comes from the attributes");
    assert_eq!(
        inner.prev_randao,
        b256!("0x2222222222222222222222222222222222222222222222222222222222222222")
    );
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

    // The base fee of a full parent-gas-limit-targeted block follows EIP-1559.
    let parent_header = chain_spec.genesis_header();
    let expected_base_fee =
        chain_spec.next_block_base_fee(parent_header, inner.timestamp).expect("london is active");
    assert_eq!(inner.base_fee_per_gas, U256::from(expected_base_fee));

    // The block value is the tip on the transfer.
    let effective_tip = tip.min(2 * PULSECHAIN_BASE_FEE as u128 - expected_base_fee as u128);
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
    assert_eq!(header.nonce, alloy_primitives::B64::ZERO);
    assert_eq!(header.ommers_hash, alloy_consensus::EMPTY_OMMER_ROOT_HASH);
    assert_eq!(header.number(), PARENT_NUMBER + 1);

    let sealed = block.clone().seal_slow();
    assert_eq!(sealed.hash(), inner.block_hash, "the payload's block hash matches its contents");

    // PulseChain consensus, called directly.
    let parent = SealedHeader::seal_slow(chain_spec.genesis_header().clone());
    HeaderValidator::validate_header(&consensus, sealed.sealed_header())?;
    HeaderValidator::validate_header_against_parent(&consensus, sealed.sealed_header(), &parent)?;
    Consensus::<Block>::validate_block_pre_execution(&consensus, &sealed)?;

    // --- import our own block, as the beacon node does after signing it ---

    let status = EngineApiClient::<EthEngineTypes>::new_payload_v2(
        &engine,
        ExecutionPayloadInputV2 {
            execution_payload: payload.payload_inner.clone(),
            withdrawals: Some(payload.withdrawals.clone()),
        },
    )
    .await?;
    assert_eq!(
        status.status,
        PayloadStatusEnum::Valid,
        "newPayloadV2 re-executes the block and checks its state root"
    );

    let new_head = ForkchoiceState {
        head_block_hash: inner.block_hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };
    let updated =
        EngineApiClient::<EthEngineTypes>::fork_choice_updated_v2(&engine, new_head, None).await?;
    assert_eq!(updated.payload_status.status, PayloadStatusEnum::Valid);

    // Wait for the canonical head to move. The forkchoice update returns
    // before the in-memory canonical state is published.
    let mut tries = 0;
    while node.provider.best_block_number()? != PARENT_NUMBER + 1 {
        tries += 1;
        assert!(tries < 50, "the built block never became canonical");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // --- the state the block produced ---

    let state = node.provider.latest()?;
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
    assert_eq!(state.account_nonce(&sender)?, Some(1));

    let receipt: serde_json::Value =
        rpc.request("eth_getTransactionReceipt", rpc_params![tx_hash]).await?;
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
