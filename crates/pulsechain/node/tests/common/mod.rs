//! Shared setup for the PulseChain block-production tests.
//!
//! Each test binary that includes this module launches real `PulsechainNode`s
//! on the real 369 or 943 hardfork schedule. The genesis sits above the
//! `PrimordialPulse` block and after PulseChain's Shanghai, so every PulseChain
//! override runs in its post-fork branch, as it does at the live head.
//!
//! The network component is the plain Ethereum one, so a test never dials the
//! real PulseChain bootnodes. The network takes no part in building or
//! validating a block.

#![allow(dead_code, unreachable_pub)]

use std::sync::Arc;

use alloy_eips::eip4895::Withdrawal;
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{address, b256, Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadAttributes};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use reth_chainspec::{make_genesis_header, ChainSpec};
use reth_e2e_test_utils::{transaction::TransactionTestContext, wallet::Wallet};
use reth_node_core::node_config::NodeConfig;
use reth_primitives_traits::SealedHeader;
use reth_pulsechain_node::spec::PulsechainChainSpec;

/// One PLS in wei.
pub const PLS: u128 = 1_000_000_000_000_000_000;

/// One gwei in wei. Consensus-layer withdrawal amounts are in gwei.
pub const GWEI: u128 = 1_000_000_000;

/// The live 369 base fee on 2026-10-26 (block 27,897,284), in wei.
pub const PULSECHAIN_BASE_FEE: u64 = 352_156_972_705_304;

/// The block every built block extends. It is above both `PrimordialPulse`
/// blocks (17,233,000 and 16,492,700), so the executor takes its post-fork path.
pub const PARENT_NUMBER: u64 = 27_900_000;

/// A parent timestamp after both PulseChain Shanghai activations.
pub const PARENT_TIMESTAMP: u64 = 1_761_000_000;

/// PulseChain's slot length, from the live beacon spec.
pub const SECONDS_PER_SLOT: u64 = 10;

/// The prevRandao the beacon node sends.
pub const PREV_RANDAO: B256 =
    b256!("0x2222222222222222222222222222222222222222222222222222222222222222");

/// The fee recipient the validator client would set.
pub const FEE_RECIPIENT: Address = address!("0x000000000000000000000000000000000000fee5");

/// Two withdrawal addresses. The first gets two withdrawals in one block.
pub const WITHDRAWAL_A: Address = address!("0x00000000000000000000000000000000000a0a0a");
pub const WITHDRAWAL_B: Address = address!("0x00000000000000000000000000000000000b0b0b");

/// Extra data the test proposer stamps into its blocks.
pub const EXTRA_DATA: &[u8] = b"valve/block-production-test";

/// The recipient of the test transfer.
pub const TRANSFER_TO: Address = address!("0x0000000000000000000000000000000000c0ffee");

/// The priority fee on the test transfer.
pub const TIP: u128 = 2 * GWEI;

/// The test sender for `chain_id`. Its address is funded in the genesis.
pub fn sender(chain_id: u64) -> PrivateKeySigner {
    Wallet::new(1).with_chain_id(chain_id).wallet_gen().remove(0)
}

/// Builds a PulseChain chain spec whose genesis is a post-fork, post-Shanghai
/// block, on the real hardfork schedule of `base` (369 or 943).
///
/// `make_genesis_header` decides the base fee from London's activation at
/// block 0. On the real PulseChain schedule London starts at 12,965,000, so
/// the header it returns has no base fee. A block at 27,900,000 must carry one,
/// so the base fee is set on the header by hand.
pub fn pulse_spec(base: &ChainSpec, gas_limit: u64, funded: Address) -> Arc<PulsechainChainSpec> {
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

/// A node config shaped like a fleet node, with every port unused.
///
/// `builder_gas_limit` is what `--builder.gaslimit` would be set to. `None`
/// keeps the PulseChain default.
pub fn node_config(
    chain_spec: Arc<PulsechainChainSpec>,
    builder_gas_limit: Option<u64>,
) -> NodeConfig<PulsechainChainSpec> {
    let mut config = NodeConfig::new(chain_spec).with_unused_ports();
    config.network.discovery.disable_discovery = true;
    config.rpc = config.rpc.with_http();
    // reth's default cap is 1 PLS, which rejects every ordinary PulseChain
    // transaction submitted over RPC. The fleet runs 1,000,000.
    config.rpc.rpc_tx_fee_cap = 1_000_000 * PLS;
    config.builder.extra_data = Bytes::from_static(EXTRA_DATA);
    config.builder.gas_limit = builder_gas_limit;
    config
}

/// Launches a `PulsechainNode` from a [`NodeConfig`], with the components the
/// fleet binary uses except the network. Evaluates to the `NodeHandle`.
macro_rules! launch_node {
    ($config:expr) => {
        reth_node_builder::NodeBuilder::new($config)
            .testing_node(reth_tasks::Runtime::test())
            .with_types::<reth_pulsechain_node::PulsechainNode>()
            .with_components(
                reth_pulsechain_node::PulsechainNode::components()
                    .network(reth_node_ethereum::EthereumNetworkBuilder::default()),
            )
            .with_add_ons(reth_node_ethereum::EthereumAddOns::default())
            .launch()
            .await?
    };
}
pub(crate) use launch_node;

/// A transfer of 1 PLS signed for `chain_id`, paying [`TIP`] over the base fee.
pub async fn signed_transfer(chain_id: u64) -> Bytes {
    let signer = sender(chain_id);
    let transfer = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(TRANSFER_TO)),
        value: Some(U256::from(PLS)),
        nonce: Some(0),
        gas: Some(21_000),
        max_fee_per_gas: Some(2 * PULSECHAIN_BASE_FEE as u128),
        max_priority_fee_per_gas: Some(TIP),
        chain_id: Some(chain_id),
        ..Default::default()
    };
    TransactionTestContext::sign_tx_bytes(signer, transfer).await
}

/// Withdrawals as the beacon node sends them, in gwei.
///
/// The first is a full 32,000,000 PLS validator exit, `MAX_EFFECTIVE_BALANCE`
/// on PulseChain. A second withdrawal to the same address checks that two
/// credits to one address both land.
pub fn withdrawals() -> Vec<Withdrawal> {
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

/// The payload attributes Lighthouse sends on a Capella chain: withdrawals,
/// a fee recipient, and no parent beacon block root.
pub fn attributes() -> PayloadAttributes {
    PayloadAttributes {
        timestamp: PARENT_TIMESTAMP + SECONDS_PER_SLOT,
        prev_randao: PREV_RANDAO,
        suggested_fee_recipient: FEE_RECIPIENT,
        withdrawals: Some(withdrawals()),
        parent_beacon_block_root: None,
        ..Default::default()
    }
}

/// A forkchoice state with every field at `hash`.
pub const fn forkchoice_at(hash: B256) -> ForkchoiceState {
    ForkchoiceState { head_block_hash: hash, safe_block_hash: hash, finalized_block_hash: hash }
}
