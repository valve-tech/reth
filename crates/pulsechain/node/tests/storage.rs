//! How a `PulsechainNode` reads withdrawals back from its database.
//!
//! Blocks before `PrimordialPulse` are Ethereum blocks. Their withdrawals follow
//! Ethereum's Shanghai timestamp, not `PulseChain`'s. The node's body reader must
//! return them, or a block read back from disk loses its withdrawals.
//!
//! These tests call the reader of `<PulsechainNode as NodeTypes>::Storage`, so
//! they pin the rule wherever that type keeps it.

use std::sync::Arc;

use alloy_consensus::Header;
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::Address;
use reth_chainspec::{Chain, ChainSpec};
use reth_db_api::{models::StoredBlockWithdrawals, tables, transaction::DbTxMut};
use reth_node_builder::NodeTypes;
use reth_provider::{test_utils::create_test_provider_factory_with_node_types, BlockBodyReader};
use reth_pulsechain_forks::{
    chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4},
    hardfork::{
        ETH_MAINNET_SHANGHAI_TIMESTAMP, PRIMORDIAL_PULSE_MAINNET_BLOCK,
        PRIMORDIAL_PULSE_MAINNET_TIMESTAMP, PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        SHANGHAI_MAINNET_TIMESTAMP,
    },
};
use reth_pulsechain_node::{PulsechainChainSpec, PulsechainNode};

/// The withdrawal every test stores for its block.
fn stored() -> Withdrawals {
    Withdrawals::new(vec![Withdrawal {
        index: 7,
        validator_index: 11,
        address: Address::repeat_byte(0x42),
        amount: 1_000,
    }])
}

/// Stores withdrawals for block `number`, then reads the body of a header
/// with that number and `timestamp` back through the node's storage type.
fn read_withdrawals(spec: Arc<ChainSpec>, number: u64, timestamp: u64) -> Option<Withdrawals> {
    let spec = Arc::new(PulsechainChainSpec::new(spec));
    let factory = create_test_provider_factory_with_node_types::<PulsechainNode>(spec);

    let provider_rw = factory.provider_rw().unwrap();
    provider_rw
        .tx_ref()
        .put::<tables::BlockWithdrawals>(number, StoredBlockWithdrawals { withdrawals: stored() })
        .unwrap();
    provider_rw.commit().unwrap();

    let header = Header { number, timestamp, ..Default::default() };
    let provider = factory.provider().unwrap();
    let storage = <PulsechainNode as NodeTypes>::Storage::default();
    let mut bodies = storage.read_block_bodies(&provider, vec![(&header, Vec::new())]).unwrap();
    assert_eq!(bodies.len(), 1);
    bodies.pop().unwrap().withdrawals
}

/// A spec with `PulseChain` mainnet's forks under another chain ID.
fn with_chain_id(id: u64) -> Arc<ChainSpec> {
    let mut spec = (**PULSECHAIN).clone();
    spec.chain = Chain::from_id(id);
    Arc::new(spec)
}

/// A pre-fork block after Ethereum's Shanghai keeps its withdrawals.
#[test]
fn mainnet_pre_fork_block_in_the_shanghai_gap_keeps_withdrawals() {
    let got = read_withdrawals(
        PULSECHAIN.clone(),
        PRIMORDIAL_PULSE_MAINNET_BLOCK - 1,
        ETH_MAINNET_SHANGHAI_TIMESTAMP + 60,
    );
    assert_eq!(got, Some(stored()));
}

/// The block number marks a block as pre-fork, not its timestamp.
///
/// Both headers carry a timestamp that the chain spec's own rule calls
/// pre-Shanghai. The reader still applies Ethereum's rule, because the block
/// number is below `PrimordialPulse`.
#[test]
fn pre_fork_block_number_decides_not_timestamp() {
    let mainnet = read_withdrawals(
        PULSECHAIN.clone(),
        PRIMORDIAL_PULSE_MAINNET_BLOCK - 1,
        SHANGHAI_MAINNET_TIMESTAMP - 10,
    );
    assert_eq!(mainnet, Some(stored()), "369");

    let testnet = read_withdrawals(
        PULSECHAIN_TESTNET_V4.clone(),
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK - 1,
        ETH_MAINNET_SHANGHAI_TIMESTAMP + 60,
    );
    assert_eq!(testnet, Some(stored()), "943");
}

/// A pre-fork block before Ethereum's Shanghai has no withdrawals list.
#[test]
fn mainnet_pre_fork_block_before_ethereum_shanghai_has_none() {
    let got = read_withdrawals(
        PULSECHAIN.clone(),
        PRIMORDIAL_PULSE_MAINNET_BLOCK - 1,
        ETH_MAINNET_SHANGHAI_TIMESTAMP - 1,
    );
    assert_eq!(got, None);
}

/// After the fork, `PulseChain`'s own Shanghai timestamp decides.
#[test]
fn mainnet_post_fork_block_follows_pulsechain_shanghai() {
    let before = read_withdrawals(
        PULSECHAIN.clone(),
        PRIMORDIAL_PULSE_MAINNET_BLOCK + 1,
        PRIMORDIAL_PULSE_MAINNET_TIMESTAMP + 20,
    );
    assert_eq!(before, None, "post-fork, pre-PulseChain-Shanghai");

    let after = read_withdrawals(
        PULSECHAIN.clone(),
        PRIMORDIAL_PULSE_MAINNET_BLOCK + 1,
        SHANGHAI_MAINNET_TIMESTAMP,
    );
    assert_eq!(after, Some(stored()), "post-fork, at PulseChain Shanghai");
}

/// Chain 32382 keeps the legacy entry from the first port: blocks below 10
/// follow Ethereum's Shanghai.
#[test]
fn legacy_devnet_chain_keeps_its_fork_block() {
    let spec = with_chain_id(32_382);
    assert_eq!(
        read_withdrawals(spec.clone(), 9, ETH_MAINNET_SHANGHAI_TIMESTAMP + 60),
        Some(stored())
    );
    assert_eq!(read_withdrawals(spec, 10, ETH_MAINNET_SHANGHAI_TIMESTAMP + 60), None);
}

/// A chain ID that no `PulseChain` network claims gets the chain spec's rule.
#[test]
fn unknown_chain_uses_the_chain_spec_rule() {
    let got = read_withdrawals(with_chain_id(12_345), 9, ETH_MAINNET_SHANGHAI_TIMESTAMP + 60);
    assert_eq!(got, None);
}
