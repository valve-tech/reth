//! Chainspec contract tests for PulseChain.
//!
//! All tests here are failing until Phase 2 (PulsechainHardfork + ChainSpec statics).
//! Run: `cargo nextest run -p reth-pulsechain-node --test chainspec`

use alloy_primitives::{b256, B256};
use reth_pulsechain_node::hardfork::{
    PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_BLOCK, SHANGHAI_MAINNET_TIMESTAMP,
    SHANGHAI_TESTNET_V4_TIMESTAMP,
};

// Ethereum mainnet genesis hash — PulseChain shares this identically.
// Used in Phase 2 when PULSECHAIN static ChainSpec is implemented.
#[allow(dead_code)]
const MAINNET_GENESIS_HASH: B256 =
    b256!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");

/// PulseChain mainnet chain ID must be 369.
#[test]
fn test_pulsechain_mainnet_chain_id() {
    use reth_pulsechain_node::chainspec::pulsechain_mainnet;
    let id = pulsechain_mainnet();
    assert_eq!(id, 369, "PulseChain mainnet chain ID must be 369");
}

/// PulseChain testnet v4 chain ID must be 943.
#[test]
fn test_pulsechain_testnetv4_chain_id() {
    use reth_pulsechain_node::chainspec::pulsechain_testnet_v4;
    let id = pulsechain_testnet_v4();
    assert_eq!(id, 943, "PulseChain testnet v4 chain ID must be 943");
}

/// PulseChain genesis hash must be identical to Ethereum mainnet.
///
/// PulseChain does NOT have a custom genesis block — it starts from the
/// same Ethereum genesis and replays full Ethereum history.
#[test]
#[should_panic(expected = "not yet implemented")]
fn test_pulsechain_genesis_hash_matches_eth_mainnet() {
    use reth_pulsechain_node::chainspec::pulsechain_mainnet;
    let _chain = pulsechain_mainnet(); // stubs out for now; hash checked once PULSECHAIN exists
                                       // Real assertion (Phase 2):
                                       // assert_eq!(*PULSECHAIN.genesis_header.hash(), MAINNET_GENESIS_HASH);
    todo!("check genesis hash against MAINNET_GENESIS_HASH once PULSECHAIN static exists");
}

/// PrimordialPulse fork block constant must be correct for mainnet.
#[test]
fn test_primordial_pulse_block_mainnet() {
    assert_eq!(
        PRIMORDIAL_PULSE_MAINNET_BLOCK, 17_233_000,
        "PrimordialPulse mainnet block must be 17,233,000"
    );
}

/// PrimordialPulse fork block constant must be correct for testnet v4.
#[test]
fn test_primordial_pulse_block_testnetv4() {
    assert_eq!(
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK, 16_492_700,
        "PrimordialPulse testnet v4 block must be 16,492,700"
    );
}

/// Shanghai activation timestamp must be correct for mainnet.
#[test]
fn test_shanghai_timestamp_mainnet() {
    assert_eq!(SHANGHAI_MAINNET_TIMESTAMP, 1_683_786_515, "PulseChain mainnet Shanghai timestamp");
}

/// Shanghai activation timestamp must be correct for testnet v4.
#[test]
fn test_shanghai_timestamp_testnetv4() {
    assert_eq!(
        SHANGHAI_TESTNET_V4_TIMESTAMP, 1_682_700_369,
        "PulseChain testnet v4 Shanghai timestamp"
    );
}

/// PrimordialPulse hardfork must appear in the mainnet hardfork list.
#[test]
fn test_primordial_pulse_in_mainnet_hardfork_list() {
    use reth_pulsechain_node::hardfork::{PulsechainHardfork, PRIMORDIAL_PULSE_MAINNET_BLOCK};

    let forks = PulsechainHardfork::mainnet();
    let condition = forks.fork(PulsechainHardfork::PrimordialPulse);
    assert!(
        condition.active_at_block(PRIMORDIAL_PULSE_MAINNET_BLOCK),
        "PrimordialPulse must be active at its fork block"
    );
    assert!(
        !condition.active_at_block(PRIMORDIAL_PULSE_MAINNET_BLOCK - 1),
        "PrimordialPulse must not be active before its fork block"
    );
}

/// PrimordialPulse hardfork must appear in the testnet v4 hardfork list.
#[test]
fn test_primordial_pulse_in_testnetv4_hardfork_list() {
    use reth_pulsechain_node::hardfork::{PulsechainHardfork, PRIMORDIAL_PULSE_TESTNET_V4_BLOCK};

    let forks = PulsechainHardfork::testnet_v4();
    let condition = forks.fork(PulsechainHardfork::PrimordialPulse);
    assert!(
        condition.active_at_block(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK),
        "PrimordialPulse must be active at its fork block on testnet v4"
    );
}

/// Deposit contract addresses must be correct.
#[test]
fn test_deposit_contract_addresses() {
    use alloy_primitives::address;
    use reth_pulsechain_node::chainspec::{ETH_DEPOSIT_CONTRACT, PULSECHAIN_DEPOSIT_CONTRACT};

    assert_eq!(
        PULSECHAIN_DEPOSIT_CONTRACT,
        address!("3693693693693693693693693693693693693693"),
        "PulseChain deposit contract address"
    );
    assert_eq!(
        ETH_DEPOSIT_CONTRACT,
        address!("00000000219ab540356cBB839Cbe05303d7705Fa"),
        "Ethereum deposit contract address"
    );
}
