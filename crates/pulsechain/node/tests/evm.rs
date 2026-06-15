//! EVM behavior contract tests for PulseChain.
//!
//! Covers CHAINID opcode behavior and the chain ID transition at PrimordialPulse.
//! All tests are failing until Phase 4 (CHAINID override in PulsechainEvmConfig).
//! Run: `cargo nextest run -p reth-pulsechain-node --test evm`

use reth_pulsechain_node::{
    chainspec::{chain_id_at_block_mainnet, chain_id_at_block_testnet_v4},
    hardfork::PRIMORDIAL_PULSE_MAINNET_BLOCK,
};

/// Before PrimordialPulse, CHAINID opcode must return 1 (Ethereum mainnet).
///
/// PulseChain replays Ethereum history, so smart contracts deployed before the
/// fork see chain ID 1. Existing Ethereum contracts designed for chain ID 1 work
/// correctly on PulseChain's pre-fork history.
#[test]
fn test_chain_id_opcode_before_fork_mainnet() {
    let block_before = PRIMORDIAL_PULSE_MAINNET_BLOCK - 1;
    let chain_id = chain_id_at_block_mainnet(block_before);
    assert_eq!(
        chain_id, 1,
        "CHAINID must return 1 before PrimordialPulse (Ethereum history replay)"
    );
}

/// At PrimordialPulse block, CHAINID opcode must return 369.
#[test]
fn test_chain_id_opcode_at_fork_mainnet() {
    let chain_id = chain_id_at_block_mainnet(PRIMORDIAL_PULSE_MAINNET_BLOCK);
    assert_eq!(chain_id, 369, "CHAINID must return 369 at PrimordialPulse block");
}

/// After PrimordialPulse, CHAINID opcode must return 369.
#[test]
fn test_chain_id_opcode_after_fork_mainnet() {
    let block_after = PRIMORDIAL_PULSE_MAINNET_BLOCK + 1;
    let chain_id = chain_id_at_block_mainnet(block_after);
    assert_eq!(chain_id, 369, "CHAINID must return 369 after PrimordialPulse");
}

/// Before PrimordialPulse on testnet v4, CHAINID must return 1.
#[test]
fn test_chain_id_opcode_before_fork_testnetv4() {
    use reth_pulsechain_node::hardfork::PRIMORDIAL_PULSE_TESTNET_V4_BLOCK;
    let chain_id = chain_id_at_block_testnet_v4(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK - 1);
    assert_eq!(chain_id, 1, "CHAINID must return 1 before PrimordialPulse on testnet v4");
}

/// After PrimordialPulse on testnet v4, CHAINID must return 943.
#[test]
fn test_chain_id_opcode_after_fork_testnetv4() {
    use reth_pulsechain_node::hardfork::PRIMORDIAL_PULSE_TESTNET_V4_BLOCK;
    let chain_id = chain_id_at_block_testnet_v4(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK);
    assert_eq!(chain_id, 943, "CHAINID must return 943 at/after PrimordialPulse on testnet v4");
}

/// CHAINID transition must be a hard boundary — block N-1 returns 1, block N returns 369.
///
/// There must be no gradual transition or intermediate state.
#[test]
fn test_chain_id_hard_boundary() {
    let last_eth_block = PRIMORDIAL_PULSE_MAINNET_BLOCK - 1;
    let first_pulse_block = PRIMORDIAL_PULSE_MAINNET_BLOCK;

    let eth_chain_id = chain_id_at_block_mainnet(last_eth_block);
    let pulse_chain_id = chain_id_at_block_mainnet(first_pulse_block);

    assert_eq!(eth_chain_id, 1, "Last Ethereum block must have chain ID 1");
    assert_eq!(pulse_chain_id, 369, "First PulseChain block must have chain ID 369");
    assert_ne!(eth_chain_id, pulse_chain_id, "Chain IDs must differ across the fork boundary");
}

/// Genesis block (block 0) chain ID must be 1 (Ethereum, pre-fork).
#[test]
fn test_chain_id_at_genesis() {
    let chain_id = chain_id_at_block_mainnet(0);
    assert_eq!(chain_id, 1, "Genesis block chain ID must be 1 (Ethereum)");
}
