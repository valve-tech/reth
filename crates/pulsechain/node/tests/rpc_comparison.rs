//! RPC response comparison tests: PulseChain vs Ethereum mainnet.
//!
//! These tests verify that PulseChain and Ethereum mainnet produce *different*
//! responses for key JSON-RPC methods, and that every PulseChain-specific
//! behaviour (CHAINID opcode transition at PrimordialPulse, missing Cancun/Prague,
//! different deposit contract, no blob transactions) is correctly modelled.
//!
//! ## Layers tested
//!
//! | RPC method        | What drives it                        | Test section        |
//! |-------------------|---------------------------------------|---------------------|
//! | `eth_chainId`     | `ChainSpec::chain().id()`             | eth_chainId section |
//! | `net_version`     | same chain id, as decimal string      | net_version section |
//! | CHAINID opcode    | `PulsechainEvmConfig::evm_env` cfg_env| evm_cfg section     |
//! | hardfork queries  | `EthereumHardforks` trait methods     | hardfork section    |
//! | blob params       | `ChainSpec::blob_params_at_timestamp` | blob section        |
//! | deposit contract  | exported address constants            | deposit section     |
//!
//! Run with: `cargo test -p reth-pulsechain-node --test rpc_comparison`

use alloy_consensus::Header;
use reth_chainspec::{EthChainSpec, EthereumHardforks, MAINNET};
use reth_evm::ConfigureEvm;
use reth_pulsechain_node::{
    chainspec::{
        chain_id_at_block_mainnet, chain_id_at_block_testnet_v4, ETH_DEPOSIT_CONTRACT, PULSECHAIN,
        PULSECHAIN_DEPOSIT_CONTRACT, PULSECHAIN_MAINNET_CHAIN_ID, PULSECHAIN_TESTNET_V4,
        PULSECHAIN_TESTNET_V4_CHAIN_ID,
    },
    hardfork::{
        PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        SHANGHAI_MAINNET_TIMESTAMP, SHANGHAI_TESTNET_V4_TIMESTAMP,
    },
    PulsechainEvmConfig,
};

// ── eth_chainId ───────────────────────────────────────────────────────────────
//
// `eth_chainId` returns `U64::from(chain_spec.chain().id())` in hex.
// The value is fixed for the lifetime of the node — it does NOT transition
// at PrimordialPulse (that is the *EVM cfg_env* chain ID, tested below).

/// `eth_chainId` for PulseChain mainnet must be 0x171 (369 decimal).
#[test]
fn test_eth_chain_id_pulsechain_mainnet_is_369() {
    assert_eq!(
        PULSECHAIN.chain().id(),
        369,
        "eth_chainId must be 369 (0x171) on PulseChain mainnet"
    );
}

/// `eth_chainId` for PulseChain testnet v4 must be 0x3af (943 decimal).
#[test]
fn test_eth_chain_id_pulsechain_testnetv4_is_943() {
    assert_eq!(
        PULSECHAIN_TESTNET_V4.chain().id(),
        943,
        "eth_chainId must be 943 on PulseChain testnet v4"
    );
}

/// `eth_chainId` for Ethereum mainnet must be 0x1 (1 decimal).
///
/// Included as a baseline to catch accidental MAINNET mutation in tests.
#[test]
fn test_eth_chain_id_ethereum_is_1() {
    assert_eq!(MAINNET.chain().id(), 1, "eth_chainId must be 1 on Ethereum mainnet");
}

/// PulseChain mainnet and Ethereum mainnet must return different `eth_chainId` values.
///
/// This is the most fundamental RPC difference between the two chains — every
/// EIP-155 wallet, smart contract, and bridge uses this to distinguish them.
#[test]
fn test_eth_chain_id_differs_between_pulsechain_and_ethereum() {
    assert_ne!(
        PULSECHAIN.chain().id(),
        MAINNET.chain().id(),
        "PulseChain and Ethereum mainnet must have different eth_chainId values"
    );
}

/// PulseChain mainnet and testnet v4 must return different `eth_chainId` values.
#[test]
fn test_eth_chain_id_differs_between_mainnet_and_testnetv4() {
    assert_ne!(
        PULSECHAIN.chain().id(),
        PULSECHAIN_TESTNET_V4.chain().id(),
        "PulseChain mainnet and testnet v4 must have different chain IDs"
    );
}

// ── net_version ───────────────────────────────────────────────────────────────
//
// `net_version` returns chain ID as a decimal string (no "0x" prefix).

/// `net_version` for PulseChain mainnet must be the string "369".
#[test]
fn test_net_version_pulsechain_mainnet_is_string_369() {
    let version = PULSECHAIN.chain().id().to_string();
    assert_eq!(version, "369", "net_version must return \"369\" for PulseChain mainnet");
}

/// `net_version` for Ethereum mainnet must be the string "1".
#[test]
fn test_net_version_ethereum_is_string_1() {
    let version = MAINNET.chain().id().to_string();
    assert_eq!(version, "1", "net_version must return \"1\" for Ethereum mainnet");
}

/// `net_version` strings differ between PulseChain and Ethereum.
#[test]
fn test_net_version_strings_differ() {
    let pulse = PULSECHAIN.chain().id().to_string();
    let eth = MAINNET.chain().id().to_string();
    assert_ne!(pulse, eth);
}

// ── EVM cfg_env.chain_id (CHAINID opcode) ────────────────────────────────────
//
// `PulsechainEvmConfig::evm_env` overrides `cfg_env.chain_id` based on block
// number. This is what the CHAINID EVM opcode returns, and what EIP-155
// transaction signing uses at execution time.
//
// Key difference from `eth_chainId`:
//   - eth_chainId  = always 369 for a PulseChain mainnet node
//   - CHAINID opcode = 1 before PrimordialPulse, 369 after
//
// On Ethereum mainnet, both are always 1.

/// Before PrimordialPulse, PulseChain EVM must report chain_id = 1.
///
/// This ensures pre-fork Ethereum contracts see the chain ID they were
/// deployed on (1), not PulseChain's post-fork identity.
#[test]
fn test_evm_cfg_chain_id_before_primordial_pulse_is_1() {
    let config = PulsechainEvmConfig::new(PULSECHAIN.clone());
    let header = Header { number: PRIMORDIAL_PULSE_MAINNET_BLOCK - 1, ..Default::default() };
    let env = config.evm_env(&header).unwrap();
    assert_eq!(
        env.cfg_env.chain_id, 1,
        "EVM cfg.chain_id must be 1 before PrimordialPulse (Ethereum history replay)"
    );
}

/// At PrimordialPulse block, PulseChain EVM must switch to chain_id = 369.
#[test]
fn test_evm_cfg_chain_id_at_primordial_pulse_switches_to_369() {
    let config = PulsechainEvmConfig::new(PULSECHAIN.clone());
    let header = Header { number: PRIMORDIAL_PULSE_MAINNET_BLOCK, ..Default::default() };
    let env = config.evm_env(&header).unwrap();
    assert_eq!(env.cfg_env.chain_id, 369, "EVM cfg.chain_id must be 369 at PrimordialPulse block");
}

/// After PrimordialPulse, PulseChain EVM must continue to report chain_id = 369.
#[test]
fn test_evm_cfg_chain_id_after_primordial_pulse_is_369() {
    let config = PulsechainEvmConfig::new(PULSECHAIN.clone());
    let header =
        Header { number: PRIMORDIAL_PULSE_MAINNET_BLOCK + 1_000_000, ..Default::default() };
    let env = config.evm_env(&header).unwrap();
    assert_eq!(env.cfg_env.chain_id, 369);
}

/// At the PrimordialPulse block, PulseChain's EVM chain_id differs from
/// what Ethereum mainnet would return at the same block number.
///
/// On Ethereum, CHAINID always returns 1. On PulseChain at or after
/// PrimordialPulse, CHAINID returns 369. This is the CHAINID opcode
/// difference visible to smart contracts.
#[test]
fn test_evm_cfg_chain_id_pulsechain_differs_from_ethereum_at_fork_block() {
    let pulse_config = PulsechainEvmConfig::new(PULSECHAIN.clone());
    let fork_header = Header { number: PRIMORDIAL_PULSE_MAINNET_BLOCK, ..Default::default() };

    let pulse_env = pulse_config.evm_env(&fork_header).unwrap();

    // PulseChain at PrimordialPulse: 369
    assert_eq!(pulse_env.cfg_env.chain_id, 369);

    // Ethereum at the same block number: always 1
    let eth_chain_id_at_same_block: u64 = 1;
    assert_ne!(
        pulse_env.cfg_env.chain_id, eth_chain_id_at_same_block,
        "CHAINID opcode must differ between PulseChain and Ethereum at block {}",
        PRIMORDIAL_PULSE_MAINNET_BLOCK,
    );
}

/// PulseChain testnet v4 EVM switches from chain_id 1 → 943 at its fork block.
#[test]
fn test_evm_cfg_chain_id_testnetv4_transition() {
    let config = PulsechainEvmConfig::new(PULSECHAIN_TESTNET_V4.clone());

    let pre_fork = Header { number: PRIMORDIAL_PULSE_TESTNET_V4_BLOCK - 1, ..Default::default() };
    let at_fork = Header { number: PRIMORDIAL_PULSE_TESTNET_V4_BLOCK, ..Default::default() };

    let pre_env = config.evm_env(&pre_fork).unwrap();
    let fork_env = config.evm_env(&at_fork).unwrap();

    assert_eq!(pre_env.cfg_env.chain_id, 1, "testnet v4 EVM chain_id must be 1 before fork");
    assert_eq!(fork_env.cfg_env.chain_id, 943, "testnet v4 EVM chain_id must be 943 at fork");
}

/// The chain_id helper functions agree with PulsechainEvmConfig::evm_env.
///
/// This cross-checks the standalone helpers against the full EVM config path
/// to prevent divergence between the two code paths.
#[test]
fn test_chain_id_helpers_agree_with_evm_config() {
    let config = PulsechainEvmConfig::new(PULSECHAIN.clone());

    for block in [0u64, PRIMORDIAL_PULSE_MAINNET_BLOCK - 1] {
        let header = Header { number: block, ..Default::default() };
        let env = config.evm_env(&header).unwrap();
        assert_eq!(
            env.cfg_env.chain_id,
            chain_id_at_block_mainnet(block),
            "evm_env chain_id must agree with chain_id_at_block_mainnet at block {block}"
        );
    }

    for block in [PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_MAINNET_BLOCK + 1] {
        let header = Header { number: block, ..Default::default() };
        let env = config.evm_env(&header).unwrap();
        assert_eq!(
            env.cfg_env.chain_id,
            chain_id_at_block_mainnet(block),
            "evm_env chain_id must agree with chain_id_at_block_mainnet at block {block}"
        );
    }
}

// ── EIP-155 replay protection ─────────────────────────────────────────────────
//
// EIP-155 transaction signing encodes chain_id in the signature's `v` value:
//   v = chain_id * 2 + 35  or  chain_id * 2 + 36
//
// A transaction signed for PulseChain (chain_id=369) cannot be replayed on
// Ethereum (chain_id=1) because the `v` values are different.

/// EIP-155 `v` values differ between PulseChain and Ethereum mainnet.
///
/// This is the cryptographic guarantee that PulseChain transactions cannot
/// be replayed on Ethereum, and vice versa.
#[test]
fn test_eip155_v_values_differ_between_chains() {
    let pulse_chain_id = PULSECHAIN_MAINNET_CHAIN_ID;
    let eth_chain_id = MAINNET.chain().id();

    // EIP-155: v = chain_id * 2 + 35 (or +36 for the other parity)
    let pulse_v = pulse_chain_id * 2 + 35; // 369 * 2 + 35 = 773
    let eth_v = eth_chain_id * 2 + 35; //   1 * 2 + 35 = 37

    assert_eq!(pulse_v, 773, "PulseChain EIP-155 v must be 773");
    assert_eq!(eth_v, 37, "Ethereum EIP-155 v must be 37");
    assert_ne!(pulse_v, eth_v, "EIP-155 v values must differ — no cross-chain replay");
}

// ── Hardfork differences ──────────────────────────────────────────────────────
//
// PulseChain mirrors Ethereum up to Shanghai (its terminal hardfork).
// Cancun (EIP-4844 blobs), Prague (EIP-7702 auth lists), and Osaka are absent.
// Ethereum mainnet has all three.

/// PulseChain mainnet must NOT have Cancun (EIP-4844 blob transactions).
#[test]
fn test_pulsechain_lacks_cancun() {
    assert!(
        !PULSECHAIN.is_cancun_active_at_timestamp(u64::MAX),
        "PulseChain must not have Cancun — blob transactions are unsupported"
    );
}

/// Ethereum mainnet MUST have Cancun.
#[test]
fn test_ethereum_mainnet_has_cancun() {
    // Ethereum Cancun activated at timestamp 1_710_338_135 (March 13, 2024).
    assert!(MAINNET.is_cancun_active_at_timestamp(u64::MAX), "Ethereum mainnet must have Cancun");
}

/// PulseChain mainnet must NOT have Prague (EIP-7702 auth lists, etc.).
#[test]
fn test_pulsechain_lacks_prague() {
    assert!(!PULSECHAIN.is_prague_active_at_timestamp(u64::MAX), "PulseChain must not have Prague");
}

/// Ethereum mainnet MUST have Prague.
#[test]
fn test_ethereum_mainnet_has_prague() {
    assert!(MAINNET.is_prague_active_at_timestamp(u64::MAX), "Ethereum mainnet must have Prague");
}

/// PulseChain mainnet MUST have Shanghai (its terminal hardfork).
#[test]
fn test_pulsechain_has_shanghai_at_activation_timestamp() {
    assert!(
        PULSECHAIN.is_shanghai_active_at_timestamp(SHANGHAI_MAINNET_TIMESTAMP),
        "PulseChain must be Shanghai-active at its activation timestamp"
    );
}

/// PulseChain testnet v4 MUST have Shanghai at its own activation timestamp.
#[test]
fn test_pulsechain_testnetv4_has_shanghai() {
    assert!(
        PULSECHAIN_TESTNET_V4.is_shanghai_active_at_timestamp(SHANGHAI_TESTNET_V4_TIMESTAMP),
        "PulseChain testnet v4 must be Shanghai-active at its activation timestamp"
    );
}

/// PulseChain and Ethereum diverge on Cancun: Ethereum has it, PulseChain does not.
///
/// This is the most important hardfork divergence for users — it determines
/// whether blob-carrying transactions (`eth_sendRawTransaction` with type 3)
/// can be submitted to the node.
#[test]
fn test_cancun_presence_differs_between_pulsechain_and_ethereum() {
    let pulse_has_cancun = PULSECHAIN.is_cancun_active_at_timestamp(u64::MAX);
    let eth_has_cancun = MAINNET.is_cancun_active_at_timestamp(u64::MAX);
    assert_ne!(
        pulse_has_cancun, eth_has_cancun,
        "Cancun presence must differ between PulseChain and Ethereum"
    );
}

// ── Blob transaction support ──────────────────────────────────────────────────
//
// Blob parameters drive `eth_feeHistory` blob base fee, blob pool acceptance,
// and the `/eth/v1/config/spec` blob-related fields. PulseChain has none.

/// PulseChain has no blob schedule — blob_params_at_timestamp always returns None.
///
/// Any attempt to submit a type-3 (EIP-4844) transaction to PulseChain should
/// be rejected at the pool layer.
#[test]
fn test_pulsechain_has_no_blob_schedule_at_any_timestamp() {
    assert!(
        PULSECHAIN.blob_params_at_timestamp(u64::MAX).is_none(),
        "PulseChain must have no blob params at any timestamp"
    );
    assert!(
        PULSECHAIN.blob_params_at_timestamp(0).is_none(),
        "PulseChain must have no blob params at timestamp 0"
    );
}

/// Ethereum mainnet has blob params from Cancun onward.
#[test]
fn test_ethereum_has_blob_schedule_from_cancun() {
    // Ethereum Cancun timestamp.
    const ETH_CANCUN_TIMESTAMP: u64 = 1_710_338_135;
    assert!(
        MAINNET.blob_params_at_timestamp(ETH_CANCUN_TIMESTAMP).is_some(),
        "Ethereum mainnet must have blob params from Cancun"
    );
}

/// PulseChain and Ethereum have different blob availability at any post-Cancun timestamp.
#[test]
fn test_blob_availability_differs_between_chains() {
    let pulse_blobs = PULSECHAIN.blob_params_at_timestamp(u64::MAX);
    let eth_blobs = MAINNET.blob_params_at_timestamp(u64::MAX);

    assert!(pulse_blobs.is_none(), "PulseChain must not have blobs");
    assert!(eth_blobs.is_some(), "Ethereum must have blobs");
}

// ── Deposit contracts ─────────────────────────────────────────────────────────

/// PulseChain deposit contract address differs from the Ethereum deposit contract.
///
/// The Ethereum contract (0x00000000219ab540...) is selfdestructed at
/// PrimordialPulse. The PulseChain contract (0x36936936...) is deployed
/// at the same block. Using the wrong address would mean staked ETH is lost.
#[test]
fn test_deposit_contract_addresses_differ() {
    assert_ne!(
        PULSECHAIN_DEPOSIT_CONTRACT, ETH_DEPOSIT_CONTRACT,
        "PulseChain and Ethereum deposit contracts must be at different addresses"
    );
}

/// PulseChain deposit contract has its canonical address.
#[test]
fn test_pulsechain_deposit_contract_canonical_address() {
    use alloy_primitives::address;
    assert_eq!(
        PULSECHAIN_DEPOSIT_CONTRACT,
        address!("3693693693693693693693693693693693693693"),
        "PulseChain deposit contract must be at 0x3693...3693"
    );
}

/// Ethereum deposit contract has its canonical address.
#[test]
fn test_eth_deposit_contract_canonical_address() {
    use alloy_primitives::address;
    assert_eq!(
        ETH_DEPOSIT_CONTRACT,
        address!("00000000219ab540356cBB839Cbe05303d7705Fa"),
        "Ethereum deposit contract must be at 0x00000000219ab540..."
    );
}

// ── chain_id helper cross-checks ──────────────────────────────────────────────
//
// Verify chain_id_at_block_mainnet / chain_id_at_block_testnet_v4 against
// the exported chain ID constants. These helpers are used in PulsechainEvmConfig
// and must be consistent with the exported PULSECHAIN_MAINNET_CHAIN_ID constant.

/// chain_id_at_block_mainnet post-fork must equal PULSECHAIN_MAINNET_CHAIN_ID constant.
#[test]
fn test_mainnet_chain_id_helper_matches_constant() {
    assert_eq!(
        chain_id_at_block_mainnet(PRIMORDIAL_PULSE_MAINNET_BLOCK),
        PULSECHAIN_MAINNET_CHAIN_ID
    );
}

/// chain_id_at_block_testnet_v4 post-fork must equal PULSECHAIN_TESTNET_V4_CHAIN_ID constant.
#[test]
fn test_testnetv4_chain_id_helper_matches_constant() {
    assert_eq!(
        chain_id_at_block_testnet_v4(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK),
        PULSECHAIN_TESTNET_V4_CHAIN_ID
    );
}

/// Pre-fork chain ID helper must be 1 (Ethereum mainnet).
#[test]
fn test_pre_fork_chain_id_is_ethereum_chain_id() {
    let eth_chain_id = MAINNET.chain().id();
    assert_eq!(chain_id_at_block_mainnet(0), eth_chain_id);
    assert_eq!(chain_id_at_block_mainnet(PRIMORDIAL_PULSE_MAINNET_BLOCK - 1), eth_chain_id);
    assert_eq!(chain_id_at_block_testnet_v4(0), eth_chain_id);
    assert_eq!(chain_id_at_block_testnet_v4(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK - 1), eth_chain_id);
}
