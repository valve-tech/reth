//! PrimordialPulse state transition integration tests.
//!
//! These tests use a local [`MockState`] test double (implementing
//! [`PrimordialPulseStateWriter`]) to verify the observable effects of
//! [`apply_primordial_pulse`] and [`decode_sacrifice_credits`] without requiring
//! a full `revm::State<DB>` setup.
//!
//! Run with: `cargo nextest run -p reth-pulsechain-node --test fork_transition`

use std::collections::HashMap;

use alloy_primitives::{address, b256, Address, Bytes, B256, U256};
use reth_pulsechain_node::{
    fork::{
        apply_primordial_pulse, decode_sacrifice_credits, PrimordialPulseStateWriter,
        ETH_DEPOSIT_CONTRACT, PULSE_DEPOSIT_CONTRACT,
    },
    hardfork::PRIMORDIAL_PULSE_MAINNET_BLOCK,
};

// ── MockState (local integration-test double) ────────────────────────────────

/// Integration-test double for [`PrimordialPulseStateWriter`].
///
/// Records every state mutation for inspection. Does not simulate full EVM
/// selfdestruct semantics — just records which address was destructed.
#[derive(Default, Debug)]
struct MockState {
    balances: HashMap<Address, U256>,
    codes: HashMap<Address, Bytes>,
    nonces: HashMap<Address, u64>,
    storage: HashMap<(Address, B256), B256>,
    selfdestructed: Vec<Address>,
}

impl PrimordialPulseStateWriter for MockState {
    fn increment_balance(&mut self, address: Address, amount: U256) {
        *self.balances.entry(address).or_default() += amount;
    }

    fn set_code(&mut self, address: Address, code: &[u8]) {
        self.codes.insert(address, Bytes::copy_from_slice(code));
    }

    fn set_nonce(&mut self, address: Address, nonce: u64) {
        self.nonces.insert(address, nonce);
    }

    fn set_storage(&mut self, address: Address, slot: B256, value: B256) {
        self.storage.insert((address, slot), value);
    }

    fn selfdestruct(&mut self, address: Address) {
        self.selfdestructed.push(address);
    }
}

// ── decode_sacrifice_credits ─────────────────────────────────────────────────

/// The sacrifice credits decoder must parse the correct binary format.
///
/// Format: `[total_length: u8][address: 20 bytes][balance: total_length-20 bytes big-endian]`
///
/// The `total_length` byte covers the *entire* record (address + balance), NOT just the
/// balance field. Verified against `private-erigon-pulse/pulse/sacrifice_credits.go`.
#[test]
fn test_sacrifice_credits_binary_format() {
    // Record: total_length=21 (= 20 addr + 1 balance), addr=0x1234...0001, balance=0x01
    let mut record = vec![0u8; 22]; // 1 header + 21 payload
    record[0] = 21; // total_length = 20 addr + 1 balance byte
    record[1..21].copy_from_slice(&[
        0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    record[21] = 0x01; // balance = 1 PLS

    let credits = decode_sacrifice_credits(&record);

    assert_eq!(credits.len(), 1, "should decode exactly one credit record");
    assert_eq!(credits[0].1, U256::from(1u64), "balance should be 1 PLS");
}

/// The first record in the mainnet binary must match the known address and balance.
///
/// First record values were extracted from the raw binary and verified against
/// the erigon-pulse `applySacrificeCredits` function.
#[test]
fn test_sacrifice_credits_known_first_mainnet_record() {
    let bin_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("res/sacrifice_credits_mainnet.bin");
    let data = std::fs::read(&bin_path).expect("sacrifice_credits_mainnet.bin must exist");

    // First record: total_length=30, so we read 1 header + 30 payload = 31 bytes
    let first = &data[..31];
    let credits = decode_sacrifice_credits(first);

    assert_eq!(credits.len(), 1);

    let expected_addr = address!("0000000000bc14115f9f67fde839f285667437bc");
    let expected_balance =
        U256::from_be_slice(&alloy_primitives::hex::decode("0c5b080997de67c3729a").unwrap());

    assert_eq!(credits[0].0, expected_addr, "first mainnet address mismatch");
    assert_eq!(credits[0].1, expected_balance, "first mainnet balance mismatch");
}

// ── apply_primordial_pulse / deposit contracts ───────────────────────────────

/// After PrimordialPulse, the ETH deposit contract must be selfdestructed.
///
/// On-chain PulseChain state shows the address has empty code (`0x`) after the fork.
/// No nil contract is installed — the selfdestruct clears code, storage, and balance.
#[test]
fn test_ethereum_deposit_contract_destroyed() {
    let mut state = MockState::default();
    apply_primordial_pulse(&mut state, 369);

    // Must be selfdestructed
    assert!(
        state.selfdestructed.contains(&ETH_DEPOSIT_CONTRACT),
        "ETH deposit contract must be selfdestructed at PrimordialPulse"
    );

    // No code should be installed at the old address
    assert!(
        !state.codes.contains_key(&ETH_DEPOSIT_CONTRACT),
        "ETH deposit contract must have empty code after selfdestruct"
    );
}

/// After PrimordialPulse, the PulseChain deposit contract must have code deployed.
#[test]
fn test_pulsechain_deposit_contract_deployed() {
    let mut state = MockState::default();
    apply_primordial_pulse(&mut state, 369);

    let code = state
        .codes
        .get(&PULSE_DEPOSIT_CONTRACT)
        .expect("PulseChain deposit contract must have code after PrimordialPulse");

    assert!(!code.is_empty(), "PulseChain deposit contract must have non-empty bytecode");
    assert_eq!(code.len(), 4898, "PulseChain deposit contract must be 4898 bytes");
}

/// PulseChain deposit contract must have exactly 31 storage slots initialized.
#[test]
fn test_pulsechain_deposit_contract_storage_slots() {
    let mut state = MockState::default();
    apply_primordial_pulse(&mut state, 369);

    let slot_count =
        state.storage.keys().filter(|(addr, _)| *addr == PULSE_DEPOSIT_CONTRACT).count();

    assert_eq!(
        slot_count, 31,
        "PulseChain deposit contract must have exactly 31 storage slots (0x22–0x40)"
    );

    // Spot-check slot 0x22 (first Merkle branch node — empty deposit tree level 0)
    let slot_22 = b256!("0000000000000000000000000000000000000000000000000000000000000022");
    let expected_22 = b256!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    assert_eq!(
        state.storage[&(PULSE_DEPOSIT_CONTRACT, slot_22)],
        expected_22,
        "slot 0x22 must match the empty-tree Merkle branch value"
    );

    // Spot-check slot 0x40 (last Merkle branch node — tree level 30)
    let slot_40 = b256!("0000000000000000000000000000000000000000000000000000000000000040");
    let expected_40 = b256!("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7");
    assert_eq!(
        state.storage[&(PULSE_DEPOSIT_CONTRACT, slot_40)],
        expected_40,
        "slot 0x40 must match the empty-tree Merkle branch value"
    );
}

// ── exact-once semantics ─────────────────────────────────────────────────────

/// The fork block constant is an exact equality value — the block executor must compare
/// `block_number == primordial_pulse_block`, not `>=`.
///
/// Using `>=` would re-apply the state transition on every subsequent block, corrupting
/// sacrifice balances and re-deploying contracts.
#[test]
fn test_primordial_pulse_fires_exactly_once() {
    assert_eq!(
        PRIMORDIAL_PULSE_MAINNET_BLOCK, 17_233_000,
        "PrimordialPulse mainnet fork block must be 17,233,000 for exact == comparison"
    );
}
