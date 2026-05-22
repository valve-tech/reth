//! `PrimordialPulse` state transition.
//!
//! Fires exactly once at `block_number == primordial_pulse_block`. Applies sacrifice credits
//! to sacrificing addresses, selfdestructs the Ethereum deposit contract, and deploys the
//! `PulseChain` deposit contract. See `docs/pulsechain-spec.md` for the full specification.
//!
//! The spec DATA — address constants, sacrifice-credit binaries, deposit-contract bytecode,
//! initial-storage table, and the decoder — was moved to
//! [`reth_pulsechain_forks::primordial_pulse`] so the firehose crate can `use` it without
//! a circular dependency. This module re-exports the relevant items for callers (tests,
//! the executor's `finish()` hook) that still expect them under this path.

use alloy_primitives::{Address, B256, U256};

// Re-exports from the canonical source in `reth-pulsechain-forks`.
pub use reth_pulsechain_forks::primordial_pulse::{
    decode_sacrifice_credits, sacrifice_credits_for, DEPOSIT_CONTRACT_BYTECODE,
    DEPOSIT_CONTRACT_INITIAL_STORAGE, ETH_DEPOSIT_CONTRACT, PULSE_DEPOSIT_CONTRACT,
    SACRIFICE_CREDITS_MAINNET, SACRIFICE_CREDITS_TESTNET_V4, TESTNET_V4_TREASURY,
    TESTNET_V4_TREASURY_BALANCE,
};

// Embedded binaries (SACRIFICE_CREDITS_*, DEPOSIT_CONTRACT_BYTECODE) and the
// DEPOSIT_CONTRACT_INITIAL_STORAGE constant moved to
// `reth-pulsechain-forks::primordial_pulse` and re-exported at the top of this file.
// Reason: the firehose crate needs the same data to emit per-write state-change
// events for the PrimordialPulse transition, but cannot depend on
// `reth-pulsechain-node` (circular). The shared `reth-pulsechain-forks` crate
// has no such dependency and serves as the single source of truth.

// ─── State writer trait ───────────────────────────────────────────────────────

/// Abstracts state writes needed by the `PrimordialPulse` transition.
///
/// Implemented by [`tests::MockState`] for unit testing and blanket-impl'd for
/// any `T: StateDB` in `evm.rs` for the live revm path.
pub trait PrimordialPulseStateWriter {
    /// Add `amount` to the balance of `address`.
    fn increment_balance(&mut self, address: Address, amount: U256);

    /// Replace the bytecode at `address` with `code`.
    fn set_code(&mut self, address: Address, code: &[u8]);

    /// Set the nonce of `address` to `nonce`.
    fn set_nonce(&mut self, address: Address, nonce: u64);

    /// Write a storage `slot → value` pair at `address`.
    fn set_storage(&mut self, address: Address, slot: B256, value: B256);

    /// Mark `address` as selfdestructed.
    ///
    /// Called before [`set_code`][Self::set_code] on the same address — matching the order in
    /// erigon-pulse `replaceDepositContract` — so existing code/storage are cleared first.
    fn selfdestruct(&mut self, address: Address);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Apply the `PrimordialPulse` state transition.
///
/// Must be called exactly once when `block_number == primordial_pulse_block`, after all
/// transactions have executed but before state root commitment. Wired in
/// `PulsechainBlockExecutor::finish` (`evm.rs`).
///
/// `chain_id` must be `369` (mainnet) or `943` (testnet v4).
pub fn apply_primordial_pulse<S: PrimordialPulseStateWriter>(state: &mut S, chain_id: u64) {
    debug_assert!(
        chain_id == 369 || chain_id == 943,
        "apply_primordial_pulse: expected chain_id 369 or 943, got {chain_id}"
    );

    // Testnet v4 treasury allocation — applied before sacrifice credits.
    // Mainnet has no treasury. Source: pulsechain-testnet-v4.json in erigon-pulse.
    if chain_id == 943 {
        state.increment_balance(TESTNET_V4_TREASURY, TESTNET_V4_TREASURY_BALANCE);
    }

    let credits =
        if chain_id == 369 { SACRIFICE_CREDITS_MAINNET } else { SACRIFICE_CREDITS_TESTNET_V4 };

    apply_sacrifice_credits(state, credits);
    destroy_eth_deposit_contract(state);
    deploy_pulsechain_deposit_contract(state);
}

/// Decode sacrifice credits and apply balance increments to `state`.
fn apply_sacrifice_credits<S: PrimordialPulseStateWriter>(state: &mut S, data: &[u8]) {
    for (address, balance) in decode_sacrifice_credits(data) {
        state.increment_balance(address, balance);
    }
}

/// Selfdestruct the Ethereum deposit contract, clearing its code, storage, and balance.
///
/// On-chain PulseChain state shows the ETH deposit contract has empty code (`0x`)
/// after PrimordialPulse — no nil contract is installed. The selfdestruct alone
/// handles the full cleanup.
fn destroy_eth_deposit_contract<S: PrimordialPulseStateWriter>(state: &mut S) {
    state.selfdestruct(ETH_DEPOSIT_CONTRACT);
}

/// Deploy the `PulseChain` deposit contract at [`PULSE_DEPOSIT_CONTRACT`].
fn deploy_pulsechain_deposit_contract<S: PrimordialPulseStateWriter>(state: &mut S) {
    state.set_code(PULSE_DEPOSIT_CONTRACT, DEPOSIT_CONTRACT_BYTECODE);
    state.set_nonce(PULSE_DEPOSIT_CONTRACT, 0);
    for (slot, value) in &DEPOSIT_CONTRACT_INITIAL_STORAGE {
        state.set_storage(PULSE_DEPOSIT_CONTRACT, *slot, *value);
    }
}

// `decode_sacrifice_credits` moved to `reth-pulsechain-forks::primordial_pulse`
// and re-exported above.

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use alloy_primitives::{address, b256, Bytes};

    use super::*;

    // ── MockState ────────────────────────────────────────────────────────────

    /// Test double for [`PrimordialPulseStateWriter`] that records all mutations.
    #[derive(Default, Debug)]
    pub(crate) struct MockState {
        pub balances: HashMap<Address, U256>,
        pub codes: HashMap<Address, Bytes>,
        pub nonces: HashMap<Address, u64>,
        pub storage: HashMap<(Address, B256), B256>,
        pub selfdestructed: Vec<Address>,
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

    // ── decode_sacrifice_credits ─────────────────────────────────────────────

    #[test]
    fn test_decode_sacrifice_credits_single_record() {
        // total_length=21 (20 addr + 1 balance byte), balance=0x01
        let mut record = vec![0u8; 22];
        record[0] = 21;
        record[1..21].copy_from_slice(&[
            0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        record[21] = 0x01;

        let credits = decode_sacrifice_credits(&record);
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].1, U256::from(1u64));
    }

    #[test]
    fn test_decode_sacrifice_credits_two_records() {
        let mut data = Vec::new();
        data.push(21u8);
        data.extend_from_slice(&[0x01u8; 20]);
        data.push(0x01);
        data.push(22u8);
        data.extend_from_slice(&[0x02u8; 20]);
        data.extend_from_slice(&[0x01, 0x02]);

        let credits = decode_sacrifice_credits(&data);
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].1, U256::from(1u64));
        assert_eq!(credits[1].1, U256::from(0x0102u64));
    }

    #[test]
    fn test_decode_sacrifice_credits_first_mainnet_record() {
        // Verified against private-erigon-pulse: first record is total_len=30,
        // addr=0x0000000000bc14115f9f67fde839f285667437bc, balance=0x0c5b080997de67c3729a.
        let first = &SACRIFICE_CREDITS_MAINNET[..31]; // 1 header + 30 payload
        let credits = decode_sacrifice_credits(first);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].0, address!("0000000000bc14115f9f67fde839f285667437bc"));
        assert_eq!(
            credits[0].1,
            U256::from_be_slice(&alloy_primitives::hex::decode("0c5b080997de67c3729a").unwrap()),
        );
    }

    #[test]
    fn test_decode_sacrifice_credits_full_mainnet_parses() {
        let credits = decode_sacrifice_credits(SACRIFICE_CREDITS_MAINNET);
        assert!(credits.len() > 200_000, "expected > 200k records, got {}", credits.len());
    }

    // ── apply_primordial_pulse ───────────────────────────────────────────────

    #[test]
    fn test_apply_primordial_pulse_mainnet_increments_balances() {
        let mut state = MockState::default();
        apply_primordial_pulse(&mut state, 369);
        assert!(state.balances.len() > 200_000, "got {}", state.balances.len());
    }

    #[test]
    fn test_apply_primordial_pulse_testnetv4_increments_balances() {
        let mut state = MockState::default();
        apply_primordial_pulse(&mut state, 943);
        assert!(!state.balances.is_empty());
    }

    #[test]
    fn test_eth_deposit_contract_selfdestructed() {
        let mut state = MockState::default();
        apply_primordial_pulse(&mut state, 369);

        assert!(state.selfdestructed.contains(&ETH_DEPOSIT_CONTRACT));
        // No code should be installed — on-chain state shows empty code after fork.
        assert!(!state.codes.contains_key(&ETH_DEPOSIT_CONTRACT));
    }

    #[test]
    fn test_pulse_deposit_contract_has_correct_code() {
        let mut state = MockState::default();
        apply_primordial_pulse(&mut state, 369);

        let code = state.codes.get(&PULSE_DEPOSIT_CONTRACT).unwrap();
        assert_eq!(code.as_ref(), DEPOSIT_CONTRACT_BYTECODE);
    }

    #[test]
    fn test_pulse_deposit_contract_has_31_storage_slots() {
        let mut state = MockState::default();
        apply_primordial_pulse(&mut state, 369);

        let count = state.storage.keys().filter(|(a, _)| *a == PULSE_DEPOSIT_CONTRACT).count();
        assert_eq!(count, 31);
    }

    #[test]
    fn test_pulse_deposit_contract_storage_slot_0x22() {
        let mut state = MockState::default();
        apply_primordial_pulse(&mut state, 369);

        let slot = b256!("0000000000000000000000000000000000000000000000000000000000000022");
        let expected = b256!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
        assert_eq!(state.storage[&(PULSE_DEPOSIT_CONTRACT, slot)], expected);
    }

    #[test]
    fn test_deposit_contract_bytecode_length() {
        assert_eq!(DEPOSIT_CONTRACT_BYTECODE.len(), 4898);
    }

    #[test]
    fn test_deposit_contract_storage_slot_count() {
        assert_eq!(DEPOSIT_CONTRACT_INITIAL_STORAGE.len(), 31);
    }

    #[test]
    fn test_deposit_contract_storage_slot_range_0x22_to_0x40() {
        for (i, (slot, _)) in DEPOSIT_CONTRACT_INITIAL_STORAGE.iter().enumerate() {
            let expected = 0x22u64 + i as u64;
            assert_eq!(slot[31] as u64, expected, "slot {i}: last byte");
            assert_eq!(&slot[..31], &[0u8; 31], "slot {i}: leading bytes must be zero");
        }
    }
}
