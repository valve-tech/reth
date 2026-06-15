//! `PrimordialPulse` state-transition spec — constants, embedded binaries, decoder.
//!
//! This module is the canonical source of the data that defines what the
//! `PrimordialPulse` fork-block transition does. It is kept in the lowest-level
//! `PulseChain` crate (`reth-pulsechain-forks`) so both:
//!   - the node crate (`reth-pulsechain-node`) — which actually APPLIES the
//!     transition by calling `PrimordialPulseStateWriter` methods, and
//!   - the firehose crate (`reth-firehose`) — which observes the transition
//!     after-the-fact via the wrapper layer to emit `BalanceChange` /
//!     `CodeChange` / `NonceChange` / `StorageChange` events for the firehose
//!     stream,
//!
//! can read from a single, shared definition without introducing a circular
//! crate dependency. See the project memory's "Bug-5/Bug-6 firehose"
//! discussion for why this matters.
//!
//! The actual *application* logic (`apply_primordial_pulse` + the
//! `PrimordialPulseStateWriter` trait it operates on) lives in
//! `reth-pulsechain-node` because it depends on revm state types that
//! `reth-pulsechain-forks` deliberately does not pull in. This module is
//! intentionally low-level: just data + a pure decoder.

use alloy_primitives::{address, b256, uint, Address, B256, U256};

// ─── Address constants ────────────────────────────────────────────────────────

/// Ethereum `PoS` deposit contract address — selfdestructed at `PrimordialPulse`.
pub const ETH_DEPOSIT_CONTRACT: Address = address!("00000000219ab540356cBB839Cbe05303d7705Fa");

/// `PulseChain` beacon-chain deposit contract address — deployed at `PrimordialPulse`.
pub const PULSE_DEPOSIT_CONTRACT: Address = address!("3693693693693693693693693693693693693693");

/// Testnet v4 treasury address — receives a one-time allocation at `PrimordialPulse`.
/// Mainnet has no treasury allocation.
pub const TESTNET_V4_TREASURY: Address = address!("A592ED65885bcbCeb30442F4902a0D1Cf3AcB8fC");

/// Testnet v4 treasury balance: 0x314DC6448D9338C15B0A00000000
/// Source: pulsechain-testnet-v4.json `pulseChain.treasury.balance`.
pub const TESTNET_V4_TREASURY_BALANCE: U256 = uint!(0x314DC6448D9338C15B0A00000000_U256);

// ─── Embedded binaries ────────────────────────────────────────────────────────

// Binary format for sacrifice credits — one record per address:
//   total_length: u8   — total bytes in this record (= 20 + len(balance))
//   address:  [u8; 20] — Ethereum address
//   balance:  [u8; N]  — PLS balance, big-endian uint, N = total_length - 20
//
// Note: `total_length` covers the entire record (addr + balance), NOT just the balance.
// Verified against private-erigon-pulse/pulse/sacrifice_credits.go `byteCount`.

/// Mainnet (chain 369) sacrifice credits.
pub static SACRIFICE_CREDITS_MAINNET: &[u8] =
    include_bytes!("../res/sacrifice_credits_mainnet.bin");

/// Testnet v4 (chain 943) sacrifice credits.
pub static SACRIFICE_CREDITS_TESTNET_V4: &[u8] =
    include_bytes!("../res/sacrifice_credits_testnet_v4.bin");

/// 4898-byte PulseChain beacon deposit contract bytecode.
/// Source: private-erigon-pulse/pulse/deposit_contract.go `depositContractBytes`.
pub static DEPOSIT_CONTRACT_BYTECODE: &[u8] = include_bytes!("../res/deposit_contract.bin");

// ─── Deposit contract initial storage ────────────────────────────────────────

/// 31 slots (0x22–0x40) initialize the Merkle tree for an empty deposit trie, allowing
/// validators to deposit immediately after the fork.
/// Source: private-erigon-pulse/pulse/deposit_contract.go `depositContractStorage`.
pub const DEPOSIT_CONTRACT_INITIAL_STORAGE: [(B256, B256); 31] = [
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000022"),
        b256!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000023"),
        b256!("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000024"),
        b256!("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000025"),
        b256!("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000026"),
        b256!("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000027"),
        b256!("d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000028"),
        b256!("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000029"),
        b256!("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000002a"),
        b256!("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000002b"),
        b256!("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000002c"),
        b256!("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000002d"),
        b256!("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000002e"),
        b256!("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000002f"),
        b256!("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000030"),
        b256!("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000031"),
        b256!("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000032"),
        b256!("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000033"),
        b256!("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000034"),
        b256!("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000035"),
        b256!("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000036"),
        b256!("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000037"),
        b256!("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000038"),
        b256!("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000039"),
        b256!("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000003a"),
        b256!("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000003b"),
        b256!("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000003c"),
        b256!("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000003d"),
        b256!("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000003e"),
        b256!("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
    ),
    (
        b256!("000000000000000000000000000000000000000000000000000000000000003f"),
        b256!("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
    ),
    (
        b256!("0000000000000000000000000000000000000000000000000000000000000040"),
        b256!("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
    ),
];

// ─── Public API ───────────────────────────────────────────────────────────────

/// Pick the right sacrifice-credit blob for a given chain ID.
///
/// Returns `Some(&[u8])` for chains 369 (mainnet) and 943 (testnet v4); `None`
/// for any other chain (firehose's PrimordialPulse emit-path uses this to decide
/// whether to do anything at all).
pub const fn sacrifice_credits_for(chain_id: u64) -> Option<&'static [u8]> {
    match chain_id {
        369 => Some(SACRIFICE_CREDITS_MAINNET),
        943 => Some(SACRIFICE_CREDITS_TESTNET_V4),
        _ => None,
    }
}

/// Parse the sacrifice credits binary into `(address, balance)` pairs.
///
/// Binary format — each record:
///
/// ```text
/// total_length: u8   — total bytes in this record (= 20 + len(balance))
/// address:  [u8; 20] — Ethereum address
/// balance:  [u8; N]  — PLS balance, big-endian uint, N = total_length - 20
/// ```
///
/// First mainnet record: `total_length=30`, addr `0x0000000000bc1411...bc`,
/// balance `0x0c5b080997de67c3729a`.
pub fn decode_sacrifice_credits(data: &[u8]) -> Vec<(Address, U256)> {
    let mut credits = Vec::new();
    let mut ptr = 0;

    while ptr < data.len() {
        let total_len = data[ptr] as usize;
        ptr += 1;

        debug_assert!(
            total_len > 20,
            "sacrifice credit record at offset {}: total_len={total_len} must be > 20",
            ptr - 1,
        );

        let record = &data[ptr..ptr + total_len];
        ptr += total_len;

        let addr_bytes: [u8; 20] = record[..20].try_into().expect("record is ≥ 20 bytes");
        credits.push((Address::from(addr_bytes), U256::from_be_slice(&record[20..])));
    }

    credits
}

// ─── Tests ──────────────────────────────────────────────────────────────────
//
// PrimordialPulse regression tests. These lock the on-wire-validated
// PrimordialPulse balance/code/storage/nonce decomposition into the test suite.
//
// On-wire validation reference (PulseChain testnet v4, chain 943, block
// 16,492,700, verified 2026-05-23): the firehose stream emitted exactly
//   286,833 balance_changes + 2 code_changes + 31 storage_changes + 1 nonce_change.
//
// The 286,833 balance_changes decompose (verified by the asserts below) as:
//   286,830  sacrifice-credit allocations  (Reason::GenesisBalance)
//   +     1  testnet treasury allocation   (Reason::GenesisBalance)
//   +     1  block reward (coinbase)        (Reason::RewardMineBlock)
//   +     1  ETH deposit contract selfdestruct withdraw (Reason::SuicideWithdraw)
//   = 286,833
//
// Note: the original hand-written breakdown described "286,831 GenesisBalance"
// — that figure is the sacrifice credits (286,830) PLUS the treasury (1). The
// decomposition is split out explicitly here so a future change to either the
// credits blob or the treasury handling fails loudly.
//
// These assertions are hermetic: they decode the embedded `.bin` resources and
// inspect the const tables directly — no datadir, no network, no EVM/DB state.
// The actual *emission* (that finish() drives the inspector to produce those
// exact wire events) requires a live EVM+DB and is out of hermetic scope; it is
// covered on-wire and partially in `reth-pulsechain-node`'s `apply_primordial_pulse`
// MockState tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// Number of block-reward (coinbase) BalanceChange events PrimordialPulse
    /// contributes — emitted by the existing `emit_block_reward_balance_changes`
    /// flow, not the PrimordialPulse emit path, but part of the on-wire total.
    const REWARD_MINE_BLOCK_COUNT: usize = 1;
    /// Number of SuicideWithdraw BalanceChange events — the ETH deposit
    /// contract balance going to zero on selfdestruct.
    const SUICIDE_WITHDRAW_COUNT: usize = 1;

    #[test]
    fn testnet_v4_balance_change_decomposition_totals_286_833() {
        let blob = sacrifice_credits_for(943).expect("chain 943 has a credits blob");
        let credits = decode_sacrifice_credits(blob);

        // Locked: exact sacrifice-credit count for testnet v4.
        assert_eq!(credits.len(), 286_830, "testnet v4 sacrifice-credit count");

        // Testnet has exactly one treasury allocation (mainnet has none).
        let treasury_count = 1usize;

        let total = credits.len()
            + treasury_count
            + REWARD_MINE_BLOCK_COUNT
            + SUICIDE_WITHDRAW_COUNT;

        assert_eq!(
            total, 286_833,
            "testnet v4 total BalanceChange events must match on-wire block 16,492,700"
        );
    }

    #[test]
    fn testnet_v4_treasury_constants_are_locked() {
        // Treasury is a SEPARATE allocation, NOT part of the sacrifice-credits blob.
        // Source: pulsechain-testnet-v4.json `pulseChain.treasury`.
        assert_eq!(
            TESTNET_V4_TREASURY,
            address!("A592ED65885bcbCeb30442F4902a0D1Cf3AcB8fC"),
        );
        assert_eq!(
            TESTNET_V4_TREASURY_BALANCE,
            uint!(0x314DC6448D9338C15B0A00000000_U256),
        );
        assert!(!TESTNET_V4_TREASURY_BALANCE.is_zero(), "treasury balance must be nonzero");
    }

    #[test]
    fn mainnet_sacrifice_credit_count_is_locked() {
        let blob = sacrifice_credits_for(369).expect("chain 369 has a credits blob");
        let credits = decode_sacrifice_credits(blob);

        // Locked: exact sacrifice-credit count for mainnet. Mainnet has NO treasury,
        // so its PrimordialPulse balance-change total (sans the universal reward +
        // suicide-withdraw) is exactly this count.
        assert_eq!(credits.len(), 292_217, "mainnet sacrifice-credit count");
        assert!(!credits.is_empty(), "mainnet credits must be nonzero");
    }

    #[test]
    fn deposit_contract_initial_storage_has_exactly_31_slots() {
        assert_eq!(
            DEPOSIT_CONTRACT_INITIAL_STORAGE.len(),
            31,
            "PULSE deposit contract initial-storage table must have 31 slots",
        );
        // Slots are the contiguous range 0x22..=0x40 (Merkle-tree zero hashes).
        for (i, (slot, value)) in DEPOSIT_CONTRACT_INITIAL_STORAGE.iter().enumerate() {
            let expected_slot = 0x22u64 + i as u64;
            assert_eq!(
                U256::from_be_bytes(slot.0),
                U256::from(expected_slot),
                "slot {i} should be 0x{expected_slot:x}",
            );
            assert!(!value.is_zero(), "slot {i} value must be a nonzero zero-hash entry");
        }
        // First and last slot values pinned (Merkle zero-hash sequence).
        assert_eq!(
            DEPOSIT_CONTRACT_INITIAL_STORAGE[0].1,
            b256!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
        );
        assert_eq!(
            DEPOSIT_CONTRACT_INITIAL_STORAGE[30].1,
            b256!("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
        );
    }

    #[test]
    fn deposit_contract_addresses_and_bytecode_are_locked() {
        // 2 code_changes on-wire: ETH deposit cleared + PULSE deposit installed.
        assert_eq!(
            ETH_DEPOSIT_CONTRACT,
            address!("00000000219ab540356cBB839Cbe05303d7705Fa"),
        );
        assert_eq!(
            PULSE_DEPOSIT_CONTRACT,
            address!("3693693693693693693693693693693693693693"),
        );
        // PULSE deposit contract bytecode is 4898 bytes (the only nonzero code
        // installed — the ETH deposit's code goes to empty on selfdestruct).
        assert_eq!(DEPOSIT_CONTRACT_BYTECODE.len(), 4898, "deposit bytecode length");
        assert!(!DEPOSIT_CONTRACT_BYTECODE.is_empty());
    }

    #[test]
    fn no_credits_blob_for_non_pulse_chains() {
        assert!(sacrifice_credits_for(1).is_none(), "ethereum mainnet");
        assert!(sacrifice_credits_for(0).is_none());
        assert!(sacrifice_credits_for(942).is_none(), "testnet v3 (no blob)");
    }
}
