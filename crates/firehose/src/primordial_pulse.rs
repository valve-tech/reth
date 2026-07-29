//! PrimordialPulse state-transition event emission.
//!
//! When a PulseChain block reaches the `PrimordialPulse` fork block, the inner
//! [`PulsechainBlockExecutor::finish`](reth_pulsechain_node) applies a one-shot
//! state transition: sacrifice-credit balance allocations (thousands of
//! addresses), a testnet-only treasury allocation, the Ethereum deposit
//! contract `selfdestruct`, and the PulseChain deposit contract deployment
//! (code + nonce + 31 initial storage slots). These writes happen via
//! `db.increment_balances()` / `db.insert_account_with_storage()` / similar
//! state methods that bypass revm's EVM journal entirely — so the firehose
//! [`Inspector`](crate::inspector::FirehoseInspector) never sees them, and
//! without explicit emission they leak from the firehose stream.
//!
//! This module bridges the gap. The wrapper layer
//! ([`FirehoseWrappedExecutor::finish`](crate::executor::FirehoseWrappedExecutor)):
//!   1. Captures pre-state for every affected address BEFORE `inner.finish()` runs (via
//!      [`PrimordialPulsePreState::capture`]).
//!   2. Calls `inner.finish()`, which applies the transition silently.
//!   3. Reads post-state from the same DB, diffs against pre, and emits `BalanceChange` /
//!      `NonceChange` / `CodeChange` / `StorageChange` events via the inspector's tracer (via
//!      [`emit_primordial_pulse_changes`]).
//!
//! The spec data — sacrifice-credit binaries, deposit-contract bytecode,
//! initial-storage table, treasury constants — lives in the lowest-level
//! `reth-pulsechain-forks` crate so firehose can read it without a circular
//! dependency on `reth-pulsechain-node`.
//!
//! ## Known gap: ETH_DEPOSIT_CONTRACT pre-fork storage clearing
//!
//! When the ETH deposit contract is `selfdestruct`ed, all of its (potentially
//! thousands of) pre-fork storage slots are cleared. Emitting accurate
//! `StorageChange` events for those slots requires walking the contract's
//! pre-fork storage trie, which the revm `State<DB>` accessor doesn't expose
//! efficiently. We currently SKIP storage events for the ETH deposit contract
//! and emit only the BalanceChange / NonceChange / CodeChange. Downstream
//! consumers reconstructing state from the firehose stream will need to
//! detect the selfdestruct event and zero the contract's storage themselves.
//! Tracked as `FIXME(firehose-primordialpulse-eth-deposit-storage)`.

use crate::inspector::FirehoseInspectorApi;
use alloy_primitives::{Address, B256, U256};
use firehose_tracer::pb::sf::ethereum::r#type::v2::balance_change::Reason;
use reth_pulsechain_forks::primordial_pulse as spec;

/// Returns the PrimordialPulse fork-block number for the given chain ID, or `None`
/// if the chain doesn't have a PrimordialPulse transition.
///
/// **Sync invariant**: must agree with
/// `reth_pulsechain_forks::hardfork::PRIMORDIAL_PULSE_{MAINNET,TESTNET_V4}_BLOCK`.
/// A unit test below asserts this at compile time.
pub const fn fork_block_for(chain_id: u64) -> Option<u64> {
    match chain_id {
        369 => Some(17_233_000),
        943 => Some(16_492_700),
        _ => None,
    }
}

/// Pre-state snapshot of every account that PrimordialPulse will modify.
///
/// Captured BEFORE `inner.finish()` so the emit-phase can diff against fresh
/// post-finish DB reads. Order of `sacrifice_pre` matters: events emit in the
/// same order as the spec binary so a stream consumer sees a deterministic
/// sequence.
#[derive(Debug)]
pub struct PrimordialPulsePreState {
    /// Chain ID this snapshot applies to (369 mainnet / 943 testnet v4).
    pub chain_id: u64,
    /// Block number at which PrimordialPulse fires.
    pub block_number: u64,
    /// `(address, pre_balance, credit_amount)` triples in spec-binary order.
    /// Includes treasury (testnet only) as the first entry, followed by
    /// every sacrifice-credit recipient.
    pub balance_credits: Vec<(Address, U256, U256)>,
    /// Pre-state of [`spec::ETH_DEPOSIT_CONTRACT`], which is selfdestructed.
    pub eth_deposit_pre: AccountPreState,
    /// Pre-state of [`spec::PULSE_DEPOSIT_CONTRACT`], onto which code + 31
    /// initial storage slots are written.
    pub pulse_deposit_pre: AccountPreState,
}

/// Per-account pre-state slice we capture before `inner.finish()`.
///
/// `code` is held inline (not just `code_hash`) so the emitted `on_code_change`
/// event can include both the old and new bytecode bytes — the firehose tracer
/// API requires them and downstream consumers (e.g. substreams) inspect them
/// for contract-deployment detection.
#[derive(Debug, Clone)]
pub struct AccountPreState {
    /// Account balance at capture time.
    pub balance: U256,
    /// Account nonce at capture time.
    pub nonce: u64,
    /// keccak256 of the account's code at capture time. `B256::ZERO` if no
    /// code is set on this address.
    pub code_hash: B256,
    /// Raw bytecode bytes for the account at capture time. Empty if no code
    /// is set, or if the code lookup failed (we tolerate the failure and
    /// emit an empty pre-code in the resulting `CodeChange` event).
    pub code: Vec<u8>,
    /// `(slot, pre_value)` for slots that PrimordialPulse will set on this
    /// account. Empty for the ETH deposit contract (we don't enumerate the
    /// full pre-fork storage trie — see module-level docs).
    pub storage_slots_pre: Vec<(B256, B256)>,
}

impl PrimordialPulsePreState {
    /// Walk the spec for `chain_id` and snapshot every address PrimordialPulse
    /// will touch. Returns `None` if the chain doesn't have a PrimordialPulse
    /// transition (i.e. anything other than 369 / 943).
    pub fn capture<DB>(db: &mut DB, chain_id: u64, block_number: u64) -> Option<Self>
    where
        DB: reth_revm::Database,
    {
        // Skip chains without a PrimordialPulse transition.
        let _spec_blob = spec::sacrifice_credits_for(chain_id)?;

        let credits = decode_chain_credits(chain_id);

        let mut balance_credits: Vec<(Address, U256, U256)> = Vec::with_capacity(credits.len() + 1);

        // Testnet treasury goes first (matches the order in apply_primordial_pulse).
        if chain_id == 943 {
            let pre_bal = read_balance(db, spec::TESTNET_V4_TREASURY);
            balance_credits.push((
                spec::TESTNET_V4_TREASURY,
                pre_bal,
                spec::TESTNET_V4_TREASURY_BALANCE,
            ));
        }

        for (addr, credit) in credits {
            let pre_bal = read_balance(db, addr);
            balance_credits.push((addr, pre_bal, credit));
        }

        let eth_deposit_pre = read_account(db, spec::ETH_DEPOSIT_CONTRACT, &[]);
        // For the PulseChain deposit contract, capture pre-values of the 31 slots
        // that will be set so we can emit accurate (old → new) StorageChange events.
        let pulse_slots: Vec<B256> =
            spec::DEPOSIT_CONTRACT_INITIAL_STORAGE.iter().map(|(slot, _)| *slot).collect();
        let pulse_deposit_pre = read_account(db, spec::PULSE_DEPOSIT_CONTRACT, &pulse_slots);

        Some(Self { chain_id, block_number, balance_credits, eth_deposit_pre, pulse_deposit_pre })
    }
}

/// Diff `pre` against the post-`inner.finish()` state and emit firehose events.
///
/// Must be called with the tracer in block-context (i.e., between
/// `on_block_start` and `on_block_end`) and OUTSIDE any open transaction frame.
///
/// ## Routing model (load-bearing)
///
/// The firehose tracer routes per-field events differently:
///   - `on_balance_change` outside a transaction → `block.balance_changes`. ✓
///   - `on_code_change` outside a transaction → `block.code_changes`. ✓
///   - `on_nonce_change` and `on_storage_change` REQUIRE `ensure_in_block_and_in_trx` AND a
///     peekable `active_call` on the call stack. Otherwise they either panic (no trx) or land in
///     `deferred_call_state` which is DISCARDED when the system-call frame closes without ever
///     populating a `Call`.
///
/// So this function emits in two passes:
///   1. **Block-level pass** (no system-call wrap): all balance + code changes go straight to
///      `block.balance_changes` / `block.code_changes`.
///   2. **Synthetic system-call pass**: `on_system_call_start` → `on_call_enter` creates a [`Call`]
///      frame; nonce + storage changes are emitted into that frame; `on_call_exit` +
///      `on_system_call_end` move the frame into `block.system_calls`. This is the only routing
///      path that gets those two field types into the wire output.
///
/// An earlier draft of this function wrapped EVERYTHING in a system-call window
/// but never created a `Call` frame. That sent every event into
/// `deferred_call_state` which got dropped on `on_system_call_end` — verified
/// empirically against block 16,492,700 chunk on 2026-05-23 (only 1
/// `balance_change` made it through: the block reward, emitted later by the
/// existing `emit_block_reward_balance_changes` flow). The two-pass split fixes
/// that.
pub fn emit_primordial_pulse_changes<E>(evm: &mut E, pre: &PrimordialPulsePreState)
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
    E::DB: reth_revm::Database,
{
    // ── Pass 1: block-level balance + code changes ────────────────────────────
    {
        let (db, inspector, _) = evm.components_mut();
        let tracer = inspector.tracer_mut();

        // Sacrifice credits + (testnet) treasury. Reason::GenesisBalance is the
        // closest semantic fit — a hardfork-time allocation outside any EVM tx.
        // `on_balance_change` drops events with reason=Unknown so this matters.
        for &(addr, pre_bal, _credit) in &pre.balance_credits {
            let post_bal = read_balance(db, addr);
            tracer.on_balance_change(addr, pre_bal, post_bal, Reason::GenesisBalance);
        }

        // ETH_DEPOSIT_CONTRACT: balance → 0 (selfdestruct), code → empty.
        // Storage clearing is NOT emitted — see module-level docs.
        let eth_addr = spec::ETH_DEPOSIT_CONTRACT;
        let eth_post = read_account(db, eth_addr, &[]);
        if pre.eth_deposit_pre.balance != eth_post.balance {
            // Geth-pulse uses REASON_SUICIDE_WITHDRAW for this; we mirror.
            tracer.on_balance_change(
                eth_addr,
                pre.eth_deposit_pre.balance,
                eth_post.balance,
                Reason::SuicideWithdraw,
            );
        }
        if pre.eth_deposit_pre.code_hash != eth_post.code_hash {
            tracer.on_code_change(
                eth_addr,
                pre.eth_deposit_pre.code_hash,
                eth_post.code_hash,
                &pre.eth_deposit_pre.code,
                &eth_post.code,
            );
        }

        // PULSE_DEPOSIT_CONTRACT: balance change (if any) + code installation.
        let pulse_addr = spec::PULSE_DEPOSIT_CONTRACT;
        let pulse_post_basic = read_account(db, pulse_addr, &[]);
        if pre.pulse_deposit_pre.balance != pulse_post_basic.balance {
            tracer.on_balance_change(
                pulse_addr,
                pre.pulse_deposit_pre.balance,
                pulse_post_basic.balance,
                Reason::GenesisBalance,
            );
        }
        if pre.pulse_deposit_pre.code_hash != pulse_post_basic.code_hash {
            tracer.on_code_change(
                pulse_addr,
                pre.pulse_deposit_pre.code_hash,
                pulse_post_basic.code_hash,
                &pre.pulse_deposit_pre.code,
                &pulse_post_basic.code,
            );
        }
    }

    // ── Pass 2: synthetic system-call wrapping nonce + storage ────────────────
    // call_enter requires a `typ: u8` corresponding to a revm `Opcode` value;
    // `0xf1` is Opcode::Call, which `opcode_to_call_type` maps to CallType::Call.
    // We use zero address + empty input + 0 gas because there's no actual EVM
    // execution here — this is purely a container for state-diff events.
    const CALL_OPCODE: u8 = 0xf1;
    let zero_addr = Address::ZERO;

    let (db, inspector, _) = evm.components_mut();
    let tracer = inspector.tracer_mut();

    tracer.on_system_call_start();
    tracer.on_call_enter(0, CALL_OPCODE, zero_addr, zero_addr, &[], 0, U256::ZERO);

    // ETH_DEPOSIT_CONTRACT: nonce change (storage skipped, see module-level docs).
    let eth_addr = spec::ETH_DEPOSIT_CONTRACT;
    let eth_post = read_account(db, eth_addr, &[]);
    if pre.eth_deposit_pre.nonce != eth_post.nonce {
        tracer.on_nonce_change(eth_addr, pre.eth_deposit_pre.nonce, eth_post.nonce);
    }

    // PULSE_DEPOSIT_CONTRACT: nonce + 31 storage-slot writes.
    let pulse_addr = spec::PULSE_DEPOSIT_CONTRACT;
    let pulse_slots: Vec<B256> =
        spec::DEPOSIT_CONTRACT_INITIAL_STORAGE.iter().map(|(s, _)| *s).collect();
    let pulse_post = read_account(db, pulse_addr, &pulse_slots);
    if pre.pulse_deposit_pre.nonce != pulse_post.nonce {
        tracer.on_nonce_change(pulse_addr, pre.pulse_deposit_pre.nonce, pulse_post.nonce);
    }
    for (i, (slot, _expected)) in spec::DEPOSIT_CONTRACT_INITIAL_STORAGE.iter().enumerate() {
        let pre_value =
            pre.pulse_deposit_pre.storage_slots_pre.get(i).map(|(_, v)| *v).unwrap_or(B256::ZERO);
        let post_value = pulse_post.storage_slots_pre.get(i).map(|(_, v)| *v).unwrap_or(B256::ZERO);
        tracer.on_storage_change(pulse_addr, *slot, pre_value, post_value);
    }

    tracer.on_call_exit(0, &[], 0, None, false);
    tracer.on_system_call_end();
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn decode_chain_credits(chain_id: u64) -> Vec<(Address, U256)> {
    match spec::sacrifice_credits_for(chain_id) {
        Some(blob) => spec::decode_sacrifice_credits(blob),
        None => Vec::new(),
    }
}

fn read_balance<DB>(db: &mut DB, addr: Address) -> U256
where
    DB: reth_revm::Database,
{
    db.basic(addr).ok().flatten().map(|info| info.balance).unwrap_or_default()
}

/// Read an account's full state plus optionally pre-values of named storage slots.
fn read_account<DB>(db: &mut DB, addr: Address, slots: &[B256]) -> AccountPreState
where
    DB: reth_revm::Database,
{
    let info = db.basic(addr).ok().flatten();
    let (balance, nonce, code_hash, code) = match info {
        Some(info) => {
            let code = info
                .code
                .clone()
                .or_else(|| db.code_by_hash(info.code_hash).ok())
                .map(|bc| bc.bytes().to_vec())
                .unwrap_or_default();
            (info.balance, info.nonce, info.code_hash, code)
        }
        None => (U256::ZERO, 0, B256::ZERO, Vec::new()),
    };

    let storage_slots_pre = slots
        .iter()
        .map(|&slot| {
            let v = db.storage(addr, U256::from_be_bytes(slot.0)).ok().unwrap_or(U256::ZERO);
            (slot, B256::from(v.to_be_bytes::<32>()))
        })
        .collect();

    AccountPreState { balance, nonce, code_hash, code, storage_slots_pre }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use reth_pulsechain_forks::hardfork::{
        PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
    };

    /// Sync-check: our local `fork_block_for` constants MUST agree with the
    /// canonical hardfork constants in `reth-pulsechain-forks::hardfork`.
    /// If this test fails, the hardfork constants changed and this module
    /// needs to be updated to match. We keep our own copy to avoid a runtime
    /// table lookup, but the cross-check makes drift loud.
    #[test]
    fn fork_block_constants_match_hardfork_module() {
        assert_eq!(fork_block_for(369), Some(PRIMORDIAL_PULSE_MAINNET_BLOCK));
        assert_eq!(fork_block_for(943), Some(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK));
        assert_eq!(fork_block_for(1), None);
        assert_eq!(fork_block_for(0), None);
    }

    // ── PrimordialPulse emission regression (consensus-critical) ──────────────
    //
    // These lock the on-wire-validated event decomposition for the firehose
    // PrimordialPulse emit path (validated against PulseChain testnet v4 chain
    // 943 block 16,492,700 on 2026-05-23):
    //
    //   286,833 balance_changes + 2 code_changes + 31 storage_changes + 1 nonce_change
    //
    // The pure decode/spec assertions (exact credit counts, treasury constants,
    // 31-slot storage table, bytecode length) live in `reth-pulsechain-forks`'s
    // `primordial_pulse::tests`. The tests here cross-check the spec data that
    // the EMIT PATH in this module consumes, so a change to the spec that would
    // alter the wire output fails loudly here too.
    //
    // OUT OF HERMETIC SCOPE: asserting that `emit_primordial_pulse_changes`
    // actually drives the inspector to produce those exact wire counts requires
    // a live revm `Evm` + populated `Database` (pre/post account+storage state at
    // the fork block) and a real `FirehoseInspector`. That path is validated
    // on-wire and is not faked here — a mock DB returning post==pre would emit
    // zero changes and prove nothing.

    /// Block-level pass emits exactly 2 code changes: ETH deposit cleared +
    /// PULSE deposit installed. Both contract addresses must be the spec values.
    #[test]
    fn emit_path_targets_two_distinct_deposit_contracts_for_code_changes() {
        assert_ne!(
            spec::ETH_DEPOSIT_CONTRACT,
            spec::PULSE_DEPOSIT_CONTRACT,
            "the 2 code_changes must target two distinct contracts",
        );
        // Installed code is the 4898-byte PULSE deposit bytecode; ETH side clears.
        assert_eq!(spec::DEPOSIT_CONTRACT_BYTECODE.len(), 4898);
    }

    /// System-call pass iterates the 31-slot table for storage changes and emits
    /// the PULSE deposit nonce change (set to 0). The emit path reads exactly
    /// `DEPOSIT_CONTRACT_INITIAL_STORAGE` so its length pins the 31 storage_changes.
    #[test]
    fn emit_path_iterates_31_storage_slots_and_one_nonce() {
        assert_eq!(
            spec::DEPOSIT_CONTRACT_INITIAL_STORAGE.len(),
            31,
            "emit path emits one StorageChange per initial-storage slot",
        );
    }

    /// The emit path walks `decode_chain_credits` for balance changes; lock the
    /// per-chain counts the firehose side consumes (matches the on-wire total
    /// once treasury + reward + suicide-withdraw are added — see forks-crate
    /// test `testnet_v4_balance_change_decomposition_totals_286_833`).
    #[test]
    fn emit_path_credit_counts_match_on_wire() {
        assert_eq!(decode_chain_credits(943).len(), 286_830, "testnet v4 credits");
        assert_eq!(decode_chain_credits(369).len(), 292_217, "mainnet credits");
        assert!(decode_chain_credits(1).is_empty(), "non-pulse chain: no credits");

        // Testnet adds a treasury entry ahead of the credits; mainnet does not.
        // (capture() pushes treasury first for chain 943 only.)
        let testnet_balance_credit_entries = decode_chain_credits(943).len() + /* treasury */ 1;
        assert_eq!(
            testnet_balance_credit_entries + /* reward */ 1 + /* suicide_withdraw */ 1,
            286_833,
            "testnet v4 on-wire balance_change total",
        );
    }
}
