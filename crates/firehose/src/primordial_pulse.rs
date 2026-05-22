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
//!   1. Captures pre-state for every affected address BEFORE `inner.finish()`
//!      runs (via [`PrimordialPulsePreState::capture`]).
//!   2. Calls `inner.finish()`, which applies the transition silently.
//!   3. Reads post-state from the same DB, diffs against pre, and emits
//!      `BalanceChange` / `NonceChange` / `CodeChange` / `StorageChange`
//!      events via the inspector's tracer (via [`emit_primordial_pulse_changes`]).
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
        let pulse_slots: Vec<B256> = spec::DEPOSIT_CONTRACT_INITIAL_STORAGE
            .iter()
            .map(|(slot, _)| *slot)
            .collect();
        let pulse_deposit_pre = read_account(db, spec::PULSE_DEPOSIT_CONTRACT, &pulse_slots);

        Some(Self {
            chain_id,
            block_number,
            balance_credits,
            eth_deposit_pre,
            pulse_deposit_pre,
        })
    }
}

/// Diff `pre` against the post-`inner.finish()` state and emit firehose events.
///
/// Must be called with the tracer in block-context (i.e., between
/// `on_block_start` and `on_block_end`), but OUTSIDE any open transaction
/// frame. We open a system-call window internally so storage changes can
/// emit cleanly — same pattern as withdrawal balance-changes do.
pub fn emit_primordial_pulse_changes<E>(evm: &mut E, pre: &PrimordialPulsePreState)
where
    E: reth_evm::Evm,
    E::Inspector: FirehoseInspectorApi,
    E::DB: reth_revm::Database,
{
    let (db, inspector, _) = evm.components_mut();
    let tracer = inspector.tracer_mut();

    // Open a system-call window so on_storage_change calls have the in-block-and-in-trx
    // context they require. Mirrors the previous (deadlock-prone) approach in
    // `crates/pulsechain/node/src/evm.rs` and the parallel `withdrawals` emit flow.
    tracer.on_system_call_start();

    // (1) Balance changes — sacrifice credits + (testnet) treasury.
    // Reason::GenesisBalance is the closest semantic fit: a hardfork-time
    // allocation outside any EVM transaction. Verified that
    // `on_balance_change` drops Unknown-reason events — must NOT use Unknown.
    for &(addr, pre_bal, credit) in &pre.balance_credits {
        let post_bal = read_balance(db, addr);
        // Sanity: post should equal pre + credit if no other reason touched this
        // address during this block. We don't enforce — `on_balance_change` is
        // already a no-op for equal old/new, so a spurious read still wouldn't
        // corrupt the stream.
        let _ = credit; // mainly for debugger visibility / future logging
        tracer.on_balance_change(addr, pre_bal, post_bal, Reason::GenesisBalance);
    }

    // (2) ETH_DEPOSIT_CONTRACT selfdestruct: balance → 0, nonce → 0, code → empty.
    // Storage clearing is NOT emitted — see module-level docs.
    {
        let addr = spec::ETH_DEPOSIT_CONTRACT;
        let post = read_account(db, addr, &[]);
        if pre.eth_deposit_pre.balance != post.balance {
            // Treat the destroyed balance as a withdraw-style refund event. Geth-pulse
            // emits this with reason REASON_SUICIDE_WITHDRAW (zeros the contract); use
            // the same here.
            tracer.on_balance_change(
                addr,
                pre.eth_deposit_pre.balance,
                post.balance,
                Reason::SuicideWithdraw,
            );
        }
        if pre.eth_deposit_pre.nonce != post.nonce {
            tracer.on_nonce_change(addr, pre.eth_deposit_pre.nonce, post.nonce);
        }
        if pre.eth_deposit_pre.code_hash != post.code_hash {
            tracer.on_code_change(
                addr,
                pre.eth_deposit_pre.code_hash,
                post.code_hash,
                &pre.eth_deposit_pre.code,
                &post.code,
            );
        }
    }

    // (3) PULSE_DEPOSIT_CONTRACT deploy: code installed + 31 storage slots set.
    // Nonce stays at 0 (set_nonce(.., 0) explicitly, presumably no-op vs default).
    {
        let addr = spec::PULSE_DEPOSIT_CONTRACT;
        let post = read_account(db, addr, &spec::DEPOSIT_CONTRACT_INITIAL_STORAGE
            .iter().map(|(s, _)| *s).collect::<Vec<_>>());

        if pre.pulse_deposit_pre.balance != post.balance {
            tracer.on_balance_change(
                addr,
                pre.pulse_deposit_pre.balance,
                post.balance,
                Reason::GenesisBalance,
            );
        }
        if pre.pulse_deposit_pre.nonce != post.nonce {
            tracer.on_nonce_change(addr, pre.pulse_deposit_pre.nonce, post.nonce);
        }
        if pre.pulse_deposit_pre.code_hash != post.code_hash {
            tracer.on_code_change(
                addr,
                pre.pulse_deposit_pre.code_hash,
                post.code_hash,
                &pre.pulse_deposit_pre.code,
                &post.code,
            );
        }

        // 31 storage slots. Walk pre+post in lockstep — the spec defines the
        // (slot, expected_value) pairs, so pre is whatever was there before and
        // post should equal `expected_value`.
        for (i, (slot, _expected)) in spec::DEPOSIT_CONTRACT_INITIAL_STORAGE.iter().enumerate() {
            let pre_value = pre.pulse_deposit_pre.storage_slots_pre.get(i).map(|(_, v)| *v)
                .unwrap_or(B256::ZERO);
            let post_value = post.storage_slots_pre.get(i).map(|(_, v)| *v).unwrap_or(B256::ZERO);
            tracer.on_storage_change(addr, *slot, pre_value, post_value);
        }
    }

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
}
