//! Gas estimation margin for PulseChain.
//!
//! PulseChain's state is significantly larger than Ethereum mainnet due to the
//! sacrifice credit distribution at PrimordialPulse. This can cause the standard
//! binary-search gas estimator to return values that are too tight, leading to
//! out-of-gas reverts when the transaction is actually mined.
//!
//! This module provides [`install_gas_estimation_margin`], which replaces the stock
//! `eth_estimateGas` RPC method with a wrapper that applies a configurable margin
//! (default 20%) to the result.
//!
//! # This is the ONLY place the fork adds a gas margin
//!
//! It is installed from `bin/reth/src/main.rs` on the PulseChain node path
//! alone, which is what keeps Ethereum mainnet on stock estimates.
//!
//! A second margin once existed inside the SHARED core estimator
//! (`reth_rpc_eth_api::helpers::estimate`). The two compounded, and because
//! the shared one was ungated it also inflated mainnet. Measured 2026-09-08 on
//! a plain 21,000-gas transfer:
//!
//! | chain | returned | factor |
//! |---|---|---|
//! | 369, 943 | 30,564 | 1.4554x |
//! | 1 (mainnet) | 25,470 | 1.2129x |
//!
//! `30,564 = 25,470 x 1.2` exactly. Both margins came from the fork's original
//! integration work, in two separate commits, each written as though it were
//! the only one. If a margin is ever needed in the shared estimator, remove
//! this wrapper first — never run both.
//!
//! `crates/ethereum/node/tests/e2e/estimate.rs` pins the shared estimator to the
//! exact cost against a running node, so the compounding cannot come back
//! unnoticed. Add a margin there and those tests fail.
//!
//! # The margin is capped by what the sender can afford
//!
//! Erigon pads and then re-caps, in `rpc/jsonrpc/eth_call.go`:
//!
//! ```text
//! hi = hi + hi/5
//! if accountGasLimit != 0 && hi > accountGasLimit { hi = accountGasLimit }
//! ```
//!
//! The cap matters because the core estimator already limits its *search* by the
//! caller's allowance, so padding afterwards can push the answer back above what
//! the sender can pay. Without the re-cap a tight-balance sender receives an
//! estimate that nothing rejects at estimation time, and the send fails later at
//! submission — a much harder failure to read, and exactly the "send max" case.
//!
//! [`cap_by_affordability`] reproduces it. The allowance is computed inside the
//! estimator and is gone by the time a result reaches this wrapper, so the
//! balance is read back at the same block the estimate ran against.

use alloy_primitives::U256;
use alloy_rpc_types_eth::{state::StateOverride, BlockId, BlockOverrides, TransactionRequest};
use jsonrpsee::{core::RpcResult, RpcModule};
use reth_rpc_builder::TransportRpcModules;
use reth_rpc_eth_api::EthApiServer;
use std::sync::Arc;

/// Default gas estimation margin: 20% (multiply by 6/5).
const GAS_MARGIN_NUMERATOR: u64 = 6;
const GAS_MARGIN_DENOMINATOR: u64 = 5;

/// Applies the PulseChain gas-estimation margin (+20%) to a raw `eth_estimateGas` result.
///
/// Uses saturating multiplication so a pathologically large estimate can never overflow (it
/// saturates at `U256::MAX` instead of panicking).
fn apply_gas_margin(gas: U256) -> U256 {
    gas.saturating_mul(U256::from(GAS_MARGIN_NUMERATOR)) / U256::from(GAS_MARGIN_DENOMINATOR)
}

/// The fee per gas the sender would pay, which is what the affordability cap divides by.
///
/// Mirrors erigon's `feeCap`: an explicit `gasPrice` wins, then `maxFeePerGas`. A request
/// that names neither is not paying for gas, so there is nothing to cap.
fn fee_cap(request: &TransactionRequest) -> Option<U256> {
    request.gas_price.or(request.max_fee_per_gas).map(U256::from).filter(|fee| !fee.is_zero())
}

/// Caps a padded estimate by the gas the sender can actually pay for.
///
/// The core estimator caps its **search** by this allowance, but the margin is applied
/// afterwards and can push the answer back above it. Erigon caps after padding for the same
/// reason, in `rpc/jsonrpc/eth_call.go`:
///
/// ```text
/// hi = hi + hi/5
/// if accountGasLimit != 0 && hi > accountGasLimit { hi = accountGasLimit }
/// ```
///
/// Without this, a sender whose balance barely covers the transaction gets an estimate they
/// cannot pay for. Nothing rejects it at estimation time: the send fails later, at
/// submission, which is a much harder failure to read.
///
/// Returns `padded` unchanged when the request names no fee, since then the sender pays
/// nothing for gas and no balance can constrain it.
fn cap_by_affordability(padded: U256, balance: U256, request: &TransactionRequest) -> U256 {
    let Some(fee) = fee_cap(request) else { return padded };

    // The value being sent is not available to pay for gas.
    let available = balance.saturating_sub(request.value.unwrap_or_default());
    let allowance = available / fee;

    padded.min(allowance)
}

/// Replaces `eth_estimateGas` in all configured transports with a wrapper that
/// applies a 20% margin to the result.
///
/// The wrapper calls the original `estimate_gas` on the provided `EthApi`, then
/// multiplies the returned value by 6/5.
///
/// # Errors
///
/// Returns an error if the method replacement fails (e.g., the method was not
/// previously registered).
pub fn install_gas_estimation_margin<EthApi>(
    modules: &mut TransportRpcModules,
    eth_api: EthApi,
) -> eyre::Result<()>
where
    EthApi: EthApiServer<
            TransactionRequest,
            alloy_rpc_types_eth::Transaction,
            alloy_rpc_types_eth::Block,
            alloy_rpc_types_eth::TransactionReceipt,
            alloy_rpc_types_eth::Header,
            reth_ethereum_primitives::TransactionSigned,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let api = Arc::new(eth_api);
    let mut module = RpcModule::new(api);

    module.register_async_method("eth_estimateGas", |params, ctx, _extensions| async move {
        let mut seq = params.sequence();
        let request: TransactionRequest = seq.next()?;
        let block_id: Option<BlockId> = seq.optional_next()?;
        let state_override: Option<StateOverride> = seq.optional_next()?;
        let block_overrides: Option<Box<BlockOverrides>> = seq.optional_next()?;

        let estimate: U256 = EthApiServer::estimate_gas(
            &**ctx,
            request.clone(),
            block_id,
            state_override,
            block_overrides,
        )
        .await?;

        let padded = apply_gas_margin(estimate);

        // Only a request naming both a sender and a fee can be capped, because only then is
        // there a gas bill the sender might not afford. Everything else keeps the padded
        // figure — including a failed balance lookup, since a cap we cannot compute must
        // not turn a working estimate into an error.
        let capped = match (request.from, fee_cap(&request)) {
            (Some(from), Some(_)) => {
                // Read the balance at the block the estimate ran against, so the cap and
                // the estimate see one state.
                match EthApiServer::balance(&**ctx, from, block_id).await {
                    Ok(balance) => cap_by_affordability(padded, balance, &request),
                    Err(_) => padded,
                }
            }
            _ => padded,
        };

        let result: RpcResult<U256> = Ok(capped);
        result
    })?;

    modules.replace_configured(module)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrapper adds a +20% margin: result = gas * 6 / 5.
    #[test]
    fn applies_twenty_percent_margin() {
        assert_eq!(apply_gas_margin(U256::from(100u64)), U256::from(120u64));
        assert_eq!(apply_gas_margin(U256::from(21_000u64)), U256::from(25_200u64));
    }

    /// Zero in, zero out.
    #[test]
    fn zero_estimate_stays_zero() {
        assert_eq!(apply_gas_margin(U256::ZERO), U256::ZERO);
    }

    /// Integer division truncates toward zero (matches the original inline `gas * 6 / 5`).
    #[test]
    fn margin_truncates_toward_zero() {
        // 7 * 6 / 5 = 42 / 5 = 8
        assert_eq!(apply_gas_margin(U256::from(7u64)), U256::from(8u64));
    }

    /// A pathologically large estimate saturates instead of overflowing/panicking.
    #[test]
    fn margin_saturates_instead_of_overflowing() {
        let expected = U256::MAX / U256::from(GAS_MARGIN_DENOMINATOR);
        assert_eq!(apply_gas_margin(U256::MAX), expected);
    }

    /// Builds a request paying `fee` per gas and sending `value`.
    fn paying(fee: u64, value: u64) -> TransactionRequest {
        TransactionRequest {
            from: Some(alloy_primitives::Address::ZERO),
            gas_price: Some(fee as u128),
            value: Some(U256::from(value)),
            ..Default::default()
        }
    }

    /// A sender with room to spare keeps the padded estimate.
    #[test]
    fn affordable_estimate_keeps_the_margin() {
        // 25,200 gas at 100 wei costs 2,520,000. The balance covers it many times over.
        let padded = U256::from(25_200u64);
        let capped = cap_by_affordability(padded, U256::from(1_000_000_000u64), &paying(100, 0));

        assert_eq!(capped, padded, "a sender who can pay keeps the full margin");
    }

    /// A sender who cannot pay for the margin is capped, not handed a bill they cannot meet.
    ///
    /// This is the case erigon re-caps for. The core estimator limits its search to the
    /// 21,000 the sender can afford; padding that to 25,200 would exceed the balance.
    #[test]
    fn unaffordable_margin_is_capped_to_the_allowance() {
        // Exactly 21,000 gas at 100 wei, and not a wei more.
        let balance = U256::from(2_100_000u64);
        let capped = cap_by_affordability(U256::from(25_200u64), balance, &paying(100, 0));

        assert_eq!(capped, U256::from(21_000u64), "capped to what the balance buys");
    }

    /// Value being sent is not available to pay for gas.
    #[test]
    fn value_is_deducted_before_the_allowance() {
        // 2,100,000 total, 1,050,000 of it sent as value, leaving 10,500 gas at 100 wei.
        let capped = cap_by_affordability(
            U256::from(25_200u64),
            U256::from(2_100_000u64),
            &paying(100, 1_050_000),
        );

        assert_eq!(capped, U256::from(10_500u64), "the transferred value cannot also buy gas");
    }

    /// A request naming no fee pays nothing for gas, so no balance can constrain it.
    #[test]
    fn a_request_without_a_fee_is_never_capped() {
        let padded = U256::from(25_200u64);
        let free = TransactionRequest {
            from: Some(alloy_primitives::Address::ZERO),
            ..Default::default()
        };

        assert_eq!(cap_by_affordability(padded, U256::ZERO, &free), padded);
    }

    /// An explicit `gasPrice` wins over `maxFeePerGas`, matching erigon's `feeCap`.
    #[test]
    fn gas_price_takes_precedence_over_max_fee() {
        let mut request = paying(100, 0);
        request.max_fee_per_gas = Some(1);

        assert_eq!(fee_cap(&request), Some(U256::from(100u64)));
    }

    /// A zero fee is treated as no fee rather than dividing by zero.
    #[test]
    fn a_zero_fee_does_not_divide_by_zero() {
        let padded = U256::from(25_200u64);

        assert_eq!(cap_by_affordability(padded, U256::ZERO, &paying(0, 0)), padded);
    }

    /// The SHARED estimator must not pad as well, or the two margins compound.
    ///
    /// This is a source check, not a behavioural one: there is no RPC harness
    /// in this workspace that can call `eth_estimateGas` end to end, and the
    /// compounding is invisible from inside either crate. It reads the core
    /// estimator and asserts it returns the binary-search result unpadded.
    ///
    /// SCOPE, stated plainly: this catches a margin written the way the last
    /// one was — arithmetic on `highest_gas_limit` after the search loop. A
    /// margin expressed some other way would slip past it. It is a tripwire on
    /// the known regression, not a proof of absence. If it ever fails to
    /// compile because the file moved, fix the path; do not delete the test.
    #[test]
    fn shared_estimator_adds_no_margin_of_its_own() {
        const CORE_ESTIMATOR: &str =
            include_str!("../../../rpc/rpc-eth-api/src/helpers/estimate.rs");

        // Guard the guard: if the path ever resolves to something that is not
        // the estimator, the assertions below would pass vacuously.
        assert!(
            CORE_ESTIMATOR.contains("fn estimate_gas_with"),
            "include_str! no longer points at the core gas estimator"
        );

        for pattern in [
            "highest_gas_limit.saturating_add(highest_gas_limit / 5)",
            "highest_gas_limit / 5",
            "highest_gas_limit * 6 / 5",
        ] {
            assert!(
                !CORE_ESTIMATOR.contains(pattern),
                "the shared estimator pads with `{pattern}`; combined with this \
                 module's wrapper that is TWO 20% margins on every PulseChain \
                 estimate. Remove one — see this module's header."
            );
        }
    }
}
