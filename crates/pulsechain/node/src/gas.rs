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

        let estimate: RpcResult<U256> =
            EthApiServer::estimate_gas(&**ctx, request, block_id, state_override, block_overrides)
                .await;

        estimate.map(apply_gas_margin)
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
}
