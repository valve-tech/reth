//! `PulseChain` chain specification parser.

use std::sync::Arc;

use eyre::Result;
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;

use reth_pulsechain_forks::chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4};

use crate::spec::PulsechainChainSpec;

/// Chain spec parser for `PulseChain`.
///
/// Recognizes `"pulsechain"` and `"pulsechain-testnet-v4"` by name, and
/// delegates all other values (mainnet, sepolia, holesky, hoodi, dev, JSON
/// file path, or inline JSON) to [`EthereumChainSpecParser`].
///
/// All returned chain specs are wrapped in [`PulsechainChainSpec`], which
/// overrides Shanghai detection for the pre-`PrimordialPulse` Ethereum-replay
/// range while leaving the fork-ID schedule untouched. See `spec.rs` for
/// rationale.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PulsechainChainSpecParser;

impl ChainSpecParser for PulsechainChainSpecParser {
    type ChainSpec = PulsechainChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] =
        &["pulsechain", "pulsechain-testnet-v4", "mainnet", "sepolia", "holesky", "hoodi", "dev"];

    fn parse(s: &str) -> Result<Arc<PulsechainChainSpec>> {
        let inner = match s {
            "pulsechain" => PULSECHAIN.clone(),
            "pulsechain-testnet-v4" => PULSECHAIN_TESTNET_V4.clone(),
            _ => EthereumChainSpecParser::parse(s)?,
        };
        Ok(Arc::new(PulsechainChainSpec::new(inner)))
    }
}
