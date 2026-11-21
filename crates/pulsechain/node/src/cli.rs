//! `PulseChain` chain specification parser.

use std::sync::Arc;

use eyre::Result;
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;

use reth_pulsechain_forks::chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4};

use crate::{fork_check::check_fork_schedule, spec::PulsechainChainSpec};

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
        check_fork_schedule(&inner)?;
        Ok(Arc::new(PulsechainChainSpec::new(inner)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_pulsechain_specs_parse() {
        for name in ["pulsechain", "pulsechain-testnet-v4"] {
            PulsechainChainSpecParser::parse(name).unwrap();
        }
    }

    #[test]
    fn ethereum_specs_parse() {
        for name in ["mainnet", "sepolia", "holesky", "hoodi", "dev"] {
            PulsechainChainSpecParser::parse(name).unwrap();
        }
    }

    fn genesis_json(chain_id: u64) -> String {
        format!(
            r#"{{"config":{{"chainId":{chain_id},"homesteadBlock":0,"cancunTime":0}},"gasLimit":"0x1c9c380","difficulty":"0x1","alloc":{{}}}}"#
        )
    }

    /// A genesis file for 369 or 943 has no `PrimordialPulse` fork, so the node refuses it.
    #[test]
    fn pulsechain_genesis_file_without_primordial_pulse_is_refused() {
        for chain_id in [369, 943] {
            let err = PulsechainChainSpecParser::parse(&genesis_json(chain_id)).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "chain {chain_id} is a PulseChain network, but its chain spec has no \
                     PrimordialPulse fork"
                )
            );
        }
    }

    /// A genesis file for another chain ID is unaffected, even with Cancun.
    #[test]
    fn other_genesis_file_is_unaffected() {
        let spec = PulsechainChainSpecParser::parse(&genesis_json(12_345)).unwrap();
        assert_eq!(spec.inner.chain.id(), 12_345);
    }
}
