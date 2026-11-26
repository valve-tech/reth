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

/// `PulseChain` p2p flags, for the binary to flatten into its own arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::Args)]
pub struct PulsechainSnap1Args {
    /// Serve `snap/1` to light clients such as reth-lite.
    ///
    /// Off by default. Accepts `--pulsechain.snap1`, `--pulsechain.snap1=<value>` and
    /// `RETH_PULSECHAIN_SNAP1=<value>`, where the value is `true|false`, `1|0`, `yes|no` or
    /// `on|off`.
    #[arg(
        long = "pulsechain.snap1",
        env = "RETH_PULSECHAIN_SNAP1",
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub snap1: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        snap1: PulsechainSnap1Args,
    }

    /// Held by every test whose result depends on `RETH_PULSECHAIN_SNAP1`.
    static SNAP1_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn snap1_flag_defaults_off_and_turns_on() {
        use clap::Parser;
        let _env = SNAP1_ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!Cli::try_parse_from(["x"]).unwrap().snap1.snap1);
        assert!(Cli::try_parse_from(["x", "--pulsechain.snap1"]).unwrap().snap1.snap1);
        assert!(Cli::try_parse_from(["x", "--pulsechain.snap1=true"]).unwrap().snap1.snap1);
        assert!(!Cli::try_parse_from(["x", "--pulsechain.snap1=false"]).unwrap().snap1.snap1);
        assert!(!PulsechainSnap1Args::default().snap1);
    }

    /// Operators write `1` or `yes` in systemd drop-ins; the env value takes the same parser.
    #[test]
    fn snap1_flag_takes_boolish_values() {
        use clap::Parser;
        for (value, on) in [("1", true), ("yes", true), ("on", true), ("TRUE", true)]
            .into_iter()
            .chain([("0", false), ("no", false), ("off", false), ("false", false)])
        {
            let arg = format!("--pulsechain.snap1={value}");
            assert_eq!(
                Cli::try_parse_from(["x", arg.as_str()]).unwrap().snap1.snap1,
                on,
                "{value}"
            );
        }
    }

    /// The documented variable turns the flag on with the same values, and the flag wins.
    #[test]
    fn snap1_env_variable_takes_boolish_values() {
        use clap::Parser;
        let _env = SNAP1_ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let parse = |value: &str, args: &[&str]| {
            // SAFETY: tests of this crate read the environment only through `std::env`, which
            // locks it, and every test that reads this variable holds `SNAP1_ENV`.
            unsafe { std::env::set_var("RETH_PULSECHAIN_SNAP1", value) };
            let parsed = Cli::try_parse_from(args).map(|cli| cli.snap1.snap1);
            // SAFETY: as above.
            unsafe { std::env::remove_var("RETH_PULSECHAIN_SNAP1") };
            parsed
        };
        for (value, on) in [("1", true), ("yes", true), ("on", true), ("TRUE", true)]
            .into_iter()
            .chain([("0", false), ("no", false), ("off", false), ("false", false)])
        {
            assert_eq!(parse(value, &["x"]).unwrap(), on, "{value}");
        }
        assert!(!parse("1", &["x", "--pulsechain.snap1=false"]).unwrap());
        assert!(parse("0", &["x", "--pulsechain.snap1"]).unwrap());
        assert_eq!(
            parse("maybe", &["x"]).unwrap_err().kind(),
            clap::error::ErrorKind::ValueValidation
        );
    }

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
