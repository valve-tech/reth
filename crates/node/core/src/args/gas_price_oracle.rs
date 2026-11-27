use super::DefaultRpcServerArgs;
use alloy_primitives::U256;
use clap::{
    builder::{PossibleValuesParser, Resettable, TypedValueParser},
    Args,
};
use reth_rpc_eth_types::{GasPriceOracleConfig, GasPriceSampleMode};
use reth_rpc_server_types::constants::gas_oracle::{
    DEFAULT_GAS_PRICE_BLOCKS, DEFAULT_GAS_PRICE_PERCENTILE, DEFAULT_IGNORE_GAS_PRICE,
    DEFAULT_MAX_GAS_PRICE,
};

/// Parameters to configure Gas Price Oracle
#[derive(Debug, Clone, Copy, Args, PartialEq, Eq)]
#[command(next_help_heading = "Gas Price Oracle")]
pub struct GasPriceOracleArgs {
    /// Number of recent blocks to check for gas price
    #[arg(long = "gpo.blocks", default_value_t = DefaultRpcServerArgs::get_global().gas_price_oracle.blocks)]
    pub blocks: u32,

    /// Gas Price below which gpo will ignore transactions
    #[arg(long = "gpo.ignoreprice", default_value_t = DefaultRpcServerArgs::get_global().gas_price_oracle.ignore_price)]
    pub ignore_price: u64,

    /// Maximum transaction priority fee(or gasprice before London Fork) to be recommended by gpo
    #[arg(long = "gpo.maxprice", default_value_t = DefaultRpcServerArgs::get_global().gas_price_oracle.max_price)]
    pub max_price: u64,

    /// The percentile of gas prices to use for the estimate
    #[arg(long = "gpo.percentile", default_value_t = DefaultRpcServerArgs::get_global().gas_price_oracle.percentile)]
    pub percentile: u32,

    /// The default gas price to use if there are no blocks to use
    #[arg(long = "gpo.default-suggested-fee", default_value = Resettable::from(DefaultRpcServerArgs::get_global().gas_price_oracle.default_suggested_fee.map(|v| v.to_string().into())))]
    pub default_suggested_fee: Option<U256>,

    /// How the oracle samples recent blocks.
    ///
    /// `reth` takes the 3 lowest tips of each of the newest `--gpo.blocks` blocks that give a
    /// sample; empty blocks do not count.
    ///
    /// `pulsechain` runs erigon-pulse's algorithm, so `eth_maxPriorityFeePerGas` matches
    /// rpc.pulsechain.com. It walks exactly `--gpo.blocks` blocks back from the head, empty ones
    /// included. Per block it drops tips under `--gpo.ignoreprice`, transactions from the block's
    /// coinbase and self-transfers, then keeps the lowest 40% of the rest (at least 3, at most
    /// 1000). It answers the `--gpo.percentile` sample, capped at `--gpo.maxprice`. With no sample
    /// it keeps its last answer: `--gpo.default-suggested-fee` at start, else 0. It changes two
    /// defaults: `--gpo.ignoreprice` becomes 1000 gwei and `--gpo.maxprice` becomes 1 PLS (1e18
    /// wei). Either flag set to its reth default value still reads as unset.
    #[arg(
        long = "gpo.sample-mode",
        default_value_t = DefaultRpcServerArgs::get_global().gas_price_oracle.sample_mode,
        value_parser = PossibleValuesParser::new(["reth", "pulsechain"])
            .map(|s| s.parse::<GasPriceSampleMode>().expect("a possible value")),
    )]
    pub sample_mode: GasPriceSampleMode,
}

impl GasPriceOracleArgs {
    /// Returns a [`GasPriceOracleConfig`] from the arguments.
    pub fn gas_price_oracle_config(&self) -> GasPriceOracleConfig {
        let Self {
            blocks,
            ignore_price,
            max_price,
            percentile,
            default_suggested_fee,
            sample_mode,
        } = self;
        match sample_mode {
            GasPriceSampleMode::Reth => GasPriceOracleConfig {
                max_price: Some(U256::from(*max_price)),
                ignore_price: Some(U256::from(*ignore_price)),
                percentile: *percentile,
                blocks: *blocks,
                default_suggested_fee: *default_suggested_fee,
                ..Default::default()
            },
            GasPriceSampleMode::Pulsechain => {
                // erigon's defaults replace reth's, unless the operator set another value
                let defaults = &DefaultRpcServerArgs::get_global().gas_price_oracle;
                let pulsechain = GasPriceOracleConfig::pulsechain();
                GasPriceOracleConfig {
                    max_price: if *max_price == defaults.max_price {
                        pulsechain.max_price
                    } else {
                        Some(U256::from(*max_price))
                    },
                    ignore_price: if *ignore_price == defaults.ignore_price {
                        pulsechain.ignore_price
                    } else {
                        Some(U256::from(*ignore_price))
                    },
                    percentile: *percentile,
                    blocks: *blocks,
                    default_suggested_fee: *default_suggested_fee,
                    ..pulsechain
                }
            }
        }
    }
}

impl Default for GasPriceOracleArgs {
    fn default() -> Self {
        Self {
            blocks: DEFAULT_GAS_PRICE_BLOCKS,
            ignore_price: DEFAULT_IGNORE_GAS_PRICE.to(),
            max_price: DEFAULT_MAX_GAS_PRICE.to(),
            percentile: DEFAULT_GAS_PRICE_PERCENTILE,
            default_suggested_fee: None,
            sample_mode: GasPriceSampleMode::Reth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_parse_gpo_args() {
        let args = CommandParser::<GasPriceOracleArgs>::parse_from(["reth"]).args;
        assert_eq!(
            args,
            GasPriceOracleArgs {
                blocks: DEFAULT_GAS_PRICE_BLOCKS,
                ignore_price: DEFAULT_IGNORE_GAS_PRICE.to(),
                max_price: DEFAULT_MAX_GAS_PRICE.to(),
                percentile: DEFAULT_GAS_PRICE_PERCENTILE,
                default_suggested_fee: None,
                sample_mode: GasPriceSampleMode::Reth,
            }
        );
    }

    #[test]
    fn gpo_args_default_sanity_test() {
        let default_args = GasPriceOracleArgs::default();
        let args = CommandParser::<GasPriceOracleArgs>::parse_from(["reth"]).args;
        assert_eq!(args, default_args);
    }

    #[test]
    fn reth_mode_config_is_unchanged() {
        let args = CommandParser::<GasPriceOracleArgs>::parse_from(["reth"]).args;
        assert_eq!(args.sample_mode, GasPriceSampleMode::Reth);
        assert_eq!(
            args.gas_price_oracle_config(),
            GasPriceOracleConfig {
                max_price: Some(DEFAULT_MAX_GAS_PRICE),
                ignore_price: Some(DEFAULT_IGNORE_GAS_PRICE),
                ..Default::default()
            }
        );
    }

    #[test]
    fn pulsechain_mode_sets_erigon_defaults() {
        let args = CommandParser::<GasPriceOracleArgs>::parse_from([
            "reth",
            "--gpo.sample-mode",
            "pulsechain",
        ])
        .args;
        assert_eq!(args.gas_price_oracle_config(), GasPriceOracleConfig::pulsechain());
        let config = args.gas_price_oracle_config();
        assert_eq!(config.ignore_price, Some(U256::from(1_000_000_000_000u64)));
        assert_eq!(config.max_price, Some(U256::from(1_000_000_000_000_000_000u64)));
        assert_eq!((config.blocks, config.percentile), (20, 60));
        assert_eq!(config.sample_mode, GasPriceSampleMode::Pulsechain);
    }

    #[test]
    fn pulsechain_mode_keeps_explicit_flags() {
        let args = CommandParser::<GasPriceOracleArgs>::parse_from([
            "reth",
            "--gpo.sample-mode",
            "pulsechain",
            "--gpo.ignoreprice",
            "5",
            "--gpo.maxprice",
            "7",
            "--gpo.blocks",
            "30",
            "--gpo.percentile",
            "50",
            "--gpo.default-suggested-fee",
            "9",
        ])
        .args;
        let config = args.gas_price_oracle_config();
        assert_eq!(config.ignore_price, Some(U256::from(5)));
        assert_eq!(config.max_price, Some(U256::from(7)));
        assert_eq!((config.blocks, config.percentile), (30, 50));
        assert_eq!(config.default_suggested_fee, Some(U256::from(9)));
        assert_eq!(config.sample_mode, GasPriceSampleMode::Pulsechain);
    }

    #[test]
    fn unknown_sample_mode_is_refused() {
        assert!(CommandParser::<GasPriceOracleArgs>::try_parse_from([
            "reth",
            "--gpo.sample-mode",
            "geth"
        ])
        .is_err());
    }
}
