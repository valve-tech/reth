//! `PulseChain` hardfork definitions.
//!
//! `PulseChain` reuses all Ethereum hardforks in their original order, then adds
//! `PrimordialPulse` as the chain-split hardfork at block 17,233,000 (mainnet)
//! or 16,492,700 (testnet v4). The `PoS` merge (Paris) also fires at those blocks.

use alloy_primitives::{uint, U256};
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition, Hardfork};

/// The `PrimordialPulse` fork block on `PulseChain` mainnet (chain ID 369).
pub const PRIMORDIAL_PULSE_MAINNET_BLOCK: u64 = 17_233_000;

/// The `PrimordialPulse` fork block on `PulseChain` testnet v4 (chain ID 943).
pub const PRIMORDIAL_PULSE_TESTNET_V4_BLOCK: u64 = 16_492_700;

/// Timestamp of the `PrimordialPulse` block on `PulseChain` mainnet (chain 369).
///
/// On-chain block 17,233,000 carries this timestamp. Used to discriminate pre-fork
/// (Ethereum-replay) from post-fork (PulseChain) blocks via timestamp alone in
/// places where block number isn't available — notably the chain spec's
/// `is_shanghai_active_at_timestamp` override. Note this is *earlier* than
/// PulseChain's own Shanghai timestamp (1,683,786,515), so a brief window of
/// post-fork blocks predates Shanghai.
pub const PRIMORDIAL_PULSE_MAINNET_TIMESTAMP: u64 = 1_683_759_171;

/// Timestamp of the `PrimordialPulse` block on `PulseChain` testnet v4 (chain 943).
///
/// On-chain block 16,492,700 carries this timestamp. See
/// [`PRIMORDIAL_PULSE_MAINNET_TIMESTAMP`] for usage.
pub const PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP: u64 = 1_681_264_700;

/// The Ethereum mainnet Merge (Paris) block — first PoS block on Ethereum.
///
/// PulseChain replays Ethereum history verbatim; blocks at or above this number are
/// post-Merge Ethereum blocks and must use `SpecId::MERGE` EVM rules, even though
/// PulseChain's own Paris activation is much later (block 17,233,001).
pub const ETH_MAINNET_MERGE_BLOCK: u64 = 15_537_394;

/// Ethereum mainnet Shanghai activation timestamp (April 12, 2023).
///
/// Blocks between ETH Shanghai and `PrimordialPulse` need `SpecId::SHANGHAI` EVM rules
/// (PUSH0, warm COINBASE, initcode metering) even though PulseChain's own Shanghai
/// timestamp is later. Mirrors the Erigon override in `IsShanghai()`:
///
/// ```text
/// if c.PrimordialPulseAhead(num) { return 1681338455 <= time }
/// ```
pub const ETH_MAINNET_SHANGHAI_TIMESTAMP: u64 = 1_681_338_455;

/// Shanghai activation timestamp on `PulseChain` mainnet.
pub const SHANGHAI_MAINNET_TIMESTAMP: u64 = 1_683_786_515;

/// Shanghai activation timestamp on `PulseChain` testnet v4.
pub const SHANGHAI_TESTNET_V4_TIMESTAMP: u64 = 1_682_700_369;

/// `PulseChain`'s terminal total difficulty for the `PoS` merge.
///
/// Slightly higher than Ethereum mainnet's final TD because `PulseChain`'s `PoW`
/// chain continued ~1.8M blocks beyond Ethereum's merge block before `PulseChain`
/// completed its own transition at block 17,233,000.
///
/// Source: `params/chainspecs/pulsechain.json` in private-erigon-pulse.
pub const PULSECHAIN_PARIS_TTD: U256 = uint!(58_750_003_716_598_352_947_541_U256);

/// PulseChain-specific hardfork extending the Ethereum hardfork set.
///
/// Only `PrimordialPulse` is defined here; all standard Ethereum forks
/// (`EthereumHardfork::Frontier` through `EthereumHardfork::Shanghai`) are
/// included in the `ChainHardforks` list alongside this variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PulsechainHardfork {
    /// The one-time state transition at block 17,233,000 (mainnet) / 16,492,700 (testnet v4).
    ///
    /// Fires exactly once (== comparison, not >=). Applies sacrifice credits,
    /// swaps deposit contracts, and transitions chain ID from 1 to 369/943.
    PrimordialPulse,
}

impl Hardfork for PulsechainHardfork {
    fn name(&self) -> &'static str {
        match self {
            Self::PrimordialPulse => "PrimordialPulse",
        }
    }
}

impl PulsechainHardfork {
    /// Returns the ordered hardfork list for `PulseChain` mainnet (chain ID 369).
    ///
    /// Includes all Ethereum hardforks at their identical mainnet block numbers,
    /// followed by Paris (`PoS` merge) and `PrimordialPulse` at block 17,233,000,
    /// then Shanghai at `PulseChain`'s timestamp.
    pub fn mainnet() -> ChainHardforks {
        ChainHardforks::new(vec![
            (Box::new(EthereumHardfork::Frontier), ForkCondition::Block(0)),
            (Box::new(EthereumHardfork::Homestead), ForkCondition::Block(1_150_000)),
            (Box::new(EthereumHardfork::Dao), ForkCondition::Block(1_920_000)),
            (Box::new(EthereumHardfork::Tangerine), ForkCondition::Block(2_463_000)),
            (Box::new(EthereumHardfork::SpuriousDragon), ForkCondition::Block(2_675_000)),
            (Box::new(EthereumHardfork::Byzantium), ForkCondition::Block(4_370_000)),
            (Box::new(EthereumHardfork::Constantinople), ForkCondition::Block(7_280_000)),
            (Box::new(EthereumHardfork::Petersburg), ForkCondition::Block(7_280_000)),
            (Box::new(EthereumHardfork::Istanbul), ForkCondition::Block(9_069_000)),
            (Box::new(EthereumHardfork::MuirGlacier), ForkCondition::Block(9_200_000)),
            (Box::new(EthereumHardfork::Berlin), ForkCondition::Block(12_244_000)),
            (Box::new(EthereumHardfork::London), ForkCondition::Block(12_965_000)),
            (Box::new(EthereumHardfork::ArrowGlacier), ForkCondition::Block(13_773_000)),
            (Box::new(EthereumHardfork::GrayGlacier), ForkCondition::Block(15_050_000)),
            (Box::new(Self::PrimordialPulse), ForkCondition::Block(PRIMORDIAL_PULSE_MAINNET_BLOCK)),
            (
                Box::new(EthereumHardfork::Paris),
                ForkCondition::TTD {
                    // The PrimordialPulse block is the last PoW block (non-zero difficulty).
                    // Paris (PoS) activates on the NEXT block, which is the first PoS block.
                    activation_block_number: PRIMORDIAL_PULSE_MAINNET_BLOCK + 1,
                    fork_block: None,
                    total_difficulty: PULSECHAIN_PARIS_TTD,
                },
            ),
            (
                Box::new(EthereumHardfork::Shanghai),
                ForkCondition::Timestamp(SHANGHAI_MAINNET_TIMESTAMP),
            ),
        ])
    }

    /// Returns the ordered hardfork list for `PulseChain` testnet v4 (chain ID 943).
    ///
    /// Same fork schedule as mainnet but with testnet-specific activation points:
    /// `PrimordialPulse` fires at block 16,492,700 and Shanghai at timestamp 1,682,700,369.
    pub fn testnet_v4() -> ChainHardforks {
        ChainHardforks::new(vec![
            (Box::new(EthereumHardfork::Frontier), ForkCondition::Block(0)),
            (Box::new(EthereumHardfork::Homestead), ForkCondition::Block(1_150_000)),
            (Box::new(EthereumHardfork::Dao), ForkCondition::Block(1_920_000)),
            (Box::new(EthereumHardfork::Tangerine), ForkCondition::Block(2_463_000)),
            (Box::new(EthereumHardfork::SpuriousDragon), ForkCondition::Block(2_675_000)),
            (Box::new(EthereumHardfork::Byzantium), ForkCondition::Block(4_370_000)),
            (Box::new(EthereumHardfork::Constantinople), ForkCondition::Block(7_280_000)),
            (Box::new(EthereumHardfork::Petersburg), ForkCondition::Block(7_280_000)),
            (Box::new(EthereumHardfork::Istanbul), ForkCondition::Block(9_069_000)),
            (Box::new(EthereumHardfork::MuirGlacier), ForkCondition::Block(9_200_000)),
            (Box::new(EthereumHardfork::Berlin), ForkCondition::Block(12_244_000)),
            (Box::new(EthereumHardfork::London), ForkCondition::Block(12_965_000)),
            (Box::new(EthereumHardfork::ArrowGlacier), ForkCondition::Block(13_773_000)),
            (Box::new(EthereumHardfork::GrayGlacier), ForkCondition::Block(15_050_000)),
            (
                Box::new(Self::PrimordialPulse),
                ForkCondition::Block(PRIMORDIAL_PULSE_TESTNET_V4_BLOCK),
            ),
            (
                Box::new(EthereumHardfork::Paris),
                ForkCondition::TTD {
                    // The PrimordialPulse block is the last PoW block (non-zero difficulty).
                    // Paris (PoS) activates on the NEXT block, which is the first PoS block.
                    activation_block_number: PRIMORDIAL_PULSE_TESTNET_V4_BLOCK + 1,
                    fork_block: None,
                    total_difficulty: PULSECHAIN_PARIS_TTD,
                },
            ),
            (
                Box::new(EthereumHardfork::Shanghai),
                ForkCondition::Timestamp(SHANGHAI_TESTNET_V4_TIMESTAMP),
            ),
        ])
    }
}
