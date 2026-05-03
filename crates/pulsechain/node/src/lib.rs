//! `PulseChain` node implementation for reth.
//!
//! `PulseChain` (chain IDs 369 mainnet / 943 testnet v4) is a literal Ethereum fork.
//! Its genesis block is identical to Ethereum mainnet. At block 17,233,000 (mainnet)
//! or 16,492,700 (testnet v4) the `PrimordialPulse` state transition fires, which:
//! - Applies sacrifice credits (~8.3 MB binary of address → balance records)
//! - Destroys the Ethereum deposit contract (0x00000000219ab540356cBB839Cbe05303d7705Fa)
//! - Deploys the `PulseChain` deposit contract (0x3693693693693693693693693693693693693693)
//! - Transitions CHAINID opcode from 1 → 369 (or 943 on testnet)
//!
//! See `docs/pulsechain-spec.md` for the full specification.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod cli;
pub mod consensus;
pub mod evm;
pub mod fork;
pub mod gas;
pub mod launch;
pub mod network;
pub mod node;
pub mod pool;
pub mod spec;

// Re-export the hardfork and chainspec modules so external users (and the
// tests) can continue using `reth_pulsechain_node::chainspec::PULSECHAIN`
// and `reth_pulsechain_node::hardfork::PulsechainHardfork` paths.
pub use reth_pulsechain_forks::{chainspec, hardfork};

pub use cli::PulsechainChainSpecParser;
pub use consensus::PulsechainConsensusBuilder;
pub use evm::{PulsechainEvmConfig, PulsechainExecutorBuilder};
pub use network::PulsechainNetworkBuilder;
pub use node::PulsechainNode;
pub use pool::PulsechainPoolBuilder;
pub use spec::PulsechainChainSpec;
