//! `PulsechainChainSpec` — newtype wrapper around `ChainSpec` that overrides
//! [`EthereumHardforks::is_shanghai_active_at_timestamp`] to handle the
//! pre-`PrimordialPulse` Ethereum-replay range correctly.
//!
//! ## Why this exists
//!
//! `PulseChain` replays Ethereum mainnet history verbatim from genesis up to
//! `PrimordialPulse`. In that replay, blocks past Ethereum's Shanghai activation
//! timestamp (`1_681_338_455`, April 12, 2023) carry validator withdrawals and
//! need Shanghai EVM rules. `PulseChain`'s own Shanghai timestamp is later, so
//! the unmodified chain spec returns false for those Ethereum-replay blocks and
//! drops their withdrawals — execution then fails later with `lack of funds`
//! errors from validator withdrawal recipients.
//!
//! Mirroring this on the post-fork side: PulseChain mainnet's PrimordialPulse
//! block (17,233,000) has timestamp `1_683_759_171`, which is **earlier** than
//! PulseChain's own Shanghai (`1_683_786_515`). So roughly 7.6 hours of
//! post-fork blocks (17,233,001 → ~17,233,033) are post-PrimordialPulse but
//! pre-PulseChain-Shanghai — they correctly carry no `withdrawals_root`, and
//! claiming Shanghai is active for them would reject valid headers as
//! `WithdrawalsRootMissing`. (Testnet v4 has the same shape: PrimordialPulse
//! at `1_681_264_700`, V4 Shanghai at `1_682_700_369` — a ~16.7-day gap.)
//!
//! ## What this fixes
//!
//! Use the timestamp of `PrimordialPulse` itself as the discriminator:
//! - **Pre-fork** (`timestamp < PRIMORDIAL_PULSE_*_TIMESTAMP`): return `timestamp >=
//!   ETH_MAINNET_SHANGHAI_TIMESTAMP`. Treats Ethereum-replay blocks as Shanghai-active per
//!   Ethereum's calendar.
//! - **Post-fork**: delegate to the inner chain spec, which already knows PulseChain's own Shanghai
//!   timestamp.
//!
//! The fork-ID schedule (used for peer handshakes) is left unchanged via
//! `ethereum_fork_activation` delegating to the inner `ChainSpec`, so this node
//! remains peer-compatible with the rest of the PulseChain network.

use core::fmt::Display;
use std::sync::Arc;

use alloy_consensus::Header;
use alloy_eips::eip7840::BlobParams;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{
    BaseFeeParams, Chain, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork,
    EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_network_peers::NodeRecord;
use reth_pulsechain_forks::{
    chainspec::{PULSECHAIN_MAINNET_CHAIN_ID, PULSECHAIN_TESTNET_V4_CHAIN_ID},
    hardfork::{
        ETH_MAINNET_SHANGHAI_TIMESTAMP, PRIMORDIAL_PULSE_MAINNET_TIMESTAMP,
        PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP,
    },
};

/// Newtype wrapper around [`ChainSpec`] that overrides Shanghai detection
/// for the pre-`PrimordialPulse` Ethereum-replay range. See module docs.
#[derive(Debug, Clone)]
pub struct PulsechainChainSpec {
    /// The wrapped Ethereum chain spec.
    pub inner: Arc<ChainSpec>,
}

impl PulsechainChainSpec {
    /// Wrap an existing `ChainSpec`.
    pub const fn new(inner: Arc<ChainSpec>) -> Self {
        Self { inner }
    }
}

impl From<Arc<ChainSpec>> for PulsechainChainSpec {
    fn from(inner: Arc<ChainSpec>) -> Self {
        Self { inner }
    }
}

impl From<ChainSpec> for PulsechainChainSpec {
    fn from(inner: ChainSpec) -> Self {
        Self { inner: Arc::new(inner) }
    }
}

impl core::ops::Deref for PulsechainChainSpec {
    type Target = ChainSpec;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Hardforks for PulsechainChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        self.inner.fork_id(head)
    }

    fn latest_fork_id(&self) -> ForkId {
        self.inner.latest_fork_id()
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        self.inner.fork_filter(head)
    }
}

impl EthereumHardforks for PulsechainChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }

    /// Pre-`PrimordialPulse` (Ethereum-replay): true once Ethereum's Shanghai
    /// timestamp is reached. Post-fork: delegate to the inner spec's PulseChain
    /// Shanghai. See module docs for the cross-over reasoning.
    fn is_shanghai_active_at_timestamp(&self, timestamp: u64) -> bool {
        let pp_timestamp = match self.inner.chain().id() {
            PULSECHAIN_MAINNET_CHAIN_ID => Some(PRIMORDIAL_PULSE_MAINNET_TIMESTAMP),
            PULSECHAIN_TESTNET_V4_CHAIN_ID => Some(PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP),
            _ => None,
        };
        match pp_timestamp {
            Some(pp) if timestamp < pp => timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP,
            _ => self.inner.is_shanghai_active_at_timestamp(timestamp),
        }
    }
}

impl EthChainSpec for PulsechainChainSpec {
    type Header = Header;

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.inner.deposit_contract()
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn display_hardforks(&self) -> Box<dyn Display> {
        self.inner.display_hardforks()
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        self.inner.bootnodes()
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.inner.final_paris_total_difficulty()
    }
}

impl EthExecutorSpec for PulsechainChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.inner.deposit_contract_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_pulsechain_forks::{
        chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4},
        hardfork::{SHANGHAI_MAINNET_TIMESTAMP, SHANGHAI_TESTNET_V4_TIMESTAMP},
    };

    /// `is_shanghai_active_at_timestamp` discriminates by `PrimordialPulse`
    /// timestamp: pre-fork uses Ethereum's Shanghai, post-fork uses PulseChain's.
    #[test]
    fn shanghai_override_uses_ethereum_timestamp() {
        let spec = PulsechainChainSpec::new(PULSECHAIN.clone());

        // Pre-fork: Ethereum Shanghai is the activation point.
        assert!(
            !spec.is_shanghai_active_at_timestamp(ETH_MAINNET_SHANGHAI_TIMESTAMP - 1),
            "1 second before Ethereum Shanghai must be pre-Shanghai"
        );
        assert!(
            spec.is_shanghai_active_at_timestamp(ETH_MAINNET_SHANGHAI_TIMESTAMP),
            "Ethereum Shanghai timestamp must activate Shanghai for pre-fork blocks"
        );

        // Pre-fork bad block (17,035,069 era) sits between ETH Shanghai and
        // PrimordialPulse — must be Shanghai-active so withdrawals are read.
        let pre_fork_post_eth_shanghai = 1_681_350_215; // ~12 min after ETH Shanghai
        assert!(
            spec.is_shanghai_active_at_timestamp(pre_fork_post_eth_shanghai),
            "block 17,035,069 must be Shanghai-active so withdrawals are read"
        );

        // Post-fork before PulseChain Shanghai: NOT Shanghai-active. Block
        // 17,233,032 has on-chain timestamp 1_683_786_505 (10 s before
        // PulseChain Shanghai) and correctly carries no withdrawals_root —
        // the wrapper must agree, otherwise consensus rejects valid headers.
        let post_fork_pre_pulsechain_shanghai = 1_683_786_505;
        assert!(
            !spec.is_shanghai_active_at_timestamp(post_fork_pre_pulsechain_shanghai),
            "post-PrimordialPulse but pre-PulseChain-Shanghai blocks must NOT be Shanghai-active"
        );

        // Post-fork at and after PulseChain Shanghai: Shanghai-active.
        assert!(
            spec.is_shanghai_active_at_timestamp(SHANGHAI_MAINNET_TIMESTAMP),
            "PulseChain's own Shanghai timestamp must activate Shanghai"
        );
    }

    /// The fork-ID schedule (peer handshake input) is unchanged — it still uses
    /// `PulseChain`'s `Shanghai` `ForkCondition`. Keeps us peer-compatible with
    /// the rest of the PulseChain network.
    #[test]
    fn ethereum_fork_activation_schedule_unchanged() {
        let spec = PulsechainChainSpec::new(PULSECHAIN.clone());
        assert_eq!(
            spec.ethereum_fork_activation(EthereumHardfork::Shanghai),
            ForkCondition::Timestamp(SHANGHAI_MAINNET_TIMESTAMP),
            "Shanghai ForkCondition must remain at PulseChain's timestamp \
             so fork ID matches the rest of the network"
        );
    }

    /// Same invariants for testnet v4. Note testnet v4's PrimordialPulse
    /// timestamp (1,681,264,700) is *earlier* than Ethereum's Shanghai
    /// (1,681,338,455) — so any timestamp at or after ETH Shanghai is already
    /// post-fork on testnet v4 and must consult the inner spec (testnet v4
    /// Shanghai = 1,682,700,369).
    #[test]
    fn testnet_v4_override_and_schedule() {
        let spec = PulsechainChainSpec::new(PULSECHAIN_TESTNET_V4.clone());

        // ETH Shanghai timestamp on testnet v4 is post-fork but pre-V4-Shanghai —
        // must NOT be Shanghai-active.
        assert!(
            !spec.is_shanghai_active_at_timestamp(ETH_MAINNET_SHANGHAI_TIMESTAMP),
            "ETH Shanghai is post-fork on testnet v4 (still pre-V4-Shanghai)"
        );

        // Just before V4 Shanghai: still not active.
        assert!(!spec.is_shanghai_active_at_timestamp(SHANGHAI_TESTNET_V4_TIMESTAMP - 1));

        // At V4 Shanghai: active.
        assert!(spec.is_shanghai_active_at_timestamp(SHANGHAI_TESTNET_V4_TIMESTAMP));

        // Fork-ID schedule unchanged.
        assert_eq!(
            spec.ethereum_fork_activation(EthereumHardfork::Shanghai),
            ForkCondition::Timestamp(SHANGHAI_TESTNET_V4_TIMESTAMP),
        );
    }
}
