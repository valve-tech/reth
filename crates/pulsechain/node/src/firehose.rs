//! Firehose hooks for `PulseChain`.
//!
//! The `PrimordialPulse` fork block changes state in the block executor's `finish`, outside the
//! EVM, so the Firehose inspector never sees it. [`PulsechainPostTxExtras`] captures the accounts
//! it writes before `finish` and emits their changes after it, through
//! [`reth_firehose::PostTxExtras::capture_post_block`].

use std::ops::DerefMut;

use reth_firehose::{FirehoseInspector, PostBlockChanges, PostTxExtras};
use reth_trie_common::bundle_state::BundleState;

pub mod primordial_pulse;

use primordial_pulse::{emit_primordial_pulse_changes, fork_block_for, PrimordialPulsePreState};

/// The `PulseChain` [`PostTxExtras`]: no per-transaction extras, and the `PrimordialPulse`
/// transition at its fork block.
#[derive(Debug, Clone, Copy, Default)]
pub struct PulsechainPostTxExtras;

impl<E: reth_evm::Evm> PostTxExtras<E> for PulsechainPostTxExtras {
    #[inline]
    fn emit_post_tx_extras<G: DerefMut<Target = firehose_tracer::Tracer>>(
        &self,
        _evm: &mut E,
        _inspector: &FirehoseInspector<G>,
        _gas_used: u64,
        _base_fee: u64,
    ) {
    }

    fn capture_post_block(
        &self,
        evm: &mut E,
        block_number: u64,
        chain_id: u64,
    ) -> Option<Box<dyn PostBlockChanges>> {
        fork_block_for(chain_id).filter(|&fork_block| fork_block == block_number)?;
        let pre = PrimordialPulsePreState::capture(evm.state_db_mut(), chain_id, block_number)?;
        Some(Box::new(pre))
    }
}

impl PostBlockChanges for PrimordialPulsePreState {
    fn emit(&self, tracer: &mut firehose_tracer::Tracer, state: &BundleState) {
        emit_primordial_pulse_changes(tracer, self, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evm::PulsechainEvmConfig, spec::PulsechainChainSpec};
    use reth_firehose::{FirehoseEvmConfig, FirehoseLiveHooks};
    use std::any::TypeId;

    /// The node runs `FirehoseEvmConfig<PulsechainEvmConfig>`. If that wrapper picked its own
    /// hooks again, the `PrimordialPulse` changes would silently vanish from both the engine and
    /// the pipeline output.
    #[test]
    fn firehose_wrapper_keeps_the_pulsechain_hooks() {
        type Wrapped = FirehoseEvmConfig<PulsechainEvmConfig<PulsechainChainSpec>>;
        assert_eq!(
            TypeId::of::<<Wrapped as FirehoseLiveHooks>::PostTxExtras>(),
            TypeId::of::<PulsechainPostTxExtras>()
        );
        assert_eq!(
            TypeId::of::<
                <PulsechainEvmConfig<PulsechainChainSpec> as FirehoseLiveHooks>::PostTxExtras,
            >(),
            TypeId::of::<PulsechainPostTxExtras>()
        );
    }

    /// The Firehose wrapper emits the block reward only for a spec before the Merge. Through the
    /// wrapper, the Ethereum post-Merge replay range must get the Merge spec, which pays no
    /// reward. The `PrimordialPulse` block must get a pre-Merge spec, because it pays one.
    #[test]
    fn firehose_wrapper_gets_the_spec_that_gates_the_block_reward() {
        use alloy_consensus::Header;
        use alloy_primitives::U256;
        use evm2::SpecId;
        use reth_evm::{ConfigureEvm, EvmEnv};
        use reth_pulsechain_forks::{
            chainspec::PULSECHAIN,
            hardfork::{ETH_MAINNET_MERGE_BLOCK, PRIMORDIAL_PULSE_MAINNET_BLOCK},
        };

        let config = FirehoseEvmConfig::new(PulsechainEvmConfig::new(PULSECHAIN.clone()));
        let spec = |number| -> SpecId {
            let header = Header {
                number,
                difficulty: U256::from(1),
                base_fee_per_gas: Some(1),
                ..Default::default()
            };
            config.evm_env(&header).unwrap().spec_id()
        };

        assert!(!spec(ETH_MAINNET_MERGE_BLOCK - 1).enables(SpecId::MERGE));
        assert!(spec(ETH_MAINNET_MERGE_BLOCK).enables(SpecId::MERGE));
        assert!(spec(PRIMORDIAL_PULSE_MAINNET_BLOCK - 1).enables(SpecId::MERGE));
        assert!(!spec(PRIMORDIAL_PULSE_MAINNET_BLOCK).enables(SpecId::MERGE));
        assert!(spec(PRIMORDIAL_PULSE_MAINNET_BLOCK + 1).enables(SpecId::MERGE));
    }
}
