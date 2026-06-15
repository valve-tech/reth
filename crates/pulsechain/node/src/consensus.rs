//! PulseChain consensus builder and wrapper.
//!
//! PulseChain replays Ethereum's full history from genesis. This creates a gap in the
//! Shanghai timestamp handling:
//!
//! - Ethereum mainnet Shanghai activated at timestamp 1,681,338,455
//! - PulseChain's chainspec has Shanghai at 1,683,786,515 (a later timestamp)
//! - Blocks with timestamps between those two values were mined on Ethereum and carry a
//!   `withdrawals_root`, but PulseChain's chainspec doesn't consider Shanghai active for them, so
//!   `EthBeaconConsensus` would incorrectly reject them.
//!
//! `PulsechainConsensus` fixes this by using the Ethereum mainnet Shanghai timestamp
//! when validating headers for pre-PrimordialPulse blocks.

use std::{fmt, sync::Arc};

use alloy_primitives::B256;
use reth_chainspec::EthChainSpec;
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_execution_types::BlockExecutionResult;
use reth_node_builder::{components::ConsensusBuilder, BuilderContext};
use reth_primitives_traits::{
    Block, BlockHeader, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader,
};

use reth_node_builder::node::{FullNodeTypes, NodeTypes};
use reth_pulsechain_forks::{
    chainspec::{PULSECHAIN_MAINNET_CHAIN_ID, PULSECHAIN_TESTNET_V4_CHAIN_ID},
    hardfork::{
        ETH_MAINNET_SHANGHAI_TIMESTAMP, PRIMORDIAL_PULSE_MAINNET_BLOCK,
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
    },
};

use crate::spec::PulsechainChainSpec;

// ---------------------------------------------------------------------------
// PulsechainConsensus — wrapper that fixes the Shanghai-timestamp gap
// ---------------------------------------------------------------------------

/// Consensus implementation for PulseChain.
///
/// Wraps [`EthBeaconConsensus`] and overrides `validate_header` to handle
/// the Shanghai activation timestamp gap that arises because PulseChain
/// replays Ethereum history but uses a different Shanghai timestamp in its
/// chainspec.
#[derive(Clone)]
pub struct PulsechainConsensus {
    inner: EthBeaconConsensus<PulsechainChainSpec>,
    chain_id: u64,
}

impl fmt::Debug for PulsechainConsensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PulsechainConsensus").field("chain_id", &self.chain_id).finish()
    }
}

impl PulsechainConsensus {
    /// Creates a new `PulsechainConsensus` wrapping the given `EthBeaconConsensus`.
    pub fn new(chain_spec: Arc<PulsechainChainSpec>) -> Self {
        let chain_id = chain_spec.chain().id();
        let inner = EthBeaconConsensus::new(chain_spec);
        Self { inner, chain_id }
    }

    /// Returns the PrimordialPulse block number for this chain.
    fn primordial_pulse_block(&self) -> u64 {
        match self.chain_id {
            PULSECHAIN_MAINNET_CHAIN_ID => PRIMORDIAL_PULSE_MAINNET_BLOCK,
            PULSECHAIN_TESTNET_V4_CHAIN_ID => PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
            // Unknown chain — default to mainnet boundary (safe: blocks below this
            // threshold will use the ETH mainnet Shanghai timestamp).
            _ => PRIMORDIAL_PULSE_MAINNET_BLOCK,
        }
    }

    /// Returns true if this block number falls before the PrimordialPulse transition.
    fn is_pre_primordial_pulse(&self, block_number: u64) -> bool {
        block_number < self.primordial_pulse_block()
    }
}

// ---------------------------------------------------------------------------
// HeaderValidator — overrides validate_header to fix the Shanghai-timestamp gap
// ---------------------------------------------------------------------------

impl<H> HeaderValidator<H> for PulsechainConsensus
where
    H: BlockHeader,
    EthBeaconConsensus<PulsechainChainSpec>: HeaderValidator<H>,
{
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        let block_number = header.header().number();

        if self.is_pre_primordial_pulse(block_number) {
            // For pre-PrimordialPulse blocks we must validate withdrawals_root using the
            // Ethereum mainnet Shanghai timestamp, not the PulseChain chainspec timestamp.
            //
            // EthBeaconConsensus calls `chain_spec.is_shanghai_active_at_timestamp()` which
            // would return false for timestamps in (ETH_mainnet_shanghai, PulseChain_shanghai).
            // Those blocks were mined on Ethereum and carry a withdrawals_root, so we apply
            // the Ethereum rule directly here before delegating to the inner validator.
            let timestamp = header.header().timestamp();
            let is_shanghai = timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP;

            if is_shanghai && header.header().withdrawals_root().is_none() {
                return Err(ConsensusError::WithdrawalsRootMissing);
            }
            if !is_shanghai && header.header().withdrawals_root().is_some() {
                return Err(ConsensusError::WithdrawalsRootUnexpected);
            }

            // Delegate the rest of the validation to the inner consensus.
            // The inner validator will also check the withdrawals_root condition using the
            // PulseChain chainspec. For timestamps in the gap this may produce a spurious
            // WithdrawalsRootUnexpected error, so we re-map that specific error to Ok since
            // we already validated the withdrawals_root above with the correct rule.
            match self.inner.validate_header(header) {
                Ok(()) => Ok(()),
                Err(ConsensusError::WithdrawalsRootMissing) |
                Err(ConsensusError::WithdrawalsRootUnexpected) => {
                    // We already applied the correct rule above; the inner validator fired
                    // a spurious withdrawals_root error due to the timestamp gap.
                    Ok(())
                }
                Err(other) => Err(other),
            }
        } else {
            self.inner.validate_header(header)
        }
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_header_against_parent(header, parent)
    }
}

// ---------------------------------------------------------------------------
// Consensus<B> — delegate entirely to the inner consensus
// ---------------------------------------------------------------------------

impl<B> Consensus<B> for PulsechainConsensus
where
    B: Block,
    EthBeaconConsensus<PulsechainChainSpec>: Consensus<B> + HeaderValidator<B::Header>,
    PulsechainConsensus: HeaderValidator<B::Header>,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_body_against_header(body, header)
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution(block)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<B>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution_with_tx_root(block, transaction_root)
    }
}

// ---------------------------------------------------------------------------
// FullConsensus<N> — delegate entirely to the inner consensus
// ---------------------------------------------------------------------------

impl<N> FullConsensus<N> for PulsechainConsensus
where
    N: NodePrimitives,
    EthBeaconConsensus<PulsechainChainSpec>: FullConsensus<N> + Consensus<N::Block>,
    PulsechainConsensus: Consensus<N::Block>,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_post_execution(
            block,
            result,
            receipt_root_bloom,
            block_access_list_hash,
        )
    }
}

// ---------------------------------------------------------------------------
// PulsechainConsensusBuilder
// ---------------------------------------------------------------------------

/// Builder for [`PulsechainConsensus`].
///
/// Constructs the PulseChain-specific consensus wrapper that handles the Shanghai
/// activation timestamp gap arising from replaying Ethereum mainnet history.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct PulsechainConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for PulsechainConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<
            ChainSpec = PulsechainChainSpec,
            Primitives = reth_ethereum_primitives::EthPrimitives,
        >,
    >,
{
    type Consensus = Arc<PulsechainConsensus>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(PulsechainConsensus::new(ctx.chain_spec())))
    }
}
