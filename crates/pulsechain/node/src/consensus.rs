//! `PulseChain` consensus builder and wrapper.
//!
//! `PulseChain` replays Ethereum's full history from genesis. This creates a gap in the
//! Shanghai timestamp handling:
//!
//! - Ethereum mainnet Shanghai activated at timestamp 1,681,338,455
//! - `PulseChain`'s chainspec has Shanghai at 1,683,786,515 (a later timestamp)
//! - Blocks with timestamps between those two values were mined on Ethereum and carry a
//!   `withdrawals_root`, but `PulseChain`'s chainspec doesn't consider Shanghai active for them, so
//!   `EthBeaconConsensus` would incorrectly reject them.
//!
//! `PulsechainConsensus` fixes this by using the Ethereum mainnet Shanghai timestamp
//! when validating headers for pre-PrimordialPulse blocks.
//!
//! On a known `PulseChain` network, a pre-fork header goes to a second
//! [`EthBeaconConsensus`] built over [`EthereumReplaySpec`]. That spec answers Shanghai by
//! Ethereum's timestamp, so every check after the withdrawals rule still runs. This keeps
//! the upstream `EthBeaconConsensus` unpatched.

use core::fmt::Display;
use std::{fmt, sync::Arc};

use alloy_consensus::Header;
use alloy_eips::eip7840::BlobParams;
use alloy_genesis::Genesis;
use alloy_primitives::{B256, U256};
use reth_chainspec::{
    BaseFeeParams, Chain, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks,
    ForkCondition,
};
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_execution_types::BlockExecutionResult;
use reth_network_peers::NodeRecord;
use reth_node_builder::{components::ConsensusBuilder, BuilderContext};
use reth_primitives_traits::{
    Block, BlockHeader, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader,
};

use reth_node_builder::node::{FullNodeTypes, NodeTypes};
use reth_pulsechain_forks::hardfork::{
    ETH_MAINNET_SHANGHAI_TIMESTAMP, PRIMORDIAL_PULSE_MAINNET_BLOCK,
};

use crate::spec::PulsechainChainSpec;

// ---------------------------------------------------------------------------
// PulsechainConsensus — wrapper that fixes the Shanghai-timestamp gap
// ---------------------------------------------------------------------------

/// Consensus implementation for `PulseChain`.
///
/// Wraps [`EthBeaconConsensus`] and overrides `validate_header` to handle
/// the Shanghai activation timestamp gap that arises because `PulseChain`
/// replays Ethereum history but uses a different Shanghai timestamp in its
/// chainspec.
#[derive(Clone)]
pub struct PulsechainConsensus {
    inner: EthBeaconConsensus<PulsechainChainSpec>,
    /// Validates pre-fork headers on a known `PulseChain` network. `None` on any other
    /// chain, where `inner` validates them.
    replay: Option<EthBeaconConsensus<EthereumReplaySpec>>,
    primordial_pulse_block: u64,
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
        let network = chain_spec.pulsechain_network();
        // A chain that no PulseChain network claims falls back to the mainnet boundary:
        // blocks below it use the Ethereum mainnet Shanghai timestamp.
        let primordial_pulse_block =
            network.map_or(PRIMORDIAL_PULSE_MAINNET_BLOCK, |n| n.primordial_pulse_block);
        let replay = network
            .map(|_| EthBeaconConsensus::new(Arc::new(EthereumReplaySpec(chain_spec.clone()))));
        let inner = EthBeaconConsensus::new(chain_spec);
        Self { inner, replay, primordial_pulse_block, chain_id }
    }

    /// Returns true if this block number falls before the `PrimordialPulse` transition.
    const fn is_pre_primordial_pulse(&self, block_number: u64) -> bool {
        block_number < self.primordial_pulse_block
    }
}

// ---------------------------------------------------------------------------
// HeaderValidator — overrides validate_header to fix the Shanghai-timestamp gap
// ---------------------------------------------------------------------------

impl<H> HeaderValidator<H> for PulsechainConsensus
where
    H: BlockHeader,
    EthBeaconConsensus<PulsechainChainSpec>: HeaderValidator<H>,
    EthBeaconConsensus<EthereumReplaySpec>: HeaderValidator<H>,
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

            // Delegate the rest of the validation. On a known network the replay validator
            // applies the same Ethereum rule, so it cannot fail on withdrawals here and every
            // later check runs.
            //
            // On any other chain the inner validator uses the PulseChain chainspec timestamp.
            // For timestamps in the gap it may produce a spurious withdrawals_root error, so
            // we re-map that specific error to Ok since we already validated the
            // withdrawals_root above with the correct rule.
            let result = match &self.replay {
                Some(replay) => replay.validate_header(header),
                None => self.inner.validate_header(header),
            };
            match result {
                Ok(()) => Ok(()),
                Err(
                    ConsensusError::WithdrawalsRootMissing |
                    ConsensusError::WithdrawalsRootUnexpected,
                ) => {
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
    Self: HeaderValidator<B::Header>,
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
    Self: Consensus<N::Block>,
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
// EthereumReplaySpec — the chain spec view for pre-fork headers
// ---------------------------------------------------------------------------

/// A [`PulsechainChainSpec`] that answers Shanghai by Ethereum's timestamp.
///
/// Every method delegates to the wrapped spec, except
/// [`EthereumHardforks::is_shanghai_active_at_timestamp`]. [`PulsechainConsensus`] uses it
/// only for headers below the `PrimordialPulse` block, which are Ethereum blocks.
#[derive(Debug, Clone)]
pub struct EthereumReplaySpec(Arc<PulsechainChainSpec>);

impl EthereumHardforks for EthereumReplaySpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.0.ethereum_fork_activation(fork)
    }

    fn is_shanghai_active_at_timestamp(&self, timestamp: u64) -> bool {
        timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP
    }
}

impl EthChainSpec for EthereumReplaySpec {
    type Header = Header;

    fn chain(&self) -> Chain {
        self.0.chain()
    }

    fn chain_id(&self) -> u64 {
        self.0.chain_id()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.0.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.0.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.0.deposit_contract()
    }

    fn genesis_hash(&self) -> B256 {
        self.0.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.0.prune_delete_limit()
    }

    fn display_hardforks(&self) -> Box<dyn Display> {
        self.0.display_hardforks()
    }

    fn genesis_header(&self) -> &Self::Header {
        self.0.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.0.genesis()
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        self.0.bootnodes()
    }

    fn is_optimism(&self) -> bool {
        self.0.is_optimism()
    }

    fn is_ethereum(&self) -> bool {
        self.0.is_ethereum()
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.0.final_paris_total_difficulty()
    }

    fn next_block_base_fee(&self, parent: &Self::Header, target_timestamp: u64) -> Option<u64> {
        self.0.next_block_base_fee(parent, target_timestamp)
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

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives_traits::Header;
    use reth_pulsechain_forks::chainspec::PULSECHAIN;

    fn mainnet_consensus() -> PulsechainConsensus {
        PulsechainConsensus::new(Arc::new(PulsechainChainSpec::new(PULSECHAIN.clone())))
    }

    fn header(number: u64, timestamp: u64, withdrawals_root: Option<B256>) -> SealedHeader {
        SealedHeader::seal_slow(Header {
            number,
            timestamp,
            withdrawals_root,
            ..Default::default()
        })
    }

    // The three tests below exercise the Shanghai-timestamp-gap fix in `validate_header`.
    // PulseChain replays Ethereum mainnet history, but its chainspec activates Shanghai at a
    // LATER timestamp than Ethereum. For pre-PrimordialPulse blocks the wrapper must validate the
    // `withdrawals_root` field against the ETHEREUM Shanghai timestamp (1,681,338,455), not
    // PulseChain's. These checks fire before delegating to the inner consensus, so a minimal
    // synthetic header is sufficient.

    /// Pre-fork block at/after Ethereum Shanghai is a real ETH Shanghai block and MUST carry a
    /// `withdrawals_root`; a missing one is rejected.
    #[test]
    fn pre_pp_post_eth_shanghai_requires_withdrawals_root() {
        let consensus = mainnet_consensus();
        let h =
            header(PRIMORDIAL_PULSE_MAINNET_BLOCK - 1, ETH_MAINNET_SHANGHAI_TIMESTAMP + 60, None);
        assert!(
            matches!(
                HeaderValidator::validate_header(&consensus, &h),
                Err(ConsensusError::WithdrawalsRootMissing)
            ),
            "pre-fork post-ETH-Shanghai block without withdrawals_root must be rejected",
        );
    }

    /// Pre-fork block before Ethereum Shanghai must NOT carry a `withdrawals_root`.
    #[test]
    fn pre_pp_pre_eth_shanghai_rejects_withdrawals_root() {
        let consensus = mainnet_consensus();
        let h = header(
            PRIMORDIAL_PULSE_MAINNET_BLOCK - 1,
            ETH_MAINNET_SHANGHAI_TIMESTAMP - 60,
            Some(B256::ZERO),
        );
        assert!(
            matches!(
                HeaderValidator::validate_header(&consensus, &h),
                Err(ConsensusError::WithdrawalsRootUnexpected)
            ),
            "pre-fork pre-ETH-Shanghai block with a withdrawals_root must be rejected",
        );
    }

    /// The Ethereum Shanghai boundary is inclusive: exactly at the timestamp counts as
    /// Shanghai-active, so a missing `withdrawals_root` is still rejected.
    #[test]
    fn pre_pp_exact_eth_shanghai_boundary_is_shanghai_active() {
        let consensus = mainnet_consensus();
        let h = header(PRIMORDIAL_PULSE_MAINNET_BLOCK - 1, ETH_MAINNET_SHANGHAI_TIMESTAMP, None);
        assert!(matches!(
            HeaderValidator::validate_header(&consensus, &h),
            Err(ConsensusError::WithdrawalsRootMissing)
        ));
    }

    // The tests below pin the full header check, not only the withdrawals rule. They use
    // headers that pass the base-fee and gas checks, so a later check decides the result.

    /// Mainnet `PulseChain` Shanghai timestamp.
    const PULSECHAIN_SHANGHAI: u64 = reth_pulsechain_forks::hardfork::SHANGHAI_MAINNET_TIMESTAMP;

    /// A pre-merge London header that passes every check before the withdrawals rule.
    fn london_header(
        number: u64,
        timestamp: u64,
        withdrawals_root: Option<B256>,
        blob_gas_used: Option<u64>,
    ) -> SealedHeader {
        SealedHeader::seal_slow(Header {
            number,
            timestamp,
            withdrawals_root,
            blob_gas_used,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            ..Default::default()
        })
    }

    fn consensus_for(spec: Arc<reth_chainspec::ChainSpec>) -> PulsechainConsensus {
        PulsechainConsensus::new(Arc::new(PulsechainChainSpec::new(spec)))
    }

    /// A pre-fork header in the Shanghai gap, with its withdrawals root, is valid.
    #[test]
    fn pre_pp_gap_block_with_withdrawals_root_is_valid() {
        let consensus = mainnet_consensus();
        let h = london_header(
            PRIMORDIAL_PULSE_MAINNET_BLOCK - 1,
            ETH_MAINNET_SHANGHAI_TIMESTAMP + 60,
            Some(B256::ZERO),
            None,
        );
        HeaderValidator::validate_header(&consensus, &h).unwrap();
    }

    /// Pre-fork headers on 369 and 943 still get every check after the withdrawals rule.
    ///
    /// The timestamps sit where the chain spec's own Shanghai rule says "not active" but the
    /// Ethereum rule says "active". Only the block number marks these headers as pre-fork.
    /// The Cancun check must still run and reject the blob gas field.
    #[test]
    fn pre_pp_header_runs_the_checks_after_withdrawals() {
        use reth_pulsechain_forks::{
            chainspec::PULSECHAIN_TESTNET_V4, hardfork::PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        };

        let cases = [
            (PULSECHAIN.clone(), PRIMORDIAL_PULSE_MAINNET_BLOCK - 1, PULSECHAIN_SHANGHAI - 10),
            (
                PULSECHAIN_TESTNET_V4.clone(),
                PRIMORDIAL_PULSE_TESTNET_V4_BLOCK - 1,
                ETH_MAINNET_SHANGHAI_TIMESTAMP + 60,
            ),
        ];
        for (spec, number, timestamp) in cases {
            let consensus = consensus_for(spec);
            let valid = london_header(number, timestamp, Some(B256::ZERO), None);
            HeaderValidator::validate_header(&consensus, &valid).unwrap();

            let blob = london_header(number, timestamp, Some(B256::ZERO), Some(0));
            assert!(
                matches!(
                    HeaderValidator::validate_header(&consensus, &blob),
                    Err(ConsensusError::BlobGasUsedUnexpected)
                ),
                "chain {}: a pre-fork header with a blob gas field must be rejected",
                consensus.chain_id,
            );
        }
    }

    /// After `PrimordialPulse` the chain spec's Shanghai rule decides, not Ethereum's.
    ///
    /// The header is post-merge and before `PulseChain`'s Shanghai, so a withdrawals root is
    /// unexpected even though Ethereum's Shanghai passed long before.
    #[test]
    fn post_pp_header_uses_the_pulsechain_shanghai_rule() {
        let consensus = mainnet_consensus();
        let post_fork = |withdrawals_root| {
            SealedHeader::seal_slow(Header {
                number: PRIMORDIAL_PULSE_MAINNET_BLOCK + 1,
                timestamp: PULSECHAIN_SHANGHAI - 10,
                withdrawals_root,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(7),
                ..Default::default()
            })
        };
        HeaderValidator::validate_header(&consensus, &post_fork(None)).unwrap();
        assert!(matches!(
            HeaderValidator::validate_header(&consensus, &post_fork(Some(B256::ZERO))),
            Err(ConsensusError::WithdrawalsRootUnexpected)
        ));
    }

    /// A chain spec that no `PulseChain` network claims keeps the mainnet fallback.
    ///
    /// Below block 17,233,000 the wrapper applies the Ethereum rule. It then drops the inner
    /// validator's withdrawals error, and with it the checks after that error. This pins that
    /// legacy behavior; changing it is a separate decision.
    #[test]
    fn unknown_chain_keeps_the_mainnet_fallback() {
        let mut spec = (**PULSECHAIN).clone();
        spec.chain = reth_chainspec::Chain::from_id(12_345);
        let consensus = consensus_for(Arc::new(spec));

        let h = london_header(
            PRIMORDIAL_PULSE_MAINNET_BLOCK - 1,
            ETH_MAINNET_SHANGHAI_TIMESTAMP + 60,
            Some(B256::ZERO),
            Some(0),
        );
        HeaderValidator::validate_header(&consensus, &h).unwrap();
    }
}
