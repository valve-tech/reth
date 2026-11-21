//! `PulseChain` block body storage.
//!
//! [`PulsechainStorage`] writes bodies as [`EthStorage`] does and reads them
//! back the same way, with one difference. Blocks before `PrimordialPulse` are
//! Ethereum blocks, so their withdrawals follow Ethereum's Shanghai timestamp,
//! not the chain spec's.
//!
//! The rule goes by block number, as the old patch to `EthStorage` did. The
//! chain spec's own Shanghai override goes by timestamp, and the two disagree
//! for a header whose number and timestamp sit on different sides of the fork.

use alloy_primitives::BlockNumber;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives};
use reth_provider::{
    providers::{ChainStorage, NodeTypesForProvider},
    BlockBodyReader, BlockBodyWriter, ChainSpecProvider, ChainStorageReader, ChainStorageWriter,
    DBProvider, DatabaseProvider, EthStorage, ProviderResult, ReadBodyInput,
};
use reth_pulsechain_forks::{
    hardfork::ETH_MAINNET_SHANGHAI_TIMESTAMP, network::pulsechain_network,
};

/// Chain 32382, a devnet from the first `PulseChain` port.
///
/// The old `EthStorage` patch listed it with `PrimordialPulse` at block 10.
/// Nothing else in the tree knows this chain. It stays here only so that this
/// move changes no behavior.
const LEGACY_DEVNET_CHAIN_ID: u64 = 32_382;

/// The `PrimordialPulse` block of [`LEGACY_DEVNET_CHAIN_ID`].
const LEGACY_DEVNET_PRIMORDIAL_PULSE_BLOCK: u64 = 10;

/// Returns the block below which `chain_id` holds Ethereum blocks, if any.
fn ethereum_replay_end(chain_id: u64) -> Option<BlockNumber> {
    match pulsechain_network(chain_id) {
        Some(network) => Some(network.primordial_pulse_block),
        None if chain_id == LEGACY_DEVNET_CHAIN_ID => Some(LEGACY_DEVNET_PRIMORDIAL_PULSE_BLOCK),
        None => None,
    }
}

/// Block body storage for `PulsechainNode`. See the module docs.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct PulsechainStorage(EthStorage);

impl<Provider> BlockBodyWriter<Provider, BlockBody> for PulsechainStorage
where
    EthStorage: BlockBodyWriter<Provider, BlockBody>,
{
    fn write_block_bodies(
        &self,
        provider: &Provider,
        bodies: Vec<(BlockNumber, Option<&BlockBody>)>,
    ) -> ProviderResult<()> {
        self.0.write_block_bodies(provider, bodies)
    }

    fn remove_block_bodies_above(
        &self,
        provider: &Provider,
        block: BlockNumber,
    ) -> ProviderResult<()> {
        self.0.remove_block_bodies_above(provider, block)
    }
}

impl<Provider> BlockBodyReader<Provider> for PulsechainStorage
where
    Provider: DBProvider + ChainSpecProvider<ChainSpec: EthereumHardforks>,
    EthStorage: BlockBodyReader<Provider, Block = Block>,
{
    type Block = Block;

    fn read_block_bodies(
        &self,
        provider: &Provider,
        inputs: Vec<ReadBodyInput<'_, Block>>,
    ) -> ProviderResult<Vec<BlockBody>> {
        let chain_spec = provider.chain_spec();
        let Some(replay_end) = ethereum_replay_end(chain_spec.chain_id()) else {
            return self.0.read_block_bodies(provider, inputs);
        };

        // For each pre-fork header where Ethereum's rule and the chain spec's rule
        // disagree, note the block and Ethereum's answer.
        let fixes: Vec<Option<(BlockNumber, bool)>> = inputs
            .iter()
            .map(|(header, _)| {
                if header.number >= replay_end {
                    return None;
                }
                let ethereum_rule = header.timestamp >= ETH_MAINNET_SHANGHAI_TIMESTAMP;
                let spec_rule = chain_spec.is_shanghai_active_at_timestamp(header.timestamp);
                (ethereum_rule != spec_rule).then_some((header.number, ethereum_rule))
            })
            .collect();

        let mut bodies = self.0.read_block_bodies(provider, inputs)?;
        if fixes.iter().all(Option::is_none) {
            return Ok(bodies);
        }

        let mut withdrawals_cursor = provider.tx_ref().cursor_read::<tables::BlockWithdrawals>()?;
        for (body, fix) in bodies.iter_mut().zip(fixes) {
            let Some((number, shanghai_active)) = fix else { continue };
            body.withdrawals = if shanghai_active {
                withdrawals_cursor
                    .seek_exact(number)?
                    .map(|(_, w)| w.withdrawals)
                    .unwrap_or_default()
                    .into()
            } else {
                None
            };
        }
        Ok(bodies)
    }
}

impl ChainStorage<EthPrimitives> for PulsechainStorage {
    fn reader<TX, Types>(
        &self,
    ) -> impl ChainStorageReader<DatabaseProvider<TX, Types>, EthPrimitives>
    where
        TX: DbTx + 'static,
        Types: NodeTypesForProvider<Primitives = EthPrimitives>,
    {
        self
    }

    fn writer<TX, Types>(
        &self,
    ) -> impl ChainStorageWriter<DatabaseProvider<TX, Types>, EthPrimitives>
    where
        TX: reth_db_api::transaction::DbTxMut + DbTx + 'static,
        Types: NodeTypesForProvider<Primitives = EthPrimitives>,
    {
        self
    }
}
