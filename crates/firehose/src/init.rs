use crate::{mapper, prelude::*};
use reth_chainspec::EthChainSpec;
use reth_provider::{BlockReader, ChainSpecProvider};

/// Emits `FIRE INIT` and, on an empty chain, the genesis block.
///
/// Call it once from the node builder's `on_component_initialized` hook. The tracer panics on a
/// block that starts before `FIRE INIT`, and the consensus engine can execute blocks before the
/// `on_node_started` hook runs.
pub fn init_blockchain<P>(provider: &P) -> eyre::Result<()>
where
    P: BlockReader + ChainSpecProvider<ChainSpec: EthChainSpec>,
    <P::Block as reth_primitives_traits::Block>::Header: BlockHeader + alloy_primitives::Sealable,
    <<P::Block as reth_primitives_traits::Block>::Body as reth_primitives_traits::BlockBody>::OmmerHeader:
        BlockHeader + alloy_primitives::Sealable,
{
    let chain_spec = provider.chain_spec();
    crate::tracer().on_blockchain_init(
        "reth",
        env!("CARGO_PKG_VERSION"),
        firehose_tracer::config::ChainConfig::new(chain_spec.chain().id()),
    );

    emit_genesis_block_on_empty_chain(provider, chain_spec.genesis())
}

/// Emits the genesis block (block 0) to the Firehose stream if the chain is empty (head still
/// at genesis).
///
/// Reth never executes the genesis block — it is written straight to the database during init —
/// so no execution hook ever fires for it. Without this, a Firehose stream started from scratch
/// begins at block 1 and downstream consumers waiting for block 0 stall forever. Mirrors geth's
/// `OnGenesisBlock` hook: emitted with the full genesis alloc, only when starting on an empty
/// chain.
///
/// Call it once at node startup, after `on_blockchain_init` and before any block is traced.
/// Embedders that report their own node name or version in `FIRE INIT` call this directly instead
/// of [`init_blockchain`].
pub fn emit_genesis_block_on_empty_chain<P>(
    provider: &P,
    genesis: &alloy_genesis::Genesis,
) -> eyre::Result<()>
where
    P: BlockReader,
    <P::Block as reth_primitives_traits::Block>::Header: BlockHeader + alloy_primitives::Sealable,
    <<P::Block as reth_primitives_traits::Block>::Body as reth_primitives_traits::BlockBody>::OmmerHeader:
        BlockHeader + alloy_primitives::Sealable,
{
    use reth_primitives_traits::Block as _;

    // OP-stack chains may place their genesis at a non-zero height (e.g. OP mainnet's
    // post-bedrock genesis); `genesis.number` carries it, defaulting to 0.
    let genesis_number = genesis.number.unwrap_or(0);
    if provider.best_block_number()? != genesis_number {
        return Ok(());
    }

    let genesis_block = provider
        .block(genesis_number.into())?
        .ok_or_else(|| eyre::eyre!("genesis block {genesis_number} not found in database"))?
        .seal_slow();

    crate::tracer().on_genesis_block(
        firehose_tracer::types::BlockEvent {
            block: mapper::to_block_data(&genesis_block),
            // Genesis is finalized by definition.
            finalized: Some(firehose_tracer::types::FinalizedBlockRef {
                number: genesis_number,
                hash: Some(genesis_block.hash()),
            }),
            flash_block: None,
        },
        mapper::to_genesis_alloc(genesis),
    );

    Ok(())
}
