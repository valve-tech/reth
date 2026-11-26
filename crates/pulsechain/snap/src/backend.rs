//! What the request server needs from a node: which lane a root belongs to, state range views,
//! and code lookups.

use crate::{bytecodes::serve_byte_codes, server::Lane};
use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth_eth_wire_types::snap::{ByteCodesMessage, GetByteCodesMessage};
use reth_provider::providers::{BlockchainProvider, ProviderNodeTypes, SNAPSHOT_STATE_RETENTION};
use reth_stages_types::StageId;
use reth_storage_api::{
    errors::provider::ProviderResult, BlockNumReader, DatabaseProviderFactory, HeaderProvider,
    StageCheckpointReader, StateProviderFactory, StateRangeProviderFactory, StateRangeView,
};

/// A state root a backend serves now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedRoot {
    /// The state root.
    pub root: B256,
    /// The lane it is served on.
    pub lane: Lane,
    /// How many blocks its block is behind the head.
    pub depth: u64,
}

/// Tells the server how expensive serving a state root is.
pub trait RootLanes {
    /// Returns the lane `root` is served on, or `None` when the root is not served.
    ///
    /// A backend that lists its roots answers here only while its listing fails, for roots the
    /// server's last list lacks. It returns `None` for any root it cannot place cheaply, so junk
    /// roots take no slot.
    fn lane(&self, root: B256) -> Option<Lane>;

    /// Returns how many blocks the block with `root` is behind the head, if it is cheap to know.
    fn depth(&self, _root: B256) -> Option<u64> {
        None
    }

    /// Returns the lane of `root` and, if cheap, its depth, in one lookup.
    ///
    /// The server calls this once per admitted request when [`Self::retained_roots`] gives
    /// nothing, on an async thread, so it must be cheap.
    fn classify(&self, root: B256) -> Option<(Lane, Option<u64>)> {
        let lane = self.lane(root)?;
        Some((lane, self.depth(root)))
    }

    /// Lists every root the backend serves now, or `None` when it cannot list them.
    ///
    /// A root may be listed more than once; the server uses its entry with the least depth.
    ///
    /// The call may block. The server makes it rarely, off the async threads, and caches the
    /// result for a short time. With a list, a root not on it is answered empty before it takes
    /// any slot. Without one, the server asks [`Self::classify`] per request.
    fn retained_roots(&self) -> Option<Vec<RetainedRoot>> {
        None
    }
}

/// Lists the roots `provider` serves among the [`SNAPSHOT_STATE_RETENTION`] persisted blocks up to
/// the `Finish` checkpoint and the blocks above it. The roots of the checkpoint block and of every
/// block above it are hot: their views need no reverts. The others are cold. `None` when the
/// provider fails.
fn list_retained_roots<P>(provider: &P) -> Option<Vec<RetainedRoot>>
where
    P: HeaderProvider + BlockNumReader + DatabaseProviderFactory,
    P::Provider: StageCheckpointReader,
{
    let best = provider.best_block_number().ok()?;
    let persisted =
        provider.database_provider_ro().ok()?.get_stage_checkpoint(StageId::Finish).ok()??;
    let persisted = persisted.block_number.min(best);
    let oldest_cold = persisted.saturating_sub(SNAPSHOT_STATE_RETENTION - 1);
    let mut roots = Vec::new();
    // The blocks above the checkpoint are the engine's in-memory chain, which its persistence
    // backpressure keeps short.
    for (range, lane) in
        [(persisted..best.saturating_add(1), Lane::Hot), (oldest_cold..persisted, Lane::Cold)]
    {
        if range.is_empty() {
            continue
        }
        for header in provider.headers_range(range).ok()? {
            let depth = best - header.number();
            roots.push(RetainedRoot { root: header.state_root(), lane, depth });
        }
    }
    Some(roots)
}

/// Everything [`Snap1Server`](crate::Snap1Server) reads from a node.
pub trait Snap1Backend: StateRangeProviderFactory + RootLanes + Send + Sync + 'static {
    /// Answers a `GetByteCodes` request.
    fn byte_codes(&self, req: &GetByteCodesMessage) -> ProviderResult<ByteCodesMessage>;
}

/// The `Finish` checkpoint block and the blocks above it are hot: their views need no reverts.
/// Any other root needs the persisted-history lookup and reverts, so it is cold. The engine keeps
/// some persisted blocks in memory after it writes them, and those below the checkpoint are cold
/// too.
///
/// [`RootLanes::retained_roots`] lists the retained roots, so the server answers any other root
/// empty at once. [`RootLanes::lane`] cannot say cheaply whether a non-memory root is retained,
/// so while listings fail it adds only the in-memory roots to the server's last list, with the
/// lane the checkpoint gives them. That costs one read transaction per request. When the
/// checkpoint cannot be read, as is likely while listings fail, an in-memory root is cold: the
/// cold lane's limits hold for any view.
impl<N: ProviderNodeTypes> RootLanes for BlockchainProvider<N> {
    fn lane(&self, root: B256) -> Option<Lane> {
        self.classify(root).map(|(lane, _)| lane)
    }

    fn classify(&self, root: B256) -> Option<(Lane, Option<u64>)> {
        // `canonical_chain` starts at the head.
        let (depth, number) = self
            .canonical_in_memory_state()
            .canonical_chain()
            .enumerate()
            .find(|(_, state)| state.state_root() == root)
            .map(|(depth, state)| (depth as u64, state.number()))?;
        // As `list_retained_roots`: the checkpoint, at most the head, is the lowest hot block.
        let finish = self
            .database_provider_ro()
            .ok()
            .and_then(|provider| provider.get_stage_checkpoint(StageId::Finish).ok().flatten());
        let lane = match finish {
            Some(finish) if number >= finish.block_number.min(number + depth) => Lane::Hot,
            _ => Lane::Cold,
        };
        Some((lane, Some(depth)))
    }

    fn retained_roots(&self) -> Option<Vec<RetainedRoot>> {
        list_retained_roots(self)
    }

    fn depth(&self, root: B256) -> Option<u64> {
        // `canonical_chain` starts at the head.
        self.canonical_in_memory_state()
            .canonical_chain()
            .position(|state| state.state_root() == root)
            .map(|depth| depth as u64)
    }
}

impl<N: ProviderNodeTypes> Snap1Backend for BlockchainProvider<N> {
    fn byte_codes(&self, req: &GetByteCodesMessage) -> ProviderResult<ByteCodesMessage> {
        serve_byte_codes(self, req)
    }
}

/// A [`Snap1Backend`] for any node provider, for code that cannot name
/// [`BlockchainProvider`] such as a generic node builder.
///
/// Without access to the in-memory chain it lists the hot roots by header: a root is hot when the
/// `Finish` checkpoint block or a block above it has it, because those views need no reverts.
/// Everything else is cold. It can place a root only by reading the database, so while
/// listings fail it serves only the roots of the last list, and only for one more
/// [`Snap1Config::roots_ttl`](crate::Snap1Config::roots_ttl).
#[derive(Debug, Clone)]
pub struct ProviderBackend<P> {
    provider: P,
}

impl<P> ProviderBackend<P> {
    /// Wraps `provider`.
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: StateRangeProviderFactory> StateRangeProviderFactory for ProviderBackend<P> {
    fn state_range_provider(&self, state_root: B256) -> ProviderResult<Option<StateRangeView>> {
        self.provider.state_range_provider(state_root)
    }
}

impl<P> RootLanes for ProviderBackend<P>
where
    P: HeaderProvider + BlockNumReader + DatabaseProviderFactory,
    P::Provider: StageCheckpointReader,
{
    fn lane(&self, _root: B256) -> Option<Lane> {
        None
    }

    fn retained_roots(&self) -> Option<Vec<RetainedRoot>> {
        list_retained_roots(&self.provider)
    }
}

impl<P> Snap1Backend for ProviderBackend<P>
where
    P: StateProviderFactory
        + StateRangeProviderFactory
        + HeaderProvider
        + BlockNumReader
        + DatabaseProviderFactory
        + Send
        + Sync
        + 'static,
    P::Provider: StageCheckpointReader,
{
    fn byte_codes(&self, req: &GetByteCodesMessage) -> ProviderResult<ByteCodesMessage> {
        serve_byte_codes(&self.provider, req)
    }
}
