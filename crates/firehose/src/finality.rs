//! Resolves which finalized block a Firehose block event may advertise.
//!
//! The Firehose protocol carries finality as a bare block *number* (`libNum` on the `FIRE BLOCK`
//! line): the consumer resolves that number against the block it already holds at that height.
//! That only holds together when the advertised finalized block is an ancestor of the block being
//! emitted. The node's finalized head is a property of the canonical chain, so stamping it
//! verbatim onto a block from a side branch tells the consumer that a block it will later see
//! replaced is irreversible.
//!
//! [`finalized_ref_for_block`] answers with a block that is always an ancestor of the block being
//! emitted: the node's finalized head when that head is on the block's own chain, and otherwise
//! the point where the block's branch left the canonical chain (which sits below the finalized
//! head and is therefore itself final). When the branch cannot be tied to the canonical chain at
//! all, it answers with genesis, the one block that is an ancestor of everything.

use crate::prelude::*;
use alloy_eips::BlockNumHash;
use firehose_tracer::types::FinalizedBlockRef;

/// Returns the finalized block to advertise for the block at `block_number` whose parent is
/// `parent_hash`, guaranteeing that the returned block is an ancestor of it.
///
/// `finalized` is the node's finalized head (`None` when the node has none yet, in which case
/// there is nothing to advertise). `block_parent` returns the number and parent hash of the block
/// with a given hash, and must see side-branch blocks, not just canonical ones. `canonical_hash`
/// returns the hash of the canonical block at a given height, or `None` above the canonical head.
///
/// The walk starts at the parent and stops at the first ancestor that is canonical:
///
/// - a block extending the canonical chain stops on the first hop, and the node's finalized head is
///   returned unchanged;
/// - a block on a side branch stops at the fork point, and the lower of the fork point and the
///   finalized head is returned.
///
/// It always terminates: every hop moves strictly down in block number, so the walk ends at the
/// fork point, at genesis, or where the chain of known headers runs out. That last case — a branch
/// that cannot be tied to the canonical chain — advertises genesis, since nothing above it can be
/// shown to be an ancestor of the block being emitted.
pub fn finalized_ref_for_block<P, C>(
    block_number: u64,
    parent_hash: B256,
    finalized: Option<BlockNumHash>,
    mut block_parent: P,
    mut canonical_hash: C,
) -> Option<FinalizedBlockRef>
where
    P: FnMut(B256) -> Option<(u64, B256)>,
    C: FnMut(u64) -> Option<B256>,
{
    let finalized = finalized?;

    // Genesis has no ancestor to fall back on, and is final by definition.
    let Some(mut number) = block_number.checked_sub(1) else {
        return Some(FinalizedBlockRef::new(finalized.number, finalized.hash));
    };

    let mut hash = parent_hash;
    loop {
        if canonical_hash(number) == Some(hash) {
            // `number` is on the canonical chain, so every canonical block at or below it is an
            // ancestor of the block being emitted.
            return Some(if finalized.number <= number {
                FinalizedBlockRef::new(finalized.number, finalized.hash)
            } else {
                FinalizedBlockRef::new(number, hash)
            });
        }

        let Some((cursor_number, next_hash)) = block_parent(hash) else { break };
        let Some(next_number) = cursor_number.checked_sub(1) else { break };
        // Each hop must move strictly down. Anything else means the header source disagrees with
        // itself, and continuing would not terminate.
        if next_number >= number {
            break;
        }
        number = next_number;
        hash = next_hash;
    }

    // The branch could not be tied back to the canonical chain, so no block above genesis can be
    // shown to be an ancestor of this one.
    warn!(
        target: "firehose",
        block_number,
        %parent_hash,
        finalized_number = finalized.number,
        "Could not tie block to the canonical chain; advertising genesis as the finalized block"
    );
    Some(FinalizedBlockRef::minimal(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use std::collections::HashMap;

    fn hash(tag: u8) -> B256 {
        B256::repeat_byte(tag)
    }

    /// Canonical chain 0..=743 plus a side branch that leaves it after 739, mirroring the BSC
    /// mainnet reorg at 120653740: both branches hold four blocks, the canonical ones tagged
    /// `0xc*` and the dead ones `0xd*`.
    struct Chains {
        /// hash -> (number, parent hash), covering both branches.
        blocks: HashMap<B256, (u64, B256)>,
        /// number -> hash, canonical only.
        canonical: HashMap<u64, B256>,
    }

    impl Chains {
        fn new() -> Self {
            let mut blocks = HashMap::new();
            let mut canonical = HashMap::new();

            // Shared history: 737, 738, 739.
            let shared = [(737u64, hash(0x37)), (738, hash(0x38)), (739, hash(0x39))];
            let mut parent = hash(0x36);
            for (number, hash) in shared {
                blocks.insert(hash, (number, parent));
                canonical.insert(number, hash);
                parent = hash;
            }

            // Canonical branch 740..=743.
            let mut parent = hash(0x39);
            for (number, hash) in
                [(740u64, hash(0xc0)), (741, hash(0xc1)), (742, hash(0xc2)), (743, hash(0xc3))]
            {
                blocks.insert(hash, (number, parent));
                canonical.insert(number, hash);
                parent = hash;
            }

            // Dead branch 740..=743, sharing 739 as parent.
            let mut parent = hash(0x39);
            for (number, hash) in
                [(740u64, hash(0xd0)), (741, hash(0xd1)), (742, hash(0xd2)), (743, hash(0xd3))]
            {
                blocks.insert(hash, (number, parent));
                parent = hash;
            }

            Self { blocks, canonical }
        }

        /// Resolves the ref for a block given its parent, with the canonical 741 finalized.
        fn resolve(&self, block_number: u64, parent_hash: B256) -> Option<FinalizedBlockRef> {
            self.resolve_with(block_number, parent_hash, Some(BlockNumHash::new(741, hash(0xc1))))
        }

        fn resolve_with(
            &self,
            block_number: u64,
            parent_hash: B256,
            finalized: Option<BlockNumHash>,
        ) -> Option<FinalizedBlockRef> {
            finalized_ref_for_block(
                block_number,
                parent_hash,
                finalized,
                |hash| self.blocks.get(&hash).copied(),
                |number| self.canonical.get(&number).copied(),
            )
        }
    }

    #[test]
    fn canonical_block_advertises_the_finalized_head() {
        let chains = Chains::new();

        // Canonical 744 extending canonical 743: the finalized head is on its own chain.
        let advertised = chains.resolve(744, hash(0xc3)).expect("finalized head is known");
        assert_eq!(advertised.number, 741);
        assert_eq!(advertised.hash, Some(hash(0xc1)));
    }

    #[test]
    fn side_branch_block_advertises_the_fork_point() {
        let chains = Chains::new();

        // Every block of the dead branch splits from the canonical chain after 739, so 739 is the
        // highest block all of them share with the finalized chain.
        for (number, parent) in
            [(740u64, hash(0x39)), (741, hash(0xd0)), (742, hash(0xd1)), (743, hash(0xd2))]
        {
            let advertised = chains.resolve(number, parent).expect("finalized head is known");
            assert_eq!(
                advertised.number, 739,
                "dead-branch block {number} must not advertise a finalized block from the \
                 canonical branch"
            );
            assert_eq!(advertised.hash, Some(hash(0x39)));
        }
    }

    #[test]
    fn advertised_number_stays_below_the_block_itself() {
        let chains = Chains::new();

        // A finalized head at or above the block being emitted can only come from another branch;
        // the answer stays on the block's own chain.
        let advertised = chains
            .resolve_with(740, hash(0x39), Some(BlockNumHash::new(743, hash(0xc3))))
            .expect("finalized head is known");
        assert_eq!(advertised.number, 739);
    }

    #[test]
    fn finalized_below_the_fork_point_is_kept() {
        let chains = Chains::new();

        // Dead-branch 743 with 738 finalized: 738 is an ancestor of it, so it is advertised as is.
        let advertised = chains
            .resolve_with(743, hash(0xd2), Some(BlockNumHash::new(738, hash(0x38))))
            .expect("finalized head is known");
        assert_eq!(advertised.number, 738);
        assert_eq!(advertised.hash, Some(hash(0x38)));
    }

    #[test]
    fn no_finalized_head_advertises_nothing() {
        let chains = Chains::new();

        assert!(chains.resolve_with(744, hash(0xc3), None).is_none());
    }

    #[test]
    fn unresolvable_branch_advertises_genesis() {
        let chains = Chains::new();

        // A parent the tree state does not hold: the walk cannot reach the canonical chain, so
        // nothing above genesis can be shown to be an ancestor of this block.
        let advertised = chains
            .resolve_with(1_000, hash(0xee), Some(BlockNumHash::new(900, hash(0xc1))))
            .expect("finalized head is known");
        assert_eq!(advertised.number, 0);
        assert_eq!(advertised.hash, None);
    }

    #[test]
    fn long_side_branch_still_finds_the_fork_point() {
        // A 300-block side branch off canonical 700, longer than any reorg either chain produces.
        // The walk has no depth limit, so it still reaches the fork point.
        let fork_point = 700u64;
        let branch_len = 300u64;
        let canonical: HashMap<u64, B256> = (0..=fork_point)
            .map(|n| (n, B256::with_last_byte(1) ^ B256::from(U256::from(n))))
            .collect();
        let mut blocks: HashMap<B256, (u64, B256)> = HashMap::new();
        let mut parent = canonical[&fork_point];
        for i in 1..=branch_len {
            let number = fork_point + i;
            let hash = B256::with_last_byte(2) ^ B256::from(U256::from(number));
            blocks.insert(hash, (number, parent));
            parent = hash;
        }
        let tip = fork_point + branch_len;
        let tip_parent = blocks[&(B256::with_last_byte(2) ^ B256::from(U256::from(tip)))].1;

        let advertised = finalized_ref_for_block(
            tip,
            tip_parent,
            Some(BlockNumHash::new(900, B256::repeat_byte(0xaa))),
            |hash| blocks.get(&hash).copied(),
            |number| canonical.get(&number).copied(),
        )
        .expect("finalized head is known");

        assert_eq!(advertised.number, fork_point);
        assert_eq!(advertised.hash, Some(canonical[&fork_point]));
    }

    #[test]
    fn inconsistent_parent_lookup_terminates() {
        // A header source that keeps answering with the same block would loop forever without the
        // strictly-decreasing guard.
        let stuck = B256::repeat_byte(0xee);
        let advertised = finalized_ref_for_block(
            500,
            stuck,
            Some(BlockNumHash::new(400, B256::repeat_byte(0xc1))),
            |_| Some((499, stuck)),
            |_| None,
        )
        .expect("finalized head is known");

        assert_eq!(advertised.number, 0);
    }

    #[test]
    fn genesis_advertises_the_finalized_head() {
        let chains = Chains::new();

        let advertised = chains
            .resolve_with(0, B256::ZERO, Some(BlockNumHash::new(0, hash(0x01))))
            .expect("finalized head is known");
        assert_eq!(advertised.number, 0);
    }
}
