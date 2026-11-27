//! The backfill below the seeded anchor.
//!
//! The node seeds its chain from one finalized block, so after a start it holds no block below
//! it: `BLOCKHASH` of an older block and reads of recent blocks fail until the head has moved
//! far enough. After each seed the node asks peers for the [`BACKFILL_BLOCKS`] canonical blocks
//! below the lowest one it holds (eth/68 `GetBlockHeaders`, then `GetBlockBodies`). A header is
//! taken only when its hash is the parent hash of the block above it, so the whole run links to
//! the seeded block and no peer can forge one. A body is taken only when it matches its header's
//! roots; a block whose body no peer serves is held without one, which `BLOCKHASH` still reads.

use crate::{
    chain::{HeaderChain, HeldBlock, HEADERS_WINDOW},
    verify::verify_body,
};
use alloy_consensus::{BlockBody, Header, TxEnvelope};
use alloy_primitives::B256;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

/// Blocks held below the anchor after a seed: what `BLOCKHASH` reaches.
pub const BACKFILL_BLOCKS: u64 = 256;
/// Bodies asked for in one request.
const BODIES_PER_REQUEST: usize = 64;
/// Tries of one [`backfill`]. Each try asks for what the ones before it did not get.
const TRIES: usize = 3;
/// The pause between two tries, and between two looks for a new seed.
const PAUSE: Duration = Duration::from_secs(5);
/// The wait before [`backfill_loop`] tries an unfinished backfill again: it doubles after each
/// round, up to [`RETRY_MAX`]. At a start the peers connect after the seed.
const RETRY_FIRST: Duration = Duration::from_secs(30);
/// The longest wait between two rounds of an unfinished backfill.
const RETRY_MAX: Duration = Duration::from_secs(600);

/// Where the backfill gets blocks. Nothing it returns is trusted.
#[async_trait]
pub trait History: Send + Sync {
    /// Up to `limit` headers from one peer: the block `hash` and then its ancestors, highest
    /// first. Empty when no peer answered.
    async fn headers_down(&self, hash: B256, limit: u64) -> Vec<Header>;
    /// The bodies of the blocks `hashes`, in their order, as one peer answers: it may stop
    /// early. Empty when no peer answered.
    async fn bodies(&self, hashes: &[B256]) -> Vec<BlockBody<TxEnvelope>>;
}

/// Fetches, checks and holds the blocks below the lowest canonical block of `chain`, until
/// [`BACKFILL_BLOCKS`] are held below the block it started from, the chain is re-seeded, or
/// [`TRIES`] tries end. A try that adds nothing waits [`PAUSE`] before the next. Returns how
/// many it held.
pub async fn backfill(chain: &HeaderChain, history: &dyn History) -> usize {
    let Some((_, start)) = chain.lowest_canonical() else { return 0 };
    backfill_to(chain, history, start.header.number.saturating_sub(BACKFILL_BLOCKS)).await
}

/// [`backfill`] down to block `bottom`.
async fn backfill_to(chain: &HeaderChain, history: &dyn History, bottom: u64) -> usize {
    let Some((epoch, _)) = chain.lowest_canonical() else { return 0 };
    let mut held = 0;
    for _ in 0..TRIES {
        let Some((now, top)) = chain.lowest_canonical() else { break };
        if now != epoch || top.header.number <= bottom {
            break;
        }
        let blocks = fetch_below(&top, top.header.number - bottom, history).await;
        match chain.backfill(epoch, top.hash, blocks) {
            Ok(0) => {}
            Ok(n) => {
                held += n;
                continue;
            }
            Err(e) => {
                tracing::debug!(%e, "backfill stopped");
                break;
            }
        }
        tokio::time::sleep(PAUSE).await;
    }
    held
}

/// Up to `count` blocks below `top`, highest first: the headers that link to it, each with its
/// body when a peer served one that matches the header.
async fn fetch_below(top: &HeldBlock, count: u64, history: &dyn History) -> Vec<HeldBlock> {
    let mut expect = top.header.parent_hash;
    let mut headers = Vec::new();
    // The answer is cut at the first header that does not link: the rest cannot be checked.
    for header in history.headers_down(expect, count).await.into_iter().take(count as usize) {
        let hash = header.hash_slow();
        if hash != expect {
            tracing::debug!(%hash, %expect, "a backfill header does not link; dropping the rest");
            break;
        }
        expect = header.parent_hash;
        headers.push((hash, header));
    }
    let mut bodies: Vec<Option<BlockBody<TxEnvelope>>> = vec![None; headers.len()];
    for (chunk, slots) in
        headers.chunks(BODIES_PER_REQUEST).zip(bodies.chunks_mut(BODIES_PER_REQUEST))
    {
        let hashes: Vec<B256> = chunk.iter().map(|(h, _)| *h).collect();
        for ((_, header), (body, slot)) in
            chunk.iter().zip(history.bodies(&hashes).await.into_iter().zip(slots))
        {
            match verify_body(header, &body) {
                Ok(()) => *slot = Some(body),
                Err(e) => {
                    tracing::debug!(%e, number = header.number, "a backfill body does not match");
                    break;
                }
            }
        }
    }
    headers
        .into_iter()
        .zip(bodies)
        .map(|((hash, header), body)| HeldBlock {
            hash,
            header,
            // The beacon root is not in the execution header: a backfilled block is never a head
            // or an anchor the beacon side compares.
            beacon_root: B256::ZERO,
            // A block with no body served is held without one (see `HeaderChain::backfill`).
            body: Arc::new(body.unwrap_or_default()),
        })
        .collect()
}

/// Fetches again the bodies of the blocks a backfill held without one, and gives each the body
/// that matches its header. Returns how many it gave.
pub async fn refill_bodies(chain: &HeaderChain, history: &dyn History) -> usize {
    let (epoch, blocks) = chain.backfill_bodiless(BACKFILL_BLOCKS as usize);
    let mut given = 0;
    for chunk in blocks.chunks(BODIES_PER_REQUEST) {
        let hashes: Vec<B256> = chunk.iter().map(|b| b.hash).collect();
        for (block, body) in chunk.iter().zip(history.bodies(&hashes).await) {
            if let Err(e) = verify_body(&block.header, &body) {
                tracing::debug!(%e, number = block.header.number, "a backfill body does not match");
                break;
            }
            let full = HeldBlock { body: Arc::new(body), ..block.clone() };
            given += usize::from(chain.backfill_body(epoch, full));
        }
    }
    given
}

/// Whether the backfill of a seed is done: the lowest canonical block is at `bottom`, at
/// genesis, or at the header window's floor below the head, and every backfilled block has its
/// body.
fn finished(chain: &HeaderChain, bottom: u64) -> bool {
    let Some((_, low)) = chain.lowest_canonical() else { return true };
    let floor = chain.head().map_or(0, |h| h.header.number.saturating_sub(HEADERS_WINDOW));
    low.header.number <= bottom.max(floor) && chain.backfill_bodiless(1).1.is_empty()
}

/// Backfills after each seed, until the task is aborted. A backfill that did not finish (no peer
/// answered, or a body was not served) is tried again after [`RETRY_FIRST`], then after twice
/// as long each time, up to [`RETRY_MAX`], until it finishes or the chain is re-seeded.
pub async fn backfill_loop(chain: Arc<HeaderChain>, history: Arc<dyn History>) {
    let mut done = None;
    loop {
        let epoch = chain.epoch();
        if let Some((_, start)) = chain.lowest_canonical().filter(|_| done != Some(epoch)) {
            let bottom = start.header.number.saturating_sub(BACKFILL_BLOCKS);
            let mut wait = RETRY_FIRST;
            loop {
                let held = backfill_to(&chain, &*history, bottom).await;
                let bodies = refill_bodies(&chain, &*history).await;
                tracing::info!(held, bodies, epoch, "backfilled below the seeded anchor");
                if chain.epoch() != epoch || finished(&chain, bottom) {
                    break;
                }
                tracing::debug!(?wait, "the backfill did not finish; trying again later");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(RETRY_MAX);
            }
            done = Some(epoch);
        }
        tokio::time::sleep(PAUSE).await;
    }
}

#[cfg(test)]
mod tests;
