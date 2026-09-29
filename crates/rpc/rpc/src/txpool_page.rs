//! Keyset-paged `txpool` methods, a valve fork extension.
//!
//! See [`TxPoolPageApiServer`] for the wire contract.

use core::fmt;
use std::{collections::BTreeMap, io, sync::Arc};

use alloy_consensus::Transaction;
use alloy_primitives::Address;
use alloy_rpc_types_txpool::{TxpoolContent, TxpoolInspect, TxpoolInspectSummary};
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use reth_primitives_traits::NodePrimitives;
use reth_rpc_api::{
    TxPoolPageApiServer, TxpoolContentPage, TxpoolInspectPage, TxpoolPageRequest,
    TXPOOL_PAGE_MAX_BYTES, TXPOOL_PAGE_MAX_SENDERS,
};
use reth_rpc_convert::RpcConvert;
use reth_rpc_eth_api::RpcTransaction;
use reth_transaction_pool::{
    AllPoolTransactions, PoolConsensusTx, PoolTransaction, TransactionPool,
};
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::trace;

/// Most txpool pages the node builds at once.
///
/// A page reads the whole pool, so a burst of calls could hold the pool's
/// read lock back to back and slow inserts. A call past this bound waits for
/// a permit. The build runs on the blocking pool, not on a runtime worker.
///
/// A caller that disconnects while it waits costs nothing. A caller that
/// disconnects after its build starts does not stop it: the build runs to
/// the end and holds its permit until then.
///
/// The bound limits concurrency, not memory per call. Each build still takes
/// O(T) memory for T pool transactions, because `all_transactions()` clones
/// an `Arc` for every transaction before the page keeps `limit + 1` senders.
///
/// `reth_rpc_builder::install_txpool_page_rpc` builds one instance and
/// merges its methods into every transport, so all transports share one
/// semaphore.
pub const TXPOOL_PAGE_CONCURRENT_BUILDS: usize = 2;

/// `txpool_contentPage` and `txpool_inspectPage` implementation.
#[derive(Clone)]
pub struct TxPoolPageApi<Pool, Eth> {
    pool: Pool,
    converter: Arc<Eth>,
    /// Serialized transaction bytes after which a page takes no more senders.
    max_page_bytes: usize,
    /// Bounds concurrent page builds; see [`TXPOOL_PAGE_CONCURRENT_BUILDS`].
    permits: Arc<Semaphore>,
    #[cfg(test)]
    probe: Arc<tests::BuildProbe>,
}

impl<Pool, Eth> TxPoolPageApi<Pool, Eth> {
    /// Creates a new instance with the default byte bound,
    /// [`TXPOOL_PAGE_MAX_BYTES`].
    pub fn new(pool: Pool, converter: Eth) -> Self {
        Self {
            pool,
            converter: Arc::new(converter),
            max_page_bytes: TXPOOL_PAGE_MAX_BYTES,
            permits: Arc::new(Semaphore::new(TXPOOL_PAGE_CONCURRENT_BUILDS)),
            #[cfg(test)]
            probe: Default::default(),
        }
    }

    /// Sets the serialized transaction bytes after which a page takes no more
    /// senders.
    pub const fn with_max_page_bytes(mut self, max_page_bytes: usize) -> Self {
        self.max_page_bytes = max_page_bytes;
        self
    }
}

#[async_trait]
impl<Pool, Eth> TxPoolPageApiServer<RpcTransaction<Eth::Network>> for TxPoolPageApi<Pool, Eth>
where
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus: Transaction>> + 'static,
    Eth: RpcConvert<Primitives: NodePrimitives<SignedTx = PoolConsensusTx<Pool>>> + 'static,
{
    async fn txpool_content_page(
        &self,
        request: Option<TxpoolPageRequest>,
    ) -> RpcResult<TxpoolContentPage<RpcTransaction<Eth::Network>>> {
        trace!(target: "rpc::eth", ?request, "Serving txpool_contentPage");
        let converter = Arc::clone(&self.converter);
        let (content, next) = self
            .build(request, move |tx| {
                converter.fill_pending(tx.clone_into_consensus()).map_err(Into::into)
            })
            .await?;
        Ok(TxpoolContentPage { content, next })
    }

    async fn txpool_inspect_page(
        &self,
        request: Option<TxpoolPageRequest>,
    ) -> RpcResult<TxpoolInspectPage> {
        trace!(target: "rpc::eth", ?request, "Serving txpool_inspectPage");
        let (content, next) = self
            .build(request, |tx| {
                Ok(TxpoolInspectSummary::from(tx.clone_into_consensus().into_inner()))
            })
            .await?;
        let TxpoolContent { pending, queued } = content;
        Ok(TxpoolInspectPage { inspect: TxpoolInspect { pending, queued }, next })
    }
}

impl<Pool, Eth> TxPoolPageApi<Pool, Eth>
where
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus: Transaction>> + 'static,
{
    /// Checks the request, waits for a permit, and builds the page on the
    /// blocking pool.
    async fn build<V: Serialize + Send + 'static>(
        &self,
        request: Option<TxpoolPageRequest>,
        render: impl FnMut(&Pool::Transaction) -> RpcResult<V> + Send + 'static,
    ) -> RpcResult<(TxpoolContent<V>, Option<Address>)> {
        let TxpoolPageRequest { limit, after } = request.unwrap_or_default();
        let limit = limit.unwrap_or(TXPOOL_PAGE_MAX_SENDERS);
        if limit == 0 || limit > TXPOOL_PAGE_MAX_SENDERS {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!("`limit` must be from 1 to {TXPOOL_PAGE_MAX_SENDERS}, got {limit}"),
                None::<()>,
            ));
        }

        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|err| internal_error(format!("txpool page permit: {err}")))?;
        let pool = self.pool.clone();
        let max_page_bytes = self.max_page_bytes;
        #[cfg(test)]
        let probe = Arc::clone(&self.probe);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            let _guard = probe.enter();
            page(&pool, limit, after, max_page_bytes, render)
        })
        .await
        .map_err(|err| internal_error(format!("txpool page task failed: {err}")))?
    }
}

impl<Pool, Eth> fmt::Debug for TxPoolPageApi<Pool, Eth> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxPoolPageApi")
            .field("max_page_bytes", &self.max_page_bytes)
            .finish_non_exhaustive()
    }
}

/// Builds one page. `render` turns one pool transaction into its RPC form.
/// Returns the page and the `next` cursor.
///
/// The map keeps at most `limit + 1` senders: the page, plus one more to tell
/// whether a sender is left after it. That keeps the cost at
/// O(T log `limit`) for T transactions in the pool, whatever `limit` is. Only
/// the senders in the page are rendered.
fn page<Pool, V>(
    pool: &Pool,
    limit: usize,
    after: Option<Address>,
    max_page_bytes: usize,
    mut render: impl FnMut(&Pool::Transaction) -> RpcResult<V>,
) -> RpcResult<(TxpoolContent<V>, Option<Address>)>
where
    Pool: TransactionPool,
    V: Serialize,
{
    // One snapshot for both sides, so a transaction that moves between
    // sub-pools meanwhile is reported on exactly one of them.
    let AllPoolTransactions { pending, queued } = pool.all_transactions();
    let mut senders = BTreeMap::<Address, (Vec<_>, Vec<_>)>::new();
    // Senders at or above this address are known to be outside the kept
    // set. Without it, a sender dropped while reading `pending` would come
    // back from `queued` with only its queued transactions: a split sender.
    let mut ceiling = None::<Address>;
    let sides =
        pending.into_iter().map(|tx| (tx, true)).chain(queued.into_iter().map(|tx| (tx, false)));
    for (tx, is_pending) in sides {
        let sender = tx.transaction.sender();
        if after.is_some_and(|a| sender <= a) || ceiling.is_some_and(|c| sender >= c) {
            continue;
        }
        let entry = senders.entry(sender).or_default();
        if is_pending {
            entry.0.push(tx);
        } else {
            entry.1.push(tx);
        }
        if senders.len() > limit + 1 &&
            let Some((dropped, _)) = senders.pop_last()
        {
            ceiling = Some(dropped);
        }
    }

    let mut content = TxpoolContent::default();
    let mut bytes = 0;
    let mut count = 0;
    let mut last = None;
    let mut senders = senders.into_iter().peekable();
    for (sender, (pending, queued)) in senders.by_ref() {
        for (txs, side) in [(pending, &mut content.pending), (queued, &mut content.queued)] {
            if txs.is_empty() {
                continue;
            }
            let mut by_nonce = BTreeMap::new();
            for tx in txs {
                by_nonce.insert(tx.transaction.nonce().to_string(), render(&tx.transaction)?);
            }
            // This serializes the transactions once to measure them, and
            // jsonrpsee serializes them again for the response. The byte
            // bound needs the size before the page is final, so the cost is
            // accepted.
            bytes += serialized_len(&by_nonce);
            side.insert(sender, by_nonce);
        }
        count += 1;
        last = Some(sender);
        if count == limit || bytes >= max_page_bytes {
            break;
        }
    }
    let next = if senders.peek().is_some() { last } else { None };
    Ok((content, next))
}

/// JSON-RPC internal error (`-32603`) with `msg` as its message.
fn internal_error(msg: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg, None::<()>)
}

/// Counts bytes written to it and keeps none.
struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// JSON size of `value`, without building the JSON.
fn serialized_len(value: &impl Serialize) -> usize {
    let mut counter = ByteCounter(0);
    // A failure here fails the response serialization too. The bound only
    // needs an estimate, so it counts what was written before the failure.
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
    };

    use alloy_primitives::TxHash;
    use jsonrpsee::{core::server::MethodsError, RpcModule};
    use reth_chainspec::MAINNET;
    use reth_rpc_api::TxPoolApiServer;
    use reth_rpc_eth_types::receipt::EthReceiptConverter;
    use reth_transaction_pool::{
        test_utils::{testing_pool, MockTransaction, TestPool},
        TransactionOrigin,
    };
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::{eth::helpers::types::EthRpcConverter, TxPoolApi};

    /// A module that serves both upstream's `txpool_*` methods and the paged
    /// ones, over a pool of `senders` senders. Each sender has nonces 0 and 1
    /// in the pending sub-pool and the gapped nonce 9 in the queued one.
    async fn module(senders: u8, max_page_bytes: usize) -> RpcModule<()> {
        let pool = testing_pool();
        for s in 1..=senders {
            for nonce in [0, 1, 9] {
                let tx = MockTransaction::legacy()
                    .with_sender(Address::with_last_byte(s))
                    .with_nonce(nonce)
                    .with_gas_price(100);
                pool.add_transaction(TransactionOrigin::External, tx).await.unwrap();
            }
        }
        let converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));
        let mut m = RpcModule::new(());
        m.merge(TxPoolApi::new(pool.clone(), converter.clone()).into_rpc()).unwrap();
        m.merge(
            TxPoolPageApi::new(pool, converter).with_max_page_bytes(max_page_bytes).into_rpc(),
        )
        .unwrap();
        m
    }

    /// Walk every page of `method` and return the pages in walk order.
    async fn walk(m: &RpcModule<()>, method: &str, limit: usize) -> Vec<Value> {
        let mut pages = Vec::new();
        let mut after = Value::Null;
        for _ in 0..1_000 {
            let mut request = json!({ "limit": limit });
            if !after.is_null() {
                request["after"] = after.clone();
            }
            let page: Value = m.call(method, vec![request]).await.unwrap();
            after = page["next"].clone();
            pages.push(page);
            if after.is_null() {
                return pages;
            }
        }
        panic!("{method} never returned a null `next`");
    }

    /// Senders in one page, pending and queued together, lowercased.
    fn senders(page: &Value) -> BTreeSet<String> {
        ["pending", "queued"]
            .iter()
            .flat_map(|side| page[side].as_object().unwrap().keys())
            .map(|k| k.to_lowercase())
            .collect()
    }

    /// Merge the `pending` and `queued` maps of every page into one
    /// `txpool_content`-shaped value.
    fn merge(pages: &[Value]) -> Value {
        let mut out = json!({ "pending": {}, "queued": {} });
        for page in pages {
            for side in ["pending", "queued"] {
                let dst: &mut Map<String, Value> = out[side].as_object_mut().unwrap();
                for (k, v) in page[side].as_object().unwrap() {
                    assert!(dst.insert(k.clone(), v.clone()).is_none(), "{k} is in two pages");
                }
            }
        }
        out
    }

    /// Checks every walk invariant against the unpaged method.
    async fn assert_walk_matches(m: &RpcModule<()>, paged: &str, whole: &str, limit: usize) {
        let pages = walk(m, paged, limit).await;
        let mut previous_max: Option<String> = None;
        for (i, page) in pages.iter().enumerate() {
            let s = senders(page);
            assert!(s.len() <= limit, "page {i} holds {} senders, limit {limit}", s.len());
            if let Some(min) = s.first() &&
                let Some(prev) = &previous_max
            {
                assert!(min > prev, "page {i} is not above the previous page");
            }
            if !page["next"].is_null() {
                let next = page["next"].as_str().unwrap().to_lowercase();
                assert_eq!(Some(&next), s.last(), "`next` must be the last sender of page {i}");
            }
            previous_max = s.last().cloned().or(previous_max);
        }
        let expected: Value = m.call(whole, Vec::<Value>::new()).await.unwrap();
        assert_eq!(merge(&pages), expected, "the pages together must equal {whole}");
    }

    /// Pins the ceiling in `page`: with `limit` 1 the map drops senders while
    /// it reads `pending`, and a dropped sender must not come back from
    /// `queued` alone. A has only queued transactions, B only pending, and C
    /// both. Each must come back whole, exactly once.
    #[tokio::test]
    async fn a_limit_one_walk_keeps_mixed_senders_whole() {
        let pool = testing_pool();
        let (a, b, c) =
            (Address::with_last_byte(1), Address::with_last_byte(2), Address::with_last_byte(3));
        for (sender, nonces) in [(a, &[9][..]), (b, &[0, 1][..]), (c, &[0, 9][..])] {
            for &nonce in nonces {
                let tx =
                    MockTransaction::legacy().with_sender(sender).with_nonce(nonce).with_gas_price(100);
                pool.add_transaction(TransactionOrigin::External, tx).await.unwrap();
            }
        }
        let converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));
        let mut m = RpcModule::new(());
        m.merge(TxPoolApi::new(pool.clone(), converter.clone()).into_rpc()).unwrap();
        m.merge(TxPoolPageApi::new(pool, converter).into_rpc()).unwrap();

        for (paged, whole) in
            [("txpool_contentPage", "txpool_content"), ("txpool_inspectPage", "txpool_inspect")]
        {
            let pages = walk(&m, paged, 1).await;
            assert_eq!(pages.len(), 3, "one sender per page");
            assert_walk_matches(&m, paged, whole, 1).await;
        }
        let pages = walk(&m, "txpool_contentPage", 1).await;
        assert!(pages[0]["pending"].as_object().unwrap().is_empty(), "A has no pending side");
        assert!(pages[1]["queued"].as_object().unwrap().is_empty(), "B has no queued side");
        let c_key = c.to_checksum(None);
        assert!(pages[2]["pending"][&c_key].get("0").is_some(), "C pending nonce 0");
        assert!(pages[2]["queued"][&c_key].get("9").is_some(), "C queued nonce 9");
    }

    /// Senders added and removed between pages must not make the walk repeat
    /// a sender, or skip one that stayed in the pool for the whole walk.
    #[tokio::test]
    async fn a_walk_is_stable_while_the_pool_changes() {
        let pool = testing_pool();
        let mut hashes = BTreeMap::new();
        async fn add(pool: &TestPool, s: u8) -> Vec<TxHash> {
            let mut added = Vec::new();
            for nonce in [0, 1, 9] {
                let tx = MockTransaction::legacy()
                    .with_sender(Address::with_last_byte(s))
                    .with_nonce(nonce)
                    .with_gas_price(100);
                added.push(*PoolTransaction::hash(&tx));
                pool.add_transaction(TransactionOrigin::External, tx).await.unwrap();
            }
            added
        }
        for s in (10..=200).step_by(10) {
            hashes.insert(s, add(&pool, s).await);
        }
        let before: BTreeSet<String> =
            hashes.keys().map(|s| Address::with_last_byte(*s).to_string().to_lowercase()).collect();
        let converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));
        let m = TxPoolPageApi::new(pool.clone(), converter).into_rpc();

        let mut seen = Vec::new();
        let mut after = Value::Null;
        let mut step = 0u8;
        loop {
            let mut request = json!({ "limit": 3 });
            if !after.is_null() {
                request["after"] = after.clone();
                // Remove one sender and add one, on both sides of the cursor.
                let gone = [10, 190][usize::from(step % 2)];
                if let Some(h) = hashes.remove(&gone) {
                    pool.remove_transactions(h);
                }
                hashes.insert(5 + step * 10, add(&pool, 5 + step * 10).await);
                step += 1;
            }
            let page: Value = m.call("txpool_contentPage", vec![request]).await.unwrap();
            seen.extend(senders(&page));
            after = page["next"].clone();
            if after.is_null() {
                break;
            }
        }

        let after_walk: BTreeSet<String> =
            hashes.keys().map(|s| Address::with_last_byte(*s).to_string().to_lowercase()).collect();
        assert!(before.difference(&after_walk).count() > 0, "the test must remove senders");
        let unique: BTreeSet<String> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), seen.len(), "the walk repeated a sender");
        for s in before.intersection(&after_walk) {
            assert!(unique.contains(s), "the walk skipped {s}, present for the whole walk");
        }
    }

    /// Counts page builds in flight and records the peak. Each build also
    /// sleeps briefly so concurrent calls overlap.
    #[derive(Debug, Default)]
    pub(super) struct BuildProbe {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    impl BuildProbe {
        pub(super) fn enter(self: &Arc<Self>) -> BuildGuard {
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(50));
            BuildGuard(Arc::clone(self))
        }
    }

    pub(super) struct BuildGuard(Arc<BuildProbe>);

    impl Drop for BuildGuard {
        fn drop(&mut self) {
            self.0.in_flight.fetch_sub(1, SeqCst);
        }
    }

    /// A page reads the whole pool, so the node must not build more than
    /// [`TXPOOL_PAGE_CONCURRENT_BUILDS`] at once however many callers arrive.
    /// Every caller must still get its answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn page_builds_are_bounded_by_the_permit_count() {
        let pool = testing_pool();
        let converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));
        let api = TxPoolPageApi::new(pool, converter);
        let probe = Arc::clone(&api.probe);
        let m = api.into_rpc();

        let calls = (0..12).map(|i| {
            let method = if i % 2 == 0 { "txpool_contentPage" } else { "txpool_inspectPage" };
            m.call::<_, Value>(method, vec![json!({})])
        });
        for v in futures::future::join_all(calls).await {
            assert!(v.unwrap()["next"].is_null());
        }

        let peak = probe.peak.load(SeqCst);
        assert!(
            peak <= TXPOOL_PAGE_CONCURRENT_BUILDS,
            "{peak} builds ran at once; the bound is {TXPOOL_PAGE_CONCURRENT_BUILDS}",
        );
        assert!(peak >= 1);
    }

    async fn call_err_code(m: &RpcModule<()>, method: &str, request: Value) -> i32 {
        match m.call::<_, Value>(method, vec![request]).await {
            Err(MethodsError::JsonRpc(e)) => e.code(),
            other => panic!("expected a JSON-RPC error from {method}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn content_page_walk_matches_txpool_content() {
        let m = module(7, TXPOOL_PAGE_MAX_BYTES).await;
        for limit in [1, 2, 3, 7, 50] {
            assert_walk_matches(&m, "txpool_contentPage", "txpool_content", limit).await;
        }
    }

    #[tokio::test]
    async fn inspect_page_walk_matches_txpool_inspect() {
        let m = module(7, TXPOOL_PAGE_MAX_BYTES).await;
        for limit in [1, 3, 50] {
            assert_walk_matches(&m, "txpool_inspectPage", "txpool_inspect", limit).await;
        }
    }

    /// A sender with pending and queued transactions appears whole in one
    /// page: every nonce, on both sides.
    #[tokio::test]
    async fn a_sender_is_never_split_across_pages() {
        let m = module(5, TXPOOL_PAGE_MAX_BYTES).await;
        for page in walk(&m, "txpool_contentPage", 2).await {
            for (sender, txs) in page["pending"].as_object().unwrap() {
                let nonces: Vec<&String> = txs.as_object().unwrap().keys().collect();
                assert_eq!(nonces, ["0", "1"], "pending nonces of {sender}");
                let queued = &page["queued"][sender];
                assert!(queued.get("9").is_some(), "queued nonce 9 of {sender} is not here");
            }
        }
    }

    /// With a byte bound below one sender, every page holds one sender even
    /// under a larger `limit`, and the walk still covers the pool.
    #[tokio::test]
    async fn byte_bound_makes_short_pages_and_the_walk_completes() {
        let m = module(6, 1).await;
        let pages = walk(&m, "txpool_contentPage", 10).await;
        assert_eq!(pages.len(), 6, "one sender per page");
        for page in &pages {
            assert_eq!(senders(page).len(), 1);
        }
        assert_walk_matches(&m, "txpool_contentPage", "txpool_content", 10).await;
        assert_walk_matches(&m, "txpool_inspectPage", "txpool_inspect", 10).await;
    }

    #[tokio::test]
    async fn limit_above_the_cap_or_zero_is_invalid_params() {
        let m = module(1, TXPOOL_PAGE_MAX_BYTES).await;
        for method in ["txpool_contentPage", "txpool_inspectPage"] {
            let over = json!({ "limit": TXPOOL_PAGE_MAX_SENDERS + 1 });
            assert_eq!(call_err_code(&m, method, over).await, -32602);
            assert_eq!(call_err_code(&m, method, json!({ "limit": 0 })).await, -32602);
            let at_cap: Value =
                m.call(method, vec![json!({ "limit": TXPOOL_PAGE_MAX_SENDERS })]).await.unwrap();
            assert_eq!(senders(&at_cap).len(), 1);
        }
    }

    /// No request is the first page at the default size.
    #[tokio::test]
    async fn no_request_returns_the_first_page() {
        let m = module(3, TXPOOL_PAGE_MAX_BYTES).await;
        let page: Value = m.call("txpool_contentPage", Vec::<Value>::new()).await.unwrap();
        assert_eq!(senders(&page).len(), 3);
        assert!(page["next"].is_null());
    }

    /// An empty pool, or a cursor past the last sender, is an empty page with
    /// a null `next`.
    #[tokio::test]
    async fn the_end_is_an_empty_page_with_a_null_next() {
        let empty = module(0, TXPOOL_PAGE_MAX_BYTES).await;
        let page: Value = empty.call("txpool_contentPage", vec![json!({})]).await.unwrap();
        assert_eq!(page, json!({ "pending": {}, "queued": {}, "next": null }));

        let m = module(3, TXPOOL_PAGE_MAX_BYTES).await;
        let past = json!({ "after": Address::repeat_byte(0xFF) });
        let page: Value = m.call("txpool_inspectPage", vec![past]).await.unwrap();
        assert_eq!(page, json!({ "pending": {}, "queued": {}, "next": null }));
    }
}
