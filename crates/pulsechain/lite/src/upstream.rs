//! The opt-in upstream state source (`--upstream.url`): JSON-RPC endpoints that serve state with
//! `eth_getProof` and `eth_getCode`.
//!
//! An upstream is trusted no more than a peer. Each call names the block by hash (EIP-1898), and
//! every answer is verified against that block's state root with the checks a peer's answer
//! gets: [`verify_account`] for an account and its slots, and the code hash for code. Only
//! verified nodes and code reach the store. An endpoint whose answer fails verification is not
//! asked again for [`BAD_FOR`], and what it was asked for goes to the next endpoint.
//!
//! An endpoint URL may hold a key in its path or query, so no log line or error carries one: an
//! endpoint is named by [`host_label`], a transport failure by its [`SourceError`] kind, and an
//! endpoint's JSON-RPC error by its code alone.
//!
//! `eth_getCode` takes an account, not a code hash, so a code miss is fetched from the account a
//! run read with that code hash ([`Fetcher::fetch_with_owners`]), or one this source proved.

use crate::{
    beacon::{classify, host_label, SourceError},
    chain::HeaderChain,
    exec::{FetchError, Fetcher},
    metrics::{FailureSource, LiteMetrics},
    net::{
        client::{MAX_PROOF_NODES, MAX_PROOF_NODE_BYTES},
        peers::BAN_FOR,
    },
    rpc::JsonCost,
    state::MissKey,
    store::NodeStore,
    verify::{verify_account, AccountProof},
};
use alloy_primitives::{
    keccak256,
    map::{AddressMap, B256Map},
    Address, Bytes, B256,
};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::Semaphore, time::Instant};
use url::Url;

/// How long one batch request may take.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(8);
/// Calls in one batch request, besides its `eth_blockNumber`.
const BATCH_CALLS: usize = 20;
/// Slots in one `eth_getProof` call.
const SLOTS_PER_PROOF: usize = 16;
/// The largest batch answer read. An honest batch of [`BATCH_CALLS`] proofs of
/// [`SLOTS_PER_PROOF`] slots each is a few MiB.
const MAX_UPSTREAM_BODY: usize = 8 << 20;
/// Batch requests in flight at once, across all fetches: with [`MAX_UPSTREAM_BODY`] they bound
/// the answers held at once.
const UPSTREAM_REQUESTS: usize = 4;
/// How long an endpoint whose answer failed verification is not asked: as long as a peer's ban.
pub const BAD_FOR: Duration = BAN_FOR;
/// Transport failures in a row that rest an endpoint for [`DOWN_FOR`].
const DOWN_AFTER: u32 = 3;
/// How long an endpoint that keeps failing rests.
const DOWN_FOR: Duration = Duration::from_secs(30);
/// Code owners this source remembers from the accounts it proved. Past it the memory starts
/// again.
const MAX_CODE_OWNERS: usize = 1 << 16;

/// One upstream endpoint.
struct Endpoint {
    /// Secret: never logged.
    url: Url,
    /// [`host_label`] of the URL.
    label: String,
    health: Mutex<Health>,
}

impl Endpoint {
    /// Whether the endpoint rests at `now`.
    fn resting(&self, now: Instant) -> bool {
        self.health.lock().resting_until.is_some_and(|t| t > now)
    }
}

/// An endpoint's recent record.
#[derive(Debug, Default)]
struct Health {
    /// Transport failures in a row.
    failures: u32,
    /// Not asked before this time.
    resting_until: Option<Instant>,
}

/// The upstream endpoints and the client that asks them.
pub struct Upstreams {
    endpoints: Vec<Endpoint>,
    http: reqwest::Client,
    permits: Semaphore,
    /// Rotates the first endpoint asked.
    next: AtomicUsize,
}

impl std::fmt::Debug for Upstreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let labels: Vec<&str> = self.endpoints.iter().map(|e| e.label.as_str()).collect();
        f.debug_struct("Upstreams").field("endpoints", &labels).finish_non_exhaustive()
    }
}

/// How one call fared.
enum Answer {
    /// Verified, and stored.
    Good,
    /// No usable answer: an error, a missing result, or an endpoint behind the block.
    Unavailable,
    /// The answer failed verification.
    Bad,
}

/// One call of a batch.
#[derive(Debug, Clone)]
enum Call {
    /// An account and some of its slots.
    Proof { address: Address, slots: Vec<B256> },
    /// The code `hash`, of the account `owner`.
    Code { hash: B256, owner: Address },
}

impl Upstreams {
    /// A client for `urls`. Redirects are not followed, as for a beacon: one could move a
    /// request to another host or to plain http.
    pub fn new(urls: Vec<Url>) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let endpoints = urls
            .into_iter()
            .map(|url| Endpoint { label: host_label(&url), url, health: Mutex::default() })
            .collect();
        Self {
            endpoints,
            http,
            permits: Semaphore::new(UPSTREAM_REQUESTS),
            next: AtomicUsize::new(0),
        }
    }

    /// The endpoints to ask, the first one rotating between calls: those not resting, or every
    /// one when all rest.
    fn order(&self, now: Instant) -> Vec<&Endpoint> {
        let n = self.endpoints.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let all: Vec<&Endpoint> =
            (0..n).map(|i| &self.endpoints[start.wrapping_add(i) % n]).collect();
        let awake: Vec<&Endpoint> = all.iter().copied().filter(|e| !e.resting(now)).collect();
        // With every endpoint resting, the rested ones are asked: there is no other source.
        if awake.is_empty() {
            all
        } else {
            awake
        }
    }

    /// Sends `calls` to `endpoint` in one JSON-RPC batch and returns each call's answer in
    /// order, `None` where there is none. The answer of `eth_blockNumber` comes first.
    async fn batch(
        &self,
        endpoint: &Endpoint,
        calls: &[(&'static str, Value)],
    ) -> Result<Vec<Option<Value>>, SourceError> {
        let body: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(id, (method, params))| {
                json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
            })
            .collect();
        // The semaphore is never closed.
        let _permit = self.permits.acquire().await.map_err(|_| SourceError::Request)?;
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        // Writing a `Value` to a `Vec` cannot fail.
        let body = serde_json::to_vec(&body).map_err(|_| SourceError::Request)?;
        let send = self
            .http
            .post(endpoint.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send();
        let mut resp = tokio::time::timeout_at(deadline, send)
            .await
            .map_err(|_| SourceError::Timeout)?
            .map_err(|e| classify(&e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(SourceError::Status(status.as_u16()));
        }
        if resp.content_length().is_some_and(|n| n > MAX_UPSTREAM_BODY as u64) {
            return Err(SourceError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = tokio::time::timeout_at(deadline, resp.chunk())
            .await
            .map_err(|_| SourceError::Timeout)?
            .map_err(|e| classify(&e))?
        {
            if bytes.len() + chunk.len() > MAX_UPSTREAM_BODY {
                return Err(SourceError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let replies = parse_replies(&bytes)?;
        let mut out = vec![None; calls.len()];
        for mut reply in replies {
            let id =
                reply.get("id").and_then(Value::as_u64).and_then(|id| usize::try_from(id).ok());
            let Some(i) = id.filter(|i| *i < calls.len()) else { continue };
            if let Some(error) = reply.get("error") {
                // The message is not logged: it may echo the URL.
                tracing::debug!(
                    host = %endpoint.label,
                    code = ?error.get("code"),
                    method = calls[i].0,
                    "an upstream answered a call with an error"
                );
                continue;
            }
            // A null result is no answer, not a lie.
            out[i] = reply.get_mut("result").map(Value::take).filter(|r| !r.is_null());
        }
        Ok(out)
    }

    /// Logs whether each endpoint answers `eth_blockNumber`, and its head.
    pub async fn probe(&self) {
        for endpoint in &self.endpoints {
            match self.batch(endpoint, &[("eth_blockNumber", json!([]))]).await {
                Ok(answers) => {
                    let head = answers[0].as_ref().and_then(quantity);
                    tracing::info!(host = %endpoint.label, ?head, "upstream state source answers");
                }
                Err(reason) => tracing::warn!(
                    host = %endpoint.label,
                    %reason,
                    "upstream state source does not answer"
                ),
            }
        }
    }
}

/// The most memory the parsed form of one batch answer may take, by [`JsonCost`]: an honest
/// answer of hex strings takes about its own size, and a hostile one of many small values
/// would take many times its [`MAX_UPSTREAM_BODY`].
const MAX_UPSTREAM_PARSED: usize = 2 * MAX_UPSTREAM_BODY;

/// The replies of a batch answer. An answer whose parsed form would take more than
/// [`MAX_UPSTREAM_PARSED`] is refused before it is parsed.
fn parse_replies(bytes: &[u8]) -> Result<Vec<Value>, SourceError> {
    let mut cost = JsonCost::default();
    cost.feed(bytes);
    if cost.cost() > MAX_UPSTREAM_PARSED {
        return Err(SourceError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| SourceError::Body)
}

/// A JSON-RPC quantity (`0x` hex).
fn quantity(v: &Value) -> Option<u64> {
    let h = v.as_str()?.strip_prefix("0x")?;
    u64::from_str_radix(h, 16).ok()
}

/// Fetches state from the upstreams and verifies it against the state root asked for.
pub struct UpstreamFetcher {
    upstreams: Upstreams,
    chain: Arc<HeaderChain>,
    store: Arc<dyn NodeStore>,
    metrics: LiteMetrics,
    /// The account of each code hash among the accounts this source proved.
    owners: Mutex<B256Map<Address>>,
}

impl std::fmt::Debug for UpstreamFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamFetcher")
            .field("upstreams", &self.upstreams)
            .finish_non_exhaustive()
    }
}

impl UpstreamFetcher {
    /// A fetcher that asks `upstreams` at the blocks of `chain` and writes into `store`.
    pub fn new(
        upstreams: Upstreams,
        chain: Arc<HeaderChain>,
        store: Arc<dyn NodeStore>,
        metrics: LiteMetrics,
    ) -> Self {
        Self { upstreams, chain, store, metrics, owners: Mutex::default() }
    }

    /// The upstream endpoints.
    pub const fn upstreams(&self) -> &Upstreams {
        &self.upstreams
    }

    /// The calls that fetch `misses`. A code miss with no known account is left out, and
    /// returned as unservable.
    fn calls(&self, misses: &[MissKey], owners: &B256Map<Address>) -> (Vec<Call>, usize) {
        let mut accounts: AddressMap<Vec<B256>> = AddressMap::default();
        let mut order = Vec::new();
        let mut codes = Vec::new();
        let mut unservable = 0;
        for m in misses {
            match m {
                MissKey::Account(a, _) | MissKey::Slot(a, _) => {
                    let slots = accounts.entry(*a).or_insert_with(|| {
                        order.push(*a);
                        Vec::new()
                    });
                    if let MissKey::Slot(_, s) = m &&
                        !slots.contains(s)
                    {
                        slots.push(*s);
                    }
                }
                MissKey::Code(hash) => {
                    let owner =
                        owners.get(hash).copied().or_else(|| self.owners.lock().get(hash).copied());
                    match owner {
                        Some(owner) => codes.push(Call::Code { hash: *hash, owner }),
                        None => unservable += 1,
                    }
                }
                // Block hashes come from the header chain.
                MissKey::Header(_) => {}
            }
        }
        let mut calls = Vec::new();
        for address in order {
            let slots = accounts.remove(&address).unwrap_or_default();
            if slots.is_empty() {
                calls.push(Call::Proof { address, slots });
            } else {
                calls.extend(
                    slots
                        .chunks(SLOTS_PER_PROOF)
                        .map(|c| Call::Proof { address, slots: c.to_vec() }),
                );
            }
        }
        calls.extend(codes);
        (calls, unservable)
    }

    /// Checks one call's answer against `root` and, when it verifies, stores what it proves.
    fn take(&self, root: B256, call: &Call, answer: Option<Value>) -> Answer {
        let Some(answer) = answer else { return Answer::Unavailable };
        match call {
            Call::Proof { address, slots } => {
                let Ok(r) = serde_json::from_value::<EIP1186AccountProofResponse>(answer) else {
                    return Answer::Bad;
                };
                let proof = AccountProof::from(r);
                let too_big = |p: &[Bytes]| {
                    p.len() > MAX_PROOF_NODES || p.iter().any(|n| n.len() > MAX_PROOF_NODE_BYTES)
                };
                if too_big(&proof.account_proof) ||
                    proof.storage_proof.iter().any(|s| too_big(&s.proof)) ||
                    slots.iter().any(|s| !proof.storage_proof.iter().any(|e| e.key == *s))
                {
                    return Answer::Bad;
                }
                let Ok((account, nodes)) = verify_account(root, *address, &proof) else {
                    return Answer::Bad;
                };
                for (h, n) in nodes {
                    self.store.put(h, n);
                }
                if let Some(a) = account {
                    let mut owners = self.owners.lock();
                    if owners.len() >= MAX_CODE_OWNERS {
                        owners.clear();
                    }
                    owners.insert(a.code_hash, *address);
                }
                Answer::Good
            }
            Call::Code { hash, .. } => {
                let Ok(code) = serde_json::from_value::<Bytes>(answer) else {
                    return Answer::Bad;
                };
                // The owner may hold other code at this block (its code hash is from another
                // run's read), so a mismatch is no lie: the code is not stored, nothing more.
                if keccak256(&code) != *hash {
                    return Answer::Unavailable;
                }
                self.store.put_code(*hash, code);
                Answer::Good
            }
        }
    }

    /// Asks `endpoint` for `calls` at block `block` of `root` and returns the calls it did not
    /// serve, and whether one of its answers failed verification.
    async fn ask(
        &self,
        endpoint: &Endpoint,
        root: B256,
        block: (B256, u64),
        calls: Vec<Call>,
    ) -> (Vec<Call>, bool) {
        let at = json!({"blockHash": block.0});
        let mut left = Vec::new();
        for (c, chunk) in calls.chunks(BATCH_CALLS).enumerate() {
            let mut batch = vec![("eth_blockNumber", json!([]))];
            batch.extend(chunk.iter().map(|c| match c {
                Call::Proof { address, slots } => ("eth_getProof", json!([address, slots, at])),
                Call::Code { owner, .. } => ("eth_getCode", json!([owner, at])),
            }));
            let answers = match self.upstreams.batch(endpoint, &batch).await {
                Ok(answers) => {
                    endpoint.health.lock().failures = 0;
                    answers
                }
                Err(reason) => {
                    tracing::debug!(host = %endpoint.label, %reason, "an upstream batch failed");
                    let mut h = endpoint.health.lock();
                    h.failures = h.failures.saturating_add(1);
                    if h.failures >= DOWN_AFTER {
                        h.resting_until = Some(Instant::now() + DOWN_FOR);
                    }
                    left.extend_from_slice(chunk);
                    continue;
                }
            };
            let mut answers = answers.into_iter();
            // An endpoint behind the block cannot serve it, and is not lying.
            let head = answers.next().flatten().as_ref().and_then(quantity);
            if head.is_some_and(|h| h < block.1) {
                tracing::debug!(host = %endpoint.label, ?head, block = block.1, "an upstream is behind the block");
                left.extend_from_slice(chunk);
                continue;
            }
            for (i, (call, answer)) in chunk.iter().zip(answers).enumerate() {
                match self.take(root, call, answer) {
                    Answer::Good => {}
                    Answer::Unavailable => left.push(call.clone()),
                    Answer::Bad => {
                        self.metrics.proof_failure(FailureSource::Upstream);
                        let now = Instant::now();
                        // Logged once per rest: a resting endpoint is asked only when every
                        // endpoint rests.
                        if !endpoint.resting(now) {
                            tracing::warn!(
                                host = %endpoint.label,
                                "an upstream answer failed verification; not asking it for 30 \
                                 minutes while another upstream is not resting"
                            );
                        }
                        endpoint.health.lock().resting_until = Some(now + BAD_FOR);
                        // Nothing more of this endpoint's is used: the rest of this batch and
                        // the batches after it go to the next endpoint.
                        left.extend_from_slice(&chunk[i..]);
                        left.extend_from_slice(
                            calls.get((c + 1) * BATCH_CALLS..).unwrap_or_default(),
                        );
                        return (left, true);
                    }
                }
            }
        }
        (left, false)
    }
}

#[async_trait]
impl Fetcher for UpstreamFetcher {
    async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
        self.fetch_with_owners(root, misses, &B256Map::default()).await
    }

    async fn fetch_with_owners(
        &self,
        root: B256,
        misses: &[MissKey],
        owners: &B256Map<Address>,
    ) -> Result<(), FetchError> {
        // The calls name a held block whose state root is `root`.
        let block = self.chain.block_with_state_root(&root).ok_or(FetchError::NoSource)?;
        let (mut calls, unservable) = self.calls(misses, owners);
        let mut saw_bad = false;
        for endpoint in self.upstreams.order(Instant::now()) {
            if calls.is_empty() {
                break;
            }
            let (left, bad) = self.ask(endpoint, root, block, calls).await;
            saw_bad |= bad;
            calls = left;
        }
        match (calls.is_empty() && unservable == 0, saw_bad) {
            (true, _) => Ok(()),
            (false, true) => Err(FetchError::Unverifiable),
            (false, false) => Err(FetchError::NoSource),
        }
    }
}

/// Fetches from `primary` (the peers), and from `upstream` when it fails. With no state peer
/// connected, it asks the upstreams at once.
pub struct FallbackFetcher {
    /// The peers' fetcher.
    pub primary: Arc<dyn Fetcher>,
    /// The upstreams' fetcher.
    pub upstream: Arc<UpstreamFetcher>,
    /// Connected peers that serve state.
    pub state_peers: Arc<dyn Fn() -> usize + Send + Sync>,
}

impl std::fmt::Debug for FallbackFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackFetcher").field("upstream", &self.upstream).finish_non_exhaustive()
    }
}

#[async_trait]
impl Fetcher for FallbackFetcher {
    async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
        self.fetch_with_owners(root, misses, &B256Map::default()).await
    }

    async fn fetch_with_owners(
        &self,
        root: B256,
        misses: &[MissKey],
        owners: &B256Map<Address>,
    ) -> Result<(), FetchError> {
        let primary = if (self.state_peers)() == 0 {
            FetchError::NoSource
        } else {
            match self.primary.fetch_with_owners(root, misses, owners).await {
                Ok(()) => return Ok(()),
                Err(e) => e,
            }
        };
        tracing::debug!(%primary, misses = misses.len(), "the peers did not serve the state; asking the upstreams");
        match self.upstream.fetch_with_owners(root, misses, owners).await {
            Ok(()) => Ok(()),
            Err(FetchError::Unverifiable) => Err(FetchError::Unverifiable),
            Err(FetchError::NoSource) => Err(primary),
        }
    }
}

#[cfg(test)]
mod tests;
