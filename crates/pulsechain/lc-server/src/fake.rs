//! A fake upstream on raw TCP and a synthetic minimal-preset chain, for the task tests.

use crate::{
    answers::Answers,
    api::{fork_schedule_json, genesis_json},
    archive::Archive,
    upstream::{Beacons, Timeouts, Upstream},
    SECONDS_PER_SLOT,
};
use alloy_primitives::{map::B256Map, B256};
use blst::min_pk::SecretKey;
use parking_lot::Mutex;
use reth_pulsechain_forks::network::PulsechainBeacon;
use reth_pulsechain_light_client::{
    derive::{
        test_utils::{block_ssz, keys, sign, state_root, state_ssz, synthetic_pins},
        CheckedState, LightClientBlock,
    },
    sync_committee::{test_utils::repeated_committee, LightClientStore, Preset, SyncCommittee},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::broadcast,
};

pub(crate) const PRESET: Preset = Preset::MINIMAL;
/// A wall-clock slot after every test slot.
pub(crate) const NOW: u64 = 10_000;
/// The signers of a test block, of 32.
pub(crate) const SIGNERS: usize = 24;

/// Short limits, so a stalled request fails fast.
pub(crate) const TIMEOUTS: Timeouts = Timeouts {
    request: Duration::from_millis(300),
    block: Duration::from_millis(500),
    state: Duration::from_millis(500),
};

/// One answer: a status, a media type and a body, sent with its length or until the
/// connection closes.
#[derive(Clone)]
pub(crate) struct Answer {
    status: u16,
    media_type: &'static str,
    body: Vec<u8>,
    with_length: bool,
    version: Option<&'static str>,
}

impl Answer {
    pub(crate) fn json(value: &serde_json::Value) -> Self {
        Self {
            status: 200,
            media_type: "application/json",
            body: value.to_string().into_bytes(),
            with_length: true,
            version: None,
        }
    }

    pub(crate) fn ssz(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            media_type: "application/octet-stream",
            body,
            with_length: true,
            version: None,
        }
    }

    pub(crate) fn status(status: u16) -> Self {
        Self {
            status,
            media_type: "application/json",
            body: format!("{{\"code\":{status}}}").into_bytes(),
            with_length: true,
            version: None,
        }
    }

    /// The answer with no `Content-Length`: the body ends when the connection closes.
    pub(crate) const fn without_length(mut self) -> Self {
        self.with_length = false;
        self
    }

    /// The answer with an `Eth-Consensus-Version` header.
    pub(crate) const fn with_version(mut self, version: &'static str) -> Self {
        self.version = Some(version);
        self
    }
}

#[derive(Default)]
struct State {
    genesis: Option<serde_json::Value>,
    fork_schedule: Option<serde_json::Value>,
    finalized: Option<B256>,
    head: Option<B256>,
    blocks: B256Map<Vec<u8>>,
    slots: BTreeMap<u64, B256>,
    states: BTreeMap<u64, Vec<u8>>,
    sse: bool,
    /// Fixed answers by path, before every route.
    answers: HashMap<String, Answer>,
    /// Paths that never answer.
    stalled: Vec<String>,
    /// Paths that answer after a delay.
    delayed: HashMap<String, Duration>,
    calls: HashMap<String, usize>,
    /// The `Accept` header of the last request for each path under the key.
    accepts: HashMap<String, String>,
}

/// A fake beacon or state URL.
pub(crate) struct Fake {
    addr: std::net::SocketAddr,
    state: Arc<Mutex<State>>,
    events: broadcast::Sender<String>,
}

impl Fake {
    pub(crate) async fn start(pins: &PulsechainBeacon) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            genesis: Some(genesis_json(pins)),
            fork_schedule: Some(fork_schedule_json(pins)),
            ..Default::default()
        }));
        let (events, _) = broadcast::channel::<String>(64);
        let (st, ev) = (state.clone(), events.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let (st, ev) = (st.clone(), ev.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let target = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let path = target.split_once('?').map_or(target.as_str(), |(path, _)| path);
                    let accept = request.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("accept").then(|| value.trim().to_owned())
                    });
                    if let (Some(rest), Some(accept)) = (path.strip_prefix("/key/secret"), accept) {
                        st.lock().accepts.insert(rest.to_owned(), accept);
                    }
                    let (answer, stream, delay) = route(&st, path);
                    if let Some(delay) = delay {
                        tokio::time::sleep(delay).await;
                    }
                    if stream {
                        let head =
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n: open\n\n";
                        if sock.write_all(head.as_bytes()).await.is_err() {
                            return
                        }
                        let mut rx = ev.subscribe();
                        while let Ok(event) = rx.recv().await {
                            if sock.write_all(event.as_bytes()).await.is_err() {
                                return
                            }
                        }
                        return
                    }
                    let length = if answer.with_length {
                        format!("Content-Length: {}\r\n", answer.body.len())
                    } else {
                        String::new()
                    };
                    let version = answer
                        .version
                        .map(|version| format!("Eth-Consensus-Version: {version}\r\n"))
                        .unwrap_or_default();
                    let head = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: {}\r\n{length}{version}Connection: close\r\n\r\n",
                        answer.status, answer.media_type,
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&answer.body).await;
                });
            }
        });
        Self { addr, state, events }
    }

    /// The base URL, with a key in its path as a keyed provider's.
    pub(crate) fn url(&self) -> url::Url {
        format!("http://{}/key/secret", self.addr).parse().unwrap()
    }

    pub(crate) fn upstream(&self) -> Upstream {
        Upstream::new(self.url(), TIMEOUTS)
    }

    /// The number of requests for `path`, under the key.
    pub(crate) fn calls(&self, path: &str) -> usize {
        self.state.lock().calls.get(path).copied().unwrap_or(0)
    }

    /// Serves the blocks of `chain` by root and by slot.
    pub(crate) fn serve_blocks(&self, chain: &TestChain) {
        let mut state = self.state.lock();
        for (slot, (bytes, block)) in &chain.blocks {
            state.blocks.insert(block.root(), bytes.clone());
            state.slots.insert(*slot, block.root());
        }
    }

    /// Serves the states of `chain`'s checkpoints.
    pub(crate) fn serve_states(&self, chain: &TestChain) {
        self.state.lock().states.extend(chain.states.clone());
    }

    /// Serves `bytes` as the state at `slot`.
    pub(crate) fn serve_state(&self, slot: u64, bytes: Vec<u8>) {
        self.state.lock().states.insert(slot, bytes);
    }

    /// Serves `root` as the finalized block root.
    pub(crate) fn finalize(&self, root: B256) {
        self.state.lock().finalized = Some(root);
    }

    pub(crate) fn enable_events(&self) {
        self.state.lock().sse = true;
    }

    /// Makes `root` the head and sends its head event to the open streams.
    pub(crate) fn set_head(&self, root: B256) {
        self.state.lock().head = Some(root);
        let _ = self.events.send(format!(
            "event: head\ndata: {}\n\n",
            json!({"slot": "1", "block": root.to_string()})
        ));
    }

    /// Answers `path` with `answer`, before every route.
    pub(crate) fn answer(&self, path: &str, answer: Answer) {
        self.state.lock().answers.insert(path.to_owned(), answer);
    }

    /// Never answers `path`.
    pub(crate) fn stall(&self, path: &str) {
        self.state.lock().stalled.push(path.to_owned());
    }

    /// Answers `path` only after `delay`.
    pub(crate) fn delay(&self, path: &str, delay: Duration) {
        self.state.lock().delayed.insert(path.to_owned(), delay);
    }

    /// Returns the `Accept` header of the last request for `path`.
    pub(crate) fn accept(&self, path: &str) -> Option<String> {
        self.state.lock().accepts.get(path).cloned()
    }

    /// Answers every path by its route again.
    pub(crate) fn heal(&self) {
        let mut state = self.state.lock();
        state.answers.clear();
        state.stalled.clear();
        state.delayed.clear();
    }
}

/// The answer to `path`, whether it is an event stream, and how long it waits first.
fn route(st: &Mutex<State>, path: &str) -> (Answer, bool, Option<Duration>) {
    let mut s = st.lock();
    let Some(rest) = path.strip_prefix("/key/secret") else {
        return (Answer::status(403), false, None)
    };
    *s.calls.entry(rest.to_owned()).or_default() += 1;
    if s.stalled.iter().any(|stalled| stalled == rest) {
        return (Answer::status(500), false, Some(Duration::from_secs(3600)))
    }
    let delay = s.delayed.get(rest).copied();
    if let Some(answer) = s.answers.get(rest) {
        return (answer.clone(), false, delay)
    }
    let not_found = Answer::status(404);
    let root = |root: Option<B256>| {
        root.map_or_else(
            || Answer::status(404),
            |root| Answer::json(&json!({"data": {"root": root.to_string()}})),
        )
    };
    let answer = match rest {
        "/eth/v1/beacon/genesis" => s.genesis.as_ref().map_or(not_found, Answer::json),
        "/eth/v1/config/fork_schedule" => s.fork_schedule.as_ref().map_or(not_found, Answer::json),
        "/eth/v1/beacon/blocks/finalized/root" => root(s.finalized),
        "/eth/v1/beacon/headers/head" => root(s.head),
        "/eth/v1/events" if s.sse => return (not_found, true, None),
        rest => {
            if let Some(id) = rest.strip_prefix("/eth/v2/beacon/blocks/") {
                let root = id
                    .parse::<u64>()
                    .map_or_else(|_| id.parse().ok(), |slot| s.slots.get(&slot).copied());
                root.and_then(|root| s.blocks.get(&root))
                    .map_or(not_found, |bytes| Answer::ssz(bytes.clone()))
            } else if let Some(slot) = rest.strip_prefix("/eth/v2/debug/beacon/states/") {
                let state = slot.parse::<u64>().ok().and_then(|slot| s.states.get(&slot));
                state.map_or(not_found, |bytes| Answer::ssz(bytes.clone()))
            } else {
                not_found
            }
        }
    };
    (answer, false, delay)
}

/// The first key of a [`TestChain::new`] chain's committees.
const FIRST_KEY: u8 = 1;

/// The keys of the committee of `period` of a chain whose keys start at `first`.
fn keys_of(first: u8, period: u64) -> Vec<SecretKey> {
    keys(first + 4 * u8::try_from(period).unwrap())
}

/// The keys of the committee of `period`.
pub(crate) fn period_keys(period: u64) -> Vec<SecretKey> {
    keys_of(FIRST_KEY, period)
}

/// The committee of `period`.
pub(crate) fn committee(period: u64) -> SyncCommittee {
    repeated_committee(&period_keys(period), PRESET.sync_committee_size())
}

/// A synthetic chain: each block's sync aggregate signs its parent with the committee of the
/// block's period, and each checkpoint block has a state.
pub(crate) struct TestChain {
    pub(crate) pins: PulsechainBeacon,
    pub(crate) blocks: BTreeMap<u64, (Vec<u8>, LightClientBlock)>,
    pub(crate) states: BTreeMap<u64, Vec<u8>>,
    head: B256,
    /// The first key of the committees.
    first_key: u8,
}

impl TestChain {
    /// A chain whose genesis puts the wall clock at slot [`NOW`], so its blocks are recent.
    pub(crate) fn new() -> Self {
        Self::with_keys(FIRST_KEY)
    }

    /// A chain as [`Self::new`] whose committees' keys start at `first_key`: with another
    /// first key than [`Self::new`]'s, a chain with other committees.
    pub(crate) fn with_keys(first_key: u8) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let pins =
            PulsechainBeacon { genesis_time: now - NOW * SECONDS_PER_SLOT, ..synthetic_pins() };
        let (blocks, states, head) = (BTreeMap::new(), BTreeMap::new(), B256::repeat_byte(1));
        Self { pins, blocks, states, head, first_key }
    }

    /// The committee of `period`.
    fn committee(&self, period: u64) -> SyncCommittee {
        repeated_committee(&keys_of(self.first_key, period), PRESET.sync_committee_size())
    }

    /// Returns the block at `slot`.
    pub(crate) fn at(&self, slot: u64) -> &LightClientBlock {
        &self.blocks[&slot].1
    }

    /// Returns the root of the block at `slot`.
    pub(crate) fn root(&self, slot: u64) -> B256 {
        self.at(slot).root()
    }

    /// Adds a block at each of `slots` on the head.
    pub(crate) fn extend(&mut self, slots: impl IntoIterator<Item = u64>) {
        for slot in slots {
            self.push(slot, self.head, SIGNERS, B256::repeat_byte(2));
        }
    }

    /// Adds a checkpoint block at `slot` on the head, whose state has finalized the block at
    /// `finalized`.
    pub(crate) fn checkpoint(&mut self, slot: u64, finalized: u64) {
        self.checkpoint_with_next(
            slot,
            finalized,
            &self.committee(PRESET.period_at_slot(slot) + 1),
        );
    }

    /// Adds a checkpoint block as [`Self::checkpoint`] does, with `next` as the next committee
    /// of its state.
    pub(crate) fn checkpoint_with_next(&mut self, slot: u64, finalized: u64, next: &SyncCommittee) {
        let state = self.state_at(slot, finalized, next);
        self.push(slot, self.head, SIGNERS, state_root(PRESET, &state));
        self.states.insert(slot, state);
    }

    /// A state at `slot` that has finalized the block at `finalized`, with the committee of
    /// `slot`'s period and `next`.
    pub(crate) fn state_at(&self, slot: u64, finalized: u64, next: &SyncCommittee) -> Vec<u8> {
        let period = PRESET.period_at_slot(slot);
        state_ssz(
            PRESET,
            &self.pins,
            slot,
            PRESET.epoch_at_slot(finalized),
            self.root(finalized),
            &self.committee(period),
            next,
        )
    }

    /// The light-client store bootstrapped at the checkpoint block at `slot`.
    pub(crate) fn store_at(&self, slot: u64) -> LightClientStore {
        let bootstrap = CheckedState::new(PRESET, &self.pins, self.at(slot), &self.states[&slot])
            .unwrap()
            .bootstrap();
        LightClientStore::bootstrap(PRESET, self.pins, self.root(slot), &bootstrap).unwrap()
    }

    /// Adds a block at `slot` on `parent`, signed by `signers` members, and makes it the head.
    pub(crate) fn push(&mut self, slot: u64, parent: B256, signers: usize, state_root: B256) {
        let period = PRESET.period_at_slot(slot);
        let keys = keys_of(self.first_key, period);
        let aggregate = sign(PRESET, &self.pins, &keys, signers, parent, slot);
        let bytes = block_ssz(PRESET, slot, parent, state_root, &aggregate);
        let block = LightClientBlock::from_ssz_bytes(&bytes, PRESET, &self.pins).unwrap();
        self.head = block.root();
        self.blocks.insert(slot, (bytes, block));
    }
}

/// A beacon URL and a state URL for `chain`, and the answers of a server in a new datadir.
pub(crate) struct Rig {
    pub(crate) beacon: Fake,
    pub(crate) state: Fake,
    pub(crate) answers: Arc<Answers>,
    /// The store at the chain's pin, which the archive checks its stored updates from, as a
    /// server's archive does. `None` on a chain with no pin.
    pin: Option<LightClientStore>,
    datadir: tempfile::TempDir,
}

impl Rig {
    /// A rig whose self-check store starts at the chain's first checkpoint, its pin.
    pub(crate) async fn start(chain: &TestChain) -> Self {
        let first = *chain.states.keys().next().expect("a chain with a checkpoint");
        Self::from_checkpoint(chain, Some(chain.store_at(first)), chain.store_at(first)).await
    }

    /// A rig whose self-check store starts as `store`, which is also the chain's pin.
    pub(crate) async fn anchored(chain: &TestChain, store: LightClientStore) -> Self {
        Self::from_checkpoint(chain, Some(store.clone()), store).await
    }

    /// A rig of a new datadir that `--checkpoint` started: its self-check store starts as
    /// `store`, on a chain whose pin is `pin`, or with no pin.
    pub(crate) async fn from_checkpoint(
        chain: &TestChain,
        pin: Option<LightClientStore>,
        store: LightClientStore,
    ) -> Self {
        let beacon = Fake::start(&chain.pins).await;
        let state = Fake::start(&chain.pins).await;
        beacon.serve_blocks(chain);
        state.serve_states(chain);
        let datadir = tempfile::tempdir().unwrap();
        let archive =
            Archive::open(datadir.path(), 1, PRESET, chain.pins, pin.clone()).await.unwrap();
        let answers = Arc::new(Answers::new(PRESET, chain.pins, archive, store.clone()));
        answers.check_archive(NOW).await.unwrap();
        // As the server does once the bootstrapped store starts.
        answers.archive().lock().await.save_anchor(&store).await.unwrap();
        Self { beacon, state, answers, pin, datadir }
    }

    /// The same upstreams and datadir with a new server, as after a restart. The self-check
    /// store is the one the server saved. The archive is not checked yet.
    pub(crate) async fn restart(self) -> Self {
        let Self { beacon, state, answers, pin, datadir } = self;
        let pins = *answers.pins();
        drop(answers);
        let mut archive =
            Archive::open(datadir.path(), 1, PRESET, pins, pin.clone()).await.unwrap();
        let store = archive.load_store(SystemTime::now()).await.unwrap().expect("a saved store");
        // As the server does with a saved store when the datadir has no anchor file.
        archive.save_anchor(&store).await.unwrap();
        let answers = Arc::new(Answers::new(PRESET, pins, archive, store));
        Self { beacon, state, answers, pin, datadir }
    }

    /// The archive's directory, `<datadir>/1`.
    pub(crate) fn dir(&self) -> std::path::PathBuf {
        self.datadir.path().join("1")
    }

    pub(crate) fn beacons(&self) -> Beacons {
        Beacons::new(PRESET, *self.answers.pins(), vec![self.beacon.upstream()])
    }
}

/// The log lines of the test's thread while it lives.
pub(crate) struct Logs {
    buf: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Logs {
    /// Captures the log lines of the calling thread.
    pub(crate) fn capture() -> Self {
        // With one registered dispatcher, tracing computes a new callsite's interest from the
        // default of the thread that hits it first. Another test's thread then caches `never`
        // and hides this thread's events. A second dispatcher that lives forever prevents that.
        static SECOND: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new()));
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = LogWriter(buf.clone());
        let subscriber =
            tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish();
        Self { buf, _guard: tracing::subscriber::set_default(subscriber) }
    }

    /// The lines so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.buf.lock().clone()).unwrap()
    }
}

/// A log writer that keeps what it is given.
#[derive(Clone)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
