//! A fake beacon and anchor on raw TCP for the follower tests: SSE or poll mode, a key in the
//! path, call counts per path.

use crate::payload::fake::{hx, make, FakeBlock, Fork};
use alloy_primitives::B256;
use parking_lot::Mutex;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::broadcast,
};

pub(crate) const KEY_PATH: &str = "/beacon/vk_secret/943";

#[derive(Default)]
pub(crate) struct State {
    pub sse: bool,
    pub head: Option<B256>,
    pub finalized: Option<B256>,
    pub blocks: HashMap<B256, FakeBlock>,
    pub calls: HashMap<String, usize>,
    /// For the anchor server: serve this block as `finalized`, optionally a different one.
    pub finalized_block: Option<FakeBlock>,
    /// How long a `blocks/{root}` answer waits before it is sent.
    pub block_delay: std::time::Duration,
    /// How long the answer for one root waits instead of [`State::block_delay`].
    pub root_delays: HashMap<B256, std::time::Duration>,
    /// Marks the head event and `headers/head` `execution_optimistic`.
    pub optimistic: bool,
    /// Answers 403 to a request whose query string lacks this `key=value` pair.
    pub require_query: Option<String>,
    /// Fixed answers by path (under [`KEY_PATH`] for a beacon), with `?query` when the answer is
    /// for that query only. They come before every other route.
    pub answers: HashMap<String, (&'static str, String)>,
}

pub(crate) struct Fake {
    pub addr: std::net::SocketAddr,
    pub state: Arc<Mutex<State>>,
    pub events: broadcast::Sender<String>,
    pub kill_streams: broadcast::Sender<()>,
}

impl Fake {
    /// A beacon under [`KEY_PATH`]. With `anchor` it serves only `blocks/finalized` at `/`.
    pub(crate) async fn start(sse: bool, anchor: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State { sse, ..Default::default() }));
        let (events, _) = broadcast::channel::<String>(64);
        let (kill, _) = broadcast::channel::<()>(4);
        let (st, ev, kl) = (state.clone(), events.clone(), kill.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let (st, ev, kl) = (st.clone(), ev.clone(), kl.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let target = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let path = path.to_owned();
                    let forbidden = st
                        .lock()
                        .require_query
                        .as_deref()
                        .is_some_and(|want| !query.split('&').any(|pair| pair == want));
                    let (status, body, stream) = if forbidden {
                        ("403 Forbidden", "{\"code\":403}".to_owned(), false)
                    } else {
                        route(&st, &path, query, anchor)
                    };
                    let delay = {
                        let s = st.lock();
                        path.rsplit_once("/eth/v2/beacon/blocks/")
                            .and_then(|(_, id)| id.parse::<B256>().ok())
                            .and_then(|root| s.root_delays.get(&root).copied())
                            .unwrap_or(s.block_delay)
                    };
                    if path.contains("/eth/v2/beacon/blocks/0x") && !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    if stream {
                        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n: connected\n\n";
                        if sock.write_all(head.as_bytes()).await.is_err() {
                            return;
                        }
                        // Like a real beacon, a stream gets only the events sent after it opened.
                        let (mut rx, mut kill) = (ev.subscribe(), kl.subscribe());
                        loop {
                            tokio::select! {
                                m = rx.recv() => match m {
                                    Ok(m) => if sock.write_all(m.as_bytes()).await.is_err() { return },
                                    Err(_) => return,
                                },
                                _ = kill.recv() => return,
                            }
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        Self { addr, state, events, kill_streams: kill }
    }

    pub(crate) fn beacon_url(&self) -> url::Url {
        format!("http://{}{KEY_PATH}", self.addr).parse().unwrap()
    }

    pub(crate) fn anchor_url(&self) -> url::Url {
        format!("http://{}", self.addr).parse().unwrap()
    }

    pub(crate) fn calls(&self, path: &str) -> usize {
        self.state.lock().calls.get(path).copied().unwrap_or(0)
    }

    /// Makes `b` servable and the head; announces it to the open event streams.
    pub(crate) fn push(&self, b: &FakeBlock) {
        let optimistic = {
            let mut s = self.state.lock();
            s.blocks.insert(b.root, b.clone());
            s.head = Some(b.root);
            s.optimistic
        };
        let ev = format!(
            "event: head\ndata: {}\n\n",
            json!({
                "slot": b.header.number.to_string(),
                "block": hx(b.root.as_slice()),
                "execution_optimistic": optimistic,
            })
        );
        let _ = self.events.send(ev);
    }

    /// Makes `b` servable and the head without an event, as a head event a stream missed.
    pub(crate) fn push_silently(&self, b: &FakeBlock) {
        let mut s = self.state.lock();
        s.blocks.insert(b.root, b.clone());
        s.head = Some(b.root);
    }

    pub(crate) fn serve_only(&self, b: &FakeBlock) {
        self.state.lock().blocks.insert(b.root, b.clone());
    }

    pub(crate) fn finalize(&self, b: &FakeBlock) {
        {
            let mut s = self.state.lock();
            s.blocks.insert(b.root, b.clone());
            s.finalized = Some(b.root);
        }
        let _ = self.events.send("event: finalized_checkpoint\ndata: {}\n\n".into());
    }

    pub(crate) fn set_anchor_block(&self, b: &FakeBlock) {
        self.state.lock().finalized_block = Some(b.clone());
    }

    /// Answers `path` (with `?query` for that query only) with `status` and `body`.
    pub(crate) fn answer(&self, path: &str, status: &'static str, body: impl Into<String>) {
        self.state.lock().answers.insert(path.to_owned(), (status, body.into()));
    }

    /// Sends `event` with `data` to the open event streams.
    pub(crate) fn send_event(&self, event: &str, data: &serde_json::Value) {
        let _ = self.events.send(format!("event: {event}\ndata: {data}\n\n"));
    }
}

/// The fixed answer for `path` and `query`, if [`State::answers`] has one.
fn fixed_answer(s: &State, path: &str, query: &str) -> Option<(&'static str, String, bool)> {
    let with_query = format!("{path}?{query}");
    let found = (!query.is_empty()).then(|| s.answers.get(&with_query)).flatten();
    found.or_else(|| s.answers.get(path)).map(|(status, body)| (*status, body.clone(), false))
}

fn route(st: &Mutex<State>, path: &str, query: &str, anchor: bool) -> (&'static str, String, bool) {
    let mut s = st.lock();
    let ok = |v: serde_json::Value| ("200 OK", v.to_string(), false);
    let not_found = || ("404 Not Found", "{\"code\":404}".to_owned(), false);
    if anchor {
        *s.calls.entry(path.to_owned()).or_default() += 1;
        if let Some(fixed) = fixed_answer(&s, path, query) {
            return fixed;
        }
        return if path == "/eth/v2/beacon/blocks/finalized" {
            s.finalized_block.as_ref().map_or_else(not_found, |b| ok(b.json.clone()))
        } else {
            not_found()
        };
    }
    let Some(rest) = path.strip_prefix(KEY_PATH) else {
        return ("403 Forbidden", "{\"code\":403}".to_owned(), false);
    };
    *s.calls.entry(rest.to_owned()).or_default() += 1;
    if let Some(fixed) = fixed_answer(&s, rest, query) {
        return fixed;
    }
    match rest {
        "/eth/v1/events" => {
            if s.sse {
                ("200 OK", String::new(), true)
            } else {
                not_found()
            }
        }
        "/eth/v1/beacon/headers/head" => match s.head {
            Some(h) => ok(json!({
                "execution_optimistic": s.optimistic,
                "data": {"root": hx(h.as_slice())},
            })),
            None => not_found(),
        },
        "/eth/v1/beacon/states/head/finality_checkpoints" => match s.finalized {
            Some(f) => ok(json!({"data": {"finalized": {"epoch": "1", "root": hx(f.as_slice())}}})),
            None => not_found(),
        },
        p => {
            let Some(id) = p.strip_prefix("/eth/v2/beacon/blocks/") else { return not_found() };
            if id == "finalized" {
                let b = s.finalized.and_then(|r| s.blocks.get(&r));
                return b.map_or_else(not_found, |b| ok(b.json.clone()));
            }
            let Ok(root) = id.parse::<B256>() else { return not_found() };
            s.blocks.get(&root).map_or_else(not_found, |b| ok(b.json.clone()))
        }
    }
}

/// A fake chain on one fork profile.
pub(crate) struct FakeChain {
    pub fork: Fork,
    pub blocks: Vec<FakeBlock>,
}

impl FakeChain {
    pub(crate) fn new(fork: Fork, start: u64) -> Self {
        let first = make(fork, start, B256::repeat_byte(0xaa), B256::repeat_byte(0xbb), "");
        Self { fork, blocks: vec![first] }
    }

    pub(crate) fn head(&self) -> &FakeBlock {
        self.blocks.last().unwrap()
    }

    pub(crate) fn next(&mut self) -> FakeBlock {
        let h = self.head();
        let b = make(self.fork, h.header.number + 1, h.hash, h.root, "");
        self.blocks.push(b.clone());
        b
    }

    /// A sibling of the block at `number`: same parent, different hash.
    pub(crate) fn alt(&self, number: u64) -> FakeBlock {
        let b = self.blocks.iter().find(|b| b.header.number == number).unwrap();
        make(self.fork, number, b.header.parent_hash, b.parent_root, "alt")
    }
}
