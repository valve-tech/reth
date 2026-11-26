use super::*;
use crate::{
    answers::Progress,
    archive::Archive,
    checkpoint::{CheckpointError, CheckpointTask},
    config::CHECKPOINTZ_369,
    fake::{committee, Answer, Fake, Rig, TestChain, NOW, PRESET},
    head::HeadTask,
    upstream::{Timeouts, Upstream, MAX_PASS_THROUGH_BODY},
};
use reth_pulsechain_forks::network::pulsechain_network;
use reth_pulsechain_light_client::{
    derive::CheckedState,
    json::{
        check_pins, parse_bootstrap, parse_fork_schedule, parse_genesis, parse_update,
        parse_updates,
    },
    sync_committee::{LightClientStore, Preset},
};
use reth_pulsechain_lite::{
    beacon::{BeaconClient, Event, Topics},
    light_client::{check_sync_committee_start, StartFrom, StoreOrigin},
};
use tokio::time::Instant;

// Period 1 of the minimal preset is slots 64 to 127, 8 slots an epoch. F is at 88 (epoch 11)
// and has finalized G at 72 (epoch 9).
const G: u64 = 72;
const F: u64 = 88;
/// The bootstrap wait of most tests: long enough that no test reaches it by chance.
const WAIT: Duration = Duration::from_secs(5);

/// Blocks at 64 to 87, the checkpoint at 88, and blocks at `after`.
fn chain_with(after: impl IntoIterator<Item = u64>) -> TestChain {
    let mut chain = TestChain::new();
    chain.extend(64..F);
    chain.checkpoint(F, G);
    chain.extend(after);
    chain
}

/// A served API. Dropping it stops the API and the tasks.
struct Served {
    url: String,
    _tasks: JoinSet<()>,
}

async fn serve_api(api: Api, mut tasks: JoinSet<()>) -> Served {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tasks.spawn(serve(listener, Arc::new(api)));
    Served { url, _tasks: tasks }
}

/// The API of `rig`, and its checkpoint task when `checkpoint`. The task polls once an hour, so
/// only its first step and the steps a bootstrap miss wakes run.
async fn serve_rig(rig: &Rig, wait: Duration, checkpoint: bool) -> Served {
    let mut tasks = JoinSet::new();
    if checkpoint {
        let task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), rig.beacons());
        tasks.spawn(task.run(Duration::from_secs(3600)));
    }
    let api = Api::new(rig.answers.clone(), rig.beacons()).with_bootstrap_wait(wait);
    serve_api(api, tasks).await
}

/// Waits until the checkpoint task has ended `steps` steps.
async fn wait_for_steps(rig: &Rig, steps: u64) {
    let mut progress = rig.answers.subscribe_progress();
    tokio::time::timeout(WAIT, progress.wait_for(|p| p.done >= steps))
        .await
        .expect("the steps end")
        .unwrap();
}

/// Builds the checkpoint at F and the optimistic update that block 92 signs.
async fn build_answers(rig: &Rig, chain: &TestChain) {
    rig.state.finalize(chain.root(F));
    let mut task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), rig.beacons());
    task.step(NOW).await.unwrap();
    let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
    assert!(head.on_head(chain.root(92), NOW).await.unwrap());
}

struct Reply {
    status: u16,
    media_type: Option<String>,
    version: Option<String>,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn request(method: reqwest::Method, url: &str, path: &str, accept: Option<&str>) -> Reply {
    let mut request = reqwest::Client::new().request(method, format!("{url}{path}"));
    if let Some(accept) = accept {
        request = request.header(ACCEPT, accept);
    }
    let resp = request.send().await.unwrap();
    let header =
        |name: &str| resp.headers().get(name).map(|value| value.to_str().unwrap().to_owned());
    let (status, media_type, version) =
        (resp.status().as_u16(), header("content-type"), header(CONSENSUS_VERSION));
    Reply { status, media_type, version, body: resp.bytes().await.unwrap().to_vec() }
}

async fn get(url: &str, path: &str) -> Reply {
    request(reqwest::Method::GET, url, path, None).await
}

/// The status and the beacon API error code of `path`.
async fn status(url: &str, path: &str) -> u16 {
    let reply = get(url, path).await;
    assert_eq!(reply.json()["code"], reply.status, "{path}");
    reply.status
}

fn bootstrap_path(root: B256) -> String {
    format!("/eth/v1/beacon/light_client/bootstrap/{root:#x}")
}

/// The answers come from the pins, with no upstream request, and pass reth-lite's check.
#[tokio::test]
async fn the_genesis_and_fork_schedule_are_the_pins() {
    let chain = chain_with([]);
    let rig = Rig::start(&chain).await;
    let served = serve_rig(&rig, WAIT, false).await;
    let genesis = get(&served.url, "/eth/v1/beacon/genesis").await;
    let schedule = get(&served.url, "/eth/v1/config/fork_schedule").await;
    assert_eq!((genesis.status, schedule.status), (200, 200));
    assert_eq!(genesis.media_type.as_deref(), Some("application/json"));
    check_pins::<()>(
        &parse_genesis(&genesis.body).unwrap(),
        &parse_fork_schedule(&schedule.body).unwrap(),
        &chain.pins,
    )
    .unwrap();
    assert_eq!(rig.beacon.calls("/eth/v1/beacon/genesis"), 0);

    let pins = pulsechain_network(369).unwrap().beacon;
    assert_eq!(
        fork_schedule_json(&pins)["data"][3],
        json!({"previous_version": "0x0000036b", "current_version": "0x0000036c", "epoch": "3"})
    );
    assert_eq!(genesis_json(&pins)["data"]["genesis_time"], "1683785555");
}

/// Before the first checkpoint `updates` is an empty list and the latest updates are 404. After
/// it each answer reads back as reth-lite reads it.
#[tokio::test]
async fn the_light_client_answers_before_and_after_the_first_checkpoint() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    let served = serve_rig(&rig, WAIT, false).await;
    let updates = "/eth/v1/beacon/light_client/updates?start_period=1&count=1";
    assert_eq!(get(&served.url, updates).await.json(), json!([]));
    assert_eq!(status(&served.url, "/eth/v1/beacon/light_client/finality_update").await, 404);
    assert_eq!(status(&served.url, "/eth/v1/beacon/light_client/optimistic_update").await, 404);

    build_answers(&rig, &chain).await;

    let finality = get(&served.url, "/eth/v1/beacon/light_client/finality_update").await;
    assert_eq!(finality.status, 200);
    let finality = parse_update(&finality.body, PRESET, UpdateKind::Finality).unwrap();
    assert_eq!(finality.attested_header, *chain.at(F).header());
    assert_eq!(finality.finalized_header, *chain.at(G).header());

    let optimistic = get(&served.url, "/eth/v1/beacon/light_client/optimistic_update").await;
    let optimistic = parse_update(&optimistic.body, PRESET, UpdateKind::Optimistic).unwrap();
    assert_eq!(optimistic.attested_header, *chain.at(91).header());
    assert_eq!(optimistic.signature_slot, 92);

    // The count is capped, not refused.
    let reply =
        get(&served.url, "/eth/v1/beacon/light_client/updates?start_period=1&count=1000").await;
    let list = parse_updates(&reply.body, PRESET, 1).unwrap();
    assert_eq!(list[0].next_sync_committee, committee(2));
    // The answer starts at the first period the server has in the range, and holds none when
    // it has none there.
    let reply =
        get(&served.url, "/eth/v1/beacon/light_client/updates?start_period=0&count=2").await;
    assert_eq!(parse_updates(&reply.body, PRESET, 1).unwrap()[0], list[0]);
    for query in ["start_period=0&count=1", &format!("start_period={}&count=2", u64::MAX)] {
        let path = format!("/eth/v1/beacon/light_client/updates?{query}");
        assert_eq!(get(&served.url, &path).await.json(), json!([]), "{query}");
    }
}

/// Until the archive is checked against the self-check store after a restart, `updates` is 503
/// and not an empty list that a client cannot tell from no history. The server checks it before
/// it serves; here the first checkpoint step does.
#[tokio::test]
async fn updates_are_503_until_a_restart_checks_the_stored_ones() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    build_answers(&rig, &chain).await;
    let rig = rig.restart().await;
    let served = serve_rig(&rig, WAIT, false).await;
    let updates = "/eth/v1/beacon/light_client/updates?start_period=1&count=1";
    assert_eq!(status(&served.url, updates).await, 503);

    // The state URL names the checkpoint that the saved store has passed; the step checks the
    // archive all the same.
    let mut task = CheckpointTask::new(rig.answers.clone(), rig.state.upstream(), rig.beacons());
    let err = task.step(NOW).await.unwrap_err();
    assert!(matches!(err, CheckpointError::OlderRoot { slot: F, newest: F }), "{err}");
    let reply = get(&served.url, updates).await;
    assert_eq!(reply.status, 200);
    assert_eq!(parse_updates(&reply.body, PRESET, 1).unwrap()[0].next_sync_committee, committee(2));
}

/// The bootstrap and the latest updates name their fork in `Eth-Consensus-Version`. A client
/// that accepts SSZ only gets 406, since the server writes JSON only.
#[tokio::test]
async fn light_client_answers_name_their_fork_and_refuse_ssz_only() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    build_answers(&rig, &chain).await;
    let served = serve_rig(&rig, WAIT, false).await;
    let latest = [
        bootstrap_path(chain.root(F)),
        "/eth/v1/beacon/light_client/finality_update".to_owned(),
        "/eth/v1/beacon/light_client/optimistic_update".to_owned(),
    ];
    for path in &latest {
        let reply = get(&served.url, path).await;
        assert_eq!((reply.status, reply.version.as_deref()), (200, Some("capella")), "{path}");
    }
    let updates = "/eth/v1/beacon/light_client/updates?start_period=1&count=1".to_owned();
    for path in latest.iter().chain([&updates]) {
        let ssz = Some("application/octet-stream");
        let reply = request(reqwest::Method::GET, &served.url, path, ssz).await;
        assert_eq!((reply.status, reply.json()["code"].as_u64()), (406, Some(406)), "{path}");
        let either = Some("application/octet-stream, application/json;q=0.9");
        assert_eq!(request(reqwest::Method::GET, &served.url, path, either).await.status, 200);
        let any = Some("*/*");
        assert_eq!(request(reqwest::Method::GET, &served.url, path, any).await.status, 200);
    }
}

/// `config/spec` gives the chain ID, as Helios reads it, and the preset and the pins.
#[tokio::test]
async fn the_spec_gives_the_chain_id_preset_and_pins() {
    let chain = chain_with([]);
    let rig = Rig::start(&chain).await;
    let served = serve_rig(&rig, WAIT, false).await;
    let reply = get(&served.url, "/eth/v1/config/spec").await;
    assert_eq!(reply.status, 200);
    let data = &reply.json()["data"];
    for (key, value) in [
        ("DEPOSIT_CHAIN_ID", "1"),
        ("DEPOSIT_NETWORK_ID", "1"),
        ("SECONDS_PER_SLOT", "10"),
        ("SLOTS_PER_EPOCH", "8"),
        ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "8"),
        ("SYNC_COMMITTEE_SIZE", "32"),
        ("GENESIS_FORK_VERSION", "0x00000001"),
        ("CAPELLA_FORK_VERSION", "0x03000001"),
        ("CAPELLA_FORK_EPOCH", "0"),
    ] {
        assert_eq!(data[key], value, "{key}");
    }
}

#[tokio::test]
async fn bad_requests_are_refused() {
    let chain = chain_with([]);
    let rig = Rig::start(&chain).await;
    let served = serve_rig(&rig, WAIT, false).await;
    for path in [
        "/eth/v1/beacon/light_client/updates?start_period=1",
        "/eth/v1/beacon/light_client/updates?start_period=x&count=1",
        "/eth/v1/beacon/light_client/updates?start_period=1&count=0",
        "/eth/v1/beacon/light_client/bootstrap/0x12",
        "/eth/v1/events",
        "/eth/v1/events?topics=head",
        "/eth/v1/events?topics=light_client_finality_update,head",
        "/eth/v2/beacon/blocks/latest",
        "/eth/v1/beacon/blocks/0x12/root",
    ] {
        assert_eq!(status(&served.url, path).await, 400, "{path}");
    }
    assert_eq!(status(&served.url, "/eth/v1/node/version").await, 404);
    assert_eq!(status(&served.url, "/eth/v2/beacon/blocks/1/extra").await, 404);
    let post = request(reqwest::Method::POST, &served.url, "/eth/v1/beacon/genesis", None).await;
    assert_eq!(post.status, 405);
}

/// One event stream past the limit is 503 at once. A stream ends at its lifetime, which frees
/// its slot for the next one.
#[tokio::test]
async fn event_streams_have_their_own_limit_and_lifetime() {
    let chain = chain_with([]);
    let rig = Rig::start(&chain).await;
    let lifetime = Duration::from_millis(300);
    let api = Api::new(rig.answers.clone(), rig.beacons()).with_event_streams(1, lifetime);
    let served = serve_api(api, JoinSet::new()).await;
    let path = format!("/eth/v1/events?topics={OPTIMISTIC_TOPIC}");

    let started = Instant::now();
    let open = reqwest::get(format!("{}{path}", served.url)).await.unwrap();
    assert_eq!(open.status(), 200);
    let refused = tokio::time::timeout(WAIT, status(&served.url, &path)).await;
    assert_eq!(refused.expect("a 503, not a stream"), 503);
    // Other requests still have their slots.
    assert_eq!(status(&served.url, "/eth/v1/beacon/light_client/finality_update").await, 404);
    assert_eq!(tokio::time::timeout(WAIT, open.bytes()).await.unwrap().unwrap(), "");
    assert!(started.elapsed() >= lifetime, "{:?}", started.elapsed());
    assert_eq!(reqwest::get(format!("{}{path}", served.url)).await.unwrap().status(), 200);
}

/// A stored bootstrap reads back as reth-lite reads it, and starts a store at its root.
#[tokio::test]
async fn a_stored_bootstrap_is_served() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    build_answers(&rig, &chain).await;
    let served = serve_rig(&rig, WAIT, false).await;
    let reply = get(&served.url, &bootstrap_path(chain.root(F))).await;
    assert_eq!(reply.status, 200);
    let bootstrap = parse_bootstrap(&reply.body, PRESET).unwrap();
    assert_eq!(bootstrap.header, *chain.at(F).header());
    LightClientStore::bootstrap(PRESET, chain.pins, chain.root(F), &bootstrap).unwrap();
}

/// A miss for a root that is not the state URL's newest finalized root wakes one step, which
/// finds the root done, and answers 404 long before the wait ends.
#[tokio::test]
async fn a_bootstrap_miss_for_another_root_is_404_after_one_step() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    rig.state.finalize(chain.root(F));
    let served = serve_rig(&rig, WAIT, true).await;
    wait_for_steps(&rig, 1).await;

    let started = Instant::now();
    assert_eq!(status(&served.url, &bootstrap_path(B256::repeat_byte(9))).await, 404);
    assert!(started.elapsed() < WAIT / 2, "{:?}", started.elapsed());
    assert_eq!(rig.answers.subscribe_progress().borrow().done, 2);
    assert_eq!(rig.state.calls("/eth/v1/beacon/blocks/finalized/root"), 2);
}

/// A miss for the newest finalized root wakes the task, which builds it, and the request waits
/// for the build.
#[tokio::test]
async fn a_bootstrap_miss_for_the_finalized_root_waits_for_its_build() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    let served = serve_rig(&rig, WAIT, true).await;
    // The first step finds no finalized root.
    wait_for_steps(&rig, 1).await;
    rig.state.finalize(chain.root(F));

    let reply = get(&served.url, &bootstrap_path(chain.root(F))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(parse_bootstrap(&reply.body, PRESET).unwrap().header, *chain.at(F).header());
    assert_eq!(rig.answers.subscribe_progress().borrow().done, 2);
}

/// A miss while the task builds the root joins that build and wakes no other step.
#[tokio::test]
async fn a_bootstrap_miss_joins_the_running_build() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    // Under the 300 ms the fake's state request has for its answer head.
    rig.state.delay("/eth/v2/debug/beacon/states/88", Duration::from_millis(150));
    rig.state.finalize(chain.root(F));
    let mut progress = rig.answers.subscribe_progress();
    let served = serve_rig(&rig, WAIT, true).await;
    tokio::time::timeout(WAIT, progress.wait_for(|p| p.building == Some(chain.root(F))))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(get(&served.url, &bootstrap_path(chain.root(F))).await.status, 200);
    assert_eq!(
        *rig.answers.subscribe_progress().borrow(),
        Progress { started: 1, done: 1, building: None }
    );
    assert_eq!(rig.state.calls("/eth/v2/debug/beacon/states/88"), 1);
}

/// A build that takes longer than the wait gives a 404 at the end of the wait.
#[tokio::test]
async fn the_bootstrap_wait_is_bounded() {
    let chain = chain_with(89..96);
    let rig = Rig::start(&chain).await;
    rig.state.stall("/eth/v2/debug/beacon/states/88");
    let wait = Duration::from_millis(200);
    let served = serve_rig(&rig, wait, true).await;
    wait_for_steps(&rig, 1).await;
    rig.state.finalize(chain.root(F));

    let started = Instant::now();
    assert_eq!(status(&served.url, &bootstrap_path(chain.root(F))).await, 404);
    let elapsed = started.elapsed();
    assert!(elapsed >= wait && elapsed < wait * 2, "{elapsed:?}");
}

/// The first beacon URL that answers 200 is streamed through, with its media type and
/// consensus version, for the `Accept` the client sent.
#[tokio::test]
async fn blocks_pass_through_to_the_first_beacon_url_that_has_them() {
    let pins = TestChain::new().pins;
    let (failing, missing, good) =
        (Fake::start(&pins).await, Fake::start(&pins).await, Fake::start(&pins).await);
    let root = B256::repeat_byte(5);
    let block = format!("/eth/v2/beacon/blocks/{root}");
    let body = json!({"version": "capella", "data": {"message": {"slot": "5"}}});
    failing.answer(&block, Answer::status(500));
    good.answer(&block, Answer::json(&body).with_version("capella"));
    let beacons =
        Beacons::new(PRESET, pins, vec![failing.upstream(), missing.upstream(), good.upstream()]);
    let answers = Rig::start(&chain_with([])).await.answers;
    let served = serve_api(Api::new(answers, beacons), JoinSet::new()).await;

    let reply = request(reqwest::Method::GET, &served.url, &block, Some("application/json")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json(), body);
    assert_eq!(reply.media_type.as_deref(), Some("application/json"));
    assert_eq!(reply.version.as_deref(), Some("capella"));
    assert_eq!(good.accept(&block).as_deref(), Some("application/json"));
    assert_eq!(failing.calls(&block), 1);

    // reth-lite reads a block root through the server.
    good.answer(
        &format!("/eth/v1/beacon/blocks/{root}/root"),
        Answer::json(&json!({"data": {"root": root}})),
    );
    let client = BeaconClient::new(served.url.parse().unwrap());
    assert_eq!(client.block_root(&root.to_string()).await.unwrap(), root);
    // A 404 from any beacon URL is a 404.
    assert_eq!(status(&served.url, &format!("/eth/v2/beacon/blocks/{}", B256::ZERO)).await, 404);
    // Checkpointz writes roots without `0x` but refuses them as block ids, so a root goes up
    // with its `0x`.
    let bare = get(&served.url, &format!("/eth/v2/beacon/blocks/{}", hex::encode(root))).await;
    assert_eq!((bare.status, bare.json()), (200, body));
}

/// A named block id has no root that a client could check the answer against, so the server
/// does not pass it through: reth-lite's anchor asks for `finalized`, and one beacon URL alone
/// would then name its trust root. Roots and slots still pass.
#[tokio::test]
async fn named_block_ids_are_not_passed_through() {
    let pins = TestChain::new().pins;
    let beacon = Fake::start(&pins).await;
    let body = json!({"version": "capella", "data": {"message": {"slot": "5"}}});
    let root_body = json!({"data": {"root": B256::repeat_byte(5)}});
    for id in ["head", "finalized", "justified", "genesis", "5"] {
        beacon.answer(&format!("/eth/v2/beacon/blocks/{id}"), Answer::json(&body));
        beacon.answer(&format!("/eth/v1/beacon/blocks/{id}/root"), Answer::json(&root_body));
    }
    let beacons = Beacons::new(PRESET, pins, vec![beacon.upstream()]);
    let answers = Rig::start(&chain_with([])).await.answers;
    let served = serve_api(Api::new(answers, beacons), JoinSet::new()).await;
    for id in ["head", "finalized", "justified", "genesis"] {
        for path in
            [format!("/eth/v2/beacon/blocks/{id}"), format!("/eth/v1/beacon/blocks/{id}/root")]
        {
            let reply = get(&served.url, &path).await;
            assert_eq!(reply.status, 400, "{path}");
            assert_eq!(
                reply.json()["message"],
                "the server passes through block roots and slots only: no client can check a \
                 named block against a root",
                "{path}"
            );
            assert_eq!(beacon.calls(&path), 0, "{path}");
        }
    }
    assert_eq!(get(&served.url, "/eth/v2/beacon/blocks/5").await.json(), body);
    assert_eq!(get(&served.url, "/eth/v1/beacon/blocks/5/root").await.json(), root_body);
    let client = BeaconClient::new(served.url.parse().unwrap());
    assert_eq!(
        client.block_root("finalized").await,
        Err(reth_pulsechain_lite::beacon::SourceError::Status(400))
    );
}

#[tokio::test]
async fn a_pass_through_with_no_good_answer_is_502() {
    let pins = TestChain::new().pins;
    let (failing, large) = (Fake::start(&pins).await, Fake::start(&pins).await);
    failing.answer("/eth/v2/beacon/blocks/5", Answer::status(500));
    large.answer("/eth/v2/beacon/blocks/5", Answer::ssz(vec![0; MAX_PASS_THROUGH_BODY + 1]));
    let beacons = Beacons::new(PRESET, pins, vec![failing.upstream(), large.upstream()]);
    let answers = Rig::start(&chain_with([])).await.answers;
    let served = serve_api(Api::new(answers, beacons), JoinSet::new()).await;
    assert_eq!(status(&served.url, "/eth/v2/beacon/blocks/5").await, 502);
    assert_eq!(large.calls("/eth/v2/beacon/blocks/5"), 1);
}

/// A body over the limit with no length to refuse up front is cut off.
#[tokio::test]
async fn a_pass_through_body_over_the_limit_is_cut_off() {
    let pins = TestChain::new().pins;
    let large = Fake::start(&pins).await;
    let answer = Answer::ssz(vec![0; MAX_PASS_THROUGH_BODY + 1]).without_length();
    large.answer("/eth/v2/beacon/blocks/5", answer);
    let beacons = Beacons::new(PRESET, pins, vec![large.upstream()]);
    let answers = Rig::start(&chain_with([])).await.answers;
    let served = serve_api(Api::new(answers, beacons), JoinSet::new()).await;
    let resp = reqwest::get(format!("{}/eth/v2/beacon/blocks/5", served.url)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes().await.is_err());
}

/// reth-lite's own start checks, event stream and store run against the server, over a fake
/// beacon URL and a fake state URL that is also reth-lite's anchor.
#[tokio::test]
async fn reth_lite_follows_the_server() {
    // F at 88 finalized 72; the checkpoint at 112 finalized 96. All are in period 1.
    let mut chain = chain_with(89..112);
    chain.checkpoint(112, 96);
    chain.extend(113..116);
    let rig = Rig::start(&chain).await;
    let served = serve_rig(&rig, BOOTSTRAP_WAIT, true).await;
    // The first step finds no finalized root, so reth-lite's bootstrap request wakes the build.
    wait_for_steps(&rig, 1).await;
    rig.state.finalize(chain.root(F));

    let server = BeaconClient::new(served.url.parse().unwrap());
    let anchor = BeaconClient::new(rig.state.url());
    let start = check_sync_committee_start(
        std::slice::from_ref(&server),
        &anchor,
        chain.pins,
        PRESET,
        StartFrom::Anchor,
        std::time::SystemTime::now(),
    )
    .await
    .unwrap();
    assert_eq!(start.origin, StoreOrigin::Bootstrap { anchor_root: chain.root(F) });
    assert_eq!((start.sources, start.unchecked), (vec![0], vec![]));
    let mut store = start.store;
    assert_eq!((store.period(), store.finalized_header()), (1, chain.at(F).header()));

    let mut events =
        server.events_of(Topics::LightClient(PRESET), Duration::from_secs(5)).await.unwrap();
    let mut head = HeadTask::new(rig.answers.clone(), rig.beacons());
    assert!(head.on_head(chain.root(98), NOW).await.unwrap());
    let Some(Event::OptimisticUpdate(update)) = events.next_event().await else {
        panic!("an optimistic update event")
    };
    store.process_update(&update, NOW).unwrap();
    assert_eq!(store.optimistic_header(), chain.at(97).header());

    // reth-lite asks for the next committee as its follower does.
    let updates = server.light_client_updates(store.period(), 16, PRESET).await.unwrap();
    store.process_update(&updates[0], NOW).unwrap();
    assert_eq!(store.next_sync_committee(), Some(&committee(2)));

    // A bootstrap request at the next finalized root wakes its build; the finality update
    // comes as an event and moves the store's finality.
    rig.state.finalize(chain.root(112));
    let bootstrap = server.light_client_bootstrap(chain.root(112), PRESET).await.unwrap();
    assert_eq!(bootstrap.header, *chain.at(112).header());
    let Some(Event::FinalityUpdate(update)) = events.next_event().await else {
        panic!("a finality update event")
    };
    store.process_update(&update, NOW).unwrap();
    assert_eq!(store.finalized_header(), chain.at(96).header());
}

/// Builds a bootstrap from the real finalized state of `checkpoint.pulsechain.com`, serves it,
/// and verifies it as reth-lite does.
#[tokio::test]
#[ignore = "fetches a 19 MB state from checkpoint.pulsechain.com"]
async fn a_bootstrap_from_the_live_369_state_verifies() {
    let pins = pulsechain_network(369).unwrap().beacon;
    let preset = Preset::PULSECHAIN;
    let checkpointz = Upstream::new(CHECKPOINTZ_369.parse().unwrap(), Timeouts::default());
    checkpointz.check_genesis(&pins).await.unwrap();
    let root = checkpointz.finalized_root().await.unwrap();
    let beacons = Beacons::new(preset, pins, vec![checkpointz.clone()]);
    let f =
        beacons.block_by_root(root).await.unwrap().expect("Checkpointz has its finalized block");
    let state = checkpointz.state(f.slot()).await.unwrap();
    let bootstrap = CheckedState::new(preset, &pins, &f, &state).unwrap().bootstrap();
    drop(state);
    let store = LightClientStore::bootstrap(preset, pins, root, &bootstrap).unwrap();

    let datadir = tempfile::tempdir().unwrap();
    let mut archive = Archive::open(datadir.path(), 369, preset, pins, None).await.unwrap();
    archive.save_bootstrap(bootstrap.clone()).await.unwrap();
    let answers = Arc::new(Answers::new(preset, pins, archive, store));
    let served = serve_api(Api::new(answers, beacons), JoinSet::new()).await;
    let client = BeaconClient::new(served.url.parse().unwrap());
    let read = client.light_client_bootstrap(root, preset).await.unwrap();
    assert_eq!(read, bootstrap);
    let store = LightClientStore::bootstrap(preset, pins, root, &read).unwrap();
    assert_eq!(store.finalized_header().beacon.slot, f.slot());
}
