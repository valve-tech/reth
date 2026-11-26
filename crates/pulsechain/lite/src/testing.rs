//! Test support: a generated world state and an honest fetcher over it.

use crate::{
    exec::{FetchError, Fetcher},
    state::{Lookup, MissKey, PartialState},
    store::NodeStore,
    verify::{slot_rlp, walk_path},
};
use alloy_consensus::{
    constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY},
    TrieAccount,
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::Nibbles;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// One account of a test world.
#[derive(Default, Clone)]
pub(crate) struct Acct {
    pub balance: u64,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: Vec<(U256, U256)>,
}

/// A state trie with every node and code blob an honest full node would hold.
pub(crate) struct World {
    pub root: B256,
    pub nodes: HashMap<B256, Bytes>,
    pub codes: HashMap<B256, Bytes>,
}

pub(crate) fn world(accts: &[(Address, Acct)]) -> World {
    let mut nodes = HashMap::new();
    let mut codes = HashMap::new();
    let mut leaves = Vec::new();
    for (addr, a) in accts {
        let storage_root = if a.storage.is_empty() {
            EMPTY_ROOT_HASH
        } else {
            let slots: Vec<_> = a
                .storage
                .iter()
                .map(|(k, v)| (keccak256(B256::from(*k)), slot_rlp(*v).to_vec()))
                .collect();
            let b = crate::verify::fixtures::build(slots, &[]);
            nodes.extend(b.all_nodes);
            b.root
        };
        let code_hash = if a.code.is_empty() {
            KECCAK_EMPTY
        } else {
            let h = keccak256(&a.code);
            codes.insert(h, Bytes::from(a.code.clone()));
            h
        };
        let t =
            TrieAccount { nonce: a.nonce, balance: U256::from(a.balance), storage_root, code_hash };
        leaves.push((keccak256(addr), crate::verify::fixtures::account_leaf(&t)));
    }
    let b = crate::verify::fixtures::build(leaves, &[]);
    nodes.extend(b.all_nodes);
    World { root: b.root, nodes, codes }
}

/// An honest full node: serves the nodes on the path of each miss and code by hash.
pub(crate) struct Honest {
    pub world: Arc<World>,
    pub store: Arc<dyn NodeStore>,
    pub calls: AtomicUsize,
}

impl Honest {
    pub(crate) fn new(world: Arc<World>, store: Arc<dyn NodeStore>) -> Self {
        Self { world, store, calls: AtomicUsize::new(0) }
    }
}

#[async_trait]
impl Fetcher for Honest {
    async fn fetch(&self, root: B256, misses: &[MissKey]) -> Result<(), FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let get = |h: &B256| self.world.nodes.get(h).cloned();
        for m in misses {
            let nodes = match m {
                MissKey::Account(a, _) => {
                    walk_path(root, &Nibbles::unpack(keccak256(a)), get).unwrap().nodes
                }
                MissKey::Slot(a, slot) => {
                    let st = PartialState::new(self.store.clone(), root);
                    let Lookup::Hit(Some(acct)) = st.account(a) else { continue };
                    walk_path(acct.storage_root, &Nibbles::unpack(keccak256(slot)), get)
                        .unwrap()
                        .nodes
                }
                MissKey::Code(h) => {
                    if let Some(c) = self.world.codes.get(h) {
                        self.store.put_code(*h, c.clone());
                    }
                    continue;
                }
                MissKey::Header(_) => continue,
            };
            for (h, n) in nodes {
                self.store.put(h, n);
            }
        }
        Ok(())
    }
}

/// Answers a snap/1 request the way an honest full node would, from `world`.
pub(crate) fn serve_snap(
    world: &World,
    msg: reth_pulsechain_snap::Snap1Message,
) -> reth_pulsechain_snap::Snap1Message {
    use reth_eth_wire_types::snap::{
        AccountData, AccountRangeMessage, ByteCodesMessage, SnapProtocolMessage as M, StorageData,
        StorageRangesMessage,
    };
    use reth_pulsechain_snap::Snap1Message as S;
    let get = |h: &B256| world.nodes.get(h).cloned();
    match msg {
        S::Shared(M::GetAccountRange(r)) => {
            let walk = walk_path(r.root_hash, &Nibbles::unpack(r.starting_hash), get).unwrap();
            let accounts = walk
                .value
                .map(|leaf| {
                    let a = <TrieAccount as alloy_rlp::Decodable>::decode(&mut leaf.as_slice())
                        .unwrap();
                    vec![AccountData::from_trie_account(r.starting_hash, &a)]
                })
                .unwrap_or_default();
            let proof = walk.nodes.into_iter().map(|(_, n)| n).collect();
            S::Shared(M::AccountRange(AccountRangeMessage {
                request_id: r.request_id,
                accounts,
                proof,
            }))
        }
        S::Shared(M::GetStorageRanges(r)) => {
            let account = r.account_hashes[0];
            let leaf = walk_path(r.root_hash, &Nibbles::unpack(account), get).unwrap().value;
            let Some(leaf) = leaf else {
                return S::Shared(M::StorageRanges(StorageRangesMessage {
                    request_id: r.request_id,
                    slots: vec![],
                    proof: vec![],
                }));
            };
            let acct = <TrieAccount as alloy_rlp::Decodable>::decode(&mut leaf.as_slice()).unwrap();
            let slot = r.starting_hash.unwrap_or(B256::ZERO);
            let walk = walk_path(acct.storage_root, &Nibbles::unpack(slot), get).unwrap();
            let slots = walk
                .value
                .map(|v| vec![vec![StorageData { hash: slot, data: Bytes::from(v) }]])
                .unwrap_or_else(|| vec![vec![]]);
            let proof = walk.nodes.into_iter().map(|(_, n)| n).collect();
            S::Shared(M::StorageRanges(StorageRangesMessage {
                request_id: r.request_id,
                slots,
                proof,
            }))
        }
        S::Shared(M::GetByteCodes(r)) => {
            let codes = r.hashes.iter().filter_map(|h| world.codes.get(h).cloned()).collect();
            S::Shared(M::ByteCodes(ByteCodesMessage { request_id: r.request_id, codes }))
        }
        other => other,
    }
}

/// The private references in every file git tracks in the checkout that holds `dir`, and in
/// their names, as `scripts/private-scan.sh` finds them. Empty when there are none. `None` when
/// git does not track `probe` (relative to `dir`): a source tarball has no `.git`, and one
/// unpacked inside another repository finds that one.
///
/// A release also publishes the history of its tag; `valve-release.yml` runs
/// `scripts/release-scan.sh` over the commits that no released tag reaches.
fn private_references(dir: &std::path::Path, probe: &str) -> Option<String> {
    let tracked = build_version::git(dir)
        .args(["ls-files", "--error-unmatch", "--", probe])
        .output()
        .is_ok_and(|out| out.status.success());
    if !tracked {
        return None
    }
    Some(match private_scan(dir, &[]) {
        (Some(0), _) => String::new(),
        (code, text) => format!("private-scan exited {code:?}:\n{text}"),
    })
}

/// Runs `scripts/private-scan.sh` with `args` in `dir`: its exit code and its standard output,
/// with its standard error after it.
fn private_scan(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String) {
    run_script("private-scan.sh", dir, args)
}

/// Runs `scripts/<name>` as [`private_scan`] does.
fn run_script(name: &str, dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String) {
    let out = std::process::Command::new("bash")
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts").join(name))
        .args(args)
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("bash runs");
    let text =
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

/// `git` in the test repository `dir`, with no user or system config, so a global hook or
/// signing rule does not run, and with a fixed author.
fn test_git(dir: &std::path::Path) -> std::process::Command {
    let mut cmd = build_version::git(dir);
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").args([
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
    ]);
    cmd
}

/// CI sets `RETH_LITE_REQUIRE_GIT=1`, so the scan fails there instead of skipping.
#[test]
fn tracked_files_cite_nothing_a_public_reader_cannot_open() {
    let Some(found) =
        private_references(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), "src/testing.rs")
    else {
        assert!(
            std::env::var_os("RETH_LITE_REQUIRE_GIT").is_none(),
            "RETH_LITE_REQUIRE_GIT is set, but git does not track src/testing.rs"
        );
        eprintln!("skipped: git does not track src/testing.rs, so there is no checkout to scan");
        return
    };
    assert_eq!(found, "", "private references");
}

/// The scan skips a tree git does not track, even inside another repository, and finds a
/// planted reference in a tracked file.
#[test]
fn the_private_scan_skips_an_untracked_tree_and_finds_a_planted_reference() {
    let root = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let out = test_git(root.path()).args(args).output().expect("git runs");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    let tarball = root.path().join("tarball");
    std::fs::create_dir(&tarball).unwrap();
    std::fs::write(tarball.join("probe.rs"), "").unwrap();
    assert_eq!(private_references(&tarball, "probe.rs"), None, "no checkout");
    git(&["init", "-q"]);
    assert_eq!(private_references(&tarball, "probe.rs"), None, "inside another checkout");
    git(&["add", "tarball/probe.rs"]);
    assert_eq!(private_references(&tarball, "probe.rs").as_deref(), Some(""), "clean");
    // Brew's prefix and the GitHub Actions home are public paths.
    std::fs::write(
        root.path().join("brew.md"),
        "/home/linuxbrew/.linuxbrew/bin\n/home/runner/work/reth/reth\nHOME=/home/runner\n",
    )
    .unwrap();
    git(&["add", "brew.md"]);
    assert_eq!(private_references(&tarball, "probe.rs").as_deref(), Some(""), "public homes");
    // Another user whose name starts the same way is not.
    std::fs::write(root.path().join("home.md"), concat!("/ho", "me/runners/x\n")).unwrap();
    git(&["add", "home.md"]);
    let found = private_references(&tarball, "probe.rs").unwrap();
    assert_eq!(found, concat!("private-scan exited Some(1):\nhome.md:1:/ho", "me/runners/x\n"));
    git(&["rm", "-q", "--cached", "home.md"]);
    // The match ignores case.
    std::fs::write(root.path().join("notes.md"), concat!("see the Jump", "Gate box\n")).unwrap();
    git(&["add", "notes.md"]);
    let found = private_references(&tarball, "probe.rs").unwrap();
    assert_eq!(
        found,
        concat!("private-scan exited Some(1):\nnotes.md:1:see the Jump", "Gate box\n")
    );
}

/// The history scan reads each commit a push of a tag publishes: messages and changes, also of
/// a file a later commit deleted, and the tag's own message. History already public is skipped.
#[test]
fn the_private_history_scan_reads_what_a_push_publishes() {
    let root = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let out = test_git(root.path()).args(args).output().expect("git runs");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["init", "-q"]);
    std::fs::write(root.path().join("a.md"), "public\n").unwrap();
    git(&["add", "a.md"]);
    git(&["commit", "-qm", "public"]);
    let public = git(&["rev-parse", "HEAD"]);
    std::fs::write(root.path().join("notes.md"), concat!("see the Jump", "Gate box\n")).unwrap();
    git(&["add", "notes.md"]);
    git(&["commit", "-qm", concat!("plan the Pulse", "Lite node")]);
    let added = git(&["rev-parse", "--short=12", "HEAD"]);
    git(&["rm", "-q", "notes.md"]);
    git(&["commit", "-qm", "drop the notes"]);
    let removed = git(&["rev-parse", "--short=12", "HEAD"]);
    git(&["tag", "-a", "v1", "-m", concat!("ships the lite", "check fixes")]);
    // The tree is clean.
    assert_eq!(private_scan(root.path(), &[]), (Some(0), String::new()));
    assert_eq!(
        private_scan(root.path(), &["v1", "HEAD"]).1,
        concat!("tag v1: ships the lite", "check fixes\n")
    );
    let (code, found) = private_scan(root.path(), &["v1", &public]);
    assert_eq!(code, Some(1), "{found}");
    for want in [
        format!(concat!("commit {}: plan the Pulse", "Lite node"), added),
        format!(concat!("commit {} notes.md: +see the Jump", "Gate box"), added),
        format!(concat!("commit {} notes.md: -see the Jump", "Gate box"), removed),
    ] {
        assert!(found.lines().any(|l| l == want), "no `{want}` in:\n{found}");
    }
    // Everything is public.
    assert_eq!(private_scan(root.path(), &["HEAD", "HEAD"]), (Some(0), String::new()));
    assert_eq!(private_scan(root.path(), &["nope"]).0, Some(2));
}

/// A step of the scan that fails makes the whole scan fail, even when the steps after it find
/// nothing. Here git cannot read part of the public tree, as in a damaged or partial clone.
#[test]
fn the_private_scan_fails_when_a_step_fails() {
    for missing in ["dir", "dir/a.md"] {
        let root = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let out = test_git(root.path()).args(args).output().expect("git runs");
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        git(&["init", "-q"]);
        std::fs::create_dir(root.path().join("dir")).unwrap();
        std::fs::write(root.path().join("dir/a.md"), "public\n").unwrap();
        git(&["add", "dir"]);
        git(&["commit", "-qm", "public"]);
        let public = git(&["rev-parse", "HEAD"]);
        std::fs::write(root.path().join("b.md"), "new\n").unwrap();
        git(&["add", "b.md"]);
        git(&["commit", "-qm", "new"]);
        assert_eq!(private_scan(root.path(), &["HEAD", &public]), (Some(0), String::new()));
        // The new commit does not touch `dir`, so only the tree scan reads it.
        let object = git(&["rev-parse", &format!("HEAD:{missing}")]);
        let (dir, file) = object.split_at(2);
        std::fs::remove_file(root.path().join(".git/objects").join(dir).join(file)).unwrap();
        let (code, text) = private_scan(root.path(), &["HEAD", &public]);
        assert_eq!(code, Some(2), "without {missing}: {text}");
    }
}

/// The release gate counts history as public only when a released tag reaches it. A branch and
/// a second tag pushed with the release tag are new too, so they hide nothing.
#[test]
fn the_release_scan_reads_what_no_released_tag_reaches() {
    let root = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let out = test_git(root.path()).args(args).output().expect("git runs");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["init", "-q"]);
    std::fs::write(root.path().join("a.md"), "public\n").unwrap();
    git(&["add", "a.md"]);
    git(&["commit", "-qm", concat!("an old Jump", "Gate note")]);
    git(&["tag", "v0-pulse"]);
    git(&["commit", "-q", "--allow-empty", "-m", concat!("plan the Pulse", "Lite node")]);
    let new = git(&["rev-parse", "--short=12", "HEAD"]);
    // One push carries the release tag, a second tag and the branch, all at the new commit.
    git(&["tag", "v1-pulse"]);
    git(&["tag", "v1-lite"]);
    let released = root.path().join("released");
    let scan = |names: &str| {
        std::fs::write(&released, names).unwrap();
        run_script("release-scan.sh", root.path(), &["v1-pulse", released.to_str().unwrap()])
    };
    let want = format!(concat!("commit {}: plan the Pulse", "Lite node\n"), new);
    assert_eq!(scan("v0-pulse\n"), (Some(1), want.clone()));
    // A rebuild of the released tag, and a released tag this clone lacks, change nothing.
    assert_eq!(scan("v1-pulse\nv0-pulse\nv9-pulse"), (Some(1), want));
    // History that a released tag reaches is public.
    git(&["tag", "v1.1-pulse"]);
    assert_eq!(scan("v0-pulse\nv1.1-pulse\n"), (Some(0), String::new()));
    // With no released tag, the scan reads every commit.
    let (code, found) = scan("");
    assert_eq!(code, Some(1));
    assert_eq!(found.lines().count(), 2, "{found}");
}

#[path = "../build_version.rs"]
mod build_version;

/// The version names a commit only of the checkout whose top is the workspace: a source tarball
/// unpacked inside another repository must not print that repository's commit.
#[test]
fn the_version_names_only_the_workspace_checkout() {
    use build_version::{lite_version, GitFacts};
    let root = tempfile::tempdir().unwrap();
    let git = |dir: &std::path::Path, args: &[&str]| {
        let out = test_git(dir).args(args).output().expect("git runs");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    let facts = |describe: &str, dirty| {
        Some(GitFacts { sha: "1a2b3c4d5e6f".into(), dirty, describe: describe.into() })
    };
    let tarball = root.path().join("tarball");
    std::fs::create_dir(&tarball).unwrap();
    let version = |git| lite_version("2.11.0", &tarball, git);
    assert_eq!(version(facts("v2.11.0", false)), "2.11.0-pulse-dev (unknown)", "no checkout");
    git(root.path(), &["init", "-q"]);
    std::fs::write(root.path().join(".gitignore"), "tarball/\n").unwrap();
    assert_eq!(version(facts("v2.11.0", false)), "2.11.0-pulse-dev (unknown)", "outer checkout");
    std::fs::write(tarball.join("Cargo.toml"), "").unwrap();
    git(root.path(), &["add", "-f", "tarball/Cargo.toml"]);
    assert_eq!(version(facts("v2.11.0", false)), "2.11.0-pulse-dev (unknown)", "outer tracks it");
    git(&tarball, &["init", "-q"]);
    assert_eq!(version(None), "2.11.0-pulse-dev (unknown)", "no facts");
    assert_eq!(version(facts("v2.11.0", false)), "2.11.0-pulse (1a2b3c4d)", "on a tag");
    assert_eq!(version(facts("v2.11.0", true)), "2.11.0-pulse-dev (1a2b3c4d)", "dirty");
    let off_tag = facts("v2.11.0-3-g1a2b3c4", false);
    assert_eq!(version(off_tag), "2.11.0-pulse-dev (1a2b3c4d)", "off a tag");
    // With no annotated tag in reach (a shallow or `--no-tags` clone) describe falls back to
    // the short sha.
    assert_eq!(version(facts("1a2b3c4d5e", false)), "2.11.0-pulse-dev (1a2b3c4d)", "no tag");
    assert_eq!(version(facts("1a2b3c4d5e-dirty", false)), "2.11.0-pulse-dev (1a2b3c4d)", "no tag");
}

/// Git exports `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` to its hooks. A hook that runs
/// these tests must not let their git commands reach the repository the hook runs for.
#[test]
fn the_git_tests_ignore_the_git_variables_of_a_hook() {
    let victim = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let out = test_git(victim.path()).args(args).output().expect("git runs");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    git(&["init", "-q"]);
    let dot_git = victim.path().join(".git");
    for test in [
        "testing::the_private_scan_skips_an_untracked_tree_and_finds_a_planted_reference",
        "testing::the_private_history_scan_reads_what_a_push_publishes",
        "testing::the_version_names_only_the_workspace_checkout",
    ] {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("GIT_DIR", &dot_git)
            .env("GIT_WORK_TREE", victim.path())
            .env("GIT_INDEX_FILE", dot_git.join("index"))
            .output()
            .expect("the test binary runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success() && text.contains("1 passed"), "{test}:\n{text}");
        assert_eq!(git(&["ls-files"]), "", "{test} staged files in the hook's repository");
    }
}

/// The fuzz READMEs build into `<top>/fuzz-target`. Untracked files there would mark every
/// later build of the checkout `-dev`, as the version counts untracked files.
#[test]
fn the_fuzz_build_directory_is_ignored() {
    let top = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."));
    let Ok(out) = build_version::git(top).args(["check-ignore", "-q", "fuzz-target/x"]).output()
    else {
        assert!(std::env::var_os("RETH_LITE_REQUIRE_GIT").is_none(), "git does not run");
        return
    };
    match out.status.code() {
        Some(0) => {}
        // Not a checkout: a source tarball.
        Some(128) if std::env::var_os("RETH_LITE_REQUIRE_GIT").is_none() => {}
        code => panic!("fuzz-target/ is not ignored at the top: {code:?}"),
    }
}

/// The build script finds the workspace from the crate's path. CI sets `RETH_LITE_REQUIRE_GIT=1`,
/// so a wrong path, which reads as no checkout, fails there.
#[test]
fn the_version_names_a_commit_in_a_checkout() {
    if std::env::var_os("RETH_LITE_REQUIRE_GIT").is_none() {
        eprintln!("skipped: RETH_LITE_REQUIRE_GIT is not set");
        return
    }
    let version = env!("RETH_LITE_VERSION");
    assert!(!version.ends_with("(unknown)"), "{version}");
}

/// The workspace inherits upstream reth's links, which send a reader of a fork-only crate to the
/// wrong project.
#[test]
fn fork_crates_link_to_the_fork() {
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["metadata", "--no-deps", "--format-version", "1", "--offline"])
        .output()
        .expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata is JSON");
    let packages = meta["packages"].as_array().expect("packages is an array");
    for name in ["reth-pulsechain-lite", "reth-pulsechain-snap"] {
        let pkg = packages.iter().find(|p| p["name"] == name).expect("package is in the workspace");
        assert_eq!(
            (pkg["repository"].as_str(), pkg["homepage"].as_str()),
            (
                Some("https://github.com/valve-tech/reth"),
                Some("https://github.com/valve-tech/reth")
            ),
            "{name}"
        );
    }
}

/// Log capture for tests. One global subscriber is installed for the whole test binary, so no
/// callsite is ever cached as disabled: with only thread-local subscribers, a callsite that
/// another test's thread registers while none is set stays off, and a test that asserts a secret
/// is absent from the logs would then pass without seeing them. Each capture collects the lines
/// its own thread logs at `level` or above.
pub(crate) mod logs {
    use std::{cell::RefCell, io::Write, sync::Once};
    use tracing::{Level, Metadata};

    thread_local! {
        static CAPTURE: RefCell<Option<(Level, Vec<u8>)>> = const { RefCell::new(None) };
    }

    struct ThreadWriter {
        keep: bool,
    }

    impl Write for ThreadWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.keep {
                CAPTURE.with(|c| {
                    if let Some((_, buf)) = c.borrow_mut().as_mut() {
                        buf.extend_from_slice(b);
                    }
                });
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MakeThreadWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeThreadWriter {
        type Writer = ThreadWriter;
        fn make_writer(&'a self) -> ThreadWriter {
            ThreadWriter { keep: false }
        }
        fn make_writer_for(&'a self, meta: &Metadata<'_>) -> ThreadWriter {
            // `TRACE` compares greatest: a line is kept when it is at most as verbose as asked.
            let keep =
                CAPTURE.with(|c| c.borrow().as_ref().is_some_and(|(l, _)| meta.level() <= l));
            ThreadWriter { keep }
        }
    }

    /// Captures this thread's log lines at `level` or above until it is dropped.
    pub(crate) struct Capture(());

    impl Capture {
        /// The text captured so far.
        pub(crate) fn text(&self) -> String {
            CAPTURE
                .with(|c| c.borrow().as_ref().map(|(_, b)| String::from_utf8_lossy(b).into_owned()))
                .unwrap_or_default()
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            CAPTURE.with(|c| c.borrow_mut().take());
        }
    }

    /// Starts capturing this thread's log lines at `level` or above.
    pub(crate) fn capture(level: Level) -> Capture {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let sub = tracing_subscriber::fmt()
                .with_writer(MakeThreadWriter)
                .with_ansi(false)
                .with_max_level(Level::TRACE)
                .finish();
            tracing::subscriber::set_global_default(sub).expect("no other global subscriber");
        });
        CAPTURE.with(|c| *c.borrow_mut() = Some((level, Vec::new())));
        Capture(())
    }

    #[test]
    fn a_capture_keeps_its_level_and_its_thread_only() {
        let cap = capture(Level::WARN);
        tracing::warn!("kept");
        tracing::info!("too verbose");
        std::thread::spawn(|| tracing::warn!("another thread")).join().unwrap();
        let text = cap.text();
        assert!(text.contains("kept"), "{text}");
        assert!(!text.contains("too verbose") && !text.contains("another thread"), "{text}");
    }
}
