//! The `RETH_LITE_VERSION` text. `build.rs` sets it, and `src/testing.rs` tests it.

use std::{path::Path, process::Command};

/// What smolgen reads from git.
pub(crate) struct GitFacts {
    /// The full commit sha.
    pub(crate) sha: String,
    /// Whether the tree has changes, untracked files included.
    pub(crate) dirty: bool,
    /// `git describe --always` over annotated tags: `<tag>`, `<tag>-<n>-g<sha prefix>`, or the
    /// bare sha prefix when no annotated tag is in reach. `-dirty` may follow.
    pub(crate) describe: String,
}

/// The version as pulse-reth sets its short version: `2.11.0-pulse (1a2b3c4d)`, with `-dev`
/// after `pulse` off a tag or in a dirty tree, and `2.11.0-pulse-dev (unknown)` when `git` is
/// `None` or comes from a checkout other than `workspace`.
pub(crate) fn lite_version(pkg: &str, workspace: &Path, git: Option<GitFacts>) -> String {
    let Some(GitFacts { sha, dirty, describe }) = git.filter(|_| checkout_top(workspace)) else {
        return format!("{pkg}-pulse-dev (unknown)")
    };
    // `git describe` ends in `-g<sha prefix>` off a tag, and is the bare prefix with no tag.
    let describe = describe.strip_suffix("-dirty").unwrap_or(&describe);
    let not_on_tag = sha.starts_with(describe) ||
        describe.rsplit_once("-g").is_some_and(|(_, hash)| sha.starts_with(hash));
    let suffix = if dirty || not_on_tag { "-dev" } else { "" };
    let short = sha.get(..8).unwrap_or(&sha);
    format!("{pkg}-pulse{suffix} ({short})")
}

/// Whether `workspace` is the top of the git checkout that holds it. A source tarball unpacked
/// inside another repository (a packaging checkout, a vendor directory) finds that repository,
/// whose commit is not a reth commit, even when that repository tracks the files.
fn checkout_top(workspace: &Path) -> bool {
    let Ok(out) = git(workspace).args(["rev-parse", "--show-toplevel"]).output() else {
        return false
    };
    let top = String::from_utf8_lossy(&out.stdout);
    let top = Path::new(top.strip_suffix('\n').unwrap_or(&top));
    out.status.success() &&
        matches!((top.canonicalize(), workspace.canonicalize()), (Ok(t), Ok(w)) if t == w)
}

/// `git` in `dir`. Git exports `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` to a hook, and a
/// build or test that a hook runs must find the checkout from `dir`, not from those.
pub(crate) fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    cmd
}
