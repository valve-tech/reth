#![allow(missing_docs)]

mod build_version;

use build_version::{lite_version, GitFacts};
use smolgen::{Emitter, Gitcl};
use std::{env, error::Error, path::Path};

/// Sets `RETH_LITE_VERSION`: see [`lite_version`].
fn main() -> Result<(), Box<dyn Error>> {
    // Debug builds skip tracking HEAD, so a commit does not rebuild the crate; release builds track
    // it, so their version always matches the checkout.
    let git = Gitcl::builder()
        .describe(false, true, None)
        .dirty(true)
        .sha(false)
        .rerun_on_head_change(env::var("PROFILE")? != "debug")
        .build();
    let mut emitter = Emitter::default();
    emitter.add_instructions(&git)?;
    emitter.emit_and_set()?;

    // Outside a git checkout (a source tarball) smolgen only warns and sets none of the variables.
    let git = match env::var("VERGEN_GIT_SHA") {
        Ok(sha) => Some(GitFacts {
            sha,
            dirty: env::var("VERGEN_GIT_DIRTY")? == "true",
            describe: env::var("VERGEN_GIT_DESCRIBE")?,
        }),
        Err(_) => None,
    };
    // This crate is `crates/pulsechain/lite` in the workspace.
    let workspace = Path::new(&env::var("CARGO_MANIFEST_DIR")?).join("../../..");
    let version = lite_version(env!("CARGO_PKG_VERSION"), &workspace, git);
    println!("cargo:rustc-env=RETH_LITE_VERSION={version}");
    Ok(())
}
