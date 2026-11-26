//! The `-dev` rule of the version text. `build.rs` uses it, and `tests/build_version.rs` tests
//! it.

/// Whether `describe` names a commit that is not a tagged release.
///
/// `describe` is `git describe --always --dirty` over annotated tags: `<tag>` on a tag,
/// `<tag>-<n>-g<sha prefix>` off one, and the bare sha prefix when no annotated tag is in reach
/// (a shallow, `--no-tags` or depth-limited CI checkout). `-dirty` may follow. Git picks the
/// length of the sha prefix from the repository size, so any prefix of `sha` matches.
pub(crate) fn not_on_tag(sha: &str, describe: &str) -> bool {
    let describe = describe.strip_suffix("-dirty").unwrap_or(describe);
    sha.starts_with(describe) ||
        describe.rsplit_once("-g").is_some_and(|(_, hash)| sha.starts_with(hash))
}
