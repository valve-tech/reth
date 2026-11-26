//! Tests the `-dev` rule of the version text that `build.rs` sets.

#[path = "../build_version.rs"]
mod build_version;

use build_version::not_on_tag;

#[test]
fn only_a_tag_reads_as_a_release() {
    let sha = "1a2b3c4d5e6f";
    assert!(!not_on_tag(sha, "v2.11.0-pulse"), "on a tag");
    assert!(!not_on_tag(sha, "v2.11.0-pulse-dirty"), "on a tag, dirty");
    assert!(not_on_tag(sha, "v2.11.0-pulse-3-g1a2b3c4"), "off a tag");
    // With no annotated tag in reach describe falls back to the short sha.
    assert!(not_on_tag(sha, "1a2b3c4"), "no tag");
    assert!(not_on_tag(sha, "1a2b3c4d5e-dirty"), "no tag, dirty");
    assert!(not_on_tag(sha, "v2.11.0-pulse-3-g1a2b3c4d5e-dirty"), "off a tag, dirty");
}
