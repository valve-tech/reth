#!/usr/bin/env bash
# Merge an upstream reth release into this fork, and do the mechanical parts for you.
#
#   scripts/merge-upstream.sh start <ref>   # e.g. reth-v2.11.0-fh3.1 (StreamingFast) or v2.11.0
#   (resolve the conflicts it lists, `git add` them)
#   scripts/merge-upstream.sh finish        # regenerate lock + CLI docs, check, commit
#
# Prefer the StreamingFast firehose tag over the bare upstream tag: it already contains the
# upstream release plus the Firehose changes for its API, so one merge compiles.
#
# What it does for you:
# - bumps our workspace and docs version lines to the ref's first, in their own commit, so those
#   lines never conflict;
# - runs the merge with rerere off (rerere silently replays old resolutions into fork fixes);
# - takes the ref's whole file for generated files (Cargo.lock, CLI reference pages) and
#   regenerates them in `finish`, so you never hand-merge them;
# - refuses to finish while any conflict marker is left in a tracked file.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The generated CLI reference. `finish` rebuilds it from the merged binary.
CLI_DOCS=docs/vocs/docs/pages/cli
# Release features without `jit`, which needs LLVM. CI builds the full default set.
RETH_FEATURES="jemalloc,otlp,otlp-logs,js-tracer,keccak-cache-global,asm-keccak,gmp,min-trace-logs,portable"

die() { echo "error: $*" >&2; exit 1; }

markers() {
  # Every tracked file, not only the conflicted ones: a marker can survive in a file that git
  # already considers resolved.
  git grep -n -I -E '^(<<<<<<< |>>>>>>> |\|\|\|\|\|\|\| [0-9a-f]+$|=======$)' -- . ':!*.md' || true
}

version_of() { git show "$1:Cargo.toml" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1; }

start() {
  local ref=$1
  git rev-parse --verify -q "$ref^{commit}" >/dev/null || die "unknown ref $ref (fetch it first)"
  [ -z "$(git status --porcelain --untracked-files=no)" ] || die "the working tree is not clean"
  [ ! -f "$(git rev-parse --git-path MERGE_HEAD)" ] || die "a merge is already in progress"

  local ours theirs
  ours=$(version_of HEAD)
  theirs=$(version_of "$ref")
  [ -n "$theirs" ] || die "no workspace version in $ref:Cargo.toml"

  if [ "$ours" != "$theirs" ]; then
    # Exactly one line in each file. Fail loudly if the layout ever changes.
    [ "$(grep -c "^version = \"$ours\"$" Cargo.toml)" = 1 ] || die "Cargo.toml: expected one version line"
    [ "$(grep -c "text: 'v$ours'," docs/vocs/vocs.config.ts)" = 1 ] || die "vocs.config.ts: expected one version line"
    sed -i.bak "s/^version = \"$ours\"$/version = \"$theirs\"/" Cargo.toml
    sed -i.bak "s/text: 'v$ours',/text: 'v$theirs',/" docs/vocs/vocs.config.ts
    rm -f Cargo.toml.bak docs/vocs/vocs.config.ts.bak
    git commit -q -m "chore: bump version to $theirs before merging $ref" -- Cargo.toml docs/vocs/vocs.config.ts
    echo "bumped $ours -> $theirs"
  fi

  set +e
  git -c rerere.enabled=false merge --no-ff --no-commit "$ref"
  set -e

  # Generated files: take the ref's whole file. `finish` regenerates them for this tree.
  local f
  for f in $(git diff --name-only --diff-filter=U); do
    case "$f" in
      Cargo.lock|"$CLI_DOCS"/*)
        git checkout --theirs -- "$f" && git add -- "$f" && echo "took $ref's $f (regenerated in finish)" ;;
    esac
  done

  local left
  left=$(git diff --name-only --diff-filter=U)
  if [ -n "$left" ]; then
    echo
    echo "Resolve these by hand, then 'git add' them and run: $0 finish"
    echo "$left" | sed 's/^/  /'
    echo
    echo "Check each one for meaning, not only markers: a clean 'keep both sides' can still drop a fork fix."
  else
    echo "No hand conflicts. Run: $0 finish"
  fi
}

finish() {
  [ -f "$(git rev-parse --git-path MERGE_HEAD)" ] || die "no merge in progress"
  [ -z "$(git diff --name-only --diff-filter=U)" ] || die "unresolved files remain: $(git diff --name-only --diff-filter=U | tr '\n' ' ')"
  local m
  m=$(markers)
  [ -z "$m" ] || die "conflict markers left:
$m"

  echo "regenerating Cargo.lock"
  cargo metadata --format-version 1 >/dev/null
  if grep -q '^\[\[patch.unused\]\]' Cargo.lock; then
    die "Cargo.lock lists an unused [patch]: a patched crate no longer matches its version"
  fi

  echo "building reth for the CLI docs"
  cargo build --locked --bin reth --no-default-features --features "$RETH_FEATURES"
  local bin
  bin="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/reth"
  # Twice: the second run must change nothing, which is what the book CI job checks.
  ./docs/cli/update.sh "$bin" >/dev/null
  ./docs/cli/update.sh "$bin" >/dev/null

  echo "checking the workspace (reth and reth-bb build above; their default jit needs LLVM)"
  cargo check --locked --workspace --all-targets --exclude reth --exclude reth-bb --exclude ef-test-runner

  m=$(markers)
  [ -z "$m" ] || die "conflict markers left:
$m"

  git add -A -- Cargo.lock "$CLI_DOCS"
  local ref
  ref=$(git name-rev --name-only --tags "$(cat "$(git rev-parse --git-path MERGE_HEAD)")" 2>/dev/null || true)
  echo
  echo "Ready. Review 'git diff --cached --stat', then commit, for example:"
  echo "  git -c rerere.enabled=false commit -m \"Merge ${ref:-<ref>} into the PulseChain fork\""
  echo "and list each hand resolution in the message body."
}

case "${1:-}" in
  start) [ $# -eq 2 ] || die "usage: $0 start <ref>"; start "$2" ;;
  finish) finish ;;
  *) die "usage: $0 start <ref> | finish" ;;
esac
