#!/usr/bin/env bash
# Finds references that a public reader of this repository cannot open: the names of private
# projects and home-directory paths. The match ignores case. `/home/linuxbrew` and the GitHub
# Actions home `/home/runner` are public paths, so the scan allows them.
#
# Usage:
#   private-scan.sh
#       Scans the files that git tracks, as they are in the work tree, and their names.
#   private-scan.sh <rev> [<public>...]
#       Scans the tree of <rev> and the tag message when <rev> is an annotated tag. Then it scans
#       each commit that <rev> reaches and no <public> reaches: its message, author, committer,
#       file names and changes. A push of <rev> publishes all of them.
#
# A <public> is a ref or a `git rev-list` option, such as `--remotes=github`, `--tags` or
# `--exclude=<glob>`, that names history that is already public. With no <public>, the scan reads
# every commit that <rev> reaches. Before you push a tag to GitHub, run:
#   git fetch github && crates/pulsechain/lite/scripts/private-scan.sh <tag> --remotes=github
#
# Exit status: 0 when nothing is found, 1 when the scan prints a hit, 2 on an error.
set -Eeuo pipefail

# Split, so that this file does not match itself. Lower case: the match folds case.
re="jump""gate|pulse""lite|lite""check|lite node ""contract|/use""rs/[a-z0-9]|/ho""me/[a-z]"
# The public paths, removed from a lower-case line before the match.
allowed='/home/(linuxbrew|runner)([^a-z0-9_.-]|$)'

# Prints each input line that holds a reference, with `$1` in front of it.
hits() {
  RE=$re OK=$allowed awk -v tag="$1" '
    { s = tolower($0); gsub(ENVIRON["OK"], "", s); if (s ~ ENVIRON["RE"]) print tag $0 }'
}

# Like `hits`, for `git log` output in which a line `\001<sha>` starts each commit. A diff line
# is checked only when it is added or removed.
commit_hits() {
  RE=$re OK=$allowed awk -v diff="$1" '
    /^\001/ { c = substr($0, 2, 12); f = ""; next }
    diff && /^diff --git / { f = $0; sub(/^diff --git a\//, "", f); sub(/ b\/.*/, "", f); next }
    diff && (/^\+\+\+ / || /^--- /) { next }
    diff && !/^[-+]/ { next }
    {
      s = tolower($0); gsub(ENVIRON["OK"], "", s)
      if (s ~ ENVIRON["RE"]) print "commit " c (f == "" ? "" : " " f) ": " $0
    }'
}

# `git grep` exits 1 when nothing matches.
grep_tree() {
  local status=0
  git grep -nIiE -e "$re" "$@" -- ':(top)' || status=$?
  [[ $status -le 1 ]] || exit 2
}

# `git grep` skips a blob it cannot read and exits 1, as if nothing matched. So check first that
# git can read each blob of the tree of `$1`.
readable() {
  git ls-tree -r "$1" | awk '$2 == "blob" { print $3 }' |
    git cat-file --batch-check='%(objecttype)' | awk '$0 != "blob" { bad = 1 } END { exit bad }' ||
    { echo "private-scan: git cannot read every file of $1" >&2; exit 2; }
}

# Any failure, here or in a scan below, exits 2. `-E` keeps the trap in functions, and the scan
# writes to a file: in a `$(...)` bash turns errexit off, so a failed step would go unseen.
trap 'exit 2' ERR
top=$(git rev-parse --show-toplevel)
cd "$top"

scan() {
  if [[ $# -eq 0 ]]; then
    grep_tree | hits ""
    git ls-files | hits "file name: "
    return
  fi
  local rev=$1
  shift
  git rev-parse --verify --quiet "$rev^{commit}" >/dev/null ||
    { echo "private-scan: $rev is not a commit" >&2; exit 2; }
  readable "$rev"
  grep_tree "$rev" | hits ""
  git ls-tree -r --name-only "$rev" | hits "file name: "
  local kind
  kind=$(git cat-file -t "$rev")
  if [[ $kind == tag ]]; then
    git cat-file tag "$rev" | hits "tag $rev: "
  fi
  git log --format=$'\001%H%n%an <%ae>%n%cn <%ce>%n%B' "$rev" --not "$@" | commit_hits 0
  git log -m --name-only --format=$'\001%H' "$rev" --not "$@" | commit_hits 0
  git log -m -p --no-color --no-ext-diff -i -G"$re" --format=$'\001%H' "$rev" --not "$@" |
    commit_hits 1
}

found=$(mktemp)
trap 'rm -f "$found"' EXIT
scan "$@" >"$found"
if [[ -s $found ]]; then
  cat "$found"
  exit 1
fi
