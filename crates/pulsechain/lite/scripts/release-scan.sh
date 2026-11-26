#!/usr/bin/env bash
# The release gate: runs private-scan.sh on what a push of release tag <tag> publishes. History
# counts as public only when a tag with a published GitHub release reaches it. Such a tag passed
# this gate, or it was released before the gate existed. No other ref counts: a branch or a
# second tag in the same push is as new as <tag>, and its history is not public yet.
#
# Usage:
#   release-scan.sh <tag> <released>
#       <released> is a file with one released tag name on each line. The script skips <tag>
#       itself, so a rebuild of a released tag scans the history it added, and it skips a name
#       that is not a tag here.
#
# Exit status: as private-scan.sh.
set -Eeuo pipefail
trap 'exit 2' ERR

[[ $# -eq 2 ]] || { echo "usage: release-scan.sh <tag> <released>" >&2; exit 2; }
tag=$1
public=()
while IFS= read -r name || [[ -n $name ]]; do
  if [[ -n $name && $name != "$tag" ]] && git show-ref --verify --quiet "refs/tags/$name"; then
    public+=("refs/tags/$name")
  fi
done <"$2"
exec "$(dirname "$0")/private-scan.sh" "refs/tags/$tag" ${public[@]+"${public[@]}"}
