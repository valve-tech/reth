#!/usr/bin/env bash
# Prints a fresh finalized checkpoint for the PulseChain network table
# (crates/pulsechain/hardforks/src/network.rs) from one beacon source, checks it against a second,
# independent source, and builds its light-client bootstrap.
#
# Usage: checkpoint-root.sh [-o <bootstrap.json>] <beacon-url> [<check-url>]
#        checkpoint-root.sh [-o <bootstrap.json>] - [-] < url-file
#                       (each - reads one URL from a line of stdin, keeps it out of `ps`)
#
# <beacon-url> must serve the finalized state (Checkpointz does). <check-url> must serve
# /eth/v1/beacon/headers/{root} (a beacon node does; Checkpointz does not): the script fails unless
# it has the same genesis and calls the root finalized and canonical, with the same header. With
# -o the check is required: a pin is the trust root of every new node, so one server must not
# decide it.
#
# A URL may hold a key, so the script never prints one, and it hands each to curl on stdin, not
# on curl's command line. Errors name the endpoint only. A beacon answer reaches the curl config,
# bash arithmetic and the terminal, so the script checks the shape of each value it reads and stops
# at the first bad one. checkpoint-root-test.sh runs it against hostile answers.
#
# The script reads the finalized root, the block (/eth/v2/beacon/blocks/{root}) and the finalized
# state (/eth/v2/debug/beacon/states/finalized, SSZ, about 19 MB). checkpoint-bootstrap.py then
# hashes the state, the block body and the header, checks that they give the block's state root,
# the state's body root and the finalized root, and builds the bootstrap at the root. With -o it
# writes the bootstrap there: a release ships it as
# crates/pulsechain/light-client/checkpoints/<chain>.json.
# Needs curl, jq and python3.
set -euo pipefail

out=
if [[ ${1:-} == -o ]]; then
  [[ $# -ge 2 ]] || { echo "-o needs a file" >&2; exit 2; }
  out=$2
  shift 2
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 [-o <bootstrap.json>] <beacon-url> [<check-url>]   (- reads a URL from stdin)" >&2
  exit 2
fi
if [[ -n $out && $# -ne 2 ]]; then
  echo "-o needs a <check-url>: a shipped pin must be checked against a second source" >&2
  exit 2
fi
# url_arg <arg>: the URL itself, or a line of stdin for -.
url_arg() {
  local url
  if [[ $1 == - ]]; then
    IFS= read -r url || { echo "stdin has no URL line" >&2; exit 2; }
  else
    url=$1
  fi
  url=${url%/}
  if [[ $url == *[[:cntrl:]]* ]]; then
    echo "a beacon URL must not hold a control character (CR, LF, tab or other)" >&2
    exit 2
  fi
  case $url in
    http://* | https://*) ;;
    *) echo "a beacon URL must start with http:// or https://" >&2; exit 2 ;;
  esac
  printf '%s' "$url"
}
base=$(url_arg "$1")
check=
if [[ $# -eq 2 ]]; then
  check=$(url_arg "$2")
fi

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# get <path> <out-file> [accept] [source]: GET source+path (default base) into out-file. Fails
# quietly on an HTTP error. Checkpointz sometimes resets the 19 MB state stream (curl exit 92),
# so every error is tried twice more.
get() {
  local url=${4:-$base}$1 accept=${3:-application/json}
  url=${url//\\/\\\\}
  url=${url//\"/\\\"}
  printf 'url = "%s"\nheader = "Accept: %s"\n' "$url" "$accept" |
    curl -sf --retry 2 --retry-all-errors --max-time 120 -K - -o "$2"
}
need() {
  get "$@" || { echo "the beacon source did not answer $1" >&2; exit 1; }
}
# need_hash <source> <name> <value>: stops unless value is a lowercase 0x 32-byte hex hash.
# The error never prints the value: it can hold a terminal escape.
need_hash() {
  [[ $3 =~ ^0x[0123456789abcdef]{64}$ ]] ||
    { echo "the $1 source gave a $2 that is not a 32-byte hex hash: do not pin it" >&2; exit 1; }
}
# need_number <source> <name> <value>: stops unless value is a decimal number with no leading zero.
need_number() {
  [[ $3 =~ ^(0|[123456789][0123456789]*)$ ]] ||
    { echo "the $1 source gave a $2 that is not a decimal number: do not pin it" >&2; exit 1; }
}

need /eth/v1/beacon/genesis "$work/genesis.json"
gvr=$(jq -r .data.genesis_validators_root "$work/genesis.json")
genesis_time=$(jq -r .data.genesis_time "$work/genesis.json")
need_hash beacon genesis_validators_root "$gvr"
need_number beacon genesis_time "$genesis_time"
case $gvr in
  0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90) chain=369 ;;
  0xd81664ba97279a6fa0832041b4aee6009172b4750a99467ff670a9faf3a34e64) chain=943 ;;
  *) echo "genesis_validators_root $gvr is not a PulseChain network" >&2; exit 1 ;;
esac

need /eth/v1/beacon/blocks/finalized/root "$work/root.json"
root=$(jq -r .data.root "$work/root.json")
root=0x${root#0x}
need_hash beacon "finalized root" "$root"

need "/eth/v2/beacon/blocks/$root" "$work/block.json"
slot=$(jq -r .data.message.slot "$work/block.json")
proposer=$(jq -r .data.message.proposer_index "$work/block.json")
parent=$(jq -r .data.message.parent_root "$work/block.json")
state_root=$(jq -r .data.message.state_root "$work/block.json")
need_number beacon "block slot" "$slot"
need_number beacon "block proposer_index" "$proposer"
need_hash beacon "block parent_root" "$parent"
need_hash beacon "block state_root" "$state_root"

need /eth/v2/debug/beacon/states/finalized "$work/state.ssz" application/octet-stream
# BeaconState: genesis_time (8), genesis_validators_root (32), slot (8), fork (16), then
# latest_block_header (slot 8, proposer 8, parent 32, state 32, body 32).
read -r state_slot header_slot body_root < <(python3 -I -c '
import sys
s = open(sys.argv[1], "rb").read(176)
u = lambda b: int.from_bytes(b, "little")
print(u(s[40:48]), u(s[64:72]), "0x" + s[144:176].hex())
' "$work/state.ssz")
need_hash beacon "state body_root" "$body_root"
if [[ $header_slot != "$slot" ]]; then
  echo "finality moved between two requests (block slot $slot, state header slot" \
    "$header_slot, state slot $state_slot): run the script again" >&2
  exit 1
fi

# Checks the state, the body and the header against the root, and builds the bootstrap.
python3 -I "$here/checkpoint-bootstrap.py" "$root" "$work/block.json" "$work/state.ssz" \
  "$work/bootstrap.json" >/dev/null || {
  echo "the source's block and state do not prove $root: do not pin it" >&2
  exit 1
}
checked="not checked against a second source"
if [[ -n $check ]]; then
  get /eth/v1/beacon/genesis "$work/check-genesis.json" application/json "$check" ||
    { echo "the check source did not answer /eth/v1/beacon/genesis" >&2; exit 1; }
  check_gvr=$(jq -r .data.genesis_validators_root "$work/check-genesis.json")
  need_hash check genesis_validators_root "$check_gvr"
  if [[ $check_gvr != "$gvr" ]]; then
    echo "the check source is on another chain (genesis_validators_root $check_gvr)" >&2
    exit 1
  fi
  get "/eth/v1/beacon/headers/$root" "$work/check-header.json" application/json "$check" ||
    { echo "the check source did not answer /eth/v1/beacon/headers/{root}" >&2; exit 1; }
  got=$(jq -r '[.finalized, .data.canonical, .data.root, .data.header.message.slot,
    .data.header.message.proposer_index, .data.header.message.parent_root,
    .data.header.message.state_root, .data.header.message.body_root] | map(tostring) | join(" ")' \
    "$work/check-header.json")
  want="true true $root $slot $proposer $parent $state_root $body_root"
  if [[ $got != "$want" ]]; then
    got=${got//[[:cntrl:]]/?}
    echo "the check source does not agree on $root (finalized, canonical, root, slot, proposer," \
      "parent, state and body roots): $got: do not pin it" >&2
    exit 1
  fi
  checked="the check source calls it finalized and canonical, with the same header"
fi

kept="no -o: the bootstrap is not kept"
if [[ -n $out ]]; then
  cp "$work/bootstrap.json" "$out"
  kept="the bootstrap is written to $out"
fi

taken=$(date -u +%Y-%m-%d)
block_time=$((genesis_time + slot * 10))
age=$(($(date -u +%s) - block_time))
cat <<OUT
chain $chain: finalized root $root at slot $slot (epoch $((slot / 32)), ${age}s old)
the state, the body and the header hash to the root; $checked; $kept

        checkpoint: Some(BeaconCheckpoint {
            root: b256!("$root"),
            slot: $(printf "%'d" "$slot" 2>/dev/null | tr , _ || echo "$slot"),
            taken: "$taken",
        }),

header fields for the_369_checkpoint_is_the_root_of_its_header:
  slot $slot, proposer_index $proposer
  parent_root $parent
  state_root $state_root
  body_root $body_root
OUT
