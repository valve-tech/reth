#!/usr/bin/env bash
# Tests checkpoint-root.sh against hostile beacon answers and URLs, with no network.
#
# Usage: checkpoint-root-test.sh
#
# A fake curl on PATH reads the -K config from stdin, logs each config and serves fixture files.
# It logs INJECTED when a config holds a line that is not the url or the Accept header. A fake
# python3 passes the bootstrap proof (checkpoint-bootstrap.py) without a real state, so the cases
# reach the check source; it runs the real python3 for everything else. Needs jq and python3.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/checkpoint-root.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

real_python=$(command -v python3)
mkdir "$tmp/bin"
cat >"$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
out=
while [[ $# -gt 0 ]]; do
  case $1 in
    -o) out=$2; shift 2 ;;
    *) shift ;;
  esac
done
config=$(cat)
url=
while IFS= read -r line; do
  case $line in
    'url = "'*'"') url=${line#'url = "'}; url=${url%'"'} ;;
    'header = "'*'"') ;;
    *) echo INJECTED >>"$CASE/log" ;;
  esac
done <<<"$config"
rest=${url#http://}
host=${rest%%/*}
path=/${rest#*/}
echo "GET $host $path" >>"$CASE/log"
file="$CASE/fixtures/$host${path//\//_}"
[[ -f $file ]] || exit 22
cp "$file" "$out"
CURL
cat >"$tmp/bin/python3" <<PYTHON
#!/usr/bin/env bash
if [[ \${2:-} == */checkpoint-bootstrap.py ]]; then
  echo '{}' >"\$6"
  exit 0
fi
exec "$real_python" "\$@"
PYTHON
chmod +x "$tmp/bin/curl" "$tmp/bin/python3"

gvr=0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90
root=0x$(printf '1%.0s' {1..64})
parent=0x$(printf '2%.0s' {1..64})
state_root=0x$(printf '3%.0s' {1..64})
body_root=0x$(printf '4%.0s' {1..64})
slot=1000

# A fixture set where every answer is good and the check source agrees.
good="$tmp/good"
mkdir -p "$good"
for host in beacon.test check.test; do
  jq -n --arg gvr "$gvr" '{data: {genesis_validators_root: $gvr, genesis_time: "1683785555"}}' \
    >"$good/${host}_eth_v1_beacon_genesis"
done
jq -n --arg root "$root" '{data: {root: $root}}' \
  >"$good/beacon.test_eth_v1_beacon_blocks_finalized_root"
jq -n --arg slot "$slot" --arg parent "$parent" --arg state "$state_root" \
  '{data: {message:
    {slot: $slot, proposer_index: "7", parent_root: $parent, state_root: $state}}}' \
  >"$good/beacon.test_eth_v2_beacon_blocks_$root"
python3 -I -c '
import sys
slot, body = int(sys.argv[1]), bytes.fromhex(sys.argv[2][2:])
s = bytearray(176)
s[40:48] = slot.to_bytes(8, "little")
s[64:72] = slot.to_bytes(8, "little")
s[144:176] = body
open(sys.argv[3], "wb").write(s)
' "$slot" "$body_root" "$good/beacon.test_eth_v2_debug_beacon_states_finalized"
jq -n --arg root "$root" --arg slot "$slot" --arg parent "$parent" --arg state "$state_root" \
  --arg body "$body_root" '{finalized: true, data: {root: $root, canonical: true, header: {message:
    {slot: $slot, proposer_index: "7", parent_root: $parent, state_root: $state,
      body_root: $body}}}}' \
  >"$good/check.test_eth_v1_beacon_headers_$root"

failed=0
fail() {
  echo "FAIL $name: $*" >&2
  failed=1
}

# start <name>: a new case with the good fixtures.
start() {
  name=$1
  case_dir="$tmp/case-$name"
  mkdir -p "$case_dir"
  cp -R "$good" "$case_dir/fixtures"
  : >"$case_dir/log"
}

# edit <fixture> <jq filter> [jq args]: change one fixture of the case.
edit() {
  local file="$case_dir/fixtures/$1" filter=$2
  shift 2
  jq "$@" "$filter" "$file" >"$file.new"
  mv "$file.new" "$file"
}

# run <expected status> <stdin> <args>: runs the script and checks what every case must hold.
run() {
  local want=$1 input=$2 status=0
  shift 2
  printf '%s' "$input" | CASE=$case_dir PATH="$tmp/bin:$PATH" \
    "$script" "$@" >"$case_dir/out" 2>&1 || status=$?
  [[ $status == "$want" ]] || fail "exit $status, want $want"
  ! grep -q INJECTED "$case_dir/log" || fail "a beacon answer added a line to the curl config"
  ! grep -q '\.test' "$case_dir/out" || fail "the output names a URL"
  ! LC_ALL=C grep -q $'[\x01-\x08\x0b-\x1f\x7f]' "$case_dir/out" ||
    fail "the output holds a control character"
}

# requests <path>...: the case fetched exactly these paths, in order.
requests() {
  local got want
  got=$(sed -n 's/^GET [^ ]* //p' "$case_dir/log")
  want=$(printf '%s\n' "$@")
  [[ $got == "$want" ]] || fail "fetched [$(echo "$got" | tr '\n' ' ')], want [$*]"
}

beacon=http://beacon.test
check=http://check.test

start good
run 0 "" "$beacon" "$check"
grep -q "finalized root $root at slot $slot" "$case_dir/out" || fail "no checkpoint printed"

start good-stdin
run 0 $'http://beacon.test\nhttp://check.test\n' - -
grep -q "the check source calls it finalized" "$case_dir/out" || fail "the check did not run"

start url-lf
run 2 "" $'http://beacon.test\nurl = "http://other.test"'
requests

start url-cr-stdin
run 2 $'http://beacon.test\r\n' -
requests

start url-esc
run 2 "" "$beacon" $'http://check.test/\e]0;x\a'
requests

start root-injects
edit beacon.test_eth_v1_beacon_blocks_finalized_root ".data.root = \$r" \
  --arg r "0x$(printf 'a%.0s' {1..64})"$'\noutput = "'"$case_dir"'/pwned"'
run 1 "" "$beacon" "$check"
requests /eth/v1/beacon/genesis /eth/v1/beacon/blocks/finalized/root
[[ ! -e $case_dir/pwned ]] || fail "a beacon answer wrote a file"

start root-short
edit beacon.test_eth_v1_beacon_blocks_finalized_root '.data.root = "0x1234"'
run 1 "" "$beacon" "$check"
requests /eth/v1/beacon/genesis /eth/v1/beacon/blocks/finalized/root

start genesis-time-runs-code
# PPID is set, so set -u lets bash expand the subscript, and with it the command.
edit beacon.test_eth_v1_beacon_genesis ".data.genesis_time = \$t" \
  --arg t "PPID[\$(touch $case_dir/pwned)]"
run 1 "" "$beacon" "$check"
requests /eth/v1/beacon/genesis
[[ ! -e $case_dir/pwned ]] || fail "a beacon answer ran a command"

start gvr-escape
edit beacon.test_eth_v1_beacon_genesis '.data.genesis_validators_root = "\u001b]0;x\u0007"'
run 1 "" "$beacon" "$check"
requests /eth/v1/beacon/genesis

for field in slot proposer_index parent_root state_root; do
  start "block-$field"
  edit "beacon.test_eth_v2_beacon_blocks_$root" ".data.message.$field = \$v" --arg v $'1\e[2J'
  run 1 "" "$beacon" "$check"
  requests /eth/v1/beacon/genesis /eth/v1/beacon/blocks/finalized/root "/eth/v2/beacon/blocks/$root"
done

start check-gvr-escape
edit check.test_eth_v1_beacon_genesis '.data.genesis_validators_root = "\u001b]0;x\u0007"'
run 1 "" "$beacon" "$check"

start check-header-escape
edit "check.test_eth_v1_beacon_headers_$root" '.data.header.message.proposer_index = "8\u001b[2J"'
run 1 "" "$beacon" "$check"
grep -q "does not agree" "$case_dir/out" || fail "the disagreement was not reported"

if [[ $failed != 0 ]]; then
  exit 1
fi
echo "checkpoint-root.sh: all cases pass"
