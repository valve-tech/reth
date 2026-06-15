#!/usr/bin/env bash
#
# Poll reth's eth_blockNumber and append a line to /var/log/reth-milestones.log
# the first time the current block crosses each configured milestone. Designed
# to be run every few minutes by a systemd timer.
#
# Each milestone is logged exactly once — state is kept in /var/lib/reth-milestones.state.

set -euo pipefail

RPC_URL=${RPC_URL:-http://127.0.0.1:8545}
LOG=${LOG:-/var/log/reth-milestones.log}
STATE=${STATE:-/var/lib/reth-milestones.state}

# Milestones to log (decimal block numbers).
# Testnet v4 PrimordialPulse is 16,492,700 — noted explicitly with fence posts.
MILESTONES=(
  1000000
  5000000
  10000000
  12000000
  14000000
  15000000
  16000000
  16400000
  16490000
  16492699    # last pre-fork block
  16492700    # PrimordialPulse — CHAINID switches 1 -> 943, sacrifice credits applied
  16492701    # first post-fork block executed
  17000000
  18000000
  19000000
  20000000
  21000000
)

log() { echo "$(date -Is) $*" | tee -a "${LOG}" >/dev/null; }

# Fetch current block height (hex -> decimal)
raw=$(curl -sf --max-time 10 -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "${RPC_URL}" || true)

if [[ -z "${raw}" ]]; then
  log "ERROR: could not reach reth RPC at ${RPC_URL}"
  exit 0   # exit 0 so systemd timer keeps retrying without backoff noise
fi

hex=$(echo "${raw}" | sed -n 's/.*"result":"0x\([0-9a-f]*\)".*/\1/p')
if [[ -z "${hex}" ]]; then
  log "ERROR: unexpected RPC response: ${raw}"
  exit 0
fi

block=$((16#${hex}))

# Best-effort peer count (net_peerCount). Failures are non-fatal.
peers_hex=$(curl -sf --max-time 5 -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' \
  "${RPC_URL}" 2>/dev/null | sed -n 's/.*"result":"0x\([0-9a-f]*\)".*/\1/p' || true)
peers="?"
if [[ -n "${peers_hex}" ]]; then
  peers=$((16#${peers_hex}))
fi

# Load already-logged milestones
touch "${STATE}"
declare -A seen
while read -r m; do
  [[ -n "${m}" ]] && seen["${m}"]=1
done < "${STATE}"

# First run — log the baseline so we have a starting reference
if [[ ! -s "${LOG}" ]]; then
  log "INFO: monitor started, current block=${block} peers=${peers}"
fi

# Heartbeat: log current status on every run so tail -f shows progress
log "STATUS: block=${block} peers=${peers}"

# Find unseen milestones we've now crossed
newly_crossed=()
for m in "${MILESTONES[@]}"; do
  if (( block >= m )) && [[ -z "${seen[${m}]:-}" ]]; then
    newly_crossed+=("${m}")
  fi
done

# Log and record them
for m in "${newly_crossed[@]}"; do
  log "MILESTONE: crossed block ${m} (current=${block})"
  echo "${m}" >> "${STATE}"
done
