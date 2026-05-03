#!/usr/bin/env bash
#
# One-shot post-build setup for a PulseChain testnet v4 reth RPC node.
#
# Prerequisites:
#   - Debian 12 installed via deploy/testnet/installimage.conf
#   - /root/reth cloned (extension-model branch), release binary built
#   - /root/lighthouse-pulse cloned, release binary built
#   - /mnt/reth exists as the data mount
#
# Usage (run on the server as root):
#   bash /path/to/setup.sh

set -euo pipefail

DATADIR=/mnt/reth
RETH_BIN=/root/reth/target/release/reth
LH_BIN=/root/lighthouse-pulse/target/release/lighthouse
JWT=${DATADIR}/jwt.hex

# Sanity checks
[[ -x "${RETH_BIN}" ]]  || { echo "reth binary missing at ${RETH_BIN}"; exit 1; }
[[ -x "${LH_BIN}" ]]    || { echo "lighthouse binary missing at ${LH_BIN}"; exit 1; }
[[ -d "${DATADIR}" ]]   || { echo "datadir missing at ${DATADIR}"; exit 1; }

# JWT for Engine API (only generate once)
if [[ ! -f "${JWT}" ]]; then
  openssl rand -hex 32 > "${JWT}"
  chmod 600 "${JWT}"
  echo "generated JWT secret at ${JWT}"
fi

mkdir -p "${DATADIR}/lighthouse"

# Install systemd units (they live next to this script)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -m 644 "${SCRIPT_DIR}/reth.service"       /etc/systemd/system/reth.service
install -m 644 "${SCRIPT_DIR}/lighthouse.service" /etc/systemd/system/lighthouse.service

systemctl daemon-reload
systemctl enable reth.service lighthouse.service

echo "setup complete. start with:"
echo "  systemctl start reth.service"
echo "  systemctl start lighthouse.service"
echo "  journalctl -u reth.service -f"
