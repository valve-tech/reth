#!/usr/bin/env bash
#
# Hardening for a PulseChain testnet v4 reth RPC node. Safe to re-run.
#
# Applies:
#   - UFW: allow SSH(22), reth P2P(30303 tcp+udp), lighthouse P2P(9300 tcp+udp),
#          reth RPC(8545/8546/9001) from anywhere (this box is a public RPC),
#          deny everything else
#   - SSH: disable password auth, disable root login via password,
#          keep pubkey auth on, move SSH to key-only
#   - unattended-upgrades: enable automatic security patches
#   - fail2ban: protect SSH
#
# Usage (run on the server as root):
#   bash /path/to/harden.sh

set -euo pipefail

# ---- UFW ---------------------------------------------------------------------
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow 22/tcp comment 'SSH'

# reth P2P
ufw allow 30303/tcp comment 'reth P2P'
ufw allow 30303/udp comment 'reth discv5'

# lighthouse P2P
ufw allow 9300/tcp comment 'lighthouse P2P'
ufw allow 9300/udp comment 'lighthouse discv5'

# Public RPC (this is the testnet RPC box, so HTTP/WS/metrics are exposed)
ufw allow 8545/tcp comment 'reth HTTP RPC'
ufw allow 8546/tcp comment 'reth WS RPC'
ufw allow 9001/tcp comment 'reth metrics (Prometheus)'

ufw --force enable

# ---- SSH hardening -----------------------------------------------------------
# Make sure pubkey auth stays on, password auth goes off, root can only log in with keys
sshd_config=/etc/ssh/sshd_config
# Use sed -i.bak to keep a backup
sed -i.bak \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' \
    -e 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' \
    -e 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' \
    "${sshd_config}"

# Validate before reloading
sshd -t

systemctl reload ssh

# ---- unattended-upgrades -----------------------------------------------------
apt-get install -y -qq unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

# ---- fail2ban ----------------------------------------------------------------
# Debian 12 uses systemd-journald (no /var/log/auth.log), so fail2ban must use
# the systemd backend. Requires python3-systemd.
apt-get install -y -qq fail2ban python3-systemd

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
backend = systemd

[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

echo "hardening complete."
ufw status verbose
