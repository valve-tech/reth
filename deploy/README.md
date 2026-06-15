# Deploy — PulseChain reth + lighthouse-pulse

Reusable configs and scripts for standing up PulseChain reth (extension-model) nodes on fresh Hetzner servers.

## Layout

- `testnet/installimage.conf` — Hetzner installimage config for the testnet v4 RPC node (Ryzen 7 7700, 4×1TB NVMe, RAID 0).
- (more files added as deploy automation grows)

## Usage — OS install (from Hetzner rescue system)

```bash
scp deploy/testnet/installimage.conf root@<ip>:/tmp/installimage.conf
ssh root@<ip> "installimage -a -c /tmp/installimage.conf"
ssh root@<ip> reboot
```

The server comes back up with a fresh Debian 12 on RAID 0, partitions laid out, and the rescue system's `/root/.ssh/authorized_keys` preserved into the installed system.

## Post-install steps

After OS install, follow the setup sequence (toolchain, build, systemd, hardening). See ops runbook for details — this is tracked in the `extension-model` branch deploy work.
