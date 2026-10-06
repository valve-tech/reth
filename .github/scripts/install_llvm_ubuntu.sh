#!/usr/bin/env bash
set -eo pipefail

v=${1:-22}
bins=(clang llvm-config lld ld.lld FileCheck)

apt-get update -qq
apt-get install -y --no-install-recommends \
    lsb-release wget gnupg ca-certificates

codename=$(lsb_release -cs)

# Configure the apt.llvm.org repository directly instead of running its `llvm.sh`
# installer. That script is fetched unpinned at build time and gates on a distro
# allow-list of its own, so it rejects Debian releases the repository itself
# already carries: on trixie it exits with "Distribution 'debian' in version '13
# (trixie)' is not supported by this script" even though
# apt.llvm.org/trixie/llvm-toolchain-trixie-$v exists.
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key |
    gpg --dearmor -o /usr/share/keyrings/apt-llvm-org.gpg
echo "deb [signed-by=/usr/share/keyrings/apt-llvm-org.gpg] http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${v} main" \
    >/etc/apt/sources.list.d/apt-llvm-org.list

# `llvm-sys` (via `revmc-llvm`) links against llvm-config, the LLVM headers and
# Polly; the rest is the toolchain the build and the `bins` symlinks below need.
apt-get update -qq
apt-get install -y --no-install-recommends \
    "clang-$v" "lld-$v" "llvm-$v" "llvm-$v-dev" "llvm-$v-tools" \
    "libpolly-$v-dev" "libclang-$v-dev" "libclang-rt-$v-dev"

for bin in "${bins[@]}"; do
    if ! command -v "$bin-$v" &>/dev/null; then
        echo "Warning: $bin-$v not found" 1>&2
        continue
    fi
    ln -fs "$(which "$bin-$v")" "/usr/bin/$bin"
done

echo "LLVM $v installed:"
llvm-config --version
