# valve-tech/reth audit scope

## Audit target

| Item | Value |
|---|---|
| Repository | https://github.com/valve-tech/reth |
| Tag | `audit-2026-10` (annotated) |
| Release | `v2.7.0.13-pulse` (GitHub release published 2026-10-12) |
| Commit | The commit the tag points at. Resolve it with `git rev-parse audit-2026-10^{commit}`, or read it from the audit handoff. |

`audit-2026-10` is the audit tag, and the commit it names is the one under audit. Changes merged to `main` after that commit are not part of the audit unless the handoff says so. The release tag is listed for reference. Take the commit under audit from the audit tag, not from the release tag.

## Upstream bases

| Upstream | Ref | Commit |
|---|---|---|
| paradigmxyz/reth | `v2.7.0` | `3d592ece6de8c4559987416a544fc215fd6d6921` |
| streamingfast/reth (Firehose) | `reth-v2.7.0-fh3.1-2` | `b50b591c3953e24758ea901a8e77f0e00406189e` |
| firehose-tracer (crates.io) | `=5.5.0` | pinned in `Cargo.toml` |

`alloy-evm` resolves to the valve-tech/evm fork through a `[patch]` in `Cargo.toml`. That fork carries the inspector patch for system calls. `crates/firehose-tests/tests/setup_guards.rs` checks for it.

## Size of the valve-only delta

```
git diff --shortstat v2.7.0 audit-2026-10
  328 files changed, 58770 insertions(+), 639 deletions(-)
git diff --shortstat reth-v2.7.0-fh3.1-2 audit-2026-10
  267 files changed, 45690 insertions(+), 727 deletions(-)
```

The 375 commits reachable from the audit tag are in neither upstream ref. Run `git log audit-2026-10 ^v2.7.0 ^reth-v2.7.0-fh3.1-2`. Some of these are upstream paradigm `main` commits that were merged after v2.7.0.

### Paths added or modified vs paradigm v2.7.0 (`git diff --numstat`, grouped)

| Path | Files | + | - | vs SF fh3.1-2 (+/-) |
|---|---|---|---|---|
| crates/net/msgboard (new) | 19 | 17557 | 0 | 17557 / 0 |
| crates/firehose/src (new) | 24 | 10823 | 0 | 2364 / 26 |
| crates/pulsechain/node (new) | 16 | 3711 | 0 | 3711 / 0 |
| crates/net/msgboard-types (new) | 10 | 2917 | 0 | 2917 / 0 |
| crates/firehose-tests (new) | 26 | 3342 | 0 | 645 / 0 (tests) |
| crates/cli/commands | 6 | 2189 | 144 | 2189 / 144 |
| crates/rpc/rpc | 9 | 1468 | 58 | 1468 / 78 |
| crates/engine/tree | 13 | 1287 | 103 | 787 / 126 |
| crates/pulsechain/hardforks (new) | 8 | 783 | 0 | 783 / 0 |
| bin | 7 | 702 | 9 | 647 / 42 |
| crates/storage/provider | 6 | 601 | 11 | 601 / 11 |
| crates/rpc/rpc-builder | 5 | 570 | 39 | 570 / 39 |
| crates/rpc/rpc-eth-types | 5 | 435 | 0 | 435 / 0 |
| crates/ethereum/node | 3 | 341 | 0 | 341 / 0 |
| crates/rpc/rpc-api | 4 | 260 | 12 | 260 / 12 |
| crates/trie/parallel | 2 | 227 | 10 | 227 / 10 |
| crates/net/network | 2 | 142 | 8 | 142 / 8 |
| crates/rpc/rpc-eth-api | 5 | 98 | 18 | |
| crates/storage/storage-api | 3 | 77 | 3 | |
| crates/stages/stages, crates/stages/api | 3 | 117 | 30 | |
| crates/ethereum/consensus | 1 | 28 | 6 | |
| crates/storage/libmdbx-rs | 1 | 20 | 0 | |
| crates/node/builder, crates/node/core | 4 | 23 | 12 | |
| crates/evm/evm, crates/chainspec | 2 | 23 | 0 | |
| Cargo.toml / Cargo.lock | 2 | 291 | 4 | |
| docs, specs, scripts, deploy, CI, notes | — | — | — | non-code |

Regenerate the table with:
`git diff --numstat v2.7.0 audit-2026-10` and `git diff --numstat reth-v2.7.0-fh3.1-2 audit-2026-10`.

## Areas to focus on

### Message board (PulseChain msgboard, `msg/1` devp2p subprotocol)
- `crates/net/msgboard-types`: wire format, message ids and hashing, and proof-of-work (`pow.rs`, spec in `specs/04-msgboard-pow-v2.md`).
- `crates/net/msgboard`: devp2p protocol handler (`protocol.rs`), board state, eviction, peer strikes (`board.rs`, `pending.rs`), persistence (`db.rs`, `index.rs`), block-range filtering (`block_filter.rs`), and RPC (`rpc.rs`, `rpc_api.rs`; `msgboard_content`, `msgboard_contentPage`). The RPC is described in `docs/msgboard-rpc.md`.
- Limits (`crates/net/msgboard/src/args.rs`):
  - `--msgboard.size-limit`: default 8192, capped at `MAX_SAFE_SIZE_LIMIT` in `protocol.rs`.
  - `--msgboard.count-limit`: default 10000.
  - `--msgboard.block-range`: default 120.
  - `--msgboard.stale-block-buffer`: default 3.
  - `--msgboard.work-multiplier`: default 10000.
  - `--msgboard.work-divisor`: default 1000000.
  - The ingress byte budget follows `size_limit`.
  - Concurrent `msgboard_content` builds are bounded.
- Keyset paging for `msgboard_content` and txpool RPC (`crates/rpc/*`).

### PulseChain chain support
- `crates/pulsechain/hardforks`: chainspecs for PulseChain mainnet (369) and testnet v4 (943), plus bootnodes.
- `crates/pulsechain/node`: consensus, EVM config, gas rules, pool, network (ENR fork-ID check skipped only on PulseChain), and launch.
- `crates/firehose/src/primordial_pulse.rs`: PrimordialPulse fork-block state transition.

### Firehose integration
- `crates/firehose/src`:
  - Executor (`executor.rs`): traced and untraced paths.
  - Block tracer and inspector (`block_tracer.rs`, `inspector*`).
  - Mapper (`mapper.rs`) and finality (`finality.rs`).
  - Health publisher (`health.rs`).
  - ExEx-based runner (`runner.rs`) and initialisation (`init.rs`).
- Block access list (BAL) handling for Amsterdam blocks:
  - BAL rebuild on staged-sync and engine paths.
  - Sidecar hash check.
  - BAL hash emission.
  - Related changes are in `crates/engine/tree` and `crates/stages`.
- CLI flags and node wiring are in `bin/` and `crates/cli/commands`.

### RPC changes
- The `--rpc.max-response-size` default is raised to 200 MiB (`crates/node/core`, `crates/rpc/rpc-builder`).
- Parity trace output omits absent `transactionHash` / `transactionPosition`.
- The RPC blocking task model was changed, and cancelled blocking IO tasks are stopped.
- In-flight call metrics were changed.
- Otterscan search behaviour was changed.

### CLI / storage
- `reth db scan-empty-hashed-accounts`, including storage v2 mode (`crates/cli/commands`).
- Provider changes in `crates/storage/provider`.

## Prior internal reviews and notes
- `docs/msgboard-security-review.md`: internal pre-audit security review of msgboard, with findings and how each was fixed.
- `docs/msgboard-parity-gaps.md`: parity analysis against the erigon-pulse msgboard.
- `docs/msgboard-spec-feedback.md` and `docs/msgboard-rpc.md`.
- `PULSE-PARITY-AUDIT.md`: PulseChain parity checklist.
- `specs/`: PulseChain support and msgboard PoW v2 specs.

## Build and test

```
git clone https://github.com/valve-tech/reth && cd reth && git checkout audit-2026-10
cargo build --release --bin reth
cargo fmt --check
cargo clippy --no-deps -p reth-msgboard -p reth-msgboard-types -p reth-firehose -p reth-pulsechain-node -p reth-pulsechain-forks
cargo nextest run --no-fail-fast \
  -p reth-firehose -p reth-firehose-tests -p reth-msgboard -p reth-msgboard-types \
  -p reth-pulsechain-node -p reth-pulsechain-forks -p reth-cli-commands
```

CI definitions are in `.github/workflows/valve-ci.yml` and `valve-release.yml`. The release binaries are built for glibc 2.36.

## Out of scope
- Upstream paradigmxyz/reth code that is unchanged from `v2.7.0`.
- StreamingFast Firehose code that is unchanged from `reth-v2.7.0-fh3.1-2`, except where valve code changes it (see the second LOC column).
- Third-party dependencies, including `firehose-tracer` 5.5.0. The valve-tech/evm (`alloy-evm`) fork is out of scope unless agreed separately.
- Docs and CI configuration. These can be reviewed for information only.
