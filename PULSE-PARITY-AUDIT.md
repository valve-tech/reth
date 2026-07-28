# PulseChain Parity Audit — `firehose` vs PulseChain v1 squash `228bdae3e`

## Executive summary

- **firehose is at FULL PulseChain parity for mainnet chain 369 and chain 1.** Every functional PulseChain change in the PulseChain v1 squash `228bdae3e` is present in firehose, either byte-identical or as a documented, behavior-preserving relocation.
- **0 MISSING findings. 0 DIVERGENT findings.** Nothing in the squash's consensus/state-root surface is absent or altered in a way that changes chain behavior.
- All consensus-critical data is verified identical: the 3 embedded binaries (deposit-contract bytecode, mainnet + testnet_v4 sacrifice credits) are **byte-identical (sha1 match)**; the 31-slot deposit-contract initial-storage table, the sacrifice-credit decoder, all address/treasury constants, the hardfork schedule, and the PrimordialPulse fork blocks (369 → 17,233,000; 943 → 16,492,700) are byte-identical.
- The only source differences are: (a) PulseChain spec DATA relocated `pulsechain/node/src/fork.rs` → `pulsechain/hardforks/src/primordial_pulse.rs` (re-exported, content-identical) to break a firehose circular dep, and (b) firehose-instrumentation wiring in `bin/reth` + comment-only changes in `pulsechain/node/src/evm.rs`. None touch consensus.
- firehose is behind `pulse/main` by 18 upstream paradigm PRs (separate from baseline parity); one — `4ffde69d9 fix(engine): apply finalized state after syncing FCU head import` — is consensus-adjacent and worth back-porting, but is not a baseline-parity gap.

**As-of:** Fetched fresh from `pulse` and `origin` over SSH on 2026-05-24 (both fetches exit 0).
- `firehose` = `7e821f5ebd63bdc66f891dfbe327c18c27b5bfe4` (== `origin/firehose`)
- `pulse/main` = `228bdae3e2870b3d649c44da34edd0ce47282217` (the squash tip itself)
- Squash analyzed: `228bdae3e` vs parent `228bdae3e~1` (`ddb3819ec`)
- merge-base(firehose, pulse/main) = `88505c7fcbfdebfd3b56d88c86b62e950043c6c4`

---

## Findings by subsystem

Legend: PRESENT = byte-identical at same path · RELOCATED = content-identical, moved/refactored · MISSING · DIVERGENT.

### PulseChain hardforks crate (`crates/pulsechain/hardforks`)

| File | baseline (`228bdae3e`) | firehose | Status |
|---|---|---|---|
| `src/chainspec.rs` | path identical | path identical | **PRESENT** (byte-identical) |
| `src/hardfork.rs` | path identical | path identical | **PRESENT** (byte-identical) |
| `src/lib.rs` | — | adds `pub mod primordial_pulse;` (line 12) | **PRESENT** (only adds the relocated module) |
| `src/primordial_pulse.rs` | n/a — this content lives inline in `node/src/fork.rs` | new file | **RELOCATED** from `node/src/fork.rs` (see below) |
| `Cargo.toml` | path identical | path identical | **PRESENT** (byte-identical; no new deps) |

Fork-block constants confirmed identical: `PRIMORDIAL_PULSE_MAINNET_BLOCK = 17_233_000` (chain 369), `PRIMORDIAL_PULSE_TESTNET_V4_BLOCK = 16_492_700` (chain 943) — `hardfork.rs:11,14` on both sides. `chainspec.rs` Paris TTD activation at `PRIMORDIAL_PULSE_*_BLOCK + 1` and the `chain_id_for(block)` history-replay gating (returns 1 pre-fork, 369/943 at-and-after) are byte-identical.

### PulseChain node crate (`crates/pulsechain/node`)

| File | Status | Notes |
|---|---|---|
| `src/spec.rs` | **PRESENT** (byte-identical) | chain spec / genesis handling |
| `src/consensus.rs` | **PRESENT** (byte-identical) | Shanghai-gap consensus, difficulty/reward rules |
| `src/gas.rs` | **PRESENT** (byte-identical) | gas/fee rules |
| `src/node.rs` | **PRESENT** (byte-identical) | component assembly |
| `src/network.rs` | **PRESENT** (byte-identical) | bootnodes / peering |
| `src/pool.rs` | **PRESENT** (byte-identical) | txpool config |
| `src/cli.rs` | **PRESENT** (byte-identical) | |
| `src/launch.rs` | **PRESENT** (byte-identical) | |
| `src/lib.rs` | **PRESENT** (byte-identical) | |
| `src/fork.rs` | **RELOCATED** | All address constants, embedded-binary `include_bytes!`, the 31-slot `DEPOSIT_CONTRACT_INITIAL_STORAGE` table, and `decode_sacrifice_credits()` moved to `hardforks/src/primordial_pulse.rs` and **re-exported** from this path (firehose `fork.rs:15-21`). Verified content-identical: storage-table `b256!` lines sha1-match, decoder body sha1-match, all 4 address/treasury constants string-match. The `PrimordialPulseStateWriter` trait + `apply_primordial_pulse` signatures are preserved; firehose removed the `TODO(Phase 4)` comments since Phase 4 is now implemented in `evm.rs`. |
| `src/evm.rs` | **PRESENT** (functionally identical) | Diff is **comment-only** (lines 284-304): expanded note explaining firehose emission was moved to `FirehoseWrappedExecutor::finish` to avoid a Mutex deadlock. The `==` fork-block guard, `apply_primordial_pulse` invocation, and all state-mutation code are byte-identical. |
| `tests/{chainspec,evm,fork_transition,rpc_comparison}.rs` | **PRESENT** (byte-identical) | |
| `res/deposit_contract.bin` | **RELOCATED → `hardforks/res/`** | sha1 `b9d0eef1…` on both sides |
| `res/sacrifice_credits_mainnet.bin` | **RELOCATED → `hardforks/res/`** | sha1 `b0e8a2c3…` on both sides |
| `res/sacrifice_credits_testnet_v4.bin` | **RELOCATED → `hardforks/res/`** | sha1 `796f9003…` on both sides |
| `Cargo.toml` | **PRESENT** (byte-identical) | |

### msgboard P2P sub-protocol (`crates/net/msgboard`, `crates/net/msgboard-types`)

All 17 `.rs` source files **PRESENT (byte-identical)**: `config.rs`, `lib.rs`, `msg_id.rs`, `pow.rs`, `protocol.rs` (types); `args.rs`, `block_filter.rs`, `board.rs`, `db.rs`, `index.rs`, `launch.rs`, `metrics.rs`, `protocol.rs`, `rpc.rs`, `rpc_api.rs`, `examples/submit_messages.rs`. Both `Cargo.toml` byte-identical.

### Other crates touched by the squash

All **PRESENT (byte-identical)**: `crates/ethereum/consensus/src/lib.rs`, `crates/net/downloaders/src/headers/reverse_headers.rs`, `crates/net/network/src/{peers,swarm}.rs`, `crates/node/core/build.rs`, `crates/rpc/rpc-eth-api/src/helpers/estimate.rs`, `crates/rpc/rpc-server-types/src/constants.rs`, `crates/stages/api/src/pipeline/mod.rs`, `crates/storage/libmdbx-rs/src/environment.rs`, `crates/storage/storage-api/src/chain.rs`, `crates/transaction-pool/src/validate/eth.rs`.

### `bin/reth` (chain dispatch)

| File | Status | Notes |
|---|---|---|
| `src/main.rs` | **PRESENT + firehose-augmented** | All PulseChain dispatch semantics preserved (CHAINID override, Shanghai-gap consensus, PrimordialPulse, 20% `eth_estimateGas` margin via `install_gas_estimation_margin`, bootnode injection). firehose adds: unconditional tracer init above chain dispatch, swaps `PulsechainFirehoseExecutorBuilder` in for the default executor (wraps `PulsechainEvmConfig` in `FirehoseEvmConfig`), and installs the `firehose` ExEx. Additive, not a regression. |
| `src/lib.rs` | **PRESENT + firehose-augmented** | adds `mod firehose;` and re-exports the two firehose executor builders. |

---

## Consensus / state-root risk section

Every item that can affect mainnet (369) or Ethereum-mainnet (1) consensus, state root, balances, rewards, or fork activation was checked and is **confirmed equivalent**:

| Risk surface | Result |
|---|---|
| PrimordialPulse mainnet fork block (chain 369) | `17_233_000` — identical (`hardfork.rs:11`) |
| PrimordialPulse testnet v4 block (chain 943) | `16_492_700` — identical (`hardfork.rs:14`) |
| Paris/PoS TTD activation (fork+1) | identical (`chainspec.rs:51,84`) |
| chain-id gating (1 pre-fork → 369/943 post-fork; history replay) | identical (`chainspec.rs:114-134`); both 369 and 1 paths handled |
| Deposit-contract bytecode swap (ETH → PULSE) | binary sha1-identical; `ETH_DEPOSIT_CONTRACT` / `PULSE_DEPOSIT_CONTRACT` (`3693…3693`) string-identical |
| Deposit-contract 31-slot initial storage (Merkle tree init) | sha1-identical |
| Sacrifice-credit allocations (mainnet + testnet) | binaries sha1-identical; decoder sha1-identical; `sacrifice_credits_for(chain)` maps 369→mainnet, 943→testnet |
| Treasury alloc (testnet only; mainnet has none) | `TESTNET_V4_TREASURY` + balance constant string-identical; mainnet correctly has no treasury alloc |
| PrimordialPulse state transition application | `evm.rs` code byte-identical (comment-only diff); `apply_primordial_pulse` + `==` once-only guard preserved |
| Block/uncle reward, difficulty, EIP-1559 base-fee rules | `consensus.rs` + `gas.rs` byte-identical |
| Genesis / chain spec | `spec.rs` byte-identical |
| msgboard P2P (mainnet peering) | all sources byte-identical |

**No consensus-critical change is MISSING or DIVERGENT.** The firehose-specific deltas (spec-data relocation, executor wrapping, comment expansion) are isolated from the state-transition math and are documented as behavior-preserving — when firehose runs without its wrapper (tests/non-firehose builds), state still commits identically and only event emission is absent.

---

## Informational: upstream paradigm PRs firehose is behind on

These 18 commits are in `pulse/main` but not `firehose` (excludes the PulseChain v1 squash). This is firehose lagging upstream paradigm — a separate concern from baseline parity. Flagged by criticality:

**Consensus / state-root adjacent (back-port candidates):**
- `4ffde69d9` fix(engine): apply finalized state after syncing FCU head import (#23838) — engine FCU/finalization correctness; **highest-priority back-port**.
- `c77e449e4` fix(cli): verify repaired trie state root before commit (#23854) — trie repair guard; relevant if running `reth db` repair on mainnet.
- `70fc51e3d` fix(reth-bb): renumber bal_index space at segment boundaries (#23868) — block-access-list indexing (reth-bb tool).

**Networking (peering on mainnet):**
- `0eeb8c5ef` fix(net): prevent eth/68 tx request packing overflow (#23848) — eth/68 tx-request overflow; worth back-porting for mainnet peering robustness.
- `d25de3005` feat: customizable discovery defaults (#23843)
- `b2794548e` feat(eth-wire): add capability message id helpers (#23908)
- `8d7c15f38` feat(net): add optional BAL fetching for block ranges (#23779)

**Lower-risk (features/chores/docs/storage-engine):**
- `ddb3819ec` feat(storage): add in-memory BAL retention (#23873)
- `e98fb4af9` feat(engine): convert built payload to execution data (#23859)
- `6d9ea5af4` feat(engine): add shared block accessor to EthBuiltPayload (#23862)
- `44879c320` feat(payload): expose built payload block access list (#23860)
- `fcfa8287f` chore(mdbx): replace deprecated MDBX_NOTLS with MDBX_NOSTICKYTHREADS (#23378) — MDBX threading flag; benign but touches the storage engine.
- `38c627ce8` chore(deps): bump hickory-resolver (#23914)
- `fa2279ff4` chore: default to min-trace-logs (#23851)
- `0d07d6ae6` chore: update rpc-compat expected failures (#23867)
- `30fe86d25` docs: update admin namespace docs (#23916)
- `077e5eecf` chore: don't enforce non-empty blocks in e2e payload building (#23837)
- `709485dcb` perf(bench): buffer RPC fetches in generate-big-block (#23830)

None of these are PulseChain-specific; firehose's own PulseChain code already matches the squash.
