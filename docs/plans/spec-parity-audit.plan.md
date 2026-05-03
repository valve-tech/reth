# Plan: Spec Parity Audit — Reth vs Protocol Specs

- **Status**: APPROVED
- **Created**: 2026-03-24
- **Source**: specs/01-pulsechain-support.md, specs/02-msgboard.md, specs/03-other-changes.md

## Context

**Goal**: Audit every section of the three protocol specs against the current reth
implementation to identify gaps that would make our nodes distinguishable from the
reference implementation (private-erigon-pulse v3.0.0-RC8).

**Code explored**:

Implemented (working):
- `crates/pulsechain/hardforks/` — PulsechainHardfork enum, ChainHardforks, constants
- `crates/pulsechain/node/src/chainspec.rs` — PULSECHAIN/PULSECHAIN_TESTNET_V4 statics
- `crates/pulsechain/node/src/fork.rs` — PrimordialPulse state transition (sacrifice credits, deposit contracts)
- `crates/pulsechain/node/src/evm.rs` — PulsechainEvmConfig (CHAINID override, block executor with fork hook)
- `crates/pulsechain/node/src/cli.rs` — PulsechainChainSpecParser
- `crates/pulsechain/node/src/node.rs` — PulsechainNode type
- `bin/reth/src/main.rs` — wired to use PulsechainChainSpecParser + PulsechainNode
- `crates/net/peers/src/bootnodes.rs` — PulseChain mainnet + testnet v4 bootnodes
- `crates/chainspec/src/spec.rs` — bootnode resolution for chain IDs 369/943
- `crates/ethereum/consensus/src/lib.rs` — Shanghai/withdrawals_root fix for pre-PrimordialPulse blocks
- `crates/storage/storage-api/src/chain.rs` — Shanghai fix for withdrawal reconstruction
- `crates/stages/api/src/pipeline/mod.rs` — Exit instead of unwind on validation errors
- `crates/net/network/src/swarm.rs` — Skip ENR fork ID filtering for PulseChain peers
- `crates/net/msgboard/` — CLI args, MDBX storage, metrics (scaffolded)

Tests:
- `crates/pulsechain/node/tests/chainspec.rs` — chain IDs, fork blocks, timestamps, deposit addresses
- `crates/pulsechain/node/tests/evm.rs` — CHAINID opcode boundary behavior
- `crates/pulsechain/node/tests/fork_transition.rs` — sacrifice credits, deposit contract deployment
- `crates/pulsechain/node/tests/rpc_comparison.rs` — (exists, not read)

---

## Spec 01: PulseChain Support — Gap Analysis

### Section 2: Chain Identity
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 2.1 Network IDs (369, 943) | Chain ID constants | ✅ Done |
| 2.2 Network names | "pulsechain", "pulsechain-testnet-v4" | ✅ Done (CLI parser) |
| 2.3 Data directories | Chain-specific datadirs | ⚠️ Needs verification |
| 2.4 Genesis hashes | Must match ETH mainnet | ✅ Done (reuses MAINNET genesis) |
| 2.5 Version string | Variant identifier | ❌ NOT IMPLEMENTED |

### Section 3: Chain Configuration
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 3.1-3.2 Config structs | PulseChainConfig, Treasury | ❌ No treasury support |
| 3.3 TTD | 58,750,003,716,598,352,947,541 | ✅ Done (PULSECHAIN_PARIS_TTD) |
| 3.4 Chain spec files | JSON config equivalents | ✅ Done (Rust statics) |
| 3.5 Helper methods | IsPrimordialPulseBlock, PrimordialPulseAhead | ✅ Done (chain_id_at_block_*) |
| 3.6 Genesis constructors | PulseChain genesis blocks | ✅ Done (clone MAINNET) |
| 3.7 Config by chain ID | Resolve by chain ID not genesis hash | ✅ Done (CLI parser) |

### Section 4: PrimordialPulse Fork Mechanism
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 4.1 Difficulty override | CalcDifficulty returns TTD offset at fork block | ⚠️ Not needed in reth (reth uses hardfork schedule, not difficulty calc) |
| 4.2 Fork actions | apply_primordial_pulse at fork block | ✅ Done |
| 4.3 Pre-fork chain ID | CHAINID returns 1 before fork | ✅ Done (PulsechainEvmConfig) |
| 4.3 Pre-fork Shanghai | Use ETH mainnet Shanghai timestamp | ✅ Done (consensus + storage-api) |
| 4.4 Merge verification | PulseChain PoS guard | ⚠️ Needs review — reth uses hardfork schedule not dynamic TTD |

### Section 5: Sacrifice Credits
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 5.1 Binary data files | Embedded mainnet + testnet v4 .bin | ✅ Done (include_bytes!) |
| 5.2 Algorithm | Parse and apply credits | ✅ Done (decode_sacrifice_credits) |
| 5.3 Balance change reason | BalanceIncreaseSacrificeCredit = 15 | ❌ NOT IMPLEMENTED (no reason tracking) |

### Section 6: Deposit Contract Replacement
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 6.1 Addresses | ETH + Pulse deposit contracts | ✅ Done |
| 6.2 Algorithm | Selfdestruct + deploy | ✅ Done |
| 6.3 Nil contract | Set nil bytecode at old ETH deposit addr | ❌ MISSING — spec says install nil contract, code says "no nil contract" |
| 6.4 Bytecode + storage | 4898 bytes code + 31 Merkle slots | ✅ Done |

### Section 7: Consensus Changes (EL)
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 7.1 IsShanghai expanded | Block number + timestamp | ✅ Done (consensus + storage-api) |
| 7.2 TTD estimation guard | Div-by-zero guard | ⚠️ Not checked |
| 7.3 EVM skip analysis | Reuse ETH mainnet skip blocks | ⚠️ Not checked |
| 7.4 Reward burn on EL | Block reward burn formula | ❌ NOT IMPLEMENTED |

### Section 8: Transaction Signing/Validation
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 8.1 MakeSigner pre-fork | Force chain ID 1 before PrimordialPulse | ⚠️ Partially done (EVM config) but tx validation? |
| 8.2 Legacy TX support | Accept chain ID 1 txs in pool | ❌ NOT IMPLEMENTED |

### Section 9: Consensus Layer (Beacon)
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 9.1-9.5 CL config | Beacon chain parameters | ❌ OUT OF SCOPE (reth is EL only, uses external CL like Lighthouse) |
| 9.6 IsPulseChain | Detection method | N/A (external CL) |
| 9.7 Big integer arithmetic | Balance overflow prevention | N/A (external CL) |
| 9.8-9.9 History download | BellatrixForkEpoch, underflow guard | N/A (external CL) |

### Section 10: Reward Burn
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 10.1 Formula | reward * secondsPerSlot / 12 * 3 / 4 | ❌ NOT IMPLEMENTED |
| 10.2 Where applied | Attestation, sync committee, epoch rewards | ❌ NOT IMPLEMENTED |
| 10.3 IncreaseBalance | applyBurn flag | N/A (CL-side, external) |

### Section 11: Snapshot Support
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 11.1-11.4 Snapshot hashes | PulseChain snapshot manifests | ❌ NOT IMPLEMENTED |

### Section 12: DNS Discovery
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 12.1-12.3 DNS | .pulsedisco.net TLD, ENR tree | ❌ NOT IMPLEMENTED |

### Section 13: Gas Estimation
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 13.1 20% padding | hi = hi + hi / 5 | ❌ NOT IMPLEMENTED |

### Section 14: Engine API
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| 14.1-14.2 Withdrawals check | Block number + timestamp for Shanghai | ✅ Done (consensus layer check) |

### Section 15: Detection Mechanisms
| Item | Spec Requirement | Status |
|------|-----------------|--------|
| All detection methods | Various PulseChain detection | ✅ Done (chain ID based) |

---

## Spec 02: MsgBoard — Gap Analysis

| Area | Spec Requirement | Status |
|------|-----------------|--------|
| P2P protocol (msg/1) | Wire protocol, capability, 3 message types | ❌ NOT IMPLEMENTED |
| Data model | PoWMsg, CheckedPoWMsg, MsgID | ❌ NOT IMPLEMENTED (types exist in msgboard-types?) |
| PoW verification | SHA-256 + secp256k1 modular arithmetic | ❌ NOT IMPLEMENTED |
| Board algorithm | addMsg, ordering, overflow/displacement | ❌ NOT IMPLEMENTED |
| Block filtering | BlockFilter, pruning, TTL | ❌ NOT IMPLEMENTED |
| gRPC API | 7 methods | ❌ NOT IMPLEMENTED |
| JSON-RPC API | 5 methods + WebSocket subscription | ❌ NOT IMPLEMENTED |
| P2P integration | Sentry layer, dual-protocol peers | ❌ NOT IMPLEMENTED |
| CLI args | --msgboard.* flags | ✅ Done (args.rs) |
| MDBX storage | Standalone DB, flush, load/repair | ✅ Done (db.rs) |
| Metrics | 4 prometheus metrics | ✅ Done (metrics.rs) |

---

## Spec 03: Other Changes — Gap Analysis

| Item | Spec Requirement | Status |
|------|-----------------|--------|
| Gas estimation +20% | hi = hi + hi / 5 after binary search | ❌ NOT IMPLEMENTED |
| RPCTxFeeCap 1M | 1 ether → 1,000,000 ether | ❌ NOT IMPLEMENTED |
| Snapshot ChainName fix | Don't disable snapshots for unknown chains | ⚠️ Needs investigation |
| MDBX MapSize defaults | 16 GB → 1 TB for diagnostics/downloader | ⚠️ Needs investigation |

---

## Critical Gaps Summary (Distinguishable Node Behavior)

### P1 — BLOCKS SYNC / CONSENSUS (will fail to sync or produce wrong state)
1. **Nil contract at ETH deposit address** — Spec says install nil bytecode, code explicitly skips this. VERIFY AGAINST ON-CHAIN STATE.
2. **Testnet v4 treasury allocation** — Spec defines treasury at PrimordialPulse for testnet v4 (0xA592...8fC, balance 0x314DC...0000). Not implemented.
3. **Reward burn on EL** — Block reward * 10/12 * 3/4. Missing entirely. However: reth is EL-only and block rewards come from CL via Engine API. VERIFY if this is CL-only.

### P2 — RPC DIVERGENCE (different responses than reference nodes)
4. **Gas estimation 20% padding** — eth_estimateGas returns different values.
5. **RPCTxFeeCap** — Transactions above 1 PLS fee rejected at RPC layer.
6. **Legacy TX acceptance** — Pool rejects ETH-chain-ID signed transactions.

### P3 — NETWORK DISTINGUISHABILITY (peers can identify us as non-reference)
7. **Version string** — No variant identifier ("pulse") in client version.
8. **DNS discovery** — Missing .pulsedisco.net support.
9. **Msgboard P2P** — msg/1 capability not advertised to peers.

### P4 — OPERATIONAL
10. **Snapshot manifests** — Can't fast-sync from PulseChain snapshot providers.
11. **MDBX MapSize** — May hit database limits on long-running nodes.

---

## Phase 1: Critical Parity Fixes — Planned: yes

### Task 1.1: Verify nil contract behavior against on-chain state
- **Status**: pending
- **Type**: deterministic
- **Action**: Query the ETH deposit contract address (0x00000000219ab540356cBB839Cbe05303d7705Fa) on PulseChain mainnet via JSON-RPC eth_getCode at a post-PrimordialPulse block. The erigon spec says install nil bytecode (0x6080604052600080fd...), but our code explicitly says "no nil contract — on-chain state shows empty code". One of these is wrong. If on-chain shows nil bytecode, add it to fork.rs. If on-chain shows empty 0x, our code is correct and the spec needs updating.
- **Files**: crates/pulsechain/node/src/fork.rs (if nil contract needed)
- **Dependencies**: none

### Task 1.2: Implement gas estimation 20% padding
- **Status**: pending
- **Type**: deterministic
- **Action**: In the eth_estimateGas binary search implementation, add  after convergence, capped by account gas limit. Find the estimate function in crates/rpc/rpc-eth-api/src/helpers/estimate.rs and add the padding.
- **Files**: crates/rpc/rpc-eth-api/src/helpers/estimate.rs
- **Dependencies**: none

### Task 1.3: Increase RPCTxFeeCap to 1,000,000
- **Status**: pending
- **Type**: deterministic
- **Action**: Find the RPC transaction fee cap default and change from 1 ether to 1,000,000 ether. This may be in the RPC config or CLI defaults.
- **Files**: TBD (search for RPCTxFeeCap or tx_fee_cap)
- **Dependencies**: none

### Task 1.4: Implement testnet v4 treasury allocation
- **Status**: pending
- **Type**: deterministic
- **Action**: At PrimordialPulse on testnet v4 (chain ID 943), allocate treasury balance of 0x314DC6448D9338C15B0A00000000 to 0xA592ED65885bcbCeb30442F4902a0D1Cf3AcB8fC. Add treasury config to apply_primordial_pulse. Mainnet has no treasury.
- **Files**: crates/pulsechain/node/src/fork.rs
- **Dependencies**: none

### Task 1.5: Add PulseChain variant to client version string
- **Status**: pending
- **Type**: deterministic
- **Action**: Add "pulse" variant identifier to the reth version string so peers see a PulseChain-identified client. Pattern: "reth/X.Y.Z-pulse".
- **Files**: TBD (search for version string construction)
- **Dependencies**: none

### Task 1.6: Accept legacy chain ID 1 transactions in tx pool
- **Status**: pending
- **Type**: deterministic
- **Action**: PulseChain nodes must accept transactions signed with chain ID 1 (Ethereum mainnet) in the transaction pool. Find the chain ID validation in the pool and add the exception for PulseChain chains.
- **Files**: TBD (search for chain_id validation in tx pool)
- **Dependencies**: none

### Task 1.7: Verify reward burn is CL-only
- **Status**: pending
- **Type**: deterministic
- **Action**: Confirm that the reward burn (reward * secondsPerSlot / 12 * 3/4) is applied on the CL side (Lighthouse) and NOT on the EL. If it is CL-only, document this clearly. If EL needs to apply it to block rewards in Finalize(), implement it. Check erigon spec section 7.4 which says "Finalize()" applies burn.
- **Files**: specs/01-pulsechain-support.md, possibly crates/pulsechain/node/src/evm.rs
- **Dependencies**: none

---

## Phase 2: Network Parity — Planned: no

DNS discovery (.pulsedisco.net), msg/1 P2P protocol capability advertisement,
snapshot manifest support. These make nodes distinguishable on the network but
don't affect consensus or RPC correctness.

**Open questions:**
- Does reth's discovery stack support custom DNS TLDs, or do we need to override?
- What is the minimum msg/1 implementation needed for peer compatibility? (Just advertising the capability + ignoring messages might suffice for now.)
- Are PulseChain snapshot providers live and compatible with reth's snapshot format?

---

## Phase 3: Full MsgBoard Implementation — Planned: no

Complete msg/1 protocol: message types (PoWMsg, CheckedPoWMsg, MsgID), PoW
verification (secp256k1 + SHA-256), board algorithm with ordering/displacement,
P2P gossip, gRPC + JSON-RPC APIs, WebSocket subscriptions.

**Open questions:**
- Should msgboard be a separate reth ExEx (Execution Extension) or integrated into the node?
- Can we reuse the existing crates/net/msgboard scaffolding or does it need restructuring?
- What is the deployment timeline — does msgboard need to work before the VPS sync completes?

---

## Design Decisions

1. **CL changes are out of scope**: Reth is EL-only. PulseChain uses Lighthouse for CL. Sections 9, 10 of the spec (beacon config, reward burn, big.Int migration) are Lighthouse's responsibility. Exception: if EL-side reward burn exists in Finalize() (section 7.4), we need it.

2. **Exit-on-validation-error is intentional**: The pipeline override that exits instead of unwinding is a development convenience — it avoids multi-hour unwinds during iterative development. This may need to be reverted for production.

3. **ENR fork ID skip is a workaround**: The swarm.rs change to skip ENR fork ID filtering works but is imprecise. A proper fix would compute PulseChain's fork ID correctly. Acceptable for now since ETH handshake still validates compatibility.

## Verification

- [ ] All existing tests pass: cargo nextest run -p reth-pulsechain-node
- [ ] Gas estimation returns values within 20% of erigon-pulse reference node
- [ ] RPCTxFeeCap allows transactions with fees up to 1M PLS
- [ ] Testnet v4 treasury balance is correct at post-PrimordialPulse blocks
- [ ] Version string includes "pulse" variant
- [ ] tx pool accepts chain ID 1 legacy transactions on PulseChain
- [ ] Nil contract / empty code at ETH deposit address matches on-chain state

## Post-Completion Log

### Deferred Scope
- MsgBoard full P2P protocol implementation (Phase 3)
- DNS discovery for .pulsedisco.net (Phase 2)
- Snapshot manifest support (Phase 2)
- Proper fork ID computation for PulseChain (instead of skip workaround)
- MDBX MapSize defaults increase
- EVM skip analysis blocks for PulseChain
