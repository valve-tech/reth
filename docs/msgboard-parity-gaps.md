# MsgBoard Parity Gaps — reth `extension-model` vs erigon-pulse `v3.0.0-RC8`

**Audit date:** 2026-04-27
**Reference source:** `~/go/src/gitlab.com/pulsechaincom/private-erigon-pulse` @ HEAD `48cdb29e35` (commit message: *Prepare release candidate 8*)
**Reth target:** `extension-model` @ `7008dd5060` (after the RPC parity + CLI wiring + canonical-state subscription work)

This document is **the operative gap spec**. The companion file `specs/02-msgboard.md` describes the full erigon-pulse design and was verified accurate against the Go source during this audit (with one minor correction noted below). This file enumerates only what reth still **diverges from** the reference.

---

## 1. Gap classification

| Class | Meaning | Action |
|---|---|---|
| **WIRE** | Affects on-the-wire bytes, peer interop, or persisted data layout. Drop-in compat at risk. | Fix promptly. |
| **OBSERVABILITY** | Metrics, logs, or status fields. No correctness impact. | Fix when observability matters. |
| **PERF** | Operational tuning (DB pages, buffers). Behavior correct, throughput/footprint differs. | Fix opportunistically. |
| **ARCH** | Reth deliberately uses a different mechanism that achieves the same end-state. | Document, don't change. |
| **N/A** | Erigon-only deployment mode (gRPC, external sentry process). | Not applicable to reth. |

---

## 2. Wire-level gaps (fix promptly)

### 2.1 `MAX_BLOCK_RANGE` mismatch — **wire** — ✅ FIXED

| | Value |
|---|---|
| Erigon | `MaxBlockRange = 1080` (`msgboardcfg/config.go:11`) |
| Reth   | `MAX_BLOCK_RANGE: u64 = 1080` (`crates/net/msgboard/src/block_filter.rs:12`) |

Resolved in `extension-model` — see commit history. The 56-block blackout zone near the tail is gone; reth and erigon now accept the same window of anchor blocks.

### 2.2 MDBX table name — **wire (persistence layer)** — ✅ FIXED

| | Value |
|---|---|
| Erigon | `BoardMessage` named table inside the `msgboard` MDBX env |
| Reth   | `BoardMessage` named table (`tx.create_db(Some(TABLE_NAME), ...)`) in `crates/net/msgboard/src/db.rs` |

Resolved in `extension-model`. `crates/net/msgboard/src/db.rs` now defines `const TABLE_NAME: &str = "BoardMessage"` and uses it consistently across `open_msgboard_db`, `db_load_all`, and `db_flush`. Two unit tests (`write_and_reload_roundtrips_through_named_table`, `discarded_hashes_are_deleted_on_flush`) cover the persistence cycle.

`set_max_dbs(1)` is sufficient — MDBX counts only **named** sub-DBs against the limit; the unnamed default DB is implicit and free.

**One-time effect on existing testnet boxes:** previously persisted messages live in the unnamed default DB and become orphaned after upgrade. Since msgboard messages naturally expire after `block_range` blocks (~30 minutes at default 120 blocks on PulseChain testnet), the next ~30 minutes will see an empty board, then peer gossip refills it.

### 2.3 `CommitEvery` flush interval — **persistence durability** — ✅ FIXED

| | Value |
|---|---|
| Erigon | `15s` (`msgboardcfg/config.go:46`) |
| Reth   | `15s` default, configurable via `--msgboard.commit-every <humantime-duration>` |

Resolved in `extension-model`. The interval is now wired through `MsgboardArgs::msgboard_commit_every` (parsed by `humantime::parse_duration`, default `15s`) and threaded into `MsgBoard::spawn_flush_task` from `bin/reth/src/main.rs`. Operators can tighten or relax it without rebuilding. Default matches erigon-pulse byte-for-byte.

---

## 3. Observability gaps — ✅ all FIXED

### 3.1 Metric gauges — ✅ FIXED

| Spec metric | Type | Reth status |
|---|---|---|
| `msgboard_msg_count` | Gauge | ✅ wired in `MsgboardMetrics`, updated by `insert_checked` / `set_head` / `load_from_db` |
| `msgboard_msg_size` | Gauge | ✅ wired alongside `msg_count` (sum of `data` bytes across live messages) |
| `msgboard_write_to_db_bytes` | Gauge | ✅ wired in `flush_to_db` |

While threading the metrics struct into `MsgBoard`, the four pre-existing histograms (`add_remote_msgs_duration_seconds`, `change_block_duration_seconds`, `sent_to_peer_duration_seconds`, `write_to_db_duration_seconds`) — which were declared but never instantiated — are also now actually emitting.

### 3.2 Periodic stats log — ✅ FIXED

Wired as `--msgboard.log-every <humantime-duration>` (default `30s`). `MsgBoard::spawn_log_task` emits an INFO line with `ready / head / count / size / work_multiplier / work_divisor`. Set the flag to a very large duration to effectively disable.

### 3.3 `headBlock = 0` at startup — ✅ FIXED

`bin/reth/src/main.rs` now calls `board.set_head(info.best_number, info.best_hash)` from `handle.node.provider.chain_info()` *before* spawning the canonical-state subscription, so the gauge reports the real chain head from the first RPC call after node launch.

---

## 4. Performance / footprint tuning gaps

### 4.1 MDBX environment parameters — ✅ FIXED

| Parameter | Erigon | Reth status |
|---|---|---|
| `PageSize` | `16 KiB` | ✅ `Geometry { page_size: PageSize::Set(16 * KIBIBYTE) }` |
| `GrowthStep` | `16 MiB` | ✅ `Geometry { growth_step: 16 * MEBIBYTE }` (was 256 GiB) |
| `DirtySpace` | `128 MiB` | ✅ `set_txn_dp_limit(8192)` (= 128 MiB ÷ 16 KiB pages) |
| `WriteMergeThreshold` | `3 × 8192` (≈37.5%) | ✅ `set_merge_threshold(3 * 8192)` — required adding `set_merge_threshold` to `reth-libmdbx`'s `EnvironmentBuilder`, which routes the value to `MDBX_opt_merge_threshold_16dot16_percent`. Additive change to a workspace-shared crate. |
| `MapSize` | `1 TiB` | ✅ unchanged |

The "severe" 256 GiB → 16 MiB GrowthStep change ends the wasteful chunked file growth on small disks. All five MDBX knobs now match erigon-pulse byte-for-byte.

### 4.2 `--msgboard.gossip-disable` flag — ✅ FIXED

Wired as `--msgboard.gossip-disable` (bool). When set:
- The bulk-announce on peer connect is skipped
- The per-message broadcast forward to peers is skipped
- The board still **receives** announcements and full messages, and still serves `GetBoardMessages` requests

`MsgboardProtocolHandler::new_gossip_disabled(board)` is the constructor used when the flag is set; `MsgboardProtocolHandler::new(board)` is used otherwise.

`--msgboard.external` is **N/A** to reth: no gRPC sentry separation exists, and the reth deployment does not need it.

---

## 5. Architectural divergences (different mechanism, same end-state)

These are **not bugs** — reth deliberately uses a different shape that produces equivalent observable behavior.

### 5.1 Outbox + 10-random-peer fanout vs per-peer broadcast — **ARCH**

| | Erigon | Reth |
|---|---|---|
| Mechanism | Outbox accumulates new accepted msgs. Every `100ms`, drains outbox and calls `AnnounceCollectedMsgIDs(ids, 10)` — fans out to up to 10 random peers per tick. | Each peer connection holds a `tokio::sync::broadcast::Receiver` on `MsgBoard::subscribe()`. On each new accepted msg, every connected peer's task fires immediately and sends one `BoardMessageIDs` frame to its peer. |
| Latency | Up to 100ms batch delay, then sent to 10 peers | Immediate, sent to all peers |
| Bandwidth | Capped at 10 announces per outbox drain | One announce per peer per new message |
| Reliability | Random-fanout requires gossip dispersion to reach all peers eventually | Direct fanout reaches every peer in one hop |

For testnet-scale msg rates (≪100/s) reth's higher bandwidth is negligible. At sustained high msg rates this would matter — but that's not a current concern.

### 5.2 Periodic peer re-sync vs lagged-broadcast re-sync — **ARCH**

| | Erigon | Reth |
|---|---|---|
| Mechanism | Every `5s`, re-announce all known IDs to peers connected within the last 5s. | On connection, send `send_board_message_ids()` once. If the broadcast receiver lags (`RecvError::Lagged`), re-announce all IDs (`protocol.rs:161-164`). |
| Coverage | Handles "peer connected during outbox drain" race | Handles same race + general broadcast-channel overflow |

Equivalent reliability via a different code path.

### 5.3 State change subscription — **ARCH**

| | Erigon | Reth |
|---|---|---|
| Source | Subscribes to `KV_StateChanges` gRPC stream | `provider.subscribe_to_canonical_state()` |
| End event | Calls `board.ChangeBlock(blockHash, height)` | Calls `board.set_head(height, hash)` |

Different APIs, same payload, same downstream effect.

### 5.4 P2P sentry registration — **ARCH**

| | Erigon | Reth |
|---|---|---|
| Mechanism | Sentry maintains a `ToProto`/`FromProto` mapping between RLPx codes and `Protocol_MSG01 = 8`. Routes msgboard frames over a separate sentry channel. | `MsgboardProtocolHandler` registered via `add_rlpx_sub_protocol`. Each peer connection multiplexes msg/1 frames natively. |

Both produce identical wire output.

---

## 6. Deliberately not implemented (N/A to reth)

| Erigon feature | Reason omitted in reth |
|---|---|
| **gRPC API** (`msgboard.Msgboard` service, 7 methods including `Status`, `AddMessage`, `Categories`, `Content`, `GetMessage`, `NewMessages` streaming) | Reth's RPC stack is jsonrpsee-only. All gRPC methods are reachable as JSON-RPC equivalents; cross-process gRPC has no consumer in the reth deployment. |
| **External msgboard mode** (`--msgboard.external`, separate `msgboard` binary connecting to remote DB + sentry over gRPC) | Reth's `extend_rpc_modules` pattern is in-process only; running msgboard as a sidecar would require building a fresh CLI and gRPC server. Not requested. |
| **Sentry layer fields** (`Protocol_MSG01 = 8`, `MsgboardMessages[messageId]` routing, `ProtocolNames["MSG01"]`, `ProtocolToString["MSG01"]`) | Erigon-only — reth's sub-protocol registration handles this directly. |

---

## 7. CLI flag mapping

| Erigon flag | Reth flag | Status |
|---|---|---|
| `--msgboard.enabled` | (no equivalent) | Reth always registers msgboard. The Erigon flag is opt-in; reth's design is opt-out (currently no opt-out path). |
| `--msgboard.external` | (none) | N/A — see §6 |
| `--msgboard.gossip.disable` | `--msgboard.gossip-disable` | ✅ wired |
| `--msgboard.work.multiplier` | `--msgboard.work-multiplier` | ✅ wired |
| `--msgboard.work.divisor` | `--msgboard.work-divisor` | ✅ wired |
| `--msgboard.msgsize.limit` | `--msgboard.size-limit` | ✅ wired |
| `--msgboard.count.limit` | `--msgboard.count-limit` | ✅ wired |
| `--msgboard.blockrange.limit` | `--msgboard.block-range` | ✅ wired |
| `--msgboard.staleblockbuffer` | `--msgboard.stale-block-buffer` | ✅ wired |
| `--msgboard.commit.every` | `--msgboard.commit-every` | ✅ wired |
| `--msgboard.log.every` | `--msgboard.log-every` | ✅ wired |
| `--msgboard.api.addr` | (none) | N/A — see §6 |

(Flag-name divergence — `.work.multiplier` vs `.work-multiplier` etc. — is intentional: reth uses kebab-case throughout per project convention.)

---

## 8. Spec accuracy

`specs/02-msgboard.md` was independently verified against the erigon-pulse Go source during this audit. It accurately describes:

- All P2P opcodes, message layouts, and the 121-byte `MsgID` flat encoding
- The full PoW algorithm (difficulty, hash, secp256k1 challenge, modular check)
- The board ordering and overflow rules
- All four named timers and their default values
- All MDBX parameters
- All CLI flags (with the documented Erigon naming)

**Spec edit applied during this audit:** §3.1 and §4.4 of `specs/02-msgboard.md` previously presented the difficulty as the float `0.01`. That value is correct (`10000 / 1000000 = 0.01`) but obscures the fact that the wire format and the CLI both take **two** integer inputs, and that comparison is done by integer cross-multiplication (`mult × cfg.div ≥ cfg.mult × div`), never as a float. The spec now presents both the multiplier and divisor as the configurable inputs and shows the ratio as `10,000 : 1,000,000` (reduced `1 : 100`). No source code change.

---

## 9. Summary — what to fix

**All gaps closed for the `extension-model` deploy:**

First-pass fixes (msgboard internals, MDBX, observability):
1. ~~`MAX_BLOCK_RANGE: 1024` → `1080`~~ ✅ done
2. ~~Flush interval `60s` → `15s` — wire `--msgboard.commit-every`~~ ✅ done
3. ~~Name the MDBX table `"BoardMessage"`~~ ✅ done
4. ~~Add `msgboard_msg_count`, `msgboard_msg_size`, `msgboard_write_to_db_bytes` Gauges~~ ✅ done
5. ~~Add `--msgboard.log-every` periodic stats log~~ ✅ done
6. ~~Mirror erigon MDBX geometry (`PageSize` 16 KiB, `GrowthStep` 16 MiB, `DirtySpace` 128 MiB, `WriteMergeThreshold` 37.5%)~~ ✅ done — required adding `set_merge_threshold` to `reth-libmdbx`
7. ~~Add `--msgboard.gossip-disable` flag~~ ✅ done
8. ~~Seed `headBlock` at startup from `chain_info()`~~ ✅ done

Second-pass review fixes (caught by cross-checking the actual code against the erigon source, not just the spec text):
9. ~~`insert_checked` did not return `BoardOverflow` when the new message itself was the one displaced — silently returned `Ok` for a message that was no longer on the board, and would then broadcast its ID to peers who'd ask for a message we don't hold~~ ✅ fixed; new test `lowest_precedence_new_message_returns_board_overflow`
10. ~~`msgboard_addMessage` accepted a structured JSON object (`{version, blockHash, …}`) where erigon takes `hexutility.Bytes` — a single hex string carrying the RLP-encoded `PoWMsg`. Reth now decodes the RLP server-side, matching erigon byte-for-byte.~~ ✅ fixed
11. ~~`MsgboardStatus` JSON used reth-only field names (`messageCount`, `totalSize`) and emitted integers as raw JSON numbers; erigon uses `count`, `size` and hex-encoded uints~~ ✅ fixed via `alloy_serde::quantity` + field renames; `headBlock` retained as a documented reth extension
12. ~~`MsgboardMsg` (`getMessage` / `content` / subscription payload) emitted all five integer fields as raw JSON numbers; erigon's `RPCPoWMsg` hex-encodes via `hexutil.Uint64`~~ ✅ fixed
13. ~~`MsgboardMsg` carried a 10th `timestamp` field not present in erigon's `RPCPoWMsg`~~ ✅ fixed by removing it from the RPC shape; `CheckedPoWMsg::timestamp` stays inside the node for DB use
14. Two new `wire_shape_tests` lock the JSON encoding (`status_serialises_with_erigon_field_names_and_hex_uints`, `msg_serialises_with_erigon_field_names_and_no_timestamp`) so future refactors can't silently regress the wire format

**Don't do (architectural):**
- Don't replace per-peer broadcast with outbox/random-fanout — reth's model is simpler and works for current scale.
- Don't add gRPC API or external-process mode.

**Minor known-divergence (documented, not blocked on):**
- `BoardStatus.enabled` semantic: erigon = static config flag (was msgboard built into this binary?). Reth = `is_ready()` (post-sync). Same observable effect for clients ("can I submit?" → `addMessage` returns an error if false), so left as-is.

---

## 10. Round-2 re-audit (post-RC8 confirmed; runtime / defensive-posture parity)

After commits `2220585eb5` (wire/persistence) and `beb773cc85` (CLI book regen), a third pass cross-checked **runtime behavior** against erigon-pulse — what each node does for malicious / partial / mid-sync peers — rather than just spec ↔ wire shape. This pass covered `board.go`, `fetch.go`, `send.go`, `pow_message.go`, `block_filter.go`, `recently_connected_peers.go`, `protocol.go`, and `util.go`.

Reference confirmed: v3.0.0-RC8 (`48cdb29e35`) is the latest msgboard-touching commit on `v3-pulsechain-msgboard-caplin`. The 3 commits after it (`3cc1c04724`, `4fe7dd8a50`, `e7505a1160`) only update CI and snapshot library refs; **zero msgboard source changes since RC8**.

Ten new gaps surfaced — all closed in this round:

**Defensive posture (deploy-blocking):**
- **N1** ✅ `add_remote_msgs` now returns `(accepted, kickable)`. Protocol task penalises peers via `Peers::reputation_change(BadMessage)` per non-circumstantial rejection (mirrors erigon `kickPeer=true`). Wire-malformed payloads (RLP / `MsgID` list) trigger `BadProtocol`. Circumstantial errors (`MessageExists`, `BoardOverflow`, `BlockExpired`, `BlockUnknown`) are **not** kickable, matching erigon's circumstantial branch in `addMsgLocked`.
- **N2** ✅ `handle_incoming` early-exits when `!board.is_ready()` for `BOARD_MESSAGE_IDS` and `GET_BOARD_MESSAGES` — mirrors erigon `handleInboundMessage`'s `!Started()` short-circuit. `BOARD_MESSAGES` already routed via `add_remote_msgs` which has its own `is_ready()` gate.
- **N3** ✅ `MsgboardConfig::gossip_disabled` lifted from a protocol-handler-only flag to a config field that gates `add_remote_msgs` (drops everything before validation/persist), inbound `BOARD_MESSAGE_IDS`, and the connect-time bulk announce — mirrors erigon `cfg.NoGossip` bidirectional semantic. Observer nodes no longer ingest peer messages.
- **N4** ✅ Initial bulk announce on connect waits for `board.is_ready()`. If readiness flips mid-connection, the announce fires once and is not repeated. Mirrors erigon's `MainLoop`-only `syncNewPeers` schedule.

**Wire / verification (minor):**
- **N5** ✅ `filter_wanted` now drops announcements whose `MsgID.version() != VERSION_V1` before issuing a `GetBoardMessages` request, mirroring erigon `FilterMessageIDs`. Saves one RTT.
- **N6** ✅ `PoWMsg::difficulty` switched from `saturating_mul`/`saturating_div` to `wrapping_mul`/`wrapping_div`, mirroring erigon's plain `uint64` arithmetic. Eliminates a wire divergence where reth would reject a message with absurd-multiplier overflow that erigon would (after wrap) silently accept. Honest inputs are unaffected.
- **N9** ✅ `BROADCAST_CAPACITY` raised from 64 to 1024 (mirrors erigon's gRPC subscriber buffer). Removes the failure mode where a brief peer-task slowdown triggered a full-board re-announce storm under sustained ingest.
- **N10** ✅ `BlockFilter::set_head` floors `lower` at `1`, mirroring erigon `calcLower`. Block 0 never sits inside the live window once the chain has advanced past genesis.

**Persistence durability:**
- **N7** ✅ `load_from_db` pushes duplicate-hash rows onto `discarded` so the next flush deletes them (mirrors erigon `loadAndRepairDbLocked`'s re-validation path).
- **N8** ✅ `load_from_db` re-runs the live config's `is_size_acceptable` and `is_work_acceptable` checks against persisted rows; rows that fail the current config land in `discarded`. Tightening `--msgboard.size-limit` or `--msgboard.work-multiplier` between restarts now actually prunes the disk.
- **Graceful-shutdown flush** ✅ `bin/reth/src/main.rs` now calls `board.flush_to_db()` after `wait_for_node_exit().await` returns. Mirrors erigon `MainLoop`'s shutdown branch (`board.go:158-166`). In-flight changes between the last 15s tick and Ctrl+C are no longer lost.

**Tests added (3 new + 1 updated; 46/46 pass):**
- `filter_wanted_rejects_non_v1_announcements` (board.rs)
- `add_remote_msgs_drops_everything_when_gossip_disabled` (board.rs)
- `lower_is_clamped_to_one_during_early_chain` (block_filter.rs)
- `add_remote_msgs_skips_invalid_and_counts_accepted` updated for the new `(accepted, kickable)` return tuple

**Closed for byte-for-byte erigon parity (no remaining ambiguity):**
- **M1** ✅ `MsgIndex::insert` comparator switched to erigon's `OR` predicate (`newMsg.block < m.block || newMsg.ratio < m.ratio`), expressed as `partition_point(|m| newMsg.block >= m.block && newMsg.ratio >= m.ratio)`. Insert position is byte-identical to erigon's `sort.Search`, including under mixed `(block, ratio)` distributions where the OR-comparator is not a true total order. New test `insert_position_matches_erigon_or_comparator` locks this. (Trade-off: reth is no longer *more correct* than erigon in the audit's narrow sense; the goal here is wire/eviction parity, not algorithmic perfection — operators must see the same evicted message under the same input.)
- **M2** ✅ `validate()` moved out of `add_local_msg` and `add_remote_msgs` to the decode boundary, mirroring erigon's `PoWMsgFromRLP` / `DecodeRLPMsgList` split. New helper `decode_validated_pow_msg` is used by `msgboard_addMessage`. Wire-side `decode_pow_msg_list` already validates. The board's hot path now matches `addMsgLocked` exactly: only size, work-ratio, block-window, and PoW. RPC clients see the same error variant erigon would surface.
- **M3** ✅ `MsgboardError::BlockUnknown` and `MsgboardError::BlockExpired` collapsed into a single `BlockTooOld` variant matching erigon's `ErrMsgTooOld`. Both call sites (`add_local_msg`'s unknown-hash path and `insert_checked`'s aged-out race-condition path) now return the same variant, eliminating the API-surface divergence for clients that pattern-match on the error type.

**Tests after this round:** 44 pass, 0 fail (3 internal-validate tests in `board.rs` removed since their semantics now live in `pow.rs::test_validate_rejects_*`; `add_remote_msgs_skips_invalid_and_counts_accepted` updated to exercise an oversized-payload kickable case which is post-decode-deterministic).
