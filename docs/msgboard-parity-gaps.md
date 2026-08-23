# MsgBoard Parity Gaps — reth `extension-model` vs erigon-pulse `v3.0.0-RC8`

**Audit date:** 2026-04-27
**Reference source:** `~/go/src/gitlab.com/pulsechaincom/erigon-pulse` @ `v3.0.0-RC8` = `48cdb29e35` (commit message: *Prepare release candidate 8*), package `msgboard/`

> **Path corrected 2026-07-28.** This line previously read `private-erigon-pulse`.
> The commit hash was right and the source was on disk the whole time under the
> name above; rounds 3 and 4 looked for the recorded path, did not find it, and
> reasoned from this document instead of from the Go. That produced §11's wrong
> fix and left §12.9/O2 open for no reason — see §13. Keep this line accurate.
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
- **M1** ⚠️ **superseded — see §11.** `MsgIndex::insert` comparator switched to erigon's `OR` predicate (`newMsg.block < m.block || newMsg.ratio < m.ratio`), expressed as `partition_point(|m| newMsg.block >= m.block && newMsg.ratio >= m.ratio)`. The claim recorded here — that this is "byte-identical to erigon's `sort.Search`, including under mixed `(block, ratio)` distributions" — **was wrong**, and wrong precisely in the case it claimed to cover. (Trade-off as recorded: reth is no longer *more correct* than erigon in the audit's narrow sense; the goal is wire/eviction parity, not algorithmic perfection — operators must see the same evicted message under the same input. That goal stands; the implementation did not achieve it until §11.)
- **M2** ✅ `validate()` moved out of `add_local_msg` and `add_remote_msgs` to the decode boundary, mirroring erigon's `PoWMsgFromRLP` / `DecodeRLPMsgList` split. New helper `decode_validated_pow_msg` is used by `msgboard_addMessage`. Wire-side `decode_pow_msg_list` already validates. The board's hot path now matches `addMsgLocked` exactly: only size, work-ratio, block-window, and PoW. RPC clients see the same error variant erigon would surface.
- **M3** ✅ `MsgboardError::BlockUnknown` and `MsgboardError::BlockExpired` collapsed into a single `BlockTooOld` variant matching erigon's `ErrMsgTooOld`. Both call sites (`add_local_msg`'s unknown-hash path and `insert_checked`'s aged-out race-condition path) now return the same variant, eliminating the API-surface divergence for clients that pattern-match on the error type.

**Tests after this round:** 44 pass, 0 fail (3 internal-validate tests in `board.rs` removed since their semantics now live in `pow.rs::test_validate_rejects_*`; `add_remote_msgs_skips_invalid_and_counts_accepted` updated to exercise an oversized-payload kickable case which is post-decode-deterministic).

---

## 11. Round-3: `partition_point` is not `sort.Search` (M1 reopened and closed)

**Audit date:** 2026-07-28
**Trigger:** a developer report of a "message index bug".

### 11.1 The defect

§10 M1 recorded `MsgIndex::insert` as achieving byte-identical insert positions
to erigon by expressing erigon's `sort.Search` predicate as a negated
`slice::partition_point`. The De Morgan negation is correct. The reasoning
underneath it was not.

**Go's `sort.Search` and Rust's `slice::partition_point` return the same index
only when the predicate is monotonic over the slice.** They use different probe
sequences — Go a classic `lo`/`hi` midpoint loop, Rust a `base`/`size` descent —
and on a non-monotonic predicate those land on different answers.

Erigon's OR-comparator is not monotonic. `index.rs` said so in its own module
docs, five lines above the code that depended on it not mattering.

### 11.2 Measured impact

Replaying identical insert sequences through both implementations:

| Metric | Rate |
|---|---|
| Sequences producing a different board order | **12.17%** |
| Sequences producing a different eviction target (`msgs[0]`) | **1.38%** |

At `count_limit`, reth evicted a different message than erigon on ~1.4% of
sequences — the exact wire-observable parity property M1 existed to guarantee.
It also flows into the `BoardOverflow` self-displacement path
(`board.rs`): reth could reject-and-not-broadcast a message erigon accepts,
and the reverse.

### 11.3 Why CI did not catch it

The guard test `insert_position_matches_erigon_or_comparator` used a
**two-element board**. At that size both algorithms probe the same single index
and cannot disagree, so the test passed under either implementation. Divergence
requires ≥5 entries. The test asserted the right property on an input too small
to falsify it.

### 11.4 Fix

`MsgIndex::insert` now calls `erigon_insert_pos`, a literal port of Go's
`sort.Search` loop. Parity on a non-monotonic predicate requires reproducing the
*search*, not just the comparator.

Verified against **real Go 1.23 `sort.Search`** over 200,000 randomized insert
sequences (~1.7M inserts), FNV-1a digesting every resulting board order:

```
Go sort.Search (reference) : 11128719865354962318
reth, after fix            : 11128719865354962318   match
reth, before fix           :  1127759515664285576   differ
```

Two tests lock this, both verified to fail against the pre-fix implementation:

- `insert_position_matches_erigon_on_deep_board` — minimised 9-message case
- `insert_order_matches_go_sort_search_over_200k_sequences` — the full differential, with the Go reference program embedded in the test docs so the digest constant can be regenerated

### 11.5 Ordering gaps found in the same pass

Two further non-determinism bugs, same family (`HashMap` iteration order
leaking into wire-visible output):

- **O1** ✅ `msgboard_categories` returned `HashMap` keys unsorted. `specs/02-msgboard.md` §9.2 specifies a **sorted** list. `MsgBoard::categories` now sorts. Test: `categories_are_returned_sorted` (16 categories, so an unsorted implementation cannot pass by chance).
- **O2** ✅ `MsgIndex::category_msgs{,_filtered}` iterated `HashMap::values()`, so `msgboard_content` returned an arbitrary per-node order for the category-filtered path while the unfiltered path returned precedence order. Both now walk the ordered `msgs` vec. Tests: `content_returns_messages_in_board_precedence_order`, `content_category_order_matches_the_unfiltered_order`.

  Note: precedence order is **not** recoverable by sorting the collected values — it is defined by the non-total OR-comparator plus insertion history, not by any key. Walking the ordered vec is the only correct source.

  **Erigon's ordering for `Content` could not be verified** — the reference source was not available during this pass. What is asserted is internal consistency and determinism, not erigon parity. If erigon returns a different order, this is still open.

- **O3** ✅ `send_board_message_ids`'s doc comment claimed "approximately 826 IDs per chunk". The actual value is `102_400 / 121` = **846**. Comment corrected; `announcing_chunks_at_846_ids_per_frame` pins the arithmetic.

### 11.6 Test coverage added

`protocol.rs`, `rpc.rs`, and `msg_id.rs` had **zero** tests before this pass.

| Crate / file | Before | After |
|---|---|---|
| `reth-msgboard` (total) | 45 | **93** |
| ├ `protocol.rs` | 0 | 26 |
| ├ `rpc.rs` | 0 | 21 |
| └ `index.rs` | 13 | 15 |
| `reth-msgboard-types` (total) | 14 | **26** |
| └ `msg_id.rs` | 0 | 12 |

`protocol.rs` tests drive `handle_incoming` / `send_board_message_ids` directly
against a real board and an mpsc sender, asserting opcode bytes, payload bytes,
frame counts, and reputation calls — covering readiness gating, `gossip_disabled`
bidirectionality, `BadMessage` vs `BadProtocol` classification, and both chunking
paths. `rpc.rs` tests drive the registered `RpcModule`, so method names, param
deserialization, result serialization, error codes, and subscriptions all run the
same path a client takes.

---

## 12. Round-4: parity constants that nothing could falsify

**Audit date:** 2026-07-28

Round 3 closed the ordering bugs. This pass targets the *other* half of the same
failure mode: properties this document asserts in prose, where no test would
fail if the code drifted away from them. Production behavior is unchanged —
every item below is test-only, plus one derive.

### 12.1 MDBX parameters were prose-only (§4.1)

§4.1 records five erigon-parity MDBX values, and `db.rs` carried two round-trip
tests — neither of which touched a single one of them. `GrowthStep` has already
regressed once here (256 GiB against erigon's 16 MiB), so this is a demonstrated
drift path, not a hypothetical.

- `mdbx_parameters_match_erigon_pulse` pins page size, growth step, dirty-page
  limit, merge threshold, and map size as literals, plus two derived invariants:
  the merge threshold stays inside MDBX's accepted `[8192, 32768]` range, and the
  dirty-page limit times the page size still multiplies out to erigon's 128 MiB
  (they are coupled — moving one silently changes the effective `DirtySpace`).
- `table_name_matches_erigon_kv_board_message` pins `kv.BoardMessage`.
- `opened_env_applies_erigons_page_size_and_map_size` reads the values back off
  the opened env, proving MDBX *applied* them rather than falling back to its
  own defaults.

**A §11.3 repeat, caught by negative control.** The read-back test was first
written comparing `stat().page_size()` against `PAGE_SIZE_BYTES` — the same
constant that configured the env. That is a tautology: it passes under any
value, exactly as the M1 guard passed under either implementation. It was only
caught because each new test was run against a deliberately broken build before
being kept. The assertions are now against erigon's literals.

### 12.2 Corrupt-record handling (`db_load_all`'s `bad` counter)

Never exercised. `undecodable_records_are_counted_as_bad_and_skipped` writes
both outright garbage and a truncated RLP prefix (the likelier on-disk failure),
and asserts both are counted while the good message still loads — a corrupt row
must not cost the operator the rest of the board.

### 12.3 CLI defaults were written twice with nothing reconciling them

`args.rs` had **zero** tests. Every default exists twice — as a clap
`default_value_t` and in the hand-rolled `Default` impl — so editing one and not
the other makes the effective value depend on whether the args came from the CLI
or from `Default`. `MsgboardArgs` now derives `PartialEq, Eq` (the only
production change in this round, matching `DatadirArgs` / `DevArgs` upstream) so
the two can be compared directly.

- `default_impl_agrees_with_the_clap_defaults` — the reconciliation.
- `defaults_match_erigon_pulse` — each default against erigon's literal value.
- `into_config_maps_every_field` — every field a distinct value, so a transposed
  assignment cannot pass. The multiplier/divisor pair is the dangerous one:
  swapping them inverts the minimum-difficulty check rather than erroring.
- `every_documented_flag_name_parses` — the §7 flag names are an operator-facing
  contract; renaming one breaks existing systemd units.
- `duration_flags_parse_humantime_units` — `2m` means two minutes, and a
  unitless `15` is rejected rather than silently reinterpreted.

### 12.4 `difficulty()` wrapping — a documented wire gap with no test

The doc comment on `PoWMsg::difficulty` explains that it must wrap like erigon's
plain `uint64` arithmetic rather than saturate, because a message crafted with
`base × multiplier > 2⁶⁴` would otherwise have reth reject what erigon accepts.
Nothing tested it. `test_difficulty_wraps_like_erigon_uint64_rather_than_saturating`
and `test_difficulty_wrapping_to_zero_is_rejected_not_a_panic` (the wrap can land
on exactly zero, which must not become a division by zero) now pin both, and
`test_difficulty_matches_the_documented_formula` pins the ordinary-input formula
so the constants cannot drift under cover of the wrapping cases.

`validate()`'s `InvalidVersion` and `InvalidData` branches were also untested;
both are now covered, including that a category alone or a body alone is valid.

### 12.5 `pow_scalar` carry handling — unreachable by random input

`pow_scalar` reduces `(nonce × digest + block_hash) mod n` in U256 and handles
the carry out of the 256-bit add by hand, with a 15-line carry analysis above
it. No test drove it, and **no random test ever would**: `product < 2¹⁹²`, so a
uniformly random `block_hash` overflows the add with probability ≈ 2⁻⁶⁴. The
branch is reachable only by a near-maximal `block_hash` — i.e. by a peer
deliberately probing for a client split.

`test_pow_scalar_matches_full_precision_arithmetic_including_carry` drives 2,000
deterministic cases (xorshift64, fixed seed), half with random block hashes and
half forced just below 2²⁵⁶, against full-precision U512 arithmetic — the
definition Go's `math/big` computes. It asserts the forced-carry regime actually
fired (≥500 cases) rather than trusting that it did; verified to fail on the
first carry iteration when the `nc` adjustment is removed.

**Finding: two carry sub-branches are dead code.** After a carry,
`sum_wrapped < 2¹⁹²`, and adding `nc = 2²⁵⁶ − n ≈ 2¹²⁸` can neither overflow
again nor reach `n`. So `carry2` and the `adjusted >= n` reduction are
unreachable for every possible message. The code is correct and harmless as
defensive depth — it is documented here so nobody mistakes it for tested,
exercised logic, and `test_pow_scalar_carry_cannot_overflow_a_second_time` pins
the bound the claim rests on. Left in place deliberately.

### 12.6 Method

Every test in this round was run against a deliberately broken build before
being kept — the discipline §11.3 shows was missing. Controls used: page size
16 KiB → 8 KiB; `bad` counter increment removed; `Default` impl drifted from the
clap default; multiplier/divisor transposed in `into_config`; `difficulty()`
switched to saturating; the `nc` carry adjustment zeroed. Each failed only the
tests it should have, and 12.1's tautology was found this way.

### 12.7 Closing the gossip loop

Every `protocol.rs` test drove **one half** of the exchange against hand-built
frames: emitters checked against what we believed the parser expects, the parser
against what we believed the emitters produce. Nothing checked the two halves
against *each other*, so a consistent misunderstanding on both sides passed the
entire suite.

Five tests now run announce → request → deliver board-to-board, with no frame
authored by the test: full convergence, re-announcement to a synced peer
requesting nothing (otherwise every reconnect re-fetches the board), a
partially-synced peer requesting only what it lacks, bidirectional exchange of
disjoint messages, and an out-of-window peer ingesting nothing without earning a
penalty.

Their value is demonstrable: making `handle_incoming` request *all* announced
IDs instead of only wanted ones — a plausible refactor slip — leaves all 30
pre-existing protocol tests green and is caught only by the partial-sync case.

### 12.8 `launch.rs` and the metric gauges

`launch.rs` had zero tests. `db_path` was extracted from `install` (the only
other production change this round) so the resolution rule is testable: default
`<datadir>/msgboard`, and an explicit `--msgboard.db-dir` used **verbatim** —
deliberately not re-rooted under the datadir, since operators point it at a
separate disk. Also covered: the once-only board publish shared across clones,
and both post-install entry points staying inert when `install` never ran (a node
that failed earlier in launch still runs `final_flush` on the way out).

The §3.1 gauges are now asserted to move — `msg_count` and `msg_size` through
insert and through `set_head`'s prune, with `msg_size` summing data bytes rather
than counting messages. The test asserts the **whole declared metric set** is
instantiated, because §3.1's original defect was metrics declared and never
instantiated: invisible to any test that only reads the ones it already knows
work.

It lives in `tests/` for a reason worth keeping: the gauges carry no labels, so
every board in a process writes the same keys, and the parallel board tests in
the unit binary would clobber each other. Cargo gives each integration-test file
its own process. (`Snapshotter::snapshot` also *drains* what it reports — take
one snapshot and query it, or each assertion sees a different, mostly empty
picture.)

### 12.9 Finding: the request path does not chunk

`send_board_message_ids` chunks announcements at 846 IDs, and the `BoardMessages`
response chunks at the 100 KiB packet limit. The `GetBoardMessages` request built
in `handle_incoming` chunks at **neither** — its size is simply whatever the peer
announced in one frame.

Measured: a single announcement of 2,000 IDs produces one 242,001-byte request,
2.4× the limit the other two paths respect. Nothing bounds this but the peer's
own politeness — a peer is not obliged to chunk, and reth does not cap what it
will ask for in one frame.

This is **not fixed here** — the change is to wire behavior, and the erigon
request path could not be consulted (same missing source as §11.5 O2). Left as a
decision for whoever has the reference to hand. What is guarded today is the
coupling that makes the current code safe in practice:
`requests_provoked_by_our_own_announcements_stay_within_the_packet_limit` fails
if the announcement chunk size is ever raised without teaching the request path
to chunk.

### 12.10 Coverage after this round

| Crate / file | Before | After |
|---|---|---|
| `reth-msgboard` (total) | 93 | **114** |
| ├ `protocol.rs` | 26 | 32 |
| ├ `db.rs` | 2 | 6 |
| ├ `args.rs` | 0 | 5 |
| ├ `launch.rs` | 0 | 5 |
| └ `tests/metrics.rs` (new) | 0 | 1 |
| `reth-msgboard-types` (total) | 26 | **34** |
| └ `pow.rs` | 11 | 19 |

148 tests, 0 failures.

### 12.11 Still open

> **Every item below is resolved or superseded — see §13 and §13.6.** Kept as
> written because it is the record of what round 4 believed, and §13.1's finding
> turns on that record being trustworthy rather than tidied. In particular the
> first bullet is wrong about the erigon source: it was on this machine, under a
> different directory name (see the header note).

- The §11.5 O2 caveat is **unchanged**: erigon's `Content` ordering remains
  unverified, and `~/go/src/gitlab.com/pulsechaincom/private-erigon-pulse` was
  not present on this machine either. Highest-value remaining parity item, and
  it now blocks §12.9 as well.
- The unbounded request frame in §12.9.
- `install` / `install_post_launch_tasks` bodies remain uncovered — they need a
  running node (`TransportRpcModules`, a network handle, a canonical-state
  provider). What was extractable has been extracted.
- `zepter` and `make lint-toml` (dprint) were not run: neither binary is
  installed on this machine. One dev-dependency was added
  (`metrics-util`, `debugging` feature), so both are worth running before this
  goes up.

---

## 13. Round-5: reading the reference instead of reasoning about it

**Audit date:** 2026-07-28
**Trigger:** §12.11 listed three items blocked on "erigon source not available on
this machine". It is available — at
`~/go/src/gitlab.com/pulsechaincom/erigon-pulse/msgboard/`, checked out at
`v3.0.0-RC8`. Rounds 3 and 4 looked for `private-erigon-pulse` and, not finding
it, reasoned from the prose in this document instead. Everything below follows
from twenty minutes of reading `message_index.go`.

### 13.1 §11's fix was aimed at the wrong function (M1 reopened, again)

**Erigon's `MsgIndex.Insert` does not call `sort.Search`. There is no
`sort.Search` anywhere in erigon's msgboard package.** It does two things:

```go
last := mIdx.Last()
if len(mIdx.msgs) == 0 || newMsg.BlockNumber > last.BlockNumber ||
    (newMsg.BlockNumber == last.BlockNumber && newMsgDifficultyRatio >= last.DifficultyRatio()) {
    mIdx.msgs = append(mIdx.msgs, newMsg)   // fast path
    return true
}
for i, msg := range mIdx.msgs {             // linear scan from 0
    if newMsg.BlockNumber < msg.BlockNumber || newMsgDifficultyRatio < msg.DifficultyRatio() {
        mIdx.msgs = spliceInto(mIdx.msgs, i, newMsg)
        break
    }
}
```

§11 diagnosed the real defect — a non-monotonic predicate makes the *search*
part of the observable behavior, not just the comparator — and then fixed it by
porting a search erigon never ran. The 200k-sequence differential that "verified"
the fix was generated by a Go program **this audit wrote**, using `sort.Search`,
because that is what §10 believed erigon did. It confirmed reth matched the
belief.

Measured, replaying identical sequences against erigon's actual `Insert`:

| Board depth | Different order | Different eviction target (`msgs[0]`) |
|---|---|---|
| 5 | 49.4% | 15.3% |
| 9 | 80.7% | 21.4% |
| 20 | 99.8% | 25.3% |
| 30 (wider block/ratio spread) | 100% | 44.9% |

The §11 fix was **worse than what it replaced** — `partition_point` diverged on
12.17% of orders and 1.38% of evictions.

**Fix.** `erigon_insert_pos` is now the fast path plus a linear
`iter().position(...)`. The fast path is load-bearing, not an optimisation: it
appends on `ratio >= last_ratio` at the same block, where the scan's strict `<`
would find an earlier position.

Verified against erigon's real `Insert` compiled and run under Go 1.23 over the
same 200,000 sequences:

```
erigon MsgIndex.Insert (reference) : 14248539691690691664
reth, after fix                    : 14248539691690691664   match
reth, sort.Search port (§11)       : 11128719865354962318   differ
reth, partition_point (§10)        :  1127759515664285576   differ
```

Also added: `insert_matches_erigon_test_insertion_vector`, a direct replay of
erigon's own `TestInsertion` from `message_index_test.go`. Its expected orders
are erigon's assertions, copied rather than derived — the one test here whose
correctness does not depend on this audit's reasoning being right.

That test passes under all three implementations, and that is worth stating
plainly rather than hiding: every message in erigon's suite shares one work
multiplier and divisor, so all ratios are equal, the comparator collapses to
`block <`, and the predicate is monotonic. It pins the comparator and the
tie-break, not the search. **Erigon's own test suite cannot detect this bug
class.** The two tests that can (`insert_position_matches_erigon_on_deep_board`,
`insert_order_matches_erigon_insert_over_200k_sequences`) were both verified to
fail against the §11 implementation.

**The lesson, for the third round running.** §11.3 diagnosed a test too small to
falsify its claim. §12.1 caught a test comparing a constant against itself. This
is the same failure at the level of the reference: the differential harness was
sound, the corpus was large, the negative control fired — and all of it
validated reth against a Go program encoding this document's assumption. A
differential test is worth exactly what its reference is worth. Locate the
reference source before writing the harness; if it cannot be found, that is the
finding, and the work stops there rather than proceeding on a reconstruction.

### 13.2 §12.9 resolved — the unchunked request frame is erigon's behavior

Erigon's `BOARD_MESSAGE_IDS` handler (`fetch.go`) filters the announced IDs
through `FilterMessageIDs` and sends the result as a single
`SendMessageById(GET_BOARD_MESSAGES, FlattenMsgIDs(mIDs))`. **No chunking**, no
cap — identical to reth, including requesting only the wanted subset (which
§12.7's partial-sync test already locks).

So the 242,001-byte request frame §12.9 measured is at parity, not a reth
divergence, and there is nothing to fix unilaterally. It remains a real
weakness in the protocol as specified — both clients will send an arbitrarily
large request frame if a peer announces one — but changing it is a wire change
requiring a coordinated pulsechaincom fix, in the same bucket as the prysm
`SlashValidator` quirk. Recorded at the call site in `protocol.rs`.

### 13.3 O2 resolved — erigon's `Content` has no order to match

`MsgIndex.CategoryMsgs` ranges over `m.categories[cat]`, a
`map[MessageHash]*CheckedPoWMsg`. Go randomises map iteration order by design,
so **erigon's category-filtered `msgboard_content` returns a different order on
every call**, from the same node against the same board.

There is therefore no erigon order to match: any deterministic order differs
from erigon on nearly every call. reth returning board precedence order stands,
now as a documented deliberate divergence rather than an unverified guess. O2 is
closed.

`MsgBoard.Categories`, by contrast, **does** sort — a byte-wise ascending
`slices.SortFunc` over the hashes (`board.go:308`). O1's fix matches erigon
exactly, and `B256`'s `Ord` is the same byte-wise comparison.

### 13.4 `msgboard_content`'s range filter diverges — ✅ DECIDED: divergence accepted

Erigon's `MsgIndex.Msgs(filter)` does **not** filter per message. It seeks a
lower and an upper index and returns the contiguous slice between them:

```go
if from != 0 {
    for i := 0; i < count; i++ {
        // seek for the lower bound assuming msgs are sorted by block number
        if from <= m.msgs[i].BlockNumber { leftIdx = i; break }
    }
}
```

Two consequences, both from that comment's assumption being false — the
OR-comparator does not produce a block-sorted vec, which is the whole of §11:

1. **Out-of-range messages ride along.** Any message between the two bounds is
   returned regardless of its own block number.
2. **The filter fails open.** If no message satisfies a bound, the seek never
   fires and the index keeps its initial value (`leftIdx = 0`, `rightIdx =
   count`). A query whose range matches nothing returns **the entire board**.

Measured over randomised boards: **68% of range-filtered `msgboard_content`
queries return a different set**, and on 30% reth returns empty where erigon
returns a non-empty slice. Worked case — board holding blocks 1, 2, 3, queried
`from=10 to=20`: erigon returns all three messages, reth returns none.

**Decision: keep reth's per-message filter. Divergence accepted and
documented.** This is the one place in this document where parity loses, and
the reason it loses is that the parity argument does not reach here. M1 mattered
because eviction order is wire-observable — two nodes fed the same messages must
drop the same one, or they gossip different boards. Nothing about the range
filter is: it is a read-only RPC projection, a peer cannot observe it, and no
eviction, gossip, or PoW decision depends on it. What is on the other side of
the scale is an operator asking for blocks 10–20 and being handed the entire
board, or a range query silently including messages outside the range.

So `msgboard_content` clients that pass a block range get a narrower and correct
result from reth than from erigon. Clients that pass no range are unaffected —
`Msgs(nil)` returns `m.msgs` whole on both sides, so the common path is
identical. Any tooling that compares the two clients' `msgboard_content` output
under a block filter will see a difference, and that is expected.

**The category-filtered path is not affected.** Erigon's `CategoryMsgs` skips
per message (`if from != 0 && msg.BlockNumber < from || ...  { continue }`),
exactly as reth does, so `msgboard_content` with a category is at parity on both
ordering (§13.3, where erigon has no order to match) and filtering.

`all_msgs_filtered_filters_per_message_where_erigon_slices` pins the decision:
it asserts both halves of the divergence against erigon's answers computed in
Go, and asserts the category path stays at parity. It uses a board that is
deliberately not block-sorted (`[2, 5, 2, 5]`), since neither half of the
divergence reproduces on a sorted one — the precondition erigon's comment
assumes.

### 13.5 Still open

- §13.2's unbounded request frame — **superseded by §14.4**, which splits it
  into the serving half (fixed in §14.3) and the sending half (unchanged).
- `install` / `install_post_launch_tasks` bodies remain uncovered — unchanged
  from §12.11; they need a running node.

### 13.6 Toolchain gates — now run

Rounds 4 and 5 recorded `zepter`, `make lint-toml` and `cargo-nextest` as
skipped because none of the three were installed. All three are installed now
and have been run against this work. Recorded here so a later round does not
re-skip them or re-discover the same findings.

- **`cargo-nextest`** — 158/158 pass. Worth preferring over `cargo test` here:
  nextest runs each test in its own process, which is what
  `tests/metrics.rs` needs (§12.8 — the gauges carry no labels, so parallel
  boards in one process clobber each other's metric keys).
- **`zepter`** — reports one issue: `bin/reth`'s `asm-keccak` feature must
  propagate to `alloy-evm`. **Pre-existing and deliberately not fixed.** It
  reproduces identically on a pristine pre-msgboard checkout, and no msgboard
  commit touches `bin/reth` or the workspace `Cargo.toml`. Fixing it means
  propagating a feature into `alloy-evm` — the crate held at a valve patch so
  firehose can trace system calls — which is exactly the surface where a
  careless feature change silently gutted tracing before. It wants a
  deliberate look, not a lint-driven reflex.
- **`make lint-toml` (dprint)** — the msgboard `Cargo.toml`s are already
  clean; the round-4 `metrics-util` dev-dependency needed no reformatting. The
  only file dprint wants to change is the workspace `Cargo.toml`, which is
  pre-existing drift unrelated to msgboard. Note for whoever installs it:
  `cargo install --locked dprint` **fails on arm64 macOS** with an unresolved
  liblzma symbol at link time; `brew install dprint` works.

  Same caveat applies to `cargo +nightly fmt --all`, which rewrites eight
  unrelated files. Both tools produce ~10 files of churn on a repo-wide run, so
  scope them to the crates you touched (`cargo +nightly fmt -p reth-msgboard
  -p reth-msgboard-types --check`) rather than running them workspace-wide and
  committing the result.

---

## 14. Round-6: three issues raised by the team

**Audit date:** 2026-07-28
**Trigger:** team report of (1) difficulty overflow, (2) multiplier/divisor
comparison via float, (3) unlimited message requests over the `GetBoardMessages`
P2P packet.

All three are real. **None is a reth-vs-erigon divergence** — (1) and (3) are
vulnerabilities reth inherited by matching erigon faithfully, and (2) is the one
place reth had already diverged in the safe direction. Each is backed by a test
that asserts the *current* behavior, so each fails the day it is fixed.

### 14.1 Difficulty overflow — free `PoW`, and it outranks honest messages — ✅ FIXED

`PoWMsg::difficulty` is erigon's expression in wrapping `u64`:

```text
difficulty = (2^24 + size × 10_000) × work_multiplier / work_divisor
```

`work_multiplier` and `work_divisor` are **attacker-chosen wire fields**. Write
`base = 2^24 + size × 10_000` as `2^k × odd`. Because `odd` is invertible mod
`2^64`, an attacker can solve `base × multiplier ≡ 2^k (mod 2^64)` and then set
`divisor = 2^k`, giving `difficulty == 1`.

The `PoW` check is `hash % difficulty == 0`. **Every hash is divisible by 1**, so
any nonce is a valid solution and the message costs *zero* work. The
`difficulty == 0` guard does not help: 1 is as free as 0 and passes it.

Worked example for a 1-byte message (`base = 16_787_216 = 2^4 × 1_049_201`):

| Field | Value |
|---|---|
| `work_multiplier` | `1014806211241672337` |
| `work_divisor` | `16` |
| `difficulty()` | **1** (honest message of the same size: 167,872) |
| clears `is_work_acceptable`? | **yes** |
| declared ratio | `6.34e16` — 6.3e18× the honest `0.01` |

The second row of that table is the part that turns a spam vector into a board
takeover. The minimum-work gate constrains the *declared ratio*
(`multiplier / divisor`), while the wrap decouples that ratio from the
difficulty actually enforced. Passing the gate requires a *large* ratio, and
board precedence is `(block, difficulty_ratio)` ascending with `evict_oldest`
popping `msgs[0]` — so the free messages sort to the **top** and the honest ones
are what get evicted.

Before the fix this was demonstrated end to end: four messages with `nonce: 1`
and no mining were accepted (`accepted == 4`, `kickable == 0` — the sender was
not even penalised), and both honest mined messages were gone from the board.

#### Fixed — accepted wire divergence

pulsechaincom is already aware of the issue, so reth no longer waits on a
coordinated fix. `PoWMsg::difficulty_checked` computes the threshold exactly in
`u128` and returns `None` when the true value exceeds `u64::MAX` (or when
`work_divisor` is zero, which previously made this a potential division-by-zero
panic on any caller reaching it before `validate`).

Rejection happens in two places:

- `to_checked` — the choke point every `CheckedPoWMsg` passes through, so no
  code path can construct one from an overflowing message. Returns
  `InvalidDifficulty`; in `add_remote_msgs` that counts as **kickable**, so the
  sender now takes a reputation hit instead of getting free board space.
- `validate` — the decode boundary, so a crafted message dies before the
  secp256k1 scalar multiplication the `PoW` check would otherwise pay for. This
  matters independently of the spam vector: without it, the cheapest way to burn
  a reth node's CPU was to send messages that fail `PoW` expensively.

`difficulty()` is kept as a total `u64` accessor that saturates to `u64::MAX`,
for display and logging only. Verification does not use it.

**What this costs.** Strict wire parity: reth now rejects messages erigon
accepts. Every such message is one whose exact `base × multiplier / divisor`
exceeds `u64::MAX` — declared work that no hash could legitimately satisfy, and
which only erigon's wrap made look cheap. No honest client produces one; the
crafted example's true threshold is ≈2^80. An erigon peer that relays such a
message to reth will see it rejected and be penalised, which is the intended
outcome. Honest messages are bit-identical before and after
(`honest_parameters_are_unchanged_by_the_exact_computation`).

**Tests.** `pow::difficulty_overflow_regression` (the crafted parameters over 64
nonces, plus proof that the minimum-work gate is *not* what rejects them, plus
the honest-path no-op) and
`board::tests::zero_work_messages_are_rejected_and_honest_ones_survive`
(`accepted == 0`, `kickable == 4`, honest messages untouched). The two
`test_difficulty_*` tests from §12.4 that pinned the wrap were inverted rather
than deleted, so the behaviour they used to guarantee cannot come back silently.
All four were verified to fail against a restored wrapping implementation.

### 14.2 Multiplier/divisor via float — reth already avoids it where it counts

Erigon compares work ratios as `float64` in both places it gates on them
(`board.go:139` computes `minDifficultyRatio` as `float64(cfg.WorkMultiplier) /
float64(cfg.WorkDivisor)`; lines 233 and 392 compare against it).

**reth does not.** `MsgboardConfig::is_work_acceptable` cross-multiplies in
`u128`:

```rust
(multiplier as u128) * (self.work_divisor as u128) >=
    (self.work_multiplier as u128) * (divisor as u128)
```

This is exact for all `u64` inputs — no rounding, no `2^53` mantissa cliff — and
it is the function used by *both* gates: `filter_wanted` (the announce filter,
erigon's line 233) and the board's add path (erigon's line 392). So the float
comparison the team asked about is not in reth's accept/reject path at all.

Float survives in exactly one place: `PoWMsg::difficulty_ratio`, used by the
insert comparator. That one is **parity-required** — erigon's `DifficultyRatio()`
is `float64`, and the comparator's output is wire-observable through eviction
(§13.1). Rust and Go both do IEEE-754 round-to-nearest-even for `u64 → f64` and
for division, so the values are bit-identical and this introduces no divergence.

Residual risk is confined to ordering: two distinct `(mult, div)` pairs above
`2^53` can round to the same `f64` and compare equal where exact rational
arithmetic would order them. That is erigon's behavior too, so changing it would
be a divergence. Worth noting only because it interacts with §14.1 — an attacker
exploiting the overflow gets an enormous ratio, and where it lands among other
enormous ratios is float-determined.

No change made. The reth-vs-erigon difference in `is_work_acceptable` (exact vs
float) is a pre-existing divergence in reth's favour; it can only ever *reject*
a message erigon accepts by a margin under one `f64` ulp, which no honest client
produces.

### 14.3 Unlimited `GetBoardMessages` requests — 68× reflection amplification — ✅ FIXED

§13.2 established that neither client chunks or caps the **request**. The
consequence on the responder is worse than the frame size alone suggests,
because the handler also does **not deduplicate**:

```rust
let msgs = board.get_messages_for_ids(&ids);   // maps each ID independently
```

Erigon's arm is the same shape — `for _, mID := range mIDs { ... append }` — so
one ID repeated N times is served N times, by both clients. An attacker needs to
know only a *single* message on the board.

Measured by `protocol::tests::get_board_messages_serves_duplicate_ids_without_dedup_or_cap`,
with one 8 KiB message (the default `size_limit`) and 500 repeats of its ID:

| | |
|---|---|
| request | 60,501 B |
| response | 4,135,710 B |
| **amplification** | **68×** |

68× is just `size_limit / MSG_ID_SIZE` = `8192 / 121`, and it scales linearly
with the repeat count: nothing bounds the request, so nothing bounds the
response. The board also does not rate-limit per peer, so this can be repeated
continuously on one connection.

#### Fixed — dedup plus a one-frame cap

`handle_incoming` now deduplicates the requested IDs and honours at most
`MAX_IDS_PER_FRAME` (= `P2P_MSG_PACKET_LIMIT / MSG_ID_SIZE` = 846) distinct IDs
per request. That constant is now shared with `send_board_message_ids`, which
previously computed the same expression inline for the announcement chunk size —
the two are the same number for a reason, and the shared const records it.

**Why this is invisible to a conforming peer.** A request is built from a single
inbound announcement; both clients announce in `MAX_IDS_PER_FRAME` chunks; and
`filter_wanted` returns a *subset* of what was announced. So no honest peer can
construct a request that reaches either limit. A peer that does is malfunctioning
or probing, and gets a truncated response with a debug log rather than a
reputation penalty — neither client documents a bound it could have respected, so
penalising would punish behaviour that was legal until this change.

**What it does and does not buy.** Dedup is the substantive half: it removes the
cheap attack entirely, since an attacker must now know N *distinct* live message
IDs to draw N messages, rather than repeating one. The 68× ratio itself is
inherent to the protocol — a 121-byte ID names an up-to-8 KiB message — and is
unchanged for a request of distinct IDs. What the cap adds is an absolute bound:
one request can now provoke at most ~6.9 MB instead of an unbounded response.
Sustained abuse across many frames is a rate-limiting problem, which neither
client does and which is not addressed here.

**Tests.** `get_board_messages_deduplicates_repeated_ids` (500 repeats of one ID
now serve one message, and the response is *smaller* than the request rather than
68× larger), `get_board_messages_caps_distinct_ids_at_one_frame` (a request of
`MAX_IDS_PER_FRAME + 50` distinct IDs serves exactly one frame's worth), and
`an_honest_request_is_served_in_full` (an ordinary five-ID request is unaffected).
Both guards were verified to fail against the pre-fix handler; the honest-path
test correctly passes under both, which is what makes it a control rather than a
duplicate.

### 14.4 Still open

- §13.2's unbounded request frame (the **sending** half) is unchanged: reth still
  emits a request as large as the peer's announcement made it. §14.3 bounds what
  reth *serves*, not what it asks for. A peer that announces a huge frame gets a
  huge request back — harmless against erigon, which does not cap either, and
  self-limiting in practice since the request is a subset of the announcement.
- Per-connection rate limiting. Both §14.3's cap and erigon's absent one bound a
  single frame; neither bounds frames per second. This is the remaining
  amplification surface and would be a genuinely new mechanism rather than a
  parity fix.

---

## 15. Round-7: the outbound queue was unbounded

§14.3 bounded what one request can make reth *serve*. It did not bound where
that response goes. The queue between the protocol handler and reth's
multiplexer was `mpsc::unbounded_channel`, so the response had somewhere
unlimited to accumulate — which is the more serious of the two, because it is
memory rather than bandwidth and any peer can trigger it.

### 15.1 Unbounded outbound queue — remote memory exhaustion — ✅ FIXED

**The defect.** `crates/net/msgboard/src/protocol.rs` created the per-connection
outbound channel with `mpsc::unbounded_channel::<BytesMut>()` and wrote to it
with `let _ = tx.send(buf)`, which never blocks and never applies backpressure.

reth's multiplexer does stop draining a protocol once its own out-buffer reaches
`MAX_MUX_OUT_BUFFER_BYTES` = 32 MiB (`crates/net/eth-wire/src/multiplex.rs:829`,
enforced at `poll_outbound_producers`). But `run_connection` kept reading inbound
frames and kept calling `tx.send()`, so the backlog simply *relocated* into
msgboard's queue and grew without limit. The multiplexer's own read loop
(`multiplex.rs:641-680`) runs before its `if !conn_ready` exit at `:685`, so it
keeps draining the socket even while the outbound sink is fully stalled.

**Why reth's own `eth` path is immune.** `crates/net/network/src/session/active.rs`
caps `MAX_QUEUED_OUTGOING_RESPONSES` at 4 (`:84`) and `break`s out of its receive
loop when exceeded (`:894`, `:904`). reth then stops reading the socket, the TCP
window closes, and the peer throttles itself. Those counters are fed only from
`EthMessage` handling (`:181`, `:258-278`), so under a msgboard-only flood they
stay at zero and the throttle never fires. `RECEIVE_MESSAGE_BUDGET` = 16 (`:97`)
counts `poll_next` *calls*, and one call drains the whole socket buffer, so it
bounds nothing here either.

**The attack.** Open one connection, send `GetBoardMessages` continuously, never
read. TCP is full-duplex, so the send direction stays open. Our send buffer
fills, the mux out-buffer pins at 32 MiB, and msgboard's queue grows at
(request rate × amplification).

Two numbers, and it is worth not confusing them the way an earlier draft of this
section did:

- The **ratio** is `encoded_message_size / MSG_ID_SIZE` — the same 68× §14.3
  measured, since it is the same quantity. It does **not** require a large
  request. After §14.3's dedup, a 122-byte request naming *one* known 8 KiB
  message draws one ~8.3 KiB frame: still 68×. **The attacker needs one live
  message ID, not 846**, and a node hands its entire ID set to any peer on
  connect (`send_board_message_ids`). So ~15 MiB of attacker traffic queues
  ~1 GiB.
- The **per-request ceiling** is 846 × 8 KiB ≈ 6.6 MiB, which is where
  `MAX_IDS_PER_FRAME` and a 102 KiB request frame come in. That bounds one
  response, not the ratio.

Both figures assume the board actually holds max-`size_limit` messages — the
ratio tracks real message sizes, so on a board of small messages it approaches
1×. That condition is cheap for an attacker to arrange: the default minimum work
ratio is `10_000/1_000_000` = 0.01 (`msgboard-types/src/config.rs:71-76`), so
mining a max-size message is on the order of 10^6 nonce trials — seconds of CPU,
as the crate's own test miner demonstrates.

Parallelisable across every established `msg/1` session — 30 inbound
(`DEFAULT_MAX_COUNT_PEERS_INBOUND`) plus up to 100 outbound
(`DEFAULT_MAX_COUNT_PEERS_OUTBOUND`, `crates/net/network-types/src/peers/config.rs:11`,
`:14`).

#### Fixed — a bounded queue, an awaited send, and a deadline paid once

Three parts, and all three are needed:

1. **`mpsc::channel(MAX_QUEUED_OUTGOING_FRAMES)`**, `MAX_QUEUED_OUTGOING_FRAMES`
   = 8. Every frame we emit is at most one `P2P_MSG_PACKET_LIMIT` packet — the
   response chunker flushes *before* pushing a message that would exceed the
   limit, so it never overshoots by a whole message, and
   `get_board_messages_chunks_large_responses` now pins that at
   `P2P_MSG_PACKET_LIMIT + 8` bytes because this arithmetic depends on it. So
   msgboard's per-peer outbound memory is ~800 KiB.
2. **Sends are awaited.** `handle_incoming` and `send_board_message_ids` became
   `async`. Because they run in the same task as the read loop, a full queue
   stops us pulling the next frame off `ProtocolConnection` — which is what
   actually stops the backlog, rather than moving it. Honest bursts exceed 8
   frames (a bulk announce is `count_limit / 846` = 12 at the default; one full
   response is up to ~69) and that is fine: a peer that reads drains as fast as
   we fill.
3. **A deadline, `OUTBOUND_SEND_TIMEOUT` = 30 s, paid once per stalled peer.**
   When it expires the rest of that frame's output is dropped, the peer is
   marked stalled on its [`OutboundQueue`], and until it accepts a frame again
   we drop without waiting. The flag clears on the first successful send.

Part 3 is not optional, and it is the part the original write-up missed. The
multiplexer's inbound queue to a satellite protocol is itself an **unbounded**
channel (`multiplex.rs:289`, `install_protocol`) that it keeps filling from the
socket regardless of what we do. Waiting indefinitely on part 2 would therefore
relocate the unbounded growth *upstream* rather than remove it — the attacker
would need 1 byte sent per byte queued instead of 1 per 68, which is a 68×
improvement but not a fix.

**The scoping of that deadline matters more than its value, and two earlier
versions of it were wrong.** Both were caught by adversarial review, and each
now has a test:

- *Per send.* Serving one request emits dozens of chunks, so one request could
  hold the read loop for `chunks × 30 s`. Measured at 60 s over a 3-chunk
  response. Fixed by sharing one deadline across everything emitted for a single
  inbound frame (`frame_deadline`), pinned by
  `one_inbound_frame_stalls_the_read_loop_for_at_most_the_timeout`.
- *Per inbound frame.* Still wrong, and worse, because a flooding peer sends
  many frames: each got a fresh 30 s budget against a queue that never drains,
  so the read loop advanced **one frame per 30 s** — about 3 KiB/s — while the
  mux filled its unbounded inbound queue at the peer's line rate. Measured at
  300 s for 10 frames. That is the same outcome as waiting forever, so the fix
  was not achieving what this section originally claimed for it ("dropping keeps
  that queue drained" — it did not). Fixed by the stalled flag, pinned by
  `a_flooding_peer_cannot_throttle_our_read_loop_frame_by_frame`.

With the flag, a peer that has stopped reading costs one 30 s wait for the whole
episode, after which we drain `ProtocolConnection` at full speed and simply drop
what it will not take. An honest peer that is merely slow never sets the flag —
it is waited on and loses nothing.

Dropped frames are counted by the new `msgboard.outbound_dropped` counter.
Nothing is lost that the peer was going to receive: it is not reading.

**Tests** (`protocol.rs`, each verified to fail with its fix reverted):

| Test | Property | Negative control |
|---|---|---|
| `the_outbound_queue_is_bounded` | queue capacity is `MAX_QUEUED_OUTGOING_FRAMES`, and `OUTBOUND_SEND_TIMEOUT` ≤ 60 s | — (structural) |
| `a_full_outbound_queue_makes_the_handler_wait_instead_of_buffering` | handler parks on a full queue and resumes one frame at a time as the mux drains | `try_send` → completes on first poll |
| `a_peer_that_stops_reading_gets_frames_dropped_not_queued_forever` | terminates; nothing beyond capacity accumulates | plain `tx.send().await` → test hangs, SIGTERM |
| `one_inbound_frame_stalls_the_read_loop_for_at_most_the_timeout` | total wait for one inbound frame ≤ `OUTBOUND_SEND_TIMEOUT` | per-send deadline → 60 s |
| `a_flooding_peer_cannot_throttle_our_read_loop_frame_by_frame` | 10 frames from a non-reading peer cost ≤ 2 × the timeout, not 10 × | stalled flag disabled → 300 s |
| `a_peer_that_resumes_reading_is_waited_on_again` | the stall clears on the first accepted frame, so the peer is waited on again | flag never cleared → handler no longer parks |
| `a_closed_outbound_queue_reports_the_connection_gone` | `Sent::Closed` propagates so `run_connection` exits | — |

The magnitude of `OUTBOUND_SEND_TIMEOUT` is pinned in
`the_outbound_queue_is_bounded` rather than in the timeout tests: those pass for
*any* finite value, because `start_paused` auto-advances to whatever deadline is
registered.

### 15.2 A response byte ceiling — evaluated and **rejected**

The original plan paired the bounded queue with a per-response byte ceiling
analogous to reth's `SOFT_RESPONSE_LIMIT` = 2 MiB
(`crates/net/network/src/eth_requests.rs:64`), on the reasoning that
`MAX_IDS_PER_FRAME` caps request *items* and nothing caps response *bytes*.

It is not worth having, for two reasons:

- **There is no attacker-controlled quantity left to bound.** Response bytes are
  already bounded by `MAX_IDS_PER_FRAME × size_limit` = 846 × 8 KiB ≈ 6.9 MB.
  `size_limit` is local operator config, not something a peer can influence, and
  §14.3 already caps the item count. A ceiling would only defend against our own
  misconfiguration, and the queue bound in §15.1 caps memory regardless of how
  large a single response is.
- **It would silently lose messages.** A ceiling below ~6.9 MB truncates honest
  responses: on first connect to a peer with a full board of 8 KiB messages, the
  first 846-ID request legitimately draws the whole ~6.6 MB. Truncated messages
  are not re-requested on any timer — reth requests only in response to an
  announcement, and a new-message announcement carries just the one new ID — so
  they would linger unfetched until a reconnect or a broadcast `Lagged`.

Recorded here so the next round does not re-derive it. The bound §15.1 provides
is the one that matters.

### 15.3 The request frame is now chunked — §14.4's first item closed

§13.2 established that erigon's `BOARD_MESSAGE_IDS` arm sends the filtered ID
list as one unchunked `SendMessageById`, and concluded reth should match. §14.3
then capped reth's *responder* at `MAX_IDS_PER_FRAME` distinct IDs per request —
and that combination is lossy in a way neither section noticed: **a reth node
asking a reth node for more than 846 IDs in one frame silently never receives the
overflow.** The responder truncates, and nothing re-requests.

`handle_incoming` now chunks the outbound `GetBoardMessages` at
`MAX_IDS_PER_FRAME`, the same constant the announcement path and the responder
cap already use. Against erigon this is invisible — it serves each frame
independently and has no cap of its own. Against reth it is the difference
between converging and not. It also removes the last outbound frame whose size
was set by the peer rather than by us, which is what makes the §15.1 memory
arithmetic hold: without it, one frame could be as large as the peer's
announcement.

No honest peer is affected either way: both clients announce in 846-ID chunks,
and `filter_wanted` returns a subset, so a request over the cap cannot arise from
a conforming announcement.

**Tests.** `requests_are_chunked_at_one_frame_of_ids` (a single announcement of
`MAX_IDS_PER_FRAME + 54` wanted IDs produces 846 + 54, in order, nothing
dropped) and `every_announced_message_transfers_when_one_frame_announces_more_than_the_cap`
(the same case end-to-end against a real responder — every message transfers).
Both fail against the unchunked handler.

### 15.4 Correction to §14.3's lock-contention note

An earlier pass flagged `get_messages_for_ids` (`board.rs`) as holding the shared
`Mutex<BoardState>` while cloning "up to ~6.6 MiB of `PoWMsg`", making request
volume a lock-contention vector. That overstates it: `PoWMsg::data` is
`alloy_primitives::Bytes`, which is reference-counted, so the clone is a refcount
bump and a ~96-byte struct copy — about 81 KiB of memcpy for a full 846-message
request, not 6.6 MiB. The message bodies are never copied. No change made.

### 15.5 Still open

> **Production evidence, 2026-08-07.** The two items below that are deferred
> "pending a production signal" were checked against seven days of fleet
> telemetry rather than left as an intention. Across `direct-{a,b}-evm-{1,369,943}`:
>
> | counter | `max_over_time(...[7d])` |
> |---|---|
> | `reth_msgboard_outbound_dropped` | **0** on every box |
> | `reth_msgboard_requests_truncated` | **0** on every box |
> | `reth_msgboard_bad_protocol` | **0** on every box |
>
> So no peer has saturated the bounded queue, none has exceeded
> `MAX_IDS_PER_FRAME`, and none has sent a malformed frame. Every trigger
> condition named below is measurably absent, which is the reason these stay
> unbuilt — building per-connection rate limiting now would add a false-positive
> risk to a network-facing subprotocol to solve a problem with no evidence of
> existing.
>
> The counters were previously unwatched, so "revisit if it goes non-zero" had
> no mechanism. Two Prometheus alerts now carry it (monorepo
> `deploy/monitoring/valve.rules.yml`, group `valve-fleet-reth`):
> `MsgboardOutboundDropped` and `MsgboardBadProtocol`, both `warning` — a
> non-zero counter means the queue bound *worked*, not that anything is down.
> Verified against live Prometheus: the expressions match five real series and
> currently return empty, so they can fire but are not firing.
>
> `direct-b-evm-1` is absent from those five: it still runs a build predating
> the counters (added in `5d238f5f85`). See `progress.txt`.
>
> Re-announcement (fourth bullet) got a partial answer too: `943a` shows 428
> `announcements_received` against 5 `requests_sent`, so `filter_wanted` is
> rejecting essentially all of it. The avoidable-work path is real but is not
> costing anything measurable in practice.

- **Per-connection rate limiting** (carried over from §14.4). §15.1 bounds
  memory and bounds how long one inbound frame can stall the reader; neither
  bounds frames per second. `reth_tokio_util::ratelimit::{Rate, RateLimit}`
  exists (`crates/tokio-util/src/ratelimit.rs`) but is used only by DNS
  discovery, so using it here would be unlike reth's convention.
- **No volume-based reputation anywhere in reth.** `eth_requests.rs:76-79` holds
  a `PeersHandle` behind `// TODO use to report spammers` and
  `#[expect(dead_code)]` — reth's own request handler intended to punish spammers
  and never wired it up. A peer that saturates a *bounded* queue is a stronger
  signal than anything available before §15.1, so escalating
  `outbound_dropped` to `report_bad_protocol` is now defensible. Deliberately not
  done here: sustained backpressure can also mean a congested link or our own
  slow uplink, and disconnecting an honest slow peer is worse than dropping
  gossip it was not reading. Revisit if `outbound_dropped` is non-zero in
  production against peers that are otherwise healthy.
- **The multiplexer's inbound `to_satellite` queue is unbounded** upstream
  (`multiplex.rs:289`). §15.1 bounds our exposure to it but cannot remove it.

  An earlier draft said a satellite protocol "has no way to stop the multiplexer
  reading the socket". That is overstated, and the correction matters because it
  is the design alternative we did not take. There **is** a lever: if the
  satellite's stream ends, `poll_outbound_producers` returns
  `ProducerPoll::Closed` (`multiplex.rs:565`) and `RlpxSatelliteStream::poll_next`
  returns `Ready(None)`, which disconnects the session — permanently stopping the
  socket read. For msgboard that is one line: return from `run_connection`. The
  accurate statement is that there is **no backpressure lever short of dropping
  the whole connection**, eth session included.

  We deliberately do not take it. The trigger — "this peer has not accepted a
  frame in 30 s" — is not specific to abuse; a congested uplink produces the
  same signal, and a node whose own upstream is saturated would mass-disconnect
  otherwise-healthy peers over a msgboard-only condition. Dropping gossip is the
  proportionate response; dropping the peer's block sync is not. Reconsider only
  if `outbound_dropped` shows sustained stalling from peers that are otherwise
  fine.
- **`BOARD_MESSAGE_IDS` re-announcement.** `filter_wanted` rejects only IDs
  already in the index, so a peer repeating the same announcement gets a fresh
  full-size request every time. Bounded by §15.1 and 1:1 in bytes, so not
  amplifying, but it is avoidable work.

### 15.6 Upstream prior art — this was reported, and rejected

The unbounded `to_satellite` queue in §15.5 is not an unnoticed corner of reth.
It was reported twice, and both reports were closed unmerged:

| PR | What it proposed | Outcome |
|---|---|---|
| [#18702](https://github.com/paradigmxyz/reth/pull/18702) (2025-09-25) | `to_primary` **and** `to_satellite` → `mpsc::channel(256)`, `try_send` with drop-on-`Full`, `ReceiverStream`, `send().await` during the handshake | Closed unmerged 2025-09-26 |
| [#18739](https://github.com/paradigmxyz/reth/pull/18739) (2025-09-26) | Primary path → `mpsc::channel(1024)`, same shape | Closed unmerged two minutes after opening |

#18702's diff is essentially the fix §15.5 asks for. The only recorded rationale
is a one-line review from mattsse: *"this has been working fine"*. No technical
objection was given. Both submitters look like drive-by contributors (adjacent
account IDs, `patch-6`/`patch-8` branches), which plausibly explains a summary
close — but the idea was not engaged with on merit.

Eight months later the same maintainer opened
[#25031](https://github.com/paradigmxyz/reth/pull/25031) — "fix(rlpx): bound mux
outbound buffer fairly", labelled `C-bug`, merged 2026-06-09 — which added the
32 MiB `MAX_MUX_OUT_BUFFER_BYTES` cap that §15.1's attack relocates into. So the
**outbound** half was independently rediscovered and shipped as a bug fix; the
**inbound** half is still `mpsc::unbounded_channel()` on `main` today.

Two consequences for us:

1. **Do not wait for upstream.** Nothing is in flight on the inbound half, and
   the one serious attempt was closed without a counter-argument. §15.1's
   stalled-flag design has to stand on its own.
2. **If this is reported upstream, it goes to security@tempo.xyz**, per reth's
   one-line `SECURITY.md` — not a public issue or PR. A public "here is how to
   grow an unbounded queue on any reth node running a subprotocol" is a
   disclosure in itself.

### 15.7 msgboard deviated from reth's documented subprotocol pattern

Worth recording as the actual root cause, because an earlier draft of this
analysis got it backwards and claimed reth's own example carries the same bug.
It does not.

`examples/custom-rlpx-subprotocol/src/subprotocol/connection/handler.rs` does
call `mpsc::unbounded_channel()` in `into_connection`, but that channel carries
`CustomCommand` — *locally issued* commands, handed out via
`ProtocolEvent::Established { to_connection }`. **A peer cannot enqueue into it.**
Peer-provoked responses are generated lazily inside
`CustomRlpxConnection::poll_next` (`connection/mod.rs:35-75`): a `Ping` is turned
into a `Pong` and returned as `Poll::Ready(Some(..))`, one at a time, and
`conn.poll_next_unpin` is only called when the multiplexer polls the stream. When
the mux stops polling, the example stops reading and stops producing. That is
backpressure by construction. The in-tree test protocol
(`crates/net/network/tests/it/multiplex.rs`) has the same shape.

msgboard instead spawns a task that reads `ProtocolConnection` on its own
schedule and pushes peer-provoked responses through a channel. That decoupling
is what made an unbounded queue reachable — the producer no longer stops when the
consumer does. The bounded queue plus the stalled flag reintroduce the coupling
the lazy-stream pattern gets for free.

The lesson generalises: a satellite protocol that buffers peer-provoked output
must bound that buffer itself, because the multiplexer's cap protects the
multiplexer, not the protocol.

---

## 16. Round-8: nine out of ten requests were for messages we were already fetching

### 16.1 The measurement

§15.5 closed with `BOARD_MESSAGE_IDS` re-announcement listed as "avoidable work"
and left it there, because nothing measured it. The counters on the fleet
(2026-08-17, taken directly off `:9001/metrics`) do measure it:

| box | `requests_sent` | `accepted_remote` | `skipped_duplicate` | uptime |
|---|---|---|---|---|
| `direct-a-evm-943` | 445 | 45 | **400 (90%)** | 2h14m |
| `direct-a-evm-1` | 65 | 1 | **64 (98%)** | 9m |
| `direct-a-evm-369` | 0 | 0 | 0 | — |

Nine out of ten messages the board asked for, it already had.

### 16.2 Why it happens

`filter_wanted` (`board.rs`) rejected an announced ID only once that ID was **in
the index**, which happens after the reply arrives and its `PoW` verifies. There
was no in-flight set. Between sending a request and inserting the reply, every
other peer announcing the same ID still read as wanted.

Gossip guarantees that window is crowded: every peer announces every message. So
N peers announcing one new message bought N requests, N replies, and N secp256k1
scalar multiplications, to keep one copy.

This is not §15.5's re-announcement bullet, which is about a single peer
repeating an announcement. It is the multi-peer convergence case, and it is
structural rather than adversarial — the honest protocol produces it.

### 16.3 Why the fix cannot live in verification

The obvious fix — dedupe before the `PoW` check in `add_remote_msgs` — is
impossible. A message's index key is its `PoW` hash:

```text
hash = sha256(challenge ‖ category ‖ data)
challenge = x-coordinate of G × scalar
```

`challenge` **is** the elliptic curve point. Nothing can look a message up
without first paying for the exact computation the lookup would avoid. The order
inside `add_remote_msgs` is already optimal: the cheap field checks and the block
lookup run first, and `insert_checked`'s duplicate check cannot be hoisted above
`to_checked` because it has no key to work with until `to_checked` returns.

The only place to spend less is upstream of the request.

### 16.4 The fix

`PendingRequests` (`crates/net/msgboard/src/pending.rs`) tracks claimed IDs with
a TTL. `filter_wanted` claims what it returns, so the second peer to announce a
message in flight is not asked.

Three properties matter, and each is the reason for a test:

- **Claims expire** (`PENDING_REQUEST_TTL`, 10s). A peer that never answers must
  not hold a message hostage. Ten seconds is well above any RTT and under 1% of
  the ~20 minute window in which the message stays fetchable.
- **Claims are released on a failed send.** `filter_wanted` claims optimistically,
  before the frame reaches the peer. A dropped or closed frame hands its claims
  back (`release_pending`), or the message stalls for the full TTL while every
  peer announcing it stays suppressed.
- **The map fails open at `MAX_PENDING_REQUESTS`** (8192, ≈1.3 MB). IDs are
  peer-supplied and pass `filter_wanted` on declared fields alone, so a peer can
  mint unlimited IDs anchored to a live block. Past the cap the tracker grants
  claims without recording them: the request goes out and deduplication stops.
  Failing open costs the duplicate requests this exists to avoid; failing closed
  would let a flood of synthetic IDs suppress real ones, which is worse.

### 16.5 What to watch after deploy

Two new metrics:

- `reth_msgboard_requests_suppressed` — requests not made. Read against
  `skipped_duplicate`, which counts the duplicates that still get through. On the
  numbers in §16.1 this should absorb most of the gap between `requests_sent` and
  `accepted_remote`.
- `reth_msgboard_pending_requests` — gauge of live claims. Near zero in steady
  state. **Pinned at 8192 means the tracker is failing open** and suppression has
  stopped; that is the signal to look for a peer minting synthetic IDs.

A `requests_suppressed` stuck at zero after deploy means the tracker is not
running, not that there is nothing to suppress.

### 16.6 Honest accounting of the win

The CPU saving is negligible and should not be the justification. 400 scalar
multiplications over two hours is microseconds of work. What the change actually
buys is roughly a 10× cut in request frames on `943a`, and the removal of a lever
where announcement volume multiplied into request volume with nothing bounding
the ratio. §15.5's per-connection rate limiting stays unbuilt — `outbound_dropped`,
`requests_truncated` and `bad_protocol` are all still flat 0.

### 16.7 Still open

- The §15.5 items are unchanged: per-connection rate limiting, the multiplexer's
  unbounded inbound `to_satellite` queue, and volume-based reputation. All three
  still lack a production signal, and the alerts added in §15.5 remain the
  mechanism that would produce one.
- Erigon has no equivalent of the in-flight set. This is a **reth-only
  divergence** in the same class as §14.3's request cap: invisible on the wire,
  strictly less traffic than erigon emits, and safe against either client
  because a suppressed request is one erigon would also have found redundant.

---

## 17. Round-9: the upstream spec changes the PoW construction

`specs/04-msgboard-pow-v2.md` (supplied 2026-08-18) specifies a different proof
of work. This section records what changes, what it buys, what it costs, and why
we should not ship it yet.

### 17.1 The two constructions

| step | what reth does today | what the spec specifies |
|---|---|---|
| scalar input | `nonce × sha256(M‖Div)[16..] + blockHash` | `sha256(ver ‖ blockHash ‖ payloadHash ‖ M ‖ Div ‖ nonce)` |
| out-of-range scalar | reduced `mod n` | **rejected**, try another nonce |
| point encoding | uncompressed x, 32 bytes | **compressed**, 33 bytes with parity prefix |
| payload binding | in the final hash | in the scalar, via `payloadHash = sha256(category ‖ data)` |
| work hash | `sha256(x ‖ category ‖ data)` | `sha256(compressed_point)` |
| difficulty | `(2²⁴ + 10⁴·len)·M/Div` as `u64`, wraps | same value as a bigint, no wrap |
| acceptance | `hash % difficulty == 0` (divisibility) | `hash < 2²⁵⁶ / D` (threshold) |

Every step differs. A message valid under one is invalid under the other.

### 17.2 The gain is real, and larger than the spec claims

The current scalar is **linear in the nonce**. From erigon-pulse
`msgboard/pow_message.go:174-192`, over the integers:

```text
scalar(nonce)     = nonce · digest + blockHash
scalar(nonce+1)   = scalar(nonce) + digest
G·scalar(nonce+1) = G·scalar(nonce) + G·digest
```

`digest` depends only on `workMultiplier` and `workDivisor`, which a miner holds
fixed. So `Q = G·digest` is a constant, and a miner walks the nonce space with
**one point addition** per attempt (~0.3–1 µs) where a verifier always pays a
full scalar multiplication (~60–120 µs). Verified numerically against the
reference inputs: the incremental walk reproduces the full scalar multiplication
exactly.

The PoW therefore costs a competent miner **50–500× less than its difficulty
parameter implies**. Spam resistance is deflated by that factor.

There is a second, larger amplification. `challenge()` reads only `Nonce`,
`WorkMultiplier`, `WorkDivisor` and `BlockHash` — it never touches `Category` or
`Data`, which enter only afterward at `pow_message.go:170`. So one challenge
table `P(1), P(2), …` is **shared by every message in the same block at the same
difficulty**. An attacker builds it once and then mines unlimited distinct spam
messages with pure SHA-256 and no further elliptic-curve work: for K messages the
EC cost is O(N), not O(K·N).

The new construction kills both. `scalar = sha256(… ‖ nonce)` is not additively
homomorphic, so consecutive scalars are unrelated and each attempt needs its own
scalar multiplication; and because the scalar commits to `payloadHash`, every
message body gets its own sequence.

A residual 2–5× miner edge remains — a miner can use a fixed-base comb where the
verifier uses the generic constant-time path, and can batch-invert across
attempts. That is an implementation artifact common to every EC-based PoW, not an
algebraic break.

### 17.3 Two of our own divergences disappear

**§14.1's overflow exploit becomes structurally impossible.** That attack worked
because `difficulty` was computed in wrapping `u64`, so an attacker could solve
`base × M ≡ 2ᵏ (mod 2⁶⁴)`, set `Div = 2ᵏ`, and wrap the threshold to 1 — free
`PoW` for any nonce. Under the spec `D` is a bigint and the target is `2²⁵⁶ / D`,
so a larger `D` makes the work *harder*, never free. There is nothing to wrap.

That also makes the minimum-work gate sound for the first time. §14.1's real
damage was that the wrap **decoupled** the declared ratio `M/Div` from the
difficulty actually enforced, so clearing `is_work_acceptable` and paying nothing
were compatible. With no wrap, `D` is monotone in `M/Div` and the gate constrains
what it appears to constrain.

Adopting therefore lets us drop the §14.1 fix, its
`rejected_invalid_difficulty` counter, and the wire divergence it created.

**Our `mod n` reduction is already wrong.** `pow_scalar()`
(`crates/net/msgboard-types/src/pow.rs:261-290`) reduces the scalar modulo the
curve order. The Go does **not** — it passes the raw sum to `ScalarBaseMult`,
whose binding rejects an out-of-range scalar
(`secp256k1@v1.0.0/ext.h:115-117`: `if (overflow || is_zero) ret = 0`). The spec
states the rule explicitly: *"Reject rather than reduce: must match Go's
secp256k1 ScalarBaseMult behavior."* About 2⁻⁶⁴ of block hashes are affected, so
this is a conformance gap rather than a live exploit — but it is a real one, and
it exists today, independent of whether we adopt the new construction.

### 17.4 The cost, and why we must not ship it yet

**The network is still on the old algorithm.** Fleet counters, 2026-08-18:

| box | `accepted_remote` | `rejected_invalid_pow` |
|---|---|---|
| `direct-a-evm-943` | 45 | **0** |
| `direct-a-evm-1` | 1 | **0** |

We are accepting peer messages and rejecting none. If peers had switched, every
message would fail our verification and `rejected_invalid_pow` would climb.
Shipping the new construction now would isolate our nodes from the live board
completely — every inbound message rejected, every outbound message refused.

**No reference for the new algorithm exists anywhere.** Not "we lack access" —
it has not been written. Three independent checks agree:

- the erigon-pulse checkout (`v3.0.0-RC8`) implements the old construction in all
  3 distinct historical versions of `pow_message.go`, across all 26 refs that
  contain it, and the `TestPoWGoldenVector` the spec cites **does not exist** in
  any of them;
- every published `@pulsechain/msgboard` release, 0.0.17 through 0.0.28,
  implements the old construction — `challenge.getX()`, `hash % difficulty === 0n`;
- `gitlab.com/pulsechaincom/msgboard`, which the spec names as the TypeScript
  reference, has had **no push in four months** (checked by the team, 2026-08-19).

So the spec is a **design document, not a description of shipped code**. Its
citations are forward-looking: it points at `pow_message.go`, `board_test.go` and
`TestPoWGoldenVector` as if they already describe the new construction, and none
of them does.

That matters more than it sounds. `msgboard-erigon-parity-method` records two
audit rounds that produced wrong "fixes" by reasoning from prose instead of the
Go, one of which left reth further from erigon than the code it replaced.
Implementing this from the spec's TypeScript excerpt alone would repeat exactly
that mistake, on the consensus-critical path of a network-facing subprotocol.

**Version ambiguity.** The spec says the wire *limits* are part of `msg/1` and
changing them requires `msg/2`. It says nothing about what version the new PoW
belongs to — yet two nodes both advertising `msg/1` and disagreeing about message
validity is a worse failure than a limit change. This needs an answer from
upstream before we write code.

### 17.5 Wire-limit deltas in the same spec

Independent of the PoW, the `msg/1 wire limits` section states requirements reth
does not meet:

| requirement | reth today | evidence |
|---|---|---|
| inbound packet ≤ 100 KiB | **no inbound check at all**; the real cap is `MAX_PAYLOAD_SIZE` = 16 MiB, 160× the spec | `eth-wire/src/p2pstream.rs:34`, `:501-506` |
| oversized packet → disconnect | nothing between 100 KiB and 16 MiB | as above |
| duplicate IDs in `GET_BOARD_MESSAGES` → kick | dedupes and truncates, no penalty (§14.3) | `msgboard/src/protocol.rs:553-587` |
| duplicate IDs in `BOARD_MESSAGE_IDS` → kick | **no duplicate check exists** | `protocol.rs:498` |
| `--msgboard.enabled`, off by default | no such flag; msgboard is registered unconditionally | `msgboard/src/args.rs:18-19` |

Two notes. The duplicate-kick rule inverts §14.3's stated reasoning — we declined
to penalise because *"neither client documents a bound it could have respected"*,
and this spec documents one. And the §16 in-flight tracker must **not** be
mistaken for duplicate detection: `PendingRequests` fails open at capacity by
design (`pending.rs:80-94`), so past 8192 claims a repeated ID is requested twice.

Making msgboard opt-in and off by default is a behaviour change for the existing
fleet, which runs it on.

### 17.6 Recommendation

Adopt — the security argument in §17.2 is strong and it retires two of our own
divergences — but in this order, and not before the first step:

1. **Establish the spec's provenance.** This is now the blocking question, and it
   is a human one, not a code one. Who wrote it, is it ratified, and is anyone
   upstream implementing it? Building an unratified proposal is how a network ends
   up with two incompatible things both called version 1 — and the spec keeps
   `version = 1` for the new construction, so the wire cannot tell them apart.
2. **Ask upstream the version question** in §17.4, and when mainnet switches.
   If the answer is "nobody is building it yet", then adopting means *becoming*
   the reference — see §17.7.
3. **Implement behind a switch**, with the golden vector as the acceptance test,
   both constructions compiled in and selected by message version.
4. **Fix the `mod n` reduction** (§17.3) — it is a conformance bug today and does
   not depend on any of the above. ✅ DONE, §19.
5. **Close the wire-limit gaps** in §17.5. The inbound size check is worth doing
   on its own merits regardless of this spec: 16 MiB of attacker-controlled frame
   decodes to ~138,000 IDs before anything rejects it. ✅ inbound size check DONE,
   §18. The duplicate-kick rules and `--msgboard.enabled` stay open, since both
   depend on the version question in §17.4.

Items 4 and 5 are independent of the PoW change and shipped ahead of it.

### 17.7 If we adopt, we are the reference

With no upstream implementation, "conform to the reference" is not available.
Whoever writes this first defines what the golden vector says, which changes the
job in three ways.

**Write it twice, independently.** A single implementation cannot catch a
misreading of the spec — it just encodes the misreading and agrees with itself,
which is exactly how §19.5's client bug survived a parity test built for the
purpose. Two implementations from two codebases (reth's Rust and the msgboard
repo's TypeScript), written against the spec rather than against each other, and
reconciled only at the vector, is the cheapest way to find an ambiguity. Both
codebases already exist.

**Publish the vector before flipping the fleet.** The point of going first is to
make our reading the one upstream adopts. That only works if the vector is
offered for ratification rather than discovered later as a divergence. Flipping
first and publishing afterwards gets the risk without the benefit.

**Know what we are accepting.** If upstream eventually ships a detail
differently, we redo the work and re-flip the board. That is survivable — the
board drains in 120 blocks — but it should be a decision, not a surprise.

Against that, the case for waiting is weak: the spec has sat for four months with
no code behind it, and the weakness it fixes (§17.2) is not under exploitation —
the board carries ~385 messages, almost all from our own arcade bots. Neither
shipping nor waiting is urgent. The deciding factor is whether we want to set the
spec rather than follow it.

---

## 18. Round-10: the inbound packet limit, and what it makes unreachable

### 18.1 The gap

§17.5 listed it: msgboard performed **no inbound frame-size check at all**.
`P2P_MSG_PACKET_LIMIT` (100 KiB) was used only for outbound chunking and to
derive `MAX_IDS_PER_FRAME`. The only real cap was eth-wire's `MAX_PAYLOAD_SIZE`
= 16 MiB (`p2pstream.rs:34`, enforced `:501-506`), 160× the spec — and a 16 MiB
`BOARD_MESSAGE_IDS` frame decodes to ~138,000 `MsgID`s before anything rejects
it, because `MsgID::decode_list` sizes its `Vec` from the payload.

### 18.2 The bound is 102,408, not 102,400

`handle_incoming` now drops any frame over `MAX_INBOUND_FRAME_SIZE` =
`P2P_MSG_PACKET_LIMIT + FRAME_OVERHEAD_ALLOWANCE` = **102,408 bytes**, before
the opcode is read.

The 8-byte allowance is not slack for its own sake. `P2P_MSG_PACKET_LIMIT`
measures the *payload* our packers build; the frame on the wire adds the RLP
list header (up to four bytes at this size) and the opcode byte. The
`BOARD_MESSAGES` packer flushes only once the **next** message would cross the
limit, so reth legitimately emits frames past 102,400 —
`get_board_messages_chunks_large_responses` has asserted
`f.len() <= P2P_MSG_PACKET_LIMIT + 8` since §15.1. **Enforcing a bare 102,400
inbound would have two reth nodes ban each other over their own largest legal
frames.**

The alternative was to reserve the header in the packer so our frames fit
102,400 exactly, then enforce the exact figure. Rejected: it changes the frames
we put on the wire to buy nothing. Erigon-pulse applies no inbound size check at
all, so no peer in the network is strict today, and 8 bytes on a 100 KiB bound
does not weaken it. `the_inbound_bound_admits_our_own_largest_frame` pins the
choice.

Erigon interop is unaffected. Both clients chunk their bulk announce at 846 IDs;
a request is `filter_wanted`'s subset of one announcement frame, so erigon's
unchunked `GET_BOARD_MESSAGES` (§13.2) is at most 846 IDs = 102,367 bytes; and
`BOARD_MESSAGES` is chunked at the packet limit by both. The spec's claim —
"honest implementations already chunk at 100 KiB" — holds against the reference.

### 18.3 Penalty: `report_bad_protocol`, not disconnect

The spec says the peer is disconnected. A satellite protocol has no disconnect
lever short of ending the stream, which tears down the whole `RLPx` session
including eth; §15.5 records why that was avoided. `report_bad_protocol` is the
closest equivalent already wired: `BadProtocol` weighs `i32::MIN`
(`network-types/src/peers/reputation.rs:32`), so the peer is banned on the first
offence. This follows the existing malformed-frame path exactly.

New counter `msgboard.rejected_oversized_frame`. The frame is dropped undecoded,
so nothing else records it — this counter is the only production signal that a
peer is sending oversized frames.

### 18.4 §14.3's cap and §15.3's chunk loop are now unreachable from the wire

This is the part worth reading before touching either.

The bound admits at most `floor(102_407 / 121)` = **846 IDs** in one frame,
which is exactly `MAX_IDS_PER_FRAME`. So:

- §14.3's responder cap (`requested.len() == MAX_IDS_PER_FRAME`) needs a request naming *more*
  than 846 distinct IDs. That frame is now rejected before it is decoded. The **dedup** half of
  §14.3 is unaffected and still fires — 500 repeats of one ID is a 60,501-byte frame, well inside
  the bound — and it was always the substantive half.
- §15.3's outbound chunk loop (`wanted.chunks(MAX_IDS_PER_FRAME)`) needs an announcement of more
  than 846 IDs to produce a second chunk. Same rejection, same conclusion.

Both were kept. They are the inner guard: the frame bound and the chunk size are
separate constants, and only the inner guard keeps them from drifting apart
silently if either is ever changed. The call sites now say so.

§12.9's premise — "a peer is not obliged to chunk its announcements" — is
retired. Under this spec it is obliged, and a peer that does not is banned.

### 18.5 Tests

New, in `protocol.rs`:

- `the_inbound_bound_admits_our_own_largest_frame` — the §18.2 self-ban guard.
- `a_frame_at_the_inbound_limit_is_accepted` — a valid `BOARD_MESSAGES` frame of exactly 102,408
  bytes is handled normally and costs no reputation. The body length is solved for, not guessed.
- `a_frame_one_byte_over_the_limit_is_rejected_and_reported` — the same frame at 102,409 bytes:
  nothing decoded, nothing served, one `BadProtocol` hit. Otherwise perfectly valid, so it pins the
  bound rather than the payload.
- `oversize_is_decided_before_the_payload_is_decoded` — an oversized frame whose ID list decodes and
  one whose length is not a whole number of IDs take the same path.

Three existing tests fed `handle_incoming` a single over-846-ID frame and now
hit the bound instead of the behaviour they were written for. They were
converted, not weakened:

| was | is | now asserts |
|---|---|---|
| `requests_are_chunked_at_one_frame_of_ids` | `a_full_frame_of_announced_ids_is_requested_in_one_legal_frame` | the largest legal announcement provokes one legal request, nothing dropped or reordered |
| `get_board_messages_caps_distinct_ids_at_one_frame` | `get_board_messages_over_one_frame_of_ids_is_rejected_not_truncated` | over-cap request draws nothing and one `BadProtocol` hit; the board is still seeded past the cap, so the old truncating path would visibly serve 846 |
| `every_announced_message_transfers_when_one_frame_announces_more_than_the_cap` | `every_message_transfers_when_the_board_spans_several_announcement_frames` | the same end-to-end convergence, driven through the chunked announce path |

Negative control: with the size check neutered, the three rejection tests fail
and the two boundary controls still pass.

### 18.6 Still open from §17.5

- Duplicate IDs in `BOARD_MESSAGE_IDS` and `GET_BOARD_MESSAGES` are still deduplicated rather than
  kicked. The spec calls them a protocol violation.
- `--msgboard.enabled`, off by default, still does not exist.


---

## 19. Round-11: reject the scalar, do not reduce it

### 19.1 The bug

`pow_scalar` reduced `nonce × difficulty_digest + block_hash` modulo the
secp256k1 group order. The reference does not reduce. It hands the raw sum to
`ScalarBaseMult` (`msgboard/pow_message.go:174-192`), and the binding refuses
anything out of range rather than wrapping it:

```text
secp256k1_scalar_set_b32(&s, scalar, &overflow);
if (overflow || secp256k1_scalar_is_zero(&s)) { ret = 0; }
```

(`ledgerwatch/secp256k1@v1.0.0/ext.h:115-117`; a sum needing more than 32 bytes
hits the `len(scalar) > 32` panic at `scalar_mult_cgo.go:26`.)

Reducing computes a challenge — and therefore a `PoW` hash, and therefore a
verdict — for a message the reference refuses outright. The new spec states the
rule explicitly for its own construction: *"Reject rather than reduce: must match
Go's secp256k1 ScalarBaseMult behavior."* The rule is the same for the current
one.

### 19.2 Reachability

Three inputs are refused, and an attacker can craft none of them:

| case | probability | why it is out of reach |
|---|---|---|
| the 256-bit add carries | ≈ 2⁻⁶⁴ | needs a `block_hash` whose top 64 bits are all ones |
| the sum lands in `[n, 2²⁵⁶)` | ≈ 2⁻¹²⁷ | a window about 2¹²⁹ wide |
| the sum is zero | ≈ 2⁻²⁵⁶ | — |

`nonce`, `work_multiplier` and `work_divisor` are attacker-chosen, but the
`product` they control is under 2¹⁹²; only `block_hash` can push the sum past the
boundary, and that has to name a real block. This is a conformance fix, not a
live exploit — but a client split is a client split, and the cost of being right
is one comparison.

### 19.3 What changed

`pow_scalar` returns the sum unreduced, or `None` outside `[1, n)`. The refusal
now propagates instead of being papered over: `challenge` and `calculate_hash`
return `Option`, and `to_checked` answers `InvalidWork`. Previously `challenge`
returned all-zeros on failure, which was then hashed and difficulty-checked like
any other value — so an unrepresentable scalar was rejected *probabilistically*
rather than definitely.

### 19.4 Tests

The property test that pinned the old contract now pins the new one: half its
2,000 iterations force the carry regime, and every case is checked against
full-precision `U512` arithmetic for both the value and the accept/refuse
verdict. The two cases the property test cannot reach — a sum in `[n, 2²⁵⁶)` at
2⁻¹²⁷, and a zero sum — are constructed by hand in
`test_pow_scalar_refuses_every_out_of_range_scalar`, together with `n-1` as the
largest scalar that must still pass through unreduced.

`test_live_board_message_still_verifies` pins a message taken off the live
testnet board on 2026-08-19. Every other vector in the file is mined by this
crate, so all of them would still agree with themselves if the construction
drifted; that one was mined by the arcade's own client and accepted by the
running fleet, which makes it the only case here that can catch reth drifting
away from the network.

Negative control: restoring the reduction fails exactly two tests.

### 19.5 A client-side mismatch found in the same pass — not fixed here

`bn.js`'s `toArray()` with no length argument returns the **minimal** byte
representation, so an x-coordinate below 2²⁴⁸ — one attempt in 256 — encodes to
31 bytes. The msgboard repo calls it that way in two places:

| site | what it is |
|---|---|
| `packages/core/src/utils.ts:61` | `getChallenge`, used by `checkWork` — the TypeScript **verifier** |
| `packages/core/src/utils.ts:115` | `createChallengeSearch`, the pure-JS incremental **grinder** |

Reth (`pow.rs`) and the repo's own Rust grinder
(`packages/pow-grinder/src/lib.rs:85`) both always use 32 bytes.

Three details make this worse than a single wrong constant:

- **The primary path is fine.** `doPoW` (`packages/sdk/src/index.ts:190`) tries
  the native/WASM Rust grinder first, which encodes 32 bytes. The bug bites only
  on the JS fallback it takes when that engine fails to load — and the fallback
  carries a comment claiming it stays *"bit-identical to checkWork (the node's
  verifier)"*. It is bit-identical to `checkWork`, because `checkWork` shares the
  same bug; neither matches the node.
- **Nothing local catches it.** The SDK's own verifier agrees with the SDK's own
  grinder, so a message mined on the fallback path verifies clean in TypeScript
  and is then rejected by the node. It presents as an unexplained submit failure.
- **The parity test cannot see it.** `packages/sdk/src/grinder.test.ts` is exactly
  the right shape — it asserts a Rust-grinder stamp passes TS `checkWork` — but it
  mines one stamp for one fixed input. The two encodings differ only when the
  x-coordinate has a leading zero byte, so the test is a coin flip that lands
  right 255 times in 256 rather than a boundary check. A fix needs a test that
  drives the leading-zero case deliberately, or asserts the encoded length
  directly.

No migration is implied: a message mined with a 31-byte challenge was always
rejected, so none of them reached the board. Fixing makes strictly more messages
valid.

The fix is `toArray('be', 32)` at both sites, in the msgboard repo rather than
this one.

---

## 20. Round-12: what of the new spec we can adopt without the network moving

§17 asked whether the new spec is worth adopting. This round asks a narrower
question: which of its normative elements can we ship **today** without our node
rejecting a message the network accepts, or emitting one the network rejects.

### 20.1 The ledger

| # | Spec element | Status | Evidence |
|---|---|---|---|
| 1 | packet cap enforced on receive | **shipped** (§18) | `MAX_INBOUND_FRAME_SIZE` = 102,408, `protocol.rs:558` |
| 2 | `MsgID` is 121 bytes | **shipped** | `MSG_ID_SIZE`, `msg_id.rs:21`; Go `messageIDSize`, `message_id.go:23` |
| 3 | `BOARD_MESSAGES` chunked at 100 KiB | **shipped** | packer at `protocol.rs:718`; Go `MaxSizeMsgChunks`, `send.go:53` |
| 4 | oversized packet costs the sender the connection | **shipped** (§18.3) | `report_bad_protocol`, weight `i32::MIN` |
| 5 | duplicate IDs in `BOARD_MESSAGE_IDS` → kick | **blocked** | §20.5 |
| 6 | duplicate IDs in `GET_BOARD_MESSAGES` → kick | **blocked** | §20.5 |
| 7 | `--msgboard.enabled`, off by default | implementable, **not shipped** | §20.5 |
| 8 | the six REST methods and the subscription | **shipped** | `rpc_api.rs:125-165` |
| 9 | `D` as a bigint, target `2²⁵⁶ / D` | **shipped** (§21) | `difficulty`/`target`, `pow.rs` |
| 10 | `payloadHash = sha256(category ‖ data)` | **shipped** (§21) | `payload_hash`, `pow.rs` |
| 11 | `scalarHash = sha256(ver ‖ blockHash ‖ payloadHash ‖ M ‖ Div ‖ nonce)` | **shipped** (§21) | `scalar_hash`, `pow.rs` |
| 12 | reject a scalar outside `[1, n)` rather than reduce it | **shipped** (§19, §21) | `challenge`, `pow.rs` |
| 13 | compressed point, `workHash = sha256(point)` | **shipped** (§21) | `challenge`/`calculate_hash`, `pow.rs` |
| 14 | acceptance `workHash < 2²⁵⁶ / D` | **shipped** (§21) | `verify`, `pow.rs` |
| 15 | `MsgSizeLimit` vs the packet limit (spec silent) | **shipped this round** | §20.3 |

Items 9-11, 13 and 14 are the new `PoW`. They stand or fall together: a message
is valid under one construction or the other, never both. They shipped in §21,
as a flag day — the table row above is the state after that decision, and §20.2
below records the coexistence design that was tried first and then dropped.

### 20.2 Version-tagged coexistence does not work

The obvious way to ship the new `PoW` early is to verify `version = 1` messages
with the old construction and `version = 2` with the new, accept both, and emit
only version 1 until the network moves. The spec makes this look available:
`Message` carries a `version` field, and `scalarHash` binds it as a 1-byte
value, so the two constructions could not collide.

Three facts in the reference kill it.

**The spec does not assign the new construction a version.** Every worked
example in it says `"version": "0x1"`, and the `scalarHash` input is the message's
own version byte, not a new one. Tagging the new construction `2` would be us
inventing wire semantics upstream has not defined — the exact failure §17.6
warns about, with the version field as the thing we get wrong.

**Erigon refuses any version but 1, at the decode boundary, for the whole
frame.** `Validate()` returns `ErrPoWMsgInvalidVersion` unless
`Version == DefaultEncodingVersion` (`pow_message.go:97-100`), and
`DecodeRLPMsgList` runs it over every element and fails the list on the first
refusal (`pow_message.go:61-72`). The caller kicks:
`return true, err // kick if we cannot parse their payload` (`fetch.go:267-271`).
So one version-2 message in a `BOARD_MESSAGES` chunk does not cost us that
message — it costs us the whole chunk, every honest version-1 message travelling
with it, and the peer.

**Nothing would ever reach the code anyway.** Erigon's announcement filter drops
a version-2 `MsgID` before it is ever requested:
`if id.Version() != DefaultEncodingVersion || ...` (`board.go:233`). A version-2
message cannot cross the network, so a version-2 verifier would be an untested
path with no reachable input, written against a spec with no reference
implementation.

**Superseded by §21.** This section was written to argue against shipping the new
construction as `version = 2`, and it shipped that way anyway before being
reversed. Its three facts are now the argument *for* what we did: the spec does
not assign the new construction a version because it does not need one — the new
construction is version 1, and the old one is gone. Read on for the fourth
reason, which is the one that actually decided it: coexistence means the weaker
construction governs for the whole window.

### 20.3 `--msgboard.size-limit` now has a ceiling

`size_limit` bounds the `data` field of every message the board accepts, and a
message the board accepts is one it may later be asked to serve. Both packers
flush only once the *next* message would cross the 100 KiB chunking target, so a
message above that target gets a frame to itself, as large as the message.

Past a `data` length of **102,301 bytes** that frame exceeds
`MAX_INBOUND_FRAME_SIZE`, and every reth peer drops it undecoded and reports the
sender — `BadProtocol` weighs `i32::MIN`, so that is a 12-hour ban from each of
them. Erigon-pulse would neither request the message (`board.go:233` skips
`id.Size() > cfg.MsgSizeLimit`) nor object to the frame (its inbound cap is
`ProtocolMaxMsgSize` = 10 MiB), so the split is reth against reth and entirely
self-inflicted.

`--msgboard.size-limit` is now rejected at parse time above that figure. The
figure is solved in `MAX_SAFE_SIZE_LIMIT` rather than written down, because the
RLP header widths depend on the length being solved for, and the answer moves
with `P2P_MSG_PACKET_LIMIT` and `FRAME_OVERHEAD_ALLOWANCE`. The default is 8 KiB,
so no existing configuration changes.

This closes row 4 of `docs/msgboard-spec-feedback.md`: the spec does not say
whether `MsgSizeLimit` must stay under the packet limit. On our side it must.

### 20.4 The self-ban guard asserted a tautology

`the_inbound_bound_admits_our_own_largest_frame` asserted
`MAX_INBOUND_FRAME_SIZE >= P2P_MSG_PACKET_LIMIT + 8`. Two lines above it,
`MAX_INBOUND_FRAME_SIZE` is *defined* as `P2P_MSG_PACKET_LIMIT + 8`. The test
restated a definition and could not fail whatever the packer did.

It now seeds the board with three real messages whose RLP lengths sum to exactly
`P2P_MSG_PACKET_LIMIT` — the largest payload the packer can put in one chunk —
drives a real `GetBoardMessages`, and asserts the emitted frame is 102,405 bytes
and inside the inbound bound. A fourth message must then split the response
rather than overshoot.

Negative control: making the packer flush *after* pushing, so a chunk overshoots
by a whole message, fails the new test and `get_board_messages_chunks_large_responses`.
The retired assertion passes under that same mutation.

### 20.5 Two things deliberately left alone

**The duplicate-hash kick (rows 5 and 6).** Erigon forwards
`FilterMessageIDs(mIDs)` straight into `GET_BOARD_MESSAGES` with no
deduplication (`fetch.go:206-227`), and `FilterMessageIDs` tests each ID against
the board, not against the IDs beside it (`board.go:214-246`) — its own comment
acknowledges the duplicate case. So any peer that announces one ID twice in a
frame makes erigon request it twice, and a spec-conforming node bans erigon for
input erigon did not originate. §14.3 declined to penalise here because no client
documented a bound; the spec documents one, and the reference still violates it.

**`--msgboard.enabled`, off by default (row 7).** The flag is trivial. Landing it
would silently stop the board on every fleet box at its next restart, until the
units are edited. That is a deploy change, not a code change, and it belongs with
one.

### 20.6 A correction: erigon's chunker drops messages

`docs/msgboard-spec-feedback.md` §2 says erigon packs a `BOARD_MESSAGES` payload
up to 102,400 bytes and emits 102,404. It does not. `MaxSizeMsgChunks`
(`send.go:53-71`) redeclares `var group` inside the loop and never reads the
group back out of `all`, so `all[totalGroups-1] = group` overwrites each group
with the single message just appended:

```text
30 messages of 8 KiB, run through the loop verbatim:
group 0: 1 msg [11]   group 1: 1 msg [23]   group 2: 1 msg [29]
in=30  out=3
```

Erigon therefore serves one message per chunk and drops the other 27. Two
consequences. Its largest `BOARD_MESSAGES` frame is one message plus headers —
about 8.3 KiB at the default `MsgSizeLimit`, not 102,404 — so reth's frames are
the large ones on this network, and §20.3's ceiling is ours alone to enforce. And
a bulk request to an erigon peer returns a fraction of what was asked for, which
is worth knowing before reading anything into convergence timing.

The packing *rule* is unchanged by the bug, and reth implements the rule: flush
before the next message crosses the limit, then add the list header.

---

## 21. Round-13: the new construction takes version 1, and the old one is gone

§20 shipped the parts of the new spec the network already accepted and left the
`PoW` itself blocked. §17.7 recorded why: nothing anywhere implements the new
construction, so adopting it means becoming the reference. This round does that.

**Decision: the new construction is `version = 1`.** It replaces the old one
outright. There is no `version = 2`, no dual-accept path, and no migration
window.

### 21.1 Why not version 2

A previous round shipped the new construction as `version = 2` alongside the old
one, on the reasoning that the version byte could carry both and clients could
move whenever they liked. That is the wrong shape for this network, for one
reason that outweighs the convenience:

**Any window in which both are accepted is a window in which the weaker one
governs.** The old construction costs an attacker 50-500× less than its
difficulty parameter claims, and lets one precomputed table mine unlimited
messages in a block (§17.2). A board that still accepts it is exactly as
spammable as it was before. Coexistence buys a smoother client rollout and no
security at all — and the security is the entire reason for the change.

Two smaller reasons point the same way. The spec never assigns the new
construction a number; every worked example in it is `"version": "0x1"`, and
`scalarHash` hashes that byte. Picking 2 ourselves means every digest we publish
is wrong for anyone who follows the spec literally. And we are the only operator,
so the coordination problem a version byte solves does not exist here.

### 21.2 What the flag day costs

Nothing on any board survives. Every message currently held was mined under the
old rules, and `verify` refuses all of them.

**Correction (§23).** This section first claimed boards drain on restart because
`load_from_db` re-checks each message against the current rules. That was wrong
when written. `load_from_db` checked the size limit and the work *ratio* and
never re-verified the `PoW`, and `db_load_all` only RLP-decodes — so old-
construction messages came straight back onto the board at startup and were
announced to peers as valid. Fixed in §23.

Every poster must be upgraded before it can post again. There is no partial
state — a poster running the old algorithm produces messages that no node will
accept, and it will not be told why beyond `InvalidWork`.

Peers that have not upgraded are kicked, and kick back. `add_remote_msgs` counts
a failed `PoW` as kickable, so the two sides ban each other on the first
exchange. On a single-operator network that is a restart; it would not be on a
larger one.

### 21.3 What changed in the code

`pow_v2.rs` is gone; its contents are `pow.rs`, without the `_v2` suffixes. The
old construction — `difficulty_digest`, `pow_scalar`, the uncompressed
x-coordinate challenge, the `hash mod D == 0` test, and the `u64` difficulty with
its overflow guard — is deleted rather than deprecated. `difficulty` now returns
`Option<U256>` and `target` returns `Option<U512>`; the widening is not
decorative, because `D = 1` puts the target at exactly 2²⁵⁶.

Two tests carry the decision:

- `test_a_message_mined_under_the_old_construction_is_now_worthless` pins a real message taken off
  the live testnet board on 2026-08-19 and asserts it no longer verifies. It was
  mined by somebody else's client and accepted by the running fleet, so it is the
  only case in the suite that can catch a partial revert toward the old
  algorithm. It replaces a test that asserted the opposite.
- `only_version_one_is_accepted` replaces the coexistence test. It also checks
  that relabelling a valid message to `version = 2` breaks its work, which is
  what makes the version byte load-bearing rather than decorative.

### 21.4 The golden vector

The spec cites `TestPoWGoldenVector` as the normative worked example. It does not
exist at `48cdb29e35`; `msgboard/pow_message_test.go` holds only
`TestPoWMessageSuite`. Ours is `mod golden_vector` in `pow.rs`, generated by
`scripts/msgboard-pow-vector.js` — an independent transcription of the spec text
with a hand-rolled secp256k1, so agreement between the two is agreement between
two readings of the spec rather than a call into the same library twice.

```text
VECTOR A — construction only, nonce fixed at 1, deliberately not mined
  version 1 / blockHash 0x3a2ca760…32b5 / category 0x63686174…0000 ("chatter")
  data "golden vector" (13 bytes) / M 10000 / Div 1000000 / D 169072
  payloadHash     0xb66106e111b0e6cd08a49c7a37afa3259541bee8e465bef5e55f6cd7223d789a
  scalarHash      0x3caed3ea9a5caa6e1e069d0126e4dc6698190aa3eec8ebcdab227d3e5b0fd18d
  compressedPoint 0x035e55e474ae91c573e38855bba370f01d64a307fa9c834eda7b435ec9d24368b9
  workHash        0x5ba003ccdb08503a19326a201834198a49e062d2f3f0e9506ff086eddb011dee

VECTOR B — the same message mined against an easier target
  nonce 57602 / M 1 / Div 1000 / D 16907
  scalarHash      0xbcff3c0ddc5d02b05e282566461d4f30f35ce90b3bfd36cde0c694dcb54a5e7d
  compressedPoint 0x030fbdcb58e555146c54a0863ebf038a0384d4bd90439d02b8d8d5f71096ca7a09
  workHash        0x00037212834e250723dc736508d445a0dbc01398040a980807641b4be2d1e361
```

Vector A pins the byte layout regardless of whether the work is sufficient — a
vector that only checks the final verdict can pass by luck; four intermediates
cannot. Vector B is mined, and nonces 57601 and 57603 are asserted to fail, so
the threshold is load-bearing.

### 21.5 A gap this surfaced: local submissions were never field-validated

`add_local_msg` went straight to `to_checked` and never called `validate`. The
remote path validates on decode (`decode_pow_msg_list`), so the asymmetry only
ever mattered for RPC submissions — but it meant a message the peers would kick
us for relaying could still enter our own board.

The version byte makes it concrete rather than theoretical. It is hashed into the
scalar, so a message mined at `version = 0` has genuine work behind it and passes
`to_checked` on its own terms; only `validate` refuses it. `add_local_msg` now
calls `validate` first.

### 21.6 What this does not settle

The spec still gives the poster's obligations and never the receiver's, and that
leaves `D` unbounded below: `M = 1`, `Div = 2²⁴`, empty body gives `D = 1`, a
target of 2²⁵⁶, and a first-nonce win. What stops it here is the operator's
minimum-work gate (`is_work_acceptable`), which is ours and not in the spec. An
implementer working from the document alone has no floor at all.

`a_difficulty_of_one_admits_every_hash` pins that case so the exemption stays
visible. Raised upstream as §2.2 of `docs/msgboard-spec-feedback.md`.

---

## 22. Round-14: no metric could tell "nobody is talking" from "nobody can"

The fleet runbook
(`monorepo/deploy/rpc/runbooks/msgboard-gossip-investigation.md`, 2026-08-21)
reports `announcements_received = 0` on all seven boxes while
`announcements_sent` is 26 and 34. Nothing arrives from any peer.

Its most useful line is not a symptom, it is an absence:

> Note there is **no metric for connected `msg/1` peers**. Adding one is
> probably the single highest-value change for diagnosing this class of fault.

That is correct, and the gap is worse than it looks. Every counter on the
receive path — `announcements_received`, `bodies_received`, `accepted_remote`,
every `rejected_*` — reads zero in two completely different worlds:

- peers negotiate `msg/1` and send us nothing, or send us things we reject;
- no connected peer speaks `msg/1` at all, so the receive path is never reached.

The fixes have nothing in common, and no combination of the existing metrics
separates them. The `bad_message 0 / bad_protocol 0` pair is the tell that it is
the second — we are not rejecting anything, because nothing arrives — but that
is an inference from two zeros, which is exactly the kind of reasoning that
produced the "wrong algorithm" false alarm the runbook opens by retracting.

### 22.1 What was added

| metric | type | reads |
|---|---|---|
| `msgboard_peer_sessions` | gauge | peers with a live `msg/1` session right now |
| `msgboard_peer_sessions_opened` | counter | sessions opened since start |
| `msgboard_peer_sessions_closed` | counter | sessions closed since start |
| `msgboard_peer_unsupported` | counter | peers that connected without the capability |

Read them together:

- **gauge 0, `peer_unsupported` climbing** — we have peers, none run a board. Nothing is broken in reth; the question is who else runs msgboard.
- **gauge 0, `opened` high** — peers negotiate and then drop the subprotocol. Look for disconnect reasons.
- **gauge > 0, `announcements_received` 0** — sessions are live and silent. Now the receive path is worth reading.

`peer_unsupported` is expected to be large. The capability is opt-in, so most of
the network will never negotiate it; the counter exists to separate "no msgboard
peers" from "no peers", which the eth peer count alone cannot do.

### 22.2 The gauge is guarded, not hand-counted

`SessionGuard` raises the gauge on construction and lowers it on `Drop`, so
every exit from `run_connection` pays the decrement — including early returns and
a panic inside the spawned connection task. A gauge incremented and decremented
by hand drifts upward the first time a path returns early, and this is precisely
the number an operator trusts when nothing else is moving. A stuck non-zero
reading would report a healthy network with no peer attached.

`the_gauge_returns_to_zero_on_every_exit_path` opens three sessions and closes
them three different ways, then asserts `opened == closed == 3` and the gauge
back at 0. Deleting the `Drop` body fails it.

It lives in its own integration test (`tests/session_gauge.rs`) rather than
beside the code, and the reason is worth recording because it will catch the
next person: **metric handles bind to whichever recorder was live when they were
built.** As a unit test it passed alone and failed in the full suite — 144 other
tests had already constructed `MsgboardMetrics` against the default recorder, so
the snapshot came back empty and the assertion read `None`, not a wrong number.
`metrics::with_local_recorder` does not help, because the binding happens at
construction rather than at emission. The test needs a process where the
recorder is installed first, which only an integration test can guarantee.

### 22.3 A caution about `expired`

The runbook reads `expired 31` on both chain-369 boxes as proof that inbound
gossip used to work, and therefore that this is a regression from the
2026-08-21 roll.

That inference does not hold. `expired` counts every message whose anchor block
left the live window, with no regard for where the message came from
(`board.rs:243-250`) — a message posted through `msgboard_addMessage` expires
exactly like one received from a peer. The boxes carry `accepted_local` 6 and 7
for a handful of probe and arcade posts, so a locally-fed board would produce
the same 31.

The number that would settle it is `accepted_remote` **before** the roll. If
Prometheus retains it and it was already zero, inbound gossip never worked and
this is not a regression at all — which points the investigation at peering and
capability negotiation rather than at anything the roll changed.


---

## 23. Round-15: the flag day did not drain the boards

`load_from_db` re-inserted every stored message that satisfied the size limit
and the work ratio, and never re-verified the `PoW` (`board.rs:151-161`;
`db_load_all` only RLP-decodes). §21.2 claimed the opposite. The claim was never
true, and the flag day is exactly the condition that makes it matter.

So at the roll each box reloaded a board full of old-construction messages,
announced them to its peers as valid, and served the bodies on request. Every
body a conforming peer rejects earns us one `BadMessage` hit **from that peer**.
At reth's defaults that is `16 × REPUTATION_UNIT` against a `50 × REPUTATION_UNIT`
threshold, so the fourth message we serve gets us banned — and the ban is global
and lasts 12 hours (`peers/config.rs:200`). It costs `eth/68` block sync, not
just msgboard.

A rules change is precisely when a stored row stops meaning what it meant when
it was written. Trusting the row is what turned a construction change into a
mutual partition.

### 23.1 The fix

`load_from_db` now re-verifies, and requires the recomputed work hash to equal
the hash the row carries:

```rust
let valid = self.cfg.is_size_acceptable(arc.msg.data.len()) &&
    self.cfg.is_work_acceptable(arc.msg.work_multiplier, arc.msg.work_divisor) &&
    arc.msg.verify().is_ok_and(|hash| hash == arc.hash);
```

Failures already went to `discarded`, so the next flush deletes them from MDBX
and the board self-cleans across one restart.

The cost is one scalar multiplication per stored row, paid once at startup —
under a second for a full `count_limit` board, against a partition measured in
hours.

`a_stored_message_that_no_longer_verifies_is_not_reloaded` writes two rows
straight through `db_flush` (which verifies nothing, by design), one sound and
one whose recorded hash does not match its own work, and asserts only the sound
one loads. Dropping the `verify` clause fails it.

### 23.2 What the fleet metrics actually said

The runbook that opened this
(`monorepo/deploy/rpc/runbooks/msgboard-gossip-investigation.md`) reports gossip
as dead fleet-wide and reads `expired 31` on chain 369 as evidence of a
regression. §22.3 already noted that `expired` cannot support that inference.
Prometheus keeps 365 days of `reth_msgboard_*` (scraped since 2026-08-03), and
it separates two problems the runbook treats as one:

| host | `accepted_remote`, 30d peak | last increase |
|---|---|---|
| direct-a-evm-369 | **0** | never |
| direct-b-evm-369 | **0** | never |
| indexer | **0** | never |
| direct-a-evm-943 | 453 | 2026-08-21 16:56Z |
| direct-b-evm-943 | 573 | 2026-08-21 16:56Z |
| direct-a-evm-1 | 6 | 2026-08-21 18:56Z |
| direct-b-evm-1 | 2016 | 2026-08-21 18:56Z |

**Chain 369 never received a single message**, across the whole retained window.
That is not a regression and the roll did not cause it; it belongs with the
peering question in the runbook's sub-problem A.

**Chains 943 and 1 were receiving until the roll and stopped at it.** `direct-b-evm-1`
alone took 2016 messages in the preceding week. Both chains stopped at their own
restart and have not resumed since — which is the regression, and §23 is its
most likely mechanism.

A prediction worth checking rather than assuming: if peer bans are the cause,
they expire 12 hours after each box's restart and gossip returns on its own,
with no deploy. If it does not return by then, the ban theory is wrong and the
next thing to read is the new `msgboard_peer_sessions` gauge from §22.

---

## 24. Round-16: the subscription notification carried the wrong method name

`msgboard_subscribe` works end to end — verified live on `direct-a-evm-943`,
where a held subscription delivered real arcade and provecash messages as they
were posted. But the notification frames named the wrong method:

```
emitted:  {"jsonrpc":"2.0","method":"msgboard_subscribe",    "params":{...}}
spec:     {"jsonrpc":"2.0","method":"msgboard_subscription", "params":{...}}
```

jsonrpsee defaults a subscription's notification name to the subscribe method's
own name; the `name = "subscribe" => "subscription"` form overrides it. Nothing
in the crate said which was intended, so the default stood.

This is a silent failure, which is what makes it worth a section. The
subscription opens, the id comes back, frames flow, and every count on the
server looks healthy. A client that filters on the documented name — as our own
`docs/msgboard-rpc.md:285` tells it to, in shipped example code — simply sees an
empty board forever.

### 24.1 Why the tests did not catch it

`subscribe_emits_newly_accepted_messages` and the category-filter test both use
jsonrpsee's typed `subscribe_unbounded` helper, which correlates on subscription
id and never inspects the method name. They passed for the whole time the name
was wrong, and would pass again if it regressed.

`subscription_notifications_use_the_method_name_the_spec_documents` reads the
raw frame through `raw_json_request` instead. Reverting the `=>` fails it.

The general lesson is the one §22 hit from the other side: a test that consumes
its own output through the same abstraction that produced it cannot see a
contract break. The typed helper and the server agreed with each other and both
disagreed with the spec.

---

## 25. Round-17: the gauge answered it, and it inverted the diagnosis

`v2.5.1-pulse-4` is deployed fleet-wide. The metrics §22 added resolve the
gossip question in one read, and they contradict both of the stories told
earlier in this document.

```
                     peer_sessions   opened/hr   peer_unsupported   accepted_local/hr
direct-a-evm-369           1            83            7,900               0
direct-b-evm-369           0           186           14,411               0
direct-a-evm-943           0             0           11,177             127
direct-b-evm-943           0             0           12,698             139
direct-a-evm-1             0             0           13,268               0
direct-b-evm-1             0             0           27,112               0
```

### 25.1 Two different faults, neither the one that was assumed

**Chain 943 (testnet v4) has no `msg/1` peers at all.** Not one session has
opened since the roll. Its nodes see 51,000-59,000 peer connections an hour and
every one of them lacks the capability. This is where all the real traffic is —
127 and 139 accepted local posts an hour — and it has nowhere to go.

**Chain 369 (mainnet) is the only chain that has `msg/1` peers.** Sessions open
at 83-186 an hour. They are short-lived, but that is ordinary churn rather than a
msgboard fault: the same boxes open 49,000-59,000 eth connections an hour, so
`msg/1` sessions track the general churn at about 0.3% of it — the share of
mainnet peers that run a board. Both 369 boards are empty, so we announce
nothing and there is nothing for a peer to request.

**Chain 1 has none, correctly.** Msgboard is a PulseChain protocol.

### 25.2 Corrections to earlier rounds

Two claims in this document were wrong, and the gauge is what showed it.

**§23.2 said chain 369 "never received a single message" and treated that as the
fault.** The zero was real, but the reading was backwards: 369 is the only chain
with msgboard peers at all. Its boards are empty because nothing is posted to
them, not because it cannot gossip.

**§23 proposed peer bans as the mechanism for 943 and chain 1 falling silent at
the roll, and predicted recovery when the 12-hour window expired.** That did not
happen. More than 24 hours passed with no recovery, and chain 1's peer count
returned to 130 while its gossip stayed at zero. Peers returning without gossip
returning falsifies it. The §23 fix — re-verifying stored messages on load — is
still correct and still worth having, but it was not the cause of the silence.

Both errors have the same shape: reading a zero as evidence of a specific
mechanism when the metric could not distinguish that mechanism from any other.
That is what §22 was written to stop, and it took deploying it to stop it.

### 25.3 The actionable finding: our own replicas are not peered

On 943 the entire msgboard network is our two boxes. They are not connected to
each other. The only TCP link between them is lighthouse on `:9300`; reth's
`:30303` has no session, and neither node's command line carries
`--trusted-peers`.

So the two replicas hold divergent boards by construction, which is precisely
the customer-visible symptom the fleet runbook opens with: a client writes to
one replica through eRPC, reads from the other, and sees nothing.

Static peering fixes it outright, because on testnet there is no third party to
depend on:

```
direct-a-evm-943  116.202.173.179:30303
  enode://c6b52cf99ec0bdecec6b1ca58c42c59358c7f9aabe0369aca5c73d51c5efdfb0
         1aeeec069aa52b0a70386682a0cc6fd5c0c8c3714ce5100011c0df2b311a43b2

direct-b-evm-943  157.90.179.40:30303
  enode://8d094139bc456c134f5d397bd5320dd40faecf6d6f586a57ce2141147599ce7f
         6f4365e10114856aa7c467ed995db84e55ced6a598d137377a2693f1b1ad5e64
```

That is a deploy change in the monorepo, not a reth change. Nothing in reth
needs to move for it.

### 25.4 What the metrics will say when it works

`peer_sessions` goes to 1 on each 943 box and stays there — a trusted peer is
reconnected rather than churned. `announcements_sent` starts tracking
`accepted_local`, which has been pinned at zero against 127/hr. Then
`announcements_received`, `requests_sent` and `accepted_remote` move on the
opposite box, and `msg_count` converges between the two.

If `peer_sessions` reaches 1 and `accepted_remote` stays at zero, the fault is
downstream of the session and §22's read order says the receive path is finally
worth reading.
