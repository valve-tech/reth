# Msgboard security review

This document tracks the internal pre-audit review of msgboard, and the work that closes each finding. Update the status column as work moves. Do not delete a closed finding: the external auditor reads this to see what we covered.

- **Review date:** 2026-09-27
- **Code reviewed:** `main` at `b3291334e4`, diffed against upstream `v2.6.0`
- **Scope:** `crates/net/msgboard/`, `crates/net/msgboard-types/`, `bin/reth/src/msgboard_net.rs`, and the msgboard parts of `bin/reth/src/{lib,main}.rs`. No other crate references msgboard.
- **Method:** four reviewers read each area in full and traced every finding from untrusted input. They ran no code. A finding is closed only when a test shows the attack on the old code and the fix stops it, or, where no sound test exists, when a second code review accepts the fix.

## Status key

| Status | Meaning |
|---|---|
| open | Not started |
| in progress | A branch has the work |
| needs review | Fixed, but no test proves the attack; a second code review must accept it |
| fixed | Test fails before the fix and passes after; merged to `main` |
| accepted | We keep the behaviour on purpose and document it |

## Findings

Severity is after verification. Finding 1 was reported as high; the reviewer assumed the multiplexer inbound queue was unbounded. Upstream v2.6.0 bounds it at 1024 frames and 32 MiB per peer, so it is medium.

| # | Severity | Finding | Where | Branch | Status |
|---|---|---|---|---|---|
| 1 | Medium | A peer that reads just under the 30 s send deadline never gets marked stalled, so it can hold up to 32 MiB of inbound frames per connection. The comment calls the queue unbounded. | `protocol.rs:468-505`, `:224-229` | `msgboard/peer-limits` | fixed in !3 (9423eb56b3) (test proves the attack; see R2) |
| 2 | Medium | The first announcer holds a 10 s claim. If it withholds, no other announcer is asked, and it gets no penalty. An attacker can censor msgboard traffic to a node. | `board.rs:332-395`, `pending.rs:98-115` | `msgboard/pending-requests` | fixed in !3 (9423eb56b3) after three review rounds (tests prove the attacks; see R1, R1a, R1b) |
| 3 | Medium | `GetBoardMessages`: an 8 KiB request returns about 2.1 MB, repeatable with no rate limit. | `protocol.rs:846-878` | `msgboard/peer-limits` | fixed in !3 (9423eb56b3) (tests prove the attack; see R3) |
| 4 | Medium | SIGTERM or Ctrl-C skips the final flush; up to 15 s of accepted messages are lost per restart. | `bin/reth/src/main.rs:233,258,328,356` | `msgboard/storage` | fixed in !3 (9423eb56b3) (test proves the attack) |
| 5 | Medium | While DB writes fail, the retry batch keeps message bodies with no bound (about 2.8 GB an hour under load). | `board.rs:245-255`, `:751-758` | `msgboard/storage` | fixed in !3 (9423eb56b3) (test proves the attack) |
| 6 | Medium | The want list counts spent entries against its cap (about 68 msg/s per peer, erigon has no such limit), and `prune` can end a newer reservation early. | `pending.rs:187-240` | `msgboard/pending-requests` | fixed in !3 (9423eb56b3) (test proves the attack) |
| 7 | Low | Expiry is O(k·n) under the board mutex. | `board.rs:280-305`, `index.rs:73-81` | `msgboard/storage` | fixed in !3 (9423eb56b3) |
| 8 | Low | secp256k1 verification runs on the async connection task, about 800 checks per hostile frame. | `protocol.rs:927` | `msgboard/peer-limits` | fixed in !3 (9423eb56b3) |
| 9 | Low | A zero `--msgboard.commit-every` or `--msgboard.log-every` starts a hot loop. | `args.rs:391-407` | `msgboard/rpc-cli-docs` | fixed in !3 (9423eb56b3) |
| 10 | Low | About 8192 fake announcements (no PoW) fill the claim map; suppression then fails open, and each call sweeps the map under the lock. | `board.rs:332-395`, `pending.rs` | `msgboard/pending-requests` | fixed in !3 (9423eb56b3) |
| 11 | Low | Two flushes can overlap and commit out of order, so an evicted row stays on disk. | `launch.rs:123`, `board.rs:734-743` | `msgboard/storage` | fixed in !3 (9423eb56b3) |
| 12 | Low | Loading from disk ignores `count_limit` and does not check that a row key matches its message hash. | `board.rs:178-218`, `db.rs:128-176` | `msgboard/storage` | fixed in !3 (9423eb56b3) |
| 13 | Low | `--http.api all` exposes `msgboard_addMessage`. | `launch.rs:302` | `msgboard/rpc-cli-docs` | accepted and documented |
| 14 | Low | One content call can build about 80 MB. Decision 2026-09-28: serve the whole board, as erigon and `txpool_content` do; build it off the RPC worker. No byte cap. | `rpc.rs:90-126` | `msgboard/rpc-cli-docs` | fixed in !3 (9423eb56b3) (see R5, R6) |
| 15 | Info | `docs/msgboard-rpc.md` has the wrong input format, names a flag that does not exist, and omits paging. | `docs/msgboard-rpc.md` | `msgboard/rpc-cli-docs` | fixed in !3 (9423eb56b3) |
| 16 | Info | The `handle_incoming` comment and code disagree on serving when gossip is disabled. | `protocol.rs:677-680`, `:861` | `msgboard/peer-limits` | fixed in !3 (9423eb56b3) (code was right; comment fixed to match erigon) |
| 17 | Info | Stale comments describe the old work hash. | `pending.rs:10`, `:163-164` | `msgboard/pending-requests` | fixed in !3 (9423eb56b3) |
| 18 | Info | Reth rejects a whole frame for a message with D = 0; erigon rejects only that message. Stricter, cannot split honest nodes. | `pow.rs:155`, `wire.rs:74` | `msgboard/rpc-cli-docs` | accepted and documented in `docs/msgboard-parity-gaps.md` §27.1 |
| 19 | Info | `CheckedPoWMsg` DB encoding has a timestamp field erigon lacks. Disk only. | `pow.rs:121-131` | `msgboard/rpc-cli-docs` | accepted and documented in `docs/msgboard-parity-gaps.md` §27.2 |

## Residual risks

These risks stay after the fixes. We accept them on purpose, and the auditor should see them stated.

| # | Risk | Why we accept it | Related |
|---|---|---|---|
| R1 | An attacker who controls most of our msgboard peer connections can delay delivery of a message to our node, or stop it for this node. The fix for finding 2 keeps up to 16 other announcers per message, evicts at random when the list is full, and asks them in turn, so the attacker must hold a large share of our peer slots (about 11 extra peers for even odds against one honest announcer). If every announcer we recorded withholds, we drop the claim. Honest peers announce a message once, so the node then gets the message only when a new peer announces it. | No pull-based gossip design can fetch a message that no reachable peer will serve. Erigon-pulse has the same exposure in a weaker form: it keeps one claimant and never retries. | 2 |
| R1a | A peer that answers part of a request can withhold the rest for a small penalty each time. It is never escalated to a ban, but it is asked last on later claims, and other announcers deliver the withheld messages after one 10 s timeout. | Escalating on a partial answer would ban honest peers that pruned stale messages at a block boundary. | 2 |
| R1b | An honest peer can still reach the larger penalty if it prunes every message of a one-message request at three block boundaries within 60 s. | Unlikely in practice. One larger penalty does not ban a peer. | 2 |
| R2 | The per-peer inbound limit (finding 1) cuts the whole session, eth included. A slow but honest peer on a busy board can hit it during one 30 s send stall: after about 150 single-ID announcements at the default message size. At the largest `--msgboard.size-limit`, the multiplexer's own 32 MiB per-connection budget is the real ceiling, so a stalled honest peer can be cut after about 330 frames. | The limit and the 32 MiB budget are in the upstream multiplexer, which we do not change. The cut costs only a low backoff and no reputation, and the peer reconnects. Memory stays at upstream's bound (32 MiB per connection). | 1 |
| R3 | The reply budget (finding 3) is a rate cap with no reputation cost: a peer can request forever. Per peer it allows a 4 MiB burst (more at larger message sizes) and 1 MiB/s after that. Across about 130 peers that is about 130 MiB/s (1.1 Gbit/s) of upload at most. It also slows an honest peer that syncs a full board from us. | On `main` the upload had no bound, so this is a strict improvement. A reputation cost would hit honest erigon peers, which over-request by design. A partial reply looks to erigon like "I no longer have it", which erigon already handles. A node-wide budget is a possible follow-up. | 3 |
| R4 | On SIGTERM, a message accepted between the final flush and the stop of the network is lost. | The window is milliseconds. The fix stops intake before the final flush where that is safe. | 4 |
| R5 | A full default board is about 167 MB of JSON, which is close to reth's default `--rpc.max-response-size` of 160 MiB. A stock reth node cannot send a nearly full board. | Our build raises the default to 200 MiB (see R6). Stock reth and erigon nodes must set `--rpc.max-response-size 200`; the RPC doc says so. | 14 |
| R6 | Our build raises the default `--rpc.max-response-size` from 160 MiB to 200 MiB so a full board fits. The limit applies to every RPC method, so `debug_trace*`, `eth_getLogs` and others can build up to 25% larger replies before they fail. | Needed for erigon parity on `msgboard_content`. Full-board builds are limited to two at a time. Operators can set the flag lower on nodes that do not serve msgboard. | 14 |

## Checked and found correct

The reviewers verified these. The auditor can use this list to see what we covered.

- **PoW:** RPC callers cannot skip it. The work hash matches erigon-pulse `78fbcffb8b` and reproduces its golden vector. Mining cannot be batched or reused across messages, blocks or difficulties. The difficulty maths runs in U256/U512 with no overflow or division by zero, and matches erigon below 2^64.
- **Encoding:** one message has one hash and one ID. Non-canonical RLP and trailing bytes are refused.
- **Replay:** a message is bound to a block hash inside a 120-block window. Messages carry no signatures, so signature malleability does not apply.
- **Malformed frames:** the frame size is checked before decoding; list decoders reject remainders; no panic path on untrusted input was found.
- **Locking:** one `parking_lot::Mutex`, never held across an await or DB IO. No deadlock is possible.
- **Subscriptions:** bounded by jsonrpsee connection limits and a fixed broadcast capacity.
- **Isolation:** a msgboard failure cannot stop the node or firehose. Metrics have no labels.

## History

| Date | Change |
|---|---|
| 2026-09-27 | Review done. Findings 1-19 recorded. Remediation started on four branches. |
| 2026-09-28 | Branches reviewed. Recorded residual risks R1-R5. Finding 14: decided to serve the whole board. Finding 1: limits set at 256 frames and 16 MiB per peer. |
| 2026-09-28 | All four branches approved and merged into `msgboard/security-review`. Local CI: 672 + 7 tests pass. |
| 2026-09-28 | MR !3 merged to GitLab `main` as 9423eb56b3. Pipeline 2835 passed. Findings 1-12 and 14-17 fixed; 13, 18 and 19 accepted and documented. |
