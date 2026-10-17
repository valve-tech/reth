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

## Round 2 findings (2026-10-01)

Round 2 reviewed `main` at `0b46d7d398` with four read-only reviewers: the changes since round 1, a section-by-section walk of the specs against the erigon-pulse Go code, an attempt to break each round-1 fix, and a fresh denial-of-service and test-quality pass. It found one bypass of a round-1 fix (finding 2), two client-visible RPC differences from erigon, and several lower issues. Round-1 findings 1 and 3 to 19 hold.

| # | Severity | Finding | Where | Branch | Status |
|---|---|---|---|---|---|
| 20 | High | Withholding fix bypass: a sybil evicted from a claim's alternate list can announce the same ID again and re-enter. About 17 looping sybils flush every honest announcer and then withhold through retries at no reputation cost. R1 is understated. | `pending.rs:182-198`, `board.rs:436` | `fix/msgboard-r2-p2p` | fixed in !20 (8ffb6c12ad) after three review rounds (tests prove the attack; see R1) |
| 21 | High (client) | `msgboard_subscribe` accepts only `"newMessages"`; erigon's name on the wire is `"messages"`. | `rpc.rs:33,213` | `fix/msgboard-r2-rpc` | fixed in !19 (1a988468a7) |
| 22 | High (client) | `fromBlock`/`toBlock` accept only JSON numbers; erigon accepts hex and decimal strings. | `rpc_api.rs:101-105` | `fix/msgboard-r2-rpc` | fixed in !19 (1a988468a7) |
| 23 | Medium | Honest reth peers can strike each other: a responder serves only the budget-sized part of a request, and the requester counts a later frame's request as unanswered. | `protocol.rs` serve and request paths | `fix/msgboard-r2-p2p` | fixed in !20 (8ffb6c12ad) (test proves the attack) |
| 24 | Medium | A stalled reader gets reply encoding for free: the lookup and encode run, the send fails, and the budget is refunded, so the rate cap never applies. | `protocol.rs:591-606,1184-1240,1384-1413` | `fix/msgboard-r2-p2p` | fixed in !20 (8ffb6c12ad) (test proves the attack) |
| 25 | Medium | After a restart the block window holds only the head hash; erigon seeds every canonical hash in the window. Messages anchored before the restart are rejected and never fetched again. | `launch.rs:209` | `fix/msgboard-r2-block-window` | fixed in !18 (44a8f12813) (test proves it) |
| 26 | Medium | Full-board memory is not bounded by the build limit: each finished reply (about 167 MB) stays alive until the client has read it. R5 and R6 are understated. | `rpc.rs:98-106` | `fix/msgboard-r2-rpc` | partly fixed in !19 (1a988468a7); see R5, R6 |
| 27 | Low-Med | Only the tip of each canonical update enters the block window, so messages anchored on intermediate blocks of a multi-block commit are refused. | `launch.rs:305-309` | `fix/msgboard-r2-block-window` | fixed in !18 (44a8f12813) (deliberately stricter than erigon; parity-gaps §28) |
| 28 | Low-Med | Orphan block hashes survive a reorg that lowers the head; reth then accepts messages erigon rejects. | `block_filter.rs:49` | `fix/msgboard-r2-block-window` | fixed in !18 (44a8f12813) |
| 29 | Low | `msgboard_contentPage` shares the two build slots with full-board `msgboard_content`, so looping full builds starve pagers. | `rpc.rs:66-115` | `fix/msgboard-r2-rpc` | fixed in !19 (1a988468a7) |
| 30 | Low | `msgboard_addMessage` verifies PoW on the RPC async worker. | `rpc.rs:105-112` | `fix/msgboard-r2-rpc` | fixed in !19 (1a988468a7) (capped at 8 concurrent) |
| 31 | Low | Withhold strikes live per connection, so a reconnect before the third strike resets escalation. | `protocol.rs:804` | `fix/msgboard-r2-p2p` | fixed in !20 (8ffb6c12ad) |
| 32 | Low | A page call copies the whole board under the board mutex before it applies the cursor; a txpool page copies the whole pool. | `board.rs:766-773`, `txpool_page.rs:184` | none | msgboard half fixed in !22 (6a577610d7): pages scan from the cursor in a hash-ordered index; txpool half open (see R8) |
| 33 | Info | Further erigon differences to document as intentional: `getMessage` miss returns `null` (erigon errors), `addMessage` decode errors return -32602 (erigon -32000), status difficulty shown as 10000/1000000 (erigon 1/100, same ratio), subscription filter `{}` means all categories, lenient penalty for unknown-block bodies. Two parity-gaps entries are stale. | `docs/msgboard-parity-gaps.md` | `fix/msgboard-r2-rpc` | documented in parity-gaps §28-29 (!18, !19) |
| 34 | Info | Test quality: six tests would still pass if the behaviour they test broke (claim release on a dropped send, the session gauge in the connection loop, subscription gauge decrement, two sleep-based tests, an eviction test with no upper bound); ten important behaviours have no test. | test modules | `fix/msgboard-r2-p2p` | fixed in !20 (8ffb6c12ad) |

## Round 3 findings (2026-10-15)

Round 3 was a read-only review of `crates/net/msgboard` and `crates/net/msgboard-types` at the audit commit. It found no Critical or High issue and no panic reachable from network input.

| # | Severity | Finding | Where | Status |
|---|---|---|---|---|
| 35 | Low | `load_from_db` queued the hash key for deletion when it met a duplicate row, which is the row of the copy it kept. | `board.rs` `load_from_db` | fixed (PR 54) |
| 36 | Low | An announced ID with a zero divisor or multiplier passed the work gate and was claimed and requested. | `config.rs` `is_work_acceptable` | fixed (PR 54) |
| 37 | Low | Operator limits were not validated, and extreme values overflowed the window and ingress arithmetic. | `args.rs`, `board.rs`, `protocol.rs` | fixed (PR 54) |
| 38 | Low | `msgboard_content` built the whole response before `--rpc.max-response-size` could refuse it. At the largest `--msgboard.size-limit` that is about 2 GB. | `rpc.rs` | fixed: a call whose estimated response is past 200 MiB is refused before the build |
| 39 | Low | The `msg/1` frame ceiling was checked only after the multiplexer had buffered the frame. | `protocol.rs` `inbound_limits_for` | fixed: the ceiling is declared to the multiplexer |
| 40 | Info | A failure to open or load the database was only logged. | `launch.rs` | fixed: `msgboard.persistence_failures` counts a failure to open, a load that errors, and a load that cannot decode half or more of its rows |
| 41 | Info | A stored row anchored far above the head was kept, announced and never expired. | `board.rs` `seed_window` | fixed: `seed_window` drops messages more than one window above the head |
| 42 | Info | Claims are keyed by the full 121-byte ID, so one work hash announced with different non-hash fields takes several claim slots. | `pending.rs` | fixed: claims are keyed by the 32-byte message hash. A claim keeps the first ID announced while it is still worth fetching and takes a later one when it is not. Exhaustion and the rescue fetch count once per message |
| 43 | Info | `MsgIndex::content_page` with `limit` 0 returns an empty page with no cursor. | `index.rs` | open: the RPC layer rejects `limit` 0, so it is not reachable |

## Verification of findings 1-34 (2026-10-16)

Each finding in rounds 1 and 2 was re-checked against `main` at `787eba55a`: the code that closes it was read at the lines below, and the regression test was found and run. Lines are in `crates/net/msgboard/src/` unless a path is given. Test names are in the same crate unless a path is given. The `Where` column in the tables above keeps the line numbers from the review date and is not updated.

Result: 29 fixed (26 with a residual risk that stays accepted as R6a), 4 accepted (13, 18, 19, 33) and 1 partly open (32: the txpool half, which is R8). Nothing was found unfixed. Two tests were added in this pass, for findings 8 and 33.

| # | Status | Evidence on `main` | Regression test |
|---|---|---|---|
| 1 | fixed | `protocol.rs:275-284` minimum ingress limits, `:326-337` `inbound_limits_for`, `:674-741` outbound queue with the stalled flag | `a_flooding_peer_is_cut_at_the_ingress_limit`, `the_ingress_limits_hold_an_honest_peers_worst_burst`, `a_peer_that_stops_reading_gets_frames_dropped_not_queued_forever` |
| 2 | fixed | `pending.rs:316-384` `claim_from` keeps alternates, `:386-410` `release` hands on, `:431` `sweep` retries | `a_withholding_announcer_does_not_censor_the_message`, `an_expired_claim_is_retried_from_the_next_announcer`, `a_released_claim_moves_to_the_next_announcer_at_once` |
| 3 | fixed | `protocol.rs:414-422` burst and refill, `:767` `ServeBudget` | `distinct_requests_stop_at_the_reply_budget`, `a_repeated_request_is_served_once`, `the_reply_budget_refuses_past_the_burst_and_refills` |
| 4 | fixed | `bin/reth/src/main.rs:205` and `:306` take `flush_guard()`, `launch.rs:285-294` flushes on drop | `the_flush_guard_flushes_when_dropped`, `dropping_the_board_without_a_final_flush_keeps_accepted_messages` |
| 5 | fixed | `board.rs:1086-1118`: the retry set holds hashes only, and a hash whose message left the index is not kept | `a_failing_database_does_not_grow_the_flush_backlog`, `a_failed_flush_keeps_the_write_set_for_the_next_attempt` |
| 6 | fixed | `pending.rs:753-776` `prune` ends only the reservation it queued, `:805-826` only unspent entries count | `spent_reservations_do_not_use_up_the_cap`, `an_old_expiry_does_not_cancel_a_newer_reservation` |
| 7 | fixed | `index.rs:107-125` one `drain` of the prefix, used at `board.rs:409` and `:434`. The test proves the result equals one-at-a-time removal; the cost is structural | `remove_below_block_matches_removing_one_at_a_time` |
| 8 | fixed | `protocol.rs:1533` hands verification to `spawn_blocking` | added: `a_delivery_is_verified_off_the_connection_task`. Replacing the `spawn_blocking` call with an inline call makes it fail (log in the PR) |
| 9 | fixed | `args.rs:23-26` minimums, enforced by the flag parsers | `duration_flags_refuse_values_below_their_minimum` |
| 10 | fixed | `pending.rs:66`, `:74` caps, `:309-340` fail-open past a cap, `:413` sweep at most once per tenth of the TTL | `one_peer_cannot_fill_the_claim_map`, `the_map_stops_growing_at_capacity_but_still_grants_claims`, `maybe_sweep_runs_at_most_once_per_tenth_of_the_ttl` |
| 11 | fixed | `board.rs:129` `flush_lock`, held for the whole flush at `:362` | `a_flush_does_not_take_its_batch_while_another_is_in_flight` |
| 12 | fixed | `board.rs:330-337` trims to `count_limit`; `db.rs:132` `db_load_all` re-files a misfiled row at `:230` | `loading_more_rows_than_the_count_limit_keeps_the_highest_precedence`, `a_misfiled_row_moves_to_its_hash_on_load` |
| 13 | accepted | `docs/msgboard-rpc.md:20` states that `all` exposes `msgboard_addMessage`; `launch.rs:168` installs the module only on a transport that names it | `naming_msgboard_enables_it_on_that_transport_only`, `a_transport_that_does_not_name_msgboard_does_not_get_it` |
| 14 | fixed | `rpc.rs:146` builds on a blocking thread; the whole board is served; `:83` budget added by finding 38 | `content_without_a_limit_returns_the_whole_board`, `content_builds_are_bounded_by_the_permit_count` |
| 15 | fixed | `docs/msgboard-rpc.md:5` input format, `:11` no `--msgboard.enabled` flag, `:28-36` flag table, `:171` paging | `every_documented_flag_name_parses` for the flag names; no test for prose |
| 16 | fixed | `protocol.rs:1361` gossip-disabled ingest returns early; `gossip_disabled_still_serves_explicit_body_requests` fixes the serving rule | `gossip_disabled_suppresses_requests_and_ingest`, `gossip_disabled_still_serves_explicit_body_requests` |
| 17 | fixed | `pending.rs:1-12` describes the current index key | none (comment) |
| 18 | accepted | `msgboard-types/src/pow.rs:145-146` rejects a zero divisor or multiplier; `docs/msgboard-parity-gaps.md` §27.1 | `test_validate_rejects_zero_divisor`, `one_invalid_body_rejects_the_whole_frame` (`msgboard-types`) |
| 19 | accepted | `msgboard-types/src/pow.rs:122` `CheckedPoWMsg` keeps the timestamp; `docs/msgboard-parity-gaps.md` §27.2 | `write_and_reload_roundtrips_through_named_table` (`db.rs`) |
| 20 | fixed | `pending.rs:316-384` and `:1111` `admit`: a returning announcer re-enters only through a session ticket | `looping_sybils_do_not_flush_an_honest_announcer`, `a_repeat_announcement_in_one_session_does_not_re_enter` |
| 21 | fixed | `rpc.rs:37` accepts `"messages"` and `"newMessages"` | `subscribe_accepts_the_erigon_and_the_legacy_kind_names` |
| 22 | fixed | `rpc_api.rs:314` bound deserialiser takes numbers, decimal and hex strings | `content_block_bounds_accept_erigon_block_number_forms` |
| 23 | fixed | `pending.rs:905-980` `RequestPacer` spaces requests to the responder's reply budget; a partial answer is not a strike | `an_honest_full_sync_is_never_penalised`, `a_bulk_sync_past_the_reply_budget_costs_an_honest_responder_nothing`, `a_partial_answer_never_escalates` |
| 24 | fixed | `protocol.rs:745` `is_stalled_and_full`, checked at `:1405` before any lookup or encode | `a_stalled_peer_with_a_full_queue_gets_no_reply_work`, `a_dropped_reply_is_refunded_to_the_budget` |
| 25 | fixed | `launch.rs:376` `seed_head_window` seeds the whole window, called at `launch.rs:213-221` | `startup_seeds_every_hash_in_the_window` |
| 26 | fixed, residual R6a accepted | `rpc.rs:83` 200 MiB estimate refused before the build, two build slots held until handoff | `content_past_the_budget_is_refused_and_names_the_page_method`, `content_permit_is_held_until_the_response_is_handed_off` |
| 27 | fixed | `launch.rs:308` `drive_canonical_head` registers every block of a commit | `a_multi_block_commit_registers_every_block` |
| 28 | fixed | `block_filter.rs:52` `retain` drops hashes outside the window | `a_reorg_to_a_lower_head_forgets_the_orphans`, `a_reorg_to_a_lower_tip_still_moves_the_head` |
| 29 | fixed | `rpc.rs:20` and `:76`: separate permit pool for pages | `content_page_is_not_starved_by_full_board_builds` |
| 30 | fixed | `rpc.rs:215` cap of 8, `:235` verifies on the blocking pool | `add_message_verifies_off_the_runtime_worker`, `add_message_verifies_are_bounded_by_the_permit_count` |
| 31 | fixed | `pending.rs:1010-1056` strikes are kept by the board, not by the connection | `reconnecting_does_not_reset_withholding_escalation` |
| 32 | msgboard half fixed; txpool half open (R8) | `index.rs:292` `content_page` scans from the cursor; `board.rs:1003`. `crates/rpc/rpc/src/txpool_page.rs:171-195` still reads the whole pool | `content_page_scan_follows_limit_not_board_size`, `content_page_matches_the_reference_on_random_boards` (`index.rs`) |
| 33 | accepted | `docs/msgboard-parity-gaps.md` §29.2 lists each difference | `get_message_returns_null_for_an_unknown_hash`, `every_decode_failure_reports_the_same_code`, `add_remote_msgs_skips_unknown_blocks`; added: `an_empty_subscription_filter_delivers_every_category` |
| 34 | fixed | fixed in !20; the tests named here exist and assert the behaviour (a gauge returns to zero on every exit path, a dropped send releases its claim) | `a_request_that_never_reaches_its_peer_releases_its_claim`, `the_gauge_returns_to_zero_on_every_exit_path` (`tests/session_gauge.rs`, `tests/subscription_gauge.rs`), `count_limit_causes_eviction` |

## Residual risks

These risks stay after the fixes. We accept them on purpose, and the auditor should see them stated.

| # | Risk | Why we accept it | Related |
|---|---|---|---|
| R1 | An attacker can delay a message to our node by one 10 s claim TTL per withholding announcer we ask. The message is lost for our node only if every kept alternate withholds, no trusted peer announced it, none of up to 3 non-announcers asked (trusted first, then new subnets) holds it, and no honest announcer reconnects and re-announces before the claim runs out. Each claim remembers announcers in keyed filters, counts at most two announcers per IPv4 /24 or IPv6 /56 in a random draw of 16 alternates (one rejoin each per claim, so at most 2 tickets per member), freezes at 1000 candidates, and puts trusted peers first. Rescue fetches are shared fairly by subnet, 16 per second. Our own nodes on each chain are trusted peers of each other. | No pull-based gossip design can fetch a message no reachable peer serves. Erigon-pulse keeps one claimant and never retries; reth's txpool keeps 8 candidates with the first 4 fixed. Metrics `msgboard.claims_exhausted` and `msgboard.claims_rescued` make an attack visible. | 2, 20 |
| R1a | A peer that answers part of a request can withhold the rest for a small penalty each time. It is never escalated to a ban, but it is asked last on later claims, and other announcers deliver the withheld messages after one 10 s timeout. | Escalating on a partial answer would ban honest peers that pruned stale messages at a block boundary. | 2 |
| R1b | An honest peer can still reach the larger penalty if it prunes every message of a one-message request at three block boundaries within 60 s. | Unlikely in practice. One larger penalty does not ban a peer. | 2 |
| R2 | The per-peer inbound limit (finding 1) cuts the whole session, eth included. A slow but honest peer on a busy board can hit it during one 30 s send stall: after about 150 single-ID announcements at the default message size. At the largest `--msgboard.size-limit`, the multiplexer's own 32 MiB per-connection budget is the real ceiling, so a stalled honest peer can be cut after about 330 frames. | The limit and the 32 MiB budget are in the upstream multiplexer, which we do not change. The cut costs only a low backoff and no reputation, and the peer reconnects. Memory stays at upstream's bound (32 MiB per connection). | 1 |
| R3 | The reply budget (finding 3) is a rate cap with no reputation cost: a peer can request forever. Per peer it allows a 4 MiB burst (more at larger message sizes) and 1 MiB/s after that. Across about 130 peers that is about 130 MiB/s (1.1 Gbit/s) of upload at most. It also slows an honest peer that syncs a full board from us. | On `main` the upload had no bound, so this is a strict improvement. A reputation cost would hit honest erigon peers, which over-request by design. A partial reply looks to erigon like "I no longer have it", which erigon already handles. A node-wide budget is a possible follow-up. | 3 |
| R4 | On SIGTERM, a message accepted between the final flush and the stop of the network is lost. | The window is milliseconds. The fix stops intake before the final flush where that is safe. | 4 |
| R5 | A full default board is about 167 MB of JSON, which is close to reth's default `--rpc.max-response-size` of 160 MiB. A stock reth node cannot send a nearly full board. | Our build raises the default to 200 MiB (see R6). Stock reth and erigon nodes must set `--rpc.max-response-size 200`; the RPC doc says so. | 14 |
| R6a | Full-board build slots (two at a time) are held until jsonrpsee hands each reply to the transport. On HTTP that is before the body is written, so after handoff only the connection limit bounds reply memory (about 167 MB per reply). In a JSON-RPC batch the slot is released when the batch copies the reply. | jsonrpsee 0.26 has no written-to-socket hook. | 26 |
| R6 | Our build raises the default `--rpc.max-response-size` from 160 MiB to 200 MiB so a full board fits. The limit applies to every RPC method, so `debug_trace*`, `eth_getLogs` and others can build up to 25% larger replies before they fail. | Needed for erigon parity on `msgboard_content`. Full-board builds are limited to two at a time. Operators can set the flag lower on nodes that do not serve msgboard. | 14 |
| R7 | Anyone willing to pay the PoW can flush every honest message off the board: eviction removes the oldest block first, then the lowest work, and the cheapest message needs about 168k hashes. | This matches erigon. The PoW cost is the only price. | 20 |
| R8 | A txpool page call costs O(pool) whatever the page size. (msgboard pages no longer do: fixed in !22.) | Bounded by two build slots; a range iterator inside reth's pool would remove it. | 32 |

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
| 2026-10-01 | Round 2 review: findings 20-34 recorded, R7 and R8 added. R1, R1b, R5 and R6 are understated until findings 20, 23 and 26 are fixed. |
| 2026-10-01 | Round 2 fixes merged: !18 (block window), !19 (RPC), !20 (p2p). Findings 20-31, 33 and 34 closed; 26 partly (R6a); 32 open (R8). R1 rewritten for the per-subnet bound. |
| 2026-10-01 | !22 hash-ordered index (finding 32, msgboard half). !23 R1 mitigations: session rejoin, trusted first, rescue fetch from non-announcers, exhaustion metrics. R1 and R8 rewritten. |
| 2026-10-15 | Round 3 review: findings 35-43 recorded. 35-37 fixed in PR 54; 38-41 fixed in the follow-up; 42 and 43 open. |
| 2026-10-16 | Findings 1-34 re-verified against `main` at `787eba55a`: 29 fixed, 4 accepted, 1 partly open (32, txpool half, R8). Regression tests added for findings 8 and 33. |
| 2026-10-16 | Finding 42 fixed: claims keyed by message hash. |
