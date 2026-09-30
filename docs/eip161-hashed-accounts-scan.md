# Scan for EIP-161 leftovers in HashedAccounts

## What the scan checks

Before upstream reth #27252 (in v2.7.0), the state root task wrote EIP-161-deleted accounts into `HashedAccounts` as all-zero rows. Canonical execution deleted them. Nothing fails until reth fully recomputes the trie branch that holds such a row. Then the state root diverges and stays wrong. Our fleet ran v2.3 to v2.6, so a node can carry these rows.

`reth db scan-empty-hashed-accounts` finds them. An all-zero row is not always a bug: Ethereum and PulseChain state still holds pre-EIP-161 empty accounts that nothing has touched since. The command separates the two. It picks the method from the datadir's storage settings and prints which one ran.

**v1 (storage v1, has `PlainAccountState`).** Pass 1 walks `PlainAccountState` and keeps `keccak256(address)` of every empty account (nonce 0, balance 0, no code). Pass 2 walks `HashedAccounts`. An empty row whose key is in the set is **legit**. Any other empty row is a **suspect**.

**v2 (storage v2, hashed state only).** Storage v2 has no `PlainAccountState`. The reference is the stored `AccountsTrie` instead. Legit empty accounts are real leaves in the trie. The bug rows never reached the trie, because the incremental state root treated them as removals. Pass 1 walks `HashedAccounts` and collects the empty rows. Pass 2 checks each one against the trie:

1. It re-reads the row. If the node changed it since pass 1, the row is skipped and counted as `changed`.
2. It finds the deepest stored branch node on the row's nibble path.
3. It rehashes the smallest subtree whose hash the trie stores, from `HashedAccounts` rows and their storage roots. It tries each choice of the subtree's empty rows and keeps the one that matches the stored hash. A match with the row is **legit**. A match without it is a **suspect**.
4. If no choice matches, the subtree is too large, or no stored hash covers it, the row is **undetermined**, with a reason.

The masks in a branch node never decide a row on their own. A stale or corrupt `state_mask` or `tree_mask` would otherwise turn a legit row into a suspect. Every suspect in the output is hash-confirmed.

Step 3 is needed because `hash_mask` in a stored branch node marks only branch children. The trie never stores a leaf's hash, so the check rehashes the parent branch. Reth does not store the root node either. For rows whose nearest stored hash is the root, the check rehashes the root and compares it with the state root of the block the trie holds. That block is the Finish checkpoint's `partial_state_trie` if it is set, because the node can persist the trie behind the Finish block. Otherwise it is the Finish block.

The command is read-only. It prints the counts per class, up to 10 samples each of suspects and undetermined rows (hashed address and reason), and one machine-readable line:

```
RESULT mode=v2 suspects=0 legit=12 undetermined=0 changed=0 hashed_empty=12 plain_empty=0 hashed_rows=... plain_rows=0 elapsed_secs=...
```

`suspects=0 undetermined=0` is a clean node. In v2 mode the report also counts suspects that still have `HashedStorages` entries. A bug row should have none. The scan cannot name the address behind a hashed row, because `HashedAccounts` holds no preimages.

## How to run it on a live node

Run it next to the node, with the node's own binary, datadir and chain. The node does not need to stop.

```
reth db --datadir /path/to/datadir --chain pulsechain scan-empty-hashed-accounts
```

Use the path in the node unit's `--datadir`. On a box with several reths, pick the unit for the chain you want.

Why it is safe on a live node:

- It opens MDBX read-only. MDBX allows readers from other processes next to the node's writer.
- It skips the static file consistency check. It reads MDBX tables and, in v2 mode, the header of the block the trie holds.
- It renews the read transaction every 1,000,000 rows or 5 seconds. A long read transaction pins old pages, and the database file grows while the node writes. The table walk remembers the last key, opens a new transaction and seeks past that key.
- In v2 mode, it checks each empty row inside one transaction. The node commits the trie, the hashed state and the Finish checkpoint together, so one transaction sees them consistent.
- It throttles to 200,000 rows per second by default. Set `--max-rows-per-sec 0` to remove the limit, or lower it on a busy box. In v2 pass 2 the throttle counts empty rows only. The trie lookups and rehash reads for one row (at most 4,096 rows) are not throttled.
- Memory is bounded. The scan aborts above 20,000,000 empty accounts (`--max-plain-empty`) and prints how many it read. PulseChain inherits Ethereum's pre-EIP-161 empty accounts, which can be millions. At the cap, v2 holds about 640 MB (32 bytes per row) and v1 about 1 to 1.3 GB (hash set overhead).

Rows that the node writes between two transactions can be seen or missed. Run the scan twice if a result looks borderline.

## Expected runtime and IO

The numbers are per 100M accounts.

| Mode and setting | Rows read | Runtime |
|---|---|---|
| v1, default throttle (200k rows/s) | 200M (both tables) | about 17 minutes |
| v2, default throttle (200k rows/s) | 100M (`HashedAccounts` only) | about 8 minutes |
| Either, no throttle, warm page cache | as above | under 1 minute |
| Either, no throttle, cold NVMe | as above | a few minutes, bound by disk reads |

Basis: I measured 4M rows in 0.9 to 1.3 s on an Apple Silicon laptop, release build, warm page cache. That is 3 to 4.4M rows/s. The throttle, not the disk, sets the default runtime.

v2 adds the trie checks, one per empty row. Each check is up to 63 point lookups in `AccountsTrie` plus a rehash of a small subtree. On a mainnet-sized trie the stored nodes reach depth 5 to 6, so an unstored subtree holds a few rows. The root rehash reads the rows under the unhashed children of 16 depth-1 nodes, and those are rare in a large trie. Expect well under 1 ms per empty row, so seconds for thousands of empty rows. This is an estimate: I tested the method only on tries of up to 3,000 accounts.

IO: an account row is small (20 or 32 byte key, about 10 to 40 bytes of value). I estimate 5 to 6 GB of sequential reads per table per 100M rows, from the row layout, not from a measurement. At the default throttle that is about 6 MB/s.

To get your own row counts first, run `reth db --datadir ... --chain pulsechain stats` and read the `HashedAccounts` line.

## What to do on hits

Upgrade to a release that carries #27252 (v2.7.0 or later) first, or the node creates new bad rows. Do not run `reth db repair-trie` as the fix. It rebuilds trie nodes from `HashedAccounts`, so it writes the bad rows into the trie.

### Storage v1

Rebuild `HashedAccounts` from `PlainAccountState`, then rebuild the trie. With the node stopped:

```
reth stage drop --datadir /path/to/datadir --chain pulsechain account-hashing
reth stage drop --datadir /path/to/datadir --chain pulsechain merkle
```

Start the node. At launch, reth finds stage checkpoints behind the first stage (`check_pipeline_consistency`). The pipeline then runs the account hashing stage over the full plain state and then the merkle stage from scratch. The merkle rebuild is the long part: plan for hours on mainnet-sized state, and keep the node out of the load balancer until it is at the tip.

I expect that `HashedStorages` does not need a rebuild. The fix in #27252 changes only the account write, and a drop of `storage-hashing` costs many more hours. If `repair-trie --dry-run` still reports storage-trie inconsistencies after the rebuild, drop `storage-hashing` too.

### Storage v2

**Never run `reth stage drop account-hashing` or `hashing` on a storage v2 node.** On v2, `HashedAccounts` is the canonical state, and the account hashing stage is a no-op. The drop clears the state and nothing rebuilds it.

The bug rows never reached the trie, so the stored trie should already be correct. Check that before any delete:

1. Run `reth db --datadir ... --chain pulsechain repair-trie --dry-run`. Only if it reports no inconsistencies is the trie correct.
2. If the dry run is clean, the repair is to delete the suspect rows from `HashedAccounts`. Delete only suspects from the scan output: they are hash-confirmed. Never delete undetermined rows.
3. If the dry run is not clean, stop and escalate. The trie itself needs attention first.

An all-zero row and a missing row mean the same thing to execution, so the delete changes no state. No reth command deletes single rows yet. That needs a small write tool, built and reviewed separately. Until then the rows are harmless unless something recomputes the trie from hashed state. Do not run `repair-trie` without `--dry-run` on a node with suspects.

Treat undetermined rows as unknown, not as clean. Run the scan again: a node that wrote during the check can cause a mismatch. If a row stays undetermined, report its hashed address and reason.

### After the repair

1. Run the scan again. Expect `suspects=0 undetermined=0`. A few `changed` rows are normal on a live node.
2. Run `reth db --datadir ... --chain pulsechain repair-trie --dry-run`. Expect no inconsistencies.
