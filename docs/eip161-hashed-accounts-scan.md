# Scan for EIP-161 leftovers in HashedAccounts

## What the scan checks

Before upstream reth #27252 (in v2.7.0), the state root task wrote EIP-161-deleted accounts into `HashedAccounts` as all-zero rows. `PlainAccountState` deleted them correctly. Nothing fails until reth fully recomputes the trie branch that holds such a row. Then the state root diverges and stays wrong. Our fleet ran v2.3 to v2.6, so a node can carry these rows.

`reth db scan-empty-hashed-accounts` finds them. It makes two sequential passes:

1. It walks `PlainAccountState` and keeps `keccak256(address)` of every empty account (nonce 0, balance 0, no code) in a set.
2. It walks `HashedAccounts`. For each empty row, the key in the set means **legit**: a pre-EIP-161 empty account that nothing has touched since. A key outside the set means **suspect**: the bug left the row behind.

The command is read-only. It prints the counts, up to 10 suspect hashed addresses, and one machine-readable line:

```
RESULT suspects=0 legit=12 hashed_empty=12 plain_empty=12 hashed_rows=... plain_rows=... elapsed_secs=...
```

`suspects=0` is a clean node. The scan cannot name the address behind a suspect, because `HashedAccounts` holds no preimages.

The command refuses a storage v2 datadir, because storage v2 has no `PlainAccountState` to compare against.

## How to run it on a live node

Run it next to the node, with the node's own binary, datadir and chain. The node does not need to stop.

```
reth db --datadir /path/to/datadir --chain pulsechain scan-empty-hashed-accounts
```

Use the path in the node unit's `--datadir`. On a box with several reths, pick the unit for the chain you want.

Why it is safe on a live node:

- It opens MDBX read-only. MDBX allows readers from other processes next to the node's writer.
- It skips the static file consistency check. It reads only two MDBX tables.
- It renews the read transaction every 1,000,000 rows or 5 seconds. A long read transaction pins old pages, and the database file grows while the node writes. The scan remembers the last key, opens a new transaction and seeks past that key.
- It throttles to 200,000 rows per second by default. Set `--max-rows-per-sec 0` to remove the limit, or lower it on a busy box.
- Memory is bounded. The set of empty plain accounts costs about 64 bytes per entry. The scan aborts above 5,000,000 entries (`--max-plain-empty`), which is about 320 MB.

Rows that the node writes between two transactions can be seen or missed. Run the scan twice if a result looks borderline.

## Expected runtime and IO

The numbers are per 100M rows in each table. A PulseChain mainnet node has the same number of rows in both tables, so read "100M" as your account count.

| Setting | Runtime for 100M accounts (both passes, 200M rows) |
|---|---|
| Default throttle, 200k rows/s | about 17 minutes |
| No throttle, warm page cache | about 1 minute |
| No throttle, cold NVMe | a few minutes, bound by disk reads |

Basis: I measured 4M rows (2M in each table) in 0.9 to 1.3 s on an Apple Silicon laptop, release build, warm page cache. That is 3 to 4.4M rows/s. The throttle, not the disk, sets the default runtime.

IO: an account row is small (20 or 32 byte key, about 10 to 40 bytes of value). I estimate 5 to 6 GB of sequential reads per table per 100M rows, from the row layout, not from a measurement. At the default throttle that is about 6 MB/s.

To get your own row counts first, run `reth db --datadir ... --chain pulsechain stats` and read the `PlainAccountState` and `HashedAccounts` lines.

## What to do on hits

Do not run `reth db repair-trie` as the fix. It rebuilds trie nodes from `HashedAccounts`, so it treats the bad rows as real accounts and writes them into the trie.

The repair is to rebuild `HashedAccounts` from `PlainAccountState`, then rebuild the trie from the clean hashed state. Upgrade to a release that carries #27252 (v2.7.0 or later) first, or the node creates new bad rows. Then, with the node stopped:

```
reth stage drop --datadir /path/to/datadir --chain pulsechain account-hashing
reth stage drop --datadir /path/to/datadir --chain pulsechain merkle
```

Start the node. At launch, reth finds stage checkpoints behind the first stage (`check_pipeline_consistency`). The pipeline then runs the account hashing stage over the full plain state and then the merkle stage from scratch. The merkle rebuild is the long part: plan for hours on mainnet-sized state, and keep the node out of the load balancer until it is at the tip.

After the rebuild:

1. Run the scan again. Expect `suspects=0`.
2. Run `reth db --datadir ... --chain pulsechain repair-trie --dry-run`. Expect no inconsistencies.

I expect that `HashedStorages` does not need a rebuild. The fix in #27252 changes only the account write, and a drop of `storage-hashing` costs many more hours. If `repair-trie --dry-run` still reports storage-trie inconsistencies after the rebuild, drop `storage-hashing` too.
