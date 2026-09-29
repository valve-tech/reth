# Valve RPC extensions

This fork adds RPC methods and parameters that upstream reth does not have. This page describes the keyset (cursor) paging methods. Each one lets a client read a large set in pages, and a page never repeats or skips an entry when the set changes between calls or when the calls go to different replicas.

Offset paging cannot give that. An offset counts positions, and an insert or a removal before the offset moves every later entry. A cursor names a key, and a key does not move.

## `txpool_contentPage` and `txpool_inspectPage`

These are paged forms of `txpool_content` and `txpool_inspect`. The node registers them on every transport whose namespace list names `txpool` (`--http.api`, `--ws.api`, `--ipc.api`), and on no other. Upstream's `txpool_*` methods do not change.

**Params:** `[request?]`, where `request` is:

| Field | Type | Optional | Meaning |
|---|---|---|---|
| `limit` | number | yes | Most senders in the page. Default and maximum `1000`. `0` or more than `1000` gives `-32602`. |
| `after` | address | yes | The page starts at the first sender above this address. Omitted: the page starts at the lowest sender. |

**Response:** `{ "pending": {…}, "queued": {…}, "next": address | null }`.

- `pending` and `queued` have the same shape as in `txpool_content` (or `txpool_inspect`): sender address, then decimal nonce, then the transaction (or the inspect summary).
- A page lists senders in ascending address order. A sender's transactions are all in one page, on both sides. A page never splits a sender.
- `next` is the `after` value for the next page. It is the last sender in this page. It is `null` when no sender is left.

**Stop when `next` is `null`.** Do not stop on a short page. The node stops adding senders to a page when the transactions in it pass about 16 MiB of JSON, so a page can hold fewer than `limit` senders before the end. A page always holds at least one sender, so one sender with more than 16 MiB of transactions makes a larger page.

The `next` field follows the Ethereum precedent for keyset paging: geth's `debug_accountRange` returns `next`, geth's `debug_storageRangeAt` returns `nextKey`, and Alchemy's `alchemy_getAssetTransfers` returns `pageKey`. Each is the key to pass back, and each is empty at the end. An explicit cursor lets the node end a page early for size without the client mistaking it for the end.

Each call reads the pool at that time. A sender whose transactions arrive during a walk comes back only if its address is above the cursor at that time. A sender present for the whole walk comes back exactly once, with its transactions as they were when its page was read.

```bash
# First page.
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"txpool_contentPage","params":[{"limit":500}]}' \
  | jq '.result.next'

# Next page: pass the `next` value back as `after`.
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"txpool_inspectPage",
       "params":[{"limit":500,"after":"0x00000000219ab540356cBB839Cbe05303d7705Fa"}]}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "pending": { "0x0216d5032f356960Cd3749C31Ab34eEFF21B3395": { "806": { "…": "…" } } },
    "queued": {},
    "next": "0x0216d5032f356960Cd3749C31Ab34eEFF21B3395"
  }
}
```

## `msgboard_content` hash cursor

`msgboard_content` takes an optional `after` hash in its filter. With `after`, the node orders the matching messages by message hash, ascending, and returns those above `after`, up to `limit`. The full reference is in [msgboard-rpc.md](msgboard-rpc.md#paging-reth-extension).

The response stays erigon-pulse's category map, so it has no room for a `next` field. The client takes the largest `hash` in the page, across all categories, as the next `after`. It stops when a page is empty or holds fewer than `limit` messages; a `msgboard_content` page is never short for size. Start the walk with the zero hash: a call without `after` returns the first page in board precedence order, not hash order.

`offset` still works, for older clients, but it is unstable across board changes and across replicas. `after` with `offset` gives `-32602`. The call with no arguments still returns the whole board, as erigon-pulse does.

```bash
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_content",
       "params":[{"limit":500,"after":"0x0000000000000000000000000000000000000000000000000000000000000000"}]}' \
  | jq '[.result[][] | .hash] | max'   # the next `after`
```
