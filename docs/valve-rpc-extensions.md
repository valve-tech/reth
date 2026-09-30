# Valve RPC extensions

This fork adds RPC methods and parameters that upstream reth does not have. This page describes the keyset (cursor) paging methods. Each one lets a client read a large set in pages, and a page never repeats or skips an entry when the set changes between calls or when the calls go to different replicas.

Offset paging cannot give that. An offset counts positions, and an insert or a removal before the offset moves every later entry. A cursor names a key, and a key does not move.

All the methods here use the same cursor rule. `next` is the last key of this page. The client passes it back unchanged as `after`, which is exclusive: the next page starts at the first key above it. The client stops only when `next` is `null`. This is the same rule as Stripe's `starting_after`, Relay's `endCursor` and NEAR's `last_key`. It is not geth's `nextKey` in `debug_storageRangeAt`, which is the first key of the next page.

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
- `next` is the last sender in this page. Pass it back unchanged as `after`. It is `null` when no sender is left.

**Stop only when `next` is `null`.** Do not stop on a short page. The node stops adding senders to a page when the transactions in it pass about 16 MiB of JSON, so a page can hold fewer than `limit` senders before the end. A page always holds at least one sender, so one sender with more than 16 MiB of transactions makes a larger page.

Each call reads the pool at that time. A sender whose transactions arrive during a walk comes back only if its address is above the cursor at that time. A sender present for the whole walk comes back exactly once, with its transactions as they were when its page was read.

```bash
# First page.
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"txpool_contentPage","params":[{"limit":500}]}' \
  | jq '.result.next'

# Next page: pass `next` back unchanged as `after`.
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

## `msgboard_contentPage`

`msgboard_contentPage` pages the msgboard in ascending message-hash order. It takes `{ limit, after?, category?, fromBlock?, toBlock? }`, where `limit` is required and from 1 to 1000. It returns `{ content, next }`. `content` is the page in erigon-pulse's category map, the same shape as `msgboard_content`. `next` is the last hash in the page, or `null` when no matching message is above it. The full reference is in [msgboard-rpc.md](msgboard-rpc.md#msgboard_contentpage-reth-extension).

Pass `next` back unchanged as `after`, and stop only when `next` is `null`. The node looks one message past the page, so `next` is never `null` while a message remains.

`msgboard_content` has no cursor: it rejects a non-null `after` field with `-32602` (`"after": null` is read as no cursor). Its `offset` still works, for older clients, but it is deprecated because it is unstable across board changes and across replicas. The call with no arguments still returns the whole board, as erigon-pulse does.

```bash
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_contentPage",
       "params":[{"limit":500,"after":"0x3f1c…"}]}' \
  | jq '.result.next'   # pass back unchanged as `after`; stop on null
```
