# MsgBoard JSON-RPC Reference

A practical guide to talking to a reth node's `msgboard_*` namespace. For protocol/wire-level details (P2P codes, RLP layouts, gRPC), see [`specs/02-msgboard.md`](../specs/02-msgboard.md). This document is the reference for **client-side request/response** shapes — the surface that users and AIs need to construct valid calls and parse replies.

> **Implementation note:** This describes the **reth** msgboard implementation on the `extension-model` branch. Method signatures match the `erigon-pulse` JSON-RPC surface (so existing erigon-pulse RPC clients work unchanged) with one ergonomic improvement: `msgboard_addMessage` accepts a structured JSON object instead of hex-encoded RLP. All other methods — including `msgboard_content`'s grouped-by-category map and `msgboard_subscribe`'s `["newMessages", filter?]` shape — are bit-for-bit compatible.

---

## Enabling the namespace

Two CLI flags are required:

```
--msgboard.enabled                 # turn on the P2P sub-protocol and RPC handler
--http.api eth,net,web3,msgboard   # expose msgboard_* over HTTP
--ws.api  eth,net,web3,msgboard    # expose msgboard_* over WebSocket (for subscriptions)
```

The board persists to `<datadir>/msgboard/` (override with `--msgboard.db-dir`). On first start the directory is created automatically.

Other tunables (defaults shown):

| Flag | Default | Meaning |
|---|---|---|
| `--msgboard.work-multiplier` | `10000` | Minimum accepted PoW multiplier |
| `--msgboard.work-divisor` | `1000000` | Maximum accepted PoW divisor |
| `--msgboard.size-limit` | `8192` | Max bytes of `data` per message |
| `--msgboard.count-limit` | `10000` | Max live messages on the board |
| `--msgboard.block-range` | `120` | Blocks before a message expires |
| `--msgboard.stale-block-buffer` | `3` | Reject peer-announced messages within this many blocks of the lower bound |
| `--msgboard.commit-every` | `15s` | How often to flush in-memory messages to MDBX. Accepts `humantime` (`15s`, `2m`, `500ms`) |
| `--msgboard.log-every` | `30s` | How often to emit a periodic stats line at INFO level. Set very large to effectively disable. |
| `--msgboard.gossip-disable` | `false` | Skip outbound P2P announcements (read-only / observer node). Inbound message acceptance is unaffected. |

---

## Methods

All methods are in the `msgboard` namespace. Hex-encoded byte values use the `0x`-prefixed form throughout.

### `msgboard_status`

No params. Returns board statistics.

**Response (`MsgboardStatus`):** All integer fields are `0x`-prefixed hex strings (Ethereum JSON-RPC "quantity" form), matching erigon-pulse byte-for-byte.

| Field | Type | Meaning |
|---|---|---|
| `enabled` | bool | Whether the board is currently accepting messages (post-sync) |
| `count` | hex uint64 | Live messages currently held |
| `size` | hex uint64 | Sum of all `data` lengths in bytes |
| `workMultiplier` | hex uint64 | Minimum multiplier the board accepts |
| `workDivisor` | hex uint64 | Maximum divisor the board accepts |
| `headBlock` | hex uint64 | Block number of the chain head as the board sees it. **Reth extension** — not present in erigon. |

```bash
curl -s http://localhost:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_status","params":[]}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "enabled": true,
    "count": "0x2a",
    "size": "0x1cac",
    "workMultiplier": "0x2710",
    "workDivisor": "0xf4240",
    "headBlock": "0x16553e3"
  }
}
```

### `msgboard_categories`

No params. Returns a sorted list of every category hash currently represented in the live board.

**Response:** `B256[]` (32-byte category hashes, hex).

```bash
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_categories","params":[]}'
```

```json
{ "jsonrpc": "2.0", "id": 1, "result": [
  "0x67b9b797bd9b41ec0c2f8a8e2b85d6c2d11c8b5b76e4729db5d2b0a4e1f0a3a2",
  "0xa3e2…"
]}
```

A category is **any 32-byte value**. The protocol does not parse it, hash it, or assign it semantics — it's stored and compared as raw `bytes32`. By convention, clients use `keccak256(<utf-8 category text>)` so that human-readable categories (`"news"`, `"alerts"`) are addressable across applications, but nothing in the protocol enforces this. A category may equally well be a token address, an EIP-712 domain hash, a random nonce, or any other 32-byte identifier — pick whatever scheme suits your application and document it for your peers.

### `msgboard_content`

Optional filter. Returns matching live messages **grouped by category**.

**Params:** `[filter?]` where `filter` (`ContentFilter`) is:

| Field | Type | Optional | Meaning |
|---|---|---|---|
| `category` | B256 hex | yes | Restrict to one category |
| `fromBlock` | uint64 | yes | Inclusive lower bound on `blockNumber` |
| `toBlock` | uint64 | yes | Inclusive upper bound on `blockNumber` |

Omitting the filter (or any field) means "no constraint." Pass `null` or `[]` for no filter.

**Response:** `{ [categoryHex: string]: MsgboardMsg[] }` — a JSON object whose keys are lowercase `0x…` 32-byte category ids and whose values are arrays of [`MsgboardMsg`](#message-shape). If a `category` filter is supplied, the map contains at most one entry; if no messages match, the map is empty (`{}`).

```bash
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":1,
    "method":"msgboard_content",
    "params":[{ "category": "0x67b9…", "fromBlock": 23415000 }]
  }' | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "0x67b9b797bd9b41ec…": [
      { "version": "0x1", "blockHash": "0x…", "blockNumber": "0x16553e3", "…": "…" }
    ],
    "0xa3e2…": [ /* … */ ]
  }
}
```

### `msgboard_getMessage`

Look up a single message by its SHA-256 PoW hash.

**Params:** `[hash: B256]`

**Response:** `MsgboardMsg | null` (`null` if no message with that hash is on the board).

```bash
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_getMessage","params":["0xabcd..."]}'
```

### `msgboard_addMessage`

Submit a new message. **The PoW must already be solved client-side** — the node only verifies; it does not mine.

**Params:** `[rlp]` where `rlp` is a `0x`-prefixed hex string carrying the **RLP-encoded `PoWMsg`**. This matches erigon-pulse's `msgboard_addMessage`, which takes `hexutility.Bytes`.

The `PoWMsg` is an RLP list of seven fields, in this exact order:

| RLP index | Field | Type | Meaning |
|---|---|---|---|
| 0 | `version` | byte | Encoding version — **must be `1`** |
| 1 | `blockHash` | bytes32 | A *recent* block hash (within `block-range` of head) |
| 2 | `nonce` | uint64 | The nonce that solves the PoW |
| 3 | `workMultiplier` | uint64 | Multiplier used (≥ node's minimum) |
| 4 | `workDivisor` | uint64 | Divisor used (≤ node's maximum) |
| 5 | `category` | bytes32 | Arbitrary 32-byte category id (see [Categories](#categories)) |
| 6 | `data` | bytes | Arbitrary payload, ≤ `size-limit` bytes |

At least one of `category` or `data` must be non-empty (a zero `category` *and* empty `data` is rejected as `invalid data`).

**Response:** `B256` — the message's SHA-256 PoW hash on success.

**Errors:** see [Error codes](#error-codes). RLP decode failures surface as `-32602 powmsg: rlp decode error: …`.

```bash
# `0xf8…` here is the RLP-encoded PoWMsg the client mined.
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":1,
    "method":"msgboard_addMessage",
    "params":["0xf8…"]
  }'
```

A minimal Node.js encoder using viem:

```javascript
import { encodeRlp, toRlp, toHex } from 'viem';

const rlp = toRlp([
  '0x01',                  // version
  blockHash,               // 32 bytes
  toHex(nonce),
  toHex(workMultiplier),
  toHex(workDivisor),
  category,                // 32 bytes
  data,                    // arbitrary bytes
]);

await fetch(rpcUrl, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'msgboard_addMessage', params: [rlp],
  }),
});
```

### `msgboard_subscribe` / `msgboard_unsubscribe` (WebSocket)

Streams newly accepted messages to the subscriber. Available on the **WebSocket transport only** (jsonrpsee binds subscriptions to WS, not HTTP) — start the node with `--ws --ws.port 8546 --ws.api msgboard,...`.

**Subscribe:** method `msgboard_subscribe`, params `["newMessages", filter?]`:

- First param: literal string `"newMessages"` — the subscription kind (only one is currently supported; matches erigon-pulse's discriminator).
- Second param (optional): a `NewMessagesFilter` object:

  | Field | Type | Optional | Meaning |
  |---|---|---|---|
  | `category` | B256 hex | yes | Only emit messages whose `category` matches |

If you omit the filter (`["newMessages"]`) the server pushes every accepted message; with a filter, the server discards non-matching messages before sending.

**Unsubscribe:** method `msgboard_unsubscribe`, params `[subscription_id]`.

**Each notification** is a [`MsgboardMsg`](#message-shape).

**Errors:**
- `-32602 unsupported subscription kind: "<kind>"` — first param was anything other than `"newMessages"`.

#### Wire example (`websocat`)

```bash
# Open a WS connection. Each line you send is one frame; each line received is one frame.
websocat ws://localhost:8546

# Send (one line) — subscribe to ALL new messages:
{"jsonrpc":"2.0","id":1,"method":"msgboard_subscribe","params":["newMessages"]}

# Or subscribe with a category filter:
{"jsonrpc":"2.0","id":1,"method":"msgboard_subscribe","params":["newMessages",{"category":"0x67b9…"}]}

# Receive (subscription id):
{"jsonrpc":"2.0","id":1,"result":"0x9f3a4b…"}

# Receive (one frame per accepted message — all uint fields hex):
{"jsonrpc":"2.0","method":"msgboard_subscription","params":{
  "subscription":"0x9f3a4b…",
  "result":{
    "version":"0x1",
    "blockHash":"0x…",
    "blockNumber":"0x16553e3",
    "nonce":"0x814f6b",
    "workMultiplier":"0x2710",
    "workDivisor":"0xf4240",
    "category":"0x67b9…",
    "data":"0x68656c6c6f",
    "hash":"0xabcd…"
  }
}}

# To stop:
{"jsonrpc":"2.0","id":2,"method":"msgboard_unsubscribe","params":["0x9f3a4b…"]}
```

#### Browser / Node.js (raw `WebSocket`)

```javascript
const ws = new WebSocket('ws://localhost:8546');

ws.onopen = () => {
  ws.send(JSON.stringify({
    jsonrpc: '2.0', id: 1,
    method: 'msgboard_subscribe',
    // Either ['newMessages'] or ['newMessages', { category: '0x…' }]
    params: ['newMessages']
  }));
};

let subId;
ws.onmessage = (e) => {
  const m = JSON.parse(e.data);

  // Subscription confirmation: result is the subscription id (string).
  if (m.id === 1 && m.result) { subId = m.result; return; }

  // Notifications carry method:"msgboard_subscription".
  if (m.method === 'msgboard_subscription') {
    const msg = m.params.result;          // MsgboardMsg
    // …filter by msg.category, msg.blockNumber, etc., on the client
  }
};

// To stop later:
// ws.send(JSON.stringify({jsonrpc:'2.0', id:2, method:'msgboard_unsubscribe', params:[subId]}));
```

#### `eth-utils` / ethers.js style (any jsonrpsee-compatible WS client)

Any client that already speaks `eth_subscribe` works with `msgboard_subscribe` unchanged — the framing is identical. The only difference is the notification's `method` field is `msgboard_subscription` (not `eth_subscription`), so route notifications by `method` rather than assuming.

#### Lag handling

The server backs the subscription with a `tokio::sync::broadcast` channel and **silently drops** notifications when the client falls behind (via `BroadcastStream::filter_map`). A slow consumer will miss messages but the connection stays open. If you need at-most-once *or* at-least-once delivery, pair the subscription with periodic `msgboard_content` polls and de-duplicate by `hash`.

---

## Message shape

`MsgboardMsg` (returned by `getMessage`, `content`, and the subscription). All integer fields are `0x`-prefixed hex strings (Ethereum JSON-RPC "quantity" form), matching erigon-pulse's `RPCPoWMsg` byte-for-byte.

| Field | Type | Notes |
|---|---|---|
| `version` | hex uint8 | Always `"0x1"` |
| `blockHash` | B256 hex | Block the message is anchored to |
| `blockNumber` | hex uint64 | Resolved server-side from `blockHash` |
| `nonce` | hex uint64 | PoW nonce |
| `workMultiplier` | hex uint64 | |
| `workDivisor` | hex uint64 | |
| `category` | B256 hex | Arbitrary 32-byte category id (see [Categories](#categories)) |
| `data` | hex bytes | Payload (0…`size-limit` bytes) |
| `hash` | B256 hex | SHA-256 PoW hash — message identity |

---

## Categories

A category is **any 32-byte value** (`bytes32`). The protocol does not parse, hash, or assign semantics to it — categories are just keys you choose to bucket related messages. The only protocol-level rule is that a message with both `category == 0x000…0` *and* empty `data` is rejected (`invalid data`); everything else is accepted as long as it's exactly 32 bytes.

Common conventions clients choose:

| Convention | When it makes sense |
|---|---|
| `keccak256(<utf-8 text>)` | Cross-app human-readable buckets ("news", "alerts"). Both ends must hash identical bytes. |
| `bytes32(uint256(token_address))` | Per-token feeds (left-pad the 20-byte address). |
| EIP-712 domain hash | Application/version namespacing without collisions. |
| Random 32 bytes | Private channels — only collaborators who know the value can post or filter to it. |
| Application id ‖ topic id (split bits) | Hierarchical schemes with a single 32-byte slot. |

Pick one scheme per application and document it for your peers. The node only knows about categories that *currently exist* on the live board; `msgboard_categories` returns the set, not a registry.

---

## Proof of work

**Required to construct a valid `addMessage` call.** Conceptually:

```
difficulty       = (2^24 + len(data) × 10_000) × workMultiplier / workDivisor
diff_digest      = sha256(workMultiplier_be8 ‖ workDivisor_be8)[16:]   // last 16 bytes
scalar           = (nonce × u128(diff_digest) + u256(blockHash)) mod secp256k1_order
challenge        = x_coordinate(G × scalar)                            // 32-byte x of secp256k1 point
hash             = sha256(challenge ‖ category ‖ data)
valid            = u256_be(hash) % difficulty == 0   // modular check, NOT leading zeros
```

Mining loop on the client: pick `(workMultiplier, workDivisor)`, fetch a recent `blockHash`, then iterate `nonce = 1, 2, …` recomputing `hash` until the `% difficulty == 0` condition holds.

Reference implementation: `crates/net/msgboard-types/src/pow.rs` — `PoWMsg::calculate_hash` and `PoWMsg::to_checked` are the exact functions the node runs to verify.

---

## Error codes

`addMessage` is the only method that surfaces validation errors. Codes follow the erigon-pulse convention:

| Error string | Code | Cause |
|---|---|---|
| `powmsg: invalid version` | `-32602` | `version != 1` |
| `powmsg: invalid block hash` | `-32602` | Zero hash |
| `powmsg: invalid nonce` | `-32602` | `nonce == 0` |
| `powmsg: invalid difficulty` | `-32602` | `workMultiplier == 0` or `workDivisor == 0` |
| `powmsg: invalid data` | `-32602` | Both `category` and `data` empty |
| `powmsg: invalid work` | `-32602` | PoW does not satisfy `hash % difficulty == 0` |
| `msgboard: message too large` | `-32000` | `len(data) > size-limit` |
| `msgboard: message work too easy` | `-32000` | Ratio below node's minimum |
| `msgboard: message block too old` | `-32000` | `blockHash` is unknown / outside the live window |
| `msgboard: message exists` | `-32000` | A message with this hash is already on the board |
| `msgboard: board overflow` | `-32000` | Board at capacity and the new message has the lowest precedence |
| `msgboard: not synced` | `-32000` | Node is still doing initial sync; try again later |

---

## Common gotchas

- **`blockHash` must be recent.** If your `blockHash` is older than `head − block-range + stale-block-buffer` blocks, the node will reject with `block too old`. Fetch the head via `eth_blockNumber` / `eth_getBlockByNumber("latest", false)` immediately before starting your PoW search.
- **Messages expire.** A successfully accepted message disappears from the board once its `blockNumber < head − block-range`. Subscribers see no "delete" event — clients should treat absence-on-`getMessage` as deletion.
- **Categories are opaque 32-byte values.** The protocol does not interpret or hash them — see [Categories](#categories). Clients sharing a category must agree on its exact byte representation; if you use `keccak256(text)`, the two ends must agree on the exact UTF-8 (no trim, no case fold) to land in the same bucket.
- **The subscription requires the kind discriminator.** `msgboard_subscribe`'s first param must be the literal string `"newMessages"` — sending an empty `params: []` returns a parse error. WebSocket transport must be enabled (`--ws --ws.api msgboard,...`); HTTP can't carry subscriptions.
- **The subscription drops on lag.** A slow consumer misses notifications silently (broadcast channel overflow). For complete history, periodically reconcile via `msgboard_content` and de-dupe by `hash`.
- **Sync gate.** Until initial sync completes, `addMessage` returns `not synced`. Use `msgboard_status` (`headBlock`) and `eth_syncing` together to decide when to start submitting.
- **The board does not mine.** The node only validates; PoW must be done client-side.

---

## Quick test (after enabling)

```bash
# 1. Confirm namespace is exposed
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_status","params":[]}' | jq

# 2. List currently active categories
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_categories","params":[]}' | jq

# 3. Pull all live messages (use cautiously on a busy board)
curl -s http://localhost:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"msgboard_content","params":[]}' | jq '.result | length'
```

If `msgboard_status` returns `method not found`, the namespace isn't on `--http.api`. If it returns `enabled: false`, the `--msgboard.enabled` flag is missing.
