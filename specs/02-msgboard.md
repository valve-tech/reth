# MsgBoard Specification

This document specifies the MsgBoard feature — a decentralized message board protocol integrated into an Ethereum execution client. Messages are proof-of-work protected, propagated over devp2p, and stored/queried via gRPC and JSON-RPC APIs.

**Scope:** All msgboard-related changes. Reference implementation: `private-erigon-pulse` at tag `v3.0.0-RC8`.

---

## Table of Contents

1. [Overview](#1-overview)
2. [P2P Protocol](#2-p2p-protocol)
3. [Data Model](#3-data-model)
4. [Proof of Work](#4-proof-of-work)
5. [Board Algorithm](#5-board-algorithm)
6. [Block Filtering and Pruning](#6-block-filtering-and-pruning)
7. [Message Lifecycle](#7-message-lifecycle)
8. [gRPC API](#8-grpc-api)
9. [JSON-RPC API](#9-json-rpc-api)
10. [P2P Integration (Sentry Layer)](#10-p2p-integration-sentry-layer)
11. [Fetch Layer](#11-fetch-layer)
12. [Send Layer](#12-send-layer)
13. [Database Storage](#13-database-storage)
14. [Configuration](#14-configuration)
15. [Deployment Modes](#15-deployment-modes)
16. [Metrics](#16-metrics)
17. [Docker Compose Dev Network](#17-docker-compose-dev-network)

---

## 1. Overview

MsgBoard is a sidecar protocol (`msg/1`) that piggybacks on the existing `eth` devp2p protocol. It enables nodes to:

1. Submit messages with proof-of-work authentication
2. Propagate messages to peers via gossip
3. Store messages linked to recent blockchain blocks
4. Query messages via gRPC and JSON-RPC APIs
5. Subscribe to new messages via WebSocket

Messages are ephemeral — they expire when their referenced block falls outside the configured block range window.

---

## 2. P2P Protocol

### 2.1 DevP2P Capability

| Property | Value |
|----------|-------|
| Capability Name | `msg` |
| Protocol Version | `1` |
| Protocol String (logging/dirs) | `msg01` |
| Protocol Length (message count) | `3` |
| Sentryproto Protocol Enum | `Protocol_MSG01 = 8` |

### 2.2 Message Types

| Message | Wire Code | Sentryproto MessageId | Numeric ID | Description |
|---------|-----------|----------------------|------------|-------------|
| `BoardMessageIDs` | `0x00` | `MessageId_BOARD_MESSAGE_IDS` | `64` | Announce known message IDs to peers |
| `GetBoardMessages` | `0x01` | `MessageId_GET_BOARD_MESSAGES` | `65` | Request full messages by their IDs |
| `BoardMessages` | `0x02` | `MessageId_BOARD_MESSAGES` | `66` | Deliver full messages |

### 2.3 Sidecar Model (No Independent Handshake)

The `msg` protocol has **no independent handshake**. It relies entirely on the `eth` protocol handshake:

1. Both `eth/67` (or `eth/68`) and `msg/1` capabilities are advertised during RLPx capability negotiation.
2. A peer connecting with `msg` but without `eth` is rejected (`"peer connected without eth protocol"`).
3. The `msg` goroutine sends its `MsgReadWriter` on a `msgConnCh` channel and blocks waiting on `ethReadyCh`.
4. The `eth` goroutine performs the standard eth handshake, then signals `ethReadyCh` with the `PeerInfo`.
5. Only after the eth handshake completes do both protocol `runPeer` loops start reading messages.
6. No discovery is performed for `msg` — it piggybacks on `eth` discovery. The `DialCandidates` iterator is `nil` for the msg protocol.

---

## 3. Data Model

### 3.1 PoWMsg (Wire Message / Client Submission)

RLP-encoded for P2P transport.

| Field | Type | RLP Encoding | Description |
|-------|------|-------------|-------------|
| `Version` | `byte` | string (1 byte) | Must be `V1 = 0x01` |
| `BlockHash` | `[32]byte` | string (32 bytes) | Keccak256 hash of the block when msg was created |
| `Nonce` | `uint64` | uint64 | Nonce found by PoW |
| `WorkMultiplier` | `uint64` | uint64 | Numerator of difficulty ratio |
| `WorkDivisor` | `uint64` | uint64 | Denominator of difficulty ratio |
| `Category` | `[32]byte` | string (32 bytes) | Keccak256 hash of category text |
| `Data` | `[]byte` | string (variable) | Arbitrary message payload |

**Validation rules (`Validate()`):**
- `Version` must equal `V1` (0x01)
- `BlockHash` must not be zero
- `Nonce` must not be zero
- `WorkMultiplier` and `WorkDivisor` must both be non-zero
- Either `Category` must be non-zero OR `Data` must be non-empty

**Size calculation:**
```
Size() = len(Data)
```

**Difficulty ratio (as a ratio, not a decimal):**

The pair `(WorkMultiplier, WorkDivisor)` defines the difficulty ratio
`WorkMultiplier : WorkDivisor`. Implementations MUST NOT compare it as a
float — both erigon-pulse and reth compare two messages by integer
cross-multiplication to avoid float drift across implementations:

```
a >= b  ⇔  a.WorkMultiplier * b.WorkDivisor >= b.WorkMultiplier * a.WorkDivisor
```

The pseudo-formula `DifficultyRatio = WorkMultiplier / WorkDivisor` is shown
in the original Go source for documentation only and is never actually
evaluated as a float in the validation path.

### 3.2 CheckedPoWMsg (Server-Side Validated Message)

Wraps `PoWMsg` with server-added metadata. RLP-encoded for gRPC transport and DB storage.

| Field | Type | Description |
|-------|------|-------------|
| `*PoWMsg` | embedded | The original message |
| `BlockNumber` | `uint64` | Block number looked up from `BlockHash` |
| `Timestamp` | `uint64` | Unix timestamp when verified |
| `Hash` | `[32]byte` | SHA-256 PoW hash |

### 3.3 MsgID (Peer Announcement / Filtering)

Flat binary layout (NOT RLP). Used for compact peer-to-peer announcements.

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 1 | Version byte |
| 1 | 32 | Block hash |
| 33 | 8 | Size (uint64 big-endian) |
| 41 | 8 | WorkMultiplier (uint64 big-endian) |
| 49 | 8 | WorkDivisor (uint64 big-endian) |
| 57 | 32 | Category hash |
| 89 | 32 | Message hash (SHA-256 PoW hash) |

**Total: 121 bytes** (`messageIDSize = 121`)

MsgIDs are packed into contiguous byte slices for P2P transport (no RLP wrapping), chunked to `p2pMsgPacketLimit = 100 * 1024` (100 KiB).

### 3.4 RPCPoWMsg (JSON-RPC Response)

| JSON Field | Type |
|------------|------|
| `version` | hex uint64 |
| `blockHash` | hex hash (32 bytes) |
| `blockNumber` | hex uint64 |
| `nonce` | hex uint64 |
| `workMultiplier` | hex uint64 |
| `workDivisor` | hex uint64 |
| `category` | hex hash (32 bytes) |
| `data` | hex bytes |
| `hash` | hex hash (32 bytes) |

---

## 4. Proof of Work

### 4.1 Difficulty Calculation

```
difficulty = (1<<24 + size * 10_000) * WorkMultiplier / WorkDivisor
```

Where:
- `1<<24 = 16,777,216` (base difficulty)
- `size = len(Data)` (each byte of data adds 10,000 to base)
- `WorkMultiplier / WorkDivisor` = difficulty ratio scaling factor

### 4.2 Hash Calculation

```
function calculateHash(msg):
    # Step 1: Compute difficulty digest
    difficultyDigest = SHA256(BigEndian(WorkMultiplier) || BigEndian(WorkDivisor))
    digest = BigInt(difficultyDigest[16:])  # last 16 bytes

    # Step 2: Compute nonce value
    nonceVal = Nonce * digest + BigInt(BlockHash)

    # Step 3: Elliptic curve point multiplication
    (x, _) = secp256k1.ScalarBaseMult(nonceVal.Bytes())
    challenge = x.FillBytes([32]byte{})

    # Step 4: Final hash
    hash = SHA256(challenge || Category || Data)
    return hash
```

### 4.3 PoW Verification

```
bigHash = BigInt(hash)
if bigHash % difficulty != 0:
    reject  # hash must be evenly divisible by difficulty
```

This is a **modular arithmetic check** (not a leading-zeros check like Bitcoin).

### 4.4 Default Difficulty

The minimum accepted difficulty is configured as **two** integers — a
multiplier and a divisor. Always quote both. The pair is the ratio; the
single decimal it reduces to is not a configurable knob.

| Knob | Default | CLI flag (reth) |
|---|---|---|
| `WorkMultiplier` (numerator)   | `10,000`    | `--msgboard.work-multiplier` |
| `WorkDivisor`    (denominator) | `1,000,000` | `--msgboard.work-divisor`    |

Default ratio: **`10,000 : 1,000,000`** (reduced: `1 : 100`). A submitted
message is accepted only if its own `(mult, div)` satisfies
`mult × cfg.div ≥ cfg.mult × div` — i.e. its ratio is at least as hard as
the configured floor.

---

## 5. Board Algorithm

### 5.1 Message Addition (`addMsgLocked`)

Validation pipeline:

1. **Size check:** `msg.Size() > cfg.MsgSizeLimit` → reject (default 8,192 bytes)
2. **Difficulty ratio check:** `msg.DifficultyRatio() < minDifficultyRatio` → reject
3. **Block age check:** `blockNumber < blockFilter.Lower()` → reject (too old)
4. **PoW verification:** `msg.ToCheckedMsg(blockNumber)` → compute SHA-256 hash, verify `hash % difficulty == 0`
5. **Duplicate check:** `content.Insert(newMsg)` → returns false if duplicate hash exists

### 5.2 Ordering (Precedence)

Messages are ordered in ascending precedence:

1. **Lower block number** = lower precedence (oldest first)
2. **Lower difficulty ratio** = lower precedence (within same block)
3. **Earlier insertion** = lower precedence (within same block and ratio)

Index 0 = lowest precedence. The newest, hardest-worked messages have highest precedence.

### 5.3 Board Overflow / Displacement

When `count > cfg.BoardCountLimit` (default 10,000):

- The lowest-precedence message (index 0) is removed
- If the newly added message itself has the lowest precedence (it gets displaced), return `ErrBoardOverflow`
- Displaced messages are added to the `discarded` list for DB deletion

---

## 6. Block Filtering and Pruning

### 6.1 Block Filter

The `BlockFilter` maintains:

- `hashToNum` map: block hash → block number
- `Lower` bound: `max(1, Head - BlockRangeLimit + 1)`

**Constants:**
- `MaxBlockRange` hard cap: `1,080` blocks
- Default `BlockRangeLimit`: `120` blocks
- Default `StaleBlockBuffer`: `3` blocks

### 6.2 MsgID Filtering

When filtering incoming MsgIDs from peers, reject messages where:

- Block number < `Lower + StaleBlockBuffer` (accounts for network latency)
- Version != V1
- Size > MsgSizeLimit
- DifficultyRatio < minDifficultyRatio
- Hash already known

### 6.3 Pruning

On each `ChangeBlock` call (triggered by chain state changes):

1. Update `Lower` based on new head block
2. Iterate all messages in ascending block number order
3. Remove all messages with `BlockNumber < Lower`
4. Add removed messages to `discarded` list for DB deletion on next flush

---

## 7. Message Lifecycle

### 7.1 Creation (Client Side)

1. Client constructs a `PoWMsg`: version=1, category hash, data, chosen WorkMultiplier/WorkDivisor, current block hash
2. Client iterates nonces until `ToCheckedMsg()` succeeds (`hash % difficulty == 0`)
3. Client RLP-encodes the `PoWMsg` and submits via `msgboard_addMessage` or gRPC `AddMessage`

### 7.2 Submission (JSON-RPC Path)

1. `MsgBoardAPIImpl.AddMessage()` receives hex-encoded RLP bytes
2. Forwards to gRPC `AddMessage` as `AddMessageRequest{rlp_msgs: [bytes]}`
3. `GrpcServer.AddMessage()` decodes RLP to `PoWMsg`, calls `Validate()`
4. `MsgBoard.AddPoWMsgs()` acquires lock, calls `addMsgLocked()` for each
5. On success: hash returned to client

### 7.3 Propagation (Outbox → Gossip)

1. **Outbox processing** (every 100ms): Drain `outbox`, build MsgIDs, announce to up to 10 random peers via `BOARD_MESSAGE_IDS`
2. **New peer sync** (every 5s): For newly connected peers, send all known MsgIDs

### 7.4 Fetching (P2P Path)

1. Peer receives `BOARD_MESSAGE_IDS`
2. Parse MsgIDs, filter via `board.FilterMessageIDs()`
3. Send `GET_BOARD_MESSAGES` with filtered IDs
4. Peer looks up messages by hash, responds with `BOARD_MESSAGES` (RLP-encoded PoWMsg list, chunked to 100 KiB)
5. Receiver decodes, calls `board.AddRemoteMsgs()`
6. Bad messages trigger peer penalty/kick

### 7.5 Storage

1. Every `CommitEvery` (default 15s), `flush()` writes all current messages to MDBX and deletes discarded ones
2. On startup, `loadAndRepairDbLocked()` loads all messages from DB, re-validates through `addMsgLocked()`, queues invalid ones for deletion

### 7.6 Expiry

On each `ChangeBlock`: prune messages with `BlockNumber < Lower`, add to discard list for DB deletion.

### 7.7 Retrieval

- `msgboard_getMessage(hash)`: Direct lookup by SHA-256 hash
- `msgboard_content(filter?)`: All messages, optionally filtered by category and/or block range, grouped by category
- `msgboard_categories()`: Sorted list of all category hashes
- `msgboard_subscribe("newMessages", filter?)`: WebSocket push of new messages

---

## 8. gRPC API

### 8.1 Service Definition

**Service:** `msgboard.Msgboard`
**Version:** `1.0.0` (Major=1, Minor=0, Patch=0)
**Proto package:** `msgboard`

### 8.2 Methods

| Method | Type | Request | Response |
|--------|------|---------|----------|
| `Version` | Unary | `google.protobuf.Empty` | `types.VersionReply` |
| `Status` | Unary | `google.protobuf.Empty` | `StatusReply` |
| `AddMessage` | Unary | `AddMessageRequest` | `AddMessageReply` |
| `Categories` | Unary | `google.protobuf.Empty` | `CategoriesReply` |
| `Content` | Unary | `ContentRequest` | `ContentReply` |
| `GetMessage` | Unary | `GetMessageRequest` | `GetMessageReply` |
| `NewMessages` | Server streaming | `NewMessagesRequest` | stream `NewMessagesReply` |

### 8.3 Message Types

```protobuf
message AddMessageRequest {
    repeated bytes rlp_msgs = 1;  // RLP-encoded PoWMsg bytes
}

message AddMessageReply {
    repeated AddResult results = 1;
}

message AddResult {
    bool success = 1;
    types.H256 hash = 2;
    string error = 3;
}

message StatusReply {
    bool enabled = 1;
    uint64 count = 2;
    uint64 size = 3;
    uint64 work_multiplier = 4;
    uint64 work_divisor = 5;
}

message CategoriesReply {
    repeated types.H256 categories = 1;
}

message ContentRequest {
    optional ContentFilter filter = 1;
}

message ContentFilter {
    optional types.H256 category = 1;
    uint64 fromBlock = 2;
    uint64 toBlock = 3;
}

message ContentReply {
    repeated bytes checked_rlp_msgs = 1;  // RLP-encoded CheckedPoWMsg bytes
}

message GetMessageRequest {
    types.H256 hash = 1;
}

message GetMessageReply {
    bytes checked_rlp_msg = 1;  // RLP-encoded CheckedPoWMsg
}

message NewMessagesRequest {}

message NewMessagesReply {
    bytes checked_rlp_msg = 1;  // RLP-encoded CheckedPoWMsg
}
```

### 8.4 Default gRPC Address

For internal mode: same as `--private.api.addr` (default `localhost:9090`)
For external mode: `--msgboard.api.addr` (default `localhost:9095`)

---

## 9. JSON-RPC API

### 9.1 Namespace

`msgboard` — registered when `"msgboard"` is included in `--http.api`.

### 9.2 Methods

| Method | Parameters | Returns |
|--------|-----------|---------|
| `msgboard_addMessage` | `input: hex bytes` (RLP-encoded PoWMsg) | `hash: hex hash` (SHA-256 PoW hash) |
| `msgboard_categories` | (none) | `categories: hex hash[]` (sorted) |
| `msgboard_content` | `filter?: ContentFilter` | `BoardContent` (map: category_hex → RPCPoWMsg[]) |
| `msgboard_getMessage` | `msgHash: hex hash` | `RPCPoWMsg` |
| `msgboard_status` | (none) | `BoardStatus` |

### 9.3 BoardStatus Response

```json
{
    "enabled": true,
    "count": "0x...",
    "size": "0x...",
    "workMultiplier": "0x2710",
    "workDivisor": "0xf4240"
}
```

### 9.4 ContentFilter Input

```json
{
    "category": "0x...",
    "fromBlock": "0x1",
    "toBlock": "0xa"
}
```

All fields are optional.

### 9.5 WebSocket Subscription

**Method:** `msgboard_subscribe`
**Params:** `["newMessages", filter?]`

**NewMessagesFilter:**
```json
{ "category": "0x..." }
```

The subscription maintains a gRPC streaming connection to the backend `NewMessages` stream. Each `CheckedPoWMsg` is decoded from RLP, converted to `RPCPoWMsg`, and pushed to WebSocket subscribers. Filtering by category hash is done at the JSON-RPC layer.

### 9.6 Error Handling

For `addMessage`: if the error string starts with `"powmsg:"`, return it as `InvalidParamsError` (-32602).

---

## 10. P2P Integration (Sentry Layer)

### 10.1 Protocol Registration

When `cfg.MsgBoardEnabled` is true, the sentry registers both `eth` and `msg` protocols.

The following maps are extended with `MSG01` entries:
- `ProtocolNames`: `MSG01 → "msg"`
- `ProtocolLengths`: `MSG01 → 3` (ProtocolLength)
- `ProtocolToString`: `MSG01 → "msg01"` (ProtocolString)
- `ToProto` / `FromProto`: message ID mapping tables

### 10.2 Dual-Protocol Peer Coordination

Each peer connection coordinates two protocol goroutines via channels:
- `ethReadyCh`: maps peer ID → channel signaling eth handshake completion
- `msgConnCh`: maps peer ID → channel passing the msg MsgReadWriter

### 10.3 Message Routing

**`SendMessageById`:** If `MsgboardMessages[messageId]` is true, route to `peerInfo.msgboardConn.rw` instead of `peerInfo.rw`. Use `peerInfo.msgboardConn.protocol` for message code lookup.

**`SendMessageToRandomPeers`:** For msgboard messages:
- Only select peers that have `msgboardConn != nil`
- Validate that `msgcode == BoardMessageIDs` (only announcements go to random peers)

### 10.4 Message ID Filtering

`filterIds` in the sentry client is extended to also accept message IDs from `Protocol_MSG01`.

---

## 11. Fetch Layer

### 11.1 Subscription

The `Fetch` struct subscribes to sentries for:
- `MessageId_BOARD_MESSAGE_IDS` (64)
- `MessageId_GET_BOARD_MESSAGES` (65)
- `MessageId_BOARD_MESSAGES` (66)

### 11.2 Message Handling

**`BOARD_MESSAGE_IDS` (inbound):**
1. Parse flat MsgID bytes (121 bytes per ID)
2. Filter via `board.FilterMessageIDs()` — rejects known, expired, wrong version, oversized, underpowered
3. Respond with `GET_BOARD_MESSAGES` containing filtered IDs

**`GET_BOARD_MESSAGES` (inbound):**
1. Parse flat MsgID bytes
2. Look up each message by hash in the board
3. RLP-encode found messages, chunk to 100 KiB
4. Respond with `BOARD_MESSAGES`

**`BOARD_MESSAGES` (inbound):**
1. Decode RLP list of PoWMsg
2. Call `board.AddRemoteMsgs()`
3. Bad messages trigger `sentryClient.PenalizePeer()`

### 11.3 State Change Subscription

Subscribes to `KV_StateChanges` (no storage, no transactions). On each state change:
- Extract latest block hash/height
- Call `board.ChangeBlock()`

### 11.4 Peer Events

On `PeerEvent_Connect`: call `board.AddPeer()` to schedule initial sync.

---

## 12. Send Layer

### 12.1 AnnounceCollectedMsgIDs

```
AnnounceCollectedMsgIDs(ids []byte, maxPeers int)
```

Sends `BOARD_MESSAGE_IDS` to up to `maxPeers` random peers. Chunks to 100 KiB per message.

### 12.2 PropagateCollectedMsgsToPeersList

```
PropagateCollectedMsgsToPeersList(peers []PeerID, ids []byte)
```

Sends `BOARD_MESSAGE_IDS` to specific peers (newly connected). Chunks to 100 KiB.

---

## 13. Database Storage

### 13.1 DB Configuration

| Property | Value |
|----------|-------|
| DB Label | `kv.MsgBoardDB` = `"msgboard"` |
| Data Directory | `<datadir>/msgboard/` |
| Table Name | `kv.BoardMessage` = `"BoardMessage"` |
| Key | `msg.Hash[:]` (32 bytes, SHA-256 PoW hash) |
| Value | RLP-encoded `CheckedPoWMsg` |

### 13.2 MDBX Parameters

| Parameter | Value |
|-----------|-------|
| WriteMergeThreshold | `3 * 8192` |
| PageSize | `16 KB` |
| GrowthStep | `16 MB` |
| DirtySpace | `128 MB` |
| MapSize | `1 TB` |

### 13.3 DB Operations

- **Load** (`dbLoadMsgs`): Iterate `BoardMessage` table ascending, decode RLP, delete bad entries
- **Write** (`dbWriteMsg`): `PUT(hash, rlp)` only if key doesn't exist
- **Delete** (`dbDeleteMsg`): `DELETE(hash)`
- **Flush** (`flush`): Every `CommitEvery` (15s), in a single write transaction: delete `discarded` messages, write all current messages (skip if exists)

### 13.4 Startup Recovery

On startup, `loadAndRepairDbLocked()`:
1. Load all messages from DB
2. Re-validate each through `addMsgLocked()`
3. Queue invalid ones for deletion

---

## 14. Configuration

### 14.1 CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--msgboard.enabled` | bool | `false` | Opt-in to enable msgboard |
| `--msgboard.external` | bool | `false` | Use external msgboard process |
| `--msgboard.gossip.disable` | bool | `false` | Disable P2P gossip |
| `--msgboard.work.multiplier` | uint64 | `10000` | PoW difficulty multiplier |
| `--msgboard.work.divisor` | uint64 | `1000000` | PoW difficulty divisor |
| `--msgboard.msgsize.limit` | uint64 | `8192` | Max message data size (bytes) |
| `--msgboard.count.limit` | uint64 | `10000` | Max messages on board |
| `--msgboard.blockrange.limit` | uint64 | `120` | Blocks before expiry |
| `--msgboard.staleblockbuffer` | uint64 | `3` | Buffer for stale block filtering |
| `--msgboard.commit.every` | duration | `15s` | DB commit interval |
| `--msgboard.log.every` | duration | `30s` | Stats logging interval |
| `--msgboard.api.addr` | string | (private.api.addr) | gRPC address for external mode |

### 14.2 RPCDaemon Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--msgboard.api.addr` | (private.api.addr) | gRPC address of msgboard backend |

Add `"msgboard"` to `--http.api` to enable the namespace.

### 14.3 Internal Timer Defaults

| Timer | Default |
|-------|---------|
| ProcessOutboxEvery | `100ms` |
| SyncNewPeersEvery | `5s` |
| CommitEvery | `15s` |
| LogEvery | `30s` |

### 14.4 Hard Constants

| Constant | Value |
|----------|-------|
| MaxBlockRange | `1,080` |
| p2pMsgPacketLimit | `102,400` (100 KiB) |
| MsgBoardAPIVersion | `1.0.0` |
| DefaultEncodingVersion (V1) | `0x01` |
| ProtocolVersion | `1` |
| ProtocolName | `"msg"` |
| ProtocolString | `"msg01"` |
| ProtocolLength | `3` |
| messageIDSize | `121` bytes |

---

## 15. Deployment Modes

### 15.1 Internal (Default)

Start the node with `--msgboard.enabled`. The msgboard runs in-process. gRPC is served on the private API address.

### 15.2 External

1. Start the node with `--msgboard.enabled --msgboard.external`
2. Start external sentry: `sentry --sentry.api.addr=localhost:9091`
3. Start external msgboard: `msgboard --private.api.addr=localhost:9090 --sentry.api.addr=localhost:9091 --msgboard.api.addr=localhost:9095`
4. Start RPCDaemon with `--msgboard.api.addr=localhost:9095`

The external msgboard binary:
- Connects to the core node via remote DB for chain data
- Connects to sentry for P2P
- Exposes its own gRPC server

---

## 16. Metrics

| Metric | Type | Prometheus Name |
|--------|------|----------------|
| Add remote msgs time | Summary | `msgboard_add_remote_msgs_runtime` |
| Change block time | Summary | `msgboard_change_block_runtime` |
| Send to peers time | Summary | `msgboard_sent_to_peer_runtime` |
| Write to DB time | Summary | `msgboard_write_to_db_runtime` |
| DB write bytes | Gauge | `msgboard_write_to_db_bytes` |
| Message count | Gauge | `msgboard_msg_count` |
| Message size | Gauge | `msgboard_msg_size` |
