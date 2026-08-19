# Upstream msgboard spec — new PoW construction

> **Provenance.** Supplied by the team on 2026-08-18 as the current upstream
> msgboard specification. Reproduced verbatim below the rule, unedited, so it
> stays a faithful record of what we were given.
>
> **This is not the algorithm reth implements today.** The PoW construction here
> differs from `specs/02-msgboard.md` and from `crates/net/msgboard-types/src/pow.rs`
> at every step: scalar derivation, out-of-range handling, point encoding, work
> hash, and the acceptance test. A message valid under one is invalid under the
> other. See `docs/msgboard-parity-gaps.md` §17 for the gap analysis and the
> adoption decision.
>
> The REST API section carries its own date of March 10, 2025 and matches what
> reth already serves; the PoW section and the `msg/1` wire-limits table are the
> new material.

---

# PoW Message Board (Experimental, Opt-in)

*The experimental new MsgBoard feature is **Opt-In** in this release.*
> To enable the msgboard protocol start Erigon with the `--msgboard.enabled` flag.

---

Message Board - a place where arbitrary ephemeral messages reside.

## msg/1 wire limits

These limits are part of `msg/1`. Changing them requires a new capability version (`msg/2`).

| Limit | Value |
| --- | --- |
| Maximum packet size | 100 KiB (`MaxMessageSize`) |
| MsgID size | 121 bytes |
| `BOARD_MESSAGES` packing | encoded RLP list ≤ 100 KiB |

Peers that send a larger packet are disconnected. Duplicate message hashes in a `BOARD_MESSAGE_IDS` or `GET_BOARD_MESSAGES` packet are a protocol violation and the peer is kicked. Honest implementations already chunk at 100 KiB, so this is compatible with current senders.

# REST API Documentation

This document describes the REST API for interacting with the `MsgBoard` RPC, which manages a message board with proof-of-work (PoW) messages categorized by hashes. The API provides endpoints to add messages, retrieve categories, fetch content, get specific messages, check the board's status, and subscribe to new messages via WebSocket.

**Date**: March 10, 2025

## Table of Contents

1. [Data Models](#data-models)
2. [Endpoints](#endpoints)
   - [Add Message](#add-message)
   - [List Categories](#list-categories)
   - [Get Content](#get-content)
   - [Get Message](#get-message)
   - [Get Status](#get-status)
   - [Subscribe to New Messages (WebSocket)](#subscribe-to-new-messages-websocket)
3. [PoW Requirements](#pow-requirements)
4. [Reference Implementations](#reference-implementations)

## Data Models

### `Message`
Represents a proof-of-work message.

```json
{
  "version": "uint64",        // Version of the message (hex-encoded)
  "blockHash": "string",      // Hash of the block (hex-encoded, 32 bytes)
  "blockNumber": "uint64",    // Block number (hex-encoded)
  "nonce": "uint64",          // Nonce used for PoW (hex-encoded)
  "workMultiplier": "uint64", // Work multiplier for PoW (hex-encoded)
  "workDivisor": "uint64",    // Work divisor for PoW (hex-encoded)
  "category": "string",       // Category hash (hex-encoded, 32 bytes)
  "data": "string",           // Message data (hex-encoded bytes)
  "hash": "string"            // Message hash (hex-encoded, 32 bytes)
}
```

### `BoardStatus`
Represents the current status of the message board.

```json
{
  "enabled": "boolean",       // Whether the board is enabled
  "count": "uint64",          // Total number of messages (hex-encoded)
  "size": "uint64",           // Total size of messages in bytes (hex-encoded)
  "workMultiplier": "uint64", // Current work multiplier (hex-encoded)
  "workDivisor": "uint64"     // Current work divisor (hex-encoded)
}
```

### `ContentFilter`
Filter for retrieving board content.

```json
{
  "category": "string",       // Optional: Category hash (hex-encoded, 32 bytes)
  "fromBlock": "uint64",      // Optional: Starting block number (hex-encoded string or uint64)
  "toBlock": "uint64"         // Optional: Ending block number (hex-encoded string or uint64)
}
```

### `BoardContent`
Response containing messages grouped by category hash.

```json
{
  "<category_hash>": [
    {
      "version": "uint64",
      "blockHash": "string",
      "blockNumber": "uint64",
      "nonce": "uint64",
      "workMultiplier": "uint64",
      "workDivisor": "uint64",
      "category": "string",
      "data": "string",
      "hash": "string"
    }
  ]
}
```

### `NewMessagesFilter`
Filter for subscribing to new messages.

```json
{
  "category": "string"        // Category hash (hex-encoded, 32 bytes)
}
```

## Endpoints

### Add Message

**POST** `msgboard_addMessage`

Adds a new proof-of-work message to the board.

#### Request Body
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_addMessage",
    "id": 1,
    "params": [
        "0xf84e01a033b45e159...0000000000000000000000000000"
    ]
}
```

#### Response
- **Success**: `200 OK`
  ```json
  {
      "jsonrpc": "2.0",
      "id": 1,
      "result": "0x4e32cd77514b788f52966a70e45706f6a2c97b26095156feece67fb8dd453e80"
  }
  ```

#### Example
```bash
curl -X POST 'http://localhost:8545' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "msgboard_addMessage",
    "id": 1,
    "params": [
        "0xf84e01a033b45e159...0000000000000000000000000000"
    ]
}'
```

---

### List Categories

**POST** `msgboard_categories`

Retrieves a list of all category hashes on the board.

#### Request Body
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_categories",
    "id": 1,
    "params": []
}
```

#### Response
- **Success**: `200 OK`
  ```json
  {
      "jsonrpc": "2.0",
      "id": 1,
      "result": [
          "0x0000000000000000000000000000000000000000000000000000000000000000", // Hex-encoded category hash (32 bytes)
          "0x0000000000000000000000000000000000000000000000000000000000000001",
          "0x0000000000000000000000000000000000000000000000000000000000000002"
      ]
  }
  ```

#### Example
```bash
curl -X POST 'http://localhost:8545' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "msgboard_categories",
    "id": 1,
    "params": []
}'
```

---

### Get Content

**POST** `msgboard_content`

Retrieves all messages on the board, grouped by category hash, optionally filtered by category and block range.

#### Request Body (Unfiltered)
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_content",
    "id": 1,
    "params": []
}
```

#### Request Body (Filtered)
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_content",
    "id": 1,
    "params": [
        {
            "category": "string",   // Optional: Hex-encoded category hash (32 bytes)
            "fromBlock": "uint64",  // Optional: uint64 or hex-encoded starting block number
            "toBlock": "uint64"     // Optional: uint64 or hex-encoded ending block number
        }
    ]
}
```

#### Response
- **Success**: `200 OK`

  Lists of messages grouped by category hash:
  ```json
  {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
          "0x0000000000000000000000000000000000000000000000000000000000000000": [ // Hex-encoded category hash (32 bytes)
              {
                  "version": "0x1",
                  "blockHash": "0xb8ef822f5d4f4c6a297170307b1d2c60803efc32fd22bdde9e11e4227cbe1dc6",
                  "blockNumber": "0xf9",
                  "nonce": "0x45895",
                  "workMultiplier": "0x1",
                  "workDivisor": "0x64",
                  "category": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "data": "0x00",
                  "hash": "0x46d22cb16a709a91aa5ec412e3f2168239d4c57edfaa529d47389132d0e6b740"
              },
              {
                  "version": "0x1",
                  "blockHash": "0x4782f2b0bef0a2fdccb9339fcb9128bccbf09708c71b390b4fa7bad2aca493af",
                  "blockNumber": "0x101",
                  "nonce": "0x2d512",
                  "workMultiplier": "0x1",
                  "workDivisor": "0x64",
                  "category": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "data": "0x00",
                  "hash": "0x787d1c820b4bfc7b9d8c7bd24ae663833457e79a73d1134a88e4a9c5884718c0"
              }
          ],
          "0x0000000000000000000000000000000000000000000000000000000000000001": [
              {
                  "version": "0x1",
                  "blockHash": "0xbe967eadd17e43983f651cccda4ba2672ac52eaa7c814759448f7100aade2d15",
                  "blockNumber": "0xfa",
                  "nonce": "0xb476",
                  "workMultiplier": "0x1",
                  "workDivisor": "0x64",
                  "category": "0x0000000000000000000000000000000000000000000000000000000000000001",
                  "data": "0x01",
                  "hash": "0xcf336eb7e9a21989134330883f7189c1f1bf684ac64f4fcd1836184146c53680"
              }
          ]
      }
  }
  ```

#### Example
```bash
curl -X POST 'http://localhost:8545' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "msgboard_content",
    "id": 1,
    "params": []
}'
```

---

### Get Message

**POST** `msgboard_getMessage`

Retrieves a specific message by its hash.

#### Request Body
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_getMessage",
    "id": 1,
    "params": ["0x46d22cb16a709a91aa5ec412e3f2168239d4c57edfaa529d47389132d0e6b740"]
}
```

#### Response
- **Success**: `200 OK`
  ```json
  {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
          "version": "0x1",
          "blockHash": "0xb8ef822f5d4f4c6a297170307b1d2c60803efc32fd22bdde9e11e4227cbe1dc6",
          "blockNumber": "0xf9",
          "nonce": "0x45895",
          "workMultiplier": "0x1",
          "workDivisor": "0x64",
          "category": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "data": "0x00",
          "hash": "0x46d22cb16a709a91aa5ec412e3f2168239d4c57edfaa529d47389132d0e6b740"
      }
  }
  ```

#### Example
```bash
curl -X POST 'http://localhost:8545' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "msgboard_getMessage",
    "id": 1,
    "params": ["0x46d22cb16a709a91aa5ec412e3f2168239d4c57edfaa529d47389132d0e6b740"]
}'
```

---

### Get Status

**POST** `msgboard_status`

Retrieves the current status of the message board.

#### Request Body
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_status",
    "id": 1,
    "params": []
}
```

#### Response
- **Success**: `200 OK`
  ```json
  {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
          "enabled": true,
          "count": "0x0",
          "size": "0x0",
          "workMultiplier": "0x1",
          "workDivisor": "0x64"
      }
  }
  ```

#### Example
```bash
curl -X POST 'http://localhost:8545' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "msgboard_status",
    "id": 1,
    "params": []
}'
```

---

### Subscribe to New Messages (WebSocket)

**WebSocket** `msgboard_subscribe`

Subscribes to notifications for newly added messages, optionally filtered by category. This uses a WebSocket connection.

#### Request Body (Unfiltered)
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_subscribe",
    "id": 1,
    "params": [
        "messages"
    ]
}
```

#### Request Body (Filtered)
```json
{
    "jsonrpc": "2.0",
    "method": "msgboard_subscribe",
    "id": 1,
    "params": [
        "messages",
        {
            "category": "0x0000000000000000000000000000000000000000000000000000000000000001"
        }
    ]
}
```

#### Response (Streamed Messages)
- **Success**: Streamed JSON messages
  ```json
  {
      "jsonrpc": "2.0",
      "method": "msgboard_subscription",
      "params": {
          "subscription": "0x760f4fb06dd30f11389cef2fd7cec57b",
          "result": {
              "version": "0x1",
              "blockHash": "0x632cab99ea3aceeaef9dcf66410bae41b0e5a6993282c4fd403683593fab6e93",
              "blockNumber": "0x1ce",
              "nonce": "0x17429",
              "workMultiplier": "0x1",
              "workDivisor": "0x64",
              "category": "0x0000000000000000000000000000000000000000000000000000000000000001",
              "data": "0x01",
              "hash": "0xf79949f99907a1878cccacd3a45862ac6ca1bbb7bd170c73fbc63df610f941c0"
          }
      }
  }
  ```

#### Example (Using WebSocket Client)
```javascript
const ws = new WebSocket("ws://localhost:8545");
ws.onopen = () => {
  ws.send(JSON.stringify({
    jsonrpc: "2.0",
    method: "msgboard_subscribe",
    id: 1,
    params: [ "messages" ]
  }));
};
ws.onmessage = (event) => {
  console.log(JSON.parse(event.data));
};
```

## PoW Requirements
To add a message to the msgboard, you will need to meet some proof of work requirements, with larger messages requiring more work. This functions as a spam prevention mechanism.

Posters iterate on `nonce` until the work hash falls below a difficulty target. Every attempt binds `category` and `data` into an elliptic-curve scalar multiply (secp256k1), so changing the payload requires new work.

1. Query the RPC ([msgboard_status](#get-status)) to retrieve the board's required difficulty, represented as `workMultiplier` and `workDivisor` in the response.

2. Compute the dynamic work parameter `D` from the message length and difficulty factors. The acceptance target is `2^256 / D`.

    ```ts
    /**
     * Returns the PoW work parameter D = ((2^24) + (10k * dataLen)) * workMultiplier / workDivisor.
     * Accept if workHash < 2^256 / D.
     */
    export function difficulty({ workMultiplier, workDivisor }: types.DifficultyFactors, dataLen: number) {
      return (((2n ** 24n) + BigInt(dataLen) * 10_000n) * workMultiplier) / workDivisor
    }

    export function powTarget(d: bigint): bigint {
      return (2n ** 256n) / d
    }
    ```

3. Hash the message payload (commits to category and data once per message body).

    ```ts
    /** Returns SHA256(category ‖ data). */
    export function payloadHash(msg: types.MessageSeed) {
      return sha256(concatBytes([
        hexToBytes(msg.category, { size: 32 }),
        hexToBytes(msg.data),
      ]))
    }
    ```

4. Build the EC scalar from the full message transcript (all fixed-width fields, including the 32-byte payload hash).

    ```ts
    /**
     * Returns SHA256(version ‖ blockHash ‖ payloadHash ‖ workMultiplier ‖ workDivisor ‖ nonce).
     * Multi-byte integers are big-endian fixed width (1-byte version; 8-byte M, D_iv, nonce).
     */
    export function scalarHash(msg: types.MessageSeed, payloadHashBytes: Uint8Array) {
      return sha256(concatBytes([
        numberToBytes(msg.version, { size: 1 }),
        hexToBytes(msg.blockHash, { size: 32 }),
        payloadHashBytes, // 32-byte SHA256 digest
        numberToBytes(msg.workMultiplier, { size: 8 }), // big-endian
        numberToBytes(msg.workDivisor, { size: 8 }),    // big-endian
        numberToBytes(msg.nonce, { size: 8 }),          // big-endian
      ]))
    }
    ```

5. Interpret `scalarHash` as an integer. Reject the attempt (try a new `nonce`) unless `1 ≤ scalar < secp256k1 curve order`. Then multiply the base point by that scalar, compress the resulting point, and SHA-256 it to get the work hash. Accept if `workHash < 2^256 / D`; otherwise try a new `nonce` (repeat from step 4).

    ```ts
    const EC = elliptic.ec
    const ec = new EC('secp256k1')
    const g = ec.g as elliptic.curve.base.BasePoint

    /**
     * Computes the work hash and checks it against the difficulty target.
     * Scalar must satisfy 1 ≤ scalar < secp256k1 curve order; otherwise try a new nonce.
     * @throws error if the scalar is out of range, the point is at infinity, or the work is not valid
     */
    export function checkWork(msg: types.MessageSeed, msgDifficulty: bigint) {
      const payloadHashBytes = hexToBytes(payloadHash(msg))
      const scalar = new BN(hexToBytes(scalarHash(msg, payloadHashBytes)))
      // Reject rather than reduce: must match Go's secp256k1 ScalarBaseMult behavior.
      if (scalar.isZero() || scalar.gte(ec.curve.n)) {
        throw new Error('invalid work')
      }
      const point = g.mul(scalar)
      if (point.isInfinity()) {
        throw new Error('invalid work')
      }
      // compressed = 0x02/0x03 ‖ x  (33 bytes)
      const compressed = Uint8Array.from(point.encodeCompressed())
      const hash = sha256(compressed)
      if (BigInt(hash) >= powTarget(msgDifficulty)) {
        throw new Error('invalid work')
      }
      return hash
    }
    ```

## Reference Implementations

1. This repo has a standard implementation of the msgboard. You can review the [message validation logic](./pow_message.go) and [test code](./board_test.go) for guidance.

2. A fixed worked example (inputs and expected digests for every PoW step) is locked in [`TestPoWGoldenVector`](./pow_message_test.go). Client implementations should match those hex values byte-for-byte.

3. A typescript reference implementation is available here: https://gitlab.com/pulsechaincom/msgboard.
