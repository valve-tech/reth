# msg/1 wire limits — spec vs erigon-pulse

**What this is:** four discrepancies between the *msg/1 wire limits* table in the
msgboard spec and what erigon-pulse actually does. Every claim below is a
file:line citation you can check.

**Sources compared**

| | version |
| --- | --- |
| Reference implementation | erigon-pulse `v3.0.0-RC8` = `48cdb29e35`, package `msgboard/` |
| Our implementation | reth fork, `msg/1`, running on PulseChain testnet v4 |
| Spec | "PoW Message Board (Experimental, Opt-in)", § *msg/1 wire limits* |

**Not in dispute:** PoW v2 matches. We reject a nonce unless `1 <= scalar < n`
rather than reducing, per step 5, and we match `TestPoWGoldenVector`
byte-for-byte. The duplicate-hash rule is unambiguous and we implement it.

---

## Summary

| # | Spec says | Reference actually | Kind |
| --- | --- | --- | --- |
| 1 | `Maximum packet size 100 KiB (MaxMessageSize)` | `MaxMessageSize` is **10 MiB**; 100 KiB is a different, send-only constant | wrong value + wrong constant |
| 2 | `BOARD_MESSAGES packing: encoded RLP list <= 100 KiB` | measures the RLP **payload** at 100 KiB, then adds the list header → emits up to **102,404 B** | wrong unit |
| 3 | `Peers that send a larger packet are disconnected` | true, but at **10 MiB**; a 200 KiB frame is accepted | wrong threshold |
| 4 | (silent) | `MsgSizeLimit` is operator-settable and can exceed the packet limit | undefined interaction |

---

## 1. `MaxMessageSize` is 10 MiB

```
eth/protocols/eth/protocol.go:63   const maxMessageSize = 10 * 1024 * 1024
eth/protocols/eth/protocol.go:64   const ProtocolMaxMsgSize = maxMessageSize
```

This is what the inbound path enforces for `msg/1`. The msgboard sidecar shares
`runPeer` with the eth protocol, and that is the only size check on the path:

```go
// p2p/sentry/sentry_grpc_server.go:412
if msg.Size > eth.ProtocolMaxMsgSize {
    msg.Discard()
    return p2p.NewPeerError(p2p.PeerErrorMessageSizeLimit, p2p.DiscSubprotocolError, ...)
}
```

The 100 KiB figure is a different constant:

```
msgboard/send.go:50   p2pMsgPacketLimit = 100 * 1024
```

`p2pMsgPacketLimit` appears only in `send.go`. It is a send-side chunking target
and never runs on receive.

## 2. The packing bound is on the payload, not the encoded list

```go
// msgboard/send.go:53-88  MaxSizeMsgChunks
msgSize := msg.RLPSize()
if totalGroups == 0 || groupSize+msgSize > p2pMsgPacketLimit {
    ... start a new group ...
}
group  = append(group, msg)
groupSize += msgSize
...
chunk := EncodeRLPMsgList(toEncode)   // list header prepended HERE
```

The flush fires only when the *next* message would cross the limit, so
`groupSize` reaches exactly 102,400. `EncodeRLPMsgList` then prepends a 4-byte
list header at that length.

```
payload      102,400 B   (what the loop measures)
+ RLP header       4 B
= encoded list 102,404 B   (what the spec bounds at 102,400)
+ opcode           1 B
= frame      102,405 B   (what goes on the wire)
```

Not a defect in erigon — a mismatch between the spec's unit ("encoded RLP list")
and the quantity the reference measures (the payload).

The ID path has no such gap: `RunWithIDChunks` (`msgboard/message_id.go:108`)
uses `maxIDsPerChunk = 102400 / 121 = 846` and `FlattenMsgIDs`, a flat
concatenation with no RLP wrapper. 846 x 121 = 102,366 B.

## 3. The disconnect threshold is 10 MiB

The sentence is true against the constant in §1. A peer sending a 200 KiB
`BOARD_MESSAGES` frame is not disconnected — it is accepted and decoded. Read
next to the 100 KiB row, the sentence implies 100 KiB is enforced on receive.

## 4. `MsgSizeLimit` vs the packet limit is undefined

```
msgboard/msgboardcfg/config.go:38   MsgSizeLimit: 8 * 1024   // operator-settable
```

Both implementations give a single message its own frame when it exceeds the
chunking target — the loop flushes only when the group is already non-empty. So
raising `MsgSizeLimit` above ~100 KiB makes a node emit over-limit frames as a
matter of course. The spec does not say whether that is permitted, or whether
`MsgSizeLimit` must be bounded by the packet limit.

---

## The one question that changes our code

**On receive, which threshold is normative for `msg/1` — 100 KiB or
`ProtocolMaxMsgSize`?**

We read the table as normative and enforce 100 KiB inbound:

```
MAX_INBOUND_FRAME_SIZE = 100 KiB + 8 = 102,408 B
```

Above that we drop the frame before decode and drop the peer's reputation to the
minimum, which disconnects it for 12 hours. The 8-byte allowance exists to absorb
the header from §2, so we accept everything erigon emits at default settings —
its true maximum is 102,405 B, leaving 3 bytes of margin.

But that makes us ~100x stricter than the reference. It costs nothing today. It
starts to matter the moment any node raises `MsgSizeLimit`: erigon peers would
accept its frames and we would ban it.

- If **100 KiB** is normative, the reference is more permissive than the spec.
- If **10 MiB** is normative, we should relax our bound and row 1 needs rewording.

## Suggested replacement table

| Limit | Value |
| --- | --- |
| Maximum packet size, enforced on receive | 10 MiB (`ProtocolMaxMsgSize`, `eth/protocols/eth/protocol.go`) |
| MsgID size | 121 bytes |
| `BOARD_MESSAGES` packing (send) | RLP **payload** chunked at 100 KiB (`p2pMsgPacketLimit`); the list header is added after measuring, so an emitted frame may reach 100 KiB + header + opcode |
| `BOARD_MESSAGE_IDS` packing (send) | `floor(100 KiB / 121)` = 846 IDs per frame, flat concatenation |
| `MsgSizeLimit` | 8 KiB default; a message above the chunking target occupies a frame alone |

For the sentence below the table: name which threshold disconnects.

## Test vectors we can supply

1. **Frame-framing boundary vectors.** `payload_len` → expected encoded frame
   length across 102,396-102,401, where the RLP header width changes. These are
   where two implementations silently disagree by a few bytes.
2. **A worst-case packing test**, in Go and Rust. Messages sized so the payload
   sum lands exactly on `p2pMsgPacketLimit`, asserting the emitted frame length.
   Worth having: our own guard for this turned out to assert a tautology.
3. **ID-frame vectors.** 845 / 846 / 847 IDs with expected byte lengths,
   confirming a chunk is always a multiple of 121 and never splits a record.
4. **A cross-implementation corpus.** Hex frames at the boundary that both nodes
   must accept or reject identically — the wire-level analogue of
   `TestPoWGoldenVector`.
5. **Our parity audit** against `v3.0.0-RC8`, with file:line on both sides.

## Reproducing the citations

```bash
git clone https://gitlab.com/pulsechaincom/erigon-pulse && cd erigon-pulse
git checkout 48cdb29e35
sed -n '60,65p'   eth/protocols/eth/protocol.go        # 10 MiB
sed -n '410,416p' p2p/sentry/sentry_grpc_server.go     # the inbound check
sed -n '48,88p'   msgboard/send.go                     # p2pMsgPacketLimit + packer
sed -n '108,128p' msgboard/message_id.go               # ID chunking
sed -n '36,40p'   msgboard/msgboardcfg/config.go       # MsgSizeLimit
grep -rn 'p2pMsgPacketLimit' .                         # send.go only
```
