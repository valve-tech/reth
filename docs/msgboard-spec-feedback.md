# msgboard — findings from an independent msg/1 implementation

We built a `msg/1` implementation in a reth fork and run it on PulseChain
testnet v4. It interoperates. Everything below was verified against
erigon-pulse `v3.0.0-RC8` = `48cdb29e35`, package `msgboard/`, with file:line
on both sides.

**What we run:** the new PoW, as `version = 1`. We match `pulse-v3.4.4`
byte for byte, including its golden vector.

**Most of this document is now answered.** It was written against
`v3.0.0-RC8`. `pulse-v3.4.4` ships the new construction at version 1, fixes the
chunker, names the packing unit, and adds the golden vector — see §2.6 and §4.
What remains open is §2.2.

---

## 1. `MaxSizeMsgChunks` drops messages

This is the one we would most want to know about if it were ours.

```go
// msgboard/send.go:53-71
for i := 0; i < len(msgs); i++ {
    var group []*CheckedPoWMsg     // re-declared nil each iteration
    ...
    group = append(group, msg)     // so this is always a 1-element slice
    groupSize += msgSize
    all[totalGroups-1] = group     // and this overwrites the accumulated group
}
```

`group` is redeclared inside the loop and the accumulated group is never read
back out of `all`, so each write replaces the group with the single message just
appended. We ran the loop verbatim twice, independently: **30 messages of 8 KiB
in, 3 out.** Six messages of 30,000 bytes produce two frames of one message each.

Every `BOARD_MESSAGES` frame the reference emits carries exactly one message, and
the rest of the requested set is silently dropped. At the default `MsgSizeLimit`
its largest frame is about 8.3 KiB, not ~100 KiB.

Two consequences beyond the lost messages:

- The wire-limits note *"honest implementations already chunk at 100 KiB, so this
  is compatible with current senders"* currently holds **because of this bug**.
- When it is fixed, frames jump from ~8 KiB to as much as ~102 KiB in one
  release, and every strict inbound bound in the network is exercised for the
  first time on that day.

## 2. The new PoW construction — we shipped it, and had to decide three things the spec leaves open

We now run the new construction in production as **`version = 1`**, replacing
the old one. Every board we run drained; every poster we run was upgraded in the
same change. Getting there meant making calls that belong in the spec.

### 2.1 The version byte stays 1, and that makes this a flag day

`scalarHash` binds the version byte, and every worked example in the spec is
`"version": "0x1"`. We read that as deliberate: the new construction *is*
version 1, and the old one is gone.

We tried the alternative first — ship the new construction as `version = 2`,
verify both, and let clients move whenever they liked. We dropped it, for a
reason worth stating rather than the convenience:

**Any window in which both are accepted is a window in which the weaker one
governs.** A board still taking version-1-old messages is exactly as spammable
as it was before, so coexistence buys a smoother rollout and no security — and
the security is the whole point of the change.

So this is a flag day, and it is worth the spec saying so out loud, next to the
construction. An implementer who reads only the PoW section will not work out on
their own that shipping it drains every board on the network and mutually bans
every node that has not.

**The ask:** confirm that version 1 is the new construction and the old one is
retired — and if you can, name something an operator can target. A release tag,
a block height, a date. Invalid work is kickable on both sides
(`fetch.go:266-269`; our `add_remote_msgs` mirrors it), so whoever switches
first is kicked by everyone who has not, and kicks them back. We will match
whatever you pick.

### 2.2 Read literally, the PoW is free

`D = ((2^24 + 10_000·dataLen)·M) / Div` is integer division over `M` and `Div`
that the poster chooses. Set `M = 1`, `Div = 16777216`, `dataLen = 0`:

```
D      = 16777216 / 16777216 = 1
target = 2^256 / 1           = 2^256
```

Every 256-bit hash is below 2^256, so the first nonce wins. Push `Div` to
16777217 and `D` is 0, and `2^256 / 0` is whatever the implementer's language
does with it.

Step 1 tells the *poster* to query `msgboard_status` for the board's difficulty.
Nothing tells the *verifier* to enforce it. The reference is safe because it
gates on the operator's configured ratio, but that gate lives in the config, not
in the spec — an implementer working from this document alone has no floor at
all and accepts zero-work messages at line rate.

We enforce a ratio floor and refuse `D = 0` at the decode boundary, before
paying for the scalar multiplication. That floor is ours, and a third
implementer cannot derive it from the text.

**The ask:** state the receiver's rule normatively — the minimum acceptable
`M/Div` (or minimum `D`), and whether a message below it is dropped or is
kickable.

### 2.3 The target does not fit in 256 bits

At `D = 1` the target is exactly 2^256. An implementer who holds it in a 256-bit
integer — the natural choice, since it is compared against a 256-bit hash —
either overflows to zero and rejects everything, or wraps and accepts
everything. The TypeScript in the spec is safe because BigInt is unbounded. Go
and Rust are not safe by default.

We compute the target in 512 bits. One sentence in the spec would settle it:
compute the target in wider arithmetic, or test `workHash · D < 2^256` and never
materialise the target. A floor on `D` (§2.2) also removes the case.

### 2.4 What is the `hash` field now?

Under the current construction the message hash is
`sha256(challenge ‖ category ‖ data)`, which visibly commits to the body. Under
the new one it is `sha256(compressedPoint)`, which commits to the body only
through the scalar.

That is still a sound identity — a different body gives a different
`payloadHash`, a different scalar, a different point. But the REST data model
documents `hash` with version-1 examples only, and that field fills the last 32
bytes of the 121-byte `MsgID` that peers announce and request by. We read it as
`hash = workHash`. Worth one line saying so.

### 2.5 The out-of-range scalar needs a receiver rule too

The spec is explicit that a poster must reject rather than reduce, and says why.
It does not say what a *receiver* does with such a message.

That matters more than the 2^-128 probability suggests. A receiver that reduces
accepts messages a conforming receiver refuses, so the disagreement is silent
and it is a conformance fork rather than a rounding error. It never happens by
accident, so it only ever appears deliberately.

**The ask:** invalid work (kickable), or malformed (drop)? We treat it as
invalid work.

### 2.6 The golden vector — found, and we match it

Withdrawn. `TestPoWGoldenVector` is absent at `v3.0.0-RC8`, which is the tree
this document was written against, and present at `pulse-v3.4.4`
(`msgboard/pow_message_test.go:256`). We ran your vector through our
implementation and reproduce every intermediate byte for byte — `payloadHash`,
`scalarHash`, the compressed point, `workHash`, `D`, and the target.

That settles interoperability far better than anything we could have asked for,
and most of the questions above with it.

### 2.7 Why the change is worth documenting

The new construction closes two independent defects and the spec names neither.
Writing them down stops a future implementer from optimising it back into the
old shape.

**The scalar was linear in the nonce.** `scalar(n+1) = scalar(n) + digest`, so
`G·scalar(n+1) = G·scalar(n) + G·digest`, and `G·digest` is constant for a given
`M`/`Div` pair. A poster advances the point with one addition, about 1 µs, where
a verifier always pays a full scalar multiplication of 60 to 120 µs. The work
costs 50 to 500 times less than the difficulty parameter claims.

**The challenge never committed to the payload.** `category` and `data` entered
only at the final hash, so one precomputed challenge sequence served every
message in that block at that difficulty. For K messages the curve cost was
O(N), not O(K·N) — the first message was cheap and every message after it was
nearly free.

They compound. The first defect makes the table cheap to build; the second makes
it reusable forever. A SHA-256 scalar that commits to `payloadHash` kills both,
which is why the fix is one line and not two.

This also settles the transition question, and it is why we did not take the
version-2 route in §2.1. Any period in which nodes accept both constructions is
a period in which the weaker one governs. The value of an accept-both window is
entirely in avoiding kicks, and none of it is in security.

## 3. `MsgSizeLimit` above the packet limit bans conforming nodes

`MsgSizeLimit` defaults to 8 KiB and is operator-settable
(`msgboardcfg/config.go:18,38`; flag at `cmd/utils/flags.go:295`, reaching
`cfg.MsgSizeLimit` at `:1705`). It is enforced per message
(`board.go:388`, `:233`) with no relation to `p2pMsgPacketLimit`.

Both packers give a message above the chunking target a frame to itself. So
raising that one flag past ~100 KiB makes a node emit over-limit frames as
ordinary traffic — not as an attack, and with no warning that the flag is bounded
by anything.

Against a receiver that enforces the wire-limits table, that is a permanent
mutual ban between two nodes that each believe they are conforming. We have
capped our own flag at 102,301 bytes, solved from the encoding rather than
written down. **Worth saying in the spec that `MsgSizeLimit` must stay below the
packet limit.**

## 4. The packing bound: payload, or encoded list?

The table bounds the *encoded RLP list* at 100 KiB. The reference measures the
RLP **payload**:

```go
// msgboard/send.go
msgSize := msg.RLPSize()
if totalGroups == 0 || groupSize+msgSize > p2pMsgPacketLimit { ...new group... }
groupSize += msgSize
...
chunk := EncodeRLPMsgList(toEncode)   // list header prepended AFTER measuring
```

The flush fires only when the *next* message would cross, so the payload reaches
exactly 102,400 and the header adds four more. An implementer who bounds the
encoded list at 102,400, as written, rejects a frame the reference intends to be
legal.

This is latent today only because of §1. It becomes live the moment the packer is
fixed. We allow 102,408 inbound — 100 KiB plus 8 — which absorbs the header, but
that allowance is ours and a third party has no way to derive it from the spec.

**Answered at `pulse-v3.4.4`, and we were on the wrong side of it.**
`MaxSizeMsgChunks` now flushes on `rlp.ListSize(content+enc) > MaxMessageSize`
(`msgboard/send.go:67`) — the encoded list — and the same release disconnects a
peer whose inbound frame exceeds it. The chunker bug in §1 is fixed there too.

We bounded the payload and added the list header afterwards, so our largest
chunk encoded to 102_404 and every upgraded peer would have dropped the
connection. Fixed on our side; we now bound the same quantity you do.

Worth putting the unit in the spec text rather than leaving it to the code — it
is the one place where a plausible misreading costs a disconnect rather than a
rejected message.

## 5. Two smaller notes

**`MaxMessageSize` names nothing in the reference,** and the closest match is the
wrong size. `grep -rn 'MaxMessageSize' --include='*.go'` finds one hit, in the
consensus-layer libp2p config. The msg/1 receive path enforces
`ProtocolMaxMsgSize` = **10 MiB** (`eth/protocols/eth/protocol.go:63-64`), via the
only size check on the path (`p2p/sentry/sentry_grpc_server.go:412`). The 100 KiB
figure is `p2pMsgPacketLimit` (`msgboard/send.go:50`), which appears only in
`send.go` and never runs on receive. We read the table as normative and enforce
100 KiB anyway — but the row as written sends an implementer to the wrong
constant.

**The duplicate-hash kick has no safe implementation yet.** The reference has no
duplicate check at all, and `AddRemoteMsgs` explicitly declines to penalise
duplicates (`board.go:268`). We have not implemented it, because erigon forwards
announced IDs into `GET_BOARD_MESSAGES` without deduplicating
(`fetch.go:206-227`) — so a node honouring that line would ban erigon for input
erigon relayed rather than originated. Worth fixing in the reference first, or
the first implementer to enforce it partitions itself.

## What we can supply

- **The golden vector for the new PoW** — printed in full in §2.6, two cases,
  every intermediate digest pinned, cross-checked in three languages. Also the
  generator, which is a dependency-free single file.
- **A repro for §1** — the loop extracted, with the input and output counts.
- **A cross-implementation corpus**: hex frames at the size boundary that both
  nodes must accept or reject identically, once §4 fixes the unit.
- **Our parity audit** against `v3.0.0-RC8`, file:line on both sides.
- **A testnet report** on running the new construction — we are on it now, so we
  will know before you do whether anything about it bites in production.

Happy to file §1 as an issue instead if that is easier.

**If you answer one thing, make it §2.2** — the missing floor on `D`. The version
byte we have now read the same way you wrote it; a receiver with no minimum
difficulty is a network anyone can fill for free.
