# reth-pulsechain-snap

`snap/1` serving for PulseChain light clients such as reth-lite. Upstream reth speaks only
`snap/2` (EIP-8189), which drops the `GetTrieNodes` and `TrieNodes` messages these clients use to
read state on demand. This crate adds the `snap/1` message set and a server for it.

`pulse-reth` serves `snap/1` only when `--pulsechain.snap1` or the environment variable
`RETH_PULSECHAIN_SNAP1` turns it on. It is off by default. Each takes `true|false`, `1|0`,
`yes|no` or `on|off`, and the bare flag means `true`. When both are set, the flag wins. To find
the boxes that serve `snap/1`, check the command line and the environment of each unit, for
example with `systemctl show -p Environment <unit>`.

## What it serves

* `GetAccountRange` and `GetStorageRanges`, with boundary proofs.
* `GetByteCodes`, which needs no state root.
* `GetTrieNodes`, answered by walking proofs from the requested root.

## Untrusted peers

Every peer is untrusted. The server bounds the work one peer can cause:

* Requests run in two lanes. The hot lane serves the roots of the persisted tip (the `Finish`
  checkpoint) and of the blocks above it, with a worker limit, a per-peer limit and a per-peer
  token bucket. The cold lane serves older roots, which rebuild reverts, with two requests at
  once and one per peer. A block the engine still holds in memory after it persisted it is cold
  when it is below the tip. A peer's further requests wait their turn, for up to 2 seconds in either lane.
* Each peer may send 1000 requests a second, in bursts of up to 2000, and take 8 MiB of replies a
  second. A request over a rate waits for its turn, for up to 2 seconds, so a fast client is
  paced rather than refused.
* A request over a limit, or for a root the node does not hold, gets an empty answer. It is never
  an error and never a disconnect.
* A frame that is too large or does not decode, a message id outside `snap/1`, or a
  response-shaped message disconnects the peer.
* A connection runs at most 64 requests at once, which reserve at most 16 MiB of replies. Further
  requests wait in a queue of at most 128 requests and 1 MiB of decoded requests, for up to 2
  seconds. A request past the queue, or one that waits too long, gets an empty answer at once.
  The connection keeps reading, because a full inbound queue would end the whole session, `eth`
  included. It stops reading only when 128 empty answers wait to be sent, which happens only
  while the peer does not read its replies.

The server limits and their defaults are in `Snap1Config` (`src/server.rs`). The connection limits
are constants in `src/protocol.rs`.
