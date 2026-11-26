# Light-client data server: design

Status: design, 2026-11-23. Built: the shared `light-client` crate (the move, the JSON writers,
the SSZ merkleizer, the Capella schemas and the build functions in `derive`), and in `lc-server`
the storage (`archive.rs`), the bounded upstream client and the start check of each upstream's
genesis (`upstream.rs`), the checkpoint and head tasks (`checkpoint.rs`, `head.rs`), and the
self-check store with the latest answers (`answers.rs`), the hyper API with SSE (`api.rs`), the
flags (`config.rs`) and the binary `reth-pulsechain-lc-server` (`server.rs`, `main.rs`). The
self-check store is the server's trust anchor (see Trust anchor). The metrics are a request
count by endpoint and status, the count of stored update files outside the chain, whether the
anchor file does not check out, and the count of refused checkpoints; the other per-cause failure
metrics are not built.

## Why

reth-lite's `--head.verify=sync-committee` needs the beacon light-client API. No public PulseChain
server has it: `checkpoint.pulsechain.com` answers 404 on every `light_client` path, and
lighthouse-pulse `master` does not serve `updates`. Without `updates` a client stops at the first
period boundary, within about 23 hours.

`lc-server` is a separate binary that a user runs. It reads the standard beacon endpoints that
PulseChain servers already answer and serves the light-client API from them. reth-lite does not
change: it points a `--beacon.url` at the server. The server also answers `config/spec` with the
chain ID, the preset and the pins, where Helios reads the chain ID; no test runs Helios against it.

The sync committee signs the latest block, not only finalized blocks. Each block carries the
committee's aggregate signature over its parent's root; the real blocks we checked had 493 and
495 of 512 signers. The 2/3 bar applies to that signature on every block. Finality is a separate
vote by all validators. So an optimistic update proves a head one slot (10 s) behind the beacon
head, and a finality update proves a finalized block.

## What the upstreams serve

Checked on 2026-11-23:

| Endpoint | `checkpoint.pulsechain.com` | A full beacon node (the keyed `--beacon.url` sources) |
|---|---|---|
| `/eth/v1/beacon/genesis` | yes | yes |
| `/eth/v1/beacon/blocks/finalized/root` | yes | yes |
| `/eth/v2/beacon/blocks/{id}`, JSON and SSZ | epoch-boundary slots only, at least 1000 epochs back; slot S±1 gives 500 | any block |
| `/eth/v2/debug/beacon/states/{slot}`, SSZ, about 19 MB | epoch-boundary slots, about the last 16 epochs; `head` gives 500 | unknown (debug API) |
| `/eth/v1/events?topics=head` | 404 | yes (reth-lite uses it today) |

So no single upstream is enough. The state must come from Checkpointz. The block that carries a
checkpoint's sync aggregate is the checkpoint's child, which only a full beacon node serves.

The server has two upstream flags: `--state.url` (default `https://checkpoint.pulsechain.com` on
369, required on 943) and `--beacon.url` (one or more, the same keyed URLs as reth-lite; the first
good answer wins).

## What each answer needs

Notation: F is the newest finalized checkpoint block, at slot S. C is F's child (the first block
after S, with `parent_root == root(F)`). G is the block at `state(F).finalized_checkpoint.root`. H
is a new head block and P is its parent. `LCH(x)` is the light-client header of block x: the beacon
header, the execution payload header and the execution branch (gindex 25), all computed from the
block body.

| Answer | Built from | Upstream calls | How often |
|---|---|---|---|
| `bootstrap/{root(F)}` | `LCH(F)`, `state(F).current_sync_committee` and its branch (gindex 54) | block F (SSZ), `states/{S}` | each finality step (one epoch, 320 s) |
| `finality_update` | attested `LCH(F)`, finalized `LCH(G)`, finality branch (gindex 105) from `state(F)`, C's `sync_aggregate`, `signature_slot` C.slot | the same state and F, plus C by slot, G by root | each finality step |
| `updates` for period p | a finality update with `next_sync_committee` and its branch (gindex 55) from `state(F)`, where F, G and C are all in period p | nothing more | the first finality step that qualifies in each period, about 2 epochs after it starts |
| `optimistic_update` | attested `LCH(P)`, H's `sync_aggregate`, `signature_slot` H.slot | H (and P, usually cached as the previous H) | each new head, every slot |
| SSE `light_client_finality_update`, `light_client_optimistic_update` | the two answers above | nothing more | on each change |
| `genesis`, `config/fork_schedule`, `config/spec` | the pinned values and the preset for the chain | none | never fetched |
| `/eth/v2/beacon/blocks/{id}`, `blocks/{id}/root` | passed through unchanged to `--beacon.url`, for a root or a slot | one per request | per client request |

reth-lite asks every source for `genesis` and `fork_schedule` at start, and fetches each verified
head block by root from the source that reported it. That is why the server answers both: the
pass-through lets a user give reth-lite one URL. reth-lite checks each block against the signed
`block_hash`, so a root adds no trust. A slot is passed through for a client that checks the block
against a verified header at that slot, as Helios does for its execution payloads; no test runs
Helios. A named block (`head`, `finalized`, `justified`, `genesis`) is 400. No client can check it
against a root, so the first beacon URL's answer would be the trust root of a client that uses
this server as its anchor: reth-lite's anchor asks for `blocks/finalized/root` and
`blocks/finalized`.

The server checks every input before it uses it. A block must hash to the root it was asked for.
F's slot must not be after the wall-clock slot. A
state must hash to its block's `state_root`. C must name F as its parent, and C needs at least 342
of 512 signers. C is fetched by slot, so no root ties it to F: once the state gives the committee,
C's aggregate must verify over F, or the server asks the other beacon URLs for C and tries the
root again. F, G and C must have a fork the binary knows. For a period update they must also
share one period, so for about the first 2 epochs of each period, while G is still in the period
before, the server builds the finality update but no period update. Then the server applies the update to its own
`LightClientStore` (the same code reth-lite runs) and serves only what that store accepts. That
store is the server's trust anchor (see Trust anchor): the server refuses a checkpoint whose
committee is not the one the store verified for F's period. It stores F's bootstrap only after
the store's own committee verifies C's aggregate over F, or when F is the store's finalized
header. The state's committees are only the claim of whoever made F, and a forger knows the
real committee: a hostile state URL and beacon URL can name a made-up F whose state holds it. An older update never moves the store or the served finality
update back. The server skips a finalized root whose F is not newer than the newest checkpoint it
handled, or that can teach the store nothing, before its state.

The server hashes each state once and builds the bootstrap, the finality update and the period
update from that one hash. It stores the bootstrap after the check of C and before it fetches G,
the block whose root the state names, and the finality branch then proves that root.

Verified finality lags the network by about two more epochs. `state(F)` proves G, and G is about two
epochs before F. So reth-lite's verified `finalized` block is about 4 epochs (21 minutes) behind the
head, not 2 epochs. That is still inside reth-lite's one-hour seed limit.

## Cost

Bandwidth: one 19 MB state per epoch is about 270 states and 5.1 GB a day. Blocks add about one
15 to 30 KB block per slot, about 200 MB a day. A state every fourth epoch would cut this to 1.3 GB,
but verified finality could then lag 42 minutes, too near the one-hour limit. So the server fetches
one state per finality step and has no flag for it. A state fetch that fails is tried at most 6
times in an epoch.

CPU: hashing a state is about 2 million SHA-256 compressions, under one second, on a blocking
thread. Each head costs one block-body hash.

Memory: the server holds one state at a time and frees it after the hash. It hashes the SSZ bytes
in place, field by field, and never decodes the validator list into structs. The body limit is
64 MB (19 MB today, of which 114,777 validators are 13.9 MB). Other memory is small: the
light-client headers of the last 64 blocks it hashed, the latest finality and optimistic updates,
and the self-check store's committee keys. The target is under 100 MB resident.

## Storage

The server keeps one directory per chain: `<datadir>/<chain_id>/`.

* `sync-committee.ssz`: the self-check store, saved each time it moves: its finalized header and
  its committees, the fields of reth-lite's store file. A restart goes on from it (see Trust
  anchor).
* `anchor.ssz`: the store that the datadir first started from, in the same form: the store
  bootstrapped at `--checkpoint` or at the pin, written once that store reaches the wall clock's
  period. A datadir from an older build, with a saved store and no anchor file, writes the saved
  store that loaded. The server writes the file once and never overwrites or deletes it, so every
  restart walks up from the datadir's first store. A file that does not check out (checksum, format
  version, chain ID or `genesis_validators_root`) stays in place, unused. The server warns, sets
  `lc_server_archive_unreadable_anchor` to 1, and walks from the pin and the self-check store only.
  An operator who moves the file away gets a new one at the next start, from the store that start
  uses. Deleting `sync-committee.ssz` does not change the file: a start that bootstraps at a new
  root keeps the old root's anchor, and the anchor's walk still serves the stored updates that the
  old root verified, before the pin's walk. The start then warns with both roots. To start the
  datadir at the new root alone, also move `anchor.ssz` away. The anchor file has no age limit, as
  the pin's store has none: it only checks the signatures of stored updates, and is never the
  server's head. It is trusted as `sync-committee.ssz` is: a forger must replace one of these two
  files, and one forged update file still gets nothing served.
* `updates/<period>.ssz`: the update for each period, kept forever. About 25 KB each, 9 MB a
  year. Checkpointz keeps only about 16 epochs of states, so the server cannot rebuild a past
  period. A period that the server missed in full is never served. The server writes an update
  only after the self-check store verified it. At start, before it serves, it walks the stored
  updates up and serves only the ones whose signatures a walk checks. Three walks run: from the
  pin's store, bootstrapped at the chain's pin from the bootstrap that ships with it, from the
  anchor file's store, and from the self-check store. Walking up from a store's period, the
  store's committee of each period must sign the period's update, and the store learns the next
  committee from it and moves on. A missing period ends each walk. The server serves the union
  of the walks. Where they take different files of a period, the file from the self-check
  store's walk is served, else the one from the anchor's, else the one from the pin's. The walks
  from the pin and the anchor do not move the self-check store, which stays the server's head.

  No update below all three walks is served. Nothing could check its signature: a forger knows
  the real committees, so a forged update can carry the committee of the period after it as its
  next one, with branches that check out against its own header. So the stored updates below the
  periods of the pin and the anchor stay in place, unserved, and are counted. Files of format
  version 1 come from builds whose store an upstream root could anchor, so the server does not
  read them: they stay in place, unserved.

  The server never moves, replaces or deletes a stored update file. A file outside the chain, or
  one that does not read, stays in place, unserved. It is counted in
  `lc_server_archive_unchained_updates` and logged once, for an operator to check. An update that
  the store accepts for a period that has such a file is written beside it as `<period>.<n>.ssz`,
  with the first free `n`, and served. Of two files of a period that both chain, the first by name
  is served. So neither a hostile newer update nor hostile older history can evict the chain that
  the store verifies, or block an update that it accepts, and a mistake in the server costs no
  file. Files that an older version set aside (`.ssz.unchained`, `.ssz.replaced`) are left alone.
  A user who writes update files cannot make the server serve one that no committee of a walk
  signed. A user who writes the store file sets the server's head, as with reth-lite's store
  file.
* `bootstraps/<root>.ssz`: a bootstrap for each checkpoint, kept for 7 days (the same limit as
  reth-lite's store file). About 1,900 files and 47 MB. At most 4,096 are kept, the oldest
  deleted first, so a state URL that names more roots than the chain finalizes cannot fill the
  disk. At start the server compares each stored bootstrap's committee with the one that the
  self-check store, or the next committee of the chained update of the period before, gives for
  its period. One that differs, as from a store at a root that the operator replaced, is not
  served and is deleted when it is old. One of a period whose committee neither gives is served.

Files use the same format rules as `sync-committee.ssz`: SSZ, a SHA-256 checksum, and an atomic
write. At start the server loads them and ignores a damaged file, or one of another format
version, with a warning. A store file of version 1 is not used, so the store bootstraps at the
root again. The latest finality
and optimistic updates are kept in memory only; after a restart the next ones come within an epoch
and a slot.

## When upstream data is missing

The server never serves an answer it could not verify. It drops the missing piece, logs once per
cause, counts it in a metric, and waits for the next checkpoint or head.

* **State URL down or slow.** No new bootstrap, finality update or period update. Optimistic
  updates go on while the self-check store can check them. The stored period updates are checked
  at start, so they stay served. The server tries the same root again while it is still the newest, and drops an
  older one that failed. It waits 1 slot after the first failure, and the wait doubles after each
  next one, up to 32 slots (one epoch). A `bootstrap` miss does not skip the wait. Each try
  fetches only what the tries before did not get, so a missing G or a full disk costs no second
  state. An upstream failure, a block that does not read or a failed write is a cause that it
  tries again: one beacon URL's bytes must not drop a root that another URL serves. Other data
  that does not check out drops the root.
* **State root mismatch.** When the first slot of an epoch has no block, the state at that slot
  is not the post-state of F, and its root differs. The server drops that checkpoint.
* **No child.** The server asks for slots S+1 to S+32 by slot. The first block it finds must have
  F as its parent. A block on another parent is a failed answer, so the server asks the next
  beacon URL, and tries the root again when none gives the child. A beacon URL and a state URL
  that disagree on F's child do not agree on the chain, so the server stores no bootstrap either.
  A block that does not read is named only when every beacon URL answered.
* **Low participation.** Below 342 signers, the server drops the update. A client would refuse it.
  The server stores no bootstrap either, since no verified committee signs F, unless F is the
  self-check store's finalized header.
* **No head events.** The server polls each beacon URL's `/eth/v1/beacon/headers/head` every
  slot, as reth-lite does, so a URL that lags does not hide the head of another. Each new head
  costs a block request to every beacon URL, so an event stream that sends more than 4 heads in
  a slot ends, and opens again a slot later. The block requests still go to the beacon URLs in
  order, so a slow URL before an honest one delays each head by up to its timeout. The server keeps
  the last 64 refused heads. A head refused for a cause that may pass, as before the first
  checkpoint, is tried again at most once a second when a URL reports it again. A head is the
  head for one slot, and a URL that relays gossip early can report it before any URL serves the
  block, so the server also tries the newest such head again on its own, a second apart, up to
  4 tries in all. A block that does
  not read is such a cause: one beacon URL's bytes may be at fault, so the next try asks every
  beacon URL again. Only a head whose blocks hash to their roots but do not give an update is
  not tried again.
* **Unknown fork.** At start the server compares each upstream's `genesis` (the validators root,
  the genesis time and the genesis fork version) with the pins and refuses a mismatch, as
  reth-lite does. The state URL and at least one beacon URL must answer. A beacon URL that does
  not answer is kept and checked before its first use; one on another chain is then never used.
  A block at a fork the binary does not know stops the derivation, and the server logs an error
  that names the fork version.
* **A task ends.** The checkpoint task, the head task and the API run until the server stops. If
  one ends, as by a panic, the server exits with an error that names it, so it never serves old
  answers with no sign.
* **A checkpoint that does not chain.** A state URL on another chain, or a self-check store that
  missed a period's update, gives a checkpoint whose committee the store does not know or does
  not have. The server refuses it: it stores no bootstrap and serves no update, and the store does
  not move. It logs an error once until a checkpoint succeeds, and counts each refusal in
  `lc_server_checkpoints_not_chained_total`.
* **No update yet for a period.** The server logs an error when a period is 8 epochs old and
  `updates/<period>.ssz` is missing. Clients stop at the next boundary unless it comes.

Answers follow Lighthouse: `bootstrap` for an unknown root is 404, `updates` is 200 with the periods
the server has (an empty list when it has none; reth-lite's start check accepts that, and 503 if
the stored ones are not yet checked, which the start does before the API listens), and
`finality_update` or `optimistic_update` before the first one is 404. `updates` gives consecutive
periods from the first one it has in `start_period` to `start_period + count`, at most 128, and
ends at the next period it does not have. The bootstrap and the latest updates name their fork in
`Eth-Consensus-Version`, and a client that accepts SSZ only gets 406. reth-lite bootstraps at the anchor's newest finalized root and exits on a 404. So a
`bootstrap` request for the state URL's current finalized root that the server has not built yet
starts or joins its derivation and waits up to 8 s for it (19 MB takes about 2.5 s to fetch).

A `bootstrap` miss wakes the checkpoint task, or joins the step that builds that root. The woken
step asks the state URL for its finalized root, and builds only that root, so a miss for any other
root is a 404 after one small request. The task starts at most one step a second, so misses cannot
make it ask the state URL without limit.

The block pass-through sends a root with its `0x`. Checkpointz writes roots without it in
`blocks/finalized/root`, but refuses them as a block id. The server serves at most 256
connections at once, event streams included, well under the usual limit of 1,024 open files. At
most 64 of them are event streams: one more is answered 503, and each stream ends after 10
minutes, so idle streams cannot take the slots of other requests. A
write to a client that makes no progress for 30 s ends the connection. The JSON of each period
update is written once when it is stored, and every `updates` answer shares those bytes, so a
client that reads slowly holds no copy. There is no limit for each client address.

## Trust anchor

The self-check store is the server's trust anchor. Four review rounds found that the archive
trusted the wrong thing: the newest file, then the oldest, then a store bootstrapped again at
whatever finalized root an upstream named. The rule is now one root and one direction.

1. **The root is the pin.** The store bootstraps from the chain's pinned checkpoint, with the
   bootstrap that ships at it in `crates/pulsechain/light-client/checkpoints/` (the same data
   and checks as reth-lite). `--checkpoint=<root>` replaces the pin; the server then builds the
   bootstrap from the beacon URLs' block and the state URL's state at the root, or reads it from
   its archive. A root or pin more than 30 days old is refused, as reth-lite refuses one. A
   chain with no pin (943 today) does not start without `--checkpoint`: reth-lite falls back to
   its anchor's root there, but the server has no independent anchor. A root starts a new
   datadir only inside its own sync-committee period (see the trade-offs).
2. **The store only moves forward.** It moves by the updates it verifies: the ones the
   checkpoint task builds, and the stored ones it verifies at start or once its committees
   change. It is saved each time, and a restart goes on from the saved store, which wins over
   `--checkpoint` and the pin, as reth-lite's store file does. Delete
   `<datadir>/<chain_id>/sync-committee.ssz` to start again at the root. For a new root, also
   move `<datadir>/<chain_id>/anchor.ssz` away: else the old root's anchor stays, and its walk
   still serves the history that the old root verified (see Storage). A saved store that does
   not read or is more than 30 days old is not used, and the store bootstraps at the root again.
   The store is never bootstrapped at a root that an upstream names.
3. **Only the updates that a walk up from a trusted store verifies are served,** and no stored
   file is ever moved, replaced or deleted (see Storage). The walks start at the pin, at the
   anchor file's store (the store that the datadir first started from) and at the self-check
   store, so a stored update below all three is not served: nothing checks its signature. The
   anchor file is trusted as the store file is. Deleting `sync-committee.ssz` does not change
   the anchor file.

The trade-offs:

* **A store that falls a period behind stays behind.** The store learns the next committee only
  from a period update, which the server builds only from a recent state. A store that missed a
  whole period, or a root from a period before the current one when the server first starts,
  has no way forward from upstream data: every later checkpoint would be refused. So the start
  checks the store after the archive's walk up. When it has no committee for the wall clock's
  period, past the first 4 epochs of that period, the saved store is not used, and a store at
  the root that does no better stops the start with the periods named. That store is not saved,
  so the next start tries `--checkpoint`. A running server that falls behind serves only its
  stored history. The old code bootstrapped again at the new checkpoint and so kept going, but
  then any state URL decided the committee.
* **History below both the pin's and the anchor's periods is never served.** A datadir that
  `--checkpoint` started after the pin's period, or on a chain with no pin (943 today), serves after
  a restart every stored period from its anchor's period up: the anchor file holds the store it
  first started from. The stored updates below the periods of the pin and the anchor stay on disk,
  unserved and counted, as those that an older datadir stored before its first start with this
  build: its anchor is the saved store of that start. The down walk that served them before checked
  no signature, so a forger who could write one update file could make the server serve it. A
  damaged anchor file costs the history from the anchor's period up to the saved store's, unless the
  pin's walk reaches it, until an operator restores the file.
* **So a pin starts a new datadir for less than a day.** A period is 8,192 slots, about 22.8
  hours, and a pin can start a new datadir only inside its own period and the first 4 epochs
  after it. The 369 pin at slot 11,169,568 is about 12 hours before the end of its period. After
  that, each new datadir, and each server that missed a whole period, needs a root that the
  operator gives with `--checkpoint`, or a release with a newer pin. The root must be one the
  operator trusts: the state URL's own finalized root makes that URL the anchor.
* **A missing period ends the chain.** A client cannot cross that period anyway, and one that
  bootstraps after it does not need the older history.
* **Files outside the chain take disk** until an operator moves them. They are small, and the
  metric and the log say where they are.
* **The trust anchor protects what the server serves, not the client.** A client still trusts
  its own bootstrap root (see below). The server's trust anchor keeps a hostile state URL from
  making the server serve another chain's updates under its name.

## What the client still trusts

The server and its upstreams can delay or withhold answers, or pick an older valid update. They
cannot forge a head, a finality step or a committee change. The client still trusts:

1. **Its bootstrap root.** The root alone decides the first committee. reth-lite takes it from its
   anchor (`--finalized.url`), not from this server, which refuses the named blocks that an
   anchor answers. A user must keep the anchor independent of the server and of its upstreams.
   By default reth-lite's anchor on 369 and this server's state URL are the same host,
   `checkpoint.pulsechain.com`, and that host names the client's root. This server serves a
   bootstrap only at a root that a committee its store verified has signed, so the host can
   pick only among signed roots through it.
2. **2/3 of the sync committee.** Members are not slashed for signing a wrong header.
3. **The pinned chain values** in its binary: `genesis_validators_root` and the fork versions.
4. **Its wall clock**, for the newest slot it accepts.
5. **The beacon nodes that validated the execution.** The committee signs what its members' clients
   checked. Nothing proves the execution itself, as before.

Liveness depends on the server and both upstreams. With no verified update reth-lite's head goes
stale after `--head.max-age`.

## Code layout

A new crate, `crates/pulsechain/light-client` (`reth-pulsechain-light-client`), holds the code
that both binaries share. It has no I/O and no tokio or reqwest, so a WASM build stays possible.

* Moved from `lite`: all of `sync_committee.rs` (types, SSZ, Merkle checks, `LightClientStore`),
  and the JSON read side of `light_client.rs` (`HeaderJson` to `parse_update`, `check_pins`).
  The JSON builders in the lite test helpers become real JSON writers.
* New: a small SSZ merkleizer driven by a type schema over byte slices; the Capella `BeaconState`
  and `SignedBeaconBlock` schemas; and the functions that build each answer from blocks and a state.
  It uses `tree_hash` for the Merkle roots. No new crate enters `Cargo.lock`.

`lite` keeps its I/O (`BeaconClient`, the start checks, the follower, the store file) and imports
the shared crate. `crates/pulsechain/lc-server` (`reth-pulsechain-lc-server`) holds the binary: the
flags, an upstream client with bounded bodies, the checkpoint and head tasks, the storage, and a
hyper server with SSE. The flags are `--chain`, `--beacon.url` or `--beacon.url-file`,
`--state.url`, `--checkpoint`, `--datadir`, `--http.addr` (default `127.0.0.1:9596`) and `--metrics.addr`. One
process serves one chain; a user runs one per chain.

## Embedding in reth-lite

The build functions are library code, so reth-lite could run them in-process and feed its own
store: about 200 more lines, and a single user then needs no server. The cost moves to that user:
5 GB a day of state downloads and a 64 MB memory peak once per epoch, for a node that is meant to be
small. The first version does not embed it. The owner decides after the server runs.

## Out of scope

* SSZ answers (`Accept: application/octet-stream`). JSON only, as reth-lite and Helios read it;
  a client that accepts SSZ only gets 406.
* Light-client gossip over libp2p.
* Rebuilding past periods from another server.
* Deneb, Electra and later forks, until PulseChain schedules them.
