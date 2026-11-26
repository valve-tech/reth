# Sync-committee head verification: design

Status: 2026-11-23. Built in the `reth-pulsechain-light-client` crate
(`crates/pulsechain/light-client`): in `sync_committee.rs` the types, the Merkle checks and the
`LightClientStore`; in `json.rs` the JSON reader and writer and the pin check. Built in
`light_client.rs`: the endpoints, the SSE topics, the `--head.verify` flag and the start checks.
Built in `beacon/sync.rs`: the follower wiring. Built in `sync_committee_file.rs`: the store file,
so a restart does not bootstrap from the anchor again. Built in `light_client.rs` and the network
table: the per-chain checkpoint pins (see Checkpoint).

## Why

Today the beacon URLs choose the head. The node rebuilds the execution block hash from the
payload, so a payload must be self-consistent. But a beacon quorum that agrees can still forge the
header fields of a block that carries the real state root (see the README trust model). The peer
check (`--head.confirm=peer`) and the finalized anchor narrow this. They do not remove it.

The Altair light-client sync protocol removes it. The chain's sync committee (512 validators,
replaced every 256 epochs) signs each block root. The node checks that BLS signature and then
proves the execution block hash into the signed beacon header with a Merkle branch. One hostile
beacon source can then delay the head, but it cannot forge one. Helios and Lodestar's light client
work this way.

## What the existing lite clients do

* **reth-lite today** does not check any beacon signature. It trusts a quorum of beacon REST
  sources, an optional static devp2p peer, and the finalized anchor.
* **The Go PulseChain lite node** does not do this either. It trusts its local consensus client.
  The block hash comes from Engine API `newPayload` and `forkchoiceUpdated`, and from
  `blinded_blocks/{head|finalized}` on an unauthenticated beacon REST URL. The safety comes from
  the local lighthouse-pulse, which runs full consensus. Our review of its code found no
  sync-committee code. A browser build of it would need a sync-committee light client for its
  roots.

So this design is new for PulseChain. It follows the Ethereum spec and the Helios model.

## PulseChain values

Checked on 2026-11-23 against `https://checkpoint.pulsechain.com` (Checkpointz v0.24.0) and the
lighthouse-pulse network configs.

| Value | 369 | 943 |
|---|---|---|
| `genesis_validators_root` | `0x3357ba00…0c90` (source and `genesis.ssz` agree) | `0xd81664ba…4e64` (`genesis.ssz` only; no 943 source checked) |
| `genesis_time` | 1683785555 | 1681356369 (`genesis.ssz`) |
| Altair / Bellatrix / Capella version, epoch | `0x0000036a` 1, `0x0000036b` 2, `0x0000036c` 3 | `0x00000944` 1, `0x00000945` 2, `0x00000946` 4200 |
| Deneb, Electra | not scheduled (`fork_schedule` shows `0xffffffff` at far future) | not scheduled |

Both chains: `SECONDS_PER_SLOT` 10, `SLOTS_PER_EPOCH` 32, `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` 256,
`SYNC_COMMITTEE_SIZE` 512, `MIN_SYNC_COMMITTEE_PARTICIPANTS` 1. One period is 8192 slots, about
22.8 hours. The finalized block at slot 11167584 had 493 of 512 participants.

These values go into the PulseChain network table (`crates/pulsechain/hardforks/src/network.rs`).
At start the node reads `/eth/v1/beacon/genesis` and `/eth/v1/config/fork_schedule` from every
beacon source and from the anchor. A source that disagrees with the pinned values is dropped, and
the node logs an error that names its host label. A source that does not answer is kept but not
used: one timeout must not drop an honest source for good. Its source task reads the values
again, with backoff from one `--beacon.poll` up to five minutes, and uses or drops the source by
the answer. The two cases log different messages. If no source agrees, the node does not start.
The node never takes these values from a source.

## Data flow

```
pin ──root──▶ bootstrap shipped in the binary;  --checkpoint ──root──▶ bootstrap/{root} (any source)
  (no checkpoint: anchor ──finalized root + block──▶ seed ──root──▶ bootstrap/{root})
                                                              │ verify: header root, execution
                                                              │ branch, current committee branch
                                                              ▼
SSE light_client_{optimistic,finality}_update ──▶ LightClientStore ◀── updates?start_period (rotation)
or poll optimistic_update / finality_update       │ verify: BLS, ≥ 2/3, branches, order
                                                  ▼
                       verified (beacon root, execution block_hash, number)
                                                  │
                      /eth/v2/beacon/blocks/{root} ──▶ parse_beacon_block ──▶ block_hash must match
                                                  ▼
                                     HeaderChain head / finalized (as today)
```

## Verification (per the spec)

The verifier is a pure module (`sync_committee.rs` in `reth-pulsechain-light-client`) with no
I/O. It follows `sync-protocol.md` for Altair and Capella.

* **Header.** `is_valid_light_client_header`: from Capella on, the `ExecutionPayloadHeader` root
  must prove into `beacon.body_root` at `EXECUTION_PAYLOAD_GINDEX` 25 (depth 4). Before Capella the
  execution part must be empty. Every head the node uses is Capella. The store accepts an Altair or
  Bellatrix header with an empty execution part, as the spec does, so the follower must take a
  head only from a Capella header.
* **Bootstrap.** `hash_tree_root(header.beacon)` must equal the trusted root, and
  `current_sync_committee` must prove into `beacon.state_root` at `CURRENT_SYNC_COMMITTEE_GINDEX`
  54 (depth 5).
* **Update.** `validate_light_client_update`, with two changes. The node needs at least 2/3 of
  the committee: `participants * 3 >= 512 * 2`, so 342 or more. It uses this one bar for optimistic
  heads and for finality. The spec's bar for finality is the same, but for the optimistic header
  it uses a lower, adaptive safety threshold. The node also never makes a forced update after the
  spec's `UPDATE_TIMEOUT`. The other checks follow the spec:
  * `current_slot >= signature_slot > attested slot >= finalized slot`. The current slot comes from
    the wall clock and the pinned `genesis_time`, with 500 ms of tolerance.
  * The signature period is the store period, or the next period when the next committee is
    known.
  * `finality_branch` proves the finalized header root at `FINALIZED_ROOT_GINDEX` 105 (depth 6).
  * `next_sync_committee_branch` proves the next committee at `NEXT_SYNC_COMMITTEE_GINDEX` 55
    (depth 5). An update in the store period must not change a next committee that is already
    known.
  * The signature: `fast_aggregate_verify` over the participants' keys (blst `min_pk`). The
    signing root is `compute_signing_root(attested_header.beacon, domain)`. The domain uses
    `DOMAIN_SYNC_COMMITTEE` `0x07000000`, the fork version at the epoch of slot
    `max(signature_slot, 1) - 1`, and the pinned `genesis_validators_root`.
* **Apply.** `process_light_client_update` for the optimistic header, the finalized header and
  the committee rotation (current = next when finality enters the next period).
* **Forks.** The generalized indices come from a table keyed by the fork of the attested header.
  Electra changes three of them: `FINALIZED_ROOT_GINDEX` 169, `CURRENT_SYNC_COMMITTEE_GINDEX` 86
  and `NEXT_SYNC_COMMITTEE_GINDEX` 87. `EXECUTION_PAYLOAD_GINDEX` stays 25 through Electra. Deneb
  adds two fields to `ExecutionPayloadHeader`, which changes its root. The first version
  implements Capella only. Deneb and Electra get table entries and tests when PulseChain schedules
  them. An update at a fork the binary does not know is refused. The node logs an error that names
  the fork version, and the head goes stale.

Crates: `blst` 0.3.17 and `tree_hash` 0.12 are already in `Cargo.lock`. `ethereum_ssz` 0.10 is
needed only for the store file. The node adds them as direct dependencies of the lite crate; no
new crate enters the tree. The alloy `light_client_*` event types have no `execution` or
`execution_branch` (they are Altair shapes), so the node defines its own Capella types. It reads
them from JSON, with the same size limits as other beacon answers.

## Checkpoint

The first committee needs a trusted root. Each chain in the network table
(`crates/pulsechain/hardforks/src/network.rs`) can pin a checkpoint: a finalized beacon block
root, its slot and the date it was read. The 369 pin is slot 11169568, read from Checkpointz on
2026-11-24. The comment next to it says how the root was checked. 943 has no pin: no 943 beacon
source was reachable.

* **Order.** A usable store file wins. Else `--checkpoint=<root>` wins over the pin. Else the pin.
  With neither (943 today) the node bootstraps at the anchor's finalized root, as before, and
  warns that the anchor's root alone decides the first committee.
* **Bootstrap.** Each pin ships with its bootstrap, in
  `crates/pulsechain/light-client/checkpoints/` (about 57 KB of JSON, in the beacon API form).
  The node checks it like a source's answer: the header must hash to the pinned root and the
  committee must prove into its state root. No
  source is asked for it. A source does not serve a bootstrap at an old root on a common node
  type: lighthouse-pulse builds one from the block's state (`get_light_client_bootstrap`), and a
  checkpoint-synced node without `--reconstruct-historic-states` deletes that state when the
  next finalization migrates it, and keeps no cold summary. A node that keeps historic states
  replays up to 8191 blocks for it (one restore point is 8192 slots), which can take longer
  than the 10 s request limit. We read this in the lighthouse-pulse source; no public source
  serves light-client data to test it. For `--checkpoint` a source
  must serve `bootstrap/{root}` at start, so the root must be the source's current finalized
  root, or close to it. The anchor is not asked anything at start, as with a saved store. If no
  source serves the bootstrap, the start fails; it does not fall back to the anchor.
* **Seed.** A checkpoint store seeds like a saved store: it catches up with `updates` and the
  sources' finality updates, and seeds at the latest verified finalized block once it is less
  than an hour old. The checkpoint header counts as a verified finalized header, since it hashes
  to a trusted root.
* **Age.** The node refuses a checkpoint whose block is more than `MAX_CHECKPOINT_AGE` (30 days)
  old by its slot and the pinned `genesis_time`. A pin is checked before any request; a
  `--checkpoint` root after the bootstrap, whose header gives its slot. The error says how to get
  a fresh root. A saved store has the same limit. Why 30 days: the older the root, the more past
  committees a hostile source can choose from to sign a made-up chain of rotations, and members
  are not slashed for it. A month gives each release's pin a month of use and keeps the catch-up
  to about 32 periods, two or three `updates` requests of 16. The limit does not come from what
  the sources keep. The spec asks a server to keep light-client data for
  `MIN_EPOCHS_FOR_BLOCK_REQUESTS` (about 122 days), but lighthouse-pulse keeps less. A bootstrap
  needs the block's state, which a checkpoint-synced node deletes about one epoch after the block
  is finalized, so the pin's bootstrap ships in the binary (see Bootstrap). The `updates` branch
  (5280b708a) keeps the best update of each period in its hot database with no pruning, but only
  for periods it imported with `--light-client-server` on. So the catch-up from a pin needs a
  source whose light-client server ran since the pin's period; the start checks this for the
  pin's own period. We read this in the source and have not seen it on a live node: no public
  source serves light-client data.
* **Refresh.** Each release refreshes the pins with `crates/pulsechain/lite/scripts/checkpoint-root.sh
  -o crates/pulsechain/light-client/checkpoints/<chain>.json <beacon-url> <check-url>` (see the README).
  It reads the finalized block and the finalized state from Checkpointz. It fails unless a
  second, independent beacon node calls the root finalized and canonical with the same header:
  a header that hashes to the root proves only that one server is self-consistent, and a pin is
  the trust root of every new node. Then `checkpoint-bootstrap.py` hashes
  the Capella `BeaconState` and `BeaconBlockBody` to build the bootstrap. So a release needs no
  light-client server.

## Endpoints

| Endpoint | When | From |
|---|---|---|
| `/eth/v1/beacon/genesis`, `/eth/v1/config/fork_schedule` | start | every source and the anchor, compared with the pins |
| `/eth/v1/beacon/blocks/finalized/root`, then `/eth/v2/beacon/blocks/{root}` | seed, only without a checkpoint | the anchor (Checkpointz serves both) |
| `/eth/v1/beacon/light_client/bootstrap/{root}` | first start, or a stale store file, at the `--checkpoint` root (else the anchor's); never at a pin, whose bootstrap ships in the binary | any beacon source |
| `/eth/v1/beacon/light_client/updates?start_period=P&count=N` | catch-up after start, and each period for the next committee | any beacon source |
| `/eth/v1/events?topics=light_client_optimistic_update,light_client_finality_update` | each head | each source, as today's SSE |
| `/eth/v1/beacon/light_client/{optimistic,finality}_update` | each poll without SSE | each source |
| `/eth/v2/beacon/blocks/{root}` | each head and ancestor, as today | each source |

The anchor root and the anchor block now come from two calls by root. Today one call
(`blocks/finalized`) gives a block with no beacon root. A bootstrap needs that root.

Availability: `checkpoint.pulsechain.com` answers 404 to every `light_client` path. Our
lighthouse-pulse `master` serves `bootstrap`, `optimistic_update`, `finality_update` and the two
SSE topics with `--light-client-server`. It does not serve `updates`. Only the local branch
`feat/light-client-updates-by-range` (5280b708a) adds it. Without `updates` the node cannot learn
the next committee, and it stops at the first period boundary, within about 23 hours.

## How it plugs into the follower

A new flag `--head.verify=quorum|sync-committee` selects the mode. The default is `quorum`, which
is today's behaviour unchanged.

* **Head acceptance.** Each source reports a head as the root of a verified update's attested
  header, not as `headers/head`. The store keeps a short map from a verified beacon root to its
  execution `block_hash` and number. `advance_once` fetches the block by that root and accepts it
  only if `parse_beacon_block` gives the same `block_hash` and the signed beacon `parent_root`.
  The ancestor walk does not change: each execution hash commits to its parent's, so a verified
  head verifies its ancestry. The node takes a head only from a Capella header.
* **Quorum.** One verified update is enough, so `--beacon.quorum` has no job in this mode, and
  the node refuses a value above 1 at start. Extra sources give liveness: the node uses the first update that verifies. A source whose update fails
  verification counts in `lite_proof_failures_total{source="beacon"}` and goes later in the order,
  as today. An honest source can send an update that is stale, signed in a period whose committee
  the node lacks, signed by too few members, from a slot the clock has not reached or from an
  unknown fork. The node drops such an update but does not count it against the source. A source
  that serves another block under a verified root is counted.
* **Peer confirmation.** It stays an independent extra check, off by default: in this mode
  `--head.confirm` defaults to `none`, so no static peer is needed. With an explicit
  `--head.confirm=peer` a head needs a verified update and the peer's block hash. Sync-committee members are not slashed for
  signing a wrong header, so this check still has value.
* **Finality.** A verified finality update (2/3 or more, finality branch) moves finality to the
  held canonical block with the proven `block_hash`. It needs no beacon quorum and no 64-block
  depth. `safe` and `finalized` then work with one source. In this mode the anchor check never
  moves finality.
* **Anchor.** With a checkpoint (see Checkpoint) the anchor gives nothing at start. Without one,
  at the first start the anchor gives the bootstrap root. The seed must be recent, and
  confirmed by the peer when `--head.confirm=peer`. A beacon quorum confirms no anchor block in this
  mode, neither for the seed nor for a re-seed: else the anchor and the beacons together could drop
  a chain the committee verified, with no signature. The bootstrap must then prove the anchor's own
  `block_hash`: the seed fetches the block under the bootstrap root from the anchor, and it must
  have the proven `block_hash` and `parent_root`. The store does not confirm the seed, since its
  bootstrap came from the anchor's root. The anchor's root alone decides the first committee. The
  seed checks compare only the execution `block_hash` and the beacon `parent_root`, not the beacon
  `state_root` that holds the committee. A lying anchor can give the root of a made-up header that
  carries the real execution payload and a state root with its own committee; the peer then confirms
  the seed, because the execution block is real. So the peer confirmation covers heads, not the
  first committee. The bootstrap root is fixed, so a block that is too old to seed never becomes
  recent again. The node then bootstraps again at the anchor's new finalized root before the next
  try. After that verified finality always wins over the anchor. An anchor block that disagrees
  with the held chain does not halt serving. The node re-seeds at it only when it is recent, the
  store or the peer confirms it, and it is not below the held finalized block or a block the store
  proved finalized at or above its number. Otherwise the node counts the check in
  `lite_anchor_disagreements_total`, logs a warning once per disagreeing block (host label only)
  and keeps serving. Quorum mode keeps the halt.
* **Re-seed.** The store's verified finalized header and the peer are the confirmation sources
  for `anchor_confirmed`. A forward re-seed (a gap above 512 blocks) uses the store's verified
  finalized header and fetches that block by its root. It does not need the anchor. Only a
  finalized header that a signed update proved counts; the bootstrap header does not. A header
  restored from the store file counts (see Persistence).
* **Next committee.** A task fetches `updates` up to the wall clock's period: once at start, and
  then every sixth `--beacon.poll` while the store lacks the next committee or is behind the wall
  clock. Without the next committee they start at the store period; with it they start at the
  next period. An update that an honest source can send but the store refuses, such as a stale
  one, does not stop the updates after it.

## Failure behaviour

The node fails closed. It never falls back to `quorum` mode by itself.

* **No light-client server at start.** If every source answers 404 or 501 for `bootstrap` or
  `updates`, the node exits non-zero. A saved or checkpoint store behind the wall clock's period
  also needs an update signed in its own period: lighthouse-pulse skips a period it holds no
  update for, so a source that enabled `--light-client-server` after that period answers `[]`,
  and the store could never leave its period. Such an answer counts as not served. When no
  source serves the bootstrap at a `--checkpoint` root, the error names the root, says that the
  source may hold no bootstrap for a root that old, and points to a fresh root and
  `checkpoint-root.sh`. Only the anchor path points to `--head.verify=quorum`. The error names the endpoint and each host label, and it
  says to enable `--light-client-server` (with `updates` support) or use `--head.verify=quorum`.
* **Bad update.** The node drops it, counts the failure against the source, and keeps the head.
  The log warns when a source starts sending bad updates, not for each one. A bad update on an
  event stream closes that stream, since a stream has no rate limit and each update costs a
  signature check. The source is then polled, and its stream reopens after twice the SSE retry
  gate, doubling for each such close in a row up to 32 times.
* **No verified update.** The head stops moving, and after `--head.max-age` reads answer
  `head is stale`. This also covers participation below 2/3 and a source that withholds updates.
* **No next committee.** When the store period ends and no source has served a valid
  `next_sync_committee`, the node logs an error that names `light_client/updates` and the period.
  The head goes stale. The node logs the same error when the store is two or more periods behind
  the wall clock and no source served the update that rotates its committees.
* **Unknown fork.** See Forks above.

New metrics: `lite_sync_committee_period`, `lite_sync_participation` (participants in the last
accepted update), `lite_head_verify{mode}` and `lite_anchor_disagreements_total`.

## Per-head latency

The signature over the block at slot S travels in the block at slot S+1. So a verified head is
always one slot (10 s) behind the beacon head, plus the time the server takes to import S+1 and
publish the update. Helios has the same lag. The `--head.max-age` warning must use two slots plus
`--beacon.poll` in this mode. The CPU cost is small: one pairing check and at most 512 point
additions per update. That is about 1 to 2 ms. The node checks and decompresses the 512 keys once
per committee, which takes about 25 ms. The network cost per head is one update, about 1 KB, on
top of today's block fetch.

## Persistence

The node keeps the store in `<datadir>/sync-committee.ssz`, not in the state store, which evicts.
It is an SSZ container of a format version, the chain ID, the `genesis_validators_root`, the
finalized `LightClientHeader`, the current committee and the next committee (a list of zero or
one), followed by the SHA-256 of the container. That is about 50 KB. The checksum catches a
flipped bit that still decodes: a changed key that stays a valid point would fail every signature
for good. The node writes the file atomically (temporary file, fsync, rename) when the committee
changes and when finality moves, at most once every ten minutes. A change inside the ten minutes is
written with the first verified update after them. The write runs on a blocking thread.

At start the node loads the file if the checksum holds, the chain ID and root match the pins and
the finalized header is at most `MAX_CHECKPOINT_AGE` (30 days) old by its slot: the
checkpoint's limit, so a store the node verified itself is never dropped for an older pin. It restores the store with the header's
execution branch and every committee key checked again. The start checks then skip the anchor:
no pins check, no finalized root and no bootstrap. The sources must still match the pins, and one
must serve `updates` for the stored period. A file that is missing, damaged, too old or for another
chain is ignored with a warning, and the node bootstraps at the checkpoint, or at the anchor's root
without one.

The restored seed does not use the anchor either. Before each try the node catches up with
`updates` from the stored period and each source's latest finality update. The seed is then the
store's latest verified finalized block, fetched from the sources by its root with the verified
`block_hash` and `parent_root`, once it is less than an hour old. Its finality is confirmed at
once. The saved finalized header counts as a verified one for `anchor_confirmed` and the re-seed:
the run that saved it applied updates only after its seed passed the anchor checks, and it writes
the file only after an update. After the seed the anchor is checked as above: it never halts
serving.

## Testing

The verifier takes the preset (committee size, slots per epoch, epochs per period), the fork table
and the `genesis_validators_root` as parameters. The consensus-spec-tests then run against the
same code:

* `light_client/single_merkle_proof` (mainnet preset, Capella): the four branches.
* `light_client/sync` (minimal preset, Altair and Capella, and Bellatrix's `capella_fork`):
  bootstrap, updates, rotation, finality. The node makes no forced update, so each case stops at
  its first `force_update` step.
* `light_client/update_ranking`: only if the node keeps a best update per period.

A small derived set goes in `crates/pulsechain/light-client/testdata/` with a README that names
the spec release. Hand-built negative tests cover: a wrong domain or fork version, participation
below 2/3, a branch for the wrong field, an execution branch that does not match, a rotation
without a valid `next_sync_committee` branch, an update older than the store, and a forged
signature.

A real PulseChain fixture needs no light-client server. A block's `sync_aggregate` signs its
`parent_root`. The finalized state from Checkpointz (`/eth/v2/debug/beacon/states`, 19 MB of SSZ)
holds the committee and gives its branch. A script outside the repo derived the `real_369*` files
from slot 11167808; only the small result (about 27 KB) is committed. The tests show that the real
signature verifies with the 369 domain and fails with the 943 domain or one flipped bit. The
committee proves into the real state root at gindex 54 and the execution header into the real body
root at gindex 25, so PulseChain's `BeaconState` and `BeaconBlockBody` use the standard layout. The
real block also bootstraps a store.

## Out of scope

* Serving light-client data, and light-client gossip over libp2p.
* Forced updates after `UPDATE_TIMEOUT`.
* Verifying the `sync_aggregate` in ordinary blocks, with the committee taken from a full state.
  This works without a light-client server, and the finalized 369 state is only 19 MB (2.5 s from
  Checkpointz on 2026-11-23). But the node must then hash a whole Capella `BeaconState` and
  `BeaconBlockBody` itself. That is far more SSZ code than the light-client path. It is an open
  question for the owner, not part of this plan.
* Deneb, Electra and later forks, until PulseChain schedules them.
* Any proof that the execution was valid. The committee signs what its members' clients
  validated; nothing in this node executes the block.
