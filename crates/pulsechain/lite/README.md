# reth-lite

A small verifying PulseChain node for edge boxes. It has no chain database and no Engine API. It
takes the head from beacon REST APIs and, by default, has a static peer confirm it. It fetches
state on demand over `snap/1` and answers a fixed JSON-RPC method list on loopback. It verifies
state, code, bodies and receipts against the roots of that head (Merkle proofs, code hashes, body
and receipt roots). It cannot verify the head itself: read the [trust model](#trust-model).

```
install -d -m 700 /etc/reth-lite
install -m 600 /dev/null /etc/reth-lite/beacon-urls
$EDITOR /etc/reth-lite/beacon-urls   # one URL per line: https://beacon.example/<key>/369

reth-lite --chain=369 --datadir=/var/lib/reth-lite \
  --http.addr=127.0.0.1 --http.port=8545 --metrics.addr=127.0.0.1:9001 \
  --beacon.url-file=/etc/reth-lite/beacon-urls \
  --finalized.url=https://checkpoint.pulsechain.com \
  --state.on-miss=error-and-warm --peer=enode://<node-id>@203.0.113.7:30303
```

Put a beacon URL that holds a key in `--beacon.url-file`, not in `--beacon.url`. Any local user can
read a command line from `ps` or `/proc/<pid>/cmdline`, and the shell keeps it in its history. The
node warns at start when the file is group- or world-readable. On chain 943 give your own
`--finalized.url`: the built-in anchor serves 369 only.

The `--peer` must serve `snap/1`. A pulse-reth peer needs `--pulsechain.snap1`, which is off by
default. go-pulse serves `snap/1` unless it runs with `--snapshot=false`. With a peer that does not
serve it, the node follows heads, but every read outside held state fails.

The full node must also trust the lite node. reth-lite only dials out, so it is an inbound peer of
the full node. When the full node's inbound slots are full, it refuses the lite node, and it can
drop it at random to rotate its peers. At start reth-lite logs its record, `enode://<id>@...`. On
a pulse-reth peer, pass `--trusted-peers=enode://<id>@<lite node IP>:30303`. pulse-reth matches a
trusted peer by its id and keeps it past the inbound limit.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--chain` | `369` | `369` or `943` |
| `--datadir` | `reth-lite-data` | node key and the on-disk store; with `--head.verify=sync-committee` also `sync-committee.ssz`, the light-client store |
| `--http.addr` / `--http.port` | `127.0.0.1` / `8545` | JSON-RPC; the address must be loopback or the node exits non-zero |
| `--metrics.addr` | `127.0.0.1:9001` | `IP:port` for Prometheus text, answered to a `GET` on any path; a host name is refused. The listener decides the `Host` check for each connection, by the address that the connection reached. A connection to a loopback address has the RPC's `Host` check (HTTP 403), also when the listener binds `0.0.0.0` or `[::]`. A connection to any other address takes any `Host`, so a scraper can use the node's DNS name. It serves at most 16 connections at once, and it closes a connection that sends no request for 10 s or stays open for 30 s. The node warns at start when the address is not loopback: the metrics show the head, the peers and the request counts, so put a firewall in front of a public address |
| `--beacon.url` | none | beacon base URL, repeatable. The whole URL is a secret: logs show only the scheme and the host. For a domain name with more than two labels they show only the last two, as `https://*.example.com`; an IP address or `localhost` shows in full. A key goes in the path or the query; every request keeps both. A URL with a fragment is refused, because no request carries it |
| `--beacon.url-file` | none | file with one beacon base URL per line, read in order; blank lines and `#` lines are skipped. Keeps a key out of the command line; use mode `600`. Exclusive with `--beacon.url` |
| `--beacon.quorum` | `1` | beacons that must agree on a head. Only a majority of the URLs tolerates a hostile minority; a smaller quorum lets that many sources set the head alone, and the node warns at start. With `--head.verify=quorum` and `--head.confirm=none`, a quorum of `1` leaves the first block unconfirmed: see `--head.confirm`. With `--head.verify=sync-committee` the node refuses a value above `1`: the committee's signature decides the head, so a quorum adds no check |
| `--beacon.poll` | `10s` | poll interval when there is no event stream; at least `1s` |
| `--finalized.url` | `https://checkpoint.pulsechain.com` on 369; none on 943 | finalized anchor source; on 943 the node refuses to start without it (or `--finalized.url-file`) |
| `--finalized.url-file` | none | file holding the one finalized anchor URL; blank lines and `#` lines are skipped. Exclusive with `--finalized.url` |
| `--finalized.recheck` | `10m` | maximum time between anchor checks; at least `30s` |
| `--state.on-miss` | `fetch` | `error`, `error-and-warm` or `fetch` |
| `--state.hot-set` | `0` | re-fetch the N most read accounts and slots after each head, at most 65536, hottest first; a new head ends the pass, so a set larger than one block can fetch refreshes only its leaders |
| `--cache.size` | 25% of memory, `64MB` to `1GB` | in-memory verified cache. The memory found is the process's cgroup memory limit (on cgroup v2 the lower of `memory.max` and `memory.high`, systemd's `MemoryMax=` and `MemoryHigh=`), or physical RAM when no limit is set or the limit is above it; when neither can be read, the default is `1GB`. The fixed budgets are twice the held-body budget (see Notes), 32 MiB of receipts and 256 MiB for the runtime, the network and the EVM. The node counts the cache at its heap bound, 1.2 times the size. A size given here wins, but the node refuses to start when that bound plus the fixed budgets is more than the memory found. The default is cut to fit, so it can be below `64MB`; when the fixed budgets alone do not fit, the default is `0` and the node logs a warning, and only `0` is taken here. The limit counts each value plus 384 bytes of bookkeeping per entry, and the cache's heap stays within about 1.2 times this value, so a `1GB` cache takes at most about 1.2 GiB. `0` turns the memory cache off: every read goes to disk |
| `--disk.limit` | `3GB` | disk limit for the state store (`<datadir>/store`); at least `16MB`. A bare number is bytes |
| `--peer` | none | static `snap/1` peer enode, repeatable; always kept and tried before discovered peers. The peer must serve `snap/1` (pulse-reth needs `--pulsechain.snap1`). The node keeps a static peer that does not, and logs a warning when it does not answer the probe (see Notes). The host must be an IP address: a host name is refused. `--head.confirm=peer`, the default with `--head.verify=quorum`, needs at least one |
| `--discovery` | `on` without `--peer`, `off` with `--peer` | `on` or `off`: discv4 and DNS discovery from the PulseChain boot nodes |
| `--max-peers` | `8` | most discovered peers kept connected. Each static `--peer` has a slot of its own on top; while one is not connected, a discovered peer can take its slot |
| `--head.confirm` | `peer` with `--head.verify=quorum`, `none` with `--head.verify=sync-committee` | `peer`: a static `--peer` must report a new head's hash before the node follows it, so `peer` needs a `--peer`, in either mode; `none`: the beacon quorum alone decides the head, or with `--head.verify=sync-committee` the committee's signature. With `none`, two starts have nothing but the anchor to confirm the first block, and the node seeds from the anchor alone: `--beacon.quorum 1` in quorum mode, and in sync-committee mode a bootstrap at the anchor's root (no pin, no `--checkpoint` and no saved store). It still starts, but it logs `UNCONFIRMED START` at warn level, logs `UNCONFIRMED SEED` with the block hash when it seeds, and sets `lite_unconfirmed_start` to 1. See the trust model |
| `--head.verify` | `quorum` | `quorum`: `--beacon.quorum` sources choose the head; `sync-committee`: opt-in light-client verification (see `SYNC-COMMITTEE-DESIGN.md`). It needs a source with lighthouse-pulse `--light-client-server` and refuses to start without one. A head is then a block whose header the sync committee signed, and a verified finality update moves finality. The node keeps its light-client store in `<datadir>/sync-committee.ssz`. It writes the file atomically on a committee change or a finality move, at most once every 10 minutes. A restart uses the file when it is for this chain and its finalized header is at most 30 days old, the checkpoint's limit: the node then catches up with `light_client/updates` and does not bootstrap again. A damaged, stale or wrong-chain file is ignored with a warning, and the node bootstraps. After the seed an anchor that disagrees with the verified chain is logged and counted, and does not halt serving |
| `--checkpoint` | the root pinned for 369 (slot 11169568); none on 943 | trusted finalized beacon block root (`0x` hex) that the first `--head.verify=sync-committee` bootstrap proves the first committee from. It wins over the pin, and a usable `sync-committee.ssz` wins over both. The node refuses a root or a pin whose block is more than 30 days old; the error says how to get a fresh one. Without a pin or this flag (943 today) the anchor's finalized root decides the first committee, and the node warns. With `--head.confirm=none` too, that is an unconfirmed start: see the trust model. Refused without `--head.verify=sync-committee` |
| `--head.max-age` | `60s` | latest and state reads answer `-32000` `head is stale` when the head is older than this, or has not moved for this long; at least `20s`, and the node warns when it is not above one slot (`10s`) plus `--beacon.poll`, or two slots with `--head.verify=sync-committee` |
| `--rpc.evmtimeout` | `5s` | EVM time limit of one `eth_call` or `eth_estimateGas`; `0` sets no limit. The text and the default are as geth's `--rpc.evmtimeout` for `eth_call`. The limit on `eth_estimateGas` is reth-lite's: geth bounds an estimate by the gas cap only. It covers the EVM time of one run over the state held, not the state fetches between runs, and for `eth_estimateGas` the whole search |

Sizes take the forms of pulse-reth's size flags, because reth-lite uses the same parser. Durations take the forms of pulse-reth's humantime flags, such as `--engine.state-root-task-timeout`:

* A size is a whole number with an optional unit `B KB MB GB TB`, in any case, with or without a space: `512MB`, `16 MB`, `3gb`. The units are binary, so `1GB` is 2^30 bytes. No unit means bytes. Fractions and `KiB MiB GiB` are refused, and so is a size above 2^64 - 1 bytes (2^32 - 1 on a 32-bit host).
* A duration is a [humantime](https://docs.rs/humantime) duration: `250ms`, `10s`, `90sec`, `10m`, `2min`, `1h 30m`, `1d`. A number other than `0` needs a unit, and units are case-sensitive: `m` is minutes, `M` months. Each duration flag takes at most `24h`. Some pulse-reth duration flags read a bare number as seconds, for example `--txpool.lifetime 10800`; reth-lite refuses it, so write `10800s` or `3h`.

## Methods, errors and metrics

* Served: `eth_blockNumber eth_chainId net_version eth_syncing eth_getBalance
  eth_getTransactionCount eth_getCode eth_getStorageAt eth_call eth_estimateGas
  eth_getBlockByNumber eth_getBlockByHash eth_getBlockTransactionCountBy{Number,Hash}
  eth_getUncleCountByBlock{Hash,Number} eth_getTransactionByHash
  eth_getTransactionByBlock{Hash,Number}AndIndex eth_getTransactionReceipt
  eth_getBlockReceipts eth_gasPrice eth_maxPriorityFeePerGas eth_feeHistory
  eth_getLogs eth_sendRawTransaction web3_clientVersion web3_sha3 net_listening
  net_peerCount eth_accounts eth_mining eth_hashrate`. Everything else is `-32601`
  `method not served`.
* Transactions: the node keeps no pool. `eth_sendRawTransaction` decodes the transaction and
  recovers its sender. It makes the checks geth's pool makes before it takes a transaction:
  the gas limit is at most the head's, the tip at most the fee cap, the gas limit at least the
  intrinsic gas, and a creation's init code at most 49,152 bytes. As geth, it takes a fee cap
  below the base fee. It reads the sender's account at the head, verified as any state read,
  and refuses a nonce below the account's or a cost above its balance. A later nonce is sent:
  a peer's pool keeps it until the gap fills. Then the node sends the transaction once, in an
  eth/68 `Transactions` message, to at most 8 connected peers, the `--peer` nodes first, and
  answers its hash. A transaction sent in the last 5 minutes (at most 4096 of them) answers its
  hash and is not sent again. Nothing confirms that a peer took it: ask a node with a pool for its state.
  When the sender's account cannot be read, the node sends nothing and answers the read's
  error: the miss in `error` and `error-and-warm` (which fetches the account for a retry),
  or `state unavailable` in `fetch`.
* Fee history: `eth_feeHistory` with `rewardPercentiles` reads each block's receipts through
  the receipt path above, so the rewards come from receipts checked against the block's
  receipts root. A reward is geth's: the effective tips of the block's transactions, lowest
  first, each weighted by the gas it used, read at each percentile of the block's gas used. A
  block without transactions rewards `0x0` and needs no receipts. As for `eth_getLogs`, a set
  the request fetches is kept in the wide receipt cache. With percentiles the history covers at
  most the newest 32 blocks, the sets the wide cache keeps, so a repeat reads them; as geth
  truncates a long history, `oldestBlock` then says where it starts. In `error` and
  `error-and-warm`, each block with transactions whose receipts are not held counts in the
  miss.
* Node answers: `web3_clientVersion` is `reth-lite/v` and the version that `--version`
  prints. `net_peerCount` is the number of connected eth peers. `net_listening` is `true`.
  The node holds no keys and does not mine, so `eth_accounts` is `[]`, `eth_mining` is
  `false` and `eth_hashrate` is `0x0`. These, `eth_chainId`, `net_version` and `web3_sha3`
  read no block, so they answer before the first head and while the node is halted.
* Logs: `eth_getLogs` takes geth's filter: `blockHash`, or `fromBlock` and `toBlock` (both
  `latest` by default), `address` (one or a list) and `topics` (each position null, one topic
  or a list; a null in a list matches anything). It reads held blocks only. A block whose
  header bloom cannot hold a match is skipped. The receipts of the others come through the
  receipt path above, so every log is checked against its block's receipts root, and in
  `error` and `error-and-warm` a block whose receipts are not held counts in the miss. A
  range that starts above the head is `[]`, and one that ends above it ends at the head. A
  `fromBlock` below the lowest held block answers the pruned-history error below. One request
  reads the receipts the node holds, and fetches those of at most 32 other blocks with
  transactions whose bloom matches. It keeps a set it fetched in the wide receipt cache, where it
  pushes out only other wide sets, never the sets single reads use. Concurrent reads of one block,
  of any kind, share one fetch, which keeps its set as a narrow read does when one joins. At
  most 16 wide reads of a block wait on fetches at once across all requests. A fetch runs only
  while a read waits on it. An answer of more than 256 logs or
  64 KiB of log data is rendered under a render permit, as a large receipt is.
* Uncle counts: PulseChain blocks have no uncles, so a held block answers `0x0`. A block not
  held is `null`, as geth answers it.
* Miss: `-32046` `state not verified locally`, `data: {"missing": N}`, in `error` and
  `error-and-warm` for state not held, and for the receipts of a held block whose receipts are
  not held. Reverts are normal answers. Blocks above the head and unknown block hashes, with
  their counts and receipts, and unknown transactions are `null`, as reth.
* Pruned history: a block number below the lowest held block answers reth's `4444`
  `pruned history unavailable: requested N, earliest available M`. `M` is the lowest held
  block. State reads answer the same for a block more than 120 blocks below the head, by number
  or by hash, and `M` is then the lowest block whose state the node serves.
* Block tags: `pending` is `latest`. The node has no transaction pool, so a pending nonce or
  balance is the confirmed one; ask the node that holds your pending transactions. As reth,
  `earliest` is the earliest available block: the lowest held block, not genesis.
* Fee estimates: `eth_maxPriorityFeePerGas` is reth's oracle over the last 20 blocks, the 60th
  percentile of each block's three lowest tips. It skips tips under 2 wei and the transactions
  of the block's producer, never answers below the chain's minimum tip (0.001 gwei on 943), and
  never above 500 gwei, as reth caps it. `eth_gasPrice` adds the head's base fee. The node
  computes the tip once per head.
* Batches: at most 1000 requests, as geth. A larger batch gets an array of one `-32600`
  `batch too large` error with the id of its first call, as geth answers it.
* Responses: when a batch's answers pass 25,000,000 bytes, as geth, each later answer gets
  `-32003` `response too large`. A single answer over 64 MiB gets the same error, and so
  does an `eth_getLogs` whose logs hold more than 24 MiB of data and topics. Do not send it
  again unchanged: ask for less.
* Requests: a body over 5 MiB gets HTTP 413, as geth. Each body is charged its bytes and its
  parsed form to a shared 48 MiB body budget. One body may hold at most 12 MiB of it, so one
  request cannot hold the whole budget; a body charged more gets HTTP 413 `body too large`. A
  body of 5 MiB of hex data fits.
* Busy: when large responses in flight fill the 64 MiB shared response budget, an answer gets
  `-32005` `server busy: too many large responses in flight`. When large request bodies fill the
  body budget, a body that finds no room for its parsed form within 1 s gets `-32005`
  `server busy: too many large requests in flight`. When 256 receipt fetches run, or a wide
  receipt read (`eth_getLogs`, `eth_feeHistory` rewards) finds none of its 16 permits free
  within 1 s, the read gets `-32005` `server busy: too many receipt fetches in flight`. Send
  any of them again later.
* Log limits: an `eth_getLogs` that matches more than 10,000 logs gets `-32005` `query
  returned more than 10000 results`, as Infura answers it. One whose filter's bloom matches
  more than 32 blocks with transactions whose receipts the node does not hold gets `-32005`
  `query needs the receipts of more than 32 blocks the node does not hold: narrow the block
  range or the filter`. Ask for a smaller range.
* Timeout: a request still unanswered after 60 s gets `-32002` `request timed out`, as geth. So
  does a large request body that sends nothing for 10 s or arrives slower than 256 KiB/s. A
  batch keeps the answers it finished before then.
* Readiness: a `GET` or `HEAD` of `/ready` on the RPC address answers HTTP 200 when the node
  is ready and 503 when it is not, with `{"ready": <bool>, "checks": [...]}`. Each check has
  an `id`, a `label`, `ok` and a `detail` that says why it fails. The checks are `consensus`
  (the node follows heads and is not halted), `head` (the head is fresh, by the stale-head
  rule of `--head.max-age`), `peers` (a connected peer serves `snap/1`) and `state` (the
  node's own state probe verified a read at most 6 blocks below the head). After each new
  head the node reads the account of the head's beneficiary at the head, fetching what it
  misses in every `--state.on-miss` mode, within 20 s. A client's read never counts, so an
  odd key or block cannot take the node out of a load balancer. Any other `GET` is the empty
  health check below.
* Host check: a request whose `Host` header is not `localhost` or an IP literal gets HTTP 403
  `invalid host specified`, as geth's default `--http.vhosts`. The check stops DNS rebinding, and
  no flag turns it off. A reverse proxy must send a local `Host`. nginx `proxy_pass` does this by
  default. In Caddy, write:

  ```caddyfile
  reverse_proxy 127.0.0.1:8545 {
      header_up Host {upstream_hostport}
  }
  ```
* With `--head.verify=quorum` a finalized-anchor mismatch halts the node (`-32000`
  `not serving: finalized anchor mismatch`). When the head-confirm peer or a beacon quorum
  confirms the anchor block, the node re-seeds from it at once (see the trust model). Otherwise it
  stays halted until a later check agrees or an operator restarts it. With
  `--head.verify=sync-committee` a mismatch does not halt the node: see the trust model.
* With no confirmation source, a head below the finalized anchor halts the node (`-32000`
  `not serving: the head is behind the finalized anchor`, and `lite_anchor_ahead` is 1): nothing
  checks the head against the anchor. The node keeps following heads. It serves again when a
  later check agrees at or above the anchor's number. A head more than 512 blocks below cannot
  walk there, so only a restart clears it, and the node logs an error that says so.
* Other `-32000` refusals:
  * `no head yet: waiting for the consensus client`: no head has been followed since start.
  * `head is stale`: see `--head.max-age`.
  * `not serving state: the head is too far past the finalized block (finality stalled)`: the
    head ran more than 2048 blocks past the finalized block.
  * `finalized block not confirmed yet`: for the `safe` and `finalized` tags, until a beacon
    quorum confirms the finalized block at depth.
  * `not serving: the chain was re-seeded during the request`: the request ran across a re-seed;
    send it again.
  * `not available in lite node: outside the recent block window`: a state read or
    `eth_feeHistory` names a block above the head or a hash the node does not hold, or an
    `eth_getLogs` names a `blockHash` the node does not hold.
  * `invalid block range`: an `eth_getLogs` with a numbered `fromBlock` above its numbered
    `toBlock`, as geth answers it.
  * `exceed max topics` and `exceed max addresses or topics per search position`: an
    `eth_getLogs` filter with more than 4 topic positions, or more than 1000 addresses or
    alternatives at one position, as geth answers them.
  * `not available in lite node: BLOCKHASH of a block outside the held headers`: an `eth_call`
    or `eth_estimateGas` read `BLOCKHASH` of a block below the held headers.
  * `block is not canonical`: a block given by hash with EIP-1898 `requireCanonical: true` is
    held but not on the followed chain.
  * `invalid transaction: <reason>`: the raw transaction does not decode.
  * `transaction type not supported`: a blob (EIP-4844) or set-code (EIP-7702) transaction,
    which the chain does not schedule, as geth answers it.
  * `only replay-protected (EIP-155) transactions allowed over RPC`: a transaction that names
    no chain, as geth answers it by default.
  * `invalid chain id for signer: have N, want M`: a transaction signed for another chain.
  * `oversized data: transaction size N, limit 131072`: a transaction over geth's 128 KiB
    limit.
  * `nonce too low: address A, tx: N state: M` and `insufficient funds for gas * price + value:
    balance B, tx cost C, overshot O`: geth's texts, checked against the head's verified state.
    The cost is the gas limit times the fee cap (the gas price of a legacy transaction), plus
    the value.
  * `exceeds block gas limit`, `max priority fee per gas higher than max fee per gas`,
    `intrinsic gas too low: gas N, needed M` and `max initcode size exceeded: code size N,
    limit 49152`: geth's pool checks.
  * `no peers to send the transaction to`: no eth peer is connected. Send it again later.
  * `invalid reward percentile: <reason>`: an `eth_feeHistory` with more than 100 reward
    percentiles, one outside 0 to 100, or one not above the one before it, as geth answers it.
  * `transaction sender could not be recovered from its signature`: a held transaction has a
    signature that does not recover. The node never answers the zero address instead.
  * `state unavailable: <reason>`: in `fetch` mode, no peer served the state, or every answer
    failed verification. Send the request again later.
  * `receipts unavailable: <reason>`: no peer served the block's receipts, or every answer failed
    verification. Send the request again later.
  * `receipts do not match the block`: the held receipts and the block's transactions differ in
    count.
  * `round N missed the same state after it was fetched` and
    `state discovery did not converge after N rounds`: in `fetch` mode, the fetched state did not
    complete the read. Send the request again.
  * `execution aborted (timeout = 5s)`: an `eth_call` ran past `--rpc.evmtimeout`, as geth
    answers it, or an `eth_estimateGas` did (geth sets no such limit on an estimate). The text
    names the limit set, in Go's form (`500ms`, `1m30s`). The node stops the run at once, so the
    run holds no EVM thread past the limit. It also stops a run whose request has gone, for example at the 60 s request
    timeout.
  * `execution aborted` and `rendering failed: <reason>`: the node stopped the work before it
    finished, for example at shutdown.
  * An `eth_call` or `eth_estimateGas` that halts or that the EVM refuses answers the EVM's text.
* Metrics: `lite_requests_total{method,outcome}`, `lite_answers_total{verified}`,
  `lite_cache_bytes`, `lite_disk_bytes`, `lite_disk_limit_bytes`, `lite_head_lag_seconds`,
  `lite_head_number`, `lite_peers{kind=static|discovered}`, `lite_proof_failures_total{source}`,
  `lite_anchor_mismatch`, `lite_anchor_ahead`, `lite_anchor_unreachable_total`, `lite_warm_queue`,
  `lite_beacon_optimistic_total{source}`, `lite_head_verify{mode}`, `lite_unconfirmed_start` (1
  when nothing but the anchor confirms the block the node starts from: alert on it), and with
  `--head.verify=sync-committee` `lite_sync_committee_period`, `lite_sync_participation` and
  `lite_anchor_disagreements_total` (anchor checks that disagreed with the verified chain). A
  beacon block marked `execution_optimistic` is refused
  but counts as unavailable, not as a proof failure. `lite_answers_total{verified="true"}` counts
  answers checked against a block's roots; `verified="false"` counts `eth_blockNumber`,
  `eth_syncing`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` and the hash
  that `eth_sendRawTransaction` answers, which no root checks. The node answers above count in neither series.

## Trust model

The node verifies state, code, bodies and receipts against a block's roots. It cannot verify the
block itself: it learns the head from the beacon URLs. Here is what each source can and cannot do.

* **Beacon URLs** choose the head. The rebuilt block hash proves only that a payload is
  self-consistent. So `--beacon.quorum` sources that agree can forge the header fields of a
  block that carries the real state root: timestamp, base fee, prevrandao and transactions. A
  quorum of `1` means any one URL can do this. Only a quorum above half the URLs tolerates a
  hostile minority.
* **A static `--peer`** is a second check on the head. With `--head.confirm=peer` (the default
  with `--head.verify=quorum`) the node follows a new head only when a static peer reports the same block hash. A forged head
  then needs the beacon quorum and that peer to agree. Choose a peer you run or trust.
* **`--head.confirm=none`** drops that check: the beacon quorum alone decides the head. The start
  error for a missing `--peer` suggests this flag; use it only when you trust the beacons. With
  `--beacon.quorum 1` it also drops the check on the first seed: see the anchor below.
* **The finalized anchor** (`--finalized.url`) is checked at start, when finality moves and at
  least every `--finalized.recheck`. With `--head.verify=quorum` a held block that disagrees with
  it halts serving. After the first seed the anchor's word alone never changes the held chain. The
  node re-seeds from the anchor block only
  when the head-confirm peer (`--head.confirm=peer`) or a beacon quorum (`--beacon.quorum` of 2
  or more) confirms that block, the block is less than one hour old, and it is not below the held
  finalized block. A re-seed drops every held block above the anchor, so `lite_head_number` falls
  to the anchor's number, and it clears the halt. The node also re-seeds forward under the same
  conditions when the anchor block is above the held head. With no confirmation source, a head
  below the anchor halts serving. The node keeps following heads, and serves again once the
  anchor agrees at or above its number. The first seed at start needs the same confirmation when
  a confirmation source exists.
* **An unconfirmed start.** Two configurations have no confirmation source at start, both with
  `--head.confirm=none`:
  * `--head.verify=quorum` with `--beacon.quorum 1`.
  * `--head.verify=sync-committee` when the first store is a bootstrap at the anchor's finalized
    root: the chain has no pinned checkpoint (943 today), no `--checkpoint` is given, and the
    data directory holds no usable `sync-committee.ssz`. `--beacon.quorum` confirms nothing in
    this mode.

  The node still starts, but it seeds from the anchor block alone, when that block is less than
  one hour old. A wrong or hostile anchor then chooses the block the node starts from, and in
  sync-committee mode also the first committee. Every verified answer rests on that choice. The
  node makes this loud:
  * At start it logs `UNCONFIRMED START` at warn level, with the flags that remove the risk.
  * When it seeds it logs `UNCONFIRMED SEED` at warn level, with the block number and hash, and
    `trusting the anchor alone`. Check that hash against a source you trust.
  * `lite_unconfirmed_start` reads 1 for the life of the process, and 0 in every other
    configuration. Alert on it.

  In quorum mode, do one of these to remove the risk: give a second `--beacon.url` and
  `--beacon.quorum 2` or more; use `--head.confirm=peer` with a `--peer`; or use
  `--head.verify=sync-committee` on a chain with a pinned checkpoint or with `--checkpoint`. In
  sync-committee mode, give `--checkpoint` with a root you trust. `--head.confirm=peer` with a
  `--peer` also clears the warning: the peer confirms the first block and each head, but not the
  committee.
* **`--head.verify=sync-committee`** replaces the beacon quorum for heads and finality. The node
  checks the sync committee's BLS signature over each head (at least 2/3 of the 512 members) and
  proves the execution block hash into the signed beacon header. One hostile beacon URL can then
  delay the head, but it cannot forge one. The trust root is the first committee. On the first
  start it comes from a light-client bootstrap at a trusted checkpoint root: `--checkpoint`, or
  else the root pinned for the chain in the binary (369 has one; see "Refreshing the checkpoint
  pin"). The bootstrap at a pin ships in the binary, so no source must serve it. A
  `--checkpoint` root needs a beacon source that serves `light_client/bootstrap` at that root.
  lighthouse-pulse builds a bootstrap from the block's state, and a node without
  `--reconstruct-historic-states` deletes that state about one epoch after the block is
  finalized. So give a root that is the source's current finalized root. The node then catches
  up with signed `light_client/updates` and seeds at the latest
  finalized block they prove; it does not ask the anchor for a root, a bootstrap or a seed. The
  node refuses a checkpoint whose block is more than 30 days old. A chain with no pin and no
  `--checkpoint` (943 today) bootstraps at the anchor's finalized block root, and the node warns
  that the anchor's root alone then decides the first committee. The seed checks compare only
  the execution block under that root, not the beacon state that holds the committee. So the
  peer confirmation of the seed does not cover the committee, and `--head.confirm=peer` protects
  heads only. Choose an anchor you trust for that first start. Later committees follow from
  signed rotations. A restart with a usable `<datadir>/sync-committee.ssz` resumes from the
  saved store, and the file wins over the checkpoint. Delete the file to bootstrap again. After the seed, verified finality
  always wins over the anchor. An anchor that disagrees with the verified chain does not halt
  serving: the node logs a warning once per disagreement, with the anchor's host label, counts
  each such check in `lite_anchor_disagreements_total`, and keeps serving. It re-seeds from the
  anchor block only when the head-confirm peer or a finalized block that the committee signed
  confirms it, and never below a block the committee finalized. In this mode the node refuses
  `--beacon.quorum` above `1`, and the beacons confirm no anchor block. Extra beacon URLs give
  liveness: the node uses the first update that verifies. In this mode `--head.confirm` defaults to `none`, so no `--peer` is needed. The
  committee members are not slashed for signing a wrong header, so an explicit
  `--head.confirm=peer` keeps its value as an extra check.
* **Discovered and static peers** that serve state cannot make the node give a wrong answer: every
  piece is checked against the head's state root. A peer whose data fails verification is dropped
  and ignored for 30 minutes.

## Refreshing the checkpoint pin

Each release refreshes the checkpoint pins in `crates/pulsechain/hardforks/src/network.rs`. The
node refuses a pin more than 30 days old, so a release with an old pin cannot start a new
`--head.verify=sync-committee` node without `--checkpoint`. A node whose store file is for this
chain and at most 30 days old resumes from the file and is not affected. A node with an older or
damaged file bootstraps at the pin, as a new node does.

1. Run `crates/pulsechain/lite/scripts/checkpoint-root.sh -o
   crates/pulsechain/light-client/checkpoints/<chain>.json <beacon-url> <check-url>` for each chain with
   two independent sources. `<beacon-url>` must serve the finalized state (Checkpointz does).
   `<check-url>` must serve `/eth/v1/beacon/headers/{root}` (a beacon node does; for 369
   `https://rpc-pulsechain.g4mm4.io/beacon-api` does). Each `-` reads one URL from a line of stdin,
   which keeps a key out of `ps`. The script never prints a URL. It reads the finalized root, its
   block and the finalized state (about 19 MB of SSZ). It hashes the state, the block body and the
   header, and checks that they give the block's state root, the state's body root and the
   finalized root. It then checks that the second source has the same genesis and calls the root
   finalized and canonical, with the same header. A pin is the trust root of every new node, so
   with `-o` the second source is required. Then it writes the bootstrap at the root and prints
   the table entry and the header fields. Needs `curl`, `jq` and `python3`.
2. Replace the chain's `checkpoint` entry and its comment, with the date and both sources. A new chain's bootstrap
   file also goes into `SHIPPED_BOOTSTRAPS` in `src/light_client.rs`.
3. For 369, replace the header fields in the `the_369_checkpoint_is_the_root_of_its_header` test
   and the slot in the `--checkpoint` row of the flags table above.
4. Run `cargo test -p reth-pulsechain-forks -p reth-pulsechain-lite`.

An operator can do step 1 too, and pass the root as `--checkpoint`. A source must then serve
`light_client/bootstrap` at that root when the node starts, so start the node within a few
minutes, while the root is still the source's finalized root.

## Notes

* With `--head.verify=quorum` the default `--head.confirm=peer` refuses to start without a
  `--peer`; with `--head.verify=sync-committee` the default is `none`. Without `--peer` (and
  with `--head.confirm=none`) discovery is on and the node finds its own state peers. A
  discovered peer is kept only if it negotiated eth/68, advertises snap/1 and has this chain's
  genesis and a matching fork id. With `--peer` discovery is off unless `--discovery=on`, and only
  the listed peers are used.
* Many PulseChain peers advertise snap/1 and never answer a snap/1 request. So the node's first
  request to a new peer is a probe: `GetByteCodes` for a hash that no account has. An honest
  server answers it at once with an empty list. A discovered peer that answers neither the probe
  nor any other request within 3 s loses its session, and discovery fills its slot. A static
  `--peer` is kept, and the node logs a warning that names it.
* With `--beacon.quorum` above 1, every beacon URL must be on its own host. The check treats
  every loopback name and address as one host and ignores a trailing dot, but it cannot see two
  DNS names for one provider.
* With `--discovery=off` and no `--peer` the node cannot fetch state: reads outside held state miss.
* Receipts come from a peer (eth/68 `GetReceipts`) and are checked against the header's receipts
  root; they are fetched in `fetch` mode and are a miss in the other modes. The node keeps the
  receipts of at most 64 blocks and 32 MiB, in RAM outside `--cache.size`, in two halves: 32
  blocks and 16 MiB for single reads (a receipt, a block's receipts), and 32 blocks and 16 MiB
  for wide reads (`eth_getLogs`, `eth_feeHistory` rewards). A wide read pushes out only wide
  sets.
* The node keeps each RPC answer as its JSON text from the moment it computes it until the client
  has read it. So the 64 MiB response budget bounds the memory that answers hold. A render of a
  full block, of block receipts or of a receipt with more than 256 logs also holds the typed
  answer and its parsed form until it ends. The parsed form of a block of small logs is about
  2.5 times its text. At most two renders run at once.
* With `--state.hot-set=N` the node counts the reads of up to 8N accounts and slots in RAM
  outside `--cache.size`: up to about 70 MB at the maximum, `65536`.
* The node keeps the bodies of held blocks in RAM outside `--cache.size`: 10% of memory, at least
  32 MiB and at most 256 MiB (256 MiB when memory is not found), by the node's estimate of their
  size, and up to as much again while the node walks to a new head. Past that, the oldest blocks
  lose their bodies: they still count for the chain, but they are not served. The head and the
  finalized block always keep theirs.
* At start the node logs the memory it found, where it found it, the cache size and the body
  budget. A `--cache.size` that does not fit stops the start with an error that names the size,
  what the node needs and the memory found, for example: `--cache.size=1GB (a heap of up to
  1229MB) and the node's fixed budgets need 1722MB, but the box has 1024MB (cgroup memory limit)`.
