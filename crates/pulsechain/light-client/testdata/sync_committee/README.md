# Sync-committee test fixtures

These files come from [consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests)
release **v1.4.0**, `mainnet.tar.gz`, directory `tests/mainnet/capella`. The PulseChain preset has
the same light-client values as mainnet (`SYNC_COMMITTEE_SIZE` 512, `SLOTS_PER_EPOCH` 32,
`EPOCHS_PER_SYNC_COMMITTEE_PERIOD` 256) and the same execution payload limits, so the mainnet
vectors apply to it.

`derive.py` made them. It needs Python 3.9 with `remerkleable` 0.1.24 and `python-snappy`:

```sh
python -I derive.py <dir that holds tests/mainnet/capella> <out dir>
```

| File | From |
|---|---|
| `ssz_static_<Type>_case_<n>.ssz` | `ssz_static/<Type>/ssz_random/case_<n>/serialized.ssz_snappy`, decompressed. The root is in `capella.json` under `ssz_static_roots`, copied from `roots.yaml`. |
| `single_merkle_proof_execution_payload_header.ssz` | The `ExecutionPayloadHeader` of the `execution_payload` in `light_client/single_merkle_proof/BeaconBlockBody/execution_merkle_proof/object.ssz_snappy`. |
| `single_merkle_proof_current_sync_committee.ssz` | `current_sync_committee` of the `BeaconState` in `light_client/single_merkle_proof/BeaconState/*/object.ssz_snappy`. That state has the same current and next committee. |
| `capella.json` | `single_merkle_proof`: each `proof.yaml` (`leaf`, `leaf_index`, `branch`) plus `root`, the root of the object the branch proves into. |

The spec tests give no object root, only the object. `derive.py` computes each `root` with its
own Capella SSZ definitions. It checks that each branch proves its `leaf` into that `root`, and
that each derived object hashes to the `leaf` that the spec gives.

## Sync vectors

The `sync_<fork>_<case>.json` files come from the same release, `minimal.tar.gz`, directory
`tests/minimal/<fork>/light_client/sync/pyspec_tests/<case>`. `derive_sync.py` made them. It needs
Python 3.9 with PyYAML only:

```sh
python -I derive_sync.py <dir that holds tests/minimal> <out dir>
```

Each file holds the case's `meta.yaml` values, the four fork versions and epochs from its
`config.yaml`, the bootstrap and each update as hex SSZ (snappy removed), and the steps. A fork that
`config.yaml` leaves out gets the minimal config's version at `FAR_FUTURE_EPOCH`. The node makes no
forced update, so the steps end at the first `force_update`; the checks after it assume one.

| Case | Forks | Updates |
|---|---|---|
| `altair` `light_client_sync`, `advance_finality_without_sync_committee` | Altair | 5 each |
| `altair` `supply_sync_committee_from_past_update`, `capella_store_with_legacy_data` | Altair | 1 each |
| `bellatrix` `capella_fork` | Bellatrix to Capella at epoch 3 | 7 |
| `capella` `light_client_sync`, `advance_finality_without_sync_committee` | Capella | 5 each |
| `capella` `supply_sync_committee_from_past_update` | Capella | 1 |

## Real PulseChain 369 block

The `real_369*` files come from `https://checkpoint.pulsechain.com` (Checkpointz v0.24.0) on
2026-11-23. They hold the finalized block at slot 11167808, root
`0x4df46dc6…6108`, and the current sync committee of its post-state. A script outside the repo
made them from three answers that agree on the finalized block:

* `/eth/v1/beacon/blocks/finalized/root`
* `/eth/v2/beacon/blocks/finalized` (JSON)
* `/eth/v2/debug/beacon/states/finalized` (SSZ, 18.8 MB, 114777 validators)

The script hashes the Capella `BeaconState` and `BeaconBlockBody` with the mainnet SSZ sizes, which
lighthouse-pulse's `PulseChainEthSpec` uses. It checks that the state hashes to the block's
`state_root`, that the state's `latest_block_header` hashes to the finalized root, and that the
body hashes to its `body_root`. Then it takes the branches out of the two trees. A public RPC gave
the same execution block hash for block 28133431.

| File | Holds |
|---|---|
| `real_369_current_sync_committee.ssz` | `state.current_sync_committee`, 24624 bytes. |
| `real_369_execution_payload_header.ssz` | The `ExecutionPayloadHeader` of the block's payload. |
| `real_369.json` | The block header and root, the block's `sync_aggregate` (495 of 512 signed), the committee root and its branch at gindex 54, and the execution header root and its branch at gindex 25. |
| `real_369_block.ssz` | The `SignedBeaconBlock` itself, 66305 bytes, from `/eth/v2/beacon/blocks/0x4df46dc6…6108` with `Accept: application/octet-stream`, fetched later the same day. Its JSON form says `capella` and holds 151 transactions and 16 withdrawals. The derive tests check that it hashes to the block root and gives the execution branch above. |

A block's `sync_aggregate` signs the root of its parent with the domain of the slot before the
block. Here that is Capella, `0x0000036c`.
