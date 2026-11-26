# SSZ merkleizer fixtures

These files come from [consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests)
release **v1.4.0**, `minimal.tar.gz` and `mainnet.tar.gz`, directories `tests/<preset>/capella`.
`derive.py` made them. It needs Python 3.9 with PyYAML only; it has its own snappy decoder:

```sh
python -I derive.py <dir that holds tests/minimal and tests/mainnet> <out dir>
```

| File | From |
|---|---|
| `<preset>_<Type>_case_<n>.ssz` | `ssz_static/<Type>/ssz_random/case_<n>/serialized.ssz_snappy`, decompressed. The root is in `ssz.json` under `ssz_static`, copied from `roots.yaml`. |
| `<preset>_proof_BeaconBlockBody.ssz` | `light_client/single_merkle_proof/BeaconBlockBody/execution_merkle_proof/object.ssz_snappy`, decompressed. |
| `minimal_proof_BeaconState.ssz` | `light_client/single_merkle_proof/BeaconState/*/object.ssz_snappy`, decompressed. The three cases share one state. |
| `mainnet_proof_BeaconState.ssz_snappy` | The same, for mainnet, kept compressed: 173 KB here, 2.7 MB raw. |
| `ssz.json` | `ssz_static`: each file's root. `single_merkle_proof`: each `proof.yaml` (`leaf`, `leaf_index`, `branch`) with the file of its object. |

The cases are `minimal` `BeaconState`, `BeaconBlockBody`, `BeaconBlock` and `SignedBeaconBlock`
(2 each), and `mainnet` `BeaconBlockBody` and `SignedBeaconBlock` (1 each). The spec tests have no
mainnet `BeaconState` in `ssz_static`. The mainnet proof state covers that preset: the tests check
its root against the one `../sync_committee/derive.py` computed with remerkleable.

The PulseChain preset has the mainnet SSZ sizes, so the mainnet cases also test it.
