"""Derive the light_client/sync fixtures from consensus-spec-tests v1.4.0 (minimal preset).

Usage: python -I derive_sync.py <spec-tests-root> <out-dir>

Each case becomes one JSON file: the meta values, the fork schedule from config.yaml, the
bootstrap and every update as hex SSZ, and the steps up to and including the first force_update.
The node makes no forced updates, so the steps after one do not apply to it.

It needs PyYAML only. It decompresses the raw snappy blocks itself.
"""

import json
import os
import sys

import yaml

CASES = [
    ("altair", "light_client_sync"),
    ("altair", "supply_sync_committee_from_past_update"),
    ("altair", "advance_finality_without_sync_committee"),
    ("altair", "capella_store_with_legacy_data"),
    ("bellatrix", "capella_fork"),
    ("capella", "light_client_sync"),
    ("capella", "supply_sync_committee_from_past_update"),
    ("capella", "advance_finality_without_sync_committee"),
]

FORKS = ["GENESIS", "ALTAIR", "BELLATRIX", "CAPELLA"]

# The minimal config's versions, for a fork that a case's config.yaml leaves out. Such a fork is
# not scheduled: its epoch is FAR_FUTURE_EPOCH.
MINIMAL_VERSIONS = {"BELLATRIX": 0x02000001, "CAPELLA": 0x03000001}
FAR_FUTURE_EPOCH = 2**64 - 1


def snappy_decompress(data):
    """Decompresses one raw (unframed) snappy block."""
    pos, length, shift = 0, 0, 0
    while True:
        byte = data[pos]
        pos += 1
        length |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            break
    out = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        kind = tag & 3
        if kind == 0:
            size = tag >> 2
            if size >= 60:
                extra = size - 59
                size = int.from_bytes(data[pos : pos + extra], "little")
                pos += extra
            size += 1
            out += data[pos : pos + size]
            pos += size
            continue
        if kind == 1:
            size = 4 + ((tag >> 2) & 7)
            offset = ((tag >> 5) << 8) | data[pos]
            pos += 1
        elif kind == 2:
            size = (tag >> 2) + 1
            offset = int.from_bytes(data[pos : pos + 2], "little")
            pos += 2
        else:
            size = (tag >> 2) + 1
            offset = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
        if offset == 0 or offset > len(out):
            raise ValueError("bad snappy copy offset")
        for _ in range(size):
            out.append(out[-offset])
    if len(out) != length:
        raise ValueError(f"snappy length {len(out)}, header says {length}")
    return bytes(out)


def read_ssz(path):
    with open(path, "rb") as f:
        return snappy_decompress(f.read())


def derive(root, fork, case):
    src = os.path.join(root, "tests", "minimal", fork, "light_client", "sync", "pyspec_tests", case)
    with open(os.path.join(src, "meta.yaml")) as f:
        meta = yaml.safe_load(f)
    with open(os.path.join(src, "config.yaml")) as f:
        config = yaml.safe_load(f)
    with open(os.path.join(src, "steps.yaml")) as f:
        steps = yaml.safe_load(f)
    if config["PRESET_BASE"] != "minimal":
        raise ValueError(f"{src}: preset {config['PRESET_BASE']}")

    forks = []
    for name in FORKS:
        version = config.get(f"{name}_FORK_VERSION", MINIMAL_VERSIONS.get(name))
        # YAML reads an unquoted 0x01000001 as an integer.
        version = version if isinstance(version, str) else f"0x{version:08x}"
        epoch = 0 if name == "GENESIS" else int(config.get(f"{name}_FORK_EPOCH", FAR_FUTURE_EPOCH))
        forks.append({"version": version, "epoch": epoch})

    out_steps = []
    for step in steps:
        (kind, body), = step.items()
        if kind == "process_update":
            update = read_ssz(os.path.join(src, body["update"] + ".ssz_snappy"))
            body = dict(body, update="0x" + update.hex())
        out_steps.append({kind: body})
        if kind == "force_update":
            break

    return {
        "source": f"consensus-spec-tests v1.4.0 tests/minimal/{fork}/light_client/sync/pyspec_tests/{case}",
        "genesis_validators_root": meta["genesis_validators_root"],
        "trusted_block_root": meta["trusted_block_root"],
        "bootstrap_fork_digest": meta["bootstrap_fork_digest"],
        "forks": forks,
        "bootstrap": "0x" + read_ssz(os.path.join(src, "bootstrap.ssz_snappy")).hex(),
        "steps": out_steps,
    }


def main():
    root, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    for fork, case in CASES:
        data = derive(root, fork, case)
        path = os.path.join(out, f"sync_{fork}_{case}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=1)
            f.write("\n")
        print(path, os.path.getsize(path), len(data["steps"]))


if __name__ == "__main__":
    main()
