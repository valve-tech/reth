"""Copy the SSZ merkleizer fixtures out of consensus-spec-tests v1.4.0 (Capella).

Usage: python -I derive_ssz.py <spec-tests-root> <out-dir>

<spec-tests-root> holds tests/minimal and tests/mainnet. The script needs Python 3.9 with PyYAML
only: it has its own snappy decoder. It writes the objects and ssz.json, and copies the roots and
branches unchanged from roots.yaml and proof.yaml.
"""

import json
import os
import sys

import yaml

STATIC = [
    ("minimal", "BeaconState", 2),
    ("minimal", "BeaconBlockBody", 2),
    ("minimal", "BeaconBlock", 2),
    ("minimal", "SignedBeaconBlock", 2),
    ("mainnet", "BeaconBlockBody", 1),
    ("mainnet", "SignedBeaconBlock", 1),
]

PROOFS = {
    "BeaconBlockBody": ["execution_merkle_proof"],
    "BeaconState": [
        "current_sync_committee_merkle_proof",
        "next_sync_committee_merkle_proof",
        "finality_root_merkle_proof",
    ],
}

# The mainnet proof state is 2.7 MB; it is kept snappy-compressed, as the spec tests ship it.
COMPRESSED = {("mainnet", "BeaconState")}


def varint(data, i):
    value = shift = 0
    while True:
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, i


def unsnappy(data):
    """Decodes the raw (unframed) snappy format of `*.ssz_snappy`."""
    length, i = varint(data, 0)
    out = bytearray()
    while i < len(data):
        tag = data[i]
        i += 1
        kind = tag & 3
        if kind == 0:
            n = tag >> 2
            if n >= 60:
                width = n - 59
                n = int.from_bytes(data[i:i + width], "little")
                i += width
            n += 1
            out += data[i:i + n]
            i += n
            continue
        if kind == 1:
            n = ((tag >> 2) & 7) + 4
            offset = ((tag >> 5) << 8) | data[i]
            i += 1
        elif kind == 2:
            n = (tag >> 2) + 1
            offset = int.from_bytes(data[i:i + 2], "little")
            i += 2
        else:
            n = (tag >> 2) + 1
            offset = int.from_bytes(data[i:i + 4], "little")
            i += 4
        if offset == 0 or offset > len(out):
            raise ValueError("bad snappy offset")
        for _ in range(n):
            out.append(out[-offset])
    if len(out) != length:
        raise ValueError("bad snappy length")
    return bytes(out)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main(root, out):
    os.makedirs(out, exist_ok=True)
    manifest = {
        "source": "ethereum/consensus-spec-tests v1.4.0, tests/{minimal,mainnet}/capella",
        "ssz_static": {},
        "single_merkle_proof": {},
    }

    for preset, kind, cases in STATIC:
        for case in range(cases):
            src = f"{root}/tests/{preset}/capella/ssz_static/{kind}/ssz_random/case_{case}"
            name = f"{preset}_{kind}_case_{case}.ssz"
            write(f"{out}/{name}", unsnappy(read(f"{src}/serialized.ssz_snappy")))
            with open(f"{src}/roots.yaml") as f:
                manifest["ssz_static"][name] = yaml.safe_load(f)["root"]

    for preset in ("minimal", "mainnet"):
        for kind, cases in PROOFS.items():
            objects = set()
            for case in cases:
                src = f"{root}/tests/{preset}/capella/light_client/single_merkle_proof/{kind}/{case}"
                objects.add(read(f"{src}/object.ssz_snappy"))
                with open(f"{src}/proof.yaml") as f:
                    proof = yaml.safe_load(f)
                manifest["single_merkle_proof"][f"{preset}_{case}"] = {
                    "object": f"{preset}_proof_{kind}.ssz",
                    "leaf": proof["leaf"],
                    "leaf_index": proof["leaf_index"],
                    "branch": proof["branch"],
                }
            # Every case of one kind proves into the same object.
            assert len(objects) == 1, (preset, kind)
            data = objects.pop()
            name = f"{preset}_proof_{kind}.ssz"
            if (preset, kind) in COMPRESSED:
                unsnappy(data)
                name += "_snappy"
                for case in cases:
                    manifest["single_merkle_proof"][f"{preset}_{case}"]["object"] = name
                write(f"{out}/{name}", data)
            else:
                write(f"{out}/{name}", unsnappy(data))

    with open(f"{out}/ssz.json", "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
