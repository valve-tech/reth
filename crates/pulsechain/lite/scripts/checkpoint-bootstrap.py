"""Builds the light-client bootstrap of a finalized PulseChain block from its post-state.

Usage: python3 -I checkpoint-bootstrap.py <root> <block.json> <state.ssz> <out.json>

<block.json> is the answer of /eth/v2/beacon/blocks/{root}. <state.ssz> is the SSZ of the block's
post-state, not advanced to a later slot (/eth/v2/debug/beacon/states/finalized while the block is
the finalized one). The script hashes the Capella BeaconState and BeaconBlockBody with the mainnet
SSZ sizes, which lighthouse-pulse's PulseChainEthSpec uses. It writes nothing unless the state
hashes to the block's state_root, the body hashes to the state's latest_block_header.body_root,
the header hashes to <root>, and the state's execution payload header hashes to the body's
payload. It then writes the bootstrap as /eth/v1/beacon/light_client/bootstrap/{root} gives it,
with the current sync committee branch (gindex 54) and the execution branch (gindex 25).

Standard library only.
"""

import hashlib
import json
import sys

ZERO = bytes(32)


def sha(a, b):
    return hashlib.sha256(a + b).digest()


ZEROS = [ZERO]
for _ in range(64):
    ZEROS.append(sha(ZEROS[-1], ZEROS[-1]))


def depth_of(limit):
    return max(limit - 1, 0).bit_length()


def merkleize(chunks, limit=None):
    """The SSZ root of `chunks`, padded with zero chunks to the next power of two of `limit`."""
    limit = len(chunks) if limit is None else limit
    if len(chunks) > limit:
        raise ValueError("more chunks than the limit")
    layer = list(chunks)
    for d in range(depth_of(limit)):
        if len(layer) % 2:
            layer.append(ZEROS[d])
        layer = [sha(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0] if layer else ZEROS[depth_of(limit)]


def tree_and_branch(leaves, index):
    """The root of `leaves` (a power of two) and the branch of leaf `index`, bottom up."""
    branch, layer = [], list(leaves)
    while len(layer) > 1:
        branch.append(layer[index ^ 1])
        layer = [sha(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        index //= 2
    return layer[0], branch


def pack(data):
    if len(data) % 32:
        data = data + bytes(32 - len(data) % 32)
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def mix_in_length(root, length):
    return sha(root, length.to_bytes(32, "little"))


def u(b):
    return int.from_bytes(b, "little")


def hexb(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


# Types. A value is an int (Uint), bytes (ByteVector, ByteList, bitfields, and lists or vectors
# of a basic type, as their SSZ bytes) or a list (containers in field order, other sequences).
class Uint:
    def __init__(self, size):
        self.size = size

    def fixed(self):
        return self.size

    def decode(self, b):
        return u(b)

    def from_json(self, v):
        return int(v)

    def encode(self, v):
        return v.to_bytes(self.size, "little")

    def root(self, v):
        return self.encode(v) + bytes(32 - self.size)


class ByteVector:
    def __init__(self, size):
        self.size = size

    def fixed(self):
        return self.size

    def decode(self, b):
        return bytes(b)

    def from_json(self, v):
        b = hexb(v)
        if len(b) != self.size:
            raise ValueError("wrong byte length")
        return b

    def root(self, v):
        return merkleize(pack(v))


class Bitvector(ByteVector):
    def __init__(self, bits):
        super().__init__((bits + 7) // 8)
        self.bits = bits

    def root(self, v):
        return merkleize(pack(v), (self.bits + 255) // 256)


class ByteList:
    def __init__(self, limit):
        self.limit = limit

    def fixed(self):
        return None

    def decode(self, b):
        return bytes(b)

    def from_json(self, v):
        return hexb(v)

    def root(self, v):
        return mix_in_length(merkleize(pack(v), (self.limit + 31) // 32), len(v))


class Bitlist(ByteList):
    def root(self, v):
        last = v[-1]
        if last == 0:
            raise ValueError("a bitlist without its delimiter")
        bits = (len(v) - 1) * 8 + last.bit_length() - 1
        data = bytearray(v)
        data[-1] ^= 1 << (last.bit_length() - 1)
        while data and data[-1] == 0 and len(data) * 8 > bits:
            data.pop()
        return mix_in_length(merkleize(pack(bytes(data)), (self.limit + 255) // 256), bits)


class Container:
    def __init__(self, *fields):
        self.fields = fields

    def fixed(self):
        sizes = [t.fixed() for _, t in self.fields]
        return None if None in sizes else sum(sizes)

    def decode(self, b):
        return decode_parts(b, [t for _, t in self.fields])

    def from_json(self, v):
        return [t.from_json(v[name]) for name, t in self.fields]

    def roots(self, v):
        return [t.root(x) for (_, t), x in zip(self.fields, v)]

    def root(self, v):
        return merkleize(self.roots(v))


class Seq:
    """A Vector (`length`) or a List (`limit`)."""

    def __init__(self, elem, n, is_list):
        self.elem, self.n, self.is_list = elem, n, is_list

    def basic(self):
        return isinstance(self.elem, Uint)

    def fixed(self):
        if self.is_list:
            return None
        size = self.elem.fixed()
        return None if size is None else size * self.n

    def decode(self, b):
        if self.basic():
            return bytes(b)
        size = self.elem.fixed()
        if size is not None:
            items = [b[i:i + size] for i in range(0, len(b), size)]
        elif not b:
            items = []
        else:
            first = u(b[0:4])
            offsets = [u(b[i:i + 4]) for i in range(0, first, 4)] + [len(b)]
            items = [b[offsets[i]:offsets[i + 1]] for i in range(len(offsets) - 1)]
        if not self.is_list and len(items) != self.n:
            raise ValueError("wrong vector length")
        return [self.elem.decode(x) for x in items]

    def from_json(self, v):
        if self.basic():
            return b"".join(self.elem.encode(self.elem.from_json(x)) for x in v)
        return [self.elem.from_json(x) for x in v]

    def root(self, v):
        if self.basic():
            size = self.elem.size
            root = merkleize(pack(v), (self.n * size + 31) // 32)
            return mix_in_length(root, len(v) // size) if self.is_list else root
        root = merkleize([self.elem.root(x) for x in v], self.n)
        return mix_in_length(root, len(v)) if self.is_list else root


def Vector(elem, n):
    return Seq(elem, n, False)


def List(elem, n):
    return Seq(elem, n, True)


def decode_parts(b, types):
    """Splits the SSZ of a container into its fields' values."""
    out, pos, var = [], 0, []
    for t in types:
        size = t.fixed()
        if size is None:
            var.append((len(out), u(b[pos:pos + 4])))
            out.append(None)
            pos += 4
        else:
            out.append(b[pos:pos + size])
            pos += size
    ends = [o for _, o in var[1:]] + [len(b)]
    for (i, start), end in zip(var, ends):
        out[i] = b[start:end]
    return [t.decode(x) for t, x in zip(types, out)]


U8, U64, U256 = Uint(1), Uint(8), Uint(32)
B20, B32, B48, B96 = ByteVector(20), ByteVector(32), ByteVector(48), ByteVector(96)

Fork = Container(("previous_version", ByteVector(4)), ("current_version", ByteVector(4)),
                 ("epoch", U64))
Checkpoint = Container(("epoch", U64), ("root", B32))
BeaconBlockHeader = Container(("slot", U64), ("proposer_index", U64), ("parent_root", B32),
                              ("state_root", B32), ("body_root", B32))
SignedBeaconBlockHeader = Container(("message", BeaconBlockHeader), ("signature", B96))
Eth1Data = Container(("deposit_root", B32), ("deposit_count", U64), ("block_hash", B32))
Validator = Container(("pubkey", B48), ("withdrawal_credentials", B32),
                      ("effective_balance", U64), ("slashed", U8),
                      ("activation_eligibility_epoch", U64), ("activation_epoch", U64),
                      ("exit_epoch", U64), ("withdrawable_epoch", U64))
AttestationData = Container(("slot", U64), ("index", U64), ("beacon_block_root", B32),
                            ("source", Checkpoint), ("target", Checkpoint))
IndexedAttestation = Container(("attesting_indices", List(U64, 2048)), ("data", AttestationData),
                               ("signature", B96))
Attestation = Container(("aggregation_bits", Bitlist(2048)), ("data", AttestationData),
                        ("signature", B96))
ProposerSlashing = Container(("signed_header_1", SignedBeaconBlockHeader),
                             ("signed_header_2", SignedBeaconBlockHeader))
AttesterSlashing = Container(("attestation_1", IndexedAttestation),
                             ("attestation_2", IndexedAttestation))
DepositData = Container(("pubkey", B48), ("withdrawal_credentials", B32), ("amount", U64),
                        ("signature", B96))
Deposit = Container(("proof", Vector(B32, 33)), ("data", DepositData))
VoluntaryExit = Container(("epoch", U64), ("validator_index", U64))
SignedVoluntaryExit = Container(("message", VoluntaryExit), ("signature", B96))
SyncAggregate = Container(("sync_committee_bits", Bitvector(512)),
                          ("sync_committee_signature", B96))
SyncCommittee = Container(("pubkeys", Vector(B48, 512)), ("aggregate_pubkey", B48))
Withdrawal = Container(("index", U64), ("validator_index", U64), ("address", B20),
                       ("amount", U64))
EXECUTION_COMMON = (("parent_hash", B32), ("fee_recipient", B20), ("state_root", B32),
                    ("receipts_root", B32), ("logs_bloom", ByteVector(256)),
                    ("prev_randao", B32), ("block_number", U64), ("gas_limit", U64),
                    ("gas_used", U64), ("timestamp", U64), ("extra_data", ByteList(32)),
                    ("base_fee_per_gas", U256), ("block_hash", B32))
ExecutionPayload = Container(*EXECUTION_COMMON,
                             ("transactions", List(ByteList(1 << 30), 1 << 20)),
                             ("withdrawals", List(Withdrawal, 16)))
ExecutionPayloadHeader = Container(*EXECUTION_COMMON, ("transactions_root", B32),
                                   ("withdrawals_root", B32))
BLSToExecutionChange = Container(("validator_index", U64), ("from_bls_pubkey", B48),
                                 ("to_execution_address", B20))
SignedBLSToExecutionChange = Container(("message", BLSToExecutionChange), ("signature", B96))
BeaconBlockBody = Container(
    ("randao_reveal", B96), ("eth1_data", Eth1Data), ("graffiti", B32),
    ("proposer_slashings", List(ProposerSlashing, 16)),
    ("attester_slashings", List(AttesterSlashing, 2)),
    ("attestations", List(Attestation, 128)), ("deposits", List(Deposit, 16)),
    ("voluntary_exits", List(SignedVoluntaryExit, 16)), ("sync_aggregate", SyncAggregate),
    ("execution_payload", ExecutionPayload),
    ("bls_to_execution_changes", List(SignedBLSToExecutionChange, 16)))
HistoricalSummary = Container(("block_summary_root", B32), ("state_summary_root", B32))
BeaconState = Container(
    ("genesis_time", U64), ("genesis_validators_root", B32), ("slot", U64), ("fork", Fork),
    ("latest_block_header", BeaconBlockHeader), ("block_roots", Vector(B32, 8192)),
    ("state_roots", Vector(B32, 8192)), ("historical_roots", List(B32, 1 << 24)),
    ("eth1_data", Eth1Data), ("eth1_data_votes", List(Eth1Data, 2048)),
    ("eth1_deposit_index", U64), ("validators", List(Validator, 1 << 40)),
    ("balances", List(U64, 1 << 40)), ("randao_mixes", Vector(B32, 65536)),
    ("slashings", Vector(U64, 8192)), ("previous_epoch_participation", List(U8, 1 << 40)),
    ("current_epoch_participation", List(U8, 1 << 40)), ("justification_bits", Bitvector(4)),
    ("previous_justified_checkpoint", Checkpoint), ("current_justified_checkpoint", Checkpoint),
    ("finalized_checkpoint", Checkpoint), ("inactivity_scores", List(U64, 1 << 40)),
    ("current_sync_committee", SyncCommittee), ("next_sync_committee", SyncCommittee),
    ("latest_execution_payload_header", ExecutionPayloadHeader),
    ("next_withdrawal_index", U64), ("next_withdrawal_validator_index", U64),
    ("historical_summaries", List(HistoricalSummary, 1 << 24)))

STATE_FIELDS = [name for name, _ in BeaconState.fields]
BODY_FIELDS = [name for name, _ in BeaconBlockBody.fields]
HEADER_FIELDS = [name for name, _ in ExecutionPayloadHeader.fields]


def padded(roots):
    width = 1 << depth_of(len(roots))
    return roots + [ZERO] * (width - len(roots))


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def h(b):
    return "0x" + b.hex()


def main():
    if len(sys.argv) != 5:
        fail(__doc__.strip().splitlines()[2])
    root = hexb(sys.argv[1])
    with open(sys.argv[2], encoding="utf-8") as f:
        block = json.load(f)
    if block.get("version") != "capella":
        fail(f"the block is {block.get('version')}, not capella")
    message = block["data"]["message"]
    with open(sys.argv[3], "rb") as f:
        state = BeaconState.decode(f.read())
    s = dict(zip(STATE_FIELDS, state))

    slot = int(message["slot"])
    if s["slot"] != slot:
        fail(f"the state is at slot {s['slot']}, not the block's slot {slot}: the block is not "
             "the last one of the state")
    state_roots = BeaconState.roots(state)
    state_root, committee_branch = tree_and_branch(padded(state_roots),
                                                   STATE_FIELDS.index("current_sync_committee"))
    if state_root != hexb(message["state_root"]):
        fail(f"the state hashes to {h(state_root)}, not the block's state_root")

    body = BeaconBlockBody.from_json(message["body"])
    body_roots = BeaconBlockBody.roots(body)
    body_root, execution_branch = tree_and_branch(padded(body_roots),
                                                  BODY_FIELDS.index("execution_payload"))
    latest = dict(zip([n for n, _ in BeaconBlockHeader.fields], s["latest_block_header"]))
    if body_root != latest["body_root"]:
        fail(f"the body hashes to {h(body_root)}, not the state's latest_block_header.body_root")
    beacon = [slot, int(message["proposer_index"]), hexb(message["parent_root"]),
              hexb(message["state_root"]), body_root]
    if BeaconBlockHeader.root(beacon) != root:
        fail(f"the header hashes to {h(BeaconBlockHeader.root(beacon))}, not {h(root)}")

    execution = s["latest_execution_payload_header"]
    if ExecutionPayloadHeader.root(execution) != body_roots[BODY_FIELDS.index("execution_payload")]:
        fail("the state's execution payload header does not hash to the body's payload")
    committee = s["current_sync_committee"]
    if SyncCommittee.root(committee) != state_roots[STATE_FIELDS.index("current_sync_committee")]:
        fail("the current sync committee does not hash to its leaf")

    e = dict(zip(HEADER_FIELDS, execution))
    numbers = ("block_number", "gas_limit", "gas_used", "timestamp", "base_fee_per_gas")
    bootstrap = {
        "version": "capella",
        "data": {
            "header": {
                "beacon": {
                    "slot": str(slot),
                    "proposer_index": message["proposer_index"],
                    "parent_root": message["parent_root"],
                    "state_root": message["state_root"],
                    "body_root": h(body_root),
                },
                "execution": {k: str(v) if k in numbers else h(v) for k, v in e.items()},
                "execution_branch": [h(x) for x in execution_branch],
            },
            "current_sync_committee": {
                "pubkeys": [h(k) for k in committee[0]],
                "aggregate_pubkey": h(committee[1]),
            },
            "current_sync_committee_branch": [h(x) for x in committee_branch],
        },
    }
    with open(sys.argv[4], "w", encoding="utf-8") as f:
        json.dump(bootstrap, f, indent=1)
        f.write("\n")
    print(f"bootstrap of {h(root)} at slot {slot}, execution block {e['block_number']} "
          f"{h(e['block_hash'])}")


if __name__ == "__main__":
    main()
