"""Derive small reth-lite fixtures from consensus-spec-tests v1.4.0 (mainnet, Capella).

Usage: python -I derive.py <spec-tests-root> <out-dir>

It checks every root it writes: the ssz_static roots against roots.yaml, and each
single_merkle_proof branch against the object root this script computes on its own.
"""

import json
import os
import shutil
import sys
from hashlib import sha256

import snappy
from remerkleable.basic import boolean, uint8, uint64, uint256
from remerkleable.bitfields import Bitlist, Bitvector
from remerkleable.byte_arrays import ByteList, ByteVector, Bytes4, Bytes32, Bytes48, Bytes96
from remerkleable.complex import Container, List, Vector

Bytes20 = ByteVector[20]
Root = Bytes32


class Fork(Container):
    previous_version: Bytes4
    current_version: Bytes4
    epoch: uint64


class Checkpoint(Container):
    epoch: uint64
    root: Root


class BeaconBlockHeader(Container):
    slot: uint64
    proposer_index: uint64
    parent_root: Root
    state_root: Root
    body_root: Root


class SignedBeaconBlockHeader(Container):
    message: BeaconBlockHeader
    signature: Bytes96


class Eth1Data(Container):
    deposit_root: Root
    deposit_count: uint64
    block_hash: Bytes32


class Validator(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    effective_balance: uint64
    slashed: boolean
    activation_eligibility_epoch: uint64
    activation_epoch: uint64
    exit_epoch: uint64
    withdrawable_epoch: uint64


class AttestationData(Container):
    slot: uint64
    index: uint64
    beacon_block_root: Root
    source: Checkpoint
    target: Checkpoint


class IndexedAttestation(Container):
    attesting_indices: List[uint64, 2048]
    data: AttestationData
    signature: Bytes96


class Attestation(Container):
    aggregation_bits: Bitlist[2048]
    data: AttestationData
    signature: Bytes96


class ProposerSlashing(Container):
    signed_header_1: SignedBeaconBlockHeader
    signed_header_2: SignedBeaconBlockHeader


class AttesterSlashing(Container):
    attestation_1: IndexedAttestation
    attestation_2: IndexedAttestation


class DepositData(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: uint64
    signature: Bytes96


class Deposit(Container):
    proof: Vector[Bytes32, 33]
    data: DepositData


class VoluntaryExit(Container):
    epoch: uint64
    validator_index: uint64


class SignedVoluntaryExit(Container):
    message: VoluntaryExit
    signature: Bytes96


class SyncAggregate(Container):
    sync_committee_bits: Bitvector[512]
    sync_committee_signature: Bytes96


class SyncCommittee(Container):
    pubkeys: Vector[Bytes48, 512]
    aggregate_pubkey: Bytes48


class Withdrawal(Container):
    index: uint64
    validator_index: uint64
    address: Bytes20
    amount: uint64


class ExecutionPayload(Container):
    parent_hash: Bytes32
    fee_recipient: Bytes20
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: ByteVector[256]
    prev_randao: Bytes32
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ByteList[32]
    base_fee_per_gas: uint256
    block_hash: Bytes32
    transactions: List[ByteList[2**30], 2**20]
    withdrawals: List[Withdrawal, 16]


class ExecutionPayloadHeader(Container):
    parent_hash: Bytes32
    fee_recipient: Bytes20
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: ByteVector[256]
    prev_randao: Bytes32
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ByteList[32]
    base_fee_per_gas: uint256
    block_hash: Bytes32
    transactions_root: Root
    withdrawals_root: Root


class BLSToExecutionChange(Container):
    validator_index: uint64
    from_bls_pubkey: Bytes48
    to_execution_address: Bytes20


class SignedBLSToExecutionChange(Container):
    message: BLSToExecutionChange
    signature: Bytes96


class HistoricalSummary(Container):
    block_summary_root: Root
    state_summary_root: Root


class BeaconBlockBody(Container):
    randao_reveal: Bytes96
    eth1_data: Eth1Data
    graffiti: Bytes32
    proposer_slashings: List[ProposerSlashing, 16]
    attester_slashings: List[AttesterSlashing, 2]
    attestations: List[Attestation, 128]
    deposits: List[Deposit, 16]
    voluntary_exits: List[SignedVoluntaryExit, 16]
    sync_aggregate: SyncAggregate
    execution_payload: ExecutionPayload
    bls_to_execution_changes: List[SignedBLSToExecutionChange, 16]


class BeaconState(Container):
    genesis_time: uint64
    genesis_validators_root: Root
    slot: uint64
    fork: Fork
    latest_block_header: BeaconBlockHeader
    block_roots: Vector[Root, 8192]
    state_roots: Vector[Root, 8192]
    historical_roots: List[Root, 2**24]
    eth1_data: Eth1Data
    eth1_data_votes: List[Eth1Data, 2048]
    eth1_deposit_index: uint64
    validators: List[Validator, 2**40]
    balances: List[uint64, 2**40]
    randao_mixes: Vector[Bytes32, 65536]
    slashings: Vector[uint64, 8192]
    previous_epoch_participation: List[uint8, 2**40]
    current_epoch_participation: List[uint8, 2**40]
    justification_bits: Bitvector[4]
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    inactivity_scores: List[uint64, 2**40]
    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee
    latest_execution_payload_header: ExecutionPayloadHeader
    next_withdrawal_index: uint64
    next_withdrawal_validator_index: uint64
    historical_summaries: List[HistoricalSummary, 2**24]


def read_snappy(path):
    with open(path, "rb") as f:
        return snappy.decompress(f.read())


def read_proof(path):
    # proof.yaml is flow-style YAML that is also valid after a quote swap.
    text = open(path).read()
    out = {}
    for key in ("leaf", "leaf_index", "branch"):
        start = text.index(key + ":") + len(key) + 1
        rest = text[start:]
        if key == "branch":
            value = rest[rest.index("[") : rest.index("]") + 1].replace("'", '"').replace("\n", "")
            out[key] = json.loads(value)
        else:
            out[key] = rest.split("\n", 1)[0].strip().strip("'")
    out["leaf_index"] = int(out["leaf_index"])
    return out


def is_valid_merkle_branch(leaf, branch, gindex, root):
    value = bytes.fromhex(leaf[2:])
    depth = gindex.bit_length() - 1
    assert len(branch) == depth
    for i, node in enumerate(branch):
        node = bytes.fromhex(node[2:])
        if (gindex >> i) & 1:
            value = sha256(node + value).digest()
        else:
            value = sha256(value + node).digest()
    return value == root


def hx(b):
    return "0x" + bytes(b).hex()


def main(spec_root, out_dir):
    capella = os.path.join(spec_root, "tests", "mainnet", "capella")
    os.makedirs(out_dir, exist_ok=True)

    # ssz_static: decompress a few cases and copy their roots.
    static_types = {
        "BeaconBlockHeader": (BeaconBlockHeader, ["case_0", "case_1"]),
        "ExecutionPayloadHeader": (ExecutionPayloadHeader, ["case_0", "case_1"]),
        "LightClientHeader": (None, ["case_0", "case_1"]),
        "SyncAggregate": (SyncAggregate, ["case_0", "case_1"]),
        "SyncCommittee": (SyncCommittee, ["case_0"]),
    }
    static_roots = {}
    for name, (typ, cases) in static_types.items():
        for case in cases:
            src = os.path.join(capella, "ssz_static", name, "ssz_random", case)
            data = read_snappy(os.path.join(src, "serialized.ssz_snappy"))
            root = open(os.path.join(src, "roots.yaml")).read().split("'")[1]
            if typ is not None:
                assert hx(typ.decode_bytes(data).hash_tree_root()) == root, (name, case)
            fname = f"ssz_static_{name}_{case}.ssz"
            with open(os.path.join(out_dir, fname), "wb") as f:
                f.write(data)
            static_roots[fname] = root

    # single_merkle_proof: the body and the state roots come from this script.
    smp = os.path.join(capella, "light_client", "single_merkle_proof")
    body = BeaconBlockBody.decode_bytes(
        read_snappy(os.path.join(smp, "BeaconBlockBody", "execution_merkle_proof", "object.ssz_snappy"))
    )
    state = BeaconState.decode_bytes(
        read_snappy(os.path.join(smp, "BeaconState", "current_sync_committee_merkle_proof", "object.ssz_snappy"))
    )
    for case in ("next_sync_committee_merkle_proof", "finality_root_merkle_proof"):
        other = read_snappy(os.path.join(smp, "BeaconState", case, "object.ssz_snappy"))
        assert other == state.encode_bytes(), case

    payload = body.execution_payload
    header = ExecutionPayloadHeader(
        **{k: getattr(payload, k) for k in ExecutionPayloadHeader.fields() if hasattr(payload, k)},
        transactions_root=payload.transactions.hash_tree_root(),
        withdrawals_root=payload.withdrawals.hash_tree_root(),
    )
    assert header.hash_tree_root() == payload.hash_tree_root()

    proofs = {}
    for group, case, root in (
        ("BeaconBlockBody", "execution_merkle_proof", body.hash_tree_root()),
        ("BeaconState", "current_sync_committee_merkle_proof", state.hash_tree_root()),
        ("BeaconState", "next_sync_committee_merkle_proof", state.hash_tree_root()),
        ("BeaconState", "finality_root_merkle_proof", state.hash_tree_root()),
    ):
        proof = read_proof(os.path.join(smp, group, case, "proof.yaml"))
        assert is_valid_merkle_branch(proof["leaf"], proof["branch"], proof["leaf_index"], root), case
        proof["root"] = hx(root)
        proofs[case] = proof

    assert hx(header.hash_tree_root()) == proofs["execution_merkle_proof"]["leaf"]
    assert hx(state.current_sync_committee.hash_tree_root()) == proofs["current_sync_committee_merkle_proof"]["leaf"]
    assert hx(state.next_sync_committee.hash_tree_root()) == proofs["next_sync_committee_merkle_proof"]["leaf"]
    assert hx(state.finalized_checkpoint.root) == proofs["finality_root_merkle_proof"]["leaf"]

    with open(os.path.join(out_dir, "single_merkle_proof_execution_payload_header.ssz"), "wb") as f:
        f.write(header.encode_bytes())
    with open(os.path.join(out_dir, "single_merkle_proof_current_sync_committee.ssz"), "wb") as f:
        f.write(state.current_sync_committee.encode_bytes())
    # The vector's state has the same current and next committee; one file serves both leaves.
    assert state.current_sync_committee == state.next_sync_committee

    manifest = {
        "source": "ethereum/consensus-spec-tests v1.4.0, tests/mainnet/capella",
        "ssz_static_roots": static_roots,
        "single_merkle_proof": proofs,
    }
    with open(os.path.join(out_dir, "capella.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
