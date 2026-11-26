//! Test helpers that other crates share: the spec-test readers, a Merkle tree builder, signed
//! committee fixtures and a real `PulseChain` 369 bootstrap.

use super::{
    hash_pair, BeaconBlockHeader, ExecutionPayloadHeader, LightClientBootstrap, LightClientHeader,
    Preset, SyncAggregate, SyncCommittee, BLS_DST,
};
use alloy_primitives::{Bytes, FixedBytes, B256};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use reth_pulsechain_forks::network::{BeaconFork, BeaconForkActivation, PulsechainBeacon};
use serde_json::Value;
use ssz::Decode;

/// A spec-test hex string as a hash.
pub fn hash(value: &Value) -> B256 {
    value.as_str().unwrap().parse().unwrap()
}

/// A spec-test hex string as bytes.
pub fn bytes(value: &Value) -> Bytes {
    value.as_str().unwrap().parse().unwrap()
}

/// A spec-test hex string as a fork version or digest.
pub fn digest(value: &Value) -> [u8; 4] {
    bytes(value).as_ref().try_into().unwrap()
}

/// The forks of a spec-test case, in schedule order.
pub const FORK_ORDER: [BeaconFork; 4] =
    [BeaconFork::Phase0, BeaconFork::Altair, BeaconFork::Bellatrix, BeaconFork::Capella];

/// The fork schedule and genesis validators root of a spec-test case.
pub fn case_beacon(case: &Value) -> PulsechainBeacon {
    let forks = case["forks"].as_array().unwrap();
    PulsechainBeacon {
        genesis_validators_root: hash(&case["genesis_validators_root"]),
        genesis_time: 0,
        forks: std::array::from_fn(|i| BeaconForkActivation {
            fork: FORK_ORDER[i],
            version: digest(&forks[i]["version"]),
            epoch: forks[i]["epoch"].as_u64().unwrap(),
        }),
    }
}

/// The value of node `gindex` in a tree of depth `depth` whose leaves are zero except
/// `leaves`.
pub fn node(leaves: &[(u64, B256)], gindex: u64, depth: u32) -> B256 {
    if let Some((_, leaf)) = leaves.iter().find(|(g, _)| *g == gindex) {
        return *leaf;
    }
    if gindex.ilog2() >= depth {
        return B256::ZERO;
    }
    hash_pair(&node(leaves, 2 * gindex, depth), &node(leaves, 2 * gindex + 1, depth))
}

/// The branch of `gindex`: the sibling of each node on its path, from the leaf up.
pub fn branch(leaves: &[(u64, B256)], gindex: u64, depth: u32) -> Vec<B256> {
    (0..gindex.ilog2()).map(|i| node(leaves, (gindex >> i) ^ 1, depth)).collect()
}

/// The depth of the state tree, enough for `FINALIZED_ROOT_GINDEX`.
pub const STATE_DEPTH: u32 = 6;

/// A committee of `size` members that repeats `keys`: member `i` holds key `i % keys.len()`.
/// A real committee may name one validator more than once, and a test then signs once per
/// key, not once per member.
pub fn repeated_committee(keys: &[SecretKey], size: usize) -> SyncCommittee {
    let distinct: Vec<PublicKey> = keys.iter().map(SecretKey::sk_to_pk).collect();
    let members: Vec<&PublicKey> = (0..size).map(|i| &distinct[i % keys.len()]).collect();
    let aggregate = AggregatePublicKey::aggregate(&members, false).unwrap().to_public_key();
    SyncCommittee {
        pubkeys: members.iter().map(|key| FixedBytes(key.compress())).collect(),
        aggregate_pubkey: FixedBytes(aggregate.compress()),
    }
}

/// Signs `signing_root` with the first `participants` members of the
/// [`repeated_committee`] of `keys` and `size`.
pub fn repeated_aggregate(
    keys: &[SecretKey],
    size: usize,
    participants: usize,
    signing_root: B256,
) -> SyncAggregate {
    let distinct: Vec<Signature> =
        keys.iter().map(|key| key.sign(signing_root.as_slice(), BLS_DST, &[])).collect();
    let signers: Vec<&Signature> = (0..participants).map(|i| &distinct[i % keys.len()]).collect();
    let signature = AggregateSignature::aggregate(&signers, false).unwrap().to_signature();
    let mut bits = vec![0; size / 8];
    for i in 0..participants {
        bits[i / 8] |= 1 << (i % 8);
    }
    SyncAggregate {
        sync_committee_bits: bits,
        sync_committee_signature: FixedBytes(signature.compress()),
    }
}

/// A finalized `PulseChain` 369 block and the committee of its state. See the testdata
/// README for how they were derived.
#[derive(Debug)]
pub struct Real369 {
    /// `real_369.json`: the roots, branches and aggregate of the block.
    pub json: Value,
    /// The beacon block header.
    pub header: BeaconBlockHeader,
    /// The current sync committee of the block's state.
    pub committee: SyncCommittee,
    /// The `sync_aggregate` of the block, which signs its parent root.
    pub aggregate: SyncAggregate,
}

impl Real369 {
    /// Reads the testdata files.
    pub fn load() -> Self {
        let json: Value =
            serde_json::from_str(include_str!("../../testdata/sync_committee/real_369.json"))
                .unwrap();
        let h = &json["header"];
        let number = |value: &Value| value.as_str().unwrap().parse().unwrap();
        let header = BeaconBlockHeader {
            slot: number(&h["slot"]),
            proposer_index: number(&h["proposer_index"]),
            parent_root: hash(&h["parent_root"]),
            state_root: hash(&h["state_root"]),
            body_root: hash(&h["body_root"]),
        };
        let committee = SyncCommittee::from_ssz_bytes(
            include_bytes!("../../testdata/sync_committee/real_369_current_sync_committee.ssz"),
            Preset::PULSECHAIN,
        )
        .unwrap();
        let a = &json["sync_aggregate"];
        let aggregate = SyncAggregate::from_ssz_bytes(
            &[bytes(&a["sync_committee_bits"]), bytes(&a["sync_committee_signature"])].concat(),
            Preset::PULSECHAIN,
        )
        .unwrap();
        Self { json, header, committee, aggregate }
    }

    /// The branch in the `field` of [`Self::json`].
    pub fn branch(&self, field: &str) -> Vec<B256> {
        self.json[field].as_array().unwrap().iter().map(hash).collect()
    }

    /// The light-client header of the block.
    pub fn light_client_header(&self) -> LightClientHeader {
        LightClientHeader {
            beacon: self.header,
            execution: ExecutionPayloadHeader::from_ssz_bytes(include_bytes!(
                "../../testdata/sync_committee/real_369_execution_payload_header.ssz"
            ))
            .unwrap(),
            execution_branch: self.branch("execution_branch").try_into().unwrap(),
        }
    }

    /// The bootstrap at the block.
    pub fn bootstrap(&self) -> LightClientBootstrap {
        LightClientBootstrap {
            header: self.light_client_header(),
            current_sync_committee: self.committee.clone(),
            current_sync_committee_branch: self.branch("current_sync_committee_branch"),
        }
    }
}
