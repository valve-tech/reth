//! Builders of synthetic Capella blocks and states, for the tests of code that reads them.

use crate::{
    capella::{
        beacon_block, beacon_block_body, beacon_state, body_field, signed_beacon_block, state_field,
    },
    ssz_merkle::{Container, SszType},
    sync_committee::{
        compute_domain, compute_signing_root, test_utils::repeated_aggregate,
        ExecutionPayloadHeader, Preset, SyncAggregate, SyncCommittee, DOMAIN_SYNC_COMMITTEE,
    },
};
use alloy_primitives::B256;
use blst::min_pk::SecretKey;
use reth_pulsechain_forks::network::{BeaconFork, BeaconForkActivation, PulsechainBeacon};
use ssz::Encode;

/// Pins with every fork at epoch 0, fork versions `[i, 0, 0, 1]` and genesis at time 0.
pub fn synthetic_pins() -> PulsechainBeacon {
    let fork =
        |fork, version: u8| BeaconForkActivation { fork, version: [version, 0, 0, 1], epoch: 0 };
    PulsechainBeacon {
        genesis_validators_root: B256::repeat_byte(0x42),
        genesis_time: 0,
        forks: [
            fork(BeaconFork::Phase0, 0),
            fork(BeaconFork::Altair, 1),
            fork(BeaconFork::Bellatrix, 2),
            fork(BeaconFork::Capella, 3),
        ],
    }
}

/// Four distinct secret keys from `seed`.
pub fn keys(seed: u8) -> Vec<SecretKey> {
    (0..4u8).map(|i| SecretKey::key_gen(&[seed + i; 32], &[]).unwrap()).collect()
}

/// Serializes a container whose field `i` holds `values[i]`, already serialized.
pub fn encode(container: &Container, values: &[Vec<u8>]) -> Vec<u8> {
    let fixed: usize = container.fields().iter().map(|f| f.fixed_len().unwrap_or(4)).sum();
    let (mut head, mut tail) = (Vec::new(), Vec::new());
    for (ty, value) in container.fields().iter().zip(values) {
        if ty.fixed_len().is_some() {
            head.extend_from_slice(value);
        } else {
            head.extend_from_slice(&u32::try_from(fixed + tail.len()).unwrap().to_le_bytes());
            tail.extend_from_slice(value);
        }
    }
    head.extend(tail);
    head
}

/// The serialized default of `ty`: zeros, empty lists, and a bitlist of no bits.
pub fn default_value(ty: &SszType) -> Vec<u8> {
    match (ty.fixed_len(), ty) {
        (Some(len), _) => vec![0; len],
        (None, SszType::Container(container)) => {
            let values: Vec<Vec<u8>> = container.fields().iter().map(default_value).collect();
            encode(container, &values)
        }
        (None, SszType::Bitlist(_)) => vec![1],
        (None, _) => Vec::new(),
    }
}

/// The container that `ty` is.
pub fn inner(ty: &SszType) -> &Container {
    let SszType::Container(container) = ty else { panic!("{ty:?} is not a container") };
    container
}

fn committee_ssz(committee: &SyncCommittee) -> Vec<u8> {
    let mut buf = Vec::new();
    committee.append_ssz(&mut buf);
    buf
}

/// A post-state at `slot` with these committees, which has finalized `finalized_root` at
/// `finalized_epoch`. Its fork is the one `beacon` has at `slot`.
pub fn state_ssz(
    preset: Preset,
    beacon: &PulsechainBeacon,
    slot: u64,
    finalized_epoch: u64,
    finalized_root: B256,
    current: &SyncCommittee,
    next: &SyncCommittee,
) -> Vec<u8> {
    let schema = beacon_state(preset);
    let mut values: Vec<Vec<u8>> = schema.fields().iter().map(default_value).collect();
    let epoch = preset.epoch_at_slot(slot);
    let index = beacon.forks.iter().rposition(|fork| fork.epoch <= epoch).unwrap_or(0);
    let previous = beacon.forks[index.saturating_sub(1)].version;
    values[state_field::SLOT] = slot.to_le_bytes().to_vec();
    values[state_field::FORK] = [previous, beacon.forks[index].version].concat();
    values[state_field::FORK].extend_from_slice(&beacon.forks[index].epoch.to_le_bytes());
    values[state_field::FINALIZED_CHECKPOINT] =
        [&finalized_epoch.to_le_bytes()[..], finalized_root.as_slice()].concat();
    values[state_field::CURRENT_SYNC_COMMITTEE] = committee_ssz(current);
    values[state_field::NEXT_SYNC_COMMITTEE] = committee_ssz(next);
    values[state_field::LATEST_EXECUTION_PAYLOAD_HEADER] =
        ExecutionPayloadHeader::default().as_ssz_bytes();
    encode(&schema, &values)
}

/// The `hash_tree_root` of a serialized state.
pub fn state_root(preset: Preset, state: &[u8]) -> B256 {
    beacon_state(preset).hash_tree_root(state).unwrap()
}

/// A signed block at `slot` with one transaction and one withdrawal. Its execution block number
/// is `slot + 1000`.
pub fn block_ssz(
    preset: Preset,
    slot: u64,
    parent: B256,
    state_root: B256,
    aggregate: &SyncAggregate,
) -> Vec<u8> {
    let transactions = [&4u32.to_le_bytes()[..], &[0x02, 0xab, 0xcd]].concat();
    block_ssz_with_transactions(preset, slot, parent, state_root, aggregate, &transactions)
}

/// [`block_ssz`] with the serialized transactions list `transactions`.
pub fn block_ssz_with_transactions(
    preset: Preset,
    slot: u64,
    parent: B256,
    state_root: B256,
    aggregate: &SyncAggregate,
    transactions: &[u8],
) -> Vec<u8> {
    let body_schema = beacon_block_body(preset);
    let mut body: Vec<Vec<u8>> = body_schema.fields().iter().map(default_value).collect();
    body[body_field::SYNC_AGGREGATE] =
        [aggregate.sync_committee_bits(), aggregate.sync_committee_signature().as_slice()].concat();
    let payload_schema = inner(&body_schema.fields()[body_field::EXECUTION_PAYLOAD]);
    let mut payload: Vec<Vec<u8>> = payload_schema.fields().iter().map(default_value).collect();
    payload[6] = (slot + 1000).to_le_bytes().to_vec(); // block_number
    payload[10] = b"lc".to_vec(); // extra_data
    payload[12] = B256::left_padding_from(&slot.to_be_bytes()).to_vec(); // block_hash
    payload[13] = transactions.to_vec();
    payload[14] = [&7u64.to_le_bytes()[..], &[0; 8], &[0x11; 20], &[0; 8]].concat();
    body[body_field::EXECUTION_PAYLOAD] = encode(payload_schema, &payload);

    let block = encode(
        &beacon_block(preset),
        &[
            slot.to_le_bytes().to_vec(),
            3u64.to_le_bytes().to_vec(),
            parent.to_vec(),
            state_root.to_vec(),
            encode(&body_schema, &body),
        ],
    );
    encode(&signed_beacon_block(preset), &[block, vec![0; 96]])
}

/// Signs `root` in a block at `slot` with the first `participants` members of the repeated
/// committee of `keys`.
pub fn sign(
    preset: Preset,
    beacon: &PulsechainBeacon,
    keys: &[SecretKey],
    participants: usize,
    root: B256,
    slot: u64,
) -> SyncAggregate {
    let version = beacon.fork_at_epoch(preset.epoch_at_slot(slot - 1)).version;
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, version, beacon.genesis_validators_root);
    repeated_aggregate(
        keys,
        preset.sync_committee_size(),
        participants,
        compute_signing_root(root, domain),
    )
}

/// An aggregate with no signers.
pub fn unsigned(preset: Preset) -> SyncAggregate {
    SyncAggregate::from_ssz_bytes(&vec![0; preset.sync_committee_size() / 8 + 96], preset).unwrap()
}
