//! The Capella SSZ schemas of the `BeaconState` and the `SignedBeaconBlock`, for
//! [`ssz_merkle`](crate::ssz_merkle), with the field indices the light-client proofs use.
//!
//! The schemas follow `capella/beacon-chain.md`. The sizes that differ between presets come from
//! [`Preset`]; the others are the same in every preset.

use crate::{
    ssz_merkle::{Container, SszType},
    sync_committee::Preset,
};

/// `VALIDATOR_REGISTRY_LIMIT`.
const VALIDATOR_REGISTRY_LIMIT: u64 = 1 << 40;
/// `HISTORICAL_ROOTS_LIMIT`.
const HISTORICAL_ROOTS_LIMIT: u64 = 1 << 24;
/// `JUSTIFICATION_BITS_LENGTH`.
const JUSTIFICATION_BITS_LENGTH: usize = 4;
/// `DEPOSIT_CONTRACT_TREE_DEPTH`.
const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;
/// `MAX_VALIDATORS_PER_COMMITTEE`.
const MAX_VALIDATORS_PER_COMMITTEE: u64 = 2048;
/// `MAX_PROPOSER_SLASHINGS`.
const MAX_PROPOSER_SLASHINGS: u64 = 16;
/// `MAX_ATTESTER_SLASHINGS`.
const MAX_ATTESTER_SLASHINGS: u64 = 2;
/// `MAX_ATTESTATIONS`.
const MAX_ATTESTATIONS: u64 = 128;
/// `MAX_DEPOSITS`.
const MAX_DEPOSITS: u64 = 16;
/// `MAX_VOLUNTARY_EXITS`.
const MAX_VOLUNTARY_EXITS: u64 = 16;
/// `MAX_BLS_TO_EXECUTION_CHANGES`.
const MAX_BLS_TO_EXECUTION_CHANGES: u64 = 16;
/// `BYTES_PER_LOGS_BLOOM`.
const BYTES_PER_LOGS_BLOOM: usize = 256;
/// `MAX_EXTRA_DATA_BYTES`.
const MAX_EXTRA_DATA_BYTES: u64 = 32;
/// `MAX_BYTES_PER_TRANSACTION`.
const MAX_BYTES_PER_TRANSACTION: u64 = 1 << 30;
/// `MAX_TRANSACTIONS_PER_PAYLOAD`.
const MAX_TRANSACTIONS_PER_PAYLOAD: u64 = 1 << 20;

/// The field indices of the `BeaconState`.
pub mod state_field {
    /// `slot`.
    pub const SLOT: usize = 2;
    /// `fork`.
    pub const FORK: usize = 3;
    /// `latest_block_header`.
    pub const LATEST_BLOCK_HEADER: usize = 4;
    /// `finalized_checkpoint`.
    pub const FINALIZED_CHECKPOINT: usize = 20;
    /// `current_sync_committee`.
    pub const CURRENT_SYNC_COMMITTEE: usize = 22;
    /// `next_sync_committee`.
    pub const NEXT_SYNC_COMMITTEE: usize = 23;
    /// `latest_execution_payload_header`.
    pub const LATEST_EXECUTION_PAYLOAD_HEADER: usize = 24;
}

/// The field index of `root` in a `Checkpoint`.
pub const CHECKPOINT_ROOT: usize = 1;

/// The field indices of the `SignedBeaconBlock`.
pub mod signed_block_field {
    /// `message`, the `BeaconBlock`.
    pub const MESSAGE: usize = 0;
}

/// The field indices of the `BeaconBlock`.
pub mod block_field {
    /// `slot`.
    pub const SLOT: usize = 0;
    /// `proposer_index`.
    pub const PROPOSER_INDEX: usize = 1;
    /// `parent_root`.
    pub const PARENT_ROOT: usize = 2;
    /// `state_root`.
    pub const STATE_ROOT: usize = 3;
    /// `body`.
    pub const BODY: usize = 4;
}

/// The field indices of the `ExecutionPayload`.
pub mod payload_field {
    /// `transactions`.
    pub const TRANSACTIONS: usize = 13;
}

/// The field indices of the `BeaconBlockBody`.
pub mod body_field {
    /// `sync_aggregate`.
    pub const SYNC_AGGREGATE: usize = 8;
    /// `execution_payload`.
    pub const EXECUTION_PAYLOAD: usize = 9;
}

const U8: SszType = SszType::Uint(1);
const U64: SszType = SszType::Uint(8);
const U256: SszType = SszType::Uint(32);
const BYTES4: SszType = SszType::Bytes(4);
const BYTES20: SszType = SszType::Bytes(20);
const BYTES32: SszType = SszType::Bytes(32);
const BYTES48: SszType = SszType::Bytes(48);
const BYTES96: SszType = SszType::Bytes(96);

const fn container(fields: Vec<SszType>) -> SszType {
    SszType::Container(Container::new(fields))
}

fn vector(item: SszType, len: usize) -> SszType {
    SszType::Vector(Box::new(item), len)
}

fn list(item: SszType, limit: u64) -> SszType {
    SszType::List(Box::new(item), limit)
}

/// Returns the `BeaconState` schema.
pub fn beacon_state(preset: Preset) -> Container {
    let validator = container(vec![
        BYTES48,          // pubkey
        BYTES32,          // withdrawal_credentials
        U64,              // effective_balance
        SszType::Boolean, // slashed
        U64,              // activation_eligibility_epoch
        U64,              // activation_epoch
        U64,              // exit_epoch
        U64,              // withdrawable_epoch
    ]);
    let per_validator = |item| list(item, VALIDATOR_REGISTRY_LIMIT);
    let historical_summary = container(vec![BYTES32, BYTES32]);
    Container::new(vec![
        U64,                                               // genesis_time
        BYTES32,                                           // genesis_validators_root
        U64,                                               // slot
        container(vec![BYTES4, BYTES4, U64]),              // fork
        beacon_block_header(),                             // latest_block_header
        vector(BYTES32, preset.slots_per_historical_root), // block_roots
        vector(BYTES32, preset.slots_per_historical_root), // state_roots
        list(BYTES32, HISTORICAL_ROOTS_LIMIT),             // historical_roots
        eth1_data(),                                       // eth1_data
        // eth1_data_votes
        list(eth1_data(), preset.epochs_per_eth1_voting_period * preset.slots_per_epoch),
        U64,                                                  // eth1_deposit_index
        per_validator(validator),                             // validators
        per_validator(U64),                                   // balances
        vector(BYTES32, preset.epochs_per_historical_vector), // randao_mixes
        vector(U64, preset.epochs_per_slashings_vector),      // slashings
        per_validator(U8),                                    // previous_epoch_participation
        per_validator(U8),                                    // current_epoch_participation
        SszType::Bitvector(JUSTIFICATION_BITS_LENGTH),        // justification_bits
        checkpoint(),                                         // previous_justified_checkpoint
        checkpoint(),                                         // current_justified_checkpoint
        checkpoint(),                                         // finalized_checkpoint
        per_validator(U64),                                   // inactivity_scores
        sync_committee(preset),                               // current_sync_committee
        sync_committee(preset),                               // next_sync_committee
        execution_payload_header(),                           // latest_execution_payload_header
        U64,                                                  // next_withdrawal_index
        U64,                                                  // next_withdrawal_validator_index
        list(historical_summary, HISTORICAL_ROOTS_LIMIT),     // historical_summaries
    ])
}

/// Returns the `SignedBeaconBlock` schema.
pub fn signed_beacon_block(preset: Preset) -> Container {
    Container::new(vec![SszType::Container(beacon_block(preset)), BYTES96])
}

/// Returns the `BeaconBlock` schema.
pub fn beacon_block(preset: Preset) -> Container {
    Container::new(vec![
        U64,                                           // slot
        U64,                                           // proposer_index
        BYTES32,                                       // parent_root
        BYTES32,                                       // state_root
        SszType::Container(beacon_block_body(preset)), // body
    ])
}

/// Returns the `BeaconBlockBody` schema.
pub fn beacon_block_body(preset: Preset) -> Container {
    let signed_header = container(vec![beacon_block_header(), BYTES96]);
    let indexed_attestation = container(vec![
        list(U64, MAX_VALIDATORS_PER_COMMITTEE), // attesting_indices
        attestation_data(),
        BYTES96,
    ]);
    let attestation = container(vec![
        SszType::Bitlist(MAX_VALIDATORS_PER_COMMITTEE), // aggregation_bits
        attestation_data(),
        BYTES96,
    ]);
    let deposit = container(vec![
        vector(BYTES32, DEPOSIT_CONTRACT_TREE_DEPTH + 1), // proof
        container(vec![BYTES48, BYTES32, U64, BYTES96]),  // data
    ]);
    let signed_voluntary_exit = container(vec![container(vec![U64, U64]), BYTES96]);
    let signed_bls_change = container(vec![container(vec![U64, BYTES48, BYTES20]), BYTES96]);
    let withdrawal = container(vec![U64, U64, BYTES20, U64]);
    let execution_payload = container(vec![
        BYTES32,                                 // parent_hash
        BYTES20,                                 // fee_recipient
        BYTES32,                                 // state_root
        BYTES32,                                 // receipts_root
        SszType::Bytes(BYTES_PER_LOGS_BLOOM),    // logs_bloom
        BYTES32,                                 // prev_randao
        U64,                                     // block_number
        U64,                                     // gas_limit
        U64,                                     // gas_used
        U64,                                     // timestamp
        SszType::ByteList(MAX_EXTRA_DATA_BYTES), // extra_data
        U256,                                    // base_fee_per_gas
        BYTES32,                                 // block_hash
        // transactions
        list(SszType::ByteList(MAX_BYTES_PER_TRANSACTION), MAX_TRANSACTIONS_PER_PAYLOAD),
        list(withdrawal, preset.max_withdrawals_per_payload), // withdrawals
    ]);
    Container::new(vec![
        BYTES96,     // randao_reveal
        eth1_data(), // eth1_data
        BYTES32,     // graffiti
        // proposer_slashings
        list(container(vec![signed_header.clone(), signed_header]), MAX_PROPOSER_SLASHINGS),
        // attester_slashings
        list(
            container(vec![indexed_attestation.clone(), indexed_attestation]),
            MAX_ATTESTER_SLASHINGS,
        ),
        list(attestation, MAX_ATTESTATIONS), // attestations
        list(deposit, MAX_DEPOSITS),         // deposits
        list(signed_voluntary_exit, MAX_VOLUNTARY_EXITS), // voluntary_exits
        container(vec![SszType::Bitvector(preset.sync_committee_size), BYTES96]), // sync_aggregate
        execution_payload,
        list(signed_bls_change, MAX_BLS_TO_EXECUTION_CHANGES), // bls_to_execution_changes
    ])
}

fn beacon_block_header() -> SszType {
    container(vec![U64, U64, BYTES32, BYTES32, BYTES32])
}

fn checkpoint() -> SszType {
    container(vec![U64, BYTES32])
}

fn eth1_data() -> SszType {
    container(vec![BYTES32, U64, BYTES32])
}

fn attestation_data() -> SszType {
    // slot, index, beacon_block_root, source, target
    container(vec![U64, U64, BYTES32, checkpoint(), checkpoint()])
}

fn sync_committee(preset: Preset) -> SszType {
    container(vec![vector(BYTES48, preset.sync_committee_size), BYTES48])
}

fn execution_payload_header() -> SszType {
    container(vec![
        BYTES32,                                 // parent_hash
        BYTES20,                                 // fee_recipient
        BYTES32,                                 // state_root
        BYTES32,                                 // receipts_root
        SszType::Bytes(BYTES_PER_LOGS_BLOOM),    // logs_bloom
        BYTES32,                                 // prev_randao
        U64,                                     // block_number
        U64,                                     // gas_limit
        U64,                                     // gas_used
        U64,                                     // timestamp
        SszType::ByteList(MAX_EXTRA_DATA_BYTES), // extra_data
        U256,                                    // base_fee_per_gas
        BYTES32,                                 // block_hash
        BYTES32,                                 // transactions_root
        BYTES32,                                 // withdrawals_root
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ssz_merkle::{container_root, field_branch, field_gindex, SszError},
        sync_committee::{
            is_valid_merkle_branch, test_utils::hash, BeaconBlockHeader, ExecutionPayloadHeader,
            Gindices, SyncAggregate, SyncCommittee,
        },
    };
    use alloy_primitives::B256;
    use reth_pulsechain_forks::network::BeaconFork;
    use serde_json::Value;
    use ssz::Decode;

    const MANIFEST: &str = include_str!("../testdata/ssz/ssz.json");
    const SYNC_MANIFEST: &str = include_str!("../testdata/sync_committee/capella.json");

    fn manifest() -> Value {
        serde_json::from_str(MANIFEST).unwrap()
    }

    fn fixture(name: &str) -> Vec<u8> {
        let bytes =
            std::fs::read(format!("{}/testdata/ssz/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        if name.ends_with(".ssz_snappy") {
            snap::raw::Decoder::new().decompress_vec(&bytes).unwrap()
        } else {
            bytes
        }
    }

    fn preset_of(name: &str) -> Preset {
        if name.starts_with("minimal") {
            Preset::MINIMAL
        } else {
            Preset::MAINNET
        }
    }

    fn schema_of(name: &str) -> Container {
        let preset = preset_of(name);
        match name.split('_').nth(1).unwrap() {
            "BeaconState" => beacon_state(preset),
            "BeaconBlockBody" => beacon_block_body(preset),
            "BeaconBlock" => beacon_block(preset),
            "SignedBeaconBlock" => signed_beacon_block(preset),
            other => panic!("no schema for {other}"),
        }
    }

    #[test]
    fn ssz_static_roots_match_the_spec() {
        let manifest = manifest();
        let roots = manifest["ssz_static"].as_object().unwrap();
        assert_eq!(roots.len(), 10);
        for (name, root) in roots {
            let bytes = fixture(name);
            assert_eq!(schema_of(name).hash_tree_root(&bytes), Ok(hash(root)), "{name}");
        }
    }

    /// The spec's light-client gindices are the field positions in these schemas.
    #[test]
    fn capella_gindices_are_the_schema_field_positions() {
        let gindices = Gindices::for_fork(BeaconFork::Capella).unwrap();
        let state_fields = beacon_state(Preset::PULSECHAIN).fields().len();
        let body_fields = beacon_block_body(Preset::PULSECHAIN).fields().len();
        assert_eq!(state_fields, 28);
        assert_eq!(
            field_gindex(state_fields, state_field::CURRENT_SYNC_COMMITTEE),
            gindices.current_sync_committee
        );
        assert_eq!(
            field_gindex(state_fields, state_field::NEXT_SYNC_COMMITTEE),
            gindices.next_sync_committee
        );
        assert_eq!(
            field_gindex(state_fields, state_field::FINALIZED_CHECKPOINT) * 2 +
                CHECKPOINT_ROOT as u64,
            gindices.finalized_root
        );
        assert_eq!(
            Some(field_gindex(body_fields, body_field::EXECUTION_PAYLOAD)),
            gindices.execution_payload
        );
    }

    /// A `single_merkle_proof` case, with the branch rebuilt from the object's field roots.
    struct Proof {
        object: Vec<u8>,
        leaf: B256,
        gindex: u64,
        branch: Vec<B256>,
    }

    fn proof(case: &str) -> Proof {
        let manifest = manifest();
        let proof = &manifest["single_merkle_proof"][case];
        Proof {
            object: fixture(proof["object"].as_str().unwrap()),
            leaf: hash(&proof["leaf"]),
            gindex: proof["leaf_index"].as_u64().unwrap(),
            branch: proof["branch"].as_array().unwrap().iter().map(hash).collect(),
        }
    }

    /// Rebuilds the state branches 54, 55 and 105 and checks them against the spec.
    fn check_state_branches(preset: Preset, state: &[u8]) -> B256 {
        let schema = beacon_state(preset);
        let roots = schema.field_roots(state).unwrap();
        let root = container_root(&roots);
        for (case, index) in [
            ("current_sync_committee_merkle_proof", state_field::CURRENT_SYNC_COMMITTEE),
            ("next_sync_committee_merkle_proof", state_field::NEXT_SYNC_COMMITTEE),
        ] {
            let spec = proof(&format!("{}_{case}", preset_name(preset)));
            assert_eq!(spec.object, state);
            assert_eq!(roots[index], spec.leaf, "{case}");
            assert_eq!(field_branch(&roots, index), spec.branch, "{case}");
            assert!(is_valid_merkle_branch(spec.leaf, &spec.branch, spec.gindex, root));
        }

        // The finalized root is one level below the state's field: the checkpoint's own branch,
        // then the state's.
        let spec = proof(&format!("{}_finality_root_merkle_proof", preset_name(preset)));
        let fields = schema.split(state).unwrap();
        let SszType::Container(checkpoint) = &schema.fields()[state_field::FINALIZED_CHECKPOINT]
        else {
            unreachable!()
        };
        let checkpoint_roots =
            checkpoint.field_roots(fields[state_field::FINALIZED_CHECKPOINT]).unwrap();
        let mut branch = field_branch(&checkpoint_roots, CHECKPOINT_ROOT);
        branch.extend(field_branch(&roots, state_field::FINALIZED_CHECKPOINT));
        assert_eq!(checkpoint_roots[CHECKPOINT_ROOT], spec.leaf);
        assert_eq!(branch, spec.branch);
        assert!(is_valid_merkle_branch(spec.leaf, &branch, spec.gindex, root));
        root
    }

    /// Rebuilds the body branch 25 and checks it against the spec.
    fn check_body_branch(preset: Preset) -> B256 {
        let spec = proof(&format!("{}_execution_merkle_proof", preset_name(preset)));
        let roots = beacon_block_body(preset).field_roots(&spec.object).unwrap();
        let root = container_root(&roots);
        assert_eq!(roots[body_field::EXECUTION_PAYLOAD], spec.leaf);
        assert_eq!(field_branch(&roots, body_field::EXECUTION_PAYLOAD), spec.branch);
        assert!(is_valid_merkle_branch(spec.leaf, &spec.branch, spec.gindex, root));
        root
    }

    fn preset_name(preset: Preset) -> &'static str {
        if preset == Preset::MINIMAL {
            "minimal"
        } else {
            "mainnet"
        }
    }

    #[test]
    fn minimal_single_merkle_proofs_are_rebuilt() {
        check_state_branches(Preset::MINIMAL, &fixture("minimal_proof_BeaconState.ssz"));
        check_body_branch(Preset::MINIMAL);
    }

    /// The mainnet objects also hash to the roots that `sync_committee/derive.py` computed with
    /// remerkleable, which the spec tests do not give.
    #[test]
    fn mainnet_single_merkle_proofs_are_rebuilt() {
        let sync: Value = serde_json::from_str(SYNC_MANIFEST).unwrap();
        let sync = &sync["single_merkle_proof"];
        let state = fixture("mainnet_proof_BeaconState.ssz_snappy");
        assert_eq!(
            check_state_branches(Preset::MAINNET, &state),
            hash(&sync["current_sync_committee_merkle_proof"]["root"])
        );
        assert_eq!(
            check_body_branch(Preset::MAINNET),
            hash(&sync["execution_merkle_proof"]["root"])
        );
    }

    /// The schema hashes the light-client types as their own structs do.
    #[test]
    fn nested_schemas_agree_with_the_light_client_types() {
        let state = fixture("mainnet_proof_BeaconState.ssz_snappy");
        let schema = beacon_state(Preset::MAINNET);
        let fields = schema.split(&state).unwrap();
        let roots = schema.field_roots(&state).unwrap();

        let header = BeaconBlockHeader::from_ssz_bytes(fields[state_field::LATEST_BLOCK_HEADER]);
        assert_eq!(header.unwrap().hash_tree_root(), roots[state_field::LATEST_BLOCK_HEADER]);
        let committee = SyncCommittee::from_ssz_bytes(
            fields[state_field::CURRENT_SYNC_COMMITTEE],
            Preset::MAINNET,
        );
        assert_eq!(committee.unwrap().hash_tree_root(), roots[state_field::CURRENT_SYNC_COMMITTEE]);
        let index = state_field::LATEST_EXECUTION_PAYLOAD_HEADER;
        let execution = ExecutionPayloadHeader::from_ssz_bytes(fields[index]);
        assert_eq!(execution.unwrap().hash_tree_root(), roots[index]);

        let body = proof("mainnet_execution_merkle_proof").object;
        let body_schema = beacon_block_body(Preset::MAINNET);
        let aggregate = body_schema.split(&body).unwrap()[body_field::SYNC_AGGREGATE];
        assert_eq!(
            SyncAggregate::from_ssz_bytes(aggregate, Preset::MAINNET).unwrap().hash_tree_root(),
            body_schema.field_roots(&body).unwrap()[body_field::SYNC_AGGREGATE]
        );
    }

    #[test]
    fn the_signed_block_nests_the_block_and_body() {
        let bytes = fixture("minimal_SignedBeaconBlock_case_0.ssz");
        let signed = signed_beacon_block(Preset::MINIMAL);
        let message = signed.split(&bytes).unwrap()[signed_block_field::MESSAGE];
        let block = beacon_block(Preset::MINIMAL);
        let block_fields = block.split(message).unwrap();
        let body_root = beacon_block_body(Preset::MINIMAL)
            .hash_tree_root(block_fields[block_field::BODY])
            .unwrap();
        assert_eq!(block.field_roots(message).unwrap()[block_field::BODY], body_root);
        assert_eq!(
            signed.field_roots(&bytes).unwrap()[signed_block_field::MESSAGE],
            block.hash_tree_root(message).unwrap()
        );
        assert_eq!(block_fields[block_field::SLOT].len(), 8);
        assert_eq!(block_fields[block_field::PARENT_ROOT].len(), 32);
    }

    #[test]
    fn a_state_with_the_wrong_preset_is_refused() {
        let state = fixture("minimal_proof_BeaconState.ssz");
        assert_eq!(
            beacon_state(Preset::MAINNET).field_roots(&state),
            Err(SszError::Truncated { need: state_fixed_len(Preset::MAINNET), got: state.len() })
        );
    }

    #[test]
    fn a_truncated_or_extended_state_is_refused() {
        let state = fixture("minimal_proof_BeaconState.ssz");
        let schema = beacon_state(Preset::MINIMAL);
        let fields = schema.split(&state).unwrap();
        // The fixture's last field, `historical_summaries`, is empty, so its offset is the end.
        assert!(fields[27].is_empty());
        let header_start = state.len() - fields[state_field::LATEST_EXECUTION_PAYLOAD_HEADER].len();
        assert_eq!(
            schema.hash_tree_root(&state[..state.len() - 1]),
            Err(SszError::BadOffset {
                offset: state.len(),
                min: header_start,
                max: state.len() - 1
            })
        );
        // An extra byte lands in `historical_summaries`, a list of 64-byte items.
        let mut extended = state.clone();
        extended.push(0);
        assert_eq!(
            schema.hash_tree_root(&extended),
            Err(SszError::PartialItem { len: 1, item: 64 })
        );
        let fixed = state_fixed_len(Preset::MINIMAL);
        assert_eq!(
            schema.hash_tree_root(&state[..fixed - 1]),
            Err(SszError::Truncated { need: fixed, got: fixed - 1 })
        );
    }

    #[test]
    fn a_state_with_a_bad_first_offset_is_refused() {
        let mut state = fixture("minimal_proof_BeaconState.ssz");
        let fixed = state_fixed_len(Preset::MINIMAL);
        // `historical_roots` is the first variable-size field; its offset is after `state_roots`.
        let at = 8 + 32 + 8 + 16 + 112 + 2 * 64 * 32;
        let offset = u32::from_le_bytes(state[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(offset, fixed);
        state[at..at + 4].copy_from_slice(&(offset as u32 + 1).to_le_bytes());
        assert_eq!(
            beacon_state(Preset::MINIMAL).hash_tree_root(&state),
            Err(SszError::BadOffset { offset: fixed + 1, min: fixed, max: fixed })
        );
    }

    /// The size of a state's fixed part: every fixed-size field, and 4 per offset.
    fn state_fixed_len(preset: Preset) -> usize {
        beacon_state(preset).fields().iter().map(|field| field.fixed_len().unwrap_or(4)).sum()
    }
}
