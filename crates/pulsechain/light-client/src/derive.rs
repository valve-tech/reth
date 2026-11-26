//! Builds the light-client answers from serialized Capella blocks and states.
//!
//! Notation follows the server design: F is a finalized checkpoint block and `state` its
//! post-state, G is the block that `state` has finalized, C is the block that carries the
//! committee's signature over F (F's child), and H is a head block whose signature covers its
//! parent P.
//!
//! [`CheckedState`] hashes a state once and builds every answer that the state backs. Each builder
//! checks what it can see in its inputs and refuses the rest. It does not check a signature: the
//! caller applies the answer to a [`LightClientStore`](crate::sync_committee::LightClientStore)
//! for that. [`CheckedState::check_signature`] checks a signature block on its own, so a caller
//! can tell a block with a bad signature from the answer it would give.

use crate::{
    capella::{
        beacon_block, beacon_block_body, beacon_state, block_field, body_field, payload_field,
        signed_beacon_block, signed_block_field, state_field, CHECKPOINT_ROOT,
    },
    json::{empty_committee, zero_branch},
    ssz_merkle::{container_root, field_branch, offset_count, SszError, SszType},
    sync_committee::{
        has_supermajority, sync_signing_root, BeaconBlockHeader, CommitteeKeys,
        ExecutionPayloadHeader, Gindices, LightClientBootstrap, LightClientHeader,
        LightClientUpdate, Preset, SyncAggregate, SyncCommittee, SyncCommitteeError,
    },
};
use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
use reth_pulsechain_forks::network::{BeaconFork, PulsechainBeacon};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// The most transactions a block may carry here, far under the SSZ limit of 2^20. A
/// transaction costs at least 21,000 gas, so a block at this limit uses 1.38 billion gas, far
/// over any `PulseChain` gas limit. The limit bounds the hash of a hostile block's body.
pub const MAX_TRANSACTIONS: usize = 1 << 16;

/// Why an answer was not built from its inputs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeriveError {
    /// The block bytes are not a Capella `SignedBeaconBlock`.
    #[error("the block is not a Capella SignedBeaconBlock: {0}")]
    Block(SszError),
    /// The state bytes are not a Capella `BeaconState`.
    #[error("the state is not a Capella BeaconState: {0}")]
    State(SszError),
    /// The block carries more than [`MAX_TRANSACTIONS`] transactions.
    #[error("the block carries {count} transactions, more than {max}")]
    TooManyTransactions {
        /// The number of transactions.
        count: usize,
        /// [`MAX_TRANSACTIONS`].
        max: usize,
    },
    /// The block's slot is at a fork whose blocks this crate does not read.
    #[error("the block at slot {slot} is at fork {fork:?}; only Capella blocks are read")]
    UnsupportedFork {
        /// The block's slot.
        slot: u64,
        /// The pinned fork at that slot.
        fork: BeaconFork,
    },
    /// The state's fork version is not the pinned version at its block's slot.
    #[error(
        "the state has fork version {}, not the pinned {}",
        alloy_primitives::hex::encode_prefixed(.version),
        alloy_primitives::hex::encode_prefixed(.pinned)
    )]
    UnknownStateFork {
        /// `state.fork.current_version`.
        version: [u8; 4],
        /// The pinned version at the block's slot.
        pinned: [u8; 4],
    },
    /// The state does not hash to the block's `state_root`.
    #[error("the state has root {state}, not the block's state root {block}")]
    StateRoot {
        /// The block's `state_root`.
        block: B256,
        /// `hash_tree_root` of the state.
        state: B256,
    },
    /// The signature block is not the child of the attested block.
    #[error("the signature block has parent {parent}, not the attested block {attested}")]
    WrongParent {
        /// The signature block's `parent_root`.
        parent: B256,
        /// The attested block's root.
        attested: B256,
    },
    /// The state has finalized another block than the finalized block given.
    #[error("the state has finalized {state}, not the given block {given}")]
    FinalizedRoot {
        /// `state.finalized_checkpoint.root`.
        state: B256,
        /// The given finalized block's root.
        given: B256,
    },
    /// The attested, finalized and signature blocks are not all in one period.
    #[error(
        "the blocks span periods: attested {attested}, finalized {finalized}, signature {signature}"
    )]
    CrossPeriod {
        /// The attested block's period.
        attested: u64,
        /// The finalized block's period.
        finalized: u64,
        /// The signature block's period.
        signature: u64,
    },
    /// Fewer than two thirds of the committee signed, so a client would refuse the update.
    #[error("{participants} of {size} sync committee members signed; at least two thirds must")]
    TooFewParticipants {
        /// The number of set participation bits.
        participants: usize,
        /// `SYNC_COMMITTEE_SIZE`.
        size: usize,
    },
    /// A sync committee in the state has a key that is not a valid BLS public key.
    #[error("the state's sync committee: {0}")]
    Committee(SyncCommitteeError),
}

/// A Capella block reduced to what the light-client answers use: its light-client header and its
/// sync aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientBlock {
    header: LightClientHeader,
    sync_aggregate: SyncAggregate,
}

impl LightClientBlock {
    /// Reads a serialized `SignedBeaconBlock` at a slot whose pinned fork is Capella.
    ///
    /// It hashes the body for the body root and the execution branch (gindex 25), and builds the
    /// execution payload header from the payload. It does not check the proposer's signature.
    pub fn from_ssz_bytes(
        bytes: &[u8],
        preset: Preset,
        beacon: &PulsechainBeacon,
    ) -> Result<Self, DeriveError> {
        let signed = signed_beacon_block(preset).split(bytes).map_err(DeriveError::Block)?;
        let block = beacon_block(preset).split(signed[signed_block_field::MESSAGE]);
        let block = block.map_err(DeriveError::Block)?;
        // The slot comes first, so a block of another fork is named before its body is read.
        let slot = read_u64(block[block_field::SLOT]);
        let fork = beacon.fork_at_epoch(preset.epoch_at_slot(slot)).fork;
        if fork != BeaconFork::Capella {
            return Err(DeriveError::UnsupportedFork { slot, fork });
        }

        let body_schema = beacon_block_body(preset);
        let body = body_schema.split(block[block_field::BODY]).map_err(DeriveError::Block)?;
        let SszType::Container(payload_schema) =
            &body_schema.fields()[body_field::EXECUTION_PAYLOAD]
        else {
            unreachable!("the Capella execution payload is a container")
        };
        let payload_bytes = body[body_field::EXECUTION_PAYLOAD];
        let payload = payload_schema.split(payload_bytes).map_err(DeriveError::Block)?;
        let count =
            offset_count(payload[payload_field::TRANSACTIONS]).map_err(DeriveError::Block)?;
        if count > MAX_TRANSACTIONS {
            return Err(DeriveError::TooManyTransactions { count, max: MAX_TRANSACTIONS });
        }
        let payload_roots =
            payload_schema.field_roots(payload_bytes).map_err(DeriveError::Block)?;
        // The payload is hashed once, for its field roots, and not again as a body field.
        let body_roots = body_schema
            .fields()
            .iter()
            .zip(&body)
            .enumerate()
            .map(|(index, (ty, field))| {
                if index == body_field::EXECUTION_PAYLOAD {
                    Ok(container_root(&payload_roots))
                } else {
                    ty.hash_tree_root(field)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(DeriveError::Block)?;

        // The header's fields are the payload's, with the two lists replaced by their roots.
        let execution = ExecutionPayloadHeader {
            parent_hash: B256::from_slice(payload[0]),
            fee_recipient: Address::from_slice(payload[1]),
            state_root: B256::from_slice(payload[2]),
            receipts_root: B256::from_slice(payload[3]),
            logs_bloom: Bloom::from_slice(payload[4]),
            prev_randao: B256::from_slice(payload[5]),
            block_number: read_u64(payload[6]),
            gas_limit: read_u64(payload[7]),
            gas_used: read_u64(payload[8]),
            timestamp: read_u64(payload[9]),
            extra_data: Bytes::copy_from_slice(payload[10]),
            base_fee_per_gas: U256::from_le_slice(payload[11]),
            block_hash: B256::from_slice(payload[12]),
            transactions_root: payload_roots[payload_field::TRANSACTIONS],
            withdrawals_root: payload_roots[14],
        };
        let header = LightClientHeader {
            beacon: BeaconBlockHeader {
                slot,
                proposer_index: read_u64(block[block_field::PROPOSER_INDEX]),
                parent_root: B256::from_slice(block[block_field::PARENT_ROOT]),
                state_root: B256::from_slice(block[block_field::STATE_ROOT]),
                body_root: container_root(&body_roots),
            },
            execution,
            execution_branch: field_branch(&body_roots, body_field::EXECUTION_PAYLOAD)
                .try_into()
                .expect("the Capella body's 11 fields make a tree of depth 4"),
        };
        let sync_aggregate =
            SyncAggregate::from_ssz_bytes(body[body_field::SYNC_AGGREGATE], preset)
                .expect("the body schema has checked the aggregate's length");
        Ok(Self { header, sync_aggregate })
    }

    /// Returns the light-client header: `LCH` in the design.
    pub const fn header(&self) -> &LightClientHeader {
        &self.header
    }

    /// Returns the block's sync aggregate, which signs its parent's root.
    pub const fn sync_aggregate(&self) -> &SyncAggregate {
        &self.sync_aggregate
    }

    /// Returns the block's slot.
    pub const fn slot(&self) -> u64 {
        self.header.beacon.slot
    }

    /// Returns the block root, `hash_tree_root` of its `BeaconBlock`.
    pub fn root(&self) -> B256 {
        self.header.beacon.hash_tree_root()
    }
}

/// A block's post-state, checked and hashed once. It keeps the parts of the state that the
/// answers use, so it gives every answer that the state backs from one hash, and outlives the
/// state's bytes.
pub struct CheckedState {
    preset: Preset,
    block: LightClientBlock,
    /// `current_sync_committee` and its branch (gindex 54).
    current: (SyncCommittee, Vec<B256>),
    /// `next_sync_committee` and its branch (gindex 55).
    next: (SyncCommittee, Vec<B256>),
    /// The keys of the current and the next committee, checked once.
    keys: [CommitteeKeys; 2],
    /// `finalized_checkpoint.root` and its branch (gindex 105).
    finalized: (B256, Vec<B256>),
}

impl std::fmt::Debug for CheckedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The committees are 1,024 keys: show the block slot only.
        f.debug_struct("CheckedState").field("slot", &self.block.slot()).finish_non_exhaustive()
    }
}

impl CheckedState {
    /// Hashes `state` and checks that it is `block`'s post-state at the pinned fork version.
    pub fn new(
        preset: Preset,
        beacon: &PulsechainBeacon,
        block: &LightClientBlock,
        state: &[u8],
    ) -> Result<Self, DeriveError> {
        let schema = beacon_state(preset);
        let fields = schema.split(state).map_err(DeriveError::State)?;
        // Every fork's state has the same fields, so the version is read before the hash, which
        // a later fork's state fails.
        let version: [u8; 4] = fields[state_field::FORK][4..8].try_into().expect("4 bytes");
        let pinned = beacon.fork_at_epoch(preset.epoch_at_slot(block.slot())).version;
        if version != pinned {
            return Err(DeriveError::UnknownStateFork { version, pinned });
        }
        let roots = schema.field_roots(state).map_err(DeriveError::State)?;
        let root = container_root(&roots);
        let block_state_root = block.header.beacon.state_root;
        if root != block_state_root {
            return Err(DeriveError::StateRoot { block: block_state_root, state: root });
        }
        let committee = |index| {
            let committee = SyncCommittee::from_ssz_bytes(fields[index], preset)
                .expect("the state schema has checked the committee's length");
            (committee, field_branch(&roots, index))
        };
        let SszType::Container(checkpoint) = &schema.fields()[state_field::FINALIZED_CHECKPOINT]
        else {
            unreachable!("the checkpoint is a container")
        };
        let checkpoint_roots = checkpoint
            .field_roots(fields[state_field::FINALIZED_CHECKPOINT])
            .expect("the state's field roots include the checkpoint's");
        // The checkpoint's own branch, then the state's.
        let mut finality_branch = field_branch(&checkpoint_roots, CHECKPOINT_ROOT);
        finality_branch.extend(field_branch(&roots, state_field::FINALIZED_CHECKPOINT));
        let (current, next) = (
            committee(state_field::CURRENT_SYNC_COMMITTEE),
            committee(state_field::NEXT_SYNC_COMMITTEE),
        );
        let keys = |(committee, _): &(SyncCommittee, _)| {
            CommitteeKeys::new(committee.clone()).map_err(DeriveError::Committee)
        };
        Ok(Self {
            preset,
            block: block.clone(),
            keys: [keys(&current)?, keys(&next)?],
            current,
            next,
            finalized: (checkpoint_roots[CHECKPOINT_ROOT], finality_branch),
        })
    }

    /// Checks the aggregate of `signature` over the state's block, with the state's committee
    /// of `signature`'s period: the current one in the block's period, the next one in the
    /// period after. It checks neither the parent nor the participation.
    pub fn check_signature(
        &self,
        beacon: &PulsechainBeacon,
        signature: &LightClientBlock,
    ) -> Result<(), SyncCommitteeError> {
        let store_period = self.preset.period_at_slot(self.block.slot());
        let signature_period = self.preset.period_at_slot(signature.slot());
        let keys = match signature_period.checked_sub(store_period) {
            Some(0) => &self.keys[0],
            Some(1) => &self.keys[1],
            _ => {
                return Err(SyncCommitteeError::SignaturePeriod {
                    signature_period,
                    store_period,
                    next_known: true,
                })
            }
        };
        keys.verify(
            &signature.sync_aggregate,
            sync_signing_root(self.preset, beacon, self.block.root(), signature.slot()),
        )
    }

    /// Returns the block whose post-state this is.
    pub const fn block(&self) -> &LightClientBlock {
        &self.block
    }

    /// Returns `finalized_checkpoint.root`: the root of G, the block that the state has
    /// finalized.
    pub const fn finalized_root(&self) -> B256 {
        self.finalized.0
    }

    /// Builds the `bootstrap` at the state's block.
    pub fn bootstrap(&self) -> LightClientBootstrap {
        let (current_sync_committee, current_sync_committee_branch) = self.current.clone();
        LightClientBootstrap {
            header: self.block.header.clone(),
            current_sync_committee,
            current_sync_committee_branch,
        }
    }

    /// Builds the `finality_update` that `signature` signs over the state's block, which is the
    /// attested block. `finalized` must be the block that the state has finalized.
    ///
    /// The blocks may span periods, as at the start of a period, when the finalized block is
    /// still in the period before. The update has no next committee.
    pub fn finality_update(
        &self,
        finalized: &LightClientBlock,
        signature: &LightClientBlock,
    ) -> Result<LightClientUpdate, DeriveError> {
        let mut update = optimistic_update(self.preset, &self.block, signature)?;
        let (finalized_root, finality_branch) = &self.finalized;
        let given = finalized.root();
        if *finalized_root != given {
            return Err(DeriveError::FinalizedRoot { state: *finalized_root, given });
        }
        update.finalized_header = finalized.header.clone();
        update.finality_branch = finality_branch.clone();
        Ok(update)
    }

    /// Builds the period's `updates` entry: [`Self::finality_update`] with the state's next
    /// committee.
    ///
    /// The three blocks must share one period: a store applies the next committee only with a
    /// finalized header in the attested period, and the committee signs only in its own period.
    pub fn period_update(
        &self,
        finalized: &LightClientBlock,
        signature: &LightClientBlock,
    ) -> Result<LightClientUpdate, DeriveError> {
        let mut update = self.finality_update(finalized, signature)?;
        let [attested_period, finalized_period, signature_period] =
            [&self.block, finalized, signature]
                .map(|block| self.preset.period_at_slot(block.slot()));
        if attested_period != finalized_period || attested_period != signature_period {
            return Err(DeriveError::CrossPeriod {
                attested: attested_period,
                finalized: finalized_period,
                signature: signature_period,
            });
        }
        (update.next_sync_committee, update.next_sync_committee_branch) = self.next.clone();
        Ok(update)
    }
}

/// Builds the `optimistic_update` that `signature` signs over its parent `attested`.
pub fn optimistic_update(
    preset: Preset,
    attested: &LightClientBlock,
    signature: &LightClientBlock,
) -> Result<LightClientUpdate, DeriveError> {
    let parent = signature.header.beacon.parent_root;
    let root = attested.root();
    if parent != root {
        return Err(DeriveError::WrongParent { parent, attested: root });
    }
    let participants = signature.sync_aggregate.participants();
    let size = preset.sync_committee_size();
    if !has_supermajority(participants, size) {
        return Err(DeriveError::TooFewParticipants { participants, size });
    }
    let gindices = Gindices::for_fork(BeaconFork::Capella).expect("Capella has light-client types");
    Ok(LightClientUpdate {
        attested_header: attested.header.clone(),
        next_sync_committee: empty_committee(preset),
        next_sync_committee_branch: zero_branch(gindices.next_sync_committee),
        finalized_header: LightClientHeader::default(),
        finality_branch: zero_branch(gindices.finalized_root),
        sync_aggregate: signature.sync_aggregate.clone(),
        signature_slot: signature.slot(),
    })
}

/// Reads a `uint64` whose length the schema has checked.
fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("the schema has checked a uint64's length"))
}

#[cfg(test)]
mod tests {
    use super::{
        test_utils::{self, keys, state_root, synthetic_pins},
        *,
    };
    use crate::{
        json::{bootstrap_json, parse_bootstrap, parse_update, update_json, UpdateKind},
        sync_committee::{
            test_utils::{hash, repeated_committee, Real369},
            LightClientStore, SyncCommitteeError,
        },
    };
    use blst::{min_pk::SecretKey, BLST_ERROR};
    use reth_pulsechain_forks::network::pulsechain_network;
    use ssz::{Decode, Encode};

    const REAL_369_BLOCK: &[u8] = include_bytes!("../testdata/sync_committee/real_369_block.ssz");

    fn pins_369() -> PulsechainBeacon {
        pulsechain_network(369).unwrap().beacon
    }

    /// The real 369 block gives the header, the execution header and the branch that the
    /// checkpoint's state and JSON block gave.
    #[test]
    fn the_real_369_block_gives_its_light_client_header() {
        let real = Real369::load();
        let block =
            LightClientBlock::from_ssz_bytes(REAL_369_BLOCK, Preset::PULSECHAIN, &pins_369())
                .unwrap();
        assert_eq!(block.root(), hash(&real.json["block_root"]));
        assert_eq!(block.header().beacon, real.header);
        assert_eq!(block.header().execution_branch.to_vec(), real.branch("execution_branch"));
        assert_eq!(
            block.header().execution.hash_tree_root(),
            hash(&real.json["execution_payload_header_root"])
        );
        assert_eq!(block.header(), &real.light_client_header());
        assert_eq!(block.sync_aggregate(), &real.aggregate);
        assert_eq!(block.sync_aggregate().participants(), 495);
        assert_eq!(block.header().validate(BeaconFork::Capella), Ok(()));
    }

    #[test]
    fn a_damaged_block_is_refused() {
        let truncated = &REAL_369_BLOCK[..REAL_369_BLOCK.len() - 1];
        assert!(matches!(
            LightClientBlock::from_ssz_bytes(truncated, Preset::PULSECHAIN, &pins_369()),
            Err(DeriveError::Block(_))
        ));
    }

    /// The real block's slot is before Capella under pins that schedule Capella later.
    #[test]
    fn a_block_before_capella_is_refused() {
        let mut pins = pins_369();
        pins.forks[3].epoch = u64::MAX;
        assert_eq!(
            LightClientBlock::from_ssz_bytes(REAL_369_BLOCK, Preset::PULSECHAIN, &pins),
            Err(DeriveError::UnsupportedFork { slot: 11_167_808, fork: BeaconFork::Bellatrix })
        );
    }

    /// A list of `count` empty transactions: the offsets alone, each at the end of the list.
    fn empty_transactions(count: usize) -> Vec<u8> {
        let end = u32::try_from(count * 4).unwrap();
        std::iter::repeat_n(end.to_le_bytes(), count).flatten().collect()
    }

    /// A block with more transactions than a block can carry is refused before its body is
    /// hashed; one at the limit reads.
    #[test]
    fn a_block_with_too_many_transactions_is_refused() {
        let block = |count| {
            let bytes = test_utils::block_ssz_with_transactions(
                PRESET,
                SLOT_B,
                B256::ZERO,
                B256::ZERO,
                &test_utils::unsigned(PRESET),
                &empty_transactions(count),
            );
            LightClientBlock::from_ssz_bytes(&bytes, PRESET, &pins())
        };
        assert_eq!(
            block(MAX_TRANSACTIONS + 1),
            Err(DeriveError::TooManyTransactions {
                count: MAX_TRANSACTIONS + 1,
                max: MAX_TRANSACTIONS
            })
        );
        assert_eq!(block(MAX_TRANSACTIONS).map(|block| block.slot()), Ok(SLOT_B));
    }

    // A synthetic minimal-preset chain in period 1 (slots 64 to 127): B is the bootstrap block,
    // G is finalized by F's state, C signs F, and H signs C.
    const SLOT_B: u64 = 72;
    const SLOT_G: u64 = 80;
    const SLOT_F: u64 = 96;
    const SLOT_C: u64 = 97;
    const SLOT_H: u64 = 98;
    const CURRENT_SLOT: u64 = 127;
    const PRESET: Preset = Preset::MINIMAL;
    const SIZE: usize = 32;

    fn pins() -> PulsechainBeacon {
        synthetic_pins()
    }

    fn state_ssz(
        slot: u64,
        finalized: B256,
        current: &SyncCommittee,
        next: &SyncCommittee,
    ) -> Vec<u8> {
        test_utils::state_ssz(
            PRESET,
            &pins(),
            slot,
            PRESET.epoch_at_slot(SLOT_G),
            finalized,
            current,
            next,
        )
    }

    fn block_ssz(slot: u64, parent: B256, state_root: B256, aggregate: &SyncAggregate) -> Vec<u8> {
        test_utils::block_ssz(PRESET, slot, parent, state_root, aggregate)
    }

    fn read(bytes: &[u8]) -> LightClientBlock {
        LightClientBlock::from_ssz_bytes(bytes, PRESET, &pins()).unwrap()
    }

    fn sign(keys: &[SecretKey], participants: usize, root: B256, slot: u64) -> SyncAggregate {
        test_utils::sign(PRESET, &pins(), keys, participants, root, slot)
    }

    fn unsigned() -> SyncAggregate {
        test_utils::unsigned(PRESET)
    }

    struct Chain {
        keys: Vec<SecretKey>,
        current: SyncCommittee,
        next: SyncCommittee,
        b: LightClientBlock,
        state_b: Vec<u8>,
        g: LightClientBlock,
        f: LightClientBlock,
        state_f: Vec<u8>,
        c: LightClientBlock,
        h: LightClientBlock,
    }

    impl Chain {
        fn state_f(&self) -> CheckedState {
            CheckedState::new(PRESET, &pins(), &self.f, &self.state_f).unwrap()
        }
    }

    fn chain_with(participants: usize) -> Chain {
        let keys = keys(1);
        let current = repeated_committee(&keys, SIZE);
        let next = repeated_committee(&self::keys(9), SIZE);
        let state_b = state_ssz(SLOT_B, B256::ZERO, &current, &next);
        let b = read(&block_ssz(
            SLOT_B,
            B256::repeat_byte(1),
            state_root(PRESET, &state_b),
            &unsigned(),
        ));
        let g = read(&block_ssz(SLOT_G, b.root(), B256::repeat_byte(2), &unsigned()));
        let state_f = state_ssz(SLOT_F, g.root(), &current, &next);
        let f = read(&block_ssz(SLOT_F, g.root(), state_root(PRESET, &state_f), &unsigned()));
        let c_aggregate = sign(&keys, participants, f.root(), SLOT_C);
        let c = read(&block_ssz(SLOT_C, f.root(), B256::repeat_byte(3), &c_aggregate));
        let h_aggregate = sign(&keys, participants, c.root(), SLOT_H);
        let h = read(&block_ssz(SLOT_H, c.root(), B256::repeat_byte(4), &h_aggregate));
        Chain { keys, current, next, b, state_b, g, f, state_f, c, h }
    }

    fn chain() -> Chain {
        chain_with(24)
    }

    /// The state checks a block's aggregate over the state's block with its committee of the
    /// block's period: the current one in the state's period and the next one in the period
    /// after. Other keys, another signed root and a later period are refused.
    #[test]
    fn the_state_checks_a_signature_over_its_block() {
        let chain = chain();
        let state_f = chain.state_f();
        let signed = |keys: &[SecretKey], root, slot| {
            read(&block_ssz(
                slot,
                chain.f.root(),
                B256::repeat_byte(3),
                &sign(keys, 24, root, slot),
            ))
        };
        assert_eq!(state_f.check_signature(&pins(), &chain.c), Ok(()));
        for block in [
            signed(&keys(5), chain.f.root(), SLOT_C),
            signed(&chain.keys, chain.c.root(), SLOT_C),
            signed(&chain.keys, chain.f.root(), 128),
        ] {
            assert!(
                matches!(
                    state_f.check_signature(&pins(), &block),
                    Err(SyncCommitteeError::Signature(_))
                ),
                "slot {}",
                block.slot()
            );
        }
        assert_eq!(
            state_f.check_signature(&pins(), &signed(&keys(9), chain.f.root(), 128)),
            Ok(())
        );
        assert_eq!(
            state_f.check_signature(&pins(), &signed(&keys(9), chain.f.root(), 192)),
            Err(SyncCommitteeError::SignaturePeriod {
                signature_period: 3,
                store_period: 1,
                next_known: true
            })
        );
    }

    /// Writes `update` as JSON of `kind`, reads it back as reth-lite does, and checks that the
    /// read gives the same update.
    fn through_json(update: &LightClientUpdate, kind: UpdateKind) -> LightClientUpdate {
        let json = update_json(update, BeaconFork::Capella, kind).unwrap().to_string();
        let parsed = parse_update(json.as_bytes(), PRESET, kind).unwrap();
        assert_eq!(&parsed, update);
        parsed
    }

    /// Every answer goes through the JSON writer and reader into a store, which accepts it.
    #[test]
    fn a_synthetic_chain_gives_answers_the_store_accepts() {
        let chain = chain();
        let beacon = pins();
        for block in [&chain.b, &chain.g, &chain.f, &chain.c, &chain.h] {
            assert_eq!(block.header().validate(BeaconFork::Capella), Ok(()));
        }

        let built =
            CheckedState::new(PRESET, &beacon, &chain.b, &chain.state_b).unwrap().bootstrap();
        assert_eq!(built.header, *chain.b.header());
        assert_eq!(built.current_sync_committee, chain.current);
        let json = bootstrap_json(&built, BeaconFork::Capella).unwrap().to_string();
        let parsed = parse_bootstrap(json.as_bytes(), PRESET).unwrap();
        assert_eq!(parsed, built);
        let mut store =
            LightClientStore::bootstrap(PRESET, beacon, chain.b.root(), &parsed).unwrap();

        let state_f = chain.state_f();
        assert_eq!(state_f.finalized_root(), chain.g.root());
        let finality = state_f.finality_update(&chain.g, &chain.c).unwrap();
        assert_eq!(finality.attested_header, *chain.f.header());
        assert_eq!(finality.finalized_header, *chain.g.header());
        assert_eq!(finality.signature_slot, SLOT_C);
        assert!(finality.is_finality_update());
        assert!(!finality.is_sync_committee_update());
        store.process_update(&through_json(&finality, UpdateKind::Finality), CURRENT_SLOT).unwrap();
        assert_eq!(store.finalized_header(), chain.g.header());
        assert_eq!(store.next_sync_committee(), None);

        let period = state_f.period_update(&chain.g, &chain.c).unwrap();
        assert_eq!(period.next_sync_committee, chain.next);
        store.process_update(&through_json(&period, UpdateKind::Full), CURRENT_SLOT).unwrap();
        assert_eq!(store.next_sync_committee(), Some(&chain.next));

        let optimistic = optimistic_update(PRESET, &chain.c, &chain.h).unwrap();
        assert_eq!(optimistic.attested_header, *chain.c.header());
        assert_eq!(optimistic.signature_slot, SLOT_H);
        assert!(!optimistic.is_finality_update());
        store
            .process_update(&through_json(&optimistic, UpdateKind::Optimistic), CURRENT_SLOT)
            .unwrap();
        assert_eq!(store.optimistic_header(), chain.c.header());
        assert_eq!(store.finalized_header(), chain.g.header());

        // The store's own check: another committee's signature does not verify.
        let forged = read(&block_ssz(
            SLOT_H,
            chain.c.root(),
            B256::repeat_byte(4),
            &sign(&keys(9), 24, chain.c.root(), SLOT_H),
        ));
        let update = optimistic_update(PRESET, &chain.c, &forged).unwrap();
        assert_eq!(
            store.validate_update(&update, CURRENT_SLOT),
            Err(SyncCommitteeError::Signature(BLST_ERROR::BLST_VERIFY_FAIL))
        );
    }

    #[test]
    fn a_state_of_another_block_is_refused() {
        let chain = chain();
        let want = DeriveError::StateRoot {
            block: chain.f.header().beacon.state_root,
            state: state_root(PRESET, &chain.state_b),
        };
        assert_eq!(CheckedState::new(PRESET, &pins(), &chain.f, &chain.state_b).unwrap_err(), want);
    }

    #[test]
    fn a_damaged_state_is_refused() {
        let chain = chain();
        let truncated = &chain.state_f[..chain.state_f.len() - 1];
        assert!(matches!(
            CheckedState::new(PRESET, &pins(), &chain.f, truncated),
            Err(DeriveError::State(_))
        ));
    }

    #[test]
    fn a_state_that_finalized_another_block_is_refused() {
        let chain = chain();
        assert_eq!(
            chain.state_f().finality_update(&chain.b, &chain.c),
            Err(DeriveError::FinalizedRoot { state: chain.g.root(), given: chain.b.root() })
        );
    }

    #[test]
    fn a_signature_block_that_is_not_the_child_is_refused() {
        let chain = chain();
        let want =
            Err(DeriveError::WrongParent { parent: chain.c.root(), attested: chain.f.root() });
        assert_eq!(chain.state_f().finality_update(&chain.g, &chain.h), want);
        assert_eq!(chain.state_f().period_update(&chain.g, &chain.h), want);
        assert_eq!(optimistic_update(PRESET, &chain.f, &chain.h), want);
    }

    /// F is in the next period, and G a period behind. The finality update is valid, and a
    /// store that knows the next committee takes its finalized header from it. The period update
    /// needs all three blocks in one period.
    #[test]
    fn a_finalized_block_a_period_behind_gives_only_a_finality_update() {
        let chain = chain();
        let beacon = pins();
        let next_period = 2 * 64;
        let g = read(&block_ssz(112, chain.f.root(), B256::repeat_byte(5), &unsigned()));
        let state = state_ssz(next_period, g.root(), &chain.next, &chain.next);
        let f = read(&block_ssz(next_period, g.root(), state_root(PRESET, &state), &unsigned()));
        let c_aggregate = sign(&keys(9), 24, f.root(), next_period + 1);
        let c = read(&block_ssz(next_period + 1, f.root(), B256::repeat_byte(3), &c_aggregate));
        let checked = CheckedState::new(PRESET, &beacon, &f, &state).unwrap();
        assert_eq!(
            checked.period_update(&g, &c),
            Err(DeriveError::CrossPeriod { attested: 2, finalized: 1, signature: 2 })
        );
        let finality = checked.finality_update(&g, &c).unwrap();
        assert_eq!(finality.finalized_header, *g.header());

        let bootstrap =
            CheckedState::new(PRESET, &beacon, &chain.b, &chain.state_b).unwrap().bootstrap();
        let mut store =
            LightClientStore::bootstrap(PRESET, beacon, chain.b.root(), &bootstrap).unwrap();
        let period = chain.state_f().period_update(&chain.g, &chain.c).unwrap();
        store.process_update(&period, CURRENT_SLOT).unwrap();
        store
            .process_update(&through_json(&finality, UpdateKind::Finality), next_period + 1)
            .unwrap();
        assert_eq!(store.finalized_header(), g.header());
        assert_eq!(store.period(), 1);

        // The signature alone in the next period.
        let last = 2 * 64 - 1;
        let state = state_ssz(last, chain.g.root(), &chain.current, &chain.next);
        let f = read(&block_ssz(last, chain.g.root(), state_root(PRESET, &state), &unsigned()));
        let c_aggregate = sign(&chain.keys, 24, f.root(), last + 1);
        let c = read(&block_ssz(last + 1, f.root(), B256::repeat_byte(3), &c_aggregate));
        let checked = CheckedState::new(PRESET, &beacon, &f, &state).unwrap();
        assert_eq!(
            checked.period_update(&chain.g, &c),
            Err(DeriveError::CrossPeriod { attested: 1, finalized: 1, signature: 2 })
        );
        assert_eq!(
            checked.finality_update(&chain.g, &c).map(|update| update.signature_slot),
            Ok(last + 1)
        );
    }

    /// 22 of 32 is two thirds; 21 is not.
    #[test]
    fn low_participation_is_refused() {
        let chain = chain_with(22);
        optimistic_update(PRESET, &chain.c, &chain.h).unwrap();
        chain.state_f().finality_update(&chain.g, &chain.c).unwrap();

        let chain = chain_with(21);
        let want = Err(DeriveError::TooFewParticipants { participants: 21, size: SIZE });
        assert_eq!(optimistic_update(PRESET, &chain.c, &chain.h), want);
        assert_eq!(chain.state_f().finality_update(&chain.g, &chain.c), want);
        assert_eq!(chain.state_f().period_update(&chain.g, &chain.c), want);
    }

    /// The `PulseChain` bar is 342 of 512.
    #[test]
    fn the_pulsechain_bar_is_342_signers() {
        assert!(has_supermajority(342, Preset::PULSECHAIN.sync_committee_size()));
        assert!(!has_supermajority(341, Preset::PULSECHAIN.sync_committee_size()));
    }

    /// A synthetic block whose slot the pins put before Capella.
    #[test]
    fn a_synthetic_block_before_capella_is_refused() {
        let mut beacon = pins();
        beacon.forks[3].epoch = PRESET.epoch_at_slot(SLOT_H) + 1;
        let bytes = block_ssz(SLOT_H, B256::ZERO, B256::ZERO, &unsigned());
        assert_eq!(
            LightClientBlock::from_ssz_bytes(&bytes, PRESET, &beacon),
            Err(DeriveError::UnsupportedFork { slot: SLOT_H, fork: BeaconFork::Bellatrix })
        );
    }

    /// A state whose fork version the pins do not have at its slot, as a later fork's would.
    #[test]
    fn a_state_at_an_unknown_fork_is_refused() {
        let chain = chain();
        let mut beacon = pins();
        beacon.forks[3].version = [4, 0, 0, 1];
        assert_eq!(
            CheckedState::new(PRESET, &beacon, &chain.f, &chain.state_f).unwrap_err(),
            DeriveError::UnknownStateFork { version: [3, 0, 0, 1], pinned: [4, 0, 0, 1] }
        );
    }

    #[test]
    fn the_test_state_and_block_fit_the_spec_types() {
        let chain = chain();
        let fields = beacon_state(PRESET).split(&chain.state_f).unwrap();
        let header = ExecutionPayloadHeader::from_ssz_bytes(
            fields[state_field::LATEST_EXECUTION_PAYLOAD_HEADER],
        );
        assert_eq!(header, Ok(ExecutionPayloadHeader::default()));
        assert_eq!(chain.f.header().execution.block_number, SLOT_F + 1000);
        assert_eq!(chain.f.header().execution.extra_data, Bytes::from_static(b"lc"));
        assert_eq!(
            BeaconBlockHeader::from_ssz_bytes(&chain.f.header().beacon.as_ssz_bytes()),
            Ok(chain.f.header().beacon)
        );
    }
}
