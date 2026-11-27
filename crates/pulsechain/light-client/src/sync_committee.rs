//! The light-client sync protocol's Capella types, Merkle checks and store, with no I/O.
//!
//! This module follows the consensus specs' `altair/light-client/sync-protocol.md` and
//! `capella/light-client/sync-protocol.md`. It takes the preset and the fork schedule as
//! parameters, so the spec tests run against the same code as `PulseChain`.

use crate::ssz_merkle::container_root;
use alloy_primitives::{Address, Bloom, Bytes, FixedBytes, B256, U256};
use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};
use reth_pulsechain_forks::network::{BeaconFork, PulsechainBeacon};
use sha2::{Digest, Sha256};
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};
use tree_hash::{merkle_root, mix_in_length, TreeHash};

/// The SSZ limit of `ExecutionPayloadHeader.extra_data` (`MAX_EXTRA_DATA_BYTES`).
const MAX_EXTRA_DATA_BYTES: usize = 32;

/// The depth of `EXECUTION_PAYLOAD_GINDEX`, which is the length of an execution branch.
pub const EXECUTION_BRANCH_DEPTH: usize = 4;

/// `DOMAIN_SYNC_COMMITTEE`, the domain type of sync-committee signatures.
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

/// The BLS ciphersuite of the consensus specs: proof of possession, signatures in G2.
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The preset values the sync protocol depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    /// `SYNC_COMMITTEE_SIZE`. A multiple of 8, so its bitvector has no padding bits.
    pub(crate) sync_committee_size: usize,
    /// `SLOTS_PER_EPOCH`.
    pub(crate) slots_per_epoch: u64,
    /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
    pub(crate) epochs_per_sync_committee_period: u64,
    /// `SLOTS_PER_HISTORICAL_ROOT`, the length of the state's block and state root vectors.
    pub(crate) slots_per_historical_root: usize,
    /// `EPOCHS_PER_HISTORICAL_VECTOR`, the length of the state's RANDAO mixes.
    pub(crate) epochs_per_historical_vector: usize,
    /// `EPOCHS_PER_SLASHINGS_VECTOR`, the length of the state's slashings.
    pub(crate) epochs_per_slashings_vector: usize,
    /// `EPOCHS_PER_ETH1_VOTING_PERIOD`.
    pub(crate) epochs_per_eth1_voting_period: u64,
    /// `MAX_WITHDRAWALS_PER_PAYLOAD`.
    pub(crate) max_withdrawals_per_payload: u64,
}

impl Preset {
    /// The lighthouse-pulse `pulsechain` preset. Its SSZ sizes are the mainnet ones.
    pub const PULSECHAIN: Self = Self::MAINNET;

    /// The consensus specs' `mainnet` preset.
    pub const MAINNET: Self = Self {
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        slots_per_historical_root: 8192,
        epochs_per_historical_vector: 65536,
        epochs_per_slashings_vector: 8192,
        epochs_per_eth1_voting_period: 64,
        max_withdrawals_per_payload: 16,
    };

    /// The consensus specs' `minimal` preset, which the `light_client/sync` spec tests use.
    pub const MINIMAL: Self = Self {
        sync_committee_size: 32,
        slots_per_epoch: 8,
        epochs_per_sync_committee_period: 8,
        slots_per_historical_root: 64,
        epochs_per_historical_vector: 64,
        epochs_per_slashings_vector: 64,
        epochs_per_eth1_voting_period: 4,
        max_withdrawals_per_payload: 4,
    };

    /// Returns `SYNC_COMMITTEE_SIZE`.
    pub const fn sync_committee_size(&self) -> usize {
        self.sync_committee_size
    }

    /// Returns `SLOTS_PER_EPOCH`.
    pub const fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    /// Returns `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
    pub const fn epochs_per_sync_committee_period(&self) -> u64 {
        self.epochs_per_sync_committee_period
    }

    /// Returns the epoch of `slot`.
    pub const fn epoch_at_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Returns the sync-committee period of `slot`.
    pub const fn period_at_slot(&self, slot: u64) -> u64 {
        self.epoch_at_slot(slot) / self.epochs_per_sync_committee_period
    }
}

/// The generalized indices of the light-client proofs at one fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gindices {
    /// `FINALIZED_ROOT_GINDEX`: `finalized_checkpoint.root` in the `BeaconState`.
    pub finalized_root: u64,
    /// `CURRENT_SYNC_COMMITTEE_GINDEX`: `current_sync_committee` in the `BeaconState`.
    pub current_sync_committee: u64,
    /// `NEXT_SYNC_COMMITTEE_GINDEX`: `next_sync_committee` in the `BeaconState`.
    pub next_sync_committee: u64,
    /// `EXECUTION_PAYLOAD_GINDEX`: `execution_payload` in the `BeaconBlockBody`. It is `None`
    /// before Capella, whose light-client headers have no execution part.
    pub execution_payload: Option<u64>,
}

impl Gindices {
    /// The Altair indices. Bellatrix uses the Altair light-client types.
    const ALTAIR: Self = Self {
        finalized_root: 105,
        current_sync_committee: 54,
        next_sync_committee: 55,
        execution_payload: None,
    };

    /// The Capella indices.
    const CAPELLA: Self = Self { execution_payload: Some(25), ..Self::ALTAIR };

    /// Returns the indices for a light-client header at `fork`, or `None` for `Phase0`, which
    /// has no sync committee.
    ///
    /// A new fork in [`BeaconFork`] does not compile here until it gets its own entry.
    pub const fn for_fork(fork: BeaconFork) -> Option<Self> {
        match fork {
            BeaconFork::Phase0 => None,
            BeaconFork::Altair | BeaconFork::Bellatrix => Some(Self::ALTAIR),
            BeaconFork::Capella => Some(Self::CAPELLA),
        }
    }

    /// Returns the indices for `fork`, or [`SyncCommitteeError::UnsupportedFork`].
    fn require(fork: BeaconFork) -> Result<Self, SyncCommitteeError> {
        Self::for_fork(fork).ok_or(SyncCommitteeError::UnsupportedFork(fork))
    }
}

/// A sync-committee check that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncCommitteeError {
    /// The fork has no light-client types.
    #[error("fork {0:?} has no sync committee, so it has no light-client data")]
    UnsupportedFork(BeaconFork),
    /// No fork in the pinned schedule has this fork digest.
    #[error("fork digest {} matches no fork version in the pinned schedule", alloy_primitives::hex::encode_prefixed(.0))]
    UnknownForkDigest([u8; 4]),
    /// The execution branch does not prove the execution payload header into the body root.
    #[error("the execution branch does not prove the execution payload header into body root {0}")]
    ExecutionBranch(B256),
    /// A header before Capella carries an execution part.
    #[error("the light-client header at slot {0} is before Capella but has an execution part")]
    ExecutionBeforeCapella(u64),
    /// The bootstrap header is not the trusted block.
    #[error("the bootstrap header has root {got}, not the trusted block root {trusted}")]
    BootstrapRoot {
        /// The trusted block root.
        trusted: B256,
        /// `hash_tree_root` of the bootstrap's beacon header.
        got: B256,
    },
    /// The current-committee branch does not prove the committee into the state root.
    #[error("the current sync committee branch does not prove into state root {0}")]
    CurrentCommitteeBranch(B256),
    /// A committee key is not a valid BLS public key.
    #[error("sync committee key {index} is not a valid BLS public key: {error:?}")]
    PublicKey {
        /// The member's index in the committee.
        index: usize,
        /// The blst error.
        error: BLST_ERROR,
    },
    /// Fewer than two thirds of the committee signed.
    #[error("{participants} of {size} sync committee members signed; at least two thirds must")]
    TooFewParticipants {
        /// The number of set participation bits.
        participants: usize,
        /// `SYNC_COMMITTEE_SIZE`.
        size: usize,
    },
    /// The slots are not `current >= signature > attested >= finalized`.
    #[error(
        "the update's slots are out of order: current {current}, signature {signature}, \
         attested {attested}, finalized {finalized}"
    )]
    SlotOrder {
        /// The current slot.
        current: u64,
        /// The update's signature slot.
        signature: u64,
        /// The attested header's slot.
        attested: u64,
        /// The finalized header's slot.
        finalized: u64,
    },
    /// The update is signed in a period whose committee the store does not know.
    #[error(
        "the update is signed in period {signature_period}, but the store is in period \
         {store_period} and knows the next committee: {next_known}"
    )]
    SignaturePeriod {
        /// The period of the signature slot.
        signature_period: u64,
        /// The period of the store's finalized header.
        store_period: u64,
        /// Whether the store knows the next committee.
        next_known: bool,
    },
    /// The update attests a slot at or below the store's finalized slot and brings no new
    /// committee.
    #[error("the update attests slot {attested}, not after the finalized slot {finalized}")]
    Stale {
        /// The attested header's slot.
        attested: u64,
        /// The store's finalized slot.
        finalized: u64,
    },
    /// An update without a finality branch carries a finalized header.
    #[error("the update has no finality branch but has a finalized header")]
    UnexpectedFinalizedHeader,
    /// The finality branch does not prove the finalized header into the attested state root.
    #[error("the finality branch does not prove the finalized header into state root {0}")]
    FinalityBranch(B256),
    /// An update without a next-committee branch carries a next committee.
    #[error("the update has no next sync committee branch but has a next sync committee")]
    UnexpectedNextCommittee,
    /// The update's next committee differs from the one the store already knows.
    #[error("the update's next sync committee differs from the one the store holds")]
    NextCommitteeChanged,
    /// The next-committee branch does not prove the committee into the attested state root.
    #[error("the next sync committee branch does not prove into state root {0}")]
    NextCommitteeBranch(B256),
    /// The aggregate signature is not a valid G2 point.
    #[error("the sync committee signature is not a valid G2 point: {0:?}")]
    SignatureEncoding(BLST_ERROR),
    /// The aggregate signature does not verify over the attested header.
    #[error("the sync committee signature does not verify over the attested header: {0:?}")]
    Signature(BLST_ERROR),
}

/// A `BeaconBlockHeader`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    /// The slot.
    pub slot: u64,
    /// The proposer's validator index.
    pub proposer_index: u64,
    /// The parent beacon block root.
    pub parent_root: B256,
    /// The root of the post-state.
    pub state_root: B256,
    /// The root of the `BeaconBlockBody`.
    pub body_root: B256,
}

impl BeaconBlockHeader {
    /// Returns `hash_tree_root(self)`, the beacon block root.
    pub fn hash_tree_root(&self) -> B256 {
        container_root(&[
            self.slot.tree_hash_root(),
            self.proposer_index.tree_hash_root(),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }
}

impl Decode for BeaconBlockHeader {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        112
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<u64>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<B256>()?;
        let mut decoder = builder.build()?;
        Ok(Self {
            slot: decoder.decode_next()?,
            proposer_index: decoder.decode_next()?,
            parent_root: decoder.decode_next()?,
            state_root: decoder.decode_next()?,
            body_root: decoder.decode_next()?,
        })
    }
}

impl Encode for BeaconBlockHeader {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <Self as Decode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        <Self as Decode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.slot.ssz_append(buf);
        self.proposer_index.ssz_append(buf);
        buf.extend_from_slice(self.parent_root.as_slice());
        buf.extend_from_slice(self.state_root.as_slice());
        buf.extend_from_slice(self.body_root.as_slice());
    }
}

/// A Capella `ExecutionPayloadHeader`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionPayloadHeader {
    /// The parent execution block hash.
    pub parent_hash: B256,
    /// The beneficiary.
    pub fee_recipient: Address,
    /// The post-state root.
    pub state_root: B256,
    /// The receipts root.
    pub receipts_root: B256,
    /// The logs bloom.
    pub logs_bloom: Bloom,
    /// The `mixHash` (the beacon RANDAO mix).
    pub prev_randao: B256,
    /// The block number.
    pub block_number: u64,
    /// The gas limit.
    pub gas_limit: u64,
    /// The gas used.
    pub gas_used: u64,
    /// The timestamp.
    pub timestamp: u64,
    /// The extra data, at most 32 bytes.
    pub extra_data: Bytes,
    /// The base fee per gas.
    pub base_fee_per_gas: U256,
    /// The execution block hash.
    pub block_hash: B256,
    /// The SSZ root of the transaction list.
    pub transactions_root: B256,
    /// The SSZ root of the withdrawal list.
    pub withdrawals_root: B256,
}

impl ExecutionPayloadHeader {
    /// Returns `hash_tree_root(self)`.
    pub fn hash_tree_root(&self) -> B256 {
        // `extra_data` is a `ByteList[32]`: one chunk, with the length mixed in.
        let extra_data = mix_in_length(&merkle_root(&self.extra_data, 1), self.extra_data.len());
        container_root(&[
            self.parent_hash,
            self.fee_recipient.tree_hash_root(),
            self.state_root,
            self.receipts_root,
            merkle_root(self.logs_bloom.as_slice(), 0),
            self.prev_randao,
            self.block_number.tree_hash_root(),
            self.gas_limit.tree_hash_root(),
            self.gas_used.tree_hash_root(),
            self.timestamp.tree_hash_root(),
            extra_data,
            self.base_fee_per_gas.tree_hash_root(),
            self.block_hash,
            self.transactions_root,
            self.withdrawals_root,
        ])
    }
}

/// The fixed part of an `ExecutionPayloadHeader`: every field but `extra_data`, and its offset.
const EXECUTION_PAYLOAD_HEADER_FIXED_LEN: usize = 568;

impl Encode for ExecutionPayloadHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        EXECUTION_PAYLOAD_HEADER_FIXED_LEN + self.extra_data.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let mut encoder = SszEncoder::container(buf, EXECUTION_PAYLOAD_HEADER_FIXED_LEN);
        encoder.append(&self.parent_hash);
        encoder.append(&self.fee_recipient);
        encoder.append(&self.state_root);
        encoder.append(&self.receipts_root);
        encoder.append(&self.logs_bloom);
        encoder.append(&self.prev_randao);
        encoder.append(&self.block_number);
        encoder.append(&self.gas_limit);
        encoder.append(&self.gas_used);
        encoder.append(&self.timestamp);
        encoder.append(&self.extra_data);
        encoder.append(&self.base_fee_per_gas);
        encoder.append(&self.block_hash);
        encoder.append(&self.transactions_root);
        encoder.append(&self.withdrawals_root);
        encoder.finalize();
    }
}

impl Decode for ExecutionPayloadHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<B256>()?;
        builder.register_type::<Address>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<Bloom>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<Bytes>()?;
        builder.register_type::<U256>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<B256>()?;
        builder.register_type::<B256>()?;
        let mut decoder = builder.build()?;
        let header = Self {
            parent_hash: decoder.decode_next()?,
            fee_recipient: decoder.decode_next()?,
            state_root: decoder.decode_next()?,
            receipts_root: decoder.decode_next()?,
            logs_bloom: decoder.decode_next()?,
            prev_randao: decoder.decode_next()?,
            block_number: decoder.decode_next()?,
            gas_limit: decoder.decode_next()?,
            gas_used: decoder.decode_next()?,
            timestamp: decoder.decode_next()?,
            extra_data: decoder.decode_next()?,
            base_fee_per_gas: decoder.decode_next()?,
            block_hash: decoder.decode_next()?,
            transactions_root: decoder.decode_next()?,
            withdrawals_root: decoder.decode_next()?,
        };
        if header.extra_data.len() > MAX_EXTRA_DATA_BYTES {
            return Err(DecodeError::BytesInvalid(format!(
                "extra_data is {} bytes, more than {MAX_EXTRA_DATA_BYTES}",
                header.extra_data.len()
            )));
        }
        Ok(header)
    }
}

/// A Capella `LightClientHeader`.
///
/// An Altair or Bellatrix header has only `beacon`. The node holds it in this shape with the
/// default `execution` and a zero branch, as the spec's `upgrade_lc_header_to_capella` does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LightClientHeader {
    /// The beacon block header.
    pub beacon: BeaconBlockHeader,
    /// The execution payload header of the same block.
    pub execution: ExecutionPayloadHeader,
    /// The branch that proves `execution` into `beacon.body_root`.
    pub execution_branch: [B256; EXECUTION_BRANCH_DEPTH],
}

impl LightClientHeader {
    /// Returns `hash_tree_root(self)`.
    pub fn hash_tree_root(&self) -> B256 {
        container_root(&[
            self.beacon.hash_tree_root(),
            self.execution.hash_tree_root(),
            container_root(&self.execution_branch),
        ])
    }

    /// Checks `is_valid_light_client_header` for a header at `fork`, the fork of its slot.
    ///
    /// From Capella on, the execution branch must prove `execution` into `beacon.body_root`.
    /// Before Capella, `execution` and the branch must be empty.
    pub fn validate(&self, fork: BeaconFork) -> Result<(), SyncCommitteeError> {
        match Gindices::require(fork)?.execution_payload {
            Some(gindex) => {
                if is_valid_merkle_branch(
                    self.execution.hash_tree_root(),
                    &self.execution_branch,
                    gindex,
                    self.beacon.body_root,
                ) {
                    Ok(())
                } else {
                    Err(SyncCommitteeError::ExecutionBranch(self.beacon.body_root))
                }
            }
            None if self.execution == ExecutionPayloadHeader::default() &&
                self.execution_branch == [B256::ZERO; EXECUTION_BRANCH_DEPTH] =>
            {
                Ok(())
            }
            None => Err(SyncCommitteeError::ExecutionBeforeCapella(self.beacon.slot)),
        }
    }

    /// Decodes a header in the SSZ form of `fork`.
    ///
    /// An Altair or Bellatrix header is a bare `BeaconBlockHeader`; see the type docs.
    pub fn from_ssz_bytes_at(bytes: &[u8], fork: BeaconFork) -> Result<Self, DecodeError> {
        if has_execution(fork)? {
            Self::from_ssz_bytes(bytes)
        } else {
            Ok(Self { beacon: BeaconBlockHeader::from_ssz_bytes(bytes)?, ..Default::default() })
        }
    }

    /// Registers a header of `fork`'s SSZ form with `builder`.
    fn register_at(
        builder: &mut SszDecoderBuilder<'_>,
        fork: BeaconFork,
    ) -> Result<(), DecodeError> {
        if has_execution(fork)? {
            builder.register_type::<Self>()
        } else {
            builder.register_type::<BeaconBlockHeader>()
        }
    }
}

/// The fixed part of a Capella `LightClientHeader`: the beacon header, the execution offset and
/// the execution branch.
const LIGHT_CLIENT_HEADER_FIXED_LEN: usize = 112 + 4 + EXECUTION_BRANCH_DEPTH * 32;

/// The Capella form, which the node holds every header in.
impl Encode for LightClientHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        LIGHT_CLIENT_HEADER_FIXED_LEN + self.execution.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let mut encoder = SszEncoder::container(buf, LIGHT_CLIENT_HEADER_FIXED_LEN);
        encoder.append(&self.beacon);
        encoder.append(&self.execution);
        encoder.append_parameterized(true, |buf| append_branch(&self.execution_branch, buf));
        encoder.finalize();
    }
}

impl Decode for LightClientHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<BeaconBlockHeader>()?;
        builder.register_type::<ExecutionPayloadHeader>()?;
        builder.register_type_parameterized(true, EXECUTION_BRANCH_DEPTH * 32)?;
        let mut decoder = builder.build()?;
        Ok(Self {
            beacon: decoder.decode_next()?,
            execution: decoder.decode_next()?,
            // The builder hands over exactly `EXECUTION_BRANCH_DEPTH * 32` bytes.
            execution_branch: decoder.decode_next_with(|bytes| {
                Ok(std::array::from_fn(|i| B256::from_slice(&bytes[i * 32..(i + 1) * 32])))
            })?,
        })
    }
}

/// A `SyncCommittee`: the preset's number of BLS public keys and their aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// Exactly `SYNC_COMMITTEE_SIZE` compressed G1 keys.
    pubkeys: Vec<FixedBytes<48>>,
    aggregate_pubkey: FixedBytes<48>,
}

impl SyncCommittee {
    /// Decodes a committee of `preset`'s size.
    pub fn from_ssz_bytes(bytes: &[u8], preset: Preset) -> Result<Self, DecodeError> {
        let keys_len = preset.sync_committee_size * 48;
        if bytes.len() != keys_len + 48 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: keys_len + 48,
            });
        }
        let (keys, aggregate) = bytes.split_at(keys_len);
        Ok(Self {
            pubkeys: keys.as_chunks::<48>().0.iter().copied().map(FixedBytes).collect(),
            aggregate_pubkey: FixedBytes::from_slice(aggregate),
        })
    }

    /// Appends the SSZ form: the keys, then the aggregate key.
    pub fn append_ssz(&self, buf: &mut Vec<u8>) {
        for key in &self.pubkeys {
            buf.extend_from_slice(key.as_slice());
        }
        buf.extend_from_slice(self.aggregate_pubkey.as_slice());
    }

    /// Returns the SSZ length.
    const fn ssz_len(&self) -> usize {
        (self.pubkeys.len() + 1) * 48
    }

    /// Returns the member keys, in committee order.
    pub fn pubkeys(&self) -> &[FixedBytes<48>] {
        &self.pubkeys
    }

    /// Returns the aggregate key the state stores.
    pub const fn aggregate_pubkey(&self) -> &FixedBytes<48> {
        &self.aggregate_pubkey
    }

    /// Returns `hash_tree_root(self)`.
    pub fn hash_tree_root(&self) -> B256 {
        let keys: Vec<B256> = self.pubkeys.iter().map(TreeHash::tree_hash_root).collect();
        container_root(&[container_root(&keys), self.aggregate_pubkey.tree_hash_root()])
    }

    /// Returns whether this is the default `SyncCommittee()`, all zero bytes.
    pub fn is_empty(&self) -> bool {
        self.aggregate_pubkey.is_zero() && self.pubkeys.iter().all(FixedBytes::is_zero)
    }
}

/// A `SyncAggregate`: the participation bits and the aggregate signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    /// `SYNC_COMMITTEE_SIZE / 8` bytes. Bit `i` is byte `i / 8`, bit `i % 8`.
    sync_committee_bits: Vec<u8>,
    sync_committee_signature: FixedBytes<96>,
}

impl SyncAggregate {
    /// Decodes an aggregate for `preset`'s committee size.
    pub fn from_ssz_bytes(bytes: &[u8], preset: Preset) -> Result<Self, DecodeError> {
        let bits_len = preset.sync_committee_size / 8;
        if bytes.len() != bits_len + 96 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: bits_len + 96,
            });
        }
        let (bits, signature) = bytes.split_at(bits_len);
        Ok(Self {
            sync_committee_bits: bits.to_vec(),
            sync_committee_signature: FixedBytes::from_slice(signature),
        })
    }

    /// Appends the SSZ form: the bits, then the signature.
    fn append_ssz(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.sync_committee_bits);
        buf.extend_from_slice(self.sync_committee_signature.as_slice());
    }

    /// Returns the SSZ length.
    const fn ssz_len(&self) -> usize {
        self.sync_committee_bits.len() + 96
    }

    /// Returns the participation bits, `SYNC_COMMITTEE_SIZE / 8` bytes.
    pub fn sync_committee_bits(&self) -> &[u8] {
        &self.sync_committee_bits
    }

    /// Returns the compressed G2 aggregate signature.
    pub const fn sync_committee_signature(&self) -> &FixedBytes<96> {
        &self.sync_committee_signature
    }

    /// Returns whether committee member `index` signed.
    fn signed(&self, index: usize) -> bool {
        self.sync_committee_bits[index / 8] >> (index % 8) & 1 == 1
    }

    /// Returns the number of members that signed.
    pub fn participants(&self) -> usize {
        self.sync_committee_bits.iter().map(|byte| byte.count_ones() as usize).sum()
    }

    /// Returns `hash_tree_root(self)`.
    pub fn hash_tree_root(&self) -> B256 {
        container_root(&[
            merkle_root(&self.sync_committee_bits, 0),
            self.sync_committee_signature.tree_hash_root(),
        ])
    }
}

/// A Capella `LightClientBootstrap`: the trusted header and the committee of its period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientBootstrap {
    /// The header of the trusted block.
    pub header: LightClientHeader,
    /// The committee that signs in the header's period.
    pub current_sync_committee: SyncCommittee,
    /// The branch that proves the committee into `header.beacon.state_root`.
    pub current_sync_committee_branch: Vec<B256>,
}

impl LightClientBootstrap {
    /// Decodes a bootstrap in the SSZ form of `fork`, for `preset`'s committee size.
    pub fn from_ssz_bytes(
        bytes: &[u8],
        preset: Preset,
        fork: BeaconFork,
    ) -> Result<Self, DecodeError> {
        let gindices = gindices_for_decode(fork)?;
        let mut builder = SszDecoderBuilder::new(bytes);
        LightClientHeader::register_at(&mut builder, fork)?;
        builder.register_type_parameterized(true, committee_len(preset))?;
        builder.register_type_parameterized(true, branch_len(gindices.current_sync_committee))?;
        let mut decoder = builder.build()?;
        Ok(Self {
            header: decoder.decode_next_with(|b| LightClientHeader::from_ssz_bytes_at(b, fork))?,
            current_sync_committee: decoder
                .decode_next_with(|b| SyncCommittee::from_ssz_bytes(b, preset))?,
            current_sync_committee_branch: decoder.decode_next_with(|b| Ok(decode_branch(b)))?,
        })
    }

    /// The length of the fixed part: the header offset, the committee and the branch.
    const fn fixed_len(&self) -> usize {
        4 + self.current_sync_committee.ssz_len() + self.current_sync_committee_branch.len() * 32
    }
}

/// The Capella form, which the node holds every header in.
impl Encode for LightClientBootstrap {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        self.fixed_len() + self.header.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let mut encoder = SszEncoder::container(buf, self.fixed_len());
        encoder.append(&self.header);
        encoder.append_parameterized(true, |buf| self.current_sync_committee.append_ssz(buf));
        encoder.append_parameterized(true, |buf| {
            append_branch(&self.current_sync_committee_branch, buf)
        });
        encoder.finalize();
    }
}

/// A Capella `LightClientUpdate`.
///
/// An update without finality has a default `finalized_header` and a zero `finality_branch`. An
/// update without a next committee has an empty `next_sync_committee` and a zero branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientUpdate {
    /// The header the committee signed.
    pub attested_header: LightClientHeader,
    /// The committee of the period after the attested header's period.
    pub next_sync_committee: SyncCommittee,
    /// The branch that proves `next_sync_committee` into the attested state root.
    pub next_sync_committee_branch: Vec<B256>,
    /// The header the attested state has finalized.
    pub finalized_header: LightClientHeader,
    /// The branch that proves the finalized root into the attested state root.
    pub finality_branch: Vec<B256>,
    /// The committee's signature over the attested header.
    pub sync_aggregate: SyncAggregate,
    /// The slot of the block that carries `sync_aggregate`.
    pub signature_slot: u64,
}

impl LightClientUpdate {
    /// Decodes an update in the SSZ form of `fork`, for `preset`'s committee size.
    pub fn from_ssz_bytes(
        bytes: &[u8],
        preset: Preset,
        fork: BeaconFork,
    ) -> Result<Self, DecodeError> {
        let gindices = gindices_for_decode(fork)?;
        let mut builder = SszDecoderBuilder::new(bytes);
        LightClientHeader::register_at(&mut builder, fork)?;
        builder.register_type_parameterized(true, committee_len(preset))?;
        builder.register_type_parameterized(true, branch_len(gindices.next_sync_committee))?;
        LightClientHeader::register_at(&mut builder, fork)?;
        builder.register_type_parameterized(true, branch_len(gindices.finalized_root))?;
        builder.register_type_parameterized(true, preset.sync_committee_size / 8 + 96)?;
        builder.register_type::<u64>()?;
        let mut decoder = builder.build()?;
        Ok(Self {
            attested_header: decoder
                .decode_next_with(|b| LightClientHeader::from_ssz_bytes_at(b, fork))?,
            next_sync_committee: decoder
                .decode_next_with(|b| SyncCommittee::from_ssz_bytes(b, preset))?,
            next_sync_committee_branch: decoder.decode_next_with(|b| Ok(decode_branch(b)))?,
            finalized_header: decoder
                .decode_next_with(|b| LightClientHeader::from_ssz_bytes_at(b, fork))?,
            finality_branch: decoder.decode_next_with(|b| Ok(decode_branch(b)))?,
            sync_aggregate: decoder
                .decode_next_with(|b| SyncAggregate::from_ssz_bytes(b, preset))?,
            signature_slot: decoder.decode_next()?,
        })
    }

    /// The spec's `is_sync_committee_update`: the next-committee branch is not all zero.
    pub fn is_sync_committee_update(&self) -> bool {
        self.next_sync_committee_branch.iter().any(|node| !node.is_zero())
    }

    /// The spec's `is_finality_update`: the finality branch is not all zero.
    pub fn is_finality_update(&self) -> bool {
        self.finality_branch.iter().any(|node| !node.is_zero())
    }

    /// The length of the fixed part: two header offsets, the committee, both branches, the
    /// aggregate and the signature slot.
    const fn fixed_len(&self) -> usize {
        4 + self.next_sync_committee.ssz_len() +
            self.next_sync_committee_branch.len() * 32 +
            4 +
            self.finality_branch.len() * 32 +
            self.sync_aggregate.ssz_len() +
            8
    }
}

/// The Capella form, which the node holds every header in.
impl Encode for LightClientUpdate {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        self.fixed_len() +
            self.attested_header.ssz_bytes_len() +
            self.finalized_header.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let mut encoder = SszEncoder::container(buf, self.fixed_len());
        encoder.append(&self.attested_header);
        encoder.append_parameterized(true, |buf| self.next_sync_committee.append_ssz(buf));
        encoder
            .append_parameterized(true, |buf| append_branch(&self.next_sync_committee_branch, buf));
        encoder.append(&self.finalized_header);
        encoder.append_parameterized(true, |buf| append_branch(&self.finality_branch, buf));
        encoder.append_parameterized(true, |buf| self.sync_aggregate.append_ssz(buf));
        encoder.append(&self.signature_slot);
        encoder.finalize();
    }
}

/// Returns whether `fork`'s light-client header has an execution part, or a decode error for a
/// fork with no light-client types.
fn has_execution(fork: BeaconFork) -> Result<bool, DecodeError> {
    Ok(gindices_for_decode(fork)?.execution_payload.is_some())
}

/// Returns `fork`'s indices, or a decode error for a fork with no light-client types.
fn gindices_for_decode(fork: BeaconFork) -> Result<Gindices, DecodeError> {
    Gindices::for_fork(fork).ok_or_else(|| {
        DecodeError::BytesInvalid(format!("fork {fork:?} has no light-client types"))
    })
}

/// Returns the SSZ length of a `SyncCommittee` of `preset`'s size.
pub const fn committee_len(preset: Preset) -> usize {
    (preset.sync_committee_size + 1) * 48
}

/// Returns the SSZ length of the branch for `gindex`.
const fn branch_len(gindex: u64) -> usize {
    gindex.ilog2() as usize * 32
}

/// Appends a branch's nodes.
fn append_branch(branch: &[B256], buf: &mut Vec<u8>) {
    for node in branch {
        buf.extend_from_slice(node.as_slice());
    }
}

/// Splits a branch into its nodes. The decoder hands over a multiple of 32 bytes.
fn decode_branch(bytes: &[u8]) -> Vec<B256> {
    bytes.as_chunks::<32>().0.iter().copied().map(B256::from).collect()
}

/// Returns `compute_fork_data_root(version, genesis_validators_root)`.
fn fork_data_root(version: [u8; 4], genesis_validators_root: B256) -> B256 {
    let mut version_chunk = B256::ZERO;
    version_chunk[..4].copy_from_slice(&version);
    hash_pair(&version_chunk, &genesis_validators_root)
}

/// Returns `compute_fork_digest(version, genesis_validators_root)`.
pub fn fork_digest(version: [u8; 4], genesis_validators_root: B256) -> [u8; 4] {
    let mut digest = [0; 4];
    digest.copy_from_slice(&fork_data_root(version, genesis_validators_root)[..4]);
    digest
}

/// Returns the fork in `beacon`'s pinned schedule whose fork digest is `digest`.
///
/// A source names the fork of light-client data with this digest (or the fork's name), and the
/// SSZ form depends on it. A digest of a fork the binary does not know, such as Deneb, is refused.
pub fn fork_of_digest(
    beacon: &PulsechainBeacon,
    digest: [u8; 4],
) -> Result<BeaconFork, SyncCommitteeError> {
    beacon
        .forks
        .iter()
        .find(|fork| fork_digest(fork.version, beacon.genesis_validators_root) == digest)
        .map(|fork| fork.fork)
        .ok_or(SyncCommitteeError::UnknownForkDigest(digest))
}

/// Returns `compute_domain(domain_type, version, genesis_validators_root)`.
pub fn compute_domain(
    domain_type: [u8; 4],
    version: [u8; 4],
    genesis_validators_root: B256,
) -> B256 {
    let mut domain = B256::ZERO;
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root(version, genesis_validators_root)[..28]);
    domain
}

/// Returns `compute_signing_root`: the root of `SigningData(object_root, domain)`.
pub fn compute_signing_root(object_root: B256, domain: B256) -> B256 {
    hash_pair(&object_root, &domain)
}

/// Returns whether `participants` of `size` members is at least two thirds.
///
/// This is the node's one bar for every update. The spec uses it for finality; for the optimistic
/// header it accepts fewer signers.
pub const fn has_supermajority(participants: usize, size: usize) -> bool {
    participants * 3 >= size * 2
}

/// A sync committee with its keys decompressed and checked, so a signature check does not redo
/// that work.
#[derive(Debug, Clone)]
pub(crate) struct CommitteeKeys {
    committee: SyncCommittee,
    keys: Vec<PublicKey>,
}

impl CommitteeKeys {
    /// Decompresses and checks every key: on the curve, in the subgroup, not the identity.
    pub(crate) fn new(committee: SyncCommittee) -> Result<Self, SyncCommitteeError> {
        let keys = committee
            .pubkeys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                PublicKey::key_validate(key.as_slice())
                    .map_err(|error| SyncCommitteeError::PublicKey { index, error })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { committee, keys })
    }

    /// Checks `FastAggregateVerify` of the members that signed over `signing_root`.
    pub(crate) fn verify(
        &self,
        aggregate: &SyncAggregate,
        signing_root: B256,
    ) -> Result<(), SyncCommitteeError> {
        let signature =
            Signature::sig_validate(aggregate.sync_committee_signature.as_slice(), true)
                .map_err(SyncCommitteeError::SignatureEncoding)?;
        let signers: Vec<&PublicKey> = self
            .keys
            .iter()
            .enumerate()
            .filter_map(|(index, key)| aggregate.signed(index).then_some(key))
            .collect();
        // `sig_validate` has done the subgroup check, and `new` has checked every key.
        match signature.fast_aggregate_verify(false, signing_root.as_slice(), BLS_DST, &signers) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            error => Err(SyncCommitteeError::Signature(error)),
        }
    }
}

/// The spec's `LightClientStore`, without the parts that serve forced updates.
///
/// It holds the latest finalized and optimistic headers it has verified and the committees that
/// sign them. It follows `validate_light_client_update` and `process_light_client_update` with two
/// changes: every update needs two thirds of the committee ([`has_supermajority`]), and the store
/// never makes a forced update after `UPDATE_TIMEOUT`.
#[derive(Debug, Clone)]
pub struct LightClientStore {
    preset: Preset,
    beacon: PulsechainBeacon,
    finalized_header: LightClientHeader,
    current_sync_committee: CommitteeKeys,
    next_sync_committee: Option<CommitteeKeys>,
    optimistic_header: LightClientHeader,
}

impl LightClientStore {
    /// The spec's `initialize_light_client_store`: checks `bootstrap` against the trusted block
    /// root and starts a store at its header.
    ///
    /// `beacon` is the pinned schedule. Its `genesis_validators_root` goes into every domain.
    pub fn bootstrap(
        preset: Preset,
        beacon: PulsechainBeacon,
        trusted_block_root: B256,
        bootstrap: &LightClientBootstrap,
    ) -> Result<Self, SyncCommitteeError> {
        let header = &bootstrap.header;
        let fork = beacon.fork_at_epoch(preset.epoch_at_slot(header.beacon.slot)).fork;
        header.validate(fork)?;
        let root = header.beacon.hash_tree_root();
        if root != trusted_block_root {
            return Err(SyncCommitteeError::BootstrapRoot {
                trusted: trusted_block_root,
                got: root,
            });
        }
        if !is_valid_merkle_branch(
            bootstrap.current_sync_committee.hash_tree_root(),
            &bootstrap.current_sync_committee_branch,
            Gindices::require(fork)?.current_sync_committee,
            header.beacon.state_root,
        ) {
            return Err(SyncCommitteeError::CurrentCommitteeBranch(header.beacon.state_root));
        }
        Ok(Self {
            preset,
            beacon,
            finalized_header: header.clone(),
            current_sync_committee: CommitteeKeys::new(bootstrap.current_sync_committee.clone())?,
            next_sync_committee: None,
            optimistic_header: header.clone(),
        })
    }

    /// Rebuilds a store from what [`Self::finalized_header`], [`Self::current_sync_committee`] and
    /// [`Self::next_sync_committee`] returned. The optimistic header starts at the finalized one.
    ///
    /// The caller must trust these values as it trusted the store they came from: nothing ties
    /// the committees to the header. The header's execution branch and every committee key are
    /// checked, so a damaged value fails here and not at the first update.
    pub fn restore(
        preset: Preset,
        beacon: PulsechainBeacon,
        finalized_header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        next_sync_committee: Option<SyncCommittee>,
    ) -> Result<Self, SyncCommitteeError> {
        finalized_header.validate(
            beacon.fork_at_epoch(preset.epoch_at_slot(finalized_header.beacon.slot)).fork,
        )?;
        Ok(Self {
            preset,
            beacon,
            optimistic_header: finalized_header.clone(),
            finalized_header,
            current_sync_committee: CommitteeKeys::new(current_sync_committee)?,
            next_sync_committee: next_sync_committee.map(CommitteeKeys::new).transpose()?,
        })
    }

    /// Returns the latest finalized header the store has verified.
    pub const fn finalized_header(&self) -> &LightClientHeader {
        &self.finalized_header
    }

    /// Returns the latest header the committee has signed, as far as the store has verified.
    pub const fn optimistic_header(&self) -> &LightClientHeader {
        &self.optimistic_header
    }

    /// Returns the committee that signs in the store's period.
    pub const fn current_sync_committee(&self) -> &SyncCommittee {
        &self.current_sync_committee.committee
    }

    /// Returns the committee of the next period, once a finalized update has proven it.
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.next_sync_committee.as_ref().map(|keys| &keys.committee)
    }

    /// Returns the preset the store checks updates with.
    pub const fn preset(&self) -> Preset {
        self.preset
    }

    /// Returns the pinned chain values the store checks updates with.
    pub const fn beacon(&self) -> &PulsechainBeacon {
        &self.beacon
    }

    /// Returns the store's period: the period of its finalized header.
    pub const fn period(&self) -> u64 {
        self.preset.period_at_slot(self.finalized_header.beacon.slot)
    }

    /// Returns the fork that is active at `slot`.
    fn fork_at_slot(&self, slot: u64) -> BeaconFork {
        self.beacon.fork_at_epoch(self.preset.epoch_at_slot(slot)).fork
    }

    /// The spec's `validate_light_client_update`, with the two-thirds bar. It does not change the
    /// store.
    ///
    /// `current_slot` is the wall-clock slot; the caller allows for clock drift.
    pub fn validate_update(
        &self,
        update: &LightClientUpdate,
        current_slot: u64,
    ) -> Result<(), SyncCommitteeError> {
        let participants = update.sync_aggregate.participants();
        let size = self.preset.sync_committee_size;
        if !has_supermajority(participants, size) {
            return Err(SyncCommitteeError::TooFewParticipants { participants, size });
        }

        let attested = &update.attested_header.beacon;
        let attested_fork = self.fork_at_slot(attested.slot);
        update.attested_header.validate(attested_fork)?;
        let gindices = Gindices::require(attested_fork)?;
        let finalized_slot = update.finalized_header.beacon.slot;
        if !(current_slot >= update.signature_slot &&
            update.signature_slot > attested.slot &&
            attested.slot >= finalized_slot)
        {
            return Err(SyncCommitteeError::SlotOrder {
                current: current_slot,
                signature: update.signature_slot,
                attested: attested.slot,
                finalized: finalized_slot,
            });
        }

        let store_period = self.period();
        let signature_period = self.preset.period_at_slot(update.signature_slot);
        let next_known = self.next_sync_committee.is_some();
        if !(signature_period == store_period || next_known && signature_period == store_period + 1)
        {
            return Err(SyncCommitteeError::SignaturePeriod {
                signature_period,
                store_period,
                next_known,
            });
        }

        let attested_period = self.preset.period_at_slot(attested.slot);
        let brings_next_committee =
            !next_known && update.is_sync_committee_update() && attested_period == store_period;
        if attested.slot <= self.finalized_header.beacon.slot && !brings_next_committee {
            return Err(SyncCommitteeError::Stale {
                attested: attested.slot,
                finalized: self.finalized_header.beacon.slot,
            });
        }

        if update.is_finality_update() {
            let finalized_root = if finalized_slot == 0 {
                // The spec proves a zero root for a genesis checkpoint.
                if update.finalized_header != LightClientHeader::default() {
                    return Err(SyncCommitteeError::UnexpectedFinalizedHeader);
                }
                B256::ZERO
            } else {
                update.finalized_header.validate(self.fork_at_slot(finalized_slot))?;
                update.finalized_header.beacon.hash_tree_root()
            };
            if !is_valid_merkle_branch(
                finalized_root,
                &update.finality_branch,
                gindices.finalized_root,
                attested.state_root,
            ) {
                return Err(SyncCommitteeError::FinalityBranch(attested.state_root));
            }
        } else if update.finalized_header != LightClientHeader::default() {
            return Err(SyncCommitteeError::UnexpectedFinalizedHeader);
        }

        if update.is_sync_committee_update() {
            if let Some(next) = &self.next_sync_committee &&
                attested_period == store_period &&
                next.committee != update.next_sync_committee
            {
                return Err(SyncCommitteeError::NextCommitteeChanged);
            }
            if !is_valid_merkle_branch(
                update.next_sync_committee.hash_tree_root(),
                &update.next_sync_committee_branch,
                gindices.next_sync_committee,
                attested.state_root,
            ) {
                return Err(SyncCommitteeError::NextCommitteeBranch(attested.state_root));
            }
        } else if !update.next_sync_committee.is_empty() {
            return Err(SyncCommitteeError::UnexpectedNextCommittee);
        }

        let committee = match &self.next_sync_committee {
            Some(next) if signature_period != store_period => next,
            _ => &self.current_sync_committee,
        };
        committee.verify(
            &update.sync_aggregate,
            sync_signing_root(
                self.preset,
                &self.beacon,
                attested.hash_tree_root(),
                update.signature_slot,
            ),
        )
    }

    /// The spec's `process_light_client_update`, without the best update a forced update would
    /// use.
    ///
    /// A valid update moves the optimistic header to its attested header when that is newer. It
    /// moves the finalized header when its finalized header is newer, or when it proves the next
    /// committee in the store period. When finality enters the next period, the committees rotate.
    /// An error leaves the store as it was.
    pub fn process_update(
        &mut self,
        update: &LightClientUpdate,
        current_slot: u64,
    ) -> Result<(), SyncCommitteeError> {
        self.validate_update(update, current_slot)?;

        let attested_slot = update.attested_header.beacon.slot;
        let finalized_slot = update.finalized_header.beacon.slot;
        let finalized_period = self.preset.period_at_slot(finalized_slot);
        let store_period = self.period();
        let next_known = self.next_sync_committee.is_some();
        let has_finalized_next_committee = !next_known &&
            update.is_sync_committee_update() &&
            update.is_finality_update() &&
            finalized_period == self.preset.period_at_slot(attested_slot);
        let apply =
            finalized_slot > self.finalized_header.beacon.slot || has_finalized_next_committee;
        let rotate = next_known && finalized_period == store_period + 1;

        // `apply_light_client_update`, with the new committee's keys checked before any change.
        let next_committee =
            if apply && (!next_known || rotate) && update.is_sync_committee_update() {
                Some(CommitteeKeys::new(update.next_sync_committee.clone())?)
            } else {
                None
            };
        if attested_slot > self.optimistic_header.beacon.slot {
            self.optimistic_header = update.attested_header.clone();
        }
        if !apply {
            return Ok(());
        }
        // Without a next committee, `validate_update` lets only the store period's committee
        // sign, so the finalized period is the store period: the spec's assert holds.
        match self.next_sync_committee.take() {
            None => self.next_sync_committee = next_committee,
            Some(next) if rotate => {
                self.current_sync_committee = next;
                self.next_sync_committee = next_committee;
            }
            known => self.next_sync_committee = known,
        }
        if finalized_slot > self.finalized_header.beacon.slot {
            // The optimistic header is already at or after the attested slot, so it does not fall
            // behind the new finalized header.
            self.finalized_header = update.finalized_header.clone();
        }
        Ok(())
    }
}

/// Returns the root that the committee signs at `signature_slot` over the block `attested_root`:
/// the domain takes the fork version of the slot before the signature slot.
pub(crate) fn sync_signing_root(
    preset: Preset,
    beacon: &PulsechainBeacon,
    attested_root: B256,
    signature_slot: u64,
) -> B256 {
    let fork_version_slot = signature_slot.max(1) - 1;
    let version = beacon.fork_at_epoch(preset.epoch_at_slot(fork_version_slot)).version;
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, version, beacon.genesis_validators_root);
    compute_signing_root(attested_root, domain)
}

/// Returns whether `branch` proves `leaf` at generalized index `gindex` into `root`.
///
/// This is the spec's `is_valid_merkle_branch` with the depth and subtree index taken from
/// `gindex`. A branch whose length is not the depth of `gindex` is invalid.
pub fn is_valid_merkle_branch(leaf: B256, branch: &[B256], gindex: u64, root: B256) -> bool {
    let Some(depth) = gindex.checked_ilog2() else { return false };
    if branch.len() != depth as usize {
        return false;
    }
    // Below the top bit, bit `i` of `gindex` says whether the node at height `i` is a right child.
    let computed = branch.iter().enumerate().fold(leaf, |node, (i, sibling)| {
        if (gindex >> i) & 1 == 1 {
            hash_pair(sibling, &node)
        } else {
            hash_pair(&node, sibling)
        }
    });
    computed == root
}

/// Returns `sha256(left ++ right)`, a parent node.
pub(crate) fn hash_pair(left: &B256, right: &B256) -> B256 {
    B256::from(<[u8; 32]>::from(Sha256::new().chain_update(left).chain_update(right).finalize()))
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(test)]
mod tests {
    use super::{test_utils::*, *};
    use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
    use reth_pulsechain_forks::network::BeaconForkActivation;
    use serde_json::Value;

    const MANIFEST: &str = include_str!("../testdata/sync_committee/capella.json");

    fn manifest() -> Value {
        serde_json::from_str(MANIFEST).unwrap()
    }

    /// One `single_merkle_proof` vector: leaf, gindex, branch and the root it proves into.
    fn proof(case: &str) -> (B256, u64, Vec<B256>, B256) {
        let proof = &manifest()["single_merkle_proof"][case];
        (
            hash(&proof["leaf"]),
            proof["leaf_index"].as_u64().unwrap(),
            proof["branch"].as_array().unwrap().iter().map(hash).collect(),
            hash(&proof["root"]),
        )
    }

    fn static_root(file: &str) -> B256 {
        hash(&manifest()["ssz_static_roots"][file])
    }

    const fn capella() -> Gindices {
        Gindices::for_fork(BeaconFork::Capella).unwrap()
    }

    const EXECUTION_HEADER: &[u8] = include_bytes!(
        "../testdata/sync_committee/single_merkle_proof_execution_payload_header.ssz"
    );
    const COMMITTEE: &[u8] =
        include_bytes!("../testdata/sync_committee/single_merkle_proof_current_sync_committee.ssz");

    /// A Capella light-client header whose execution part is the spec's execution proof vector.
    fn header() -> LightClientHeader {
        let (_, _, branch, body_root) = proof("execution_merkle_proof");
        LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: 100,
                proposer_index: 7,
                parent_root: B256::repeat_byte(1),
                state_root: B256::repeat_byte(2),
                body_root,
            },
            execution: ExecutionPayloadHeader::from_ssz_bytes(EXECUTION_HEADER).unwrap(),
            execution_branch: branch.try_into().unwrap(),
        }
    }

    #[test]
    fn pulsechain_preset_has_the_mainnet_light_client_values() {
        assert_eq!(Preset::PULSECHAIN, Preset::MAINNET);
        let preset = Preset::PULSECHAIN;
        assert_eq!(preset.sync_committee_size(), 512);
        assert_eq!(preset.epoch_at_slot(31), 0);
        assert_eq!(preset.epoch_at_slot(32), 1);
        assert_eq!(preset.period_at_slot(8191), 0);
        assert_eq!(preset.period_at_slot(8192), 1);
        // The finalized PulseChain slot read on 2026-11-23.
        assert_eq!(preset.period_at_slot(11_167_584), 1363);
    }

    #[test]
    fn capella_gindices_match_the_spec_vectors() {
        let g = capella();
        assert_eq!(g.execution_payload, Some(proof("execution_merkle_proof").1));
        assert_eq!(g.current_sync_committee, proof("current_sync_committee_merkle_proof").1);
        assert_eq!(g.next_sync_committee, proof("next_sync_committee_merkle_proof").1);
        assert_eq!(g.finalized_root, proof("finality_root_merkle_proof").1);
        assert_eq!(g.execution_payload.unwrap().ilog2() as usize, EXECUTION_BRANCH_DEPTH);
    }

    /// `Phase0` has no light-client data. Altair and Bellatrix share Capella's state indices and
    /// have no execution part.
    #[test]
    fn forks_before_capella_have_altair_gindices() {
        assert_eq!(Gindices::for_fork(BeaconFork::Phase0), None);
        for fork in [BeaconFork::Altair, BeaconFork::Bellatrix] {
            let expected = Gindices { execution_payload: None, ..capella() };
            assert_eq!(Gindices::for_fork(fork), Some(expected), "{fork:?}");
        }
    }

    /// The `ssz_static` cases decode and hash to the spec's roots.
    #[test]
    fn ssz_static_roots_match_the_spec() {
        macro_rules! case {
            ($file:literal) => {
                ($file, include_bytes!(concat!("../testdata/sync_committee/", $file)).as_slice())
            };
        }
        let preset = Preset::MAINNET;
        for (file, bytes) in [
            case!("ssz_static_BeaconBlockHeader_case_0.ssz"),
            case!("ssz_static_BeaconBlockHeader_case_1.ssz"),
        ] {
            let root = BeaconBlockHeader::from_ssz_bytes(bytes).unwrap().hash_tree_root();
            assert_eq!(root, static_root(file), "{file}");
        }
        for (file, bytes) in [
            case!("ssz_static_ExecutionPayloadHeader_case_0.ssz"),
            case!("ssz_static_ExecutionPayloadHeader_case_1.ssz"),
        ] {
            let root = ExecutionPayloadHeader::from_ssz_bytes(bytes).unwrap().hash_tree_root();
            assert_eq!(root, static_root(file), "{file}");
        }
        for (file, bytes) in [
            case!("ssz_static_LightClientHeader_case_0.ssz"),
            case!("ssz_static_LightClientHeader_case_1.ssz"),
        ] {
            let root = LightClientHeader::from_ssz_bytes(bytes).unwrap().hash_tree_root();
            assert_eq!(root, static_root(file), "{file}");
        }
        for (file, bytes) in [
            case!("ssz_static_SyncAggregate_case_0.ssz"),
            case!("ssz_static_SyncAggregate_case_1.ssz"),
        ] {
            let root = SyncAggregate::from_ssz_bytes(bytes, preset).unwrap().hash_tree_root();
            assert_eq!(root, static_root(file), "{file}");
        }
        let (file, bytes) = case!("ssz_static_SyncCommittee_case_0.ssz");
        let root = SyncCommittee::from_ssz_bytes(bytes, preset).unwrap().hash_tree_root();
        assert_eq!(root, static_root(file), "{file}");
    }

    /// `single_merkle_proof`: the execution payload header proves into the body root.
    #[test]
    fn execution_payload_header_proves_into_the_body_root() {
        let (leaf, _, branch, body_root) = proof("execution_merkle_proof");
        let execution = ExecutionPayloadHeader::from_ssz_bytes(EXECUTION_HEADER).unwrap();
        assert_eq!(execution.hash_tree_root(), leaf);
        let gindex = capella().execution_payload.unwrap();
        assert!(is_valid_merkle_branch(leaf, &branch, gindex, body_root));
    }

    /// `single_merkle_proof`: both committee branches prove the committee into the state root.
    #[test]
    fn sync_committees_prove_into_the_state_root() {
        let committee = SyncCommittee::from_ssz_bytes(COMMITTEE, Preset::MAINNET).unwrap();
        assert_eq!(committee.pubkeys().len(), 512);
        for (case, gindex) in [
            ("current_sync_committee_merkle_proof", capella().current_sync_committee),
            ("next_sync_committee_merkle_proof", capella().next_sync_committee),
        ] {
            let (leaf, _, branch, state_root) = proof(case);
            assert_eq!(committee.hash_tree_root(), leaf, "{case}");
            assert!(is_valid_merkle_branch(leaf, &branch, gindex, state_root), "{case}");
        }
    }

    /// `single_merkle_proof`: the finalized root proves into the state root.
    #[test]
    fn finalized_root_proves_into_the_state_root() {
        let (leaf, _, branch, state_root) = proof("finality_root_merkle_proof");
        assert!(is_valid_merkle_branch(leaf, &branch, capella().finalized_root, state_root));
    }

    /// A valid branch read as the branch of a neighbouring field fails.
    #[test]
    fn a_branch_for_the_wrong_field_fails() {
        // Gindex 24 is the body's `sync_aggregate`, the execution payload's sibling.
        let (leaf, gindex, branch, body_root) = proof("execution_merkle_proof");
        assert!(!is_valid_merkle_branch(leaf, &branch, gindex - 1, body_root));
        // Gindex 52 is the state's `finalized_checkpoint`, at the same depth as the committee.
        let (leaf, gindex, branch, state_root) = proof("current_sync_committee_merkle_proof");
        assert!(!is_valid_merkle_branch(leaf, &branch, gindex - 2, state_root));
        // The finality branch is one level deeper than a committee branch.
        let (_, _, finality_branch, _) = proof("finality_root_merkle_proof");
        assert!(!is_valid_merkle_branch(leaf, &finality_branch, gindex, state_root));
    }

    #[test]
    fn a_branch_of_the_wrong_length_or_a_zero_gindex_fails() {
        let (leaf, gindex, branch, root) = proof("execution_merkle_proof");
        assert!(!is_valid_merkle_branch(leaf, &branch[..3], gindex, root));
        let mut long = branch;
        long.push(B256::ZERO);
        assert!(!is_valid_merkle_branch(leaf, &long, gindex, root));
        assert!(!is_valid_merkle_branch(leaf, &[], 0, leaf));
        // Gindex 1 is the root itself, with an empty branch.
        assert!(is_valid_merkle_branch(root, &[], 1, root));
    }

    #[test]
    fn a_light_client_header_with_a_matching_execution_branch_verifies() {
        assert_eq!(header().validate(BeaconFork::Capella), Ok(()));
    }

    #[test]
    fn a_header_whose_execution_branch_does_not_match_fails() {
        let mut changed = header();
        changed.execution.block_hash = B256::repeat_byte(0xee);
        let body_root = changed.beacon.body_root;
        assert_eq!(
            changed.validate(BeaconFork::Capella),
            Err(SyncCommitteeError::ExecutionBranch(body_root))
        );

        let mut changed = header();
        changed.execution_branch[2] = B256::ZERO;
        assert_eq!(
            changed.validate(BeaconFork::Capella),
            Err(SyncCommitteeError::ExecutionBranch(body_root))
        );

        let mut changed = header();
        changed.beacon.body_root = B256::repeat_byte(3);
        assert_eq!(
            changed.validate(BeaconFork::Capella),
            Err(SyncCommitteeError::ExecutionBranch(B256::repeat_byte(3)))
        );
    }

    /// Before Capella a header must have an empty execution part, and `Phase0` has no headers.
    #[test]
    fn a_header_before_capella_must_have_no_execution_part() {
        let bare = LightClientHeader { beacon: header().beacon, ..Default::default() };
        assert_eq!(bare.validate(BeaconFork::Bellatrix), Ok(()));
        assert_eq!(bare.validate(BeaconFork::Altair), Ok(()));
        // The empty part fails at Capella, where the branch must prove it.
        assert_eq!(
            bare.validate(BeaconFork::Capella),
            Err(SyncCommitteeError::ExecutionBranch(bare.beacon.body_root))
        );
        assert_eq!(
            header().validate(BeaconFork::Bellatrix),
            Err(SyncCommitteeError::ExecutionBeforeCapella(100))
        );
        let mut branch_only = bare.clone();
        branch_only.execution_branch[0] = B256::repeat_byte(1);
        assert_eq!(
            branch_only.validate(BeaconFork::Altair),
            Err(SyncCommitteeError::ExecutionBeforeCapella(100))
        );
        assert_eq!(
            bare.validate(BeaconFork::Phase0),
            Err(SyncCommitteeError::UnsupportedFork(BeaconFork::Phase0))
        );
    }

    /// The beacon block root of a header is its `hash_tree_root`, and every field changes it.
    #[test]
    fn beacon_block_header_root_covers_every_field() {
        let header = header().beacon;
        let root = header.hash_tree_root();
        let changed = [
            BeaconBlockHeader { slot: 101, ..header },
            BeaconBlockHeader { proposer_index: 8, ..header },
            BeaconBlockHeader { parent_root: B256::ZERO, ..header },
            BeaconBlockHeader { state_root: B256::ZERO, ..header },
            BeaconBlockHeader { body_root: B256::ZERO, ..header },
        ];
        for header in changed {
            assert_ne!(header.hash_tree_root(), root, "{header:?}");
        }
    }

    #[test]
    fn extra_data_longer_than_32_bytes_is_refused() {
        let mut execution = ExecutionPayloadHeader::from_ssz_bytes(EXECUTION_HEADER).unwrap();
        // `extra_data` is the only variable field, so it is the encoding's tail.
        let fixed = EXECUTION_HEADER.len() - execution.extra_data.len();
        let mut bytes = EXECUTION_HEADER[..fixed].to_vec();
        bytes.extend_from_slice(&[0xab; 33]);
        assert_eq!(
            ExecutionPayloadHeader::from_ssz_bytes(&bytes),
            Err(DecodeError::BytesInvalid("extra_data is 33 bytes, more than 32".into()))
        );
        bytes.pop();
        execution.extra_data = Bytes::from(vec![0xab; 32]);
        assert_eq!(ExecutionPayloadHeader::from_ssz_bytes(&bytes), Ok(execution));
    }

    #[test]
    fn a_committee_or_aggregate_of_the_wrong_size_is_refused() {
        assert_eq!(
            SyncCommittee::from_ssz_bytes(&COMMITTEE[48..], Preset::MAINNET),
            Err(DecodeError::InvalidByteLength { len: 24_576, expected: 24_624 })
        );
        let aggregate = [0u8; 160];
        assert_eq!(
            SyncAggregate::from_ssz_bytes(&aggregate[1..], Preset::MAINNET),
            Err(DecodeError::InvalidByteLength { len: 159, expected: 160 })
        );
        assert!(SyncAggregate::from_ssz_bytes(&aggregate, Preset::MAINNET).is_ok());
    }

    /// Keys keep their committee order, and the aggregate key is the last 48 bytes.
    #[test]
    fn committee_keys_decode_in_order() {
        let committee = SyncCommittee::from_ssz_bytes(COMMITTEE, Preset::MAINNET).unwrap();
        assert_eq!(committee.pubkeys()[0].as_slice(), &COMMITTEE[..48]);
        assert_eq!(committee.pubkeys()[511].as_slice(), &COMMITTEE[511 * 48..512 * 48]);
        assert_eq!(committee.aggregate_pubkey().as_slice(), &COMMITTEE[512 * 48..]);
    }

    /// Encoding a decoded spec object gives back the spec's bytes, as the store file needs.
    #[test]
    fn ssz_encoding_gives_back_the_spec_bytes() {
        macro_rules! case {
            ($file:literal) => {
                include_bytes!(concat!("../testdata/sync_committee/", $file)).as_slice()
            };
        }
        for bytes in [
            case!("ssz_static_BeaconBlockHeader_case_0.ssz"),
            case!("ssz_static_BeaconBlockHeader_case_1.ssz"),
        ] {
            assert_eq!(BeaconBlockHeader::from_ssz_bytes(bytes).unwrap().as_ssz_bytes(), bytes);
        }
        for bytes in [
            case!("ssz_static_ExecutionPayloadHeader_case_0.ssz"),
            case!("ssz_static_ExecutionPayloadHeader_case_1.ssz"),
        ] {
            let header = ExecutionPayloadHeader::from_ssz_bytes(bytes).unwrap();
            assert_eq!(header.as_ssz_bytes(), bytes);
            assert_eq!(header.ssz_bytes_len(), bytes.len());
        }
        for bytes in [
            case!("ssz_static_LightClientHeader_case_0.ssz"),
            case!("ssz_static_LightClientHeader_case_1.ssz"),
        ] {
            let header = LightClientHeader::from_ssz_bytes(bytes).unwrap();
            assert_eq!(header.as_ssz_bytes(), bytes);
            assert_eq!(header.ssz_bytes_len(), bytes.len());
        }
        let mut committee = Vec::new();
        SyncCommittee::from_ssz_bytes(COMMITTEE, Preset::MAINNET)
            .unwrap()
            .append_ssz(&mut committee);
        assert_eq!(committee, COMMITTEE);
    }

    /// The Capella `light_client/sync` bootstrap and updates encode back to the spec's bytes.
    #[test]
    fn bootstrap_and_updates_encode_back_to_the_spec_bytes() {
        let case: Value = serde_json::from_str(include_str!(
            "../testdata/sync_committee/sync_capella_light_client_sync.json"
        ))
        .unwrap();
        let (preset, fork) = (Preset::MINIMAL, BeaconFork::Capella);
        let ssz = bytes(&case["bootstrap"]);
        let bootstrap = LightClientBootstrap::from_ssz_bytes(&ssz, preset, fork).unwrap();
        assert_eq!(bootstrap.as_ssz_bytes(), ssz.as_ref());
        assert_eq!(bootstrap.ssz_bytes_len(), ssz.len());
        let mut updates = 0;
        for step in case["steps"].as_array().unwrap() {
            let Some(step) = step.get("process_update") else { continue };
            let ssz = bytes(&step["update"]);
            let update = LightClientUpdate::from_ssz_bytes(&ssz, preset, fork).unwrap();
            assert_eq!(update.as_ssz_bytes(), ssz.as_ref());
            assert_eq!(update.ssz_bytes_len(), ssz.len());
            updates += 1;
        }
        assert!(updates > 0);
    }

    // The `light_client/sync` spec vectors (minimal preset).

    /// Checks a store header against a step's `checks` entry. The spec's `execution_root` is zero
    /// before Capella.
    fn check_header(store: &LightClientStore, header: &LightClientHeader, check: &Value) {
        assert_eq!(header.beacon.slot, check["slot"].as_u64().unwrap());
        assert_eq!(header.beacon.hash_tree_root(), hash(&check["beacon_root"]));
        if let Some(root) = check.get("execution_root") {
            let expected = if store.fork_at_slot(header.beacon.slot) >= BeaconFork::Capella {
                header.execution.hash_tree_root()
            } else {
                B256::ZERO
            };
            assert_eq!(expected, hash(root));
        }
    }

    /// Runs one `light_client/sync` case and returns the number of updates it processed.
    fn run_sync_case(json: &str) -> usize {
        let case: Value = serde_json::from_str(json).unwrap();
        let beacon = case_beacon(&case);
        let fork = fork_of_digest(&beacon, digest(&case["bootstrap_fork_digest"])).unwrap();
        let bootstrap =
            LightClientBootstrap::from_ssz_bytes(&bytes(&case["bootstrap"]), Preset::MINIMAL, fork)
                .unwrap();
        let trusted = hash(&case["trusted_block_root"]);
        let mut store =
            LightClientStore::bootstrap(Preset::MINIMAL, beacon, trusted, &bootstrap).unwrap();
        let steps = case["steps"].as_array().unwrap();
        let mut updates = 0;
        for (i, step) in steps.iter().enumerate() {
            if let Some(step) = step.get("process_update") {
                let fork = fork_of_digest(&beacon, digest(&step["update_fork_digest"])).unwrap();
                let update = LightClientUpdate::from_ssz_bytes(
                    &bytes(&step["update"]),
                    Preset::MINIMAL,
                    fork,
                )
                .unwrap();
                store.process_update(&update, step["current_slot"].as_u64().unwrap()).unwrap();
                check_header(&store, store.finalized_header(), &step["checks"]["finalized_header"]);
                check_header(
                    &store,
                    store.optimistic_header(),
                    &step["checks"]["optimistic_header"],
                );
                updates += 1;
            } else if step.get("force_update").is_some() {
                // The node makes no forced update, so `derive_sync.py` ends the case here.
                assert_eq!(i, steps.len() - 1);
            } else {
                // The store holds every header in the Capella form, so an upgrade changes nothing.
                assert!(step.get("upgrade_store").is_some(), "{step}");
            }
        }
        updates
    }

    macro_rules! sync_case {
        ($name:ident, $file:literal, $updates:expr) => {
            #[test]
            fn $name() {
                let json = include_str!(concat!("../testdata/sync_committee/", $file));
                assert_eq!(run_sync_case(json), $updates);
            }
        };
    }

    sync_case!(spec_altair_light_client_sync, "sync_altair_light_client_sync.json", 5);
    sync_case!(
        spec_altair_supply_sync_committee_from_past_update,
        "sync_altair_supply_sync_committee_from_past_update.json",
        1
    );
    sync_case!(
        spec_altair_advance_finality_without_sync_committee,
        "sync_altair_advance_finality_without_sync_committee.json",
        5
    );
    sync_case!(
        spec_altair_capella_store_with_legacy_data,
        "sync_altair_capella_store_with_legacy_data.json",
        1
    );
    sync_case!(spec_bellatrix_capella_fork, "sync_bellatrix_capella_fork.json", 7);
    sync_case!(spec_capella_light_client_sync, "sync_capella_light_client_sync.json", 5);
    sync_case!(
        spec_capella_supply_sync_committee_from_past_update,
        "sync_capella_supply_sync_committee_from_past_update.json",
        1
    );
    sync_case!(
        spec_capella_advance_finality_without_sync_committee,
        "sync_capella_advance_finality_without_sync_committee.json",
        5
    );

    /// A Deneb update names a fork digest the pinned schedule does not have.
    #[test]
    fn an_unknown_fork_digest_is_refused() {
        let case: Value = serde_json::from_str(include_str!(
            "../testdata/sync_committee/sync_capella_light_client_sync.json"
        ))
        .unwrap();
        let beacon = case_beacon(&case);
        for (fork, activation) in FORK_ORDER.iter().zip(beacon.forks) {
            let known = fork_digest(activation.version, beacon.genesis_validators_root);
            assert_eq!(fork_of_digest(&beacon, known), Ok(*fork));
        }
        // The minimal config's `DENEB_FORK_VERSION`.
        let deneb = fork_digest([4, 0, 0, 1], beacon.genesis_validators_root);
        assert_eq!(
            fork_of_digest(&beacon, deneb),
            Err(SyncCommitteeError::UnknownForkDigest(deneb))
        );
        // The same version under another genesis validators root is another digest.
        let other_chain = fork_digest(beacon.forks[3].version, B256::repeat_byte(1));
        assert_eq!(
            fork_of_digest(&beacon, other_chain),
            Err(SyncCommitteeError::UnknownForkDigest(other_chain))
        );
    }

    #[test]
    fn phase0_has_no_light_client_types() {
        let bytes = [0; 4096];
        let error = DecodeError::BytesInvalid("fork Phase0 has no light-client types".into());
        assert_eq!(
            LightClientBootstrap::from_ssz_bytes(&bytes, Preset::MINIMAL, BeaconFork::Phase0),
            Err(error.clone())
        );
        assert_eq!(
            LightClientUpdate::from_ssz_bytes(&bytes, Preset::MINIMAL, BeaconFork::Phase0),
            Err(error)
        );
    }

    // Hand-built updates on a minimal-preset chain: 32 members, 8 slots an epoch, 64 slots a
    // period.

    const GVR: B256 = B256::repeat_byte(0x42);

    /// `DOMAIN_BEACON_PROPOSER`, a domain the committee must not sign with.
    const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0, 0, 0, 0];

    /// A schedule with the minimal config's versions and Capella from `capella_epoch`.
    fn beacon(altair_epoch: u64, capella_epoch: u64) -> PulsechainBeacon {
        let epochs = [0, altair_epoch, altair_epoch, capella_epoch];
        PulsechainBeacon {
            genesis_validators_root: GVR,
            genesis_time: 0,
            forks: std::array::from_fn(|i| BeaconForkActivation {
                fork: FORK_ORDER[i],
                version: [i as u8, 0, 0, 1],
                epoch: epochs[i],
            }),
        }
    }

    fn committee_of(keys: &[SecretKey]) -> SyncCommittee {
        let pubkeys: Vec<PublicKey> = keys.iter().map(SecretKey::sk_to_pk).collect();
        let refs: Vec<&PublicKey> = pubkeys.iter().collect();
        let aggregate = AggregatePublicKey::aggregate(&refs, false).unwrap().to_public_key();
        SyncCommittee {
            pubkeys: pubkeys.iter().map(|key| FixedBytes(key.compress())).collect(),
            aggregate_pubkey: FixedBytes(aggregate.compress()),
        }
    }

    fn empty_committee() -> SyncCommittee {
        SyncCommittee { pubkeys: vec![FixedBytes::ZERO; 32], aggregate_pubkey: FixedBytes::ZERO }
    }

    /// Signs `signing_root` with the first `participants` of `keys`.
    fn aggregate(keys: &[SecretKey], participants: usize, signing_root: B256) -> SyncAggregate {
        let signatures: Vec<Signature> = keys[..participants]
            .iter()
            .map(|key| key.sign(signing_root.as_slice(), BLS_DST, &[]))
            .collect();
        let refs: Vec<&Signature> = signatures.iter().collect();
        let signature = AggregateSignature::aggregate(&refs, false).unwrap().to_signature();
        let mut bits = vec![0; keys.len() / 8];
        for i in 0..participants {
            bits[i / 8] |= 1 << (i % 8);
        }
        SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: FixedBytes(signature.compress()),
        }
    }

    /// What one hand-built update holds.
    #[derive(Clone, Copy)]
    struct Spec {
        attested: u64,
        signature: u64,
        finalized: Option<u64>,
        /// The committee the attested state names as next.
        next: Option<usize>,
        /// The committee that signs.
        signer: usize,
        participants: usize,
    }

    impl Spec {
        const fn new(attested: u64, finalized: Option<u64>, next: Option<usize>) -> Self {
            Self { attested, signature: attested + 1, finalized, next, signer: 0, participants: 32 }
        }
    }

    /// A minimal-preset chain with three committees, one for each of periods 0 to 2.
    struct TestChain {
        beacon: PulsechainBeacon,
        keys: Vec<Vec<SecretKey>>,
        committees: Vec<SyncCommittee>,
    }

    impl TestChain {
        fn new(beacon: PulsechainBeacon) -> Self {
            let keys: Vec<Vec<SecretKey>> = (0..3u8)
                .map(|period| {
                    (0..32u8)
                        .map(|member| {
                            let mut ikm = [0x55; 32];
                            ikm[0] = period;
                            ikm[1] = member;
                            SecretKey::key_gen(&ikm, &[]).unwrap()
                        })
                        .collect()
                })
                .collect();
            let committees = keys.iter().map(|keys| committee_of(keys)).collect();
            Self { beacon, keys, committees }
        }

        /// Every slot is Capella.
        fn capella() -> Self {
            Self::new(beacon(0, 0))
        }

        fn fork_at_slot(&self, slot: u64) -> BeaconFork {
            self.beacon.fork_at_epoch(Preset::MINIMAL.epoch_at_slot(slot)).fork
        }

        /// A header at `slot` whose state holds `state_leaves`. Before Capella it has no
        /// execution part.
        fn header(&self, slot: u64, state_leaves: &[(u64, B256)]) -> LightClientHeader {
            let execution = ExecutionPayloadHeader {
                block_number: slot,
                block_hash: B256::left_padding_from(&slot.to_be_bytes()),
                ..Default::default()
            };
            let body = [(25, execution.hash_tree_root())];
            let mut header = LightClientHeader {
                beacon: BeaconBlockHeader {
                    slot,
                    proposer_index: slot,
                    parent_root: B256::repeat_byte(9),
                    state_root: node(state_leaves, 1, STATE_DEPTH),
                    body_root: node(&body, 1, 4),
                },
                execution,
                execution_branch: branch(&body, 25, 4).try_into().unwrap(),
            };
            if self.fork_at_slot(slot) < BeaconFork::Capella {
                header.execution = ExecutionPayloadHeader::default();
                header.execution_branch = Default::default();
            }
            header
        }

        /// A bootstrap at `slot` for committee 0.
        fn bootstrap(&self, slot: u64) -> LightClientBootstrap {
            let leaves = [(54, self.committees[0].hash_tree_root())];
            LightClientBootstrap {
                header: self.header(slot, &leaves),
                current_sync_committee: self.committees[0].clone(),
                current_sync_committee_branch: branch(&leaves, 54, STATE_DEPTH),
            }
        }

        /// A store bootstrapped at slot 8, in period 0.
        fn store(&self) -> LightClientStore {
            let bootstrap = self.bootstrap(8);
            let root = bootstrap.header.beacon.hash_tree_root();
            LightClientStore::bootstrap(Preset::MINIMAL, self.beacon, root, &bootstrap).unwrap()
        }

        /// The signing root of `header` for a signature at `signature_slot`, with the domain
        /// parts given.
        fn signing_root_with(
            header: &BeaconBlockHeader,
            domain_type: [u8; 4],
            version: [u8; 4],
            genesis_validators_root: B256,
        ) -> B256 {
            let domain = compute_domain(domain_type, version, genesis_validators_root);
            compute_signing_root(header.hash_tree_root(), domain)
        }

        /// The fork version a signature at `signature_slot` uses.
        fn version(&self, signature_slot: u64) -> [u8; 4] {
            let epoch = Preset::MINIMAL.epoch_at_slot(signature_slot.max(1) - 1);
            self.beacon.fork_at_epoch(epoch).version
        }

        fn update(&self, spec: Spec) -> LightClientUpdate {
            let finalized = spec.finalized.map(|slot| self.header(slot, &[]));
            let mut leaves = Vec::new();
            if let Some(finalized) = &finalized {
                leaves.push((105, finalized.beacon.hash_tree_root()));
            }
            if let Some(next) = spec.next {
                leaves.push((55, self.committees[next].hash_tree_root()));
            }
            let attested_header = self.header(spec.attested, &leaves);
            let root = Self::signing_root_with(
                &attested_header.beacon,
                DOMAIN_SYNC_COMMITTEE,
                self.version(spec.signature),
                GVR,
            );
            LightClientUpdate {
                sync_aggregate: aggregate(&self.keys[spec.signer], spec.participants, root),
                attested_header,
                next_sync_committee: spec
                    .next
                    .map_or_else(empty_committee, |next| self.committees[next].clone()),
                next_sync_committee_branch: if spec.next.is_some() {
                    branch(&leaves, 55, STATE_DEPTH)
                } else {
                    vec![B256::ZERO; 5]
                },
                finalized_header: finalized.unwrap_or_default(),
                finality_branch: if spec.finalized.is_some() {
                    branch(&leaves, 105, STATE_DEPTH)
                } else {
                    vec![B256::ZERO; 6]
                },
                signature_slot: spec.signature,
            }
        }

        /// Re-signs `update` with committee `signer` and the domain parts given.
        fn resign(
            &self,
            update: &mut LightClientUpdate,
            signer: usize,
            domain_type: [u8; 4],
            version: [u8; 4],
            genesis_validators_root: B256,
        ) {
            let root = Self::signing_root_with(
                &update.attested_header.beacon,
                domain_type,
                version,
                genesis_validators_root,
            );
            update.sync_aggregate = aggregate(&self.keys[signer], 32, root);
        }
    }

    /// The update that proves committee 1 and finalizes slot 16 in period 0.
    const LEARN_NEXT: Spec = Spec::new(20, Some(16), Some(1));

    /// The update that finalizes slot 72 in period 1, signed by committee 1, naming committee 2.
    const ROTATE: Spec = Spec { signer: 1, ..Spec::new(80, Some(72), Some(2)) };

    /// The slots of the store's finalized and optimistic headers and its period.
    fn slots(store: &LightClientStore) -> (u64, u64, u64) {
        (
            store.finalized_header().beacon.slot,
            store.optimistic_header().beacon.slot,
            store.period(),
        )
    }

    /// Checks that `update` fails with `error` and leaves `store` as it was.
    fn assert_refused(
        store: &mut LightClientStore,
        update: &LightClientUpdate,
        current_slot: u64,
        error: SyncCommitteeError,
    ) {
        let before = (
            slots(store),
            store.current_sync_committee().clone(),
            store.next_sync_committee().cloned(),
        );
        assert_eq!(store.process_update(update, current_slot), Err(error));
        let after = (
            slots(store),
            store.current_sync_committee().clone(),
            store.next_sync_committee().cloned(),
        );
        assert_eq!(before, after);
    }

    #[test]
    fn a_bootstrap_starts_the_store_at_the_trusted_header() {
        let chain = TestChain::capella();
        let store = chain.store();
        assert_eq!(slots(&store), (8, 8, 0));
        assert_eq!(store.current_sync_committee(), &chain.committees[0]);
        assert_eq!(store.next_sync_committee(), None);
        assert_eq!(store.optimistic_header().execution.block_number, 8);
    }

    #[test]
    fn a_bootstrap_for_another_root_or_field_fails() {
        let chain = TestChain::capella();
        let bootstrap = chain.bootstrap(8);
        let root = bootstrap.header.beacon.hash_tree_root();
        let other = B256::repeat_byte(7);
        assert_eq!(
            LightClientStore::bootstrap(Preset::MINIMAL, chain.beacon, other, &bootstrap).err(),
            Some(SyncCommitteeError::BootstrapRoot { trusted: other, got: root })
        );

        // The committee sits at `NEXT_SYNC_COMMITTEE_GINDEX`, not at the current one.
        let leaves = [(55, chain.committees[0].hash_tree_root())];
        let wrong_field = LightClientBootstrap {
            header: chain.header(8, &leaves),
            current_sync_committee: chain.committees[0].clone(),
            current_sync_committee_branch: branch(&leaves, 55, STATE_DEPTH),
        };
        let root = wrong_field.header.beacon.hash_tree_root();
        let state_root = wrong_field.header.beacon.state_root;
        assert_eq!(
            LightClientStore::bootstrap(Preset::MINIMAL, chain.beacon, root, &wrong_field).err(),
            Some(SyncCommitteeError::CurrentCommitteeBranch(state_root))
        );

        let mut forged = chain.bootstrap(8);
        forged.header.execution.block_hash = B256::repeat_byte(0xee);
        let body_root = forged.header.beacon.body_root;
        let root = forged.header.beacon.hash_tree_root();
        assert_eq!(
            LightClientStore::bootstrap(Preset::MINIMAL, chain.beacon, root, &forged).err(),
            Some(SyncCommitteeError::ExecutionBranch(body_root))
        );
    }

    /// A committee key that is the identity point is refused, even with a valid branch.
    #[test]
    fn a_bootstrap_committee_with_an_invalid_key_fails() {
        let chain = TestChain::capella();
        let mut committee = chain.committees[0].clone();
        let mut infinity = [0; 48];
        infinity[0] = 0xc0;
        committee.pubkeys[3] = FixedBytes(infinity);
        let leaves = [(54, committee.hash_tree_root())];
        let bootstrap = LightClientBootstrap {
            header: chain.header(8, &leaves),
            current_sync_committee: committee,
            current_sync_committee_branch: branch(&leaves, 54, STATE_DEPTH),
        };
        let root = bootstrap.header.beacon.hash_tree_root();
        assert_eq!(
            LightClientStore::bootstrap(Preset::MINIMAL, chain.beacon, root, &bootstrap).err(),
            Some(SyncCommitteeError::PublicKey {
                index: 3,
                error: BLST_ERROR::BLST_PK_IS_INFINITY
            })
        );
    }

    /// `Phase0` slots have no sync committee, so a bootstrap there is refused.
    #[test]
    fn a_bootstrap_before_altair_is_refused() {
        let chain = TestChain::new(beacon(1, 1));
        let bootstrap = chain.bootstrap(3);
        let root = bootstrap.header.beacon.hash_tree_root();
        assert_eq!(
            LightClientStore::bootstrap(Preset::MINIMAL, chain.beacon, root, &bootstrap).err(),
            Some(SyncCommitteeError::UnsupportedFork(BeaconFork::Phase0))
        );
    }

    /// A store restored from its finalized header and committees takes the updates the saved
    /// store would have taken.
    #[test]
    fn a_restored_store_continues_where_the_saved_one_stopped() {
        let chain = TestChain::capella();
        let mut saved = chain.store();
        saved.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        let mut restored = LightClientStore::restore(
            Preset::MINIMAL,
            chain.beacon,
            saved.finalized_header().clone(),
            saved.current_sync_committee().clone(),
            saved.next_sync_committee().cloned(),
        )
        .unwrap();
        // The optimistic header starts at the finalized one.
        assert_eq!(slots(&restored), (16, 16, 0));
        assert_eq!(restored.next_sync_committee(), Some(&chain.committees[1]));
        restored.process_update(&chain.update(ROTATE), 81).unwrap();
        assert_eq!(slots(&restored), (72, 80, 1));
        assert_eq!(restored.current_sync_committee(), &chain.committees[1]);

        // Without the next committee, it learns it again from an update.
        let mut restored = LightClientStore::restore(
            Preset::MINIMAL,
            chain.beacon,
            chain.store().finalized_header().clone(),
            chain.committees[0].clone(),
            None,
        )
        .unwrap();
        restored.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        assert_eq!(restored.next_sync_committee(), Some(&chain.committees[1]));
    }

    /// A restore checks the header's execution branch and every committee key.
    #[test]
    fn a_restore_with_a_bad_header_or_key_fails() {
        let chain = TestChain::capella();
        let header = chain.store().finalized_header().clone();
        let restore = |header: &LightClientHeader, next: Option<SyncCommittee>| {
            LightClientStore::restore(
                Preset::MINIMAL,
                chain.beacon,
                header.clone(),
                chain.committees[0].clone(),
                next,
            )
            .err()
        };
        let mut forged = header.clone();
        forged.execution.block_hash = B256::repeat_byte(0xee);
        assert_eq!(
            restore(&forged, None),
            Some(SyncCommitteeError::ExecutionBranch(header.beacon.body_root))
        );
        let mut next = chain.committees[1].clone();
        let mut infinity = [0; 48];
        infinity[0] = 0xc0;
        next.pubkeys[5] = FixedBytes(infinity);
        assert_eq!(
            restore(&header, Some(next)),
            Some(SyncCommitteeError::PublicKey {
                index: 5,
                error: BLST_ERROR::BLST_PK_IS_INFINITY
            })
        );
    }

    #[test]
    fn a_finality_update_moves_both_headers_and_learns_the_next_committee() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        assert_eq!(slots(&store), (16, 20, 0));
        assert_eq!(store.next_sync_committee(), Some(&chain.committees[1]));
        assert_eq!(store.optimistic_header().execution.block_hash, B256::with_last_byte(20));
        assert_eq!(store.finalized_header().execution.block_hash, B256::with_last_byte(16));
    }

    #[test]
    fn an_update_without_finality_moves_only_the_optimistic_header() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(Spec::new(30, None, None)), 31).unwrap();
        assert_eq!(slots(&store), (8, 30, 0));
        assert_eq!(store.next_sync_committee(), None);
        // An older update that still attests after the finalized slot changes nothing.
        store.process_update(&chain.update(Spec::new(25, None, None)), 31).unwrap();
        assert_eq!(slots(&store), (8, 30, 0));
    }

    #[test]
    fn finality_in_the_next_period_rotates_the_committees() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        store.process_update(&chain.update(ROTATE), 81).unwrap();
        assert_eq!(slots(&store), (72, 80, 1));
        assert_eq!(store.current_sync_committee(), &chain.committees[1]);
        assert_eq!(store.next_sync_committee(), Some(&chain.committees[2]));
    }

    /// The next committee signs before finality reaches its period; the committees rotate only
    /// with finality.
    #[test]
    fn the_next_committee_signs_without_rotating_until_finality() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        let spec = Spec { signer: 1, ..Spec::new(66, Some(40), None) };
        store.process_update(&chain.update(spec), 67).unwrap();
        assert_eq!(slots(&store), (40, 66, 0));
        assert_eq!(store.current_sync_committee(), &chain.committees[0]);
        assert_eq!(store.next_sync_committee(), Some(&chain.committees[1]));
    }

    #[test]
    fn participation_below_two_thirds_fails() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        let update = chain.update(Spec { participants: 21, ..LEARN_NEXT });
        assert_refused(
            &mut store,
            &update,
            21,
            SyncCommitteeError::TooFewParticipants { participants: 21, size: 32 },
        );
        store.process_update(&chain.update(Spec { participants: 22, ..LEARN_NEXT }), 21).unwrap();
        assert_eq!(slots(&store), (16, 20, 0));

        assert!(!has_supermajority(341, 512));
        assert!(has_supermajority(342, 512));
        assert!(has_supermajority(512, 512));
    }

    #[test]
    fn a_wrong_domain_or_fork_version_fails() {
        let chain = TestChain::capella();
        let capella = chain.version(21);
        let signature_error = SyncCommitteeError::Signature(BLST_ERROR::BLST_VERIFY_FAIL);
        for (domain_type, version, gvr) in [
            (DOMAIN_BEACON_PROPOSER, capella, GVR),
            (DOMAIN_SYNC_COMMITTEE, [1, 0, 0, 1], GVR),
            (DOMAIN_SYNC_COMMITTEE, capella, B256::repeat_byte(1)),
        ] {
            let mut store = chain.store();
            let mut update = chain.update(LEARN_NEXT);
            chain.resign(&mut update, 0, domain_type, version, gvr);
            assert_refused(&mut store, &update, 21, signature_error.clone());
        }
        // The same parts with the right values verify.
        let mut store = chain.store();
        let mut update = chain.update(LEARN_NEXT);
        chain.resign(&mut update, 0, DOMAIN_SYNC_COMMITTEE, capella, GVR);
        assert_eq!(store.process_update(&update, 21), Ok(()));
    }

    /// The domain takes the fork version of the slot before the signature slot. At the first
    /// Capella slot that is still Bellatrix.
    #[test]
    fn the_domain_uses_the_fork_of_the_slot_before_the_signature() {
        // Capella starts at epoch 3, slot 24.
        let chain = TestChain::new(beacon(0, 3));
        let bellatrix = [2, 0, 0, 1];
        let capella = [3, 0, 0, 1];
        assert_eq!(chain.version(24), bellatrix);
        assert_eq!(chain.version(25), capella);

        let mut store = chain.store();
        assert_eq!(store.finalized_header().execution, ExecutionPayloadHeader::default());
        let mut update = chain.update(Spec::new(23, Some(16), None));
        assert_eq!(update.signature_slot, 24);
        chain.resign(&mut update, 0, DOMAIN_SYNC_COMMITTEE, capella, GVR);
        assert_refused(
            &mut store,
            &update,
            24,
            SyncCommitteeError::Signature(BLST_ERROR::BLST_VERIFY_FAIL),
        );
        chain.resign(&mut update, 0, DOMAIN_SYNC_COMMITTEE, bellatrix, GVR);
        store.process_update(&update, 24).unwrap();
        assert_eq!(slots(&store), (16, 23, 0));

        // The first Capella header proves its execution part.
        store.process_update(&chain.update(Spec::new(24, Some(16), None)), 25).unwrap();
        assert_eq!(store.optimistic_header().execution.block_number, 24);
    }

    #[test]
    fn a_forged_signature_fails() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        let verify_fail = SyncCommitteeError::Signature(BLST_ERROR::BLST_VERIFY_FAIL);

        // Keys outside the committee sign.
        let update = chain.update(Spec { signer: 2, ..LEARN_NEXT });
        assert_refused(&mut store, &update, 21, verify_fail.clone());

        // The bits claim a member that did not sign.
        let mut update = chain.update(Spec { participants: 31, ..LEARN_NEXT });
        update.sync_aggregate.sync_committee_bits[3] |= 0x80;
        assert_eq!(update.sync_aggregate.participants(), 32);
        assert_refused(&mut store, &update, 21, verify_fail.clone());

        // The attested header changes after the committee signed it.
        let mut update = chain.update(LEARN_NEXT);
        update.attested_header.beacon.proposer_index += 1;
        assert_refused(&mut store, &update, 21, verify_fail);

        // The identity point, and bytes that are no point at all.
        let mut update = chain.update(LEARN_NEXT);
        let mut infinity = [0; 96];
        infinity[0] = 0xc0;
        update.sync_aggregate.sync_committee_signature = FixedBytes(infinity);
        assert_refused(
            &mut store,
            &update,
            21,
            SyncCommitteeError::SignatureEncoding(BLST_ERROR::BLST_PK_IS_INFINITY),
        );
        update.sync_aggregate.sync_committee_signature = FixedBytes([0xff; 96]);
        assert_refused(
            &mut store,
            &update,
            21,
            SyncCommitteeError::SignatureEncoding(BLST_ERROR::BLST_BAD_ENCODING),
        );
    }

    #[test]
    fn an_update_older_than_the_store_fails() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        for attested in [16, 12] {
            let update = chain.update(Spec::new(attested, None, None));
            assert_refused(
                &mut store,
                &update,
                21,
                SyncCommitteeError::Stale { attested, finalized: 16 },
            );
        }
        // The update that moved the store does not move it again, and does not fail.
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        assert_eq!(slots(&store), (16, 20, 0));
    }

    /// Before the store knows the next committee, an older update in its period may supply it.
    #[test]
    fn an_older_update_may_supply_the_next_committee() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(Spec::new(6, Some(4), Some(1))), 9).unwrap();
        assert_eq!(slots(&store), (8, 8, 0));
        assert_eq!(store.next_sync_committee(), Some(&chain.committees[1]));
    }

    #[test]
    fn a_rotation_without_a_valid_next_committee_branch_fails() {
        let chain = TestChain::capella();

        // No next committee is known, so a period-1 signature has no committee to check.
        let mut store = chain.store();
        assert_refused(
            &mut store,
            &chain.update(ROTATE),
            81,
            SyncCommitteeError::SignaturePeriod {
                signature_period: 1,
                store_period: 0,
                next_known: false,
            },
        );

        // A damaged branch, and a branch that proves the current committee's field.
        let mut update = chain.update(LEARN_NEXT);
        update.next_sync_committee_branch[1] = B256::repeat_byte(1);
        let state_root = update.attested_header.beacon.state_root;
        assert_refused(
            &mut store,
            &update,
            21,
            SyncCommitteeError::NextCommitteeBranch(state_root),
        );
        let leaves = [(54, chain.committees[1].hash_tree_root())];
        let mut update = chain.update(LEARN_NEXT);
        update.attested_header = chain.header(20, &leaves);
        update.next_sync_committee_branch = branch(&leaves, 54, STATE_DEPTH);
        update.finality_branch = vec![B256::ZERO; 6];
        update.finalized_header = LightClientHeader::default();
        chain.resign(&mut update, 0, DOMAIN_SYNC_COMMITTEE, chain.version(21), GVR);
        let state_root = update.attested_header.beacon.state_root;
        assert_refused(
            &mut store,
            &update,
            21,
            SyncCommitteeError::NextCommitteeBranch(state_root),
        );

        // With the next committee known, a rotation whose own next branch is damaged.
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        let mut update = chain.update(ROTATE);
        update.next_sync_committee_branch[4] = B256::repeat_byte(1);
        let state_root = update.attested_header.beacon.state_root;
        assert_refused(
            &mut store,
            &update,
            81,
            SyncCommitteeError::NextCommitteeBranch(state_root),
        );
        assert_eq!(store.current_sync_committee(), &chain.committees[0]);
    }

    #[test]
    fn a_known_next_committee_cannot_change_in_its_period() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        store.process_update(&chain.update(LEARN_NEXT), 21).unwrap();
        let update = chain.update(Spec::new(30, None, Some(2)));
        assert_refused(&mut store, &update, 31, SyncCommitteeError::NextCommitteeChanged);
        // The same committee again is fine.
        store.process_update(&chain.update(Spec::new(30, None, Some(1))), 31).unwrap();
        assert_eq!(slots(&store), (16, 30, 0));
    }

    #[test]
    fn a_finality_branch_for_the_wrong_field_fails() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        let finalized = chain.header(16, &[]);
        // Gindex 104 is `finalized_checkpoint.epoch`, the root's sibling.
        let leaves = [(104, finalized.beacon.hash_tree_root())];
        let mut update = chain.update(LEARN_NEXT);
        update.attested_header = chain.header(20, &leaves);
        update.finality_branch = branch(&leaves, 104, STATE_DEPTH);
        update.next_sync_committee = empty_committee();
        update.next_sync_committee_branch = vec![B256::ZERO; 5];
        chain.resign(&mut update, 0, DOMAIN_SYNC_COMMITTEE, chain.version(21), GVR);
        let state_root = update.attested_header.beacon.state_root;
        assert_refused(&mut store, &update, 21, SyncCommitteeError::FinalityBranch(state_root));
    }

    /// The committee signs only the beacon header, so a forged execution part keeps a valid
    /// signature. The execution branch catches it.
    #[test]
    fn an_update_whose_execution_branch_does_not_match_fails() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        let mut update = chain.update(LEARN_NEXT);
        update.attested_header.execution.block_hash = B256::repeat_byte(0xee);
        let body_root = update.attested_header.beacon.body_root;
        assert_refused(&mut store, &update, 21, SyncCommitteeError::ExecutionBranch(body_root));

        let mut update = chain.update(LEARN_NEXT);
        update.finalized_header.execution.state_root = B256::repeat_byte(0xee);
        let body_root = update.finalized_header.beacon.body_root;
        assert_refused(&mut store, &update, 21, SyncCommitteeError::ExecutionBranch(body_root));
    }

    #[test]
    fn slots_out_of_order_fail() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        // The signature slot is after the current slot.
        assert_refused(
            &mut store,
            &chain.update(LEARN_NEXT),
            20,
            SyncCommitteeError::SlotOrder {
                current: 20,
                signature: 21,
                attested: 20,
                finalized: 16,
            },
        );
        // The committee signs in the attested slot itself.
        let update = chain.update(Spec { signature: 20, ..LEARN_NEXT });
        assert_refused(
            &mut store,
            &update,
            21,
            SyncCommitteeError::SlotOrder {
                current: 21,
                signature: 20,
                attested: 20,
                finalized: 16,
            },
        );
    }

    #[test]
    fn a_committee_or_finalized_header_without_its_branch_fails() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        let mut update = chain.update(Spec::new(20, None, None));
        update.next_sync_committee = chain.committees[1].clone();
        assert_refused(&mut store, &update, 21, SyncCommitteeError::UnexpectedNextCommittee);

        let mut update = chain.update(Spec::new(20, None, None));
        update.finalized_header = chain.header(16, &[]);
        assert_refused(&mut store, &update, 21, SyncCommitteeError::UnexpectedFinalizedHeader);
    }

    /// As the spec asks, a finality update at the genesis slot proves the zero root and carries
    /// the empty header. A real header at slot 0 is refused, even with a branch that proves it.
    #[test]
    fn a_finalized_header_at_the_genesis_slot_must_be_empty() {
        let chain = TestChain::capella();
        let mut store = chain.store();
        let update = chain.update(Spec::new(20, Some(0), Some(1)));
        assert_eq!(update.finalized_header.beacon.slot, 0);
        assert_ne!(update.finalized_header, LightClientHeader::default());
        assert_refused(&mut store, &update, 21, SyncCommitteeError::UnexpectedFinalizedHeader);
    }

    impl Real369 {
        /// The domain of the block's `sync_aggregate` on `chain_id`: the fork of the slot
        /// before the block.
        fn domain(&self, chain_id: u64) -> B256 {
            let beacon = network(chain_id);
            let epoch = Preset::PULSECHAIN.epoch_at_slot(self.header.slot - 1);
            compute_domain(
                DOMAIN_SYNC_COMMITTEE,
                beacon.fork_at_epoch(epoch).version,
                beacon.genesis_validators_root,
            )
        }

        /// Checks the block's `sync_aggregate` over `signed_root` with `domain`.
        fn verify(
            &self,
            aggregate: &SyncAggregate,
            signed_root: B256,
            domain: B256,
        ) -> Result<(), SyncCommitteeError> {
            CommitteeKeys::new(self.committee.clone())?
                .verify(aggregate, compute_signing_root(signed_root, domain))
        }
    }

    fn network(chain_id: u64) -> PulsechainBeacon {
        reth_pulsechain_forks::network::pulsechain_network(chain_id).unwrap().beacon
    }

    /// The header fields hash to the finalized block root that Checkpointz served.
    #[test]
    fn real_369_header_hashes_to_the_finalized_block_root() {
        let real = Real369::load();
        assert_eq!(real.header.hash_tree_root(), hash(&real.json["block_root"]));
        assert_eq!(real.header.slot, 11_167_808);
    }

    /// The committee proves into the real state root at the standard Capella gindex 54, so
    /// `PulseChain`'s `BeaconState` has the standard field layout.
    #[test]
    fn real_369_committee_proves_into_the_state_root_at_gindex_54() {
        let real = Real369::load();
        let gindex = capella().current_sync_committee;
        assert_eq!(gindex, 54);
        let leaf = real.committee.hash_tree_root();
        assert_eq!(leaf, hash(&real.json["current_sync_committee_root"]));
        let branch = real.branch("current_sync_committee_branch");
        let state_root = real.header.state_root;
        assert!(is_valid_merkle_branch(leaf, &branch, gindex, state_root));

        // The next committee's index, and a branch with one flipped bit, do not prove.
        assert!(!is_valid_merkle_branch(leaf, &branch, capella().next_sync_committee, state_root));
        let mut flipped = branch;
        flipped[2][31] ^= 1;
        assert!(!is_valid_merkle_branch(leaf, &flipped, gindex, state_root));
    }

    /// The real block bootstraps a store: the committee branch, the execution branch at gindex
    /// 25 and all 512 keys check out.
    #[test]
    fn real_369_bootstrap_starts_a_store_at_the_finalized_block() {
        let real = Real369::load();
        let root = hash(&real.json["block_root"]);
        let store =
            LightClientStore::bootstrap(Preset::PULSECHAIN, network(369), root, &real.bootstrap())
                .unwrap();
        let execution = &store.finalized_header().execution;
        assert_eq!(execution.block_hash, hash(&real.json["execution_block_hash"]));
        assert_eq!(execution.block_number, 28_133_431);
        assert_eq!(execution.hash_tree_root(), hash(&real.json["execution_payload_header_root"]));

        let mut bootstrap = real.bootstrap();
        bootstrap.header.execution.block_number += 1;
        assert_eq!(
            LightClientStore::bootstrap(Preset::PULSECHAIN, network(369), root, &bootstrap)
                .unwrap_err(),
            SyncCommitteeError::ExecutionBranch(real.header.body_root)
        );
    }

    /// The block's `sync_aggregate` signs its parent root under the pinned 369 domain.
    #[test]
    fn real_369_sync_aggregate_verifies_under_the_369_domain() {
        let real = Real369::load();
        assert_eq!(real.aggregate.participants(), 495);
        assert!(has_supermajority(real.aggregate.participants(), 512));
        let parent = real.header.parent_root;
        assert_eq!(real.verify(&real.aggregate, parent, real.domain(369)), Ok(()));
    }

    /// One flipped bit in the signed root or the participation bits, or the 943 domain, fails.
    #[test]
    fn real_369_sync_aggregate_fails_with_a_flipped_bit_or_the_943_domain() {
        let real = Real369::load();
        let verify_fail = Err(SyncCommitteeError::Signature(BLST_ERROR::BLST_VERIFY_FAIL));
        let parent = real.header.parent_root;
        let domain = real.domain(369);

        let mut flipped_root = parent;
        flipped_root[0] ^= 1;
        assert_eq!(real.verify(&real.aggregate, flipped_root, domain), verify_fail);

        // Member 7 signed; without its bit the aggregate key no longer matches the signature.
        let mut aggregate = real.aggregate.clone();
        assert!(aggregate.signed(7));
        aggregate.sync_committee_bits[0] ^= 1 << 7;
        assert_eq!(real.verify(&aggregate, parent, domain), verify_fail);

        assert_ne!(real.domain(943), domain);
        assert_eq!(real.verify(&real.aggregate, parent, real.domain(943)), verify_fail);

        // The 369 Bellatrix version with the 369 root is a wrong fork version.
        let gvr = network(369).genesis_validators_root;
        let bellatrix = compute_domain(DOMAIN_SYNC_COMMITTEE, 0x0000_036b_u32.to_be_bytes(), gvr);
        assert_eq!(real.verify(&real.aggregate, parent, bellatrix), verify_fail);
    }
}
