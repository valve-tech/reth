//! The beacon API's JSON form of the light-client answers, read and written, and the check of a
//! source's genesis and fork schedule against the pinned chain values.
//!
//! Reading is strict: each field the answer's kind carries is required, numbers are decimal
//! strings, and each branch has the depth of its gindex. Nothing here checks a signature or a
//! branch: [`LightClientStore`](crate::sync_committee::LightClientStore) does that.

use crate::sync_committee::{
    BeaconBlockHeader, ExecutionPayloadHeader, Gindices, LightClientBootstrap, LightClientHeader,
    LightClientUpdate, Preset, SyncAggregate, SyncCommittee, EXECUTION_BRANCH_DEPTH,
};
use alloy_primitives::{hex, Address, Bloom, Bytes, FixedBytes, B256, U256};
use reth_pulsechain_forks::network::{BeaconFork, PulsechainBeacon};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// Why a light-client JSON answer was not read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// The JSON is not what the beacon API sends.
    #[error("malformed light-client JSON")]
    Malformed,
    /// Light-client data of a fork this crate has no light-client types for, such as Deneb.
    #[error("light-client data of an unsupported fork")]
    UnsupportedFork,
}

/// What a source's `/eth/v1/beacon/genesis` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Genesis {
    /// The start of slot 0, in seconds since the Unix epoch.
    pub genesis_time: u64,
    /// The root of the genesis validator set.
    pub genesis_validators_root: B256,
    /// The fork version at genesis.
    pub genesis_fork_version: [u8; 4],
}

/// One entry of a source's `/eth/v1/config/fork_schedule`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledFork {
    /// The fork version before the fork.
    pub previous_version: [u8; 4],
    /// The fork version from `epoch` on.
    pub current_version: [u8; 4],
    /// The first epoch of the fork. `u64::MAX` (`FAR_FUTURE_EPOCH`) means not scheduled.
    pub epoch: u64,
}

/// Which light-client update an answer holds. The spec's optimistic and finality updates are
/// updates with some fields left at their defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateKind {
    /// A `LightClientUpdate`, from `updates`.
    Full,
    /// A `LightClientFinalityUpdate`: no next committee.
    Finality,
    /// A `LightClientOptimisticUpdate`: no finality and no next committee.
    Optimistic,
}

/// How a source or the anchor differs from the pinned chain values.
///
/// `E` is the caller's error for a failed read. [`check_pins`] never returns
/// [`PinError::Unreadable`]: a caller that reads the values over the network does.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError<E> {
    /// The source did not answer one of the two endpoints.
    #[error("{endpoint}: {error}")]
    Unreadable {
        /// The endpoint.
        endpoint: &'static str,
        /// What went wrong.
        error: E,
    },
    /// Another `genesis_validators_root`: another chain.
    #[error("genesis_validators_root {got} is not the pinned {want}")]
    GenesisValidatorsRoot {
        /// What the source sent.
        got: B256,
        /// The pinned value.
        want: B256,
    },
    /// Another `genesis_time`.
    #[error("genesis_time {got} is not the pinned {want}")]
    GenesisTime {
        /// What the source sent.
        got: u64,
        /// The pinned value.
        want: u64,
    },
    /// Another genesis fork version.
    #[error("genesis_fork_version {} is not the pinned {}", hex::encode_prefixed(.got), hex::encode_prefixed(.want))]
    GenesisForkVersion {
        /// What the source sent.
        got: [u8; 4],
        /// The pinned value.
        want: [u8; 4],
    },
    /// The scheduled forks differ.
    #[error("the fork schedule [{got}] is not the pinned [{want}]")]
    ForkSchedule {
        /// The source's scheduled forks, as `version@epoch`.
        got: String,
        /// The pinned forks, as `version@epoch`.
        want: String,
    },
}

/// Checks a source's genesis and fork schedule against `pins`.
///
/// Every pinned fork must be scheduled at its version and epoch. A fork the pins do not have may
/// appear only at `FAR_FUTURE_EPOCH`, as Deneb and Electra do on `PulseChain` today.
pub fn check_pins<E>(
    genesis: &Genesis,
    schedule: &[ScheduledFork],
    pins: &PulsechainBeacon,
) -> Result<(), PinError<E>> {
    check_genesis(genesis, pins)?;
    let mut got: Vec<([u8; 4], u64)> = schedule
        .iter()
        .filter(|f| f.epoch != u64::MAX)
        .map(|f| (f.current_version, f.epoch))
        .collect();
    got.sort_unstable_by_key(|&(version, epoch)| (epoch, version));
    let want: Vec<([u8; 4], u64)> = pins.forks.iter().map(|f| (f.version, f.epoch)).collect();
    if got != want {
        let show = |forks: &[([u8; 4], u64)]| {
            forks
                .iter()
                .map(|(version, epoch)| format!("{}@{epoch}", hex::encode_prefixed(version)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(PinError::ForkSchedule { got: show(&got), want: show(&want) });
    }
    Ok(())
}

/// Checks a source's genesis against `pins`: the validators root, the time and the genesis fork
/// version. [`check_pins`] also checks the fork schedule.
pub fn check_genesis<E>(genesis: &Genesis, pins: &PulsechainBeacon) -> Result<(), PinError<E>> {
    if genesis.genesis_validators_root != pins.genesis_validators_root {
        return Err(PinError::GenesisValidatorsRoot {
            got: genesis.genesis_validators_root,
            want: pins.genesis_validators_root,
        });
    }
    if genesis.genesis_time != pins.genesis_time {
        return Err(PinError::GenesisTime { got: genesis.genesis_time, want: pins.genesis_time });
    }
    let genesis_version = pins.forks[0].version;
    if genesis.genesis_fork_version != genesis_version {
        return Err(PinError::GenesisForkVersion {
            got: genesis.genesis_fork_version,
            want: genesis_version,
        });
    }
    Ok(())
}

/// Parses a `/eth/v1/beacon/genesis` answer.
pub fn parse_genesis(bytes: &[u8]) -> Result<Genesis, JsonError> {
    let data = parse::<Data<GenesisJson>>(bytes)?.data;
    Ok(Genesis {
        genesis_time: data.genesis_time,
        genesis_validators_root: data.genesis_validators_root,
        genesis_fork_version: data.genesis_fork_version.0,
    })
}

/// Parses a `/eth/v1/config/fork_schedule` answer.
pub fn parse_fork_schedule(bytes: &[u8]) -> Result<Vec<ScheduledFork>, JsonError> {
    Ok(parse::<Data<Vec<ForkJson>>>(bytes)?
        .data
        .into_iter()
        .map(|f| ScheduledFork {
            previous_version: f.previous_version.0,
            current_version: f.current_version.0,
            epoch: f.epoch,
        })
        .collect())
}

/// Parses a `bootstrap` answer.
pub fn parse_bootstrap(bytes: &[u8], preset: Preset) -> Result<LightClientBootstrap, JsonError> {
    let answer = parse::<Versioned<BootstrapJson>>(bytes)?;
    let fork = fork_of_name(&answer.version)?;
    let gindices = gindices(fork)?;
    let data = answer.data;
    Ok(LightClientBootstrap {
        header: data.header.into_header(fork)?,
        current_sync_committee: data.current_sync_committee.into_committee(preset)?,
        current_sync_committee_branch: branch(
            data.current_sync_committee_branch,
            gindices.current_sync_committee,
        )?,
    })
}

/// Parses an `updates` answer of at most `count` updates.
pub fn parse_updates(
    bytes: &[u8],
    preset: Preset,
    count: usize,
) -> Result<Vec<LightClientUpdate>, JsonError> {
    let answers = parse::<Vec<Versioned<UpdateJson>>>(bytes)?;
    if answers.len() > count {
        return Err(JsonError::Malformed);
    }
    answers.into_iter().map(|a| a.into_update(preset, UpdateKind::Full)).collect()
}

/// Parses one update answer of `kind`: a REST answer or the data of an event.
pub fn parse_update(
    bytes: &[u8],
    preset: Preset,
    kind: UpdateKind,
) -> Result<LightClientUpdate, JsonError> {
    parse::<Versioned<UpdateJson>>(bytes)?.into_update(preset, kind)
}

/// Writes `bootstrap` as the `bootstrap` endpoint sends it at `fork`.
pub fn bootstrap_json(
    bootstrap: &LightClientBootstrap,
    fork: BeaconFork,
) -> Result<Value, JsonError> {
    let data = BootstrapJson {
        header: HeaderJson::new(&bootstrap.header, fork)?,
        current_sync_committee: CommitteeJson::new(&bootstrap.current_sync_committee),
        current_sync_committee_branch: bootstrap.current_sync_committee_branch.clone(),
    };
    versioned(fork, data)
}

/// Writes `update` at `fork` as the endpoint for `kind` sends it: without the fields `kind`
/// does not carry. The fields it carries are written as they are, so a branch of the wrong depth
/// is written too and [`parse_update`] refuses it.
pub fn update_json(
    update: &LightClientUpdate,
    fork: BeaconFork,
    kind: UpdateKind,
) -> Result<Value, JsonError> {
    let (next_sync_committee, next_sync_committee_branch) = match kind {
        UpdateKind::Full => (
            Some(CommitteeJson::new(&update.next_sync_committee)),
            Some(update.next_sync_committee_branch.clone()),
        ),
        UpdateKind::Finality | UpdateKind::Optimistic => (None, None),
    };
    let (finalized_header, finality_branch) = match kind {
        UpdateKind::Full | UpdateKind::Finality => (
            Some(HeaderJson::new(&update.finalized_header, fork)?),
            Some(update.finality_branch.clone()),
        ),
        UpdateKind::Optimistic => (None, None),
    };
    let aggregate = &update.sync_aggregate;
    let data = UpdateJson {
        attested_header: HeaderJson::new(&update.attested_header, fork)?,
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate: AggregateJson {
            sync_committee_bits: Bytes::copy_from_slice(aggregate.sync_committee_bits()),
            sync_committee_signature: *aggregate.sync_committee_signature(),
        },
        signature_slot: update.signature_slot,
    };
    versioned(fork, data)
}

/// `data` with the `version` of `fork`.
fn versioned<T: Serialize>(fork: BeaconFork, data: T) -> Result<Value, JsonError> {
    let version = name_of_fork(fork)?.to_owned();
    Ok(serde_json::to_value(Versioned { version, data })
        .expect("the light-client JSON types have string keys only"))
}

fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, JsonError> {
    serde_json::from_slice(bytes).map_err(|_| JsonError::Malformed)
}

/// The fork of a light-client answer's `version`. Only forks with light-client types parse.
fn fork_of_name(name: &str) -> Result<BeaconFork, JsonError> {
    match name {
        "altair" => Ok(BeaconFork::Altair),
        "bellatrix" => Ok(BeaconFork::Bellatrix),
        "capella" => Ok(BeaconFork::Capella),
        _ => Err(JsonError::UnsupportedFork),
    }
}

/// The `version` of a light-client answer at `fork`: the inverse of [`fork_of_name`].
const fn name_of_fork(fork: BeaconFork) -> Result<&'static str, JsonError> {
    match fork {
        BeaconFork::Altair => Ok("altair"),
        BeaconFork::Bellatrix => Ok("bellatrix"),
        BeaconFork::Capella => Ok("capella"),
        BeaconFork::Phase0 => Err(JsonError::UnsupportedFork),
    }
}

fn gindices(fork: BeaconFork) -> Result<Gindices, JsonError> {
    Gindices::for_fork(fork).ok_or(JsonError::UnsupportedFork)
}

/// Checks that `nodes` has the depth of `gindex`, as the SSZ form fixes it.
fn branch(nodes: Vec<B256>, gindex: u64) -> Result<Vec<B256>, JsonError> {
    if nodes.len() == gindex.ilog2() as usize {
        Ok(nodes)
    } else {
        Err(JsonError::Malformed)
    }
}

/// The all-zero branch of `gindex`, which marks a field an update does not carry.
pub(crate) fn zero_branch(gindex: u64) -> Vec<B256> {
    vec![B256::ZERO; gindex.ilog2() as usize]
}

/// A beacon API number: a decimal string.
mod decimal {
    use super::*;

    pub(super) fn serialize<S: Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse().ok())
            .flatten()
            .ok_or_else(|| D::Error::custom("not a decimal u64"))
    }
}

/// A beacon API `uint256`: a decimal string.
mod decimal_u256 {
    use super::*;

    pub(super) fn serialize<S: Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let s = String::deserialize(d)?;
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| U256::from_str_radix(&s, 10).ok())
            .flatten()
            .ok_or_else(|| D::Error::custom("not a decimal uint256"))
    }
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Serialize, Deserialize)]
struct Versioned<T> {
    version: String,
    data: T,
}

#[derive(Deserialize)]
struct GenesisJson {
    #[serde(with = "decimal")]
    genesis_time: u64,
    genesis_validators_root: B256,
    genesis_fork_version: FixedBytes<4>,
}

#[derive(Deserialize)]
struct ForkJson {
    previous_version: FixedBytes<4>,
    current_version: FixedBytes<4>,
    #[serde(with = "decimal")]
    epoch: u64,
}

#[derive(Serialize, Deserialize)]
struct BeaconHeaderJson {
    #[serde(with = "decimal")]
    slot: u64,
    #[serde(with = "decimal")]
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body_root: B256,
}

#[derive(Serialize, Deserialize)]
struct ExecutionJson {
    parent_hash: B256,
    fee_recipient: Address,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    prev_randao: B256,
    #[serde(with = "decimal")]
    block_number: u64,
    #[serde(with = "decimal")]
    gas_limit: u64,
    #[serde(with = "decimal")]
    gas_used: u64,
    #[serde(with = "decimal")]
    timestamp: u64,
    extra_data: Bytes,
    #[serde(with = "decimal_u256")]
    base_fee_per_gas: U256,
    block_hash: B256,
    transactions_root: B256,
    withdrawals_root: B256,
}

#[derive(Serialize, Deserialize)]
struct HeaderJson {
    beacon: BeaconHeaderJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<ExecutionJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_branch: Option<Vec<B256>>,
}

impl HeaderJson {
    /// `header` in `fork`'s form: with an execution part from Capella on, without one before.
    fn new(header: &LightClientHeader, fork: BeaconFork) -> Result<Self, JsonError> {
        let b = &header.beacon;
        let beacon = BeaconHeaderJson {
            slot: b.slot,
            proposer_index: b.proposer_index,
            parent_root: b.parent_root,
            state_root: b.state_root,
            body_root: b.body_root,
        };
        if gindices(fork)?.execution_payload.is_none() {
            return Ok(Self { beacon, execution: None, execution_branch: None });
        }
        let e = &header.execution;
        let execution = ExecutionJson {
            parent_hash: e.parent_hash,
            fee_recipient: e.fee_recipient,
            state_root: e.state_root,
            receipts_root: e.receipts_root,
            logs_bloom: e.logs_bloom,
            prev_randao: e.prev_randao,
            block_number: e.block_number,
            gas_limit: e.gas_limit,
            gas_used: e.gas_used,
            timestamp: e.timestamp,
            extra_data: e.extra_data.clone(),
            base_fee_per_gas: e.base_fee_per_gas,
            block_hash: e.block_hash,
            transactions_root: e.transactions_root,
            withdrawals_root: e.withdrawals_root,
        };
        Ok(Self {
            beacon,
            execution: Some(execution),
            execution_branch: Some(header.execution_branch.to_vec()),
        })
    }

    /// The header in `fork`'s form: with an execution part from Capella on, without one before.
    fn into_header(self, fork: BeaconFork) -> Result<LightClientHeader, JsonError> {
        let b = self.beacon;
        let beacon = BeaconBlockHeader {
            slot: b.slot,
            proposer_index: b.proposer_index,
            parent_root: b.parent_root,
            state_root: b.state_root,
            body_root: b.body_root,
        };
        match (gindices(fork)?.execution_payload, self.execution, self.execution_branch) {
            (Some(_), Some(e), Some(nodes)) => {
                let execution_branch: [B256; EXECUTION_BRANCH_DEPTH] =
                    nodes.try_into().map_err(|_| JsonError::Malformed)?;
                // `MAX_EXTRA_DATA_BYTES`, as the SSZ form limits it.
                if e.extra_data.len() > 32 {
                    return Err(JsonError::Malformed);
                }
                let execution = ExecutionPayloadHeader {
                    parent_hash: e.parent_hash,
                    fee_recipient: e.fee_recipient,
                    state_root: e.state_root,
                    receipts_root: e.receipts_root,
                    logs_bloom: e.logs_bloom,
                    prev_randao: e.prev_randao,
                    block_number: e.block_number,
                    gas_limit: e.gas_limit,
                    gas_used: e.gas_used,
                    timestamp: e.timestamp,
                    extra_data: e.extra_data,
                    base_fee_per_gas: e.base_fee_per_gas,
                    block_hash: e.block_hash,
                    transactions_root: e.transactions_root,
                    withdrawals_root: e.withdrawals_root,
                };
                Ok(LightClientHeader { beacon, execution, execution_branch })
            }
            (None, None, None) => Ok(LightClientHeader { beacon, ..Default::default() }),
            _ => Err(JsonError::Malformed),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CommitteeJson {
    pubkeys: Vec<FixedBytes<48>>,
    aggregate_pubkey: FixedBytes<48>,
}

impl CommitteeJson {
    fn new(committee: &SyncCommittee) -> Self {
        Self {
            pubkeys: committee.pubkeys().to_vec(),
            aggregate_pubkey: *committee.aggregate_pubkey(),
        }
    }

    /// The committee, which must have `preset`'s size.
    fn into_committee(self, preset: Preset) -> Result<SyncCommittee, JsonError> {
        if self.pubkeys.len() != preset.sync_committee_size() {
            return Err(JsonError::Malformed);
        }
        let ssz: Vec<u8> =
            self.pubkeys.iter().chain([&self.aggregate_pubkey]).flat_map(|k| k.0).collect();
        SyncCommittee::from_ssz_bytes(&ssz, preset).map_err(|_| JsonError::Malformed)
    }
}

#[derive(Serialize, Deserialize)]
struct AggregateJson {
    sync_committee_bits: Bytes,
    sync_committee_signature: FixedBytes<96>,
}

#[derive(Serialize, Deserialize)]
struct BootstrapJson {
    header: HeaderJson,
    current_sync_committee: CommitteeJson,
    current_sync_committee_branch: Vec<B256>,
}

#[derive(Serialize, Deserialize)]
struct UpdateJson {
    attested_header: HeaderJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_sync_committee: Option<CommitteeJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_sync_committee_branch: Option<Vec<B256>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finalized_header: Option<HeaderJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finality_branch: Option<Vec<B256>>,
    sync_aggregate: AggregateJson,
    #[serde(with = "decimal")]
    signature_slot: u64,
}

impl Versioned<UpdateJson> {
    /// The update of `kind`. The fields `kind` does not carry get their defaults: an empty
    /// committee, a default header and zero branches. Fields it does carry are required.
    fn into_update(self, preset: Preset, kind: UpdateKind) -> Result<LightClientUpdate, JsonError> {
        let fork = fork_of_name(&self.version)?;
        let gindices = gindices(fork)?;
        let d = self.data;
        let (next_sync_committee, next_sync_committee_branch) = match kind {
            UpdateKind::Full => (
                d.next_sync_committee.ok_or(JsonError::Malformed)?.into_committee(preset)?,
                branch(
                    d.next_sync_committee_branch.ok_or(JsonError::Malformed)?,
                    gindices.next_sync_committee,
                )?,
            ),
            UpdateKind::Finality | UpdateKind::Optimistic => {
                (empty_committee(preset), zero_branch(gindices.next_sync_committee))
            }
        };
        let (finalized_header, finality_branch) = match kind {
            UpdateKind::Full | UpdateKind::Finality => (
                d.finalized_header.ok_or(JsonError::Malformed)?.into_header(fork)?,
                branch(d.finality_branch.ok_or(JsonError::Malformed)?, gindices.finalized_root)?,
            ),
            UpdateKind::Optimistic => {
                (LightClientHeader::default(), zero_branch(gindices.finalized_root))
            }
        };
        let aggregate = d.sync_aggregate;
        let aggregate_ssz =
            [aggregate.sync_committee_bits.as_ref(), aggregate.sync_committee_signature.as_slice()]
                .concat();
        Ok(LightClientUpdate {
            attested_header: d.attested_header.into_header(fork)?,
            next_sync_committee,
            next_sync_committee_branch,
            finalized_header,
            finality_branch,
            sync_aggregate: SyncAggregate::from_ssz_bytes(&aggregate_ssz, preset)
                .map_err(|_| JsonError::Malformed)?,
            signature_slot: d.signature_slot,
        })
    }
}

/// The default `SyncCommittee()` of `preset`'s size: all zero bytes.
pub(crate) fn empty_committee(preset: Preset) -> SyncCommittee {
    let zeros = vec![0; (preset.sync_committee_size() + 1) * 48];
    SyncCommittee::from_ssz_bytes(&zeros, preset).expect("the length is the preset's")
}

#[cfg(test)]
mod tests {
    use super::{test_utils::*, *};
    use crate::sync_committee::{
        test_utils::{hash, Real369},
        LightClientStore,
    };
    use serde_json::Value;

    const ALTAIR_SYNC: &str =
        include_str!("../testdata/sync_committee/sync_altair_light_client_sync.json");

    fn pins_369() -> PulsechainBeacon {
        reth_pulsechain_forks::network::pulsechain_network(369).unwrap().beacon
    }

    fn written(value: Result<Value, JsonError>) -> Vec<u8> {
        value.unwrap().to_string().into_bytes()
    }

    #[test]
    fn a_bootstrap_round_trips_through_json() {
        let (_, _, bootstrap, _) = capella_case();
        let json = written(bootstrap_json(&bootstrap, BeaconFork::Capella));
        assert_eq!(parse_bootstrap(&json, Preset::MINIMAL), Ok(bootstrap));
    }

    #[test]
    fn a_full_update_round_trips_through_json() {
        let (_, _, _, updates) = capella_case();
        for (update, _) in updates {
            let json = written(update_json(&update, BeaconFork::Capella, UpdateKind::Full));
            assert_eq!(parse_update(&json, Preset::MINIMAL, UpdateKind::Full), Ok(update));
        }
    }

    /// A finality update is written without the next committee, and reads back with it at its
    /// default.
    #[test]
    fn a_finality_update_round_trips_through_json() {
        let (_, _, _, updates) = capella_case();
        let update = &updates[0].0;
        let value = update_json(update, BeaconFork::Capella, UpdateKind::Finality).unwrap();
        let data = value["data"].as_object().unwrap();
        assert!(!data.contains_key("next_sync_committee"), "{value}");
        assert!(!data.contains_key("next_sync_committee_branch"), "{value}");
        assert!(data.contains_key("finalized_header"), "{value}");
        let json = value.to_string().into_bytes();
        assert_eq!(
            parse_update(&json, Preset::MINIMAL, UpdateKind::Finality),
            Ok(as_kind(update, UpdateKind::Finality))
        );
        // A full update needs the next committee the finality form leaves out.
        assert_eq!(
            parse_update(&json, Preset::MINIMAL, UpdateKind::Full),
            Err(JsonError::Malformed)
        );
    }

    /// An optimistic update is written with only the attested header and the aggregate.
    #[test]
    fn an_optimistic_update_round_trips_through_json() {
        let (_, _, _, updates) = capella_case();
        let update = &updates[0].0;
        let value = update_json(update, BeaconFork::Capella, UpdateKind::Optimistic).unwrap();
        let mut keys: Vec<&str> =
            value["data"].as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["attested_header", "signature_slot", "sync_aggregate"]);
        let json = value.to_string().into_bytes();
        assert_eq!(
            parse_update(&json, Preset::MINIMAL, UpdateKind::Optimistic),
            Ok(as_kind(update, UpdateKind::Optimistic))
        );
    }

    /// The real 369 bootstrap is written in the beacon API's form and reads back to a bootstrap
    /// the store accepts.
    #[test]
    fn the_real_369_bootstrap_round_trips_through_json() {
        let real = Real369::load();
        let root = hash(&real.json["block_root"]);
        let value = bootstrap_json(&real.bootstrap(), BeaconFork::Capella).unwrap();
        assert_eq!(value["version"], "capella");
        let header = &value["data"]["header"];
        assert_eq!(header["beacon"]["slot"], "11167808");
        assert_eq!(header["execution"]["block_number"], "28133431");
        let fee_recipient = header["execution"]["fee_recipient"].as_str().unwrap();
        assert_eq!(fee_recipient, fee_recipient.to_lowercase());
        assert_eq!(
            value["data"]["current_sync_committee"]["pubkeys"].as_array().unwrap().len(),
            512
        );

        let bootstrap = parse_bootstrap(value.to_string().as_bytes(), Preset::PULSECHAIN).unwrap();
        assert_eq!(bootstrap, real.bootstrap());
        let store =
            LightClientStore::bootstrap(Preset::PULSECHAIN, pins_369(), root, &bootstrap).unwrap();
        assert_eq!(store.finalized_header().execution.block_number, 28_133_431);
    }

    /// Before Capella a header has no execution part, and the writer leaves it out.
    #[test]
    fn an_altair_update_round_trips_without_an_execution_part() {
        let (_, _, bootstrap, updates) = sync_case(ALTAIR_SYNC, BeaconFork::Altair);
        let value = bootstrap_json(&bootstrap, BeaconFork::Altair).unwrap();
        assert_eq!(value["version"], "altair");
        let header = value["data"]["header"].as_object().unwrap();
        assert_eq!(header.keys().collect::<Vec<_>>(), ["beacon"]);
        assert_eq!(parse_bootstrap(value.to_string().as_bytes(), Preset::MINIMAL), Ok(bootstrap));

        let (update, _) = &updates[0];
        let json = written(update_json(update, BeaconFork::Altair, UpdateKind::Full));
        assert_eq!(parse_update(&json, Preset::MINIMAL, UpdateKind::Full), Ok(update.clone()));
    }

    #[test]
    fn phase0_has_no_json_form() {
        let (_, _, bootstrap, updates) = capella_case();
        assert_eq!(bootstrap_json(&bootstrap, BeaconFork::Phase0), Err(JsonError::UnsupportedFork));
        assert_eq!(
            update_json(&updates[0].0, BeaconFork::Phase0, UpdateKind::Full),
            Err(JsonError::UnsupportedFork)
        );
    }
}
