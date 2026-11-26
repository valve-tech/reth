//! `<datadir>/sync-committee.ssz`: the light-client store of `--head.verify=sync-committee`,
//! kept across restarts so that a restart does not bootstrap again.
//!
//! The file is an SSZ container followed by the SHA-256 of the container:
//!
//! ```text
//! version: u64, chain_id: u64, genesis_validators_root: Bytes32,
//! finalized_header: LightClientHeader (Capella form),
//! current_sync_committee: SyncCommittee,
//! next_sync_committee: List[SyncCommittee, 1]
//! ```
//!
//! The checksum catches a flipped bit that still decodes: a committee key that changed but stays
//! a valid point would make every signature fail, and the head would go stale for good.

use crate::{
    config::SLOT,
    light_client::MAX_CHECKPOINT_AGE,
    sync_committee::{
        committee_len, LightClientHeader, LightClientStore, Preset, SyncCommittee,
        SyncCommitteeError,
    },
};
use alloy_primitives::B256;
use reth_pulsechain_forks::network::PulsechainBeacon;
use sha2::{Digest, Sha256};
use ssz::{DecodeError, SszDecoderBuilder, SszEncoder};
use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// The file name in the data directory.
pub const FILE_NAME: &str = "sync-committee.ssz";
/// The layout version this binary writes and reads.
const FORMAT_VERSION: u64 = 1;
/// A saved finalized header older than this is not used. It is the checkpoint's limit, so the
/// node never drops a store it verified itself for an older checkpoint, and the catch-up has the
/// same bound (see [`MAX_CHECKPOINT_AGE`]).
pub const MAX_AGE: Duration = MAX_CHECKPOINT_AGE;
/// The largest file read. A `PulseChain` store is about 50 KB.
const MAX_FILE_BYTES: u64 = 1 << 20;
/// The length of the trailing checksum.
const CHECKSUM_LEN: usize = 32;

/// Why a saved store is not used. The node then bootstraps at the checkpoint, or at the anchor's
/// root without one.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read the file: {0}")]
    Read(#[from] io::Error),
    /// The file is larger than any store.
    #[error("the file is {0} bytes, more than {MAX_FILE_BYTES}")]
    TooLarge(u64),
    /// The checksum does not match: the file is truncated or damaged.
    #[error("the checksum does not match: the file is truncated or damaged")]
    Checksum,
    /// Another layout version.
    #[error("format version {0} is not {FORMAT_VERSION}")]
    Version(u64),
    /// The container does not decode.
    #[error("the file does not decode: {0:?}")]
    Decode(DecodeError),
    /// The file is for another chain.
    #[error("the file is for chain {got}, not {want}")]
    ChainId {
        /// The chain ID in the file.
        got: u64,
        /// The node's chain ID.
        want: u64,
    },
    /// The file has another `genesis_validators_root` than the pinned one.
    #[error("the file's genesis_validators_root {got} is not the pinned {want}")]
    GenesisValidatorsRoot {
        /// The value in the file.
        got: B256,
        /// The pinned value.
        want: B256,
    },
    /// The saved finalized header is too old.
    #[error("the saved finalized header at slot {slot} is {age_secs} s old, more than {} s", MAX_AGE.as_secs())]
    Stale {
        /// The header's slot.
        slot: u64,
        /// Its age by the wall clock.
        age_secs: u64,
    },
    /// The saved header or a committee key does not check out.
    #[error("the saved store does not check out: {0}")]
    Store(#[from] SyncCommitteeError),
}

/// The store file of one chain in one data directory.
#[derive(Debug, Clone)]
pub struct SyncCommitteeFile {
    path: PathBuf,
    chain_id: u64,
}

impl SyncCommitteeFile {
    /// The file [`FILE_NAME`] in `datadir`, for chain `chain_id`.
    pub fn new(datadir: &Path, chain_id: u64) -> Self {
        Self { path: datadir.join(FILE_NAME), chain_id }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the file's bytes for `store`.
    pub fn encode(&self, store: &LightClientStore) -> Vec<u8> {
        let preset = store.preset();
        let next = store.next_sync_committee();
        let fixed = 8 + 8 + 32 + 4 + committee_len(preset) + 4;
        let mut buf = Vec::new();
        let mut encoder = SszEncoder::container(&mut buf, fixed);
        encoder.append(&FORMAT_VERSION);
        encoder.append(&self.chain_id);
        encoder.append(&store.beacon().genesis_validators_root);
        encoder.append(store.finalized_header());
        encoder.append_parameterized(true, |buf| store.current_sync_committee().append_ssz(buf));
        encoder.append_parameterized(false, |buf| {
            if let Some(next) = next {
                next.append_ssz(buf);
            }
        });
        encoder.finalize();
        let checksum = Sha256::digest(&buf);
        buf.extend_from_slice(&checksum);
        buf
    }

    /// Writes `bytes` (from [`Self::encode`]) atomically: a temporary file, fsync, rename.
    pub fn save(&self, bytes: &[u8]) -> io::Result<()> {
        crate::net::wire::write_private(&self.path, bytes)
    }

    /// Loads the saved store, checked against `chain_id`, `beacon`'s pins and the wall clock
    /// `now`. `Ok(None)` when there is no file.
    pub fn load(
        &self,
        preset: Preset,
        beacon: PulsechainBeacon,
        now: SystemTime,
    ) -> Result<Option<LightClientStore>, LoadError> {
        let len = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if len > MAX_FILE_BYTES {
            return Err(LoadError::TooLarge(len));
        }
        let bytes = std::fs::read(&self.path)?;
        self.decode(&bytes, preset, beacon, now).map(Some)
    }

    /// Checks and decodes the file's `bytes`.
    fn decode(
        &self,
        bytes: &[u8],
        preset: Preset,
        beacon: PulsechainBeacon,
        now: SystemTime,
    ) -> Result<LightClientStore, LoadError> {
        let (body, checksum) = bytes
            .split_at_checked(bytes.len().saturating_sub(CHECKSUM_LEN))
            .filter(|(_, checksum)| checksum.len() == CHECKSUM_LEN)
            .ok_or(LoadError::Checksum)?;
        if Sha256::digest(body).as_slice() != checksum {
            return Err(LoadError::Checksum);
        }
        let Some(version) = body.first_chunk::<8>().map(|b| u64::from_le_bytes(*b)) else {
            let len = body.len();
            return Err(LoadError::Decode(DecodeError::InvalidByteLength { len, expected: 8 }));
        };
        if version != FORMAT_VERSION {
            return Err(LoadError::Version(version));
        }

        let mut builder = SszDecoderBuilder::new(body);
        let decode = LoadError::Decode;
        builder.register_type::<u64>().map_err(decode)?;
        builder.register_type::<u64>().map_err(decode)?;
        builder.register_type::<B256>().map_err(decode)?;
        builder.register_type::<LightClientHeader>().map_err(decode)?;
        builder.register_type_parameterized(true, committee_len(preset)).map_err(decode)?;
        builder.register_type_parameterized(false, 4).map_err(decode)?;
        let mut decoder = builder.build().map_err(decode)?;
        let _version: u64 = decoder.decode_next().map_err(decode)?;
        let chain_id: u64 = decoder.decode_next().map_err(decode)?;
        let genesis_validators_root: B256 = decoder.decode_next().map_err(decode)?;
        let finalized_header: LightClientHeader = decoder.decode_next().map_err(decode)?;
        let current = decoder
            .decode_next_with(|b| SyncCommittee::from_ssz_bytes(b, preset))
            .map_err(decode)?;
        let next = decoder
            .decode_next_with(|b| {
                if b.is_empty() {
                    Ok(None)
                } else {
                    SyncCommittee::from_ssz_bytes(b, preset).map(Some)
                }
            })
            .map_err(decode)?;

        if chain_id != self.chain_id {
            return Err(LoadError::ChainId { got: chain_id, want: self.chain_id });
        }
        if genesis_validators_root != beacon.genesis_validators_root {
            return Err(LoadError::GenesisValidatorsRoot {
                got: genesis_validators_root,
                want: beacon.genesis_validators_root,
            });
        }
        let slot = finalized_header.beacon.slot;
        let slot_time = UNIX_EPOCH +
            Duration::from_secs(
                beacon.genesis_time.saturating_add(slot.saturating_mul(SLOT.as_secs())),
            );
        let age = now.duration_since(slot_time).unwrap_or_default();
        if age > MAX_AGE {
            return Err(LoadError::Stale { slot, age_secs: age.as_secs() });
        }
        Ok(LightClientStore::restore(preset, beacon, finalized_header, current, next)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_committee::test_utils::{hash, Real369};
    use ssz::Encode;

    fn pins() -> PulsechainBeacon {
        reth_pulsechain_forks::network::pulsechain_network(369).unwrap().beacon
    }

    /// The real 369 store, with its committee also as the next one when `with_next`.
    fn store(with_next: bool) -> LightClientStore {
        let real = Real369::load();
        let bootstrap = real.bootstrap();
        let root = hash(&real.json["block_root"]);
        let store =
            LightClientStore::bootstrap(Preset::PULSECHAIN, pins(), root, &bootstrap).unwrap();
        let next = with_next.then(|| bootstrap.current_sync_committee.clone());
        LightClientStore::restore(
            Preset::PULSECHAIN,
            pins(),
            store.finalized_header().clone(),
            store.current_sync_committee().clone(),
            next,
        )
        .unwrap()
    }

    /// The wall clock `after` the store's finalized slot.
    fn at_slot(store: &LightClientStore, after: Duration) -> SystemTime {
        let slot = store.finalized_header().beacon.slot;
        UNIX_EPOCH + Duration::from_secs(pins().genesis_time + slot * 10) + after
    }

    fn assert_same(got: &LightClientStore, want: &LightClientStore) {
        assert_eq!(got.finalized_header(), want.finalized_header());
        assert_eq!(got.optimistic_header(), want.finalized_header());
        assert_eq!(got.current_sync_committee(), want.current_sync_committee());
        assert_eq!(got.next_sync_committee(), want.next_sync_committee());
        assert_eq!(got.beacon(), want.beacon());
    }

    #[test]
    fn a_saved_store_loads_back_with_and_without_the_next_committee() {
        let dir = tempfile::tempdir().unwrap();
        let file = SyncCommitteeFile::new(dir.path(), 369);
        assert_eq!(file.path(), dir.path().join("sync-committee.ssz"));
        assert!(file.load(Preset::PULSECHAIN, pins(), SystemTime::now()).unwrap().is_none());
        for with_next in [false, true] {
            let saved = store(with_next);
            let bytes = file.encode(&saved);
            // About 50 KB with both committees.
            let committees = if with_next { 2 } else { 1 };
            assert_eq!(bytes.len(), 56 + 837 + committees * 24_624 + 32, "next {with_next}");
            file.save(&bytes).unwrap();
            let now = at_slot(&saved, Duration::from_secs(3600));
            let loaded = file.load(Preset::PULSECHAIN, pins(), now).unwrap().unwrap();
            assert_same(&loaded, &saved);
        }
        // Only the file is left: the temporary file was renamed.
        let names: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![FILE_NAME]);
    }

    #[test]
    fn a_truncated_or_damaged_file_is_refused() {
        let file = SyncCommitteeFile::new(Path::new("/nonexistent"), 369);
        let saved = store(true);
        let bytes = file.encode(&saved);
        let now = at_slot(&saved, Duration::ZERO);
        let decode = |b: &[u8]| file.decode(b, Preset::PULSECHAIN, pins(), now).unwrap_err();
        for len in [0, 31, 32, 100, bytes.len() / 2, bytes.len() - 1] {
            assert!(matches!(decode(&bytes[..len]), LoadError::Checksum), "len {len}");
        }
        // One flipped bit in a committee key.
        let mut flipped = bytes.clone();
        flipped[2000] ^= 1;
        assert!(matches!(decode(&flipped), LoadError::Checksum));

        // A body that matches its checksum but does not decode: the next committee a key short.
        let mut short = bytes[..bytes.len() - CHECKSUM_LEN - 48].to_vec();
        short.extend_from_slice(&Sha256::digest(&short));
        assert!(matches!(decode(&short), LoadError::Decode(_)), "{:?}", decode(&short));

        // Another layout version.
        let mut other = bytes[..bytes.len() - CHECKSUM_LEN].to_vec();
        other[0] = 2;
        other.extend_from_slice(&Sha256::digest(&other));
        assert!(matches!(decode(&other), LoadError::Version(2)));
    }

    #[test]
    fn a_file_for_another_chain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let saved = store(false);
        let now = at_slot(&saved, Duration::ZERO);
        let on_943 = SyncCommitteeFile::new(dir.path(), 943);
        on_943.save(&on_943.encode(&saved)).unwrap();
        let on_369 = SyncCommitteeFile::new(dir.path(), 369);
        assert!(matches!(
            on_369.load(Preset::PULSECHAIN, pins(), now),
            Err(LoadError::ChainId { got: 943, want: 369 })
        ));

        // The same chain ID with another genesis_validators_root.
        on_369.save(&on_369.encode(&saved)).unwrap();
        let other = PulsechainBeacon { genesis_validators_root: B256::repeat_byte(1), ..pins() };
        let err = on_369.load(Preset::PULSECHAIN, other, now).unwrap_err();
        assert!(
            matches!(err, LoadError::GenesisValidatorsRoot { want, .. } if want == B256::repeat_byte(1)),
            "{err}"
        );
    }

    /// A saved store has the checkpoint's age limit, 30 days: the node never drops a store it
    /// verified itself for a checkpoint that may be older.
    #[test]
    fn a_file_older_than_the_checkpoint_limit_is_refused() {
        let file = SyncCommitteeFile::new(Path::new("/nonexistent"), 369);
        let saved = store(false);
        let bytes = file.encode(&saved);
        let decode =
            |after| file.decode(&bytes, Preset::PULSECHAIN, pins(), at_slot(&saved, after));
        let days = |n: u64| Duration::from_secs(n * 86_400);
        assert!(decode(days(8)).is_ok());
        assert!(decode(days(30)).is_ok());
        let slot = saved.finalized_header().beacon.slot;
        let age_secs = days(30).as_secs() + 1;
        assert!(matches!(
            decode(days(30) + Duration::from_secs(1)),
            Err(LoadError::Stale { slot: s, age_secs: a }) if s == slot && a == age_secs
        ));
    }

    /// A file whose header was changed and its checksum rewritten fails the execution branch.
    #[test]
    fn a_saved_header_that_does_not_check_out_is_refused() {
        let file = SyncCommitteeFile::new(Path::new("/nonexistent"), 369);
        let saved = store(false);
        let header = saved.finalized_header();
        let mut forged = header.clone();
        forged.execution.block_number += 1;
        let mut bytes = file.encode(&saved);
        let (want, put) = (header.as_ssz_bytes(), forged.as_ssz_bytes());
        let at = bytes.windows(want.len()).position(|w| w == want).unwrap();
        bytes[at..at + put.len()].copy_from_slice(&put);
        let body_len = bytes.len() - CHECKSUM_LEN;
        let checksum = Sha256::digest(&bytes[..body_len]);
        bytes[body_len..].copy_from_slice(&checksum);
        let now = at_slot(&saved, Duration::ZERO);
        let err = file.decode(&bytes, Preset::PULSECHAIN, pins(), now).unwrap_err();
        let body_root = header.beacon.body_root;
        assert!(
            matches!(err, LoadError::Store(SyncCommitteeError::ExecutionBranch(r)) if r == body_root),
            "{err}"
        );
    }
}
