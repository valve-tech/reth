//! 121-byte compact message identifier used for peer announcements.
//!
//! `MsgID` encodes the most important message fields in a fixed-size layout so
//! peers can filter announcements without fetching the full payload:
//!
//! ```text
//! byte   0        : version
//! bytes  1..=32   : block_hash   (32 bytes)
//! bytes 33..=40   : size         (u64, big-endian)
//! bytes 41..=48   : work_multiplier (u64, big-endian)
//! bytes 49..=56   : work_divisor    (u64, big-endian)
//! bytes 57..=88   : category_hash (32 bytes)
//! bytes 89..=120  : message_hash  (32 bytes)
//! ```

extern crate alloc;

use alloy_primitives::B256;

/// Total size of a [`MsgID`] in bytes.
pub const MSG_ID_SIZE: usize = 121;

const VERSION_BYTE: usize = 0;
const BLOCK_HASH_START: usize = VERSION_BYTE + 1;
const BLOCK_HASH_END: usize = BLOCK_HASH_START + 32;
const SIZE_START: usize = BLOCK_HASH_END;
const SIZE_END: usize = SIZE_START + 8;
const WORK_MULT_START: usize = SIZE_END;
const WORK_MULT_END: usize = WORK_MULT_START + 8;
const WORK_DIV_START: usize = WORK_MULT_END;
const WORK_DIV_END: usize = WORK_DIV_START + 8;
const CATEGORY_HASH_START: usize = WORK_DIV_END;
const CATEGORY_HASH_END: usize = CATEGORY_HASH_START + 32;
const MSG_HASH_START: usize = CATEGORY_HASH_END;
const MSG_HASH_END: usize = MSG_HASH_START + 32;

const _: () = assert!(MSG_HASH_END == MSG_ID_SIZE, "MsgID layout size mismatch");

/// Fixed-size message identifier used in `BoardMessageIDs` / `GetBoardMessages` packets.
///
/// Peers send lists of `MsgID`s to announce or request messages. The receiver
/// uses [`version`](MsgID::version), [`size`](MsgID::size), and
/// [`difficulty_ratio`](MsgID::difficulty_ratio) to filter IDs that exceed
/// configured limits before making a `GetBoardMessages` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct MsgID([u8; MSG_ID_SIZE]);

impl MsgID {
    /// Construct a `MsgID` from a checked `PoW` message.
    pub fn from_checked(
        version: u8,
        block_hash: &B256,
        data_size: u64,
        work_multiplier: u64,
        work_divisor: u64,
        category: &B256,
        msg_hash: &B256,
    ) -> Self {
        let mut id = [0u8; MSG_ID_SIZE];
        id[VERSION_BYTE] = version;
        id[BLOCK_HASH_START..BLOCK_HASH_END].copy_from_slice(block_hash.as_slice());
        id[SIZE_START..SIZE_END].copy_from_slice(&data_size.to_be_bytes());
        id[WORK_MULT_START..WORK_MULT_END].copy_from_slice(&work_multiplier.to_be_bytes());
        id[WORK_DIV_START..WORK_DIV_END].copy_from_slice(&work_divisor.to_be_bytes());
        id[CATEGORY_HASH_START..CATEGORY_HASH_END].copy_from_slice(category.as_slice());
        id[MSG_HASH_START..MSG_HASH_END].copy_from_slice(msg_hash.as_slice());
        Self(id)
    }

    /// Decode a slice of bytes into a list of `MsgID`s.
    ///
    /// Returns an error if `bytes.len()` is not a multiple of [`MSG_ID_SIZE`].
    pub fn decode_list(bytes: &[u8]) -> Result<Vec<Self>, crate::MsgboardError> {
        if !bytes.len().is_multiple_of(MSG_ID_SIZE) {
            return Err(crate::MsgboardError::MalformedIdList);
        }
        Ok(bytes
            .chunks_exact(MSG_ID_SIZE)
            .map(|chunk| Self(chunk.try_into().expect("chunk is exactly MSG_ID_SIZE bytes")))
            .collect())
    }

    /// Flatten a slice of `MsgID`s into a contiguous byte buffer.
    pub fn encode_list(ids: &[Self]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(ids.len() * MSG_ID_SIZE);
        for id in ids {
            out.extend_from_slice(&id.0);
        }
        out
    }

    /// Raw bytes of this `MsgID`.
    pub const fn as_bytes(&self) -> &[u8; MSG_ID_SIZE] {
        &self.0
    }

    // ── field accessors ──────────────────────────────────────────────────────

    /// Encoding version byte.
    pub const fn version(&self) -> u8 {
        self.0[VERSION_BYTE]
    }

    /// Block hash the message was anchored to.
    pub fn block_hash(&self) -> B256 {
        B256::from_slice(&self.0[BLOCK_HASH_START..BLOCK_HASH_END])
    }

    /// Byte length of the message's `data` field.
    pub fn size(&self) -> u64 {
        u64::from_be_bytes(self.0[SIZE_START..SIZE_END].try_into().unwrap())
    }

    /// Work multiplier used in the `PoW` difficulty calculation.
    pub fn work_multiplier(&self) -> u64 {
        u64::from_be_bytes(self.0[WORK_MULT_START..WORK_MULT_END].try_into().unwrap())
    }

    /// Work divisor used in the `PoW` difficulty calculation.
    pub fn work_divisor(&self) -> u64 {
        u64::from_be_bytes(self.0[WORK_DIV_START..WORK_DIV_END].try_into().unwrap())
    }

    /// Category hash (keccak256 of the category text).
    pub fn category_hash(&self) -> B256 {
        B256::from_slice(&self.0[CATEGORY_HASH_START..CATEGORY_HASH_END])
    }

    /// SHA-256 hash of the message (the `PoW` hash).
    pub fn message_hash(&self) -> B256 {
        B256::from_slice(&self.0[MSG_HASH_START..MSG_HASH_END])
    }

    /// Ratio `work_multiplier / work_divisor`. Used for minimum-difficulty filtering.
    pub fn difficulty_ratio(&self) -> f64 {
        self.work_multiplier() as f64 / self.work_divisor() as f64
    }
}
