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

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;
    use crate::{MsgboardError, PoWMsg, VERSION_V1};

    fn b256(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn sample() -> MsgID {
        MsgID::from_checked(
            VERSION_V1,
            &b256(0x11),
            1234,
            10_000,
            1_000_000,
            &b256(0x22),
            &b256(0x33),
        )
    }

    // ── layout ───────────────────────────────────────────────────────────────

    #[test]
    fn layout_constants_match_the_documented_121_byte_wire_format() {
        assert_eq!(MSG_ID_SIZE, 121);
        assert_eq!(VERSION_BYTE, 0);
        assert_eq!(BLOCK_HASH_START..BLOCK_HASH_END, 1..33);
        assert_eq!(SIZE_START..SIZE_END, 33..41);
        assert_eq!(WORK_MULT_START..WORK_MULT_END, 41..49);
        assert_eq!(WORK_DIV_START..WORK_DIV_END, 49..57);
        assert_eq!(CATEGORY_HASH_START..CATEGORY_HASH_END, 57..89);
        assert_eq!(MSG_HASH_START..MSG_HASH_END, 89..121);
    }

    #[test]
    fn from_checked_round_trips_through_every_accessor() {
        let id = sample();
        assert_eq!(id.version(), VERSION_V1);
        assert_eq!(id.block_hash(), b256(0x11));
        assert_eq!(id.size(), 1234);
        assert_eq!(id.work_multiplier(), 10_000);
        assert_eq!(id.work_divisor(), 1_000_000);
        assert_eq!(id.category_hash(), b256(0x22));
        assert_eq!(id.message_hash(), b256(0x33));
    }

    /// Locks the byte layout itself, not just accessor agreement. Accessors
    /// read the same constants `from_checked` writes, so a layout change would
    /// otherwise round-trip cleanly while breaking erigon interop.
    #[test]
    fn field_bytes_land_at_the_erigon_specified_offsets() {
        let id = sample();
        let raw = id.as_bytes();

        assert_eq!(raw[0], VERSION_V1);
        assert_eq!(&raw[1..33], b256(0x11).as_slice());
        // u64 fields are big-endian.
        assert_eq!(&raw[33..41], &1234u64.to_be_bytes());
        assert_eq!(&raw[41..49], &10_000u64.to_be_bytes());
        assert_eq!(&raw[49..57], &1_000_000u64.to_be_bytes());
        assert_eq!(&raw[57..89], b256(0x22).as_slice());
        assert_eq!(&raw[89..121], b256(0x33).as_slice());
    }

    #[test]
    fn u64_fields_are_big_endian_not_little_endian() {
        let id = MsgID::from_checked(VERSION_V1, &b256(0), 1, 1, 1, &b256(0), &b256(0));
        // Big-endian: the significant byte sits at the END of each 8-byte run.
        assert_eq!(id.as_bytes()[33..41], [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(id.as_bytes()[41..49], [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(id.as_bytes()[49..57], [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn u64_fields_survive_max_values() {
        let id = MsgID::from_checked(
            VERSION_V1,
            &b256(0),
            u64::MAX,
            u64::MAX,
            u64::MAX,
            &b256(0),
            &b256(0),
        );
        assert_eq!(id.size(), u64::MAX);
        assert_eq!(id.work_multiplier(), u64::MAX);
        assert_eq!(id.work_divisor(), u64::MAX);
    }

    // ── list encoding ────────────────────────────────────────────────────────

    #[test]
    fn encode_decode_list_round_trips() {
        let ids =
            vec![sample(), MsgID::from_checked(2, &b256(0xAA), 7, 3, 9, &b256(0xBB), &b256(0xCC))];
        let encoded = MsgID::encode_list(&ids);
        assert_eq!(encoded.len(), 2 * MSG_ID_SIZE);
        assert_eq!(MsgID::decode_list(&encoded).unwrap(), ids);
    }

    #[test]
    fn encode_list_is_a_flat_concatenation_with_no_framing() {
        let ids = vec![sample(), sample()];
        let encoded = MsgID::encode_list(&ids);
        assert_eq!(&encoded[..MSG_ID_SIZE], sample().as_bytes());
        assert_eq!(&encoded[MSG_ID_SIZE..], sample().as_bytes());
    }

    #[test]
    fn empty_list_round_trips_to_empty() {
        assert!(MsgID::encode_list(&[]).is_empty());
        assert!(MsgID::decode_list(&[]).unwrap().is_empty());
    }

    /// A peer sending a truncated or padded ID list is a wire-protocol
    /// violation; `handle_incoming` maps this to a `BadProtocol` reputation
    /// hit, so the error variant matters.
    #[test]
    fn decode_list_rejects_lengths_that_are_not_a_multiple_of_msg_id_size() {
        for bad_len in [1, MSG_ID_SIZE - 1, MSG_ID_SIZE + 1, 2 * MSG_ID_SIZE - 1] {
            let bytes = vec![0u8; bad_len];
            assert!(
                matches!(MsgID::decode_list(&bytes), Err(MsgboardError::MalformedIdList)),
                "len {bad_len} should be rejected as a malformed ID list",
            );
        }
    }

    #[test]
    fn decode_list_accepts_exact_multiples() {
        for n in [1usize, 2, 5] {
            let bytes = vec![0u8; n * MSG_ID_SIZE];
            assert_eq!(MsgID::decode_list(&bytes).unwrap().len(), n);
        }
    }

    // ── difficulty ratio ─────────────────────────────────────────────────────

    /// `MsgID::difficulty_ratio` and `PoWMsg::difficulty_ratio` are separate
    /// implementations of the same quantity. `filter_wanted` compares an
    /// announced ID's ratio against config, and the board later compares the
    /// fetched message's ratio; if the two ever disagree a node would request
    /// a message it then rejects, burning a round trip per announcement.
    #[test]
    fn difficulty_ratio_agrees_with_the_pow_msg_implementation() {
        for (mult, div) in
            [(1u64, 1u64), (10_000, 1_000_000), (1, 1_000_000), (7, 3), (u64::MAX, 1)]
        {
            let msg = PoWMsg {
                version: VERSION_V1,
                block_hash: b256(0),
                nonce: 0,
                work_multiplier: mult,
                work_divisor: div,
                category: b256(0),
                data: Default::default(),
            };
            let id = MsgID::from_checked(VERSION_V1, &b256(0), 0, mult, div, &b256(0), &b256(0));
            assert_eq!(
                id.difficulty_ratio(),
                msg.difficulty_ratio(),
                "ratio mismatch for {mult}/{div}",
            );
        }
    }

    #[test]
    fn difficulty_ratio_computes_the_expected_value() {
        let id =
            MsgID::from_checked(VERSION_V1, &b256(0), 0, 10_000, 1_000_000, &b256(0), &b256(0));
        assert!((id.difficulty_ratio() - 0.01).abs() < f64::EPSILON);
    }
}
