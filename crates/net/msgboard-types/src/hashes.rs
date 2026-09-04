//! `GetBoardMessages` payload codec: a flat run of 32-byte message hashes.
//!
//! Erigon-pulse changed this payload's unit at `pulse-v3.4.4` (`78fbcffb8b`,
//! `msgboard/hashes.go`). It used to carry 121-byte [`MsgID`](crate::MsgID)
//! records, the same as `BoardMessageIDs`. It now carries the bare 32-byte
//! message hash, which is all the responder ever reads: erigon's old handler
//! called `mID.MessageHash()` and discarded the rest of every record.
//!
//! The two units do not overlap by accident. `gcd(32, 121) = 1`, so a payload
//! length is legal under both readings only at 3,872 bytes. Every other frame
//! one side sends is a decode failure on the other, and both clients answer a
//! decode failure with a peer penalty.

extern crate alloc;

use alloc::vec::Vec;

use alloy_primitives::B256;

use crate::MsgboardError;

/// Bytes per record in a `GetBoardMessages` payload.
pub const MSG_HASH_SIZE: usize = 32;

/// Most hashes erigon accepts in one `GetBoardMessages` frame, and the most it
/// sends (`MaxGetBoardMessages`, `msgboard/protocol.go:30`).
///
/// A conforming frame is therefore at most 8 KiB. Erigon kicks a peer that
/// exceeds the count before it looks anything up, so a request built from a
/// full announcement frame must be split — one 846-ID announcement produces
/// four requests, not one.
pub const MAX_GET_BOARD_MESSAGES: usize = 256;

/// Decode a flat run of 32-byte message hashes.
///
/// Sized from the bytes supplied, never from a declared length — the payload
/// carries no length field. The caller bounds the input before this runs; see
/// `MAX_INBOUND_FRAME_SIZE` in the `reth-msgboard` protocol module.
pub fn decode_msg_hash_list(bytes: &[u8]) -> Result<Vec<B256>, MsgboardError> {
    let (chunks, rest) = bytes.as_chunks::<MSG_HASH_SIZE>();
    if !rest.is_empty() {
        return Err(MsgboardError::MalformedHashList);
    }
    Ok(chunks.iter().map(B256::from).collect())
}

/// Concatenate message hashes into a `GetBoardMessages` payload.
pub fn encode_msg_hash_list(hashes: &[B256]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hashes.len() * MSG_HASH_SIZE);
    for h in hashes {
        out.extend_from_slice(h.as_slice());
    }
    out
}

/// Reject a list that names any hash twice.
///
/// Erigon treats a duplicate as a protocol violation and kicks
/// (`CheckUniqueHashes`, `msgboard/hashes.go:390`), on both the request and
/// the delivery path. A conforming peer never sends one: it would be asking
/// for the same body twice in a frame it built from a de-duplicated index.
pub fn check_unique_hashes(hashes: &[B256]) -> Result<(), MsgboardError> {
    if hashes.len() < 2 {
        return Ok(());
    }
    let mut seen = alloc::collections::BTreeSet::new();
    for h in hashes {
        if !seen.insert(h) {
            return Err(MsgboardError::DuplicateHashes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    #[test]
    fn round_trip_preserves_order() {
        let hashes = [h(1), h(2), h(3)];
        let encoded = encode_msg_hash_list(&hashes);
        assert_eq!(encoded.len(), 3 * MSG_HASH_SIZE);
        assert_eq!(decode_msg_hash_list(&encoded).unwrap(), hashes);
    }

    #[test]
    fn empty_payload_decodes_to_no_hashes() {
        assert!(decode_msg_hash_list(&[]).unwrap().is_empty());
    }

    #[test]
    fn a_length_off_a_record_boundary_is_refused() {
        for bad in [1usize, MSG_HASH_SIZE - 1, MSG_HASH_SIZE + 1, 3 * MSG_HASH_SIZE - 1] {
            assert!(
                matches!(
                    decode_msg_hash_list(&vec![0u8; bad]),
                    Err(MsgboardError::MalformedHashList)
                ),
                "len {bad} must be refused",
            );
        }
    }

    /// The one length both readings accept. Pins the arithmetic that makes
    /// every other frame a mutual decode failure.
    #[test]
    fn the_two_wire_units_agree_only_at_3872_bytes() {
        let overlap =
            (1..=400).map(|n| n * MSG_HASH_SIZE).find(|len| len % crate::MSG_ID_SIZE == 0);
        assert_eq!(overlap, Some(3872));
        assert_eq!(3872 / MSG_HASH_SIZE, 121);
        assert_eq!(3872 / crate::MSG_ID_SIZE, 32);
    }

    #[test]
    fn duplicates_are_refused() {
        assert!(check_unique_hashes(&[h(1), h(2)]).is_ok());
        assert!(matches!(
            check_unique_hashes(&[h(1), h(2), h(1)]),
            Err(MsgboardError::DuplicateHashes)
        ));
    }
}
