//! `BoardMessages` payload codec: proof-of-work messages carrying a claimed hash.
//!
//! Erigon-pulse changed this payload's element type at `pulse-v3.4.4`
//! (`78fbcffb8b`, `msgboard/pow_message.go:51`). Each element used to be a
//! bare [`PoWMsg`]; it is now that message paired with the hash the sender
//! claims for it.
//!
//! The claimed hash exists to make a delivery checkable **before** the
//! expensive step. A message's identity is `sha256` of the compressed elliptic
//! curve point, so nothing can look a message up, match it against a request,
//! or notice it is already held without first paying a secp256k1 scalar
//! multiplication. Putting the hash on the wire moves those three decisions in
//! front of that cost. The claim is never trusted: the receiver recomputes and
//! kicks on a mismatch.

extern crate alloc;

use alloc::vec::Vec;

use alloy_primitives::B256;
use alloy_rlp::{RlpDecodable, RlpEncodable};

use crate::{MsgboardError, PoWMsg};

/// A `BoardMessages` element: the message body plus its claimed work hash.
///
/// Encodes as a two-item list, `[[version, block_hash, nonce, multiplier,
/// divisor, category, data], claimed_hash]`, matching Go's embedded
/// pointer-to-struct encoding of `WirePoWMsg`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct WirePoWMsg {
    /// The message body.
    pub msg: PoWMsg,
    /// The work hash the sender claims for [`msg`](Self::msg). Untrusted until
    /// the receiver recomputes it.
    pub hash: B256,
}

impl WirePoWMsg {
    /// Pair a message with a claimed hash.
    pub const fn new(msg: PoWMsg, hash: B256) -> Self {
        Self { msg, hash }
    }
}

/// Decode a `BoardMessages` payload and field-validate every element.
///
/// Rejects, in order: trailing bytes after the list, a missing element body, a
/// zero claimed hash, and any message that fails [`PoWMsg::validate`]. One bad
/// element rejects the whole frame, as erigon's `DecodeRLPWireMsgList` does —
/// the sender is about to be penalised either way, and a partial accept would
/// let a peer mix valid messages into a frame it knows will be refused.
///
/// Trailing bytes are refused because Go's `rlp.DecodeBytes` refuses them
/// (`errMoreThanOneValue`), and erigon's comment says it chose `DecodeBytes`
/// for exactly that. Without the check one message set has many valid frames.
///
/// A zero claimed hash is refused rather than treated as "no claim". Erigon
/// uses zero as its absent-claim sentinel internally, but a peer that omits
/// the claim on the wire is asking us to pay the verification it was supposed
/// to let us skip.
pub fn decode_wire_pow_msg_list(payload: &[u8]) -> Result<Vec<WirePoWMsg>, MsgboardError> {
    use alloy_rlp::Decodable;

    let mut buf = payload;
    let msgs = Vec::<WirePoWMsg>::decode(&mut buf).map_err(MsgboardError::Rlp)?;
    if !buf.is_empty() {
        return Err(MsgboardError::TrailingBytes);
    }
    for m in &msgs {
        if m.hash.is_zero() {
            return Err(MsgboardError::MissingClaimedHash);
        }
        m.msg.validate()?;
    }
    Ok(msgs)
}

/// Encode messages and their claimed hashes as a `BoardMessages` payload.
pub fn encode_wire_pow_msg_list(msgs: &[WirePoWMsg]) -> Vec<u8> {
    use alloy_rlp::{length_of_length, Encodable, Header};

    let payload_len: usize = msgs.iter().map(Encodable::length).sum();
    let mut out = Vec::with_capacity(length_of_length(payload_len) + payload_len);
    Header { list: true, payload_length: payload_len }.encode(&mut out);
    for m in msgs {
        m.encode(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;

    use super::*;
    use crate::VERSION_V1;

    fn msg(seed: u8, data: &[u8]) -> PoWMsg {
        let mut block_hash = [0u8; 32];
        block_hash[0] = seed;
        block_hash[1] = 0xAA;
        let mut category = [0u8; 32];
        category[0] = seed;
        category[1] = 0xCC;
        PoWMsg {
            version: VERSION_V1,
            block_hash: B256::from(block_hash),
            nonce: u64::from(seed) + 1,
            work_multiplier: 10_000,
            work_divisor: 1_000_000,
            category: B256::from(category),
            data: Bytes::copy_from_slice(data),
        }
    }

    fn wire(seed: u8, data: &[u8]) -> WirePoWMsg {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        hash[1] = 0xEE;
        WirePoWMsg::new(msg(seed, data), B256::from(hash))
    }

    #[test]
    fn round_trip_preserves_bodies_and_claims() {
        let msgs = [wire(1, b"hello"), wire(2, b"")];
        let decoded = decode_wire_pow_msg_list(&encode_wire_pow_msg_list(&msgs)).unwrap();
        assert_eq!(decoded, msgs);
    }

    #[test]
    fn an_empty_list_round_trips() {
        assert!(decode_wire_pow_msg_list(&encode_wire_pow_msg_list(&[])).unwrap().is_empty());
    }

    #[test]
    fn trailing_bytes_after_the_list_are_refused() {
        let mut encoded = encode_wire_pow_msg_list(&[wire(1, b"hi")]);
        encoded.push(0xC0);
        assert!(matches!(decode_wire_pow_msg_list(&encoded), Err(MsgboardError::TrailingBytes)));
    }

    #[test]
    fn a_zero_claimed_hash_is_refused() {
        let mut m = wire(1, b"hi");
        m.hash = B256::ZERO;
        assert!(matches!(
            decode_wire_pow_msg_list(&encode_wire_pow_msg_list(&[m])),
            Err(MsgboardError::MissingClaimedHash)
        ));
    }

    #[test]
    fn one_invalid_body_rejects_the_whole_frame() {
        let mut bad = wire(2, b"hi");
        bad.msg.nonce = 0;
        let encoded = encode_wire_pow_msg_list(&[wire(1, b"ok"), bad]);
        assert!(matches!(decode_wire_pow_msg_list(&encoded), Err(MsgboardError::InvalidNonce)));
    }

    /// The old payload is a list of seven-field lists; the new one is a list of
    /// two-item lists. Neither decoder accepts the other's frame, which is the
    /// whole of the interop break.
    #[test]
    fn the_old_and_new_payload_shapes_do_not_overlap() {
        let plain = crate::encode_pow_msg_list(&[msg(1, b"hello")]);
        assert!(decode_wire_pow_msg_list(&plain).is_err(), "new decoder must refuse old frames");

        let wired = encode_wire_pow_msg_list(&[wire(1, b"hello")]);
        assert!(crate::decode_pow_msg_list(&wired).is_err(), "old decoder must refuse new frames",);
    }
}
