//! `PoW` message types and verification.
//!
//! ## Wire format
//!
//! [`PoWMsg`] is the payload sent across the wire (RLP-encoded list). Its
//! fields must be declared in exactly this order for the derive macros to
//! produce a compatible encoding.
//!
//! [`CheckedPoWMsg`] wraps a validated `PoWMsg` with server-side metadata
//! (`block_number`, `timestamp`, and the `PoW` `hash`). Its RLP encoding nests
//! the `PoWMsg` as an inner list — matching the Go reference implementation's
//! behaviour for embedded pointer-to-struct fields.
//!
//! ## `PoW` algorithm
//!
//! Implemented from `specs/04-msgboard-pow-v2.md`.
//!
//! ```text
//! D           = (2^24 + 10_000·len(data)) · M / Div          // arbitrary precision
//! target      = 2^256 / D
//! payloadHash = sha256(category ‖ data)
//! scalarHash  = sha256(version ‖ blockHash ‖ payloadHash ‖ M ‖ Div ‖ nonce)
//! scalar      = int(scalarHash), refused unless 1 ≤ scalar < n
//! point       = G × scalar
//! workHash    = sha256(compress(point))                      // 33 bytes, 0x02/0x03 ‖ x
//! accept iff  int(workHash) < target
//! ```
//!
//! ## What this replaced
//!
//! Until this construction landed, `version = 1` named a different algorithm:
//! `scalar = nonce × sha256(M ‖ Div)[16..] + blockHash`, an uncompressed
//! x-coordinate for the challenge, `hash = sha256(challenge ‖ category ‖ data)`,
//! and acceptance on `hash mod D == 0`. It had two independent defects, and
//! they compounded.
//!
//! **The scalar was linear in the nonce.** `scalar(n+1) = scalar(n) + digest`,
//! so `G×scalar(n+1) = G×scalar(n) + G×digest` where `G×digest` is constant for
//! a given multiplier/divisor pair. A miner walked nonces with one point
//! addition (~1 µs) where a verifier always paid a full scalar multiplication
//! (~60–120 µs), so the work cost 50–500× less than the difficulty parameter
//! implied.
//!
//! **The challenge never committed to the payload.** `category` and `data`
//! entered only at the final hash, so one precomputed challenge sequence mined
//! every message in that block at that difficulty. For K messages the
//! elliptic-curve cost was O(N), not O(K·N) — the first message was cheap and
//! every message after it was nearly free.
//!
//! The first defect made the table cheap to build; the second made it reusable.
//! Here the scalar is a SHA-256 digest, which is not additively homomorphic, so
//! consecutive nonces give unrelated scalars and every attempt needs its own
//! scalar multiplication. Because the digest commits to `payloadHash`, each
//! message body gets its own sequence and the table-reuse amplification dies
//! with it. One change closes both.
//!
//! A third divergence goes with them: `D` used to be computed in wrapping
//! `u64`, which let an attacker solve `base × M ≡ 2ᵏ (mod 2⁶⁴)`, set
//! `Div = 2ᵏ`, and wrap the threshold to 1 — free `PoW` for any nonce. Here `D`
//! is arbitrary precision and a larger `D` makes the work *harder*, so there is
//! nothing to wrap. That also makes the minimum-work gate sound for the first
//! time: `D` is monotone in `M/Div`, so clearing the gate and paying nothing
//! are no longer compatible.
//!
//! ## This is a flag day
//!
//! The version byte did not change, so a message mined under the old rules does
//! not verify here and never will. There is no dual-accept path: the two
//! constructions share a version number, so nothing can tell them apart, and
//! accepting both would mean the weaker one governs. Boards must be drained and
//! posters must be upgraded together.

use alloy_primitives::{Bytes, B256, U256, U512};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use sha2::{Digest, Sha256};

use crate::{MsgID, MsgboardError};

/// secp256k1 group order `n` in big-endian (32 bytes).
///
/// `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // FFFFFFFF FFFFFFFF
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, // FFFFFFFF FFFFFFFE
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, // BAAEDCE6 AF48A03B
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, // BFD25E8C D0364141
];

/// Encoding version 1 — the only version, and the only construction.
///
/// The byte did not change when the algorithm did; see the module docs.
pub const VERSION_V1: u8 = 1;

/// The `PoW` message payload exchanged between peers.
///
/// Encoded as an RLP list in field-declaration order. All fields must remain
/// in this exact sequence for wire-format compatibility with erigon-pulse.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PoWMsg {
    /// Encoding version. Must be [`VERSION_V1`].
    pub version: u8,
    /// Keccak-256 hash of the block when the message was submitted.
    pub block_hash: B256,
    /// Nonce found during `PoW` mining.
    pub nonce: u64,
    /// Work multiplier for the difficulty calculation.
    pub work_multiplier: u64,
    /// Work divisor for the difficulty calculation.
    pub work_divisor: u64,
    /// Application-defined 32-byte category id (clients commonly use
    /// `keccak256(text)`, but any 32-byte scheme is valid).
    pub category: B256,
    /// Arbitrary message body.
    pub data: Bytes,
}

/// A validated `PoWMsg` with server-side metadata.
///
/// The RLP encoding nests `msg` as an inner list followed by the three
/// metadata fields — matching Go's embedded pointer-to-struct RLP encoding.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct CheckedPoWMsg {
    /// The validated message payload.
    pub msg: PoWMsg,
    /// Block number corresponding to [`PoWMsg::block_hash`].
    pub block_number: u64,
    /// Unix timestamp (seconds) when this message was validated.
    pub timestamp: u64,
    /// SHA-256 `PoW` hash (used to identify and re-verify the message).
    pub hash: B256,
}

impl PoWMsg {
    /// Perform basic field-level validation (does **not** verify the `PoW`).
    pub fn validate(&self) -> Result<(), MsgboardError> {
        if self.version != VERSION_V1 {
            return Err(MsgboardError::InvalidVersion);
        }
        if self.block_hash == B256::ZERO {
            return Err(MsgboardError::InvalidBlockHash);
        }
        if self.nonce == 0 {
            return Err(MsgboardError::InvalidNonce);
        }
        if self.work_multiplier == 0 || self.work_divisor == 0 {
            return Err(MsgboardError::InvalidDifficulty);
        }
        // Reject a zero difficulty here as well as in `to_checked`, so a
        // crafted message dies at the decode boundary — before the secp256k1
        // scalar multiplication the `PoW` check would otherwise pay for it, and
        // early enough for the sender to earn a reputation penalty.
        //
        // `D` is computed exactly and cannot wrap, so the only bad value is
        // zero, which admits nothing rather than everything.
        if self.difficulty().is_none_or(|d| d.is_zero()) {
            return Err(MsgboardError::InvalidDifficulty);
        }
        if self.category == B256::ZERO && self.data.is_empty() {
            return Err(MsgboardError::InvalidData);
        }
        Ok(())
    }

    /// Byte length of the `data` field.
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// `work_multiplier / work_divisor` as a float. Used for minimum-ratio checks.
    pub fn difficulty_ratio(&self) -> f64 {
        self.work_multiplier as f64 / self.work_divisor as f64
    }

    // ── the PoW itself ───────────────────────────────────────────────────────

    /// `sha256(category ‖ data)`, binding the message body into the scalar.
    pub fn payload_hash(&self) -> B256 {
        let mut h = Sha256::new();
        h.update(self.category.as_slice());
        h.update(&self.data);
        B256::from_slice(&h.finalize())
    }

    /// `sha256(version ‖ blockHash ‖ payloadHash ‖ M ‖ Div ‖ nonce)`.
    ///
    /// Integers are big-endian at fixed width: one byte for `version`, eight
    /// each for `work_multiplier`, `work_divisor` and `nonce`.
    pub fn scalar_hash(&self) -> B256 {
        let mut h = Sha256::new();
        h.update([self.version]);
        h.update(self.block_hash.as_slice());
        h.update(self.payload_hash().as_slice());
        h.update(self.work_multiplier.to_be_bytes());
        h.update(self.work_divisor.to_be_bytes());
        h.update(self.nonce.to_be_bytes());
        B256::from_slice(&h.finalize())
    }

    /// The compressed `G × scalar`, or `None` when the scalar is out of range.
    ///
    /// The scalar is [`scalar_hash`](Self::scalar_hash) read big-endian,
    /// **refused** rather than reduced when it falls outside `[1, n)` — the
    /// spec is explicit that this must match Go's `ScalarBaseMult`, which
    /// rejects an out-of-range scalar instead of wrapping it. A caller mining a
    /// message treats `None` as "try the next nonce"; a verifier treats it as
    /// an invalid message.
    ///
    /// SHA-256 output lands outside `[1, n)` with probability about 2⁻¹²⁸, so
    /// this is a conformance rule rather than a reachable branch. It still
    /// earns its place: a verifier that reduced would accept messages a
    /// conforming verifier refuses, and the disagreement would be silent.
    pub fn challenge(&self) -> Option<[u8; 33]> {
        let digest = self.scalar_hash();
        let scalar = U256::from_be_slice(digest.as_slice());
        if scalar.is_zero() || scalar >= U256::from_be_slice(&SECP256K1_ORDER) {
            return None;
        }
        // `from_slice` enforces the same range rule a second time; the point at
        // infinity the spec names is unreachable for a scalar in `[1, n)`.
        let sk = secp256k1::SecretKey::from_slice(digest.as_slice()).ok()?;
        let pk = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &sk);
        Some(pk.serialize())
    }

    /// `sha256(compressed_point)` — the work hash compared against the target.
    pub fn calculate_hash(&self) -> Option<B256> {
        let compressed = self.challenge()?;
        Some(B256::from_slice(&Sha256::digest(compressed)))
    }

    /// `D = (2^24 + 10_000·len(data)) · M / Div`, exact.
    ///
    /// `None` only when `work_divisor` is zero. This cannot overflow: the base
    /// is under 2²⁵ for any message the size limit admits and `M` is a `u64`,
    /// so the product stays far inside 256 bits.
    pub fn difficulty(&self) -> Option<U256> {
        let divisor = U256::from(self.work_divisor);
        if divisor.is_zero() {
            return None;
        }
        let base = U256::from(1u64 << 24) + U256::from(self.size()) * U256::from(10_000u64);
        Some(base * U256::from(self.work_multiplier) / divisor)
    }

    /// `2^256 / D`, the value the work hash must fall below.
    ///
    /// Returned as [`U512`] because `D = 1` gives exactly 2²⁵⁶, which does not
    /// fit in 256 bits. `None` when `D` is zero or undefined — a zero threshold
    /// admits nothing, so the message is unminable rather than free, and
    /// refusing it outright says so.
    pub fn target(&self) -> Option<U512> {
        let d = self.difficulty()?;
        if d.is_zero() {
            return None;
        }
        let two_256 = U512::from(1u8) << 256;
        Some(two_256 / u512_from_u256(d))
    }

    /// Verify the `PoW`, returning the work hash on success.
    pub fn verify(&self) -> Result<B256, MsgboardError> {
        let Some(target) = self.target() else {
            return Err(MsgboardError::InvalidDifficulty);
        };
        let Some(hash) = self.calculate_hash() else {
            return Err(MsgboardError::InvalidWork);
        };
        if u512_from_u256(U256::from_be_slice(hash.as_slice())) >= target {
            return Err(MsgboardError::InvalidWork);
        }
        Ok(hash)
    }

    /// Verify the `PoW` and return a [`CheckedPoWMsg`] on success.
    ///
    /// The caller supplies `block_number` (looked up from `block_hash`) and
    /// `timestamp` (current time in Unix seconds).
    pub fn to_checked(
        self,
        block_number: u64,
        timestamp: u64,
    ) -> Result<CheckedPoWMsg, MsgboardError> {
        let hash = self.verify()?;
        Ok(CheckedPoWMsg { msg: self, block_number, timestamp, hash })
    }
}

/// Widen a `U256` without going through a string or a fallible conversion.
fn u512_from_u256(value: U256) -> U512 {
    let mut buf = [0u8; 64];
    buf[32..].copy_from_slice(&value.to_be_bytes::<32>());
    U512::from_be_slice(&buf)
}

impl CheckedPoWMsg {
    /// Build a [`MsgID`] for peer announcement.
    pub fn msg_id(&self) -> MsgID {
        MsgID::from_checked(
            self.msg.version,
            &self.msg.block_hash,
            self.msg.size(),
            self.msg.work_multiplier,
            self.msg.work_divisor,
            &self.msg.category,
            &self.hash,
        )
    }
}

/// Decode an RLP-list payload of [`PoWMsg`]s (`BoardMessages` wire message).
///
/// Each decoded message is field-validated on the spot — mirrors erigon's
/// `DecodeRLPMsgList` calling `Validate()` per element. Callers downstream
/// (`MsgBoard::add_remote_msgs` etc.) can therefore trust the input.
pub fn decode_pow_msg_list(payload: &[u8]) -> Result<Vec<PoWMsg>, MsgboardError> {
    use alloy_rlp::Decodable;
    let msgs = Vec::<PoWMsg>::decode(&mut &*payload).map_err(MsgboardError::Rlp)?;
    for m in &msgs {
        m.validate()?;
    }
    Ok(msgs)
}

/// Decode a single RLP-encoded [`PoWMsg`] and validate it in one step.
///
/// Used by the JSON-RPC `msgboard_addMessage` handler. Mirrors erigon-pulse's
/// `PoWMsgFromRLP` (decode + `Validate`) so the validation step lives at the
/// decode boundary, not inside the board's hot path.
pub fn decode_validated_pow_msg(payload: &[u8]) -> Result<PoWMsg, MsgboardError> {
    use alloy_rlp::Decodable;
    let msg = PoWMsg::decode(&mut &*payload).map_err(MsgboardError::Rlp)?;
    msg.validate()?;
    Ok(msg)
}

/// Encode a slice of [`PoWMsg`]s as an RLP list (`BoardMessages` wire message).
pub fn encode_pow_msg_list(msgs: &[PoWMsg]) -> Vec<u8> {
    use alloy_rlp::{length_of_length, Encodable, Header};
    // Compute payload length to pre-size the header correctly.
    let payload_len: usize = msgs.iter().map(|m| m.length()).sum();
    let mut out = Vec::with_capacity(length_of_length(payload_len) + payload_len);
    Header { list: true, payload_length: payload_len }.encode(&mut out);
    for msg in msgs {
        msg.encode(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    fn block_hash_one() -> B256 {
        // Matches Go's common.Hash{0x1}: first byte = 0x01, rest zero.
        let mut b = [0u8; 32];
        b[0] = 0x01;
        B256::from(b)
    }

    fn category_from_str(s: &str) -> B256 {
        // Go uses keccak256 for category hashes.
        keccak256(s.as_bytes())
    }

    fn make_msg(nonce: u64, data: &[u8]) -> PoWMsg {
        PoWMsg {
            version: VERSION_V1,
            block_hash: block_hash_one(),
            nonce,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: category_from_str("random-input"),
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Brute-force search for a valid nonce (≤ 1 M iterations).
    fn find_nonce(data: &[u8]) -> Option<u64> {
        (1u64..=1_000_000).find(|n| make_msg(*n, data).to_checked(0, 0).is_ok())
    }

    #[test]
    fn test_pow_accepts_valid_work() {
        let n = find_nonce(&[0u8]).expect("nonce found within 1M iterations");
        assert!(make_msg(n, &[0u8]).to_checked(0, 0).is_ok());
    }

    #[test]
    fn test_validate_rejects_zero_block_hash() {
        let mut msg = make_msg(1, &[1]);
        msg.block_hash = B256::ZERO;
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidBlockHash)));
    }

    #[test]
    fn test_validate_rejects_zero_nonce() {
        let msg = make_msg(0, &[1]);
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidNonce)));
    }

    #[test]
    fn test_validate_rejects_zero_divisor() {
        let mut msg = make_msg(1, &[1]);
        msg.work_divisor = 0;
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidDifficulty)));
    }

    #[test]
    fn test_validate_rejects_zero_multiplier() {
        let mut msg = make_msg(1, &[1]);
        msg.work_multiplier = 0;
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidDifficulty)));
    }

    /// Version 1 is the only version, and it now names the new construction.
    /// Anything else is refused at the decode boundary.
    ///
    /// Version 2 is checked explicitly: it was briefly used here to carry the
    /// new construction alongside the old one, and reverting to that would
    /// silently re-admit a second algorithm.
    #[test]
    fn test_validate_rejects_versions_we_do_not_speak() {
        let mut msg = make_msg(1, &[1]);

        msg.version = VERSION_V1;
        assert!(msg.validate().is_ok());

        for bad in [0u8, 2, 3, 255] {
            msg.version = bad;
            assert!(
                matches!(msg.validate(), Err(MsgboardError::InvalidVersion)),
                "version {bad} must be refused",
            );
        }
    }

    /// A message with neither a category nor a body carries no information but
    /// still costs a board slot, so it is rejected. Either field alone is enough
    /// to make it meaningful.
    #[test]
    fn test_validate_rejects_empty_category_and_data_together() {
        let mut msg = make_msg(1, &[]);
        msg.category = B256::ZERO;
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidData)));

        // A body with no category is valid.
        let mut with_data = make_msg(1, &[7]);
        with_data.category = B256::ZERO;
        assert!(with_data.validate().is_ok(), "data alone should be accepted");

        // A category with no body is valid.
        let with_category = make_msg(1, &[]);
        assert!(with_category.validate().is_ok(), "category alone should be accepted");
    }

    /// `D` is arbitrary precision, so the wrap that used to make `PoW` free is
    /// gone — see the module docs.
    ///
    /// `work_multiplier = 2⁴⁰ + 3` against an empty body (`base = 2²⁴`) puts the
    /// product past the `u64` boundary. Under the old wrapping arithmetic that
    /// produced `3 × 2²⁴`, a trivially cheap threshold, from a message whose
    /// declared work is astronomically expensive. Here the exact value survives,
    /// and a bigger `D` means a *smaller* target, so the message is merely
    /// unminable.
    #[test]
    fn test_difficulty_is_exact_and_never_wraps() {
        let mut msg = make_msg(1, &[]);
        msg.work_multiplier = (1u64 << 40) + 3;
        msg.work_divisor = 1;

        let d = msg.difficulty().expect("a nonzero divisor always yields a difficulty");
        assert_eq!(d, U256::from(1u64 << 24) * U256::from((1u64 << 40) + 3));
        assert!(d > U256::from(u64::MAX), "the exact value must not be truncated to a u64");
        assert_ne!(d, U256::from(3u64 * (1u64 << 24)), "the old wrapped value");

        // Field validation passes — the parameters are well formed, just very
        // expensive. The rejection is the work check, not the decode boundary.
        assert!(msg.validate().is_ok());
        assert!(matches!(msg.to_checked(0, 0), Err(MsgboardError::InvalidWork)));
    }

    /// `D` floors to zero when `M/Div` is small enough, and a zero `D` would be
    /// a division by zero in [`target`](PoWMsg::target). It is refused at both
    /// gates rather than divided by.
    ///
    /// A zero threshold admits nothing, so refusing it costs no honest message.
    #[test]
    fn test_zero_difficulty_is_refused_not_divided_by() {
        let mut msg = make_msg(1, &[]);
        msg.work_multiplier = 1;
        msg.work_divisor = u64::MAX;

        assert_eq!(msg.difficulty(), Some(U256::ZERO));
        assert_eq!(msg.target(), None);
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidDifficulty)));
        assert!(matches!(msg.to_checked(0, 0), Err(MsgboardError::InvalidDifficulty)));
    }

    /// `work_divisor == 0` must not divide by zero. `validate` rejects it
    /// first, but `difficulty` is public and total on its own.
    #[test]
    fn test_zero_divisor_returns_none_rather_than_panicking() {
        let mut msg = make_msg(1, &[]);
        msg.work_divisor = 0;

        assert_eq!(msg.difficulty(), None);
        assert_eq!(msg.target(), None);
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidDifficulty)));
        assert!(matches!(msg.to_checked(0, 0), Err(MsgboardError::InvalidDifficulty)));
    }

    /// Pins the documented formula `(2²⁴ + size × 10_000) × multiplier / divisor`
    /// on ordinary inputs, so the constants cannot drift under cover of the
    /// wrapping tests above.
    #[test]
    fn test_difficulty_matches_the_documented_formula() {
        // Empty body at the default ratio: 2^24 × 10_000 / 1_000_000.
        let mut msg = make_msg(1, &[]);
        msg.work_multiplier = 10_000;
        msg.work_divisor = 1_000_000;
        assert_eq!(msg.difficulty(), Some(U256::from(167_772u64)));

        // Each body byte adds 10_000 to the base.
        let mut sized = make_msg(1, &[0u8; 100]);
        sized.work_multiplier = 10_000;
        sized.work_divisor = 1_000_000;
        assert_eq!(sized.difficulty(), Some(U256::from(177_772u64)));
        assert!(sized.difficulty() > msg.difficulty(), "a larger body must cost more work");

        // And a larger D must mean a *smaller* target, or the gate is inverted.
        assert!(sized.target() < msg.target(), "more work must mean a tighter target");
    }

    #[test]
    fn test_rlp_round_trip_single() {
        let n = find_nonce(&[42u8]).expect("nonce found");
        let checked = make_msg(n, &[42u8]).to_checked(100, 999).expect("valid");

        use alloy_rlp::{Decodable, Encodable};
        let mut enc = Vec::new();
        checked.encode(&mut enc);
        let dec = CheckedPoWMsg::decode(&mut enc.as_slice()).expect("decode ok");
        assert_eq!(dec.msg, checked.msg);
        assert_eq!(dec.hash, checked.hash);
        assert_eq!(dec.block_number, 100);
        assert_eq!(dec.timestamp, 999);
    }

    #[test]
    fn test_rlp_round_trip_list() {
        let msgs: Vec<PoWMsg> = (0u8..5)
            .filter_map(|i| {
                let n = find_nonce(&[i])?;
                Some(make_msg(n, &[i]))
            })
            .collect();
        let encoded = encode_pow_msg_list(&msgs);
        let decoded = decode_pow_msg_list(&encoded).expect("decode ok");
        assert_eq!(decoded.len(), msgs.len());
        for (orig, dec) in msgs.iter().zip(decoded.iter()) {
            assert_eq!(orig.nonce, dec.nonce);
            assert_eq!(orig.data, dec.data);
        }
    }

    /// Decodes the hardcoded Go test vector, verifying wire-format compatibility.
    #[test]
    fn test_hardcoded_list_compatibility() {
        // From msgboard/pow_message_test.go TestHardcodedList — 20 messages.
        let hex = concat!(
            "f905f0",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000601830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c00",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000b01830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c01",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000801830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c02",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001f01830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c03",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000101830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c04",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000002101830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c05",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000301830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c06",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000101830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c07",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001001830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c08",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001101830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c09",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001901830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c0a",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001601830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c0b",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000901830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c0c",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000501830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c0d",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000e01830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c0e",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001e01830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c0f",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000901830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c10",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000001801830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c11",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000004801830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c12",
            "f84a01a001000000000000000000000000000000000000000000000000000000000000000d01830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c13",
        );
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();

        let msgs = decode_pow_msg_list(&bytes).expect("decode ok");
        assert_eq!(msgs.len(), 20);

        let first = &msgs[0];
        assert_eq!(first.nonce, 6);
        assert_eq!(first.work_multiplier, 1);
        assert_eq!(first.work_divisor, 1_000_000);
        assert_eq!(first.block_hash, block_hash_one());
        assert_eq!(first.data, Bytes::from(vec![0u8]));
    }

    #[test]
    fn test_msg_id_fields() {
        let n = find_nonce(&[7u8]).expect("nonce found");
        let msg = make_msg(n, &[7u8]);
        let checked = msg.to_checked(42, 0).expect("valid");
        let id = checked.msg_id();
        assert_eq!(id.version(), VERSION_V1);
        assert_eq!(id.block_hash(), checked.msg.block_hash);
        assert_eq!(id.message_hash(), checked.hash);
        assert_eq!(id.size(), 1);
        assert_eq!(id.work_multiplier(), 1);
        assert_eq!(id.work_divisor(), 1_000_000);
    }

    #[test]
    fn test_msg_id_encode_decode_list() {
        let n = find_nonce(&[0u8]).expect("nonce found");
        let checked = make_msg(n, &[0u8]).to_checked(0, 0).expect("valid");
        let id = checked.msg_id();
        let flat = MsgID::encode_list(&[id]);
        let ids = MsgID::decode_list(&flat).expect("decode ok");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], id);
    }

    /// Verifies [`MsgID`] round-trip for 100 messages, mirroring Go's `TestChunkEncoding`.
    ///
    /// The Go test additionally verifies chunk-size boundaries when the IDs are
    /// split for transmission. That chunking logic lives in the msgboard manager crate;
    /// here we focus on the flat-byte encoding of the IDs themselves.
    #[test]
    fn test_msg_id_round_trip_large_batch() {
        let msgs: Vec<CheckedPoWMsg> = (0u8..20)
            .filter_map(|i| {
                let n = find_nonce(&[i])?;
                make_msg(n, &[i]).to_checked(u64::from(i), 0).ok()
            })
            .collect();

        let ids: Vec<MsgID> = msgs.iter().map(|m| m.msg_id()).collect();
        let flat = MsgID::encode_list(&ids);

        // Byte length must be an exact multiple of MSG_ID_SIZE.
        assert_eq!(flat.len() % crate::MSG_ID_SIZE, 0);
        assert_eq!(flat.len() / crate::MSG_ID_SIZE, ids.len());

        let decoded = MsgID::decode_list(&flat).expect("decode ok");
        assert_eq!(decoded.len(), ids.len());

        for (orig, dec) in ids.iter().zip(decoded.iter()) {
            assert_eq!(orig.block_hash(), dec.block_hash(), "block_hash mismatch");
            assert_eq!(orig.category_hash(), dec.category_hash(), "category_hash mismatch");
            assert_eq!(orig.message_hash(), dec.message_hash(), "msg_hash mismatch");
            assert_eq!(orig.size(), dec.size(), "size mismatch");
            assert_eq!(orig.work_multiplier(), dec.work_multiplier(), "multiplier mismatch");
            assert_eq!(orig.work_divisor(), dec.work_divisor(), "divisor mismatch");
        }
    }

    /// A message taken off the live `PulseChain` testnet board (`direct-a-evm-943`,
    /// 2026-08-19), mined under the construction this replaced.
    ///
    /// It is pinned here as a negative control. The golden vectors are mined by
    /// this crate, so they would still agree with themselves if the code drifted
    /// back toward the old algorithm; this one was mined by somebody else's
    /// client and accepted by the running fleet, so it is the only case here
    /// that can catch a partial revert.
    ///
    /// Its work is real — it satisfied `hash mod D == 0` under the old rules —
    /// and it is worthless now. That is the flag day, stated as a test.
    #[test]
    fn test_a_message_mined_under_the_old_construction_is_now_worthless() {
        let msg = PoWMsg {
            version: VERSION_V1,
            block_hash: B256::from(hex_literal::hex!(
                "3a2ca760216c5cb648c32aab73cbc1cdfdbcf02f77a4cd190995e3c46f3932b5"
            )),
            nonce: 0x2_ce3e,
            work_multiplier: 0x2710,
            work_divisor: 0xf_4240,
            category: B256::from(hex_literal::hex!(
                "6368617474657200000000000000000000000000000000000000000000000000"
            )),
            data: Bytes::from_static(b"Velit et tempor veniam cupidatat sint."),
        };

        // The fields are still well formed — nothing about the message is
        // malformed, so it reaches the work check and dies there.
        msg.validate().expect("field validation is unchanged by the construction");

        assert!(
            matches!(msg.clone().to_checked(0x1_8009a1, 0), Err(MsgboardError::InvalidWork)),
            "a message mined under the old rules must not verify under the new ones",
        );

        // And the hash the network assigned it is not the hash this computes.
        assert_ne!(
            msg.calculate_hash().expect("the scalar is in range"),
            B256::from(hex_literal::hex!(
                "9cee9288b15680744308a5aad4f1d6f5c04a4e4313a8eeb4d573f40387b741bc"
            )),
            "the old PoW hash must not be reproducible by the new construction",
        );
    }

    /// Decodes the hardcoded `CheckedPoWMsg` from Go's `TestEncodeAndDecode`.
    ///
    /// This vector was captured from a real run of the Go reference implementation and is
    /// used here as a regression guard for RLP wire-format compatibility.
    ///
    /// The test only asserts the fields that the Go test checks (`block_hash`); we
    /// additionally verify `block_number` and that the nested `PoWMsg` round-trips correctly.
    #[test]
    fn test_hardcoded_checked_msg_compatibility() {
        // From msgboard/pow_message_test.go TestEncodeAndDecode.
        let hex = "f873f84a01a001000000000000000000000000000000000000000000000000000000000000000a01830f4240a0e35b90d0a20cb5bce23094ae1bf57a14936e8d58ffbb6367d49d322b154ffc9c00808466d6a9c8a0aa9613114408f76174691a88a2c92af6ef6d329dc209f46c05073a0b6debd71b";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();

        use alloy_rlp::Decodable;
        let msg = CheckedPoWMsg::decode(&mut bytes.as_slice()).expect("decode ok");

        // Block hash must match common.Hash{0x1} from the Go test.
        let mut expected_hash = [0u8; 32];
        expected_hash[0] = 0x01;
        assert_eq!(msg.msg.block_hash, B256::from(expected_hash));

        // block_number was passed as 0 in Go's ToCheckedMsg(0) call.
        assert_eq!(msg.block_number, 0);

        // Sanity-check the version byte.
        assert_eq!(msg.msg.version, VERSION_V1);
    }
}

#[cfg(test)]
mod difficulty_overflow_regression {
    use super::*;
    use crate::MsgboardConfig;
    use alloy_primitives::keccak256;

    /// `work_multiplier`/`work_divisor` that wrapped [`PoWMsg::difficulty`] onto
    /// 1 for a 1-byte message under erigon's `uint64` arithmetic, found by
    /// solving `base × multiplier ≡ 2^v2(base) (mod 2^64)`.
    ///
    /// `base = 2^24 + 1 × 10_000 = 16_787_216 = 2^4 × 1_049_201`, so the
    /// multiplier is the inverse of `1_049_201` mod `2^60` and the divisor is
    /// `2^4`.
    const EVIL_MULTIPLIER: u64 = 1_014_806_211_241_672_337;
    const EVIL_DIVISOR: u64 = 16;

    fn evil_msg(nonce: u64) -> PoWMsg {
        let mut b = [0u8; 32];
        b[0] = 0x01;
        PoWMsg {
            version: VERSION_V1,
            block_hash: B256::from(b),
            nonce,
            work_multiplier: EVIL_MULTIPLIER,
            work_divisor: EVIL_DIVISOR,
            category: keccak256(b"spam"),
            data: Bytes::copy_from_slice(&[0u8]),
        }
    }

    /// Regression test for the zero-work exploit — see
    /// `docs/msgboard-parity-gaps.md` §14.1.
    ///
    /// Under erigon's wrapping arithmetic these parameters made `difficulty ==
    /// 1`, and every hash is divisible by 1, so any nonce was a valid solution
    /// and the message cost no work at all.
    ///
    /// The exploit needed two things: a threshold that wraps, and an acceptance
    /// test where a *smaller* threshold is easier. Both are gone. `D` is exact
    /// here, and a larger `D` gives a tighter target, so the crafted parameters
    /// now buy the attacker the hardest message on the board instead of the
    /// cheapest.
    #[test]
    fn crafted_overflow_no_longer_makes_pow_free() {
        let d = evil_msg(1).difficulty().expect("well-formed parameters");
        assert_eq!(
            d,
            U256::from(1_064_735_691_640_973_857_652_737u128),
            "the exact threshold, ~2^80 — never the wrapped 1",
        );
        assert!(d > U256::from(u64::MAX));

        for nonce in 1..=64u64 {
            assert!(
                matches!(evil_msg(nonce).to_checked(100, 0), Err(MsgboardError::InvalidWork)),
                "nonce {nonce} must be rejected, not accepted for free",
            );
        }
    }

    /// The minimum-work gate never defended against this on its own, and the
    /// crafted ratio still clears it. What changed is that clearing the gate now
    /// implies paying the work.
    ///
    /// The gate constrains the declared ratio `multiplier / divisor`, and the
    /// crafted ratio is enormous precisely because that is what the overflow
    /// required. `D` is monotone in `M/Div`, so a ratio this large can only mean
    /// a target this tight.
    #[test]
    fn the_minimum_work_gate_still_accepts_the_crafted_ratio() {
        let cfg = MsgboardConfig::default();
        assert!(
            cfg.is_work_acceptable(EVIL_MULTIPLIER, EVIL_DIVISOR),
            "the gate is not what rejects these messages",
        );

        let evil = evil_msg(1).difficulty_ratio();
        let honest = cfg.work_multiplier as f64 / cfg.work_divisor as f64;
        assert!(evil > honest * 1e18, "declared ratio {evil} dwarfs the honest {honest}");

        // Monotonicity is the property that makes the gate sound: the crafted
        // ratio cannot buy a target any looser than the honest one.
        let honest_msg = PoWMsg { work_multiplier: 10_000, work_divisor: 1_000_000, ..evil_msg(1) };
        assert!(
            evil_msg(1).target() < honest_msg.target(),
            "a higher declared ratio must mean a tighter target",
        );
    }

    /// An honest message with the same body is unaffected.
    #[test]
    fn honest_parameters_are_unchanged_by_the_exact_computation() {
        let honest = PoWMsg { work_multiplier: 10_000, work_divisor: 1_000_000, ..evil_msg(1) };
        assert_eq!(honest.difficulty(), Some(U256::from(167_872u64)));
        assert!(honest.validate().is_ok());
    }
}

#[cfg(test)]
mod golden_vector {
    use super::*;

    /// The message both vectors are built from.
    fn vector_msg(nonce: u64, work_multiplier: u64, work_divisor: u64) -> PoWMsg {
        PoWMsg {
            version: VERSION_V1,
            block_hash: B256::from(hex_literal::hex!(
                "3a2ca760216c5cb648c32aab73cbc1cdfdbcf02f77a4cd190995e3c46f3932b5"
            )),
            nonce,
            work_multiplier,
            work_divisor,
            category: B256::from(hex_literal::hex!(
                "6368617474657200000000000000000000000000000000000000000000000000"
            )),
            data: Bytes::from_static(b"golden vector"),
        }
    }

    /// Vector A — the construction, at a fixed nonce, deliberately *not* mined.
    ///
    /// Difficulty is irrelevant here: the point is the byte layout. A vector
    /// that only checks the final verdict can pass by luck; four intermediates
    /// cannot.
    ///
    /// `specs/04-msgboard-pow-v2.md` cites `TestPoWGoldenVector` as the
    /// normative worked example, and no such test exists upstream. These digests
    /// were generated by an independent transcription of the spec text with a
    /// hand-rolled secp256k1, so agreement between it and this code is agreement
    /// between two readings of the spec rather than a tautology.
    #[test]
    fn vector_a_pins_every_intermediate() {
        let msg = vector_msg(1, 10_000, 1_000_000);

        assert_eq!(
            msg.payload_hash(),
            B256::from(hex_literal::hex!(
                "b66106e111b0e6cd08a49c7a37afa3259541bee8e465bef5e55f6cd7223d789a"
            )),
            "payloadHash = sha256(category ‖ data)",
        );
        assert_eq!(
            msg.scalar_hash(),
            B256::from(hex_literal::hex!(
                "3caed3ea9a5caa6e1e069d0126e4dc6698190aa3eec8ebcdab227d3e5b0fd18d"
            )),
            "scalarHash field order or widths differ from the spec",
        );
        assert_eq!(
            msg.challenge().expect("scalar in range"),
            hex_literal::hex!("035e55e474ae91c573e38855bba370f01d64a307fa9c834eda7b435ec9d24368b9"),
            "the point must be COMPRESSED — 33 bytes with a parity prefix",
        );
        assert_eq!(
            msg.calculate_hash().expect("scalar in range"),
            B256::from(hex_literal::hex!(
                "5ba003ccdb08503a19326a201834198a49e062d2f3f0e9506ff086eddb011dee"
            )),
            "workHash = sha256(compressed point)",
        );
        assert_eq!(msg.difficulty(), Some(U256::from(169_072u64)));

        // This vector is not mined, so it must NOT verify. That direction
        // matters: a check that only ever asserts success cannot tell a working
        // threshold from one that accepts everything.
        assert!(matches!(msg.verify(), Err(MsgboardError::InvalidWork)));
    }

    /// Vector B — the same message mined against an easier target.
    #[test]
    fn vector_b_verifies_when_mined() {
        let msg = vector_msg(57_602, 1, 1_000);

        assert_eq!(msg.difficulty(), Some(U256::from(16_907u64)));
        assert_eq!(
            msg.scalar_hash(),
            B256::from(hex_literal::hex!(
                "bcff3c0ddc5d02b05e282566461d4f30f35ce90b3bfd36cde0c694dcb54a5e7d"
            )),
        );
        assert_eq!(
            msg.challenge().expect("scalar in range"),
            hex_literal::hex!("030fbdcb58e555146c54a0863ebf038a0384d4bd90439d02b8d8d5f71096ca7a09"),
        );

        // Through `to_checked`, not just `verify` — that is the path the wire
        // takes, and it is what stamps the hash onto the `CheckedPoWMsg`.
        let checked = msg.clone().to_checked(100, 0).expect("vector B must be accepted");
        assert_eq!(checked.hash, msg.verify().expect("and agree with the direct call"));
        assert_eq!(
            checked.hash,
            B256::from(hex_literal::hex!(
                "00037212834e250723dc736508d445a0dbc01398040a980807641b4be2d1e361"
            )),
        );
    }

    /// One nonce either side of the mined one must fail, so the threshold is
    /// doing work rather than the vector happening to pass.
    #[test]
    fn neighbouring_nonces_do_not_verify() {
        for nonce in [57_601u64, 57_603] {
            assert!(
                vector_msg(nonce, 1, 1_000).verify().is_err(),
                "nonce {nonce} must not satisfy the target",
            );
        }
    }

    /// `D = 1` puts the target at exactly 2²⁵⁶, which is why it is carried as a
    /// `U512`. Truncating it to `U256::MAX` would reject the single hash equal
    /// to 2²⁵⁶−1.
    ///
    /// This is also the shape of the free-`PoW` case the spec leaves open: with
    /// no floor on `D`, `M = 1` and `Div = 2²⁴` make the first nonce win. What
    /// stops it here is the operator's minimum-work gate, not the arithmetic.
    #[test]
    fn a_difficulty_of_one_admits_every_hash() {
        let mut msg = vector_msg(1, 1, 1 << 24);
        msg.data = Bytes::new();
        assert_eq!(msg.difficulty(), Some(U256::from(1u8)));
        assert_eq!(msg.target(), Some(U512::from(1u8) << 256));
        assert!(msg.verify().is_ok(), "every hash is below 2^256");
    }
}
#[cfg(test)]
mod upstream_golden_vector {
    use super::*;

    /// Our exact `D` and erigon's saturating `u64` agree everywhere a message
    /// can exist.
    ///
    /// erigon-pulse computes the full 192-bit product and returns
    /// `math.MaxUint64` only when the quotient would not fit a `u64`
    /// (`msgboard/pow_message.go:132-154`, `pulse-v3.4.4`). We compute the same
    /// quotient in `U256` and never saturate, so the two can only differ in that
    /// one regime.
    ///
    /// They differ harmlessly there. Saturating **raises** the threshold rather
    /// than lowering it — `MaxUint64` is the largest `D` expressible, so
    /// erigon's target becomes `2^256 / 2^64 = 2^192` while ours is smaller
    /// still. Clearing either needs about 2^64 scalar multiplications, so no
    /// message reaches the disagreement, and the direction is the safe one:
    /// wherever the two differ, erigon is the more permissive and we reject a
    /// superset of what it rejects.
    ///
    /// This is worth pinning because the same expression in plain `u64` used to
    /// **wrap**, which made `D` small and the work free (§14.1). Saturation is
    /// the opposite failure and is not exploitable — but the two are one
    /// careless edit apart.
    #[test]
    fn saturating_and_exact_difficulty_agree_wherever_a_message_can_exist() {
        /// erigon's `difficulty`, transcribed.
        fn erigon_difficulty(size: u64, multiplier: u64, divisor: u64) -> u64 {
            let base = (1u128 << 24) + u128::from(size) * 10_000;
            let product = base * u128::from(multiplier);
            let quotient = product / u128::from(divisor);
            u64::try_from(quotient).unwrap_or(u64::MAX)
        }

        let mut msg = PoWMsg {
            version: VERSION_V1,
            block_hash: B256::repeat_byte(1),
            nonce: 1,
            work_multiplier: 1,
            work_divisor: 1,
            category: B256::repeat_byte(2),
            data: Bytes::from_static(b"x"),
        };

        // Ordinary parameters: identical, no saturation anywhere.
        for (m, d) in [(1u64, 1u64), (10_000, 1_000_000), (1, 1_000), (u32::MAX as u64, 7)] {
            msg.work_multiplier = m;
            msg.work_divisor = d;
            let exact = msg.difficulty().expect("nonzero divisor");
            let erigon = erigon_difficulty(msg.size(), m, d);
            assert_eq!(exact, U256::from(erigon), "M={m} Div={d} must agree exactly");
        }

        // The saturating regime. erigon clamps to MaxUint64; we do not.
        msg.work_multiplier = 1 << 60;
        msg.work_divisor = 1;
        let exact = msg.difficulty().expect("nonzero divisor");
        assert_eq!(erigon_difficulty(msg.size(), 1 << 60, 1), u64::MAX, "erigon saturates here");
        assert!(exact > U256::from(u64::MAX), "we keep the exact value");

        // And the divergence is unreachable: erigon's own target in that regime
        // is 2^256 / 2^64, which needs about 2^64 attempts to clear. Ours is
        // tighter still, so we reject a superset — never the other way round.
        let erigon_target = (U512::from(1u8) << 256) / u512_from_u256(U256::from(u64::MAX));
        assert!(
            msg.target().expect("nonzero D") < erigon_target,
            "wherever the two differ, we must be the stricter one",
        );
        assert!(
            erigon_target < (U512::from(1u8) << 193),
            "and erigon's own threshold there is already out of reach",
        );
    }

    /// The upstream golden vector, `TestPoWGoldenVector` in erigon-pulse at
    /// `pulse-v3.4.4` (`msgboard/pow_message_test.go:256`).
    ///
    /// This is the artefact `specs/04-msgboard-pow-v2.md` cites under
    /// *Reference Implementations*. Earlier rounds recorded it as missing —
    /// it is absent at `v3.0.0-RC8`, which is the tree those rounds read, and
    /// present at `pulse-v3.4.4`. Ours was generated independently; this
    /// asserts the two agree, which is what makes us interoperable rather than
    /// merely self-consistent.
    #[test]
    fn we_reproduce_the_upstream_golden_vector() {
        let msg = PoWMsg {
            version: 1,
            block_hash: B256::from(hex_literal::hex!(
                "2222222222222222222222222222222222222222222222222222222222222222"
            )),
            nonce: 44,
            work_multiplier: 1,
            work_divisor: 1_000_000,
            category: B256::from(hex_literal::hex!(
                "1111111111111111111111111111111111111111111111111111111111111111"
            )),
            data: Bytes::from_static(b"golden"),
        };

        assert_eq!(
            msg.payload_hash(),
            B256::from(hex_literal::hex!(
                "2e0ef2bdf57f87bed3bba450118d7e9353af23a432d4d266e188a1ba97984166"
            )),
        );
        assert_eq!(
            msg.scalar_hash(),
            B256::from(hex_literal::hex!(
                "80a78c97a0c6fb125f111743e7b741008fa75e13dc1bb7c2b9112f2a41996f0d"
            )),
        );
        assert_eq!(
            msg.challenge().expect("scalar in range"),
            hex_literal::hex!("03f7fa35a9e98a3dcfa07049278de28c35fb688a9e95c8a83e0c391d441f67200e"),
        );
        assert_eq!(
            msg.calculate_hash().expect("scalar in range"),
            B256::from(hex_literal::hex!(
                "05af3628ff0ca1b329d012d76b57fc5976ef8ef8df6c3f6e8c6cd4df1e30a922"
            )),
        );
        assert_eq!(msg.difficulty(), Some(U256::from(16u64)));
        assert_eq!(
            msg.target(),
            Some(
                U512::from_str_radix(
                    "1000000000000000000000000000000000000000000000000000000000000000",
                    16
                )
                .unwrap()
            ),
        );

        let checked = msg.clone().to_checked(0, 0).expect("upstream vector must verify");
        assert_eq!(checked.hash, msg.calculate_hash().unwrap());
    }
}
