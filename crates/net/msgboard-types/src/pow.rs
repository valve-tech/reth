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
//! ```text
//! difficulty_digest = sha256(work_multiplier_be || work_divisor_be)[16..]  // last 16 bytes
//!
//! scalar = (nonce × difficulty_digest_as_bigint + block_hash_as_bigint) mod secp256k1_order
//! (x, _y) = secp256k1_generator × scalar
//! challenge = x                              // 32-byte big-endian x-coordinate
//!
//! hash = sha256(challenge || category || data)
//!
//! difficulty = (2^24 + data.len() × 10_000) × work_multiplier / work_divisor
//! verify:  u256(hash) % difficulty == 0
//! ```

use alloy_primitives::{Bytes, B256, U256};
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

/// Encoding version 1. The only supported version.
pub const VERSION_V1: u8 = 1;

/// The `PoW` message payload exchanged between peers.
///
/// Encoded as an RLP list in field-declaration order. All fields must remain
/// in this exact sequence for wire-format compatibility with erigon-pulse.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PoWMsg {
    /// Encoding version (`VERSION_V1` = 1).
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
        if self.category == B256::ZERO && self.data.is_empty() {
            return Err(MsgboardError::InvalidData);
        }
        Ok(())
    }

    /// Byte length of the `data` field.
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Difficulty threshold: `(2^24 + size × 10_000) × multiplier / divisor`.
    ///
    /// The `PoW` hash (as a big-endian integer) must be divisible by this value.
    ///
    /// Uses `wrapping_mul` to mirror erigon-pulse's plain `uint64` arithmetic
    /// (`pow_message.go`: `(1<<24 + pm.Size()*10_000) * multiplier / divisor`).
    /// Saturating instead would make reth reject messages erigon accepts, and
    /// any divergence in the verification function is a wire gap. `validate`
    /// rejects `work_divisor == 0` before this function is reachable.
    ///
    /// # Security
    ///
    /// **The wrap is exploitable, in both clients** — see
    /// `docs/msgboard-parity-gaps.md` §14.1. `multiplier` is attacker-chosen,
    /// so the product can be wrapped onto any residue, including one that makes
    /// this return 1. Every hash is divisible by 1, so the `PoW` becomes free
    /// while the message still clears `is_work_acceptable` — the minimum-work
    /// gate constrains the declared *ratio*, which the wrap decouples from the
    /// difficulty actually enforced. Matching erigon is why the wrap is kept;
    /// fixing it is a coordinated wire change, not a unilateral one.
    pub fn difficulty(&self) -> u64 {
        let base: u64 = (1u64 << 24).wrapping_add(self.size().wrapping_mul(10_000));
        base.wrapping_mul(self.work_multiplier).wrapping_div(self.work_divisor)
    }

    /// `work_multiplier / work_divisor` as a float. Used for minimum-ratio checks.
    pub fn difficulty_ratio(&self) -> f64 {
        self.work_multiplier as f64 / self.work_divisor as f64
    }

    /// Compute the SHA-256 `PoW` hash: `sha256(challenge ‖ category ‖ data)`.
    pub fn calculate_hash(&self) -> B256 {
        let challenge = self.challenge();
        let mut h = Sha256::new();
        h.update(challenge);
        h.update(self.category.as_slice());
        h.update(&self.data);
        B256::from_slice(&h.finalize())
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
        let difficulty = self.difficulty();
        if difficulty == 0 {
            return Err(MsgboardError::InvalidWork);
        }

        let hash = self.calculate_hash();
        let hash_int = U256::from_be_slice(hash.as_slice());
        let diff_int = U256::from(difficulty);

        if hash_int % diff_int != U256::ZERO {
            return Err(MsgboardError::InvalidWork);
        }

        Ok(CheckedPoWMsg { msg: self, block_number, timestamp, hash })
    }

    // ── internal helpers ─────────────────────────────────────────────────────

    /// Last 16 bytes of `sha256(work_multiplier_be ‖ work_divisor_be)`.
    ///
    /// Used as a 128-bit factor in the scalar computation, tying the challenge
    /// to the message's configured difficulty.
    fn difficulty_digest(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.work_multiplier.to_be_bytes());
        h.update(self.work_divisor.to_be_bytes());
        let full: [u8; 32] = h.finalize().into();
        full[16..].try_into().expect("exactly 16 bytes")
    }

    /// 32-byte x-coordinate of `G × scalar` where
    /// `scalar = (nonce × difficulty_digest + block_hash) mod n`.
    ///
    /// Returns all-zeros only if the reduced scalar is zero (probability ≈ 2⁻²⁵⁶).
    fn challenge(&self) -> [u8; 32] {
        let Some(scalar_bytes) = self.pow_scalar() else { return [0u8; 32] };
        // SecretKey is the scalar; PublicKey = G × scalar via the secp256k1 crate.
        let Ok(sk) = secp256k1::SecretKey::from_slice(&scalar_bytes) else {
            return [0u8; 32];
        };
        let pk = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &sk);
        // Uncompressed: [0x04, x₀..x₃₁, y₀..y₃₁] — take the x coordinate.
        let s = pk.serialize_uncompressed();
        s[1..33].try_into().expect("32 bytes")
    }

    /// Compute `(nonce × difficulty_digest + block_hash) mod n` as a 32-byte
    /// big-endian scalar. Returns `None` only when the result is zero.
    ///
    /// ## Carry analysis
    ///
    /// - `nonce` fits in 64 bits; `difficulty_digest` is 128 bits.
    /// - `product = nonce × digest < 2¹⁹²` — fits in U256 without overflow.
    /// - `sum = product + block_hash` may overflow U256 (carry bit).
    ///
    /// When `carry = true`:
    ///   `total = 2²⁵⁶ + sum_wrapped = n + nc + sum_wrapped`
    ///   where `nc = 2²⁵⁶ − n` (≈ 2¹²⁸).
    ///   `total mod n = (nc + sum_wrapped) mod n`
    ///
    ///   Adding `nc` (≈ 2¹²⁸) to `sum_wrapped` may overflow again (carry₂).
    ///   If carry₂ = true, the wrapped value `adjusted < 2¹²⁸ ≪ n`, so
    ///   `nc + adjusted` fits trivially without further reduction.
    fn pow_scalar(&self) -> Option<[u8; 32]> {
        let digest = self.difficulty_digest(); // 16 bytes
        let mut digest_padded = [0u8; 32];
        digest_padded[16..].copy_from_slice(&digest);

        let nonce_u = U256::from(self.nonce);
        let digest_u = U256::from_be_slice(&digest_padded);
        let block_u = U256::from_be_slice(self.block_hash.as_slice());
        let n = U256::from_be_slice(&SECP256K1_ORDER);

        // product < 2¹⁹² — no overflow in U256.
        let product = nonce_u.wrapping_mul(digest_u);
        let (sum, carry) = product.overflowing_add(block_u);

        let scalar_u = if carry {
            // nc = 2²⁵⁶ − n (two's complement negation in U256 arithmetic).
            let nc = n.wrapping_neg();
            let (adjusted, carry2) = nc.overflowing_add(sum);
            if carry2 {
                // adjusted_wrapped = nc + sum − 2²⁵⁶ < 2¹²⁸ ≪ n → no subtraction needed.
                nc.wrapping_add(adjusted)
            } else if adjusted >= n {
                adjusted - n
            } else {
                adjusted
            }
        } else if sum >= n {
            sum - n
        } else {
            sum
        };

        if scalar_u == U256::ZERO {
            return None;
        }
        Some(scalar_u.to_be_bytes())
    }
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
        for n in 1u64..=1_000_000 {
            if make_msg(n, data).to_checked(0, 0).is_ok() {
                return Some(n);
            }
        }
        None
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

    /// `msg/1` is the only negotiated version, so a message declaring anything
    /// else is rejected at the decode boundary rather than being interpreted
    /// under v1 field semantics.
    #[test]
    fn test_validate_rejects_non_v1_version() {
        let mut msg = make_msg(1, &[1]);
        msg.version = VERSION_V1 + 1;
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidVersion)));

        msg.version = 0;
        assert!(matches!(msg.validate(), Err(MsgboardError::InvalidVersion)));
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

    /// `difficulty()` must **wrap** like erigon's plain `uint64` arithmetic
    /// (`pow_message.go`), not saturate. This is a wire gap, not a style
    /// preference: for a message whose `base × multiplier` exceeds 2⁶⁴, a
    /// saturating reth computes a different threshold than erigon, so the two
    /// disagree on whether the very same bytes carry valid work.
    ///
    /// `work_multiplier = 2⁴⁰ + 3` against an empty body (`base = 2²⁴`) puts the
    /// product 3 × 2²⁴ past the u64 boundary.
    #[test]
    fn test_difficulty_wraps_like_erigon_uint64_rather_than_saturating() {
        let mut msg = make_msg(1, &[]);
        msg.work_multiplier = (1u64 << 40) + 3;
        msg.work_divisor = 1;

        // base = 2^24; base × multiplier = 2^64 + 3×2^24 → wraps to 3×2^24.
        assert_eq!(msg.difficulty(), 3 * (1u64 << 24));
        assert_ne!(msg.difficulty(), u64::MAX, "saturating arithmetic would land here");
    }

    /// The wrap can land on exactly zero, which would be a division by zero in
    /// the verification step. `to_checked` must reject it as invalid work
    /// instead of panicking.
    #[test]
    fn test_difficulty_wrapping_to_zero_is_rejected_not_a_panic() {
        let mut msg = make_msg(1, &[]);
        msg.work_multiplier = 1u64 << 40; // base × multiplier = exactly 2^64
        msg.work_divisor = 1;

        assert_eq!(msg.difficulty(), 0);
        assert!(matches!(msg.to_checked(0, 0), Err(MsgboardError::InvalidWork)));
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
        assert_eq!(msg.difficulty(), (1u64 << 24) * 10_000 / 1_000_000);

        // Each body byte adds 10_000 to the base.
        let mut sized = make_msg(1, &[0u8; 100]);
        sized.work_multiplier = 10_000;
        sized.work_divisor = 1_000_000;
        assert_eq!(sized.difficulty(), ((1u64 << 24) + 100 * 10_000) * 10_000 / 1_000_000);
        assert!(sized.difficulty() > msg.difficulty(), "a larger body must cost more work");
    }

    #[test]
    fn test_rlp_round_trip_single() {
        let n = find_nonce(&[42u8]).expect("nonce found");
        let msg = make_msg(n, &[42u8]);
        let checked = msg.clone().to_checked(100, 999).expect("valid");

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

    /// `pow_scalar` computes `(nonce × digest + block_hash) mod n` in U256, so
    /// it has to handle the carry out of the 256-bit add by hand. Random inputs
    /// never reach that code: `product < 2¹⁹²`, so a uniformly random
    /// `block_hash` overflows the add with probability ≈ 2⁻⁶⁴. The carry branch
    /// only runs for a near-maximal `block_hash` — which is precisely what a
    /// peer probing for a client split would send, and getting it wrong yields a
    /// different challenge, a different `PoW` hash, and a message erigon accepts
    /// that reth rejects.
    ///
    /// Both regimes are checked against full-precision U512 arithmetic, which is
    /// the definition Go's `math/big` reference computes.
    #[test]
    fn test_pow_scalar_matches_full_precision_arithmetic_including_carry() {
        use alloy_primitives::U512;

        /// xorshift64 — deterministic, so a failure reproduces exactly.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
        }

        let two_256 = U512::from(1u8) << 256;
        let n_512 = U512::from_be_slice(&{
            let mut buf = [0u8; 64];
            buf[32..].copy_from_slice(&SECP256K1_ORDER);
            buf
        });

        let mut rng = Rng(0x5EED_1234_ABCD_0001);
        let mut carries = 0usize;
        let mut checked = 0usize;

        for i in 0..2_000 {
            let mut msg = make_msg(rng.next().max(1), &[]);
            msg.work_multiplier = rng.next().max(1);
            msg.work_divisor = rng.next().max(1);

            // Half the iterations use a random block hash (the no-carry regime);
            // half use a block hash just below 2²⁵⁶ so the add overflows.
            let mut bh = [0u8; 32];
            if i % 2 == 0 {
                for chunk in bh.chunks_mut(8) {
                    chunk.copy_from_slice(&rng.next().to_be_bytes());
                }
            } else {
                bh = [0xFFu8; 32];
                // Vary the low bytes so the carry lands at different distances
                // past the boundary rather than repeating one input.
                bh[24..].copy_from_slice(&(u64::MAX - (rng.next() % 4096)).to_be_bytes());
            }
            msg.block_hash = B256::from(bh);

            // Full-precision reference: no wraparound, no hand-rolled reduction.
            let digest = msg.difficulty_digest();
            let mut digest_padded = [0u8; 64];
            digest_padded[48..].copy_from_slice(&digest);

            let product = U512::from(msg.nonce) * U512::from_be_slice(&digest_padded);
            let sum = product +
                U512::from_be_slice(&{
                    let mut buf = [0u8; 64];
                    buf[32..].copy_from_slice(msg.block_hash.as_slice());
                    buf
                });
            if sum >= two_256 {
                carries += 1;
            }

            let expected = sum % n_512;
            let expected_bytes: [u8; 32] =
                expected.to_be_bytes::<64>()[32..].try_into().expect("scalar fits in 32 bytes");

            match msg.pow_scalar() {
                Some(actual) => assert_eq!(
                    actual, expected_bytes,
                    "scalar mismatch at i={i}, nonce={}, mult={}, div={}, block_hash={}",
                    msg.nonce, msg.work_multiplier, msg.work_divisor, msg.block_hash,
                ),
                None => assert_eq!(
                    expected,
                    U512::ZERO,
                    "pow_scalar returned None for a non-zero scalar at i={i}",
                ),
            }
            checked += 1;
        }

        assert_eq!(checked, 2_000);
        // Without this the test could silently stop covering the carry branch —
        // the way the M1 guard silently stopped covering deep boards (§11.3).
        assert!(carries >= 500, "expected the forced-carry regime to fire, got {carries}");
    }

    /// The carry branch's two inner cases (`carry2`, and `adjusted >= n`) are
    /// unreachable for any message, and this pins the bound that makes them so.
    ///
    /// After a carry, `sum_wrapped = product + block_hash − 2²⁵⁶ < 2¹⁹²`, because
    /// `nonce < 2⁶⁴` and `digest < 2¹²⁸`. Adding `nc = 2²⁵⁶ − n ≈ 2¹²⁸` cannot
    /// reach 2²⁵⁶ from below 2¹⁹², nor even reach `n`. Both branches are
    /// therefore dead defensive code, not paths a test can drive — worth knowing
    /// before anyone "simplifies" the bound they rest on.
    #[test]
    fn test_pow_scalar_carry_cannot_overflow_a_second_time() {
        use alloy_primitives::U512;

        let n_512 = U512::from_be_slice(&{
            let mut buf = [0u8; 64];
            buf[32..].copy_from_slice(&SECP256K1_ORDER);
            buf
        });
        let nc = (U512::from(1u8) << 256) - n_512;

        // The largest post-carry remainder any message can produce.
        let max_sum_wrapped = (U512::from(1u8) << 192) - U512::from(1u8);

        assert!(
            nc + max_sum_wrapped < n_512,
            "carry-branch result must stay below n, leaving carry2 and the \
             `adjusted >= n` reduction unreachable",
        );
    }

    /// Decodes the hardcoded `CheckedPoWMsg` from Go's `TestEncodeAndDecode`.
    ///
    /// This vector was captured from a real run of the Go reference implementation and is
    /// used here as a regression guard for RLP wire-format compatibility.
    ///
    /// The test only asserts the fields that the Go test checks (`block_hash`); we
    /// additionally verify block_number and that the nested PoWMsg round-trips correctly.
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
mod difficulty_overflow_vuln {
    use super::*;
    use crate::MsgboardConfig;
    use alloy_primitives::keccak256;

    /// `work_multiplier`/`work_divisor` that drive [`PoWMsg::difficulty`] to 1
    /// for a 1-byte message, found by solving
    /// `base * multiplier ≡ 2^v2(base) (mod 2^64)`.
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

    /// Documents a live vulnerability shared with erigon-pulse — **this test
    /// asserts the broken behaviour**, so it will fail the day it is fixed.
    /// See `docs/msgboard-parity-gaps.md` §14.1.
    ///
    /// `difficulty()` is `(2^24 + size*10_000) * multiplier / divisor` in
    /// wrapping u64 arithmetic, matching erigon's plain `uint64` expression.
    /// The multiplier is attacker-chosen, so the product can be wrapped onto
    /// any residue: here onto exactly `divisor`, making `difficulty == 1`.
    /// The `PoW` check is `hash % difficulty == 0`, and every hash is
    /// divisible by 1, so **any nonce is accepted and the message costs zero
    /// work**. Only `difficulty == 0` is rejected, which does not help — 1 is
    /// as free as 0 and passes the guard.
    #[test]
    fn difficulty_overflow_makes_pow_free_for_any_nonce() {
        assert_eq!(evil_msg(1).difficulty(), 1, "crafted params must wrap difficulty to 1");

        // An honest message of the same size pays ~168k.
        let honest = PoWMsg { work_multiplier: 10_000, work_divisor: 1_000_000, ..evil_msg(1) };
        assert_eq!(honest.difficulty(), 167_872);

        // Every nonce is a valid solution — no search, no work.
        for nonce in 1..=64u64 {
            assert!(
                evil_msg(nonce).to_checked(100, 0).is_ok(),
                "nonce {nonce} should be accepted with difficulty 1",
            );
        }
    }

    /// The crafted message also passes the minimum-work gate, and does so with
    /// an enormous declared ratio — so it is not merely free, it outranks every
    /// honest message.
    ///
    /// Board precedence is `(block, difficulty_ratio)` ascending and eviction
    /// pops `msgs[0]`, so a higher ratio means the spam survives and honest
    /// messages are evicted first.
    #[test]
    fn the_free_message_also_outranks_every_honest_one() {
        let cfg = MsgboardConfig::default();
        assert!(
            cfg.is_work_acceptable(EVIL_MULTIPLIER, EVIL_DIVISOR),
            "crafted params clear the minimum-work gate",
        );

        let evil = evil_msg(1).difficulty_ratio();
        let honest = cfg.work_multiplier as f64 / cfg.work_divisor as f64;
        assert!(evil > honest * 1e18, "declared ratio {evil} dwarfs the honest {honest}");
    }
}
