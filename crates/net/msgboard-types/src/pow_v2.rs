//! The `version = 2` `PoW` construction.
//!
//! Implemented from `specs/04-msgboard-pow-v2.md`. Every step differs from
//! [`pow`](crate::pow), so the two share only the [`PoWMsg`] fields:
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
//! # Why this replaces v1
//!
//! v1's scalar is `nonce × digest + blockHash`, which is **linear in the
//! nonce**: `scalar(n+1) = scalar(n) + digest`, so `G×scalar(n+1) =
//! G×scalar(n) + G×digest` where `G×digest` is constant for a given
//! multiplier/divisor pair. A miner walks nonces with one point addition
//! (~1 µs) where a verifier pays a full scalar multiplication (~60–120 µs), so
//! the work costs 50–500× less than the difficulty parameter implies.
//!
//! Worse, v1's challenge never commits to `category` or `data` — they enter
//! only at the final hash — so one precomputed challenge table mines unlimited
//! distinct messages in the same block. For K messages the elliptic-curve cost
//! is O(N), not O(K·N).
//!
//! Here the scalar is a SHA-256 digest, which is not additively homomorphic, so
//! consecutive nonces give unrelated scalars and every attempt needs its own
//! scalar multiplication. Because the digest commits to `payloadHash`, each
//! message body gets its own sequence and the table-reuse amplification dies
//! with it.
//!
//! # Two v1 divergences this retires
//!
//! v1 computed `D` in wrapping `u64`, which let an attacker solve
//! `base × M ≡ 2ᵏ (mod 2⁶⁴)`, set `Div = 2ᵏ`, and wrap the threshold to 1 —
//! free `PoW` for any nonce. Here `D` is arbitrary precision and a larger `D`
//! makes the work *harder*, so there is nothing to wrap. That also makes the
//! minimum-work gate sound for the first time: `D` is monotone in `M/Div`, so
//! clearing the gate and paying nothing are no longer compatible.

use alloy_primitives::{B256, U256, U512};
use sha2::{Digest, Sha256};

use crate::{pow::SECP256K1_ORDER, MsgboardError, PoWMsg};

/// Encoding version 2 — the construction in this module.
pub const VERSION_V2: u8 = 2;

impl PoWMsg {
    /// `sha256(category ‖ data)`, binding the message body into the scalar.
    pub fn payload_hash_v2(&self) -> B256 {
        let mut h = Sha256::new();
        h.update(self.category.as_slice());
        h.update(&self.data);
        B256::from_slice(&h.finalize())
    }

    /// `sha256(version ‖ blockHash ‖ payloadHash ‖ M ‖ Div ‖ nonce)`.
    ///
    /// Integers are big-endian at fixed width: one byte for `version`, eight
    /// each for `work_multiplier`, `work_divisor` and `nonce`.
    pub fn scalar_hash_v2(&self) -> B256 {
        let mut h = Sha256::new();
        h.update([self.version]);
        h.update(self.block_hash.as_slice());
        h.update(self.payload_hash_v2().as_slice());
        h.update(self.work_multiplier.to_be_bytes());
        h.update(self.work_divisor.to_be_bytes());
        h.update(self.nonce.to_be_bytes());
        B256::from_slice(&h.finalize())
    }

    /// The compressed `G × scalar`, or `None` when the scalar is out of range.
    ///
    /// The scalar is the digest read big-endian, **refused** rather than
    /// reduced when it falls outside `[1, n)` — the spec is explicit that this
    /// must match Go's `ScalarBaseMult`, which rejects an out-of-range scalar
    /// instead of wrapping it. A caller mining a message treats `None` as
    /// "try the next nonce"; a verifier treats it as an invalid message.
    ///
    /// SHA-256 output lands outside `[1, n)` with probability about 2⁻¹²⁸, so
    /// this is a conformance rule rather than a reachable branch.
    pub fn challenge_v2(&self) -> Option<[u8; 33]> {
        let digest = self.scalar_hash_v2();
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
    pub fn work_hash_v2(&self) -> Option<B256> {
        let compressed = self.challenge_v2()?;
        Some(B256::from_slice(&Sha256::digest(compressed)))
    }

    /// `D = (2^24 + 10_000·len(data)) · M / Div`, exact.
    ///
    /// `None` only when `work_divisor` is zero. Unlike v1 this cannot overflow:
    /// the base is under 2²⁵ for any message the size limit admits and `M` is a
    /// `u64`, so the product stays far inside 256 bits.
    pub fn difficulty_v2(&self) -> Option<U256> {
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
    pub fn target_v2(&self) -> Option<U512> {
        let d = self.difficulty_v2()?;
        if d.is_zero() {
            return None;
        }
        let two_256 = U512::from(1u8) << 256;
        Some(two_256 / u512_from_u256(d))
    }

    /// Verify the v2 `PoW`, returning the work hash on success.
    pub fn verify_v2(&self) -> Result<B256, MsgboardError> {
        let Some(target) = self.target_v2() else {
            return Err(MsgboardError::InvalidDifficulty);
        };
        let Some(hash) = self.work_hash_v2() else {
            return Err(MsgboardError::InvalidWork);
        };
        if u512_from_u256(U256::from_be_slice(hash.as_slice())) >= target {
            return Err(MsgboardError::InvalidWork);
        }
        Ok(hash)
    }
}

/// Widen a `U256` without going through a string or a fallible conversion.
fn u512_from_u256(value: U256) -> U512 {
    let mut buf = [0u8; 64];
    buf[32..].copy_from_slice(&value.to_be_bytes::<32>());
    U512::from_be_slice(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    /// The message both golden vectors are built from.
    fn vector_msg(nonce: u64, work_multiplier: u64, work_divisor: u64) -> PoWMsg {
        PoWMsg {
            version: 1,
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
    /// that only checks the final verdict can pass by luck; five intermediates
    /// cannot. Generated from `specs/04-msgboard-pow-v2.md` by an independent
    /// transcription, so agreement between it and this code is agreement
    /// between two readings of the spec rather than a tautology.
    #[test]
    fn golden_vector_a_pins_every_intermediate() {
        let msg = vector_msg(1, 10_000, 1_000_000);

        assert_eq!(
            msg.payload_hash_v2(),
            B256::from(hex_literal::hex!(
                "b66106e111b0e6cd08a49c7a37afa3259541bee8e465bef5e55f6cd7223d789a"
            )),
            "payloadHash = sha256(category ‖ data)",
        );
        assert_eq!(
            msg.scalar_hash_v2(),
            B256::from(hex_literal::hex!(
                "3caed3ea9a5caa6e1e069d0126e4dc6698190aa3eec8ebcdab227d3e5b0fd18d"
            )),
            "scalarHash field order or widths differ from the spec",
        );
        assert_eq!(
            msg.challenge_v2().expect("scalar in range"),
            hex_literal::hex!("035e55e474ae91c573e38855bba370f01d64a307fa9c834eda7b435ec9d24368b9"),
            "the point must be COMPRESSED — 33 bytes with a parity prefix",
        );
        assert_eq!(
            msg.work_hash_v2().expect("scalar in range"),
            B256::from(hex_literal::hex!(
                "5ba003ccdb08503a19326a201834198a49e062d2f3f0e9506ff086eddb011dee"
            )),
            "workHash = sha256(compressed point)",
        );
        assert_eq!(msg.difficulty_v2(), Some(U256::from(169_072u64)));

        // This vector is not mined, so it must NOT verify. That direction
        // matters: a check that only ever asserts success cannot tell a working
        // threshold from one that accepts everything.
        assert!(matches!(msg.verify_v2(), Err(MsgboardError::InvalidWork)));
    }

    /// Vector B — the same message mined against an easier target.
    #[test]
    fn golden_vector_b_verifies_when_mined() {
        let msg = vector_msg(57_602, 1, 1_000);

        assert_eq!(msg.difficulty_v2(), Some(U256::from(16_907u64)));
        assert_eq!(
            msg.scalar_hash_v2(),
            B256::from(hex_literal::hex!(
                "bcff3c0ddc5d02b05e282566461d4f30f35ce90b3bfd36cde0c694dcb54a5e7d"
            )),
        );
        assert_eq!(
            msg.challenge_v2().expect("scalar in range"),
            hex_literal::hex!("030fbdcb58e555146c54a0863ebf038a0384d4bd90439d02b8d8d5f71096ca7a09"),
        );

        let hash = msg.verify_v2().expect("vector B is mined and must verify");
        assert_eq!(
            hash,
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
                vector_msg(nonce, 1, 1_000).verify_v2().is_err(),
                "nonce {nonce} must not satisfy the target",
            );
        }
    }

    /// `D = 1` puts the target at exactly 2²⁵⁶, which is why it is carried as a
    /// `U512`. Truncating it to `U256::MAX` would reject the single hash equal
    /// to 2²⁵⁶−1.
    #[test]
    fn a_difficulty_of_one_admits_every_hash() {
        let mut msg = vector_msg(1, 1, 1 << 24);
        msg.data = Bytes::new();
        assert_eq!(msg.difficulty_v2(), Some(U256::from(1u8)));
        assert_eq!(msg.target_v2(), Some(U512::from(1u8) << 256));
        assert!(msg.verify_v2().is_ok(), "every hash is below 2^256");
    }

    /// A zero divisor and a zero `D` are both refused rather than dividing.
    #[test]
    fn a_zero_difficulty_is_refused_not_divided_by() {
        let mut zero_divisor = vector_msg(1, 1, 0);
        zero_divisor.work_divisor = 0;
        assert_eq!(zero_divisor.difficulty_v2(), None);
        assert!(matches!(zero_divisor.verify_v2(), Err(MsgboardError::InvalidDifficulty)));

        // M/Div small enough that the integer division floors to zero.
        let zero_d = vector_msg(1, 1, u64::MAX);
        assert_eq!(zero_d.difficulty_v2(), Some(U256::ZERO));
        assert!(matches!(zero_d.verify_v2(), Err(MsgboardError::InvalidDifficulty)));
    }
}
