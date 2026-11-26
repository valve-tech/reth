//! Serving `GetByteCodes` (`0x04`).
//!
//! Code is addressed by hash, so the request carries no state root and any state that holds the
//! code can serve it. This module reads the latest state, which includes canonical blocks still
//! in memory.
//!
//! The limits and edge cases follow go-ethereum's `ServiceGetByteCodesQuery`, which is what
//! `PulseChain` clients expect from a `snap/1` peer:
//!
//! - The response budget is the requested byte count, capped at [`SOFT_RESPONSE_LIMIT`].
//! - At most [`MAX_BYTE_CODES_SERVE`] hashes are looked up.
//! - The empty code hash is answered with empty code, without a lookup.
//! - Unknown hashes are skipped, so the response can be shorter than the request.
//! - Serving stops after the code that takes the total past the budget.

use alloy_primitives::{Bytes, KECCAK256_EMPTY};
use reth_eth_wire_types::snap::{ByteCodesMessage, GetByteCodesMessage};
use reth_storage_api::{errors::provider::ProviderResult, BytecodeReader, StateProviderFactory};

/// The most data one response carries before it stops: 2 MiB, as in go-ethereum.
pub const SOFT_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;

/// The most code hashes one request looks up, as in go-ethereum.
pub const MAX_BYTE_CODES_SERVE: usize = 1024;

/// Answers a `GetByteCodes` request from the latest state of `factory`.
pub fn serve_byte_codes<F: StateProviderFactory>(
    factory: &F,
    request: &GetByteCodesMessage,
) -> ProviderResult<ByteCodesMessage> {
    let budget =
        usize::try_from(request.response_bytes).unwrap_or(usize::MAX).min(SOFT_RESPONSE_LIMIT);
    let state = factory.latest()?;

    let mut codes = Vec::new();
    let mut total = 0usize;
    for hash in request.hashes.iter().take(MAX_BYTE_CODES_SERVE) {
        let code = if *hash == KECCAK256_EMPTY {
            Bytes::new()
        } else {
            match state.bytecode_by_hash(hash)? {
                Some(bytecode) => bytecode.original_bytes(),
                None => continue,
            }
        };
        total += code.len();
        codes.push(code);
        if total > budget {
            break
        }
    }

    Ok(ByteCodesMessage { request_id: request.request_id, codes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, Address, B256};
    use proptest::prelude::*;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};

    /// Returns a provider holding one contract per entry of `codes`, and the code hashes.
    fn provider_with(codes: &[Vec<u8>]) -> (MockEthProvider, Vec<B256>) {
        let provider = MockEthProvider::default();
        let mut hashes = Vec::new();
        for (i, code) in codes.iter().enumerate() {
            let address = Address::with_last_byte(i as u8 + 1);
            provider.add_account(
                address,
                ExtendedAccount::new(0, Default::default()).with_bytecode(code.clone().into()),
            );
            hashes.push(keccak256(code));
        }
        (provider, hashes)
    }

    fn request(hashes: Vec<B256>, response_bytes: u64) -> GetByteCodesMessage {
        GetByteCodesMessage { request_id: 9, hashes, response_bytes }
    }

    #[test]
    fn serves_known_codes_in_request_order_and_skips_unknown_ones() {
        let (provider, hashes) = provider_with(&[vec![0x60, 0x01], vec![0x60, 0x02, 0x00]]);
        let unknown = B256::repeat_byte(0xee);
        let response =
            serve_byte_codes(&provider, &request(vec![hashes[1], unknown, hashes[0]], 4 << 20))
                .unwrap();
        assert_eq!(response.request_id, 9);
        assert_eq!(
            response.codes,
            vec![Bytes::from_static(&[0x60, 0x02, 0x00]), Bytes::from_static(&[0x60, 0x01])]
        );
    }

    #[test]
    fn answers_the_empty_code_hash_with_empty_code() {
        let (provider, hashes) = provider_with(&[vec![0x60, 0x01]]);
        let response =
            serve_byte_codes(&provider, &request(vec![KECCAK256_EMPTY, hashes[0]], 1024)).unwrap();
        assert_eq!(response.codes, vec![Bytes::new(), Bytes::from_static(&[0x60, 0x01])]);
    }

    #[test]
    fn stops_after_the_code_that_crosses_the_budget() {
        let (provider, hashes) =
            provider_with(&[vec![0x01; 600], vec![0x02; 600], vec![0x03; 600]]);
        // 600 bytes fit a 1000-byte budget; the second code crosses it and is the last one.
        let response = serve_byte_codes(&provider, &request(hashes, 1000)).unwrap();
        assert_eq!(response.codes.len(), 2);
        assert_eq!(response.codes[1], Bytes::from(vec![0x02; 600]));
    }

    #[test]
    fn caps_the_budget_at_the_soft_response_limit() {
        // reth-lite asks for 4 MiB; a server stops at 2 MiB like go-ethereum.
        let mib = 1024 * 1024;
        let (provider, hashes) = provider_with(&[
            vec![0x01; 3 * mib / 2],
            vec![0x02; 3 * mib / 2],
            vec![0x03; 3 * mib / 2],
        ]);
        let response = serve_byte_codes(&provider, &request(hashes, 4 << 20)).unwrap();
        assert_eq!(response.codes.len(), 2);
    }

    /// A request hash: a known code by index, the empty code hash, or an unknown hash.
    #[derive(Debug, Clone, Copy)]
    enum Asked {
        Known(usize),
        Empty,
        Unknown,
    }

    /// Every response is the first codes of the request, in order, up to and including the one
    /// that crosses the budget, from at most the first 1024 hashes; each code hashes to the hash
    /// it answers.
    #[test]
    fn serves_the_budgeted_prefix_of_known_codes() {
        // One provider for all cases: building a mock provider takes about 0.2 s. The codes are
        // legacy code of distinct lengths, so none parses as EOF or a delegation.
        let codes: Vec<Vec<u8>> = [1usize, 2, 7, 33, 120, 299]
            .iter()
            .enumerate()
            .map(|(i, len)| [vec![0x60, i as u8], vec![0x5b; *len]].concat())
            .collect();
        let (provider, known) = provider_with(&codes);
        let asked = proptest::collection::vec(
            prop_oneof![
                6 => (0..codes.len()).prop_map(Asked::Known),
                3 => Just(Asked::Empty),
                1 => Just(Asked::Unknown),
            ],
            0..1100,
        );
        // A budget from the range, or one that the codes of the first `k` known hashes fill
        // exactly, so the boundary where the total equals the budget comes up.
        let budget =
            prop_oneof![(0u64..3000).prop_map(Ok), (0usize..40).prop_map(Err), Just(Ok(u64::MAX)),];
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(64));
        runner
            .run(&(asked, budget), |(asked, budget)| {
                let code_len = |a: &Asked| match *a {
                    Asked::Known(i) => Some(codes[i].len() as u64),
                    Asked::Empty => Some(0),
                    Asked::Unknown => None,
                };
                let budget = budget.unwrap_or_else(|k| {
                    asked.iter().take(MAX_BYTE_CODES_SERVE).filter_map(code_len).take(k).sum()
                });
                let hashes: Vec<B256> = asked
                    .iter()
                    .map(|a| match *a {
                        Asked::Known(i) => known[i],
                        Asked::Empty => KECCAK256_EMPTY,
                        Asked::Unknown => B256::repeat_byte(0xee),
                    })
                    .collect();

                let mut expected = Vec::new();
                let mut total = 0u64;
                for a in asked.iter().take(MAX_BYTE_CODES_SERVE) {
                    let code = match *a {
                        Asked::Known(i) => Bytes::from(codes[i].clone()),
                        Asked::Empty => Bytes::new(),
                        Asked::Unknown => continue,
                    };
                    total += code.len() as u64;
                    expected.push(code);
                    if total > budget.min(SOFT_RESPONSE_LIMIT as u64) {
                        break
                    }
                }

                let response = serve_byte_codes(&provider, &request(hashes.clone(), budget))?;
                prop_assert!(response.codes.len() <= MAX_BYTE_CODES_SERVE);
                let mut rest = hashes.iter();
                for code in &response.codes {
                    let hash = keccak256(code);
                    prop_assert!(rest.any(|h| *h == hash), "code out of request order");
                }
                prop_assert_eq!(response.codes, expected);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn looks_up_at_most_the_hash_cap() {
        let (provider, _) = provider_with(&[]);
        let hashes = vec![KECCAK256_EMPTY; MAX_BYTE_CODES_SERVE + 10];
        let response = serve_byte_codes(&provider, &request(hashes, 4 << 20)).unwrap();
        assert_eq!(response.codes.len(), MAX_BYTE_CODES_SERVE);
    }
}
