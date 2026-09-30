//! What `firehose-tracer` keeps of a call's KECCAK256 preimages, input and return data. The
//! tracer owns these rules; these tests pin them end to end through the reth inspector, so a
//! tracer bump that changes FIRE output for downstream consumers fails here first.

use super::support::*;
use crate::inspector::*;
use reth_revm::revm::primitives::hardfork::SpecId;

const CONTRACT: Address = Address::repeat_byte(0xa1);

/// The `identity` precompile: it returns its input, so one call moves the same number of bytes
/// as input and as return data.
const IDENTITY_PRECOMPILE: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);

/// `MSTORE(0, word)` then `KECCAK256(0, 32)`, leaving the hash on the stack.
fn op_keccak_word(word: B256) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(push(word.as_slice()));
    code.extend(push(&[0]));
    code.push(0x52); // MSTORE
    code.extend(push(&[32]));
    code.extend(push(&[0]));
    code.push(0x20); // KECCAK256
    code
}

/// A preimage whose hash is a written storage slot explains that slot and is kept. A preimage
/// whose hash is never used as a slot is dropped (firehose-tracer 5.5.0 keccak preimage filter).
#[test]
fn keccak_preimage_is_kept_only_when_it_explains_a_written_slot() {
    let slot_word = B256::repeat_byte(0x01);
    let unused_word = B256::repeat_byte(0x02);

    let mut code = op_keccak_word(slot_word);
    code.extend(push(&[1]));
    code.push(0x90); // SWAP1: SSTORE(key = hash, value = 1)
    code.push(0x55); // SSTORE
    code.extend(op_keccak_word(unused_word));
    code.push(0x50); // POP

    let block = drive_tx(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT, code_account(&code, 0))],
        CONTRACT,
        0,
    );

    let call = &block.transaction_traces[0].calls[0];
    let slot_hash = alloy_primitives::hex::encode(alloy_primitives::keccak256(slot_word));
    let unused_hash = alloy_primitives::hex::encode(alloy_primitives::keccak256(unused_word));

    assert_eq!(
        call.keccak_preimages.get(&slot_hash),
        Some(&alloy_primitives::hex::encode(slot_word)),
        "the preimage of a written storage slot must be kept"
    );
    assert!(
        !call.keccak_preimages.contains_key(&unused_hash),
        "a preimage that explains no written slot must be dropped"
    );
}

/// Number of identity calls the root call makes, each passing 1 MiB of input and getting
/// 1 MiB back. 55 MiB goes past both per-transaction limits (50 MiB input, 25 MiB return data).
const IDENTITY_CALLS: usize = 55;
const MIB: usize = 1024 * 1024;

/// Past 50 MiB of internal call input, later calls keep only their 4-byte selector. Past 25 MiB
/// of return data, later calls keep none. The first internal call and the root call keep all of
/// theirs.
#[test]
fn call_input_and_return_data_are_truncated_past_the_per_tx_limits() {
    // Memory word 0 starts with the selector 0xdeadbeef; writing the last word grows memory to
    // 1 MiB once, so every CALL below passes the same 1 MiB without further expansion cost.
    let mut code = Vec::new();
    code.extend(push(&[0xde, 0xad, 0xbe, 0xef]));
    code.extend(push(&[0xe0]));
    code.push(0x1b); // SHL
    code.extend(push(&[0]));
    code.push(0x52); // MSTORE
    code.extend(push(&[1]));
    code.extend(push(&((MIB - 32) as u32).to_be_bytes()[1..]));
    code.push(0x52); // MSTORE
    for _ in 0..IDENTITY_CALLS {
        code.extend(push(&(MIB as u32).to_be_bytes()[1..])); // retLength
        code.extend(push(&[0])); // retOffset
        code.extend(push(&(MIB as u32).to_be_bytes()[1..])); // argsLength
        code.extend(push(&[0])); // argsOffset
        code.extend(push(&[0])); // value
        code.extend(push(IDENTITY_PRECOMPILE.as_slice()));
        code.push(0x5a); // GAS
        code.push(0xf1); // CALL
        code.push(0x50); // POP
    }

    let block = drive_txs(
        SpecId::PRAGUE,
        &[(SENDER, balance_account(1_000_000)), (CONTRACT, code_account(&code, 0))],
        &[DriveTx::call(CONTRACT, 0).with_gas(30_000_000)],
    );

    let calls = &block.transaction_traces[0].calls;
    assert_eq!(calls.len(), IDENTITY_CALLS + 1, "root call plus one call per identity CALL");
    assert!(calls.iter().skip(1).all(|call| !call.status_failed), "all calls succeed");

    let first = &calls[1];
    assert_eq!(first.input.len(), MIB, "the first internal call keeps its full input");
    assert_eq!(first.return_data.len(), MIB, "the first internal call keeps its return data");

    let last = &calls[IDENTITY_CALLS];
    // Compare lengths first: a failing `assert_eq!` on a 1 MiB vector prints megabytes.
    assert_eq!(last.input.len(), 4, "past 50 MiB only the selector stays");
    assert_eq!(last.input, [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(last.return_data.len(), 0, "past 25 MiB no return data stays");
    assert!(last.input_truncated && last.return_data_truncated, "the cuts must be flagged");
    assert!(!first.input_truncated && !first.return_data_truncated);
    assert!(!calls[0].input_truncated && !calls[0].return_data_truncated, "root call is not cut");
}
