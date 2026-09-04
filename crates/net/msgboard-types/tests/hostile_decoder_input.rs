//! Hostile-input tests for the three decoders a peer can reach.
//!
//! `MsgID::decode_list`, `decode_pow_msg_list` and `decode_validated_pow_msg`
//! are the crate's only attacker-controlled entry points. Everything
//! downstream — `MsgBoard::add_remote_msgs`, `filter_wanted`, the RPC handler —
//! is written against the invariant that whatever these return is already
//! field-validated and bounded in size. These tests pin the second half of that
//! invariant: the decoders refuse or bound every payload, and neither the record
//! count nor the memory they reserve is under the sender's control.
//!
//! Allocation is measured, not argued. The test binary installs a global
//! allocator that tracks the high-water mark of live bytes per thread, so a
//! regression that reintroduces length-prefix amplification fails an assertion
//! instead of surviving a code review.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use alloy_primitives::B256;
use alloy_rlp::Encodable;
use proptest::prelude::*;
use reth_msgboard_types::{
    decode_pow_msg_list, decode_validated_pow_msg, encode_pow_msg_list, MsgID, MsgboardError,
    PoWMsg, MSG_ID_SIZE, VERSION_V1,
};

/// Largest inbound frame the `msg/1` handler admits, opcode byte included.
///
/// Mirrors the private `MAX_INBOUND_FRAME_SIZE` in
/// `crates/net/msgboard/src/protocol.rs` — a 100 KiB packet limit plus an
/// 8-byte frame allowance. That constant is `pub(crate)` and the dependency
/// runs the other way, so this crate cannot import it. Every assertion below
/// treats the figure as an upper bound on what a decoder is ever handed, so the
/// two drifting apart weakens a bound rather than invalidating a result.
const MAX_INBOUND_FRAME_SIZE: usize = 100 * 1024 + 8;

/// `MsgID` records that fit one maximum frame: `102_408 / 121` = 846.
const MAX_IDS_PER_FRAME: usize = MAX_INBOUND_FRAME_SIZE / MSG_ID_SIZE;

/// Bytes of the smallest `PoWMsg` that clears `validate`.
///
/// `block_hash` and `category` are 32-byte strings at 33 bytes each; `version`
/// is 1; `nonce`, `work_multiplier` and `work_divisor` are all non-zero so each
/// costs at least 1; `data` may be empty at 1. That is 71 bytes of payload
/// behind a 2-byte list header. Every message a decoder returns has passed
/// `validate`, so this divides an input length into a hard ceiling on the
/// message count that input can yield.
const MINIMAL_MSG_ENCODED_LEN: usize = 73;

// ── MsgID::decode_list ───────────────────────────────────────────────────────

/// The audit claim was that `decode_list` "sizes its `Vec` from the payload
/// length", meaning the classic length-prefix amplification bug. There is no
/// length prefix: the count comes from bytes already in memory, so the reserved
/// capacity equals the record count exactly and the ratio to the input is fixed
/// at `size_of::<MsgID>() / MSG_ID_SIZE` = 1.
#[test]
fn decode_list_reserves_exactly_one_record_per_msg_id_sized_run_of_input() {
    for records in [0usize, 1, 2, MAX_IDS_PER_FRAME] {
        let payload = vec![0xABu8; records * MSG_ID_SIZE];
        let (decoded, peak) = peak_alloc(|| MsgID::decode_list(&payload).expect("exact multiple"));

        assert_eq!(decoded.len(), records);
        assert_eq!(
            decoded.capacity(),
            records,
            "capacity must equal the record count, not a rounded-up growth step",
        );
        assert!(
            peak <= payload.len() + 4096,
            "{records} records peaked at {peak} B, over the {} B of input they came from",
            payload.len(),
        );
    }
}

/// The frame handler admits at most `MAX_INBOUND_FRAME_SIZE` bytes, so 846 is
/// the ceiling on decoded IDs. Pinning the arithmetic here keeps the bound
/// checkable from the crate that owns the record size the division uses.
#[test]
fn decode_list_output_is_capped_at_846_ids_by_the_inbound_frame_size() {
    assert_eq!(MAX_IDS_PER_FRAME, 846);

    let full_frame = vec![0u8; MAX_IDS_PER_FRAME * MSG_ID_SIZE];
    assert!(full_frame.len() <= MAX_INBOUND_FRAME_SIZE);
    assert_eq!(MsgID::decode_list(&full_frame).expect("a full frame decodes").len(), 846);

    // One more record no longer fits a frame, so the handler drops it undecoded.
    const _: () = assert!((MAX_IDS_PER_FRAME + 1) * MSG_ID_SIZE > MAX_INBOUND_FRAME_SIZE);
}

/// A payload one byte off a record boundary is a wire-protocol violation, and
/// the sender earns a `BadProtocol` report for it. The variant is load-bearing:
/// `handle_incoming` matches on it to choose the reputation hit.
#[test]
fn decode_list_rejects_lengths_one_byte_off_a_record_boundary_without_allocating() {
    let mut lengths = vec![1usize, MSG_ID_SIZE - 1, MSG_ID_SIZE + 1, MAX_INBOUND_FRAME_SIZE];
    for records in [1usize, 2, 845, MAX_IDS_PER_FRAME] {
        lengths.push(records * MSG_ID_SIZE - 1);
        lengths.push(records * MSG_ID_SIZE + 1);
    }

    for len in lengths {
        let payload = vec![0xFFu8; len];
        let (result, peak) = peak_alloc(|| MsgID::decode_list(&payload));

        assert!(
            matches!(result, Err(MsgboardError::MalformedIdList)),
            "length {len} must be refused as a malformed ID list",
        );
        assert!(peak <= 4096, "a refused {len}-byte payload allocated {peak} B");
    }
}

/// `decode_list` used to unwrap the slice-to-array conversion, which could only
/// fail if the length check and the conversion disagreed. They now come from one
/// `as_chunks` split, so there is nothing left to disagree — but the property is
/// what matters, so it is checked across every length up to five records rather
/// than reasoned about.
#[test]
fn decode_list_returns_a_result_for_every_short_length() {
    for len in 0..=5 * MSG_ID_SIZE {
        let payload = vec![0x5Au8; len];
        match MsgID::decode_list(&payload) {
            Ok(ids) => {
                assert!(len.is_multiple_of(MSG_ID_SIZE), "length {len} should not have decoded");
                assert_eq!(ids.len(), len / MSG_ID_SIZE);
            }
            Err(MsgboardError::MalformedIdList) => {
                assert!(!len.is_multiple_of(MSG_ID_SIZE), "length {len} should have decoded");
            }
            Err(other) => panic!("length {len} produced an unexpected error: {other}"),
        }
    }
}

/// `MsgID` has no reserved bits and no invalid encoding — every 121-byte run is
/// a well-formed record, so all-zero and all-`0xFF` payloads have to decode and
/// the accessors have to read them without panicking. An all-zero record is the
/// case that matters: `difficulty_ratio` divides by `work_divisor`.
#[test]
fn decode_list_accepts_degenerate_field_values_and_survives_reading_them() {
    for fill in [0x00u8, 0xFF, 0x80, 0x01] {
        let payload = vec![fill; MAX_IDS_PER_FRAME * MSG_ID_SIZE];
        let ids = MsgID::decode_list(&payload).expect("any exact multiple is well-formed");
        assert_eq!(ids.len(), MAX_IDS_PER_FRAME);

        let id = ids[0];
        let _ = id.version();
        let _ = id.block_hash();
        let _ = id.size();
        let _ = id.work_multiplier();
        let _ = id.category_hash();
        let _ = id.message_hash();
        // A zero divisor gives NaN rather than a panic, and every comparison
        // against NaN is false, so `filter_wanted` drops the ID. That is the
        // safe side of the branch.
        let ratio = id.difficulty_ratio();
        assert!(ratio.is_nan() || ratio >= 0.0, "unexpected ratio {ratio} for fill {fill:#04x}");
    }
}

// ── decode_pow_msg_list ──────────────────────────────────────────────────────

/// The header a peer sends declares a payload length, which is the shape of the
/// bug the audit was reaching for. `alloy_rlp::Header::decode` refuses a
/// declared length longer than the bytes actually supplied, before any element
/// is read, and `Vec::<PoWMsg>::decode` starts from `Vec::new` and pushes — it
/// never reserves from the declared figure. A header claiming `u64::MAX`
/// therefore costs one bounds check, not a 16 EiB reservation.
#[test]
fn decode_pow_msg_list_refuses_a_header_declaring_more_bytes_than_it_supplies() {
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        // 0xF9 — list, two length bytes — declares 65_535 bytes, supplies 4.
        ("two-byte length, 4 bytes supplied", vec![0xF9, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04]),
        // 0xFF — list, eight length bytes — declares u64::MAX.
        ("u64::MAX length", vec![0xFF; 9]),
    ];
    // The same declarations padded to a full frame, so the shortfall between
    // declared and supplied is the only defect the decoder can find.
    for (name, prefix) in [
        ("u64::MAX length in a full frame", vec![0xFFu8; 9]),
        ("4 GiB length in a full frame", vec![0xFB, 0xFF, 0xFF, 0xFF, 0xFF]),
    ] {
        let mut padded = prefix;
        padded.resize(MAX_INBOUND_FRAME_SIZE, 0);
        cases.push((name, padded));
    }

    for (name, payload) in cases {
        let (result, peak) = peak_alloc(|| decode_pow_msg_list(&payload));

        assert!(
            matches!(result, Err(MsgboardError::Rlp(_))),
            "{name}: an over-declared header must be an RLP error, got {result:?}",
        );
        assert!(
            peak <= 64 * 1024,
            "{name}: a refused {}-byte payload peaked at {peak} B",
            payload.len(),
        );
    }
}

/// The decoded message count and the memory behind it both scale with the bytes
/// the peer actually sent. A full frame of the smallest messages the format
/// admits is the worst case, and it is the one measured.
#[test]
fn decode_pow_msg_list_allocation_scales_with_the_bytes_supplied() {
    let payload = frame_filled_with_minimal_messages();
    assert!(payload.len() <= MAX_INBOUND_FRAME_SIZE);

    let (msgs, peak) =
        peak_alloc(|| decode_pow_msg_list(&payload).expect("every message is valid"));

    assert!(
        msgs.len() <= payload.len() / MINIMAL_MSG_ENCODED_LEN,
        "{} messages out of {} bytes exceeds the per-byte ceiling",
        msgs.len(),
        payload.len(),
    );
    // Amplification is a small constant: a `PoWMsg` struct is wider than its
    // minimal encoding, and `Vec` growth doubles. Neither factor depends on the
    // sender, which is the property the ceiling exists to pin.
    assert!(
        peak <= 8 * payload.len(),
        "{} B of input peaked at {peak} B — over the 8x amplification ceiling",
        payload.len(),
    );
}

/// `PoWMsg` has no recursive field: every one of the seven is a scalar or a byte
/// string, and `CheckedPoWMsg` nests it exactly once. A nested list where a
/// scalar belongs is a type error at depth two, so arbitrarily deep input cannot
/// drive arbitrarily deep recursion and neither decoder can overflow the stack.
/// A full frame of nesting proves that rather than leaving the type graph to
/// argue it.
#[test]
fn deeply_nested_input_cannot_drive_deep_recursion() {
    // 0xC1 is a one-byte list header whose payload is the next byte, so a run of
    // them is a legally framed nesting `MAX_INBOUND_FRAME_SIZE` levels deep.
    let mut payload = vec![0xC1u8; MAX_INBOUND_FRAME_SIZE - 1];
    payload.push(0xC0);

    let (list_result, list_peak) = peak_alloc(|| decode_pow_msg_list(&payload));
    assert!(matches!(list_result, Err(MsgboardError::Rlp(_))), "deep nesting must be refused");
    assert!(list_peak <= 64 * 1024, "refusing deep nesting peaked at {list_peak} B");

    assert!(
        matches!(decode_validated_pow_msg(&payload), Err(MsgboardError::Rlp(_))),
        "deep nesting must be refused by the single-message decoder too",
    );
}

/// Truncation is the cheapest attack on a streaming decoder: cut a valid frame
/// anywhere and see whether the parser reads past the end. Every prefix of a
/// real three-message frame is tried, and none may panic or return a message
/// that skipped validation.
#[test]
fn every_prefix_of_a_valid_frame_is_refused_or_decodes_cleanly() {
    let full = encode_pow_msg_list(&[minimal_msg(1), minimal_msg(2), minimal_msg(3)]);

    for cut in 0..full.len() {
        match decode_pow_msg_list(&full[..cut]) {
            Ok(msgs) => {
                assert!(
                    msgs.len() < 3,
                    "a {cut}-byte prefix of a {}-byte frame decoded all 3 messages",
                    full.len(),
                );
                for msg in &msgs {
                    msg.validate().expect("decode_pow_msg_list validates what it returns");
                }
            }
            Err(MsgboardError::Rlp(_)) => {}
            Err(other) => panic!("prefix of {cut} bytes gave an unexpected error: {other}"),
        }
    }

    assert_eq!(decode_pow_msg_list(&full).expect("the whole frame decodes").len(), 3);
}

/// Uniform buffers reach the RLP header branches that need no crafting: `0x00`
/// is a single-byte string where a list must be, and `0xFF` is a list header
/// declaring `u64::MAX`. Both are refused, at every size up to a full frame.
///
/// `0xC0` is excluded because it is the empty list, which is legal — see
/// `trailing_bytes_after_a_complete_value_are_ignored`.
#[test]
fn uniform_fill_buffers_are_refused_at_every_size_up_to_a_full_frame() {
    for fill in [0x00u8, 0xFF, 0x80, 0xF8] {
        for len in [1usize, 2, 55, 56, 1024, MAX_INBOUND_FRAME_SIZE] {
            let payload = vec![fill; len];
            let (list_result, peak) = peak_alloc(|| decode_pow_msg_list(&payload));

            assert!(
                list_result.is_err(),
                "a {len}-byte buffer of {fill:#04x} must not decode as a message list",
            );
            assert!(peak <= 64 * 1024, "fill {fill:#04x} at {len} B peaked at {peak} B");
            assert!(decode_validated_pow_msg(&payload).is_err());
        }
    }

    // Empty input is an RLP error, not a silent empty list.
    assert!(decode_pow_msg_list(&[]).is_err());
    assert!(decode_validated_pow_msg(&[]).is_err());
}

/// Both decoders stop at the end of the first complete RLP value and ignore
/// whatever follows it, so a peer can append arbitrary bytes to a valid frame
/// and still have it accepted.
///
/// This is a divergence from the Go reference: `rlp.DecodeBytes` — which
/// erigon-pulse's `DecodeRLPMsgList` and `PoWMsgFromRLP` both use — returns
/// `errMoreThanOneValue` for trailing data. Nothing here is a memory hazard:
/// the trailing bytes are never read, and `MAX_INBOUND_FRAME_SIZE` still bounds
/// what a peer can send. The consequence is malleability — several distinct
/// frames carry one message set — which matters wherever a caller keys on the
/// bytes rather than on the decoded fields. The board keys on the `PoW` hash,
/// which is computed from fields, so nothing downstream is affected today.
///
/// Pinned rather than fixed: tightening it changes what reth accepts on the
/// wire, which belongs in its own change.
#[test]
fn trailing_bytes_after_a_complete_value_are_ignored() {
    let mut list = encode_pow_msg_list(&[minimal_msg(1)]);
    let clean = decode_pow_msg_list(&list).expect("the frame decodes");
    list.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(decode_pow_msg_list(&list).expect("trailing bytes are ignored"), clean);

    let mut single = encode_single_msg(&minimal_msg(1));
    single.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        decode_validated_pow_msg(&single).expect("trailing bytes are ignored"),
        minimal_msg(1),
    );

    // The degenerate case: an empty list followed by anything at all.
    let mut padded = vec![0xC0u8];
    padded.resize(MAX_INBOUND_FRAME_SIZE, 0xC0);
    assert!(decode_pow_msg_list(&padded).expect("an empty list decodes").is_empty());
}

// ── decode_validated_pow_msg ─────────────────────────────────────────────────

/// The RPC path decodes one message rather than a list, so it needs its own
/// coverage of the same header hazard. A `data` field declaring more bytes than
/// the payload holds is refused by the same bounds check the list decoder relies
/// on, before `Bytes::decode` copies anything.
#[test]
fn decode_validated_pow_msg_refuses_an_over_declared_data_field() {
    let mut msg = encode_single_msg(&minimal_msg(1));
    // The last field is `data`, encoded as the empty string 0x80. Rewrite it as
    // a long-form header declaring 4 GiB with no bytes behind it.
    assert_eq!(msg.pop(), Some(0x80), "the minimal message ends with an empty data field");
    msg.extend_from_slice(&[0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);

    let (result, peak) = peak_alloc(|| decode_validated_pow_msg(&msg));
    assert!(
        matches!(result, Err(MsgboardError::Rlp(_))),
        "an over-declared data field must be an RLP error, got {result:?}",
    );
    assert!(peak <= 64 * 1024, "refusing an over-declared data field peaked at {peak} B");
}

/// What `decode_validated_pow_msg` returns is field-validated, so the RPC
/// handler and the board can skip re-checking it. Every prefix of a valid
/// message either fails or comes back having passed `validate`.
#[test]
fn every_prefix_of_a_valid_message_is_refused_or_field_validated() {
    let full = encode_single_msg(&minimal_msg(7));

    for cut in 0..full.len() {
        if let Ok(msg) = decode_validated_pow_msg(&full[..cut]) {
            msg.validate().expect("what it returns must already be valid");
        }
    }

    assert_eq!(decode_validated_pow_msg(&full).expect("the whole message decodes"), minimal_msg(7));
}

/// A message whose `data` fills a whole frame is the largest single payload the
/// decoder can be handed. It has to come back intact and cost memory in
/// proportion to its size.
#[test]
fn a_frame_sized_data_field_decodes_without_amplifying() {
    let mut msg = minimal_msg(1);
    msg.data = vec![0x5Au8; 100 * 1024].into();
    let encoded = encode_single_msg(&msg);

    let (decoded, peak) = peak_alloc(|| decode_validated_pow_msg(&encoded).expect("valid"));
    assert_eq!(decoded.data.len(), 100 * 1024);
    assert!(peak <= 4 * encoded.len(), "{} B of input peaked at {peak} B", encoded.len());
}

// ── fuzzing ──────────────────────────────────────────────────────────────────

proptest! {
    /// Unstructured bytes. Most are refused at the first header byte, which is
    /// the point: the cheap rejections have to stay cheap and total.
    #[test]
    fn no_decoder_panics_on_arbitrary_bytes(
        payload in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        check_all_decoders(&payload);
    }

    /// Bytes behind a well-formed outer list header, so the generator gets past
    /// the first branch and exercises the per-element loop — where a decoder
    /// that trusted a declared length would do its damage.
    #[test]
    fn no_decoder_panics_behind_a_well_formed_list_header(
        body in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut payload = rlp_list_header(body.len());
        payload.extend_from_slice(&body);
        check_all_decoders(&payload);
    }

    /// Mutations of a real frame. Random bytes almost never form a valid header,
    /// so corrupting a valid encoding is what reaches the deeper paths: a length
    /// byte rewritten upward, a type byte flipped, a field cut short.
    #[test]
    fn no_decoder_panics_on_a_mutated_valid_frame(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..24),
        truncate_to in any::<prop::sample::Index>(),
    ) {
        let mut payload = encode_pow_msg_list(&[minimal_msg(1), minimal_msg(2)]);
        for (at, byte) in edits {
            let at = at.index(payload.len());
            payload[at] = byte;
        }
        payload.truncate(truncate_to.index(payload.len() + 1));
        check_all_decoders(&payload);
    }
}

/// Deterministic sweep at the size the frame handler actually admits.
///
/// `proptest` is kept to small inputs so a run stays quick; this covers the
/// 102 KB end with a fixed seed, so a failure reproduces from its case index
/// alone. Both are needed: the small cases find shape bugs, and only the large
/// ones would expose an allocation that grows faster than its input.
#[test]
fn full_frame_hostile_buffers_are_refused_or_bounded() {
    let mut rng = XorShift64::new(0x2545_F491_4F6C_DD1D);

    for case in 0..48 {
        let mut payload = vec![0u8; MAX_INBOUND_FRAME_SIZE];
        rng.fill(&mut payload);

        // Half the cases get a header that frames the rest of the buffer, so the
        // element loop runs on random bytes instead of dying at byte zero.
        if case % 2 == 0 {
            let header = rlp_list_header(payload.len() - 4);
            payload[..header.len()].copy_from_slice(&header);
        }

        let (list_result, peak) = peak_alloc(|| decode_pow_msg_list(&payload));
        assert!(
            peak <= 8 * payload.len(),
            "case {case}: {} B of input peaked at {peak} B",
            payload.len(),
        );
        if let Ok(msgs) = list_result {
            assert!(msgs.len() <= payload.len() / MINIMAL_MSG_ENCODED_LEN);
            for msg in &msgs {
                msg.validate().expect("returned messages are validated");
            }
        }

        // The same bytes reach the other two decoders: nothing about a payload
        // decides which opcode a peer labels it with.
        let (id_result, id_peak) = peak_alloc(|| MsgID::decode_list(&payload));
        assert!(id_peak <= 2 * payload.len(), "case {case}: ID decode peaked at {id_peak} B");
        match id_result {
            Ok(ids) => assert!(ids.len() <= MAX_IDS_PER_FRAME),
            Err(MsgboardError::MalformedIdList) => {}
            Err(other) => panic!("case {case}: unexpected ID error {other}"),
        }

        let (single, single_peak) = peak_alloc(|| decode_validated_pow_msg(&payload));
        assert!(single_peak <= 8 * payload.len(), "case {case}: peaked at {single_peak} B");
        if let Ok(msg) = single {
            msg.validate().expect("returned messages are validated");
            assert!(msg.data.len() <= payload.len());
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Feed the same bytes to all three decoders and check the contract each owes:
/// return `Err`, or return a bounded, already-validated result.
fn check_all_decoders(payload: &[u8]) {
    if let Ok(msgs) = decode_pow_msg_list(payload) {
        assert!(msgs.len() <= payload.len() / MINIMAL_MSG_ENCODED_LEN);
        for msg in &msgs {
            msg.validate().expect("decode_pow_msg_list validates what it returns");
        }
    }

    if let Ok(msg) = decode_validated_pow_msg(payload) {
        msg.validate().expect("decode_validated_pow_msg validates what it returns");
        assert!(msg.data.len() <= payload.len());
    }

    match MsgID::decode_list(payload) {
        Ok(ids) => {
            assert_eq!(ids.len(), payload.len() / MSG_ID_SIZE);
            assert_eq!(ids.capacity(), ids.len());
        }
        Err(MsgboardError::MalformedIdList) => {
            assert!(!payload.len().is_multiple_of(MSG_ID_SIZE));
        }
        Err(other) => panic!("MsgID::decode_list gave an unexpected error: {other}"),
    }
}

/// The smallest `PoWMsg` that passes `validate`, varying only the nonce.
fn minimal_msg(nonce: u64) -> PoWMsg {
    PoWMsg {
        version: VERSION_V1,
        block_hash: B256::repeat_byte(0x11),
        nonce,
        work_multiplier: 10_000,
        work_divisor: 1_000_000,
        category: B256::repeat_byte(0x22),
        data: Default::default(),
    }
}

/// RLP bytes of a single `PoWMsg`, without a surrounding list.
fn encode_single_msg(msg: &PoWMsg) -> Vec<u8> {
    let mut out = Vec::new();
    msg.encode(&mut out);
    out
}

/// A well-formed RLP list header for a payload of `payload_len` bytes.
fn rlp_list_header(payload_len: usize) -> Vec<u8> {
    if payload_len < 56 {
        return vec![0xC0 + payload_len as u8];
    }
    let be = payload_len.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).expect("payload_len is at least 56 here");
    let trimmed = &be[first..];
    let mut out = Vec::with_capacity(1 + trimmed.len());
    out.push(0xF7 + trimmed.len() as u8);
    out.extend_from_slice(trimmed);
    out
}

/// A frame packed with as many minimal messages as fit under the inbound cap.
fn frame_filled_with_minimal_messages() -> Vec<u8> {
    let mut msgs: Vec<PoWMsg> = Vec::new();
    let mut encoded = encode_pow_msg_list(&msgs);
    loop {
        msgs.push(minimal_msg(msgs.len() as u64 + 1));
        let next = encode_pow_msg_list(&msgs);
        if next.len() > MAX_INBOUND_FRAME_SIZE {
            return encoded;
        }
        encoded = next;
    }
}

/// Deterministic PRNG, so a failing large-buffer case reproduces from its index.
struct XorShift64(u64);

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

// ── allocation measurement ───────────────────────────────────────────────────

/// Run `f` and report the high-water mark of bytes it held live on this thread.
///
/// The counters reset first, so the figure is the peak caused by `f` and not
/// whatever the harness already holds. `f`'s return value is still alive when
/// the peak is read, so anything it hands back is counted.
fn peak_alloc<T>(f: impl FnOnce() -> T) -> (T, usize) {
    COUNTERS.with(|c| c.set(Counters { live: 0, peak: 0 }));
    let value = f();
    let peak = COUNTERS.with(|c| c.get().peak);
    (value, peak)
}

/// Live and peak byte counts for one thread.
#[derive(Clone, Copy)]
struct Counters {
    live: usize,
    peak: usize,
}

thread_local! {
    /// A `Cell` of a `Copy` struct with a `const` initialiser: no destructor and
    /// no lazy registration, so reading it from inside the allocator cannot
    /// allocate and cannot re-enter.
    static COUNTERS: Cell<Counters> = const { Cell::new(Counters { live: 0, peak: 0 }) };
}

fn record_alloc(bytes: usize) {
    let _ = COUNTERS.try_with(|c| {
        let mut counters = c.get();
        counters.live += bytes;
        counters.peak = counters.peak.max(counters.live);
        c.set(counters);
    });
}

fn record_dealloc(bytes: usize) {
    let _ = COUNTERS.try_with(|c| {
        let mut counters = c.get();
        counters.live = counters.live.saturating_sub(bytes);
        c.set(counters);
    });
}

/// Forwards to the system allocator and records the peak live bytes per thread.
struct PeakTrackingAllocator;

// SAFETY: every method forwards to `System`, which upholds the `GlobalAlloc`
// contract. The bookkeeping around each call touches only a `Copy` thread-local
// with a `const` initialiser, so it cannot allocate or re-enter the allocator.
unsafe impl GlobalAlloc for PeakTrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the caller's, forwarded unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record_dealloc(layout.size());
        // SAFETY: `ptr` and `layout` are the caller's, and this is the only
        // allocator that could have produced the block.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Count the new block before the call, not after: a growing realloc can
        // hold both blocks at once, and the peak must include that moment.
        record_alloc(new_size);
        // SAFETY: arguments are the caller's, forwarded unchanged.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        record_dealloc(if new_ptr.is_null() { new_size } else { layout.size() });
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: PeakTrackingAllocator = PeakTrackingAllocator;
