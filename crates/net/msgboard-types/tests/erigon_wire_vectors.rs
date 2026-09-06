//! Golden vectors from erigon-pulse `pulse-v3.4.4` (`78fbcffb8b`), the newest
//! msgboard reference.
//!
//! Every byte string below was emitted by erigon's own encoders — `FlattenMsgHashes`,
//! `EncodeRLPWireMsgList`, `FlattenMsgIDs` — compiled and run against that commit.
//! They are not reconstructions. Regenerate with the Go in `regenerate()` below.
//!
//! Two of erigon's three opcodes changed shape at that commit:
//!
//! | opcode | `v3.0.0-RC8` | `pulse-v3.4.4` |
//! |---|---|---|
//! | `BOARD_MESSAGE_IDS` | 121-byte `MsgID` records | unchanged |
//! | `GET_BOARD_MESSAGES` | 121-byte `MsgID` records | 32-byte message hashes |
//! | `BOARD_MESSAGES` | RLP list of `PoWMsg` | RLP list of `{PoWMsg, claimedHash}` |
//!
//! These tests assert what reth does with erigon's real bytes. They are the
//! evidence for whether the two clients can talk.
//!
//! # Regenerating
//!
//! The Go below produced every vector. It runs inside erigon's `msgboard`
//! package at `78fbcffb8b`, because it needs the package's own encoders:
//!
//! Runs inside erigon's `msgboard` package at `78fbcffb8b`, because it needs
//! the unexported `messageIDSize` and the package's own encoders:
//!
//! ```text
//! func TestGoldenVectorsForReth(t *testing.T) {
//!     mk := func(seed byte, data []byte) *PoWMsg {
//!         return &PoWMsg{
//!             Version: V1, BlockHash: common.Hash{seed, 0xAA}, Nonce: uint64(seed) + 1,
//!             WorkMultiplier: 10_000, WorkDivisor: 1_000_000,
//!             Category: common.Hash{seed, 0xCC}, Data: data,
//!         }
//!     }
//!     msgs := []*PoWMsg{mk(1, []byte("hello")), mk(2, nil)}
//!     // ... build CheckedPoWMsg{PoWMsg, BlockNumber: 100+i, Hash: {i+1, 0xEE}},
//!     //     WirePoWMsg{PoWMsg, Hash}, and MsgIDFromPoWMsg(checked[i]) ...
//!     hex.EncodeToString(FlattenMsgHashes(hashes))
//!     hex.EncodeToString(EncodeRLPWireMsgList(wire))
//!     hex.EncodeToString(FlattenMsgIDs(ids))
//! }
//! ```

use reth_msgboard_types::{
    decode_msg_hash_list, decode_pow_msg_list, decode_wire_pow_msg_list, MsgID, MSG_HASH_SIZE,
    MSG_ID_SIZE,
};

/// Build a 32-byte value the way the Go fixture did: two leading marker bytes,
/// then zeros.
fn marked(a: u8, b: u8) -> alloy_primitives::B256 {
    let mut out = [0u8; 32];
    out[0] = a;
    out[1] = b;
    alloy_primitives::B256::from(out)
}

/// `FlattenMsgHashes` over two messages. Two 32-byte hashes, no framing.
const ERIGON_GET_BOARD_MESSAGES: &str = "01ee00000000000000000000000000000000000000000000000000000000000002ee000000000000000000000000000000000000000000000000000000000000";

/// `EncodeRLPWireMsgList` over the same two messages. Each element is a
/// two-item list: the 7-field `PoWMsg` list, then the claimed hash.
const ERIGON_BOARD_MESSAGES: &str = "f8e7f874f85101a001aa00000000000000000000000000000000000000000000000000000000000002822710830f4240a001cc0000000000000000000000000000000000000000000000000000000000008568656c6c6fa001ee000000000000000000000000000000000000000000000000000000000000f86ff84c01a002aa00000000000000000000000000000000000000000000000000000000000003822710830f4240a002cc00000000000000000000000000000000000000000000000000000000000080a002ee000000000000000000000000000000000000000000000000000000000000";

/// `FlattenMsgIDs` over the same two messages. Unchanged between the releases,
/// so this is the one frame both clients still agree on.
const ERIGON_BOARD_MESSAGE_IDS: &str = "0101aa0000000000000000000000000000000000000000000000000000000000000000000000000005000000000000271000000000000f424001cc00000000000000000000000000000000000000000000000000000000000001ee0000000000000000000000000000000000000000000000000000000000000102aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000271000000000000f424002cc00000000000000000000000000000000000000000000000000000000000002ee000000000000000000000000000000000000000000000000000000000000";

fn bytes(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// The one opcode that still works. Guards against a regression that would
/// break gossip announcement, which is the only thing still crossing.
#[test]
fn reth_decodes_erigons_board_message_ids() {
    let raw = bytes(ERIGON_BOARD_MESSAGE_IDS);
    assert_eq!(raw.len(), 2 * MSG_ID_SIZE);
    let ids = MsgID::decode_list(&raw).expect("announcements still interoperate");
    assert_eq!(ids.len(), 2);
}

/// Reth parses erigon's `GetBoardMessages` payload.
///
/// Erigon sends 32-byte message hashes. Reth's `MsgID` decoder requires a
/// multiple of 121 and refuses this frame; `gcd(32, 121) = 1`, so the two
/// lengths coincide only at 3,872 bytes and every ordinary frame is a mutual
/// decode failure. Both clients answer that with a peer penalty, so this is
/// the frame on which the two ban each other.
#[test]
fn reth_decodes_erigons_get_board_messages() {
    let raw = bytes(ERIGON_GET_BOARD_MESSAGES);
    assert_eq!(raw.len(), 2 * MSG_HASH_SIZE, "two 32-byte hashes");

    let hashes = decode_msg_hash_list(&raw).expect("reth must parse erigon's GET payload");
    assert_eq!(hashes, vec![marked(0x01, 0xEE), marked(0x02, 0xEE)]);

    assert!(
        MsgID::decode_list(&raw).is_err(),
        "the pre-pulse-v3.4.4 reading must refuse it, or the break was never real",
    );
}

/// Reth parses erigon's `BoardMessages` payload.
///
/// Each element is a two-item list: the seven-field body, then the claimed
/// work hash. Reth's old decoder expects a flat seven-field element and meets
/// a list header where it wants the single-byte version field.
#[test]
fn reth_decodes_erigons_board_messages() {
    let raw = bytes(ERIGON_BOARD_MESSAGES);

    let msgs = decode_wire_pow_msg_list(&raw).expect("reth must parse erigon's BOARD_MESSAGES");
    assert_eq!(msgs.len(), 2);

    assert_eq!(msgs[0].msg.data.as_ref(), b"hello");
    assert_eq!(msgs[0].msg.block_hash, marked(0x01, 0xAA));
    assert_eq!(msgs[0].msg.nonce, 2);
    assert_eq!(msgs[0].msg.work_multiplier, 10_000);
    assert_eq!(msgs[0].msg.work_divisor, 1_000_000);
    assert_eq!(msgs[0].msg.category, marked(0x01, 0xCC));
    assert_eq!(msgs[0].hash, marked(0x01, 0xEE));

    assert!(msgs[1].msg.data.is_empty());
    assert_eq!(msgs[1].msg.nonce, 3);
    assert_eq!(msgs[1].hash, marked(0x02, 0xEE));

    assert!(
        decode_pow_msg_list(&raw).is_err(),
        "the pre-pulse-v3.4.4 reading must refuse it, or the break was never real",
    );
}
