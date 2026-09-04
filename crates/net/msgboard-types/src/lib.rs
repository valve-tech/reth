//! `PulseChain` msgboard P2P protocol types, `PoW` verification, and RLP codec.
//!
//! This crate implements the wire types for the `msg/1` devp2p capability that
//! `PulseChain` nodes negotiate alongside `eth/68`. Three message types carry
//! the full msgboard gossip protocol:
//!
//! | Opcode | Name               | Payload                          |
//! |--------|--------------------|----------------------------------|
//! | 0x00   | `BoardMessageIDs`  | Flat concatenated [`MsgID`]s     |
//! | 0x01   | `GetBoardMessages` | Flat concatenated message hashes |
//! | 0x02   | `BoardMessages`    | RLP list of [`WirePoWMsg`]s      |
//!
//! See [`protocol`] for opcode constants and capability metadata.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod config;
pub use config::MsgboardConfig;

pub mod msg_id;
pub use msg_id::{MsgID, MSG_ID_SIZE};

pub mod pow;
pub use pow::{
    decode_pow_msg_list, decode_validated_pow_msg, encode_pow_msg_list, CheckedPoWMsg, PoWMsg,
    VERSION_V1,
};

pub mod hashes;
pub use hashes::{
    check_unique_hashes, decode_msg_hash_list, encode_msg_hash_list, MAX_GET_BOARD_MESSAGES,
    MSG_HASH_SIZE,
};

pub mod wire;
pub use wire::{decode_wire_pow_msg_list, encode_wire_pow_msg_list, WirePoWMsg};

pub mod protocol;
pub use protocol::{
    BOARD_MESSAGES, BOARD_MESSAGE_IDS, GET_BOARD_MESSAGES, PROTOCOL_LENGTH, PROTOCOL_NAME,
    PROTOCOL_VERSION,
};

/// Errors produced by msgboard type decoding and `PoW` verification.
#[derive(Debug, thiserror::Error)]
pub enum MsgboardError {
    /// The [`PoWMsg::version`] field is not `VERSION_V1`.
    #[error("powmsg: invalid version")]
    InvalidVersion,

    /// [`PoWMsg::block_hash`] is the zero hash.
    #[error("powmsg: invalid block hash")]
    InvalidBlockHash,

    /// [`PoWMsg::nonce`] is zero, which is always an invalid `PoW` solution.
    #[error("powmsg: invalid nonce")]
    InvalidNonce,

    /// [`PoWMsg::work_multiplier`] or [`PoWMsg::work_divisor`] is zero,
    /// making the difficulty calculation degenerate.
    #[error("powmsg: invalid difficulty")]
    InvalidDifficulty,

    /// Both `category` and `data` are empty/zero, which is not a valid message.
    #[error("powmsg: invalid data")]
    InvalidData,

    /// The `PoW` hash does not satisfy the required difficulty.
    #[error("powmsg: invalid work")]
    InvalidWork,

    /// The message `data` field exceeds the configured size limit.
    #[error("msgboard: message too large")]
    MessageTooLarge,

    /// The work ratio `multiplier / divisor` is below the minimum threshold.
    #[error("msgboard: message work too easy")]
    WorkTooEasy,

    /// The message's `block_hash` is not in the live block window — either
    /// the hash is unknown (peer is on a different fork or further ahead), or
    /// it was in the window at lookup time and aged out before insertion.
    ///
    /// Mirrors erigon-pulse's single `ErrMsgTooOld` variant; reth used to
    /// distinguish `BlockUnknown` and `BlockExpired` internally, but both
    /// surfaced the same wire string and the split was a parity divergence
    /// for clients pattern-matching on the variant.
    #[error("msgboard: message block too old")]
    BlockTooOld,

    /// A message with this hash already exists in the board.
    #[error("msgboard: message exists")]
    MessageExists,

    /// The board is at capacity and the message doesn't displace any existing one.
    #[error("msgboard: board overflow")]
    BoardOverflow,

    /// The board is not yet accepting messages (node still syncing).
    #[error("msgboard: not synced")]
    NotReady,

    /// A [`MsgID`] list payload is not a whole multiple of [`MSG_ID_SIZE`].
    #[error("MsgID list length is not a multiple of MSG_ID_SIZE")]
    MalformedIdList,

    /// A message-hash list payload is not a whole multiple of [`MSG_HASH_SIZE`].
    #[error("message hash list length is not a multiple of MSG_HASH_SIZE")]
    MalformedHashList,

    /// A `GetBoardMessages` frame names the same hash twice.
    #[error("msgboard: duplicate message hashes")]
    DuplicateHashes,

    /// A `GetBoardMessages` frame names more than [`MAX_GET_BOARD_MESSAGES`] hashes.
    #[error("msgboard: GetBoardMessages exceeds the hash cap")]
    GetTooManyHashes,

    /// A `BoardMessages` element carries a zero claimed hash.
    #[error("msgboard: missing claimed message hash")]
    MissingClaimedHash,

    /// A delivered message's recomputed work hash is not the one claimed for it.
    #[error("msgboard: claimed hash does not match computed hash")]
    ClaimedHashMismatch,

    /// A payload carries bytes after the end of its RLP value.
    #[error("msgboard: trailing bytes after RLP value")]
    TrailingBytes,

    /// RLP decoding error.
    #[error("RLP decode error: {0}")]
    Rlp(alloy_rlp::Error),
}
