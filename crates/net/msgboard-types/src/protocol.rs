//! Protocol constants for the `msg/1` devp2p capability.
//!
//! `PulseChain` nodes negotiate this capability alongside `eth/68` during the
//! devp2p handshake. The three message types carry the full msgboard gossip
//! protocol: announce IDs → request by ID → deliver payloads.

/// Short capability name used during devp2p negotiation.
pub const PROTOCOL_NAME: &str = "msg";

/// Capability version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Number of message types implemented by `msg/1`.
pub const PROTOCOL_LENGTH: u8 = 3;

/// `BoardMessageIDs` (0x00) — flat bytes of concatenated [`MsgID`](crate::MsgID)s.
///
/// Sent by a peer to announce which messages it holds (without sending the
/// full payloads). Each record is exactly [`MSG_ID_SIZE`](crate::MSG_ID_SIZE)
/// bytes, so the total payload length is always a multiple of that.
pub const BOARD_MESSAGE_IDS: u8 = 0x00;

/// `GetBoardMessages` (0x01) — flat bytes of concatenated [`MsgID`](crate::MsgID)s.
///
/// Requests the full [`PoWMsg`](crate::PoWMsg) payloads corresponding to the
/// given IDs from the remote peer.
pub const GET_BOARD_MESSAGES: u8 = 0x01;

/// `BoardMessages` (0x02) — RLP-encoded list of [`PoWMsg`](crate::PoWMsg)s.
///
/// Reply to `GetBoardMessages`. The payload is an RLP list where each element
/// is an RLP-encoded `PoWMsg`.
pub const BOARD_MESSAGES: u8 = 0x02;
