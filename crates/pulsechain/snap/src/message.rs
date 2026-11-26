//! The `snap/1` message set.
//!
//! `snap/1` and `snap/2` share ids `0x00..=0x05` with the same wire shape, so those reuse
//! [`SnapProtocolMessage`]. `snap/1` adds `GetTrieNodes` (`0x06`) and `TrieNodes` (`0x07`), which
//! `snap/2` removed. The `snap/2` block access list ids (`0x08`/`0x09`) are not part of `snap/1`.
//!
//! Reference: <https://github.com/ethereum/devp2p/blob/master/caps/snap.md>

use crate::{
    bytecodes::MAX_BYTE_CODES_SERVE, ranges::MAX_STORAGE_RANGE_ACCOUNTS_SERVE,
    trie_nodes::MAX_TRIE_NODE_LOOKUPS,
};
use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, Encodable, Header, RlpEncodable};
use reth_eth_wire_types::snap::{
    AccountRangeMessage, ByteCodesMessage, SnapMessageId, SnapProtocolMessage, StorageRangesMessage,
};

/// The `snap/1` capability version.
pub const SNAP1_VERSION: usize = 1;

/// The number of message ids `snap/1` reserves (`0x00..=0x07`).
pub const SNAP1_MESSAGE_COUNT: u8 = 8;

/// Id of `GetTrieNodes`.
const GET_TRIE_NODES_ID: u8 = 0x06;

/// Id of `TrieNodes`.
const TRIE_NODES_ID: u8 = 0x07;

/// Id of `AccountRange`.
const ACCOUNT_RANGE_ID: u8 = SnapMessageId::AccountRange as u8;

/// Id of `StorageRanges`.
const STORAGE_RANGES_ID: u8 = SnapMessageId::StorageRanges as u8;

/// Id of `ByteCodes`.
const BYTE_CODES_ID: u8 = SnapMessageId::ByteCodes as u8;

/// The most nodes a range proof in a response may carry. A proof of the two range boundaries needs
/// at most 130: 64 nibbles of branches and a leaf for each.
pub const MAX_RANGE_PROOF_NODES: usize = 1024;

/// The error for a response list longer than its cap.
const TOO_MANY_ENTRIES: &str = "snap/1 response list too long";

/// One group of trie node paths.
///
/// A set with one element is a compact-encoded path in the account trie. A longer set starts
/// with an account hash, and every later element is a compact-encoded path in that account's
/// storage trie.
pub type TrieNodePathSet = Vec<Bytes>;

/// Request for trie nodes by path at a given state root (`0x06`).
///
/// Decoding keeps only the path sets that serving reads: the first [`MAX_TRIE_NODE_LOOKUPS`]
/// sets, and in them the first [`MAX_TRIE_NODE_LOOKUPS`] lookups. The rest is checked by header
/// and skipped, so a frame decodes to at most that many sets. A tiny set still takes many times
/// its wire size once decoded, which the connection counts against its limits.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable)]
pub struct GetTrieNodesMessage {
    /// Request id to match up responses with.
    pub request_id: u64,
    /// The state root the paths are resolved against.
    pub root_hash: B256,
    /// The path sets to serve.
    pub paths: Vec<TrieNodePathSet>,
    /// Soft limit at which to stop returning data.
    pub response_bytes: u64,
}

impl Decodable for GetTrieNodesMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        decode_fields(buf, |body| {
            Ok(Self {
                request_id: u64::decode(body)?,
                root_hash: B256::decode(body)?,
                paths: decode_served_path_sets(body)?,
                response_bytes: u64::decode(body)?,
            })
        })
    }
}

/// Decodes a list with `fields`, which must read all of it.
fn decode_fields<T>(
    buf: &mut &[u8],
    fields: impl FnOnce(&mut &[u8]) -> alloy_rlp::Result<T>,
) -> alloy_rlp::Result<T> {
    let mut body = Header::decode_bytes(buf, true)?;
    let payload_length = body.len();
    let decoded = fields(&mut body)?;
    if !body.is_empty() {
        return Err(alloy_rlp::Error::ListLengthMismatch {
            expected: payload_length,
            got: payload_length - body.len(),
        })
    }
    Ok(decoded)
}

/// Decodes a list of at most `max` items, and fails at the first item past it.
///
/// A response list can hold one-byte items that take 24 or 32 bytes each once decoded, so the
/// derived decoders would turn a frame into many times its size.
fn decode_capped_list<T: Decodable>(buf: &mut &[u8], max: usize) -> alloy_rlp::Result<Vec<T>> {
    let mut payload = Header::decode_bytes(buf, true)?;
    let mut items = Vec::new();
    while !payload.is_empty() {
        if items.len() >= max {
            return Err(alloy_rlp::Error::Custom(TOO_MANY_ENTRIES))
        }
        items.push(T::decode(&mut payload)?);
    }
    Ok(items)
}

/// Decodes an `AccountRange` body. An account entry takes at least 39 bytes on the wire, so only
/// the proof needs a cap.
fn decode_account_range(buf: &mut &[u8]) -> alloy_rlp::Result<AccountRangeMessage> {
    decode_fields(buf, |body| {
        Ok(AccountRangeMessage {
            request_id: u64::decode(body)?,
            accounts: Vec::decode(body)?,
            proof: decode_capped_list(body, MAX_RANGE_PROOF_NODES)?,
        })
    })
}

/// Decodes a `StorageRanges` body with at most one slot list per account a server answers. A slot
/// takes at least 35 bytes on the wire, so the slot lists need no cap of their own.
fn decode_storage_ranges(buf: &mut &[u8]) -> alloy_rlp::Result<StorageRangesMessage> {
    decode_fields(buf, |body| {
        Ok(StorageRangesMessage {
            request_id: u64::decode(body)?,
            slots: decode_capped_list(body, MAX_STORAGE_RANGE_ACCOUNTS_SERVE)?,
            proof: decode_capped_list(body, MAX_RANGE_PROOF_NODES)?,
        })
    })
}

/// Decodes a `ByteCodes` body with at most as many codes as a server answers.
fn decode_byte_codes(buf: &mut &[u8]) -> alloy_rlp::Result<ByteCodesMessage> {
    decode_fields(buf, |body| {
        Ok(ByteCodesMessage {
            request_id: u64::decode(body)?,
            codes: decode_capped_list(body, MAX_BYTE_CODES_SERVE)?,
        })
    })
}

/// Decodes a list of path sets, keeping what `serve_trie_nodes` reads of it.
///
/// A set with one element is one lookup; a longer set is its owner and one lookup per later
/// element. Serving reads at most [`MAX_TRIE_NODE_LOOKUPS`] sets and stops once that many
/// lookups are taken, so a kept set never loses its owner.
fn decode_served_path_sets(buf: &mut &[u8]) -> alloy_rlp::Result<Vec<TrieNodePathSet>> {
    let mut payload = Header::decode_bytes(buf, true)?;
    let mut sets = Vec::new();
    let mut lookups = 0usize;
    while !payload.is_empty() {
        let mut items = Header::decode_bytes(&mut payload, true)?;
        if sets.len() >= MAX_TRIE_NODE_LOOKUPS || lookups >= MAX_TRIE_NODE_LOOKUPS {
            continue
        }
        let mut set = Vec::new();
        while !items.is_empty() {
            // The owner of a storage set takes no lookup; the elements after it take one each.
            let kept = set.len().saturating_sub(1);
            if kept < MAX_TRIE_NODE_LOOKUPS - lookups {
                set.push(Bytes::decode(&mut items)?);
            } else {
                Header::decode_bytes(&mut items, false)?;
            }
        }
        lookups += match set.len() {
            0 => 0,
            1 => 1,
            n => n - 1,
        };
        sets.push(set);
    }
    Ok(sets)
}

/// Response with the requested trie nodes (`0x07`).
///
/// Decoding fails past [`MAX_TRIE_NODE_LOOKUPS`] nodes, the most a server answers.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable)]
pub struct TrieNodesMessage {
    /// Id of the request this is a response for.
    pub request_id: u64,
    /// The RLP-encoded nodes. An empty entry means no node at that path.
    pub nodes: Vec<Bytes>,
}

impl Decodable for TrieNodesMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        decode_fields(buf, |body| {
            Ok(Self {
                request_id: u64::decode(body)?,
                nodes: decode_capped_list(body, MAX_TRIE_NODE_LOOKUPS)?,
            })
        })
    }
}

/// A `snap/1` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Snap1Message {
    /// A message with an id in `0x00..=0x05`, shared with `snap/2`.
    Shared(SnapProtocolMessage),
    /// A `GetTrieNodes` request.
    GetTrieNodes(GetTrieNodesMessage),
    /// A `TrieNodes` response.
    TrieNodes(TrieNodesMessage),
}

/// An error decoding or encoding a `snap/1` message.
#[derive(Debug, thiserror::Error)]
pub enum Snap1Error {
    /// The payload was empty and carried no message id.
    #[error("empty snap/1 message")]
    Empty,
    /// The message id is not part of `snap/1`.
    #[error("message id {0:#x} is not part of snap/1")]
    UnsupportedMessageId(u8),
    /// Decoding the RLP message body failed.
    #[error("RLP error: {0}")]
    Rlp(#[from] alloy_rlp::Error),
}

impl Snap1Message {
    /// Returns the `snap/1`-relative message id.
    pub const fn message_id(&self) -> u8 {
        match self {
            Self::Shared(msg) => msg.message_id() as u8,
            Self::GetTrieNodes(_) => GET_TRIE_NODES_ID,
            Self::TrieNodes(_) => TRIE_NODES_ID,
        }
    }

    /// Returns `true` if the id is a `snap/1` id this enum can hold.
    const fn is_snap1_id(id: u8) -> bool {
        id <= SnapMessageId::ByteCodes as u8 || id == GET_TRIE_NODES_ID || id == TRIE_NODES_ID
    }

    /// Decodes a framed message (`[id, body..]`) with a `snap/1`-relative id.
    ///
    /// Rejects ids outside `snap/1` and bodies with trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Snap1Error> {
        let (&id, mut body) = bytes.split_first().ok_or(Snap1Error::Empty)?;
        if !Self::is_snap1_id(id) {
            return Err(Snap1Error::UnsupportedMessageId(id))
        }
        let msg = match id {
            GET_TRIE_NODES_ID => Self::GetTrieNodes(GetTrieNodesMessage::decode(&mut body)?),
            TRIE_NODES_ID => Self::TrieNodes(TrieNodesMessage::decode(&mut body)?),
            ACCOUNT_RANGE_ID => {
                Self::Shared(SnapProtocolMessage::AccountRange(decode_account_range(&mut body)?))
            }
            STORAGE_RANGES_ID => {
                Self::Shared(SnapProtocolMessage::StorageRanges(decode_storage_ranges(&mut body)?))
            }
            BYTE_CODES_ID => {
                Self::Shared(SnapProtocolMessage::ByteCodes(decode_byte_codes(&mut body)?))
            }
            _ => Self::Shared(SnapProtocolMessage::decode(id, &mut body)?),
        };
        if !body.is_empty() {
            return Err(Snap1Error::Rlp(alloy_rlp::Error::UnexpectedLength))
        }
        Ok(msg)
    }

    /// Encodes the message framed as `[id, body..]` with a `snap/1`-relative id.
    ///
    /// Fails for a shared message whose id `snap/1` does not have, such as a `snap/2` block access
    /// list message.
    pub fn encode(&self) -> Result<Bytes, Snap1Error> {
        let id = self.message_id();
        if !Self::is_snap1_id(id) {
            return Err(Snap1Error::UnsupportedMessageId(id))
        }
        let out = match self {
            Self::Shared(msg) => msg.encode(),
            Self::GetTrieNodes(msg) => frame(id, msg),
            Self::TrieNodes(msg) => frame(id, msg),
        };
        Ok(out)
    }
}

/// Frames `msg` behind its message id.
fn frame(id: u8, msg: &impl Encodable) -> Bytes {
    let mut buf = Vec::with_capacity(1 + msg.length());
    buf.push(id);
    msg.encode(&mut buf);
    buf.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_TRIE_NODE_LOOKUPS;
    use alloy_primitives::hex;
    use reth_eth_wire_types::snap::{GetBlockAccessListsMessage, GetByteCodesMessage};

    // A GetTrieNodes body as go-ethereum encodes it: request id 1, root 0x11..11, one account
    // path set [0x00] and one storage path set [0x22..22, 0x00, 0x12], 100 response bytes.
    // Encoded by hand, independently of the derive under test.
    const GETH_GET_TRIE_NODES: &str = "f84a01a01111111111111111111111111111111111111111111111111111111111111111e6c100e3a02222222222222222222222222222222222222222222222222222222222222222001264";

    // A TrieNodes body for request id 1: an empty entry (no node at the path), then the node
    // 0xc28080.
    const GETH_TRIE_NODES: &str = "c701c58083c28080";

    fn framed(id: u8, body_hex: &str) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(hex::decode(body_hex).unwrap());
        out
    }

    fn geth_request() -> GetTrieNodesMessage {
        GetTrieNodesMessage {
            request_id: 1,
            root_hash: B256::repeat_byte(0x11),
            paths: vec![
                vec![Bytes::from_static(&[0x00])],
                vec![
                    Bytes::from(B256::repeat_byte(0x22).to_vec()),
                    Bytes::from_static(&[0x00]),
                    Bytes::from_static(&[0x12]),
                ],
            ],
            response_bytes: 100,
        }
    }

    #[test]
    fn decodes_a_geth_get_trie_nodes_request() {
        let msg = Snap1Message::decode(&framed(0x06, GETH_GET_TRIE_NODES)).unwrap();
        assert_eq!(msg, Snap1Message::GetTrieNodes(geth_request()));
    }

    #[test]
    fn encodes_get_trie_nodes_as_geth_does() {
        let encoded = Snap1Message::GetTrieNodes(geth_request()).encode().unwrap();
        assert_eq!(encoded.as_ref(), framed(0x06, GETH_GET_TRIE_NODES).as_slice());
    }

    #[test]
    fn trie_nodes_keep_empty_entries_in_place() {
        let msg = Snap1Message::decode(&framed(0x07, GETH_TRIE_NODES)).unwrap();
        let expected = TrieNodesMessage {
            request_id: 1,
            nodes: vec![Bytes::new(), Bytes::from_static(&[0xc2, 0x80, 0x80])],
        };
        assert_eq!(msg, Snap1Message::TrieNodes(expected.clone()));
        assert_eq!(
            Snap1Message::TrieNodes(expected).encode().unwrap().as_ref(),
            framed(0x07, GETH_TRIE_NODES).as_slice()
        );
    }

    #[test]
    fn shared_messages_round_trip_with_their_snap2_ids() {
        let msg = Snap1Message::Shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
            request_id: 7,
            hashes: vec![B256::repeat_byte(0x33)],
            response_bytes: 4 << 20,
        }));
        let encoded = msg.encode().unwrap();
        assert_eq!(encoded[0], 0x04);
        assert_eq!(Snap1Message::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn rejects_ids_outside_snap1() {
        for id in [0x08u8, 0x09, 0x0a, 0xff] {
            assert!(matches!(
                Snap1Message::decode(&[id, 0xc0]),
                Err(Snap1Error::UnsupportedMessageId(got)) if got == id
            ));
        }
        assert!(matches!(Snap1Message::decode(&[]), Err(Snap1Error::Empty)));
    }

    #[test]
    fn refuses_to_encode_a_snap2_only_message() {
        let msg = Snap1Message::Shared(SnapProtocolMessage::GetBlockAccessLists(
            GetBlockAccessListsMessage { request_id: 1, block_hashes: vec![], response_bytes: 1 },
        ));
        assert!(matches!(msg.encode(), Err(Snap1Error::UnsupportedMessageId(0x08))));
    }

    /// Frames a `GetTrieNodes` whose path list payload is `sets`, as raw RLP.
    fn trie_nodes_frame(sets: &[u8]) -> Vec<u8> {
        use alloy_rlp::Header;
        let mut paths = Vec::new();
        Header { list: true, payload_length: sets.len() }.encode(&mut paths);
        paths.extend_from_slice(sets);
        let mut body = Vec::new();
        7u64.encode(&mut body);
        B256::repeat_byte(0x11).encode(&mut body);
        body.extend(paths);
        100u64.encode(&mut body);
        let mut out = vec![GET_TRIE_NODES_ID];
        Header { list: true, payload_length: body.len() }.encode(&mut out);
        out.extend(body);
        out
    }

    fn trie_request(bytes: &[u8]) -> GetTrieNodesMessage {
        match Snap1Message::decode(bytes).unwrap() {
            Snap1Message::GetTrieNodes(m) => m,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_frame_of_tiny_path_sets_keeps_only_the_sets_served() {
        // A full frame of `[0x80]` sets: about 65,000 on the wire.
        let sets: Vec<u8> = [0xc1, 0x80].repeat(64 * 1024 - 64);
        let msg = trie_request(&trie_nodes_frame(&sets));
        assert_eq!(msg.paths.len(), MAX_TRIE_NODE_LOOKUPS);
        assert!(msg.paths.iter().all(|set| set == &[Bytes::new()]));
        // The fields after the skipped sets still decode.
        assert_eq!((msg.request_id, msg.response_bytes), (7, 100));
        // Empty sets take no lookup, but serving reads only the first 1024 sets of any kind.
        let msg = trie_request(&trie_nodes_frame(&[0xc0].repeat(128 * 1024 - 64)));
        assert_eq!(msg.paths.len(), MAX_TRIE_NODE_LOOKUPS);
        assert!(msg.paths.iter().all(Vec::is_empty));
    }

    #[test]
    fn a_huge_storage_set_keeps_its_owner_and_the_lookup_cap() {
        let mut set = vec![0xa0];
        set.extend([0x22; 32]);
        set.extend([0x80].repeat(60_000));
        let mut sets = Vec::new();
        alloy_rlp::Header { list: true, payload_length: set.len() }.encode(&mut sets);
        sets.extend(set);
        // A set past the cap is skipped, even one that is not a list of strings.
        sets.extend([0xc2, 0xc1, 0x80]);
        let msg = trie_request(&trie_nodes_frame(&sets));
        assert_eq!(msg.paths.len(), 1);
        assert_eq!(msg.paths[0].len(), 1 + MAX_TRIE_NODE_LOOKUPS);
        assert_eq!(msg.paths[0][0], Bytes::from(vec![0x22; 32]));
    }

    #[test]
    fn a_path_set_that_is_not_a_list_is_rejected() {
        assert!(matches!(
            Snap1Message::decode(&trie_nodes_frame(&[0x80])),
            Err(Snap1Error::Rlp(alloy_rlp::Error::UnexpectedString))
        ));
        assert!(matches!(
            Snap1Message::decode(&trie_nodes_frame(&[0xc1, 0xc0])),
            Err(Snap1Error::Rlp(alloy_rlp::Error::UnexpectedList))
        ));
    }

    /// Frames a response `[request_id, lists..]` whose lists hold `counts` empty entries
    /// (`0x80`, or `0xc0` for the slot lists of `StorageRanges`).
    fn response_frame(id: u8, counts: &[usize]) -> Vec<u8> {
        use alloy_rlp::Header;
        let mut body = Vec::new();
        7u64.encode(&mut body);
        for (i, &count) in counts.iter().enumerate() {
            let entry = if id == 0x03 && i == 0 { 0xc0 } else { 0x80 };
            Header { list: true, payload_length: count }.encode(&mut body);
            body.extend(std::iter::repeat_n(entry, count));
        }
        let mut out = vec![id];
        Header { list: true, payload_length: body.len() }.encode(&mut out);
        out.extend(body);
        out
    }

    #[test]
    fn response_lists_past_their_cap_are_rejected_before_they_grow() {
        use crate::{MAX_BYTE_CODES_SERVE, MAX_STORAGE_RANGE_ACCOUNTS_SERVE};
        // Each one-byte entry would take 24 or 32 bytes once decoded. Lists: AccountRange
        // [accounts, proof], StorageRanges [slots, proof], ByteCodes [codes], TrieNodes [nodes].
        let p = MAX_RANGE_PROOF_NODES;
        let cases: [(u8, [usize; 2], [usize; 2]); 6] = [
            (0x01, [0, p], [0, p + 1]),
            (
                0x03,
                [MAX_STORAGE_RANGE_ACCOUNTS_SERVE, 0],
                [MAX_STORAGE_RANGE_ACCOUNTS_SERVE + 1, 0],
            ),
            (0x03, [0, p], [0, p + 1]),
            (0x05, [MAX_BYTE_CODES_SERVE, 0], [MAX_BYTE_CODES_SERVE + 1, 0]),
            (0x07, [MAX_TRIE_NODE_LOOKUPS, 0], [MAX_TRIE_NODE_LOOKUPS + 1, 0]),
            // A frame as large as reth-lite takes: 4 MiB of empty trie nodes.
            (0x07, [0, 0], [4 << 20, 0]),
        ];
        for (id, at_cap, past_cap) in cases {
            let lists = if matches!(id, 0x05 | 0x07) { 1 } else { 2 };
            let decoded = Snap1Message::decode(&response_frame(id, &at_cap[..lists]));
            assert!(decoded.is_ok(), "id {id:#x} at the cap: {decoded:?}");
            assert!(
                matches!(
                    Snap1Message::decode(&response_frame(id, &past_cap[..lists])),
                    Err(Snap1Error::Rlp(alloy_rlp::Error::Custom(TOO_MANY_ENTRIES)))
                ),
                "id {id:#x} past the cap"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = framed(0x07, GETH_TRIE_NODES);
        bytes.push(0x00);
        assert!(matches!(
            Snap1Message::decode(&bytes),
            Err(Snap1Error::Rlp(alloy_rlp::Error::UnexpectedLength))
        ));
    }

    mod props {
        use super::*;
        use alloy_primitives::{KECCAK256_EMPTY, U256};
        use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
        use proptest::{collection::vec, prelude::*};
        use reth_eth_wire_types::snap::{
            AccountData, AccountRangeMessage, ByteCodesMessage, GetAccountRangeMessage,
            GetStorageRangesMessage, RangeBound, StorageData, StorageRangesMessage,
        };

        fn b256() -> impl Strategy<Value = B256> {
            any::<[u8; 32]>().prop_map(B256::from)
        }

        fn bytes(max: usize) -> impl Strategy<Value = Bytes> + Clone {
            vec(any::<u8>(), 0..max).prop_map(Bytes::from)
        }

        fn bound() -> impl Strategy<Value = RangeBound> {
            proptest::option::of(b256()).prop_map(|b| b.map(RangeBound::from).unwrap_or_default())
        }

        fn account() -> impl Strategy<Value = AccountData> {
            let root = prop_oneof![Just(EMPTY_ROOT_HASH), b256()];
            let code = prop_oneof![Just(KECCAK256_EMPTY), b256()];
            (b256(), any::<u64>(), any::<[u8; 32]>(), root, code).prop_map(
                |(hash, nonce, balance, root, code)| {
                    let balance = U256::from_be_bytes(balance);
                    AccountData::from_trie_account(
                        hash,
                        &TrieAccount::new(nonce, balance, root, code),
                    )
                },
            )
        }

        /// Any message of the eight `snap/1` ids.
        fn message() -> impl Strategy<Value = Snap1Message> {
            let shared = |m| Snap1Message::Shared(m);
            prop_oneof![
                (any::<u64>(), b256(), b256(), b256(), any::<u64>()).prop_map(
                    move |(request_id, root_hash, starting_hash, limit_hash, response_bytes)| {
                        shared(SnapProtocolMessage::GetAccountRange(GetAccountRangeMessage {
                            request_id,
                            root_hash,
                            starting_hash,
                            limit_hash,
                            response_bytes,
                        }))
                    }
                ),
                (any::<u64>(), vec(account(), 0..4), vec(bytes(80), 0..4)).prop_map(
                    move |(request_id, accounts, proof)| {
                        shared(SnapProtocolMessage::AccountRange(AccountRangeMessage {
                            request_id,
                            accounts,
                            proof,
                        }))
                    }
                ),
                (any::<u64>(), b256(), vec(b256(), 0..4), bound(), bound(), any::<u64>()).prop_map(
                    move |(request_id, root_hash, account_hashes, start, limit, bytes)| {
                        shared(SnapProtocolMessage::GetStorageRanges(GetStorageRangesMessage {
                            request_id,
                            root_hash,
                            account_hashes,
                            starting_hash: start,
                            limit_hash: limit,
                            response_bytes: bytes,
                        }))
                    }
                ),
                (any::<u64>(), vec(vec((b256(), bytes(40)), 0..4), 0..4), vec(bytes(80), 0..4))
                    .prop_map(move |(request_id, slots, proof)| {
                        let slots = slots
                            .into_iter()
                            .map(|r| {
                                r.into_iter()
                                    .map(|(hash, data)| StorageData { hash, data })
                                    .collect()
                            })
                            .collect();
                        shared(SnapProtocolMessage::StorageRanges(StorageRangesMessage {
                            request_id,
                            slots,
                            proof,
                        }))
                    }),
                (any::<u64>(), vec(b256(), 0..4), any::<u64>()).prop_map(
                    move |(request_id, hashes, response_bytes)| {
                        shared(SnapProtocolMessage::GetByteCodes(GetByteCodesMessage {
                            request_id,
                            hashes,
                            response_bytes,
                        }))
                    }
                ),
                (any::<u64>(), vec(bytes(80), 0..4)).prop_map(move |(request_id, codes)| {
                    shared(SnapProtocolMessage::ByteCodes(ByteCodesMessage { request_id, codes }))
                }),
                (any::<u64>(), b256(), vec(vec(bytes(40), 0..4), 0..6), any::<u64>()).prop_map(
                    |(request_id, root_hash, paths, response_bytes)| {
                        Snap1Message::GetTrieNodes(GetTrieNodesMessage {
                            request_id,
                            root_hash,
                            paths,
                            response_bytes,
                        })
                    }
                ),
                (any::<u64>(), vec(bytes(80), 0..4)).prop_map(|(request_id, nodes)| {
                    Snap1Message::TrieNodes(TrieNodesMessage { request_id, nodes })
                }),
            ]
        }

        /// The lookups `serve_trie_nodes` reads from a path set.
        fn lookups(set: &TrieNodePathSet) -> usize {
            set.len().saturating_sub(usize::from(set.len() > 1))
        }

        /// Path sets mostly of a few paths, sometimes one far past the lookup cap.
        fn path_sets() -> impl Strategy<Value = Vec<TrieNodePathSet>> {
            let path = bytes(3);
            let set = prop_oneof![
                12 => vec(path.clone(), 0..4),
                1 => vec(path, 900..1100),
            ];
            vec(set, 0..1300)
        }

        /// Rewrites the frame with one top-level field inserted (a `u64`), removed or repeated
        /// at `at`, and the list header fixed up to match.
        fn edit_fields(frame: &[u8], (op, at, extra): (u8, prop::sample::Index, u64)) -> Vec<u8> {
            let (&id, mut body) = frame.split_first().unwrap();
            let mut payload = Header::decode_bytes(&mut body, true).unwrap();
            let mut fields = Vec::new();
            while !payload.is_empty() {
                let field = payload;
                let header = Header::decode(&mut payload).unwrap();
                payload = &payload[header.payload_length..];
                fields.push(field[..field.len() - payload.len()].to_vec());
            }
            let i = at.index(fields.len() + 1);
            match op {
                0 => fields.insert(i, alloy_rlp::encode(extra)),
                1 if i < fields.len() => drop(fields.remove(i)),
                _ if i < fields.len() => fields.insert(i, fields[i].clone()),
                _ => {}
            }
            let fields = fields.concat();
            let mut out = vec![id];
            Header { list: true, payload_length: fields.len() }.encode(&mut out);
            out.extend(fields);
            out
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Encoding then decoding gives back the message, and its id leads the frame.
            #[test]
            fn every_snap1_message_round_trips(msg in message()) {
                let encoded = msg.encode().unwrap();
                prop_assert_eq!(encoded[0], msg.message_id());
                let decoded = Snap1Message::decode(&encoded).unwrap();
                prop_assert_eq!(decoded.encode().unwrap(), encoded);
                prop_assert_eq!(decoded, msg);
            }

            /// A frame cut short or followed by one more byte is an RLP error, not a message.
            #[test]
            fn cut_and_extended_frames_are_rejected(msg in message(), extra in any::<u8>()) {
                let encoded = msg.encode().unwrap();
                for len in 1..encoded.len() {
                    let got = Snap1Message::decode(&encoded[..len]);
                    prop_assert!(
                        matches!(got, Err(Snap1Error::Rlp(alloy_rlp::Error::InputTooShort))),
                        "prefix of {} bytes: {:?}", len, got
                    );
                }
                let mut longer = encoded.to_vec();
                longer.push(extra);
                let got = Snap1Message::decode(&longer);
                prop_assert!(
                    matches!(got, Err(Snap1Error::Rlp(alloy_rlp::Error::UnexpectedLength))),
                    "{:?}", got
                );
            }

            /// Untrusted bytes never panic the decoder. A request it accepts is canonical: it
            /// encodes back to the same bytes. Inputs are valid frames with bytes overwritten
            /// or with a field added, dropped or repeated, so many get past the header checks.
            #[test]
            fn damaged_frames_never_panic_and_accepted_requests_are_canonical(
                msg in message(),
                edits in vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
                cut in any::<prop::sample::Index>(),
                field_edit in (0u8..3, any::<prop::sample::Index>(), any::<u64>()),
            ) {
                let frame = msg.encode().unwrap().to_vec();
                let mut bytes = frame.clone();
                for (at, value) in edits {
                    let at = at.index(bytes.len());
                    bytes[at] = value;
                }
                let len = cut.index(bytes.len() + 1);
                let reshaped = edit_fields(&frame, field_edit);
                for input in [&bytes[..], &bytes[..len], &bytes[1..], &reshaped[..]] {
                    // A frame under 1024 bytes holds fewer sets than the cap, so decoding
                    // drops nothing.
                    if let Ok(msg @ (Snap1Message::GetTrieNodes(_) |
                        Snap1Message::Shared(
                            SnapProtocolMessage::GetAccountRange(_) |
                            SnapProtocolMessage::GetStorageRanges(_) |
                            SnapProtocolMessage::GetByteCodes(_),
                        ))) = Snap1Message::decode(input)
                    {
                        let encoded = msg.encode().unwrap();
                        prop_assert_eq!(encoded.as_ref(), input);
                    }
                }
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Decoding keeps a prefix of the sets that holds at most the cap of sets and of
            /// lookups, and drops a set or a path only once a cap is reached.
            #[test]
            fn decoded_path_sets_are_the_capped_prefix(paths in path_sets()) {
                let sent = GetTrieNodesMessage {
                    request_id: 1,
                    root_hash: B256::ZERO,
                    paths,
                    response_bytes: 1,
                };
                let Snap1Message::GetTrieNodes(got) = Snap1Message::decode(
                    &Snap1Message::GetTrieNodes(sent.clone()).encode().unwrap(),
                )
                .unwrap() else {
                    panic!("not a GetTrieNodes")
                };
                prop_assert!(got.paths.len() <= MAX_TRIE_NODE_LOOKUPS);
                let total: usize = got.paths.iter().map(lookups).sum();
                prop_assert!(total <= MAX_TRIE_NODE_LOOKUPS, "{} lookups", total);
                let full = got.paths.len() == MAX_TRIE_NODE_LOOKUPS ||
                    total == MAX_TRIE_NODE_LOOKUPS;
                for (i, (kept, set)) in got.paths.iter().zip(&sent.paths).enumerate() {
                    prop_assert!(set.starts_with(kept), "set {} is not a prefix", i);
                    prop_assert!(kept == set || (full && i + 1 == got.paths.len()), "set {} cut", i);
                }
                prop_assert!(got.paths.len() == sent.paths.len() || full);
                prop_assert_eq!(
                    (got.request_id, got.response_bytes),
                    (sent.request_id, sent.response_bytes)
                );
            }
        }
    }
}
