//! Untrusted bytes into the `snap/1` frame decoder, as the connection hands it every frame.
//!
//! Invariants:
//! - A frame that decodes re-encodes, and that encoding decodes to the same message.
//! - The decoded id is the frame's id, and a decoded request is canonical: it encodes back to the
//!   same bytes, unless `GetTrieNodes` dropped path sets serving never reads.
//! - A decoded frame cut by one byte, or with one byte added, does not decode.
//! - `GetTrieNodes` keeps at most the serving caps of sets and lookups, and agrees with a plain
//!   derived decode, cut to what serving reads, wherever that decode succeeds.
//!
//! Raw bytes seldom form a frame with more than a thousand sets, so each input is also read as
//! the parts of a `GetTrieNodes` frame with repeated sets, and that frame is checked the same way.

#![no_main]

use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, Encodable, Header, RlpDecodable};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use reth_eth_wire_types::snap::SnapProtocolMessage;
use reth_pulsechain_snap::{
    fuzz_api::reply_budget, protocol::MAX_FRAME_BYTES, Snap1Message, TrieNodePathSet,
    MAX_TRIE_NODE_LOOKUPS, SOFT_RESPONSE_LIMIT,
};

/// `GetTrieNodes` as a plain derive decodes it, with every path set kept.
#[derive(Debug, RlpDecodable)]
struct PlainGetTrieNodes {
    request_id: u64,
    root_hash: B256,
    paths: Vec<Vec<Bytes>>,
    response_bytes: u64,
}

/// The lookups serving reads from a set: one for an account path, one per path after the owner.
fn lookups(set: &TrieNodePathSet) -> usize {
    set.len().saturating_sub(usize::from(set.len() > 1))
}

/// The part of `paths` serving reads: the first sets up to the cap, stopping once the lookups
/// reach the cap, with the last set cut to the lookups left.
fn served_prefix(paths: &[TrieNodePathSet]) -> Vec<TrieNodePathSet> {
    let mut out = Vec::new();
    let mut taken = 0;
    for set in paths {
        if out.len() >= MAX_TRIE_NODE_LOOKUPS || taken >= MAX_TRIE_NODE_LOOKUPS {
            break
        }
        let kept = set[..set.len().min(MAX_TRIE_NODE_LOOKUPS - taken + 1)].to_vec();
        taken += lookups(&kept);
        out.push(kept);
    }
    out
}

fn plain_get_trie_nodes(data: &[u8]) -> Option<PlainGetTrieNodes> {
    let (&0x06, mut body) = data.split_first()? else { return None };
    let msg = PlainGetTrieNodes::decode(&mut body).ok()?;
    body.is_empty().then_some(msg)
}

const fn is_request(msg: &Snap1Message) -> bool {
    matches!(
        msg,
        Snap1Message::GetTrieNodes(_) |
            Snap1Message::Shared(
                SnapProtocolMessage::GetAccountRange(_) |
                    SnapProtocolMessage::GetStorageRanges(_) |
                    SnapProtocolMessage::GetByteCodes(_)
            )
    )
}

/// One path set of a built frame: strings, or any bytes as the payload of a list.
#[derive(Arbitrary, Debug)]
enum SetPart {
    Strings(Vec<Vec<u8>>, u16),
    Raw(Vec<u8>),
}

/// The parts of a `GetTrieNodes` frame whose last set repeats.
#[derive(Arbitrary, Debug)]
struct FrameParts {
    request_id: u64,
    root_hash: [u8; 32],
    sets: Vec<SetPart>,
    repeat_last: u16,
    response_bytes: u64,
}

fn list(payload: &[u8], out: &mut Vec<u8>) {
    Header { list: true, payload_length: payload.len() }.encode(out);
    out.extend_from_slice(payload);
}

impl FrameParts {
    fn frame(&self) -> Vec<u8> {
        let mut sets = Vec::new();
        let mut last = Vec::new();
        for set in &self.sets {
            last.clear();
            match set {
                SetPart::Strings(strings, repeat) => {
                    let mut payload = Vec::new();
                    for s in strings {
                        s.as_slice().encode(&mut payload);
                    }
                    if let Some(s) = strings.last() {
                        for _ in 0..*repeat % 1100 {
                            s.as_slice().encode(&mut payload);
                        }
                    }
                    list(&payload, &mut last);
                }
                SetPart::Raw(payload) => list(payload, &mut last),
            }
            sets.extend_from_slice(&last);
        }
        let copies = (self.repeat_last as usize % 1300).min(MAX_FRAME_BYTES / last.len().max(1));
        for _ in 0..copies {
            sets.extend_from_slice(&last);
        }
        let mut body = Vec::new();
        self.request_id.encode(&mut body);
        B256::from(self.root_hash).encode(&mut body);
        list(&sets, &mut body);
        self.response_bytes.encode(&mut body);
        let mut out = vec![0x06];
        list(&body, &mut out);
        out
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    if let Ok(parts) = FrameParts::arbitrary_take_rest(Unstructured::new(data)) {
        check(&parts.frame());
    }
});

fn check(data: &[u8]) {
    // The connection drops larger frames before decoding.
    if data.len() > MAX_FRAME_BYTES {
        return
    }
    let plain = plain_get_trie_nodes(data);
    let msg = match Snap1Message::decode(data) {
        Ok(msg) => msg,
        Err(err) => {
            assert!(plain.is_none(), "the plain derive decodes what snap/1 rejects: {err}");
            return
        }
    };
    assert_eq!(msg.message_id(), data[0]);
    assert!(reply_budget(&msg) <= SOFT_RESPONSE_LIMIT);

    let encoded = msg.encode().expect("a decoded message encodes");
    let again = Snap1Message::decode(&encoded).expect("an encoded message decodes");
    assert_eq!(again, msg);
    assert_eq!(again.encode().unwrap(), encoded);

    let mut dropped = false;
    if let Snap1Message::GetTrieNodes(req) = &msg {
        assert!(req.paths.len() <= MAX_TRIE_NODE_LOOKUPS, "{} sets kept", req.paths.len());
        let total: usize = req.paths.iter().map(lookups).sum();
        assert!(total <= MAX_TRIE_NODE_LOOKUPS, "{total} lookups kept");
        if let Some(plain) = &plain {
            assert_eq!(
                (plain.request_id, plain.root_hash, plain.response_bytes),
                (req.request_id, req.root_hash, req.response_bytes)
            );
            assert_eq!(req.paths, served_prefix(&plain.paths));
            dropped = req.paths != plain.paths;
        } else {
            // Only what lies past a cap is checked by header alone, so the plain derive can
            // fail only when a cap was reached.
            assert!(
                req.paths.len() == MAX_TRIE_NODE_LOOKUPS || total == MAX_TRIE_NODE_LOOKUPS,
                "accepted a request the plain derive rejects, below the caps"
            );
            dropped = true;
        }
    }
    if is_request(&msg) && !dropped {
        assert_eq!(encoded.as_ref(), data, "a request decoded from non-canonical bytes");
    }

    assert!(Snap1Message::decode(&data[..data.len() - 1]).is_err(), "a cut frame decodes");
    let mut longer = data.to_vec();
    longer.push(0);
    assert!(Snap1Message::decode(&longer).is_err(), "a frame with a trailing byte decodes");
}
