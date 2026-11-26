//! A small SSZ merkleizer that a type schema drives over serialized bytes.
//!
//! It computes `hash_tree_root` without decoding values into structs, so a 19 MB `BeaconState`
//! is hashed in place. It checks the bytes while it hashes them: lengths, offsets, limits,
//! booleans and bitfield padding. Each list limit is a `u64` and each list is padded up to its
//! limit with zero hashes, so no tree size ever needs a `usize` wider than the input.

use crate::sync_committee::hash_pair;
use alloy_primitives::B256;
use std::sync::LazyLock;
use tree_hash::{merkle_root, mix_in_length};

/// The size of an SSZ offset.
const OFFSET_LEN: usize = 4;

/// The size of a Merkle chunk.
const CHUNK_LEN: usize = 32;

/// The bits in a Merkle chunk.
const CHUNK_BITS: u64 = 256;

/// An SSZ type.
///
/// A schema has no zero-size type: SSZ has no empty container and no vector of length 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SszType {
    /// `uintN`, of this many bytes: 1, 2, 4, 8, 16 or 32.
    Uint(usize),
    /// `boolean`.
    Boolean,
    /// `ByteVector[N]`, also named `BytesN`.
    Bytes(usize),
    /// `ByteList[N]`.
    ByteList(u64),
    /// `Bitvector[N]`.
    Bitvector(usize),
    /// `Bitlist[N]`.
    Bitlist(u64),
    /// `Vector[T, N]`.
    Vector(Box<Self>, usize),
    /// `List[T, N]`.
    List(Box<Self>, u64),
    /// A container.
    Container(Container),
}

/// An SSZ container: its field types, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    fields: Vec<SszType>,
}

/// Why serialized bytes do not fit their SSZ type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SszError {
    /// A fixed-size value has the wrong length.
    #[error("expected {expected} bytes, got {got}")]
    WrongLength {
        /// The size of the type.
        expected: usize,
        /// The size of the input.
        got: usize,
    },
    /// A variable-size value is shorter than its fixed part.
    #[error("expected at least {need} bytes, got {got}")]
    Truncated {
        /// The size of the fixed part.
        need: usize,
        /// The size of the input.
        got: usize,
    },
    /// An offset is outside the range that the offsets before it allow.
    #[error("offset {offset} is outside {min}..={max}")]
    BadOffset {
        /// The offset.
        offset: usize,
        /// The lowest offset allowed here.
        min: usize,
        /// The highest offset allowed here.
        max: usize,
    },
    /// The first offset of a list of variable-size items is not a whole number of offsets.
    #[error("the first offset {0} is not a positive multiple of 4")]
    MisalignedOffset(usize),
    /// The bytes of a list of fixed-size items end inside an item.
    #[error("{len} bytes are not a whole number of {item}-byte items")]
    PartialItem {
        /// The size of the list.
        len: usize,
        /// The size of one item.
        item: usize,
    },
    /// A list or byte list has more items than its limit.
    #[error("{len} items exceed the limit of {limit}")]
    TooLong {
        /// The number of items.
        len: u64,
        /// The limit of the type.
        limit: u64,
    },
    /// A boolean byte is neither 0 nor 1.
    #[error("boolean byte {0} is not 0 or 1")]
    InvalidBoolean(u8),
    /// A bitvector has a bit set after its length.
    #[error("a bitvector has a bit set after its length")]
    BitvectorPadding,
    /// A bitlist has no delimiter bit: it is empty or its last byte is zero.
    #[error("a bitlist has no delimiter bit")]
    NoBitlistDelimiter,
}

impl SszType {
    /// Returns the serialized size of a fixed-size type, or `None` for a variable-size type.
    pub fn fixed_len(&self) -> Option<usize> {
        match self {
            Self::Uint(len) | Self::Bytes(len) => Some(*len),
            Self::Boolean => Some(1),
            Self::Bitvector(bits) => Some(bits.div_ceil(8)),
            Self::Vector(item, len) => item.fixed_len().map(|item| item * len),
            Self::Container(container) => container.fixed_len(),
            Self::ByteList(_) | Self::Bitlist(_) | Self::List(..) => None,
        }
    }

    /// Returns `hash_tree_root` of `bytes` as this type, after it checks them.
    pub fn hash_tree_root(&self, bytes: &[u8]) -> Result<B256, SszError> {
        match self {
            Self::Uint(len) | Self::Bytes(len) => {
                expect_len(bytes, *len)?;
                Ok(merkleize(bytes, 0))
            }
            Self::Boolean => {
                expect_len(bytes, 1)?;
                check_booleans(bytes)?;
                Ok(merkleize(bytes, 0))
            }
            Self::ByteList(limit) => {
                check_limit(bytes.len(), *limit)?;
                Ok(mix_in_length(&merkleize(bytes, limit.div_ceil(CHUNK_LEN as u64)), bytes.len()))
            }
            Self::Bitvector(bits) => {
                expect_len(bytes, bits.div_ceil(8))?;
                let used = bits % 8;
                if used != 0 && bytes[bytes.len() - 1] >> used != 0 {
                    return Err(SszError::BitvectorPadding);
                }
                Ok(merkleize(bytes, 0))
            }
            Self::Bitlist(limit) => {
                let (&last, _) = bytes.split_last().ok_or(SszError::NoBitlistDelimiter)?;
                if last == 0 {
                    return Err(SszError::NoBitlistDelimiter);
                }
                // The highest set bit of the last byte is the delimiter, not a bit of the list.
                let delimiter = 7 - last.leading_zeros() as usize;
                let len = (bytes.len() - 1) * 8 + delimiter;
                check_limit(len, *limit)?;
                // The data is `len` bits: a delimiter alone in the last byte drops that byte.
                let mut bits = bytes[..len.div_ceil(8)].to_vec();
                if let Some(last) = bits.get_mut(bytes.len() - 1) {
                    *last ^= 1 << delimiter;
                }
                Ok(mix_in_length(&merkleize(&bits, limit.div_ceil(CHUNK_BITS)), len))
            }
            Self::Vector(item, len) => {
                if let Some(size) = item.basic_len() {
                    expect_len(bytes, size * len)?;
                    if **item == Self::Boolean {
                        check_booleans(bytes)?;
                    }
                    return Ok(merkleize(bytes, 0));
                }
                let items = match item.fixed_len() {
                    Some(size) => {
                        expect_len(bytes, size * len)?;
                        bytes.chunks_exact(size).collect()
                    }
                    None => split(bytes, &vec![None; *len])?,
                };
                Ok(merkleize(&item.item_roots(&items)?, *len as u64))
            }
            Self::List(item, limit) => {
                if let Some(size) = item.basic_len() {
                    let len = whole_items(bytes, size)?;
                    check_limit(len, *limit)?;
                    if **item == Self::Boolean {
                        check_booleans(bytes)?;
                    }
                    let chunks = (limit * size as u64).div_ceil(CHUNK_LEN as u64);
                    return Ok(mix_in_length(&merkleize(bytes, chunks), len));
                }
                let items = match item.fixed_len() {
                    Some(size) => {
                        check_limit(whole_items(bytes, size)?, *limit)?;
                        bytes.chunks_exact(size).collect()
                    }
                    None => {
                        let len = offset_count(bytes)?;
                        check_limit(len, *limit)?;
                        split(bytes, &vec![None; len])?
                    }
                };
                Ok(mix_in_length(&merkleize(&item.item_roots(&items)?, *limit), items.len()))
            }
            Self::Container(container) => container.hash_tree_root(bytes),
        }
    }

    /// Returns the size of a basic type, which packs into chunks, or `None` for a composite type.
    const fn basic_len(&self) -> Option<usize> {
        match self {
            Self::Uint(len) => Some(*len),
            Self::Boolean => Some(1),
            _ => None,
        }
    }

    /// Returns the concatenated roots of `items` of this type.
    fn item_roots(&self, items: &[&[u8]]) -> Result<Vec<u8>, SszError> {
        let mut roots = Vec::with_capacity(items.len() * CHUNK_LEN);
        for item in items {
            roots.extend_from_slice(self.hash_tree_root(item)?.as_slice());
        }
        Ok(roots)
    }
}

impl Container {
    /// Returns a container with these field types.
    pub const fn new(fields: Vec<SszType>) -> Self {
        Self { fields }
    }

    /// Returns the field types.
    pub fn fields(&self) -> &[SszType] {
        &self.fields
    }

    /// Splits `bytes` into the serialized fields, after it checks the lengths and offsets.
    ///
    /// It does not check the fields' contents; [`Self::field_roots`] does.
    pub fn split<'a>(&self, bytes: &'a [u8]) -> Result<Vec<&'a [u8]>, SszError> {
        let sizes: Vec<Option<usize>> = self.fields.iter().map(SszType::fixed_len).collect();
        split(bytes, &sizes)
    }

    /// Returns `hash_tree_root` of each field of `bytes`, in order, after it checks them.
    pub fn field_roots(&self, bytes: &[u8]) -> Result<Vec<B256>, SszError> {
        let fields = self.split(bytes)?;
        self.fields.iter().zip(fields).map(|(ty, field)| ty.hash_tree_root(field)).collect()
    }

    /// Returns `hash_tree_root` of `bytes` as this container, after it checks them.
    pub fn hash_tree_root(&self, bytes: &[u8]) -> Result<B256, SszError> {
        self.field_roots(bytes).map(|roots| container_root(&roots))
    }

    fn fixed_len(&self) -> Option<usize> {
        self.fields.iter().map(SszType::fixed_len).sum()
    }
}

/// Splits `bytes` into parts of these sizes, where `None` is a variable-size part that an offset
/// in the fixed part locates. The last variable-size part runs to the end of `bytes`.
fn split<'a>(bytes: &'a [u8], sizes: &[Option<usize>]) -> Result<Vec<&'a [u8]>, SszError> {
    let fixed: usize = sizes.iter().map(|size| size.unwrap_or(OFFSET_LEN)).sum();
    if sizes.iter().all(Option::is_some) {
        expect_len(bytes, fixed)?;
    } else if bytes.len() < fixed {
        return Err(SszError::Truncated { need: fixed, got: bytes.len() });
    }

    let mut parts = Vec::with_capacity(sizes.len());
    // The variable-size parts: their index in `parts` and their offset.
    let mut variable = Vec::new();
    let mut position = 0;
    for size in sizes {
        match size {
            Some(size) => {
                parts.push(&bytes[position..position + size]);
                position += size;
            }
            None => {
                let offset = read_offset(bytes, position)?;
                // The first offset ends the fixed part. Each later one starts at or after the one
                // before it.
                let (min, max) = match variable.last() {
                    None => (fixed, fixed),
                    Some(&(_, previous)) => (previous, bytes.len()),
                };
                if offset < min || offset > max {
                    return Err(SszError::BadOffset { offset, min, max });
                }
                variable.push((parts.len(), offset));
                parts.push(&[]);
                position += OFFSET_LEN;
            }
        }
    }
    let ends = variable.iter().skip(1).map(|&(_, offset)| offset).chain([bytes.len()]);
    for (&(index, start), end) in variable.iter().zip(ends) {
        parts[index] = &bytes[start..end];
    }
    Ok(parts)
}

/// Returns the number of variable-size items in a list's `bytes`: the first offset ends the
/// offsets, so it counts them.
///
/// The count is at most a quarter of the input, so a caller can allocate for it.
pub(crate) fn offset_count(bytes: &[u8]) -> Result<usize, SszError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let first = read_offset(bytes, 0)?;
    if first == 0 || !first.is_multiple_of(OFFSET_LEN) {
        return Err(SszError::MisalignedOffset(first));
    }
    if first > bytes.len() {
        return Err(SszError::Truncated { need: first, got: bytes.len() });
    }
    Ok(first / OFFSET_LEN)
}

/// Reads the little-endian offset at `position`.
fn read_offset(bytes: &[u8], position: usize) -> Result<usize, SszError> {
    let offset = bytes
        .get(position..position + OFFSET_LEN)
        .ok_or(SszError::Truncated { need: position + OFFSET_LEN, got: bytes.len() })?;
    let offset = u32::from_le_bytes(offset.try_into().expect("an offset is 4 bytes"));
    Ok(usize::try_from(offset).expect("a u32 fits in usize"))
}

/// The root of a tree of zero chunks at each depth from 0 to 64.
static ZERO_HASHES: LazyLock<[B256; 65]> = LazyLock::new(|| {
    let mut zeros = [B256::ZERO; 65];
    for depth in 1..zeros.len() {
        zeros[depth] = hash_pair(&zeros[depth - 1], &zeros[depth - 1]);
    }
    zeros
});

/// Returns the root of `chunks` (packed values, or concatenated roots) in a tree with room for
/// `limit` chunks, or exactly enough room when `limit` is 0.
///
/// The tree above the chunks is zero hashes, so a large limit costs one hash per level, and an
/// empty list none.
fn merkleize(chunks: &[u8], limit: u64) -> B256 {
    let target = ceil_log2(limit) as usize;
    if chunks.is_empty() {
        return ZERO_HASHES[target];
    }
    let mut depth = ceil_log2(chunks.len().div_ceil(CHUNK_LEN) as u64) as usize;
    let mut root = merkle_root(chunks, 0);
    while depth < target {
        root = hash_pair(&root, &ZERO_HASHES[depth]);
        depth += 1;
    }
    root
}

/// Returns the depth of the smallest tree with at least `leaves` leaves.
const fn ceil_log2(leaves: u64) -> u32 {
    if leaves <= 1 {
        0
    } else {
        u64::BITS - (leaves - 1).leading_zeros()
    }
}

const fn expect_len(bytes: &[u8], expected: usize) -> Result<(), SszError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(SszError::WrongLength { expected, got: bytes.len() })
    }
}

/// Returns the number of `item`-byte items in `bytes`.
const fn whole_items(bytes: &[u8], item: usize) -> Result<usize, SszError> {
    if bytes.len().is_multiple_of(item) {
        Ok(bytes.len() / item)
    } else {
        Err(SszError::PartialItem { len: bytes.len(), item })
    }
}

const fn check_limit(len: usize, limit: u64) -> Result<(), SszError> {
    let len = len as u64;
    if len <= limit {
        Ok(())
    } else {
        Err(SszError::TooLong { len, limit })
    }
}

fn check_booleans(bytes: &[u8]) -> Result<(), SszError> {
    match bytes.iter().find(|&&byte| byte > 1) {
        Some(&byte) => Err(SszError::InvalidBoolean(byte)),
        None => Ok(()),
    }
}

/// Returns the root of a container, or of a vector of roots, with these field roots in order.
pub fn container_root(field_roots: &[B256]) -> B256 {
    merkle_root(&field_roots.concat(), field_roots.len())
}

/// Returns the Merkle branch that proves field `index` into [`container_root`] of `field_roots`,
/// from the leaf's sibling up.
///
/// # Panics
///
/// If `index` is not a field.
pub fn field_branch(field_roots: &[B256], index: usize) -> Vec<B256> {
    assert!(index < field_roots.len(), "field {index} of {} does not exist", field_roots.len());
    let mut level = field_roots.to_vec();
    level.resize(field_roots.len().next_power_of_two(), B256::ZERO);
    let mut index = index;
    let mut branch = Vec::new();
    while level.len() > 1 {
        branch.push(level[index ^ 1]);
        level =
            level.as_chunks::<2>().0.iter().map(|[left, right]| hash_pair(left, right)).collect();
        index /= 2;
    }
    branch
}

/// Returns the generalized index of field `index` in a container of `field_count` fields.
pub const fn field_gindex(field_count: usize, index: usize) -> u64 {
    (field_count.next_power_of_two() + index) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_committee::is_valid_merkle_branch;
    use tree_hash::TreeHash;

    fn list(item: SszType, limit: u64) -> SszType {
        SszType::List(Box::new(item), limit)
    }

    fn vector(item: SszType, len: usize) -> SszType {
        SszType::Vector(Box::new(item), len)
    }

    /// `{a: uint64, b: List[uint16, 4], c: Bytes4, d: ByteList[8]}`, with two offsets.
    fn two_offsets() -> Container {
        Container::new(vec![
            SszType::Uint(8),
            list(SszType::Uint(2), 4),
            SszType::Bytes(4),
            SszType::ByteList(8),
        ])
    }

    /// `two_offsets` with `a` 7, `b` [1, 2], `c` 0xaabbccdd and `d` [9, 9, 9].
    fn two_offsets_bytes() -> Vec<u8> {
        let mut bytes = 7u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&20u32.to_le_bytes());
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        bytes.extend_from_slice(&24u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 0, 2, 0]);
        bytes.extend_from_slice(&[9, 9, 9]);
        bytes
    }

    fn with_offset(mut bytes: Vec<u8>, at: usize, offset: u32) -> Vec<u8> {
        bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        bytes
    }

    #[test]
    fn basic_values_hash_as_tree_hash_does() {
        let cases: [(SszType, Vec<u8>, B256); 5] = [
            (SszType::Uint(8), 77u64.to_le_bytes().to_vec(), 77u64.tree_hash_root()),
            (SszType::Boolean, vec![1], true.tree_hash_root()),
            (SszType::Bytes(4), vec![1, 2, 3, 4], [1u8, 2, 3, 4].tree_hash_root()),
            (
                vector(SszType::Uint(8), 5),
                (1..=5u64).flat_map(u64::to_le_bytes).collect(),
                merkle_root(&(1..=5u64).flat_map(u64::to_le_bytes).collect::<Vec<_>>(), 0),
            ),
            (SszType::Bytes(48), vec![5; 48], merkle_root(&[5; 48], 2)),
        ];
        for (ty, bytes, root) in cases {
            assert_eq!(ty.hash_tree_root(&bytes), Ok(root), "{ty:?}");
        }
    }

    #[test]
    fn lists_mix_in_their_length_and_pad_to_their_limit() {
        // List[uint64, 8]: 2 chunks of room, 1 used.
        let items: Vec<u8> = [3u64, 4].into_iter().flat_map(u64::to_le_bytes).collect();
        let expected = mix_in_length(&merkle_root(&items, 2), 2);
        assert_eq!(list(SszType::Uint(8), 8).hash_tree_root(&items), Ok(expected));

        // An empty list of 2^40 roots: the zero hash at depth 40, then the length 0.
        let mut zero = B256::ZERO;
        for _ in 0..40 {
            zero = hash_pair(&zero, &zero);
        }
        assert_eq!(
            list(SszType::Bytes(32), 1 << 40).hash_tree_root(&[]),
            Ok(mix_in_length(&zero, 0))
        );

        // ByteList[2^30] of 3 bytes: one chunk in a tree of 2^25.
        let mut root = merkle_root(&[1, 2, 3], 0);
        let mut zero = B256::ZERO;
        for _ in 0..25 {
            root = hash_pair(&root, &zero);
            zero = hash_pair(&zero, &zero);
        }
        assert_eq!(
            SszType::ByteList(1 << 30).hash_tree_root(&[1, 2, 3]),
            Ok(mix_in_length(&root, 3))
        );
    }

    #[test]
    fn bitfields_hash_without_their_delimiter() {
        // Bitlist[2048] with bits 1, 0, 1: the delimiter is bit 3.
        let expected = mix_in_length(&merkle_root(&[0b0101], 8), 3);
        assert_eq!(SszType::Bitlist(2048).hash_tree_root(&[0b1101]), Ok(expected));
        // An empty bitlist is the delimiter alone.
        assert_eq!(
            SszType::Bitlist(2048).hash_tree_root(&[1]),
            Ok(mix_in_length(&merkle_root(&[], 8), 0))
        );
        assert_eq!(SszType::Bitvector(4).hash_tree_root(&[0b1010]), Ok(merkle_root(&[0b1010], 0)));
        // A full Bitlist[2048]: the delimiter is alone in the 257th byte, which is not data.
        let mut full = vec![0xff; 256];
        full.push(1);
        let expected = mix_in_length(&merkle_root(&[0xff; 256], 8), 2048);
        assert_eq!(SszType::Bitlist(2048).hash_tree_root(&full), Ok(expected));
        // A full Bitlist[256] in a tree of one chunk.
        let mut full = vec![0xff; 32];
        full.push(1);
        let expected = mix_in_length(&merkle_root(&[0xff; 32], 1), 256);
        assert_eq!(SszType::Bitlist(256).hash_tree_root(&full), Ok(expected));
    }

    #[test]
    fn a_container_splits_at_its_offsets() {
        let bytes = two_offsets_bytes();
        let fields = two_offsets().split(&bytes).unwrap();
        assert_eq!(
            fields,
            [&7u64.to_le_bytes()[..], &[1, 0, 2, 0], &[0xaa, 0xbb, 0xcc, 0xdd], &[9, 9, 9]]
        );
        let roots = two_offsets().field_roots(&bytes).unwrap();
        assert_eq!(roots[0], 7u64.tree_hash_root());
        assert_eq!(roots[1], mix_in_length(&merkle_root(&[1, 0, 2, 0], 1), 2));
        assert_eq!(roots[3], mix_in_length(&merkle_root(&[9, 9, 9], 1), 3));
        assert_eq!(two_offsets().hash_tree_root(&bytes), Ok(merkle_root(&roots.concat(), 4)));
    }

    #[test]
    fn bad_offsets_are_refused() {
        let bytes = two_offsets_bytes();
        // The first offset must end the fixed part exactly.
        assert_eq!(
            two_offsets().split(&with_offset(bytes.clone(), 8, 21)),
            Err(SszError::BadOffset { offset: 21, min: 20, max: 20 })
        );
        // Offsets must not decrease.
        assert_eq!(
            two_offsets().split(&with_offset(bytes.clone(), 16, 19)),
            Err(SszError::BadOffset { offset: 19, min: 20, max: 27 })
        );
        // Offsets must stay inside the input.
        assert_eq!(
            two_offsets().split(&with_offset(bytes, 16, 28)),
            Err(SszError::BadOffset { offset: 28, min: 20, max: 27 })
        );
    }

    #[test]
    fn variable_size_items_split_at_their_offsets() {
        let ty = list(SszType::ByteList(4), 3);
        // Two items, [5] and [6, 7], after two offsets.
        let bytes = [8, 0, 0, 0, 9, 0, 0, 0, 5, 6, 7];
        let item = |b: &[u8]| SszType::ByteList(4).hash_tree_root(b).unwrap();
        let expected = mix_in_length(&merkle_root(&[item(&[5]), item(&[6, 7])].concat(), 3), 2);
        assert_eq!(ty.hash_tree_root(&bytes), Ok(expected));
        assert_eq!(ty.hash_tree_root(&[]), Ok(mix_in_length(&merkle_root(&[], 3), 0)));

        assert_eq!(ty.hash_tree_root(&[6, 0, 0, 0, 0, 0]), Err(SszError::MisalignedOffset(6)));
        assert_eq!(ty.hash_tree_root(&[0, 0, 0, 0]), Err(SszError::MisalignedOffset(0)));
        assert_eq!(ty.hash_tree_root(&[8, 0, 0]), Err(SszError::Truncated { need: 4, got: 3 }));
        // Two offsets do not fit in four bytes.
        assert_eq!(ty.hash_tree_root(&[8, 0, 0, 0]), Err(SszError::Truncated { need: 8, got: 4 }));
        // A first offset past the end is refused before the offsets are counted against the
        // limit, so it allocates nothing.
        let transactions = list(SszType::ByteList(1 << 30), 1 << 20);
        assert_eq!(
            transactions.hash_tree_root(&[0xfc, 0xff, 0xff, 0xff]),
            Err(SszError::Truncated { need: 0xffff_fffc, got: 4 })
        );
        // Four offsets exceed the limit of 3 before the later ones are read.
        let mut four = [0; 16];
        four[0] = 16;
        assert_eq!(ty.hash_tree_root(&four), Err(SszError::TooLong { len: 4, limit: 3 }));
        // A vector of variable-size items needs exactly its length in offsets.
        let pair = vector(SszType::ByteList(4), 2);
        assert_eq!(
            pair.hash_tree_root(&bytes),
            Ok(merkle_root(&[item(&[5]), item(&[6, 7])].concat(), 2))
        );
        assert_eq!(
            vector(SszType::ByteList(4), 1).hash_tree_root(&bytes),
            Err(SszError::BadOffset { offset: 8, min: 4, max: 4 })
        );
    }

    #[test]
    fn truncated_input_is_refused() {
        let bytes = two_offsets_bytes();
        assert_eq!(
            two_offsets().split(&bytes[..19]),
            Err(SszError::Truncated { need: 20, got: 19 })
        );
        // Cutting the last byte list is not visible to the split, but cutting into `b` is.
        assert_eq!(
            two_offsets().field_roots(&bytes[..23]),
            Err(SszError::BadOffset { offset: 24, min: 20, max: 23 })
        );
        let header = Container::new(vec![SszType::Uint(8); 2]);
        assert_eq!(header.split(&[0; 15]), Err(SszError::WrongLength { expected: 16, got: 15 }));
        assert_eq!(
            SszType::Uint(8).hash_tree_root(&[0; 7]),
            Err(SszError::WrongLength { expected: 8, got: 7 })
        );
        assert_eq!(
            list(SszType::Uint(8), 4).hash_tree_root(&[0; 12]),
            Err(SszError::PartialItem { len: 12, item: 8 })
        );
        assert_eq!(
            vector(SszType::Bytes(32), 2).hash_tree_root(&[0; 63]),
            Err(SszError::WrongLength { expected: 64, got: 63 })
        );
    }

    #[test]
    fn oversized_input_is_refused() {
        let header = Container::new(vec![SszType::Uint(8); 2]);
        assert_eq!(header.split(&[0; 17]), Err(SszError::WrongLength { expected: 16, got: 17 }));
        assert_eq!(
            SszType::Bytes(4).hash_tree_root(&[0; 5]),
            Err(SszError::WrongLength { expected: 4, got: 5 })
        );
        assert_eq!(
            list(SszType::Uint(8), 2).hash_tree_root(&[0; 24]),
            Err(SszError::TooLong { len: 3, limit: 2 })
        );
        assert_eq!(
            SszType::ByteList(2).hash_tree_root(&[0; 3]),
            Err(SszError::TooLong { len: 3, limit: 2 })
        );
        // Bitlist[4] with five bits.
        assert_eq!(
            SszType::Bitlist(4).hash_tree_root(&[0b10_0000]),
            Err(SszError::TooLong { len: 5, limit: 4 })
        );
        // A container's last list takes the extra bytes, and its limit refuses them.
        let mut bytes = two_offsets_bytes();
        bytes.extend_from_slice(&[9; 6]);
        assert_eq!(two_offsets().field_roots(&bytes), Err(SszError::TooLong { len: 9, limit: 8 }));
    }

    #[test]
    fn malformed_basic_values_and_bitfields_are_refused() {
        assert_eq!(SszType::Boolean.hash_tree_root(&[2]), Err(SszError::InvalidBoolean(2)));
        assert_eq!(
            list(SszType::Boolean, 4).hash_tree_root(&[1, 0, 3]),
            Err(SszError::InvalidBoolean(3))
        );
        assert_eq!(
            SszType::Bitvector(4).hash_tree_root(&[0b1_0000]),
            Err(SszError::BitvectorPadding)
        );
        assert_eq!(
            SszType::Bitvector(12).hash_tree_root(&[0]),
            Err(SszError::WrongLength { expected: 2, got: 1 })
        );
        assert_eq!(SszType::Bitlist(8).hash_tree_root(&[]), Err(SszError::NoBitlistDelimiter));
        assert_eq!(SszType::Bitlist(16).hash_tree_root(&[1, 0]), Err(SszError::NoBitlistDelimiter));
    }

    #[test]
    fn field_branches_prove_each_field() {
        for count in [1, 2, 3, 5, 8, 28] {
            let roots: Vec<B256> = (0..count).map(|i| B256::with_last_byte(i as u8 + 1)).collect();
            let root = container_root(&roots);
            for index in 0..count {
                let branch = field_branch(&roots, index);
                let gindex = field_gindex(count, index);
                assert!(
                    is_valid_merkle_branch(roots[index], &branch, gindex, root),
                    "{count} {index}"
                );
            }
        }
        assert_eq!(field_gindex(1, 0), 1);
        assert_eq!(field_gindex(28, 22), 54);
        assert_eq!(field_gindex(11, 9), 25);
    }

    #[test]
    #[should_panic(expected = "field 3 of 3")]
    fn a_branch_for_a_missing_field_panics() {
        field_branch(&[B256::ZERO; 3], 3);
    }
}
