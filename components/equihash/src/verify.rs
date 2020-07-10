//! Verification functions for the [Equihash] proof-of-work algorithm.
//!
//! [Equihash]: https://zips.z.cash/protocol/protocol.pdf#equihash

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams, State as Blake2bState};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::Cursor;
use std::mem::size_of;

#[derive(Clone, Copy)]
pub(crate) struct Params {
    pub(crate) n: u32,
    pub(crate) k: u32,
}

#[derive(Clone)]
struct Node {
    hash: Vec<u8>,
    indices: Vec<u32>,
}

impl Params {
    fn new(n: u32, k: u32) -> Result<Self, Error> {
        // We place the following requirements on the parameters:
        // - n is a multiple of 8, so the hash output has an exact byte length.
        // - k >= 3 so the encoded solutions have an exact byte length.
        // - k < n, so the collision bit length is at least 1.
        // - n is a multiple of k + 1, so we have an integer collision bit length.
        if (n % 8 == 0) && (k >= 3) && (k < n) && (n % (k + 1) == 0) {
            Ok(Params { n, k })
        } else {
            Err(Error(Kind::InvalidParams))
        }
    }
    fn indices_per_hash_output(&self) -> u32 {
        512 / self.n
    }
    fn hash_output(&self) -> u8 {
        (self.indices_per_hash_output() * self.n / 8) as u8
    }
    fn collision_bit_length(&self) -> usize {
        (self.n / (self.k + 1)) as usize
    }
    fn collision_byte_length(&self) -> usize {
        (self.collision_bit_length() + 7) / 8
    }
    #[cfg(test)]
    fn hash_length(&self) -> usize {
        ((self.k as usize) + 1) * self.collision_byte_length()
    }
}

impl Node {
    fn new(p: &Params, state: &Blake2bState, i: u32) -> Self {
        let hash = generate_hash(state, i / p.indices_per_hash_output());
        let start = ((i % p.indices_per_hash_output()) * p.n / 8) as usize;
        let end = start + (p.n as usize) / 8;
        Node {
            hash: expand_array(&hash.as_bytes()[start..end], p.collision_bit_length(), 0),
            indices: vec![i],
        }
    }

    fn from_children(a: Node, b: Node, trim: usize) -> Self {
        let hash: Vec<_> = a
            .hash
            .iter()
            .zip(b.hash.iter())
            .skip(trim)
            .map(|(a, b)| a ^ b)
            .collect();
        let indices = if a.indices_before(&b) {
            let mut indices = a.indices;
            indices.extend(b.indices.iter());
            indices
        } else {
            let mut indices = b.indices;
            indices.extend(a.indices.iter());
            indices
        };
        Node { hash, indices }
    }

    #[cfg(test)]
    fn from_children_ref(a: &Node, b: &Node, trim: usize) -> Self {
        let hash: Vec<_> = a
            .hash
            .iter()
            .zip(b.hash.iter())
            .skip(trim)
            .map(|(a, b)| a ^ b)
            .collect();
        let mut indices = Vec::with_capacity(a.indices.len() + b.indices.len());
        if a.indices_before(b) {
            indices.extend(a.indices.iter());
            indices.extend(b.indices.iter());
        } else {
            indices.extend(b.indices.iter());
            indices.extend(a.indices.iter());
        }
        Node { hash, indices }
    }

    fn indices_before(&self, other: &Node) -> bool {
        // Indices are serialized in big-endian so that integer
        // comparison is equivalent to array comparison
        self.indices[0] < other.indices[0]
    }

    fn is_zero(&self, len: usize) -> bool {
        self.hash.iter().take(len).all(|v| *v == 0)
    }
}

/// An Equihash solution failed to verify.
#[derive(Debug)]
pub struct Error(Kind);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid solution: {}", self.0)
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq)]
pub(crate) enum Kind {
    InvalidParams,
    Collision,
    OutOfOrder,
    DuplicateIdxs,
    NonZeroRootHash,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::InvalidParams => f.write_str("invalid parameters"),
            Kind::Collision => f.write_str("invalid collision length between StepRows"),
            Kind::OutOfOrder => f.write_str("Index tree incorrectly ordered"),
            Kind::DuplicateIdxs => f.write_str("duplicate indices"),
            Kind::NonZeroRootHash => f.write_str("root hash of tree is non-zero"),
        }
    }
}

fn initialise_state(n: u32, k: u32, digest_len: u8) -> Blake2bState {
    let mut personalization: Vec<u8> = Vec::from("ZcashPoW");
    personalization.write_u32::<LittleEndian>(n).unwrap();
    personalization.write_u32::<LittleEndian>(k).unwrap();

    Blake2bParams::new()
        .hash_length(digest_len as usize)
        .personal(&personalization)
        .to_state()
}

fn generate_hash(base_state: &Blake2bState, i: u32) -> Blake2bHash {
    let mut lei = [0u8; 4];
    (&mut lei[..]).write_u32::<LittleEndian>(i).unwrap();

    let mut state = base_state.clone();
    state.update(&lei);
    state.finalize()
}

fn expand_array(vin: &[u8], bit_len: usize, byte_pad: usize) -> Vec<u8> {
    assert!(bit_len >= 8);
    assert!(8 * size_of::<u32>() >= 7 + bit_len);

    let out_width = (bit_len + 7) / 8 + byte_pad;
    let out_len = 8 * out_width * vin.len() / bit_len;

    // Shortcut for parameters where expansion is a no-op
    if out_len == vin.len() {
        return vin.to_vec();
    }

    let mut vout: Vec<u8> = vec![0; out_len];
    let bit_len_mask: u32 = (1 << bit_len) - 1;

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    let mut acc_bits = 0;
    let mut acc_value: u32 = 0;

    let mut j = 0;
    for b in vin {
        acc_value = (acc_value << 8) | u32::from(*b);
        acc_bits += 8;

        // When we have bit_len or more bits in the accumulator, write the next
        // output element.
        if acc_bits >= bit_len {
            acc_bits -= bit_len;
            for x in byte_pad..out_width {
                vout[j + x] = ((
                    // Big-endian
                    acc_value >> (acc_bits + (8 * (out_width - x - 1)))
                ) & (
                    // Apply bit_len_mask across byte boundaries
                    (bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF
                )) as u8;
            }
            j += out_width;
        }
    }

    vout
}

fn indices_from_minimal(p: Params, minimal: &[u8]) -> Result<Vec<u32>, Error> {
    let c_bit_len = p.collision_bit_length();
    // Division is exact because k >= 3.
    if minimal.len() != ((1 << p.k) * (c_bit_len + 1)) / 8 {
        return Err(Error(Kind::InvalidParams));
    }

    assert!(((c_bit_len + 1) + 7) / 8 <= size_of::<u32>());
    let len_indices = 8 * size_of::<u32>() * minimal.len() / (c_bit_len + 1);
    let byte_pad = size_of::<u32>() - ((c_bit_len + 1) + 7) / 8;

    let mut csr = Cursor::new(expand_array(minimal, c_bit_len + 1, byte_pad));
    let mut ret = Vec::with_capacity(len_indices);

    // Big-endian so that lexicographic array comparison is equivalent to integer
    // comparison
    while let Ok(i) = csr.read_u32::<BigEndian>() {
        ret.push(i);
    }

    Ok(ret)
}

fn has_collision(a: &Node, b: &Node, len: usize) -> bool {
    a.hash
        .iter()
        .zip(b.hash.iter())
        .take(len)
        .all(|(a, b)| a == b)
}

fn distinct_indices(a: &Node, b: &Node) -> bool {
    for i in &(a.indices) {
        for j in &(b.indices) {
            if i == j {
                return false;
            }
        }
    }
    true
}

fn validate_subtrees(p: &Params, a: &Node, b: &Node) -> Result<(), Kind> {
    if !has_collision(a, b, p.collision_byte_length()) {
        Err(Kind::Collision)
    } else if b.indices_before(a) {
        Err(Kind::OutOfOrder)
    } else if !distinct_indices(a, b) {
        Err(Kind::DuplicateIdxs)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn is_valid_solution_iterative(
    p: Params,
    input: &[u8],
    nonce: &[u8],
    indices: &[u32],
) -> Result<(), Error> {
    let mut state = initialise_state(p.n, p.k, p.hash_output());
    state.update(input);
    state.update(nonce);

    let mut rows = Vec::new();
    for i in indices {
        rows.push(Node::new(&p, &state, *i));
    }

    let mut hash_len = p.hash_length();
    while rows.len() > 1 {
        let mut cur_rows = Vec::new();
        for pair in rows.chunks(2) {
            let a = &pair[0];
            let b = &pair[1];
            validate_subtrees(&p, a, b).map_err(Error)?;
            cur_rows.push(Node::from_children_ref(a, b, p.collision_byte_length()));
        }
        rows = cur_rows;
        hash_len -= p.collision_byte_length();
    }

    assert!(rows.len() == 1);

    if rows[0].is_zero(hash_len) {
        Ok(())
    } else {
        Err(Error(Kind::NonZeroRootHash))
    }
}

fn tree_validator(p: &Params, state: &Blake2bState, indices: &[u32]) -> Result<Node, Error> {
    if indices.len() > 1 {
        let end = indices.len();
        let mid = end / 2;
        let a = tree_validator(p, state, &indices[0..mid])?;
        let b = tree_validator(p, state, &indices[mid..end])?;
        validate_subtrees(p, &a, &b).map_err(Error)?;
        Ok(Node::from_children(a, b, p.collision_byte_length()))
    } else {
        Ok(Node::new(&p, &state, indices[0]))
    }
}

fn is_valid_solution_recursive(
    p: Params,
    input: &[u8],
    nonce: &[u8],
    indices: &[u32],
) -> Result<(), Error> {
    let mut state = initialise_state(p.n, p.k, p.hash_output());
    state.update(input);
    state.update(nonce);

    let root = tree_validator(&p, &state, indices)?;

    // Hashes were trimmed, so only need to check remaining length
    if root.is_zero(p.collision_byte_length()) {
        Ok(())
    } else {
        Err(Error(Kind::NonZeroRootHash))
    }
}

/// Checks whether `soln` is a valid solution for `(input, nonce)` with the
/// parameters `(n, k)`.
pub fn is_valid_solution(
    n: u32,
    k: u32,
    input: &[u8],
    nonce: &[u8],
    soln: &[u8],
) -> Result<(), Error> {
    let p = Params::new(n, k)?;
    let indices = indices_from_minimal(p, soln)?;

    // Recursive validation is faster
    is_valid_solution_recursive(p, input, nonce, &indices)
}

#[cfg(test)]
mod tests {
    use super::{
        expand_array, indices_from_minimal, is_valid_solution, is_valid_solution_iterative,
        is_valid_solution_recursive, Params,
    };
    use crate::test_vectors::{INVALID_TEST_VECTORS, VALID_TEST_VECTORS};

    #[test]
    fn array_expansion() {
        let check_array = |(bit_len, byte_pad), compact, expanded| {
            assert_eq!(expand_array(compact, bit_len, byte_pad), expanded);
        };

        // 8 11-bit chunks, all-ones
        check_array(
            (11, 0),
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[
                0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff,
                0x07, 0xff,
            ][..],
        );
        // 8 21-bit chunks, alternating 1s and 0s
        check_array(
            (21, 0),
            &[
                0xaa, 0xaa, 0xad, 0x55, 0x55, 0x6a, 0xaa, 0xab, 0x55, 0x55, 0x5a, 0xaa, 0xaa, 0xd5,
                0x55, 0x56, 0xaa, 0xaa, 0xb5, 0x55, 0x55,
            ],
            &[
                0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55,
                0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55,
            ][..],
        );
        // 8 21-bit chunks, based on example in the spec
        check_array(
            (21, 0),
            &[
                0x00, 0x02, 0x20, 0x00, 0x0a, 0x7f, 0xff, 0xfe, 0x00, 0x12, 0x30, 0x22, 0xb3, 0x82,
                0x26, 0xac, 0x19, 0xbd, 0xf2, 0x34, 0x56,
            ],
            &[
                0x00, 0x00, 0x44, 0x00, 0x00, 0x29, 0x1f, 0xff, 0xff, 0x00, 0x01, 0x23, 0x00, 0x45,
                0x67, 0x00, 0x89, 0xab, 0x00, 0xcd, 0xef, 0x12, 0x34, 0x56,
            ][..],
        );
        // 16 14-bit chunks, alternating 11s and 00s
        check_array(
            (14, 0),
            &[
                0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33, 0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33,
                0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33, 0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33,
            ],
            &[
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33,
            ][..],
        );
        // 8 11-bit chunks, all-ones, 2-byte padding
        check_array(
            (11, 2),
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[
                0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00,
                0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff,
                0x00, 0x00, 0x07, 0xff,
            ][..],
        );
    }

    #[test]
    fn minimal_solution_repr() {
        let check_repr = |minimal, indices| {
            assert_eq!(
                indices_from_minimal(Params { n: 80, k: 3 }, minimal).unwrap(),
                indices,
            );
        };

        // The solutions here are not intended to be valid.
        check_repr(
            &[
                0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x80,
                0x00, 0x04, 0x00, 0x00, 0x20, 0x00, 0x01,
            ],
            &[1, 1, 1, 1, 1, 1, 1, 1],
        );
        check_repr(
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[
                2097151, 2097151, 2097151, 2097151, 2097151, 2097151, 2097151, 2097151,
            ],
        );
        check_repr(
            &[
                0x0f, 0xff, 0xf8, 0x00, 0x20, 0x03, 0xff, 0xfe, 0x00, 0x08, 0x00, 0xff, 0xff, 0x80,
                0x02, 0x00, 0x3f, 0xff, 0xe0, 0x00, 0x80,
            ],
            &[131071, 128, 131071, 128, 131071, 128, 131071, 128],
        );
        check_repr(
            &[
                0x00, 0x02, 0x20, 0x00, 0x0a, 0x7f, 0xff, 0xfe, 0x00, 0x4d, 0x10, 0x01, 0x4c, 0x80,
                0x0f, 0xfc, 0x00, 0x00, 0x2f, 0xff, 0xff,
            ],
            &[68, 41, 2097151, 1233, 665, 1023, 1, 1048575],
        );
    }

    #[test]
    fn valid_test_vectors() {
        for tv in VALID_TEST_VECTORS {
            for soln in tv.solutions {
                is_valid_solution_iterative(tv.params, tv.input, &tv.nonce, soln).unwrap();
                is_valid_solution_recursive(tv.params, tv.input, &tv.nonce, soln).unwrap();
            }
        }
    }

    #[test]
    fn invalid_test_vectors() {
        for tv in INVALID_TEST_VECTORS {
            assert_eq!(
                is_valid_solution_iterative(tv.params, tv.input, &tv.nonce, &tv.solution)
                    .unwrap_err()
                    .0,
                tv.error
            );
            assert_eq!(
                is_valid_solution_recursive(tv.params, tv.input, &tv.nonce, &tv.solution)
                    .unwrap_err()
                    .0,
                tv.error
            );
        }
    }

    #[test]
    fn all_bits_matter() {
        // Initialize the state according to one of the valid test vectors.
        let n = 96;
        let k = 5;
        let input = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        let nonce = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let soln = &[
            0x04, 0x6a, 0x8e, 0xd4, 0x51, 0xa2, 0x19, 0x73, 0x32, 0xe7, 0x1f, 0x39, 0xdb, 0x9c,
            0x79, 0xfb, 0xf9, 0x3f, 0xc1, 0x44, 0x3d, 0xa5, 0x8f, 0xb3, 0x8d, 0x05, 0x99, 0x17,
            0x21, 0x16, 0xd5, 0x55, 0xb1, 0xb2, 0x1f, 0x32, 0x70, 0x5c, 0xe9, 0x98, 0xf6, 0x0d,
            0xa8, 0x52, 0xf7, 0x7f, 0x0e, 0x7f, 0x4d, 0x63, 0xfc, 0x2d, 0xd2, 0x30, 0xa3, 0xd9,
            0x99, 0x53, 0xa0, 0x78, 0x7d, 0xfe, 0xfc, 0xab, 0x34, 0x1b, 0xde, 0xc8,
        ];

        // Prove that the solution is valid.
        is_valid_solution(n, k, input, &nonce, soln).unwrap();

        // Changing any single bit of the encoded solution should make it invalid.
        for i in 0..soln.len() * 8 {
            let mut mutated = soln.to_vec();
            mutated[i / 8] ^= 1 << (i % 8);
            is_valid_solution(n, k, input, &nonce, &mutated).unwrap_err();
        }
    }
}
