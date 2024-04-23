//! Verification functions for the [Equihash] proof-of-work algorithm.
//!
//! [Equihash]: https://zips.z.cash/protocol/protocol.pdf#equihash

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams, State as Blake2bState};
use byteorder::{LittleEndian, WriteBytesExt};
use std::fmt;

use crate::{
    minimal::{expand_array, indices_from_minimal},
    params::Params,
};

#[derive(Clone)]
struct Node {
    hash: Vec<u8>,
    indices: Vec<u32>,
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

    // Clippy incorrectly interprets the first argument as `self`.
    #[allow(clippy::wrong_self_convention)]
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
        Ok(Node::new(p, state, indices[0]))
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
    let p = Params::new(n, k).ok_or(Error(Kind::InvalidParams))?;
    let indices = indices_from_minimal(p, soln).ok_or(Error(Kind::InvalidParams))?;

    // Recursive validation is faster
    is_valid_solution_recursive(p, input, nonce, &indices)
}

#[cfg(test)]
mod tests {
    use super::{is_valid_solution, is_valid_solution_iterative, is_valid_solution_recursive};
    use crate::test_vectors::{INVALID_TEST_VECTORS, VALID_TEST_VECTORS};

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
                is_valid_solution_iterative(tv.params, tv.input, &tv.nonce, tv.solution)
                    .unwrap_err()
                    .0,
                tv.error
            );
            assert_eq!(
                is_valid_solution_recursive(tv.params, tv.input, &tv.nonce, tv.solution)
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
