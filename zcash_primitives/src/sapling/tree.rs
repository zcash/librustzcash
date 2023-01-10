use bitvec::{order::Lsb0, view::AsBits};
use group::{ff::PrimeField, Curve};
use incrementalmerkletree::Altitude;
use lazy_static::lazy_static;
use std::io::{self, Read, Write};

use super::{
    note::ExtractedNoteCommitment,
    pedersen_hash::{pedersen_hash, Personalization},
};
use crate::merkle_tree::{HashSer, Hashable};

pub const SAPLING_COMMITMENT_TREE_DEPTH: usize = 32;
pub const SAPLING_COMMITMENT_TREE_DEPTH_U8: u8 = 32;

lazy_static! {
    static ref UNCOMMITTED_SAPLING: bls12_381::Scalar = bls12_381::Scalar::one();
    static ref EMPTY_ROOTS: Vec<Node> = {
        let mut v = vec![Node::blank()];
        for d in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            let next = Node::combine(d, &v[d], &v[d]);
            v.push(next);
        }
        v
    };
}

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let lhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(lhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    let rhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(rhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    jubjub::ExtendedPoint::from(pedersen_hash(
        Personalization::MerkleTree(depth),
        lhs.iter()
            .copied()
            .take(bls12_381::Scalar::NUM_BITS as usize)
            .chain(
                rhs.iter()
                    .copied()
                    .take(bls12_381::Scalar::NUM_BITS as usize),
            ),
    ))
    .to_affine()
    .get_u()
    .to_repr()
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub(super) repr: [u8; 32],
}

impl Node {
    #[cfg(test)]
    pub(crate) fn new(repr: [u8; 32]) -> Self {
        Node { repr }
    }

    /// Creates a tree leaf from the given Sapling note commitment.
    pub fn from_cmu(value: &ExtractedNoteCommitment) -> Self {
        Node {
            repr: value.to_bytes(),
        }
    }

    /// Constructs a new note commitment tree node from a [`bls12_381::Scalar`]
    pub fn from_scalar(cmu: bls12_381::Scalar) -> Self {
        Self {
            repr: cmu.to_repr(),
        }
    }
}

impl incrementalmerkletree::Hashable for Node {
    fn empty_leaf() -> Self {
        Node {
            repr: UNCOMMITTED_SAPLING.to_repr(),
        }
    }

    fn combine(altitude: Altitude, lhs: &Self, rhs: &Self) -> Self {
        Node {
            repr: merkle_hash(altitude.into(), &lhs.repr, &rhs.repr),
        }
    }

    fn empty_root(altitude: Altitude) -> Self {
        EMPTY_ROOTS[<usize>::from(altitude)]
    }
}

impl HashSer for Node {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        Ok(Node { repr })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.repr.as_ref())
    }
}

impl From<Node> for bls12_381::Scalar {
    fn from(node: Node) -> Self {
        // Tree nodes should be in the prime field.
        bls12_381::Scalar::from_repr(node.repr).unwrap()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub(super) mod testing {
    use proptest::prelude::*;

    use super::Node;

    prop_compose! {
        pub fn arb_node()(value in prop::array::uniform32(prop::num::u8::ANY)) -> Node {
            Node {
                repr: value
            }
        }
    }
}
