use std::fmt;
use std::io;

use blake2b_simd::Params as Blake2Params;
use byteorder::{ByteOrder, LittleEndian};

use crate::{node_data, EntryKind, EntryLink, NodeData, MAX_NODE_DATA_SIZE};

fn blake2b_personal(personalization: &[u8], input: &[u8]) -> [u8; 32] {
    let hash_result = Blake2Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state()
        .update(input)
        .finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash_result.as_bytes());
    result
}

fn personalization(branch_id: u32) -> [u8; 16] {
    let mut result = [0u8; 16];
    result[..12].copy_from_slice(b"ZcashHistory");
    LittleEndian::write_u32(&mut result[12..], branch_id);
    result
}

/// A version of the chain history tree.
pub trait Version {
    /// The node data for this tree version.
    type NodeData: fmt::Debug;

    /// The entry kind for this tree version.
    type EntryKind: fmt::Debug;

    /// The entry link for this tree version.
    type EntryLink: fmt::Debug;

    /// Returns the consensus branch ID for the given node data.
    fn consensus_branch_id(data: &Self::NodeData) -> u32;

    /// Returns the start height for the given node data.
    fn start_height(data: &Self::NodeData) -> u64;

    /// Returns the end height for the given node data.
    fn end_height(data: &Self::NodeData) -> u64;

    /// Combines two nodes' metadata.
    fn combine(left: &Self::NodeData, right: &Self::NodeData) -> Self::NodeData {
        assert_eq!(
            Self::consensus_branch_id(left),
            Self::consensus_branch_id(right)
        );

        let mut hash_buf = [0u8; MAX_NODE_DATA_SIZE * 2];
        let size = {
            let mut cursor = ::std::io::Cursor::new(&mut hash_buf[..]);
            Self::write(left, &mut cursor)
                .expect("Writing to memory buf with enough length cannot fail; qed");
            Self::write(right, &mut cursor)
                .expect("Writing to memory buf with enough length cannot fail; qed");
            cursor.position() as usize
        };

        let hash = blake2b_personal(
            &personalization(Self::consensus_branch_id(left)),
            &hash_buf[..size],
        );

        Self::combine_inner(hash, left, right)
    }

    /// Combines two nodes metadata.
    ///
    /// For internal use.
    fn combine_inner(
        subtree_commitment: [u8; 32],
        left: &Self::NodeData,
        right: &Self::NodeData,
    ) -> Self::NodeData;

    /// Parses node data from the given reader.
    fn read<R: io::Read>(consensus_branch_id: u32, r: &mut R) -> io::Result<Self::NodeData>;

    /// Writes the byte representation of the given node data to the given writer.
    fn write<W: io::Write>(data: &Self::NodeData, w: &mut W) -> io::Result<()>;

    /// Converts to byte representation.
    #[allow(clippy::wrong_self_convention)]
    fn to_bytes(data: &Self::NodeData) -> Vec<u8> {
        let mut buf = [0u8; MAX_NODE_DATA_SIZE];
        let pos = {
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            Self::write(data, &mut cursor).expect("Cursor cannot fail");
            cursor.position() as usize
        };

        buf[0..pos].to_vec()
    }

    /// Convert from byte representation.
    fn from_bytes<T: AsRef<[u8]>>(consensus_branch_id: u32, buf: T) -> io::Result<Self::NodeData> {
        let mut cursor = std::io::Cursor::new(buf);
        Self::read(consensus_branch_id, &mut cursor)
    }

    /// Hash node metadata
    fn hash(data: &Self::NodeData) -> [u8; 32] {
        let bytes = Self::to_bytes(data);

        blake2b_personal(&personalization(Self::consensus_branch_id(data)), &bytes)
    }

    /// Reads the version-specific entry kind.
    fn read_entry_kind<R: io::Read>(r: &mut R) -> io::Result<Self::EntryKind>;

    /// Writes the version-specific entry kind.
    fn write_entry_kind<W: io::Write>(kind: &Self::EntryKind, w: &mut W) -> io::Result<()>;

    /// Constructs a version-specific node entry.
    fn make_node(left: Self::EntryLink, right: Self::EntryLink) -> Self::EntryKind;

    /// Constructs a version-specific leaf entry.
    fn make_leaf() -> Self::EntryKind;

    /// Returns true if the given entry kind represents a leaf.
    fn is_leaf(kind: &Self::EntryKind) -> bool;

    /// Returns the left child (if any) from the entry kind.
    fn get_left(kind: &Self::EntryKind) -> Option<Self::EntryLink>;

    /// Returns the right child (if any) from the entry kind.
    fn get_right(kind: &Self::EntryKind) -> Option<Self::EntryLink>;

    /// Constructs a version-specific stored entry link.
    fn make_stored(v: u32) -> Self::EntryLink;

    /// Constructs a version-specific generated entry link.
    fn make_generated(v: u32) -> Self::EntryLink;
}

/// Version 1 of the Zcash chain history tree.
///
/// This version was used for the Heartwood and Canopy epochs.
#[cfg_attr(
    feature = "remote_read_state_service",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum V1 {}

impl Version for V1 {
    type NodeData = NodeData;
    type EntryKind = EntryKind;
    type EntryLink = EntryLink;

    fn consensus_branch_id(data: &Self::NodeData) -> u32 {
        data.consensus_branch_id
    }

    fn start_height(data: &Self::NodeData) -> u64 {
        data.start_height
    }

    fn end_height(data: &Self::NodeData) -> u64 {
        data.end_height
    }

    fn combine_inner(
        subtree_commitment: [u8; 32],
        left: &Self::NodeData,
        right: &Self::NodeData,
    ) -> Self::NodeData {
        NodeData::combine_inner(subtree_commitment, left, right)
    }

    fn read<R: io::Read>(consensus_branch_id: u32, r: &mut R) -> io::Result<Self::NodeData> {
        NodeData::read(consensus_branch_id, r)
    }

    fn write<W: io::Write>(data: &Self::NodeData, w: &mut W) -> io::Result<()> {
        data.write(w)
    }

    fn read_entry_kind<R: io::Read>(r: &mut R) -> io::Result<Self::EntryKind> {
        EntryKind::read(r)
    }

    fn write_entry_kind<W: io::Write>(kind: &Self::EntryKind, w: &mut W) -> io::Result<()> {
        kind.write(w)
    }

    fn make_node(left: Self::EntryLink, right: Self::EntryLink) -> Self::EntryKind {
        EntryKind::Node(left, right)
    }

    fn make_leaf() -> Self::EntryKind {
        EntryKind::Leaf
    }

    fn is_leaf(kind: &Self::EntryKind) -> bool {
        matches!(kind, EntryKind::Leaf)
    }

    fn get_left(kind: &Self::EntryKind) -> Option<Self::EntryLink> {
        if let EntryKind::Node(left, _) = kind {
            Some(*left)
        } else {
            None
        }
    }

    fn get_right(kind: &Self::EntryKind) -> Option<Self::EntryLink> {
        if let EntryKind::Node(_, right) = kind {
            Some(*right)
        } else {
            None
        }
    }

    fn make_stored(v: u32) -> Self::EntryLink {
        EntryLink::Stored(v)
    }

    fn make_generated(v: u32) -> Self::EntryLink {
        EntryLink::Generated(v)
    }
}

/// Version 2 of the Zcash chain history tree.
///
/// This version is used from the NU5 epoch.
#[cfg_attr(
    feature = "remote_read_state_service",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum V2 {}

impl Version for V2 {
    type NodeData = node_data::V2;
    type EntryKind = EntryKind;
    type EntryLink = EntryLink;

    fn consensus_branch_id(data: &Self::NodeData) -> u32 {
        data.v1.consensus_branch_id
    }

    fn start_height(data: &Self::NodeData) -> u64 {
        data.v1.start_height
    }

    fn end_height(data: &Self::NodeData) -> u64 {
        data.v1.end_height
    }

    fn combine_inner(
        subtree_commitment: [u8; 32],
        left: &Self::NodeData,
        right: &Self::NodeData,
    ) -> Self::NodeData {
        node_data::V2::combine_inner(subtree_commitment, left, right)
    }

    fn read<R: io::Read>(consensus_branch_id: u32, r: &mut R) -> io::Result<Self::NodeData> {
        node_data::V2::read(consensus_branch_id, r)
    }

    fn write<W: io::Write>(data: &Self::NodeData, w: &mut W) -> io::Result<()> {
        data.write(w)
    }

    fn read_entry_kind<R: io::Read>(r: &mut R) -> io::Result<Self::EntryKind> {
        EntryKind::read(r)
    }

    fn write_entry_kind<W: io::Write>(kind: &Self::EntryKind, w: &mut W) -> io::Result<()> {
        kind.write(w)
    }

    fn make_node(left: Self::EntryLink, right: Self::EntryLink) -> Self::EntryKind {
        EntryKind::Node(left, right)
    }

    fn make_leaf() -> Self::EntryKind {
        EntryKind::Leaf
    }

    fn is_leaf(kind: &Self::EntryKind) -> bool {
        matches!(kind, EntryKind::Leaf)
    }

    fn get_left(kind: &Self::EntryKind) -> Option<Self::EntryLink> {
        if let EntryKind::Node(left, _) = kind {
            Some(*left)
        } else {
            None
        }
    }

    fn get_right(kind: &Self::EntryKind) -> Option<Self::EntryLink> {
        if let EntryKind::Node(_, right) = kind {
            Some(*right)
        } else {
            None
        }
    }

    fn make_stored(v: u32) -> Self::EntryLink {
        EntryLink::Stored(v)
    }

    fn make_generated(v: u32) -> Self::EntryLink {
        EntryLink::Generated(v)
    }
}
