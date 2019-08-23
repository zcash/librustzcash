//! MMR library for Zcash
//!
//! To be used in zebra and via FFI bindings in zcashd

#[cfg(test)] #[macro_use] extern crate assert_matches;
#[cfg(test)] #[macro_use] extern crate quickcheck;

mod tree;

pub use tree::Tree;

/// Node metadata.
#[repr(C)]
#[derive(Debug)]
pub struct NodeData {
    subtree_commitment: [u8; 32],
    start_time: u32,
    end_time: u32,
    start_target: u32,
    end_target: u32,
    start_sapling_root: [u8; 32],
    end_sapling_root: [u8; 32],
    subtree_total_work: u64,
    start_height: u32,
    end_height: u32,
    shielded_tx: u64,
}

/// Reference to to the tree node.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum NodeLink {
    /// Reference to the stored (in the array representation) leaf/node.
    Stored(u32),
    /// Reference to the generated leaf/node.
    Generated(u32),
}

/// MMR Node. It is leaf when `left`, `right` are `None` and node when they are not.
#[repr(C)]
#[derive(Debug)]
// TODO: Better layout would be enum (node, leaf), with left, right set only for nodes?
pub struct MMRNode {
    left: Option<NodeLink>,
    right: Option<NodeLink>,
    data: NodeData,
}

impl MMRNode {
    fn complete(&self) -> bool {
        let leaves = self.data.end_height - self.data.start_height + 1;
        leaves & (leaves - 1) == 0
    }
}

impl From<NodeData> for MMRNode {
    fn from(s: NodeData) -> Self {
        MMRNode { left: None, right: None, data: s }
    }
}

#[no_mangle]
pub extern fn append(
    _stored: *const MMRNode,
    _stored_count: u32,
    _generated: *const MMRNode,
    _generated_count: u32,
    _append_count: *mut u32,
    _append_buffer: *mut MMRNode,
) {

    // TODO: construct tree and write to (append_count, append_buffer)
    // TODO: also return generated??
    unimplemented!()
}
