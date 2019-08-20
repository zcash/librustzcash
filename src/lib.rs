//! MMR library for Zcash
//!
//! To be used in zebra and via FFI bindings in zcashd

extern crate owning_ref;

mod tree;

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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum NodeLink {
    Stored(u32),
    Generated(u32),
}

#[repr(C)]
#[derive(Debug)]
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
    stored: *const MMRNode,
    stored_count: u32,
    generated: *const MMRNode,
    generated_count: u32,
    append_count: *mut u32,
    append_buffer: *mut MMRNode,
) {

    // TODO: construct tree and write to (append_count, append_buffer)
    // TODO: also return generated??
    unimplemented!()
}
