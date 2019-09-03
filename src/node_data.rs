/// Node metadata.
#[repr(C)]
#[derive(Debug)]
pub struct NodeData {
    pub subtree_commitment: [u8; 32],
    pub start_time: u32,
    pub end_time: u32,
    pub start_target: u32,
    pub end_target: u32,
    pub start_sapling_root: [u8; 32],
    pub end_sapling_root: [u8; 32],
    pub subtree_total_work: u64,
    pub start_height: u32,
    pub end_height: u32,
    pub shielded_tx: u64,
}

impl NodeData {
    pub fn combine(left: &NodeData, right: &NodeData) -> NodeData {
        NodeData {
            // TODO: hash children
            subtree_commitment: [0u8; 32],
            start_time: left.start_time,
            end_time: right.end_time,
            start_target: left.start_target,
            end_target: right.end_target,
            start_sapling_root: left.start_sapling_root,
            end_sapling_root: right.end_sapling_root,

            // TODO: sum work?
            subtree_total_work: 0,
            start_height: left.start_height,
            end_height: right.end_height,
            shielded_tx: left.shielded_tx + right.shielded_tx,
        }
    }
}