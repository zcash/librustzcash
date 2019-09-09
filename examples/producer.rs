use zcash_mmr::{NodeData, Tree, EntryLink, Entry};
use std::io::Write;

fn prepare_tree(vec: &Vec<NodeData>) -> Tree {

    assert!(vec.len() > 0);

    // integer log2 of (vec.len()+1), -1
    let mut h = (32 - ((vec.len()+1) as u32).leading_zeros() - 1)-1;
    let mut peak_pos = (1 << (h+1)) - 1;
    let mut nodes = Vec::new();

    loop {

        if peak_pos > vec.len() {
            // left child, -2^h
            peak_pos = peak_pos - (1<<h);
            h = h - 1;
        }

        if peak_pos <= vec.len() {
            let mut peak: Entry = vec[peak_pos-1].clone().into();
            if h != 0 {
                peak.update_siblings(
                    EntryLink::Stored((peak_pos - (1<<h) - 1) as u32),
                    EntryLink::Stored((peak_pos - 2) as u32),
                );
            }
            nodes.push(((peak_pos-1) as u32, peak));

            // right sibling
            peak_pos = peak_pos + (1 << (h+1)) - 1;
        }

        if h == 0 {
            break;
        }
    }

    Tree::new(vec.len() as u32, nodes, vec![])
}

fn main() {

    let mut initial_tree_vec = vec![

        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 10,
            end_time: 20,
            start_target: 100,
            end_target: 110,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 1,
            end_height: 1,
            shielded_tx: 5,
        },

        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 21,
            end_time: 30,
            start_target: 110,
            end_target: 120,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 2,
            end_height: 2,
            shielded_tx: 4,
        },
    ];

    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[0], &initial_tree_vec[1]));

    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 31,
            end_time: 40,
            start_target: 120,
            end_target: 130,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 3,
            end_height: 3,
            shielded_tx: 6,
        },
    );

    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 41,
            end_time: 50,
            start_target: 130,
            end_target: 140,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 4,
            end_height: 4,
            shielded_tx: 7,
        },
    );

    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[3], &initial_tree_vec[4]));
    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[2], &initial_tree_vec[5]));

    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 51,
            end_time: 60,
            start_target: 140,
            end_target: 150,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 5,
            end_height: 5,
            shielded_tx: 8,
        },
    );
    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 61,
            end_time: 70,
            start_target: 150,
            end_target: 160,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 6,
            end_height: 6,
            shielded_tx: 9,
        },
    );
    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[7], &initial_tree_vec[8]));

    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 71,
            end_time: 80,
            start_target: 160,
            end_target: 170,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 7,
            end_height: 7,
            shielded_tx: 10,
        },
    );
    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 81,
            end_time: 90,
            start_target: 170,
            end_target: 180,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 8,
            end_height: 8,
            shielded_tx: 11,
        },
    );
    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[10], &initial_tree_vec[11]));
    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[9], &initial_tree_vec[12]));
    initial_tree_vec.push(NodeData::combine(&initial_tree_vec[6], &initial_tree_vec[13]));

    initial_tree_vec.push(
        NodeData {
            consensus_branch_id: 0,
            subtree_commitment: [0u8; 32],
            start_time: 91,
            end_time: 100,
            start_target: 180,
            end_target: 190,
            start_sapling_root: [0u8; 32],
            end_sapling_root: [0u8; 32],
            subtree_total_work: Default::default(),
            start_height: 9,
            end_height: 9,
            shielded_tx: 12,
        },
    );

    let tree = prepare_tree(&initial_tree_vec);

    let mut buf = Vec::new();
    if let Some(out_file_path) = ::std::env::args().nth(1) {
        for node in initial_tree_vec.into_iter() {
            node.write(&mut buf);
        }

        let mut file = std::fs::File::create(&out_file_path)
            .expect("Failed to create output file");

        file.write_all(&buf[..])
            .expect("Failed to write data to file");
    }

    println!("root: {}", tree.root());


}