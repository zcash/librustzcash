use zcash_mmr::{Entry, EntryLink, NodeData, Tree};

#[path= "lib/shared.rs"]
mod share;

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
            let left_idx = (peak_pos - (1<<h) - 1) as u32;
            let right_idx = (peak_pos - 2) as u32;
            if h != 0 {
                peak.update_siblings(
                    EntryLink::Stored(left_idx),
                    EntryLink::Stored(right_idx),
                );
            }
            nodes.push(((peak_pos-1) as u32, peak));

            println!("Peak #{}: ({}, {})", nodes.len(), left_idx, right_idx);

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
    let number= match std::env::args().skip(1).next() {
        None => { eprintln!("writer <number of nodes> [<out_file>]"); std::process::exit(1); },
        Some(number) => {
            number.parse::<usize>().expect("invalid number")
        }
    };

    let long_vec = share::NodeDataIterator::new().take(number)
        .collect::<Vec<NodeData>>();

    let now = std::time::Instant::now();

    let tree = prepare_tree(&long_vec);

    println!("Tree final root: {}-{}",
        tree.root_node().expect("root").data().start_height,
        tree.root_node().expect("root").data().end_height,
    );

    println!("Prepare tree of {} length: {} ns / {} mcs / {} ms",
        number,
        now.elapsed().as_nanos(), now.elapsed().as_micros(), now.elapsed().as_millis()
    );
}
