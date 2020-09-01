use zcash_history::{Entry, EntryLink, NodeData, Tree};

#[path = "lib/shared.rs"]
mod share;

fn draft(into: &mut Vec<(u32, Entry)>, vec: &Vec<NodeData>, peak_pos: usize, h: u32) {
    let node_data = vec[peak_pos - 1].clone();
    let peak: Entry = match h {
        0 => node_data.into(),
        _ => Entry::new(
            node_data,
            EntryLink::Stored((peak_pos - (1 << h) - 1) as u32),
            EntryLink::Stored((peak_pos - 2) as u32),
        ),
    };

    println!("Entry #{}: {}", into.len(), peak);

    into.push(((peak_pos - 1) as u32, peak));
}

fn prepare_tree(vec: &Vec<NodeData>) -> Tree {
    assert!(vec.len() > 0);

    // integer log2 of (vec.len()+1), -1
    let mut h = (32 - ((vec.len() + 1) as u32).leading_zeros() - 1) - 1;
    let mut peak_pos = (1 << (h + 1)) - 1;
    let mut nodes = Vec::new();

    // used later
    let mut last_peak_pos = 0;
    let mut last_peak_h = 0;

    loop {
        if peak_pos > vec.len() {
            // left child, -2^h
            peak_pos = peak_pos - (1 << h);
            h = h - 1;
        }

        if peak_pos <= vec.len() {
            draft(&mut nodes, vec, peak_pos, h);

            // save to be used in next loop
            last_peak_pos = peak_pos;
            last_peak_h = h;

            // right sibling
            peak_pos = peak_pos + (1 << (h + 1)) - 1;
        }

        if h == 0 {
            break;
        }
    }

    // for deletion, everything on the right slope of the last peak should be pre-loaded
    let mut extra = Vec::new();
    let mut h = last_peak_h;
    let mut peak_pos = last_peak_pos;

    while h > 0 {
        let left_pos = peak_pos - (1 << h);
        let right_pos = peak_pos - 1;
        h = h - 1;

        // drafting left child
        draft(&mut extra, vec, left_pos, h);

        // drafting right child
        draft(&mut extra, vec, right_pos, h);

        // continuing on right slope
        peak_pos = right_pos;
    }

    println!("Total extra of {} required for deletion!", extra.len());

    Tree::new(vec.len() as u32, nodes, extra)
}

fn main() {
    let number = match std::env::args().skip(1).next() {
        None => {
            eprintln!("writer <number of nodes> [<out_file>]");
            std::process::exit(1);
        }
        Some(number) => number.parse::<usize>().expect("invalid number"),
    };

    let long_vec = share::NodeDataIterator::new()
        .take(number)
        .collect::<Vec<NodeData>>();

    let now = std::time::Instant::now();

    let tree = prepare_tree(&long_vec);
    let elapsed = now.elapsed();

    println!(
        "Tree final root: {}-{}",
        tree.root_node().expect("root").data().start_height,
        tree.root_node().expect("root").data().end_height,
    );

    println!(
        "Prepare tree of {} length: {} ns / {} mcs / {} ms",
        number,
        elapsed.as_nanos(),
        elapsed.as_micros(),
        elapsed.as_millis()
    );
}
