#[path = "lib/shared.rs"]
mod share;

// Test data generator
// $ cargo run --example writer -- 16 nodes.dat
// or
// $ cargo run --example writer -- 16
// to preview

fn main() {
    let mut args = std::env::args().skip(1);

    let (number, out_file) = match args.next() {
        None => {
            eprintln!("writer <number of nodes> [<out_file>]");
            std::process::exit(1);
        }
        Some(number) => (
            number.parse::<usize>().expect("invalid number"),
            args.next(),
        ),
    };

    let iterator = share::NodeDataIterator::new().take(number);

    if let Some(out_file_path) = out_file {
        use std::io::Write;

        let mut buf = Vec::new();

        for node in iterator {
            node.write(&mut buf).expect("Failed to write data");
        }

        let mut file = std::fs::File::create(&out_file_path).expect("Failed to create output file");

        file.write_all(&buf[..])
            .expect("Failed to write data to file");
    } else {
        for n in iterator {
            println!("{:?}", n);
        }
    }
}
