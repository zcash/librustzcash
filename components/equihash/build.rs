//! Build script for the equihash tromp solver in C.

fn main() {
    #[cfg(feature = "solver")]
    cc::Build::new()
        .include("tromp/")
        .file("tromp/equi_miner.c")
        .compile("equitromp");

    // Tell Cargo to only rerun this build script if the tromp C files or headers change.
    #[cfg(feature = "solver")]
    println!("cargo:rerun-if-changed=tromp");
}
