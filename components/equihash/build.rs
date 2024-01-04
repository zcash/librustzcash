fn main() {
    cc::Build::new()
        .include("tromp/")
        .file("tromp/equi_miner.c")
        .compile("equitromp");
}
