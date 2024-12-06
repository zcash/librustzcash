use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    // - We check for the existence of protoc in the same way as prost_build, so that
    //   people building from source do not need to have protoc installed. If they make
    //   changes to the proto files, the discrepancy will be caught by CI.
    if env::var_os("PROTOC")
        .map(PathBuf::from)
        .or_else(|| which::which("protoc").ok())
        .is_some()
    {
        build()?;
    }

    Ok(())
}

fn build() -> io::Result<()> {
    let out: PathBuf = env::var_os("OUT_DIR")
        .expect("Cannot find OUT_DIR environment variable")
        .into();

    prost_build::compile_protos(
        &[
            "src/proto/memory_wallet.proto",
            "src/proto/notes.proto",
            "src/proto/primitives.proto",
            "src/proto/shardtree.proto",
            "src/proto/transparent.proto",
        ],
        &["src/"],
    )?;

    // Copy the generated types into the source tree so changes can be committed.
    fs::copy(out.join("memwallet.rs"), "src/proto/generated.rs")?;

    Ok(())
}
