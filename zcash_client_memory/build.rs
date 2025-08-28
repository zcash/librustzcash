use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

const MEMORY_WALLET_PROTO: &str = "proto/memory_wallet.proto";

fn main() -> io::Result<()> {
    // - We don't include the proto files in releases so that downstreams do not need to
    //  regenerate the bindings even if protoc is present.
    // - We check for the existence of protoc in the same way as prost_build, so that
    //   people building from source do not need to have protoc installed. If they make
    //   changes to the proto files, the discrepancy will be caught by CI.
    if Path::new(MEMORY_WALLET_PROTO).exists()
        && env::var_os("PROTOC")
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
            MEMORY_WALLET_PROTO,
            "proto/notes.proto",
            "proto/primitives.proto",
            "proto/shardtree.proto",
            "proto/transparent.proto",
        ],
        &["proto/"],
    )?;

    // Copy the generated types into the source tree so changes can be committed.
    fs::copy(out.join("memwallet.rs"), "src/proto/memwallet.rs")?;

    Ok(())
}
