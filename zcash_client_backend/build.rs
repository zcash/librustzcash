use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const COMPACT_FORMATS_PROTO: &str = "proto/compact_formats.proto";

fn main() -> io::Result<()> {
    // We don't include the proto files in releases so that downstreams do not need to
    // regenerate the bindings even if protoc is present.
    if Path::new(COMPACT_FORMATS_PROTO).exists() {
        println!("cargo:rerun-if-changed={}", COMPACT_FORMATS_PROTO);

        // We check for the existence of protoc in the same way as prost_build, so that people
        // building from source do not need to have protoc installed. If they make changes to
        // the proto files, the discrepancy will be caught by CI.
        if env::var_os("PROTOC")
            .map(PathBuf::from)
            .or_else(|| which::which("protoc").ok())
            .is_some()
        {
            build()?;
        }
    }

    Ok(())
}

fn build() -> io::Result<()> {
    let out: PathBuf = env::var_os("OUT_DIR")
        .expect("Cannot find OUT_DIR environment variable")
        .into();

    prost_build::compile_protos(&[COMPACT_FORMATS_PROTO], &["proto/"])?;

    // Copy the generated files into the source tree so changes can be committed.
    fs::copy(
        out.join("cash.z.wallet.sdk.rpc.rs"),
        "src/proto/compact_formats.rs",
    )?;

    Ok(())
}
