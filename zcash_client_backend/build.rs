use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const COMPACT_FORMATS_PROTO: &str = "proto/compact_formats.proto";
const SERVICE_PROTO: &str = "proto/service.proto";

fn main() -> io::Result<()> {
    // - We don't include the proto files in releases so that downstreams do not need to
    //  regenerate the bindings even if protoc is present.
    // - We check for the existence of protoc in the same way as prost_build, so that
    //   people building from source do not need to have protoc installed. If they make
    //   changes to the proto files, the discrepancy will be caught by CI.
    if Path::new(COMPACT_FORMATS_PROTO).exists()
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

    // Build the compact format types.
    tonic_build::compile_protos(COMPACT_FORMATS_PROTO)?;

    // Copy the generated types into the source tree so changes can be committed.
    fs::copy(
        out.join("cash.z.wallet.sdk.rpc.rs"),
        "src/proto/compact_formats.rs",
    )?;

    // Build the gRPC types and client.
    tonic_build::configure()
        .build_server(false)
        .client_mod_attribute(
            "cash.z.wallet.sdk.rpc",
            r#"#[cfg(feature = "lightwalletd-tonic")]"#,
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.ChainMetadata",
            "crate::proto::compact_formats::ChainMetadata",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.CompactBlock",
            "crate::proto::compact_formats::CompactBlock",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.CompactTx",
            "crate::proto::compact_formats::CompactTx",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.CompactSaplingSpend",
            "crate::proto::compact_formats::CompactSaplingSpend",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.CompactSaplingOutput",
            "crate::proto::compact_formats::CompactSaplingOutput",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.CompactOrchardAction",
            "crate::proto::compact_formats::CompactOrchardAction",
        )
        .compile(&[SERVICE_PROTO], &["proto/"])?;

    // Copy the generated types into the source tree so changes can be committed. The
    // file has the same name as for the compact format types because they have the
    // same package, but we've set things up so this only contains the service types.
    fs::copy(out.join("cash.z.wallet.sdk.rpc.rs"), "src/proto/service.rs")?;

    Ok(())
}
