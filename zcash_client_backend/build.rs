use protobuf_codegen_pure;

fn main() {
    protobuf_codegen_pure::run(protobuf_codegen_pure::Args {
        out_dir: "src/proto",
        input: &["proto/compact_formats.proto"],
        includes: &["proto"],
        customize: Default::default(),
    })
    .expect("protoc");
}
