use protobuf_codegen_pure;

fn main() {
    protobuf_codegen_pure::Codegen::new()
        .out_dir("src/proto")
        .inputs(&["proto/compact_formats.proto"])
        .includes(&["proto"])
        .run()
        .expect("Protobuf codegen failed");
}
