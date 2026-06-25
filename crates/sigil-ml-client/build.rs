//! Generate the tonic gRPC client from `proto/sigil_ml.proto`.
//!
//! We point `prost-build` at a vendored `protoc` so the build is hermetic — no
//! system `protoc` install required on dev machines or in CI.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
    std::env::set_var("PROTOC", protoc);

    let proto = "../../proto/sigil_ml.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&[proto], &["../../proto"])
        .expect("compile sigil_ml.proto");
}
