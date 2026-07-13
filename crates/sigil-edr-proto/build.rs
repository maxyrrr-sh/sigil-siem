//! Generate the tonic gRPC **client and server** stubs from
//! `proto/sigil_edr.proto`. Both `sigil-edr` (server) and `sigil-agent`
//! (client) depend on this crate so the wire contract lives in one place.
//!
//! Like `sigil-ml-client`, we point `prost-build` at a vendored `protoc` so the
//! build is hermetic — no system `protoc` install required.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
    std::env::set_var("PROTOC", protoc);

    let proto = "../../proto/sigil_edr.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["../../proto"])
        .expect("compile sigil_edr.proto");
}
