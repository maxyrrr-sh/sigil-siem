//! `sigil-edr-proto` — the generated gRPC types + client/server stubs for the
//! Sigil EDR agent protocol (`package sigil.edr.v1`, see
//! `proto/sigil_edr.proto`). Shared by `sigil-edr` (server) and `sigil-agent`
//! (endpoint binary) so the wire contract has a single source of truth.

/// Generated protobuf types + client/server stubs.
pub mod pb {
    tonic::include_proto!("sigil.edr.v1");
}

pub use pb::*;
