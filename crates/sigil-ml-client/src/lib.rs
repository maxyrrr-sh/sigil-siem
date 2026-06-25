//! `sigil-ml-client` — typed gRPC client for the Python ML sidecar (DESIGN §9.9).
//!
//! The sidecar runs the heavy ML (SecureBERT embeddings, the GNN/MAGIC anomaly
//! scorer). Rust orchestrates and calls it over gRPC; the contract lives in
//! `proto/sigil_ml.proto`. This is the **control + small-request** surface —
//! bulk tensor payloads are intended to move over Arrow Flight later.
//!
//! `sigil-correlate` uses this behind its `sidecar` feature, falling back to the
//! offline `HashingEmbedder` when the sidecar is unset or unreachable, so the
//! default build never requires a running Python process.

use sigil_core::{Error, Result};

/// Generated protobuf types + client stub (`package sigil.ml.v1`).
pub mod pb {
    tonic::include_proto!("sigil.ml.v1");
}

use pb::ml_sidecar_client::MlSidecarClient;
use tonic::transport::Channel;

fn transport_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(format!("ml-sidecar: {e}"))
}

/// A connected client to the ML sidecar.
#[derive(Clone)]
pub struct SidecarClient {
    inner: MlSidecarClient<Channel>,
    endpoint: String,
}

impl SidecarClient {
    /// Connect to the sidecar at `endpoint` (e.g. `http://127.0.0.1:50051`).
    pub async fn connect(endpoint: impl Into<String>) -> Result<SidecarClient> {
        let endpoint = endpoint.into();
        let inner = MlSidecarClient::connect(endpoint.clone())
            .await
            .map_err(transport_err)?;
        Ok(SidecarClient { inner, endpoint })
    }

    /// The endpoint this client is bound to.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Liveness + version handshake. Returns `(ok, version)`.
    pub async fn health(&mut self) -> Result<(bool, String)> {
        let reply = self
            .inner
            .health(pb::HealthRequest {})
            .await
            .map_err(transport_err)?
            .into_inner();
        Ok((reply.ok, reply.version))
    }

    /// Embed a batch of JSON-serialized events into dense vectors.
    pub async fn embed(&mut self, events_json: Vec<String>) -> Result<Vec<Vec<f32>>> {
        let reply = self
            .inner
            .embed(pb::EmbedRequest {
                event_json: events_json,
            })
            .await
            .map_err(transport_err)?
            .into_inner();
        Ok(reply.vectors.into_iter().map(|v| v.values).collect())
    }

    /// Score a JSON-serialized subgraph, returning `(anomaly, causal)` in 0..=1.
    pub async fn score(&mut self, subgraph_json: String) -> Result<(f32, f32)> {
        let reply = self
            .inner
            .score(pb::ScoreRequest { subgraph_json })
            .await
            .map_err(transport_err)?
            .into_inner();
        Ok((reply.anomaly, reply.causal))
    }
}
