//! Sidecar-backed embeddings (DESIGN §9.9), behind the `sidecar` feature.
//!
//! The [`Embedder`] trait is synchronous, but the gRPC sidecar is async, so we
//! **batch-embed up front**: [`precompute`] serializes every event, asks the
//! sidecar for vectors in one call, and returns a [`PrecomputedEmbedder`] that
//! the existing synchronous correlation pipeline can use by lookup. Any event
//! the sidecar didn't cover falls back to the offline [`HashingEmbedder`], so a
//! partial/unreachable sidecar degrades gracefully rather than failing.

use std::collections::HashMap;

use sigil_core::{Event, Result};
use sigil_ml_client::SidecarClient;

use crate::embed::{serialize_event, Embedder, HashingEmbedder};

/// An [`Embedder`] backed by vectors the sidecar already computed, keyed by the
/// same field-aware serialization the pipeline embeds with.
pub struct PrecomputedEmbedder {
    dim: usize,
    map: HashMap<String, Vec<f32>>,
    fallback: HashingEmbedder,
}

impl PrecomputedEmbedder {
    /// Build from an explicit `serialized-text → vector` map (used in tests and
    /// by [`precompute`]).
    pub fn from_map(dim: usize, map: HashMap<String, Vec<f32>>) -> Self {
        PrecomputedEmbedder {
            dim,
            map,
            fallback: HashingEmbedder::new(dim),
        }
    }

    /// How many events were covered by the sidecar.
    pub fn covered(&self) -> usize {
        self.map.len()
    }
}

impl Embedder for PrecomputedEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        self.map
            .get(text)
            .cloned()
            .unwrap_or_else(|| self.fallback.embed(text))
    }
}

/// Connect to the sidecar at `endpoint`, embed all `events` in one request, and
/// return a [`PrecomputedEmbedder`]. The vector dimension is taken from the
/// sidecar's reply (falling back to `default_dim` if it returned nothing).
pub async fn precompute(
    endpoint: &str,
    events: &[Event],
    default_dim: usize,
) -> Result<PrecomputedEmbedder> {
    let mut client = SidecarClient::connect(endpoint.to_string()).await?;
    let texts: Vec<String> = events.iter().map(serialize_event).collect();
    let vectors = client.embed(texts.clone()).await?;
    let dim = vectors.first().map(|v| v.len()).unwrap_or(default_dim);
    let map: HashMap<String, Vec<f32>> = texts.into_iter().zip(vectors).collect();
    tracing::info!(
        endpoint,
        covered = map.len(),
        dim,
        "sidecar embeddings ready"
    );
    Ok(PrecomputedEmbedder::from_map(dim, map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_hits_precomputed_and_falls_back() {
        let mut map = HashMap::new();
        map.insert(
            "class=authentication msg=login".to_string(),
            vec![1.0, 0.0, 0.0],
        );
        let emb = PrecomputedEmbedder::from_map(3, map);
        // Known text → exact precomputed vector.
        assert_eq!(
            emb.embed("class=authentication msg=login"),
            vec![1.0, 0.0, 0.0]
        );
        // Unknown text → deterministic fallback of the right dimension.
        let v = emb.embed("class=process_activity msg=whoami");
        assert_eq!(v.len(), 3);
        assert_eq!(emb.covered(), 1);
    }
}
