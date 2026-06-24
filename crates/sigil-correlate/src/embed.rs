//! Event embeddings (DESIGN §9.3): a field-aware serialization of an event
//! into text, then a dense vector.
//!
//! Phase 3 ships a deterministic, offline [`HashingEmbedder`] (feature-hashing
//! bag-of-tokens) so correlation runs with no model download. This captures
//! *lexical* similarity (shared users / ips / verbs). The production path is the
//! same [`Embedder`] trait backed by the ML sidecar (SecureBERT) for true
//! semantic similarity — a drop-in swap (DESIGN §9.9).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use sigil_core::Event;

/// Anything that turns event text into a dense vector.
pub trait Embedder: Send + Sync {
    fn dim(&self) -> usize;
    fn embed(&self, text: &str) -> Vec<f32>;

    /// Convenience: embed an event via [`serialize_event`].
    fn embed_event(&self, event: &Event) -> Vec<f32> {
        self.embed(&serialize_event(event))
    }
}

/// Field-aware serialization of an event to a single text line (DESIGN §9.3).
pub fn serialize_event(event: &Event) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = write!(s, "class={}", class_token(event));
    if let Some(a) = &event.actor {
        let _ = write!(s, " actor={}:{}", a.kind, a.id);
    }
    if let Some(t) = &event.target {
        let _ = write!(s, " target={}:{}", t.kind, t.id);
    }
    if let Some(h) = &event.host {
        let _ = write!(s, " host={}", h.id);
    }
    if let Some(tid) = event.template_id {
        let _ = write!(s, " template={tid}");
    }
    if !event.message.is_empty() {
        let _ = write!(s, " msg={}", event.message);
    }
    s
}

fn class_token(event: &Event) -> &'static str {
    use sigil_core::OcsfClass::*;
    match event.ocsf_class {
        Authentication => "authentication",
        ProcessActivity => "process_activity",
        FileSystemActivity => "file_system_activity",
        NetworkActivity => "network_activity",
        HttpActivity => "http_activity",
        ApiActivity => "api_activity",
        Other(_) => "other",
    }
}

/// Deterministic feature-hashing embedder. Tokens are hashed into `dim`
/// buckets with a sign, then the vector is L2-normalized. Matches the Python
/// sidecar's fallback embedder so the two are interchangeable.
#[derive(Debug, Clone)]
pub struct HashingEmbedder {
    dim: usize,
}

impl HashingEmbedder {
    pub fn new(dim: usize) -> Self {
        HashingEmbedder { dim: dim.max(1) }
    }
}

impl Default for HashingEmbedder {
    fn default() -> Self {
        HashingEmbedder::new(128)
    }
}

impl Embedder for HashingEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; self.dim];
        for token in text.split_whitespace() {
            let h = hash_token(&token.to_lowercase());
            let bucket = (h % self.dim as u64) as usize;
            let sign = if (h >> 33) & 1 == 0 { 1.0 } else { -1.0 };
            v[bucket] += sign;
        }
        l2_normalize(&mut v);
        v
    }
}

fn hash_token(token: &str) -> u64 {
    let mut h = DefaultHasher::new();
    token.hash(&mut h);
    h.finish()
}

fn l2_normalize(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{EntityRef, OcsfClass};

    #[test]
    fn serialization_includes_entities_and_class() {
        let mut e = Event::new("acme");
        e.ocsf_class = OcsfClass::Authentication;
        e.actor = Some(EntityRef::new("user", "root"));
        e.message = "login ok".into();
        let s = serialize_event(&e);
        assert!(s.contains("class=authentication"));
        assert!(s.contains("actor=user:root"));
        assert!(s.contains("msg=login ok"));
    }

    #[test]
    fn embedding_is_unit_length_and_deterministic() {
        let emb = HashingEmbedder::new(64);
        let a = emb.embed("failed password for root from 10.0.0.9");
        let b = emb.embed("failed password for root from 10.0.0.9");
        assert_eq!(a, b);
        let norm: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn shared_tokens_raise_cosine() {
        let emb = HashingEmbedder::new(256);
        let dot = |a: &[f32], b: &[f32]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();
        let base = emb.embed("user root host web01 connect 9.9.9.9");
        let near = emb.embed("user root host web01 execute bash");
        let far = emb.embed("totally unrelated tokens here xyz");
        assert!(dot(&base, &near) > dot(&base, &far));
    }
}
