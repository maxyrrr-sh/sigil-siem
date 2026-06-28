//! `sigil-enrich` — the enrichment/processor chain (DESIGN §5 step "enrich",
//! §12.1 `Processor`).
//!
//! Pipelines declare enrich steps (`enrich: [geoip, threat_intel]`). This crate
//! turns those names into [`Enricher`]s and runs them as an [`EnrichChain`] on
//! the hot path **after normalize, before index/Sigma**. Enrichers mutate an
//! [`Event`] in place (1→1, no allocation per event) and declare the
//! [`Capability`]s they need so the host can refuse ungranted ones
//! (deny-by-default; see `sigil-plugin-wasm`).
//!
//! Shipped enrichers: [`redact`], [`entropy`], [`threatintel`]. `geoip` is
//! recognized but not implemented yet (it needs a MaxMind database).

use sigil_core::{Capability, Event};

pub mod entropy;
pub mod redact;
pub mod threatintel;

pub use entropy::EntropyEnricher;
pub use redact::RedactEnricher;
pub use threatintel::ThreatIntelEnricher;

/// An in-place event enricher. Cheap, synchronous, runs on the ingest hot path.
pub trait Enricher: Send + Sync {
    /// Stable identifier (matches the config `enrich:` name).
    fn name(&self) -> &'static str;
    /// Capabilities this enricher requires (checked against the host policy).
    fn capabilities(&self) -> Vec<Capability>;
    /// Enrich one event in place.
    fn enrich(&self, event: &mut Event);
}

/// An ordered list of enrichers applied to every event.
#[derive(Default)]
pub struct EnrichChain {
    enrichers: Vec<Box<dyn Enricher>>,
}

impl EnrichChain {
    pub fn new(enrichers: Vec<Box<dyn Enricher>>) -> Self {
        EnrichChain { enrichers }
    }

    pub fn is_empty(&self) -> bool {
        self.enrichers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.enrichers.len()
    }

    /// Names of the enrichers in order (for logging).
    pub fn names(&self) -> Vec<&'static str> {
        self.enrichers.iter().map(|e| e.name()).collect()
    }

    /// Apply every enricher to `event`, in order.
    pub fn apply(&self, event: &mut Event) {
        for e in &self.enrichers {
            e.enrich(event);
        }
    }
}

/// The enricher names this crate knows how to build.
pub const KNOWN_ENRICHERS: &[&str] = &["redact", "entropy", "threatintel", "threat_intel"];

/// Construct an enricher by name + per-step settings. Returns `None` (with a
/// warning) for unknown or not-yet-implemented names so configs stay
/// forward-compatible.
pub fn build_enricher(name: &str, settings: &serde_yaml::Value) -> Option<Box<dyn Enricher>> {
    match name {
        "redact" => Some(Box::new(RedactEnricher::new())),
        "entropy" => Some(Box::new(EntropyEnricher::from_settings(settings))),
        "threatintel" | "threat_intel" => {
            Some(Box::new(ThreatIntelEnricher::from_settings(settings)))
        }
        "geoip" => {
            tracing::warn!(
                "enricher `geoip` is not implemented yet (needs a MaxMind database); skipping"
            );
            None
        }
        other => {
            tracing::warn!(enricher = %other, "unknown enricher; skipping");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_enricher_is_skipped() {
        assert!(build_enricher("does_not_exist", &serde_yaml::Value::Null).is_none());
        assert!(build_enricher("geoip", &serde_yaml::Value::Null).is_none());
    }

    #[test]
    fn chain_applies_in_order() {
        let chain = EnrichChain::new(vec![Box::new(RedactEnricher::new())]);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.names(), vec!["redact"]);
    }
}
