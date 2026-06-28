//! `sigil-detect` — custom detectors beyond Sigma (DESIGN §8, §12.1
//! `Detector`).
//!
//! Sigma covers per-event signatures; this crate hosts detectors that express
//! things Sigma can't, and a [`DetectorChain`] the runtime evaluates **after**
//! the Sigma engine. Each detector implements [`sigil_core::Detector`] and
//! returns an [`Alert`] when it fires.
//!
//! Shipped: [`dga::DgaDetector`] (flags algorithmically-generated domains using
//! the `dga.score` stamped by the `entropy` enricher).

use sigil_core::{Alert, Detector, Event};

pub mod dga;

pub use dga::DgaDetector;

/// An ordered set of custom detectors evaluated over each event.
#[derive(Default)]
pub struct DetectorChain {
    detectors: Vec<Box<dyn Detector + Send + Sync>>,
}

impl DetectorChain {
    pub fn new(detectors: Vec<Box<dyn Detector + Send + Sync>>) -> Self {
        DetectorChain { detectors }
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn names(&self) -> Vec<&str> {
        self.detectors
            .iter()
            .map(|d| d.manifest().name.as_str())
            .collect()
    }

    /// Evaluate every detector over `event`, collecting all that fire.
    pub fn eval(&self, event: &Event) -> Vec<Alert> {
        self.detectors
            .iter()
            .filter_map(|d| d.eval(event))
            .collect()
    }
}

/// The detector names this crate knows how to build.
pub const KNOWN_DETECTORS: &[&str] = &["dga"];

/// Construct a detector by name + settings. Returns `None` (with a warning) for
/// unknown names so configs stay forward-compatible.
pub fn build_detector(
    name: &str,
    settings: &serde_yaml::Value,
) -> Option<Box<dyn Detector + Send + Sync>> {
    match name {
        "dga" => Some(Box::new(DgaDetector::from_settings(settings))),
        other => {
            tracing::warn!(detector = %other, "unknown detector; skipping");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_detector_is_skipped() {
        assert!(build_detector("nope", &serde_yaml::Value::Null).is_none());
    }

    #[test]
    fn chain_collects_firing_detectors() {
        let chain = DetectorChain::new(vec![Box::new(DgaDetector::default())]);
        assert_eq!(chain.names(), vec!["dga"]);
        let mut e = Event::new("t");
        e.fields.insert("dga.score".into(), serde_json::json!(4.2));
        assert_eq!(chain.eval(&e).len(), 1);
    }
}
