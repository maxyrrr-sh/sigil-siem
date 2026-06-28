//! DGA (domain-generation-algorithm) detector (`detect:dga`).
//!
//! Fires when an event's `dga.score` (bits/char, stamped by the `entropy`
//! enricher) meets a threshold — flagging likely C2 domains. Maps to ATT&CK
//! T1568.002 (Dynamic Resolution: Domain Generation Algorithms).

use sigil_core::{Alert, Detector, Event, Plugin, PluginManifest, Severity};

const DEFAULT_THRESHOLD: f64 = 3.5;

pub struct DgaDetector {
    manifest: PluginManifest,
    threshold: f64,
}

impl Default for DgaDetector {
    fn default() -> Self {
        DgaDetector {
            manifest: PluginManifest {
                name: "dga".into(),
                version: "0.0.0".into(),
                capabilities: vec!["read:field:dga.score".into()],
            },
            threshold: DEFAULT_THRESHOLD,
        }
    }
}

impl DgaDetector {
    /// Read an optional `threshold` (bits/char) from step settings.
    pub fn from_settings(settings: &serde_yaml::Value) -> Self {
        let threshold = settings
            .get("threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(DEFAULT_THRESHOLD);
        DgaDetector {
            threshold,
            ..Default::default()
        }
    }
}

impl Plugin for DgaDetector {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Detector for DgaDetector {
    fn eval(&self, event: &Event) -> Option<Alert> {
        let score: f64 = event.field_str("dga.score")?.parse().ok()?;
        if score < self.threshold {
            return None;
        }
        let domain = event
            .target
            .as_ref()
            .map(|t| t.id.clone())
            .or_else(|| event.field_str("domain"))
            .unwrap_or_default();
        Some(Alert {
            rule_id: "dga-domain".into(),
            title: if domain.is_empty() {
                "DGA-like domain".into()
            } else {
                format!("DGA-like domain: {domain}")
            },
            severity: Severity::Medium,
            technique: Some("T1568.002".into()),
            events: vec![event.id.clone()],
            ts: event.ts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::EntityRef;

    #[test]
    fn fires_above_threshold() {
        let mut e = Event::new("t");
        e.target = Some(EntityRef::new("domain", "a8f3kq9zx2m7wp1r.example.com"));
        e.fields.insert("dga.score".into(), serde_json::json!(4.0));
        let alert = DgaDetector::default().eval(&e).expect("should fire");
        assert_eq!(alert.rule_id, "dga-domain");
        assert_eq!(alert.technique.as_deref(), Some("T1568.002"));
        assert!(alert.title.contains("a8f3kq9zx2m7wp1r"));
    }

    #[test]
    fn quiet_below_threshold() {
        let mut e = Event::new("t");
        e.fields.insert("dga.score".into(), serde_json::json!(2.0));
        assert!(DgaDetector::default().eval(&e).is_none());
    }

    #[test]
    fn quiet_without_score() {
        let e = Event::new("t");
        assert!(DgaDetector::default().eval(&e).is_none());
    }

    #[test]
    fn respects_custom_threshold() {
        let det = DgaDetector::from_settings(&serde_yaml::from_str("threshold: 4.5").unwrap());
        let mut e = Event::new("t");
        e.fields.insert("dga.score".into(), serde_json::json!(4.0));
        assert!(det.eval(&e).is_none(), "4.0 < custom 4.5 should stay quiet");
    }
}
