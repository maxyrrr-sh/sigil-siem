//! Threat-intel IOC-matching enricher (`enrich:threatintel`).
//!
//! Loads indicators (IPs / domains / hashes) from a local feed file and stamps
//! `threat.matched` + `threat.indicator` and a `threat-intel-hit` label on
//! events whose entities or key fields match. The feed is loaded once into an
//! in-memory set so matching never touches the network on the hot path; a
//! remote, periodically-refreshed feed (requiring `net:egress`) is a follow-up.

use std::collections::HashSet;

use serde_json::Value;
use sigil_core::{Capability, Event};

use crate::Enricher;

/// Event fields that may carry a matchable indicator.
const IOC_FIELDS: &[&str] = &[
    "src_ip",
    "dst_ip",
    "ip",
    "domain",
    "dns_query",
    "query",
    "url",
    "hash",
    "md5",
    "sha1",
    "sha256",
];

pub struct ThreatIntelEnricher {
    indicators: HashSet<String>,
}

impl ThreatIntelEnricher {
    /// Build from an explicit set (used in tests).
    pub fn from_set(indicators: HashSet<String>) -> Self {
        ThreatIntelEnricher { indicators }
    }

    /// Read indicators from a local `feed` file (one per line; `#` comments).
    pub fn from_settings(settings: &serde_yaml::Value) -> Self {
        let mut indicators = HashSet::new();
        if let Some(path) = settings.get("feed").and_then(|v| v.as_str()) {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        indicators.insert(line.to_ascii_lowercase());
                    }
                    tracing::info!(feed = %path, count = indicators.len(), "loaded threat-intel feed");
                }
                Err(e) => {
                    tracing::warn!(feed = %path, error = %e, "cannot read threat-intel feed; matching disabled")
                }
            }
        } else {
            tracing::warn!("threatintel enricher has no `feed` path; matching disabled");
        }
        ThreatIntelEnricher { indicators }
    }

    /// First indicator that matches any candidate value in the event.
    fn match_event(&self, event: &Event) -> Option<String> {
        if self.indicators.is_empty() {
            return None;
        }
        let check = |val: &str| -> Option<String> {
            let v = val.to_ascii_lowercase();
            self.indicators.get(&v).cloned()
        };
        for entity in [&event.host, &event.actor, &event.target]
            .into_iter()
            .flatten()
        {
            if let Some(hit) = check(&entity.id) {
                return Some(hit);
            }
        }
        for key in IOC_FIELDS {
            if let Some(s) = event.field_str(key) {
                if let Some(hit) = check(&s) {
                    return Some(hit);
                }
            }
        }
        None
    }
}

impl Enricher for ThreatIntelEnricher {
    fn name(&self) -> &'static str {
        "threatintel"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::Enrich("threatintel".into())]
    }

    fn enrich(&self, event: &mut Event) {
        if let Some(indicator) = self.match_event(event) {
            event
                .fields
                .insert("threat.matched".into(), Value::Bool(true));
            event
                .fields
                .insert("threat.indicator".into(), Value::String(indicator));
            if !event.labels.iter().any(|l| l == "threat-intel-hit") {
                event.labels.push("threat-intel-hit".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::EntityRef;

    fn enricher() -> ThreatIntelEnricher {
        let mut set = HashSet::new();
        set.insert("198.51.100.7".to_string());
        set.insert("evil.example".to_string());
        ThreatIntelEnricher::from_set(set)
    }

    #[test]
    fn matches_field_indicator() {
        let mut e = Event::new("t");
        e.fields
            .insert("dst_ip".into(), serde_json::json!("198.51.100.7"));
        enricher().enrich(&mut e);
        assert_eq!(e.field_str("threat.matched").as_deref(), Some("true"));
        assert_eq!(
            e.field_str("threat.indicator").as_deref(),
            Some("198.51.100.7")
        );
        assert!(e.labels.iter().any(|l| l == "threat-intel-hit"));
    }

    #[test]
    fn matches_entity_case_insensitively() {
        let mut e = Event::new("t");
        e.target = Some(EntityRef::new("domain", "EVIL.example"));
        enricher().enrich(&mut e);
        assert!(e.labels.iter().any(|l| l == "threat-intel-hit"));
    }

    #[test]
    fn no_match_leaves_event_clean() {
        let mut e = Event::new("t");
        e.fields
            .insert("dst_ip".into(), serde_json::json!("10.0.0.1"));
        enricher().enrich(&mut e);
        assert!(e.field_str("threat.matched").is_none());
        assert!(e.labels.is_empty());
    }

    #[test]
    fn empty_feed_is_inert() {
        let enr = ThreatIntelEnricher::from_set(HashSet::new());
        let mut e = Event::new("t");
        e.target = Some(EntityRef::new("domain", "evil.example"));
        enr.enrich(&mut e);
        assert!(e.labels.is_empty());
    }
}
