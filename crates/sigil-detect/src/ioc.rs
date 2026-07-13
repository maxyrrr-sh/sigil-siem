//! IOC-matching detector (`detect:ioc`).
//!
//! Matches endpoint/network telemetry against analyst-supplied indicator lists
//! — file/process/module SHA-256 hashes, IP addresses, and domains. Fires when
//! an event references any known-bad indicator. Indicator sets load from files
//! (one value per line, `#` comments allowed) or inline lists in the config.

use std::collections::HashSet;

use sigil_core::{Alert, Detector, Event, Plugin, PluginManifest, Severity};

/// A single indicator category and the fields it is checked against.
pub struct IocDetector {
    manifest: PluginManifest,
    hashes: HashSet<String>,
    ips: HashSet<String>,
    domains: HashSet<String>,
}

impl Default for IocDetector {
    fn default() -> Self {
        IocDetector {
            manifest: PluginManifest {
                name: "ioc".into(),
                version: "0.0.0".into(),
                capabilities: vec![
                    "read:field:file.hash.sha256".into(),
                    "read:field:process.hash.sha256".into(),
                    "read:field:destination.ip".into(),
                    "read:field:dns.question.name".into(),
                ],
            },
            hashes: HashSet::new(),
            ips: HashSet::new(),
            domains: HashSet::new(),
        }
    }
}

impl IocDetector {
    /// Build from step settings. Each of `hashes`/`ips`/`domains` may be a file
    /// path (newline-delimited) or an inline list of indicators.
    pub fn from_settings(settings: &serde_yaml::Value) -> Self {
        IocDetector {
            hashes: load_set(settings.get("hashes")),
            ips: load_set(settings.get("ips")),
            domains: load_set(settings.get("domains")),
            ..Default::default()
        }
    }

    /// Total indicators loaded (for logging / tests).
    pub fn len(&self) -> usize {
        self.hashes.len() + self.ips.len() + self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn hash_hit(&self, event: &Event) -> Option<String> {
        for field in [
            "process.hash.sha256",
            "file.hash.sha256",
            "module.hash.sha256",
        ] {
            if let Some(v) = event.field_str(field) {
                let v = v.to_lowercase();
                if self.hashes.contains(&v) {
                    return Some(v);
                }
            }
        }
        None
    }

    fn ip_hit(&self, event: &Event) -> Option<String> {
        for field in ["destination.ip", "source.ip"] {
            if let Some(v) = event.field_str(field) {
                if self.ips.contains(&v) {
                    return Some(v);
                }
            }
        }
        None
    }

    fn domain_hit(&self, event: &Event) -> Option<String> {
        if let Some(v) = event.field_str("dns.question.name") {
            let v = v.to_lowercase();
            if self.domains.contains(&v) {
                return Some(v);
            }
        }
        if let Some(t) = &event.target {
            if t.kind == "domain" && self.domains.contains(&t.id.to_lowercase()) {
                return Some(t.id.clone());
            }
        }
        None
    }
}

impl Plugin for IocDetector {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Detector for IocDetector {
    fn eval(&self, event: &Event) -> Option<Alert> {
        let (kind, value, technique) = if let Some(h) = self.hash_hit(event) {
            ("hash", h, "T1204")
        } else if let Some(ip) = self.ip_hit(event) {
            ("ip", ip, "T1071")
        } else if let Some(d) = self.domain_hit(event) {
            ("domain", d, "T1071")
        } else {
            return None;
        };
        Some(Alert {
            rule_id: format!("ioc-{kind}-match"),
            title: format!("IOC match ({kind}): {value}"),
            severity: Severity::High,
            technique: Some(technique.into()),
            events: vec![event.id.clone()],
            ts: event.ts,
        })
    }
}

/// Load an indicator set from a config value: a file path, or an inline list.
fn load_set(value: Option<&serde_yaml::Value>) -> HashSet<String> {
    let mut out = HashSet::new();
    match value {
        Some(serde_yaml::Value::String(path)) => match std::fs::read_to_string(path) {
            Ok(text) => {
                for line in text.lines() {
                    add_indicator(&mut out, line);
                }
            }
            Err(e) => tracing::warn!(path = %path, error = %e, "cannot read IOC file"),
        },
        Some(serde_yaml::Value::Sequence(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    add_indicator(&mut out, s);
                }
            }
        }
        _ => {}
    }
    out
}

fn add_indicator(set: &mut HashSet<String>, raw: &str) {
    let v = raw.trim();
    if v.is_empty() || v.starts_with('#') {
        return;
    }
    set.insert(v.to_lowercase());
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::EntityRef;

    fn detector() -> IocDetector {
        let settings = serde_yaml::from_str(
            "hashes:\n  - DEADBEEF\nips:\n  - 10.0.0.9\ndomains:\n  - evil.example.com\n",
        )
        .unwrap();
        IocDetector::from_settings(&settings)
    }

    #[test]
    fn matches_hash_case_insensitively() {
        let det = detector();
        let mut e = Event::new("t");
        e.fields
            .insert("file.hash.sha256".into(), serde_json::json!("deadbeef"));
        let alert = det.eval(&e).expect("hash IOC should fire");
        assert_eq!(alert.rule_id, "ioc-hash-match");
        assert_eq!(alert.technique.as_deref(), Some("T1204"));
    }

    #[test]
    fn matches_destination_ip() {
        let det = detector();
        let mut e = Event::new("t");
        e.fields
            .insert("destination.ip".into(), serde_json::json!("10.0.0.9"));
        assert_eq!(det.eval(&e).unwrap().rule_id, "ioc-ip-match");
    }

    #[test]
    fn matches_domain_target() {
        let det = detector();
        let mut e = Event::new("t");
        e.target = Some(EntityRef::new("domain", "evil.example.com"));
        assert_eq!(det.eval(&e).unwrap().rule_id, "ioc-domain-match");
    }

    #[test]
    fn quiet_on_clean_event() {
        let det = detector();
        let mut e = Event::new("t");
        e.fields
            .insert("destination.ip".into(), serde_json::json!("8.8.8.8"));
        assert!(det.eval(&e).is_none());
    }
}
