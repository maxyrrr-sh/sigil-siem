//! Entropy / DGA-scoring enricher (`enrich:entropy`).
//!
//! Computes the Shannon entropy of domain-like values and stamps a `dga.score`
//! (bits/char) + `dga.entropy` field, labelling likely algorithmically-
//! generated domains. The DGA *detector* (Phase E) thresholds this score.

use serde_json::Value;
use sigil_core::{Capability, Event};

use crate::Enricher;

/// Default bits/char above which a domain label is flagged.
const DEFAULT_THRESHOLD: f64 = 3.5;
/// Minimum candidate length to bother scoring (short strings are noisy).
const MIN_LEN: usize = 8;

/// Fields that may carry a domain/host to score, in priority order.
const DOMAIN_FIELDS: &[&str] = &["domain", "dns_query", "query", "dns.question.name", "host"];

pub struct EntropyEnricher {
    threshold: f64,
}

impl Default for EntropyEnricher {
    fn default() -> Self {
        EntropyEnricher {
            threshold: DEFAULT_THRESHOLD,
        }
    }
}

impl EntropyEnricher {
    /// Read an optional `threshold` (bits/char) from step settings.
    pub fn from_settings(settings: &serde_yaml::Value) -> Self {
        let threshold = settings
            .get("threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(DEFAULT_THRESHOLD);
        EntropyEnricher { threshold }
    }
}

impl Enricher for EntropyEnricher {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::Enrich("entropy".into())]
    }

    fn enrich(&self, event: &mut Event) {
        let Some(candidate) = candidate_domain(event) else {
            return;
        };
        // Score the most-significant label (strip a trailing TLD).
        let label = significant_label(&candidate);
        if label.len() < MIN_LEN {
            return;
        }
        let bits = shannon_entropy(label);
        event.fields.insert(
            "dga.entropy".into(),
            Value::from((bits * 100.0).round() / 100.0),
        );
        event.fields.insert(
            "dga.score".into(),
            Value::from((bits * 100.0).round() / 100.0),
        );
        if bits >= self.threshold && !event.labels.iter().any(|l| l == "dga-suspect") {
            event.labels.push("dga-suspect".into());
        }
    }
}

/// Find a domain/host candidate from the event target or known fields.
fn candidate_domain(event: &Event) -> Option<String> {
    if let Some(t) = &event.target {
        if t.kind == "domain" || t.kind == "host" {
            return Some(t.id.clone());
        }
    }
    for key in DOMAIN_FIELDS {
        if let Some(s) = event.field_str(key) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// The most-significant label of a domain: e.g. `kq3v9z.example.com` → `kq3v9z`.
fn significant_label(domain: &str) -> &str {
    let trimmed = domain.trim_end_matches('.');
    let parts: Vec<&str> = trimmed.split('.').collect();
    match parts.len() {
        0 => trimmed,
        1 => parts[0],
        // Drop the last two labels (registrable domain + TLD) when present.
        n => parts.get(n.saturating_sub(3)).copied().unwrap_or(parts[0]),
    }
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    let mut total = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
        total += 1;
    }
    let total = total as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::EntityRef;

    #[test]
    fn entropy_higher_for_random_strings() {
        let normal = shannon_entropy("wwwgoogle");
        let random = shannon_entropy("xq3v9zkpwm");
        assert!(
            random > normal,
            "random {random} should exceed normal {normal}"
        );
    }

    #[test]
    fn flags_high_entropy_domain() {
        let mut e = Event::new("t");
        // 16 distinct chars → ~4 bits/char, well above the 3.5 threshold.
        e.target = Some(EntityRef::new("domain", "a8f3kq9zx2m7wp1r.example.com"));
        EntropyEnricher::default().enrich(&mut e);
        assert!(e.labels.iter().any(|l| l == "dga-suspect"));
        assert!(e.field_str("dga.score").is_some());
    }

    #[test]
    fn leaves_normal_domain_unflagged() {
        let mut e = Event::new("t");
        e.target = Some(EntityRef::new("domain", "downloads.example.com"));
        EntropyEnricher::default().enrich(&mut e);
        assert!(!e.labels.iter().any(|l| l == "dga-suspect"));
    }

    #[test]
    fn significant_label_strips_registrable_domain() {
        assert_eq!(significant_label("kq3v9z.example.com"), "kq3v9z");
        assert_eq!(significant_label("example.com"), "example");
    }
}
