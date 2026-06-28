//! PII redaction + defang enricher (`enrich:redact`).
//!
//! Masks emails and obvious secrets and defangs URLs in `message` and string
//! fields so alerts/exports are safe to share. Pure + offline. Runs early in
//! the chain — order it *after* detectors if you need to match on raw values.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;
use sigil_core::{Capability, Event};

use crate::Enricher;

/// Redacts PII/secrets in place.
#[derive(Default)]
pub struct RedactEnricher;

impl RedactEnricher {
    pub fn new() -> Self {
        RedactEnricher
    }
}

impl Enricher for RedactEnricher {
    fn name(&self) -> &'static str {
        "redact"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::Enrich("redact".into())]
    }

    fn enrich(&self, event: &mut Event) {
        event.message = redact(&event.message);
        for v in event.fields.values_mut() {
            if let Value::String(s) = v {
                let r = redact(s);
                if &r != s {
                    *s = r;
                }
            }
        }
    }
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})").unwrap())
}

fn aws_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap())
}

fn secret_kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // password=..., token: ..., secret = ... (value up to whitespace)
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b(\s*[:=]\s*)(\S+)").unwrap()
    })
}

/// Apply all redactions to a string.
fn redact(input: &str) -> String {
    // Mask email local-part, keep the domain for triage.
    let s = email_re().replace_all(input, "***@$2").into_owned();
    let s = aws_key_re()
        .replace_all(&s, "AKIA****************")
        .into_owned();
    let s = secret_kv_re().replace_all(&s, "$1$2***").into_owned();
    // Defang URL schemes so links aren't clickable in downstream tools.
    s.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_email_keeps_domain() {
        assert_eq!(
            redact("login from alice@corp.com ok"),
            "login from ***@corp.com ok"
        );
    }

    #[test]
    fn masks_secrets_and_keys() {
        assert_eq!(redact("password=hunter2"), "password=***");
        assert_eq!(redact("api_key: ABC123"), "api_key: ***");
        assert_eq!(
            redact("key AKIAIOSFODNN7EXAMPLE used"),
            "key AKIA**************** used"
        );
    }

    #[test]
    fn defangs_urls() {
        assert_eq!(redact("see http://evil.test/x"), "see hxxp://evil.test/x");
    }

    #[test]
    fn enriches_message_and_fields() {
        let mut e = Event::new("t");
        e.message = "user bob@x.io".into();
        e.fields
            .insert("note".into(), serde_json::json!("token=abc"));
        RedactEnricher::new().enrich(&mut e);
        assert_eq!(e.message, "user ***@x.io");
        assert_eq!(e.field_str("note").as_deref(), Some("token=***"));
    }
}
