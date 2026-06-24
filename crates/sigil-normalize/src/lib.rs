//! `sigil-normalize` — map decoded [`Record`]s onto the OCSF [`Event`] model
//! (DESIGN §6).
//!
//! Phase 0 ships a minimal but real mapping for a few source shapes: generic
//! syslog, authentication lines, network/JSON, and HTTP/JSON. It recognizes a
//! handful of ECS aliases (`host.name`, `source.ip`, ...) alongside flat keys.
//! The raw record is always preserved on the event; unmapped fields are kept
//! verbatim (schema-on-read fallback).

use std::collections::BTreeMap;

use serde_json::Value;
use sigil_core::{value_to_string, EntityRef, Event, OcsfClass, Record, Severity};

/// Maps records into normalized events for a given tenant.
#[derive(Debug, Clone)]
pub struct Normalizer {
    tenant: String,
}

impl Normalizer {
    pub fn new(tenant: impl Into<String>) -> Self {
        Normalizer {
            tenant: tenant.into(),
        }
    }

    /// Normalize one decoded record. `codec_kind` is the codec that produced it
    /// (`"syslog"`, `"json"`, ...) and steers a couple of defaults.
    pub fn normalize(&self, record: Record, codec_kind: &str) -> Event {
        let mut ev = Event::new(self.tenant.clone());
        ev.raw = record.raw.clone();

        let f = &record.fields;
        let message = first_str(f, &["message", "msg", "event.original"]).unwrap_or_default();
        ev.message = message.clone();

        // Host entity from common aliases.
        if let Some(host) = first_str(f, &["host", "hostname", "host.name", "host_name"]) {
            if !host.is_empty() {
                ev.host = Some(EntityRef::new("host", host));
            }
        }

        // Severity: prefer an explicit syslog severity, else infer from text.
        ev.severity = severity_from(f, &message, codec_kind);

        // Classify + attach actor/target entities.
        ev.ocsf_class = classify(f, &message, &mut ev);

        // Carry every decoded field through (schema-on-read fallback).
        for (k, v) in record.fields.into_iter() {
            ev.fields.insert(k, v);
        }

        ev
    }
}

/// Decide the OCSF class and populate actor/target entities as a side effect.
fn classify(f: &BTreeMap<String, Value>, message: &str, ev: &mut Event) -> OcsfClass {
    let msg_lc = message.to_lowercase();

    // Authentication: explicit fields or telltale message text.
    let looks_auth = has_any(f, &["user", "username", "user.name", "auth", "logon_type"])
        || msg_lc.contains("authentication")
        || msg_lc.contains("failed password")
        || msg_lc.contains("login")
        || msg_lc.contains("logon")
        || msg_lc.contains("sshd");
    if looks_auth {
        if let Some(user) = first_str(f, &["user", "username", "user.name", "user_name"])
            .or_else(|| extract_user_from_message(message))
        {
            ev.actor = Some(EntityRef::new("user", user));
        }
        if let Some(src) = first_str(f, &["src_ip", "source.ip", "src", "client_ip"]) {
            ev.target = Some(EntityRef::new("ip", src));
        }
        return OcsfClass::Authentication;
    }

    // HTTP activity.
    if has_any(
        f,
        &[
            "http_method",
            "method",
            "url",
            "uri",
            "http.request.method",
            "status_code",
        ],
    ) {
        if let Some(url) = first_str(f, &["url", "uri", "url.full"]) {
            ev.target = Some(EntityRef::new("url", url));
        }
        return OcsfClass::HttpActivity;
    }

    // Network activity.
    if has_any(
        f,
        &[
            "src_ip",
            "dst_ip",
            "source.ip",
            "destination.ip",
            "dest_ip",
            "dst_port",
        ],
    ) {
        if let Some(src) = first_str(f, &["src_ip", "source.ip", "src"]) {
            ev.actor = Some(EntityRef::new("ip", src));
        }
        if let Some(dst) = first_str(f, &["dst_ip", "destination.ip", "dest_ip", "dst"]) {
            ev.target = Some(EntityRef::new("ip", dst));
        }
        return OcsfClass::NetworkActivity;
    }

    // Process activity.
    if has_any(
        f,
        &[
            "process",
            "process.name",
            "cmd",
            "command_line",
            "exe",
            "image",
        ],
    ) {
        if let Some(proc_name) = first_str(f, &["process", "process.name", "exe", "image"]) {
            ev.actor = Some(EntityRef::new("process", proc_name));
        }
        return OcsfClass::ProcessActivity;
    }

    // Cloud API audit (e.g. GCP/AWS).
    if has_any(
        f,
        &["eventName", "methodName", "protoPayload", "eventSource"],
    ) {
        return OcsfClass::ApiActivity;
    }

    // Syslog with an app/tag we couldn't classify: still useful — the app
    // becomes the actor process.
    if let Some(app) = first_str(f, &["app", "appname", "tag"]) {
        if !app.is_empty() {
            ev.actor = Some(EntityRef::new("process", app));
            return OcsfClass::ProcessActivity;
        }
    }

    OcsfClass::default()
}

fn severity_from(f: &BTreeMap<String, Value>, message: &str, _codec_kind: &str) -> Severity {
    // RFC 5424 numeric severity (0 emerg .. 7 debug) → our scale.
    if let Some(sev) = f.get("syslog_severity").and_then(value_as_u64) {
        return match sev {
            0..=2 => Severity::Critical,
            3 => Severity::High,
            4 => Severity::Medium,
            5 => Severity::Low,
            _ => Severity::Informational,
        };
    }
    let msg_lc = message.to_lowercase();
    if msg_lc.contains("failed") || msg_lc.contains("error") || msg_lc.contains("denied") {
        Severity::Medium
    } else {
        Severity::Informational
    }
}

// --- small helpers -------------------------------------------------------

fn first_str(f: &BTreeMap<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = f.get(*k) {
            let s = value_to_string(v);
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn has_any(f: &BTreeMap<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|k| f.contains_key(*k))
}

fn value_as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Pull a username out of common sshd-style messages, e.g.
/// "Failed password for invalid user admin from 1.2.3.4".
fn extract_user_from_message(msg: &str) -> Option<String> {
    let lc = msg.to_lowercase();
    let idx = lc.find("for ")? + 4;
    let tail = &msg[idx..];
    let tail = tail.strip_prefix("invalid user ").unwrap_or(tail);
    tail.split_whitespace().next().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_classified_with_actor() {
        let mut r = Record::from_pairs([
            (
                "message",
                "Failed password for invalid user admin from 10.0.0.9 port 22",
            ),
            ("host", "web01"),
            ("app", "sshd"),
        ]);
        r.raw = b"raw line".to_vec();
        let ev = Normalizer::new("acme").normalize(r, "syslog");
        assert_eq!(ev.ocsf_class, OcsfClass::Authentication);
        assert_eq!(ev.actor.as_ref().unwrap().id, "admin");
        assert_eq!(ev.host.as_ref().unwrap().id, "web01");
        assert_eq!(ev.severity, Severity::Medium);
        assert_eq!(ev.raw, b"raw line");
    }

    #[test]
    fn json_network_event_classified() {
        let r = Record::from_pairs([
            ("src_ip", "1.2.3.4"),
            ("dst_ip", "5.6.7.8"),
            ("dst_port", "443"),
        ]);
        let ev = Normalizer::new("acme").normalize(r, "json");
        assert_eq!(ev.ocsf_class, OcsfClass::NetworkActivity);
        assert_eq!(ev.actor.as_ref().unwrap().id, "1.2.3.4");
        assert_eq!(ev.target.as_ref().unwrap().id, "5.6.7.8");
    }

    #[test]
    fn http_event_classified() {
        let r = Record::from_pairs([("method", "GET"), ("url", "/admin"), ("status_code", "200")]);
        let ev = Normalizer::new("acme").normalize(r, "json");
        assert_eq!(ev.ocsf_class, OcsfClass::HttpActivity);
        assert_eq!(ev.target.as_ref().unwrap().id, "/admin");
    }

    #[test]
    fn unclassified_fields_are_carried_through() {
        let r = Record::from_pairs([("foo", "bar")]);
        let ev = Normalizer::new("acme").normalize(r, "json");
        assert_eq!(ev.field_str("foo").as_deref(), Some("bar"));
        assert_eq!(ev.ocsf_class, OcsfClass::default());
    }
}
