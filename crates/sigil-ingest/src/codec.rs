//! Codecs decode raw input bytes into untyped [`Record`]s (DESIGN §5 step 2).
//!
//! Phase 0 ships `json` and `syslog`. A failed parse never loses the event: it
//! produces a record carrying the raw bytes and a `decode_error` field so the
//! caller can dead-letter it.

use std::collections::BTreeMap;

use serde_json::Value;
use sigil_core::{Codec, Plugin, PluginManifest, Record, Result};

/// Build a codec from a config `type` string. Unknown kinds fall back to a
/// raw codec (whole frame as `message`) so ingestion never hard-fails.
pub fn build_codec(kind: &str) -> Box<dyn Codec + Send + Sync> {
    match kind {
        "json" => Box::new(JsonCodec::new()),
        "syslog" => Box::new(SyslogCodec::new()),
        _ => Box::new(RawCodec::new()),
    }
}

fn manifest(name: &str) -> PluginManifest {
    PluginManifest {
        name: name.to_string(),
        version: "0.0.0".into(),
        capabilities: vec![],
    }
}

/// Decodes JSON: a top-level object becomes one record; a top-level array
/// becomes one record per element. Nested values are kept as JSON.
pub struct JsonCodec {
    manifest: PluginManifest,
}

impl JsonCodec {
    pub fn new() -> Self {
        JsonCodec {
            manifest: manifest("json"),
        }
    }
}

impl Default for JsonCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for JsonCodec {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Codec for JsonCodec {
    fn decode(&self, raw: &[u8]) -> Result<Vec<Record>> {
        let value: Value = match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(e) => return Ok(vec![dead_letter(raw, &e.to_string())]),
        };
        let objects = match value {
            Value::Array(items) => items,
            other => vec![other],
        };
        let records = objects
            .into_iter()
            .map(|obj| record_from_json(obj, raw))
            .collect();
        Ok(records)
    }
}

fn record_from_json(value: Value, raw: &[u8]) -> Record {
    let mut fields = BTreeMap::new();
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                fields.insert(k, v);
            }
        }
        other => {
            fields.insert("message".to_string(), other);
        }
    }
    Record {
        fields,
        raw: raw.to_vec(),
    }
}

/// Minimal syslog parser covering the common shapes of RFC 3164 and RFC 5424.
/// It is intentionally lenient: anything it can't structure lands in `message`.
pub struct SyslogCodec {
    manifest: PluginManifest,
}

impl SyslogCodec {
    pub fn new() -> Self {
        SyslogCodec {
            manifest: manifest("syslog"),
        }
    }
}

impl Default for SyslogCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for SyslogCodec {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Codec for SyslogCodec {
    fn decode(&self, raw: &[u8]) -> Result<Vec<Record>> {
        let line = String::from_utf8_lossy(raw);
        Ok(vec![parse_syslog(line.trim_end())])
    }
}

fn str_field(map: &mut BTreeMap<String, Value>, key: &str, val: impl Into<String>) {
    map.insert(key.to_string(), Value::String(val.into()));
}

/// Parse a single syslog line into a [`Record`]. Extracts the PRI (and derived
/// facility/severity), then best-effort host/app/message.
pub fn parse_syslog(line: &str) -> Record {
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    let mut rest = line;

    // <PRI> prefix → facility / severity.
    if let Some(stripped) = rest.strip_prefix('<') {
        if let Some(end) = stripped.find('>') {
            if let Ok(pri) = stripped[..end].parse::<u16>() {
                fields.insert("syslog_facility".into(), Value::from(pri >> 3));
                fields.insert("syslog_severity".into(), Value::from(pri & 0x7));
            }
            rest = &stripped[end + 1..];
        }
    }

    // RFC 5424 begins with a version digit + space ("1 ...").
    let is_5424 = rest
        .split_once(' ')
        .map(|(v, _)| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) && v.len() <= 2)
        .unwrap_or(false);

    if is_5424 {
        // VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG
        let mut it = rest.splitn(7, ' ');
        let _version = it.next();
        if let Some(ts) = it.next() {
            str_field(&mut fields, "timestamp", ts);
        }
        if let Some(host) = it.next() {
            str_field(&mut fields, "host", nil_to_empty(host));
        }
        if let Some(app) = it.next() {
            str_field(&mut fields, "app", nil_to_empty(app));
        }
        if let Some(procid) = it.next() {
            str_field(&mut fields, "procid", nil_to_empty(procid));
        }
        if let Some(msgid) = it.next() {
            str_field(&mut fields, "msgid", nil_to_empty(msgid));
        }
        if let Some(tail) = it.next() {
            // Drop a leading structured-data block "[...]" if present.
            let msg = strip_structured_data(tail);
            str_field(&mut fields, "message", msg);
        }
    } else {
        // RFC 3164: "Mmm dd hh:mm:ss host tag[pid]: message"
        let tokens: Vec<&str> = rest.splitn(5, ' ').collect();
        if tokens.len() >= 4 && is_month(tokens[0]) {
            let ts = format!("{} {} {}", tokens[0], tokens[1], tokens[2]);
            str_field(&mut fields, "timestamp", ts);
            str_field(&mut fields, "host", tokens[3]);
            if let Some(remainder) = tokens.get(4) {
                split_tag(remainder, &mut fields);
            }
        } else {
            str_field(&mut fields, "message", rest);
        }
    }

    Record {
        fields,
        raw: line.as_bytes().to_vec(),
    }
}

fn nil_to_empty(s: &str) -> &str {
    if s == "-" {
        ""
    } else {
        s
    }
}

fn strip_structured_data(s: &str) -> &str {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[end + 1..].trim_start();
        }
    } else if let Some(rest) = s.strip_prefix('-') {
        // "-" means no structured data.
        return rest.trim_start();
    }
    s
}

fn split_tag(remainder: &str, fields: &mut BTreeMap<String, Value>) {
    // "tag[pid]: message" or "tag: message"
    if let Some((tag_part, msg)) = remainder.split_once(": ") {
        if let Some((tag, pid)) = tag_part.split_once('[') {
            str_field(fields, "app", tag);
            str_field(fields, "procid", pid.trim_end_matches(']'));
        } else {
            str_field(fields, "app", tag_part);
        }
        str_field(fields, "message", msg);
    } else {
        str_field(fields, "message", remainder);
    }
}

fn is_month(s: &str) -> bool {
    matches!(
        s,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    )
}

/// A codec that passes the whole frame through as `message`.
pub struct RawCodec {
    manifest: PluginManifest,
}

impl RawCodec {
    pub fn new() -> Self {
        RawCodec {
            manifest: manifest("raw"),
        }
    }
}

impl Default for RawCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for RawCodec {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Codec for RawCodec {
    fn decode(&self, raw: &[u8]) -> Result<Vec<Record>> {
        let mut fields = BTreeMap::new();
        str_field(&mut fields, "message", String::from_utf8_lossy(raw));
        Ok(vec![Record {
            fields,
            raw: raw.to_vec(),
        }])
    }
}

fn dead_letter(raw: &[u8], err: &str) -> Record {
    let mut fields = BTreeMap::new();
    str_field(&mut fields, "message", String::from_utf8_lossy(raw));
    str_field(&mut fields, "decode_error", err);
    Record {
        fields,
        raw: raw.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_object_decodes_fields() {
        let codec = JsonCodec::new();
        let recs = codec.decode(br#"{"user":"root","port":22}"#).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].get_str("user").as_deref(), Some("root"));
        assert_eq!(recs[0].get_str("port").as_deref(), Some("22"));
    }

    #[test]
    fn json_array_decodes_to_many() {
        let codec = JsonCodec::new();
        let recs = codec.decode(br#"[{"a":1},{"a":2}]"#).unwrap();
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn json_invalid_is_dead_lettered_not_lost() {
        let codec = JsonCodec::new();
        let recs = codec.decode(b"not json").unwrap();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].get_str("decode_error").is_some());
        assert_eq!(recs[0].get_str("message").as_deref(), Some("not json"));
    }

    #[test]
    fn syslog_3164_parses() {
        let r = parse_syslog("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick");
        assert_eq!(r.get_str("host").as_deref(), Some("mymachine"));
        assert_eq!(r.get_str("app").as_deref(), Some("su"));
        assert_eq!(r.get_str("syslog_severity").as_deref(), Some("2"));
        assert!(r.get_str("message").unwrap().contains("failed for lonvick"));
    }

    #[test]
    fn syslog_5424_parses() {
        let r = parse_syslog(
            "<165>1 2003-10-11T22:14:15.003Z host.example.com evntslog 1024 ID47 - the message",
        );
        assert_eq!(r.get_str("host").as_deref(), Some("host.example.com"));
        assert_eq!(r.get_str("app").as_deref(), Some("evntslog"));
        assert_eq!(r.get_str("message").as_deref(), Some("the message"));
    }
}
