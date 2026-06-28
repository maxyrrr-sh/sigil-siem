//! ArcSight **CEF** (Common Event Format) codec (DESIGN §5).
//!
//! `CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension`
//! where Extension is space-separated `key=value` pairs. A line that doesn't
//! contain a `CEF:` header is dead-lettered, never dropped.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;
use sigil_core::{Codec, Plugin, PluginManifest, Record, Result};

/// Decodes one CEF record per line.
pub struct CefCodec {
    manifest: PluginManifest,
}

impl CefCodec {
    pub fn new() -> Self {
        CefCodec {
            manifest: PluginManifest {
                name: "cef".into(),
                version: "0.0.0".into(),
                capabilities: vec![],
            },
        }
    }
}

impl Default for CefCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for CefCodec {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Codec for CefCodec {
    fn decode(&self, raw: &[u8]) -> Result<Vec<Record>> {
        let line = String::from_utf8_lossy(raw);
        Ok(vec![parse_cef(line.trim_end(), raw)])
    }
}

const HEADER_KEYS: &[&str] = &[
    "cef_version",
    "device_vendor",
    "device_product",
    "device_version",
    "signature_id",
    "name",
    "cef_severity",
];

/// Parse one CEF line into a [`Record`]. Falls back to a dead-letter record if
/// there's no `CEF:` header or fewer than the 7 header fields.
pub fn parse_cef(line: &str, raw: &[u8]) -> Record {
    let Some(idx) = line.find("CEF:") else {
        return dead_letter(line, raw, "no CEF: header");
    };
    let body = &line[idx + 4..];
    let parts = split_header(body);
    if parts.len() < 7 {
        return dead_letter(line, raw, "incomplete CEF header");
    }

    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    for (key, val) in HEADER_KEYS.iter().zip(parts.iter()) {
        fields.insert((*key).to_string(), Value::String(val.clone()));
    }
    // The Name header is the human-readable message.
    fields.insert("message".into(), Value::String(parts[5].clone()));

    if let Some(ext) = parts.get(7) {
        parse_extension(ext, &mut fields);
    }

    Record {
        fields,
        raw: raw.to_vec(),
    }
}

/// Split the CEF header on unescaped `|` into at most 8 parts (7 header fields
/// + extension), unescaping `\|` and `\\` in each header field.
fn split_header(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('|') => cur.push('|'),
                Some('\\') => cur.push('\\'),
                Some(other) => {
                    cur.push('\\');
                    cur.push(other);
                }
                None => cur.push('\\'),
            },
            '|' if parts.len() < 7 => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

fn key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([A-Za-z][A-Za-z0-9_.]*)=").unwrap())
}

/// Parse the `key=value` extension. Values may contain spaces and `=`; a value
/// runs until the next whitespace-preceded `key=`.
fn parse_extension(ext: &str, fields: &mut BTreeMap<String, Value>) {
    let bytes = ext.as_bytes();
    // Accept a key only at the start or after whitespace (so values with '='
    // don't get split mid-token).
    let keys: Vec<(String, usize, usize)> = key_re()
        .captures_iter(ext)
        .filter_map(|c| {
            let whole = c.get(0).unwrap();
            let start = whole.start();
            if start == 0 || bytes[start - 1].is_ascii_whitespace() {
                Some((c[1].to_string(), whole.end(), start))
            } else {
                None
            }
        })
        .collect();

    for i in 0..keys.len() {
        let (ref key, val_start, _) = keys[i];
        let val_end = keys.get(i + 1).map(|k| k.2).unwrap_or(ext.len());
        let val = ext[val_start..val_end].trim();
        fields.insert(key.clone(), Value::String(unescape(val)));
    }
}

/// Unescape CEF extension values (`\=`, `\\`, `\n`, `\r`).
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('=') => out.push('='),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn dead_letter(line: &str, raw: &[u8], err: &str) -> Record {
    let mut fields = BTreeMap::new();
    fields.insert("message".into(), Value::String(line.to_string()));
    fields.insert("decode_error".into(), Value::String(err.to_string()));
    Record {
        fields,
        raw: raw.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(line: &str) -> Record {
        parse_cef(line, line.as_bytes())
    }

    #[test]
    fn parses_header_and_extension() {
        let r = rec("CEF:0|Security|Firewall|1.0|100|Port scan detected|7|src=10.0.0.9 dst=10.0.0.1 spt=1234");
        assert_eq!(r.get_str("device_vendor").as_deref(), Some("Security"));
        assert_eq!(r.get_str("device_product").as_deref(), Some("Firewall"));
        assert_eq!(r.get_str("signature_id").as_deref(), Some("100"));
        assert_eq!(r.get_str("message").as_deref(), Some("Port scan detected"));
        assert_eq!(r.get_str("cef_severity").as_deref(), Some("7"));
        assert_eq!(r.get_str("src").as_deref(), Some("10.0.0.9"));
        assert_eq!(r.get_str("dst").as_deref(), Some("10.0.0.1"));
        assert_eq!(r.get_str("spt").as_deref(), Some("1234"));
    }

    #[test]
    fn handles_syslog_prefix_and_escapes() {
        let r = rec(
            r"<134>Oct 12 04:16:11 host CEF:0|V|P|1|99|Bad\|name|3|msg=a b c request=https://x/y?q=1",
        );
        assert_eq!(r.get_str("message").as_deref(), Some("Bad|name"));
        // Value with spaces is captured whole.
        assert_eq!(r.get_str("msg").as_deref(), Some("a b c"));
        // Value containing '=' stays intact.
        assert_eq!(r.get_str("request").as_deref(), Some("https://x/y?q=1"));
    }

    #[test]
    fn non_cef_is_dead_lettered() {
        let r = rec("just a plain log line");
        assert!(r.get_str("decode_error").is_some());
        assert_eq!(
            r.get_str("message").as_deref(),
            Some("just a plain log line")
        );
    }
}
