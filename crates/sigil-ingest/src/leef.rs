//! IBM QRadar **LEEF** (Log Event Extended Format) codec (DESIGN §5).
//!
//! `LEEF:Version|Vendor|Product|Version|EventID|[Delimiter|]Attributes`
//! LEEF 1.0 attributes are tab-delimited; LEEF 2.0 carries an explicit
//! delimiter field (a char or `xHH` hex). Non-LEEF lines are dead-lettered.

use std::collections::BTreeMap;

use serde_json::Value;
use sigil_core::{Codec, Plugin, PluginManifest, Record, Result};

pub struct LeefCodec {
    manifest: PluginManifest,
}

impl LeefCodec {
    pub fn new() -> Self {
        LeefCodec {
            manifest: PluginManifest {
                name: "leef".into(),
                version: "0.0.0".into(),
                capabilities: vec![],
            },
        }
    }
}

impl Default for LeefCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for LeefCodec {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Codec for LeefCodec {
    fn decode(&self, raw: &[u8]) -> Result<Vec<Record>> {
        let line = String::from_utf8_lossy(raw);
        Ok(vec![parse_leef(line.trim_end(), raw)])
    }
}

/// Parse one LEEF line into a [`Record`].
pub fn parse_leef(line: &str, raw: &[u8]) -> Record {
    let Some(idx) = line.find("LEEF:") else {
        return dead_letter(line, raw, "no LEEF: header");
    };
    let rest = &line[idx + 5..];
    let Some((version, after_ver)) = rest.split_once('|') else {
        return dead_letter(line, raw, "incomplete LEEF header");
    };
    let is_v2 = version.trim().starts_with('2');

    // After the version: Vendor|Product|Version|EventID[|Delimiter]|Attributes
    let non_attr = if is_v2 { 5 } else { 4 };
    let segs: Vec<&str> = after_ver.splitn(non_attr + 1, '|').collect();
    if segs.len() < non_attr + 1 {
        return dead_letter(line, raw, "incomplete LEEF header");
    }

    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    fields.insert(
        "leef_version".into(),
        Value::String(version.trim().to_string()),
    );
    fields.insert("device_vendor".into(), Value::String(segs[0].to_string()));
    fields.insert("device_product".into(), Value::String(segs[1].to_string()));
    fields.insert("device_version".into(), Value::String(segs[2].to_string()));
    fields.insert("event_id".into(), Value::String(segs[3].to_string()));

    let (delim, attrs) = if is_v2 {
        (parse_delim(segs[4]), segs[5])
    } else {
        ('\t', segs[4])
    };

    for pair in attrs.split(delim) {
        if let Some((k, v)) = pair.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                fields.insert(k.to_string(), Value::String(v.to_string()));
            }
        }
    }

    // Prefer an explicit `msg` attribute as the message, else the event id.
    let message = fields
        .get("msg")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("LEEF event {}", segs[3]));
    fields.insert("message".into(), Value::String(message));

    Record {
        fields,
        raw: raw.to_vec(),
    }
}

/// Parse a LEEF 2.0 delimiter spec: a single char or `xHH`/`0xHH` hex; tab
/// when empty/unrecognized.
fn parse_delim(spec: &str) -> char {
    let s = spec.trim();
    if s.is_empty() {
        return '\t';
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix('x')) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            if let Some(c) = char::from_u32(n) {
                return c;
            }
        }
    }
    s.chars().next().unwrap_or('\t')
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
        parse_leef(line, line.as_bytes())
    }

    #[test]
    fn parses_leef_1_0_tab_delimited() {
        let r = rec("LEEF:1.0|Lab|Sensor|1.5|EventX|src=10.0.0.9\tdst=10.0.0.1\tmsg=blocked");
        assert_eq!(r.get_str("leef_version").as_deref(), Some("1.0"));
        assert_eq!(r.get_str("device_vendor").as_deref(), Some("Lab"));
        assert_eq!(r.get_str("event_id").as_deref(), Some("EventX"));
        assert_eq!(r.get_str("src").as_deref(), Some("10.0.0.9"));
        assert_eq!(r.get_str("msg").as_deref(), Some("blocked"));
        assert_eq!(r.get_str("message").as_deref(), Some("blocked"));
    }

    #[test]
    fn parses_leef_2_0_with_hex_delimiter() {
        // x09 = tab.
        let r = rec("LEEF:2.0|Lab|Sensor|1.5|42|x09|cat=auth\tusrName=alice");
        assert_eq!(r.get_str("leef_version").as_deref(), Some("2.0"));
        assert_eq!(r.get_str("usrName").as_deref(), Some("alice"));
        assert_eq!(r.get_str("cat").as_deref(), Some("auth"));
        // No msg attribute → message falls back to the event id.
        assert_eq!(r.get_str("message").as_deref(), Some("LEEF event 42"));
    }

    #[test]
    fn parses_leef_2_0_with_char_delimiter() {
        let r = rec("LEEF:2.0|Lab|Sensor|1.5|42|^|a=1^b=2");
        assert_eq!(r.get_str("a").as_deref(), Some("1"));
        assert_eq!(r.get_str("b").as_deref(), Some("2"));
    }

    #[test]
    fn non_leef_is_dead_lettered() {
        let r = rec("plain syslog line");
        assert!(r.get_str("decode_error").is_some());
    }
}
