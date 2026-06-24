//! The normalized event model (DESIGN §6). This is the contract shared by
//! every crate: inputs/codecs produce [`Record`]s, normalization turns them
//! into [`Event`]s, and the index/Sigma/correlation paths all consume `Event`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Event time / ingest time, represented as Unix epoch **microseconds**.
pub type Timestamp = i64;

/// Current wall-clock time as an epoch-microsecond [`Timestamp`].
pub fn now_micros() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// OCSF event class. We model the handful of classes Phase 0 normalizes plus a
/// numeric escape hatch (`Other`) so unmapped sources still round-trip.
///
/// Numeric ids are the OCSF `class_uid`s (<https://schema.ocsf.io/>).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcsfClass {
    /// 1001 — File System Activity.
    FileSystemActivity,
    /// 1007 — Process Activity.
    ProcessActivity,
    /// 3002 — Authentication.
    Authentication,
    /// 4001 — Network Activity.
    NetworkActivity,
    /// 4002 — HTTP Activity.
    HttpActivity,
    /// 6003 — API Activity (cloud audit logs).
    ApiActivity,
    /// 1008 — generic/unknown; carries the raw `class_uid` we couldn't map.
    Other(u32),
}

impl Default for OcsfClass {
    fn default() -> Self {
        // 1008 = "Base Event" in OCSF; our neutral default.
        OcsfClass::Other(1008)
    }
}

impl OcsfClass {
    /// The OCSF `class_uid` for this class.
    pub fn uid(&self) -> u32 {
        match self {
            OcsfClass::FileSystemActivity => 1001,
            OcsfClass::ProcessActivity => 1007,
            OcsfClass::Authentication => 3002,
            OcsfClass::NetworkActivity => 4001,
            OcsfClass::HttpActivity => 4002,
            OcsfClass::ApiActivity => 6003,
            OcsfClass::Other(uid) => *uid,
        }
    }
}

/// Normalized severity, aligned to OCSF `severity_id` (0..=6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Unknown,
    #[default]
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Fatal,
}

impl Severity {
    /// OCSF `severity_id`.
    pub fn id(&self) -> u8 {
        *self as u8
    }
}

/// Reference to an entity (process/file/user/host/...) in the causal graph
/// (DESIGN §9.3). `kind` is drawn from the shared entity vocabulary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    /// e.g. `process`, `file`, `user`, `host`, `ip`, `domain`, `hash`.
    pub kind: String,
    /// Stable identifier within `kind` (pid+host, path, username, ...).
    pub id: String,
    /// Optional human-friendly name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl EntityRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        EntityRef {
            kind: kind.into(),
            id: id.into(),
            name: None,
        }
    }
}

/// A raw decoded record produced by a [`crate::Codec`], before normalization.
/// Fields are untyped key/values; normalization maps them onto [`Event`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    pub fields: BTreeMap<String, serde_json::Value>,
    /// The undecoded bytes, preserved for `raw` and dead-letter handling.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "serde_bytes_compat"
    )]
    pub raw: Vec<u8>,
}

impl Record {
    /// Build a record from an iterator of string key/value pairs.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let fields = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), serde_json::Value::String(v.into())))
            .collect();
        Record {
            fields,
            raw: Vec::new(),
        }
    }

    /// Look up a field as a string (numbers/bools are stringified).
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.fields.get(key).map(value_to_string)
    }
}

/// Normalized security event (OCSF-aligned). See DESIGN §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// ULID string: monotonic, time-sortable, URL-safe.
    pub id: String,
    /// Event time (when it happened), epoch micros.
    pub ts: Timestamp,
    /// Ingest time (when Sigil received it), epoch micros.
    pub ingest_ts: Timestamp,
    /// OCSF class of this event.
    pub ocsf_class: OcsfClass,
    /// Tenant / namespace this event belongs to.
    pub tenant: String,
    /// Normalized severity.
    pub severity: Severity,
    /// Host the event originated on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<EntityRef>,
    /// Actor (user/process) that initiated the activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EntityRef>,
    /// Target the activity acted upon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EntityRef>,
    /// Human-readable message (full-text searchable).
    #[serde(default)]
    pub message: String,
    /// Typed normalized fields (OCSF record, schema-on-read fallback).
    #[serde(default)]
    pub fields: BTreeMap<String, serde_json::Value>,
    /// Template id from online template mining (DESIGN §9.2), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<u64>,
    /// Routing / detection labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// The original raw bytes (always preserved; compressed at rest later).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "serde_bytes_compat"
    )]
    pub raw: Vec<u8>,
}

impl Default for Event {
    fn default() -> Self {
        let ts = now_micros();
        Event {
            id: ulid::Ulid::new().to_string(),
            ts,
            ingest_ts: ts,
            ocsf_class: OcsfClass::default(),
            tenant: "default".to_string(),
            severity: Severity::default(),
            host: None,
            actor: None,
            target: None,
            message: String::new(),
            fields: BTreeMap::new(),
            template_id: None,
            labels: Vec::new(),
            raw: Vec::new(),
        }
    }
}

impl Event {
    /// Start a new event with a fresh ULID and `ts`/`ingest_ts` set to now.
    pub fn new(tenant: impl Into<String>) -> Self {
        Event {
            tenant: tenant.into(),
            ..Default::default()
        }
    }

    /// Convenience accessor: a field as a display string.
    pub fn field_str(&self, key: &str) -> Option<String> {
        self.fields.get(key).map(value_to_string)
    }
}

/// Render a JSON value as a flat string (used for indexing/search).
pub fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Serde helper so `Vec<u8>` round-trips as a UTF-8 string when possible and a
/// JSON array otherwise — keeps `raw` human-readable in API output without a
/// `serde_bytes` dependency in `sigil-core`.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(bytes) {
            Ok(text) => s.serialize_str(text),
            Err(_) => bytes.to_vec().serialize(s),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Bytes(Vec<u8>),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Text(s) => s.into_bytes(),
            Raw::Bytes(b) => b,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocsf_uids() {
        assert_eq!(OcsfClass::ProcessActivity.uid(), 1007);
        assert_eq!(OcsfClass::Other(4242).uid(), 4242);
        assert_eq!(OcsfClass::default().uid(), 1008);
    }

    #[test]
    fn event_roundtrips_through_json() {
        let mut ev = Event::new("acme");
        ev.message = "user root logged in".into();
        ev.ocsf_class = OcsfClass::Authentication;
        ev.actor = Some(EntityRef::new("user", "root"));
        ev.raw = b"raw syslog line".to_vec();
        let json = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, ev.id);
        assert_eq!(back.message, ev.message);
        assert_eq!(back.actor, ev.actor);
        assert_eq!(back.raw, ev.raw);
    }

    #[test]
    fn record_from_pairs_reads_back() {
        let r = Record::from_pairs([("user", "root"), ("action", "login")]);
        assert_eq!(r.get_str("user").as_deref(), Some("root"));
        assert_eq!(r.get_str("missing"), None);
    }
}
