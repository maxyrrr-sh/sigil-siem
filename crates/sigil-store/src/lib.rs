//! `sigil-store` — durable embedded persistence for the API surface (DESIGN §14).
//!
//! The hot path keeps alerts in an in-memory ring for speed; this crate adds a
//! restart-durable store so **triage state** (status / assignee / notes) and
//! **saved objects** (searches, dashboards, hunt notebooks) survive a process
//! restart. It is backed by [`redb`] (a pure-Rust embedded key/value store), so
//! it fits Sigil's single-binary ethos with no external database.
//!
//! Two logical tables:
//! - `alerts`  — keyed by a stable [`fingerprint`] of an [`Alert`], value is an
//!   [`AlertRecord`] (the alert plus its triage envelope).
//! - `saved`   — keyed by `"{kind}\u{1f}{id}"`, value is a [`SavedObject`].

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use sigil_core::{now_micros, Alert, Error, Result, Timestamp};

const ALERTS: TableDefinition<&str, &str> = TableDefinition::new("alerts");
const SAVED: TableDefinition<&str, &str> = TableDefinition::new("saved");
/// ASCII unit separator — joins `kind` + `id` into a saved-object key.
const SEP: char = '\u{1f}';

fn be<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// Analyst triage state for an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TriageStatus {
    /// Newly fired, not yet looked at.
    #[default]
    Open,
    /// Seen and acknowledged by an analyst.
    Acknowledged,
    /// Resolved / dismissed.
    Closed,
}

impl TriageStatus {
    /// Parse from the wire (`open` | `acknowledged` | `closed`).
    pub fn parse(s: &str) -> Option<TriageStatus> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Some(TriageStatus::Open),
            "acknowledged" | "ack" => Some(TriageStatus::Acknowledged),
            "closed" | "close" => Some(TriageStatus::Closed),
            _ => None,
        }
    }
}

/// A free-text triage note appended by an analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub ts: Timestamp,
    pub author: String,
    pub text: String,
}

/// An [`Alert`] plus its durable triage envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    /// Stable identity derived from the alert (see [`fingerprint`]).
    pub fingerprint: String,
    pub alert: Alert,
    #[serde(default)]
    pub status: TriageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(default)]
    pub notes: Vec<Note>,
    pub created_ts: Timestamp,
    pub updated_ts: Timestamp,
}

impl AlertRecord {
    /// Wrap a fresh alert with default (Open) triage state.
    pub fn new(alert: Alert) -> Self {
        let now = now_micros();
        AlertRecord {
            fingerprint: fingerprint(&alert),
            alert,
            status: TriageStatus::Open,
            assignee: None,
            notes: Vec::new(),
            created_ts: now,
            updated_ts: now,
        }
    }
}

/// A user-saved object (search / dashboard / hunt notebook). The `body` is
/// opaque JSON owned by the frontend — the store only versions it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedObject {
    pub kind: String,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub owner: Option<String>,
    pub updated_ts: Timestamp,
    pub body: serde_json::Value,
}

/// A partial update to an alert's triage envelope.
#[derive(Debug, Clone, Default)]
pub struct AlertPatch {
    pub status: Option<TriageStatus>,
    /// `Some(Some(name))` sets, `Some(None)` clears, `None` leaves unchanged.
    pub assignee: Option<Option<String>>,
    pub note: Option<Note>,
}

/// Stable fingerprint of an alert: `rule_id` + `ts` + triggering event ids.
/// Re-deriving the same alert (e.g. after restart) yields the same key, so
/// triage state reconciles instead of duplicating.
pub fn fingerprint(alert: &Alert) -> String {
    let mut h = DefaultHasher::new();
    alert.rule_id.hash(&mut h);
    alert.ts.hash(&mut h);
    for e in &alert.events {
        e.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

/// The durable store. Cheap to [`Clone`]-share via `Arc` at the call site.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if absent) the store at `path`, ensuring both tables exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Io(format!("create store dir {}: {e}", parent.display()))
                })?;
            }
        }
        let db = Database::create(path).map_err(be)?;
        let wt = db.begin_write().map_err(be)?;
        {
            wt.open_table(ALERTS).map_err(be)?;
            wt.open_table(SAVED).map_err(be)?;
        }
        wt.commit().map_err(be)?;
        Ok(Store { db })
    }

    // --- alerts -----------------------------------------------------------

    /// Insert an alert if its fingerprint is new, preserving any existing triage
    /// state otherwise. Returns the resulting record.
    pub fn upsert_alert(&self, alert: Alert) -> Result<AlertRecord> {
        let fp = fingerprint(&alert);
        if let Some(existing) = self.get_alert(&fp)? {
            return Ok(existing);
        }
        let rec = AlertRecord::new(alert);
        self.write_alert(&rec)?;
        Ok(rec)
    }

    fn write_alert(&self, rec: &AlertRecord) -> Result<()> {
        let json = serde_json::to_string(rec).map_err(be)?;
        let wt = self.db.begin_write().map_err(be)?;
        {
            let mut t = wt.open_table(ALERTS).map_err(be)?;
            t.insert(rec.fingerprint.as_str(), json.as_str())
                .map_err(be)?;
        }
        wt.commit().map_err(be)?;
        Ok(())
    }

    /// Fetch one alert record by fingerprint.
    pub fn get_alert(&self, fp: &str) -> Result<Option<AlertRecord>> {
        let rt = self.db.begin_read().map_err(be)?;
        let t = rt.open_table(ALERTS).map_err(be)?;
        match t.get(fp).map_err(be)? {
            Some(v) => Ok(Some(serde_json::from_str(v.value()).map_err(be)?)),
            None => Ok(None),
        }
    }

    /// Most recent alerts (newest first), optionally filtered by ATT&CK technique.
    pub fn list_alerts(&self, limit: usize, technique: Option<&str>) -> Result<Vec<AlertRecord>> {
        let rt = self.db.begin_read().map_err(be)?;
        let t = rt.open_table(ALERTS).map_err(be)?;
        let mut out: Vec<AlertRecord> = Vec::new();
        for item in t.iter().map_err(be)? {
            let (_, v) = item.map_err(be)?;
            let rec: AlertRecord = serde_json::from_str(v.value()).map_err(be)?;
            if let Some(tech) = technique {
                if rec.alert.technique.as_deref() != Some(tech) {
                    continue;
                }
            }
            out.push(rec);
        }
        out.sort_by_key(|r| std::cmp::Reverse(r.alert.ts));
        out.truncate(limit);
        Ok(out)
    }

    /// Number of stored alert records.
    pub fn alert_count(&self) -> Result<usize> {
        let rt = self.db.begin_read().map_err(be)?;
        let t = rt.open_table(ALERTS).map_err(be)?;
        Ok(t.len().map_err(be)? as usize)
    }

    /// Apply a triage patch to one alert. Returns the updated record, or `None`
    /// if no alert with that fingerprint exists.
    pub fn patch_alert(&self, fp: &str, patch: &AlertPatch) -> Result<Option<AlertRecord>> {
        let Some(mut rec) = self.get_alert(fp)? else {
            return Ok(None);
        };
        if let Some(s) = patch.status {
            rec.status = s;
        }
        if let Some(a) = &patch.assignee {
            rec.assignee = a.clone();
        }
        if let Some(n) = &patch.note {
            rec.notes.push(n.clone());
        }
        rec.updated_ts = now_micros();
        self.write_alert(&rec)?;
        Ok(Some(rec))
    }

    // --- saved objects ----------------------------------------------------

    fn saved_key(kind: &str, id: &str) -> String {
        format!("{kind}{SEP}{id}")
    }

    /// Create or replace a saved object.
    pub fn put_saved(&self, obj: &SavedObject) -> Result<()> {
        let key = Self::saved_key(&obj.kind, &obj.id);
        let json = serde_json::to_string(obj).map_err(be)?;
        let wt = self.db.begin_write().map_err(be)?;
        {
            let mut t = wt.open_table(SAVED).map_err(be)?;
            t.insert(key.as_str(), json.as_str()).map_err(be)?;
        }
        wt.commit().map_err(be)?;
        Ok(())
    }

    /// Fetch one saved object.
    pub fn get_saved(&self, kind: &str, id: &str) -> Result<Option<SavedObject>> {
        let key = Self::saved_key(kind, id);
        let rt = self.db.begin_read().map_err(be)?;
        let t = rt.open_table(SAVED).map_err(be)?;
        match t.get(key.as_str()).map_err(be)? {
            Some(v) => Ok(Some(serde_json::from_str(v.value()).map_err(be)?)),
            None => Ok(None),
        }
    }

    /// List every saved object of a given `kind`, newest first.
    pub fn list_saved(&self, kind: &str) -> Result<Vec<SavedObject>> {
        let prefix = format!("{kind}{SEP}");
        let rt = self.db.begin_read().map_err(be)?;
        let t = rt.open_table(SAVED).map_err(be)?;
        let mut out = Vec::new();
        for item in t.iter().map_err(be)? {
            let (k, v) = item.map_err(be)?;
            if !k.value().starts_with(&prefix) {
                continue;
            }
            out.push(serde_json::from_str::<SavedObject>(v.value()).map_err(be)?);
        }
        out.sort_by_key(|o| std::cmp::Reverse(o.updated_ts));
        Ok(out)
    }

    /// Delete a saved object. Returns whether a row was removed.
    pub fn delete_saved(&self, kind: &str, id: &str) -> Result<bool> {
        let key = Self::saved_key(kind, id);
        let wt = self.db.begin_write().map_err(be)?;
        let removed;
        {
            let mut t = wt.open_table(SAVED).map_err(be)?;
            removed = t.remove(key.as_str()).map_err(be)?.is_some();
        }
        wt.commit().map_err(be)?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("store.redb")).unwrap();
        (store, dir)
    }

    fn alert(rule: &str) -> Alert {
        Alert {
            rule_id: rule.into(),
            ts: 100,
            events: vec!["e1".into()],
            ..Default::default()
        }
    }

    #[test]
    fn upsert_is_idempotent_and_preserves_triage() {
        let (s, _d) = store();
        let rec = s.upsert_alert(alert("r1")).unwrap();
        let fp = rec.fingerprint.clone();
        s.patch_alert(
            &fp,
            &AlertPatch {
                status: Some(TriageStatus::Acknowledged),
                ..Default::default()
            },
        )
        .unwrap();
        // Re-deriving the same alert must NOT reset the acknowledged state.
        let again = s.upsert_alert(alert("r1")).unwrap();
        assert_eq!(again.fingerprint, fp);
        assert_eq!(again.status, TriageStatus::Acknowledged);
        assert_eq!(s.alert_count().unwrap(), 1);
    }

    #[test]
    fn patch_missing_returns_none() {
        let (s, _d) = store();
        assert!(s
            .patch_alert("nope", &AlertPatch::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_alerts_newest_first_and_filtered() {
        let (s, _d) = store();
        let mut a = alert("r1");
        a.ts = 10;
        a.technique = Some("T1110".into());
        s.upsert_alert(a).unwrap();
        let mut b = alert("r2");
        b.ts = 20;
        b.events = vec!["e2".into()];
        s.upsert_alert(b).unwrap();
        let all = s.list_alerts(10, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].alert.rule_id, "r2"); // newest first
        let only = s.list_alerts(10, Some("T1110")).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].alert.rule_id, "r1");
    }

    #[test]
    fn saved_objects_roundtrip() {
        let (s, _d) = store();
        let obj = SavedObject {
            kind: "searches".into(),
            id: "1".into(),
            name: "failed logins".into(),
            owner: Some("admin".into()),
            updated_ts: 5,
            body: serde_json::json!({ "q": "failed", "mode": "search" }),
        };
        s.put_saved(&obj).unwrap();
        assert_eq!(s.list_saved("searches").unwrap().len(), 1);
        assert_eq!(s.list_saved("dashboards").unwrap().len(), 0);
        assert!(s.delete_saved("searches", "1").unwrap());
        assert!(s.list_saved("searches").unwrap().is_empty());
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        {
            let s = Store::open(&path).unwrap();
            s.upsert_alert(alert("persist")).unwrap();
        }
        let s2 = Store::open(&path).unwrap();
        assert_eq!(s2.alert_count().unwrap(), 1);
    }
}
