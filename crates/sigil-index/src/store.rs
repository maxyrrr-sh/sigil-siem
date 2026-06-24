//! The columnar/analytical store (DESIGN §7): writes immutable Parquet
//! segments to the cold tier, tracks them in a [`Catalog`], runs SQL via
//! [`Analytics`], and enforces retention. This is the analytical sibling of the
//! Tantivy-backed [`crate::EventIndex`] hot tier.

use std::path::PathBuf;
use std::sync::Mutex;

use sigil_core::{now_micros, Event, Result};

use crate::analytics::{Analytics, QueryResult};
use crate::catalog::{segment_meta, Catalog, SegmentMeta};
use crate::columnar::write_segment;

/// Cold-tier columnar store: Parquet segments + catalog + DataFusion queries.
pub struct ColumnarStore {
    cold_dir: PathBuf,
    catalog: Mutex<Catalog>,
    analytics: Analytics,
}

impl ColumnarStore {
    /// Open the store rooted at `cold_dir`, with the catalog at `catalog_path`.
    pub fn open(cold_dir: impl Into<PathBuf>, catalog_path: impl Into<PathBuf>) -> Result<Self> {
        let cold_dir = cold_dir.into();
        std::fs::create_dir_all(&cold_dir)
            .map_err(|e| sigil_core::Error::Io(format!("create cold dir: {e}")))?;
        let catalog = Catalog::open(catalog_path.into())?;
        let analytics = Analytics::new(&cold_dir);
        Ok(ColumnarStore {
            cold_dir,
            catalog: Mutex::new(catalog),
            analytics,
        })
    }

    /// Roll a batch of events into a new Parquet segment and register it.
    /// Returns the segment metadata, or `None` if `events` was empty.
    pub fn write_segment(&self, events: &[Event]) -> Result<Option<SegmentMeta>> {
        if events.is_empty() {
            return Ok(None);
        }
        let id = ulid_like();
        let path = self.cold_dir.join(format!("{id}.parquet"));
        let rows = write_segment(&path, events)?;

        let min_ts = events.iter().map(|e| e.ts).min().unwrap_or(0);
        let max_ts = events.iter().map(|e| e.ts).max().unwrap_or(0);
        let meta = segment_meta(id, &path, min_ts, max_ts, rows);
        self.catalog.lock().unwrap().add(meta.clone())?;
        Ok(Some(meta))
    }

    /// Run a SQL query over the cold tier.
    pub async fn sql(&self, query: &str) -> Result<QueryResult> {
        self.analytics.sql(query).await
    }

    /// Delete segments whose data is older than `max_age_micros`. Returns the
    /// number of segments removed.
    pub fn enforce_retention(&self, max_age_micros: i64) -> Result<usize> {
        let mut cat = self.catalog.lock().unwrap();
        let expired: Vec<String> = cat
            .expired(now_micros(), max_age_micros)
            .into_iter()
            .map(|s| s.id)
            .collect();
        cat.remove(&expired)
    }

    pub fn segment_count(&self) -> usize {
        self.catalog.lock().unwrap().segments().len()
    }

    pub fn total_rows(&self) -> usize {
        self.catalog.lock().unwrap().total_rows()
    }
}

fn ulid_like() -> String {
    // A monotonic-ish, filesystem-safe id without pulling ulid into this crate.
    format!("seg-{:016x}", now_micros())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{EntityRef, OcsfClass};

    fn ev(host: &str, ts: i64) -> Event {
        let mut e = Event::new("acme");
        e.ts = ts;
        e.host = Some(EntityRef::new("host", host));
        e.ocsf_class = OcsfClass::Authentication;
        e
    }

    #[tokio::test]
    async fn write_then_query() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ColumnarStore::open(dir.path().join("cold"), dir.path().join("catalog.json")).unwrap();

        store
            .write_segment(&[ev("web01", 100), ev("web02", 200)])
            .unwrap();
        assert_eq!(store.segment_count(), 1);
        assert_eq!(store.total_rows(), 2);

        let res = store.sql("SELECT count(*) AS n FROM events").await.unwrap();
        assert_eq!(res.rows[0]["n"], serde_json::json!(2));
    }

    #[test]
    fn retention_drops_old_segments() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ColumnarStore::open(dir.path().join("cold"), dir.path().join("catalog.json")).unwrap();
        // ts far in the past → immediately expired under any small retention.
        store.write_segment(&[ev("old", 1_000)]).unwrap();
        assert_eq!(store.segment_count(), 1);
        let removed = store.enforce_retention(1_000_000).unwrap(); // 1s retention
        assert_eq!(removed, 1);
        assert_eq!(store.segment_count(), 0);
    }
}
