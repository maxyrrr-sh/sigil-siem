//! The columnar/analytical store (DESIGN §7): writes immutable Parquet
//! segments, tracks them in a [`Catalog`], runs SQL via [`Analytics`], and
//! drives the tier lifecycle. Fresh segments are **warm** (local Parquet that
//! DataFusion scans directly); [`ColumnarStore::migrate_warm`] moves aged
//! segments into the **cold** object-store archive, from which
//! [`ColumnarStore::read_range`] fetches them back on demand (retro-hunt).
//! This is the analytical sibling of the Tantivy-backed [`crate::EventIndex`]
//! hot tier.

use std::path::PathBuf;
use std::sync::Mutex;

use sigil_core::{now_micros, Event, Result};

use crate::analytics::{Analytics, QueryResult};
use crate::catalog::{segment_meta, Catalog, SegmentMeta, Tier};
use crate::columnar::{read_segment, read_segment_bytes, write_segment};
use crate::object::ObjectColdStore;

/// Columnar store: Parquet segments + catalog + DataFusion queries + tiering.
pub struct ColumnarStore {
    cold_dir: PathBuf,
    catalog: Mutex<Catalog>,
    analytics: Analytics,
    /// Cold archive; `None` disables warm→cold migration.
    archive: Option<ObjectColdStore>,
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
            archive: None,
        })
    }

    /// Attach a cold object-store archive (enables [`Self::migrate_warm`]).
    pub fn with_archive(mut self, archive: ObjectColdStore) -> Self {
        self.archive = Some(archive);
        self
    }

    pub fn archive(&self) -> Option<&ObjectColdStore> {
        self.archive.as_ref()
    }

    /// Roll a batch of events into a new (warm) Parquet segment and register
    /// it. Returns the segment metadata, or `None` if `events` was empty.
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

    /// Run a SQL query over the (warm) columnar tier.
    pub async fn sql(&self, query: &str) -> Result<QueryResult> {
        self.analytics.sql(query).await
    }

    /// Every event with `ts` in `[start, end]`, pulled from warm segments on
    /// disk and cold segments in the archive (segment-pruned via the catalog).
    /// This is the retro-hunt read path.
    pub async fn read_range(&self, start: i64, end: i64) -> Result<Vec<Event>> {
        let overlapping: Vec<SegmentMeta> = {
            let cat = self.catalog.lock().unwrap();
            cat.overlapping(start, end).into_iter().cloned().collect()
        };
        let mut events = Vec::new();
        for seg in overlapping {
            let segment_events = match (seg.tier, &self.archive) {
                (Tier::Cold, Some(archive)) => read_segment_bytes(archive.get(&seg.path).await?)?,
                // Hot/warm (and cold with no archive attached): a local file.
                _ => read_segment(std::path::Path::new(&seg.path))?,
            };
            events.extend(
                segment_events
                    .into_iter()
                    .filter(|e| e.ts >= start && e.ts <= end),
            );
        }
        Ok(events)
    }

    /// Migrate warm segments older than `max_warm_age_micros` into the cold
    /// archive. No-op (returns 0) when no archive is attached. Returns the
    /// number of segments migrated.
    pub async fn migrate_warm(&self, max_warm_age_micros: i64) -> Result<usize> {
        let Some(archive) = &self.archive else {
            return Ok(0);
        };
        let now = now_micros();
        let aged: Vec<SegmentMeta> = {
            let cat = self.catalog.lock().unwrap();
            cat.segments()
                .iter()
                .filter(|s| s.tier == Tier::Warm && now - s.max_ts > max_warm_age_micros)
                .cloned()
                .collect()
        };
        let mut migrated = 0;
        for seg in aged {
            let local = PathBuf::from(&seg.path);
            let data = std::fs::read(&local)
                .map_err(|e| sigil_core::Error::Io(format!("read segment {}: {e}", seg.path)))?;
            let key = archive.key(&seg.id);
            archive.put(&key, data).await?;
            self.catalog
                .lock()
                .unwrap()
                .migrate(&seg.id, Tier::Cold, key)?;
            // The archived copy is now authoritative; drop the local file.
            let _ = std::fs::remove_file(&local);
            migrated += 1;
        }
        Ok(migrated)
    }

    /// Delete segments whose data is older than `max_age_micros`, in whichever
    /// tier they live. Returns the number of segments removed.
    pub async fn enforce_retention(&self, max_age_micros: i64) -> Result<usize> {
        let expired: Vec<SegmentMeta> = self
            .catalog
            .lock()
            .unwrap()
            .expired(now_micros(), max_age_micros);
        // Delete archived objects first; catalog removal unlinks local files.
        if let Some(archive) = &self.archive {
            for seg in expired.iter().filter(|s| s.tier == Tier::Cold) {
                archive.delete(&seg.path).await?;
            }
        }
        let ids: Vec<String> = expired.into_iter().map(|s| s.id).collect();
        self.catalog.lock().unwrap().remove(&ids)
    }

    pub fn segment_count(&self) -> usize {
        self.catalog.lock().unwrap().segments().len()
    }

    pub fn total_rows(&self) -> usize {
        self.catalog.lock().unwrap().total_rows()
    }

    /// Segment count per tier `(hot, warm, cold)` — lifecycle observability.
    pub fn tier_counts(&self) -> (usize, usize, usize) {
        let cat = self.catalog.lock().unwrap();
        let mut counts = (0, 0, 0);
        for s in cat.segments() {
            match s.tier {
                Tier::Hot => counts.0 += 1,
                Tier::Warm => counts.1 += 1,
                Tier::Cold => counts.2 += 1,
            }
        }
        counts
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

    #[tokio::test]
    async fn retention_drops_old_segments() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ColumnarStore::open(dir.path().join("cold"), dir.path().join("catalog.json")).unwrap();
        // ts far in the past → immediately expired under any small retention.
        store.write_segment(&[ev("old", 1_000)]).unwrap();
        assert_eq!(store.segment_count(), 1);
        let removed = store.enforce_retention(1_000_000).await.unwrap(); // 1s retention
        assert_eq!(removed, 1);
        assert_eq!(store.segment_count(), 0);
    }

    #[tokio::test]
    async fn read_range_prunes_by_time() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ColumnarStore::open(dir.path().join("cold"), dir.path().join("catalog.json")).unwrap();
        store.write_segment(&[ev("a", 100), ev("b", 200)]).unwrap();
        store.write_segment(&[ev("c", 5_000)]).unwrap();

        let events = store.read_range(150, 300).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host.as_ref().unwrap().id, "b");
    }

    #[tokio::test]
    async fn warm_segments_migrate_to_archive_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let archive = ObjectColdStore::local(dir.path().join("archive")).unwrap();
        let store = ColumnarStore::open(dir.path().join("cold"), dir.path().join("catalog.json"))
            .unwrap()
            .with_archive(archive);

        let meta = store.write_segment(&[ev("web01", 1_000)]).unwrap().unwrap();
        assert_eq!(store.tier_counts(), (0, 1, 0));

        // Everything is older than a 1s warm window (ts=1000 micros ≪ now).
        let migrated = store.migrate_warm(1_000_000).await.unwrap();
        assert_eq!(migrated, 1);
        assert_eq!(store.tier_counts(), (0, 0, 1));
        // Local warm file is gone; the archived object exists.
        assert!(!std::path::Path::new(&meta.path).exists());

        // Cold data still serves reads (fetched from the archive).
        let events = store.read_range(0, 2_000).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host.as_ref().unwrap().id, "web01");

        // Retention reaches into the archive too.
        let removed = store.enforce_retention(1).await.unwrap();
        assert_eq!(removed, 1);
        assert!(store.read_range(0, 2_000).await.unwrap().is_empty());
    }
}
