//! Segment catalog (DESIGN §7): metadata for every Parquet segment, used for
//! time-based **segment pruning** at query time and **retention** at lifecycle
//! time. Persisted as JSON so it stays inspectable and declarative-friendly.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sigil_core::{now_micros, Error, Result};

/// Storage tier a segment currently lives in (DESIGN §7 lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Hot,
    Warm,
    Cold,
}

/// Metadata describing one immutable Parquet segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMeta {
    pub id: String,
    pub path: String,
    pub tier: Tier,
    /// Min/max event time (epoch micros) covered by the segment.
    pub min_ts: i64,
    pub max_ts: i64,
    pub rows: usize,
    pub created_ts: i64,
}

/// The on-disk catalog of segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(skip)]
    path: PathBuf,
    segments: Vec<SegmentMeta>,
}

impl Catalog {
    /// Open the catalog at `path`, loading existing entries or starting empty.
    pub fn open(path: impl Into<PathBuf>) -> Result<Catalog> {
        let path = path.into();
        let segments = match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str::<CatalogFile>(&text)
                    .map_err(|e| Error::Backend(format!("parsing catalog: {e}")))?
                    .segments
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(Error::Io(format!(
                    "reading catalog {}: {e}",
                    path.display()
                )))
            }
        };
        Ok(Catalog { path, segments })
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let body = serde_json::to_string_pretty(&CatalogFile {
            segments: self.segments.clone(),
        })
        .map_err(|e| Error::Backend(e.to_string()))?;
        std::fs::write(&self.path, body)
            .map_err(|e| Error::Io(format!("writing catalog {}: {e}", self.path.display())))
    }

    /// Register a new segment and persist.
    pub fn add(&mut self, seg: SegmentMeta) -> Result<()> {
        self.segments.push(seg);
        self.save()
    }

    pub fn segments(&self) -> &[SegmentMeta] {
        &self.segments
    }

    pub fn total_rows(&self) -> usize {
        self.segments.iter().map(|s| s.rows).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Segments whose `[min_ts, max_ts]` overlaps the query window — i.e. the
    /// segments a scan must read. This is segment pruning.
    pub fn overlapping(&self, start: i64, end: i64) -> Vec<&SegmentMeta> {
        self.segments
            .iter()
            .filter(|s| s.min_ts <= end && s.max_ts >= start)
            .collect()
    }

    /// Segments older than `max_age_micros` relative to `now` (by `max_ts`).
    /// These are the retention-expired segments.
    pub fn expired(&self, now: i64, max_age_micros: i64) -> Vec<SegmentMeta> {
        self.segments
            .iter()
            .filter(|s| now - s.max_ts > max_age_micros)
            .cloned()
            .collect()
    }

    /// Move a segment to another tier/location (warm→cold migration) and
    /// persist. Returns false if the id is unknown.
    pub fn migrate(&mut self, id: &str, tier: Tier, path: String) -> Result<bool> {
        let Some(seg) = self.segments.iter_mut().find(|s| s.id == id) else {
            return Ok(false);
        };
        seg.tier = tier;
        seg.path = path;
        self.save()?;
        Ok(true)
    }

    /// Delete the given segments from the catalog and remove their files.
    pub fn remove(&mut self, ids: &[String]) -> Result<usize> {
        let mut removed = 0;
        self.segments.retain(|s| {
            if ids.contains(&s.id) {
                let _ = std::fs::remove_file(&s.path);
                removed += 1;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            self.save()?;
        }
        Ok(removed)
    }
}

#[derive(Serialize, Deserialize)]
struct CatalogFile {
    segments: Vec<SegmentMeta>,
}

/// Parse a retention duration like `7d`, `30d`, `12h`, `90m`, `2w` into
/// microseconds. Returns `None` on a malformed string.
pub fn parse_duration_micros(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = num.parse().ok()?;
    let per = match unit {
        "s" => 1_000_000,
        "m" => 60 * 1_000_000,
        "h" => 3_600 * 1_000_000,
        "d" => 86_400 * 1_000_000,
        "w" => 7 * 86_400 * 1_000_000_i64,
        _ => return None,
    };
    Some(n * per)
}

/// Build a [`SegmentMeta`] for a freshly written segment. New segments are
/// **warm**: local Parquet that DataFusion scans directly; they migrate to
/// the cold object-store archive when they age past the warm window.
pub fn segment_meta(id: String, path: &Path, min_ts: i64, max_ts: i64, rows: usize) -> SegmentMeta {
    SegmentMeta {
        id,
        path: path.to_string_lossy().to_string(),
        tier: Tier::Warm,
        min_ts,
        max_ts,
        rows,
        created_ts: now_micros(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(id: &str, min_ts: i64, max_ts: i64) -> SegmentMeta {
        SegmentMeta {
            id: id.into(),
            path: format!("/tmp/{id}.parquet"),
            tier: Tier::Cold,
            min_ts,
            max_ts,
            rows: 10,
            created_ts: 0,
        }
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration_micros("7d"), Some(7 * 86_400 * 1_000_000));
        assert_eq!(parse_duration_micros("90m"), Some(90 * 60 * 1_000_000));
        assert_eq!(
            parse_duration_micros("2w"),
            Some(2 * 7 * 86_400 * 1_000_000)
        );
        assert_eq!(parse_duration_micros("nonsense"), None);
        assert_eq!(parse_duration_micros("10y"), None);
    }

    #[test]
    fn pruning_selects_overlapping_segments() {
        let dir = tempfile::tempdir().unwrap();
        let mut cat = Catalog::open(dir.path().join("catalog.json")).unwrap();
        cat.add(seg("a", 0, 100)).unwrap();
        cat.add(seg("b", 100, 200)).unwrap();
        cat.add(seg("c", 300, 400)).unwrap();

        let hit = cat.overlapping(150, 350);
        let ids: Vec<&str> = hit.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c"]); // "a" pruned out
    }

    #[test]
    fn expired_by_retention() {
        let dir = tempfile::tempdir().unwrap();
        let mut cat = Catalog::open(dir.path().join("catalog.json")).unwrap();
        cat.add(seg("old", 0, 1_000)).unwrap();
        cat.add(seg("new", 0, 1_000_000_000)).unwrap();
        // now=2e9, retention=1e9 micros → "old" (max_ts 1000) is expired.
        let expired = cat.expired(2_000_000_000, 1_000_000_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "old");
    }

    #[test]
    fn reopen_persists_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        {
            let mut cat = Catalog::open(&path).unwrap();
            cat.add(seg("x", 1, 2)).unwrap();
        }
        let cat = Catalog::open(&path).unwrap();
        assert_eq!(cat.segments().len(), 1);
        assert_eq!(cat.total_rows(), 10);
    }
}
