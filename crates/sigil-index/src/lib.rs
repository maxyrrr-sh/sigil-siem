//! `sigil-index` — Sigil's own indexer (DESIGN §7).
//!
//! Phase 0 implements the **hot tier**: an immutable-segment full-text index
//! backed by [Tantivy]. Events are indexed with searchable columns (message,
//! tenant, host/actor/target, time, class, severity) plus the full event
//! stored as JSON so search can reconstruct it. Warm/cold tiers, DataFusion
//! analytics, and the segment catalog land in Phase 2.
//!
//! [Tantivy]: https://github.com/quickwit-oss/tantivy

pub mod analytics;
pub mod catalog;
pub mod columnar;
pub mod object;
pub mod store;

pub use analytics::{Analytics, QueryResult};
pub use catalog::{parse_duration_micros, Catalog, SegmentMeta, Tier};
pub use object::ObjectColdStore;
pub use store::ColumnarStore;

use std::path::Path;
use std::sync::Mutex;

use sigil_core::{Error, Event, Result};
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{AllQuery, QueryParser};
use tantivy::schema::{Field, Schema, Value, FAST, INDEXED, STORED, STRING, TEXT};
use tantivy::{Index as TantivyIndex, IndexReader, IndexWriter, Order, TantivyDocument};

fn backend<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// Searchable + stored fields of the event index schema.
#[derive(Clone, Copy)]
struct Fields {
    id: Field,
    ts: Field,
    ocsf_class: Field,
    severity: Field,
    tenant: Field,
    host: Field,
    actor: Field,
    target: Field,
    message: Field,
    event_json: Field,
}

fn build_schema() -> (Schema, Fields) {
    let mut b = Schema::builder();
    let fields = Fields {
        id: b.add_text_field("id", STRING | STORED),
        ts: b.add_i64_field("ts", FAST | INDEXED | STORED),
        ocsf_class: b.add_u64_field("ocsf_class", FAST | INDEXED | STORED),
        severity: b.add_u64_field("severity", FAST | INDEXED | STORED),
        tenant: b.add_text_field("tenant", STRING | STORED),
        host: b.add_text_field("host", STRING | STORED),
        actor: b.add_text_field("actor", TEXT | STORED),
        target: b.add_text_field("target", TEXT | STORED),
        message: b.add_text_field("message", TEXT | STORED),
        // Whole event as JSON for faithful reconstruction on read.
        event_json: b.add_text_field("event_json", STORED),
    };
    (b.build(), fields)
}

/// A search request against the index.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Free-text query over message/host/actor/target. Empty = match all.
    pub text: String,
    /// Max hits to return.
    pub limit: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        SearchQuery {
            text: String::new(),
            limit: 50,
        }
    }
}

impl SearchQuery {
    pub fn new(text: impl Into<String>, limit: usize) -> Self {
        SearchQuery {
            text: text.into(),
            limit,
        }
    }
}

/// The hot-tier event index.
pub struct EventIndex {
    index: TantivyIndex,
    reader: IndexReader,
    writer: Mutex<IndexWriter>,
    fields: Fields,
}

impl EventIndex {
    /// Open the index at `path`, creating it (and the directory) if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)
            .map_err(|e| Error::Io(format!("create index dir {}: {e}", path.display())))?;
        let (schema, fields) = build_schema();
        let dir = tantivy::directory::MmapDirectory::open(path).map_err(backend)?;
        let index = TantivyIndex::open_or_create(dir, schema).map_err(backend)?;
        Self::from_index(index, fields, 50_000_000)
    }

    /// Open a transient in-memory index (tests, ephemeral nodes).
    pub fn in_memory() -> Result<Self> {
        let (schema, fields) = build_schema();
        let index = TantivyIndex::create_in_ram(schema);
        Self::from_index(index, fields, 15_000_000)
    }

    fn from_index(index: TantivyIndex, fields: Fields, budget: usize) -> Result<Self> {
        let writer: IndexWriter = index.writer(budget).map_err(backend)?;
        let reader = index
            .reader_builder()
            .reload_policy(tantivy::ReloadPolicy::Manual)
            .try_into()
            .map_err(backend)?;
        Ok(EventIndex {
            index,
            reader,
            writer: Mutex::new(writer),
            fields,
        })
    }

    /// Index a batch of events and commit. Commit makes them searchable.
    pub fn index_events(&self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        {
            let writer = self.writer.lock().unwrap();
            for ev in events {
                writer.add_document(self.event_doc(ev)?).map_err(backend)?;
            }
        }
        self.commit()
    }

    /// Index a single event (no commit). Call [`commit`](Self::commit) after.
    pub fn add(&self, ev: &Event) -> Result<()> {
        let writer = self.writer.lock().unwrap();
        writer.add_document(self.event_doc(ev)?).map_err(backend)?;
        Ok(())
    }

    /// Commit buffered writes and refresh the reader.
    pub fn commit(&self) -> Result<()> {
        {
            let mut writer = self.writer.lock().unwrap();
            writer.commit().map_err(backend)?;
        }
        self.reader.reload().map_err(backend)?;
        Ok(())
    }

    fn event_doc(&self, ev: &Event) -> Result<TantivyDocument> {
        let f = self.fields;
        let mut doc = TantivyDocument::default();
        doc.add_text(f.id, &ev.id);
        doc.add_i64(f.ts, ev.ts);
        doc.add_u64(f.ocsf_class, ev.ocsf_class.uid() as u64);
        doc.add_u64(f.severity, ev.severity.id() as u64);
        doc.add_text(f.tenant, &ev.tenant);
        if let Some(h) = &ev.host {
            doc.add_text(f.host, &h.id);
        }
        if let Some(a) = &ev.actor {
            doc.add_text(f.actor, &a.id);
        }
        if let Some(t) = &ev.target {
            doc.add_text(f.target, &t.id);
        }
        doc.add_text(f.message, &ev.message);
        let json = serde_json::to_string(ev)?;
        doc.add_text(f.event_json, &json);
        Ok(doc)
    }

    /// Total number of indexed documents.
    pub fn count(&self) -> Result<usize> {
        let searcher = self.reader.searcher();
        searcher.search(&AllQuery, &Count).map_err(backend)
    }

    /// Search the index, newest events first.
    pub fn search(&self, query: &SearchQuery) -> Result<Vec<Event>> {
        let searcher = self.reader.searcher();
        let f = self.fields;

        let collector =
            TopDocs::with_limit(query.limit.max(1)).order_by_fast_field::<i64>("ts", Order::Desc);

        let hits = if query.text.trim().is_empty() {
            searcher.search(&AllQuery, &collector).map_err(backend)?
        } else {
            let mut parser =
                QueryParser::for_index(&self.index, vec![f.message, f.host, f.actor, f.target]);
            parser.set_conjunction_by_default();
            let parsed = parser
                .parse_query(&query.text)
                .map_err(|e| Error::Parse(format!("query `{}`: {e}", query.text)))?;
            searcher.search(&parsed, &collector).map_err(backend)?
        };

        let mut out = Vec::with_capacity(hits.len());
        for (_ts, addr) in hits {
            let doc: TantivyDocument = searcher.doc(addr).map_err(backend)?;
            let json = doc
                .get_first(f.event_json)
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Backend("stored event_json missing".into()))?;
            out.push(serde_json::from_str(json)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{EntityRef, OcsfClass};

    fn sample(message: &str, host: &str, ts: i64) -> Event {
        let mut ev = Event::new("acme");
        ev.message = message.into();
        ev.ts = ts;
        ev.host = Some(EntityRef::new("host", host));
        ev.ocsf_class = OcsfClass::Authentication;
        ev
    }

    #[test]
    fn write_then_search_roundtrip() {
        let idx = EventIndex::in_memory().unwrap();
        idx.index_events(&[
            sample("failed password for root", "web01", 100),
            sample("accepted password for alice", "web02", 200),
            sample("nginx restarted", "web01", 300),
        ])
        .unwrap();

        assert_eq!(idx.count().unwrap(), 3);

        // Full-text over message.
        let hits = idx.search(&SearchQuery::new("password", 10)).unwrap();
        assert_eq!(hits.len(), 2);
        // Newest first (ts desc): alice (200) before root (100).
        assert!(hits[0].message.contains("alice"));

        // Match by host (STRING field).
        let hits = idx.search(&SearchQuery::new("web01", 10)).unwrap();
        assert_eq!(hits.len(), 2);

        // Empty query returns everything, newest first.
        let all = idx.search(&SearchQuery::new("", 10)).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].ts, 300);
    }

    #[test]
    fn reopen_persists_events() {
        let dir = tempfile::tempdir().unwrap();
        {
            let idx = EventIndex::open(dir.path()).unwrap();
            idx.index_events(&[sample("hello world", "h", 1)]).unwrap();
        }
        let idx = EventIndex::open(dir.path()).unwrap();
        assert_eq!(idx.count().unwrap(), 1);
        assert_eq!(idx.search(&SearchQuery::new("hello", 10)).unwrap().len(), 1);
    }
}
