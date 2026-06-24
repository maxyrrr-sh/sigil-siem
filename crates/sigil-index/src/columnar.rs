//! Columnar representation of events (DESIGN §7): an Arrow schema plus
//! conversion of [`Event`]s to a `RecordBatch` and Parquet segment writing.
//! This is the analytical counterpart to the Tantivy hot tier.

use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, Int32Array, Int64Array, RecordBatch, StringArray, UInt32Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::parquet::arrow::ArrowWriter;
use datafusion::parquet::file::properties::WriterProperties;
use sigil_core::{Error, Event, OcsfClass, Result, Severity};

fn backend<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// The Arrow schema for an analytical event segment.
pub fn event_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("ingest_ts", DataType::Int64, false),
        Field::new("ocsf_class", DataType::UInt32, false),
        Field::new("ocsf_class_name", DataType::Utf8, false),
        Field::new("severity", DataType::Utf8, false),
        Field::new("severity_id", DataType::Int32, false),
        Field::new("tenant", DataType::Utf8, false),
        Field::new("host", DataType::Utf8, true),
        Field::new("actor", DataType::Utf8, true),
        Field::new("target", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("fields_json", DataType::Utf8, false),
    ]))
}

/// Human-readable OCSF class name (matches the serde snake_case representation).
pub fn class_name(c: &OcsfClass) -> &'static str {
    match c {
        OcsfClass::FileSystemActivity => "file_system_activity",
        OcsfClass::ProcessActivity => "process_activity",
        OcsfClass::Authentication => "authentication",
        OcsfClass::NetworkActivity => "network_activity",
        OcsfClass::HttpActivity => "http_activity",
        OcsfClass::ApiActivity => "api_activity",
        OcsfClass::Other(_) => "other",
    }
}

fn severity_name(s: &Severity) -> &'static str {
    match s {
        Severity::Unknown => "unknown",
        Severity::Informational => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        Severity::Fatal => "fatal",
    }
}

/// Build a `RecordBatch` from a slice of events.
pub fn events_to_batch(events: &[Event]) -> Result<RecordBatch> {
    let mut id = Vec::with_capacity(events.len());
    let mut ts = Vec::with_capacity(events.len());
    let mut ingest_ts = Vec::with_capacity(events.len());
    let mut class = Vec::with_capacity(events.len());
    let mut class_nm = Vec::with_capacity(events.len());
    let mut sev = Vec::with_capacity(events.len());
    let mut sev_id = Vec::with_capacity(events.len());
    let mut tenant = Vec::with_capacity(events.len());
    let mut host: Vec<Option<String>> = Vec::with_capacity(events.len());
    let mut actor: Vec<Option<String>> = Vec::with_capacity(events.len());
    let mut target: Vec<Option<String>> = Vec::with_capacity(events.len());
    let mut message = Vec::with_capacity(events.len());
    let mut fields_json = Vec::with_capacity(events.len());

    for ev in events {
        id.push(ev.id.clone());
        ts.push(ev.ts);
        ingest_ts.push(ev.ingest_ts);
        class.push(ev.ocsf_class.uid());
        class_nm.push(class_name(&ev.ocsf_class));
        sev.push(severity_name(&ev.severity));
        sev_id.push(ev.severity.id() as i32);
        tenant.push(ev.tenant.clone());
        host.push(ev.host.as_ref().map(|e| e.id.clone()));
        actor.push(ev.actor.as_ref().map(|e| e.id.clone()));
        target.push(ev.target.as_ref().map(|e| e.id.clone()));
        message.push(ev.message.clone());
        let fmap: serde_json::Map<String, serde_json::Value> = ev
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        fields_json.push(serde_json::Value::Object(fmap).to_string());
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from(id)),
        Arc::new(Int64Array::from(ts)),
        Arc::new(Int64Array::from(ingest_ts)),
        Arc::new(UInt32Array::from(class)),
        Arc::new(StringArray::from(class_nm)),
        Arc::new(StringArray::from(sev)),
        Arc::new(Int32Array::from(sev_id)),
        Arc::new(StringArray::from(tenant)),
        Arc::new(StringArray::from(host)),
        Arc::new(StringArray::from(actor)),
        Arc::new(StringArray::from(target)),
        Arc::new(StringArray::from(message)),
        Arc::new(StringArray::from(fields_json)),
    ];
    RecordBatch::try_new(event_schema(), columns).map_err(backend)
}

/// Write a batch of events to a Parquet file at `path`. Returns rows written.
pub fn write_segment(path: &std::path::Path, events: &[Event]) -> Result<usize> {
    let batch = events_to_batch(events)?;
    let file = std::fs::File::create(path)
        .map_err(|e| Error::Io(format!("create segment {}: {e}", path.display())))?;
    let props = WriterProperties::builder().build();
    let mut writer = ArrowWriter::try_new(file, event_schema(), Some(props)).map_err(backend)?;
    writer.write(&batch).map_err(backend)?;
    writer.close().map_err(backend)?;
    Ok(events.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::EntityRef;

    #[test]
    fn builds_batch_with_expected_shape() {
        let mut ev = Event::new("acme");
        ev.message = "hello".into();
        ev.ocsf_class = OcsfClass::Authentication;
        ev.actor = Some(EntityRef::new("user", "root"));
        let batch = events_to_batch(&[ev]).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), event_schema().fields().len());
    }

    #[test]
    fn writes_parquet_segment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.parquet");
        let ev = Event::new("acme");
        let n = write_segment(&path, &[ev]).unwrap();
        assert_eq!(n, 1);
        assert!(path.exists() && std::fs::metadata(&path).unwrap().len() > 0);
    }
}
