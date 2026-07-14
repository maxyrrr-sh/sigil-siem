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
use sigil_core::{EntityRef, Error, Event, OcsfClass, Result, Severity};

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
        Field::new("actor_kind", DataType::Utf8, true),
        Field::new("target", DataType::Utf8, true),
        Field::new("target_kind", DataType::Utf8, true),
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
        OcsfClass::DnsActivity => "dns_activity",
        OcsfClass::ModuleActivity => "module_activity",
        OcsfClass::ScheduledJobActivity => "scheduled_job_activity",
        OcsfClass::RegistryKeyActivity => "registry_key_activity",
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
    let mut actor_kind: Vec<Option<String>> = Vec::with_capacity(events.len());
    let mut target: Vec<Option<String>> = Vec::with_capacity(events.len());
    let mut target_kind: Vec<Option<String>> = Vec::with_capacity(events.len());
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
        actor_kind.push(ev.actor.as_ref().map(|e| e.kind.clone()));
        target.push(ev.target.as_ref().map(|e| e.id.clone()));
        target_kind.push(ev.target.as_ref().map(|e| e.kind.clone()));
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
        Arc::new(StringArray::from(actor_kind)),
        Arc::new(StringArray::from(target)),
        Arc::new(StringArray::from(target_kind)),
        Arc::new(StringArray::from(message)),
        Arc::new(StringArray::from(fields_json)),
    ];
    RecordBatch::try_new(event_schema(), columns).map_err(backend)
}

/// Read a Parquet segment back into events (inverse of [`write_segment`],
/// used by retro-hunt). Reconstruction is lossy only for `raw`/`labels`/
/// `template_id`, which the columnar schema does not carry.
pub fn read_segment(path: &std::path::Path) -> Result<Vec<Event>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::Io(format!("open segment {}: {e}", path.display())))?;
    read_parquet_events(file)
}

/// Read a Parquet segment from an in-memory buffer (a cold segment fetched
/// from the object-store archive).
pub fn read_segment_bytes(data: bytes::Bytes) -> Result<Vec<Event>> {
    read_parquet_events(data)
}

fn read_parquet_events<R>(reader: R) -> Result<Vec<Event>>
where
    R: datafusion::parquet::file::reader::ChunkReader + 'static,
{
    use datafusion::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let reader = ParquetRecordBatchReaderBuilder::try_new(reader)
        .map_err(backend)?
        .build()
        .map_err(backend)?;
    let mut events = Vec::new();
    for batch in reader {
        batch_into_events(&batch.map_err(backend)?, &mut events)?;
    }
    Ok(events)
}

fn batch_into_events(batch: &RecordBatch, out: &mut Vec<Event>) -> Result<()> {
    use datafusion::arrow::array::Array;

    fn str_col<'a>(batch: &'a RecordBatch, name: &str) -> Option<&'a StringArray> {
        batch
            .column_by_name(name)
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
    }
    fn opt(col: Option<&StringArray>, row: usize) -> Option<String> {
        col.filter(|c| !c.is_null(row)).map(|c| c.value(row).into())
    }

    let missing = |name: &str| Error::Backend(format!("segment missing column `{name}`"));
    let id = str_col(batch, "id").ok_or_else(|| missing("id"))?;
    let ts = batch
        .column_by_name("ts")
        .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
        .ok_or_else(|| missing("ts"))?;
    let ingest_ts = batch
        .column_by_name("ingest_ts")
        .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
        .ok_or_else(|| missing("ingest_ts"))?;
    let class = batch
        .column_by_name("ocsf_class")
        .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
        .ok_or_else(|| missing("ocsf_class"))?;
    let sev_id = batch
        .column_by_name("severity_id")
        .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
        .ok_or_else(|| missing("severity_id"))?;
    let tenant = str_col(batch, "tenant").ok_or_else(|| missing("tenant"))?;
    let message = str_col(batch, "message").ok_or_else(|| missing("message"))?;
    let fields_json = str_col(batch, "fields_json").ok_or_else(|| missing("fields_json"))?;
    let host = str_col(batch, "host");
    let actor = str_col(batch, "actor");
    let target = str_col(batch, "target");
    // Kind columns are absent in segments written before they were added.
    let actor_kind = str_col(batch, "actor_kind");
    let target_kind = str_col(batch, "target_kind");

    for row in 0..batch.num_rows() {
        let mut ev = Event {
            id: id.value(row).to_string(),
            ts: ts.value(row),
            ingest_ts: ingest_ts.value(row),
            ocsf_class: OcsfClass::from_uid(class.value(row)),
            severity: Severity::from_id(sev_id.value(row).clamp(0, u8::MAX as i32) as u8),
            tenant: tenant.value(row).to_string(),
            message: message.value(row).to_string(),
            ..Default::default()
        };
        ev.host = opt(host, row).map(|h| EntityRef::new("host", h));
        ev.actor = opt(actor, row)
            .map(|a| EntityRef::new(opt(actor_kind, row).unwrap_or_else(|| "user".into()), a));
        ev.target = opt(target, row)
            .map(|t| EntityRef::new(opt(target_kind, row).unwrap_or_else(|| "host".into()), t));
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(fields_json.value(row))
        {
            ev.fields = map.into_iter().collect();
        }
        out.push(ev);
    }
    Ok(())
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

    #[test]
    fn segment_round_trips_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.parquet");
        let mut ev = Event::new("acme");
        ev.ts = 42;
        ev.message = "Failed password for root".into();
        ev.ocsf_class = OcsfClass::Authentication;
        ev.severity = sigil_core::Severity::High;
        ev.actor = Some(EntityRef::new("user", "root"));
        ev.target = Some(EntityRef::new("ip", "10.0.0.9"));
        ev.host = Some(EntityRef::new("host", "web01"));
        ev.fields.insert("app".into(), "sshd".into());
        write_segment(&path, &[ev.clone()]).unwrap();

        let back = read_segment(&path).unwrap();
        assert_eq!(back.len(), 1);
        let b = &back[0];
        assert_eq!(b.id, ev.id);
        assert_eq!(b.ts, 42);
        assert_eq!(b.ocsf_class, OcsfClass::Authentication);
        assert_eq!(b.severity, sigil_core::Severity::High);
        assert_eq!(b.actor, ev.actor);
        assert_eq!(b.target, ev.target);
        assert_eq!(b.host, ev.host);
        assert_eq!(b.field_str("app").as_deref(), Some("sshd"));
    }
}
