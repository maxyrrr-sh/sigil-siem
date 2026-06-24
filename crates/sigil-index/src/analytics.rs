//! Analytical query engine (DESIGN §7): [DataFusion] over the Parquet cold
//! tier. Registers the segment directory as a table named `events` and runs
//! SQL, returning results as JSON rows and a pretty-printed table.
//!
//! [DataFusion]: https://datafusion.apache.org/

use std::path::PathBuf;

use datafusion::arrow::array::{
    Array, BooleanArray, Float64Array, Int32Array, Int64Array, LargeStringArray, RecordBatch,
    StringArray, StringViewArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::datatypes::DataType;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use sigil_core::{Error, Result};

use crate::columnar::event_schema;

fn backend<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// Result of an analytical query.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<serde_json::Value>,
    /// Pretty-printed ASCII table (handy for the CLI).
    pub table: String,
}

/// Runs SQL over the Parquet segments under `cold_dir`.
#[derive(Debug, Clone)]
pub struct Analytics {
    cold_dir: PathBuf,
}

impl Analytics {
    pub fn new(cold_dir: impl Into<PathBuf>) -> Self {
        Analytics {
            cold_dir: cold_dir.into(),
        }
    }

    /// True if any Parquet segment exists to query.
    fn has_segments(&self) -> bool {
        std::fs::read_dir(&self.cold_dir)
            .map(|rd| {
                rd.flatten()
                    .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("parquet"))
            })
            .unwrap_or(false)
    }

    /// Execute a SQL query against the `events` table.
    pub async fn sql(&self, query: &str) -> Result<QueryResult> {
        let ctx = SessionContext::new();
        if self.has_segments() {
            let dir = self.cold_dir.to_string_lossy().to_string();
            ctx.register_parquet("events", &dir, ParquetReadOptions::default())
                .await
                .map_err(backend)?;
        } else {
            // No data yet: register an empty table so queries still resolve.
            let empty = RecordBatch::new_empty(event_schema());
            ctx.register_batch("events", empty).map_err(backend)?;
        }

        let df = ctx.sql(query).await.map_err(backend)?;
        let arrow_schema = df.schema().as_arrow().clone();
        let columns: Vec<String> = arrow_schema
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        let batches = df.collect().await.map_err(backend)?;

        let rows = batches_to_json(&batches);
        let table = datafusion::arrow::util::pretty::pretty_format_batches(&batches)
            .map_err(backend)?
            .to_string();
        Ok(QueryResult {
            columns,
            rows,
            table,
        })
    }
}

/// Convert record batches to JSON objects (one per row) for common types.
fn batches_to_json(batches: &[RecordBatch]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for batch in batches {
        let schema = batch.schema();
        for row in 0..batch.num_rows() {
            let mut obj = serde_json::Map::new();
            for (col, field) in schema.fields().iter().enumerate() {
                let array = batch.column(col);
                obj.insert(field.name().clone(), cell_to_json(array, row));
            }
            out.push(serde_json::Value::Object(obj));
        }
    }
    out
}

fn cell_to_json(array: &dyn Array, row: usize) -> serde_json::Value {
    use serde_json::Value;
    if array.is_null(row) {
        return Value::Null;
    }
    macro_rules! get {
        ($ty:ty) => {
            array.as_any().downcast_ref::<$ty>().map(|a| a.value(row))
        };
    }
    match array.data_type() {
        DataType::Utf8 => get!(StringArray).map(|v| Value::String(v.to_string())),
        DataType::Utf8View => get!(StringViewArray).map(|v| Value::String(v.to_string())),
        DataType::LargeUtf8 => get!(LargeStringArray).map(|v| Value::String(v.to_string())),
        DataType::Int64 => get!(Int64Array).map(Value::from),
        DataType::Int32 => get!(Int32Array).map(Value::from),
        DataType::UInt32 => get!(UInt32Array).map(Value::from),
        DataType::UInt64 => get!(UInt64Array).map(Value::from),
        DataType::Float64 => get!(Float64Array).map(Value::from),
        DataType::Boolean => get!(BooleanArray).map(Value::from),
        _ => Some(Value::String(format!("{:?}", array.data_type()))),
    }
    .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::columnar::write_segment;
    use sigil_core::{EntityRef, Event, OcsfClass};

    fn ev(host: &str, class: OcsfClass, ts: i64) -> Event {
        let mut e = Event::new("acme");
        e.ts = ts;
        e.host = Some(EntityRef::new("host", host));
        e.ocsf_class = class;
        e.message = "m".into();
        e
    }

    #[tokio::test]
    async fn sql_aggregation_over_segments() {
        let dir = tempfile::tempdir().unwrap();
        write_segment(
            &dir.path().join("s1.parquet"),
            &[
                ev("web01", OcsfClass::Authentication, 10),
                ev("web01", OcsfClass::Authentication, 20),
                ev("web02", OcsfClass::NetworkActivity, 30),
            ],
        )
        .unwrap();

        let a = Analytics::new(dir.path());
        let res = a
            .sql("SELECT host, count(*) AS n FROM events GROUP BY host ORDER BY host")
            .await
            .unwrap();
        assert_eq!(res.rows.len(), 2);
        assert_eq!(res.rows[0]["host"], serde_json::json!("web01"));
        assert_eq!(res.rows[0]["n"], serde_json::json!(2));
    }

    #[tokio::test]
    async fn sql_on_empty_store_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let a = Analytics::new(dir.path());
        let res = a.sql("SELECT count(*) AS n FROM events").await.unwrap();
        assert_eq!(res.rows[0]["n"], serde_json::json!(0));
    }
}
