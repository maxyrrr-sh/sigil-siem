//! Cold/archive object-store backend (DESIGN §7, ADR: S3-compatible cold
//! tier). Warm Parquet segments live on local disk where DataFusion scans
//! them; once a segment ages past the warm window it migrates here and is
//! fetched back on demand (retro-hunt / `read_range`).
//!
//! The default backend is a local filesystem directory so the core build and
//! CI stay hermetic; S3-compatible stores are behind the `s3` feature.

use std::sync::Arc;

use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use sigil_core::{Error, Result};

fn backend<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(format!("object store: {e}"))
}

/// An archive for cold segments, keyed by segment file name.
#[derive(Clone)]
pub struct ObjectColdStore {
    store: Arc<dyn ObjectStore>,
    /// Key prefix inside the store (e.g. `segments`).
    prefix: String,
    /// Human-readable description for logs (`local:./data/archive`, `s3://…`).
    desc: String,
}

impl std::fmt::Debug for ObjectColdStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectColdStore")
            .field("desc", &self.desc)
            .finish()
    }
}

impl ObjectColdStore {
    /// A local-filesystem archive rooted at `root` (created if missing).
    pub fn local(root: impl AsRef<std::path::Path>) -> Result<ObjectColdStore> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)
            .map_err(|e| Error::Io(format!("create archive dir {}: {e}", root.display())))?;
        let store = LocalFileSystem::new_with_prefix(root).map_err(backend)?;
        Ok(ObjectColdStore {
            store: Arc::new(store),
            prefix: "segments".into(),
            desc: format!("local:{}", root.display()),
        })
    }

    /// An S3-compatible archive. Credentials come from the environment
    /// (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, etc.).
    #[cfg(feature = "s3")]
    pub fn s3(
        bucket: &str,
        region: Option<&str>,
        endpoint: Option<&str>,
        prefix: Option<&str>,
    ) -> Result<ObjectColdStore> {
        let mut builder = object_store::aws::AmazonS3Builder::from_env().with_bucket_name(bucket);
        if let Some(r) = region {
            builder = builder.with_region(r);
        }
        if let Some(e) = endpoint {
            builder = builder.with_endpoint(e).with_allow_http(true);
        }
        let store = builder.build().map_err(backend)?;
        Ok(ObjectColdStore {
            store: Arc::new(store),
            prefix: prefix.unwrap_or("segments").to_string(),
            desc: format!("s3://{bucket}"),
        })
    }

    /// Build from the `cluster.object_store:` config block:
    ///
    /// ```yaml
    /// object_store: { kind: local, root: ./data/archive }
    /// object_store: { kind: s3, bucket: sigil-cold, region: us-east-1 }
    /// ```
    ///
    /// Returns `Ok(None)` when the block is absent/null (tiering disabled).
    pub fn from_config(value: &serde_yaml::Value) -> Result<Option<ObjectColdStore>> {
        let serde_yaml::Value::Mapping(map) = value else {
            return Ok(None);
        };
        let get = |key: &str| -> Option<String> {
            map.get(serde_yaml::Value::String(key.into()))
                .and_then(|v| v.as_str().map(str::to_string))
        };
        match get("kind").as_deref() {
            None | Some("local") => {
                let root = get("root").unwrap_or_else(|| "./data/archive".into());
                Ok(Some(ObjectColdStore::local(root)?))
            }
            #[cfg(feature = "s3")]
            Some("s3") => {
                let bucket = get("bucket")
                    .ok_or_else(|| Error::Config("object_store: s3 needs `bucket`".into()))?;
                Ok(Some(ObjectColdStore::s3(
                    &bucket,
                    get("region").as_deref(),
                    get("endpoint").as_deref(),
                    get("prefix").as_deref(),
                )?))
            }
            #[cfg(not(feature = "s3"))]
            Some("s3") => Err(Error::Config(
                "object_store kind `s3` requires building sigil-index with the `s3` feature".into(),
            )),
            Some(other) => Err(Error::Config(format!(
                "unknown object_store kind `{other}` (expected local|s3)"
            ))),
        }
    }

    /// Where a segment id lives inside the store.
    pub fn key(&self, segment_id: &str) -> String {
        format!("{}/{segment_id}.parquet", self.prefix)
    }

    pub fn describe(&self) -> &str {
        &self.desc
    }

    /// Upload a segment's bytes under `key`.
    pub async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
        self.store
            .put(&ObjPath::from(key), PutPayload::from(data))
            .await
            .map(|_| ())
            .map_err(backend)
    }

    /// Fetch a segment's bytes.
    pub async fn get(&self, key: &str) -> Result<bytes::Bytes> {
        self.store
            .get(&ObjPath::from(key))
            .await
            .map_err(backend)?
            .bytes()
            .await
            .map_err(backend)
    }

    /// Delete a segment (idempotent: missing objects are not an error).
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self.store.delete(&ObjPath::from(key)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(backend(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_archive_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectColdStore::local(dir.path().join("archive")).unwrap();
        let key = store.key("seg-1");
        store.put(&key, b"hello parquet".to_vec()).await.unwrap();
        assert_eq!(store.get(&key).await.unwrap().as_ref(), b"hello parquet");
        store.delete(&key).await.unwrap();
        assert!(store.get(&key).await.is_err());
        store.delete(&key).await.unwrap(); // idempotent
    }

    #[test]
    fn config_parses_local_and_rejects_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = format!("{{ kind: local, root: {} }}", dir.path().display());
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(ObjectColdStore::from_config(&v).unwrap().is_some());

        let none: serde_yaml::Value = serde_yaml::Value::Null;
        assert!(ObjectColdStore::from_config(&none).unwrap().is_none());

        let bad: serde_yaml::Value = serde_yaml::from_str("{ kind: carrier-pigeon }").unwrap();
        assert!(ObjectColdStore::from_config(&bad).is_err());
    }
}
