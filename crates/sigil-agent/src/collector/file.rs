//! File-integrity monitoring via [`notify`]. Watches configured paths
//! recursively and emits `FILE_CREATE` / `FILE_MODIFY` / `FILE_DELETE`,
//! hashing the file on create/modify.

use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sigil_edr_proto::pb;

use super::{new_event, sha256_file, Collector};

/// Cap on file size we'll hash on a FIM event (25 MiB).
const HASH_MAX: u64 = 25 * 1024 * 1024;

pub struct FileCollector {
    // Watcher must stay alive for events to flow; it's read via `rx`.
    _watcher: RecommendedWatcher,
    rx: Receiver<notify::Result<notify::Event>>,
}

impl FileCollector {
    /// Watch each of `paths` recursively. Missing paths are skipped with a warn.
    pub fn new(paths: &[String]) -> notify::Result<FileCollector> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })?;
        for p in paths {
            let path = PathBuf::from(p);
            if path.exists() {
                if let Err(e) = watcher.watch(&path, RecursiveMode::Recursive) {
                    tracing::warn!(path = %p, error = %e, "cannot watch path");
                }
            } else {
                tracing::warn!(path = %p, "watch path does not exist; skipping");
            }
        }
        Ok(FileCollector {
            _watcher: watcher,
            rx,
        })
    }
}

impl Collector for FileCollector {
    fn name(&self) -> &'static str {
        "file"
    }

    fn poll(&mut self) -> Vec<pb::EndpointEvent> {
        let mut events = Vec::new();
        while let Ok(res) = self.rx.try_recv() {
            let event = match res {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(error = %e, "fim watch error");
                    continue;
                }
            };
            let kind = match event.kind {
                EventKind::Create(_) => pb::EventKind::FileCreate,
                EventKind::Modify(_) => pb::EventKind::FileModify,
                EventKind::Remove(_) => pb::EventKind::FileDelete,
                _ => continue, // ignore Access/Any/Other
            };
            for path in event.paths {
                let mut ev = new_event(kind);
                let hash = if kind != pb::EventKind::FileDelete {
                    sha256_file(&path, HASH_MAX).unwrap_or_default()
                } else {
                    String::new()
                };
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                ev.file = Some(pb::FileInfo {
                    path: path.to_string_lossy().to_string(),
                    hash_sha256: hash,
                    size,
                    mode: String::new(),
                });
                events.push(ev);
            }
        }
        events
    }
}
