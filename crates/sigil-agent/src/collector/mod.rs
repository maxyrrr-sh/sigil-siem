//! Portable telemetry collectors. Each [`Collector`] is polled on the agent's
//! interval and emits [`pb::EndpointEvent`]s. The set here is cross-platform by
//! design (process snapshot-diff, file-integrity monitoring, active-connection
//! polling, persistence-point inventory); native fast paths (eBPF/ETW/ES) are a
//! later phase behind the same trait.

use std::time::Duration;

use sigil_edr_proto::pb;

pub mod file;
pub mod network;
pub mod persistence;
pub mod process;

pub use file::FileCollector;
pub use network::NetworkCollector;
pub use persistence::PersistenceCollector;
pub use process::ProcessCollector;

/// A source of endpoint telemetry, polled on the agent interval.
pub trait Collector: Send {
    /// Stable collector name (for logs / stats).
    fn name(&self) -> &'static str;
    /// Produce any events observed since the last poll.
    fn poll(&mut self) -> Vec<pb::EndpointEvent>;
}

/// Run the collectors on a background OS thread, forwarding every event into
/// the async telemetry channel. Collectors do blocking OS work, so they live on
/// their own thread and bridge into tokio via `blocking_send`.
pub fn spawn(
    mut collectors: Vec<Box<dyn Collector>>,
    interval: Duration,
    tx: tokio::sync::mpsc::Sender<pb::EndpointEvent>,
) {
    if collectors.is_empty() {
        return;
    }
    let names: Vec<&str> = collectors.iter().map(|c| c.name()).collect();
    tracing::info!(collectors = ?names, "telemetry collectors active");
    std::thread::spawn(move || loop {
        for c in collectors.iter_mut() {
            for ev in c.poll() {
                if tx.blocking_send(ev).is_err() {
                    return; // channel closed; agent shutting down
                }
            }
        }
        std::thread::sleep(interval);
    });
}

/// A fresh endpoint event with a ULID + current timestamp.
pub(crate) fn new_event(kind: pb::EventKind) -> pb::EndpointEvent {
    pb::EndpointEvent {
        id: ulid::Ulid::new().to_string(),
        ts: now_micros(),
        kind: kind as i32,
        ..Default::default()
    }
}

/// Current time as epoch microseconds.
pub(crate) fn now_micros() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// SHA-256 of a file's contents as lowercase hex, or `None` if unreadable or
/// larger than `max_bytes` (avoids hashing huge files on the hot path).
pub(crate) fn sha256_file(path: &std::path::Path, max_bytes: u64) -> Option<String> {
    use sha2::{Digest, Sha256};
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max_bytes {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(format!("{:x}", h.finalize()))
}
