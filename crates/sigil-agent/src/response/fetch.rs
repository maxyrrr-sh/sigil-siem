//! Fetch a file for triage, bounded by `max_bytes`. (Large-file chunking is a
//! later refinement; v1 caps at the requested size.)

use sigil_edr_proto::pb;

/// Returns `(ok, message, payload)`.
pub fn run(fetch: Option<&pb::FetchFile>) -> (bool, String, Vec<u8>) {
    let Some(f) = fetch else {
        return (false, "missing fetch params".into(), Vec::new());
    };
    if f.path.is_empty() {
        return (false, "fetch requires a path".into(), Vec::new());
    }
    let max = if f.max_bytes == 0 {
        1024 * 1024
    } else {
        f.max_bytes
    };
    match std::fs::read(&f.path) {
        Ok(mut bytes) => {
            let truncated = bytes.len() as u64 > max;
            if truncated {
                bytes.truncate(max as usize);
            }
            let msg = format!(
                "read {} bytes from {}{}",
                bytes.len(),
                f.path,
                if truncated { " (truncated)" } else { "" }
            );
            (true, msg, bytes)
        }
        Err(e) => (false, format!("read {}: {e}", f.path), Vec::new()),
    }
}
