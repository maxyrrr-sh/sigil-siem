//! Quarantine a file: move it into the quarantine directory, strip its
//! permissions, and record the original path in a sidecar so it is reversible.

use std::path::PathBuf;

use sigil_edr_proto::pb;

/// Returns `(ok, message)`.
pub fn run(q: Option<&pb::QuarantineFile>, quarantine_dir: &str) -> (bool, String) {
    let Some(q) = q else {
        return (false, "missing quarantine params".into());
    };
    if q.path.is_empty() {
        return (false, "quarantine requires a path".into());
    }
    let src = PathBuf::from(&q.path);
    if !src.exists() {
        return (false, format!("no such file: {}", q.path));
    }

    let dir = PathBuf::from(quarantine_dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return (false, format!("create quarantine dir: {e}"));
    }
    let stem = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let dst = dir.join(format!("{}-{stem}", ulid::Ulid::new()));

    // Move (rename), falling back to copy+remove across filesystems.
    if std::fs::rename(&src, &dst).is_err() {
        if let Err(e) = std::fs::copy(&src, &dst) {
            return (false, format!("copy to quarantine: {e}"));
        }
        if let Err(e) = std::fs::remove_file(&src) {
            return (false, format!("remove original after copy: {e}"));
        }
    }

    strip_permissions(&dst);

    // Sidecar records the original path for later restore.
    let meta = serde_json::json!({ "original_path": q.path, "hash_sha256": q.hash_sha256 });
    let _ = std::fs::write(dst.with_extension("meta.json"), meta.to_string());

    (true, format!("quarantined {} -> {}", q.path, dst.display()))
}

#[cfg(unix)]
fn strip_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000));
}

#[cfg(not(unix))]
fn strip_permissions(path: &std::path::Path) {
    // Best-effort: mark read-only on non-unix platforms.
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        let _ = std::fs::set_permissions(path, perms);
    }
}
