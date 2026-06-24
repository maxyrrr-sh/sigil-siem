//! Inputs / collectors (DESIGN §5 step 1).
//!
//! Phase 0 implements:
//! * [`FileTailer`] — `file` input: tail newly-appended lines with an on-disk
//!   checkpoint (at-least-once across restarts), handling truncation/rotation.
//! * [`spawn_syslog_udp`] / [`spawn_syslog_tcp`] — `syslog` listeners that push
//!   raw frames onto a channel for the pipeline runtime to decode.

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sigil_core::{Error, Input, Plugin, PluginManifest, Result};
use tokio::sync::mpsc::Sender;

/// Tails a file, emitting complete (newline-terminated) lines appended since
/// the last poll. The byte offset is persisted next to the source so restarts
/// resume where they left off.
pub struct FileTailer {
    path: PathBuf,
    checkpoint_path: PathBuf,
    offset: u64,
    manifest: PluginManifest,
}

impl FileTailer {
    /// Open a tailer for `path`, restoring any saved checkpoint.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let checkpoint_path = default_checkpoint_path(&path);
        let offset = read_checkpoint(&checkpoint_path);
        Ok(FileTailer {
            manifest: PluginManifest {
                name: format!("file:{}", path.display()),
                version: "0.0.0".into(),
                capabilities: vec![],
            },
            path,
            checkpoint_path,
            offset,
        })
    }

    /// Override where the checkpoint is stored (useful for tests / read-only
    /// log directories).
    pub fn with_checkpoint_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.checkpoint_path = p.into();
        self.offset = read_checkpoint(&self.checkpoint_path);
        self
    }

    /// Read complete lines appended since the last call, advancing and
    /// persisting the checkpoint. Returns an empty vec when there is nothing
    /// new. Resets to offset 0 if the file shrank (rotation/truncation).
    pub fn poll_lines(&mut self) -> Result<Vec<Vec<u8>>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            // Missing file is not fatal for a tailer — it may appear later.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(Error::Io(format!("open {}: {e}", self.path.display()))),
        };
        let len = file.metadata()?.len();
        if len < self.offset {
            // Truncated or rotated: start over.
            self.offset = 0;
        }
        if len == self.offset {
            return Ok(vec![]);
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.offset))?;

        let mut lines = Vec::new();
        let mut consumed = self.offset;
        loop {
            let mut buf = Vec::new();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break; // EOF
            }
            if buf.last() != Some(&b'\n') {
                // Partial trailing line: leave it for the next poll.
                break;
            }
            consumed += n as u64;
            // Trim the trailing newline (and a CR if present).
            if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
            }
            if !buf.is_empty() {
                lines.push(buf);
            }
        }

        if consumed != self.offset {
            self.offset = consumed;
            self.write_checkpoint();
        }
        Ok(lines)
    }

    fn write_checkpoint(&self) {
        if let Err(e) = std::fs::write(&self.checkpoint_path, self.offset.to_string()) {
            tracing::warn!(path = %self.checkpoint_path.display(), error = %e, "failed to persist checkpoint");
        }
    }

    /// Current byte offset (exposed for tests / observability).
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl Plugin for FileTailer {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl Input for FileTailer {
    fn poll(&mut self) -> Result<Vec<Vec<u8>>> {
        self.poll_lines()
    }
}

fn default_checkpoint_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".sigil-checkpoint");
    path.with_file_name(name)
}

fn read_checkpoint(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Bind a UDP syslog listener and forward each datagram as a raw frame.
/// Runs until the channel receiver is dropped.
pub async fn spawn_syslog_udp(listen: &str, tx: Sender<Vec<u8>>) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind(listen)
        .await
        .map_err(|e| Error::Io(format!("bind udp {listen}: {e}")))?;
    tracing::info!(%listen, "syslog UDP listener bound");
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, _peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "udp recv error");
                continue;
            }
        };
        if tx.send(buf[..n].to_vec()).await.is_err() {
            break; // pipeline shut down
        }
    }
    Ok(())
}

/// Bind a TCP syslog listener (one syslog line per `\n`-delimited frame).
/// Each accepted connection is handled on its own task.
pub async fn spawn_syslog_tcp(listen: &str, tx: Sender<Vec<u8>>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| Error::Io(format!("bind tcp {listen}: {e}")))?;
    tracing::info!(%listen, "syslog TCP listener bound");
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept error");
                continue;
            }
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(stream);
            let mut line = Vec::new();
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let mut frame = line.clone();
                        if frame.last() == Some(&b'\n') {
                            frame.pop();
                            if frame.last() == Some(&b'\r') {
                                frame.pop();
                            }
                        }
                        if !frame.is_empty() && tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tails_appended_lines_and_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        std::fs::write(&log, "line one\nline two\n").unwrap();

        let mut tailer = FileTailer::open(&log).unwrap();
        let lines = tailer.poll_lines().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"line one");

        // Nothing new yet.
        assert!(tailer.poll_lines().unwrap().is_empty());

        // Append more; only the new line is returned.
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "line three").unwrap();
        let lines = tailer.poll_lines().unwrap();
        assert_eq!(lines, vec![b"line three".to_vec()]);

        // A fresh tailer resumes from the persisted checkpoint.
        let mut resumed = FileTailer::open(&log).unwrap();
        assert_eq!(resumed.offset(), tailer.offset());
        assert!(resumed.poll_lines().unwrap().is_empty());
    }

    #[test]
    fn partial_trailing_line_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("p.log");
        std::fs::write(&log, "complete\npartial-no-newline").unwrap();
        let mut tailer = FileTailer::open(&log).unwrap();
        let lines = tailer.poll_lines().unwrap();
        assert_eq!(lines, vec![b"complete".to_vec()]);

        // Finish the partial line; now it is emitted.
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, " now-done").unwrap();
        let lines = tailer.poll_lines().unwrap();
        assert_eq!(lines, vec![b"partial-no-newline now-done".to_vec()]);
    }

    #[test]
    fn rotation_resets_offset() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("r.log");
        std::fs::write(&log, "aaaa\nbbbb\n").unwrap();
        let mut tailer = FileTailer::open(&log).unwrap();
        assert_eq!(tailer.poll_lines().unwrap().len(), 2);

        // Rotate: shorter file.
        std::fs::write(&log, "new\n").unwrap();
        let lines = tailer.poll_lines().unwrap();
        assert_eq!(lines, vec![b"new".to_vec()]);
    }
}
