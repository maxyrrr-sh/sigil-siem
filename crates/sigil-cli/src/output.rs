//! Alerting outputs (DESIGN §8): emit matched alerts to a JSON-lines file
//! and/or an HTTP webhook. Both sinks are best-effort — a failing sink logs a
//! warning and never blocks detection.

use std::io::Write;
use std::path::PathBuf;

use sigil_config::AlertOutputs;
use sigil_core::Alert;

/// Configured alert sinks plus a shared HTTP client.
#[derive(Clone)]
pub struct Outputs {
    file: Option<PathBuf>,
    webhook: Option<String>,
    http: reqwest::Client,
}

impl Outputs {
    /// Build from config, creating the parent directory of the file sink.
    pub fn new(cfg: &AlertOutputs) -> Self {
        let file = cfg.file.as_ref().map(PathBuf::from);
        if let Some(path) = &file {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        Outputs {
            file,
            webhook: cfg.webhook.clone(),
            http: reqwest::Client::new(),
        }
    }

    /// True if no sinks are configured (alerts will only hit the store + log).
    pub fn is_empty(&self) -> bool {
        self.file.is_none() && self.webhook.is_none()
    }

    /// Emit one alert to every configured sink.
    pub async fn emit(&self, alert: &Alert) {
        if let Some(path) = &self.file {
            if let Err(e) = append_jsonl(path, alert) {
                tracing::warn!(error = %e, "failed to write alert to file sink");
            }
        }
        if let Some(url) = &self.webhook {
            match self.http.post(url).json(alert).send().await {
                Ok(resp) if !resp.status().is_success() => {
                    tracing::warn!(status = %resp.status(), "webhook returned non-success");
                }
                Err(e) => tracing::warn!(error = %e, "webhook POST failed"),
                _ => {}
            }
        }
    }
}

fn append_jsonl(path: &PathBuf, alert: &Alert) -> std::io::Result<()> {
    let mut line = serde_json::to_string(alert).unwrap_or_else(|_| "{}".into());
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())
}
