//! Alerting outputs (DESIGN §8): fan a matched alert out to every configured
//! sink. Sinks are **best-effort** — a failing sink logs a warning and never
//! blocks detection. The `file` sink is local + synchronous; network sinks
//! (webhook, Slack, PagerDuty, Jira, MISP) implement the async [`OutputSink`]
//! trait and conceptually require the `net:egress` capability.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use sigil_config::AlertOutputs;
use sigil_core::{Alert, Severity};

mod jira;
mod misp;
mod pagerduty;
mod slack;

use jira::JiraSink;
use misp::MispSink;
use pagerduty::PagerDutySink;
use slack::SlackSink;

/// A network alert sink. Implementations POST one alert to an external service.
/// They must never panic and never block detection — log and swallow errors.
#[async_trait::async_trait]
pub trait OutputSink: Send + Sync {
    /// Short identifier for logs/metrics.
    fn name(&self) -> &'static str;
    /// Deliver one alert using the shared HTTP client.
    async fn emit(&self, alert: &Alert, http: &reqwest::Client);
}

/// Configured alert sinks plus a shared HTTP client.
#[derive(Clone)]
pub struct Outputs {
    file: Option<PathBuf>,
    sinks: Arc<Vec<Box<dyn OutputSink>>>,
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

        let mut sinks: Vec<Box<dyn OutputSink>> = Vec::new();
        if let Some(url) = &cfg.webhook {
            sinks.push(Box::new(WebhookSink::new(url.clone())));
        }
        if let Some(url) = &cfg.slack {
            sinks.push(Box::new(SlackSink::new(url.clone())));
        }
        if let Some(pd) = &cfg.pagerduty {
            sinks.push(Box::new(PagerDutySink::new(pd.clone())));
        }
        if let Some(jira) = &cfg.jira {
            sinks.push(Box::new(JiraSink::new(jira.clone())));
        }
        if let Some(misp) = &cfg.misp {
            sinks.push(Box::new(MispSink::new(misp.clone())));
        }

        Outputs {
            file,
            sinks: Arc::new(sinks),
            http: reqwest::Client::new(),
        }
    }

    /// True if no sinks are configured (alerts will only hit the store + log).
    pub fn is_empty(&self) -> bool {
        self.file.is_none() && self.sinks.is_empty()
    }

    /// Emit one alert to every configured sink.
    pub async fn emit(&self, alert: &Alert) {
        if let Some(path) = &self.file {
            if let Err(e) = append_jsonl(path, alert) {
                tracing::warn!(error = %e, "failed to write alert to file sink");
            }
        }
        for sink in self.sinks.iter() {
            sink.emit(alert, &self.http).await;
        }
    }
}

/// The short headline for an alert, falling back to the rule id.
pub(crate) fn alert_title(alert: &Alert) -> &str {
    if alert.title.is_empty() {
        &alert.rule_id
    } else {
        &alert.title
    }
}

/// Lowercase severity label (`critical`, `high`, ...).
pub(crate) fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Unknown => "unknown",
        Severity::Informational => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        Severity::Fatal => "fatal",
    }
}

/// Log a sink delivery outcome uniformly.
pub(crate) fn log_result(sink: &'static str, result: reqwest::Result<reqwest::Response>) {
    match result {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!(sink, status = %resp.status(), "alert sink returned non-success");
        }
        Err(e) => tracing::warn!(sink, error = %e, "alert sink request failed"),
        _ => {}
    }
}

/// Generic JSON webhook sink: POST the alert as-is.
struct WebhookSink {
    url: String,
}

impl WebhookSink {
    fn new(url: String) -> Self {
        WebhookSink { url }
    }
}

#[async_trait::async_trait]
impl OutputSink for WebhookSink {
    fn name(&self) -> &'static str {
        "webhook"
    }
    async fn emit(&self, alert: &Alert, http: &reqwest::Client) {
        log_result(self.name(), http.post(&self.url).json(alert).send().await);
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
