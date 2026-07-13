//! Agent configuration + persisted enrollment identity.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Static agent configuration (from `agent.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// EDR gateway URL, e.g. `http://siem:50055` or `https://siem:50055`.
    pub server_url: String,
    /// Pre-shared enrollment token (used once, at `enroll`).
    #[serde(default)]
    pub enrollment_token: String,
    /// Paths to watch for file-integrity monitoring.
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<String>,
    /// Directory quarantined files are moved into.
    #[serde(default = "default_quarantine")]
    pub quarantine_dir: String,
    /// PEM CA bundle to pin for TLS (required for `https://` servers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<String>,
    /// Where the enrollment identity is persisted (defaults next to the config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_file: Option<String>,
    /// Collector poll cadence.
    #[serde(default = "default_poll_secs")]
    pub poll_interval_secs: u64,
    /// Max telemetry events per batch.
    #[serde(default = "default_batch")]
    pub batch_size: usize,
    /// Per-collector enable flags.
    #[serde(default)]
    pub collectors: CollectorToggles,
}

/// Which collectors run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorToggles {
    #[serde(default = "yes")]
    pub process: bool,
    #[serde(default = "yes")]
    pub file: bool,
    #[serde(default = "yes")]
    pub network: bool,
    #[serde(default = "yes")]
    pub persistence: bool,
}

impl Default for CollectorToggles {
    fn default() -> Self {
        CollectorToggles {
            process: true,
            file: true,
            network: true,
            persistence: true,
        }
    }
}

fn yes() -> bool {
    true
}
fn default_watch_paths() -> Vec<String> {
    // Sensible cross-platform defaults; override in config.
    if cfg!(target_os = "windows") {
        vec!["C:/Windows/System32/drivers/etc".into()]
    } else {
        vec!["/etc".into(), "/usr/local/bin".into(), "/tmp".into()]
    }
}
fn default_quarantine() -> String {
    "./sigil-quarantine".into()
}
fn default_poll_secs() -> u64 {
    5
}
fn default_batch() -> usize {
    256
}

impl AgentConfig {
    /// Load config from a YAML file.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<AgentConfig> {
        let text = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// A minimal config from just a server URL + enrollment token (used by
    /// `enroll` when no config file is present).
    pub fn minimal(server_url: String, enrollment_token: String) -> AgentConfig {
        AgentConfig {
            server_url,
            enrollment_token,
            watch_paths: default_watch_paths(),
            quarantine_dir: default_quarantine(),
            tls_ca: None,
            state_file: None,
            poll_interval_secs: default_poll_secs(),
            batch_size: default_batch(),
            collectors: CollectorToggles::default(),
        }
    }

    /// Resolved state-file path (identity persistence).
    pub fn state_path(&self) -> PathBuf {
        self.state_file
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./sigil-agent-state.json"))
    }
}

/// The identity granted at enrollment; persisted so the agent reconnects
/// without re-enrolling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub session_token: String,
    pub server_url: String,
}

impl AgentIdentity {
    /// Load persisted identity, if present.
    pub fn load(path: impl AsRef<Path>) -> Option<AgentIdentity> {
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Persist identity to disk.
    pub fn save(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }
}
