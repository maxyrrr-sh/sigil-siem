//! `sigil-config` — declarative configuration (DESIGN §13).
//!
//! The config file is the source of truth. This crate loads YAML into typed
//! structs ([`Config`]), runs schema + semantic [`validate`](Config::validate),
//! and (later) drives `plan`/`apply`/drift. Phase 0 implements load + validate;
//! the remaining verbs are stubbed in the CLI.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

mod validate;
pub use validate::ValidationReport;

/// Sinks a pipeline may route to. Phase 0 only wires `index`.
pub const KNOWN_SINKS: &[&str] = &["index", "sigma", "correlation"];
/// Codecs Phase 0 ships. Others parse but warn on validate.
pub const KNOWN_CODECS: &[&str] = &["json", "syslog"];
/// Input kinds Phase 0 implements end-to-end.
pub const IMPLEMENTED_INPUTS: &[&str] = &["file", "syslog"];

/// Top-level declared state of a Sigil node (DESIGN §13.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Config schema version. Only `1` is supported today.
    pub version: u32,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub inputs: Vec<InputConfig>,
    #[serde(default)]
    pub pipelines: Vec<PipelineConfig>,
    #[serde(default)]
    pub index: IndexConfig,
    #[serde(default)]
    pub sigma: SigmaConfig,
    /// API authentication / RBAC (DESIGN §14). Defaults to enabled.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Directory for the durable embedded store (alerts triage + saved objects).
    /// Defaults to `./data/store`.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Address of the optional ML sidecar (`http://host:port`). When unset the
    /// offline embedder is used (DESIGN §9.9).
    #[serde(default)]
    pub ml_sidecar: Option<String>,
    /// Permissively-parsed sections not yet wired to behavior (Phases 3+).
    #[serde(default)]
    pub correlation: serde_yaml::Value,
    #[serde(default)]
    pub plugins: Vec<serde_yaml::Value>,
}

impl Config {
    /// Resolved on-disk path for the durable embedded store.
    pub fn resolved_data_dir(&self) -> String {
        self.data_dir
            .clone()
            .unwrap_or_else(|| "./data/store".to_string())
    }
}

/// `auth:` block — local JWT authentication + role-based access (DESIGN §14).
///
/// This ships a local-credentials provider (users declared here); the same
/// surface is structured so an OIDC provider drops in later. Passwords may be
/// given as an argon2 `password_hash` (preferred) or, for dev, a plaintext
/// `password`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// HS256 signing secret for issued JWTs. If empty, an ephemeral secret is
    /// generated at startup (tokens then don't survive a restart).
    #[serde(default)]
    pub jwt_secret: String,
    /// Token lifetime in seconds (default 8h).
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            enabled: true,
            jwt_secret: String::new(),
            token_ttl_secs: default_token_ttl(),
            users: Vec::new(),
        }
    }
}

fn default_token_ttl() -> u64 {
    8 * 60 * 60
}

/// One declared API user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    /// Argon2 PHC string (preferred). Mutually exclusive with `password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// Plaintext password (dev convenience only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Roles: `viewer`, `analyst`, `admin`.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// `cluster:` block (DESIGN §4). Defaults to a monolith / in-proc node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Roles this node runs (`[all]` or e.g. `[ingest, index]`).
    #[serde(default)]
    pub targets: Vec<String>,
    /// Member node ids (for the shard map). Empty = single local node.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Number of logical index shards.
    #[serde(default)]
    pub shards: Option<u32>,
    /// Copies of each shard (primary + replicas).
    #[serde(default)]
    pub replication: Option<u32>,
    #[serde(default)]
    pub object_store: serde_yaml::Value,
    #[serde(default)]
    pub transport: serde_yaml::Value,
}

impl ClusterConfig {
    /// The configured transport `kind` string (e.g. `inproc`, `redpanda`).
    pub fn transport_kind(&self) -> Option<String> {
        match &self.transport {
            serde_yaml::Value::Mapping(m) => m
                .get(serde_yaml::Value::String("kind".into()))
                .and_then(|v| match v {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    _ => None,
                }),
            _ => None,
        }
    }
}

/// One input source. Type-specific settings are captured permissively so new
/// input kinds need no struct change; accessors expose the common ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub codec: CodecConfig,
    /// All other keys (`listen`, `path`, `subscription`, ...).
    #[serde(flatten)]
    pub settings: BTreeMap<String, serde_yaml::Value>,
}

impl InputConfig {
    /// A string setting (e.g. `path`, `listen`) if present.
    pub fn setting_str(&self, key: &str) -> Option<String> {
        self.settings.get(key).and_then(|v| match v {
            serde_yaml::Value::String(s) => Some(s.clone()),
            other => serde_yaml::to_string(other)
                .ok()
                .map(|s| s.trim().to_string()),
        })
    }
}

/// `codec:` block on an input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub settings: BTreeMap<String, serde_yaml::Value>,
}

impl Default for CodecConfig {
    fn default() -> Self {
        CodecConfig {
            kind: "json".to_string(),
            settings: BTreeMap::new(),
        }
    }
}

/// A processing pipeline: where events come from, what happens, where they go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub id: String,
    #[serde(default)]
    pub from: Vec<String>,
    /// Ordered steps (`normalize`, `enrich`, ...). Parsed permissively in
    /// Phase 0 — the run loop always normalizes then routes.
    #[serde(default)]
    pub steps: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub route: Vec<RouteTarget>,
}

/// A single `route` entry (`- to: index`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTarget {
    pub to: String,
}

/// `sigma:` block — the detection engine (DESIGN §8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Named rulepacks (e.g. `sigmahq/windows`). Not resolvable yet — prefer
    /// `rules_dir` in Phase 1.
    #[serde(default)]
    pub rulepacks: Vec<String>,
    /// Directory of Sigma rule YAML files to load (recursively).
    #[serde(default)]
    pub rules_dir: Option<String>,
    /// Where matched alerts are emitted.
    #[serde(default)]
    pub outputs: AlertOutputs,
}

impl Default for SigmaConfig {
    fn default() -> Self {
        SigmaConfig {
            enabled: true,
            rulepacks: Vec::new(),
            rules_dir: None,
            outputs: AlertOutputs::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Alerting sinks (DESIGN §8 outputs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertOutputs {
    /// Append matched alerts as JSON lines to this file.
    #[serde(default)]
    pub file: Option<String>,
    /// POST each alert as JSON to this URL.
    #[serde(default)]
    pub webhook: Option<String>,
}

/// `index:` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexConfig {
    #[serde(default)]
    pub retention: Retention,
    /// Where hot (Tantivy) segments live. Defaults to `./data/index`.
    #[serde(default)]
    pub path: Option<String>,
    /// Where cold (Parquet) segments live. Defaults to `./data/cold`.
    #[serde(default)]
    pub cold_path: Option<String>,
    /// Segment catalog file. Defaults to `./data/catalog.json`.
    #[serde(default)]
    pub catalog_path: Option<String>,
}

impl IndexConfig {
    /// Resolved on-disk hot index directory.
    pub fn resolved_path(&self) -> String {
        self.path
            .clone()
            .unwrap_or_else(|| "./data/index".to_string())
    }

    /// Resolved cold (Parquet) segment directory.
    pub fn resolved_cold_path(&self) -> String {
        self.cold_path
            .clone()
            .unwrap_or_else(|| "./data/cold".to_string())
    }

    /// Resolved segment catalog path.
    pub fn resolved_catalog_path(&self) -> String {
        self.catalog_path
            .clone()
            .unwrap_or_else(|| "./data/catalog.json".to_string())
    }
}

/// Tiered-storage retention windows (durations like `7d`, `30d`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retention {
    #[serde(default = "default_hot")]
    pub hot: String,
    #[serde(default = "default_warm")]
    pub warm: String,
    #[serde(default = "default_cold")]
    pub cold: String,
}

fn default_hot() -> String {
    "7d".into()
}
fn default_warm() -> String {
    "30d".into()
}
fn default_cold() -> String {
    "365d".into()
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            hot: default_hot(),
            warm: default_warm(),
            cold: default_cold(),
        }
    }
}

impl Config {
    /// Load and parse a YAML config file (no semantic validation).
    pub fn load(path: impl AsRef<Path>) -> sigil_core::Result<Config> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| sigil_core::Error::Config(format!("reading {}: {e}", path.display())))?;
        Config::parse(&text)
    }

    /// Parse a YAML config from a string.
    pub fn parse(text: &str) -> sigil_core::Result<Config> {
        serde_yaml::from_str(text)
            .map_err(|e| sigil_core::Error::Config(format!("parsing config: {e}")))
    }

    /// Load + validate; returns the report. Use [`ValidationReport::ok`] to
    /// decide whether to proceed.
    pub fn load_and_validate(
        path: impl AsRef<Path>,
    ) -> sigil_core::Result<(Config, ValidationReport)> {
        let cfg = Config::load(path)?;
        let report = cfg.validate();
        Ok((cfg, report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../configs/sigil.yaml");

    #[test]
    fn parses_example_config() {
        let cfg = Config::parse(EXAMPLE).expect("example config must parse");
        assert_eq!(cfg.version, 1);
        assert!(cfg.inputs.iter().any(|i| i.id == "syslog_main"));
        let syslog = cfg.inputs.iter().find(|i| i.id == "syslog_main").unwrap();
        assert_eq!(syslog.kind, "syslog");
        assert_eq!(
            syslog.setting_str("listen").as_deref(),
            Some("0.0.0.0:5514")
        );
        assert_eq!(syslog.codec.kind, "syslog");
    }

    #[test]
    fn example_config_validates() {
        let cfg = Config::parse(EXAMPLE).unwrap();
        let report = cfg.validate();
        assert!(report.ok(), "unexpected errors: {:?}", report.errors);
    }
}
