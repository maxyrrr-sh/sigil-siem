//! Plugin extension traits and the higher-level detection/correlation types
//! they operate on (DESIGN §9, §12).
//!
//! These trait *shapes* are the stable contract. They are synchronous today to
//! keep `sigil-core` dependency-light; production I/O implementations wrap them
//! in `async` (via `async-trait`) without changing the names here.

use serde::{Deserialize, Serialize};

use crate::event::{Event, Record, Severity, Timestamp};
use crate::Result;

/// A detection match (e.g. produced by a Sigma rule). Input to correlation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Alert {
    /// Identifier of the rule/detector that fired.
    pub rule_id: String,
    /// Short human-readable title.
    #[serde(default)]
    pub title: String,
    /// Alert severity.
    #[serde(default)]
    pub severity: Severity,
    /// MITRE ATT&CK technique id, if known (from Sigma `tags`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
    /// Ids of the events that triggered this alert.
    #[serde(default)]
    pub events: Vec<String>,
    /// When the alert fired (epoch micros).
    #[serde(default)]
    pub ts: Timestamp,
}

/// Incremental update to an incident produced by correlation (DESIGN §9.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncidentDelta {
    pub incident_id: String,
    pub added_events: Vec<String>,
    pub confidence: f32,
}

/// A node in the causal attack graph: one event/alert (DESIGN §9.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CausalNode {
    pub event_id: String,
    /// Short human label (e.g. `process_activity process:nc`).
    pub label: String,
    pub ts: Timestamp,
    /// ATT&CK technique id, if mapped.
    pub technique: Option<String>,
    /// ATT&CK tactic, if mapped.
    pub tactic: Option<String>,
    /// Anomaly score in 0..=1 (from the GNN/MAGIC scorer; heuristic today).
    pub anomaly: f32,
}

/// A directed causal edge between two nodes, with a causal score in 0..=1.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CausalEdge {
    pub from: usize,
    pub to: usize,
    pub score: f32,
}

/// Causal / provenance graph over a candidate (DESIGN §9.4, §9.6). Nodes are
/// time-ordered events; edges carry causal scores. A [`PathSelector`] walks
/// this to assemble the kill-chain.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CausalGraph {
    pub nodes: Vec<CausalNode>,
    pub edges: Vec<CausalEdge>,
}

impl CausalGraph {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    /// Edges leaving `node`.
    pub fn outgoing(&self, node: usize) -> impl Iterator<Item = &CausalEdge> {
        self.edges.iter().filter(move |e| e.from == node)
    }
}

/// A reconstructed multi-stage attack chain (DESIGN §9.6): an ordered path of
/// node indices into a [`CausalGraph`], plus the total causal score.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Node indices into the causal graph, in kill-chain order.
    pub path: Vec<usize>,
    /// Total causal score of the path.
    pub score: f32,
}

/// A capability a plugin may request (DESIGN §12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    NetEgress,
    ReadField(String),
    Enrich(String),
}

/// Plugin manifest: identity + requested capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub capabilities: Vec<String>,
}

// ---------------------------------------------------------------------------
// Plugin traits (DESIGN §12.1). Sync stubs today; async in real impls.
// ---------------------------------------------------------------------------

/// Common base every plugin implements.
pub trait Plugin {
    fn manifest(&self) -> &PluginManifest;
}

/// A source of raw events.
pub trait Input: Plugin {
    fn poll(&mut self) -> Result<Vec<Vec<u8>>>;
}

/// Decode raw bytes into [`Record`]s.
pub trait Codec: Plugin {
    fn decode(&self, raw: &[u8]) -> Result<Vec<Record>>;
}

/// Map / filter / enrich a normalized event.
pub trait Processor: Plugin {
    fn process(&self, event: Event) -> Result<Vec<Event>>;
}

/// Stateless detection over a single event.
pub trait Detector: Plugin {
    fn eval(&self, event: &Event) -> Option<Alert>;
}

/// Correlate a batch of events into incident deltas.
pub trait Correlator: Plugin {
    fn correlate(&self, batch: &[Event]) -> Vec<IncidentDelta>;
}

/// Select the most plausible attack chain from a causal graph.
///
/// The default strategy is beam-search (in `sigil-correlate`); the optional
/// `sigil-correlate-rl` crate provides a GRAIN-style RL implementation.
pub trait PathSelector: Plugin {
    fn select(&self, graph: &CausalGraph) -> AttackChain;
}

/// Emit alerts/incidents to an external sink.
pub trait Output: Plugin {
    fn emit(&self, payload: &[u8]) -> Result<()>;
}

/// Pluggable storage backend for the indexer.
pub trait StorageBackend: Plugin {
    fn flush(&self) -> Result<()>;
}
