//! `sigil-correlate` — semantic + causal correlation orchestrator (DESIGN §9).
//!
//! Phase 3 (semantics): turn heterogeneous events into semantic atoms and link
//! them into **campaign candidates**.
//!
//! - [`triplet`] — `(subject, action, object)` extraction (§9.2).
//! - [`embed`] — field-aware embeddings; offline [`embed::HashingEmbedder`] by
//!   default, sidecar/SecureBERT as a drop-in (§9.3, §9.9).
//! - [`vector`] — [`vector::VectorStore`] KNN (exact today, HNSW later) (§9.3).
//! - [`campaign`] — cross-domain candidate generation: embedding KNN + shared
//!   entities (via `sigil-graph`) + time window → connected components (§9.4–5).
//!
//! Phase 4 (causality) turns candidates into incidents:
//!
//! - [`causal`] — build a time-ordered [`sigil_core::CausalGraph`] with causal
//!   edge scores + a deterministic anomaly heuristic (GNN/MAGIC stand-in).
//! - [`pathselect`] — [`pathselect::BeamSearchSelector`], the default
//!   [`sigil_core::PathSelector`] that assembles the kill-chain.
//! - [`attack`] — ATT&CK tactic mapping.
//! - [`incident`] — [`incident::Incident`]: the reconstructed attack graph with
//!   confidence + explanations.

pub mod attack;
pub mod campaign;
pub mod causal;
pub mod embed;
pub mod incident;
pub mod pathselect;
pub mod triplet;
pub mod vector;

pub use attack::{tactic_for, tactic_for_class};
pub use campaign::{build_campaigns, CampaignCandidate, CampaignConfig};
pub use causal::{build_causal_graph, CausalBuild, CausalConfig};
pub use embed::{serialize_event, Embedder, HashingEmbedder};
pub use incident::{build_incident, Incident, IncidentStep};
pub use pathselect::BeamSearchSelector;
pub use triplet::{extract_triplet, Triplet};
pub use vector::{FlatVectorStore, VectorStore};
