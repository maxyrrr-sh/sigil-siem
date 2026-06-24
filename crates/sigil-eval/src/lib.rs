//! `sigil-eval` — evaluation harness + metrics for the correlation feature
//! (DESIGN §11).
//!
//! - [`metrics`] — detection (P/R/F1), correlation (ARI / NMI / alert-reduction),
//!   attribution (technique-chain P/R, graph edit distance).
//! - [`scenario`] — labelled scenarios with ground truth; a deterministic
//!   `synthetic` generator ships (real DARPA/ATLAS loaders slot in behind it).
//! - [`harness`] — run the pipeline under combined / baseline / ablation
//!   variants and produce a reproducible [`harness::EvalReport`].

pub mod harness;
pub mod metrics;
pub mod scenario;

pub use harness::{run_eval, EvalReport, Variant, VariantResult};
pub use scenario::{synthetic, LabeledEvent, Scenario};
