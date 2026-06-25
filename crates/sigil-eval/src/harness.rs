//! Evaluation harness (DESIGN §11.3–11.4): run the correlation pipeline over a
//! labelled scenario under several variants — the **combined** approach plus
//! **baselines** (Sigma-only) and **ablations** (±embeddings, ±provenance) —
//! and score each against ground truth. Produces a reproducible comparison.

use std::collections::HashMap;
use std::fmt;

use serde::Serialize;
use sigil_core::Event;
use sigil_correlate::{
    build_campaigns, build_incident, BeamSearchSelector, CampaignConfig, CausalConfig,
    HashingEmbedder,
};

use crate::metrics::{
    adjusted_rand_index, alert_reduction_ratio, normalized_chain_similarity,
    normalized_mutual_info, set_prf1,
};
use crate::scenario::Scenario;

/// Which approach to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Full approach: embeddings + provenance + causal chain assembly.
    Combined,
    /// Ablation: shared-entity (provenance) links only.
    ProvenanceOnly,
    /// Ablation: embedding (semantic) links only.
    SemanticOnly,
    /// Baseline: Sigma alerts, no correlation (each alert stands alone).
    SigmaOnly,
}

impl Variant {
    fn label(&self) -> &'static str {
        match self {
            Variant::Combined => "combined",
            Variant::ProvenanceOnly => "provenance-only",
            Variant::SemanticOnly => "semantic-only",
            Variant::SigmaOnly => "sigma-only",
        }
    }
}

/// Scores for one variant.
#[derive(Debug, Clone, Serialize)]
pub struct VariantResult {
    pub variant: &'static str,
    pub ari: f64,
    pub nmi: f64,
    pub alert_reduction: f64,
    pub technique_f1: f64,
    pub chain_similarity: f64,
    pub incidents: usize,
}

/// The full comparison report.
#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    pub scenario: String,
    pub alerts: usize,
    pub rows: Vec<VariantResult>,
}

impl fmt::Display for EvalReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario: {}  ({} alerts)", self.scenario, self.alerts)?;
        writeln!(
            f,
            "{:<16} {:>6} {:>6} {:>10} {:>8} {:>10} {:>10}",
            "variant", "ARI", "NMI", "reduction", "tech-F1", "chain-sim", "incidents"
        )?;
        for r in &self.rows {
            writeln!(
                f,
                "{:<16} {:>6.2} {:>6.2} {:>10.2} {:>8.2} {:>10.2} {:>10}",
                r.variant,
                r.ari,
                r.nmi,
                r.alert_reduction,
                r.technique_f1,
                r.chain_similarity,
                r.incidents
            )?;
        }
        Ok(())
    }
}

/// Run all variants over a scenario and score them against ground truth.
pub fn run_eval(scenario: &Scenario) -> EvalReport {
    let events: Vec<Event> = scenario.events.iter().map(|le| le.event.clone()).collect();
    let index: HashMap<&str, usize> = events
        .iter()
        .enumerate()
        .map(|(i, e)| (e.id.as_str(), i))
        .collect();
    let truth_labels: Vec<u32> = scenario
        .events
        .iter()
        .map(|le| le.campaign.unwrap_or(0))
        .collect();
    let techniques: HashMap<String, String> = scenario
        .events
        .iter()
        .filter_map(|le| le.technique.clone().map(|t| (le.event.id.clone(), t)))
        .collect();
    let alerts = scenario.events.iter().filter(|le| le.malicious).count();

    let base = CampaignConfig {
        window_micros: 60 * 60 * 1_000_000,
        sim_threshold: 0.25,
        knn: 10,
        require_cross_domain: true,
        semantic_links: true,
        entity_links: true,
    };

    let mut rows = Vec::new();
    for variant in [
        Variant::Combined,
        Variant::ProvenanceOnly,
        Variant::SemanticOnly,
        Variant::SigmaOnly,
    ] {
        rows.push(score_variant(
            variant,
            &events,
            &index,
            &truth_labels,
            &techniques,
            scenario,
            alerts,
            &base,
        ));
    }

    EvalReport {
        scenario: scenario.name.clone(),
        alerts,
        rows,
    }
}

#[allow(clippy::too_many_arguments)]
fn score_variant(
    variant: Variant,
    events: &[Event],
    index: &HashMap<&str, usize>,
    truth_labels: &[u32],
    techniques: &HashMap<String, String>,
    scenario: &Scenario,
    alerts: usize,
    base: &CampaignConfig,
) -> VariantResult {
    let (pred_labels, incidents, pred_techniques, pred_chain) = match variant {
        Variant::SigmaOnly => {
            // No grouping: each malicious alert is its own incident, no chain.
            let mut pred = vec![0u32; events.len()];
            let mut next = 2u32;
            for (i, le) in scenario.events.iter().enumerate() {
                if le.malicious {
                    pred[i] = next;
                    next += 1;
                }
            }
            let techs = scenario.truth_techniques.clone(); // all detected, but uncorrelated
            (pred, alerts, techs, Vec::new())
        }
        _ => {
            let cfg = CampaignConfig {
                semantic_links: variant != Variant::ProvenanceOnly,
                entity_links: variant != Variant::SemanticOnly,
                ..base.clone()
            };
            let cands = build_campaigns(events, &cfg, &HashingEmbedder::default());
            let mut pred = vec![0u32; events.len()];
            for (ci, c) in cands.iter().enumerate() {
                for eid in &c.events {
                    if let Some(&i) = index.get(eid.as_str()) {
                        pred[i] = ci as u32 + 1;
                    }
                }
            }
            let (techs, chain) = match cands.first() {
                Some(top) => {
                    let selector = BeamSearchSelector::default();
                    let cfg = CausalConfig {
                        window_micros: base.window_micros,
                        ..Default::default()
                    };
                    let inc = build_incident(0, top, events, techniques, &selector, &cfg);
                    (
                        inc.techniques,
                        inc.chain.iter().map(|s| s.event_id.clone()).collect(),
                    )
                }
                None => (Vec::new(), Vec::new()),
            };
            (pred, cands.len(), techs, chain)
        }
    };

    VariantResult {
        variant: variant.label(),
        ari: adjusted_rand_index(&pred_labels, truth_labels),
        nmi: normalized_mutual_info(&pred_labels, truth_labels),
        alert_reduction: alert_reduction_ratio(alerts, incidents),
        technique_f1: set_prf1(&pred_techniques, &scenario.truth_techniques).f1,
        chain_similarity: normalized_chain_similarity(&pred_chain, &scenario.truth_chain),
        incidents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::synthetic;

    #[test]
    fn combined_beats_sigma_only_baseline() {
        let report = run_eval(&synthetic(7));
        let combined = report
            .rows
            .iter()
            .find(|r| r.variant == "combined")
            .unwrap();
        let sigma = report
            .rows
            .iter()
            .find(|r| r.variant == "sigma-only")
            .unwrap();

        // The research claim: correlation reconstructs the campaign + chain that
        // the alert-only baseline cannot.
        assert!(
            combined.ari > sigma.ari,
            "combined ARI {} !> sigma {}",
            combined.ari,
            sigma.ari
        );
        assert!(combined.chain_similarity > sigma.chain_similarity);
        assert!(combined.alert_reduction > sigma.alert_reduction);
    }

    #[test]
    fn combined_groups_the_campaign_well() {
        let report = run_eval(&synthetic(1));
        let combined = report
            .rows
            .iter()
            .find(|r| r.variant == "combined")
            .unwrap();
        // Near-perfect grouping of the 4-stage attack vs benign noise.
        assert!(combined.ari > 0.9, "ARI was {}", combined.ari);
        assert!(
            combined.chain_similarity > 0.9,
            "chain sim was {}",
            combined.chain_similarity
        );
    }
}
