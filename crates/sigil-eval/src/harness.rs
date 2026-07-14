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

// --- multi-seed aggregation --------------------------------------------------

/// A metric aggregated over seeds: mean ± half-width of the 95% CI
/// (Student's t on the sample standard deviation).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MetricSummary {
    pub mean: f64,
    pub ci95: f64,
}

impl MetricSummary {
    fn from_samples(samples: &[f64]) -> MetricSummary {
        let n = samples.len();
        let mean = samples.iter().sum::<f64>() / n as f64;
        if n < 2 {
            return MetricSummary { mean, ci95: 0.0 };
        }
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
        let se = (var / n as f64).sqrt();
        MetricSummary {
            mean,
            ci95: t_critical_95(n - 1) * se,
        }
    }
}

impl fmt::Display for MetricSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}±{:.2}", self.mean, self.ci95)
    }
}

/// Two-sided 95% Student-t critical value for `df` degrees of freedom.
fn t_critical_95(df: usize) -> f64 {
    const TABLE: [f64; 30] = [
        12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160,
        2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056,
        2.052, 2.048, 2.045, 2.042,
    ];
    match df {
        0 => f64::INFINITY,
        1..=30 => TABLE[df - 1],
        _ => 1.96,
    }
}

/// One variant's metrics aggregated across seeds.
#[derive(Debug, Clone, Serialize)]
pub struct VariantSummary {
    pub variant: &'static str,
    pub ari: MetricSummary,
    pub nmi: MetricSummary,
    pub alert_reduction: MetricSummary,
    pub technique_f1: MetricSummary,
    pub chain_similarity: MetricSummary,
}

/// A multi-seed comparison: every variant's mean ± 95% CI over the seeds.
#[derive(Debug, Clone, Serialize)]
pub struct MultiSeedReport {
    pub scenario: String,
    pub seeds: Vec<u64>,
    pub rows: Vec<VariantSummary>,
}

impl fmt::Display for MultiSeedReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "scenario: {}  ({} seeds, mean ± 95% CI)",
            self.scenario,
            self.seeds.len()
        )?;
        writeln!(
            f,
            "{:<16} {:>12} {:>12} {:>12} {:>12} {:>12}",
            "variant", "ARI", "NMI", "reduction", "tech-F1", "chain-sim"
        )?;
        for r in &self.rows {
            writeln!(
                f,
                "{:<16} {:>12} {:>12} {:>12} {:>12} {:>12}",
                r.variant,
                r.ari.to_string(),
                r.nmi.to_string(),
                r.alert_reduction.to_string(),
                r.technique_f1.to_string(),
                r.chain_similarity.to_string()
            )?;
        }
        Ok(())
    }
}

/// Run the full comparison across `scenarios` (one per seed) and aggregate
/// each metric to mean ± 95% CI. Single-seed results still work — the CI is
/// just zero-width.
pub fn run_eval_multi(scenarios: &[Scenario]) -> MultiSeedReport {
    let reports: Vec<EvalReport> = scenarios.iter().map(run_eval).collect();
    let variants: Vec<&'static str> = reports
        .first()
        .map(|r| r.rows.iter().map(|row| row.variant).collect())
        .unwrap_or_default();

    let pick = |v: &str, get: fn(&VariantResult) -> f64| -> MetricSummary {
        let samples: Vec<f64> = reports
            .iter()
            .flat_map(|r| r.rows.iter().filter(|row| row.variant == v).map(get))
            .collect();
        MetricSummary::from_samples(&samples)
    };

    MultiSeedReport {
        scenario: scenarios
            .first()
            .map(|s| s.name.clone())
            .unwrap_or_default(),
        seeds: (0..scenarios.len() as u64).collect(),
        rows: variants
            .into_iter()
            .map(|v| VariantSummary {
                variant: v,
                ari: pick(v, |r| r.ari),
                nmi: pick(v, |r| r.nmi),
                alert_reduction: pick(v, |r| r.alert_reduction),
                technique_f1: pick(v, |r| r.technique_f1),
                chain_similarity: pick(v, |r| r.chain_similarity),
            })
            .collect(),
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
    fn multi_seed_report_aggregates_with_cis() {
        let scenarios: Vec<Scenario> = (1..=5).map(synthetic).collect();
        let report = run_eval_multi(&scenarios);
        assert_eq!(report.seeds.len(), 5);
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
        // Means are within metric range, CIs are finite and non-negative.
        assert!((0.0..=1.0).contains(&combined.ari.mean));
        assert!(combined.ari.ci95.is_finite() && combined.ari.ci95 >= 0.0);
        // The headline claim holds on averages too.
        assert!(combined.ari.mean > sigma.ari.mean);
        // Display renders the ± form.
        assert!(report.to_string().contains('±'));
    }

    #[test]
    fn metric_summary_math() {
        let s = MetricSummary::from_samples(&[1.0, 1.0, 1.0]);
        assert_eq!(s.mean, 1.0);
        assert_eq!(s.ci95, 0.0);
        let s = MetricSummary::from_samples(&[0.9]);
        assert_eq!(s.ci95, 0.0); // single sample: no interval
        let s = MetricSummary::from_samples(&[0.8, 1.0]);
        assert!((s.mean - 0.9).abs() < 1e-9);
        assert!(s.ci95 > 0.0);
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
