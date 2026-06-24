//! Incident assembly (DESIGN §9.6): turn a campaign candidate into a
//! reconstructed, time-ordered attack graph mapped to ATT&CK, with a confidence
//! score and per-edge explanations. This is the correlation output — an
//! incident case, not "just another alert".

use std::collections::HashMap;

use serde::Serialize;
use sigil_core::{Event, PathSelector};

use crate::campaign::CampaignCandidate;
use crate::causal::{build_causal_graph, CausalConfig};

/// One stage of the reconstructed kill-chain.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentStep {
    pub event_id: String,
    pub label: String,
    pub ts: i64,
    pub tactic: Option<String>,
    pub technique: Option<String>,
    pub anomaly: f32,
}

/// A correlated incident: the causal attack graph + ATT&CK chain + confidence.
#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub id: usize,
    /// All member event ids.
    pub events: Vec<String>,
    /// The reconstructed kill-chain, time-ordered.
    pub chain: Vec<IncidentStep>,
    /// Distinct ATT&CK tactics along the chain (kill-chain stages).
    pub tactics: Vec<String>,
    /// Distinct ATT&CK techniques along the chain.
    pub techniques: Vec<String>,
    /// Confidence in 0..=1 (heuristic; real scoring is the GNN, §9.5).
    pub confidence: f32,
    /// Contributing edges, as human-readable explanations (§9.6 explainability).
    pub explanation: Vec<String>,
}

/// Build an incident for one campaign candidate using the given path selector
/// (default: beam search).
pub fn build_incident(
    id: usize,
    candidate: &CampaignCandidate,
    all_events: &[Event],
    techniques: &HashMap<String, String>,
    selector: &dyn PathSelector,
    cfg: &CausalConfig,
) -> Incident {
    let by_id: HashMap<&str, &Event> = all_events.iter().map(|e| (e.id.as_str(), e)).collect();
    let events: Vec<&Event> = candidate
        .events
        .iter()
        .filter_map(|id| by_id.get(id.as_str()).copied())
        .collect();

    let build = build_causal_graph(&events, techniques, cfg);
    let chain = selector.select(&build.graph);
    let g = &build.graph;

    let steps: Vec<IncidentStep> = chain
        .path
        .iter()
        .map(|&n| {
            let node = &g.nodes[n];
            IncidentStep {
                event_id: node.event_id.clone(),
                label: node.label.clone(),
                ts: node.ts,
                tactic: node.tactic.clone(),
                technique: node.technique.clone(),
                anomaly: node.anomaly,
            }
        })
        .collect();

    // Explanations for each consecutive edge on the chosen path.
    let mut explanation = Vec::new();
    for w in chain.path.windows(2) {
        let (a, b) = (w[0], w[1]);
        let reason = build.reasons.get(&(a, b)).cloned().unwrap_or_default();
        let score = g
            .outgoing(a)
            .find(|e| e.to == b)
            .map(|e| e.score)
            .unwrap_or(0.0);
        explanation.push(format!(
            "{} → {} ({reason}; causal={score:.2})",
            g.nodes[a].label, g.nodes[b].label
        ));
    }

    let tactics = distinct(steps.iter().filter_map(|s| s.tactic.clone()));
    let technique_list = distinct(steps.iter().filter_map(|s| s.technique.clone()));
    let confidence = confidence(&steps, &tactics);

    Incident {
        id,
        events: candidate.events.clone(),
        chain: steps,
        tactics,
        techniques: technique_list,
        confidence,
        explanation,
    }
}

/// Heuristic confidence: rewards longer chains, more distinct tactics, and
/// higher average anomaly. Documented as a proxy for the GNN/causal score.
fn confidence(steps: &[IncidentStep], tactics: &[String]) -> f32 {
    if steps.len() < 2 {
        return 0.0;
    }
    let avg_anomaly = steps.iter().map(|s| s.anomaly).sum::<f32>() / steps.len() as f32;
    let len_term = 0.15 * (steps.len() as f32 - 1.0);
    let tactic_term = 0.10 * (tactics.len() as f32 - 1.0).max(0.0);
    (0.2 + len_term + tactic_term + 0.3 * avg_anomaly).clamp(0.0, 0.99)
}

fn distinct(iter: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in iter {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{build_campaigns, CampaignConfig};
    use crate::embed::HashingEmbedder;
    use crate::pathselect::BeamSearchSelector;
    use sigil_core::{EntityRef, OcsfClass};

    fn ev(id: &str, class: OcsfClass, host: &str, ts: i64, msg: &str) -> Event {
        let mut e = Event::new("acme");
        e.id = id.into();
        e.ts = ts;
        e.ocsf_class = class;
        e.host = Some(EntityRef::new("host", host));
        e.message = msg.into();
        e
    }

    #[test]
    fn reconstructs_killchain_with_attck_and_confidence() {
        let events = vec![
            ev(
                "e1",
                OcsfClass::Authentication,
                "web01",
                100,
                "failed password then success",
            ),
            ev(
                "e2",
                OcsfClass::ProcessActivity,
                "web01",
                200,
                "nc -e /bin/sh reverse shell",
            ),
            ev(
                "e3",
                OcsfClass::NetworkActivity,
                "web01",
                300,
                "outbound to 9.9.9.9",
            ),
        ];
        let cfg = CampaignConfig {
            window_micros: 1_000_000,
            sim_threshold: 2.0,
            knn: 5,
            require_cross_domain: true,
            semantic_links: true,
            entity_links: true,
        };
        let cands = build_campaigns(&events, &cfg, &HashingEmbedder::default());
        assert_eq!(cands.len(), 1);

        let mut techniques = HashMap::new();
        techniques.insert("e1".to_string(), "T1110.001".to_string());

        let selector = BeamSearchSelector::default();
        let inc = build_incident(
            0,
            &cands[0],
            &events,
            &techniques,
            &selector,
            &CausalConfig::default(),
        );

        // Time-ordered kill-chain across three tactics.
        assert_eq!(inc.chain.len(), 3);
        assert_eq!(inc.chain[0].event_id, "e1");
        assert_eq!(inc.chain[2].event_id, "e3");
        assert!(inc.tactics.contains(&"credential-access".to_string()));
        assert!(inc.techniques.contains(&"T1110.001".to_string()));
        assert!(inc.confidence > 0.0 && inc.confidence < 1.0);
        assert_eq!(inc.explanation.len(), 2); // two edges on a 3-node chain
    }
}
