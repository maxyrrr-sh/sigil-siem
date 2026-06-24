//! Causal subgraph construction + scoring (DESIGN §9.4–9.6).
//!
//! From a campaign's events we build a time-ordered [`CausalGraph`]: nodes are
//! events (with an anomaly score), edges are causal hypotheses scored from
//! temporal proximity, shared entities, and the target's anomaly. The anomaly
//! score is a deterministic heuristic standing in for the sidecar GNN / masked
//! graph autoencoder (MAGIC-style, §9.5) — a drop-in swap.

use std::collections::HashMap;

use sigil_core::{CausalEdge, CausalGraph, CausalNode, EntityRef, Event, OcsfClass, Severity};

use crate::attack::tactic_for;

/// Tunables for causal graph construction.
#[derive(Debug, Clone)]
pub struct CausalConfig {
    /// Max time gap (micros) for a causal edge.
    pub window_micros: i64,
    /// Beam width for chain assembly.
    pub beam_width: usize,
}

impl Default for CausalConfig {
    fn default() -> Self {
        CausalConfig {
            window_micros: 30 * 60 * 1_000_000,
            beam_width: 4,
        }
    }
}

/// A built causal graph plus per-edge human explanations.
pub struct CausalBuild {
    pub graph: CausalGraph,
    /// `(from, to)` → why the edge exists (for incident explanations).
    pub reasons: HashMap<(usize, usize), String>,
}

/// Build the causal graph for a set of events (uses `techniques` to label
/// nodes with ATT&CK technique ids where a Sigma rule matched).
pub fn build_causal_graph(
    events: &[&Event],
    techniques: &HashMap<String, String>,
    cfg: &CausalConfig,
) -> CausalBuild {
    let mut ordered: Vec<&Event> = events.to_vec();
    ordered.sort_by_key(|e| e.ts);

    let nodes: Vec<CausalNode> = ordered
        .iter()
        .map(|e| {
            let technique = techniques.get(&e.id).cloned();
            let tactic = Some(tactic_for(technique.as_deref(), &e.ocsf_class).to_string());
            CausalNode {
                event_id: e.id.clone(),
                label: label_for(e),
                ts: e.ts,
                technique,
                tactic,
                anomaly: anomaly_score(e),
            }
        })
        .collect();

    let mut edges = Vec::new();
    let mut reasons = HashMap::new();
    for i in 0..ordered.len() {
        for j in (i + 1)..ordered.len() {
            let (a, b) = (ordered[i], ordered[j]);
            if b.ts - a.ts > cfg.window_micros {
                continue;
            }
            let shared = shared_entities(a, b);
            if shared.is_empty() {
                continue; // require a provenance link for a causal hypothesis
            }
            let temporal = temporal_score(b.ts - a.ts);
            let score = (0.45 + 0.25 * temporal + 0.30 * nodes[j].anomaly).min(1.0);
            edges.push(CausalEdge {
                from: i,
                to: j,
                score,
            });
            reasons.insert(
                (i, j),
                format!("shares {}; Δt={}", shared.join(", "), human_dt(b.ts - a.ts)),
            );
        }
    }

    CausalBuild {
        graph: CausalGraph { nodes, edges },
        reasons,
    }
}

fn label_for(e: &Event) -> String {
    let class = match e.ocsf_class {
        OcsfClass::Authentication => "authentication",
        OcsfClass::ProcessActivity => "process_activity",
        OcsfClass::FileSystemActivity => "file_system_activity",
        OcsfClass::NetworkActivity => "network_activity",
        OcsfClass::HttpActivity => "http_activity",
        OcsfClass::ApiActivity => "api_activity",
        OcsfClass::Other(_) => "other",
    };
    match &e.actor {
        Some(a) => format!("{class} {}:{}", a.kind, a.id),
        None => class.to_string(),
    }
}

/// Deterministic anomaly heuristic in 0..=1 (stand-in for the GNN/MAGIC score).
fn anomaly_score(e: &Event) -> f32 {
    let mut s: f32 = match e.severity {
        Severity::Critical | Severity::Fatal => 0.9,
        Severity::High => 0.75,
        Severity::Medium => 0.5,
        Severity::Low => 0.3,
        _ => 0.2,
    };
    let msg = e.message.to_lowercase();
    for kw in [
        "shadow",
        "reverse shell",
        "nc -e",
        "/bin/sh",
        "mimikatz",
        "failed password",
        "exploit",
    ] {
        if msg.contains(kw) {
            s += 0.1;
        }
    }
    s.min(1.0)
}

fn shared_entities(a: &Event, b: &Event) -> Vec<String> {
    let keys = |e: &Event| -> Vec<String> {
        [&e.host, &e.actor, &e.target]
            .into_iter()
            .flatten()
            .map(key)
            .collect()
    };
    let bkeys = keys(b);
    keys(a).into_iter().filter(|k| bkeys.contains(k)).collect()
}

fn key(e: &EntityRef) -> String {
    format!("{}:{}", e.kind, e.id)
}

/// Closer in time → closer to 1.0 (1-minute scale).
fn temporal_score(dt_micros: i64) -> f32 {
    let secs = (dt_micros.max(0) as f32) / 1_000_000.0;
    1.0 / (1.0 + secs / 60.0)
}

fn human_dt(dt_micros: i64) -> String {
    let secs = (dt_micros.max(0) as f64) / 1_000_000.0;
    if secs < 90.0 {
        format!("{secs:.0}s")
    } else {
        format!("{:.1}m", secs / 60.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, class: OcsfClass, host: &str, ts: i64) -> Event {
        let mut e = Event::new("acme");
        e.id = id.into();
        e.ts = ts;
        e.ocsf_class = class;
        e.host = Some(EntityRef::new("host", host));
        e
    }

    #[test]
    fn builds_time_ordered_graph_with_shared_entity_edges() {
        let events = [
            ev("e2", OcsfClass::ProcessActivity, "web01", 200),
            ev("e1", OcsfClass::Authentication, "web01", 100),
            ev("e3", OcsfClass::NetworkActivity, "web01", 300),
        ];
        let refs: Vec<&Event> = events.iter().collect();
        let build = build_causal_graph(&refs, &HashMap::new(), &CausalConfig::default());
        // Sorted by ts: e1, e2, e3.
        assert_eq!(build.graph.nodes[0].event_id, "e1");
        assert_eq!(build.graph.nodes[2].event_id, "e3");
        // All share host web01 → 3 forward edges (1-2, 1-3, 2-3).
        assert_eq!(build.graph.edges.len(), 3);
        assert_eq!(
            build.graph.nodes[0].tactic.as_deref(),
            Some("credential-access")
        );
    }
}
