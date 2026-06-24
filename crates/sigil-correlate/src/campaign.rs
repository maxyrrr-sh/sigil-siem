//! Cross-domain campaign-candidate generation (DESIGN §9.4–9.5, step 4).
//!
//! Cheap candidate generation in the Rust core: link events that are either
//! **semantically similar** (embedding KNN) or **share an entity** (provenance
//! graph), within a **time window**, then take connected components as campaign
//! candidates. The expensive GNN/causal scoring (Phase 4) refines these.

use std::collections::{BTreeSet, HashMap, HashSet};

use sigil_core::Event;
use sigil_graph::ProvenanceGraph;

use crate::embed::Embedder;
use crate::vector::{FlatVectorStore, VectorStore};

/// Tunables for candidate generation (DESIGN §9.4 `graph.window`).
#[derive(Debug, Clone)]
pub struct CampaignConfig {
    /// Max time gap (micros) between two linked events.
    pub window_micros: i64,
    /// Min cosine similarity for a semantic link.
    pub sim_threshold: f32,
    /// Neighbors considered per event for semantic linking.
    pub knn: usize,
    /// Keep only candidates spanning ≥2 OCSF classes (cross-domain).
    pub require_cross_domain: bool,
    /// Enable embedding (semantic) links. Ablation knob (±embeddings).
    pub semantic_links: bool,
    /// Enable shared-entity (provenance) links. Ablation knob.
    pub entity_links: bool,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        CampaignConfig {
            window_micros: 30 * 60 * 1_000_000, // 30 minutes
            sim_threshold: 0.5,
            knn: 10,
            require_cross_domain: true,
            semantic_links: true,
            entity_links: true,
        }
    }
}

/// A group of events that plausibly belong to one campaign.
#[derive(Debug, Clone)]
pub struct CampaignCandidate {
    pub id: usize,
    /// Member event ids, time-ordered.
    pub events: Vec<String>,
    /// Distinct OCSF class names spanned.
    pub domains: Vec<String>,
    /// Number of links holding the group together.
    pub links: usize,
    /// Heuristic confidence proxy (real scoring arrives with the GNN, Phase 4).
    pub score: f32,
}

/// Generate campaign candidates from a batch of events.
pub fn build_campaigns(
    events: &[Event],
    cfg: &CampaignConfig,
    embedder: &dyn Embedder,
) -> Vec<CampaignCandidate> {
    if events.is_empty() {
        return Vec::new();
    }
    let pos: HashMap<&str, usize> = events
        .iter()
        .enumerate()
        .map(|(i, e)| (e.id.as_str(), i))
        .collect();

    // Embeddings + vector index + provenance graph.
    let mut vectors: Vec<Vec<f32>> = Vec::with_capacity(events.len());
    let mut store = FlatVectorStore::new();
    let mut graph = ProvenanceGraph::new();
    for e in events {
        let v = embedder.embed_event(e);
        store.add(e.id.clone(), v.clone());
        vectors.push(v);
        graph.add_event(e);
    }

    // Collect candidate links as (min, max) → (best_sim, cross_domain).
    let mut links: HashMap<(usize, usize), (f32, bool)> = HashMap::new();
    let mut record = |a: usize, b: usize, sim: f32, events: &[Event]| {
        if a == b {
            return;
        }
        if (events[a].ts - events[b].ts).abs() > cfg.window_micros {
            return;
        }
        let key = if a < b { (a, b) } else { (b, a) };
        let cross = events[a].ocsf_class.uid() != events[b].ocsf_class.uid();
        let entry = links.entry(key).or_insert((f32::MIN, cross));
        if sim > entry.0 {
            entry.0 = sim;
        }
        entry.1 = cross;
    };

    // Semantic links: KNN neighbors above the threshold (±embeddings ablation).
    if cfg.semantic_links {
        for (i, vector) in vectors.iter().enumerate() {
            for (id_j, sim) in store.knn(vector, cfg.knn + 1) {
                if sim < cfg.sim_threshold {
                    continue;
                }
                if let Some(&j) = pos.get(id_j.as_str()) {
                    record(i, j, sim, events);
                }
            }
        }
    }

    // Shared-entity links from the provenance graph (±provenance ablation).
    if cfg.entity_links {
        for (i, e) in events.iter().enumerate() {
            for id_j in graph.co_entity_events(e) {
                if let Some(&j) = pos.get(id_j.as_str()) {
                    let sim = dot(&vectors[i], &vectors[j]);
                    record(i, j, sim, events);
                }
            }
        }
    }

    // Union linked events into connected components.
    let mut dsu = Dsu::new(events.len());
    for &(a, b) in links.keys() {
        dsu.union(a, b);
    }
    let mut comps: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..events.len() {
        comps.entry(dsu.find(i)).or_default().push(i);
    }

    // Build candidates from components of ≥2 events.
    let mut candidates = Vec::new();
    for members in comps.into_values() {
        if members.len() < 2 {
            continue;
        }
        let domains: BTreeSet<String> = members
            .iter()
            .map(|&i| class_token(&events[i]).to_string())
            .collect();
        if cfg.require_cross_domain && domains.len() < 2 {
            continue;
        }

        let member_set: HashSet<usize> = members.iter().copied().collect();
        let edge_sims: Vec<f32> = links
            .iter()
            .filter(|((a, b), _)| member_set.contains(a) && member_set.contains(b))
            .map(|(_, (sim, _))| *sim)
            .collect();
        let link_count = edge_sims.len();
        let avg_sim = if edge_sims.is_empty() {
            0.0
        } else {
            edge_sims.iter().sum::<f32>() / edge_sims.len() as f32
        };
        let score = domains.len() as f32 + (members.len() as f32 - 1.0) * 0.5 + avg_sim.max(0.0);

        let mut event_ids: Vec<(i64, String)> = members
            .iter()
            .map(|&i| (events[i].ts, events[i].id.clone()))
            .collect();
        event_ids.sort();

        candidates.push(CampaignCandidate {
            id: 0,
            events: event_ids.into_iter().map(|(_, id)| id).collect(),
            domains: domains.into_iter().collect(),
            links: link_count,
            score,
        });
    }

    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    for (i, c) in candidates.iter_mut().enumerate() {
        c.id = i;
    }
    candidates
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn class_token(event: &Event) -> &'static str {
    use sigil_core::OcsfClass::*;
    match event.ocsf_class {
        Authentication => "authentication",
        ProcessActivity => "process_activity",
        FileSystemActivity => "file_system_activity",
        NetworkActivity => "network_activity",
        HttpActivity => "http_activity",
        ApiActivity => "api_activity",
        Other(_) => "other",
    }
}

/// Disjoint-set union for component finding.
struct Dsu {
    parent: Vec<usize>,
}

impl Dsu {
    fn new(n: usize) -> Self {
        Dsu {
            parent: (0..n).collect(),
        }
    }
    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cur = x;
        while self.parent[cur] != root {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra] = rb;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::HashingEmbedder;
    use sigil_core::{EntityRef, OcsfClass};

    fn ev(id: &str, class: OcsfClass, host: &str, ts: i64) -> Event {
        let mut e = Event::new("acme");
        e.id = id.into();
        e.ts = ts;
        e.ocsf_class = class;
        e.host = Some(EntityRef::new("host", host));
        e
    }

    #[test]
    fn groups_cross_domain_events_sharing_a_host() {
        // A multi-stage scenario on web01 within a tight window, plus noise.
        let events = vec![
            ev("e1", OcsfClass::Authentication, "web01", 100),
            ev("e2", OcsfClass::ProcessActivity, "web01", 200),
            ev("e3", OcsfClass::NetworkActivity, "web01", 300),
            ev("e4", OcsfClass::HttpActivity, "db99", 10_000_000_000),
        ];
        // sim_threshold > 1 disables semantic links → pure shared-entity test.
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
        assert_eq!(cands[0].events, vec!["e1", "e2", "e3"]);
        assert_eq!(cands[0].domains.len(), 3);
    }

    #[test]
    fn far_apart_events_do_not_link() {
        let events = vec![
            ev("a", OcsfClass::Authentication, "h", 0),
            ev("b", OcsfClass::ProcessActivity, "h", 10_000_000_000),
        ];
        let cfg = CampaignConfig {
            window_micros: 1000,
            sim_threshold: 2.0,
            knn: 5,
            require_cross_domain: true,
            semantic_links: true,
            entity_links: true,
        };
        let cands = build_campaigns(&events, &cfg, &HashingEmbedder::default());
        assert!(cands.is_empty());
    }

    #[test]
    fn single_domain_filtered_when_required() {
        let events = vec![
            ev("a", OcsfClass::Authentication, "h", 0),
            ev("b", OcsfClass::Authentication, "h", 100),
        ];
        let cfg = CampaignConfig {
            window_micros: 1000,
            sim_threshold: 2.0,
            knn: 5,
            require_cross_domain: true,
            semantic_links: true,
            entity_links: true,
        };
        assert!(build_campaigns(&events, &cfg, &HashingEmbedder::default()).is_empty());
        let cfg2 = CampaignConfig {
            require_cross_domain: false,
            ..cfg
        };
        assert_eq!(
            build_campaigns(&events, &cfg2, &HashingEmbedder::default()).len(),
            1
        );
    }
}
