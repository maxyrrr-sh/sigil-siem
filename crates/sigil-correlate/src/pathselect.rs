//! Default chain assembly (DESIGN §9.5, §19 ADR-5): beam search over the
//! causal graph to find the highest-scoring time-ordered path — the
//! reconstructed kill-chain. Implements the [`PathSelector`] trait; the
//! optional `sigil-correlate-rl` crate provides a GRAIN-style alternative.

use sigil_core::{AttackChain, CausalGraph, PathSelector, Plugin, PluginManifest};

/// Beam-search path selector. `beam_width` caps the partial paths kept.
pub struct BeamSearchSelector {
    manifest: PluginManifest,
    beam_width: usize,
}

impl BeamSearchSelector {
    pub fn new(beam_width: usize) -> Self {
        BeamSearchSelector {
            manifest: PluginManifest {
                name: "beam-search".into(),
                version: "0.0.0".into(),
                capabilities: vec![],
            },
            beam_width: beam_width.max(1),
        }
    }
}

impl Default for BeamSearchSelector {
    fn default() -> Self {
        BeamSearchSelector::new(4)
    }
}

impl Plugin for BeamSearchSelector {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl PathSelector for BeamSearchSelector {
    fn select(&self, graph: &CausalGraph) -> AttackChain {
        beam_search(graph, self.beam_width)
    }
}

/// A path's score weights edge causal scores plus a small node-anomaly bonus,
/// so anomalous, well-linked, longer chains win.
fn node_bonus(graph: &CausalGraph, node: usize) -> f32 {
    graph.nodes[node].anomaly * 0.1
}

fn beam_search(graph: &CausalGraph, width: usize) -> AttackChain {
    if graph.is_empty() {
        return AttackChain::default();
    }
    // Each beam entry: (path, score).
    let mut beam: Vec<(Vec<usize>, f32)> = (0..graph.len())
        .map(|i| (vec![i], node_bonus(graph, i)))
        .collect();
    let mut best = beam
        .iter()
        .cloned()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap_or((vec![0], 0.0));

    loop {
        let mut candidates: Vec<(Vec<usize>, f32)> = Vec::new();
        for (path, score) in &beam {
            let last = *path.last().unwrap();
            for edge in graph.outgoing(last) {
                if path.contains(&edge.to) {
                    continue;
                }
                let mut np = path.clone();
                np.push(edge.to);
                let ns = score + edge.score + node_bonus(graph, edge.to);
                candidates.push((np, ns));
            }
        }
        if candidates.is_empty() {
            break;
        }
        for c in &candidates {
            if c.1 > best.1 {
                best = c.clone();
            }
        }
        candidates.sort_by(|a, b| b.1.total_cmp(&a.1));
        candidates.truncate(width);
        beam = candidates;
    }

    AttackChain {
        path: best.0,
        score: best.1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{CausalEdge, CausalNode};

    fn node(id: &str, anomaly: f32) -> CausalNode {
        CausalNode {
            event_id: id.into(),
            anomaly,
            ..Default::default()
        }
    }

    #[test]
    fn finds_heaviest_chain() {
        // 0→1→2 chain plus a weak shortcut 0→2.
        let graph = CausalGraph {
            nodes: vec![node("a", 0.5), node("b", 0.5), node("c", 0.9)],
            edges: vec![
                CausalEdge {
                    from: 0,
                    to: 1,
                    score: 0.8,
                },
                CausalEdge {
                    from: 1,
                    to: 2,
                    score: 0.8,
                },
                CausalEdge {
                    from: 0,
                    to: 2,
                    score: 0.2,
                },
            ],
        };
        let chain = BeamSearchSelector::default().select(&graph);
        assert_eq!(chain.path, vec![0, 1, 2]); // full chain beats the shortcut
    }

    #[test]
    fn empty_graph_yields_empty_chain() {
        let chain = BeamSearchSelector::default().select(&CausalGraph::default());
        assert!(chain.path.is_empty());
    }
}
