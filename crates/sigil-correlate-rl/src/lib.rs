//! `sigil-correlate-rl` — **optional** GRAIN-style RL path selection (DESIGN
//! §9.5, §19 ADR-5).
//!
//! Reconstructing the kill-chain is framed as sequential decision making: from
//! each starting event the agent picks the next causal edge that maximizes the
//! expected cumulative causal effect. This crate ships a deterministic,
//! value-guided greedy policy (Q ≈ edge score + γ·best-next) as a stand-in for a
//! trained RL agent; it implements the same [`PathSelector`] trait as the
//! default beam search so it is a drop-in research comparison.
//!
//! It is intentionally **not** in the workspace default members — enable it
//! explicitly with `cargo build -p sigil-correlate-rl`.

use sigil_core::{AttackChain, CausalGraph, PathSelector, Plugin, PluginManifest};

/// Discount applied to the one-step lookahead value.
const GAMMA: f32 = 0.5;

/// GRAIN-style RL path selector (value-guided greedy stand-in).
pub struct RlPathSelector {
    manifest: PluginManifest,
    gamma: f32,
}

impl RlPathSelector {
    pub fn new(gamma: f32) -> Self {
        RlPathSelector {
            manifest: PluginManifest {
                name: "rl-grain".into(),
                version: "0.0.0".into(),
                capabilities: vec![],
            },
            gamma,
        }
    }
}

impl Default for RlPathSelector {
    fn default() -> Self {
        RlPathSelector::new(GAMMA)
    }
}

impl Plugin for RlPathSelector {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl PathSelector for RlPathSelector {
    fn select(&self, graph: &CausalGraph) -> AttackChain {
        if graph.is_empty() {
            return AttackChain::default();
        }
        let mut best = AttackChain {
            path: vec![0],
            score: f32::MIN,
        };
        for start in 0..graph.len() {
            let chain = self.rollout(graph, start);
            if chain.score > best.score {
                best = chain;
            }
        }
        best
    }
}

impl RlPathSelector {
    /// Greedy episode from `start`, choosing the action with the highest
    /// Q ≈ immediate causal score + γ·(best next causal score).
    fn rollout(&self, graph: &CausalGraph, start: usize) -> AttackChain {
        let mut path = vec![start];
        let mut total = node_bonus(graph, start);
        let mut cur = start;
        loop {
            let mut best: Option<(usize, f32, f32)> = None; // (to, q, edge_score)
            for edge in graph.outgoing(cur) {
                if path.contains(&edge.to) {
                    continue;
                }
                let future = graph
                    .outgoing(edge.to)
                    .map(|e| e.score)
                    .fold(0.0f32, f32::max);
                let q = edge.score + self.gamma * future;
                if best.map(|b| q > b.1).unwrap_or(true) {
                    best = Some((edge.to, q, edge.score));
                }
            }
            match best {
                Some((to, _, edge_score)) => {
                    total += edge_score + node_bonus(graph, to);
                    cur = to;
                    path.push(cur);
                }
                None => break,
            }
        }
        AttackChain { path, score: total }
    }
}

fn node_bonus(graph: &CausalGraph, node: usize) -> f32 {
    graph.nodes[node].anomaly * 0.1
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
    fn rl_selects_full_chain_over_shortcut() {
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
        let chain = RlPathSelector::default().select(&graph);
        assert_eq!(chain.path, vec![0, 1, 2]);
    }

    #[test]
    fn empty_graph_is_handled() {
        assert!(RlPathSelector::default()
            .select(&CausalGraph::default())
            .path
            .is_empty());
    }
}
