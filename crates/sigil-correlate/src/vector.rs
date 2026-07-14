//! Vector index for embedding nearest-neighbor search (DESIGN §7, §9.3).
//!
//! Behind the [`VectorStore`] trait so the backend can be swapped:
//! [`FlatVectorStore`] is exact cosine KNN over normalized vectors (default
//! for small corpora and the ground truth in tests); [`HnswVectorStore`] is
//! the embedded HNSW graph index (ADR-3) for approximate search at scale.
//! Qdrant remains the optional distributed backend.

/// A nearest-neighbor index over event embeddings.
pub trait VectorStore {
    /// Insert a vector under an id.
    fn add(&mut self, id: String, vector: Vec<f32>);
    /// Top-`k` neighbors as `(id, cosine_similarity)`, highest first.
    fn knn(&self, query: &[f32], k: usize) -> Vec<(String, f32)>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Exact cosine-KNN store. Assumes inserted vectors are L2-normalized, so
/// cosine similarity is just the dot product.
#[derive(Default)]
pub struct FlatVectorStore {
    items: Vec<(String, Vec<f32>)>,
}

impl FlatVectorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl VectorStore for FlatVectorStore {
    fn add(&mut self, id: String, vector: Vec<f32>) {
        self.items.push((id, vector));
    }

    fn knn(&self, query: &[f32], k: usize) -> Vec<(String, f32)> {
        let mut scored: Vec<(String, f32)> = self
            .items
            .iter()
            .map(|(id, v)| (id.clone(), dot(query, v)))
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.truncate(k);
        scored
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Embedded HNSW index ([Malkov & Yashunin 2016]): a layered
/// small-world graph giving approximate KNN in roughly logarithmic time.
/// Vectors are assumed L2-normalized (cosine similarity = dot product),
/// matching [`FlatVectorStore`]. Construction is deterministic — layer
/// assignment hashes the insertion counter, so runs are reproducible.
///
/// [Malkov & Yashunin 2016]: https://arxiv.org/abs/1603.09320
pub struct HnswVectorStore {
    /// Max neighbors per node per upper layer (layer 0 allows `2*m`).
    m: usize,
    /// Candidate-list width during construction.
    ef_construction: usize,
    /// Candidate-list width during search (raised to `k` if smaller).
    ef_search: usize,
    nodes: Vec<HnswNode>,
    /// Entry node index (highest-layered node), if any.
    entry: Option<usize>,
}

struct HnswNode {
    id: String,
    vector: Vec<f32>,
    /// `neighbors[layer]` = indices of connected nodes at that layer.
    neighbors: Vec<Vec<usize>>,
}

impl Default for HnswVectorStore {
    fn default() -> Self {
        HnswVectorStore::new(16, 100, 64)
    }
}

impl HnswVectorStore {
    pub fn new(m: usize, ef_construction: usize, ef_search: usize) -> Self {
        HnswVectorStore {
            m: m.max(2),
            ef_construction: ef_construction.max(m),
            ef_search: ef_search.max(1),
            nodes: Vec::new(),
            entry: None,
        }
    }

    /// Deterministic layer for the `n`-th insert: geometric distribution with
    /// p = 1/e, sampled from a splitmix64 hash of the counter.
    fn assign_layer(&self, n: u64) -> usize {
        let mut x = n.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^= x >> 31;
        let unit = (x >> 11) as f64 / (1u64 << 53) as f64; // uniform in [0,1)
        let ml = 1.0 / (self.m as f64).ln();
        (-(unit.max(f64::MIN_POSITIVE)).ln() * ml).floor() as usize
    }

    fn max_neighbors(&self, layer: usize) -> usize {
        if layer == 0 {
            self.m * 2
        } else {
            self.m
        }
    }

    /// Greedy walk on `layer` toward `query`, starting at `ep`.
    fn greedy_step(&self, query: &[f32], mut ep: usize, layer: usize) -> usize {
        let mut best = dot(query, &self.nodes[ep].vector);
        loop {
            let mut improved = false;
            for &n in &self.nodes[ep].neighbors[layer] {
                let sim = dot(query, &self.nodes[n].vector);
                if sim > best {
                    best = sim;
                    ep = n;
                    improved = true;
                }
            }
            if !improved {
                return ep;
            }
        }
    }

    /// Beam search on `layer`: the `ef` most similar nodes reachable from `ep`,
    /// best first.
    fn search_layer(&self, query: &[f32], ep: usize, ef: usize, layer: usize) -> Vec<(usize, f32)> {
        let mut visited = vec![false; self.nodes.len()];
        visited[ep] = true;
        let ep_sim = dot(query, &self.nodes[ep].vector);
        // Candidates to expand (best first) and current result set.
        let mut candidates = vec![(ep, ep_sim)];
        let mut results = vec![(ep, ep_sim)];
        while let Some(pos) = candidates
            .iter()
            .enumerate()
            .max_by(|a, b| a.1 .1.total_cmp(&b.1 .1))
            .map(|(i, _)| i)
        {
            let (node, sim) = candidates.swap_remove(pos);
            let worst = results.iter().map(|r| r.1).fold(f32::INFINITY, f32::min);
            if results.len() >= ef && sim < worst {
                break; // no candidate can improve the result set
            }
            for &n in &self.nodes[node].neighbors[layer] {
                if std::mem::replace(&mut visited[n], true) {
                    continue;
                }
                let n_sim = dot(query, &self.nodes[n].vector);
                let worst = results.iter().map(|r| r.1).fold(f32::INFINITY, f32::min);
                if results.len() < ef || n_sim > worst {
                    candidates.push((n, n_sim));
                    results.push((n, n_sim));
                    if results.len() > ef {
                        // Drop the current worst.
                        let worst_pos = results
                            .iter()
                            .enumerate()
                            .min_by(|a, b| a.1 .1.total_cmp(&b.1 .1))
                            .map(|(i, _)| i)
                            .unwrap();
                        results.swap_remove(worst_pos);
                    }
                }
            }
        }
        results.sort_by(|a, b| b.1.total_cmp(&a.1));
        results
    }

    /// Connect `node` to `targets` on `layer`, pruning both sides to capacity
    /// (keep the most similar neighbors — the simple heuristic from the paper).
    fn connect(&mut self, node: usize, targets: &[usize], layer: usize) {
        let cap = self.max_neighbors(layer);
        self.nodes[node].neighbors[layer].extend_from_slice(targets);
        self.prune(node, layer, cap);
        for &t in targets {
            self.nodes[t].neighbors[layer].push(node);
            self.prune(t, layer, cap);
        }
    }

    fn prune(&mut self, node: usize, layer: usize, cap: usize) {
        if self.nodes[node].neighbors[layer].len() <= cap {
            return;
        }
        let anchor = self.nodes[node].vector.clone();
        let mut scored: Vec<(usize, f32)> = self.nodes[node].neighbors[layer]
            .iter()
            .map(|&n| (n, dot(&anchor, &self.nodes[n].vector)))
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.truncate(cap);
        scored.dedup_by_key(|s| s.0);
        self.nodes[node].neighbors[layer] = scored.into_iter().map(|s| s.0).collect();
    }
}

impl VectorStore for HnswVectorStore {
    fn add(&mut self, id: String, vector: Vec<f32>) {
        let layer = self.assign_layer(self.nodes.len() as u64);
        let idx = self.nodes.len();
        self.nodes.push(HnswNode {
            id,
            vector,
            neighbors: vec![Vec::new(); layer + 1],
        });
        let Some(entry) = self.entry else {
            self.entry = Some(idx);
            return;
        };

        let query = self.nodes[idx].vector.clone();
        let top = self.nodes[entry].neighbors.len() - 1;
        let mut ep = entry;
        // Descend greedily through layers above the new node's top layer.
        for l in (layer + 1..=top).rev() {
            ep = self.greedy_step(&query, ep, l);
        }
        // Insert into every layer the node participates in.
        for l in (0..=layer.min(top)).rev() {
            let found = self.search_layer(&query, ep, self.ef_construction, l);
            ep = found[0].0;
            let m = self.max_neighbors(l).min(found.len());
            let targets: Vec<usize> = found.iter().take(m).map(|f| f.0).collect();
            self.connect(idx, &targets, l);
        }
        // A node above the current top layer becomes the new entry point.
        if layer > top {
            self.entry = Some(idx);
        }
    }

    fn knn(&self, query: &[f32], k: usize) -> Vec<(String, f32)> {
        let Some(entry) = self.entry else {
            return Vec::new();
        };
        let mut ep = entry;
        for l in (1..self.nodes[entry].neighbors.len()).rev() {
            ep = self.greedy_step(query, ep, l);
        }
        let ef = self.ef_search.max(k);
        self.search_layer(query, ep, ef, 0)
            .into_iter()
            .take(k)
            .map(|(n, sim)| (self.nodes[n].id.clone(), sim))
            .collect()
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knn_orders_by_similarity() {
        let mut s = FlatVectorStore::new();
        s.add("a".into(), vec![1.0, 0.0]);
        s.add("b".into(), vec![0.0, 1.0]);
        s.add("c".into(), vec![0.6, 0.8]); // unit vector, closer to query than "b"
        let hits = s.knn(&[1.0, 0.0], 2);
        assert_eq!(hits[0].0, "a");
        assert_eq!(hits[1].0, "c"); // closer than "b"
        assert_eq!(s.len(), 3);
    }

    /// Deterministic pseudo-random unit vector (splitmix64-driven).
    fn unit_vector(seed: u64, dim: usize) -> Vec<f32> {
        let mut x = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut v: Vec<f32> = (0..dim)
            .map(|_| {
                x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                ((x >> 11) as f64 / (1u64 << 53) as f64 - 0.5) as f32
            })
            .collect();
        let norm = v.iter().map(|a| a * a).sum::<f32>().sqrt().max(1e-9);
        v.iter_mut().for_each(|a| *a /= norm);
        v
    }

    #[test]
    fn hnsw_small_store_matches_exact_knn() {
        let mut hnsw = HnswVectorStore::default();
        let mut flat = FlatVectorStore::new();
        for i in 0..20u64 {
            let v = unit_vector(i, 8);
            hnsw.add(format!("e{i}"), v.clone());
            flat.add(format!("e{i}"), v);
        }
        let q = unit_vector(7, 8);
        // With len < ef_search the beam covers everything: results are exact.
        assert_eq!(hnsw.knn(&q, 5), flat.knn(&q, 5));
    }

    #[test]
    fn hnsw_recall_at_10_is_high() {
        let dim = 16;
        let n = 500u64;
        let mut hnsw = HnswVectorStore::default();
        let mut flat = FlatVectorStore::new();
        for i in 0..n {
            let v = unit_vector(i, dim);
            hnsw.add(format!("e{i}"), v.clone());
            flat.add(format!("e{i}"), v);
        }
        let mut hits = 0;
        let mut total = 0;
        for q in 0..20u64 {
            let query = unit_vector(1_000_000 + q, dim);
            let truth: Vec<String> = flat.knn(&query, 10).into_iter().map(|h| h.0).collect();
            let approx: Vec<String> = hnsw.knn(&query, 10).into_iter().map(|h| h.0).collect();
            hits += truth.iter().filter(|t| approx.contains(t)).count();
            total += truth.len();
        }
        let recall = hits as f64 / total as f64;
        assert!(recall >= 0.9, "HNSW recall@10 too low: {recall:.3}");
    }

    #[test]
    fn hnsw_empty_and_single() {
        let mut s = HnswVectorStore::default();
        assert!(s.knn(&[1.0, 0.0], 3).is_empty());
        assert!(s.is_empty());
        s.add("only".into(), vec![1.0, 0.0]);
        let hits = s.knn(&[1.0, 0.0], 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "only");
    }
}
