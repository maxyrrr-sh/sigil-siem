//! Vector index for embedding nearest-neighbor search (DESIGN §7, §9.3).
//!
//! Behind the [`VectorStore`] trait so the backend can be swapped. Phase 3
//! ships [`FlatVectorStore`] (exact cosine KNN over normalized vectors). The
//! production swap is an embedded HNSW (`usearch`/`hnsw_rs`) for approximate
//! search at scale, and Qdrant as an optional distributed backend (ADR-3).

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
}
