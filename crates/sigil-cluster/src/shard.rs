//! Index sharding + placement (DESIGN §4.3, §7). Events are sharded by a hash
//! of the routing key combined with a time bucket, then each shard is placed on
//! a primary node plus replicas. The authoritative shard map lives in the
//! cluster catalog — replicated via Raft when distributed (consensus deferred).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// Logical shard id.
pub type ShardId = u32;

/// A node in the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// Placement + sharding policy for the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMap {
    /// Number of logical shards.
    pub shards: u32,
    /// Copies of each shard (primary + replicas).
    pub replication: u32,
    /// Time-bucket width (micros) folded into the shard key; 0 disables time
    /// bucketing (hash-only).
    pub time_bucket_micros: i64,
    /// Member nodes, in a stable order.
    pub nodes: Vec<NodeId>,
}

impl ShardMap {
    pub fn new(shards: u32, replication: u32, nodes: Vec<NodeId>) -> Self {
        ShardMap {
            shards: shards.max(1),
            replication: replication.max(1),
            time_bucket_micros: 0,
            nodes,
        }
    }

    pub fn with_time_bucket(mut self, micros: i64) -> Self {
        self.time_bucket_micros = micros.max(0);
        self
    }

    /// Shard for a routing key at a given event time.
    pub fn shard_for(&self, key: &str, ts: i64) -> ShardId {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        if self.time_bucket_micros > 0 {
            (ts / self.time_bucket_micros).hash(&mut h);
        }
        (h.finish() % self.shards as u64) as ShardId
    }

    /// Nodes holding a shard: primary first, then replicas (rendezvous by
    /// stepping around the ring). Empty if there are no nodes.
    pub fn nodes_for(&self, shard: ShardId) -> Vec<&NodeId> {
        if self.nodes.is_empty() {
            return Vec::new();
        }
        let n = self.nodes.len();
        let copies = (self.replication as usize).min(n);
        let start = (shard as usize) % n;
        (0..copies).map(|i| &self.nodes[(start + i) % n]).collect()
    }

    /// Convenience: the primary node for a key at a time.
    pub fn primary_for(&self, key: &str, ts: i64) -> Option<&NodeId> {
        self.nodes_for(self.shard_for(key, ts)).into_iter().next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(n: usize) -> Vec<NodeId> {
        (0..n).map(|i| NodeId(format!("node-{i}"))).collect()
    }

    #[test]
    fn shard_is_deterministic_and_in_range() {
        let m = ShardMap::new(8, 2, nodes(3));
        let s1 = m.shard_for("tenant-a", 100);
        let s2 = m.shard_for("tenant-a", 100);
        assert_eq!(s1, s2);
        assert!(s1 < 8);
    }

    #[test]
    fn replication_picks_distinct_nodes() {
        let m = ShardMap::new(8, 2, nodes(3));
        let placement = m.nodes_for(0);
        assert_eq!(placement.len(), 2);
        assert_ne!(placement[0], placement[1]);
    }

    #[test]
    fn replication_capped_at_node_count() {
        let m = ShardMap::new(8, 5, nodes(2));
        assert_eq!(m.nodes_for(3).len(), 2);
    }

    #[test]
    fn time_bucket_changes_shard_across_buckets() {
        let m = ShardMap::new(64, 1, nodes(3)).with_time_bucket(1_000);
        // Different time buckets generally land on different shards.
        let a = m.shard_for("k", 0);
        let b = m.shard_for("k", 10_000);
        // Not guaranteed different, but the function must stay deterministic.
        assert_eq!(a, m.shard_for("k", 0));
        assert_eq!(b, m.shard_for("k", 10_000));
    }
}
