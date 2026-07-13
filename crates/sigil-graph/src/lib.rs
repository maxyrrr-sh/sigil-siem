//! `sigil-graph` — provenance / causal graph store (DESIGN §9.4).
//!
//! Nodes are entities (process / file / user / host / ip / ...), edges are
//! events (with an action label and timestamp). Phase 3 builds the **local
//! provenance graph** plus the lookups correlation needs: which events touched
//! an entity (for shared-entity linking) and k-hop entity traversal. The graph
//! is in-memory (`petgraph`); a persistent RocksDB backing lands later.

use std::collections::{HashMap, HashSet};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use sigil_core::{EntityRef, Event};

/// A node: one entity in the provenance graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityNode {
    pub kind: String,
    pub id: String,
}

/// An edge: an event linking two entities, with action + time.
#[derive(Debug, Clone)]
pub struct EventEdge {
    pub event_id: String,
    pub action: String,
    pub ts: i64,
}

/// A reference to an event that touched an entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRef {
    pub event_id: String,
    pub ts: i64,
}

/// The provenance graph and its entity/event indices.
#[derive(Default)]
pub struct ProvenanceGraph {
    graph: DiGraph<EntityNode, EventEdge>,
    /// entity key (`kind:id`) → node index.
    index: HashMap<String, NodeIndex>,
    /// entity key → events that touched it (for shared-entity linking).
    entity_events: HashMap<String, Vec<EventRef>>,
}

/// Canonical key for an entity.
pub fn entity_key(e: &EntityRef) -> String {
    format!("{}:{}", e.kind, e.id)
}

impl ProvenanceGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    fn node_for(&mut self, e: &EntityRef) -> NodeIndex {
        let key = entity_key(e);
        if let Some(&idx) = self.index.get(&key) {
            return idx;
        }
        let idx = self.graph.add_node(EntityNode {
            kind: e.kind.clone(),
            id: e.id.clone(),
        });
        self.index.insert(key, idx);
        idx
    }

    /// Add an event: create nodes for its entities, chain edges along
    /// host → actor → target, and record the event on each touched entity.
    pub fn add_event(&mut self, event: &Event) {
        let action = action_for(event);
        let chain: Vec<EntityRef> = [&event.host, &event.actor, &event.target]
            .into_iter()
            .flatten()
            .cloned()
            .collect();

        for e in &chain {
            let key = entity_key(e);
            self.node_for(e);
            self.entity_events.entry(key).or_default().push(EventRef {
                event_id: event.id.clone(),
                ts: event.ts,
            });
        }

        for pair in chain.windows(2) {
            let a = self.node_for(&pair[0]);
            let b = self.node_for(&pair[1]);
            self.graph.add_edge(
                a,
                b,
                EventEdge {
                    event_id: event.id.clone(),
                    action: action.clone(),
                    ts: event.ts,
                },
            );
        }
    }

    /// Events that touched the given entity.
    pub fn events_on(&self, e: &EntityRef) -> &[EventRef] {
        self.entity_events
            .get(&entity_key(e))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// All event ids that share at least one entity with `event` (excluding the
    /// event itself). A cheap shared-entity link signal.
    pub fn co_entity_events(&self, event: &Event) -> HashSet<String> {
        let mut out = HashSet::new();
        for e in [&event.host, &event.actor, &event.target]
            .into_iter()
            .flatten()
        {
            for r in self.events_on(e) {
                if r.event_id != event.id {
                    out.insert(r.event_id.clone());
                }
            }
        }
        out
    }

    /// Entity keys reachable within `hops` of the given entity (undirected
    /// BFS), excluding the start. Supports k-hop traversal (DESIGN §9.4).
    pub fn khop(&self, start: &EntityRef, hops: usize) -> HashSet<String> {
        let mut seen = HashSet::new();
        let Some(&start_idx) = self.index.get(&entity_key(start)) else {
            return seen;
        };
        let mut frontier = vec![start_idx];
        for _ in 0..hops {
            let mut next = Vec::new();
            for node in frontier.drain(..) {
                let out = self.graph.edges(node).map(|e| e.target());
                let inc = self
                    .graph
                    .edges_directed(node, petgraph::Direction::Incoming)
                    .map(|e| e.source());
                for nb in out.chain(inc) {
                    let key = node_key(&self.graph[nb]);
                    if seen.insert(key) {
                        next.push(nb);
                    }
                }
            }
            frontier = next;
        }
        seen.remove(&node_key(&self.graph[start_idx]));
        seen
    }
}

fn node_key(n: &EntityNode) -> String {
    format!("{}:{}", n.kind, n.id)
}

/// A coarse action label derived from the event's OCSF class.
fn action_for(event: &Event) -> String {
    use sigil_core::OcsfClass::*;
    match event.ocsf_class {
        Authentication => "authenticate",
        ProcessActivity => "execute",
        FileSystemActivity => "access",
        NetworkActivity => "connect",
        HttpActivity => "request",
        ApiActivity => "invoke",
        DnsActivity => "resolve",
        ModuleActivity => "load",
        ScheduledJobActivity => "schedule",
        RegistryKeyActivity => "modify",
        Other(_) => "event",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{EntityRef, OcsfClass};

    fn ev(
        id: &str,
        host: &str,
        actor: (&str, &str),
        target: Option<(&str, &str)>,
        ts: i64,
    ) -> Event {
        let mut e = Event::new("acme");
        e.id = id.into();
        e.ts = ts;
        e.host = Some(EntityRef::new("host", host));
        e.actor = Some(EntityRef::new(actor.0, actor.1));
        e.target = target.map(|(k, v)| EntityRef::new(k, v));
        e.ocsf_class = OcsfClass::ProcessActivity;
        e
    }

    #[test]
    fn builds_nodes_and_edges() {
        let mut g = ProvenanceGraph::new();
        g.add_event(&ev(
            "e1",
            "web01",
            ("process", "bash"),
            Some(("file", "/etc/shadow")),
            1,
        ));
        // entities: host web01, process bash, file /etc/shadow = 3 nodes
        assert_eq!(g.node_count(), 3);
        // chain edges host→process, process→file = 2 edges
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn shared_entity_links_events() {
        let mut g = ProvenanceGraph::new();
        g.add_event(&ev("e1", "web01", ("user", "root"), None, 1));
        let e2 = ev("e2", "web01", ("process", "nc"), Some(("ip", "9.9.9.9")), 2);
        g.add_event(&e2);
        // e2 shares host web01 with e1.
        let shared = g.co_entity_events(&e2);
        assert!(shared.contains("e1"));
    }

    #[test]
    fn khop_traverses_entities() {
        let mut g = ProvenanceGraph::new();
        g.add_event(&ev(
            "e1",
            "web01",
            ("process", "bash"),
            Some(("file", "/etc/shadow")),
            1,
        ));
        let one_hop = g.khop(&EntityRef::new("host", "web01"), 1);
        assert!(one_hop.contains("process:bash"));
        let two_hop = g.khop(&EntityRef::new("host", "web01"), 2);
        assert!(two_hop.contains("file:/etc/shadow"));
    }
}
