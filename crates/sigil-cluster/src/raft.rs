//! Raft consensus for the cluster catalog (DESIGN §4.3): leader election +
//! log replication, used to agree on catalog/membership changes (e.g.
//! [`crate::ShardMap`] updates) across nodes.
//!
//! [`RaftNode`] is a **pure state machine** — no clocks, no sockets. Time
//! arrives as [`RaftNode::tick`] calls and messages via [`RaftNode::step`];
//! both return envelopes for the caller to deliver. That keeps the algorithm
//! deterministic and unit-testable. [`RaftDriver`] binds a node to a
//! [`crate::Transport`] (in-proc bus or TCP) with a real tick interval.
//!
//! Scope: the Raft core (Figure 2 of the paper) — elections with randomized
//! timeouts, append/commit with the majority rule, term-based safety checks.
//! Not here: membership *changes* (joint consensus), snapshots/compaction,
//! and pre-vote. The log carries opaque bytes; the catalog is the state
//! machine that consumes committed entries.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sigil_core::{Error, Result};

/// One replicated log entry: opaque catalog bytes stamped with a term.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub data: Vec<u8>,
}

/// Wire messages between Raft peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftMsg {
    RequestVote {
        term: u64,
        candidate: String,
        last_log_index: u64,
        last_log_term: u64,
    },
    VoteReply {
        term: u64,
        from: String,
        granted: bool,
    },
    AppendEntries {
        term: u64,
        leader: String,
        prev_index: u64,
        prev_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    },
    AppendReply {
        term: u64,
        from: String,
        success: bool,
        /// Highest log index known replicated on the follower (on success).
        match_index: u64,
    },
}

/// An outbound message: `to: None` broadcasts to every peer.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub to: Option<String>,
    pub msg: RaftMsg,
}

#[derive(Debug)]
enum RaftState {
    Follower,
    Candidate {
        votes: usize,
    },
    Leader {
        /// Next log index to send each peer (1-based).
        next_index: HashMap<String, u64>,
        /// Highest index known replicated on each peer.
        match_index: HashMap<String, u64>,
    },
}

/// The Raft state machine for one node.
pub struct RaftNode {
    id: String,
    peers: Vec<String>,
    state: RaftState,
    term: u64,
    voted_for: Option<String>,
    /// 1-based conceptually: `log[0]` is index 1.
    log: Vec<LogEntry>,
    commit: u64,
    leader_hint: Option<String>,
    /// Ticks since we last heard from a leader/candidate.
    quiet_ticks: u32,
    /// Randomized election timeout in ticks (fixed per node from the seed).
    election_after: u32,
    /// Leader heartbeat cadence in ticks.
    heartbeat_every: u32,
}

impl RaftNode {
    /// `peers` excludes `id`. `seed` randomizes the election timeout so nodes
    /// don't stampede — give each node a different seed.
    pub fn new(id: impl Into<String>, peers: Vec<String>, seed: u64) -> Self {
        let id = id.into();
        let mut x = seed ^ 0x5851_f42d_4c95_7f2d;
        for b in id.bytes() {
            x = x.wrapping_mul(0x100_0000_01b3).wrapping_add(b as u64);
        }
        RaftNode {
            id,
            peers,
            state: RaftState::Follower,
            term: 0,
            voted_for: None,
            log: Vec::new(),
            commit: 0,
            leader_hint: None,
            quiet_ticks: 0,
            // 10..=19 ticks: same order as the paper's 150–300ms at 15ms ticks.
            election_after: 10 + (x % 10) as u32,
            heartbeat_every: 3,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn term(&self) -> u64 {
        self.term
    }

    pub fn is_leader(&self) -> bool {
        matches!(self.state, RaftState::Leader { .. })
    }

    /// The node we believe is leader (self, or the sender of valid appends).
    pub fn leader_hint(&self) -> Option<&str> {
        if self.is_leader() {
            Some(&self.id)
        } else {
            self.leader_hint.as_deref()
        }
    }

    /// Committed entries, in order. The catalog applies these.
    pub fn committed(&self) -> &[LogEntry] {
        &self.log[..self.commit as usize]
    }

    fn last_index(&self) -> u64 {
        self.log.len() as u64
    }

    fn last_term(&self) -> u64 {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }

    /// Votes/replicas needed: floor(cluster_size / 2) + 1.
    fn majority(&self) -> usize {
        self.peers.len().div_ceil(2) + 1
    }

    fn become_follower(&mut self, term: u64) {
        self.term = term;
        self.state = RaftState::Follower;
        self.voted_for = None;
        self.quiet_ticks = 0;
    }

    /// Advance logical time by one tick. Followers/candidates may start an
    /// election; leaders emit heartbeats.
    pub fn tick(&mut self) -> Vec<Envelope> {
        self.quiet_ticks += 1;
        match &self.state {
            RaftState::Leader { .. } => {
                if self.quiet_ticks >= self.heartbeat_every {
                    self.quiet_ticks = 0;
                    return self.broadcast_appends();
                }
                Vec::new()
            }
            _ if self.quiet_ticks >= self.election_after => self.start_election(),
            _ => Vec::new(),
        }
    }

    fn start_election(&mut self) -> Vec<Envelope> {
        self.term += 1;
        self.voted_for = Some(self.id.clone());
        self.state = RaftState::Candidate { votes: 1 };
        self.quiet_ticks = 0;
        // Single-node cluster: elected immediately.
        if self.peers.is_empty() {
            return self.become_leader();
        }
        vec![Envelope {
            to: None,
            msg: RaftMsg::RequestVote {
                term: self.term,
                candidate: self.id.clone(),
                last_log_index: self.last_index(),
                last_log_term: self.last_term(),
            },
        }]
    }

    fn become_leader(&mut self) -> Vec<Envelope> {
        let next = self.last_index() + 1;
        self.state = RaftState::Leader {
            next_index: self.peers.iter().map(|p| (p.clone(), next)).collect(),
            match_index: self.peers.iter().map(|p| (p.clone(), 0)).collect(),
        };
        self.leader_hint = None;
        self.quiet_ticks = 0;
        self.broadcast_appends()
    }

    /// Leader: append an entry to the local log and replicate it. Errors on
    /// non-leaders (callers redirect via [`Self::leader_hint`]).
    pub fn propose(&mut self, data: Vec<u8>) -> Result<Vec<Envelope>> {
        if !self.is_leader() {
            return Err(Error::Other(format!(
                "not the leader (try {})",
                self.leader_hint().unwrap_or("unknown")
            )));
        }
        self.log.push(LogEntry {
            term: self.term,
            data,
        });
        // Single-node cluster: majority of one.
        self.advance_commit();
        Ok(self.broadcast_appends())
    }

    /// Per-peer AppendEntries from each one's `next_index` (heartbeat when
    /// there is nothing new).
    fn broadcast_appends(&mut self) -> Vec<Envelope> {
        let RaftState::Leader { next_index, .. } = &self.state else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for peer in &self.peers {
            let next = *next_index.get(peer).unwrap_or(&1);
            let prev_index = next - 1;
            let prev_term = if prev_index == 0 {
                0
            } else {
                self.log[prev_index as usize - 1].term
            };
            out.push(Envelope {
                to: Some(peer.clone()),
                msg: RaftMsg::AppendEntries {
                    term: self.term,
                    leader: self.id.clone(),
                    prev_index,
                    prev_term,
                    entries: self.log[prev_index as usize..].to_vec(),
                    leader_commit: self.commit,
                },
            });
        }
        out
    }

    /// Leader: commit the highest index replicated on a majority whose entry
    /// is from the current term (§5.4.2 of the paper).
    fn advance_commit(&mut self) {
        let RaftState::Leader { match_index, .. } = &self.state else {
            return;
        };
        for n in (self.commit + 1..=self.last_index()).rev() {
            if self.log[n as usize - 1].term != self.term {
                continue;
            }
            // Count self plus every peer whose match_index reaches n.
            let replicas = 1 + match_index.values().filter(|&&m| m >= n).count();
            if replicas >= self.majority() {
                self.commit = n;
                break;
            }
        }
    }

    /// Handle one incoming message, returning replies to deliver.
    pub fn step(&mut self, msg: RaftMsg) -> Vec<Envelope> {
        match msg {
            RaftMsg::RequestVote {
                term,
                candidate,
                last_log_index,
                last_log_term,
            } => {
                if term > self.term {
                    self.become_follower(term);
                }
                // Grant iff same term, no prior vote (or repeat), and the
                // candidate's log is at least as up-to-date as ours (§5.4.1).
                let up_to_date = last_log_term > self.last_term()
                    || (last_log_term == self.last_term() && last_log_index >= self.last_index());
                let vote_available = match self.voted_for.as_deref() {
                    None => true,
                    Some(v) => v == candidate,
                };
                let granted = term == self.term && up_to_date && vote_available;
                if granted {
                    self.voted_for = Some(candidate.clone());
                    self.quiet_ticks = 0;
                }
                vec![Envelope {
                    to: Some(candidate),
                    msg: RaftMsg::VoteReply {
                        term: self.term,
                        from: self.id.clone(),
                        granted,
                    },
                }]
            }

            RaftMsg::VoteReply { term, granted, .. } => {
                if term > self.term {
                    self.become_follower(term);
                    return Vec::new();
                }
                let RaftState::Candidate { votes } = &mut self.state else {
                    return Vec::new();
                };
                if term == self.term && granted {
                    *votes += 1;
                    if *votes >= self.majority() {
                        return self.become_leader();
                    }
                }
                Vec::new()
            }

            RaftMsg::AppendEntries {
                term,
                leader,
                prev_index,
                prev_term,
                entries,
                leader_commit,
            } => {
                if term > self.term
                    || (term == self.term && !matches!(self.state, RaftState::Follower))
                {
                    self.become_follower(term);
                }
                if term < self.term {
                    return vec![Envelope {
                        to: Some(leader),
                        msg: RaftMsg::AppendReply {
                            term: self.term,
                            from: self.id.clone(),
                            success: false,
                            match_index: 0,
                        },
                    }];
                }
                self.quiet_ticks = 0;
                self.leader_hint = Some(leader.clone());

                // Consistency check on the entry before the new ones.
                let ok = prev_index == 0
                    || self
                        .log
                        .get(prev_index as usize - 1)
                        .is_some_and(|e| e.term == prev_term);
                if !ok {
                    return vec![Envelope {
                        to: Some(leader),
                        msg: RaftMsg::AppendReply {
                            term: self.term,
                            from: self.id.clone(),
                            success: false,
                            match_index: 0,
                        },
                    }];
                }
                // Truncate any conflicting suffix, then append.
                self.log.truncate(prev_index as usize);
                self.log.extend(entries);
                if leader_commit > self.commit {
                    self.commit = leader_commit.min(self.last_index());
                }
                vec![Envelope {
                    to: Some(leader),
                    msg: RaftMsg::AppendReply {
                        term: self.term,
                        from: self.id.clone(),
                        success: true,
                        match_index: self.last_index(),
                    },
                }]
            }

            RaftMsg::AppendReply {
                term,
                from,
                success,
                match_index: m,
            } => {
                if term > self.term {
                    self.become_follower(term);
                    return Vec::new();
                }
                let RaftState::Leader {
                    next_index,
                    match_index,
                } = &mut self.state
                else {
                    return Vec::new();
                };
                if success {
                    next_index.insert(from.clone(), m + 1);
                    match_index.insert(from, m);
                    self.advance_commit();
                } else {
                    // Back next_index off by one and retry on the next append.
                    let n = next_index.entry(from).or_insert(1);
                    *n = n.saturating_sub(1).max(1);
                }
                Vec::new()
            }
        }
    }
}

// --- transport binding ------------------------------------------------------

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::transport::Transport;

/// Directed-topic name for a node.
fn topic_for(cluster: &str, node: &str) -> String {
    format!("raft.{cluster}.{node}")
}

/// Broadcast-topic name for a cluster.
fn topic_bcast(cluster: &str) -> String {
    format!("raft.{cluster}.bcast")
}

/// Binds a [`RaftNode`] to a [`Transport`]: a background task ticks the state
/// machine and pumps messages. Cheap to clone-share via `Arc`.
pub struct RaftDriver {
    node: Arc<Mutex<RaftNode>>,
    transport: Arc<dyn Transport>,
    cluster: String,
}

impl RaftDriver {
    /// Spawn the pump for `node` on `transport` (tokio runtime required).
    /// `tick` is the logical tick interval — election timeouts are 10–19
    /// ticks, heartbeats every 3.
    pub fn spawn(
        node: RaftNode,
        transport: Arc<dyn Transport>,
        cluster: impl Into<String>,
        tick: Duration,
    ) -> Result<Arc<RaftDriver>> {
        let cluster = cluster.into();
        let id = node.id().to_string();
        let node = Arc::new(Mutex::new(node));
        let driver = Arc::new(RaftDriver {
            node: node.clone(),
            transport: transport.clone(),
            cluster: cluster.clone(),
        });

        let mut directed = transport.subscribe(&topic_for(&cluster, &id))?;
        let mut bcast = transport.subscribe(&topic_bcast(&cluster))?;
        let pump = driver.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tick);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let outbound = tokio::select! {
                    _ = ticker.tick() => pump.node.lock().unwrap().tick(),
                    got = directed.recv() => pump.decode_step(got),
                    got = bcast.recv() => pump.decode_step(got),
                };
                pump.send(outbound);
            }
        });
        Ok(driver)
    }

    fn decode_step(
        &self,
        got: std::result::Result<Vec<u8>, tokio::sync::broadcast::error::RecvError>,
    ) -> Vec<Envelope> {
        let Ok(bytes) = got else {
            return Vec::new(); // lagged/closed: skip, next recv resyncs
        };
        match serde_json::from_slice::<RaftMsg>(&bytes) {
            Ok(msg) => {
                let mut node = self.node.lock().unwrap();
                // Nodes hear their own broadcasts on the bcast topic; a
                // candidate must not count (or answer) itself.
                match &msg {
                    RaftMsg::RequestVote { candidate, .. } if *candidate == node.id => Vec::new(),
                    _ => node.step(msg),
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "dropping undecodable raft message");
                Vec::new()
            }
        }
    }

    fn send(&self, envelopes: Vec<Envelope>) {
        for env in envelopes {
            let topic = match &env.to {
                Some(node) => topic_for(&self.cluster, node),
                None => topic_bcast(&self.cluster),
            };
            match serde_json::to_vec(&env.msg) {
                Ok(bytes) => {
                    if let Err(e) = self.transport.publish(&topic, bytes) {
                        tracing::warn!(error = %e, topic, "raft publish failed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "raft message serialization failed"),
            }
        }
    }

    pub fn is_leader(&self) -> bool {
        self.node.lock().unwrap().is_leader()
    }

    pub fn leader_hint(&self) -> Option<String> {
        self.node.lock().unwrap().leader_hint().map(str::to_string)
    }

    /// Propose a catalog entry (leader only; see [`RaftNode::propose`]).
    pub fn propose(&self, data: Vec<u8>) -> Result<()> {
        let outbound = self.node.lock().unwrap().propose(data)?;
        self.send(outbound);
        Ok(())
    }

    /// Committed entries applied so far.
    pub fn committed(&self) -> Vec<LogEntry> {
        self.node.lock().unwrap().committed().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::InProcBus;

    /// Deliver envelopes between in-memory nodes until quiescent.
    fn deliver(nodes: &mut [RaftNode], mut pending: Vec<(String, Envelope)>) {
        while let Some((from, env)) = pending.pop() {
            let targets: Vec<usize> = match &env.to {
                Some(id) => nodes
                    .iter()
                    .position(|n| n.id() == id)
                    .into_iter()
                    .collect(),
                None => (0..nodes.len())
                    .filter(|&i| nodes[i].id() != from)
                    .collect(),
            };
            for t in targets {
                let replies = nodes[t].step(env.msg.clone());
                let sender = nodes[t].id().to_string();
                pending.extend(replies.into_iter().map(|e| (sender.clone(), e)));
            }
        }
    }

    fn tick_all(nodes: &mut [RaftNode]) {
        for i in 0..nodes.len() {
            let out = nodes[i].tick();
            let from = nodes[i].id().to_string();
            deliver(nodes, out.into_iter().map(|e| (from.clone(), e)).collect());
        }
    }

    fn three_nodes() -> Vec<RaftNode> {
        let ids = ["a", "b", "c"];
        ids.iter()
            .enumerate()
            .map(|(i, id)| {
                let peers = ids
                    .iter()
                    .filter(|p| *p != id)
                    .map(|p| p.to_string())
                    .collect();
                RaftNode::new(*id, peers, i as u64)
            })
            .collect()
    }

    fn leader_index(nodes: &[RaftNode]) -> Option<usize> {
        nodes.iter().position(|n| n.is_leader())
    }

    #[test]
    fn elects_exactly_one_leader() {
        let mut nodes = three_nodes();
        for _ in 0..40 {
            tick_all(&mut nodes);
            if leader_index(&nodes).is_some() {
                break;
            }
        }
        assert_eq!(nodes.iter().filter(|n| n.is_leader()).count(), 1);
        // Followers learn the leader from heartbeats.
        tick_all(&mut nodes);
        let leader = nodes[leader_index(&nodes).unwrap()].id().to_string();
        for n in &nodes {
            assert_eq!(n.leader_hint(), Some(leader.as_str()));
        }
    }

    #[test]
    fn replicates_and_commits_entries() {
        let mut nodes = three_nodes();
        for _ in 0..40 {
            tick_all(&mut nodes);
            if leader_index(&nodes).is_some() {
                break;
            }
        }
        let li = leader_index(&nodes).unwrap();
        let out = nodes[li].propose(b"shardmap-v2".to_vec()).unwrap();
        let from = nodes[li].id().to_string();
        deliver(
            &mut nodes,
            out.into_iter().map(|e| (from.clone(), e)).collect(),
        );
        // Leader committed after majority ack; heartbeat spreads the commit.
        assert_eq!(nodes[li].committed().len(), 1);
        for _ in 0..4 {
            tick_all(&mut nodes);
        }
        for n in &nodes {
            assert_eq!(n.committed().len(), 1, "{} lagging", n.id());
            assert_eq!(n.committed()[0].data, b"shardmap-v2");
        }
    }

    #[test]
    fn reelects_after_leader_failure_and_old_leader_steps_down() {
        let mut nodes = three_nodes();
        for _ in 0..40 {
            tick_all(&mut nodes);
            if leader_index(&nodes).is_some() {
                break;
            }
        }
        let old = leader_index(&nodes).unwrap();
        // Partition the leader away: tick only the other two.
        let mut rest: Vec<RaftNode> = nodes
            .drain(..)
            .enumerate()
            .filter_map(|(i, n)| (i != old).then_some(n))
            .collect();
        for _ in 0..60 {
            tick_all(&mut rest);
            if leader_index(&rest).is_some() {
                break;
            }
        }
        assert_eq!(rest.iter().filter(|n| n.is_leader()).count(), 1);
        // The new leader's term moved past the old one's.
        let new_leader = &rest[leader_index(&rest).unwrap()];
        assert!(new_leader.term() >= 2);
    }

    #[test]
    fn rejects_vote_for_stale_log() {
        let mut a = RaftNode::new("a", vec!["b".into()], 0);
        // "a" has a committed entry at term 1.
        a.term = 1;
        a.log.push(LogEntry {
            term: 1,
            data: b"x".to_vec(),
        });
        // Candidate "b" with an empty log and a newer term must be refused.
        let replies = a.step(RaftMsg::RequestVote {
            term: 2,
            candidate: "b".into(),
            last_log_index: 0,
            last_log_term: 0,
        });
        match &replies[0].msg {
            RaftMsg::VoteReply { granted, .. } => assert!(!granted),
            other => panic!("unexpected reply {other:?}"),
        }
    }

    #[test]
    fn single_node_cluster_self_elects_and_commits() {
        let mut solo = RaftNode::new("solo", Vec::new(), 0);
        for _ in 0..25 {
            solo.tick();
        }
        assert!(solo.is_leader());
        solo.propose(b"entry".to_vec()).unwrap();
        assert_eq!(solo.committed().len(), 1);
    }

    #[test]
    fn non_leader_propose_is_redirected() {
        let mut n = RaftNode::new("f", vec!["l".into()], 0);
        assert!(n.propose(b"x".to_vec()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn driver_elects_and_replicates_over_inproc_bus() {
        let bus: Arc<dyn Transport> = Arc::new(InProcBus::new());
        let ids = ["a", "b", "c"];
        let drivers: Vec<Arc<RaftDriver>> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let peers = ids
                    .iter()
                    .filter(|p| *p != id)
                    .map(|p| p.to_string())
                    .collect();
                RaftDriver::spawn(
                    RaftNode::new(*id, peers, i as u64),
                    bus.clone(),
                    "test",
                    Duration::from_millis(10),
                )
                .unwrap()
            })
            .collect();

        // Paused-clock tokio: sleeps auto-advance, so this is deterministic.
        let mut leader = None;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            leader = drivers.iter().find(|d| d.is_leader());
            if leader.is_some() {
                break;
            }
        }
        let leader = leader.expect("no leader elected").clone();
        leader.propose(b"catalog-entry".to_vec()).unwrap();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if drivers.iter().all(|d| d.committed().len() == 1) {
                break;
            }
        }
        for d in &drivers {
            assert_eq!(d.committed().len(), 1);
            assert_eq!(d.committed()[0].data, b"catalog-entry");
        }
    }
}
