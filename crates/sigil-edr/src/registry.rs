//! Fleet registry: tracks enrolled agents (durable) and their live control
//! sessions (in-memory). Agent metadata persists as `sigil-store` saved objects
//! of kind `edr-agent`; the live `command_tx` and connection status live only in
//! memory (they don't survive a restart, and shouldn't).

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sigil_core::{now_micros, Result, Timestamp};
use sigil_edr_proto::pb;
use sigil_store::{SavedObject, Store};
use tokio::sync::mpsc;

/// Saved-object kind for durable agent records.
pub const AGENT_KIND: &str = "edr-agent";

/// Durable identity + last-known state of an enrolled agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub agent_version: String,
    pub fingerprint: String,
    /// Opaque bearer credential presented on `Connect`.
    pub session_token: String,
    pub enrolled_ts: Timestamp,
    #[serde(default)]
    pub last_seen: Timestamp,
    #[serde(default)]
    pub isolated: bool,
}

/// A read view of an agent for the API (durable record + live status).
#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub agent_version: String,
    pub enrolled_ts: Timestamp,
    pub last_seen: Timestamp,
    pub connected: bool,
    pub isolated: bool,
}

/// Live, in-memory session state for a connected agent.
struct LiveSession {
    command_tx: mpsc::Sender<pb::Command>,
    last_seen: Timestamp,
    isolated: bool,
}

/// The fleet registry. Cheap to share via `Arc`.
pub struct AgentRegistry {
    store: Arc<Store>,
    live: DashMap<String, LiveSession>,
}

impl AgentRegistry {
    pub fn new(store: Arc<Store>) -> Arc<AgentRegistry> {
        Arc::new(AgentRegistry {
            store,
            live: DashMap::new(),
        })
    }

    /// Persist a freshly enrolled agent, returning its record.
    pub fn enroll(&self, req: &pb::EnrollRequest, session_token: String) -> Result<AgentRecord> {
        let now = now_micros();
        let agent_id = ulid::Ulid::new().to_string();
        let rec = AgentRecord {
            agent_id: agent_id.clone(),
            hostname: req.hostname.clone(),
            os: req.os.clone(),
            os_version: req.os_version.clone(),
            agent_version: req.agent_version.clone(),
            fingerprint: req.fingerprint.clone(),
            session_token,
            enrolled_ts: now,
            last_seen: now,
            isolated: false,
        };
        self.persist(&rec)?;
        Ok(rec)
    }

    /// Validate a `Hello` credential against the stored record.
    pub fn validate_session(&self, agent_id: &str, token: &str) -> Result<bool> {
        Ok(self
            .record(agent_id)?
            .is_some_and(|r| !token.is_empty() && r.session_token == token))
    }

    /// Register a live control session, returning its outbound command receiver.
    pub fn connect(&self, agent_id: &str) -> mpsc::Receiver<pb::Command> {
        let (tx, rx) = mpsc::channel::<pb::Command>(64);
        let isolated = self.live.get(agent_id).map(|s| s.isolated).unwrap_or(false);
        self.live.insert(
            agent_id.to_string(),
            LiveSession {
                command_tx: tx,
                last_seen: now_micros(),
                isolated,
            },
        );
        rx
    }

    /// Tear down a live session (persisting last-seen/isolated on the way out).
    pub fn disconnect(&self, agent_id: &str) {
        if let Some((_, session)) = self.live.remove(agent_id) {
            if let Ok(Some(mut rec)) = self.record(agent_id) {
                rec.last_seen = session.last_seen;
                rec.isolated = session.isolated;
                let _ = self.persist(&rec);
            }
        }
    }

    /// Update live status from a heartbeat.
    pub fn heartbeat(&self, agent_id: &str, isolated: bool) {
        if let Some(mut s) = self.live.get_mut(agent_id) {
            s.last_seen = now_micros();
            s.isolated = isolated;
        }
    }

    /// The command sender for a connected agent, if any.
    pub fn command_sender(&self, agent_id: &str) -> Option<mpsc::Sender<pb::Command>> {
        self.live.get(agent_id).map(|s| s.command_tx.clone())
    }

    /// True if the agent currently holds a live control stream.
    pub fn is_connected(&self, agent_id: &str) -> bool {
        self.live.contains_key(agent_id)
    }

    /// All enrolled agents, newest-enrolled first.
    pub fn list(&self) -> Result<Vec<AgentView>> {
        let mut out: Vec<AgentView> = self
            .store
            .list_saved(AGENT_KIND)?
            .into_iter()
            .filter_map(|o| serde_json::from_value::<AgentRecord>(o.body).ok())
            .map(|r| self.view(r))
            .collect();
        out.sort_by_key(|v| std::cmp::Reverse(v.enrolled_ts));
        Ok(out)
    }

    /// One agent view by id.
    pub fn get(&self, agent_id: &str) -> Result<Option<AgentView>> {
        Ok(self.record(agent_id)?.map(|r| self.view(r)))
    }

    fn view(&self, rec: AgentRecord) -> AgentView {
        let live = self.live.get(&rec.agent_id);
        AgentView {
            connected: live.is_some(),
            last_seen: live.as_ref().map(|s| s.last_seen).unwrap_or(rec.last_seen),
            isolated: live.as_ref().map(|s| s.isolated).unwrap_or(rec.isolated),
            agent_id: rec.agent_id,
            hostname: rec.hostname,
            os: rec.os,
            os_version: rec.os_version,
            agent_version: rec.agent_version,
            enrolled_ts: rec.enrolled_ts,
        }
    }

    fn record(&self, agent_id: &str) -> Result<Option<AgentRecord>> {
        match self.store.get_saved(AGENT_KIND, agent_id)? {
            Some(o) => Ok(serde_json::from_value(o.body).ok()),
            None => Ok(None),
        }
    }

    fn persist(&self, rec: &AgentRecord) -> Result<()> {
        let obj = SavedObject {
            kind: AGENT_KIND.into(),
            id: rec.agent_id.clone(),
            name: rec.hostname.clone(),
            owner: None,
            updated_ts: now_micros(),
            body: serde_json::to_value(rec)
                .map_err(|e| sigil_core::Error::Backend(e.to_string()))?,
        };
        self.store.put_saved(&obj)
    }
}
