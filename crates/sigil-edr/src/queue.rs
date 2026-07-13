//! Response-command queue + audit trail. The API enqueues a command; if the
//! target agent holds a live stream it is delivered immediately, otherwise it
//! waits (status `pending`) until the agent reconnects. Every command — and its
//! result — is persisted as a `sigil-store` saved object of kind `edr-command`,
//! forming an immutable-ish audit log (who issued what, when, and the outcome).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sigil_core::{now_micros, Error, Result, Timestamp};
use sigil_edr_proto::pb;
use sigil_store::{SavedObject, Store};

use crate::registry::AgentRegistry;

/// Saved-object kind for command audit records.
pub const COMMAND_KIND: &str = "edr-command";

/// Parameters for a response command (union of all command types).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_cidrs: Option<Vec<String>>,
}

/// One issued response command plus its lifecycle + result (the audit record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command_id: String,
    pub agent_id: String,
    /// `kill_process` | `quarantine_file` | `isolate_host` | `unisolate_host` | `fetch_file`.
    pub command_type: String,
    pub params: CommandParams,
    /// `pending` | `sent` | `completed` | `failed`.
    pub status: String,
    pub issued_by: String,
    pub issued_ts: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_ts: Option<Timestamp>,
}

/// The command queue. Cheap to share via `Arc`.
pub struct CommandQueue {
    store: Arc<Store>,
    registry: Arc<AgentRegistry>,
}

impl CommandQueue {
    pub fn new(store: Arc<Store>, registry: Arc<AgentRegistry>) -> Arc<CommandQueue> {
        Arc::new(CommandQueue { store, registry })
    }

    /// Enqueue a response command for `agent_id`. Persists the audit record and
    /// delivers it over the live stream if the agent is connected.
    pub async fn enqueue(
        &self,
        agent_id: &str,
        command_type: &str,
        params: CommandParams,
        issued_by: &str,
    ) -> Result<CommandRecord> {
        let ctype = parse_command_type(command_type)?;
        let command_id = ulid::Ulid::new().to_string();
        let mut rec = CommandRecord {
            command_id: command_id.clone(),
            agent_id: agent_id.to_string(),
            command_type: command_type.to_string(),
            params: params.clone(),
            status: "pending".into(),
            issued_by: issued_by.to_string(),
            issued_ts: now_micros(),
            result_ok: None,
            result_message: None,
            result_bytes: None,
            completed_ts: None,
        };
        self.persist(&rec)?;

        if let Some(tx) = self.registry.command_sender(agent_id) {
            let cmd = build_command(&command_id, ctype, &params);
            if tx.send(cmd).await.is_ok() {
                rec.status = "sent".into();
                self.persist(&rec)?;
            }
        }
        Ok(rec)
    }

    /// Record a command result reported by an agent.
    pub fn record_result(&self, result: &pb::CommandResult) -> Result<()> {
        if let Some(mut rec) = self.get(&result.command_id)? {
            rec.status = if result.ok { "completed" } else { "failed" }.into();
            rec.result_ok = Some(result.ok);
            rec.result_message = Some(result.message.clone());
            if !result.payload.is_empty() {
                rec.result_bytes = Some(result.payload.len());
            }
            rec.completed_ts = Some(now_micros());
            self.persist(&rec)?;
        } else {
            tracing::warn!(command_id = %result.command_id, "result for unknown command");
        }
        Ok(())
    }

    /// One command record by id.
    pub fn get(&self, command_id: &str) -> Result<Option<CommandRecord>> {
        match self.store.get_saved(COMMAND_KIND, command_id)? {
            Some(o) => Ok(serde_json::from_value(o.body).ok()),
            None => Ok(None),
        }
    }

    /// List command records (newest first), optionally filtered to one agent.
    pub fn list(&self, limit: usize, agent_id: Option<&str>) -> Result<Vec<CommandRecord>> {
        let mut out: Vec<CommandRecord> = self
            .store
            .list_saved(COMMAND_KIND)?
            .into_iter()
            .filter_map(|o| serde_json::from_value::<CommandRecord>(o.body).ok())
            .filter(|r| match agent_id {
                Some(a) => r.agent_id == a,
                None => true,
            })
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.issued_ts));
        out.truncate(limit);
        Ok(out)
    }

    fn persist(&self, rec: &CommandRecord) -> Result<()> {
        let obj = SavedObject {
            kind: COMMAND_KIND.into(),
            id: rec.command_id.clone(),
            name: format!("{} → {}", rec.command_type, rec.agent_id),
            owner: Some(rec.issued_by.clone()),
            updated_ts: now_micros(),
            body: serde_json::to_value(rec).map_err(|e| Error::Backend(e.to_string()))?,
        };
        self.store.put_saved(&obj)
    }
}

/// Parse an API command-type string into the protobuf enum.
pub fn parse_command_type(s: &str) -> Result<pb::CommandType> {
    match s.to_ascii_lowercase().as_str() {
        "kill_process" | "kill" => Ok(pb::CommandType::KillProcess),
        "quarantine_file" | "quarantine" => Ok(pb::CommandType::QuarantineFile),
        "isolate_host" | "isolate" => Ok(pb::CommandType::IsolateHost),
        "unisolate_host" | "unisolate" => Ok(pb::CommandType::UnisolateHost),
        "fetch_file" | "fetch" => Ok(pb::CommandType::FetchFile),
        other => Err(Error::Config(format!("unknown command type `{other}`"))),
    }
}

/// Construct the wire [`pb::Command`] for a command type + params.
pub fn build_command(
    command_id: &str,
    ctype: pb::CommandType,
    params: &CommandParams,
) -> pb::Command {
    let mut cmd = pb::Command {
        command_id: command_id.to_string(),
        r#type: ctype as i32,
        ..Default::default()
    };
    match ctype {
        pb::CommandType::KillProcess => {
            cmd.kill = Some(pb::KillProcess {
                pid: params.pid.unwrap_or(0),
                hash_sha256: params.hash_sha256.clone().unwrap_or_default(),
            });
        }
        pb::CommandType::QuarantineFile => {
            cmd.quarantine = Some(pb::QuarantineFile {
                path: params.path.clone().unwrap_or_default(),
                hash_sha256: params.hash_sha256.clone().unwrap_or_default(),
            });
        }
        pb::CommandType::IsolateHost => {
            cmd.isolate = Some(pb::Isolate {
                allowlist_cidrs: params.allowlist_cidrs.clone().unwrap_or_default(),
            });
        }
        pb::CommandType::UnisolateHost => {}
        pb::CommandType::FetchFile => {
            cmd.fetch = Some(pb::FetchFile {
                path: params.path.clone().unwrap_or_default(),
                max_bytes: params.max_bytes.unwrap_or(1024 * 1024),
            });
        }
        pb::CommandType::Unspecified => {}
    }
    cmd
}
