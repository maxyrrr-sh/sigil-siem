//! Response-action executors. Commands arrive over the control stream and are
//! executed locally, then a [`pb::CommandResult`] is reported back. The basic
//! set is: kill process, quarantine file, host network isolation (with a
//! server-control-channel allowlist so isolation can't sever the agent), and
//! fetch-file for triage. No arbitrary remote shell (by design).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sigil_edr_proto::pb;

mod fetch;
mod isolate;
mod kill;
mod quarantine;

/// Context the executors need (config + live isolation state).
#[derive(Clone)]
pub struct ResponseCtx {
    pub quarantine_dir: String,
    /// Host the control channel lives on — ALWAYS allowed during isolation.
    pub control_host: String,
    /// Shared isolation flag (reported in heartbeats).
    pub isolated: Arc<AtomicBool>,
}

/// Execute one command, producing a result to report upstream.
pub fn execute(cmd: &pb::Command, ctx: &ResponseCtx) -> pb::CommandResult {
    let (ok, message, payload) = match cmd.r#type() {
        pb::CommandType::KillProcess => {
            let (o, m) = kill::run(cmd.kill.as_ref());
            (o, m, Vec::new())
        }
        pb::CommandType::QuarantineFile => {
            let (o, m) = quarantine::run(cmd.quarantine.as_ref(), &ctx.quarantine_dir);
            (o, m, Vec::new())
        }
        pb::CommandType::IsolateHost => {
            let (o, m) = isolate::isolate(cmd.isolate.as_ref(), &ctx.control_host);
            if o {
                ctx.isolated.store(true, Ordering::SeqCst);
            }
            (o, m, Vec::new())
        }
        pb::CommandType::UnisolateHost => {
            let (o, m) = isolate::unisolate();
            if o {
                ctx.isolated.store(false, Ordering::SeqCst);
            }
            (o, m, Vec::new())
        }
        pb::CommandType::FetchFile => fetch::run(cmd.fetch.as_ref()),
        pb::CommandType::Unspecified => (false, "unspecified command".into(), Vec::new()),
    };
    pb::CommandResult {
        command_id: cmd.command_id.clone(),
        ok,
        message,
        payload,
        ts: crate::collector::now_micros(),
    }
}
