//! Kill a process by pid (portable via `sysinfo`).

use sigil_edr_proto::pb;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Returns `(ok, message)`.
pub fn run(kill: Option<&pb::KillProcess>) -> (bool, String) {
    let Some(k) = kill else {
        return (false, "missing kill params".into());
    };
    if k.pid == 0 {
        return (
            false,
            "kill requires a pid (hash-only kill not supported in v1)".into(),
        );
    }
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[Pid::from_u32(k.pid)]),
        true,
        ProcessRefreshKind::new(),
    );
    match sys.process(Pid::from_u32(k.pid)) {
        Some(p) => {
            if p.kill() {
                (true, format!("killed pid {}", k.pid))
            } else {
                (false, format!("failed to kill pid {}", k.pid))
            }
        }
        None => (false, format!("no process with pid {}", k.pid)),
    }
}
