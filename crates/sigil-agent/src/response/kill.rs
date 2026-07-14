//! Kill a process by pid, or every process whose image SHA-256 matches (portable
//! via `sysinfo`).

use sigil_edr_proto::pb;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

use crate::collector::sha256_file;

/// Cap on image size we'll hash when matching by hash (200 MiB).
const HASH_MAX: u64 = 200 * 1024 * 1024;

/// Returns `(ok, message)`.
pub fn run(kill: Option<&pb::KillProcess>) -> (bool, String) {
    let Some(k) = kill else {
        return (false, "missing kill params".into());
    };

    // Kill by pid.
    if k.pid != 0 {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from_u32(k.pid)]),
            true,
            ProcessRefreshKind::new(),
        );
        return match sys.process(Pid::from_u32(k.pid)) {
            Some(p) => {
                if p.kill() {
                    (true, format!("killed pid {}", k.pid))
                } else {
                    (false, format!("failed to kill pid {}", k.pid))
                }
            }
            None => (false, format!("no process with pid {}", k.pid)),
        };
    }

    // Kill every process whose image hash matches.
    if !k.hash_sha256.is_empty() {
        let target = k.hash_sha256.to_lowercase();
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        let mut matched = 0usize;
        let mut killed = 0usize;
        for proc_ in sys.processes().values() {
            let Some(exe) = proc_.exe() else { continue };
            if sha256_file(exe, HASH_MAX).as_deref() == Some(target.as_str()) {
                matched += 1;
                if proc_.kill() {
                    killed += 1;
                }
            }
        }
        return if matched == 0 {
            (
                false,
                format!(
                    "no running process matched hash {}",
                    &target[..target.len().min(12)]
                ),
            )
        } else {
            (
                true,
                format!("killed {killed}/{matched} process(es) matching hash"),
            )
        };
    }

    (false, "kill requires a pid or hash_sha256".into())
}
