//! Process collector: snapshot-diff via [`sysinfo`]. Emits `PROCESS_START` for
//! processes that appear and `PROCESS_STOP` for those that vanish. The first
//! poll primes the baseline without emitting (avoids a start-flood at boot).

use std::collections::HashMap;

use sigil_edr_proto::pb;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

use super::{new_event, sha256_file, Collector};

/// Cap on image size we'll hash for a new process (50 MiB).
const HASH_MAX: u64 = 50 * 1024 * 1024;

/// Lightweight cached view of a live process (for stop events).
struct Known {
    name: String,
    path: String,
}

pub struct ProcessCollector {
    sys: System,
    known: HashMap<u32, Known>,
    primed: bool,
}

impl Default for ProcessCollector {
    fn default() -> Self {
        ProcessCollector {
            sys: System::new(),
            known: HashMap::new(),
            primed: false,
        }
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    fn poll(&mut self) -> Vec<pb::EndpointEvent> {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );

        let mut events = Vec::new();
        let mut current: HashMap<u32, Known> = HashMap::new();

        for (pid, proc_) in self.sys.processes() {
            let pid = pid.as_u32();
            let name = proc_.name().to_string_lossy().to_string();
            let path = proc_
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            current.insert(
                pid,
                Known {
                    name: name.clone(),
                    path: path.clone(),
                },
            );

            if self.primed && !self.known.contains_key(&pid) {
                events.push(self.start_event(pid, proc_));
            }
        }

        if self.primed {
            for (pid, known) in &self.known {
                if !current.contains_key(pid) {
                    let mut ev = new_event(pb::EventKind::ProcessStop);
                    ev.process = Some(pb::Process {
                        pid: *pid,
                        name: known.name.clone(),
                        path: known.path.clone(),
                        ..Default::default()
                    });
                    events.push(ev);
                }
            }
        }

        self.known = current;
        self.primed = true;
        events
    }
}

impl ProcessCollector {
    fn start_event(&self, pid: u32, proc_: &sysinfo::Process) -> pb::EndpointEvent {
        let name = proc_.name().to_string_lossy().to_string();
        let path = proc_
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmdline = proc_
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let ppid = proc_.parent().map(|p| p.as_u32()).unwrap_or(0);
        let hash = proc_
            .exe()
            .and_then(|p| sha256_file(p, HASH_MAX))
            .unwrap_or_default();
        let user = proc_.user_id().map(|u| u.to_string()).unwrap_or_default();

        let mut ev = new_event(pb::EventKind::ProcessStart);
        ev.user = user.clone();
        ev.process = Some(pb::Process {
            pid,
            ppid,
            name,
            path,
            cmdline,
            hash_sha256: hash,
            user,
        });
        if ppid != 0 {
            if let Some(parent) = self.sys.process(Pid::from_u32(ppid)) {
                ev.parent = Some(pb::Process {
                    pid: ppid,
                    name: parent.name().to_string_lossy().to_string(),
                    path: parent
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    ..Default::default()
                });
            }
        }
        ev
    }
}
