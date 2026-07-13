//! Persistence-point inventory: diffs the contents of OS-specific autostart
//! locations and emits `PERSISTENCE_ADD` for new entries (cron jobs, systemd
//! units, launch agents/daemons, etc.). Portable via a per-OS directory list;
//! deeper native hooks are a later phase.

use std::collections::HashSet;
use std::path::PathBuf;

use sigil_edr_proto::pb;

use super::{new_event, Collector};

/// A watched persistence location: a directory + the `kind` label to report.
struct Location {
    kind: &'static str,
    dir: PathBuf,
}

#[derive(Default)]
pub struct PersistenceCollector {
    seen: HashSet<String>,
    primed: bool,
}

impl Collector for PersistenceCollector {
    fn name(&self) -> &'static str {
        "persistence"
    }

    fn poll(&mut self) -> Vec<pb::EndpointEvent> {
        let mut events = Vec::new();
        let mut current: HashSet<String> = HashSet::new();

        for loc in locations() {
            let entries = match std::fs::read_dir(&loc.dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let key = format!("{}::{}", loc.kind, path.display());
                current.insert(key.clone());
                if self.primed && !self.seen.contains(&key) {
                    let mut ev = new_event(pb::EventKind::PersistenceAdd);
                    ev.persistence = Some(pb::PersistenceInfo {
                        kind: loc.kind.to_string(),
                        name,
                        target: path.to_string_lossy().to_string(),
                    });
                    events.push(ev);
                }
            }
        }

        self.seen = current;
        self.primed = true;
        events
    }
}

#[cfg(target_os = "linux")]
fn locations() -> Vec<Location> {
    vec![
        loc("cron", "/etc/cron.d"),
        loc("cron", "/var/spool/cron/crontabs"),
        loc("systemd", "/etc/systemd/system"),
        loc("systemd", "/lib/systemd/system"),
    ]
}

#[cfg(target_os = "macos")]
fn locations() -> Vec<Location> {
    let mut v = vec![
        loc("launchd", "/Library/LaunchAgents"),
        loc("launchd", "/Library/LaunchDaemons"),
        loc("cron", "/var/at/tabs"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push("Library/LaunchAgents");
        v.push(Location {
            kind: "launchd",
            dir: p,
        });
    }
    v
}

#[cfg(target_os = "windows")]
fn locations() -> Vec<Location> {
    let mut v = Vec::new();
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let mut p = PathBuf::from(appdata);
        p.push("Microsoft/Windows/Start Menu/Programs/Startup");
        v.push(Location {
            kind: "startup-folder",
            dir: p,
        });
    }
    v.push(loc(
        "startup-folder",
        "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp",
    ));
    v
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn locations() -> Vec<Location> {
    Vec::new()
}

fn loc(kind: &'static str, dir: &str) -> Location {
    Location {
        kind,
        dir: PathBuf::from(dir),
    }
}
