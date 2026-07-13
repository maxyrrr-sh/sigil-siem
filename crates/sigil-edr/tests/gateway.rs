//! End-to-end loopback test for the EDR gateway: an in-process client enrolls,
//! opens the control stream, pushes telemetry (asserting it becomes an
//! `Event`), and receives a queued response command.

use std::sync::Arc;
use std::time::Duration;

use sigil_edr::{CommandParams, EdrState};
use sigil_edr_proto::pb;
use sigil_edr_proto::pb::agent_service_client::AgentServiceClient;
use sigil_store::Store;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn agent_enrolls_streams_telemetry_and_receives_command() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("store.redb")).unwrap());
    let state = EdrState::new(store, &["secret-token".to_string()]).unwrap();

    let (ev_tx, mut ev_rx) = mpsc::channel::<sigil_core::Event>(64);
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");

    // Run the gateway.
    let serve_state = state.clone();
    tokio::spawn(async move {
        sigil_edr::serve(&listen, serve_state, ev_tx, "acme".into(), None)
            .await
            .unwrap();
    });

    // Connect (retry until the server is up).
    let endpoint = format!("http://127.0.0.1:{port}");
    let mut client = None;
    for _ in 0..50 {
        if let Ok(c) = AgentServiceClient::connect(endpoint.clone()).await {
            client = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = client.expect("gateway did not come up");

    // Enroll.
    let enroll = client
        .enroll(pb::EnrollRequest {
            enrollment_token: "secret-token".into(),
            hostname: "host-a".into(),
            os: "macos".into(),
            os_version: "15".into(),
            agent_version: "0.1".into(),
            fingerprint: "fp-1".into(),
        })
        .await
        .expect("enroll ok")
        .into_inner();
    assert!(!enroll.agent_id.is_empty());
    let agent_id = enroll.agent_id.clone();

    // Open the control stream: Hello, then a telemetry batch.
    let (up_tx, up_rx) = mpsc::channel::<pb::AgentMessage>(16);
    let mut down = client
        .session(ReceiverStream::new(up_rx))
        .await
        .expect("session ok")
        .into_inner();

    up_tx
        .send(pb::AgentMessage {
            kind: Some(pb::agent_message::Kind::Hello(pb::Hello {
                agent_id: agent_id.clone(),
                session_token: enroll.session_token.clone(),
            })),
        })
        .await
        .unwrap();

    // Expect HelloAck.
    let first = down.next().await.expect("hello ack").expect("ok");
    match first.kind {
        Some(pb::server_message::Kind::HelloAck(a)) => assert!(a.ok, "hello rejected"),
        other => panic!("expected HelloAck, got {other:?}"),
    }

    // Push telemetry: a process start.
    up_tx
        .send(pb::AgentMessage {
            kind: Some(pb::agent_message::Kind::Telemetry(pb::TelemetryBatch {
                events: vec![pb::EndpointEvent {
                    id: "e1".into(),
                    ts: 1000,
                    kind: pb::EventKind::ProcessStart as i32,
                    process: Some(pb::Process {
                        pid: 100,
                        name: "bash".into(),
                        cmdline: "bash -c id".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
            })),
        })
        .await
        .unwrap();

    // The telemetry should surface as an Event on the pipeline channel.
    let ev = tokio::time::timeout(Duration::from_secs(2), ev_rx.recv())
        .await
        .expect("event within timeout")
        .expect("event present");
    assert_eq!(ev.ocsf_class, sigil_core::OcsfClass::ProcessActivity);
    assert_eq!(ev.tenant, "acme");
    assert_eq!(
        ev.field_str("process.command_line").as_deref(),
        Some("bash -c id")
    );

    // Enqueue a response command; the agent should receive it on the stream.
    state
        .queue
        .enqueue(
            &agent_id,
            "kill_process",
            CommandParams {
                pid: Some(100),
                ..Default::default()
            },
            "analyst-1",
        )
        .await
        .expect("enqueue ok");

    let cmd = tokio::time::timeout(Duration::from_secs(2), down.next())
        .await
        .expect("command within timeout")
        .expect("stream item")
        .expect("ok");
    match cmd.kind {
        Some(pb::server_message::Kind::Command(c)) => {
            assert_eq!(c.r#type, pb::CommandType::KillProcess as i32);
            assert_eq!(c.kill.unwrap().pid, 100);
        }
        other => panic!("expected Command, got {other:?}"),
    }

    // The command audit record exists.
    let cmds = state.queue.list(10, Some(&agent_id)).unwrap();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_type, "kill_process");
}
