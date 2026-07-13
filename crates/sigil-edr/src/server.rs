//! The tonic [`AgentService`] gateway: agent enrollment + the long-lived
//! bidirectional control stream. Inbound telemetry is mapped to
//! [`sigil_core::Event`]s and pushed into the SIEM pipeline via `event_tx`;
//! inbound command results update the audit trail; queued response commands are
//! forwarded down the stream.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use sigil_core::{now_micros, Error, Event};
use sigil_edr_proto::pb;
use sigil_edr_proto::pb::agent_service_server::{AgentService, AgentServiceServer};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use crate::map;
use crate::EdrState;

/// Default heartbeat cadence handed to agents at enrollment.
const HEARTBEAT_SECS: u32 = 30;

/// The gRPC gateway implementation.
struct AgentGateway {
    state: Arc<EdrState>,
    event_tx: mpsc::Sender<Event>,
    tenant: String,
}

/// Bind and serve the EDR agent gateway until the process exits.
///
/// `tls` is `(cert_pem, key_pem)`; when `None` the gateway runs plaintext (dev
/// only) with a loud warning. Telemetry events are sent on `event_tx`.
pub async fn serve(
    listen: &str,
    state: Arc<EdrState>,
    event_tx: mpsc::Sender<Event>,
    tenant: String,
    tls: Option<(Vec<u8>, Vec<u8>)>,
) -> sigil_core::Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| Error::Config(format!("edr.listen `{listen}`: {e}")))?;
    let gateway = AgentGateway {
        state,
        event_tx,
        tenant,
    };
    let svc = AgentServiceServer::new(gateway);

    let mut builder = Server::builder();
    match tls {
        Some((cert, key)) => {
            let identity = Identity::from_pem(cert, key);
            builder = builder
                .tls_config(ServerTlsConfig::new().identity(identity))
                .map_err(|e| Error::Config(format!("edr tls: {e}")))?;
            tracing::info!(%addr, "EDR agent gateway listening (TLS)");
        }
        None => {
            tracing::warn!(
                %addr,
                "EDR agent gateway listening WITHOUT TLS (plaintext) — set edr.tls_cert/tls_key for production"
            );
        }
    }

    builder
        .add_service(svc)
        .serve(addr)
        .await
        .map_err(|e| Error::Io(format!("edr gateway serve: {e}")))
}

#[tonic::async_trait]
impl AgentService for AgentGateway {
    async fn enroll(
        &self,
        request: Request<pb::EnrollRequest>,
    ) -> Result<Response<pb::EnrollReply>, Status> {
        let req = request.into_inner();
        match self.state.tokens.valid(&req.enrollment_token) {
            Ok(true) => {}
            Ok(false) => return Err(Status::unauthenticated("invalid enrollment token")),
            Err(e) => return Err(Status::internal(e.to_string())),
        }
        let session_token = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
        let rec = self
            .state
            .registry
            .enroll(&req, session_token.clone())
            .map_err(|e| Status::internal(e.to_string()))?;
        tracing::info!(agent_id = %rec.agent_id, hostname = %rec.hostname, os = %rec.os, "agent enrolled");
        Ok(Response::new(pb::EnrollReply {
            agent_id: rec.agent_id,
            session_token,
            heartbeat_secs: HEARTBEAT_SECS,
        }))
    }

    type SessionStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<pb::ServerMessage, Status>> + Send>>;

    async fn session(
        &self,
        request: Request<Streaming<pb::AgentMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let mut inbound = request.into_inner();
        let (out_tx, out_rx) = mpsc::channel::<Result<pb::ServerMessage, Status>>(64);

        let state = self.state.clone();
        let event_tx = self.event_tx.clone();
        let tenant = self.tenant.clone();

        tokio::spawn(async move {
            // First frame must be a valid Hello.
            let hello = match inbound.message().await {
                Ok(Some(msg)) => match msg.kind {
                    Some(pb::agent_message::Kind::Hello(h)) => h,
                    _ => {
                        let _ = out_tx
                            .send(Err(Status::unauthenticated("expected Hello")))
                            .await;
                        return;
                    }
                },
                _ => return,
            };
            match state
                .registry
                .validate_session(&hello.agent_id, &hello.session_token)
            {
                Ok(true) => {}
                _ => {
                    let _ = out_tx.send(hello_ack(false, "invalid session")).await;
                    return;
                }
            }

            let agent_id = hello.agent_id.clone();
            let hostname = state
                .registry
                .get(&agent_id)
                .ok()
                .flatten()
                .map(|v| v.hostname)
                .unwrap_or_default();
            let mut cmd_rx = state.registry.connect(&agent_id);
            let _ = out_tx.send(hello_ack(true, "ok")).await;
            tracing::info!(%agent_id, "agent control stream up");

            loop {
                tokio::select! {
                    inbound_msg = inbound.message() => {
                        match inbound_msg {
                            Ok(Some(msg)) => match msg.kind {
                                Some(pb::agent_message::Kind::Heartbeat(hb)) => {
                                    let isolated = hb.stats.map(|s| s.isolated).unwrap_or(false);
                                    state.registry.heartbeat(&agent_id, isolated);
                                    let ack = pb::ServerMessage {
                                        kind: Some(pb::server_message::Kind::HeartbeatAck(
                                            pb::HeartbeatAck { ts: now_micros() as u64 },
                                        )),
                                    };
                                    let _ = out_tx.send(Ok(ack)).await;
                                }
                                Some(pb::agent_message::Kind::Telemetry(batch)) => {
                                    for ee in &batch.events {
                                        let ev = map::to_event(&agent_id, &hostname, &tenant, ee);
                                        if event_tx.send(ev).await.is_err() {
                                            tracing::warn!("event channel closed; dropping telemetry");
                                        }
                                    }
                                }
                                Some(pb::agent_message::Kind::Result(r)) => {
                                    if let Err(e) = state.queue.record_result(&r) {
                                        tracing::warn!(error = %e, "record result failed");
                                    }
                                }
                                Some(pb::agent_message::Kind::Hello(_)) | None => {}
                            },
                            Ok(None) | Err(_) => break, // stream ended
                        }
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(command) => {
                                let msg = pb::ServerMessage {
                                    kind: Some(pb::server_message::Kind::Command(command)),
                                };
                                if out_tx.send(Ok(msg)).await.is_err() {
                                    break;
                                }
                            }
                            None => break, // session replaced/closed
                        }
                    }
                }
            }

            state.registry.disconnect(&agent_id);
            tracing::info!(%agent_id, "agent control stream down");
        });

        let stream: Self::SessionStream = Box::pin(ReceiverStream::new(out_rx));
        Ok(Response::new(stream))
    }
}

// `tonic::Status` is large by nature; boxing it here would fight the stream's
// item type. This helper just wraps a message.
#[allow(clippy::result_large_err)]
fn hello_ack(ok: bool, msg: &str) -> Result<pb::ServerMessage, Status> {
    Ok(pb::ServerMessage {
        kind: Some(pb::server_message::Kind::HelloAck(pb::HelloAck {
            ok,
            message: msg.to_string(),
        })),
    })
}
