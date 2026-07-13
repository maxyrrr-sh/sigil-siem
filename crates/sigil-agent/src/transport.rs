//! gRPC transport: one-time enrollment, then the long-lived control stream with
//! exponential-backoff reconnect. Telemetry is batched up; commands are executed
//! (off the async runtime, on a blocking thread) and their results reported back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sigil_edr_proto::pb;
use sigil_edr_proto::pb::agent_service_client::AgentServiceClient;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::collector::now_micros;
use crate::config::{AgentConfig, AgentIdentity};
use crate::response::{self, ResponseCtx};

/// Connect a gRPC client, applying TLS (with an optional pinned CA) for
/// `https://` servers.
async fn connect_client(cfg: &AgentConfig) -> Result<AgentServiceClient<Channel>, String> {
    let mut endpoint: Endpoint = Endpoint::from_shared(cfg.server_url.clone())
        .map_err(|e| format!("bad server_url: {e}"))?;
    if cfg.server_url.starts_with("https") {
        let mut tls = ClientTlsConfig::new();
        if let Some(ca) = &cfg.tls_ca {
            let pem = std::fs::read(ca).map_err(|e| format!("read tls_ca: {e}"))?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| format!("tls config: {e}"))?;
    }
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok(AgentServiceClient::new(channel))
}

/// Enroll with the gateway, returning the granted identity.
pub async fn enroll(cfg: &AgentConfig) -> Result<AgentIdentity, String> {
    let mut client = connect_client(cfg).await?;
    let (hostname, os_version) = host_info();
    let reply = client
        .enroll(pb::EnrollRequest {
            enrollment_token: cfg.enrollment_token.clone(),
            hostname: hostname.clone(),
            os: std::env::consts::OS.to_string(),
            os_version,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprint: fingerprint(&hostname),
        })
        .await
        .map_err(|e| format!("enroll rejected: {}", e.message()))?
        .into_inner();
    Ok(AgentIdentity {
        agent_id: reply.agent_id,
        session_token: reply.session_token,
        server_url: cfg.server_url.clone(),
    })
}

/// Run the control loop forever, reconnecting with backoff.
pub async fn run(
    cfg: AgentConfig,
    identity: AgentIdentity,
    mut telemetry_rx: mpsc::Receiver<pb::EndpointEvent>,
) {
    let isolated = Arc::new(AtomicBool::new(false));
    let ctx = ResponseCtx {
        quarantine_dir: cfg.quarantine_dir.clone(),
        control_host: host_only(&cfg.server_url),
        isolated: isolated.clone(),
    };
    let mut backoff = 1u64;
    loop {
        match session_once(&cfg, &identity, &mut telemetry_rx, &ctx, &isolated).await {
            Ok(()) => {
                tracing::info!("control stream closed; reconnecting");
                backoff = 1;
            }
            Err(e) => {
                tracing::warn!(error = %e, backoff, "session error; reconnecting");
            }
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn session_once(
    cfg: &AgentConfig,
    identity: &AgentIdentity,
    telemetry_rx: &mut mpsc::Receiver<pb::EndpointEvent>,
    ctx: &ResponseCtx,
    isolated: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut client = connect_client(cfg).await?;
    let (up_tx, up_rx) = mpsc::channel::<pb::AgentMessage>(256);
    let mut down = client
        .session(ReceiverStream::new(up_rx))
        .await
        .map_err(|e| format!("open session: {}", e.message()))?
        .into_inner();

    // Hello handshake.
    up_tx
        .send(pb::AgentMessage {
            kind: Some(pb::agent_message::Kind::Hello(pb::Hello {
                agent_id: identity.agent_id.clone(),
                session_token: identity.session_token.clone(),
            })),
        })
        .await
        .map_err(|_| "send hello".to_string())?;
    match down.next().await {
        Some(Ok(msg)) => match msg.kind {
            Some(pb::server_message::Kind::HelloAck(a)) if a.ok => {}
            Some(pb::server_message::Kind::HelloAck(a)) => {
                return Err(format!("hello rejected: {}", a.message))
            }
            _ => return Err("expected HelloAck".into()),
        },
        Some(Err(e)) => return Err(format!("stream error: {}", e.message())),
        None => return Err("stream closed before HelloAck".into()),
    }
    tracing::info!(agent_id = %identity.agent_id, "connected to gateway");

    let mut batch: Vec<pb::EndpointEvent> = Vec::new();
    let mut flush = tokio::time::interval(Duration::from_secs(2));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            ev = telemetry_rx.recv() => match ev {
                Some(ev) => {
                    batch.push(ev);
                    if batch.len() >= cfg.batch_size {
                        send_batch(&up_tx, &mut batch).await?;
                    }
                }
                None => return Ok(()), // collectors gone
            },
            _ = flush.tick() => {
                if !batch.is_empty() {
                    send_batch(&up_tx, &mut batch).await?;
                }
            }
            _ = heartbeat.tick() => {
                let hb = pb::AgentMessage {
                    kind: Some(pb::agent_message::Kind::Heartbeat(pb::Heartbeat {
                        ts: now_micros(),
                        stats: Some(pb::AgentStats {
                            isolated: isolated.load(Ordering::SeqCst),
                            ..Default::default()
                        }),
                    })),
                };
                up_tx.send(hb).await.map_err(|_| "send heartbeat".to_string())?;
            }
            down_msg = down.next() => match down_msg {
                Some(Ok(msg)) => match msg.kind {
                    Some(pb::server_message::Kind::Command(cmd)) => {
                        let ctx = ctx.clone();
                        let up = up_tx.clone();
                        // Response actions do blocking OS work; run off-runtime.
                        tokio::spawn(async move {
                            let result = tokio::task::spawn_blocking(move || {
                                response::execute(&cmd, &ctx)
                            })
                            .await;
                            if let Ok(result) = result {
                                let _ = up
                                    .send(pb::AgentMessage {
                                        kind: Some(pb::agent_message::Kind::Result(result)),
                                    })
                                    .await;
                            }
                        });
                    }
                    Some(pb::server_message::Kind::HeartbeatAck(_)) => {}
                    _ => {}
                },
                Some(Err(e)) => return Err(format!("stream error: {}", e.message())),
                None => return Ok(()), // server closed
            }
        }
    }
}

async fn send_batch(
    up_tx: &mpsc::Sender<pb::AgentMessage>,
    batch: &mut Vec<pb::EndpointEvent>,
) -> Result<(), String> {
    let events = std::mem::take(batch);
    up_tx
        .send(pb::AgentMessage {
            kind: Some(pb::agent_message::Kind::Telemetry(pb::TelemetryBatch {
                events,
            })),
        })
        .await
        .map_err(|_| "send telemetry".to_string())
}

/// `(hostname, os_version)` for enrollment.
fn host_info() -> (String, String) {
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
    let os_version = sysinfo::System::os_version().unwrap_or_default();
    (hostname, os_version)
}

/// A stable, non-reversible machine fingerprint.
fn fingerprint(hostname: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(hostname.as_bytes());
    h.update(std::env::consts::OS.as_bytes());
    format!("{:x}", h.finalize())
}

/// Extract just the host from a `scheme://host:port` URL (for the isolation
/// allowlist).
fn host_only(url: &str) -> String {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = no_scheme.split(['/', ':']).next().unwrap_or(no_scheme);
    host.to_string()
}

#[cfg(test)]
mod tests {
    use super::host_only;

    #[test]
    fn host_only_strips_scheme_and_port() {
        assert_eq!(host_only("https://siem.internal:50055"), "siem.internal");
        assert_eq!(host_only("http://10.0.0.5:50055/path"), "10.0.0.5");
        assert_eq!(host_only("siem"), "siem");
    }
}
