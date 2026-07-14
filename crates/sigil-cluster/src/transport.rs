//! Transport abstraction (DESIGN §4.3, §19 ADR-2). One `Transport` trait with
//! three tiers: [`InProcBus`] for the monolith, [`TcpBus`] for brokerless
//! multi-node clusters (length-prefixed frames over persistent peer links),
//! and broker backends (Redpanda/Kafka default, NATS optional) that slot in
//! behind the same trait when an external bus is available.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sigil_core::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc};

/// Which transport backend to use (from `cluster.transport.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// In-process channels — monolith mode, no broker.
    Inproc,
    /// Direct TCP links between configured peers — no broker required.
    Tcp,
    /// Redpanda/Kafka — distributed (not wired yet).
    Redpanda,
    /// NATS JetStream — distributed (not wired yet).
    Nats,
}

impl TransportKind {
    pub fn parse(s: &str) -> Option<TransportKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "inproc" | "in-proc" | "in_proc" => Some(TransportKind::Inproc),
            "tcp" => Some(TransportKind::Tcp),
            "redpanda" | "kafka" => Some(TransportKind::Redpanda),
            "nats" => Some(TransportKind::Nats),
            _ => None,
        }
    }
}

/// A publish/subscribe transport over named topics.
pub trait Transport: Send + Sync {
    /// Publish a message to a topic.
    fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<()>;
    /// Subscribe to a topic, receiving messages published after subscribing.
    fn subscribe(&self, topic: &str) -> Result<broadcast::Receiver<Vec<u8>>>;
}

/// In-process broadcast bus. Backs monolith mode and tests.
pub struct InProcBus {
    capacity: usize,
    topics: Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>,
}

impl InProcBus {
    pub fn new() -> Self {
        InProcBus {
            capacity: 1024,
            topics: Mutex::new(HashMap::new()),
        }
    }

    fn sender(&self, topic: &str) -> broadcast::Sender<Vec<u8>> {
        let mut topics = self.topics.lock().unwrap();
        topics
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .clone()
    }
}

impl Default for InProcBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for InProcBus {
    fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<()> {
        // A send error just means no current subscribers — not fatal.
        let _ = self.sender(topic).send(payload);
        Ok(())
    }

    fn subscribe(&self, topic: &str) -> Result<broadcast::Receiver<Vec<u8>>> {
        Ok(self.sender(topic).subscribe())
    }
}

/// Live TCP transport between configured peers — a real multi-node bus with
/// no external broker (ADR-2's brokerless tier). Every publish is delivered
/// locally *and* framed to every peer as
/// `[topic_len u32][topic][payload_len u32][payload]` (big-endian); frames
/// received from peers feed the same local topics. Peer links are persistent
/// with lazy reconnect; a peer being down drops its copies (at-most-once, the
/// same delivery contract as the in-proc bus).
pub struct TcpBus {
    local: InProcBus,
    peers: Vec<mpsc::Sender<(String, Vec<u8>)>>,
}

/// Cap on frame fields (16 MiB) so a corrupt length prefix can't OOM us.
const MAX_FRAME: u32 = 16 * 1024 * 1024;

impl TcpBus {
    /// Listen on `listen` and hold outbound links to `peers` (host:port).
    /// Requires a tokio runtime.
    pub async fn spawn(listen: &str, peers: &[String]) -> Result<Arc<TcpBus>> {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| Error::Io(format!("tcp transport bind {listen}: {e}")))?;

        let bus = Arc::new(TcpBus {
            local: InProcBus::new(),
            peers: peers.iter().map(|p| Self::peer_task(p.clone())).collect(),
        });

        // Accept loop: every inbound frame becomes a local publish.
        let accept = bus.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, from)) = listener.accept().await else {
                    continue;
                };
                let bus = accept.clone();
                tokio::spawn(async move {
                    if let Err(e) = bus.read_frames(stream).await {
                        tracing::debug!(error = %e, %from, "tcp transport peer link closed");
                    }
                });
            }
        });
        Ok(bus)
    }

    /// A queue + writer task per peer: connects lazily, reconnects on failure,
    /// drops frames while the peer is unreachable.
    fn peer_task(addr: String) -> mpsc::Sender<(String, Vec<u8>)> {
        let (tx, mut rx) = mpsc::channel::<(String, Vec<u8>)>(1024);
        tokio::spawn(async move {
            let mut conn: Option<tokio::net::TcpStream> = None;
            while let Some((topic, payload)) = rx.recv().await {
                if conn.is_none() {
                    conn = tokio::net::TcpStream::connect(&addr).await.ok();
                    if conn.is_none() {
                        tracing::debug!(peer = %addr, "tcp transport peer unreachable; dropping frame");
                        continue;
                    }
                }
                let stream = conn.as_mut().unwrap();
                if write_frame(stream, &topic, &payload).await.is_err() {
                    conn = None; // reconnect on the next frame
                }
            }
        });
        tx
    }

    async fn read_frames(&self, mut stream: tokio::net::TcpStream) -> Result<()> {
        let io = |e: std::io::Error| Error::Io(format!("tcp transport read: {e}"));
        loop {
            let topic_len = stream.read_u32().await.map_err(io)?;
            if topic_len > MAX_FRAME {
                return Err(Error::Other("tcp transport: oversized topic".into()));
            }
            let mut topic = vec![0u8; topic_len as usize];
            stream.read_exact(&mut topic).await.map_err(io)?;
            let payload_len = stream.read_u32().await.map_err(io)?;
            if payload_len > MAX_FRAME {
                return Err(Error::Other("tcp transport: oversized payload".into()));
            }
            let mut payload = vec![0u8; payload_len as usize];
            stream.read_exact(&mut payload).await.map_err(io)?;
            let topic = String::from_utf8_lossy(&topic).to_string();
            self.local.publish(&topic, payload)?;
        }
    }
}

async fn write_frame(
    stream: &mut tokio::net::TcpStream,
    topic: &str,
    payload: &[u8],
) -> std::io::Result<()> {
    stream.write_u32(topic.len() as u32).await?;
    stream.write_all(topic.as_bytes()).await?;
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

impl Transport for TcpBus {
    fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<()> {
        self.local.publish(topic, payload.clone())?;
        for peer in &self.peers {
            // Full queue = slow/unreachable peer: drop rather than block the
            // publisher (same at-most-once contract as a lagged broadcast).
            let _ = peer.try_send((topic.to_string(), payload.clone()));
        }
        Ok(())
    }

    fn subscribe(&self, topic: &str) -> Result<broadcast::Receiver<Vec<u8>>> {
        self.local.subscribe(topic)
    }
}

/// Build a transport for the given kind. `Tcp` needs listen/peer addresses —
/// use [`TcpBus::spawn`]; broker backends are not wired yet and return a
/// clear error.
pub fn build_transport(kind: TransportKind) -> Result<Box<dyn Transport>> {
    match kind {
        TransportKind::Inproc => Ok(Box::new(InProcBus::new())),
        TransportKind::Tcp => Err(Error::Config(
            "tcp transport needs addresses; build it with TcpBus::spawn(listen, peers)".into(),
        )),
        TransportKind::Redpanda => Err(Error::Other(
            "redpanda/kafka transport not implemented yet (bring a broker; ADR-2)".into(),
        )),
        TransportKind::Nats => Err(Error::Other(
            "nats transport not implemented yet (bring a broker; ADR-2)".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inproc_pubsub_delivers() {
        let bus = InProcBus::new();
        let mut rx = bus.subscribe("events").unwrap();
        bus.publish("events", b"hello".to_vec()).unwrap();
        let got = rx.recv().await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn kind_parsing_and_unimplemented_backends() {
        assert_eq!(
            TransportKind::parse("redpanda"),
            Some(TransportKind::Redpanda)
        );
        assert_eq!(TransportKind::parse("tcp"), Some(TransportKind::Tcp));
        assert!(build_transport(TransportKind::Inproc).is_ok());
        assert!(build_transport(TransportKind::Redpanda).is_err());
    }

    #[tokio::test]
    async fn tcp_bus_delivers_between_two_nodes() {
        // Bind ephemeral listeners first to learn the ports, then cross-wire.
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap().to_string();
        let a2 = l2.local_addr().unwrap().to_string();
        drop((l1, l2));

        let n1 = TcpBus::spawn(&a1, std::slice::from_ref(&a2)).await.unwrap();
        let n2 = TcpBus::spawn(&a2, std::slice::from_ref(&a1)).await.unwrap();

        let mut sub2 = n2.subscribe("catalog").unwrap();
        let mut sub1_local = n1.subscribe("catalog").unwrap();
        n1.publish("catalog", b"shardmap-v2".to_vec()).unwrap();

        // Local delivery is immediate; remote arrives over the socket.
        assert_eq!(sub1_local.recv().await.unwrap(), b"shardmap-v2");
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), sub2.recv())
            .await
            .expect("timed out waiting for tcp delivery")
            .unwrap();
        assert_eq!(got, b"shardmap-v2");

        // And the reverse direction.
        let mut sub1 = n1.subscribe("acks").unwrap();
        n2.publish("acks", b"ok".to_vec()).unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), sub1.recv())
            .await
            .expect("timed out waiting for reverse tcp delivery")
            .unwrap();
        assert_eq!(got, b"ok");
    }
}
