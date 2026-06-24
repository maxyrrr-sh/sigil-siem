//! Transport abstraction (DESIGN §4.3, §19 ADR-2). One `Transport` trait that
//! is in-process for the monolith and a message bus (Redpanda/Kafka default,
//! NATS optional) when scaled out. Phase 5 ships the in-proc bus; broker
//! backends slot in behind this trait.

use std::collections::HashMap;
use std::sync::Mutex;

use sigil_core::{Error, Result};
use tokio::sync::broadcast;

/// Which transport backend to use (from `cluster.transport.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// In-process channels — monolith mode, no broker.
    Inproc,
    /// Redpanda/Kafka — distributed (not wired yet).
    Redpanda,
    /// NATS JetStream — distributed (not wired yet).
    Nats,
}

impl TransportKind {
    pub fn parse(s: &str) -> Option<TransportKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "inproc" | "in-proc" | "in_proc" => Some(TransportKind::Inproc),
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

/// Build a transport for the given kind. Distributed backends are not wired
/// yet and return a clear error.
pub fn build_transport(kind: TransportKind) -> Result<Box<dyn Transport>> {
    match kind {
        TransportKind::Inproc => Ok(Box::new(InProcBus::new())),
        TransportKind::Redpanda => Err(Error::Other(
            "redpanda/kafka transport not implemented yet (Phase 5+)".into(),
        )),
        TransportKind::Nats => Err(Error::Other(
            "nats transport not implemented yet (Phase 5+)".into(),
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
        assert!(build_transport(TransportKind::Inproc).is_ok());
        assert!(build_transport(TransportKind::Redpanda).is_err());
    }
}
