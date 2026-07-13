//! `sigil-edr` — the server-side EDR module (DESIGN §12, optional endpoint
//! companion).
//!
//! Sigil is a SIEM that *consumes* telemetry; `sigil-edr` is the gateway that
//! lets Sigil's own optional endpoint agent (`sigil-agent`) push high-fidelity
//! process/file/network/DNS provenance and receive response commands. It holds:
//!
//! - a tonic gRPC gateway ([`serve`]) implementing the agent protocol
//!   (`proto/sigil_edr.proto`),
//! - a durable [`AgentRegistry`] of enrolled agents + live control sessions,
//!   an enrollment [`TokenStore`], and a [`CommandQueue`] audit trail (all
//!   persisted via `sigil-store`),
//! - the [`map::to_event`] bridge that turns endpoint telemetry into normalized
//!   [`sigil_core::Event`]s so it flows through the existing Sigma / index /
//!   correlation pipeline unchanged.

use std::sync::Arc;

use sigil_store::Store;

pub mod map;
pub mod queue;
pub mod registry;
pub mod server;
pub mod tokens;

pub use queue::{CommandParams, CommandQueue, CommandRecord};
pub use registry::{AgentRecord, AgentRegistry, AgentView};
pub use server::serve;
pub use tokens::{TokenInfo, TokenStore};

/// The shared EDR state: fleet registry, command queue, and enrollment tokens.
/// Held by the gRPC gateway and by the API so the control surface (list agents,
/// enqueue actions, manage tokens) and the data plane share one source of truth.
pub struct EdrState {
    pub registry: Arc<AgentRegistry>,
    pub queue: Arc<CommandQueue>,
    pub tokens: Arc<TokenStore>,
}

impl EdrState {
    /// Build the EDR state over a durable [`Store`], seeding any config-provided
    /// enrollment tokens.
    pub fn new(
        store: Arc<Store>,
        enrollment_tokens: &[String],
    ) -> sigil_core::Result<Arc<EdrState>> {
        let registry = AgentRegistry::new(store.clone());
        let tokens = TokenStore::new(store.clone());
        tokens.seed(enrollment_tokens)?;
        let queue = CommandQueue::new(store, registry.clone());
        Ok(Arc::new(EdrState {
            registry,
            queue,
            tokens,
        }))
    }
}
