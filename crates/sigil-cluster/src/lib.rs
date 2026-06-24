//! `sigil-cluster` — roles, transport, and the shard catalog (DESIGN §4).
//!
//! Phase 5 delivers the "monolith that scales" scaffolding:
//! - [`role`] — config-selectable [`Role`]s; a monolith runs them all.
//! - [`transport`] — a [`Transport`] trait with an in-proc bus
//!   ([`InProcBus`]); Redpanda/Kafka + NATS slot in behind it (ADR-2).
//! - [`shard`] — [`ShardMap`]: time+hash sharding and node placement.
//!
//! Real Raft consensus (`openraft`) for replicating the catalog/membership is
//! the distributed swap; the shard map + placement logic here is its data model.

pub mod role;
pub mod shard;
pub mod transport;

pub use role::{Role, RoleSet};
pub use shard::{NodeId, ShardId, ShardMap};
pub use transport::{build_transport, InProcBus, Transport, TransportKind};
