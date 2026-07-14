//! `sigil-cluster` — roles, transport, and the shard catalog (DESIGN §4).
//!
//! Phase 5 delivers the "monolith that scales" scaffolding:
//! - [`role`] — config-selectable [`Role`]s; a monolith runs them all.
//! - [`transport`] — a [`Transport`] trait with an in-proc bus
//!   ([`InProcBus`]); Redpanda/Kafka + NATS slot in behind it (ADR-2).
//! - [`shard`] — [`ShardMap`]: time+hash sharding and node placement.
//! - [`raft`] — Raft consensus for the cluster catalog: a deterministic
//!   [`RaftNode`] state machine + a [`RaftDriver`] that binds it to any
//!   transport (in-proc for tests/monolith, TCP for real clusters).

pub mod raft;
pub mod role;
pub mod shard;
pub mod transport;

pub use raft::{LogEntry, RaftDriver, RaftNode};
pub use role::{Role, RoleSet};
pub use shard::{NodeId, ShardId, ShardMap};
pub use transport::{build_transport, InProcBus, TcpBus, Transport, TransportKind};
