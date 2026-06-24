//! `sigil-core` — foundational types and plugin traits for **Sigil SIEM**.
//!
//! This crate is the contract shared by every other crate: the normalized
//! [`Event`] model (OCSF-aligned, DESIGN §6) and the plugin extension traits
//! ([`Input`], [`Codec`], [`Processor`], [`Detector`], [`Correlator`],
//! [`PathSelector`], [`Output`], [`StorageBackend`], DESIGN §12).
//!
//! Keep this crate dependency-light — it is the root of the dependency graph.

pub mod error;
pub mod event;
pub mod plugin;

pub use error::{Error, Result};
pub use event::{
    now_micros, value_to_string, EntityRef, Event, OcsfClass, Record, Severity, Timestamp,
};
pub use plugin::{
    Alert, AttackChain, Capability, CausalEdge, CausalGraph, CausalNode, Codec, Correlator,
    Detector, IncidentDelta, Input, Output, PathSelector, Plugin, PluginManifest, Processor,
    StorageBackend,
};
