//! `sigil-plugin-wasm` — WASM plugin host + capability model (DESIGN §12).
//!
//! The Tier-2 extension story: community/untrusted plugins run sandboxed under
//! [wasmtime] with **capability-based permissions** (DESIGN §12.2).
//!
//! - [`manifest`] — the plugin manifest (identity + requested capabilities).
//! - [`capability`] — capability parsing + a deny-by-default [`CapabilityPolicy`].
//! - [`host`] — the wasmtime host (behind the default `runtime` feature):
//!   capability-gated instantiation + sandboxed execution. The WIT interface
//!   for the full Component Model lives in `wit/processor.wit`.
//!
//! [wasmtime]: https://wasmtime.dev/

pub mod capability;
pub mod manifest;

#[cfg(feature = "runtime")]
pub mod host;

pub use capability::{capability_str, parse_capability, CapabilityPolicy};
pub use manifest::WasmManifest;
pub use sigil_core::Capability;

#[cfg(feature = "runtime")]
pub use host::{HostCtx, LoadedPlugin, PluginSource, WasmHost};
