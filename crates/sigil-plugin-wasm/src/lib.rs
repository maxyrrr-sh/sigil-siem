//! `sigil-plugin-wasm` — WASM plugin host + capability model (DESIGN §12).
//!
//! The Tier-2 extension story: community/untrusted plugins run sandboxed under
//! [wasmtime] with **capability-based permissions** (DESIGN §12.2).
//!
//! - [`manifest`] — the plugin manifest (identity + requested capabilities).
//! - [`capability`] — capability parsing + a deny-by-default [`CapabilityPolicy`].
//! - [`signature`] — ed25519 plugin signing: a [`SignaturePolicy`] of trusted
//!   publisher keys, enforced before instantiation (DESIGN §12.4).
//! - [`host`] — the wasmtime host (behind the default `runtime` feature):
//!   capability- and signature-gated instantiation + sandboxed execution. The
//!   WIT interface for the full Component Model lives in `wit/processor.wit`.
//!
//! [wasmtime]: https://wasmtime.dev/

pub mod capability;
pub mod manifest;
pub mod signature;

#[cfg(feature = "runtime")]
pub mod host;

pub use capability::{capability_str, parse_capability, CapabilityPolicy};
pub use manifest::WasmManifest;
pub use sigil_core::Capability;
pub use signature::{public_key_hex, sign_module, SignaturePolicy};

#[cfg(feature = "runtime")]
pub use host::{HostCtx, LoadedPlugin, PluginSource, WasmHost};
