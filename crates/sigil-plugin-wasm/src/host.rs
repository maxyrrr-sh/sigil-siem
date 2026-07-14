//! WASM plugin host (DESIGN §12.2): load and run sandboxed plugins with
//! [wasmtime]. Instantiation is **capability-gated** — a plugin whose manifest
//! requests a capability the policy doesn't grant is refused before it runs,
//! and the sandbox grants no ambient host imports (deny-by-default).
//!
//! Phase 5 runs core WASM modules; the full Component Model + WIT bindings
//! (see `wit/processor.wit`) are the next step.
//!
//! [wasmtime]: https://wasmtime.dev/

use sigil_core::{Capability, Error, Result};
use wasmtime::{Engine, Instance, Linker, Module, Store};

use crate::capability::CapabilityPolicy;
use crate::manifest::WasmManifest;
use crate::signature::SignaturePolicy;

fn backend<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// Source for a plugin module: WAT text (tests/dev) or wasm bytes.
pub enum PluginSource {
    Wat(String),
    Wasm(Vec<u8>),
}

/// Per-instance host state: the capabilities actually granted to this plugin.
pub struct HostCtx {
    pub granted: Vec<Capability>,
}

/// The WASM host: owns a shared wasmtime engine + the signing policy.
pub struct WasmHost {
    engine: Engine,
    signatures: SignaturePolicy,
}

impl Default for WasmHost {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmHost {
    pub fn new() -> Self {
        WasmHost {
            engine: Engine::default(),
            signatures: SignaturePolicy::default(),
        }
    }

    /// Enforce plugin signing: only modules signed by one of the policy's
    /// trusted keys will instantiate (DESIGN §12.4).
    pub fn with_signature_policy(mut self, signatures: SignaturePolicy) -> Self {
        self.signatures = signatures;
        self
    }

    /// Instantiate a plugin after enforcing its capability requests against
    /// the policy and (when enforced) its signature against the trusted keys.
    /// Errors (without running anything) on any denial.
    pub fn instantiate(
        &self,
        manifest: &WasmManifest,
        policy: &CapabilityPolicy,
        source: &PluginSource,
    ) -> Result<LoadedPlugin> {
        let requested = manifest.requested_capabilities()?;
        if let Err(denied) = policy.check(&requested) {
            return Err(Error::Other(format!(
                "plugin `{}` denied capabilities: {}",
                manifest.name,
                denied.join(", ")
            )));
        }

        let bytes = match source {
            PluginSource::Wat(text) => wat::parse_str(text).map_err(backend)?,
            PluginSource::Wasm(b) => b.clone(),
        };
        // The signature covers the final wasm bytes we are about to compile.
        self.signatures
            .verify(&bytes, manifest.signature.as_deref())
            .map_err(|e| Error::Other(format!("plugin `{}`: {e}", manifest.name)))?;
        let module = Module::new(&self.engine, &bytes).map_err(backend)?;

        let mut store = Store::new(&self.engine, HostCtx { granted: requested });
        // Empty linker = no ambient capabilities. Capability-gated host
        // functions would be added here based on `store.data().granted`.
        let linker: Linker<HostCtx> = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, &module).map_err(backend)?;

        Ok(LoadedPlugin { store, instance })
    }
}

/// A live, sandboxed plugin instance.
pub struct LoadedPlugin {
    store: Store<HostCtx>,
    instance: Instance,
}

impl LoadedPlugin {
    /// Call an exported `(i32) -> i32` function (the simple processor shape used
    /// before full Component Model bindings).
    pub fn call_i32(&mut self, func: &str, arg: i32) -> Result<i32> {
        let f = self
            .instance
            .get_typed_func::<i32, i32>(&mut self.store, func)
            .map_err(backend)?;
        f.call(&mut self.store, arg).map_err(backend)
    }

    /// Capabilities granted to this instance.
    pub fn granted(&self) -> &[Capability] {
        &self.store.data().granted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCESS_WAT: &str = r#"
        (module
          (func (export "process") (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.add))
    "#;

    fn manifest(caps: &[&str]) -> WasmManifest {
        WasmManifest {
            name: "demo".into(),
            version: "0.0.0".into(),
            kind: "wasm".into(),
            path: None,
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            signature: None,
        }
    }

    #[test]
    fn runs_sandboxed_module() {
        let host = WasmHost::new();
        let policy = CapabilityPolicy::default();
        let mut plugin = host
            .instantiate(
                &manifest(&[]),
                &policy,
                &PluginSource::Wat(PROCESS_WAT.into()),
            )
            .unwrap();
        assert_eq!(plugin.call_i32("process", 41).unwrap(), 42);
    }

    #[test]
    fn denies_ungranted_capabilities_before_running() {
        let host = WasmHost::new();
        let policy = CapabilityPolicy::default(); // grants nothing
        let result = host.instantiate(
            &manifest(&["net:egress"]),
            &policy,
            &PluginSource::Wat(PROCESS_WAT.into()),
        );
        match result {
            Err(e) => assert!(e.to_string().contains("denied capabilities")),
            Ok(_) => panic!("expected capability denial"),
        }
    }

    #[test]
    fn signature_policy_gates_instantiation() {
        use crate::signature::{public_key_hex, sign_module, SignaturePolicy};

        let secret = [3u8; 32];
        let host = WasmHost::new().with_signature_policy(
            SignaturePolicy::from_hex_keys(&[public_key_hex(&secret)]).unwrap(),
        );
        let policy = CapabilityPolicy::default();

        // Unsigned plugin: refused before compiling.
        let err = match host.instantiate(
            &manifest(&[]),
            &policy,
            &PluginSource::Wat(PROCESS_WAT.into()),
        ) {
            Err(e) => e,
            Ok(_) => panic!("unsigned plugin must be refused"),
        };
        assert!(err.to_string().contains("unsigned"));

        // Correctly signed plugin (signature covers the compiled wasm bytes).
        let wasm = wat::parse_str(PROCESS_WAT).unwrap();
        let mut m = manifest(&[]);
        m.signature = Some(sign_module(&secret, &wasm));
        let mut plugin = host
            .instantiate(&m, &policy, &PluginSource::Wasm(wasm.clone()))
            .unwrap();
        assert_eq!(plugin.call_i32("process", 41).unwrap(), 42);

        // Signature from an untrusted key: refused.
        m.signature = Some(sign_module(&[8u8; 32], &wasm));
        assert!(host
            .instantiate(&m, &policy, &PluginSource::Wasm(wasm))
            .is_err());
    }

    #[test]
    fn runs_when_capability_is_granted() {
        let host = WasmHost::new();
        let policy = CapabilityPolicy::from_strings(&["net:egress".into()]).unwrap();
        let plugin = host
            .instantiate(
                &manifest(&["net:egress"]),
                &policy,
                &PluginSource::Wat(PROCESS_WAT.into()),
            )
            .unwrap();
        assert_eq!(plugin.granted().len(), 1);
    }
}
