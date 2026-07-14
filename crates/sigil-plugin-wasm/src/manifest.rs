//! Plugin manifest (DESIGN §12.2, §12.4): identity, requested capabilities, and
//! an optional signature, loaded from a JSON file shipped with the plugin.

use serde::{Deserialize, Serialize};
use sigil_core::{Capability, Error, Result};

use crate::capability::parse_capability;

/// A WASM plugin's on-disk manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmManifest {
    pub name: String,
    pub version: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Path to the `.wasm` component, relative to the manifest.
    #[serde(default)]
    pub path: Option<String>,
    /// Requested capabilities (capability strings, DESIGN §12.2).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Detached ed25519 signature (hex) over the `.wasm` module bytes,
    /// verified against the host's [`crate::SignaturePolicy`] trusted keys.
    #[serde(default)]
    pub signature: Option<String>,
}

fn default_kind() -> String {
    "wasm".to_string()
}

impl WasmManifest {
    /// Parse a manifest from JSON text.
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::Config(format!("parsing plugin manifest: {e}")))
    }

    /// Load a manifest from a JSON file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("reading manifest {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// The requested capabilities, parsed and validated.
    pub fn requested_capabilities(&self) -> Result<Vec<Capability>> {
        self.capabilities
            .iter()
            .map(|s| parse_capability(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest_and_capabilities() {
        let m = WasmManifest::parse(
            r#"{
                "name": "my_parser",
                "version": "1.0.0",
                "path": "./my_parser.wasm",
                "capabilities": ["read:field:message", "enrich:geoip"]
            }"#,
        )
        .unwrap();
        assert_eq!(m.name, "my_parser");
        assert_eq!(m.kind, "wasm");
        let caps = m.requested_capabilities().unwrap();
        assert_eq!(caps.len(), 2);
    }
}
