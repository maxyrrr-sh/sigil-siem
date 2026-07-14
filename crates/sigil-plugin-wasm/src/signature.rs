//! Plugin signature verification (DESIGN §12.4): a manifest's detached
//! `signature` is an ed25519 signature (hex) over the raw `.wasm` module
//! bytes, checked against a set of trusted publisher keys before anything is
//! compiled or instantiated. Like capabilities, this is deny-by-default once
//! a policy is configured: unsigned plugins and unknown signers are refused.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sigil_core::{Error, Result};

/// Trusted plugin-publisher keys. An empty policy means signing is not
/// enforced (dev mode); any configured key makes a valid signature mandatory.
#[derive(Debug, Clone, Default)]
pub struct SignaturePolicy {
    keys: Vec<VerifyingKey>,
}

impl SignaturePolicy {
    /// Build from hex-encoded 32-byte ed25519 public keys.
    pub fn from_hex_keys<S: AsRef<str>>(keys: &[S]) -> Result<SignaturePolicy> {
        let keys = keys
            .iter()
            .map(|k| {
                let bytes: [u8; 32] = decode_hex(k.as_ref())?
                    .try_into()
                    .map_err(|_| Error::Config("public key must be 32 bytes".into()))?;
                VerifyingKey::from_bytes(&bytes)
                    .map_err(|e| Error::Config(format!("invalid ed25519 public key: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(SignaturePolicy { keys })
    }

    /// Is signing enforced?
    pub fn required(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Verify `signature_hex` (from the manifest) over the module bytes.
    /// Accepts a signature from any trusted key. A no-key policy accepts
    /// everything; otherwise a missing signature is an error.
    pub fn verify(&self, module: &[u8], signature_hex: Option<&str>) -> Result<()> {
        if !self.required() {
            return Ok(());
        }
        let sig_hex = signature_hex
            .ok_or_else(|| Error::Other("plugin is unsigned but signing is enforced".into()))?;
        let sig_bytes: [u8; 64] = decode_hex(sig_hex)?
            .try_into()
            .map_err(|_| Error::Config("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        if self.keys.iter().any(|k| k.verify(module, &sig).is_ok()) {
            Ok(())
        } else {
            Err(Error::Other(
                "plugin signature does not verify against any trusted key".into(),
            ))
        }
    }
}

/// Sign module bytes with a raw 32-byte ed25519 secret key, returning the
/// hex signature for the manifest. (Publisher-side helper; the host only
/// ever verifies.)
pub fn sign_module(secret_key: &[u8; 32], module: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    encode_hex(&key.sign(module).to_bytes())
}

/// The hex public key paired with a raw 32-byte secret key.
pub fn public_key_hex(secret_key: &[u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    encode_hex(key.verifying_key().as_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let pairs = s.as_bytes().chunks_exact(2);
    if !pairs.remainder().is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Config("invalid hex string".into()));
    }
    pairs
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ascii checked"), 16)
                .map_err(|_| Error::Config("invalid hex string".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];
    const MODULE: &[u8] = b"\0asm fake module bytes";

    #[test]
    fn signed_module_verifies() {
        let sig = sign_module(&SECRET, MODULE);
        let policy = SignaturePolicy::from_hex_keys(&[public_key_hex(&SECRET)]).unwrap();
        assert!(policy.required());
        policy.verify(MODULE, Some(&sig)).unwrap();
    }

    #[test]
    fn tampered_module_or_wrong_key_fails() {
        let sig = sign_module(&SECRET, MODULE);
        let policy = SignaturePolicy::from_hex_keys(&[public_key_hex(&SECRET)]).unwrap();
        assert!(policy.verify(b"tampered", Some(&sig)).is_err());

        let other = SignaturePolicy::from_hex_keys(&[public_key_hex(&[9u8; 32])]).unwrap();
        assert!(other.verify(MODULE, Some(&sig)).is_err());
    }

    #[test]
    fn unsigned_is_refused_only_when_enforced() {
        let open = SignaturePolicy::default();
        assert!(!open.required());
        open.verify(MODULE, None).unwrap();

        let strict = SignaturePolicy::from_hex_keys(&[public_key_hex(&SECRET)]).unwrap();
        assert!(strict.verify(MODULE, None).is_err());
    }

    #[test]
    fn rejects_malformed_keys_and_signatures() {
        assert!(SignaturePolicy::from_hex_keys(&["zz"]).is_err());
        assert!(SignaturePolicy::from_hex_keys(&["abcd"]).is_err()); // wrong length
        let policy = SignaturePolicy::from_hex_keys(&[public_key_hex(&SECRET)]).unwrap();
        assert!(policy.verify(MODULE, Some("nothex")).is_err());
        assert!(policy.verify(MODULE, Some("abcd")).is_err()); // wrong length
    }
}
