//! Enrollment-token store. A pre-shared enrollment token is what an agent
//! presents (once) to `Enroll`. Tokens are persisted as `sigil-store` saved
//! objects of kind `edr-token` so they survive restarts and can be issued /
//! revoked at runtime via the admin API. Config-seeded tokens are inserted at
//! startup.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sigil_core::{now_micros, Result, Timestamp};
use sigil_store::{SavedObject, Store};

/// Saved-object kind for enrollment tokens.
pub const TOKEN_KIND: &str = "edr-token";

/// A pre-shared enrollment token record. The token value is the id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token: String,
    pub label: String,
    pub created_ts: Timestamp,
    #[serde(default)]
    pub created_by: Option<String>,
}

/// A public view (never exposes the raw token except right after issuance).
#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    /// First 8 chars, for identification without leaking the secret.
    pub prefix: String,
    pub label: String,
    pub created_ts: Timestamp,
    pub created_by: Option<String>,
}

/// Runtime enrollment-token store backed by [`Store`].
pub struct TokenStore {
    store: Arc<Store>,
}

impl TokenStore {
    pub fn new(store: Arc<Store>) -> Arc<TokenStore> {
        Arc::new(TokenStore { store })
    }

    /// Insert config-provided tokens if absent (idempotent).
    pub fn seed(&self, tokens: &[String]) -> Result<()> {
        for t in tokens {
            if t.is_empty() {
                continue;
            }
            if self.store.get_saved(TOKEN_KIND, t)?.is_none() {
                self.write(&TokenRecord {
                    token: t.clone(),
                    label: "config".into(),
                    created_ts: now_micros(),
                    created_by: Some("config".into()),
                })?;
            }
        }
        Ok(())
    }

    /// Mint a new random enrollment token, returning its raw value.
    pub fn issue(&self, label: &str, created_by: Option<String>) -> Result<String> {
        let token = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
        self.write(&TokenRecord {
            token: token.clone(),
            label: label.to_string(),
            created_ts: now_micros(),
            created_by,
        })?;
        Ok(token)
    }

    /// True if `token` is a known, non-empty enrollment token.
    pub fn valid(&self, token: &str) -> Result<bool> {
        Ok(!token.is_empty() && self.store.get_saved(TOKEN_KIND, token)?.is_some())
    }

    /// Revoke a token. Returns whether it existed.
    pub fn revoke(&self, token: &str) -> Result<bool> {
        self.store.delete_saved(TOKEN_KIND, token)
    }

    /// List issued tokens (prefixes only), newest first.
    pub fn list(&self) -> Result<Vec<TokenInfo>> {
        let mut out: Vec<TokenInfo> = self
            .store
            .list_saved(TOKEN_KIND)?
            .into_iter()
            .filter_map(|o| serde_json::from_value::<TokenRecord>(o.body).ok())
            .map(|r| TokenInfo {
                prefix: r.token.chars().take(8).collect(),
                label: r.label,
                created_ts: r.created_ts,
                created_by: r.created_by,
            })
            .collect();
        out.sort_by_key(|t| std::cmp::Reverse(t.created_ts));
        Ok(out)
    }

    fn write(&self, rec: &TokenRecord) -> Result<()> {
        let obj = SavedObject {
            kind: TOKEN_KIND.into(),
            id: rec.token.clone(),
            name: rec.label.clone(),
            owner: rec.created_by.clone(),
            updated_ts: rec.created_ts,
            body: serde_json::to_value(rec)
                .map_err(|e| sigil_core::Error::Backend(e.to_string()))?,
        };
        self.store.put_saved(&obj)
    }
}
