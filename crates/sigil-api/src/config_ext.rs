//! Structured platform-config helpers for the Configuration Studio.
//!
//! The form editor works over a **structured** `Config` (not raw YAML), so
//! secrets must never reach the browser. These helpers:
//! - [`redact`] blanks secret fields before sending a `Config` to the client;
//! - [`merge_secrets`] fills blank secrets back from the on-disk config on save
//!   ("leave blank keeps the existing value");
//! - [`redact_yaml`] / [`restore_yaml`] hide/restore secrets in the raw-YAML
//!   view (comments preserved) via field-identified placeholders;
//! - [`meta`] exposes the enum lists that drive the form's selects.
//!
//! Secret fields: `auth.jwt_secret`, `auth.users[].password`/`password_hash`,
//! `edr.enrollment_tokens`.

use sigil_config::{Config, IMPLEMENTED_INPUTS, KNOWN_CODECS, KNOWN_SINKS};

const JWT_PH: &str = "<redacted:jwt_secret>";

fn user_hash_ph(u: &str) -> String {
    format!("<redacted:user:{u}:password_hash>")
}
fn user_pw_ph(u: &str) -> String {
    format!("<redacted:user:{u}:password>")
}
fn token_ph(i: usize) -> String {
    format!("<redacted:edr_token:{i}>")
}

/// A clone of `cfg` with every secret field blanked (for the structured form).
pub fn redact(cfg: &Config) -> Config {
    let mut c = cfg.clone();
    c.auth.jwt_secret = String::new();
    for u in &mut c.auth.users {
        u.password = None;
        u.password_hash = None;
    }
    c.edr.enrollment_tokens = Vec::new();
    c
}

/// Fill blank secrets in `new` from `current` so the form never resends them.
/// Users are matched by `username`; enrollment tokens are kept wholesale (they
/// are managed on the EDR page, not the Studio).
pub fn merge_secrets(mut new: Config, current: &Config) -> Config {
    if new.auth.jwt_secret.trim().is_empty() {
        new.auth.jwt_secret = current.auth.jwt_secret.clone();
    }
    for u in &mut new.auth.users {
        if u.password.is_none() && u.password_hash.is_none() {
            if let Some(cur) = current.auth.users.iter().find(|c| c.username == u.username) {
                u.password = cur.password.clone();
                u.password_hash = cur.password_hash.clone();
            }
        }
    }
    if new.edr.enrollment_tokens.is_empty() {
        new.edr.enrollment_tokens = current.edr.enrollment_tokens.clone();
    }
    new
}

/// Replace real secret values in raw YAML text with placeholders, preserving
/// all comments and formatting.
pub fn redact_yaml(yaml: &str, cfg: &Config) -> String {
    let mut out = yaml.to_string();
    let jwt = cfg.auth.jwt_secret.trim();
    if !jwt.is_empty() {
        out = out.replace(jwt, JWT_PH);
    }
    for u in &cfg.auth.users {
        if let Some(h) = u.password_hash.as_deref().filter(|s| !s.is_empty()) {
            out = out.replace(h, &user_hash_ph(&u.username));
        }
        if let Some(p) = u.password.as_deref().filter(|s| !s.is_empty()) {
            out = out.replace(p, &user_pw_ph(&u.username));
        }
    }
    for (i, t) in cfg.edr.enrollment_tokens.iter().enumerate() {
        if !t.is_empty() {
            out = out.replace(t, &token_ph(i));
        }
    }
    out
}

/// Restore placeholders in submitted raw YAML back to the on-disk secrets.
pub fn restore_yaml(yaml: &str, current: &Config) -> String {
    let mut out = yaml.replace(JWT_PH, &current.auth.jwt_secret);
    for u in &current.auth.users {
        if let Some(h) = &u.password_hash {
            out = out.replace(&user_hash_ph(&u.username), h);
        }
        if let Some(p) = &u.password {
            out = out.replace(&user_pw_ph(&u.username), p);
        }
    }
    for (i, t) in current.edr.enrollment_tokens.iter().enumerate() {
        out = out.replace(&token_ph(i), t);
    }
    out
}

/// Enum metadata that drives the form's selects + secret-presence hints.
pub fn meta(cfg: &Config) -> serde_json::Value {
    serde_json::json!({
        "input_kinds": IMPLEMENTED_INPUTS,
        "codecs": KNOWN_CODECS,
        "sinks": KNOWN_SINKS,
        "roles": ["viewer", "analyst", "admin"],
        "cluster_roles": ["ingest", "index", "correlate", "query", "coordinator", "all"],
        "transports": ["inproc", "redpanda", "nats"],
        "edr_token_count": cfg.edr.enrollment_tokens.len(),
        "jwt_secret_set": !cfg.auth.jwt_secret.trim().is_empty(),
        "users_with_password": cfg.auth.users.iter()
            .filter(|u| u.password.is_some() || u.password_hash.is_some())
            .map(|u| u.username.clone())
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_yaml() -> &'static str {
        r#"
version: 1
auth:
  enabled: true
  jwt_secret: super-secret-key
  users:
    - username: admin
      password_hash: $argon2id$v=19$abc
      roles: [admin]
edr:
  enabled: true
  enrollment_tokens: ["tok-aaaa", "tok-bbbb"]
"#
    }

    #[test]
    fn redact_blanks_all_secrets() {
        let cfg = Config::parse(cfg_yaml()).unwrap();
        let r = redact(&cfg);
        assert_eq!(r.auth.jwt_secret, "");
        assert!(r.auth.users[0].password_hash.is_none());
        assert!(r.edr.enrollment_tokens.is_empty());
    }

    #[test]
    fn merge_restores_blank_secrets_from_current() {
        let current = Config::parse(cfg_yaml()).unwrap();
        let incoming = redact(&current); // form sends blanks
        let merged = merge_secrets(incoming, &current);
        assert_eq!(merged.auth.jwt_secret, "super-secret-key");
        assert_eq!(
            merged.auth.users[0].password_hash.as_deref(),
            Some("$argon2id$v=19$abc")
        );
        assert_eq!(merged.edr.enrollment_tokens, vec!["tok-aaaa", "tok-bbbb"]);
    }

    #[test]
    fn merge_keeps_newly_set_secret() {
        let current = Config::parse(cfg_yaml()).unwrap();
        let mut incoming = redact(&current);
        incoming.auth.jwt_secret = "rotated-key".into();
        let merged = merge_secrets(incoming, &current);
        assert_eq!(merged.auth.jwt_secret, "rotated-key");
    }

    #[test]
    fn raw_redact_restore_round_trips() {
        let cfg = Config::parse(cfg_yaml()).unwrap();
        let raw = cfg_yaml();
        let redacted = redact_yaml(raw, &cfg);
        assert!(!redacted.contains("super-secret-key"));
        assert!(!redacted.contains("tok-aaaa"));
        assert!(redacted.contains(JWT_PH));
        let restored = restore_yaml(&redacted, &cfg);
        assert!(restored.contains("super-secret-key"));
        assert!(restored.contains("tok-aaaa"));
        assert!(restored.contains("tok-bbbb"));
    }
}
