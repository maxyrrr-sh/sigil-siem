//! Local JWT authentication + role-based access control (DESIGN §14).
//!
//! Ships a **local-credentials** provider: users are declared in config with an
//! argon2 `password_hash` (preferred) or, for dev, a plaintext `password`. A
//! successful `POST /auth/login` mints an HS256 JWT carrying the user's roles; a
//! middleware verifies the bearer token on every `/api/v1` request and injects
//! an [`AuthUser`] extension. The surface is structured so an OIDC provider can
//! drop in later without changing handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sigil_config::AuthConfig;

/// An access role. Ordering is privilege: `Viewer < Analyst < Admin`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    Viewer,
    Analyst,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s.to_ascii_lowercase().as_str() {
            "viewer" => Some(Role::Viewer),
            "analyst" => Some(Role::Analyst),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Analyst => "analyst",
            Role::Admin => "admin",
        }
    }
}

/// The authenticated principal, injected into request extensions by the
/// middleware and extracted by handlers via `Extension<AuthUser>`.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub username: String,
    pub roles: Vec<Role>,
}

impl AuthUser {
    /// True if the user holds `role` or anything more privileged.
    pub fn has(&self, role: Role) -> bool {
        self.roles.iter().any(|r| *r >= role)
    }

    /// The implicit principal when auth is disabled (full privilege).
    fn system() -> Self {
        AuthUser {
            username: "system".into(),
            roles: vec![Role::Admin],
        }
    }
}

/// JWT body.
#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
    exp: usize,
}

struct UserCred {
    password_hash: Option<String>,
    password: Option<String>,
    roles: Vec<Role>,
}

/// Shared authentication state: signing keys, token lifetime, and the user table.
pub struct AuthState {
    pub enabled: bool,
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: u64,
    users: HashMap<String, UserCred>,
}

impl AuthState {
    /// Build from the `[auth]` config block. An empty `jwt_secret` yields an
    /// ephemeral random secret (tokens then don't survive a restart).
    pub fn from_config(cfg: &AuthConfig) -> AuthState {
        let secret: Vec<u8> = if cfg.jwt_secret.trim().is_empty() {
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s.to_vec()
        } else {
            cfg.jwt_secret.as_bytes().to_vec()
        };
        let users = cfg
            .users
            .iter()
            .map(|u| {
                (
                    u.username.clone(),
                    UserCred {
                        password_hash: u.password_hash.clone(),
                        password: u.password.clone(),
                        roles: u.roles.iter().filter_map(|r| Role::parse(r)).collect(),
                    },
                )
            })
            .collect();
        AuthState {
            enabled: cfg.enabled,
            encoding: EncodingKey::from_secret(&secret),
            decoding: DecodingKey::from_secret(&secret),
            ttl: cfg.token_ttl_secs,
            users,
        }
    }

    /// Verify a username/password against the user table.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<AuthUser> {
        let cred = self.users.get(username)?;
        let ok = if let Some(hash) = &cred.password_hash {
            verify_password(password, hash)
        } else if let Some(plain) = &cred.password {
            constant_time_eq(password.as_bytes(), plain.as_bytes())
        } else {
            false
        };
        if !ok {
            return None;
        }
        Some(AuthUser {
            username: username.to_string(),
            roles: cred.roles.clone(),
        })
    }

    /// Mint a signed JWT for an authenticated user.
    pub fn issue(&self, user: &AuthUser) -> Result<String, Response> {
        let exp = (now_secs() + self.ttl) as usize;
        let claims = Claims {
            sub: user.username.clone(),
            roles: user.roles.iter().map(|r| r.as_str().to_string()).collect(),
            exp,
        };
        encode(&Header::default(), &claims, &self.encoding).map_err(|e| {
            tracing::error!(error = %e, "token signing failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "token signing failed").into_response()
        })
    }

    /// Token lifetime in seconds (for the login response).
    pub fn ttl(&self) -> u64 {
        self.ttl
    }

    fn verify(&self, token: &str) -> Option<AuthUser> {
        let data = decode::<Claims>(token, &self.decoding, &Validation::default()).ok()?;
        Some(AuthUser {
            username: data.claims.sub,
            roles: data
                .claims
                .roles
                .iter()
                .filter_map(|r| Role::parse(r))
                .collect(),
        })
    }
}

/// Hash a plaintext password into an argon2 PHC string (used by `sigil auth hash`).
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Axum middleware: validate the bearer token (or `?token=` for SSE) and inject
/// [`AuthUser`]. When auth is disabled, every request runs as `system`.
pub async fn require_auth(
    State(auth): State<Arc<AuthState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if !auth.enabled {
        req.extensions_mut().insert(AuthUser::system());
        return next.run(req).await;
    }
    match extract_token(&req).and_then(|t| auth.verify(&t)) {
        Some(user) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid token" })),
        )
            .into_response(),
    }
}

/// Pull a token from the `Authorization: Bearer` header, or a `token` query
/// parameter (browsers' `EventSource` cannot set headers, so SSE uses the query).
fn extract_token(req: &Request<Body>) -> Option<String> {
    if let Some(h) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(s) = h.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
        }
    }
    let query = req.uri().query()?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("token=") {
            return Some(v.to_string());
        }
    }
    None
}

/// Guard a handler: return `403` unless the user holds `role`.
pub fn require(user: &AuthUser, role: Role) -> Result<(), Response> {
    if user.has(role) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!("requires `{}` role", role.as_str())
            })),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_config::{AuthConfig, UserConfig};

    fn state() -> AuthState {
        AuthState::from_config(&AuthConfig {
            enabled: true,
            jwt_secret: "test-secret".into(),
            token_ttl_secs: 3600,
            users: vec![
                UserConfig {
                    username: "admin".into(),
                    password_hash: Some(hash_password("hunter2").unwrap()),
                    password: None,
                    roles: vec!["admin".into()],
                },
                UserConfig {
                    username: "viewer".into(),
                    password_hash: None,
                    password: Some("plain".into()),
                    roles: vec!["viewer".into()],
                },
            ],
        })
    }

    #[test]
    fn argon2_login_and_token_roundtrip() {
        let s = state();
        let user = s.authenticate("admin", "hunter2").expect("login ok");
        assert!(user.has(Role::Analyst)); // admin >= analyst
        let token = s.issue(&user).unwrap();
        let back = s.verify(&token).unwrap();
        assert_eq!(back.username, "admin");
        assert!(back.has(Role::Admin));
    }

    #[test]
    fn wrong_password_and_plaintext_path() {
        let s = state();
        assert!(s.authenticate("admin", "nope").is_none());
        assert!(s.authenticate("viewer", "plain").is_some());
        assert!(s.authenticate("ghost", "x").is_none());
    }

    #[test]
    fn rbac_blocks_insufficient_role() {
        let viewer = AuthUser {
            username: "v".into(),
            roles: vec![Role::Viewer],
        };
        assert!(require(&viewer, Role::Viewer).is_ok());
        assert!(require(&viewer, Role::Analyst).is_err());
    }
}
