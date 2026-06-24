//! Shared error type for Sigil. Per-crate errors convert into this at module
//! boundaries; `sigil-core` itself stays dependency-light (DESIGN §12).

use thiserror::Error;

/// The crate-wide error type.
#[derive(Debug, Error)]
pub enum Error {
    /// A record/event could not be parsed or decoded.
    #[error("parse error: {0}")]
    Parse(String),

    /// A normalized field was missing or had the wrong shape.
    #[error("schema error: {0}")]
    Schema(String),

    /// Configuration was invalid (shape or semantics).
    #[error("config error: {0}")]
    Config(String),

    /// An I/O operation failed.
    #[error("io error: {0}")]
    Io(String),

    /// A backend (index, graph, sidecar, ...) failed.
    #[error("backend error: {0}")]
    Backend(String),

    /// Catch-all for anything not yet given a dedicated variant.
    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(e.to_string())
    }
}

/// Convenience result type used across the workspace.
pub type Result<T> = std::result::Result<T, Error>;
