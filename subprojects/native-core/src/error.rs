use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("policy denied: {0}")]
    Denied(String),
    #[error("resource limit exceeded: {0}")]
    Limit(String),
    #[error("upstream failure: {0}")]
    Upstream(String),
    #[error("audit is unavailable")]
    AuditUnavailable,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
