//! Storage error types.

use thiserror::Error;
use uuid::Uuid;

/// Errors from storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The requested agent was not found.
    #[error("agent not found: {0}")]
    AgentNotFound(Uuid),

    /// The requested session was not found.
    #[error("session not found: {0}")]
    SessionNotFound(Uuid),

    /// The requested delegation link was not found.
    #[error("delegation link not found: from={from}, to={to}")]
    DelegationNotFound { from: Uuid, to: Uuid },

    /// A database or backend error occurred.
    #[error("backend error: {0}")]
    Backend(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Migration error during schema setup.
    #[error("migration error: {0}")]
    Migration(String),

    /// Connection pool error.
    #[error("connection error: {0}")]
    Connection(String),

    /// Field-level encryption or decryption error.
    #[error("encryption error: {0}")]
    Encryption(String),
}

#[cfg(feature = "sqlite")]
impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        StorageError::Backend(err.to_string())
    }
}

#[cfg(feature = "sqlite")]
impl From<sqlx::migrate::MigrateError> for StorageError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        StorageError::Migration(err.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

impl From<crate::encryption::EncryptionError> for StorageError {
    fn from(err: crate::encryption::EncryptionError) -> Self {
        StorageError::Encryption(err.to_string())
    }
}
