//! Credential error types.

use thiserror::Error;

/// Errors that can occur during credential resolution or injection.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// The requested credential reference was not found.
    #[error("credential not found: {0}")]
    NotFound(String),

    /// The underlying provider encountered an error.
    #[error("provider error: {0}")]
    ProviderError(String),

    /// Decryption of the credential store failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// The credential reference is malformed.
    #[error("invalid reference: {0}")]
    InvalidReference(String),
}
