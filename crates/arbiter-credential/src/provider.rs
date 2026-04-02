//! The `CredentialProvider` trait and supporting types.
//!
//! Every credential backend (file, env-var, vault, etc.) implements this trait
//! so the injection middleware can resolve references without knowing the
//! storage details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::CredentialError;

/// Metadata about a single credential reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRef {
    /// The reference name used to look up this credential.
    pub name: String,

    /// Which provider owns this credential ("file", "env", "vault", etc.).
    pub provider: String,

    /// When the credential was last rotated, if known.
    pub last_rotated: Option<DateTime<Utc>>,
}

/// A provider capable of resolving credential references to their secret values.
///
/// Resolved values are returned as [`SecretString`] to ensure they are zeroized
/// on drop and never accidentally logged via `Debug` or `Display`.
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Resolve a reference name to the corresponding secret value.
    async fn resolve(&self, reference: &str) -> Result<SecretString, CredentialError>;

    /// List all credential references available from this provider.
    async fn list_refs(&self) -> Result<Vec<CredentialRef>, CredentialError>;
}
