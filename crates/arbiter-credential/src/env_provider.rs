//! Environment-variable credential provider.

use std::env;

use async_trait::async_trait;
use secrecy::SecretString;
use tracing::{debug, warn};

use crate::error::CredentialError;
use crate::provider::{CredentialProvider, CredentialRef};

/// A credential provider that resolves references from environment variables.
pub struct EnvProvider {
    /// Prefix used by `list_refs()` to discover credential env vars.
    prefix: String,
}

impl EnvProvider {
    /// Create a new env provider with the default prefix `ARBITER_CRED_`.
    pub fn new() -> Self {
        Self {
            prefix: "ARBITER_CRED_".into(),
        }
    }

    /// Create a new env provider with a custom prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

impl Default for EnvProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialProvider for EnvProvider {
    async fn resolve(&self, reference: &str) -> Result<SecretString, CredentialError> {
        debug!(reference, "resolving credential from environment");

        if !reference.starts_with(&self.prefix) {
            return Err(CredentialError::NotFound(format!(
                "credential reference '{}' does not match required prefix '{}'",
                reference, self.prefix
            )));
        }

        env::var(reference).map(SecretString::from).map_err(|e| {
            warn!(reference, error = %e, "env var not found");
            CredentialError::NotFound(format!("env var {reference}: {e}"))
        })
    }

    async fn list_refs(&self) -> Result<Vec<CredentialRef>, CredentialError> {
        let refs: Vec<CredentialRef> = env::vars()
            .filter(|(key, _)| key.starts_with(&self.prefix))
            .map(|(key, _)| CredentialRef {
                name: key,
                provider: "env".into(),
                last_rotated: None,
            })
            .collect();

        debug!(count = refs.len(), prefix = %self.prefix, "listed env credential refs");
        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[tokio::test]
    async fn resolves_env_var() {
        let key = "ARBITER_CRED_TEST_RESOLVE_42";
        // SAFETY: test-only, no concurrent env access
        unsafe { env::set_var(key, "secret-value") };

        let provider = EnvProvider::new();
        let value = provider.resolve(key).await.unwrap();
        assert_eq!(value.expose_secret(), "secret-value");

        unsafe { env::remove_var(key) };
    }

    #[tokio::test]
    async fn missing_env_var_is_not_found() {
        let provider = EnvProvider::new();
        let err = provider
            .resolve("ARBITER_CRED_DEFINITELY_DOES_NOT_EXIST_XYZ")
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialError::NotFound(_)));
    }

    #[tokio::test]
    async fn list_refs_filters_by_prefix() {
        let key1 = "ARBITER_CRED_LIST_TEST_A";
        let key2 = "ARBITER_CRED_LIST_TEST_B";
        let key3 = "UNRELATED_VAR_LIST_TEST";
        // SAFETY: test-only, no concurrent env access
        unsafe {
            env::set_var(key1, "a");
            env::set_var(key2, "b");
            env::set_var(key3, "c");
        }

        let provider = EnvProvider::new();
        let refs = provider.list_refs().await.unwrap();

        let names: Vec<_> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&key1));
        assert!(names.contains(&key2));
        assert!(!names.contains(&key3));
        assert!(refs.iter().all(|r| r.provider == "env"));

        unsafe {
            env::remove_var(key1);
            env::remove_var(key2);
            env::remove_var(key3);
        }
    }

    #[tokio::test]
    async fn custom_prefix() {
        let key = "MY_PREFIX_KEY_1";
        // SAFETY: test-only, no concurrent env access
        unsafe { env::set_var(key, "value") };

        let provider = EnvProvider::with_prefix("MY_PREFIX_");
        let refs = provider.list_refs().await.unwrap();
        let names: Vec<_> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&key));

        unsafe { env::remove_var(key) };
    }
}
