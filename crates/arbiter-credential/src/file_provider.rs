//! File-based credential provider.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::CredentialError;
use crate::provider::{CredentialProvider, CredentialRef};

#[derive(Deserialize)]
struct CredentialFile {
    credentials: HashMap<String, String>,
}

// Manual Debug that does not expose credential values.
impl std::fmt::Debug for CredentialFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialFile")
            .field("credentials", &format!("{} entries", self.credentials.len()))
            .finish()
    }
}

pub struct FileProvider {
    credentials: Arc<RwLock<HashMap<String, SecretString>>>,
    source_path: PathBuf,
}

// Manual Debug that does not expose credential values.
impl std::fmt::Debug for FileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileProvider")
            .field("credentials", &"<locked>")
            .field("source_path", &self.source_path)
            .finish()
    }
}

impl FileProvider {
    pub async fn from_path(path: impl AsRef<Path>) -> Result<Self, CredentialError> {
        let path = path.as_ref().to_path_buf();
        info!(path = %path.display(), "loading credential file");

        if path.extension().is_some_and(|ext| ext == "age") {
            return Err(CredentialError::ProviderError(
                "encrypted .age files are not yet supported; \
                 age decryption support is planned (GAP-CRED-1)"
                    .into(),
            ));
        }

        // Emit a security warning for plaintext credential files.
        warn!(
            path = %path.display(),
            "loading PLAINTEXT credential file. Credentials are stored \
             unencrypted on disk. Use encrypted .age files (when supported) \
             or set ARBITER_STORAGE_ENCRYPTION_KEY for at-rest protection."
        );

        let contents = tokio::fs::read_to_string(&path).await.map_err(|e| {
            CredentialError::ProviderError(format!("reading {}: {e}", path.display()))
        })?;

        let parsed: CredentialFile = toml::from_str(&contents).map_err(|e| {
            CredentialError::ProviderError(format!("parsing {}: {e}", path.display()))
        })?;

        let count = parsed.credentials.len();
        debug!(count, "loaded credentials from file");

        // Convert plaintext strings to SecretString at load time so they are
        // zeroized on drop. The original HashMap<String, String> is dropped here.
        let credentials: HashMap<String, SecretString> = parsed
            .credentials
            .into_iter()
            .map(|(k, v)| (k, SecretString::from(v)))
            .collect();

        Ok(Self {
            credentials: Arc::new(RwLock::new(credentials)),
            source_path: path,
        })
    }

    /// Reload credentials from the source file without restarting.
    /// The credential map is swapped atomically under a write lock.
    pub async fn reload(&self) -> Result<usize, CredentialError> {
        let contents = tokio::fs::read_to_string(&self.source_path)
            .await
            .map_err(|e| {
                CredentialError::ProviderError(format!(
                    "reading {}: {e}",
                    self.source_path.display()
                ))
            })?;
        let parsed: CredentialFile = toml::from_str(&contents).map_err(|e| {
            CredentialError::ProviderError(format!(
                "parsing {}: {e}",
                self.source_path.display()
            ))
        })?;
        let new_creds: HashMap<String, SecretString> = parsed
            .credentials
            .into_iter()
            .map(|(k, v)| (k, SecretString::from(v)))
            .collect();
        let count = new_creds.len();
        let mut creds = self.credentials.write().await;
        *creds = new_creds;
        info!(count, path = %self.source_path.display(), "reloaded credentials from file");
        Ok(count)
    }
}

#[async_trait]
impl CredentialProvider for FileProvider {
    async fn resolve(&self, reference: &str) -> Result<SecretString, CredentialError> {
        use secrecy::ExposeSecret;
        let creds = self.credentials.read().await;
        creds
            .get(reference)
            .map(|v| SecretString::from(v.expose_secret().to_string()))
            .ok_or_else(|| {
                warn!(reference, "credential not found in file provider");
                CredentialError::NotFound(reference.to_string())
            })
    }

    async fn list_refs(&self) -> Result<Vec<CredentialRef>, CredentialError> {
        let creds = self.credentials.read().await;
        Ok(creds
            .keys()
            .map(|name| CredentialRef {
                name: name.clone(),
                provider: "file".into(),
                last_rotated: None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn write_temp_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("create temp file");
        f.write_all(content.as_bytes()).expect("write temp file");
        f.flush().expect("flush temp file");
        f
    }

    #[tokio::test]
    async fn loads_plaintext_toml() {
        let f = write_temp_toml(
            r#"
[credentials]
aws_key = "AKIAIOSFODNN7EXAMPLE"
github_token = "ghp_abc123"
"#,
        );

        let provider = FileProvider::from_path(f.path()).await.unwrap();
        assert_eq!(
            provider.resolve("aws_key").await.unwrap().expose_secret(),
            "AKIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            provider
                .resolve("github_token")
                .await
                .unwrap()
                .expose_secret(),
            "ghp_abc123"
        );
    }

    #[tokio::test]
    async fn not_found_returns_error() {
        let f = write_temp_toml(
            r#"
[credentials]
one = "1"
"#,
        );
        let provider = FileProvider::from_path(f.path()).await.unwrap();
        let err = provider.resolve("nonexistent").await.unwrap_err();
        assert!(matches!(err, CredentialError::NotFound(_)));
    }

    #[tokio::test]
    async fn list_refs_returns_all_keys() {
        let f = write_temp_toml(
            r#"
[credentials]
a = "1"
b = "2"
c = "3"
"#,
        );
        let provider = FileProvider::from_path(f.path()).await.unwrap();
        let refs = provider.list_refs().await.unwrap();
        assert_eq!(refs.len(), 3);
        assert!(refs.iter().all(|r| r.provider == "file"));
    }

    #[tokio::test]
    async fn rejects_age_extension() {
        let dir = tempfile::tempdir().unwrap();
        let age_path = dir.path().join("creds.toml.age");
        std::fs::write(&age_path, b"not real age data").unwrap();
        let err = FileProvider::from_path(&age_path).await.unwrap_err();
        assert!(matches!(err, CredentialError::ProviderError(_)));
    }

    #[tokio::test]
    async fn rejects_malformed_toml() {
        let f = write_temp_toml("this is not valid toml {{{{");
        let err = FileProvider::from_path(f.path()).await.unwrap_err();
        assert!(matches!(err, CredentialError::ProviderError(_)));
    }

    #[tokio::test]
    async fn toml_with_special_keys() {
        let f = write_temp_toml(
            r#"
[credentials]
"my.api-key" = "secret-value"
"dots.and.hyphens-too" = "another-secret"
simple_key = "plain"
"#,
        );
        let provider = FileProvider::from_path(f.path()).await.unwrap();
        assert_eq!(
            provider
                .resolve("my.api-key")
                .await
                .unwrap()
                .expose_secret(),
            "secret-value"
        );
        assert_eq!(
            provider
                .resolve("dots.and.hyphens-too")
                .await
                .unwrap()
                .expose_secret(),
            "another-secret"
        );
        assert_eq!(
            provider
                .resolve("simple_key")
                .await
                .unwrap()
                .expose_secret(),
            "plain"
        );
        assert_eq!(provider.list_refs().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn empty_credentials_table() {
        let f = write_temp_toml(
            r#"
[credentials]
"#,
        );
        let provider = FileProvider::from_path(f.path()).await.unwrap();
        assert!(provider.list_refs().await.unwrap().is_empty());
        assert!(matches!(
            provider.resolve("anything").await.unwrap_err(),
            CredentialError::NotFound(_)
        ));
    }
}
