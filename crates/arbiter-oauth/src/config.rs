//! OAuth configuration types, loaded from TOML.

use serde::Deserialize;

use crate::error::OAuthError;

/// Top-level OAuth configuration supporting multiple identity providers.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    /// One or more configured identity providers / issuers.
    pub issuers: Vec<IssuerConfig>,

    /// How long (in seconds) to cache JWKS keys before refreshing.
    /// Defaults to 3600 (1 hour).
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_secs: u64,
}

/// Configuration for a single OAuth issuer (e.g. Keycloak, Auth0, Okta).
#[derive(Clone, Deserialize)]
pub struct IssuerConfig {
    /// Human-readable name for this issuer (used in logs).
    pub name: String,

    /// The expected `iss` claim value in JWTs from this issuer.
    pub issuer_url: String,

    /// URL of the JWKS endpoint serving the issuer's public keys.
    pub jwks_uri: String,

    /// Expected audience values. If empty, audience validation is skipped.
    #[serde(default)]
    pub audiences: Vec<String>,

    /// Optional token introspection endpoint (RFC 7662).
    #[serde(default)]
    pub introspection_url: Option<String>,

    /// Client ID for introspection authentication.
    #[serde(default)]
    pub client_id: Option<String>,

    /// Client secret for introspection authentication.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Allowed redirect URIs for authorization code flow.
    /// If non-empty, redirect_uri in token exchange must exactly match
    /// one of these values (no prefix matching, no wildcards).
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
}

impl std::fmt::Debug for IssuerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerConfig")
            .field("name", &self.name)
            .field("issuer_url", &self.issuer_url)
            .field("jwks_uri", &self.jwks_uri)
            .field("audiences", &self.audiences)
            .field("introspection_url", &self.introspection_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "[REDACTED]"))
            .field("allowed_redirect_uris", &self.allowed_redirect_uris)
            .finish()
    }
}

impl OAuthConfig {
    /// Validate that JWKS and introspection URLs use HTTPS
    /// (or localhost for development).
    pub fn validate(&self) -> Result<(), OAuthError> {
        for issuer in &self.issuers {
            validate_url_scheme(&issuer.jwks_uri, "jwks_uri", &issuer.name)?;
            if let Some(ref url) = issuer.introspection_url {
                validate_url_scheme(url, "introspection_url", &issuer.name)?;
            }
        }
        Ok(())
    }
}

fn validate_url_scheme(url: &str, field: &str, issuer_name: &str) -> Result<(), OAuthError> {
    let is_https = url.starts_with("https://");
    let is_localhost = url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://[::1]");
    if !is_https && !is_localhost {
        tracing::warn!(
            issuer = issuer_name,
            field = field,
            url = url,
            "non-HTTPS URL detected, vulnerable to MITM"
        );
        return Err(OAuthError::InsecureUrl(format!(
            "issuer '{}' {} must use HTTPS (got: {}). HTTP is only allowed for localhost.",
            issuer_name, field, url
        )));
    }
    Ok(())
}

fn default_jwks_cache_ttl() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_oauth_config() {
        let toml = r#"
jwks_cache_ttl_secs = 1800

[[issuers]]
name = "keycloak"
issuer_url = "https://keycloak.example.com/realms/arbiter"
jwks_uri = "https://keycloak.example.com/realms/arbiter/protocol/openid-connect/certs"
audiences = ["arbiter-api"]

[[issuers]]
name = "auth0"
issuer_url = "https://arbiter.auth0.com/"
jwks_uri = "https://arbiter.auth0.com/.well-known/jwks.json"
introspection_url = "https://arbiter.auth0.com/oauth/token/introspect"
client_id = "my-client"
client_secret = "my-secret"
"#;
        let config: OAuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.issuers.len(), 2);
        assert_eq!(config.jwks_cache_ttl_secs, 1800);
        assert_eq!(config.issuers[0].name, "keycloak");
        assert!(config.issuers[0].introspection_url.is_none());
        assert_eq!(
            config.issuers[1].introspection_url.as_deref(),
            Some("https://arbiter.auth0.com/oauth/token/introspect")
        );
    }
}
