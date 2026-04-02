//! OAuth 2.0 Token Introspection (RFC 7662).
//!
//! Provides an async fallback for when local JWT validation fails —
//! for example, opaque tokens or tokens whose signing key is not
//! in the local JWKS cache.

use serde::Deserialize;

use crate::claims::Claims;
use crate::config::IssuerConfig;
use crate::error::OAuthError;

/// Response from an RFC 7662 introspection endpoint.
#[derive(Debug, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    pub active: bool,

    /// Subject identifier.
    #[serde(default)]
    pub sub: Option<String>,

    /// Issuer.
    #[serde(default)]
    pub iss: Option<String>,

    /// Audience.
    #[serde(default)]
    pub aud: Option<String>,

    /// Expiration time (seconds since epoch).
    #[serde(default)]
    pub exp: Option<u64>,

    /// Issued-at time (seconds since epoch).
    #[serde(default)]
    pub iat: Option<u64>,
}

/// Introspect a token against the given issuer's introspection endpoint.
///
/// Returns [`Claims`] on success, or an error if the endpoint is not
/// configured, unreachable, or reports the token as inactive.
pub async fn introspect_token(token: &str, issuer: &IssuerConfig) -> Result<Claims, OAuthError> {
    let url = issuer
        .introspection_url
        .as_ref()
        .ok_or_else(|| OAuthError::IntrospectionFailed("no introspection URL configured".into()))?;

    let client = reqwest::Client::new();
    let mut req = client
        .post(url)
        .form(&[("token", token), ("token_type_hint", "access_token")]);

    if let (Some(id), Some(secret)) = (&issuer.client_id, &issuer.client_secret) {
        req = req.basic_auth(id, Some(secret));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| OAuthError::IntrospectionFailed(e.to_string()))?;

    let body: IntrospectionResponse = resp
        .json()
        .await
        .map_err(|e| OAuthError::IntrospectionFailed(e.to_string()))?;

    if !body.active {
        return Err(OAuthError::TokenNotActive);
    }

    Ok(Claims {
        sub: body.sub,
        iss: body.iss,
        aud: None,
        exp: body.exp,
        iat: body.iat,
        custom: Default::default(),
    })
}
