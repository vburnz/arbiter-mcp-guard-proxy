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
/// Introspection client timeout (matches JWKS fetch timeout).
const INTROSPECTION_TIMEOUT_SECS: u64 = 30;

pub async fn introspect_token(token: &str, issuer: &IssuerConfig) -> Result<Claims, OAuthError> {
    let url = issuer
        .introspection_url
        .as_ref()
        .ok_or_else(|| OAuthError::IntrospectionFailed("no introspection URL configured".into()))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(INTROSPECTION_TIMEOUT_SECS))
        .build()
        .map_err(|e| OAuthError::IntrospectionFailed(e.to_string()))?;
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

    // Re-validate issuer against configured value (don't trust the introspection
    // endpoint blindly -- a compromised endpoint could return arbitrary claims).
    if let Some(ref returned_iss) = body.iss
        && returned_iss != &issuer.issuer_url
    {
        tracing::warn!(
            expected = %issuer.issuer_url,
            actual = %returned_iss,
            "introspection response issuer does not match configured issuer"
        );
        return Err(OAuthError::IntrospectionFailed(
            "issuer mismatch in introspection response".into(),
        ));
    }

    // Re-validate audience if the issuer has configured audiences.
    if !issuer.audiences.is_empty()
        && let Some(ref returned_aud) = body.aud
        && !issuer.audiences.contains(returned_aud)
    {
        tracing::warn!(
            expected = ?issuer.audiences,
            actual = %returned_aud,
            "introspection response audience not in configured set"
        );
        return Err(OAuthError::IntrospectionFailed(
            "audience mismatch in introspection response".into(),
        ));
    }

    // Re-validate expiry against current time.
    if let Some(exp) = body.exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if exp < now {
            tracing::warn!(
                exp,
                now,
                "introspection returned active token with past expiry"
            );
            return Err(OAuthError::IntrospectionFailed(
                "token expired per introspection response exp claim".into(),
            ));
        }
    }

    Ok(Claims {
        sub: body.sub,
        iss: body.iss,
        aud: body.aud.map(crate::claims::Audience::Single),
        exp: body.exp,
        iat: body.iat,
        scope: Vec::new(),
        custom: Default::default(),
    })
}
