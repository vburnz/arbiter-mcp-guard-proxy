//! Error types for OAuth validation.

use thiserror::Error;

/// Errors that can occur during OAuth token validation.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// No Authorization header was present on the request.
    #[error("missing Authorization header")]
    MissingAuthHeader,

    /// The Authorization header value could not be parsed.
    #[error("invalid Authorization header format")]
    InvalidAuthHeader,

    /// JWT signature or claims validation failed.
    #[error("JWT validation failed: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),

    /// No cached key matched the JWT's `kid` header.
    #[error("no matching key found for kid: {0}")]
    KeyNotFound(String),

    /// Fetching the JWKS endpoint failed.
    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    /// Token introspection returned an error or network failure.
    #[error("token introspection failed: {0}")]
    IntrospectionFailed(String),

    /// The introspection endpoint reported the token as inactive.
    #[error("token is not active")]
    TokenNotActive,

    /// The JWT header did not contain a `kid` claim.
    #[error("no kid in JWT header")]
    MissingKid,

    /// The JWT uses an algorithm that is not in the allowed list.
    #[error("JWT uses disallowed algorithm: {0}")]
    DisallowedAlgorithm(String),

    /// The JWT token exceeds the maximum allowed size.
    #[error("JWT token too large: {0} bytes")]
    TokenTooLarge(usize),

    /// A configured URL uses an insecure scheme (not HTTPS).
    #[error("insecure URL: {0}")]
    InsecureUrl(String),
}
