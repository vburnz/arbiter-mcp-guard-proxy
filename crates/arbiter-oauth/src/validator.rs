//! Core JWT validation logic, independent of HTTP framework types.

use std::time::Duration;

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

use crate::claims::Claims;
use crate::config::OAuthConfig;
use crate::error::OAuthError;
use crate::jwks::JwksCache;

/// Per-issuer runtime state: configuration paired with its JWKS cache.
pub(crate) struct IssuerState {
    pub(crate) config: crate::config::IssuerConfig,
    pub(crate) jwks: JwksCache,
}

/// Validates JWT bearer tokens against one or more configured issuers.
///
/// The validator checks the token's `kid` header against cached JWKS keys
/// for each issuer, validates the signature and standard claims, and
/// returns typed [`Claims`] on success.
pub struct OAuthValidator {
    pub(crate) issuers: Vec<IssuerState>,
    /// Cooldown for refresh-on-miss to prevent amplified JWKS fetches.
    /// An attacker sending tokens with random kid values could force unlimited outbound
    /// JWKS requests, potentially causing DoS at the IdP or CPU exhaustion.
    last_refresh_on_miss: std::sync::RwLock<Option<std::time::Instant>>,
}

impl OAuthValidator {
    /// Build a validator from configuration. JWKS caches start empty —
    /// call [`refresh_jwks`](Self::refresh_jwks) to populate them.
    pub fn new(config: &OAuthConfig) -> Self {
        let ttl = Duration::from_secs(config.jwks_cache_ttl_secs);
        let issuers = config
            .issuers
            .iter()
            .map(|ic| IssuerState {
                config: ic.clone(),
                jwks: JwksCache::new(ttl),
            })
            .collect();
        Self {
            issuers,
            last_refresh_on_miss: std::sync::RwLock::new(None),
        }
    }

    /// Refresh JWKS keys for all issuers that need it.
    pub async fn refresh_jwks(&self) -> Result<(), OAuthError> {
        for issuer in &self.issuers {
            if issuer.jwks.needs_refresh() {
                tracing::info!(issuer = %issuer.config.name, "refreshing JWKS");
                issuer
                    .jwks
                    .refresh_from_uri(&issuer.config.jwks_uri)
                    .await?;
            }
        }
        Ok(())
    }

    /// Insert a decoding key for a specific issuer (by index) and `kid`.
    /// This is intended for testing. Production code should use
    /// [`refresh_jwks`](Self::refresh_jwks).
    pub fn insert_key(&self, issuer_index: usize, kid: &str, key: DecodingKey) {
        self.issuers[issuer_index]
            .jwks
            .insert_key(kid.to_string(), key);
    }

    /// Validate a bearer token string (without the "Bearer " prefix).
    ///
    /// Tries each configured issuer in order. Returns [`Claims`] from the
    /// first issuer whose JWKS cache contains a matching key and whose
    /// validation succeeds.
    ///
    /// If the kid is not found in any cache, triggers
    /// a JWKS refresh before returning KeyNotFound. This handles key rotation
    /// at the IdP without waiting for the full cache TTL to expire.
    pub fn validate_token(&self, token: &str) -> Result<Claims, OAuthError> {
        // Reject oversized tokens to prevent DoS via large payloads.
        const MAX_TOKEN_BYTES: usize = 16 * 1024; // 16 KiB, generous for JWTs
        if token.len() > MAX_TOKEN_BYTES {
            return Err(OAuthError::TokenTooLarge(token.len()));
        }

        let header = decode_header(token).map_err(OAuthError::JwtValidation)?;

        let kid = header.kid.as_ref().ok_or(OAuthError::MissingKid)?;

        // Restrict JWT algorithms to prevent algorithm confusion attacks.
        // Only asymmetric algorithms are allowed. Symmetric algorithms (HS256/384/512)
        // could allow signature forgery if the JWKS public key is used as an HMAC secret.
        let allowed_algorithms = [
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384,
            jsonwebtoken::Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512,
            jsonwebtoken::Algorithm::EdDSA,
        ];
        if !allowed_algorithms.contains(&header.alg) {
            tracing::warn!(algorithm = ?header.alg, "JWT uses disallowed algorithm");
            return Err(OAuthError::DisallowedAlgorithm(format!("{:?}", header.alg)));
        }

        let mut last_error: Option<OAuthError> = None;

        for issuer in &self.issuers {
            let Some(key) = issuer.jwks.get_key(kid) else {
                continue;
            };

            let mut validation = Validation::new(header.alg);
            validation.set_required_spec_claims(&["exp", "iss"]);
            // Add clock skew tolerance to prevent
            // legitimate token rejection due to clock drift between systems.
            validation.leeway = 60; // 60 seconds leeway
            validation.set_issuer(&[&issuer.config.issuer_url]);

            if issuer.config.audiences.is_empty() {
                validation.set_audience::<&str>(&[]);
                validation.validate_aud = false;
            } else {
                validation.set_audience(&issuer.config.audiences);
            }

            match decode::<Claims>(token, &key, &validation) {
                Ok(token_data) => {
                    tracing::debug!(
                        issuer = %issuer.config.name,
                        sub = ?token_data.claims.sub,
                        "JWT validated successfully"
                    );
                    return Ok(token_data.claims);
                }
                Err(e) => {
                    tracing::debug!(
                        issuer = %issuer.config.name,
                        error = %e,
                        "JWT validation failed for this issuer"
                    );
                    last_error = Some(OAuthError::JwtValidation(e));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| OAuthError::KeyNotFound(kid.clone())))
    }

    /// Validate with refresh-on-miss (rate-limited).
    /// If the initial validation fails with KeyNotFound, refreshes all JWKS caches
    /// and retries once. This handles key rotation at the IdP without waiting for
    /// the full cache TTL to expire (which could reject valid tokens for up to 3600s).
    ///
    /// Refresh-on-miss is rate-limited to at most once per 30 seconds to prevent
    /// an attacker from forcing unlimited JWKS fetches by sending tokens with random kid values.
    pub async fn validate_token_with_refresh(&self, token: &str) -> Result<Claims, OAuthError> {
        const REFRESH_ON_MISS_COOLDOWN: Duration = Duration::from_secs(30);

        match self.validate_token(token) {
            Ok(claims) => Ok(claims),
            Err(OAuthError::KeyNotFound(kid)) => {
                // Check cooldown before triggering refresh.
                let should_refresh = {
                    let last = self
                        .last_refresh_on_miss
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    match *last {
                        Some(t) => t.elapsed() >= REFRESH_ON_MISS_COOLDOWN,
                        None => true,
                    }
                };

                if !should_refresh {
                    tracing::debug!(
                        %kid,
                        "kid not found; refresh-on-miss suppressed by cooldown"
                    );
                    return Err(OAuthError::KeyNotFound(kid));
                }

                tracing::info!(%kid, "kid not found in JWKS cache, triggering refresh-on-miss");

                // Update cooldown timestamp.
                {
                    let mut last = self
                        .last_refresh_on_miss
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    *last = Some(std::time::Instant::now());
                }

                // Refresh all issuers' caches.
                for issuer in &self.issuers {
                    if let Err(e) = issuer.jwks.refresh_from_uri(&issuer.config.jwks_uri).await {
                        tracing::warn!(issuer = %issuer.config.name, error = %e, "JWKS refresh-on-miss failed");
                    }
                }
                // Retry validation with refreshed caches.
                self.validate_token(token)
            }
            Err(other) => Err(other),
        }
    }
}
