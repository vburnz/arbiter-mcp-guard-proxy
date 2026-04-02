//! JWKS key cache with configurable TTL.
//!
//! Keys are stored in a `std::sync::RwLock` so that the synchronous
//! [`Middleware::process`] path can read without an async runtime.
//! The async [`refresh_from_uri`] method fetches fresh keys from a
//! remote JWKS endpoint.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::DecodingKey;

use crate::error::OAuthError;

/// Thread-safe cache of JWKS decoding keys, keyed by `kid`.
pub struct JwksCache {
    inner: RwLock<CacheState>,
    ttl: Duration,
}

struct CacheState {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Option<Instant>,
}

impl JwksCache {
    /// Create a new empty cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(CacheState {
                keys: HashMap::new(),
                last_refresh: None,
            }),
            ttl,
        }
    }

    /// Look up a decoding key by `kid`. Returns `None` if not cached.
    pub fn get_key(&self, kid: &str) -> Option<DecodingKey> {
        let cache = self.inner.read().unwrap_or_else(|e| e.into_inner());
        cache.keys.get(kid).cloned()
    }

    /// Check if a kid exists in the cache without retrieving it.
    /// Used to determine if a refresh-on-miss should be attempted.
    pub fn has_key(&self, kid: &str) -> bool {
        let cache = self.inner.read().unwrap_or_else(|e| e.into_inner());
        cache.keys.contains_key(kid)
    }

    /// Insert a decoding key directly (primarily for testing).
    pub fn insert_key(&self, kid: String, key: DecodingKey) {
        let mut cache = self.inner.write().unwrap_or_else(|e| e.into_inner());
        cache.keys.insert(kid, key);
    }

    /// Returns `true` if the cache has never been populated or has exceeded its TTL.
    pub fn needs_refresh(&self) -> bool {
        let cache = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match cache.last_refresh {
            None => true,
            Some(t) => t.elapsed() > self.ttl,
        }
    }

    /// Fetch keys from a remote JWKS endpoint and populate the cache.
    pub async fn refresh_from_uri(&self, uri: &str) -> Result<(), OAuthError> {
        // Add timeout and response size limit to JWKS fetch.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| OAuthError::JwksFetchFailed(e.to_string()))?;

        let resp = client
            .get(uri)
            .send()
            .await
            .map_err(|e| OAuthError::JwksFetchFailed(e.to_string()))?;

        // Limit response size to 1 MiB to prevent memory exhaustion from malicious JWKS endpoints.
        const MAX_JWKS_RESPONSE_BYTES: usize = 1024 * 1024;
        let resp_bytes = resp
            .bytes()
            .await
            .map_err(|e| OAuthError::JwksFetchFailed(e.to_string()))?;
        if resp_bytes.len() > MAX_JWKS_RESPONSE_BYTES {
            return Err(OAuthError::JwksFetchFailed(format!(
                "JWKS response too large: {} bytes (limit: {})",
                resp_bytes.len(),
                MAX_JWKS_RESPONSE_BYTES
            )));
        }

        let jwks: JwkSet = serde_json::from_slice(&resp_bytes)
            .map_err(|e| OAuthError::JwksFetchFailed(e.to_string()))?;

        let mut new_keys = HashMap::new();
        for jwk in &jwks.keys {
            if let Some(kid) = &jwk.common.key_id {
                match DecodingKey::from_jwk(jwk) {
                    Ok(dk) => {
                        new_keys.insert(kid.clone(), dk);
                    }
                    Err(e) => {
                        tracing::warn!(kid = %kid, error = %e, "skipping unusable JWK");
                    }
                }
            }
        }

        tracing::info!(key_count = new_keys.len(), "refreshed JWKS cache");

        let mut cache = self.inner.write().unwrap_or_else(|e| e.into_inner());
        cache.keys = new_keys;
        cache.last_refresh = Some(Instant::now());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_needs_refresh() {
        let cache = JwksCache::new(Duration::from_secs(3600));
        assert!(cache.needs_refresh());
    }

    #[test]
    fn insert_and_retrieve_key() {
        let cache = JwksCache::new(Duration::from_secs(3600));
        let key = DecodingKey::from_secret(b"test");
        cache.insert_key("kid-1".to_string(), key);
        assert!(cache.get_key("kid-1").is_some());
        assert!(cache.get_key("kid-2").is_none());
    }
}
