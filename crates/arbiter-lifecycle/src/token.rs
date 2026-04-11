use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Claims embedded in agent short-lived JWTs.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentTokenClaims {
    pub sub: String,
    pub agent_id: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    /// Unique token identifier for future revocation tracking.
    /// NOTE: JTI is generated per-token but not currently checked against a
    /// blocklist during validation. Token revocation is handled at the session
    /// and agent level (deactivate agent → cascade invalidation). A JTI
    /// blocklist would add per-request state lookup; the current design trades
    /// fine-grained token revocation for stateless validation performance.
    pub jti: String,
}

/// Configuration for token issuance.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// HMAC secret for signing tokens.
    pub signing_secret: String,
    /// Token validity duration in seconds. Default: 3600 (1 hour).
    pub expiry_seconds: i64,
    /// Issuer claim.
    pub issuer: String,
}

impl Default for TokenConfig {
    /// Default config with an empty signing secret that will be rejected by issue_token.
    /// Operators MUST provide a real secret via configuration.
    fn default() -> Self {
        Self {
            signing_secret: String::new(),
            expiry_seconds: 3600,
            issuer: "arbiter".into(),
        }
    }
}

/// Minimum signing secret length.
/// HMAC-SHA256 requires at least 256 bits (32 bytes) for security.
pub const MIN_SIGNING_SECRET_LEN: usize = 32;

/// Maximum token expiry to prevent tokens with infinite-like lifetimes.
pub const MAX_TOKEN_EXPIRY_SECS: i64 = 86400; // 24 hours

/// Issue a short-lived JWT for an agent.
///
/// Note: These tokens use HS256 (symmetric HMAC) and are intended
/// for agent-to-admin-API authentication ONLY. They MUST NOT be validated through
/// the proxy's OAuth middleware, which restricts to asymmetric algorithms (RS256, ES256,
/// etc.) per FIX-008. The proxy's OAuth path is for external IdP tokens.
///
/// If you need agents to authenticate to the proxy via OAuth, issue tokens from an
/// external IdP that uses asymmetric signing, and configure it as an OAuth issuer.
pub fn issue_token(
    agent_id: Uuid,
    owner: &str,
    config: &TokenConfig,
) -> Result<String, jsonwebtoken::errors::Error> {
    // Signing secret minimum length is now a hard error.
    // Previously only warned, allowing 1-byte secrets that are trivially brutable.
    if config.signing_secret.len() < MIN_SIGNING_SECRET_LEN {
        tracing::error!(
            length = config.signing_secret.len(),
            minimum = MIN_SIGNING_SECRET_LEN,
            "signing secret is shorter than required minimum, refusing to issue token"
        );
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidKeyFormat,
        ));
    }

    // Cap token expiry to prevent arbitrarily long-lived tokens.
    let effective_expiry = config.expiry_seconds.min(MAX_TOKEN_EXPIRY_SECS);

    let now = Utc::now();
    let claims = AgentTokenClaims {
        sub: owner.to_string(),
        agent_id: agent_id.to_string(),
        iss: config.issuer.clone(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(effective_expiry)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.signing_secret.as_bytes()),
    )
}

/// In-memory JTI blocklist for token revocation.
///
/// Stores revoked JTI values with their expiry time so they can be
/// cleaned up once the token would have expired anyway.
pub struct JtiBlocklist {
    /// Map of JTI -> expiry timestamp. Entries are removed after expiry.
    revoked: Mutex<HashMap<String, i64>>,
}

impl JtiBlocklist {
    /// Create a new empty blocklist.
    pub fn new() -> Self {
        Self {
            revoked: Mutex::new(HashMap::new()),
        }
    }

    /// Revoke a token by its JTI. The `exp` is the token's expiry time;
    /// the entry will be auto-cleaned after that time.
    pub fn revoke(&self, jti: &str, exp: i64) {
        let mut map = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(jti.to_string(), exp);
        tracing::info!(jti, "token revoked via JTI blocklist");
    }

    /// Check if a JTI has been revoked.
    pub fn is_revoked(&self, jti: &str) -> bool {
        let map = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
        map.contains_key(jti)
    }

    /// Remove expired entries from the blocklist.
    pub fn cleanup(&self) {
        let now = Utc::now().timestamp();
        let mut map = self.revoked.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, exp| *exp > now);
        let removed = before - map.len();
        if removed > 0 {
            tracing::debug!(removed, "cleaned up expired JTI blocklist entries");
        }
    }

    /// Number of currently revoked JTIs.
    pub fn len(&self) -> usize {
        self.revoked.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for JtiBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode};

    fn test_config() -> TokenConfig {
        TokenConfig {
            signing_secret: "a]3Fz!9qL#mR&vXw2Tp7Ks@Yc0Nd8Ge$".into(),
            expiry_seconds: 3600,
            issuer: "arbiter".into(),
        }
    }

    #[test]
    fn default_config_rejects_token_issuance() {
        let config = TokenConfig::default();
        let agent_id = Uuid::new_v4();
        let result = issue_token(agent_id, "user:alice", &config);
        assert!(result.is_err(), "default config with empty secret must reject token issuance");
    }

    #[test]
    fn issue_and_decode_token() {
        let config = test_config();
        let agent_id = Uuid::new_v4();
        let token = issue_token(agent_id, "user:alice", &config).unwrap();

        let mut validation = Validation::default();
        validation.set_issuer(&[&config.issuer]);
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);

        let decoded = decode::<AgentTokenClaims>(
            &token,
            &DecodingKey::from_secret(config.signing_secret.as_bytes()),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.agent_id, agent_id.to_string());
        assert_eq!(decoded.claims.sub, "user:alice");
        assert_eq!(decoded.claims.iss, "arbiter");
    }

    /// A signing secret shorter than 32 bytes must be rejected.
    #[test]
    fn short_signing_secret_rejected() {
        let config = TokenConfig {
            signing_secret: "only-16-bytes!!!".into(), // 16 bytes
            expiry_seconds: 3600,
            issuer: "arbiter".into(),
        };
        let agent_id = Uuid::new_v4();
        let result = issue_token(agent_id, "user:alice", &config);
        assert!(result.is_err(), "16-byte secret must be rejected");
    }

    /// Exactly 32 bytes should be accepted (boundary condition).
    #[test]
    fn minimum_length_secret_accepted() {
        let config = TokenConfig {
            signing_secret: "a]3Fz!9qL#mR&vXw2Tp7Ks@Yc0Nd8Ge$".into(), // exactly 32 bytes
            expiry_seconds: 3600,
            issuer: "arbiter".into(),
        };
        let agent_id = Uuid::new_v4();
        let result = issue_token(agent_id, "user:alice", &config);
        assert!(result.is_ok(), "32-byte secret must be accepted");
    }

    /// Token expiry must be capped at MAX_TOKEN_EXPIRY_SECS (24h).
    #[test]
    fn expiry_capped_at_24_hours() {
        let config = TokenConfig {
            signing_secret: "a]3Fz!9qL#mR&vXw2Tp7Ks@Yc0Nd8Ge$".into(),
            expiry_seconds: 172_800, // 48 hours — should be capped to 24h
            issuer: "arbiter".into(),
        };
        let agent_id = Uuid::new_v4();
        let token = issue_token(agent_id, "user:alice", &config).unwrap();

        let mut validation = Validation::default();
        validation.set_issuer(&[&config.issuer]);
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);

        let decoded = decode::<AgentTokenClaims>(
            &token,
            &DecodingKey::from_secret(config.signing_secret.as_bytes()),
            &validation,
        )
        .unwrap();

        let delta = decoded.claims.exp - decoded.claims.iat;
        assert!(
            delta <= MAX_TOKEN_EXPIRY_SECS,
            "exp - iat ({delta}) must be <= {MAX_TOKEN_EXPIRY_SECS}"
        );
    }

    /// A normal expiry (below the cap) should not be altered.
    #[test]
    fn normal_expiry_not_capped() {
        let config = TokenConfig {
            signing_secret: "a]3Fz!9qL#mR&vXw2Tp7Ks@Yc0Nd8Ge$".into(),
            expiry_seconds: 3600,
            issuer: "arbiter".into(),
        };
        let agent_id = Uuid::new_v4();
        let token = issue_token(agent_id, "user:alice", &config).unwrap();

        let mut validation = Validation::default();
        validation.set_issuer(&[&config.issuer]);
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);

        let decoded = decode::<AgentTokenClaims>(
            &token,
            &DecodingKey::from_secret(config.signing_secret.as_bytes()),
            &validation,
        )
        .unwrap();

        let delta = decoded.claims.exp - decoded.claims.iat;
        assert_eq!(delta, 3600, "exp - iat should equal the configured 3600s");
    }

    /// Each issued token must carry a unique jti for revocation tracking.
    #[test]
    fn each_token_has_unique_jti() {
        let config = test_config();
        let agent_id = Uuid::new_v4();

        let token_a = issue_token(agent_id, "user:alice", &config).unwrap();
        let token_b = issue_token(agent_id, "user:alice", &config).unwrap();

        let mut validation = Validation::default();
        validation.set_issuer(&[&config.issuer]);
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);

        let claims_a = decode::<AgentTokenClaims>(
            &token_a,
            &DecodingKey::from_secret(config.signing_secret.as_bytes()),
            &validation,
        )
        .unwrap()
        .claims;

        let claims_b = decode::<AgentTokenClaims>(
            &token_b,
            &DecodingKey::from_secret(config.signing_secret.as_bytes()),
            &validation,
        )
        .unwrap()
        .claims;

        assert_ne!(
            claims_a.jti, claims_b.jti,
            "each token must have a unique jti"
        );
    }
}
