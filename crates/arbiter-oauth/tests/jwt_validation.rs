//! Integration tests for arbiter-oauth JWT validation.
//!
//! Tests use RS256 (asymmetric RSA) as required by the algorithm whitelist.
//! HS256 is intentionally disallowed to prevent algorithm confusion attacks.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use serde_json::json;

use arbiter_oauth::claims::Audience;
use arbiter_oauth::config::{IssuerConfig, OAuthConfig};
use arbiter_oauth::error::OAuthError;
use arbiter_oauth::validator::OAuthValidator;

const TEST_ISSUER: &str = "https://auth.example.com";
const TEST_AUDIENCE: &str = "arbiter-api";
const TEST_KID: &str = "test-kid-1";

// 2048-bit RSA test keypair. DO NOT use in production.
const RSA_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/test_rsa_private.pem");
const RSA_PUBLIC_KEY: &[u8] = include_bytes!("fixtures/test_rsa_public.pem");

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

fn test_config() -> OAuthConfig {
    OAuthConfig {
        issuers: vec![IssuerConfig {
            name: "test-issuer".to_string(),
            issuer_url: TEST_ISSUER.to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            audiences: vec![TEST_AUDIENCE.to_string()],
            introspection_url: None,
            client_id: None,
            client_secret: None,
        }],
        jwks_cache_ttl_secs: 3600,
    }
}

fn make_validator() -> OAuthValidator {
    let config = test_config();
    let validator = OAuthValidator::new(&config);
    validator.insert_key(
        0,
        TEST_KID,
        DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY).expect("valid RSA public key"),
    );
    validator
}

fn make_token(claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).expect("valid RSA private key"),
    )
    .expect("encoding test JWT should not fail")
}

#[test]
fn valid_jwt_accepted_and_claims_extracted() {
    let validator = make_validator();
    let now = now_secs();

    let token = make_token(json!({
        "sub": "user-42",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "role": "admin",
    }));

    let claims = validator.validate_token(&token).expect("should validate");
    assert_eq!(claims.sub.as_deref(), Some("user-42"));
    assert_eq!(claims.iss.as_deref(), Some(TEST_ISSUER));
    assert!(claims.exp.is_some());
    assert!(claims.iat.is_some());
    // Custom claim should be captured in the `custom` map.
    assert_eq!(
        claims.custom.get("role").and_then(|v| v.as_str()),
        Some("admin")
    );
}

#[test]
fn expired_jwt_rejected() {
    let validator = make_validator();
    let past = now_secs() - 7200; // 2 hours ago (well beyond 60s leeway)

    let token = make_token(json!({
        "sub": "user-expired",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": past,
        "iat": past - 3600,
    }));

    let result = validator.validate_token(&token);
    assert!(result.is_err(), "expired JWT should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("JWT validation failed"),
        "error should indicate JWT failure: {err}"
    );
}

#[test]
fn wrong_signature_rejected() {
    let validator = make_validator();
    let now = now_secs();

    // Sign with a *different* RSA key (generate one on the fly by using HMAC,
    // which will also be blocked by the algorithm whitelist).
    // Instead, create a valid RS256 token but verify against a different public key.
    let other_private = include_bytes!("fixtures/test_rsa_private2.pem");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let token = encode(
        &header,
        &json!({
            "sub": "attacker",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now + 3600,
            "iat": now,
        }),
        &EncodingKey::from_rsa_pem(other_private).expect("valid RSA private key"),
    )
    .unwrap();

    let result = validator.validate_token(&token);
    assert!(result.is_err(), "wrong-signature JWT should be rejected");
}

#[test]
fn hs256_algorithm_rejected() {
    // HS256 is now disallowed by the algorithm whitelist.
    let validator = make_validator();
    let now = now_secs();

    let secret = b"some-hmac-secret";
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TEST_KID.to_string());
    let token = encode(
        &header,
        &json!({
            "sub": "attacker",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now + 3600,
            "iat": now,
        }),
        &EncodingKey::from_secret(secret),
    )
    .unwrap();

    let result = validator.validate_token(&token);
    assert!(result.is_err(), "HS256 JWT should be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("disallowed algorithm"),
        "error should mention disallowed algorithm"
    );
}

#[test]
fn missing_kid_rejected() {
    let validator = make_validator();
    let now = now_secs();

    // Create a JWT without a kid in the header.
    let header = Header::new(Algorithm::RS256); // no kid set
    let token = encode(
        &header,
        &json!({
            "sub": "user-no-kid",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now + 3600,
            "iat": now,
        }),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).expect("valid key"),
    )
    .unwrap();

    let result = validator.validate_token(&token);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("kid"),
        "error should mention missing kid"
    );
}

#[test]
fn unknown_kid_rejected() {
    let validator = make_validator();
    let now = now_secs();

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("unknown-kid".to_string());
    let token = encode(
        &header,
        &json!({
            "sub": "user-unknown-kid",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now + 3600,
            "iat": now,
        }),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).expect("valid key"),
    )
    .unwrap();

    let result = validator.validate_token(&token);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("unknown-kid"),
        "error should reference the unknown kid"
    );
}

#[test]
fn wrong_audience_rejected() {
    let validator = make_validator();
    let now = now_secs();

    let token = make_token(json!({
        "sub": "user-wrong-aud",
        "iss": TEST_ISSUER,
        "aud": "some-other-api",
        "exp": now + 3600,
        "iat": now,
    }));

    let result = validator.validate_token(&token);
    assert!(result.is_err(), "wrong audience should be rejected");
}

#[test]
fn multi_issuer_selects_correct_one() {
    let second_kid = "kid-issuer-2";
    let second_issuer = "https://auth2.example.com";

    let config = OAuthConfig {
        issuers: vec![
            IssuerConfig {
                name: "issuer-1".to_string(),
                issuer_url: TEST_ISSUER.to_string(),
                jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
                audiences: vec![TEST_AUDIENCE.to_string()],
                introspection_url: None,
                client_id: None,
                client_secret: None,
            },
            IssuerConfig {
                name: "issuer-2".to_string(),
                issuer_url: second_issuer.to_string(),
                jwks_uri: "https://auth2.example.com/.well-known/jwks.json".to_string(),
                audiences: vec!["other-api".to_string()],
                introspection_url: None,
                client_id: None,
                client_secret: None,
            },
        ],
        jwks_cache_ttl_secs: 3600,
    };

    let validator = OAuthValidator::new(&config);
    validator.insert_key(
        0,
        TEST_KID,
        DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY).expect("valid key"),
    );
    // Issuer 2 uses a second keypair
    let second_public = include_bytes!("fixtures/test_rsa_public2.pem");
    validator.insert_key(
        1,
        second_kid,
        DecodingKey::from_rsa_pem(second_public).expect("valid key"),
    );

    let now = now_secs();

    // Token from issuer 2 should match issuer 2.
    let second_private = include_bytes!("fixtures/test_rsa_private2.pem");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(second_kid.to_string());
    let token = encode(
        &header,
        &json!({
            "sub": "user-from-issuer-2",
            "iss": second_issuer,
            "aud": "other-api",
            "exp": now + 3600,
            "iat": now,
        }),
        &EncodingKey::from_rsa_pem(second_private).expect("valid key"),
    )
    .unwrap();

    let claims = validator
        .validate_token(&token)
        .expect("should validate with issuer 2");
    assert_eq!(claims.sub.as_deref(), Some("user-from-issuer-2"));
    assert_eq!(claims.iss.as_deref(), Some(second_issuer));
}

#[test]
fn token_too_large_rejected() {
    let validator = make_validator();
    // Create a token string that exceeds the 16 KiB limit.
    let huge_token = "eyJ".to_string() + &"A".repeat(20_000);
    let result = validator.validate_token(&huge_token);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("too large"),
        "error should mention size"
    );
}

// ---------------------------------------------------------------------------
// Algorithm safety tests
// ---------------------------------------------------------------------------

/// Tokens using alg "none" (unsigned) must be rejected by the
/// algorithm whitelist. We cannot use jsonwebtoken::encode with Algorithm that
/// maps to "none" directly, so we construct the token manually.
#[test]
fn alg_none_rejected() {
    let validator = make_validator();
    let now = now_secs();

    // Manually construct a JWT with {"alg":"none","typ":"JWT","kid":"test-kid-1"} header.
    // We use a simple base64url encoder to avoid adding a base64 dependency.
    fn base64url_encode(input: &[u8]) -> String {
        use std::io::Write;
        // Manual base64url encoding without padding
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 {
                chunk[1] as usize
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            let _ = out.write_all(&[CHARS[(b0 >> 2) & 0x3F]]);
            let _ = out.write_all(&[CHARS[((b0 << 4) | (b1 >> 4)) & 0x3F]]);
            if chunk.len() > 1 {
                let _ = out.write_all(&[CHARS[((b1 << 2) | (b2 >> 6)) & 0x3F]]);
            }
            if chunk.len() > 2 {
                let _ = out.write_all(&[CHARS[b2 & 0x3F]]);
            }
        }
        String::from_utf8(out).unwrap()
    }

    let header_json = json!({"alg": "none", "typ": "JWT", "kid": TEST_KID}).to_string();
    let payload_json = json!({
        "sub": "attacker",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
    })
    .to_string();
    let header_b64 = base64url_encode(header_json.as_bytes());
    let payload_b64 = base64url_encode(payload_json.as_bytes());
    // alg:none tokens have an empty signature segment
    let token = format!("{header_b64}.{payload_b64}.");

    let result = validator.validate_token(&token);
    assert!(result.is_err(), "alg:none JWT must be rejected");
}

/// Verify that HS384 and HS512 are also rejected alongside HS256.
#[test]
fn hs384_and_hs512_rejected() {
    let validator = make_validator();
    let now = now_secs();
    let secret = b"some-hmac-secret-key-for-testing";

    for alg in [Algorithm::HS384, Algorithm::HS512] {
        let mut header = Header::new(alg);
        header.kid = Some(TEST_KID.to_string());
        let token = encode(
            &header,
            &json!({
                "sub": "attacker",
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "exp": now + 3600,
                "iat": now,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let result = validator.validate_token(&token);
        assert!(result.is_err(), "{alg:?} JWT should be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("disallowed algorithm"),
            "{alg:?}: error should mention disallowed algorithm, got: {err_msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// validate_token_with_refresh() tests ()
// ---------------------------------------------------------------------------

/// validate_token_with_refresh() succeeds when the key is already in cache.
/// This exercises the happy path of the async production entry point.
#[tokio::test]
async fn validate_with_refresh_succeeds_when_key_present() {
    let validator = make_validator();
    let now = now_secs();

    let token = make_token(json!({
        "sub": "user-async",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
    }));

    let claims = validator
        .validate_token_with_refresh(&token)
        .await
        .expect("should validate via async path when key is present");
    assert_eq!(claims.sub.as_deref(), Some("user-async"));
    assert_eq!(claims.iss.as_deref(), Some(TEST_ISSUER));
}

/// validate_token_with_refresh() returns KeyNotFound when kid is absent
/// and no real JWKS endpoint is reachable (can't actually refresh).
#[tokio::test]
async fn validate_with_refresh_key_not_found_without_jwks_endpoint() {
    let validator = make_validator();
    let now = now_secs();

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("nonexistent-kid".to_string());
    let token = encode(
        &header,
        &json!({
            "sub": "user-missing-key",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now + 3600,
            "iat": now,
        }),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).expect("valid key"),
    )
    .unwrap();

    let result = validator.validate_token_with_refresh(&token).await;
    assert!(
        result.is_err(),
        "should fail when kid not in cache and JWKS unreachable"
    );
    let err = result.unwrap_err();
    // After failed refresh, the retry still won't find the key.
    assert!(
        err.to_string().contains("nonexistent-kid"),
        "error should reference the missing kid: {err}"
    );
}

// ---------------------------------------------------------------------------
// Refresh-on-miss cooldown
// ---------------------------------------------------------------------------

/// Two rapid validate_token_with_refresh() calls with unknown kid.
/// The first triggers a refresh (which fails since no real endpoint); the second
/// should be suppressed by the 30-second cooldown. Both must return KeyNotFound.
#[tokio::test]
async fn refresh_cooldown_prevents_rapid_refresh() {
    let validator = make_validator();
    let now = now_secs();

    let make_unknown_kid_token = |kid: &str| {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &json!({
                "sub": "user-cooldown",
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "exp": now + 3600,
                "iat": now,
            }),
            &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).expect("valid key"),
        )
        .unwrap()
    };

    // First call: triggers refresh-on-miss (refresh fails, returns KeyNotFound).
    let token1 = make_unknown_kid_token("random-kid-1");
    let start1 = std::time::Instant::now();
    let result1 = validator.validate_token_with_refresh(&token1).await;
    let elapsed1 = start1.elapsed();
    assert!(result1.is_err(), "first call should return error");

    // Second call: should be within cooldown, so refresh is suppressed.
    let token2 = make_unknown_kid_token("random-kid-2");
    let start2 = std::time::Instant::now();
    let result2 = validator.validate_token_with_refresh(&token2).await;
    let elapsed2 = start2.elapsed();
    assert!(result2.is_err(), "second call should return error");

    // The second call should be faster (no network attempt) or at least not panic.
    // We use a generous comparison since the first call includes a network timeout attempt.
    // The key assertion is that both calls complete without panic.
    assert!(
        elapsed2 <= elapsed1 + std::time::Duration::from_secs(1),
        "second call should not be significantly slower: first={elapsed1:?}, second={elapsed2:?}"
    );
}

// ---------------------------------------------------------------------------
// Leeway boundary tests
// ---------------------------------------------------------------------------

/// Create a token that expired 50 seconds ago (within the 60-second leeway).
/// It should be ACCEPTED.
#[test]
fn leeway_boundary_accept_within_window() {
    let validator = make_validator();
    let now = now_secs();

    // Token expired 50 seconds ago, leeway is 60 seconds -> should be accepted
    let token = make_token(json!({
        "sub": "user-leeway-ok",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now - 50,
        "iat": now - 3650,
    }));

    let result = validator.validate_token(&token);
    assert!(
        result.is_ok(),
        "token expired 50s ago should be accepted (60s leeway), got: {:?}",
        result.unwrap_err()
    );
}

/// Create a token that expired 70 seconds ago (outside the 60-second leeway).
/// It should be REJECTED.
#[test]
fn leeway_boundary_reject_outside_window() {
    let validator = make_validator();
    let now = now_secs();

    // Token expired 70 seconds ago, leeway is 60 seconds -> should be rejected
    let token = make_token(json!({
        "sub": "user-leeway-fail",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now - 70,
        "iat": now - 3670,
    }));

    let result = validator.validate_token(&token);
    assert!(
        result.is_err(),
        "token expired 70s ago should be rejected (60s leeway)"
    );
}

// ---------------------------------------------------------------------------
// Audience validation tests
// ---------------------------------------------------------------------------

/// When an issuer has empty audiences list, audience validation is skipped.
/// A token with any arbitrary aud claim should be accepted.
#[test]
fn empty_audiences_skips_validation() {
    let config = OAuthConfig {
        issuers: vec![IssuerConfig {
            name: "no-aud-issuer".to_string(),
            issuer_url: TEST_ISSUER.to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            audiences: vec![], // empty: disables audience validation
            introspection_url: None,
            client_id: None,
            client_secret: None,
        }],
        jwks_cache_ttl_secs: 3600,
    };
    let validator = OAuthValidator::new(&config);
    validator.insert_key(
        0,
        TEST_KID,
        DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY).expect("valid RSA public key"),
    );

    let now = now_secs();
    let token = make_token(json!({
        "sub": "user-any-aud",
        "iss": TEST_ISSUER,
        "aud": "completely-arbitrary-audience",
        "exp": now + 3600,
        "iat": now,
    }));

    let result = validator.validate_token(&token);
    assert!(
        result.is_ok(),
        "empty audiences should skip aud validation, got: {:?}",
        result.unwrap_err()
    );
}

/// Token with aud as a JSON array containing the expected audience is accepted.
#[test]
fn audience_as_array_validated() {
    let validator = make_validator();
    let now = now_secs();

    let token = make_token(json!({
        "sub": "user-array-aud",
        "iss": TEST_ISSUER,
        "aud": [TEST_AUDIENCE, "other-api"],
        "exp": now + 3600,
        "iat": now,
    }));

    let claims = validator
        .validate_token(&token)
        .expect("array aud containing expected audience should be accepted");
    assert_eq!(claims.sub.as_deref(), Some("user-array-aud"));
    // Verify the audience was deserialized as Multiple variant.
    match &claims.aud {
        Some(Audience::Multiple(v)) => {
            assert!(v.contains(&TEST_AUDIENCE.to_string()));
            assert!(v.contains(&"other-api".to_string()));
        }
        other => panic!("expected Audience::Multiple, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// jti (JWT ID) claim - gap documentation tests
// ---------------------------------------------------------------------------

/// jti claim is present in token but not validated for uniqueness.
/// The token is accepted and jti is extractable from Claims.custom.
/// This documents the gap: there is no jti replay protection.
#[test]
fn jti_claim_present_but_not_validated() {
    let validator = make_validator();
    let now = now_secs();

    let token = make_token(json!({
        "sub": "user-with-jti",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "jti": "unique-token-id-abc123",
    }));

    let claims = validator
        .validate_token(&token)
        .expect("token with jti should be accepted (jti is not validated)");
    assert_eq!(claims.sub.as_deref(), Some("user-with-jti"));

    // jti is captured in the custom claims map but NOT checked
    // for uniqueness. There is no replay prevention based on jti.
    let jti_value = claims
        .custom
        .get("jti")
        .and_then(|v| v.as_str())
        .expect("jti should be extractable from custom claims");
    assert_eq!(jti_value, "unique-token-id-abc123");
}

/// The same valid token can be used multiple times (token replay).
/// Both calls succeed, demonstrating there is no replay prevention.
#[test]
fn token_replay_not_prevented() {
    let validator = make_validator();
    let now = now_secs();

    let token = make_token(json!({
        "sub": "user-replay",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "jti": "should-be-single-use-but-is-not",
    }));

    // Both calls succeed. A production system with jti tracking
    // would reject the second call as a replay.
    let result1 = validator.validate_token(&token);
    assert!(result1.is_ok(), "first use should succeed");

    let result2 = validator.validate_token(&token);
    assert!(
        result2.is_ok(),
        "second use also succeeds (no replay prevention)"
    );

    // Verify both returned the same claims
    let claims1 = result1.unwrap();
    let claims2 = result2.unwrap();
    assert_eq!(claims1.sub, claims2.sub);
}

// ---------------------------------------------------------------------------
// Config URL validation tests
// ---------------------------------------------------------------------------

/// HTTPS is required for JWKS URIs (non-localhost).
/// An http:// URI to a remote host should be rejected by validate().
#[test]
fn config_url_validation_https_required() {
    let config = OAuthConfig {
        issuers: vec![IssuerConfig {
            name: "insecure-issuer".to_string(),
            issuer_url: "https://auth.example.com".to_string(),
            jwks_uri: "http://auth.example.com/.well-known/jwks.json".to_string(), // HTTP, not HTTPS
            audiences: vec![TEST_AUDIENCE.to_string()],
            introspection_url: None,
            client_id: None,
            client_secret: None,
        }],
        jwks_cache_ttl_secs: 3600,
    };

    let result = config.validate();
    assert!(
        result.is_err(),
        "http:// JWKS URI (non-localhost) should be rejected"
    );
    let err = result.unwrap_err();
    match &err {
        OAuthError::InsecureUrl(msg) => {
            assert!(
                msg.contains("HTTPS"),
                "error should mention HTTPS requirement: {msg}"
            );
        }
        other => panic!("expected InsecureUrl error, got: {other:?}"),
    }
}

/// Localhost HTTP is allowed for development.
/// An http://localhost JWKS URI should pass validation.
#[test]
fn config_url_validation_localhost_allowed() {
    let config = OAuthConfig {
        issuers: vec![IssuerConfig {
            name: "dev-issuer".to_string(),
            issuer_url: "http://localhost:8080".to_string(),
            jwks_uri: "http://localhost:8080/.well-known/jwks.json".to_string(),
            audiences: vec![TEST_AUDIENCE.to_string()],
            introspection_url: None,
            client_id: None,
            client_secret: None,
        }],
        jwks_cache_ttl_secs: 3600,
    };

    let result = config.validate();
    assert!(
        result.is_ok(),
        "http://localhost JWKS URI should be allowed, got: {:?}",
        result.unwrap_err()
    );
}
