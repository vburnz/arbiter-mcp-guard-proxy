//! Response body data classification.
//!
//! Scans upstream response bodies for sensitive data patterns (PII, secrets,
//! internal infrastructure) and reports findings with sensitivity levels.
//! Used by the gateway to enforce data sensitivity ceilings per session.

use regex::Regex;
use std::sync::LazyLock;

/// Sensitivity level of detected data in a response body.
///
/// Ordered from least to most sensitive, matching the ordering of
/// [`arbiter_session::DataSensitivity`] (minus `Public`, which cannot be
/// "detected" — it is the absence of sensitive content).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectedSensitivity {
    /// Emails, internal IPs — organizational metadata.
    Internal,
    /// PII: SSNs, credit card numbers, phone numbers.
    Confidential,
    /// Secrets: private keys, AWS keys, bearer tokens, API keys.
    Restricted,
}

/// A finding from response body scanning.
#[derive(Debug, Clone)]
pub struct DataFinding {
    /// The sensitivity level of the detected pattern.
    pub sensitivity: DetectedSensitivity,
    /// Human-readable name of the pattern that matched.
    pub pattern_name: &'static str,
}

// ---------------------------------------------------------------------------
// Pattern definitions (LazyLock<Regex>)
// ---------------------------------------------------------------------------

// ── Restricted ─────────────────────────────────────────────────────────

static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("AWS access key regex is valid"));

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN.*PRIVATE KEY-----").expect("private key regex is valid")
});

static BEARER_TOKEN_JSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[Bb]earer\s+[a-zA-Z0-9._\-]{20,}"#).expect("bearer token regex is valid")
});

static GENERIC_API_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-[a-zA-Z0-9]{20,}").expect("generic API key regex is valid"));

// ── Confidential ───────────────────────────────────────────────────────

static SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("SSN regex is valid"));

static CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").expect("credit card regex is valid")
});

static EMAIL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
        .expect("email regex is valid")
});

// ── Internal ───────────────────────────────────────────────────────────

static INTERNAL_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b")
        .expect("internal IP regex is valid")
});

/// All patterns paired with their sensitivity and name.
static PATTERNS: LazyLock<Vec<(DetectedSensitivity, &'static str, &'static LazyLock<Regex>)>> =
    LazyLock::new(|| {
        vec![
            // Restricted
            (
                DetectedSensitivity::Restricted,
                "AWS access key",
                &AWS_ACCESS_KEY,
            ),
            (DetectedSensitivity::Restricted, "private key", &PRIVATE_KEY),
            (
                DetectedSensitivity::Restricted,
                "bearer token",
                &BEARER_TOKEN_JSON,
            ),
            (
                DetectedSensitivity::Restricted,
                "generic API key (sk-)",
                &GENERIC_API_KEY,
            ),
            // Confidential
            (DetectedSensitivity::Confidential, "SSN", &SSN),
            (
                DetectedSensitivity::Confidential,
                "credit card number",
                &CREDIT_CARD,
            ),
            (
                DetectedSensitivity::Confidential,
                "email address",
                &EMAIL_ADDRESS,
            ),
            // Internal
            (
                DetectedSensitivity::Internal,
                "internal IP address",
                &INTERNAL_IP,
            ),
        ]
    });

/// Scan a response body for sensitive data patterns.
///
/// Returns all findings. Callers should compare the highest finding sensitivity
/// against the session's `data_sensitivity_ceiling` to decide whether to block
/// or flag the response.
pub fn scan_response(body: &str) -> Vec<DataFinding> {
    let mut findings = Vec::new();
    for (sensitivity, name, pattern) in PATTERNS.iter() {
        if pattern.is_match(body) {
            findings.push(DataFinding {
                sensitivity: *sensitivity,
                pattern_name: name,
            });
        }
    }
    findings
}

/// Return the highest (most sensitive) finding, if any.
pub fn max_sensitivity(findings: &[DataFinding]) -> Option<DetectedSensitivity> {
    findings.iter().map(|f| f.sensitivity).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Individual pattern tests ────────────────────────────────────────

    #[test]
    fn detects_aws_access_key() {
        let body = r#"{"access_key": "AKIAIOSFODNN7EXAMPLE"}"#;
        let findings = scan_response(body);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sensitivity, DetectedSensitivity::Restricted);
        assert_eq!(findings[0].pattern_name, "AWS access key");
    }

    #[test]
    fn detects_private_key() {
        let body = "here is -----BEGIN RSA PRIVATE KEY----- data";
        let findings = scan_response(body);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sensitivity, DetectedSensitivity::Restricted);
        assert_eq!(findings[0].pattern_name, "private key");
    }

    #[test]
    fn detects_ec_private_key() {
        let body = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...";
        let findings = scan_response(body);
        assert!(
            findings.iter().any(|f| f.pattern_name == "private key"),
            "should detect EC private keys"
        );
    }

    #[test]
    fn detects_bearer_token() {
        let body = r#"{"auth": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"}"#;
        let findings = scan_response(body);
        assert!(
            findings.iter().any(|f| f.pattern_name == "bearer token"),
            "should detect bearer tokens in JSON, findings: {:?}",
            findings
        );
    }

    #[test]
    fn detects_generic_api_key() {
        let body = r#"{"key": "sk-abcdefghijklmnopqrstuvwx"}"#;
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "generic API key (sk-)"),
            "should detect sk- prefixed API keys"
        );
    }

    #[test]
    fn detects_ssn() {
        let body = r#"{"ssn": "123-45-6789"}"#;
        let findings = scan_response(body);
        assert!(
            findings.iter().any(|f| f.pattern_name == "SSN"),
            "should detect SSN patterns"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.pattern_name == "SSN")
                .unwrap()
                .sensitivity,
            DetectedSensitivity::Confidential
        );
    }

    #[test]
    fn detects_credit_card() {
        let body = "card: 4111-1111-1111-1111";
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "credit card number"),
            "should detect credit card numbers"
        );
    }

    #[test]
    fn detects_credit_card_with_spaces() {
        let body = "card: 4111 1111 1111 1111";
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "credit card number"),
            "should detect credit card numbers with spaces"
        );
    }

    #[test]
    fn detects_credit_card_contiguous() {
        let body = "card: 4111111111111111";
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "credit card number"),
            "should detect contiguous credit card numbers"
        );
    }

    #[test]
    fn detects_email_address() {
        let body = r#"{"email": "user@example.com"}"#;
        let findings = scan_response(body);
        assert!(
            findings.iter().any(|f| f.pattern_name == "email address"),
            "should detect email addresses"
        );
    }

    #[test]
    fn detects_internal_ip_10() {
        let body = "server: 10.0.1.42";
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "internal IP address"),
            "should detect 10.x.x.x IPs"
        );
    }

    #[test]
    fn detects_internal_ip_172() {
        let body = "server: 172.16.0.1";
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "internal IP address"),
            "should detect 172.16-31.x.x IPs"
        );
    }

    #[test]
    fn detects_internal_ip_192_168() {
        let body = "server: 192.168.1.1";
        let findings = scan_response(body);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "internal IP address"),
            "should detect 192.168.x.x IPs"
        );
    }

    // ── Negative tests ─────────────────────────────────────────────────

    #[test]
    fn clean_response_has_no_findings() {
        let body = r#"{"status": "ok", "count": 42, "message": "hello world"}"#;
        let findings = scan_response(body);
        assert!(findings.is_empty(), "clean body should have no findings");
    }

    #[test]
    fn partial_aws_key_not_matched() {
        // AKIA + only 5 chars (need 16)
        let body = "key: AKIA12345";
        let findings = scan_response(body);
        assert!(
            !findings.iter().any(|f| f.pattern_name == "AWS access key"),
            "partial AWS key (too short) should not match"
        );
    }

    #[test]
    fn short_sk_key_not_matched() {
        // sk- followed by only 10 chars (need 20+)
        let body = "key: sk-abc1234567";
        let findings = scan_response(body);
        assert!(
            !findings
                .iter()
                .any(|f| f.pattern_name == "generic API key (sk-)"),
            "short sk- key should not match"
        );
    }

    #[test]
    fn public_ip_not_matched() {
        let body = "server: 8.8.8.8";
        let findings = scan_response(body);
        assert!(
            !findings
                .iter()
                .any(|f| f.pattern_name == "internal IP address"),
            "public IP 8.8.8.8 should not match"
        );
    }

    #[test]
    fn non_rfc1918_172_not_matched() {
        // 172.32.x.x is outside the private range (172.16-31)
        let body = "server: 172.32.0.1";
        let findings = scan_response(body);
        assert!(
            !findings
                .iter()
                .any(|f| f.pattern_name == "internal IP address"),
            "172.32.x.x is not a private IP"
        );
    }

    #[test]
    fn short_bearer_not_matched() {
        // Bearer token with only 10 chars (need 20+)
        let body = r#""Bearer abc1234567""#;
        let findings = scan_response(body);
        assert!(
            !findings.iter().any(|f| f.pattern_name == "bearer token"),
            "short bearer token should not match"
        );
    }

    // ── Composite tests ────────────────────────────────────────────────

    #[test]
    fn multiple_findings_in_one_body() {
        let body = r#"{
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "ssn": "123-45-6789",
            "email": "test@internal.corp",
            "server": "10.0.0.5"
        }"#;
        let findings = scan_response(body);

        let pattern_names: Vec<&str> = findings.iter().map(|f| f.pattern_name).collect();
        assert!(
            pattern_names.contains(&"AWS access key"),
            "should find AWS key"
        );
        assert!(pattern_names.contains(&"SSN"), "should find SSN");
        assert!(
            pattern_names.contains(&"email address"),
            "should find email"
        );
        assert!(
            pattern_names.contains(&"internal IP address"),
            "should find internal IP"
        );
        assert!(findings.len() >= 4, "should find at least 4 patterns");
    }

    #[test]
    fn max_sensitivity_returns_highest() {
        let body = r#"{
            "ssn": "123-45-6789",
            "key": "AKIAIOSFODNN7EXAMPLE"
        }"#;
        let findings = scan_response(body);
        assert_eq!(
            max_sensitivity(&findings),
            Some(DetectedSensitivity::Restricted),
            "max should be Restricted when AWS key is present"
        );
    }

    #[test]
    fn max_sensitivity_empty_findings() {
        let findings: Vec<DataFinding> = vec![];
        assert_eq!(max_sensitivity(&findings), None);
    }

    #[test]
    fn max_sensitivity_internal_only() {
        let body = "server at 10.0.0.1";
        let findings = scan_response(body);
        assert_eq!(
            max_sensitivity(&findings),
            Some(DetectedSensitivity::Internal)
        );
    }

    // ── Ordering test ──────────────────────────────────────────────────

    #[test]
    fn detected_sensitivity_ordering() {
        assert!(DetectedSensitivity::Internal < DetectedSensitivity::Confidential);
        assert!(DetectedSensitivity::Confidential < DetectedSensitivity::Restricted);
        assert!(DetectedSensitivity::Internal < DetectedSensitivity::Restricted);
    }

    // ── Integration-level test: SSN in Public-ceiling session ──────────

    #[test]
    fn ssn_exceeds_public_ceiling() {
        use arbiter_session::DataSensitivity;

        let ceiling = DataSensitivity::Public;
        let body = r#"{"customer_ssn": "123-45-6789"}"#;
        let findings = scan_response(body);
        assert!(!findings.is_empty(), "should detect SSN");

        let max = max_sensitivity(&findings).unwrap();
        // Map DetectedSensitivity to DataSensitivity for comparison
        let detected_as_data_sensitivity = match max {
            DetectedSensitivity::Internal => DataSensitivity::Internal,
            DetectedSensitivity::Confidential => DataSensitivity::Confidential,
            DetectedSensitivity::Restricted => DataSensitivity::Restricted,
        };

        assert!(
            detected_as_data_sensitivity > ceiling,
            "Confidential SSN data ({:?}) should exceed Public ceiling ({:?})",
            detected_as_data_sensitivity,
            ceiling
        );
    }

    #[test]
    fn internal_data_within_internal_ceiling() {
        use arbiter_session::DataSensitivity;

        let ceiling = DataSensitivity::Internal;
        let body = "backend at 10.0.0.5";
        let findings = scan_response(body);
        let max = max_sensitivity(&findings).unwrap();

        let detected_as_data_sensitivity = match max {
            DetectedSensitivity::Internal => DataSensitivity::Internal,
            DetectedSensitivity::Confidential => DataSensitivity::Confidential,
            DetectedSensitivity::Restricted => DataSensitivity::Restricted,
        };

        assert!(
            detected_as_data_sensitivity <= ceiling,
            "Internal data should be within Internal ceiling"
        );
    }

    #[test]
    fn restricted_data_blocked_for_confidential_ceiling() {
        use arbiter_session::DataSensitivity;

        let ceiling = DataSensitivity::Confidential;
        let body = "key: AKIAIOSFODNN7EXAMPLE";
        let findings = scan_response(body);
        let max = max_sensitivity(&findings).unwrap();

        let detected_as_data_sensitivity = match max {
            DetectedSensitivity::Internal => DataSensitivity::Internal,
            DetectedSensitivity::Confidential => DataSensitivity::Confidential,
            DetectedSensitivity::Restricted => DataSensitivity::Restricted,
        };

        assert!(
            detected_as_data_sensitivity > ceiling,
            "Restricted data should exceed Confidential ceiling"
        );
    }
}
