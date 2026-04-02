//! Credential injection middleware.
//!
//! Scans outgoing HTTP request bodies and headers for credential reference
//! patterns (`${CRED:ref_name}`) and substitutes them with resolved secret
//! values. Also scans response bodies to ensure credentials never leak back
//! to the agent.
//!
//! This module provides standalone async functions. Wiring into the full proxy
//! pipeline is done in the main binary crate.

use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use std::sync::LazyLock;
use tracing::{debug, warn};

use crate::error::CredentialError;
use crate::provider::CredentialProvider;

/// Pattern matching `${CRED:reference_name}`. The reference name is captured
/// in group 1 and may contain alphanumerics, underscores, hyphens, and dots.
static CRED_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{CRED:([A-Za-z0-9_.\-]+)\}").expect("credential pattern is valid regex")
});

/// The sentinel string used to mask leaked credentials in response bodies.
const REDACTED: &str = "[CREDENTIAL]";

/// Result of injecting credentials into a request.
#[derive(Debug)]
pub struct InjectedRequest {
    /// The rewritten request body with credential references substituted.
    pub body: String,
    /// Rewritten headers (name, value) with credential references substituted.
    pub headers: Vec<(String, String)>,
    /// Which credential references were resolved during injection.
    pub resolved_refs: Vec<String>,
    /// The actual resolved secret values for response scrubbing.
    /// Stored as [`SecretString`] so they are zeroized on drop and never
    /// accidentally exposed through `Debug` or `Display`.
    pub resolved_values: Vec<SecretString>,
}

/// Inject credentials into a request body and a set of headers.
///
/// Every occurrence of `${CRED:ref}` in `body` and in the header values is
/// replaced with the resolved secret. Returns an error if any referenced
/// credential cannot be resolved.
pub async fn inject_credentials(
    body: &str,
    headers: &[(String, String)],
    provider: &dyn CredentialProvider,
) -> Result<InjectedRequest, CredentialError> {
    let mut resolved_refs: Vec<String> = Vec::new();
    let mut resolved_values: Vec<SecretString> = Vec::new();

    // --- body ---
    let new_body = replace_refs(body, provider, &mut resolved_refs, &mut resolved_values).await?;

    // --- headers ---
    let mut new_headers = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let new_value =
            replace_refs(value, provider, &mut resolved_refs, &mut resolved_values).await?;
        new_headers.push((name.clone(), new_value));
    }

    debug!(count = resolved_refs.len(), "credential injection complete");

    Ok(InjectedRequest {
        body: new_body,
        headers: new_headers,
        resolved_refs,
        resolved_values,
    })
}

/// Encoding-aware response scrubbing using [`SecretString`] values.
///
/// The plaintext is only exposed for the duration of the scrub operation and
/// is not stored in any intermediate `String` that outlives this call.
///
/// `known_values` should contain the secret values that were injected into the
/// outgoing request so we can detect them if the upstream echoes them back.
pub fn scrub_response(body: &str, known_values: &[SecretString]) -> String {
    // Sort credentials by length (longest first) to prevent
    // partial-match interference. If credential A = "abc" and B = "abcdef",
    // scrubbing A first would mangle B's value, preventing its detection.
    let mut sorted_values: Vec<&SecretString> = known_values.iter().collect();
    sorted_values.sort_by_key(|v| std::cmp::Reverse(v.expose_secret().len()));

    let mut scrubbed = body.to_string();
    for secret in sorted_values {
        let value = secret.expose_secret();
        if value.is_empty() {
            continue;
        }
        scrub_single_value(&mut scrubbed, value);
    }
    scrubbed
}

/// Encoding-aware response scrubbing for plain `&[String]` values.
///
/// Backward-compatible entry point for callers that do not yet use
/// [`SecretString`]. Prefer [`scrub_response`] with `SecretString` values.
pub fn scrub_response_plain(body: &str, known_values: &[String]) -> String {
    let mut sorted_values: Vec<&String> = known_values.iter().collect();
    sorted_values.sort_by_key(|v| std::cmp::Reverse(v.len()));

    let mut scrubbed = body.to_string();
    for value in sorted_values {
        if value.is_empty() {
            continue;
        }
        scrub_single_value(&mut scrubbed, value);
    }
    scrubbed
}

/// Scrub all encoded variants of a single credential value from a response body.
fn scrub_single_value(scrubbed: &mut String, value: &str) {
    // Direct match
    if scrubbed.contains(value) {
        warn!("credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(value, REDACTED);
    }
    // URL-encoded variant
    let url_encoded = urlencoding_encode(value);
    if url_encoded != value && scrubbed.contains(&url_encoded) {
        warn!("URL-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&url_encoded, REDACTED);
    }
    // Lowercase percent-encoded variant (RFC 3986 allows both %2F and %2f).
    let url_lower = urlencoding_encode_lower(value);
    if url_lower != url_encoded && url_lower != value && scrubbed.contains(&url_lower) {
        warn!("lowercase-percent-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&url_lower, REDACTED);
    }
    // JSON-escaped variant (handles quotes, backslashes, etc.)
    if let Ok(json_str) = serde_json::to_string(value) {
        // Remove surrounding quotes from JSON string
        let json_escaped = &json_str[1..json_str.len() - 1];
        if json_escaped != value && scrubbed.contains(json_escaped) {
            warn!("JSON-escaped credential value detected in response body, scrubbing");
            *scrubbed = scrubbed.replace(json_escaped, REDACTED);
        }
    }
    // Hex-encoded variant (lowercase)
    let hex_encoded: String = value.bytes().map(|b| format!("{:02x}", b)).collect();
    if scrubbed.contains(&hex_encoded) {
        warn!("hex-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&hex_encoded, REDACTED);
    }
    // Uppercase hex variant.
    let hex_upper: String = value.bytes().map(|b| format!("{:02X}", b)).collect();
    if hex_upper != hex_encoded && scrubbed.contains(&hex_upper) {
        warn!("uppercase-hex-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&hex_upper, REDACTED);
    }
    // Base64-encoded credential scrubbing.
    let b64_encoded = base64_encode_value(value);
    if b64_encoded != value && scrubbed.contains(&b64_encoded) {
        warn!("base64-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&b64_encoded, REDACTED);
    }
    // Base64url variant (RFC 4648 S5: '-' '_', no padding).
    let b64url_encoded = base64url_encode_value(value);
    if b64url_encoded != value
        && b64url_encoded != b64_encoded
        && scrubbed.contains(&b64url_encoded)
    {
        warn!("base64url-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&b64url_encoded, REDACTED);
    }
    // Unicode JSON escape sequence variant (\u00XX per character).
    let unicode_escaped = unicode_json_escape(value);
    if unicode_escaped != value && scrubbed.contains(&unicode_escaped) {
        warn!("unicode-escaped credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&unicode_escaped, REDACTED);
    }
    // Double URL-encoding variant.
    let double_url_encoded = urlencoding_encode(&url_encoded);
    if double_url_encoded != url_encoded && scrubbed.contains(&double_url_encoded) {
        warn!("double-URL-encoded credential value detected in response body, scrubbing");
        *scrubbed = scrubbed.replace(&double_url_encoded, REDACTED);
    }
}

/// Simple percent-encoding for credential scrubbing.
fn urlencoding_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Lowercase percent-encoding variant for credential scrubbing.
/// RFC 3986 allows both `%2F` and `%2f`; the standard encoder uses uppercase,
/// but a malicious upstream may use lowercase to evade scrubbing.
fn urlencoding_encode_lower(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02x}", byte));
            }
        }
    }
    encoded
}

/// Unicode JSON escape sequence encoding (\u00XX per byte).
/// A credential "abc" becomes "\u0061\u0062\u0063" which is valid JSON
/// and renders identically when parsed.
fn unicode_json_escape(input: &str) -> String {
    input.bytes().map(|b| format!("\\u{:04x}", b)).collect()
}

/// Collect all `${CRED:...}` references found in `input`.
pub fn find_refs(input: &str) -> Vec<String> {
    CRED_PATTERN
        .captures_iter(input)
        .map(|cap| cap[1].to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Replace all `${CRED:ref}` patterns in `input` by resolving each reference
/// through the provider. Appends resolved reference names and values.
async fn replace_refs(
    input: &str,
    provider: &dyn CredentialProvider,
    resolved: &mut Vec<String>,
    secret_values: &mut Vec<SecretString>,
) -> Result<String, CredentialError> {
    // Collect all matches first so we can resolve them.
    let refs = find_refs(input);
    if refs.is_empty() {
        return Ok(input.to_string());
    }

    // Validate all credential references exist before injecting any.
    // This prevents partial injection where some refs are resolved but others fail,
    // which could leak information about which credential names are valid.
    let mut resolved_pairs: Vec<(String, SecretString)> = Vec::new();
    for reference in &refs {
        let value = provider.resolve(reference).await?;
        resolved_pairs.push((reference.clone(), value));
    }

    let mut output = input.to_string();
    for (reference, secret) in &resolved_pairs {
        let placeholder = format!("${{CRED:{reference}}}");
        output = output.replace(&placeholder, secret.expose_secret());
        if !resolved.contains(reference) {
            resolved.push(reference.clone());
            // Capture resolved values at injection time.
            // Previously the handler re-resolved from the provider for scrubbing,
            // which could return different values after credential rotation.
            secret_values.push(SecretString::from(secret.expose_secret().to_owned()));
        }
    }

    Ok(output)
}

/// Base64url encoding (RFC 4648 S5) for credential scrubbing.
/// Uses '-' and '_' instead of '+' and '/', no padding.
fn base64url_encode_value(input: &str) -> String {
    let standard = base64_encode_value(input);
    standard
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Simple base64 encoding for credential scrubbing (standard alphabet, with padding).
fn base64_encode_value(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{CredentialProvider, CredentialRef};
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// A trivial in-memory provider for tests.
    struct MockProvider {
        store: HashMap<String, String>,
    }

    impl MockProvider {
        fn new(entries: &[(&str, &str)]) -> Self {
            Self {
                store: entries
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
    }

    #[async_trait]
    impl CredentialProvider for MockProvider {
        async fn resolve(&self, reference: &str) -> Result<SecretString, CredentialError> {
            self.store
                .get(reference)
                .map(|v| SecretString::from(v.clone()))
                .ok_or_else(|| CredentialError::NotFound(reference.to_string()))
        }

        async fn list_refs(&self) -> Result<Vec<CredentialRef>, CredentialError> {
            Ok(self
                .store
                .keys()
                .map(|k| CredentialRef {
                    name: k.clone(),
                    provider: "mock".into(),
                    last_rotated: None,
                })
                .collect())
        }
    }

    /// Helper: create a Vec<SecretString> from plain string slices.
    fn secret_vec(values: &[&str]) -> Vec<SecretString> {
        values
            .iter()
            .map(|v| SecretString::from(v.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn injects_body_credentials() {
        let provider = MockProvider::new(&[("api_key", "sk-secret-123")]);
        let body = r#"{"key": "${CRED:api_key}"}"#;

        let result = inject_credentials(body, &[], &provider).await.unwrap();
        assert_eq!(result.body, r#"{"key": "sk-secret-123"}"#);
        assert_eq!(result.resolved_refs, vec!["api_key"]);
    }

    #[tokio::test]
    async fn injects_header_credentials() {
        let provider = MockProvider::new(&[("token", "ghp_abc")]);
        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer ${CRED:token}".to_string(),
            ),
            ("X-Custom".to_string(), "plain-value".to_string()),
        ];

        let result = inject_credentials("", &headers, &provider).await.unwrap();
        assert_eq!(result.headers[0].1, "Bearer ghp_abc");
        assert_eq!(result.headers[1].1, "plain-value");
    }

    #[tokio::test]
    async fn multiple_refs_in_body() {
        let provider = MockProvider::new(&[("a", "AAA"), ("b", "BBB")]);
        let body = "first=${CRED:a}&second=${CRED:b}";

        let result = inject_credentials(body, &[], &provider).await.unwrap();
        assert_eq!(result.body, "first=AAA&second=BBB");
        assert!(result.resolved_refs.contains(&"a".to_string()));
        assert!(result.resolved_refs.contains(&"b".to_string()));
    }

    #[tokio::test]
    async fn unknown_ref_returns_error() {
        let provider = MockProvider::new(&[]);
        let body = "key=${CRED:missing}";

        let err = inject_credentials(body, &[], &provider).await.unwrap_err();
        assert!(matches!(err, CredentialError::NotFound(_)));
    }

    #[tokio::test]
    async fn no_refs_is_passthrough() {
        let provider = MockProvider::new(&[]);
        let body = "no credential references here";

        let result = inject_credentials(body, &[], &provider).await.unwrap();
        assert_eq!(result.body, body);
        assert!(result.resolved_refs.is_empty());
    }

    #[test]
    fn scrub_response_masks_leaked_values() {
        let body = r#"{"echo": "sk-secret-123", "other": "safe"}"#;
        let known = secret_vec(&["sk-secret-123"]);

        let scrubbed = scrub_response(body, &known);
        assert_eq!(scrubbed, r#"{"echo": "[CREDENTIAL]", "other": "safe"}"#);
    }

    #[test]
    fn scrub_response_no_match_is_passthrough() {
        let body = "nothing to see here";
        let known = secret_vec(&["secret"]);
        let scrubbed = scrub_response(body, &known);
        assert_eq!(scrubbed, body);
    }

    #[test]
    fn scrub_response_empty_value_ignored() {
        let body = "some body";
        let known = secret_vec(&[""]);
        let scrubbed = scrub_response(body, &known);
        assert_eq!(scrubbed, body);
    }

    #[test]
    fn scrub_response_multiple_values() {
        let body = "has AAA and BBB in it";
        let known = secret_vec(&["AAA", "BBB"]);
        let scrubbed = scrub_response(body, &known);
        assert_eq!(scrubbed, "has [CREDENTIAL] and [CREDENTIAL] in it");
    }

    #[test]
    fn find_refs_extracts_all_references() {
        let input = "${CRED:one} and ${CRED:two.three} and ${CRED:four-five}";
        let refs = find_refs(input);
        assert_eq!(refs, vec!["one", "two.three", "four-five"]);
    }

    #[test]
    fn find_refs_empty_on_no_match() {
        assert!(find_refs("no credentials here").is_empty());
    }

    // -----------------------------------------------------------------------
    // Encoding-aware scrubbing tests
    // -----------------------------------------------------------------------

    #[test]
    fn scrub_response_url_encoded() {
        let known = secret_vec(&["p@ss w0rd!"]);
        let body = "the response contains p%40ss%20w0rd%21 in a query string";

        let scrubbed = scrub_response(body, &known);
        assert_eq!(
            scrubbed,
            "the response contains [CREDENTIAL] in a query string"
        );
        assert!(!scrubbed.contains("%40"));
        assert!(!scrubbed.contains("%20"));
        assert!(!scrubbed.contains("%21"));
    }

    #[test]
    fn scrub_response_json_escaped() {
        let known = secret_vec(&[r#"pass"word\"#]);
        let body = r#"{"field": "pass\"word\\"}"#;

        let scrubbed = scrub_response(body, &known);
        assert_eq!(scrubbed, r#"{"field": "[CREDENTIAL]"}"#);
        assert!(!scrubbed.contains("pass"));
        assert!(!scrubbed.contains("word"));
    }

    #[test]
    fn scrub_response_hex_encoded() {
        let hex_of_secret = "736563726574";
        let body = format!("debug dump: hex={hex_of_secret} end");
        let known = secret_vec(&["secret"]);

        let scrubbed = scrub_response(&body, &known);
        assert_eq!(scrubbed, "debug dump: hex=[CREDENTIAL] end");
        assert!(!scrubbed.contains(hex_of_secret));
    }

    #[test]
    fn scrub_response_base64_encoded() {
        let b64 = base64_encode_value("my-secret-key");
        assert_eq!(b64, "bXktc2VjcmV0LWtleQ==");
        let body = format!("Authorization: Basic {b64} is here");
        let known = secret_vec(&["my-secret-key"]);

        let scrubbed = scrub_response(&body, &known);
        assert_eq!(scrubbed, "Authorization: Basic [CREDENTIAL] is here");
        assert!(!scrubbed.contains(&b64));
    }

    #[test]
    fn scrub_response_longest_first_ordering() {
        let known = secret_vec(&["abc", "abcdef"]);
        let body = "values: abcdef and abc end";

        let scrubbed = scrub_response(body, &known);
        assert_eq!(scrubbed, "values: [CREDENTIAL] and [CREDENTIAL] end");
        assert!(!scrubbed.contains("abc"));
        assert!(!scrubbed.contains("abcdef"));
    }

    #[test]
    fn scrub_response_all_encodings_simultaneously() {
        let secret = "s3cr&t!";
        let url_enc = urlencoding_encode(secret);
        let hex_enc: String = secret.bytes().map(|b| format!("{:02x}", b)).collect();
        let b64_enc = base64_encode_value(secret);
        let json_enc = {
            let full = serde_json::to_string(secret).unwrap();
            full[1..full.len() - 1].to_string()
        };

        let body =
            format!("plain={secret} url={url_enc} json={json_enc} hex={hex_enc} b64={b64_enc}");
        let known = secret_vec(&[secret]);

        let scrubbed = scrub_response(&body, &known);

        assert_eq!(
            scrubbed,
            "plain=[CREDENTIAL] url=[CREDENTIAL] json=[CREDENTIAL] hex=[CREDENTIAL] b64=[CREDENTIAL]"
        );
        assert!(!scrubbed.contains(secret));
        assert!(!scrubbed.contains(&url_enc));
        assert!(!scrubbed.contains(&hex_enc));
        assert!(!scrubbed.contains(&b64_enc));
    }

    #[tokio::test]
    async fn scrub_response_partial_injection_prevented() {
        let provider = MockProvider::new(&[("valid_key", "resolved-value")]);
        let body = "first=${CRED:valid_key}&second=${CRED:missing_key}";

        let result = inject_credentials(body, &[], &provider).await;
        assert!(
            result.is_err(),
            "injection must fail when any ref is unresolvable"
        );
        assert!(
            matches!(result.unwrap_err(), CredentialError::NotFound(ref name) if name == "missing_key")
        );
    }

    #[tokio::test]
    async fn resolved_values_captured_at_injection_time() {
        let provider = MockProvider::new(&[("key_a", "alpha-secret"), ("key_b", "beta-secret")]);
        let body = "a=${CRED:key_a} b=${CRED:key_b}";

        let result = inject_credentials(body, &[], &provider).await.unwrap();

        assert_eq!(result.body, "a=alpha-secret b=beta-secret");

        let exposed: Vec<&str> = result
            .resolved_values
            .iter()
            .map(|s| s.expose_secret())
            .collect();
        assert!(exposed.contains(&"alpha-secret"));
        assert!(exposed.contains(&"beta-secret"));
        assert_eq!(result.resolved_values.len(), 2);

        let leaked_response = "upstream echoed alpha-secret back";
        let scrubbed = scrub_response(leaked_response, &result.resolved_values);
        assert_eq!(scrubbed, "upstream echoed [CREDENTIAL] back");
    }

    // -----------------------------------------------------------------------
    // Recursive credential injection must not expand
    // -----------------------------------------------------------------------

    #[test]
    fn recursive_ref_not_expanded() {
        let input = "${CRED:${CRED:inner}}";
        let refs = find_refs(input);
        assert_eq!(
            refs,
            vec!["inner"],
            "only the inner ref 'inner' should be matched. Got: {:?}",
            refs
        );

        let input3 = "${CRED:${CRED:${CRED:deep}}}";
        let refs3 = find_refs(input3);
        assert_eq!(
            refs3,
            vec!["deep"],
            "only the innermost ref 'deep' should be matched. Got: {:?}",
            refs3
        );
    }

    #[tokio::test]
    async fn recursive_injection_does_not_re_expand() {
        let provider = MockProvider::new(&[("outer", "${CRED:inner}"), ("inner", "real-secret")]);
        let body = "key=${CRED:outer}";

        let result = inject_credentials(body, &[], &provider).await.unwrap();

        assert_eq!(
            result.body, "key=${CRED:inner}",
            "credential values containing ${{CRED:...}} must NOT be re-expanded"
        );
        assert_eq!(result.resolved_refs, vec!["outer"]);
    }

    // -----------------------------------------------------------------------
    // Credential value with regex metacharacters in scrubbing
    // -----------------------------------------------------------------------

    #[test]
    fn credential_with_special_chars_in_value() {
        let special_value = r"p@$$w0rd!.*+";
        let body = format!("the password is {} here", special_value);
        let known = secret_vec(&[special_value]);

        let scrubbed = scrub_response(&body, &known);
        assert_eq!(
            scrubbed, "the password is [CREDENTIAL] here",
            "credential with regex metacharacters must be scrubbed literally"
        );
        assert!(
            !scrubbed.contains(special_value),
            "original credential value must not survive in scrubbed output"
        );
    }

    #[test]
    fn credential_ref_name_injection_rejected() {
        assert!(find_refs("${CRED:../../etc/passwd}").is_empty());
        assert!(find_refs("${CRED:..\\..\\windows\\system32}").is_empty());
        assert!(find_refs("${CRED:ref;rm -rf /}").is_empty());
        assert!(find_refs("${CRED:ref$(whoami)}").is_empty());
        assert!(find_refs("${CRED:ref`id`}").is_empty());
        assert!(find_refs("${CRED:ref name}").is_empty());
        assert!(find_refs("${CRED:ref&other}").is_empty());
        assert!(find_refs("${CRED:ref|pipe}").is_empty());
        assert!(find_refs("${CRED:}").is_empty());
        assert_eq!(
            find_refs("${CRED:valid.ref-name_123}"),
            vec!["valid.ref-name_123"]
        );
        assert_eq!(find_refs("${CRED:API_KEY}"), vec!["API_KEY"]);
        assert_eq!(find_refs("${CRED:my-secret.v2}"), vec!["my-secret.v2"]);
    }

    // -----------------------------------------------------------------------
    // Encoding variant bypass tests
    // -----------------------------------------------------------------------

    fn test_base64url_encode(input: &str) -> String {
        let standard = base64_encode_value(input);
        standard
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string()
    }

    #[test]
    fn scrub_response_base64url_bypass() {
        let secret = "secret+key/value";
        let b64url_encoded = test_base64url_encode(secret);
        let b64_standard = base64_encode_value(secret);
        assert_ne!(
            b64url_encoded, b64_standard,
            "base64url and standard base64 should differ for this input"
        );

        let body = format!("token={b64url_encoded} end");
        let known = secret_vec(&[secret]);
        let scrubbed = scrub_response(&body, &known);

        assert!(
            !scrubbed.contains(&b64url_encoded),
            "SCRUBBING BYPASS: base64url-encoded credential survives in response: {scrubbed}"
        );
    }

    #[test]
    fn scrub_response_uppercase_hex_bypass() {
        let secret = "sk-key";
        let upper_hex: String = secret.bytes().map(|b| format!("{:02X}", b)).collect();
        let lower_hex: String = secret.bytes().map(|b| format!("{:02x}", b)).collect();
        assert_ne!(
            upper_hex, lower_hex,
            "test requires hex representations to differ: upper={upper_hex} lower={lower_hex}"
        );

        let body = format!("hex={upper_hex} end");
        let known = secret_vec(&[secret]);
        let scrubbed = scrub_response(&body, &known);

        assert!(
            !scrubbed.contains(&upper_hex),
            "SCRUBBING BYPASS: uppercase-hex credential survives in response: {scrubbed}"
        );
    }

    #[test]
    fn scrub_response_double_url_encoding_bypass() {
        let secret = "p@ss!";
        let single_encoded = urlencoding_encode(secret);
        let double_encoded = urlencoding_encode(&single_encoded);

        assert_ne!(single_encoded, double_encoded);

        let body = format!("reflected={double_encoded} end");
        let known = secret_vec(&[secret]);
        let scrubbed = scrub_response(&body, &known);

        assert!(
            !scrubbed.contains(&double_encoded),
            "SCRUBBING BYPASS: double-URL-encoded credential survives in response: {scrubbed}"
        );
    }

    // -----------------------------------------------------------------------
    // Memory safety: SecretString Debug/Display never leaks plaintext
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn secret_string_debug_does_not_leak() {
        let provider = MockProvider::new(&[("api_key", "super-secret-value-12345")]);
        let body = r#"{"key": "${CRED:api_key}"}"#;

        let result = inject_credentials(body, &[], &provider).await.unwrap();

        // Debug formatting of resolved_values must NOT contain the plaintext.
        // Note: the body field legitimately contains the injected credential
        // (it's the rewritten request), so we check resolved_values specifically.
        let values_debug = format!("{:?}", result.resolved_values);
        assert!(
            !values_debug.contains("super-secret-value-12345"),
            "Debug output of resolved_values must not contain plaintext credential. Got: {values_debug}"
        );
        // The SecretString Debug impl should show the redacted wrapper
        assert!(
            values_debug.contains("REDACTED") || values_debug.contains("SecretBox"),
            "Debug output should show redacted wrapper, got: {values_debug}"
        );
    }

    #[test]
    fn scrub_response_with_secret_string() {
        // Verify that scrub_response works correctly with SecretString values,
        // scrubbing all encoding variants.
        let secrets = secret_vec(&["my-api-key-999"]);
        let b64 = base64_encode_value("my-api-key-999");
        let hex: String = "my-api-key-999"
            .bytes()
            .map(|b| format!("{:02x}", b))
            .collect();

        let body = format!("plain=my-api-key-999 b64={b64} hex={hex}");
        let scrubbed = scrub_response(&body, &secrets);

        assert!(
            !scrubbed.contains("my-api-key-999"),
            "plaintext must be scrubbed"
        );
        assert!(!scrubbed.contains(&b64), "base64 must be scrubbed");
        assert!(!scrubbed.contains(&hex), "hex must be scrubbed");
        assert_eq!(
            scrubbed,
            "plain=[CREDENTIAL] b64=[CREDENTIAL] hex=[CREDENTIAL]"
        );
    }

    #[tokio::test]
    async fn scrub_response_lowercase_percent_encoding() {
        let secret = SecretString::from("my-secret/value".to_string());
        // Lowercase percent-encoded: '/' becomes %2f instead of %2F
        let response = "result: my-secret%2fvalue";
        let scrubbed = scrub_response(response, &[secret]);
        assert!(
            !scrubbed.contains("my-secret"),
            "lowercase percent-encoded credential should be scrubbed"
        );
        assert!(scrubbed.contains(REDACTED));
    }

    #[tokio::test]
    async fn scrub_response_unicode_json_escape() {
        let secret = SecretString::from("abc".to_string());
        let response = r#"{"data": "\u0061\u0062\u0063"}"#;
        let scrubbed = scrub_response(response, &[secret]);
        assert!(
            !scrubbed.contains(r"\u0061\u0062\u0063"),
            "unicode-escaped credential should be scrubbed"
        );
        assert!(scrubbed.contains(REDACTED));
    }
}
