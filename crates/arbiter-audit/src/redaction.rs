//! Argument redaction for sensitive fields.
//!
//! Walks a JSON value tree and replaces any object key matching a configured
//! pattern with `"[REDACTED]"`. Patterns use case-insensitive word-boundary
//! matching (letters only) compiled to regexes, so `key` matches `api_key`
//! but not `monkey` or `keyboard`.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Placeholder text inserted in place of redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Configuration for argument redaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    /// Case-insensitive patterns matched against JSON object keys using
    /// letter-boundary matching. A pattern matches when it is not surrounded
    /// by letters on both sides (underscores, hyphens, digits, and string
    /// boundaries act as separators).
    pub patterns: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        // Expanded default redaction patterns to cover common variants.
        Self {
            patterns: vec![
                "password".into(),
                "passwd".into(),
                "pwd".into(),
                "token".into(),
                "access_token".into(),
                "refresh_token".into(),
                "secret".into(),
                "client_secret".into(),
                "key".into(),
                "api_key".into(),
                "apikey".into(),
                "api-key".into(),
                "authorization".into(),
                "auth".into(),
                "credential".into(),
                "cred".into(),
                "private".into(),
                "private_key".into(),
                "ssn".into(),
                "social_security".into(),
                "credit_card".into(),
                "card_number".into(),
                "cvv".into(),
                "cvc".into(),
            ],
        }
    }
}

/// Pre-compiled redaction patterns for efficient per-request redaction.
///
/// Compile once at startup via [`RedactionConfig::compile`] and reuse across
/// requests. Previously, regexes were compiled on every call to
/// [`redact_arguments`], adding unnecessary CPU overhead under load.
#[derive(Debug, Clone)]
pub struct CompiledRedaction {
    patterns: Vec<Regex>,
}

impl CompiledRedaction {
    /// Redact sensitive fields using pre-compiled patterns.
    pub fn redact(&self, value: &serde_json::Value) -> serde_json::Value {
        redact_value(value, &self.patterns)
    }
}

impl RedactionConfig {
    /// Pre-compile patterns into regexes for reuse across requests.
    pub fn compile(&self) -> CompiledRedaction {
        let patterns = self
            .patterns
            .iter()
            .filter_map(|p| Regex::new(&format!("(?i){}", regex::escape(p))).ok())
            .collect();
        CompiledRedaction { patterns }
    }
}

/// Redact sensitive fields in a JSON value based on the given configuration.
///
/// Object keys matching any pattern (case-insensitive, letter-boundary) have
/// their values replaced with `"[REDACTED]"`. The walk is recursive through
/// objects and arrays.
///
/// For hot-path usage, prefer [`RedactionConfig::compile`] + [`CompiledRedaction::redact`]
/// to avoid recompiling regexes on every call.
pub fn redact_arguments(value: &serde_json::Value, config: &RedactionConfig) -> serde_json::Value {
    config.compile().redact(value)
}

/// Check whether a pattern match has letter-boundaries: the characters
/// immediately before and after the match must NOT be ASCII letters.
/// This prevents `key` from matching inside `monkey` or `keyboard`,
/// while still matching `api_key`, `api-key`, or standalone `key`.
fn has_letter_boundary_match(key: &str, pattern: &Regex) -> bool {
    for m in pattern.find_iter(key) {
        let before = key[..m.start()].chars().next_back();
        let after = key[m.end()..].chars().next();
        let preceded_by_letter = before.is_some_and(|c| c.is_ascii_alphabetic());
        let followed_by_letter = after.is_some_and(|c| c.is_ascii_alphabetic());
        if !preceded_by_letter && !followed_by_letter {
            return true;
        }
    }
    false
}

/// Maximum recursion depth for redaction to prevent stack overflow
/// from adversarially deep JSON structures.
const MAX_REDACTION_DEPTH: usize = 64;

fn redact_value(value: &serde_json::Value, patterns: &[Regex]) -> serde_json::Value {
    redact_value_depth(value, patterns, 0)
}

fn redact_value_depth(
    value: &serde_json::Value,
    patterns: &[Regex],
    depth: usize,
) -> serde_json::Value {
    if depth >= MAX_REDACTION_DEPTH {
        // Truncate at max depth to prevent stack overflow.
        return serde_json::Value::String("[TRUNCATED: max redaction depth]".into());
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (k, v) in map {
                if patterns.iter().any(|p| has_letter_boundary_match(k, p)) {
                    redacted.insert(k.clone(), serde_json::Value::String(REDACTED.into()));
                } else {
                    redacted.insert(k.clone(), redact_value_depth(v, patterns, depth + 1));
                }
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| redact_value_depth(v, patterns, depth + 1))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_sensitive_fields() {
        let config = RedactionConfig::default();
        let input = json!({
            "path": "/etc/hosts",
            "api_key": "sk-12345",
            "password": "hunter2",
            "nested": {
                "access_token": "abc",
                "count": 42
            }
        });

        let redacted = redact_arguments(&input, &config);

        assert_eq!(redacted["path"], "/etc/hosts");
        assert_eq!(redacted["api_key"], REDACTED);
        assert_eq!(redacted["password"], REDACTED);
        assert_eq!(redacted["nested"]["access_token"], REDACTED);
        assert_eq!(redacted["nested"]["count"], 42);
    }

    #[test]
    fn redaction_is_case_insensitive() {
        let config = RedactionConfig {
            patterns: vec!["secret".into()],
        };
        let input = json!({
            "SECRET_VALUE": "classified",
            "my_Secret": "also classified",
            "public": "visible"
        });

        let redacted = redact_arguments(&input, &config);

        assert_eq!(redacted["SECRET_VALUE"], REDACTED);
        assert_eq!(redacted["my_Secret"], REDACTED);
        assert_eq!(redacted["public"], "visible");
    }

    #[test]
    fn redacts_inside_arrays() {
        let config = RedactionConfig {
            patterns: vec!["token".into()],
        };
        let input = json!([
            {"token": "abc", "id": 1},
            {"token": "def", "id": 2}
        ]);

        let redacted = redact_arguments(&input, &config);
        let arr = redacted.as_array().unwrap();

        assert_eq!(arr[0]["token"], REDACTED);
        assert_eq!(arr[0]["id"], 1);
        assert_eq!(arr[1]["token"], REDACTED);
    }

    #[test]
    fn empty_patterns_redact_nothing() {
        let config = RedactionConfig { patterns: vec![] };
        let input = json!({"password": "hunter2", "secret": "x"});
        let redacted = redact_arguments(&input, &config);

        assert_eq!(redacted["password"], "hunter2");
        assert_eq!(redacted["secret"], "x");
    }

    #[test]
    fn scalar_values_pass_through() {
        let config = RedactionConfig::default();
        let input = json!("just a string");
        assert_eq!(redact_arguments(&input, &config), json!("just a string"));

        let input = json!(42);
        assert_eq!(redact_arguments(&input, &config), json!(42));
    }

    // -----------------------------------------------------------------------
    // Redaction over-match (substring matching behavior)
    // -----------------------------------------------------------------------

    /// Redaction uses word-boundary matching (letter-boundary): pattern "key"
    /// matches "api_key" and "key_id" (separated by underscore) but NOT
    /// "monkey" or "keyboard" (embedded in other letters).
    #[test]
    fn redaction_is_word_boundary_match() {
        let config = RedactionConfig {
            patterns: vec!["key".into()],
        };
        let input = json!({
            "api_key": "secret-1",
            "key_id": "secret-2",
            "monkey": "banana",
            "keyboard": "qwerty",
            "unrelated": "visible"
        });

        let redacted = redact_arguments(&input, &config);

        // Fields where "key" appears at a word boundary are redacted.
        assert_eq!(
            redacted["api_key"], REDACTED,
            "api_key has 'key' at boundary"
        );
        assert_eq!(redacted["key_id"], REDACTED, "key_id has 'key' at boundary");

        // Fields where "key" is embedded in other letters are NOT redacted.
        assert_eq!(
            redacted["monkey"], "banana",
            "monkey should not be redacted"
        );
        assert_eq!(
            redacted["keyboard"], "qwerty",
            "keyboard should not be redacted"
        );

        // Fields without "key" are left alone.
        assert_eq!(redacted["unrelated"], "visible");
    }

    /// Pattern "token" matches "tokelau_island" because "token" is NOT a
    /// substring of "tokelau_island" (different letters: "token" vs "tokel").
    /// But it DOES match "tokenizer", "access_token", etc.
    #[test]
    fn redaction_does_not_match_unrelated() {
        let config = RedactionConfig {
            patterns: vec!["token".into()],
        };
        let input = json!({
            "access_token": "secret",
            "token_type": "bearer",
            "tokelau_island": "pacific",
            "notation": "musical"
        });

        let redacted = redact_arguments(&input, &config);

        // "access_token" and "token_type" contain "token" -> redacted.
        assert_eq!(redacted["access_token"], REDACTED);
        assert_eq!(redacted["token_type"], REDACTED);

        // "tokelau_island" does NOT contain "token" -> NOT redacted.
        assert_eq!(redacted["tokelau_island"], "pacific");

        // "notation" does NOT contain "token" -> NOT redacted.
        assert_eq!(redacted["notation"], "musical");
    }

    // -----------------------------------------------------------------------
    // Deeply nested JSON redaction (no stack overflow)
    // -----------------------------------------------------------------------

    #[test]
    fn deeply_nested_json_redaction() {
        let config = RedactionConfig {
            patterns: vec!["secret".into()],
        };

        // Build 10 levels of nesting: {"level": {"level": ... {"secret": "value"}}}
        let mut value = json!({"secret": "deep-secret-value", "visible": "ok"});
        for _ in 0..10 {
            value = json!({"level": value});
        }

        let redacted = redact_arguments(&value, &config);

        // Walk down 10 levels to verify the deeply nested "secret" was redacted.
        let mut current = &redacted;
        for _ in 0..10 {
            current = &current["level"];
        }
        assert_eq!(
            current["secret"], REDACTED,
            "deeply nested 'secret' field must be redacted"
        );
        assert_eq!(
            current["visible"], "ok",
            "non-secret field at depth must be preserved"
        );
    }

    #[test]
    fn does_not_redact_non_sensitive_substrings() {
        let config = RedactionConfig::default();
        let input = json!({
            "keyboard": "mechanical",
            "monkey": "curious george",
            "author": "Jane Doe",
            "authenticate_method": "oauth2"
        });
        let redacted = redact_arguments(&input, &config);
        assert_eq!(
            redacted["keyboard"], "mechanical",
            "keyboard should not be redacted"
        );
        assert_eq!(
            redacted["monkey"], "curious george",
            "monkey should not be redacted"
        );
        assert_eq!(
            redacted["author"], "Jane Doe",
            "author should not be redacted"
        );
        assert_eq!(
            redacted["authenticate_method"], "oauth2",
            "authenticate_method should not be redacted"
        );
    }

    #[test]
    fn still_redacts_sensitive_compound_fields() {
        let config = RedactionConfig::default();
        let input = json!({
            "api_key": "sk-12345",
            "api-key": "sk-67890",
            "x-auth-token": "bearer-abc",
            "user_password": "hunter2"
        });
        let redacted = redact_arguments(&input, &config);
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["api-key"], "[REDACTED]");
        assert_eq!(redacted["x-auth-token"], "[REDACTED]");
        assert_eq!(redacted["user_password"], "[REDACTED]");
    }

    // ── RT-206: CompiledRedaction direct tests ────────────────────────

    #[test]
    fn compiled_redaction_matches_redact_arguments() {
        let config = RedactionConfig::default();
        let compiled = config.compile();
        let input = json!({
            "path": "/etc/hosts",
            "api_key": "sk-12345",
            "password": "hunter2",
            "nested": {
                "access_token": "abc",
                "count": 42
            }
        });

        let result_compiled = compiled.redact(&input);
        let result_wrapper = redact_arguments(&input, &config);
        assert_eq!(
            result_compiled, result_wrapper,
            "compiled and wrapper should produce identical output"
        );
    }

    #[test]
    fn compiled_redaction_reusable_across_calls() {
        let config = RedactionConfig {
            patterns: vec!["secret".into(), "key".into()],
        };
        let compiled = config.compile();

        let input1 = json!({"secret": "val1", "public": "ok"});
        let input2 = json!({"api_key": "val2", "name": "test"});

        let r1 = compiled.redact(&input1);
        let r2 = compiled.redact(&input2);

        assert_eq!(r1["secret"], REDACTED);
        assert_eq!(r1["public"], "ok");
        assert_eq!(r2["api_key"], REDACTED);
        assert_eq!(r2["name"], "test");
    }

    #[test]
    fn compiled_redaction_empty_patterns() {
        let config = RedactionConfig { patterns: vec![] };
        let compiled = config.compile();
        let input = json!({"password": "hunter2", "secret": "x"});
        let redacted = compiled.redact(&input);
        assert_eq!(redacted["password"], "hunter2");
        assert_eq!(redacted["secret"], "x");
    }
}
