//! Typed JWT claims extracted from validated tokens.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard and custom claims extracted from a validated JWT.
///
/// Standard OAuth 2.1 / OIDC claims (`sub`, `iss`, `aud`, `exp`, `iat`)
/// go into typed fields. Any additional claims present in the token are
/// captured in the `custom` map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier (the user or service).
    #[serde(default)]
    pub sub: Option<String>,

    /// Token issuer URL.
    #[serde(default)]
    pub iss: Option<String>,

    /// Intended audience(s) for this token.
    #[serde(default)]
    pub aud: Option<Audience>,

    /// Expiration time as seconds since Unix epoch.
    #[serde(default)]
    pub exp: Option<u64>,

    /// Issued-at time as seconds since Unix epoch.
    #[serde(default)]
    pub iat: Option<u64>,

    /// OAuth scopes granted to this token (space-delimited string or array).
    /// Extracted from the `scope` claim if present. If absent, defaults to empty.
    #[serde(default, deserialize_with = "deserialize_scope")]
    pub scope: Vec<String>,

    /// Any additional claims not covered by the standard fields above.
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Check whether this token has a specific scope.
    pub fn has_scope(&self, required: &str) -> bool {
        self.scope.iter().any(|s| s == required)
    }
}

/// Deserialize the `scope` claim which may be a space-delimited string
/// (RFC 6749) or an array of strings.
fn deserialize_scope<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct ScopeVisitor;

    impl<'de> de::Visitor<'de> for ScopeVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a space-delimited string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.split_whitespace().map(String::from).collect())
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut scopes = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                scopes.push(s);
            }
            Ok(scopes)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(ScopeVisitor)
}

/// JWT audience: may be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience string.
    Single(String),
    /// Multiple audience strings.
    Multiple(Vec<String>),
}

impl Audience {
    /// Check whether this audience contains `target`.
    pub fn contains(&self, target: &str) -> bool {
        match self {
            Audience::Single(s) => s == target,
            Audience::Multiple(v) => v.iter().any(|s| s == target),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience_single_contains() {
        let aud = Audience::Single("api".to_string());
        assert!(aud.contains("api"));
        assert!(!aud.contains("other"));
    }

    #[test]
    fn audience_multiple_contains() {
        let aud = Audience::Multiple(vec!["api".to_string(), "web".to_string()]);
        assert!(aud.contains("api"));
        assert!(aud.contains("web"));
        assert!(!aud.contains("other"));
    }
}
