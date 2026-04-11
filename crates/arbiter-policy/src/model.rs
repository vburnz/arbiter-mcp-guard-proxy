use arbiter_identity::TrustLevel;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a policy rule.
pub type PolicyId = String;

/// Top-level policy configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Ordered list of policies. Evaluated top-to-bottom; most specific match wins.
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// A single authorization policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier for this policy.
    pub id: PolicyId,

    /// Matching criteria for the agent making the request.
    #[serde(default)]
    pub agent_match: AgentMatch,

    /// Matching criteria for the principal (human) on whose behalf the agent acts.
    #[serde(default)]
    pub principal_match: PrincipalMatch,

    /// Matching criteria for the declared task intent.
    #[serde(default)]
    pub intent_match: IntentMatch,

    /// Tools that this policy applies to. Empty means "all tools".
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Allowed resource URI prefixes for non-tool-call methods (resources/read, etc.).
    /// If non-empty, the request's resource_uri must start with one of these prefixes.
    /// Empty means "all resource URIs" (no URI restriction beyond tool matching).
    #[serde(default)]
    pub resource_match: Vec<String>,

    /// Parameter constraints as key-value bounds (e.g., max file size).
    #[serde(default)]
    pub parameter_constraints: Vec<ParameterConstraint>,

    /// The effect of this policy when matched.
    pub effect: Effect,

    /// How this policy's effect is enforced. Block (default) returns an error.
    /// Annotate forwards the request with governance metadata attached.
    #[serde(default)]
    pub disposition: Disposition,

    /// Priority for specificity ordering. Higher = more specific = wins ties.
    /// Automatically computed from match criteria if not set.
    #[serde(default)]
    pub priority: i32,
}

/// Matching criteria for an agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentMatch {
    /// Match a specific agent by ID. Most specific match.
    #[serde(default)]
    pub agent_id: Option<Uuid>,

    /// Match agents at or above this trust level.
    #[serde(default)]
    pub trust_level: Option<TrustLevel>,

    /// Match agents with all of these capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Matching criteria for a principal (human user).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrincipalMatch {
    /// Match a specific principal by subject identifier.
    #[serde(default)]
    pub sub: Option<String>,

    /// Match principals belonging to any of these groups.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Matching criteria for the declared task intent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentMatch {
    /// Keywords that must appear in the declared intent (case-insensitive).
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Regex pattern the declared intent must match.
    #[serde(default)]
    pub regex: Option<String>,

    /// Pre-compiled regex (populated by `PolicyConfig::compile()`).
    /// Avoids per-evaluation regex compilation in the hot path.
    #[serde(skip)]
    pub compiled_regex: Option<Regex>,

    /// Pre-compiled keyword word-boundary regexes.
    /// Previously, a new Regex was compiled for EACH keyword on EVERY evaluation,
    /// causing O(n*m) regex compilations per request (n policies, m keywords each).
    #[serde(skip)]
    pub compiled_keywords: Vec<Regex>,
}

/// A constraint on a tool parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterConstraint {
    /// The parameter key path (e.g., "arguments.max_tokens").
    pub key: String,

    /// Maximum numeric value allowed.
    #[serde(default)]
    pub max_value: Option<f64>,

    /// Minimum numeric value allowed.
    #[serde(default)]
    pub min_value: Option<f64>,

    /// Allowed string values (whitelist).
    #[serde(default)]
    pub allowed_values: Vec<String>,
}

/// The effect of a policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
    Escalate,
}

/// How a deny or escalate policy disposition is enforced.
/// Block returns a JSON-RPC error. Annotate forwards the call with metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    #[default]
    Block,
    Annotate,
}

impl Policy {
    /// Compute the specificity score for this policy. Higher = more specific.
    /// agent_id match (100) > trust_level match (50) > capability match (25 each, max 3)
    /// principal sub (40) > group (20 each)
    /// intent regex (30) > keywords (10 each)
    pub fn specificity(&self) -> i32 {
        if self.priority != 0 {
            return self.priority;
        }

        let mut score = 0i32;

        if self.agent_match.agent_id.is_some() {
            score += 100;
        }
        if self.agent_match.trust_level.is_some() {
            score += 50;
        }
        // Cap capability contribution to prevent specificity gaming via capability stacking.
        score += std::cmp::min(self.agent_match.capabilities.len(), 3) as i32 * 25;

        if self.principal_match.sub.is_some() {
            score += 40;
        }
        score += self.principal_match.groups.len() as i32 * 20;

        if self.intent_match.regex.is_some() {
            score += 30;
        }
        score += self.intent_match.keywords.len() as i32 * 10;

        score
    }
}

impl PolicyConfig {
    /// Parse a policy configuration from a TOML string.
    /// Automatically compiles any intent-match regexes for hot-path performance.
    pub fn from_toml(toml_str: &str) -> Result<Self, crate::PolicyError> {
        let mut config: PolicyConfig = toml::from_str(toml_str)?;
        config.compile()?;
        Ok(config)
    }

    /// Pre-compile all intent-match regexes in the policy set.
    /// Called automatically by `from_toml`. Call manually after constructing
    /// a `PolicyConfig` programmatically.
    pub fn compile(&mut self) -> Result<(), crate::PolicyError> {
        // Check for duplicate policy IDs.
        {
            let mut seen = std::collections::HashSet::new();
            for policy in &self.policies {
                if !seen.insert(&policy.id) {
                    return Err(crate::PolicyError::DuplicatePolicyId {
                        policy_id: policy.id.clone(),
                    });
                }
            }
        }

        // Cap manual priority override to prevent
        // specificity gaming via arbitrarily high priority values.
        const MAX_PRIORITY: i32 = 1000;
        for policy in &self.policies {
            if policy.priority > MAX_PRIORITY {
                return Err(crate::PolicyError::PriorityTooHigh {
                    policy_id: policy.id.clone(),
                    priority: policy.priority,
                    max: MAX_PRIORITY,
                });
            }
        }

        // Limit regex pattern length to prevent
        // expensive pattern compilation and matching.
        const MAX_REGEX_PATTERN_LEN: usize = 500;

        for policy in &mut self.policies {
            if let Some(ref pattern) = policy.intent_match.regex {
                if pattern.len() > MAX_REGEX_PATTERN_LEN {
                    return Err(crate::PolicyError::RegexTooLong {
                        policy_id: policy.id.clone(),
                        length: pattern.len(),
                        max: MAX_REGEX_PATTERN_LEN,
                    });
                }
                let compiled =
                    Regex::new(pattern).map_err(|e| crate::PolicyError::InvalidRegex {
                        policy_id: policy.id.clone(),
                        pattern: pattern.clone(),
                        reason: e.to_string(),
                    })?;
                policy.intent_match.compiled_regex = Some(compiled);
            }

            // Pre-compile keyword word-boundary regexes at compile time.
            // Previously compiled on every evaluation, O(n*m) per request.
            let mut compiled_keywords = Vec::with_capacity(policy.intent_match.keywords.len());
            for keyword in &policy.intent_match.keywords {
                let lower_kw = keyword.to_lowercase();
                let pattern = format!(r"\b{}\b", regex::escape(&lower_kw));
                let compiled =
                    Regex::new(&pattern).map_err(|e| crate::PolicyError::InvalidRegex {
                        policy_id: policy.id.clone(),
                        pattern,
                        reason: e.to_string(),
                    })?;
                compiled_keywords.push(compiled);
            }
            policy.intent_match.compiled_keywords = compiled_keywords;
        }

        // Warn when allowed_tools is empty (wildcard).
        // An empty allowed_tools list means the policy matches ALL tools, which
        // may be unintentional and creates an overpermissive rule.
        for policy in &self.policies {
            if policy.allowed_tools.is_empty() {
                let effect_name = format!("{:?}", policy.effect).to_lowercase();
                tracing::warn!(
                    policy_id = %policy.id,
                    effect = %effect_name,
                    "policy has empty allowed_tools (matches ALL tools). \
                     This creates a blanket {effect} rule. Set allowed_tools explicitly.",
                    effect = effect_name,
                );
            }
        }

        Ok(())
    }
}

/// A diagnostic produced by policy validation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDiagnostic {
    /// "error" or "warning".
    pub level: String,
    /// Which policy triggered the diagnostic (if applicable).
    pub policy_id: Option<String>,
    /// Human-readable description.
    pub message: String,
}

/// Result of policy validation.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    /// Whether the configuration is valid (no errors).
    pub valid: bool,
    /// Number of policies parsed.
    pub policy_count: usize,
    /// All diagnostics (errors + warnings).
    pub diagnostics: Vec<PolicyDiagnostic>,
}

impl PolicyConfig {
    /// Validate a TOML policy configuration string without loading it.
    /// Returns structured diagnostics for errors and warnings.
    pub fn validate_toml(toml_str: &str) -> ValidationResult {
        let mut diagnostics = Vec::new();

        // Step 1: Parse TOML.
        let mut config: PolicyConfig = match toml::from_str(toml_str) {
            Ok(c) => c,
            Err(e) => {
                diagnostics.push(PolicyDiagnostic {
                    level: "error".into(),
                    policy_id: None,
                    message: format!("TOML parse error: {e}"),
                });
                return ValidationResult {
                    valid: false,
                    policy_count: 0,
                    diagnostics,
                };
            }
        };

        let policy_count = config.policies.len();

        // Step 2: Check for duplicate IDs.
        let mut seen_ids = std::collections::HashSet::new();
        for policy in &config.policies {
            if !seen_ids.insert(&policy.id) {
                diagnostics.push(PolicyDiagnostic {
                    level: "error".into(),
                    policy_id: Some(policy.id.clone()),
                    message: format!("duplicate policy ID '{}'", policy.id),
                });
            }
        }

        // Step 3: Compile regexes.
        for policy in &mut config.policies {
            if let Some(ref pattern) = policy.intent_match.regex
                && let Err(e) = Regex::new(pattern)
            {
                diagnostics.push(PolicyDiagnostic {
                    level: "error".into(),
                    policy_id: Some(policy.id.clone()),
                    message: format!("invalid regex '{}': {}", pattern, e),
                });
            }
        }

        // Step 4: Check for shadowed policies.
        // A policy is shadowed if a higher-specificity policy with conflicting
        // effect covers the same or broader scope.
        let mut sorted: Vec<(usize, i32)> = config
            .policies
            .iter()
            .enumerate()
            .map(|(i, p)| (i, p.specificity()))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1)); // highest specificity first

        for i in 0..sorted.len() {
            for j in (i + 1)..sorted.len() {
                let (hi_idx, hi_spec) = sorted[i];
                let (lo_idx, lo_spec) = sorted[j];
                let hi = &config.policies[hi_idx];
                let lo = &config.policies[lo_idx];

                // Only flag if they overlap on tools and have conflicting effects.
                if hi_spec > lo_spec
                    && hi.effect != lo.effect
                    && tools_overlap(&hi.allowed_tools, &lo.allowed_tools)
                {
                    diagnostics.push(PolicyDiagnostic {
                        level: "warning".into(),
                        policy_id: Some(lo.id.clone()),
                        message: format!(
                            "policy '{}' (specificity {}) may be shadowed by '{}' (specificity {}) with conflicting effect",
                            lo.id, lo_spec, hi.id, hi_spec
                        ),
                    });
                }
            }
        }

        let has_errors = diagnostics.iter().any(|d| d.level == "error");
        ValidationResult {
            valid: !has_errors,
            policy_count,
            diagnostics,
        }
    }
}

/// Check if two tool lists overlap. Empty list means "all tools" (wildcard).
fn tools_overlap(a: &[String], b: &[String]) -> bool {
    if a.is_empty() || b.is_empty() {
        return true; // wildcard overlaps with everything
    }
    a.iter().any(|tool| b.contains(tool))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specificity_agent_id_beats_trust_level() {
        let specific = Policy {
            id: "specific".into(),
            agent_match: AgentMatch {
                agent_id: Some(Uuid::new_v4()),
                ..Default::default()
            },
            principal_match: Default::default(),
            intent_match: Default::default(),
            allowed_tools: vec![],
            resource_match: vec![],
            parameter_constraints: vec![],
            effect: Effect::Allow,
            disposition: Disposition::Block,
            priority: 0,
        };

        let general = Policy {
            id: "general".into(),
            agent_match: AgentMatch {
                trust_level: Some(TrustLevel::Basic),
                ..Default::default()
            },
            principal_match: Default::default(),
            intent_match: Default::default(),
            allowed_tools: vec![],
            resource_match: vec![],
            parameter_constraints: vec![],
            effect: Effect::Deny,
            disposition: Disposition::Block,
            priority: 0,
        };

        assert!(specific.specificity() > general.specificity());
    }

    #[test]
    fn parse_policy_config_from_toml() {
        let toml_str = r#"
[[policies]]
id = "allow-read"
effect = "allow"
allowed_tools = ["read_file", "list_dir"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read", "analyze"]
"#;
        let config = PolicyConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].id, "allow-read");
        assert_eq!(config.policies[0].effect, Effect::Allow);
        assert_eq!(
            config.policies[0].allowed_tools,
            vec!["read_file", "list_dir"]
        );
    }

    #[test]
    fn disposition_serde_roundtrip() {
        let json = serde_json::json!("annotate");
        let d: Disposition = serde_json::from_value(json).unwrap();
        assert_eq!(d, Disposition::Annotate);

        let back = serde_json::to_value(d).unwrap();
        assert_eq!(back, "annotate");
    }

    #[test]
    fn disposition_defaults_to_block() {
        assert_eq!(Disposition::default(), Disposition::Block);
    }

    #[test]
    fn policy_without_disposition_defaults_block() {
        let toml_str = r#"
[[policies]]
id = "deny-all"
effect = "deny"
"#;
        let config = PolicyConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.policies[0].disposition, Disposition::Block);
    }

    // -----------------------------------------------------------------------
    // Policy priority cap (MAX=1000) enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn priority_cap_enforced() {
        // Priority = 1001 must be rejected.
        let toml_over = r#"
[[policies]]
id = "too-high"
effect = "allow"
priority = 1001
"#;
        let err = PolicyConfig::from_toml(toml_over).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PolicyError::PriorityTooHigh {
                    priority: 1001,
                    max: 1000,
                    ..
                }
            ),
            "priority 1001 must be rejected, got: {:?}",
            err
        );

        // Priority = 1000 must succeed (boundary).
        let toml_ok = r#"
[[policies]]
id = "max-allowed"
effect = "allow"
priority = 1000
"#;
        let config = PolicyConfig::from_toml(toml_ok).unwrap();
        assert_eq!(config.policies[0].priority, 1000);

        // Priority = 999 must succeed (below boundary).
        let toml_below = r#"
[[policies]]
id = "below-max"
effect = "allow"
priority = 999
"#;
        let config = PolicyConfig::from_toml(toml_below).unwrap();
        assert_eq!(config.policies[0].priority, 999);
    }

    // -----------------------------------------------------------------------
    // Regex pattern length cap (500 chars)
    // -----------------------------------------------------------------------

    #[test]
    fn regex_pattern_length_cap_enforced() {
        // Pattern of 501 chars must be rejected.
        let long_pattern: String = "a".repeat(501);
        let toml_over = format!(
            r#"
[[policies]]
id = "long-regex"
effect = "allow"

[policies.intent_match]
regex = "{}"
"#,
            long_pattern
        );
        let err = PolicyConfig::from_toml(&toml_over).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PolicyError::RegexTooLong {
                    length: 501,
                    max: 500,
                    ..
                }
            ),
            "regex of 501 chars must be rejected, got: {:?}",
            err
        );

        // Pattern of exactly 500 chars must succeed (boundary).
        let ok_pattern: String = "a".repeat(500);
        let toml_ok = format!(
            r#"
[[policies]]
id = "ok-regex"
effect = "allow"

[policies.intent_match]
regex = "{}"
"#,
            ok_pattern
        );
        let config = PolicyConfig::from_toml(&toml_ok).unwrap();
        assert_eq!(
            config.policies[0].intent_match.regex.as_deref(),
            Some(ok_pattern.as_str())
        );
    }

    // -----------------------------------------------------------------------
    // Invalid regex rejection
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_regex_rejected() {
        let toml_str = r#"
[[policies]]
id = "bad-regex"
effect = "allow"

[policies.intent_match]
regex = "[invalid"
"#;
        let err = PolicyConfig::from_toml(toml_str).unwrap_err();
        assert!(
            matches!(err, crate::PolicyError::InvalidRegex { .. }),
            "unmatched bracket regex must be rejected, got: {:?}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // tools_overlap with empty (wildcard)
    // -----------------------------------------------------------------------

    #[test]
    fn tools_overlap_with_empty_wildcard() {
        // Empty list (wildcard) overlaps with everything.
        assert!(
            tools_overlap(&[], &["read_file".to_string()]),
            "empty (wildcard) must overlap with any tool list"
        );
        assert!(
            tools_overlap(&["read_file".to_string()], &[]),
            "any tool list must overlap with empty (wildcard)"
        );
        assert!(tools_overlap(&[], &[]), "two wildcards must overlap");

        // Non-overlapping explicit lists must not overlap.
        assert!(
            !tools_overlap(&["read_file".to_string()], &["write_file".to_string()]),
            "disjoint tool lists must not overlap"
        );

        // Overlapping explicit lists must overlap.
        assert!(
            tools_overlap(
                &["read_file".to_string(), "write_file".to_string()],
                &["write_file".to_string(), "delete_file".to_string()]
            ),
            "tool lists sharing 'write_file' must overlap"
        );
    }
}
