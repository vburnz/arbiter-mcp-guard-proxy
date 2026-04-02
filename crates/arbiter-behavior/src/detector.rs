//! Behavioral anomaly detector.
//!
//! Analyzes the declared intent of a session against the actual operation
//! types being performed, flagging mismatches as anomalies.

use regex::RegexSet;
use serde::{Deserialize, Serialize};

use crate::classifier::OperationType;

/// Default read-intent keywords. Each indicates that a session's declared intent
/// is read-only, and any write/delete/admin operations should be flagged.
///
/// Rationale for each keyword:
/// - "read", "view", "inspect" -- explicit read operations
/// - "analyze", "summarize", "review", "explain", "describe" -- comprehension tasks that consume but don't modify
/// - "check", "search", "query", "list" -- enumeration/lookup operations
fn default_read_intent_keywords() -> Vec<String> {
    vec![
        "read".into(),
        "analyze".into(),
        "summarize".into(),
        "review".into(),
        "inspect".into(),
        "view".into(),
        "check".into(),
        "list".into(),
        "search".into(),
        "query".into(),
        "describe".into(),
        "explain".into(),
    ]
}

/// Default write-intent keywords. Sessions matching these may perform read
/// and write operations, but admin operations are flagged.
///
/// Rationale: these verbs imply data mutation but not system administration.
fn default_write_intent_keywords() -> Vec<String> {
    vec![
        "write".into(),
        "create".into(),
        "update".into(),
        "modify".into(),
        "edit".into(),
        "deploy".into(),
        "build".into(),
        "generate".into(),
        "publish".into(),
        "upload".into(),
    ]
}

/// Default admin-intent keywords. Sessions matching these may perform any
/// operation; no anomaly is flagged regardless of operation type.
///
/// Rationale: these verbs imply system-level authority.
fn default_admin_intent_keywords() -> Vec<String> {
    vec![
        "admin".into(),
        "manage".into(),
        "configure".into(),
        "setup".into(),
        "install".into(),
        "maintain".into(),
        "operate".into(),
        "provision".into(),
    ]
}

/// The classified privilege tier of a session's declared intent.
/// Used to determine which operation types are anomalous.
///
/// Precedence: Admin > Write > Read > Unknown.
/// If multiple keyword sets match, the highest tier wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentTier {
    /// No intent keywords matched. Anomaly detection skipped.
    Unknown,
    /// Read-only intent: write/delete/admin ops are anomalous.
    Read,
    /// Write intent: admin ops are anomalous, read/write/delete are normal.
    Write,
    /// Admin intent: delete ops flagged, all others normal.
    Admin,
}

/// Default suspicious argument patterns that trigger anomaly detection in read
/// sessions. Each pattern is matched (case-insensitive) against the serialized
/// JSON argument text.
///
/// Categories:
/// - Destructive shell commands: "rm -rf", "rm -f", "mkfs", "dd if=", "chmod 777"
/// - Destructive SQL: "drop table", "drop database", "delete from", "truncate table"
/// - SQL injection fragments: "; --", "' or '1'='1", "union select"
/// - Path traversal: "../../../", "..\\..\\"
fn default_suspicious_arg_patterns() -> Vec<String> {
    vec![
        "rm -rf".into(),
        "rm -f".into(),
        "mkfs".into(),
        "dd if=".into(),
        "chmod 777".into(),
        "drop table".into(),
        "drop database".into(),
        "delete from".into(),
        "truncate table".into(),
        "; --".into(),
        "' or '1'='1".into(),
        "union select".into(),
        "../../../".into(),
        "..\\..\\".into(),
    ]
}

/// Suspicious argument key substrings. If any argument key in a read-intent
/// session contains one of these substrings, the call is flagged.
const SUSPICIOUS_ARG_KEY_FRAGMENTS: &[&str] = &[
    "exec", "shell", "command", "query", "sql", "eval", "script", "code", "run", "system",
];

/// Maximum string value length (in bytes) allowed in a read-intent session
/// before flagging as a potential payload injection.
const MAX_READ_ARG_STRING_LEN: usize = 1024;

/// Configuration for anomaly detection behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Whether anomalies should escalate to deny (hard block).
    /// If false, anomalies are logged and flagged but the request proceeds.
    #[serde(default)]
    pub escalate_to_deny: bool,

    /// Keywords that indicate a session's declared intent is read-only.
    /// If the intent matches any of these (case-insensitive word boundary),
    /// then write/delete/admin operations are flagged as anomalies.
    #[serde(default = "default_read_intent_keywords")]
    pub read_intent_keywords: Vec<String>,

    /// Keywords that indicate a session's declared intent includes writes.
    /// Write-intent sessions may perform read and write operations, but
    /// admin operations are flagged.
    #[serde(default = "default_write_intent_keywords")]
    pub write_intent_keywords: Vec<String>,

    /// Keywords that indicate a session's declared intent is administrative.
    /// Admin-intent sessions may perform any operation without anomaly flags.
    #[serde(default = "default_admin_intent_keywords")]
    pub admin_intent_keywords: Vec<String>,

    /// Suspicious argument patterns that trigger anomaly detection in read sessions.
    /// Matched case-insensitively against the serialized JSON argument text.
    #[serde(default = "default_suspicious_arg_patterns")]
    pub suspicious_arg_patterns: Vec<String>,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            escalate_to_deny: false,
            read_intent_keywords: default_read_intent_keywords(),
            write_intent_keywords: default_write_intent_keywords(),
            admin_intent_keywords: default_admin_intent_keywords(),
            suspicious_arg_patterns: default_suspicious_arg_patterns(),
        }
    }
}

/// The result of anomaly detection on a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyResponse {
    /// No anomaly detected.
    Normal,
    /// Anomaly detected but request proceeds (soft flag).
    Flagged {
        /// Description of the anomaly.
        reason: String,
    },
    /// Anomaly detected and request should be denied (hard block).
    Denied {
        /// Description of the anomaly.
        reason: String,
    },
}

/// Behavioral anomaly detector.
pub struct AnomalyDetector {
    config: AnomalyConfig,
    /// Pre-compiled regex sets for intent word-boundary matching.
    /// Built from config keywords at construction time. No per-call compilation.
    read_intent_regex: RegexSet,
    write_intent_regex: RegexSet,
    admin_intent_regex: RegexSet,
}

fn build_regex_set(keywords: &[String], label: &str) -> RegexSet {
    let patterns: Vec<String> = keywords
        .iter()
        .map(|p| format!(r"(?i)\b{}\b", regex::escape(p)))
        .collect();
    RegexSet::new(&patterns).unwrap_or_else(|e| panic!("{label} must be valid regex atoms: {e}"))
}

impl AnomalyDetector {
    /// Create a new anomaly detector with the given config.
    /// Pre-compiles intent keywords into RegexSets for O(1) matching.
    pub fn new(config: AnomalyConfig) -> Self {
        let read_intent_regex =
            build_regex_set(&config.read_intent_keywords, "read_intent_keywords");
        let write_intent_regex =
            build_regex_set(&config.write_intent_keywords, "write_intent_keywords");
        let admin_intent_regex =
            build_regex_set(&config.admin_intent_keywords, "admin_intent_keywords");
        Self {
            config,
            read_intent_regex,
            write_intent_regex,
            admin_intent_regex,
        }
    }

    /// Classify the declared intent into a privilege tier.
    /// Highest matching tier wins: Admin > Write > Read > Unknown.
    pub fn classify_intent(&self, declared_intent: &str) -> IntentTier {
        if self.admin_intent_regex.is_match(declared_intent) {
            IntentTier::Admin
        } else if self.write_intent_regex.is_match(declared_intent) {
            IntentTier::Write
        } else if self.read_intent_regex.is_match(declared_intent) {
            IntentTier::Read
        } else {
            IntentTier::Unknown
        }
    }

    /// Detect anomalies for a tool call given the session's declared intent.
    ///
    /// Tiered detection:
    /// - Admin intent: delete ops flagged, all others normal
    /// - Write intent: admin ops flagged, everything else normal
    /// - Read intent: write/delete/admin ops flagged
    /// - Unknown intent: no anomaly detection
    pub fn detect(
        &self,
        declared_intent: &str,
        operation_type: OperationType,
        tool_name: &str,
    ) -> AnomalyResponse {
        self.detect_with_args(declared_intent, operation_type, tool_name, None)
    }

    /// Detect anomalies with argument-level scanning.
    pub fn detect_with_args(
        &self,
        declared_intent: &str,
        operation_type: OperationType,
        tool_name: &str,
        arguments: Option<&serde_json::Value>,
    ) -> AnomalyResponse {
        let tier = self.classify_intent(declared_intent);

        let is_anomalous = match tier {
            // Unknown intent: flag ALL operations. Unclassified intents receive
            // maximum scrutiny — less specific intent declarations should trigger
            // more monitoring, not less. Previously returned false (no monitoring),
            // allowing trivial bypass by declaring non-keyword intents like "do stuff".
            IntentTier::Unknown => true,
            // Admin intent: flag delete operations. Admin sessions are powerful
            // and deletion should always leave an anomaly trace for forensics.
            IntentTier::Admin => operation_type == OperationType::Delete,
            IntentTier::Write => operation_type == OperationType::Admin,
            IntentTier::Read => !matches!(operation_type, OperationType::Read),
        };

        if !is_anomalous {
            // Argument scanning for destructive patterns applies to Read and
            // Unknown tiers. Unknown-tier sessions should receive at least
            // read-level scrutiny for destructive argument patterns.
            if matches!(tier, IntentTier::Read | IntentTier::Unknown)
                && let Some(args) = arguments
            {
                // Pattern-based scan against configurable suspicious patterns.
                let text = args.to_string().to_lowercase();
                for pattern in &self.config.suspicious_arg_patterns {
                    if text.contains(pattern.as_str()) {
                        let reason = format!(
                            "suspicious argument content in tool '{}': pattern '{}' detected",
                            tool_name, pattern
                        );
                        return if self.config.escalate_to_deny {
                            AnomalyResponse::Denied { reason }
                        } else {
                            AnomalyResponse::Flagged { reason }
                        };
                    }
                }

                // Structural analysis for read/unknown-intent sessions.
                if let Some(reason) = check_structural_anomalies(args, tool_name) {
                    return if self.config.escalate_to_deny {
                        AnomalyResponse::Denied { reason }
                    } else {
                        AnomalyResponse::Flagged { reason }
                    };
                }
            }
            return AnomalyResponse::Normal;
        }

        let tier_label = match tier {
            IntentTier::Unknown => "unknown (unclassified)",
            IntentTier::Read => "read-only",
            IntentTier::Write => "write",
            IntentTier::Admin => "admin",
        };

        let reason = format!(
            "session intent '{}' classified as {}, but tool '{}' classified as {:?}",
            declared_intent, tier_label, tool_name, operation_type
        );

        tracing::warn!(
            intent = %declared_intent,
            tool = %tool_name,
            operation = ?operation_type,
            intent_tier = ?tier,
            "behavioral anomaly detected"
        );

        if self.config.escalate_to_deny {
            AnomalyResponse::Denied { reason }
        } else {
            AnomalyResponse::Flagged { reason }
        }
    }
}

/// Check for structural anomalies in arguments for a read-intent session.
///
/// Read operations typically take simple scalar parameters (strings, numbers,
/// booleans). Complex structures or known-dangerous key names suggest an
/// attempt to smuggle write/execute semantics through a read-classified call.
///
/// Returns `Some(reason)` if an anomaly is found, `None` otherwise.
fn check_structural_anomalies(args: &serde_json::Value, tool_name: &str) -> Option<String> {
    let obj = args.as_object()?;

    for (key, value) in obj {
        // 1. Nested objects/arrays: read ops should only have scalar params.
        if value.is_object() || value.is_array() {
            return Some(format!(
                "structural anomaly in tool '{}': argument '{}' contains a nested {} in a read session",
                tool_name,
                key,
                if value.is_object() { "object" } else { "array" },
            ));
        }

        // 2. Suspicious argument key names.
        let key_lower = key.to_lowercase();
        for fragment in SUSPICIOUS_ARG_KEY_FRAGMENTS {
            if key_lower.contains(fragment) {
                return Some(format!(
                    "structural anomaly in tool '{}': argument key '{}' contains suspicious fragment '{}'",
                    tool_name, key, fragment,
                ));
            }
        }

        // 3. Long string values (potential payload injection).
        if let Some(s) = value.as_str()
            && s.len() > MAX_READ_ARG_STRING_LEN
        {
            return Some(format!(
                "structural anomaly in tool '{}': argument '{}' has a string value of {} bytes (max {})",
                tool_name,
                key,
                s.len(),
                MAX_READ_ARG_STRING_LEN,
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_read_sequence_no_anomaly() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());

        let result = detector.detect(
            "read and analyze the log files",
            OperationType::Read,
            "read_file",
        );
        assert_eq!(result, AnomalyResponse::Normal);

        let result = detector.detect("summarize the report", OperationType::Read, "get_document");
        assert_eq!(result, AnomalyResponse::Normal);
    }

    #[test]
    fn write_in_read_only_session_flagged() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        let result = detector.detect(
            "read the configuration files",
            OperationType::Write,
            "write_file",
        );
        assert!(matches!(result, AnomalyResponse::Flagged { .. }));

        // Delete in a read session should also flag.
        let result = detector.detect(
            "analyze the database",
            OperationType::Delete,
            "delete_record",
        );
        assert!(matches!(result, AnomalyResponse::Flagged { .. }));
    }

    #[test]
    fn anomaly_escalation_to_deny() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        let result = detector.detect("review the source code", OperationType::Write, "write_file");
        assert!(matches!(result, AnomalyResponse::Denied { .. }));

        if let AnomalyResponse::Denied { reason } = result {
            assert!(reason.contains("review the source code"));
            assert!(reason.contains("write_file"));
        }
    }

    #[test]
    fn admin_in_read_session_detected() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        let result = detector.detect(
            "check the system status",
            OperationType::Admin,
            "configure_settings",
        );
        assert!(matches!(result, AnomalyResponse::Flagged { .. }));
    }

    // ── Tiered intent classification tests ───────────────────────────

    #[test]
    fn classify_intent_tiers() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());

        assert_eq!(detector.classify_intent("read the logs"), IntentTier::Read);
        assert_eq!(
            detector.classify_intent("analyze reports"),
            IntentTier::Read
        );
        assert_eq!(
            detector.classify_intent("create new user"),
            IntentTier::Write
        );
        assert_eq!(
            detector.classify_intent("deploy the app"),
            IntentTier::Write
        );
        assert_eq!(
            detector.classify_intent("manage the servers"),
            IntentTier::Admin
        );
        assert_eq!(
            detector.classify_intent("configure settings"),
            IntentTier::Admin
        );
        assert_eq!(
            detector.classify_intent("do something"),
            IntentTier::Unknown
        );
    }

    #[test]
    fn admin_intent_highest_precedence() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());

        // "manage" (admin) + "read" (read) → admin wins
        assert_eq!(
            detector.classify_intent("manage and read the system"),
            IntentTier::Admin
        );
    }

    #[test]
    fn write_intent_beats_read() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());

        // "create" (write) + "read" (read) → write wins
        assert_eq!(
            detector.classify_intent("read files and create backups"),
            IntentTier::Write
        );
    }

    #[test]
    fn write_intent_allows_writes_but_flags_admin() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        // Write intent allows read and write operations.
        let result = detector.detect("create new documents", OperationType::Read, "list_files");
        assert_eq!(result, AnomalyResponse::Normal);

        let result = detector.detect("create new documents", OperationType::Write, "write_file");
        assert_eq!(result, AnomalyResponse::Normal);

        let result = detector.detect("create new documents", OperationType::Delete, "delete_file");
        assert_eq!(result, AnomalyResponse::Normal);

        // But admin ops are flagged.
        let result = detector.detect(
            "create new documents",
            OperationType::Admin,
            "configure_settings",
        );
        assert!(matches!(result, AnomalyResponse::Flagged { .. }));
    }

    #[test]
    fn admin_intent_allows_non_delete_operations() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        for op in [
            OperationType::Read,
            OperationType::Write,
            OperationType::Admin,
        ] {
            let result = detector.detect("manage the cluster", op, "any_tool");
            assert_eq!(
                result,
                AnomalyResponse::Normal,
                "admin intent should allow {op:?}"
            );
        }
    }

    #[test]
    fn admin_intent_flags_delete_operations() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        let result = detector.detect(
            "manage the cluster",
            OperationType::Delete,
            "delete_resource",
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { .. }),
            "admin intent should flag delete operations, got: {result:?}"
        );
    }

    #[test]
    fn admin_intent_denies_delete_when_escalated() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        let result = detector.detect(
            "manage the cluster",
            OperationType::Delete,
            "delete_resource",
        );
        assert!(
            matches!(result, AnomalyResponse::Denied { .. }),
            "admin intent with escalation should deny delete operations, got: {result:?}"
        );
    }

    #[test]
    fn unknown_intent_flags_everything() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        for op in [
            OperationType::Read,
            OperationType::Write,
            OperationType::Delete,
            OperationType::Admin,
        ] {
            let result = detector.detect("do something", op, "any_tool");
            assert!(
                matches!(result, AnomalyResponse::Flagged { .. }),
                "unknown intent should flag {op:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn unknown_intent_denies_when_escalated() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        for op in [
            OperationType::Read,
            OperationType::Write,
            OperationType::Delete,
            OperationType::Admin,
        ] {
            let result = detector.detect("do something", op, "any_tool");
            assert!(
                matches!(result, AnomalyResponse::Denied { .. }),
                "unknown intent with escalation should deny {op:?}, got {result:?}"
            );
        }
    }

    /// RT-202: Unknown intent gets argument scanning (same as Read tier).
    /// Suspicious arg patterns should be detected even when intent is unclassified.
    #[test]
    fn unknown_intent_scans_arguments_for_suspicious_patterns() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        // Unknown intent + Read operation + suspicious "rm -rf" pattern in args.
        // Even though the operation type alone wouldn't trigger (Read is normal),
        // the argument scanning should catch the suspicious pattern.
        let args = serde_json::json!({"command": "rm -rf /"});
        let result = detector.detect_with_args(
            "do something", // Unknown intent (no keyword match)
            OperationType::Read,
            "some_tool",
            Some(&args),
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { .. }),
            "unknown intent should scan args for suspicious patterns, got {result:?}"
        );
    }

    /// Unknown intent triggers structural anomaly detection (suspicious key names).
    #[test]
    fn unknown_intent_detects_structural_anomalies() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        // Argument with suspicious key name "exec_command" (contains "exec" fragment).
        let args = serde_json::json!({"exec_command": "ls"});
        let result = detector.detect_with_args(
            "perform tasks", // Unknown intent
            OperationType::Read,
            "run_tool",
            Some(&args),
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { .. }),
            "unknown intent should detect structural anomalies in args, got {result:?}"
        );
    }

    /// Intent classification uses case-insensitive word-boundary matching,
    /// so uppercase keywords should still match their respective tiers.
    #[test]
    fn custom_keywords_case_insensitive() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());

        // "READ" (uppercase) should match the read tier
        assert_eq!(detector.classify_intent("READ FILES"), IntentTier::Read);

        // "ANALYZE" (uppercase) should also match read tier
        assert_eq!(detector.classify_intent("ANALYZE DATA"), IntentTier::Read);

        // "CREATE" (uppercase) should match write tier
        assert_eq!(
            detector.classify_intent("CREATE REPORTS"),
            IntentTier::Write
        );

        // "MANAGE" (uppercase) should match admin tier
        assert_eq!(
            detector.classify_intent("MANAGE SERVERS"),
            IntentTier::Admin
        );

        // Mixed case
        assert_eq!(
            detector.classify_intent("Read And Deploy"),
            IntentTier::Write
        );
    }

    /// Destructive arguments in read session must be flagged.
    #[test]
    fn argument_evasion_destructive_args() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });
        let args = serde_json::json!({"path": "/etc", "command": "rm -rf /"});
        let result = detector.detect_with_args(
            "read and analyze files",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert!(!matches!(result, AnomalyResponse::Normal));
    }

    /// SQL injection in arguments must be flagged.
    #[test]
    fn argument_evasion_sql_injection() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let args = serde_json::json!({"query": "'; DROP TABLE users; --"});
        let result = detector.detect_with_args(
            "search the database",
            OperationType::Read,
            "search_records",
            Some(&args),
        );
        assert!(!matches!(result, AnomalyResponse::Normal));
    }

    // ── Configurable argument patterns ──────────────────────────────

    /// Custom pattern supplied via AnomalyConfig triggers detection.
    #[test]
    fn configurable_patterns_trigger_detection() {
        let detector = AnomalyDetector::new(AnomalyConfig {
            suspicious_arg_patterns: vec!["super_secret_payload".into()],
            ..Default::default()
        });
        let args = serde_json::json!({"data": "contains super_secret_payload here"});
        let result = detector.detect_with_args(
            "read the logs",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { ref reason } if reason.contains("super_secret_payload")),
            "custom pattern should trigger flagging, got: {result:?}"
        );
    }

    // ── Structural argument analysis (read-intent only) ─────────────

    /// Nested array in a read session should be flagged.
    #[test]
    fn nested_array_in_read_session_flagged() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let args = serde_json::json!({"files": ["a", "b"]});
        let result = detector.detect_with_args(
            "read the config",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { ref reason } if reason.contains("nested") && reason.contains("array")),
            "nested array should be flagged, got: {result:?}"
        );
    }

    /// Suspicious key name in a read session should be flagged.
    #[test]
    fn suspicious_key_in_read_session_flagged() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let args = serde_json::json!({"shell_command": "ls"});
        let result = detector.detect_with_args(
            "read the config",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { ref reason } if reason.contains("suspicious fragment")),
            "suspicious key should be flagged, got: {result:?}"
        );
    }

    /// String value > 1KB in a read session should be flagged.
    #[test]
    fn long_value_in_read_session_flagged() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let long_string = "A".repeat(1025);
        let args = serde_json::json!({"payload": long_string});
        let result = detector.detect_with_args(
            "read the config",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert!(
            matches!(result, AnomalyResponse::Flagged { ref reason } if reason.contains("1025 bytes")),
            "long value should be flagged, got: {result:?}"
        );
    }

    /// Structural checks should NOT fire for admin-intent sessions.
    #[test]
    fn structural_checks_skip_admin_sessions() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let args = serde_json::json!({"files": ["a", "b"], "shell_command": "ls"});
        let result = detector.detect_with_args(
            "manage the servers",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert_eq!(
            result,
            AnomalyResponse::Normal,
            "admin session should not trigger structural checks"
        );
    }

    /// Structural checks should NOT fire for write-intent sessions.
    #[test]
    fn structural_checks_skip_write_sessions() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let args = serde_json::json!({"files": ["a", "b"], "shell_command": "ls"});
        let result = detector.detect_with_args(
            "create the documents",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert_eq!(
            result,
            AnomalyResponse::Normal,
            "write session should not trigger structural checks"
        );
    }

    /// Normal scalar arguments in a read session should NOT be flagged.
    #[test]
    fn normal_read_args_not_flagged() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let args = serde_json::json!({"path": "/etc/config", "recursive": true});
        let result = detector.detect_with_args(
            "read the config",
            OperationType::Read,
            "read_file",
            Some(&args),
        );
        assert_eq!(
            result,
            AnomalyResponse::Normal,
            "normal scalar args should not be flagged, got: {result:?}"
        );
    }
}
