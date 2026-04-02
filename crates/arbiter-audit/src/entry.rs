//! The core audit log entry structure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A structured audit log entry capturing a complete request lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,

    /// Unique identifier for this request.
    pub request_id: Uuid,

    /// The agent that made the request.
    pub agent_id: String,

    /// Serialized delegation chain (human → agent → sub-agent …).
    pub delegation_chain: String,

    /// The task session this request belongs to.
    pub task_session_id: String,

    /// The MCP tool (or HTTP path) that was called.
    pub tool_called: String,

    /// Tool arguments, with sensitive fields redacted.
    pub arguments: serde_json::Value,

    /// The authorization decision: "allow", "deny", or "escalate".
    pub authorization_decision: String,

    /// Which policy rule matched (if any).
    pub policy_matched: Option<String>,

    /// Anomaly flags raised by the behavior engine.
    pub anomaly_flags: Vec<String>,

    /// Failure category: "governance", "infrastructure", or "protocol".
    /// Distinguishes policy denials from upstream errors in audit analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_category: Option<String>,

    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,

    /// HTTP status code from the upstream response.
    pub upstream_status: Option<u16>,

    /// Inspection findings from content inspection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inspection_findings: Vec<String>,

    /// Monotonic sequence number for tamper detection.
    /// A gap in sequence numbers indicates a lost or deleted entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_sequence: Option<u64>,

    /// Blake3 hash of the previous entry (hex-encoded).
    /// Forms a hash chain for integrity verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_prev_hash: Option<String>,

    /// Blake3 hash of this entry (hex-encoded), computed over all fields
    /// except this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_record_hash: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry with the given request ID and current timestamp.
    pub fn new(request_id: Uuid) -> Self {
        Self {
            timestamp: Utc::now(),
            request_id,
            agent_id: String::new(),
            delegation_chain: String::new(),
            task_session_id: String::new(),
            tool_called: String::new(),
            arguments: serde_json::Value::Null,
            authorization_decision: String::new(),
            policy_matched: None,
            anomaly_flags: Vec::new(),
            failure_category: None,
            latency_ms: 0,
            upstream_status: None,
            inspection_findings: Vec::new(),
            chain_sequence: None,
            chain_prev_hash: None,
            chain_record_hash: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_serialization_roundtrip() {
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.agent_id = "agent-1".into();
        entry.delegation_chain = "human>agent-1".into();
        entry.task_session_id = Uuid::new_v4().to_string();
        entry.tool_called = "read_file".into();
        entry.arguments = serde_json::json!({"path": "/etc/hosts"});
        entry.authorization_decision = "allow".into();
        entry.policy_matched = Some("policy-read-all".into());
        entry.anomaly_flags = vec!["unusual_hour".into()];
        entry.latency_ms = 42;
        entry.upstream_status = Some(200);

        let json = serde_json::to_string(&entry).expect("serialize");
        let deserialized: AuditEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.request_id, entry.request_id);
        assert_eq!(deserialized.agent_id, "agent-1");
        assert_eq!(deserialized.tool_called, "read_file");
        assert_eq!(deserialized.latency_ms, 42);
        assert_eq!(deserialized.upstream_status, Some(200));
        assert_eq!(deserialized.anomaly_flags, vec!["unusual_hour"]);
    }

    #[test]
    fn entry_defaults_are_empty() {
        let entry = AuditEntry::new(Uuid::nil());
        assert_eq!(entry.agent_id, "");
        assert_eq!(entry.arguments, serde_json::Value::Null);
        assert!(entry.anomaly_flags.is_empty());
        assert!(entry.policy_matched.is_none());
        assert!(entry.upstream_status.is_none());
    }

    // -----------------------------------------------------------------------
    // Log injection via newlines in audit fields
    // -----------------------------------------------------------------------

    /// JSONL (JSON Lines) format requires each log entry to be a single line.
    /// If agent_id or tool_called contain literal newlines, serde_json must
    /// escape them as `\n` and `\r` in the output, ensuring one JSON object
    /// per line and preventing log injection attacks.
    #[test]
    fn entry_with_newlines_in_fields() {
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.agent_id = "agent\ninjected".into();
        entry.tool_called = "tool\r\ncall".into();
        entry.delegation_chain = "human\n>agent".into();
        entry.task_session_id = "session\nid".into();

        let json = serde_json::to_string(&entry).expect("serialize");

        // The JSON output must NOT contain raw newline characters.
        // serde_json escapes them as \n and \r in the JSON string.
        assert!(
            !json.contains('\n'),
            "JSON output must not contain raw newline (LF). Got: {}",
            json
        );
        assert!(
            !json.contains('\r'),
            "JSON output must not contain raw carriage return (CR). Got: {}",
            json
        );

        // Verify the escaped sequences are present instead.
        assert!(
            json.contains(r#"agent\ninjected"#),
            "agent_id newline must be escaped as \\n in JSON. Got: {}",
            json
        );
        assert!(
            json.contains(r#"tool\r\ncall"#),
            "tool_called CRLF must be escaped as \\r\\n in JSON. Got: {}",
            json
        );

        // Verify deserialization recovers the original values.
        let deserialized: AuditEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.agent_id, "agent\ninjected");
        assert_eq!(deserialized.tool_called, "tool\r\ncall");
        assert_eq!(deserialized.delegation_chain, "human\n>agent");
    }

    // -----------------------------------------------------------------------
    // JSONL injection via tool names
    // -----------------------------------------------------------------------

    /// A tool_called field containing a literal newline followed by a fake JSON
    /// object must not break JSONL format. serde_json must escape the newline
    /// as `\n` in the output, keeping the entire entry on one line and
    /// preventing log injection / log splitting attacks.
    #[test]
    fn entry_with_jsonl_injection_in_tool_name() {
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.agent_id = "agent-1".into();
        entry.tool_called = "read_file\n{\"injected\": true}".into();
        entry.authorization_decision = "allow".into();

        let json = serde_json::to_string(&entry).expect("serialize");

        // The serialized output must be a single line (no literal newlines).
        assert!(
            !json.contains('\n'),
            "serialized JSON must not contain raw newline (LF). Got: {}",
            json
        );
        assert!(
            !json.contains('\r'),
            "serialized JSON must not contain raw carriage return (CR). Got: {}",
            json
        );

        // The escaped sequence must be present in the output.
        assert!(
            json.contains(r#"read_file\n{\"injected\": true}"#),
            "tool_called newline must be JSON-escaped as \\n. Got: {}",
            json
        );

        // Roundtrip: parse it back and verify the tool name is preserved exactly.
        let deserialized: AuditEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            deserialized.tool_called, "read_file\n{\"injected\": true}",
            "tool_called must survive serialization roundtrip with embedded newline and JSON"
        );
    }
}
