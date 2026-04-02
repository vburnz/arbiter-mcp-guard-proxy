//! Audit capture middleware: wraps a proxied request with timing and context.
//!
//! The proxy creates an [`AuditCapture`] at the start of each request, fills in
//! context as it becomes available, then finalizes the capture after the upstream
//! response. The resulting [`AuditEntry`] is written to the configured sink.

use std::time::Instant;

use uuid::Uuid;

use std::sync::Arc;

use crate::entry::AuditEntry;
use crate::redaction::{CompiledRedaction, RedactionConfig};

/// Captures audit context across a single proxied request lifecycle.
///
/// # Usage
///
/// ```ignore
/// let compiled = redaction_config.compile();
/// let mut capture = AuditCapture::begin_compiled(Arc::new(compiled));
/// capture.set_agent_id("agent-1");
/// capture.set_tool_called("/tools/call");
/// // … proxy the request …
/// let entry = capture.finalize(Some(200));
/// audit_sink.write(&entry).await?;
/// ```
pub struct AuditCapture {
    start: Instant,
    entry: AuditEntry,
    compiled_redaction: Arc<CompiledRedaction>,
}

impl AuditCapture {
    /// Begin a new audit capture with a fresh request ID.
    ///
    /// Compiles redaction patterns on each call. For hot-path usage, prefer
    /// [`begin_compiled`](Self::begin_compiled) with a pre-compiled config.
    pub fn begin(redaction_config: RedactionConfig) -> Self {
        Self {
            start: Instant::now(),
            entry: AuditEntry::new(Uuid::new_v4()),
            compiled_redaction: Arc::new(redaction_config.compile()),
        }
    }

    /// Begin a new audit capture with pre-compiled redaction patterns.
    pub fn begin_compiled(compiled: Arc<CompiledRedaction>) -> Self {
        Self {
            start: Instant::now(),
            entry: AuditEntry::new(Uuid::new_v4()),
            compiled_redaction: compiled,
        }
    }

    /// Begin a new audit capture with a caller-supplied request ID.
    pub fn begin_with_id(request_id: Uuid, redaction_config: RedactionConfig) -> Self {
        Self {
            start: Instant::now(),
            entry: AuditEntry::new(request_id),
            compiled_redaction: Arc::new(redaction_config.compile()),
        }
    }

    /// Begin a new audit capture with a caller-supplied request ID and
    /// pre-compiled redaction patterns.
    pub fn begin_with_id_compiled(request_id: Uuid, compiled: Arc<CompiledRedaction>) -> Self {
        Self {
            start: Instant::now(),
            entry: AuditEntry::new(request_id),
            compiled_redaction: compiled,
        }
    }

    pub fn set_agent_id(&mut self, agent_id: impl Into<String>) {
        self.entry.agent_id = agent_id.into();
    }

    pub fn set_delegation_chain(&mut self, chain: impl Into<String>) {
        self.entry.delegation_chain = chain.into();
    }

    pub fn set_task_session_id(&mut self, session_id: impl Into<String>) {
        self.entry.task_session_id = session_id.into();
    }

    pub fn set_tool_called(&mut self, tool: impl Into<String>) {
        self.entry.tool_called = tool.into();
    }

    pub fn set_arguments(&mut self, args: serde_json::Value) {
        self.entry.arguments = args;
    }

    /// Valid authorization decision values. Callers must use one of these.
    const VALID_DECISIONS: &'static [&'static str] = &["allow", "deny", "escalate"];

    pub fn set_authorization_decision(&mut self, decision: impl Into<String>) {
        let decision = decision.into();
        if !Self::VALID_DECISIONS.contains(&decision.as_str()) {
            tracing::warn!(
                decision = %decision,
                "invalid authorization_decision value; expected one of: allow, deny, escalate"
            );
        }
        self.entry.authorization_decision = decision;
    }

    pub fn set_policy_matched(&mut self, policy: impl Into<String>) {
        self.entry.policy_matched = Some(policy.into());
    }

    pub fn set_anomaly_flags(&mut self, flags: Vec<String>) {
        self.entry.anomaly_flags = flags;
    }

    pub fn set_failure_category(&mut self, category: impl Into<String>) {
        self.entry.failure_category = Some(category.into());
    }

    pub fn add_inspection_findings(&mut self, findings: Vec<String>) {
        self.entry.inspection_findings = findings;
    }

    /// Finalize the capture: compute latency, apply redaction, return the entry.
    pub fn finalize(mut self, upstream_status: Option<u16>) -> AuditEntry {
        self.entry.latency_ms = self.start.elapsed().as_millis() as u64;
        self.entry.upstream_status = upstream_status;
        self.entry.arguments = self.compiled_redaction.redact(&self.entry.arguments);
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn captures_latency() {
        let capture = AuditCapture::begin(RedactionConfig::default());
        // Simulate some work.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let entry = capture.finalize(Some(200));

        assert!(entry.latency_ms >= 5, "latency should be at least 5ms");
        assert_eq!(entry.upstream_status, Some(200));
    }

    #[test]
    fn redacts_arguments_on_finalize() {
        let mut capture = AuditCapture::begin(RedactionConfig::default());
        capture.set_arguments(json!({
            "path": "/etc/hosts",
            "api_key": "sk-secret-123"
        }));
        capture.set_tool_called("read_file");

        let entry = capture.finalize(Some(200));

        assert_eq!(entry.arguments["path"], "/etc/hosts");
        assert_eq!(entry.arguments["api_key"], "[REDACTED]");
        assert_eq!(entry.tool_called, "read_file");
    }

    #[test]
    fn sets_all_fields() {
        let id = Uuid::new_v4();
        let mut capture = AuditCapture::begin_with_id(id, RedactionConfig { patterns: vec![] });
        capture.set_agent_id("agent-42");
        capture.set_delegation_chain("human>agent-42");
        capture.set_task_session_id("session-abc");
        capture.set_tool_called("write_file");
        capture.set_authorization_decision("allow");
        capture.set_policy_matched("policy-write");
        capture.set_anomaly_flags(vec!["high_frequency".into()]);
        capture.set_arguments(json!({"content": "hello"}));

        let entry = capture.finalize(Some(201));

        assert_eq!(entry.request_id, id);
        assert_eq!(entry.agent_id, "agent-42");
        assert_eq!(entry.delegation_chain, "human>agent-42");
        assert_eq!(entry.task_session_id, "session-abc");
        assert_eq!(entry.tool_called, "write_file");
        assert_eq!(entry.authorization_decision, "allow");
        assert_eq!(entry.policy_matched, Some("policy-write".into()));
        assert_eq!(entry.anomaly_flags, vec!["high_frequency"]);
        assert_eq!(entry.upstream_status, Some(201));
        assert_eq!(entry.arguments["content"], "hello");
    }
}
