//! Audit output sinks: structured JSON lines to stdout and file.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

use crate::entry::AuditEntry;

/// Errors from writing audit entries.
#[derive(Debug, Error)]
pub enum SinkError {
    #[error("JSON serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("file I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for the audit sink.
#[derive(Debug, Clone)]
pub struct AuditSinkConfig {
    /// Write JSON lines to stdout (12-factor compatible).
    pub write_stdout: bool,

    /// Optional path to an append-only audit log file.
    pub file_path: Option<PathBuf>,
}

impl Default for AuditSinkConfig {
    fn default() -> Self {
        Self {
            write_stdout: true,
            file_path: None,
        }
    }
}

/// Writes audit entries to configured outputs.
///
/// Tracks write failures via an atomic counter. When the file sink
/// fails (disk full, permissions), the proxy can surface this via
/// `X-Arbiter-Audit-Degraded` response headers.
pub struct AuditSink {
    config: AuditSinkConfig,
    stats: crate::stats::AuditStats,
    /// Consecutive write failures. Reset to 0 on each successful write.
    write_failures: AtomicU64,
    /// Total write failures since startup.
    total_write_failures: AtomicU64,
}

impl AuditSink {
    /// Create a new audit sink with the given configuration.
    pub fn new(config: AuditSinkConfig) -> Self {
        Self {
            config,
            stats: crate::stats::AuditStats::new(),
            write_failures: AtomicU64::new(0),
            total_write_failures: AtomicU64::new(0),
        }
    }

    /// Get a handle to the audit stats tracker for querying.
    pub fn stats(&self) -> &crate::stats::AuditStats {
        &self.stats
    }

    /// Returns true if the audit sink has had recent write failures.
    pub fn is_degraded(&self) -> bool {
        self.write_failures.load(Ordering::Relaxed) > 0
    }

    /// Number of consecutive write failures (0 = healthy).
    pub fn consecutive_failures(&self) -> u64 {
        self.write_failures.load(Ordering::Relaxed)
    }

    /// Total write failures since startup.
    pub fn total_failures(&self) -> u64 {
        self.total_write_failures.load(Ordering::Relaxed)
    }

    /// Write an audit entry to all configured outputs.
    ///
    /// Writes to stdout and file sinks in order. The file sink is considered
    /// critical -- errors are tracked and returned.
    pub async fn write(&self, entry: &AuditEntry) -> Result<(), SinkError> {
        // Update in-memory stats counters.
        self.stats.record(entry).await;

        let json = serde_json::to_string(entry)?;

        if self.config.write_stdout {
            // Structured JSON line to stdout via tracing (12-factor).
            tracing::info!(target: "arbiter_audit", audit_entry = %json);
        }

        if let Some(path) = &self.config.file_path {
            match self.write_to_file(path, &json).await {
                Ok(()) => {
                    self.write_failures.store(0, Ordering::Relaxed);
                }
                Err(e) => {
                    let consecutive = self.write_failures.fetch_add(1, Ordering::Relaxed) + 1;
                    self.total_write_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(
                        error = %e,
                        consecutive_failures = consecutive,
                        "audit file write failed; audit data may be lost"
                    );
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    async fn write_to_file(&self, path: &PathBuf, json: &str) -> Result<(), SinkError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn write_to_file() {
        let dir = std::env::temp_dir().join(format!("arbiter-audit-test-{}", Uuid::new_v4()));
        let file_path = dir.join("audit.jsonl");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let sink = AuditSink::new(AuditSinkConfig {
            write_stdout: false,
            file_path: Some(file_path.clone()),
            ..Default::default()
        });

        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.agent_id = "test-agent".into();
        entry.tool_called = "test_tool".into();
        entry.latency_ms = 10;

        sink.write(&entry).await.unwrap();
        sink.write(&entry).await.unwrap();

        let contents = tokio::fs::read_to_string(&file_path).await.unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON.
        let parsed: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.agent_id, "test-agent");

        // Cleanup.
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn tracks_write_failures() {
        // Point at a non-existent directory to force write failures.
        let sink = AuditSink::new(AuditSinkConfig {
            write_stdout: false,
            file_path: Some(PathBuf::from("/nonexistent/dir/audit.jsonl")),
            ..Default::default()
        });

        assert!(!sink.is_degraded());
        assert_eq!(sink.consecutive_failures(), 0);

        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.tool_called = "test".into();

        // First write should fail.
        assert!(sink.write(&entry).await.is_err());
        assert!(sink.is_degraded());
        assert_eq!(sink.consecutive_failures(), 1);
        assert_eq!(sink.total_failures(), 1);

        // Second failure increments.
        assert!(sink.write(&entry).await.is_err());
        assert_eq!(sink.consecutive_failures(), 2);
        assert_eq!(sink.total_failures(), 2);
    }

    #[tokio::test]
    async fn resets_failures_on_success() {
        let dir = std::env::temp_dir().join(format!("arbiter-audit-reset-{}", Uuid::new_v4()));
        let file_path = dir.join("audit.jsonl");

        // Start with bad path.
        let sink = AuditSink::new(AuditSinkConfig {
            write_stdout: false,
            file_path: Some(PathBuf::from("/nonexistent/dir/audit.jsonl")),
            ..Default::default()
        });

        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.tool_called = "test".into();

        // Force a failure.
        let _ = sink.write(&entry).await;
        assert!(sink.is_degraded());

        // Now create the real dir and point to it (simulate recovery).
        // Since config is immutable, we test with a new sink to prove the counter logic.
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let recovered_sink = AuditSink::new(AuditSinkConfig {
            write_stdout: false,
            file_path: Some(file_path.clone()),
            ..Default::default()
        });
        // Manually simulate degraded state then recovery.
        recovered_sink.write_failures.store(3, Ordering::Relaxed);
        assert!(recovered_sink.is_degraded());

        // Successful write resets consecutive counter.
        recovered_sink.write(&entry).await.unwrap();
        assert!(!recovered_sink.is_degraded());
        assert_eq!(recovered_sink.consecutive_failures(), 0);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn serialization_produces_valid_json() {
        let mut entry = AuditEntry::new(Uuid::new_v4());
        entry.agent_id = "test-agent".into();
        entry.tool_called = "dangerous_tool".into();
        entry.authorization_decision = "deny".into();
        entry.policy_matched = Some("block-dangerous".into());
        entry.anomaly_flags = vec!["scope_violation".into(), "unusual_hour".into()];
        entry.latency_ms = 7;
        entry.upstream_status = Some(403);

        let json = serde_json::to_string(&entry).unwrap();

        // The JSON must round-trip cleanly.
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "test-agent");
        assert_eq!(parsed.authorization_decision, "deny");
        assert_eq!(parsed.anomaly_flags.len(), 2);
        assert_eq!(parsed.upstream_status, Some(403));

        // The JSON must be a single line (suitable for JSONL).
        assert!(!json.contains('\n'), "JSON must be a single line");
    }
}
