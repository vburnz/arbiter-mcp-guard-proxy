//! Behavioral call sequence tracker.
//!
//! Tracks the sequence of tool calls within a task session for
//! anomaly detection purposes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::classifier::OperationType;

/// A record of a single tool call in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    /// The tool that was called.
    pub tool_name: String,
    /// The MCP method.
    pub method: String,
    /// Classified operation type.
    pub operation_type: OperationType,
    /// When the call was made.
    pub timestamp: DateTime<Utc>,
}

/// Tracks call sequences per session.
#[derive(Clone)]
pub struct BehaviorTracker {
    /// session_id -> ordered list of call records.
    records: Arc<RwLock<HashMap<Uuid, Vec<CallRecord>>>>,
}

impl BehaviorTracker {
    /// Create a new behavior tracker.
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a tool call for a session.
    pub async fn record_call(
        &self,
        session_id: Uuid,
        tool_name: String,
        method: String,
        operation_type: OperationType,
    ) {
        let record = CallRecord {
            tool_name,
            method,
            operation_type,
            timestamp: Utc::now(),
        };

        tracing::trace!(
            session_id = %session_id,
            tool = %record.tool_name,
            op = ?record.operation_type,
            "recording tool call"
        );

        let mut records = self.records.write().await;
        records
            .entry(session_id)
            .or_insert_with(Vec::new)
            .push(record);
    }

    /// Get all call records for a session.
    pub async fn get_records(&self, session_id: Uuid) -> Vec<CallRecord> {
        let records = self.records.read().await;
        records.get(&session_id).cloned().unwrap_or_default()
    }

    /// Remove records for a session (called on session close/cleanup).
    pub async fn clear_session(&self, session_id: Uuid) {
        let mut records = self.records.write().await;
        records.remove(&session_id);
    }
}

impl Default for BehaviorTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn track_and_retrieve_calls() {
        let tracker = BehaviorTracker::new();
        let session_id = Uuid::new_v4();

        tracker
            .record_call(
                session_id,
                "read_file".into(),
                "tools/call".into(),
                OperationType::Read,
            )
            .await;

        tracker
            .record_call(
                session_id,
                "list_dir".into(),
                "tools/call".into(),
                OperationType::Read,
            )
            .await;

        let records = tracker.get_records(session_id).await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].tool_name, "read_file");
        assert_eq!(records[1].tool_name, "list_dir");
    }

    #[tokio::test]
    async fn clear_session_records() {
        let tracker = BehaviorTracker::new();
        let session_id = Uuid::new_v4();

        tracker
            .record_call(
                session_id,
                "read_file".into(),
                "tools/call".into(),
                OperationType::Read,
            )
            .await;

        tracker.clear_session(session_id).await;
        let records = tracker.get_records(session_id).await;
        assert!(records.is_empty());
    }
}
