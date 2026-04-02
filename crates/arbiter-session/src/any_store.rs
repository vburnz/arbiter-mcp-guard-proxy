//! Unified session store enum dispatching to either in-memory or storage-backed.

use crate::error::SessionError;
use crate::model::{SessionId, TaskSession};
use crate::storage_store::StorageBackedSessionStore;
use crate::store::{CreateSessionRequest, SessionStore};

/// A session store that dispatches to either in-memory or storage-backed.
#[derive(Clone)]
pub enum AnySessionStore {
    InMemory(SessionStore),
    StorageBacked(StorageBackedSessionStore),
}

impl AnySessionStore {
    /// Create a new task session and return it.
    pub async fn create(&self, req: CreateSessionRequest) -> TaskSession {
        match self {
            AnySessionStore::InMemory(s) => s.create(req).await,
            AnySessionStore::StorageBacked(s) => s.create(req).await,
        }
    }

    /// Record a tool call against the session.
    pub async fn use_session(
        &self,
        session_id: SessionId,
        tool_name: &str,
    ) -> Result<TaskSession, SessionError> {
        match self {
            AnySessionStore::InMemory(s) => s.use_session(session_id, tool_name).await,
            AnySessionStore::StorageBacked(s) => s.use_session(session_id, tool_name).await,
        }
    }

    /// Atomically validate and record a batch of tool calls against the session.
    ///
    /// Validates ALL tools and budget atomically under a single
    /// lock acquisition. No budget is consumed unless every tool in the batch
    /// passes validation.
    pub async fn use_session_batch(
        &self,
        session_id: SessionId,
        tool_names: &[&str],
    ) -> Result<TaskSession, SessionError> {
        match self {
            AnySessionStore::InMemory(s) => s.use_session_batch(session_id, tool_names).await,
            AnySessionStore::StorageBacked(s) => s.use_session_batch(session_id, tool_names).await,
        }
    }

    /// Close a session.
    pub async fn close(&self, session_id: SessionId) -> Result<TaskSession, SessionError> {
        match self {
            AnySessionStore::InMemory(s) => s.close(session_id).await,
            AnySessionStore::StorageBacked(s) => s.close(session_id).await,
        }
    }

    /// Get a session by ID.
    pub async fn get(&self, session_id: SessionId) -> Result<TaskSession, SessionError> {
        match self {
            AnySessionStore::InMemory(s) => s.get(session_id).await,
            AnySessionStore::StorageBacked(s) => s.get(session_id).await,
        }
    }

    /// List all sessions.
    pub async fn list_all(&self) -> Vec<TaskSession> {
        match self {
            AnySessionStore::InMemory(s) => s.list_all().await,
            AnySessionStore::StorageBacked(s) => s.list_all().await,
        }
    }

    /// Count the number of active sessions for a given agent.
    ///
    /// P0: Used to enforce per-agent concurrent session caps.
    pub async fn count_active_for_agent(&self, agent_id: uuid::Uuid) -> u64 {
        match self {
            AnySessionStore::InMemory(s) => s.count_active_for_agent(agent_id).await,
            AnySessionStore::StorageBacked(s) => s.count_active_for_agent(agent_id).await,
        }
    }

    /// Close all active sessions belonging to a specific agent.
    ///
    /// Called during agent deactivation.
    pub async fn close_sessions_for_agent(&self, agent_id: uuid::Uuid) -> usize {
        match self {
            AnySessionStore::InMemory(s) => s.close_sessions_for_agent(agent_id).await,
            AnySessionStore::StorageBacked(s) => s.close_sessions_for_agent(agent_id).await,
        }
    }

    /// Remove expired sessions. Returns the number removed.
    pub async fn cleanup_expired(&self) -> usize {
        match self {
            AnySessionStore::InMemory(s) => s.cleanup_expired().await,
            AnySessionStore::StorageBacked(s) => s.cleanup_expired().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DataSensitivity;

    #[tokio::test]
    async fn any_store_in_memory_dispatch() {
        let store = AnySessionStore::InMemory(SessionStore::new());

        let req = CreateSessionRequest {
            agent_id: uuid::Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: "test intent".into(),
            authorized_tools: vec!["read_file".into()],
            time_limit: chrono::Duration::hours(1),
            call_budget: 10,
            rate_limit_per_minute: None,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: DataSensitivity::Internal,
        };

        // Create.
        let session = store.create(req).await;
        assert_eq!(session.calls_made, 0);
        assert!(session.is_active());

        // Use.
        let updated = store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();
        assert_eq!(updated.calls_made, 1);

        // Get.
        let fetched = store.get(session.session_id).await.unwrap();
        assert_eq!(fetched.calls_made, 1);
        assert_eq!(fetched.declared_intent, "test intent");

        // List.
        let all = store.list_all().await;
        assert_eq!(all.len(), 1);

        // Count active for agent.
        let count = store.count_active_for_agent(session.agent_id).await;
        assert_eq!(count, 1);

        // Close.
        let closed = store.close(session.session_id).await.unwrap();
        assert_eq!(closed.status, crate::model::SessionStatus::Closed);

        // Use after close should fail.
        let err = store.use_session(session.session_id, "read_file").await;
        assert!(matches!(err, Err(SessionError::AlreadyClosed(_))));
    }
}
