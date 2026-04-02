//! Storage-backed session store with in-memory write-through cache.
//!
//! Design decision: In-memory cache for hot-path reads (request latency),
//! write-through to persistent storage for durability (persistence depth).
//! On startup, the cache is populated from storage.
//!
//! REQ-001: Session state survives process restart.
//! REQ-007: Storage behind async trait; swappable backends.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use arbiter_storage::{
    SessionStore as StorageSessionStore, StorageError, StoredDataSensitivity, StoredSession,
    StoredSessionStatus,
};

use crate::error::SessionError;
use crate::model::{DataSensitivity, SessionId, SessionStatus, TaskSession};
use crate::store::CreateSessionRequest;

/// A session store backed by persistent storage with an in-memory cache.
///
/// All reads hit the cache first. All writes go to both the cache and
/// the underlying storage backend. On construction, the cache is warmed
/// from storage to handle process restarts.
#[derive(Clone)]
pub struct StorageBackedSessionStore {
    cache: Arc<RwLock<HashMap<SessionId, TaskSession>>>,
    storage: Arc<dyn StorageSessionStore>,
}

impl StorageBackedSessionStore {
    /// Create a new storage-backed session store.
    ///
    /// Loads all existing sessions from storage into the in-memory cache.
    pub async fn new(storage: Arc<dyn StorageSessionStore>) -> Result<Self, StorageError> {
        let store = Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            storage,
        };

        // Warm cache from storage.
        store.reload_from_storage().await?;

        Ok(store)
    }

    /// Reload the in-memory cache from storage.
    async fn reload_from_storage(&self) -> Result<(), StorageError> {
        let stored_sessions = self.storage.list_sessions().await?;
        let mut cache = self.cache.write().await;
        cache.clear();
        for stored in stored_sessions {
            if let Ok(session) = stored_to_domain(stored) {
                cache.insert(session.session_id, session);
            }
        }
        tracing::info!(sessions = cache.len(), "session cache warmed from storage");
        Ok(())
    }

    /// Create a new task session and return it.
    pub async fn create(&self, req: CreateSessionRequest) -> TaskSession {
        let session = TaskSession {
            session_id: Uuid::new_v4(),
            agent_id: req.agent_id,
            delegation_chain_snapshot: req.delegation_chain_snapshot,
            declared_intent: req.declared_intent,
            authorized_tools: req.authorized_tools,
            authorized_credentials: req.authorized_credentials,
            time_limit: req.time_limit,
            call_budget: req.call_budget,
            calls_made: 0,
            rate_limit_per_minute: req.rate_limit_per_minute,
            rate_window_start: chrono::Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: req.rate_limit_window_secs,
            data_sensitivity_ceiling: req.data_sensitivity_ceiling,
            created_at: chrono::Utc::now(),
            status: SessionStatus::Active,
        };

        tracing::info!(
            session_id = %session.session_id,
            agent_id = %session.agent_id,
            intent = %session.declared_intent,
            budget = session.call_budget,
            "created task session (storage-backed)"
        );

        // Write to storage first, then cache.
        let stored = domain_to_stored(&session);
        if let Err(e) = self.storage.insert_session(&stored).await {
            tracing::error!(error = %e, "failed to persist session to storage");
        }

        let mut cache = self.cache.write().await;
        cache.insert(session.session_id, session.clone());
        session
    }

    /// Atomically check per-agent session cap and create if under the limit.
    pub async fn create_if_under_cap(
        &self,
        req: CreateSessionRequest,
        max_sessions: u64,
    ) -> Result<TaskSession, SessionError> {
        let mut cache = self.cache.write().await;

        let active_count = cache
            .values()
            .filter(|s| s.agent_id == req.agent_id && s.status == SessionStatus::Active)
            .count() as u64;

        if active_count >= max_sessions {
            return Err(SessionError::TooManySessions {
                agent_id: req.agent_id.to_string(),
                max: max_sessions,
                current: active_count,
            });
        }

        let session = TaskSession {
            session_id: uuid::Uuid::new_v4(),
            agent_id: req.agent_id,
            delegation_chain_snapshot: req.delegation_chain_snapshot,
            declared_intent: req.declared_intent,
            authorized_tools: req.authorized_tools,
            authorized_credentials: req.authorized_credentials,
            time_limit: req.time_limit,
            call_budget: req.call_budget,
            calls_made: 0,
            rate_limit_per_minute: req.rate_limit_per_minute,
            rate_window_start: chrono::Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: req.rate_limit_window_secs,
            data_sensitivity_ceiling: req.data_sensitivity_ceiling,
            created_at: chrono::Utc::now(),
            status: SessionStatus::Active,
        };

        // Write-through to storage.
        let stored = domain_to_stored(&session);
        if let Err(e) = self.storage.insert_session(&stored).await {
            tracing::error!(error = %e, "failed to persist session to storage");
        }

        cache.insert(session.session_id, session.clone());
        Ok(session)
    }

    /// Record a tool call against the session, checking all constraints.
    pub async fn use_session(
        &self,
        session_id: SessionId,
        tool_name: &str,
        requesting_agent_id: Option<uuid::Uuid>,
    ) -> Result<TaskSession, SessionError> {
        let mut cache = self.cache.write().await;
        let session = cache
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;

        // Verify agent binding to prevent session fixation.
        if let Some(agent_id) = requesting_agent_id
            && agent_id != session.agent_id
        {
            return Err(SessionError::AgentMismatch {
                session_id,
                expected: session.agent_id,
                actual: agent_id,
            });
        }

        if session.status == SessionStatus::Closed {
            return Err(SessionError::AlreadyClosed(session_id));
        }

        if session.is_expired() {
            session.status = SessionStatus::Expired;
            // Write-through: update storage.
            let stored = domain_to_stored(session);
            if let Err(e) = self.storage.update_session(&stored).await {
                tracing::error!(error = %e, "failed to persist expired session status");
            }
            return Err(SessionError::Expired(session_id));
        }

        if session.is_budget_exceeded() {
            return Err(SessionError::BudgetExceeded {
                session_id,
                limit: session.call_budget,
                used: session.calls_made,
            });
        }

        if !session.is_tool_authorized(tool_name) {
            return Err(SessionError::ToolNotAuthorized {
                session_id,
                tool: tool_name.into(),
            });
        }

        if session.check_rate_limit() {
            return Err(SessionError::RateLimited {
                session_id,
                limit_per_minute: session.rate_limit_per_minute.unwrap_or(0),
            });
        }

        session.calls_made += 1;

        tracing::debug!(
            session_id = %session_id,
            tool = tool_name,
            calls = session.calls_made,
            budget = session.call_budget,
            "session tool call recorded (storage-backed)"
        );

        let result = session.clone();

        // Write-through: update storage. Propagate failure so callers know
        // the budget increment is not durably committed.
        let stored = domain_to_stored(&result);
        if let Err(e) = self.storage.update_session(&stored).await {
            tracing::error!(error = %e, "failed to persist session update");
            return Err(SessionError::StorageWriteThrough {
                session_id,
                detail: e.to_string(),
            });
        }

        Ok(result)
    }

    /// Atomically validate and record a batch of tool calls against the session.
    ///
    /// Acquires the write lock once, validates ALL tools against
    /// the whitelist and budget, and only increments `calls_made` by the full
    /// batch count if every tool passes. If any tool fails validation, no
    /// budget is consumed for any of them.
    pub async fn use_session_batch(
        &self,
        session_id: SessionId,
        tool_names: &[&str],
        requesting_agent_id: Option<uuid::Uuid>,
    ) -> Result<TaskSession, SessionError> {
        let mut cache = self.cache.write().await;
        let session = cache
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;

        // Verify agent binding to prevent session fixation.
        if let Some(agent_id) = requesting_agent_id
            && agent_id != session.agent_id
        {
            return Err(SessionError::AgentMismatch {
                session_id,
                expected: session.agent_id,
                actual: agent_id,
            });
        }

        if session.status == SessionStatus::Closed {
            return Err(SessionError::AlreadyClosed(session_id));
        }

        if session.is_expired() {
            session.status = SessionStatus::Expired;
            // Write-through: update storage.
            let stored = domain_to_stored(session);
            if let Err(e) = self.storage.update_session(&stored).await {
                tracing::error!(error = %e, "failed to persist expired session status");
            }
            return Err(SessionError::Expired(session_id));
        }

        let batch_size = tool_names.len() as u64;

        // Check budget for the entire batch.
        if session.calls_made + batch_size > session.call_budget {
            return Err(SessionError::BudgetExceeded {
                session_id,
                limit: session.call_budget,
                used: session.calls_made,
            });
        }

        // Check tool authorization for every tool before consuming any budget.
        for tool_name in tool_names {
            if !session.is_tool_authorized(tool_name) {
                return Err(SessionError::ToolNotAuthorized {
                    session_id,
                    tool: (*tool_name).into(),
                });
            }
        }

        // Check rate limit for the entire batch.
        if let Some(limit) = session.rate_limit_per_minute {
            let now = chrono::Utc::now();
            let elapsed = now - session.rate_window_start;
            if elapsed >= chrono::Duration::seconds(session.rate_limit_window_secs as i64) {
                // New window; will be reset below after all checks pass.
            } else if session.rate_window_calls + batch_size > limit {
                return Err(SessionError::RateLimited {
                    session_id,
                    limit_per_minute: limit,
                });
            }
        }

        // All checks passed. Atomically increment counters.
        if let Some(_limit) = session.rate_limit_per_minute {
            let now = chrono::Utc::now();
            let elapsed = now - session.rate_window_start;
            if elapsed >= chrono::Duration::seconds(session.rate_limit_window_secs as i64) {
                session.rate_window_start = now;
                session.rate_window_calls = batch_size;
            } else {
                session.rate_window_calls += batch_size;
            }
        }

        session.calls_made += batch_size;

        tracing::debug!(
            session_id = %session_id,
            batch_size = batch_size,
            calls = session.calls_made,
            budget = session.call_budget,
            "session batch tool calls recorded (storage-backed)"
        );

        let result = session.clone();

        // Write-through: update storage. Propagate failure.
        let stored = domain_to_stored(&result);
        if let Err(e) = self.storage.update_session(&stored).await {
            tracing::error!(error = %e, "failed to persist session batch update");
            return Err(SessionError::StorageWriteThrough {
                session_id,
                detail: e.to_string(),
            });
        }

        Ok(result)
    }

    /// Close a session, preventing further use.
    pub async fn close(&self, session_id: SessionId) -> Result<TaskSession, SessionError> {
        let mut cache = self.cache.write().await;
        let session = cache
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;

        if session.status == SessionStatus::Closed {
            return Err(SessionError::AlreadyClosed(session_id));
        }

        session.status = SessionStatus::Closed;
        tracing::info!(session_id = %session_id, "session closed (storage-backed)");

        let result = session.clone();

        // Write-through: update storage.
        let stored = domain_to_stored(&result);
        if let Err(e) = self.storage.update_session(&stored).await {
            tracing::error!(error = %e, "failed to persist session close");
        }

        Ok(result)
    }

    /// Get a session by ID without modifying it.
    pub async fn get(&self, session_id: SessionId) -> Result<TaskSession, SessionError> {
        let cache = self.cache.read().await;
        cache
            .get(&session_id)
            .cloned()
            .ok_or(SessionError::NotFound(session_id))
    }

    /// List all sessions currently in the store.
    pub async fn list_all(&self) -> Vec<TaskSession> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    /// Count the number of active sessions for a given agent.
    ///
    /// P0: Used to enforce per-agent concurrent session caps.
    pub async fn count_active_for_agent(&self, agent_id: uuid::Uuid) -> u64 {
        let cache = self.cache.read().await;
        cache
            .values()
            .filter(|s| s.agent_id == agent_id && s.status == SessionStatus::Active)
            .count() as u64
    }

    /// Close all active sessions belonging to a specific agent.
    ///
    /// Called during agent deactivation.
    pub async fn close_sessions_for_agent(&self, agent_id: uuid::Uuid) -> usize {
        // Collect sessions to close while holding the write lock, then release
        // the lock before performing storage writes. This prevents blocking all
        // other session operations during sequential async storage writes.
        let to_persist: Vec<StoredSession>;
        let closed: usize;
        {
            let mut cache = self.cache.write().await;
            let mut count = 0usize;
            let mut stored_sessions = Vec::new();
            for session in cache.values_mut() {
                if session.agent_id == agent_id && session.status == SessionStatus::Active {
                    session.status = SessionStatus::Closed;
                    stored_sessions.push(domain_to_stored(session));
                    count += 1;
                }
            }
            to_persist = stored_sessions;
            closed = count;
        } // write lock released here

        // Persist closures outside the critical section.
        for stored in &to_persist {
            if let Err(e) = self.storage.update_session(stored).await {
                tracing::error!(
                    error = %e,
                    session_id = %stored.session_id,
                    "failed to persist session closure during agent deactivation"
                );
            }
        }
        closed
    }

    /// Remove expired sessions from cache and storage. Returns the number removed.
    pub async fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.write().await;
        let before = cache.len();
        cache.retain(|_, s| {
            if s.is_expired() {
                tracing::debug!(session_id = %s.session_id, "cleaning up expired session (storage-backed)");
                false
            } else {
                true
            }
        });
        let removed = before - cache.len();

        // Also clean up storage.
        if let Err(e) = self.storage.delete_expired_sessions().await {
            tracing::error!(error = %e, "failed to clean up expired sessions in storage");
        }

        if removed > 0 {
            tracing::info!(removed, "cleaned up expired sessions (storage-backed)");
        }
        removed
    }
}

// ── Conversion helpers ──────────────────────────────────────────────

fn domain_to_stored(session: &TaskSession) -> StoredSession {
    StoredSession {
        session_id: session.session_id,
        agent_id: session.agent_id,
        delegation_chain_snapshot: session.delegation_chain_snapshot.clone(),
        declared_intent: session.declared_intent.clone(),
        authorized_tools: session.authorized_tools.clone(),
        time_limit_secs: session.time_limit.num_seconds(),
        call_budget: session.call_budget,
        calls_made: session.calls_made,
        rate_limit_per_minute: session.rate_limit_per_minute,
        rate_window_start: session.rate_window_start,
        rate_window_calls: session.rate_window_calls,
        rate_limit_window_secs: session.rate_limit_window_secs,
        data_sensitivity_ceiling: sensitivity_to_stored(session.data_sensitivity_ceiling),
        created_at: session.created_at,
        status: status_to_stored(session.status),
    }
}

/// Maximum session duration (24 hours). Re-validated on reload to prevent
/// a compromised storage backend from extending sessions indefinitely.
const MAX_SESSION_TIME_LIMIT_SECS: i64 = 86400;

fn stored_to_domain(stored: StoredSession) -> Result<TaskSession, String> {
    // Re-validate time_limit_secs upper bound on reload.
    let clamped_time_limit = stored.time_limit_secs.min(MAX_SESSION_TIME_LIMIT_SECS);
    if stored.time_limit_secs > MAX_SESSION_TIME_LIMIT_SECS {
        tracing::warn!(
            session_id = %stored.session_id,
            stored = stored.time_limit_secs,
            clamped = clamped_time_limit,
            "session time_limit_secs exceeded maximum on reload, clamping"
        );
    }

    Ok(TaskSession {
        session_id: stored.session_id,
        agent_id: stored.agent_id,
        delegation_chain_snapshot: stored.delegation_chain_snapshot,
        declared_intent: stored.declared_intent,
        authorized_tools: stored.authorized_tools,
        authorized_credentials: vec![], // TODO: persist in StoredSession once storage schema is updated
        time_limit: chrono::Duration::seconds(clamped_time_limit),
        call_budget: stored.call_budget,
        calls_made: stored.calls_made,
        rate_limit_per_minute: stored.rate_limit_per_minute,
        rate_window_start: stored.rate_window_start,
        rate_window_calls: stored.rate_window_calls,
        rate_limit_window_secs: stored.rate_limit_window_secs,
        data_sensitivity_ceiling: stored_to_sensitivity(stored.data_sensitivity_ceiling),
        created_at: stored.created_at,
        status: stored_to_status(stored.status),
    })
}

fn status_to_stored(status: SessionStatus) -> StoredSessionStatus {
    match status {
        SessionStatus::Active => StoredSessionStatus::Active,
        SessionStatus::Closed => StoredSessionStatus::Closed,
        SessionStatus::Expired => StoredSessionStatus::Expired,
    }
}

fn stored_to_status(status: StoredSessionStatus) -> SessionStatus {
    match status {
        StoredSessionStatus::Active => SessionStatus::Active,
        StoredSessionStatus::Closed => SessionStatus::Closed,
        StoredSessionStatus::Expired => SessionStatus::Expired,
    }
}

fn sensitivity_to_stored(sensitivity: DataSensitivity) -> StoredDataSensitivity {
    match sensitivity {
        DataSensitivity::Public => StoredDataSensitivity::Public,
        DataSensitivity::Internal => StoredDataSensitivity::Internal,
        DataSensitivity::Confidential => StoredDataSensitivity::Confidential,
        DataSensitivity::Restricted => StoredDataSensitivity::Restricted,
    }
}

fn stored_to_sensitivity(sensitivity: StoredDataSensitivity) -> DataSensitivity {
    match sensitivity {
        StoredDataSensitivity::Public => DataSensitivity::Public,
        StoredDataSensitivity::Internal => DataSensitivity::Internal,
        StoredDataSensitivity::Confidential => DataSensitivity::Confidential,
        StoredDataSensitivity::Restricted => DataSensitivity::Restricted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// In-memory mock implementing `StorageSessionStore` (arbiter_storage::SessionStore).
    #[derive(Clone)]
    struct MockStorage {
        sessions: Arc<RwLock<HashMap<Uuid, StoredSession>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                sessions: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl StorageSessionStore for MockStorage {
        async fn insert_session(&self, session: &StoredSession) -> Result<(), StorageError> {
            let mut map = self.sessions.write().await;
            map.insert(session.session_id, session.clone());
            Ok(())
        }

        async fn get_session(&self, session_id: Uuid) -> Result<StoredSession, StorageError> {
            let map = self.sessions.read().await;
            map.get(&session_id)
                .cloned()
                .ok_or(StorageError::SessionNotFound(session_id))
        }

        async fn update_session(&self, session: &StoredSession) -> Result<(), StorageError> {
            let mut map = self.sessions.write().await;
            map.insert(session.session_id, session.clone());
            Ok(())
        }

        async fn delete_expired_sessions(&self) -> Result<usize, StorageError> {
            let mut map = self.sessions.write().await;
            let before = map.len();
            let now = chrono::Utc::now();
            map.retain(|_, s| {
                let created = s.created_at;
                let limit = chrono::Duration::seconds(s.time_limit_secs);
                let elapsed = now - created;
                elapsed <= limit && s.status != StoredSessionStatus::Expired
            });
            Ok(before - map.len())
        }

        async fn list_sessions(&self) -> Result<Vec<StoredSession>, StorageError> {
            let map = self.sessions.read().await;
            Ok(map.values().cloned().collect())
        }
    }

    fn test_create_request() -> CreateSessionRequest {
        CreateSessionRequest {
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: "read and analyze files".into(),
            authorized_tools: vec!["read_file".into(), "list_dir".into()],
            authorized_credentials: vec![],
            time_limit: chrono::Duration::hours(1),
            call_budget: 5,
            rate_limit_per_minute: None,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: DataSensitivity::Internal,
        }
    }

    async fn make_store() -> (StorageBackedSessionStore, MockStorage) {
        let mock = MockStorage::new();
        let store = StorageBackedSessionStore::new(Arc::new(mock.clone()))
            .await
            .expect("failed to create storage-backed store");
        (store, mock)
    }

    #[tokio::test]
    async fn create_and_use_session() {
        let (store, _mock) = make_store().await;
        let session = store.create(test_create_request()).await;

        assert_eq!(session.calls_made, 0);
        assert!(session.is_active());

        let updated = store
            .use_session(session.session_id, "read_file", None)
            .await
            .unwrap();
        assert_eq!(updated.calls_made, 1);

        // Verify get returns same data.
        let fetched = store.get(session.session_id).await.unwrap();
        assert_eq!(fetched.calls_made, 1);
    }

    #[tokio::test]
    async fn budget_enforcement() {
        let (store, _mock) = make_store().await;
        let mut req = test_create_request();
        req.call_budget = 2;
        let session = store.create(req).await;

        store
            .use_session(session.session_id, "read_file", None)
            .await
            .unwrap();
        store
            .use_session(session.session_id, "read_file", None)
            .await
            .unwrap();

        let result = store
            .use_session(session.session_id, "read_file", None)
            .await;
        assert!(matches!(result, Err(SessionError::BudgetExceeded { .. })));
    }

    #[tokio::test]
    async fn tool_whitelist_enforcement() {
        let (store, _mock) = make_store().await;
        let session = store.create(test_create_request()).await;

        store
            .use_session(session.session_id, "read_file", None)
            .await
            .unwrap();

        let result = store
            .use_session(session.session_id, "delete_file", None)
            .await;
        assert!(matches!(
            result,
            Err(SessionError::ToolNotAuthorized { .. })
        ));
    }

    #[tokio::test]
    async fn session_expiry() {
        let (store, _mock) = make_store().await;
        let mut req = test_create_request();
        req.time_limit = chrono::Duration::zero();
        let session = store.create(req).await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let result = store
            .use_session(session.session_id, "read_file", None)
            .await;
        assert!(matches!(result, Err(SessionError::Expired(_))));
    }

    #[tokio::test]
    async fn close_and_reuse() {
        let (store, _mock) = make_store().await;
        let session = store.create(test_create_request()).await;

        store.close(session.session_id).await.unwrap();

        let result = store
            .use_session(session.session_id, "read_file", None)
            .await;
        assert!(matches!(result, Err(SessionError::AlreadyClosed(_))));
    }

    #[tokio::test]
    async fn session_not_found() {
        let (store, _mock) = make_store().await;
        let fake_id = Uuid::new_v4();
        let result = store.use_session(fake_id, "anything", None).await;
        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }

    /// batch with one bad tool must consume zero budget.
    #[tokio::test]
    async fn batch_validation_atomicity() {
        let (store, _mock) = make_store().await;
        let mut req = test_create_request();
        req.call_budget = 10;
        req.authorized_tools = vec!["read_file".into(), "list_dir".into()];
        let session = store.create(req).await;

        // Batch contains one unauthorized tool ("delete_file").
        let result = store
            .use_session_batch(session.session_id, &["read_file", "delete_file"], None)
            .await;
        assert!(
            matches!(result, Err(SessionError::ToolNotAuthorized { .. })),
            "expected ToolNotAuthorized, got {result:?}"
        );

        // Budget must remain untouched.
        let s = store.get(session.session_id).await.unwrap();
        assert_eq!(
            s.calls_made, 0,
            "no budget should be consumed on batch failure"
        );
    }

    #[tokio::test]
    async fn batch_budget_enforcement() {
        let (store, _mock) = make_store().await;
        let mut req = test_create_request();
        req.call_budget = 3;
        req.authorized_tools = vec!["read_file".into()];
        let session = store.create(req).await;

        // Batch of 4 exceeds budget of 3.
        let result = store
            .use_session_batch(
                session.session_id,
                &["read_file", "read_file", "read_file", "read_file"],
                None,
            )
            .await;
        assert!(
            matches!(result, Err(SessionError::BudgetExceeded { .. })),
            "expected BudgetExceeded, got {result:?}"
        );

        // Budget must remain at 0 (no partial consumption).
        let s = store.get(session.session_id).await.unwrap();
        assert_eq!(
            s.calls_made, 0,
            "no budget should be consumed on batch failure"
        );
    }

    #[tokio::test]
    async fn batch_rate_limit_enforcement() {
        let (store, _mock) = make_store().await;
        let mut req = test_create_request();
        req.call_budget = 100;
        req.rate_limit_per_minute = Some(3);
        req.authorized_tools = vec!["read_file".into()];
        let session = store.create(req).await;

        // Batch of 4 exceeds rate limit of 3.
        let result = store
            .use_session_batch(
                session.session_id,
                &["read_file", "read_file", "read_file", "read_file"],
                None,
            )
            .await;
        assert!(
            matches!(result, Err(SessionError::RateLimited { .. })),
            "expected RateLimited, got {result:?}"
        );
    }

    #[tokio::test]
    async fn cleanup_expired_sessions() {
        let (store, _mock) = make_store().await;

        // Create an already-expired session.
        let mut req = test_create_request();
        req.time_limit = chrono::Duration::zero();
        store.create(req).await;

        // Create a valid session.
        store.create(test_create_request()).await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let removed = store.cleanup_expired().await;
        assert_eq!(removed, 1);
    }

    #[tokio::test]
    async fn count_active_for_agent() {
        let (store, _mock) = make_store().await;
        let agent_id = Uuid::new_v4();

        // Create 3 sessions for the same agent.
        for _ in 0..3 {
            let mut req = test_create_request();
            req.agent_id = agent_id;
            store.create(req).await;
        }

        // Create 1 session for a different agent.
        store.create(test_create_request()).await;

        let count = store.count_active_for_agent(agent_id).await;
        assert_eq!(count, 3);
    }

    /// Verify that mutations are written through to the mock storage backend.
    #[tokio::test]
    async fn storage_write_through() {
        let (store, mock) = make_store().await;
        let session = store.create(test_create_request()).await;

        // After create, session must exist in storage.
        let stored = mock
            .get_session(session.session_id)
            .await
            .expect("session should exist in storage after create");
        assert_eq!(stored.calls_made, 0);

        // After use_session, storage must reflect the increment.
        store
            .use_session(session.session_id, "read_file", None)
            .await
            .unwrap();
        let stored = mock.get_session(session.session_id).await.unwrap();
        assert_eq!(stored.calls_made, 1, "storage must reflect the tool call");

        // After close, storage must reflect the new status.
        store.close(session.session_id).await.unwrap();
        let stored = mock.get_session(session.session_id).await.unwrap();
        assert_eq!(
            stored.status,
            StoredSessionStatus::Closed,
            "storage must reflect the closed status"
        );
    }
}
