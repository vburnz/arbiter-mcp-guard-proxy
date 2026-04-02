//! In-memory session store with TTL-based cleanup.

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::SessionError;
use crate::model::{DataSensitivity, SessionId, SessionStatus, TaskSession};

/// Request to create a new task session.
pub struct CreateSessionRequest {
    /// The agent ID for this session.
    pub agent_id: Uuid,
    /// Delegation chain snapshot (serialized).
    pub delegation_chain_snapshot: Vec<String>,
    /// Declared intent for the session.
    pub declared_intent: String,
    /// Tools authorized by policy evaluation.
    pub authorized_tools: Vec<String>,
    /// Session time limit.
    pub time_limit: chrono::Duration,
    /// Maximum number of tool calls.
    pub call_budget: u64,
    /// Per-minute rate limit. `None` means no rate limit.
    pub rate_limit_per_minute: Option<u64>,
    /// Duration of the rate-limit window in seconds. Defaults to 60.
    pub rate_limit_window_secs: u64,
    /// Data sensitivity ceiling.
    pub data_sensitivity_ceiling: DataSensitivity,
}

/// In-memory session store with TTL-based cleanup.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<SessionId, TaskSession>>>,
}

impl SessionStore {
    /// Create a new empty session store.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new task session and return it.
    pub async fn create(&self, req: CreateSessionRequest) -> TaskSession {
        let session = TaskSession {
            session_id: Uuid::new_v4(),
            agent_id: req.agent_id,
            delegation_chain_snapshot: req.delegation_chain_snapshot,
            declared_intent: req.declared_intent,
            authorized_tools: req.authorized_tools,
            time_limit: req.time_limit,
            call_budget: req.call_budget,
            calls_made: 0,
            rate_limit_per_minute: req.rate_limit_per_minute,
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: req.rate_limit_window_secs,
            data_sensitivity_ceiling: req.data_sensitivity_ceiling,
            created_at: Utc::now(),
            status: SessionStatus::Active,
        };

        tracing::info!(
            session_id = %session.session_id,
            agent_id = %session.agent_id,
            intent = %session.declared_intent,
            budget = session.call_budget,
            "created task session"
        );

        let mut sessions = self.sessions.write().await;
        sessions.insert(session.session_id, session.clone());
        session
    }

    /// Record a tool call against the session, checking all constraints.
    ///
    /// Returns the updated session on success, or an error if:
    /// - Session not found
    /// - Session expired (would return 408)
    /// - Budget exceeded (would return 429)
    /// - Tool not authorized (would return 403)
    pub async fn use_session(
        &self,
        session_id: SessionId,
        tool_name: &str,
    ) -> Result<TaskSession, SessionError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;

        if session.status == SessionStatus::Closed {
            return Err(SessionError::AlreadyClosed(session_id));
        }

        // Check expiry.
        if session.is_expired() {
            session.status = SessionStatus::Expired;
            return Err(SessionError::Expired(session_id));
        }

        // Check budget.
        if session.is_budget_exceeded() {
            return Err(SessionError::BudgetExceeded {
                session_id,
                limit: session.call_budget,
                used: session.calls_made,
            });
        }

        // Check tool authorization.
        if !session.is_tool_authorized(tool_name) {
            return Err(SessionError::ToolNotAuthorized {
                session_id,
                tool: tool_name.into(),
            });
        }

        // Check rate limit.
        if session.check_rate_limit() {
            return Err(SessionError::RateLimited {
                session_id,
                limit_per_minute: session.rate_limit_per_minute.unwrap_or(0),
            });
        }

        // All checks passed. Increment counter.
        session.calls_made += 1;

        tracing::debug!(
            session_id = %session_id,
            tool = tool_name,
            calls = session.calls_made,
            budget = session.call_budget,
            "session tool call recorded"
        );

        Ok(session.clone())
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
    ) -> Result<TaskSession, SessionError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;

        if session.status == SessionStatus::Closed {
            return Err(SessionError::AlreadyClosed(session_id));
        }

        // Check expiry.
        if session.is_expired() {
            session.status = SessionStatus::Expired;
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
        // We check whether adding batch_size calls would exceed the limit,
        // without mutating state until we know it's safe.
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
        // Update rate limit window.
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
            "session batch tool calls recorded"
        );

        Ok(session.clone())
    }

    /// Close a session, preventing further use.
    pub async fn close(&self, session_id: SessionId) -> Result<TaskSession, SessionError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;

        if session.status == SessionStatus::Closed {
            return Err(SessionError::AlreadyClosed(session_id));
        }

        session.status = SessionStatus::Closed;
        tracing::info!(session_id = %session_id, "session closed");
        Ok(session.clone())
    }

    /// Get a session by ID without modifying it.
    pub async fn get(&self, session_id: SessionId) -> Result<TaskSession, SessionError> {
        let sessions = self.sessions.read().await;
        sessions
            .get(&session_id)
            .cloned()
            .ok_or(SessionError::NotFound(session_id))
    }

    /// List all sessions currently in the store (active, expired, and closed).
    pub async fn list_all(&self) -> Vec<TaskSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Count the number of active sessions for a given agent.
    ///
    /// P0: Used to enforce per-agent concurrent session caps.
    pub async fn count_active_for_agent(&self, agent_id: uuid::Uuid) -> u64 {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| s.agent_id == agent_id && s.status == SessionStatus::Active)
            .count() as u64
    }

    /// Close all active sessions belonging to a specific agent.
    ///
    /// When an agent is deactivated via cascade_deactivate,
    /// all its sessions must be immediately closed.
    pub async fn close_sessions_for_agent(&self, agent_id: uuid::Uuid) -> usize {
        let mut sessions = self.sessions.write().await;
        let mut closed = 0usize;
        for session in sessions.values_mut() {
            if session.agent_id == agent_id && session.status == SessionStatus::Active {
                session.status = SessionStatus::Closed;
                closed += 1;
                tracing::info!(
                    session_id = %session.session_id,
                    agent_id = %agent_id,
                    "closed session due to agent deactivation"
                );
            }
        }
        closed
    }

    /// Remove expired sessions from the store. Returns the number removed.
    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        // Also clean up closed sessions, not just expired ones.
        // Previously, closed sessions accumulated indefinitely, growing the store without bound.
        sessions.retain(|_, s| {
            if s.is_expired() {
                tracing::debug!(session_id = %s.session_id, "cleaning up expired session");
                false
            } else if s.status == SessionStatus::Closed {
                tracing::debug!(session_id = %s.session_id, "cleaning up closed session");
                false
            } else {
                true
            }
        });
        let removed = before - sessions.len();
        if removed > 0 {
            tracing::info!(removed, "cleaned up expired/closed sessions");
        }
        removed
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_create_request() -> CreateSessionRequest {
        CreateSessionRequest {
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: "read and analyze files".into(),
            authorized_tools: vec!["read_file".into(), "list_dir".into()],
            time_limit: chrono::Duration::hours(1),
            call_budget: 5,
            rate_limit_per_minute: None,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: DataSensitivity::Internal,
        }
    }

    #[tokio::test]
    async fn create_and_use_session() {
        let store = SessionStore::new();
        let session = store.create(test_create_request()).await;

        assert_eq!(session.calls_made, 0);
        assert!(session.is_active());

        let updated = store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();
        assert_eq!(updated.calls_made, 1);
    }

    #[tokio::test]
    async fn budget_enforcement() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.call_budget = 2;
        let session = store.create(req).await;

        // Use up the budget.
        store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();
        store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();

        // Third call should fail.
        let result = store.use_session(session.session_id, "read_file").await;
        assert!(matches!(result, Err(SessionError::BudgetExceeded { .. })));
    }

    #[tokio::test]
    async fn tool_whitelist_enforcement() {
        let store = SessionStore::new();
        let session = store.create(test_create_request()).await;

        // Authorized tool works.
        store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();

        // Unauthorized tool is rejected.
        let result = store.use_session(session.session_id, "delete_file").await;
        assert!(matches!(
            result,
            Err(SessionError::ToolNotAuthorized { .. })
        ));
    }

    #[tokio::test]
    async fn session_expiry() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        // Set a very short time limit (zero duration = immediately expired on next check).
        req.time_limit = chrono::Duration::zero();
        let session = store.create(req).await;

        // The session was just created, but with zero duration it expires immediately.
        // We need the clock to advance at least slightly, which it does between create and use.
        // Use tokio::time::sleep to guarantee advancement.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let result = store.use_session(session.session_id, "read_file").await;
        assert!(matches!(result, Err(SessionError::Expired(_))));
    }

    #[tokio::test]
    async fn close_and_reuse() {
        let store = SessionStore::new();
        let session = store.create(test_create_request()).await;

        store.close(session.session_id).await.unwrap();

        let result = store.use_session(session.session_id, "read_file").await;
        assert!(matches!(result, Err(SessionError::AlreadyClosed(_))));
    }

    #[tokio::test]
    async fn cleanup_expired_sessions() {
        let store = SessionStore::new();

        // Create an already-expired session.
        let mut req = test_create_request();
        req.time_limit = chrono::Duration::zero();
        store.create(req).await;

        // Create a valid session.
        let valid_req = test_create_request();
        store.create(valid_req).await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let removed = store.cleanup_expired().await;
        assert_eq!(removed, 1);
    }

    #[tokio::test]
    async fn session_not_found() {
        let store = SessionStore::new();
        let fake_id = Uuid::new_v4();
        let result = store.use_session(fake_id, "anything").await;
        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }

    #[tokio::test]
    async fn rate_limit_enforcement() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.rate_limit_per_minute = Some(3);
        req.call_budget = 100; // high budget, rate limit should trigger first
        let session = store.create(req).await;

        // First 3 calls succeed (within rate limit).
        store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();
        store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();
        store
            .use_session(session.session_id, "read_file")
            .await
            .unwrap();

        // 4th call hits rate limit.
        let result = store.use_session(session.session_id, "read_file").await;
        assert!(
            matches!(result, Err(SessionError::RateLimited { .. })),
            "expected RateLimited, got {result:?}"
        );
    }

    #[tokio::test]
    async fn no_rate_limit_when_unset() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.rate_limit_per_minute = None;
        req.call_budget = 100;
        let session = store.create(req).await;

        // All calls succeed without rate limiting.
        for _ in 0..10 {
            store
                .use_session(session.session_id, "read_file")
                .await
                .unwrap();
        }
    }

    /// batch with one unauthorized tool must consume zero budget.
    #[tokio::test]
    async fn batch_validation_atomicity() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.call_budget = 10;
        req.authorized_tools = vec!["read_file".into(), "list_dir".into()];
        let session = store.create(req).await;

        // Batch contains one unauthorized tool ("delete_file").
        let result = store
            .use_session_batch(session.session_id, &["read_file", "delete_file"])
            .await;
        assert!(
            matches!(result, Err(SessionError::ToolNotAuthorized { .. })),
            "expected ToolNotAuthorized, got {result:?}"
        );

        // Budget must remain untouched.
        let s = store.get(session.session_id).await.unwrap();
        assert_eq!(s.calls_made, 0, "no budget should be consumed on batch failure");
    }

    #[tokio::test]
    async fn batch_budget_enforcement() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.call_budget = 3;
        req.authorized_tools = vec!["read_file".into()];
        let session = store.create(req).await;

        // Batch of 4 exceeds budget of 3.
        let result = store
            .use_session_batch(
                session.session_id,
                &["read_file", "read_file", "read_file", "read_file"],
            )
            .await;
        assert!(
            matches!(result, Err(SessionError::BudgetExceeded { .. })),
            "expected BudgetExceeded, got {result:?}"
        );

        // Budget must remain at 0.
        let s = store.get(session.session_id).await.unwrap();
        assert_eq!(s.calls_made, 0, "no budget should be consumed on batch failure");
    }

    #[tokio::test]
    async fn batch_rate_limit_enforcement() {
        let store = SessionStore::new();
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
            )
            .await;
        assert!(
            matches!(result, Err(SessionError::RateLimited { .. })),
            "expected RateLimited, got {result:?}"
        );
    }

    #[tokio::test]
    async fn empty_batch_succeeds() {
        let store = SessionStore::new();
        let session = store.create(test_create_request()).await;

        // Empty batch should succeed without consuming budget.
        let result = store
            .use_session_batch(session.session_id, &[])
            .await
            .unwrap();
        assert_eq!(result.calls_made, 0, "empty batch must not consume budget");
    }

    /// cleanup should also remove closed sessions.
    #[tokio::test]
    async fn cleanup_also_removes_closed() {
        let store = SessionStore::new();
        let session = store.create(test_create_request()).await;

        // Close it.
        store.close(session.session_id).await.unwrap();

        // Cleanup should remove the closed session.
        let removed = store.cleanup_expired().await;
        assert_eq!(removed, 1, "closed session should be cleaned up");

        // It should be gone.
        let result = store.get(session.session_id).await;
        assert!(
            matches!(result, Err(SessionError::NotFound(_))),
            "closed session should be removed after cleanup"
        );
    }

    /// A session created with call_budget=0 should immediately fail on use.
    #[tokio::test]
    async fn zero_budget_session() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.call_budget = 0;
        let session = store.create(req).await;

        let result = store.use_session(session.session_id, "read_file").await;
        assert!(
            matches!(result, Err(SessionError::BudgetExceeded { .. })),
            "zero-budget session must reject the first call, got {result:?}"
        );
    }

    /// Agent deactivation must close all agent sessions.
    #[tokio::test]
    async fn deactivation_closes_agent_sessions() {
        let store = SessionStore::new();
        let agent_id = Uuid::new_v4();
        let other_agent = Uuid::new_v4();

        for _ in 0..3 {
            let mut req = test_create_request();
            req.agent_id = agent_id;
            store.create(req).await;
        }
        let mut other_req = test_create_request();
        other_req.agent_id = other_agent;
        let other_session = store.create(other_req).await;

        let closed = store.close_sessions_for_agent(agent_id).await;
        assert_eq!(closed, 3);

        let all = store.list_all().await;
        for s in &all {
            if s.agent_id == agent_id {
                assert_eq!(s.status, SessionStatus::Closed);
            }
        }
        let other = store.get(other_session.session_id).await.unwrap();
        assert_eq!(other.status, SessionStatus::Active);
    }

    /// Concurrent budget enforcement.
    /// Spawn 10 tasks each calling use_session once on a session with budget=5.
    /// Exactly 5 must succeed and 5 must fail with BudgetExceeded.
    #[tokio::test]
    async fn concurrent_budget_enforcement() {
        let store = SessionStore::new();
        let mut req = test_create_request();
        req.call_budget = 5;
        req.authorized_tools = vec!["read_file".into()];
        let session = store.create(req).await;

        let successes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let failures = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let store = store.clone();
            let sid = session.session_id;
            let s = successes.clone();
            let f = failures.clone();
            handles.push(tokio::spawn(async move {
                match store.use_session(sid, "read_file").await {
                    Ok(_) => {
                        s.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(SessionError::BudgetExceeded { .. }) => {
                        f.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => panic!("unexpected error: {e:?}"),
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            successes.load(std::sync::atomic::Ordering::Relaxed),
            5,
            "exactly 5 calls should succeed"
        );
        assert_eq!(
            failures.load(std::sync::atomic::Ordering::Relaxed),
            5,
            "exactly 5 calls should fail with BudgetExceeded"
        );
    }
}
