//! SQLite storage backend with WAL mode and auto-migration.
//!
//! REQ-001: State survives process restart with WAL-mode consistency.
//! Design decision: Persistence depth vs request latency. SQLite with WAL mode
//!        provides durable writes with minimal latency overhead.

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::str::FromStr;
use uuid::Uuid;

use crate::encryption::FieldEncryptor;
use crate::error::StorageError;
use crate::traits::*;

/// SQLite storage backend.
///
/// Uses a connection pool with WAL mode for concurrent read access
/// and durable writes. Migrations are run automatically on first connection.
#[derive(Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
    /// Optional field-level encryptor for sensitive session columns.
    /// When `None`, data is stored in plaintext (backward compatible).
    encryptor: Option<FieldEncryptor>,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend at the given path.
    ///
    /// - Enables WAL journal mode for concurrent readers.
    /// - Runs embedded migrations automatically.
    /// - Creates the database file if it doesn't exist.
    pub async fn new(database_url: &str) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| StorageError::Connection(e.to_string()))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| StorageError::Connection(e.to_string()))?;

        // Run embedded migrations.
        sqlx::migrate!("./migrations").run(&pool).await?;

        tracing::info!(database_url, "sqlite storage initialized with WAL mode");

        Ok(Self {
            pool,
            encryptor: None,
        })
    }

    /// Set the field-level encryptor for sensitive session columns.
    ///
    /// When set, `delegation_chain_snapshot`, `declared_intent`, and
    /// `authorized_tools` are encrypted before being written to SQLite
    /// and decrypted after being read.
    pub fn with_encryptor(mut self, encryptor: FieldEncryptor) -> Self {
        self.encryptor = Some(encryptor);
        self
    }

    /// Set an optional field-level encryptor.
    pub fn with_optional_encryptor(mut self, encryptor: Option<FieldEncryptor>) -> Self {
        self.encryptor = encryptor;
        self
    }

    /// Get a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Close the connection pool gracefully.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    // ── Private encryption helpers ─────────────────────────────────

    /// Encrypt a string field if an encryptor is configured, otherwise pass through.
    fn encrypt_field(&self, plaintext: &str) -> Result<String, StorageError> {
        match &self.encryptor {
            Some(enc) => Ok(enc.encrypt_field(plaintext)?),
            None => Ok(plaintext.to_string()),
        }
    }

    /// Encrypt a `Vec<String>` field (JSON-serialize + encrypt), or plain JSON-serialize.
    fn encrypt_string_vec(&self, values: &[String]) -> Result<String, StorageError> {
        match &self.encryptor {
            Some(enc) => Ok(enc.encrypt_string_vec(values)?),
            None => Ok(serde_json::to_string(values)?),
        }
    }

}

// ── AgentStore implementation ───────────────────────────────────────

#[async_trait]
impl AgentStore for SqliteStorage {
    async fn insert_agent(&self, agent: &StoredAgent) -> Result<(), StorageError> {
        let id = agent.id.to_string();
        let capabilities = serde_json::to_string(&agent.capabilities)?;
        let trust_level = agent.trust_level.to_string();
        let created_at = agent.created_at.to_rfc3339();
        let expires_at = agent.expires_at.map(|e| e.to_rfc3339());
        let active = agent.active as i32;

        sqlx::query(
            "INSERT INTO agents (id, owner, model, capabilities, trust_level, created_at, expires_at, active)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(&agent.owner)
        .bind(&agent.model)
        .bind(&capabilities)
        .bind(&trust_level)
        .bind(&created_at)
        .bind(&expires_at)
        .bind(active)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_agent(&self, id: Uuid) -> Result<StoredAgent, StorageError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM agents WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::AgentNotFound(id))?;

        row_to_agent(&row)
    }

    async fn update_trust_level(
        &self,
        id: Uuid,
        level: StoredTrustLevel,
    ) -> Result<(), StorageError> {
        let id_str = id.to_string();
        let level_str = level.to_string();

        let result = sqlx::query("UPDATE agents SET trust_level = ? WHERE id = ?")
            .bind(&level_str)
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(StorageError::AgentNotFound(id));
        }
        Ok(())
    }

    async fn deactivate_agent(&self, id: Uuid) -> Result<(), StorageError> {
        let id_str = id.to_string();

        let result = sqlx::query("UPDATE agents SET active = 0 WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(StorageError::AgentNotFound(id));
        }
        Ok(())
    }

    async fn list_agents(&self) -> Result<Vec<StoredAgent>, StorageError> {
        let rows = sqlx::query("SELECT * FROM agents")
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_agent).collect()
    }
}

// ── SessionStore implementation ─────────────────────────────────────

#[async_trait]
impl SessionStore for SqliteStorage {
    async fn insert_session(&self, session: &StoredSession) -> Result<(), StorageError> {
        let session_id = session.session_id.to_string();
        let agent_id = session.agent_id.to_string();
        let delegation_chain =
            self.encrypt_string_vec(&session.delegation_chain_snapshot)?;
        let declared_intent = self.encrypt_field(&session.declared_intent)?;
        let authorized_tools =
            self.encrypt_string_vec(&session.authorized_tools)?;
        let rate_limit_per_minute = session.rate_limit_per_minute.map(|v| v as i64);
        let rate_window_start = session.rate_window_start.to_rfc3339();
        let data_sensitivity = session.data_sensitivity_ceiling.to_string();
        let created_at = session.created_at.to_rfc3339();
        let status = session.status.to_string();

        sqlx::query(
            "INSERT INTO sessions (
                session_id, agent_id, delegation_chain_snapshot, declared_intent,
                authorized_tools, time_limit_secs, call_budget, calls_made,
                rate_limit_per_minute, rate_window_start, rate_window_calls,
                rate_limit_window_secs, data_sensitivity_ceiling, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session_id)
        .bind(&agent_id)
        .bind(&delegation_chain)
        .bind(&declared_intent)
        .bind(&authorized_tools)
        .bind(session.time_limit_secs)
        .bind(session.call_budget as i64)
        .bind(session.calls_made as i64)
        .bind(rate_limit_per_minute)
        .bind(&rate_window_start)
        .bind(session.rate_window_calls as i64)
        .bind(session.rate_limit_window_secs as i64)
        .bind(&data_sensitivity)
        .bind(&created_at)
        .bind(&status)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_session(&self, session_id: Uuid) -> Result<StoredSession, StorageError> {
        let id_str = session_id.to_string();
        let row = sqlx::query("SELECT * FROM sessions WHERE session_id = ?")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::SessionNotFound(session_id))?;

        row_to_session(&row, self.encryptor.as_ref())
    }

    async fn update_session(&self, session: &StoredSession) -> Result<(), StorageError> {
        let session_id = session.session_id.to_string();
        let delegation_chain =
            self.encrypt_string_vec(&session.delegation_chain_snapshot)?;
        let declared_intent = self.encrypt_field(&session.declared_intent)?;
        let authorized_tools =
            self.encrypt_string_vec(&session.authorized_tools)?;
        let rate_limit_per_minute = session.rate_limit_per_minute.map(|v| v as i64);
        let rate_window_start = session.rate_window_start.to_rfc3339();
        let data_sensitivity = session.data_sensitivity_ceiling.to_string();
        let created_at = session.created_at.to_rfc3339();
        let status = session.status.to_string();

        let result = sqlx::query(
            "UPDATE sessions SET
                agent_id = ?, delegation_chain_snapshot = ?, declared_intent = ?,
                authorized_tools = ?, time_limit_secs = ?, call_budget = ?,
                calls_made = ?, rate_limit_per_minute = ?, rate_window_start = ?,
                rate_window_calls = ?, rate_limit_window_secs = ?,
                data_sensitivity_ceiling = ?, created_at = ?, status = ?
            WHERE session_id = ?",
        )
        .bind(session.agent_id.to_string())
        .bind(&delegation_chain)
        .bind(&declared_intent)
        .bind(&authorized_tools)
        .bind(session.time_limit_secs)
        .bind(session.call_budget as i64)
        .bind(session.calls_made as i64)
        .bind(rate_limit_per_minute)
        .bind(&rate_window_start)
        .bind(session.rate_window_calls as i64)
        .bind(session.rate_limit_window_secs as i64)
        .bind(&data_sensitivity)
        .bind(&created_at)
        .bind(&status)
        .bind(&session_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(StorageError::SessionNotFound(session.session_id));
        }
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> Result<usize, StorageError> {
        // Delete sessions whose created_at + time_limit_secs is in the past,
        // or whose status is already 'expired'.
        let result = sqlx::query(
            "DELETE FROM sessions WHERE status = 'expired'
             OR (status = 'active' AND
                 datetime(created_at, '+' || time_limit_secs || ' seconds') < datetime('now'))",
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    async fn list_sessions(&self) -> Result<Vec<StoredSession>, StorageError> {
        let rows = sqlx::query("SELECT * FROM sessions")
            .fetch_all(&self.pool)
            .await?;

        rows.iter()
            .map(|row| row_to_session(row, self.encryptor.as_ref()))
            .collect()
    }
}

// ── DelegationStore implementation ──────────────────────────────────

#[async_trait]
impl DelegationStore for SqliteStorage {
    async fn insert_delegation(&self, link: &StoredDelegationLink) -> Result<i64, StorageError> {
        let from_agent = link.from_agent.to_string();
        let to_agent = link.to_agent.to_string();
        let scope_narrowing = serde_json::to_string(&link.scope_narrowing)?;
        let created_at = link.created_at.to_rfc3339();
        let expires_at = link.expires_at.map(|e| e.to_rfc3339());

        let result = sqlx::query(
            "INSERT INTO delegation_links (from_agent, to_agent, scope_narrowing, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&from_agent)
        .bind(&to_agent)
        .bind(&scope_narrowing)
        .bind(&created_at)
        .bind(&expires_at)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    async fn get_delegations_from(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<StoredDelegationLink>, StorageError> {
        let id_str = agent_id.to_string();
        let rows = sqlx::query("SELECT * FROM delegation_links WHERE from_agent = ?")
            .bind(&id_str)
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_delegation).collect()
    }

    async fn get_delegations_to(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<StoredDelegationLink>, StorageError> {
        let id_str = agent_id.to_string();
        let rows = sqlx::query("SELECT * FROM delegation_links WHERE to_agent = ?")
            .bind(&id_str)
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_delegation).collect()
    }

    async fn list_delegations(&self) -> Result<Vec<StoredDelegationLink>, StorageError> {
        let rows = sqlx::query("SELECT * FROM delegation_links")
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_delegation).collect()
    }
}

// ── Row conversion helpers ──────────────────────────────────────────

fn row_to_agent(row: &sqlx::sqlite::SqliteRow) -> Result<StoredAgent, StorageError> {
    let id_str: String = row.get("id");
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| StorageError::Serialization(format!("invalid agent UUID: {e}")))?;

    let capabilities_json: String = row.get("capabilities");
    let capabilities: Vec<String> = serde_json::from_str(&capabilities_json)?;

    let trust_level_str: String = row.get("trust_level");
    let trust_level = StoredTrustLevel::from_str(&trust_level_str)?;

    let created_at_str: String = row.get("created_at");
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| StorageError::Serialization(format!("invalid created_at: {e}")))?
        .with_timezone(&chrono::Utc);

    let expires_at: Option<chrono::DateTime<chrono::Utc>> = {
        let val: Option<String> = row.get("expires_at");
        val.map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| StorageError::Serialization(format!("invalid expires_at: {e}")))
        })
        .transpose()?
    };

    let active_int: i32 = row.get("active");

    Ok(StoredAgent {
        id,
        owner: row.get("owner"),
        model: row.get("model"),
        capabilities,
        trust_level,
        created_at,
        expires_at,
        active: active_int != 0,
    })
}

fn row_to_session(
    row: &sqlx::sqlite::SqliteRow,
    encryptor: Option<&FieldEncryptor>,
) -> Result<StoredSession, StorageError> {
    let session_id_str: String = row.get("session_id");
    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|e| StorageError::Serialization(format!("invalid session UUID: {e}")))?;

    let agent_id_str: String = row.get("agent_id");
    let agent_id = Uuid::parse_str(&agent_id_str)
        .map_err(|e| StorageError::Serialization(format!("invalid agent UUID: {e}")))?;

    // Sensitive field: delegation_chain_snapshot (Vec<String>)
    let delegation_raw: String = row.get("delegation_chain_snapshot");
    let delegation_chain_snapshot: Vec<String> = match encryptor {
        Some(enc) => enc.decrypt_string_vec(&delegation_raw)?,
        None => serde_json::from_str(&delegation_raw)?,
    };

    // Sensitive field: declared_intent (String)
    let intent_raw: String = row.get("declared_intent");
    let declared_intent: String = match encryptor {
        Some(enc) => enc.decrypt_field(&intent_raw)?,
        None => intent_raw,
    };

    // Sensitive field: authorized_tools (Vec<String>)
    let tools_raw: String = row.get("authorized_tools");
    let authorized_tools: Vec<String> = match encryptor {
        Some(enc) => enc.decrypt_string_vec(&tools_raw)?,
        None => serde_json::from_str(&tools_raw)?,
    };

    let rate_limit_per_minute: Option<i64> = row.get("rate_limit_per_minute");

    let rate_window_start_str: String = row.get("rate_window_start");
    let rate_window_start = chrono::DateTime::parse_from_rfc3339(&rate_window_start_str)
        .map_err(|e| StorageError::Serialization(format!("invalid rate_window_start: {e}")))?
        .with_timezone(&chrono::Utc);

    let data_sensitivity_str: String = row.get("data_sensitivity_ceiling");
    let data_sensitivity_ceiling = StoredDataSensitivity::from_str(&data_sensitivity_str)?;

    let created_at_str: String = row.get("created_at");
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| StorageError::Serialization(format!("invalid created_at: {e}")))?
        .with_timezone(&chrono::Utc);

    let status_str: String = row.get("status");
    let status = StoredSessionStatus::from_str(&status_str)?;

    let time_limit_secs: i64 = row.get("time_limit_secs");
    let call_budget: i64 = row.get("call_budget");
    let calls_made: i64 = row.get("calls_made");
    let rate_window_calls: i64 = row.get("rate_window_calls");
    let rate_limit_window_secs: i64 = row.get("rate_limit_window_secs");

    Ok(StoredSession {
        session_id,
        agent_id,
        delegation_chain_snapshot,
        declared_intent,
        authorized_tools,
        time_limit_secs,
        call_budget: call_budget as u64,
        calls_made: calls_made as u64,
        rate_limit_per_minute: rate_limit_per_minute.map(|v| v as u64),
        rate_window_start,
        rate_window_calls: rate_window_calls as u64,
        rate_limit_window_secs: rate_limit_window_secs as u64,
        data_sensitivity_ceiling,
        created_at,
        status,
    })
}

fn row_to_delegation(row: &sqlx::sqlite::SqliteRow) -> Result<StoredDelegationLink, StorageError> {
    let id: i64 = row.get("id");

    let from_str: String = row.get("from_agent");
    let from_agent = Uuid::parse_str(&from_str)
        .map_err(|e| StorageError::Serialization(format!("invalid from_agent UUID: {e}")))?;

    let to_str: String = row.get("to_agent");
    let to_agent = Uuid::parse_str(&to_str)
        .map_err(|e| StorageError::Serialization(format!("invalid to_agent UUID: {e}")))?;

    let scope_json: String = row.get("scope_narrowing");
    let scope_narrowing: Vec<String> = serde_json::from_str(&scope_json)?;

    let created_at_str: String = row.get("created_at");
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| StorageError::Serialization(format!("invalid created_at: {e}")))?
        .with_timezone(&chrono::Utc);

    let expires_at: Option<chrono::DateTime<chrono::Utc>> = {
        let val: Option<String> = row.get("expires_at");
        val.map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| StorageError::Serialization(format!("invalid expires_at: {e}")))
        })
        .transpose()?
    };

    Ok(StoredDelegationLink {
        id,
        from_agent,
        to_agent,
        scope_narrowing,
        created_at,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    async fn test_storage() -> SqliteStorage {
        // Use in-memory SQLite for tests; each call gets a fresh database.
        SqliteStorage::new("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn agent_crud() {
        let storage = test_storage().await;

        let agent = StoredAgent {
            id: Uuid::new_v4(),
            owner: "user:alice".into(),
            model: "claude-opus-4-6".into(),
            capabilities: vec!["read".into(), "write".into()],
            trust_level: StoredTrustLevel::Basic,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        };

        storage.insert_agent(&agent).await.unwrap();

        let fetched = storage.get_agent(agent.id).await.unwrap();
        assert_eq!(fetched.owner, "user:alice");
        assert_eq!(fetched.model, "claude-opus-4-6");
        assert_eq!(fetched.capabilities, vec!["read", "write"]);
        assert_eq!(fetched.trust_level, StoredTrustLevel::Basic);
        assert!(fetched.active);

        // Update trust level.
        storage
            .update_trust_level(agent.id, StoredTrustLevel::Verified)
            .await
            .unwrap();
        let updated = storage.get_agent(agent.id).await.unwrap();
        assert_eq!(updated.trust_level, StoredTrustLevel::Verified);

        // Deactivate.
        storage.deactivate_agent(agent.id).await.unwrap();
        let deactivated = storage.get_agent(agent.id).await.unwrap();
        assert!(!deactivated.active);
    }

    #[tokio::test]
    async fn agent_not_found() {
        let storage = test_storage().await;
        let result = storage.get_agent(Uuid::new_v4()).await;
        assert!(matches!(result, Err(StorageError::AgentNotFound(_))));
    }

    #[tokio::test]
    async fn list_agents() {
        let storage = test_storage().await;

        for i in 0..3 {
            let agent = StoredAgent {
                id: Uuid::new_v4(),
                owner: format!("user:{i}"),
                model: "test-model".into(),
                capabilities: vec![],
                trust_level: StoredTrustLevel::Basic,
                created_at: Utc::now(),
                expires_at: None,
                active: true,
            };
            storage.insert_agent(&agent).await.unwrap();
        }

        let agents = storage.list_agents().await.unwrap();
        assert_eq!(agents.len(), 3);
    }

    #[tokio::test]
    async fn session_crud() {
        let storage = test_storage().await;

        let session = StoredSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec!["chain-link-1".into()],
            declared_intent: "read and analyze files".into(),
            authorized_tools: vec!["read_file".into(), "list_dir".into()],
            time_limit_secs: 3600,
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: Some(10),
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: StoredDataSensitivity::Internal,
            created_at: Utc::now(),
            status: StoredSessionStatus::Active,
        };

        storage.insert_session(&session).await.unwrap();

        let fetched = storage.get_session(session.session_id).await.unwrap();
        assert_eq!(fetched.declared_intent, "read and analyze files");
        assert_eq!(fetched.authorized_tools, vec!["read_file", "list_dir"]);
        assert_eq!(fetched.call_budget, 100);
        assert_eq!(fetched.status, StoredSessionStatus::Active);

        // Update session (increment calls_made).
        let mut updated = fetched;
        updated.calls_made = 5;
        updated.status = StoredSessionStatus::Closed;
        storage.update_session(&updated).await.unwrap();

        let refetched = storage.get_session(session.session_id).await.unwrap();
        assert_eq!(refetched.calls_made, 5);
        assert_eq!(refetched.status, StoredSessionStatus::Closed);
    }

    #[tokio::test]
    async fn session_not_found() {
        let storage = test_storage().await;
        let result = storage.get_session(Uuid::new_v4()).await;
        assert!(matches!(result, Err(StorageError::SessionNotFound(_))));
    }

    #[tokio::test]
    async fn delegation_crud() {
        let storage = test_storage().await;

        let from_id = Uuid::new_v4();
        let to_id = Uuid::new_v4();

        let link = StoredDelegationLink {
            id: 0, // auto-generated
            from_agent: from_id,
            to_agent: to_id,
            scope_narrowing: vec!["read".into()],
            created_at: Utc::now(),
            expires_at: None,
        };

        let id = storage.insert_delegation(&link).await.unwrap();
        assert!(id > 0);

        let from_links = storage.get_delegations_from(from_id).await.unwrap();
        assert_eq!(from_links.len(), 1);
        assert_eq!(from_links[0].to_agent, to_id);

        let to_links = storage.get_delegations_to(to_id).await.unwrap();
        assert_eq!(to_links.len(), 1);
        assert_eq!(to_links[0].from_agent, from_id);

        let all = storage.list_delegations().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn agent_with_expiry() {
        let storage = test_storage().await;

        let expires = Utc::now() + chrono::Duration::hours(1);
        let agent = StoredAgent {
            id: Uuid::new_v4(),
            owner: "user:expiry-test".into(),
            model: "test-model".into(),
            capabilities: vec!["admin".into()],
            trust_level: StoredTrustLevel::Trusted,
            created_at: Utc::now(),
            expires_at: Some(expires),
            active: true,
        };

        storage.insert_agent(&agent).await.unwrap();
        let fetched = storage.get_agent(agent.id).await.unwrap();
        assert!(fetched.expires_at.is_some());
    }

    /// Agent metadata with SQL injection payloads stores and retrieves
    /// correctly because sqlx uses parameterized queries.
    #[tokio::test]
    async fn agent_metadata_with_special_chars() {
        let storage = test_storage().await;

        let malicious_capabilities = vec![
            "read'; DROP TABLE agents; --".to_string(),
            r#"write" OR "1"="1"#.to_string(),
            "normal_cap".to_string(),
            "cap with\nnewline".to_string(),
            "cap with\ttab".to_string(),
            r#"{"nested": "json", "key": "value"}"#.to_string(),
        ];

        let agent = StoredAgent {
            id: Uuid::new_v4(),
            owner: "user:injection-test".into(),
            model: "test-model".into(),
            capabilities: malicious_capabilities.clone(),
            trust_level: StoredTrustLevel::Basic,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        };

        storage.insert_agent(&agent).await.unwrap();

        // Verify the agent table still exists and the data is intact
        let fetched = storage.get_agent(agent.id).await.unwrap();
        assert_eq!(fetched.capabilities, malicious_capabilities);
        assert_eq!(fetched.owner, "user:injection-test");

        // Verify listing still works (table was not dropped)
        let all = storage.list_agents().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    /// Session with a very large declared_intent stores and retrieves
    /// correctly, stress-testing row conversion with large data.
    #[tokio::test]
    async fn session_with_large_metadata() {
        let storage = test_storage().await;

        let large_intent = "x".repeat(10_000);

        let session = StoredSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: large_intent.clone(),
            authorized_tools: vec!["read_file".into()],
            time_limit_secs: 3600,
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: None,
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: StoredDataSensitivity::Internal,
            created_at: Utc::now(),
            status: StoredSessionStatus::Active,
        };

        storage.insert_session(&session).await.unwrap();

        let fetched = storage.get_session(session.session_id).await.unwrap();
        assert_eq!(fetched.declared_intent.len(), 10_000);
        assert_eq!(fetched.declared_intent, large_intent);
    }

    /// Concurrent session updates should not panic. SQLite WAL mode
    /// handles write contention via busy/retry semantics.
    #[tokio::test]
    async fn concurrent_session_updates() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("concurrent-test.db");
        let db_url = format!("sqlite:{}", db_path.display());
        let storage = SqliteStorage::new(&db_url).await.unwrap();

        let session_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        let session = StoredSession {
            session_id,
            agent_id,
            delegation_chain_snapshot: vec![],
            declared_intent: "concurrent test".into(),
            authorized_tools: vec!["read_file".into()],
            time_limit_secs: 3600,
            call_budget: 1000,
            calls_made: 0,
            rate_limit_per_minute: Some(100),
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: StoredDataSensitivity::Internal,
            created_at: Utc::now(),
            status: StoredSessionStatus::Active,
        };

        storage.insert_session(&session).await.unwrap();

        let mut handles = Vec::new();
        for i in 0u64..5 {
            let s = storage.clone();
            let mut sess = session.clone();
            handles.push(tokio::spawn(async move {
                sess.calls_made = i * 10;
                s.update_session(&sess).await
            }));
        }

        // All tasks should complete without panic
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok(), "task should not panic");
            // The update itself may succeed or fail due to contention,
            // but it must not panic.
        }

        // Verify the session is still retrievable
        let final_session = storage.get_session(session_id).await.unwrap();
        assert_eq!(final_session.session_id, session_id);

        storage.close().await;
    }

    fn test_encryption_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        key
    }

    async fn test_storage_encrypted() -> SqliteStorage {
        let key = test_encryption_key();
        let encryptor = FieldEncryptor::new(&key);
        SqliteStorage::new("sqlite::memory:")
            .await
            .unwrap()
            .with_encryptor(encryptor)
    }

    /// Session CRUD works identically when encryption is enabled.
    #[tokio::test]
    async fn encrypted_session_crud() {
        let storage = test_storage_encrypted().await;

        let session = StoredSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec!["chain-link-1".into(), "chain-link-2".into()],
            declared_intent: "read and analyze confidential files".into(),
            authorized_tools: vec!["read_file".into(), "list_dir".into()],
            time_limit_secs: 3600,
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: Some(10),
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: StoredDataSensitivity::Confidential,
            created_at: Utc::now(),
            status: StoredSessionStatus::Active,
        };

        storage.insert_session(&session).await.unwrap();

        let fetched = storage.get_session(session.session_id).await.unwrap();
        assert_eq!(fetched.declared_intent, "read and analyze confidential files");
        assert_eq!(fetched.delegation_chain_snapshot, vec!["chain-link-1", "chain-link-2"]);
        assert_eq!(fetched.authorized_tools, vec!["read_file", "list_dir"]);
        assert_eq!(fetched.call_budget, 100);

        // Update session with encryption.
        let mut updated = fetched;
        updated.calls_made = 7;
        updated.declared_intent = "updated intent after re-scoping".into();
        updated.status = StoredSessionStatus::Closed;
        storage.update_session(&updated).await.unwrap();

        let refetched = storage.get_session(session.session_id).await.unwrap();
        assert_eq!(refetched.calls_made, 7);
        assert_eq!(refetched.declared_intent, "updated intent after re-scoping");
        assert_eq!(refetched.status, StoredSessionStatus::Closed);
    }

    /// Encrypted data on disk does not contain plaintext sensitive fields.
    #[tokio::test]
    async fn encrypted_fields_not_readable_as_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("encryption-test.db");
        let db_url = format!("sqlite:{}", db_path.display());

        let key = test_encryption_key();
        let encryptor = FieldEncryptor::new(&key);
        let storage = SqliteStorage::new(&db_url)
            .await
            .unwrap()
            .with_encryptor(encryptor);

        let secret_intent = "steal all production database credentials";
        let secret_tools = vec!["admin_shell".to_string(), "exfiltrate_data".to_string()];
        let secret_chain = vec!["root-agent-uuid-here".to_string()];

        let session = StoredSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: secret_chain.clone(),
            declared_intent: secret_intent.into(),
            authorized_tools: secret_tools.clone(),
            time_limit_secs: 3600,
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: None,
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: StoredDataSensitivity::Restricted,
            created_at: Utc::now(),
            status: StoredSessionStatus::Active,
        };

        storage.insert_session(&session).await.unwrap();
        storage.close().await;

        // Read the raw database file and verify plaintext is absent.
        let raw_bytes = std::fs::read(&db_path).unwrap();
        let raw_str = String::from_utf8_lossy(&raw_bytes);

        assert!(
            !raw_str.contains(secret_intent),
            "raw database must not contain plaintext declared_intent"
        );
        assert!(
            !raw_str.contains("admin_shell"),
            "raw database must not contain plaintext authorized_tools"
        );
        assert!(
            !raw_str.contains("exfiltrate_data"),
            "raw database must not contain plaintext authorized_tools"
        );
        assert!(
            !raw_str.contains("root-agent-uuid-here"),
            "raw database must not contain plaintext delegation_chain_snapshot"
        );
    }

    /// Encrypted session data survives storage restart with same key.
    #[tokio::test]
    async fn encrypted_state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("encrypted-restart.db");
        let db_url = format!("sqlite:{}", db_path.display());

        let key = test_encryption_key();
        let session_id = Uuid::new_v4();

        // Phase 1: Write encrypted session.
        {
            let encryptor = FieldEncryptor::new(&key);
            let storage = SqliteStorage::new(&db_url)
                .await
                .unwrap()
                .with_encryptor(encryptor);

            storage
                .insert_session(&StoredSession {
                    session_id,
                    agent_id: Uuid::new_v4(),
                    delegation_chain_snapshot: vec!["link-a".into()],
                    declared_intent: "persist-through-restart".into(),
                    authorized_tools: vec!["tool_x".into()],
                    time_limit_secs: 3600,
                    call_budget: 50,
                    calls_made: 3,
                    rate_limit_per_minute: None,
                    rate_window_start: Utc::now(),
                    rate_window_calls: 0,
                    rate_limit_window_secs: 60,
                    data_sensitivity_ceiling: StoredDataSensitivity::Internal,
                    created_at: Utc::now(),
                    status: StoredSessionStatus::Active,
                })
                .await
                .unwrap();

            storage.close().await;
        }

        // Phase 2: Re-open with same key, verify data.
        {
            let encryptor = FieldEncryptor::new(&key);
            let storage = SqliteStorage::new(&db_url)
                .await
                .unwrap()
                .with_encryptor(encryptor);

            let session = storage.get_session(session_id).await.unwrap();
            assert_eq!(session.declared_intent, "persist-through-restart");
            assert_eq!(session.delegation_chain_snapshot, vec!["link-a"]);
            assert_eq!(session.authorized_tools, vec!["tool_x"]);
            assert_eq!(session.calls_made, 3);

            storage.close().await;
        }
    }

    /// REQ-001 evidence: state survives across storage handle drop/recreate.
    #[tokio::test]
    async fn state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test-restart.db");
        let db_url = format!("sqlite:{}", db_path.display());

        let agent_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let from_id = Uuid::new_v4();
        let to_id = Uuid::new_v4();

        // Phase 1: Create state.
        {
            let storage = SqliteStorage::new(&db_url).await.unwrap();

            storage
                .insert_agent(&StoredAgent {
                    id: agent_id,
                    owner: "user:restart-test".into(),
                    model: "test-model".into(),
                    capabilities: vec!["read".into()],
                    trust_level: StoredTrustLevel::Verified,
                    created_at: Utc::now(),
                    expires_at: None,
                    active: true,
                })
                .await
                .unwrap();

            storage
                .insert_session(&StoredSession {
                    session_id,
                    agent_id,
                    delegation_chain_snapshot: vec![],
                    declared_intent: "restart test".into(),
                    authorized_tools: vec!["read_file".into()],
                    time_limit_secs: 3600,
                    call_budget: 50,
                    calls_made: 10,
                    rate_limit_per_minute: None,
                    rate_window_start: Utc::now(),
                    rate_window_calls: 0,
                    rate_limit_window_secs: 60,
                    data_sensitivity_ceiling: StoredDataSensitivity::Internal,
                    created_at: Utc::now(),
                    status: StoredSessionStatus::Active,
                })
                .await
                .unwrap();

            storage
                .insert_delegation(&StoredDelegationLink {
                    id: 0,
                    from_agent: from_id,
                    to_agent: to_id,
                    scope_narrowing: vec!["read".into()],
                    created_at: Utc::now(),
                    expires_at: None,
                })
                .await
                .unwrap();

            // Drop storage, simulating process restart.
            storage.close().await;
        }

        // Phase 2: Recreate from same file. Verify all state is present.
        {
            let storage = SqliteStorage::new(&db_url).await.unwrap();

            let agent = storage.get_agent(agent_id).await.unwrap();
            assert_eq!(agent.owner, "user:restart-test");
            assert_eq!(agent.trust_level, StoredTrustLevel::Verified);
            assert!(agent.active);

            let session = storage.get_session(session_id).await.unwrap();
            assert_eq!(session.declared_intent, "restart test");
            assert_eq!(session.calls_made, 10);
            assert_eq!(session.call_budget, 50);

            let delegations = storage.get_delegations_from(from_id).await.unwrap();
            assert_eq!(delegations.len(), 1);
            assert_eq!(delegations[0].to_agent, to_id);

            storage.close().await;
        }
    }
}
