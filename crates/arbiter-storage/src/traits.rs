//! Async storage traits for Arbiter state persistence.
//!
//! These traits define the contract for storing agents, sessions, and
//! delegation links. Implementations can back these with in-memory
//! storage, SQLite, PostgreSQL, or any other backend.
//!
//! REQ-007: Storage behind async trait; swappable backends.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::StorageError;

// ── Agent storage types ─────────────────────────────────────────────

/// Trust level assigned to an agent, determining its permissions.
/// Mirrors arbiter_identity::TrustLevel but lives in the storage layer
/// to avoid circular dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoredTrustLevel {
    Untrusted,
    Basic,
    Verified,
    Trusted,
}

impl std::fmt::Display for StoredTrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoredTrustLevel::Untrusted => write!(f, "untrusted"),
            StoredTrustLevel::Basic => write!(f, "basic"),
            StoredTrustLevel::Verified => write!(f, "verified"),
            StoredTrustLevel::Trusted => write!(f, "trusted"),
        }
    }
}

impl std::str::FromStr for StoredTrustLevel {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "untrusted" => Ok(StoredTrustLevel::Untrusted),
            "basic" => Ok(StoredTrustLevel::Basic),
            "verified" => Ok(StoredTrustLevel::Verified),
            "trusted" => Ok(StoredTrustLevel::Trusted),
            _ => Err(StorageError::Serialization(format!(
                "unknown trust level: {s}"
            ))),
        }
    }
}

/// A stored agent record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredAgent {
    pub id: Uuid,
    pub owner: String,
    pub model: String,
    pub capabilities: Vec<String>,
    pub trust_level: StoredTrustLevel,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

/// A stored delegation link.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredDelegationLink {
    pub id: i64,
    pub from_agent: Uuid,
    pub to_agent: Uuid,
    pub scope_narrowing: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ── Session storage types ───────────────────────────────────────────

/// Stored session status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoredSessionStatus {
    Active,
    Closed,
    Expired,
}

impl std::fmt::Display for StoredSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoredSessionStatus::Active => write!(f, "active"),
            StoredSessionStatus::Closed => write!(f, "closed"),
            StoredSessionStatus::Expired => write!(f, "expired"),
        }
    }
}

impl std::str::FromStr for StoredSessionStatus {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(StoredSessionStatus::Active),
            "closed" => Ok(StoredSessionStatus::Closed),
            "expired" => Ok(StoredSessionStatus::Expired),
            _ => Err(StorageError::Serialization(format!(
                "unknown session status: {s}"
            ))),
        }
    }
}

/// Stored data sensitivity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoredDataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl std::fmt::Display for StoredDataSensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoredDataSensitivity::Public => write!(f, "public"),
            StoredDataSensitivity::Internal => write!(f, "internal"),
            StoredDataSensitivity::Confidential => write!(f, "confidential"),
            StoredDataSensitivity::Restricted => write!(f, "restricted"),
        }
    }
}

impl std::str::FromStr for StoredDataSensitivity {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "public" => Ok(StoredDataSensitivity::Public),
            "internal" => Ok(StoredDataSensitivity::Internal),
            "confidential" => Ok(StoredDataSensitivity::Confidential),
            "restricted" => Ok(StoredDataSensitivity::Restricted),
            _ => Err(StorageError::Serialization(format!(
                "unknown data sensitivity: {s}"
            ))),
        }
    }
}

/// A stored task session record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredSession {
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub delegation_chain_snapshot: Vec<String>,
    pub declared_intent: String,
    pub authorized_tools: Vec<String>,
    pub time_limit_secs: i64,
    pub call_budget: u64,
    pub calls_made: u64,
    pub rate_limit_per_minute: Option<u64>,
    pub rate_window_start: DateTime<Utc>,
    pub rate_window_calls: u64,
    pub rate_limit_window_secs: u64,
    pub data_sensitivity_ceiling: StoredDataSensitivity,
    pub created_at: DateTime<Utc>,
    pub status: StoredSessionStatus,
}

// ── Async storage traits ────────────────────────────────────────────

/// Async storage trait for agent records.
#[async_trait]
pub trait AgentStore: Send + Sync {
    /// Insert a new agent. Returns the stored agent.
    async fn insert_agent(&self, agent: &StoredAgent) -> Result<(), StorageError>;

    /// Get an agent by ID.
    async fn get_agent(&self, id: Uuid) -> Result<StoredAgent, StorageError>;

    /// Update an agent's trust level.
    async fn update_trust_level(
        &self,
        id: Uuid,
        level: StoredTrustLevel,
    ) -> Result<(), StorageError>;

    /// Mark an agent as inactive.
    async fn deactivate_agent(&self, id: Uuid) -> Result<(), StorageError>;

    /// List all agents.
    async fn list_agents(&self) -> Result<Vec<StoredAgent>, StorageError>;
}

/// Async storage trait for task session records.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Insert a new session.
    async fn insert_session(&self, session: &StoredSession) -> Result<(), StorageError>;

    /// Get a session by ID.
    async fn get_session(&self, session_id: Uuid) -> Result<StoredSession, StorageError>;

    /// Update a session (full replacement).
    async fn update_session(&self, session: &StoredSession) -> Result<(), StorageError>;

    /// Delete expired sessions. Returns the number removed.
    async fn delete_expired_sessions(&self) -> Result<usize, StorageError>;

    /// List all sessions.
    async fn list_sessions(&self) -> Result<Vec<StoredSession>, StorageError>;
}

/// Async storage trait for delegation links.
#[async_trait]
pub trait DelegationStore: Send + Sync {
    /// Insert a new delegation link. Returns the auto-generated ID.
    async fn insert_delegation(&self, link: &StoredDelegationLink) -> Result<i64, StorageError>;

    /// Get all delegation links where `from_agent` matches.
    async fn get_delegations_from(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<StoredDelegationLink>, StorageError>;

    /// Get all delegation links where `to_agent` matches.
    async fn get_delegations_to(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<StoredDelegationLink>, StorageError>;

    /// Get all delegation links.
    async fn list_delegations(&self) -> Result<Vec<StoredDelegationLink>, StorageError>;
}
