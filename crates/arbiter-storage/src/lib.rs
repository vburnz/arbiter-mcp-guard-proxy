//! Storage abstraction layer for Arbiter.
//!
//! Provides async traits ([`AgentStore`], [`SessionStore`], [`DelegationStore`])
//! with pluggable backends. The default backend is in-memory; the `sqlite`
//! feature enables a WAL-mode SQLite backend with auto-migration.
//!
//! REQ-007: Storage behind async trait; swappable backends.
//! Design decision: SQLite chosen, designed for swappable.

pub mod encryption;
pub mod error;
pub mod traits;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use encryption::FieldEncryptor;
pub use error::StorageError;
pub use traits::{
    AgentStore, DelegationStore, SessionStore, StoredAgent, StoredDataSensitivity,
    StoredDelegationLink, StoredSession, StoredSessionStatus, StoredTrustLevel,
};
