//! Task session management for Arbiter.
//!
//! Provides task sessions with call budgets, tool whitelisting,
//! time limits, and TTL-based cleanup. Sessions track what an agent is
//! authorized to do and enforce those bounds per-request.
//!
//! The [`StorageBackedSessionStore`] provides persistent sessions through
//! an in-memory write-through cache backed by any `SessionStore` storage
//! implementation (REQ-001, REQ-007).
//!
//! Behavioral anomaly detection lives in the `arbiter-behavior` crate,
//! which provides tiered intent classification (read/write/admin).

pub mod any_store;
pub mod error;
pub mod middleware;
pub mod model;
pub mod storage_store;
pub mod store;

pub use any_store::AnySessionStore;
pub use error::SessionError;
pub use middleware::{parse_session_header, status_code_for_error};
pub use model::{DataSensitivity, SessionId, SessionStatus, TaskSession};
pub use storage_store::StorageBackedSessionStore;
pub use store::{CreateSessionRequest, SessionStore};
