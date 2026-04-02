use thiserror::Error;
use uuid::Uuid;

/// Errors from session operations.
///
/// Display impls are intentionally opaque — they appear in
/// HTTP error responses sent to agents. Internal fields are preserved for
/// structured logging via Debug. Previously, Display exposed budget limits,
/// rate limit values, tool names, and session caps to untrusted agents.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The referenced session does not exist.
    #[error("session not found")]
    NotFound(Uuid),

    /// The session has expired (time limit exceeded).
    #[error("session expired")]
    Expired(Uuid),

    /// The session's call budget has been exhausted.
    #[error("session budget exceeded")]
    BudgetExceeded {
        session_id: Uuid,
        limit: u64,
        used: u64,
    },

    /// The requested tool is not in the session's authorized set.
    #[error("tool not authorized in session")]
    ToolNotAuthorized { session_id: Uuid, tool: String },

    /// The session has already been closed.
    #[error("session already closed")]
    AlreadyClosed(Uuid),

    /// The session's per-minute rate limit has been exceeded.
    #[error("session rate limit exceeded")]
    RateLimited {
        session_id: Uuid,
        limit_per_minute: u64,
    },

    /// The presenting agent does not match the session's bound agent.
    #[error("agent mismatch")]
    AgentMismatch {
        session_id: Uuid,
        expected: Uuid,
        actual: Uuid,
    },

    /// Storage write-through failed after updating cache.
    /// The session state in the cache is ahead of durable storage.
    #[error("storage write-through failed")]
    StorageWriteThrough { session_id: Uuid, detail: String },

    /// The agent has reached the maximum number of concurrent active sessions.
    ///
    /// P0: Per-agent session cap to prevent session multiplication attacks.
    #[error("too many concurrent sessions")]
    TooManySessions {
        agent_id: String,
        max: u64,
        current: u64,
    },
}
