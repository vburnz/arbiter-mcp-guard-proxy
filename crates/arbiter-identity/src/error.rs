use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during identity registry operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("agent not found: {0}")]
    AgentNotFound(Uuid),

    #[error("agent already deactivated: {0}")]
    AgentDeactivated(Uuid),

    #[error("delegation source agent not found: {0}")]
    DelegationSourceNotFound(Uuid),

    #[error("delegation target agent not found: {0}")]
    DelegationTargetNotFound(Uuid),

    #[error("scope narrowing violation: child requested scope '{scope}' not held by parent")]
    ScopeNarrowingViolation { scope: String },

    #[error("delegation chain expired at link from {from} to {to}")]
    ChainExpired { from: Uuid, to: Uuid },

    #[error("delegation chain broken: no link found for agent {0}")]
    ChainBroken(Uuid),

    #[error("agent expired: {0}")]
    AgentExpired(Uuid),

    #[error("cannot delegate from deactivated agent: {0}")]
    DelegateFromDeactivated(Uuid),

    #[error("circular delegation detected: {from} -> {to} would create a cycle")]
    CircularDelegation { from: Uuid, to: Uuid },

    #[error("internal storage error: {0}")]
    InternalError(String),
}
