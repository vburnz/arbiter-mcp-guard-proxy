use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for an agent in the system.
pub type AgentId = Uuid;

/// Trust level assigned to an agent, determining its permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Untrusted,
    Basic,
    Verified,
    Trusted,
}

/// An AI agent registered in the identity system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: AgentId,
    /// The human principal (OAuth sub) who owns this agent.
    pub owner: String,
    /// Model name (e.g. "claude-opus-4-6").
    pub model: String,
    /// Capabilities this agent is authorized to use.
    pub capabilities: Vec<String>,
    pub trust_level: TrustLevel,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

/// A single link in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    pub from: AgentId,
    pub to: AgentId,
    /// Scopes narrowed from the parent; must be a subset of the parent's capabilities.
    pub scope_narrowing: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Agent {
    /// Returns true if the agent is currently expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
}

impl DelegationLink {
    /// Returns true if this delegation link has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn agent_not_expired_without_expiry() {
        let agent = Agent {
            id: Uuid::new_v4(),
            owner: "user:123".into(),
            model: "test-model".into(),
            capabilities: vec![],
            trust_level: TrustLevel::Basic,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        };
        assert!(!agent.is_expired());
    }

    #[test]
    fn agent_expired_with_past_expiry() {
        let agent = Agent {
            id: Uuid::new_v4(),
            owner: "user:123".into(),
            model: "test-model".into(),
            capabilities: vec![],
            trust_level: TrustLevel::Basic,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() - Duration::hours(1)),
            active: true,
        };
        assert!(agent.is_expired());
    }

    #[test]
    fn trust_level_serialization() {
        assert_eq!(
            serde_json::to_string(&TrustLevel::Verified).unwrap(),
            "\"verified\""
        );
    }
}
