//! Unified registry enum dispatching to either in-memory or storage-backed impl.
//!
//! This avoids changing the `AgentRegistry` trait to be dyn-compatible while
//! still allowing the main binary to select the backend at startup.

use chrono::{DateTime, Utc};

use crate::error::IdentityError;
use crate::model::{Agent, AgentId, DelegationLink, TrustLevel};
use crate::registry::{AgentRegistry, InMemoryRegistry};
use crate::storage_registry::StorageBackedRegistry;

/// A registry that dispatches to either in-memory or storage-backed.
pub enum AnyRegistry {
    InMemory(InMemoryRegistry),
    StorageBacked(StorageBackedRegistry),
}

// Forward all AgentRegistry trait methods.
impl AgentRegistry for AnyRegistry {
    async fn register_agent(
        &self,
        owner: String,
        model: String,
        capabilities: Vec<String>,
        trust_level: TrustLevel,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Agent, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => {
                r.register_agent(owner, model, capabilities, trust_level, expires_at)
                    .await
            }
            AnyRegistry::StorageBacked(r) => {
                r.register_agent(owner, model, capabilities, trust_level, expires_at)
                    .await
            }
        }
    }

    async fn get_agent(&self, id: AgentId) -> Result<Agent, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => r.get_agent(id).await,
            AnyRegistry::StorageBacked(r) => r.get_agent(id).await,
        }
    }

    async fn update_trust_level(
        &self,
        id: AgentId,
        level: TrustLevel,
    ) -> Result<Agent, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => r.update_trust_level(id, level).await,
            AnyRegistry::StorageBacked(r) => r.update_trust_level(id, level).await,
        }
    }

    async fn deactivate_agent(&self, id: AgentId) -> Result<(), IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => r.deactivate_agent(id).await,
            AnyRegistry::StorageBacked(r) => r.deactivate_agent(id).await,
        }
    }

    async fn list_agents(&self) -> Vec<Agent> {
        match self {
            AnyRegistry::InMemory(r) => r.list_agents().await,
            AnyRegistry::StorageBacked(r) => r.list_agents().await,
        }
    }

    async fn create_delegation(
        &self,
        from: AgentId,
        to: AgentId,
        scope_narrowing: Vec<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<DelegationLink, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => {
                r.create_delegation(from, to, scope_narrowing, expires_at)
                    .await
            }
            AnyRegistry::StorageBacked(r) => {
                r.create_delegation(from, to, scope_narrowing, expires_at)
                    .await
            }
        }
    }

    async fn verify_chain(&self, agent_id: AgentId) -> Result<Vec<DelegationLink>, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => r.verify_chain(agent_id).await,
            AnyRegistry::StorageBacked(r) => r.verify_chain(agent_id).await,
        }
    }

    async fn get_chain_for_agent(
        &self,
        agent_id: AgentId,
    ) -> Result<Vec<DelegationLink>, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => r.get_chain_for_agent(agent_id).await,
            AnyRegistry::StorageBacked(r) => r.get_chain_for_agent(agent_id).await,
        }
    }

    async fn cascade_deactivate(&self, id: AgentId) -> Result<Vec<AgentId>, IdentityError> {
        match self {
            AnyRegistry::InMemory(r) => r.cascade_deactivate(id).await,
            AnyRegistry::StorageBacked(r) => r.cascade_deactivate(id).await,
        }
    }
}

// Forward convenience delegation listing methods (used by lifecycle API).
impl AnyRegistry {
    /// Return all delegation links originating from this agent (outgoing).
    pub async fn list_delegations_from(&self, agent_id: AgentId) -> Vec<DelegationLink> {
        match self {
            AnyRegistry::InMemory(r) => r.list_delegations_from(agent_id).await,
            AnyRegistry::StorageBacked(r) => r.list_delegations_from(agent_id).await,
        }
    }

    /// Return all delegation links targeting this agent (incoming).
    pub async fn list_delegations_to(&self, agent_id: AgentId) -> Vec<DelegationLink> {
        match self {
            AnyRegistry::InMemory(r) => r.list_delegations_to(agent_id).await,
            AnyRegistry::StorageBacked(r) => r.list_delegations_to(agent_id).await,
        }
    }
}
