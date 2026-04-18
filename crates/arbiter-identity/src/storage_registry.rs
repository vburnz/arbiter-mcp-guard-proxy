//! Storage-backed agent registry.
//!
//! Wraps the generic storage traits from `arbiter-storage` and implements
//! the `AgentRegistry` trait, providing persistent agent and delegation
//! state through any backend (SQLite, PostgreSQL, etc.).
//!
//! REQ-001: Identity and delegation state survives process restart.
//! REQ-007: Storage behind async trait; swappable backends.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use arbiter_storage::{
    AgentStore, DelegationStore, StorageError, StoredAgent, StoredDelegationLink, StoredTrustLevel,
};

use crate::error::IdentityError;
use crate::model::{Agent, AgentId, DelegationLink, TrustLevel};
use crate::registry::AgentRegistry;

/// An `AgentRegistry` implementation backed by persistent storage.
///
/// Delegates all operations to the underlying `AgentStore` and
/// `DelegationStore` implementations, converting between domain
/// types and storage types at the boundary.
pub struct StorageBackedRegistry {
    agent_store: Arc<dyn AgentStore>,
    delegation_store: Arc<dyn DelegationStore>,
}

impl StorageBackedRegistry {
    /// Create a new storage-backed registry.
    pub fn new(
        agent_store: Arc<dyn AgentStore>,
        delegation_store: Arc<dyn DelegationStore>,
    ) -> Self {
        Self {
            agent_store,
            delegation_store,
        }
    }

    /// Return all delegation links originating from this agent (outgoing).
    pub async fn list_delegations_from(&self, agent_id: AgentId) -> Vec<DelegationLink> {
        match self.delegation_store.get_delegations_from(agent_id).await {
            Ok(links) => links.into_iter().map(stored_delegation_to_domain).collect(),
            Err(e) => {
                tracing::error!(error = %e, "failed to list delegations from storage");
                Vec::new()
            }
        }
    }

    /// Return all delegation links targeting this agent (incoming).
    pub async fn list_delegations_to(&self, agent_id: AgentId) -> Vec<DelegationLink> {
        match self.delegation_store.get_delegations_to(agent_id).await {
            Ok(links) => links.into_iter().map(stored_delegation_to_domain).collect(),
            Err(e) => {
                tracing::error!(error = %e, "failed to list delegations to storage");
                Vec::new()
            }
        }
    }
}

// ── Type conversions ────────────────────────────────────────────────

fn trust_level_to_stored(level: TrustLevel) -> StoredTrustLevel {
    match level {
        TrustLevel::Untrusted => StoredTrustLevel::Untrusted,
        TrustLevel::Basic => StoredTrustLevel::Basic,
        TrustLevel::Verified => StoredTrustLevel::Verified,
        TrustLevel::Trusted => StoredTrustLevel::Trusted,
    }
}

fn stored_to_trust_level(level: StoredTrustLevel) -> TrustLevel {
    match level {
        StoredTrustLevel::Untrusted => TrustLevel::Untrusted,
        StoredTrustLevel::Basic => TrustLevel::Basic,
        StoredTrustLevel::Verified => TrustLevel::Verified,
        StoredTrustLevel::Trusted => TrustLevel::Trusted,
    }
}

fn stored_agent_to_domain(stored: StoredAgent) -> Agent {
    Agent {
        id: stored.id,
        owner: stored.owner,
        model: stored.model,
        capabilities: stored.capabilities,
        trust_level: stored_to_trust_level(stored.trust_level),
        created_at: stored.created_at,
        expires_at: stored.expires_at,
        active: stored.active,
    }
}

fn domain_agent_to_stored(agent: &Agent) -> StoredAgent {
    StoredAgent {
        id: agent.id,
        owner: agent.owner.clone(),
        model: agent.model.clone(),
        capabilities: agent.capabilities.clone(),
        trust_level: trust_level_to_stored(agent.trust_level),
        created_at: agent.created_at,
        expires_at: agent.expires_at,
        active: agent.active,
    }
}

fn stored_delegation_to_domain(stored: StoredDelegationLink) -> DelegationLink {
    DelegationLink {
        from: stored.from_agent,
        to: stored.to_agent,
        scope_narrowing: stored.scope_narrowing,
        created_at: stored.created_at,
        expires_at: stored.expires_at,
    }
}

fn storage_err_to_identity(err: StorageError) -> IdentityError {
    match err {
        StorageError::AgentNotFound(id) => IdentityError::AgentNotFound(id),
        other => {
            // Log unexpected storage errors as they indicate backend issues.
            tracing::error!(error = %other, "storage backend error");
            IdentityError::InternalError(other.to_string())
        }
    }
}

// ── AgentRegistry impl ─────────────────────────────────────────────

impl AgentRegistry for StorageBackedRegistry {
    async fn register_agent(
        &self,
        owner: String,
        model: String,
        capabilities: Vec<String>,
        trust_level: TrustLevel,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Agent, IdentityError> {
        let agent = Agent {
            id: Uuid::new_v4(),
            owner,
            model,
            capabilities,
            trust_level,
            created_at: Utc::now(),
            expires_at,
            active: true,
        };

        let stored = domain_agent_to_stored(&agent);
        self.agent_store
            .insert_agent(&stored)
            .await
            .map_err(storage_err_to_identity)?;

        tracing::info!(agent_id = %agent.id, owner = %agent.owner, "registered new agent (storage-backed)");
        Ok(agent)
    }

    async fn get_agent(&self, id: AgentId) -> Result<Agent, IdentityError> {
        let stored = self
            .agent_store
            .get_agent(id)
            .await
            .map_err(storage_err_to_identity)?;
        let agent = stored_agent_to_domain(stored);

        // Check expiry (mirrors InMemoryRegistry::get_agent behavior).
        // Previously, StorageBackedRegistry did not check expires_at,
        // allowing expired agents to continue authenticating.
        if !agent.active {
            return Err(IdentityError::AgentDeactivated(id));
        }
        if let Some(expires_at) = agent.expires_at
            && chrono::Utc::now() > expires_at
        {
            return Err(IdentityError::AgentDeactivated(id));
        }

        Ok(agent)
    }

    async fn update_trust_level(
        &self,
        id: AgentId,
        level: TrustLevel,
    ) -> Result<Agent, IdentityError> {
        // First check the agent exists and is active.
        let stored = self
            .agent_store
            .get_agent(id)
            .await
            .map_err(storage_err_to_identity)?;
        if !stored.active {
            return Err(IdentityError::AgentDeactivated(id));
        }

        self.agent_store
            .update_trust_level(id, trust_level_to_stored(level))
            .await
            .map_err(storage_err_to_identity)?;

        tracing::info!(agent_id = %id, old = ?stored.trust_level, new = ?level, "updated trust level (storage-backed)");

        // Re-fetch to return the updated agent.
        let updated = self
            .agent_store
            .get_agent(id)
            .await
            .map_err(storage_err_to_identity)?;
        Ok(stored_agent_to_domain(updated))
    }

    async fn deactivate_agent(&self, id: AgentId) -> Result<(), IdentityError> {
        let stored = self
            .agent_store
            .get_agent(id)
            .await
            .map_err(storage_err_to_identity)?;
        if !stored.active {
            return Err(IdentityError::AgentDeactivated(id));
        }

        self.agent_store
            .deactivate_agent(id)
            .await
            .map_err(storage_err_to_identity)?;

        tracing::info!(agent_id = %id, "deactivated agent (storage-backed)");
        Ok(())
    }

    async fn list_agents(&self) -> Vec<Agent> {
        match self.agent_store.list_agents().await {
            Ok(agents) => agents.into_iter().map(stored_agent_to_domain).collect(),
            Err(e) => {
                tracing::error!(error = %e, "failed to list agents from storage");
                Vec::new()
            }
        }
    }

    async fn create_delegation(
        &self,
        from: AgentId,
        to: AgentId,
        scope_narrowing: Vec<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<DelegationLink, IdentityError> {
        // Reject self-delegation immediately.
        if from == to {
            return Err(IdentityError::CircularDelegation { from, to });
        }

        // Validate parent exists and is active.
        let parent = self
            .agent_store
            .get_agent(from)
            .await
            .map_err(|_| IdentityError::DelegationSourceNotFound(from))?;
        if !parent.active {
            return Err(IdentityError::DelegateFromDeactivated(from));
        }

        // Validate target exists.
        let target = self
            .agent_store
            .get_agent(to)
            .await
            .map_err(|_| IdentityError::DelegationTargetNotFound(to))?;

        // Prevent cross-owner delegation.
        if parent.owner != target.owner {
            return Err(IdentityError::CrossOwnerDelegation {
                from,
                to,
                from_owner: parent.owner.clone(),
                to_owner: target.owner.clone(),
            });
        }

        // Enforce scope narrowing.
        for scope in &scope_narrowing {
            if !parent.capabilities.contains(scope) {
                return Err(IdentityError::ScopeNarrowingViolation {
                    scope: scope.clone(),
                });
            }
        }

        // Detect circular delegations to prevent infinite loops.
        // Walk the chain from 'from' back to root. If we encounter 'to' at any point,
        // creating this delegation would form a cycle.
        {
            let mut visited = std::collections::HashSet::new();
            let mut current = from;
            visited.insert(current);
            loop {
                let incoming = self
                    .delegation_store
                    .get_delegations_to(current)
                    .await
                    .map_err(storage_err_to_identity)?;
                match incoming.into_iter().next() {
                    Some(link) => {
                        if link.from_agent == to {
                            return Err(IdentityError::CircularDelegation { from, to });
                        }
                        if !visited.insert(link.from_agent) {
                            break; // Already visited, existing cycle in chain
                        }
                        current = link.from_agent;
                    }
                    None => break,
                }
            }
        }

        let link = DelegationLink {
            from,
            to,
            scope_narrowing: scope_narrowing.clone(),
            created_at: Utc::now(),
            expires_at,
        };

        let stored = StoredDelegationLink {
            id: 0, // auto-generated
            from_agent: from,
            to_agent: to,
            scope_narrowing,
            created_at: link.created_at,
            expires_at,
        };

        self.delegation_store
            .insert_delegation(&stored)
            .await
            .map_err(storage_err_to_identity)?;

        tracing::info!(from = %from, to = %to, "created delegation link (storage-backed)");
        Ok(link)
    }

    async fn verify_chain(&self, agent_id: AgentId) -> Result<Vec<DelegationLink>, IdentityError> {
        let chain = self.get_chain_for_agent(agent_id).await?;

        // Verify no links are expired.
        for link in &chain {
            if link.is_expired() {
                return Err(IdentityError::ChainExpired {
                    from: link.from,
                    to: link.to,
                });
            }
        }

        // Verify all agents in the chain are active.
        for link in &chain {
            let agent = self
                .agent_store
                .get_agent(link.from)
                .await
                .map_err(storage_err_to_identity)?;
            if !agent.active {
                return Err(IdentityError::AgentDeactivated(link.from));
            }
        }

        Ok(chain)
    }

    async fn get_chain_for_agent(
        &self,
        agent_id: AgentId,
    ) -> Result<Vec<DelegationLink>, IdentityError> {
        let mut chain = Vec::new();
        let mut current = agent_id;
        // Prevent infinite loops in chain traversal.
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);

        // Walk backwards from the agent to the root of the delegation chain.
        loop {
            let incoming = self
                .delegation_store
                .get_delegations_to(current)
                .await
                .map_err(storage_err_to_identity)?;

            match incoming.into_iter().next() {
                Some(link) => {
                    let domain_link = stored_delegation_to_domain(link);
                    current = domain_link.from;
                    chain.push(domain_link);
                    if !visited.insert(current) {
                        tracing::warn!(agent_id = %agent_id, "circular delegation chain detected during traversal");
                        break;
                    }
                }
                None => break,
            }
        }

        chain.reverse();
        Ok(chain)
    }

    async fn cascade_deactivate(&self, id: AgentId) -> Result<Vec<AgentId>, IdentityError> {
        // First deactivate the target agent.
        self.deactivate_agent(id).await?;

        let mut deactivated = vec![id];
        let mut to_process = vec![id];

        while let Some(current) = to_process.pop() {
            let children: Vec<AgentId> = self
                .delegation_store
                .get_delegations_from(current)
                .await
                .map_err(storage_err_to_identity)?
                .into_iter()
                .map(|d| d.to_agent)
                .collect();

            for child in children {
                // Check if still active before deactivating.
                let Ok(agent) = self.agent_store.get_agent(child).await else {
                    continue;
                };
                if agent.active && self.agent_store.deactivate_agent(child).await.is_ok() {
                    tracing::info!(
                        agent_id = %child,
                        cascade_from = %id,
                        "cascade deactivated agent (storage-backed)"
                    );
                    deactivated.push(child);
                    to_process.push(child);
                }
            }
        }

        Ok(deactivated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_storage::{
        AgentStore, DelegationStore, StorageError, StoredAgent, StoredDelegationLink,
        StoredTrustLevel,
    };
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Minimal in-memory agent store for testing StorageBackedRegistry logic.
    struct MockAgentStore {
        agents: RwLock<std::collections::HashMap<Uuid, StoredAgent>>,
    }

    impl MockAgentStore {
        fn new() -> Self {
            Self {
                agents: RwLock::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl AgentStore for MockAgentStore {
        async fn insert_agent(&self, agent: &StoredAgent) -> Result<(), StorageError> {
            let mut agents = self.agents.write().await;
            agents.insert(agent.id, agent.clone());
            Ok(())
        }

        async fn get_agent(&self, id: Uuid) -> Result<StoredAgent, StorageError> {
            let agents = self.agents.read().await;
            agents
                .get(&id)
                .cloned()
                .ok_or(StorageError::AgentNotFound(id))
        }

        async fn update_trust_level(
            &self,
            id: Uuid,
            level: StoredTrustLevel,
        ) -> Result<(), StorageError> {
            let mut agents = self.agents.write().await;
            let agent = agents.get_mut(&id).ok_or(StorageError::AgentNotFound(id))?;
            agent.trust_level = level;
            Ok(())
        }

        async fn deactivate_agent(&self, id: Uuid) -> Result<(), StorageError> {
            let mut agents = self.agents.write().await;
            let agent = agents.get_mut(&id).ok_or(StorageError::AgentNotFound(id))?;
            agent.active = false;
            Ok(())
        }

        async fn list_agents(&self) -> Result<Vec<StoredAgent>, StorageError> {
            let agents = self.agents.read().await;
            Ok(agents.values().cloned().collect())
        }
    }

    /// Minimal in-memory delegation store for testing.
    struct MockDelegationStore {
        links: RwLock<Vec<StoredDelegationLink>>,
        next_id: RwLock<i64>,
    }

    impl MockDelegationStore {
        fn new() -> Self {
            Self {
                links: RwLock::new(Vec::new()),
                next_id: RwLock::new(1),
            }
        }
    }

    #[async_trait]
    impl DelegationStore for MockDelegationStore {
        async fn insert_delegation(
            &self,
            link: &StoredDelegationLink,
        ) -> Result<i64, StorageError> {
            let mut links = self.links.write().await;
            let mut next_id = self.next_id.write().await;
            let id = *next_id;
            *next_id += 1;
            let mut stored = link.clone();
            stored.id = id;
            links.push(stored);
            Ok(id)
        }

        async fn get_delegations_from(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<StoredDelegationLink>, StorageError> {
            let links = self.links.read().await;
            Ok(links
                .iter()
                .filter(|l| l.from_agent == agent_id)
                .cloned()
                .collect())
        }

        async fn get_delegations_to(
            &self,
            agent_id: Uuid,
        ) -> Result<Vec<StoredDelegationLink>, StorageError> {
            let links = self.links.read().await;
            Ok(links
                .iter()
                .filter(|l| l.to_agent == agent_id)
                .cloned()
                .collect())
        }

        async fn list_delegations(&self) -> Result<Vec<StoredDelegationLink>, StorageError> {
            let links = self.links.read().await;
            Ok(links.clone())
        }
    }

    fn test_registry() -> StorageBackedRegistry {
        StorageBackedRegistry::new(
            Arc::new(MockAgentStore::new()),
            Arc::new(MockDelegationStore::new()),
        )
    }

    /// StorageBackedRegistry basic register + get roundtrip.
    #[tokio::test]
    async fn storage_backed_register_and_get_agent() {
        let registry = test_registry();
        let agent = registry
            .register_agent(
                "user:alice".into(),
                "claude-opus-4-6".into(),
                vec!["read".into(), "write".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        let fetched = registry.get_agent(agent.id).await.unwrap();
        assert_eq!(fetched.owner, "user:alice");
        assert_eq!(fetched.model, "claude-opus-4-6");
        assert_eq!(fetched.capabilities, vec!["read", "write"]);
        assert!(fetched.active);
    }

    /// StorageBackedRegistry delegation creation and chain traversal.
    #[tokio::test]
    async fn storage_backed_delegation_chain() {
        let registry = test_registry();

        let parent = registry
            .register_agent(
                "user:alice".into(),
                "parent-model".into(),
                vec!["read".into(), "write".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let child = registry
            .register_agent(
                "user:alice".into(),
                "child-model".into(),
                vec!["read".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        let link = registry
            .create_delegation(parent.id, child.id, vec!["read".into()], None)
            .await
            .unwrap();

        assert_eq!(link.from, parent.id);
        assert_eq!(link.to, child.id);

        let chain = registry.get_chain_for_agent(child.id).await.unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].from, parent.id);
    }

    /// StorageBackedRegistry deactivation works.
    #[tokio::test]
    async fn storage_backed_deactivate_agent() {
        let registry = test_registry();

        let agent = registry
            .register_agent(
                "user:bob".into(),
                "test-model".into(),
                vec![],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        registry.deactivate_agent(agent.id).await.unwrap();

        // get_agent should now return AgentDeactivated for inactive agents.
        let result = registry.get_agent(agent.id).await;
        assert!(
            matches!(result, Err(IdentityError::AgentDeactivated(_))),
            "get_agent on deactivated agent should return AgentDeactivated, got {result:?}"
        );

        // Double deactivation should error
        let result = registry.deactivate_agent(agent.id).await;
        assert!(result.is_err(), "double deactivation should return error");
    }

    /// Error mapping preserves context for non-AgentNotFound errors.
    #[test]
    fn storage_err_to_identity_preserves_context() {
        // AgentNotFound should map directly
        let agent_id = Uuid::new_v4();
        let err = storage_err_to_identity(StorageError::AgentNotFound(agent_id));
        assert!(
            matches!(err, IdentityError::AgentNotFound(id) if id == agent_id),
            "AgentNotFound should map directly"
        );

        // Backend errors should map to InternalError, not AgentNotFound(nil)
        let err = storage_err_to_identity(StorageError::Backend("connection lost".into()));
        match err {
            IdentityError::InternalError(msg) => {
                assert!(
                    msg.contains("connection lost"),
                    "InternalError should preserve the original error message, got: {msg}"
                );
            }
            other => panic!("expected InternalError for Backend error, got: {other}"),
        }

        // Serialization errors should also map to InternalError
        let err = storage_err_to_identity(StorageError::Serialization("bad json".into()));
        assert!(
            matches!(err, IdentityError::InternalError(_)),
            "Serialization errors should map to InternalError"
        );
    }

    /// Delegation from a deactivated agent is rejected in storage-backed registry.
    #[tokio::test]
    async fn storage_backed_delegation_from_deactivated_rejected() {
        let registry = test_registry();

        let parent = registry
            .register_agent(
                "user:alice".into(),
                "parent-model".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let child = registry
            .register_agent(
                "user:alice".into(),
                "child-model".into(),
                vec!["read".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        registry.deactivate_agent(parent.id).await.unwrap();

        let result = registry
            .create_delegation(parent.id, child.id, vec!["read".into()], None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::DelegateFromDeactivated(id) => {
                assert_eq!(id, parent.id);
            }
            other => panic!("expected DelegateFromDeactivated, got: {other}"),
        }
    }

    /// Circular delegation detection in storage-backed registry.
    #[tokio::test]
    async fn storage_backed_circular_delegation_rejected() {
        let registry = test_registry();

        let a = registry
            .register_agent(
                "user:alice".into(),
                "model-a".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let b = registry
            .register_agent(
                "user:alice".into(),
                "model-b".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        registry
            .create_delegation(a.id, b.id, vec!["read".into()], None)
            .await
            .unwrap();

        let result = registry
            .create_delegation(b.id, a.id, vec!["read".into()], None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::CircularDelegation { from, to } => {
                assert_eq!(from, b.id);
                assert_eq!(to, a.id);
            }
            other => panic!("expected CircularDelegation, got: {other}"),
        }
    }

    /// Cascade deactivation in storage-backed registry.
    #[tokio::test]
    async fn storage_backed_cascade_deactivate() {
        let registry = test_registry();

        let root = registry
            .register_agent(
                "user:alice".into(),
                "root".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let mid = registry
            .register_agent(
                "user:alice".into(),
                "mid".into(),
                vec!["read".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        let leaf = registry
            .register_agent(
                "user:alice".into(),
                "leaf".into(),
                vec!["read".into()],
                TrustLevel::Untrusted,
                None,
            )
            .await
            .unwrap();

        registry
            .create_delegation(root.id, mid.id, vec!["read".into()], None)
            .await
            .unwrap();
        registry
            .create_delegation(mid.id, leaf.id, vec!["read".into()], None)
            .await
            .unwrap();

        let deactivated = registry.cascade_deactivate(root.id).await.unwrap();
        assert_eq!(deactivated.len(), 3);

        // All three should be deactivated (get_agent returns error).
        for agent_id in [root.id, mid.id, leaf.id] {
            let result = registry.get_agent(agent_id).await;
            assert!(
                matches!(result, Err(IdentityError::AgentDeactivated(_))),
                "cascade-deactivated agent {agent_id} should return AgentDeactivated, got {result:?}"
            );
        }
    }
}
