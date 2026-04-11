use crate::error::IdentityError;
use crate::model::{Agent, AgentId, DelegationLink, TrustLevel};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::future::Future;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Trait defining the agent registry interface.
///
/// Implementations can back this with in-memory storage, PostgreSQL, etc.
pub trait AgentRegistry: Send + Sync {
    fn register_agent(
        &self,
        owner: String,
        model: String,
        capabilities: Vec<String>,
        trust_level: TrustLevel,
        expires_at: Option<DateTime<Utc>>,
    ) -> impl Future<Output = Result<Agent, IdentityError>> + Send;

    fn get_agent(&self, id: AgentId) -> impl Future<Output = Result<Agent, IdentityError>> + Send;

    fn update_trust_level(
        &self,
        id: AgentId,
        level: TrustLevel,
    ) -> impl Future<Output = Result<Agent, IdentityError>> + Send;

    fn deactivate_agent(
        &self,
        id: AgentId,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;

    fn list_agents(&self) -> impl Future<Output = Vec<Agent>> + Send;

    fn create_delegation(
        &self,
        from: AgentId,
        to: AgentId,
        scope_narrowing: Vec<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> impl Future<Output = Result<DelegationLink, IdentityError>> + Send;

    fn verify_chain(
        &self,
        agent_id: AgentId,
    ) -> impl Future<Output = Result<Vec<DelegationLink>, IdentityError>> + Send;

    fn get_chain_for_agent(
        &self,
        agent_id: AgentId,
    ) -> impl Future<Output = Result<Vec<DelegationLink>, IdentityError>> + Send;

    /// Deactivate an agent and all agents it has delegated to (cascade).
    fn cascade_deactivate(
        &self,
        id: AgentId,
    ) -> impl Future<Output = Result<Vec<AgentId>, IdentityError>> + Send;
}

/// In-memory implementation of the agent registry.
pub struct InMemoryRegistry {
    agents: RwLock<HashMap<AgentId, Agent>>,
    delegations: RwLock<Vec<DelegationLink>>,
}

impl InMemoryRegistry {
    /// Create a new empty in-memory registry.
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            delegations: RwLock::new(Vec::new()),
        }
    }
}

impl InMemoryRegistry {
    /// Return all delegation links originating from this agent (outgoing).
    pub async fn list_delegations_from(&self, agent_id: AgentId) -> Vec<DelegationLink> {
        let delegations = self.delegations.read().await;
        delegations
            .iter()
            .filter(|d| d.from == agent_id)
            .cloned()
            .collect()
    }

    /// Return all delegation links targeting this agent (incoming).
    pub async fn list_delegations_to(&self, agent_id: AgentId) -> Vec<DelegationLink> {
        let delegations = self.delegations.read().await;
        delegations
            .iter()
            .filter(|d| d.to == agent_id)
            .cloned()
            .collect()
    }
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRegistry for InMemoryRegistry {
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
        tracing::info!(agent_id = %agent.id, owner = %agent.owner, "registered new agent");
        let mut agents = self.agents.write().await;
        agents.insert(agent.id, agent.clone());
        Ok(agent)
    }

    async fn get_agent(&self, id: AgentId) -> Result<Agent, IdentityError> {
        let agents = self.agents.read().await;
        let agent = agents
            .get(&id)
            .cloned()
            .ok_or(IdentityError::AgentNotFound(id))?;
        // Enforce agent expiry on lookup.
        // Previously, expired agents were still returned from the registry.
        if let Some(expires_at) = agent.expires_at
            && Utc::now() > expires_at
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
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&id)
            .ok_or(IdentityError::AgentNotFound(id))?;
        if !agent.active {
            return Err(IdentityError::AgentDeactivated(id));
        }
        tracing::info!(agent_id = %id, old = ?agent.trust_level, new = ?level, "updated trust level");
        agent.trust_level = level;
        Ok(agent.clone())
    }

    async fn deactivate_agent(&self, id: AgentId) -> Result<(), IdentityError> {
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&id)
            .ok_or(IdentityError::AgentNotFound(id))?;
        if !agent.active {
            return Err(IdentityError::AgentDeactivated(id));
        }
        tracing::info!(agent_id = %id, "deactivated agent");
        agent.active = false;
        Ok(())
    }

    async fn list_agents(&self) -> Vec<Agent> {
        let agents = self.agents.read().await;
        let now = Utc::now();
        agents
            .values()
            .filter(|a| {
                a.active && a.expires_at.map_or(true, |exp| now < exp)
            })
            .cloned()
            .collect()
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

        let agents = self.agents.read().await;

        let parent = agents
            .get(&from)
            .ok_or(IdentityError::DelegationSourceNotFound(from))?;
        if !parent.active {
            return Err(IdentityError::DelegateFromDeactivated(from));
        }

        // Verify target exists
        let target = agents
            .get(&to)
            .ok_or(IdentityError::DelegationTargetNotFound(to))?;

        // Prevent cross-owner delegation: the from and to agents must belong
        // to the same owner. Without this, a compromised agent under one
        // principal can grant capabilities to an agent owned by a different
        // principal with no registry-level enforcement.
        if parent.owner != target.owner {
            return Err(IdentityError::CrossOwnerDelegation {
                from,
                to,
                from_owner: parent.owner.clone(),
                to_owner: target.owner.clone(),
            });
        }

        // Enforce maximum delegation chain depth to prevent resource exhaustion.
        const MAX_CHAIN_DEPTH: usize = 10;
        {
            let delegations = self.delegations.read().await;
            let mut depth = 0;
            let mut current = from;
            loop {
                match delegations.iter().find(|d| d.to == current) {
                    Some(link) => {
                        depth += 1;
                        if depth >= MAX_CHAIN_DEPTH {
                            return Err(IdentityError::InternalError(format!(
                                "delegation chain depth would exceed maximum of {MAX_CHAIN_DEPTH}"
                            )));
                        }
                        current = link.from;
                    }
                    None => break,
                }
            }
        }

        // Reject empty scope_narrowing: an empty list has ambiguous semantics
        // ("no access" vs "all parent scopes"). Force callers to be explicit.
        if scope_narrowing.is_empty() {
            return Err(IdentityError::InternalError(
                "scope_narrowing must not be empty; specify at least one scope".into(),
            ));
        }

        // Enforce scope narrowing: every requested scope must exist in parent's capabilities
        for scope in &scope_narrowing {
            if !parent.capabilities.contains(scope) {
                return Err(IdentityError::ScopeNarrowingViolation {
                    scope: scope.clone(),
                });
            }
        }
        drop(agents);

        // Detect circular delegations to prevent infinite loops.
        // Walk the chain from 'from' back to root. If we encounter 'to' at any point,
        // creating this delegation would form a cycle.
        {
            let delegations = self.delegations.read().await;
            let mut visited = std::collections::HashSet::new();
            let mut current = from;
            visited.insert(current);
            loop {
                let parent = delegations.iter().find(|d| d.to == current);
                match parent {
                    Some(link) => {
                        if link.from == to {
                            return Err(IdentityError::CircularDelegation { from, to });
                        }
                        if !visited.insert(link.from) {
                            break; // Already visited, existing cycle in chain
                        }
                        current = link.from;
                    }
                    None => break,
                }
            }
        }

        let link = DelegationLink {
            from,
            to,
            scope_narrowing,
            created_at: Utc::now(),
            expires_at,
        };
        tracing::info!(from = %from, to = %to, "created delegation link");
        let mut delegations = self.delegations.write().await;
        delegations.push(link.clone());
        Ok(link)
    }

    async fn verify_chain(&self, agent_id: AgentId) -> Result<Vec<DelegationLink>, IdentityError> {
        let chain = self.get_chain_for_agent(agent_id).await?;

        // Verify no links are expired
        for link in &chain {
            if link.is_expired() {
                return Err(IdentityError::ChainExpired {
                    from: link.from,
                    to: link.to,
                });
            }
        }

        // Verify all agents in the chain are active
        let agents = self.agents.read().await;
        for link in &chain {
            if let Some(agent) = agents.get(&link.from)
                && !agent.active
            {
                return Err(IdentityError::AgentDeactivated(link.from));
            }
        }

        Ok(chain)
    }

    async fn get_chain_for_agent(
        &self,
        agent_id: AgentId,
    ) -> Result<Vec<DelegationLink>, IdentityError> {
        let delegations = self.delegations.read().await;
        let mut chain = Vec::new();
        let mut current = agent_id;
        // Prevent infinite loops in chain traversal.
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);

        // Walk backwards from the agent to the root of the delegation chain
        loop {
            let link = delegations.iter().find(|d| d.to == current);
            match link {
                Some(l) => {
                    chain.push(l.clone());
                    current = l.from;
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
        // First deactivate the target agent
        self.deactivate_agent(id).await?;

        let mut deactivated = vec![id];
        let mut to_process = vec![id];

        while let Some(current) = to_process.pop() {
            // Find all agents delegated from current
            let children: Vec<AgentId> = {
                let delegations = self.delegations.read().await;
                delegations
                    .iter()
                    .filter(|d| d.from == current)
                    .map(|d| d.to)
                    .collect()
            };

            for child in children {
                let mut agents = self.agents.write().await;
                if let Some(agent) = agents.get_mut(&child)
                    && agent.active
                {
                    agent.active = false;
                    tracing::info!(agent_id = %child, cascade_from = %id, "cascade deactivated agent");
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
    use chrono::Duration;

    #[tokio::test]
    async fn register_and_get_agent() {
        let registry = InMemoryRegistry::new();
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
        assert_eq!(fetched.trust_level, TrustLevel::Basic);
        assert!(fetched.active);
    }

    #[tokio::test]
    async fn delegation_chain_creation_and_verification() {
        let registry = InMemoryRegistry::new();

        let parent = registry
            .register_agent(
                "user:alice".into(),
                "claude-opus-4-6".into(),
                vec!["read".into(), "write".into(), "admin".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let child = registry
            .register_agent(
                "user:alice".into(),
                "claude-haiku-4-5".into(),
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

        let chain = registry.verify_chain(child.id).await.unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].from, parent.id);
    }

    #[tokio::test]
    async fn scope_narrowing_rejection() {
        let registry = InMemoryRegistry::new();

        let parent = registry
            .register_agent(
                "user:alice".into(),
                "claude-opus-4-6".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let child = registry
            .register_agent(
                "user:alice".into(),
                "claude-haiku-4-5".into(),
                vec!["read".into(), "write".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        // Parent only has "read", trying to delegate "write" should fail
        let result = registry
            .create_delegation(parent.id, child.id, vec!["write".into()], None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::ScopeNarrowingViolation { scope } => {
                assert_eq!(scope, "write");
            }
            other => panic!("expected ScopeNarrowingViolation, got: {other}"),
        }
    }

    #[tokio::test]
    async fn expired_delegation_chain_rejected() {
        let registry = InMemoryRegistry::new();

        let parent = registry
            .register_agent(
                "user:alice".into(),
                "claude-opus-4-6".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let child = registry
            .register_agent(
                "user:alice".into(),
                "claude-haiku-4-5".into(),
                vec!["read".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        // Create an already-expired delegation
        let expired = Utc::now() - Duration::hours(1);
        registry
            .create_delegation(parent.id, child.id, vec!["read".into()], Some(expired))
            .await
            .unwrap();

        // verify_chain should fail because the link is expired
        let result = registry.verify_chain(child.id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::ChainExpired { from, to } => {
                assert_eq!(from, parent.id);
                assert_eq!(to, child.id);
            }
            other => panic!("expected ChainExpired, got: {other}"),
        }
    }

    #[tokio::test]
    async fn cascade_deactivation() {
        let registry = InMemoryRegistry::new();

        let root = registry
            .register_agent(
                "user:alice".into(),
                "root-agent".into(),
                vec!["read".into(), "write".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        let mid = registry
            .register_agent(
                "user:alice".into(),
                "mid-agent".into(),
                vec!["read".into()],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        let leaf = registry
            .register_agent(
                "user:alice".into(),
                "leaf-agent".into(),
                vec!["read".into()],
                TrustLevel::Untrusted,
                None,
            )
            .await
            .unwrap();

        // root -> mid -> leaf
        registry
            .create_delegation(root.id, mid.id, vec!["read".into()], None)
            .await
            .unwrap();
        registry
            .create_delegation(mid.id, leaf.id, vec!["read".into()], None)
            .await
            .unwrap();

        // Cascade deactivate from root
        let deactivated = registry.cascade_deactivate(root.id).await.unwrap();
        assert_eq!(deactivated.len(), 3);

        // All three should be deactivated
        let root_agent = registry.get_agent(root.id).await.unwrap();
        let mid_agent = registry.get_agent(mid.id).await.unwrap();
        let leaf_agent = registry.get_agent(leaf.id).await.unwrap();
        assert!(!root_agent.active);
        assert!(!mid_agent.active);
        assert!(!leaf_agent.active);
    }

    #[tokio::test]
    async fn agent_not_found_error() {
        let registry = InMemoryRegistry::new();
        let fake_id = Uuid::new_v4();
        let result = registry.get_agent(fake_id).await;
        assert!(matches!(result, Err(IdentityError::AgentNotFound(_))));
    }

    #[tokio::test]
    async fn update_trust_level() {
        let registry = InMemoryRegistry::new();
        let agent = registry
            .register_agent(
                "user:bob".into(),
                "test-model".into(),
                vec![],
                TrustLevel::Untrusted,
                None,
            )
            .await
            .unwrap();

        let updated = registry
            .update_trust_level(agent.id, TrustLevel::Verified)
            .await
            .unwrap();
        assert_eq!(updated.trust_level, TrustLevel::Verified);
    }

    #[tokio::test]
    async fn list_agents_returns_all() {
        let registry = InMemoryRegistry::new();
        registry
            .register_agent("a".into(), "m".into(), vec![], TrustLevel::Basic, None)
            .await
            .unwrap();
        registry
            .register_agent("b".into(), "m".into(), vec![], TrustLevel::Basic, None)
            .await
            .unwrap();

        let all = registry.list_agents().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn self_delegation_rejected() {
        let registry = InMemoryRegistry::new();
        let agent = registry
            .register_agent(
                "user:alice".into(),
                "claude-opus-4-6".into(),
                vec!["read".into()],
                TrustLevel::Trusted,
                None,
            )
            .await
            .unwrap();

        // Attempt self-delegation: A -> A
        let result = registry
            .create_delegation(agent.id, agent.id, vec!["read".into()], None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::CircularDelegation { from, to } => {
                assert_eq!(from, agent.id);
                assert_eq!(to, agent.id);
            }
            other => panic!("expected CircularDelegation, got: {other}"),
        }
    }

    /// Delegation from a deactivated agent must be rejected.
    #[tokio::test]
    async fn delegation_from_deactivated_agent_rejected() {
        let registry = InMemoryRegistry::new();
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

        // Deactivate the parent first
        registry.deactivate_agent(parent.id).await.unwrap();

        // Attempt to delegate from deactivated parent
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

    #[tokio::test]
    async fn double_deactivation_error() {
        let registry = InMemoryRegistry::new();
        let agent = registry
            .register_agent(
                "user:alice".into(),
                "test-model".into(),
                vec![],
                TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();

        // First deactivation succeeds
        registry.deactivate_agent(agent.id).await.unwrap();

        // Second deactivation should return AgentDeactivated, not silently succeed
        let result = registry.deactivate_agent(agent.id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::AgentDeactivated(id) => {
                assert_eq!(id, agent.id);
            }
            other => panic!("expected AgentDeactivated, got: {other}"),
        }
    }

    #[tokio::test]
    async fn deep_delegation_chain() {
        let registry = InMemoryRegistry::new();
        let mut agents = Vec::new();

        // Create 10 agents under the same owner (cross-owner delegation is now blocked).
        for i in 0..10 {
            let agent = registry
                .register_agent(
                    "user:alice".into(),
                    format!("model-{i}"),
                    vec!["read".into()],
                    TrustLevel::Trusted,
                    None,
                )
                .await
                .unwrap();
            agents.push(agent);
        }

        // Create chain: A->B->C->...->J (9 delegation links)
        for i in 0..9 {
            registry
                .create_delegation(agents[i].id, agents[i + 1].id, vec!["read".into()], None)
                .await
                .unwrap();
        }

        // Verify get_chain_for_agent(J) returns 9 links
        let chain = registry.get_chain_for_agent(agents[9].id).await.unwrap();
        assert_eq!(chain.len(), 9, "chain should have 9 links for 10 agents");

        // Verify the chain is ordered root-to-leaf
        assert_eq!(chain[0].from, agents[0].id);
        assert_eq!(chain[0].to, agents[1].id);
        assert_eq!(chain[8].from, agents[8].id);
        assert_eq!(chain[8].to, agents[9].id);
    }

    #[tokio::test]
    async fn circular_chain_detection() {
        let registry = InMemoryRegistry::new();

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

        // Create A -> B delegation
        registry
            .create_delegation(a.id, b.id, vec!["read".into()], None)
            .await
            .unwrap();

        // Attempt B -> A (would create cycle)
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

    #[tokio::test]
    async fn deep_delegation_chain_does_not_overflow() {
        let registry = InMemoryRegistry::new();
        // Max chain depth is 10, so we use 10 agents (9 links).
        let chain_len = 10;
        let mut agents = Vec::with_capacity(chain_len);

        // Register 50 agents, all with the same capabilities so scope narrowing
        // is satisfied at every link (each delegation uses the same scope subset).
        for i in 0..chain_len {
            let agent = registry
                .register_agent(
                    "user:alice".into(),
                    format!("model-deep-{i}"),
                    vec!["read".into()],
                    TrustLevel::Trusted,
                    None,
                )
                .await
                .unwrap();
            agents.push(agent);
        }

        // Create chain: agent[0] -> agent[1] -> ... -> agent[49] (49 delegation links)
        for i in 0..(chain_len - 1) {
            registry
                .create_delegation(agents[i].id, agents[i + 1].id, vec!["read".into()], None)
                .await
                .unwrap();
        }

        // Verify get_chain_for_agent on the deepest agent returns the full chain
        let chain = registry
            .get_chain_for_agent(agents[chain_len - 1].id)
            .await
            .unwrap();
        assert_eq!(
            chain.len(),
            chain_len - 1,
            "chain should have {} links for {} agents",
            chain_len - 1,
            chain_len
        );

        // Verify ordering: first link starts at root, last link ends at deepest agent
        assert_eq!(chain[0].from, agents[0].id);
        assert_eq!(chain[0].to, agents[1].id);
        assert_eq!(chain[chain_len - 2].from, agents[chain_len - 2].id);
        assert_eq!(chain[chain_len - 2].to, agents[chain_len - 1].id);

        // verify_chain must succeed on the deepest agent without overflow or panic
        let verified = registry
            .verify_chain(agents[chain_len - 1].id)
            .await
            .unwrap();
        assert_eq!(verified.len(), chain_len - 1);

        // Cascade deactivate from agent[0] should deactivate all 50 agents
        let deactivated = registry.cascade_deactivate(agents[0].id).await.unwrap();
        assert_eq!(
            deactivated.len(),
            chain_len,
            "cascade_deactivate should deactivate all {} agents",
            chain_len
        );

        // Confirm every agent is now inactive
        for agent in &agents {
            let fetched = registry.get_agent(agent.id).await.unwrap();
            assert!(
                !fetched.active,
                "agent {} should be deactivated after cascade",
                agent.id
            );
        }
    }
}
