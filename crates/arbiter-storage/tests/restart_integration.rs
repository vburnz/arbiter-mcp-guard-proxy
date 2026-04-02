//! Integration test (REQ-001): State survives process restart with WAL-mode consistency.
//!
//! This test creates agents, sessions, and delegations using the SQLite backend,
//! drops the storage handle (simulating a process restart), creates a new storage
//! handle from the same SQLite file, and verifies all state is present.

#[cfg(feature = "sqlite")]
mod sqlite_restart {
    use arbiter_storage::sqlite::SqliteStorage;
    use arbiter_storage::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn full_state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("c001-restart.db");
        let db_url = format!("sqlite:{}", db_path.display());

        // Fixed UUIDs for cross-phase verification.
        let root_agent_id = Uuid::new_v4();
        let child_agent_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        // ── Phase 1: Create state ───────────────────────────────────────
        {
            let storage = SqliteStorage::new(&db_url).await.unwrap();

            // Register root agent with capabilities.
            storage
                .insert_agent(&StoredAgent {
                    id: root_agent_id,
                    owner: "user:alice".into(),
                    model: "claude-opus-4-6".into(),
                    capabilities: vec!["read".into(), "write".into(), "admin".into()],
                    trust_level: StoredTrustLevel::Trusted,
                    created_at: Utc::now(),
                    expires_at: None,
                    active: true,
                })
                .await
                .unwrap();

            // Register child agent.
            storage
                .insert_agent(&StoredAgent {
                    id: child_agent_id,
                    owner: "user:alice".into(),
                    model: "claude-haiku-4-5".into(),
                    capabilities: vec!["read".into()],
                    trust_level: StoredTrustLevel::Basic,
                    created_at: Utc::now(),
                    expires_at: None,
                    active: true,
                })
                .await
                .unwrap();

            // Create delegation: root -> child with scope narrowing.
            storage
                .insert_delegation(&StoredDelegationLink {
                    id: 0,
                    from_agent: root_agent_id,
                    to_agent: child_agent_id,
                    scope_narrowing: vec!["read".into()],
                    created_at: Utc::now(),
                    expires_at: None,
                })
                .await
                .unwrap();

            // Create a session with some progress.
            storage
                .insert_session(&StoredSession {
                    session_id,
                    agent_id: child_agent_id,
                    delegation_chain_snapshot: vec![
                        root_agent_id.to_string(),
                        child_agent_id.to_string(),
                    ],
                    declared_intent: "analyze production logs".into(),
                    authorized_tools: vec!["read_file".into(), "grep".into()],
                    time_limit_secs: 3600,
                    call_budget: 100,
                    calls_made: 42,
                    rate_limit_per_minute: Some(10),
                    rate_window_start: Utc::now(),
                    rate_window_calls: 3,
                    rate_limit_window_secs: 60,
                    data_sensitivity_ceiling: StoredDataSensitivity::Confidential,
                    created_at: Utc::now(),
                    status: StoredSessionStatus::Active,
                })
                .await
                .unwrap();

            // Close the pool, simulating process termination.
            storage.close().await;
        }

        // ── Phase 2: Reopen and verify ──────────────────────────────────
        {
            let storage = SqliteStorage::new(&db_url).await.unwrap();

            // Verify root agent.
            let root = storage.get_agent(root_agent_id).await.unwrap();
            assert_eq!(root.owner, "user:alice");
            assert_eq!(root.model, "claude-opus-4-6");
            assert_eq!(root.capabilities, vec!["read", "write", "admin"]);
            assert_eq!(root.trust_level, StoredTrustLevel::Trusted);
            assert!(root.active);

            // Verify child agent.
            let child = storage.get_agent(child_agent_id).await.unwrap();
            assert_eq!(child.model, "claude-haiku-4-5");
            assert_eq!(child.trust_level, StoredTrustLevel::Basic);
            assert!(child.active);

            // Verify delegation.
            let delegations = storage.get_delegations_from(root_agent_id).await.unwrap();
            assert_eq!(delegations.len(), 1);
            assert_eq!(delegations[0].to_agent, child_agent_id);
            assert_eq!(delegations[0].scope_narrowing, vec!["read"]);

            let incoming = storage.get_delegations_to(child_agent_id).await.unwrap();
            assert_eq!(incoming.len(), 1);
            assert_eq!(incoming[0].from_agent, root_agent_id);

            // Verify session with all its fields.
            let session = storage.get_session(session_id).await.unwrap();
            assert_eq!(session.agent_id, child_agent_id);
            assert_eq!(session.declared_intent, "analyze production logs");
            assert_eq!(session.authorized_tools, vec!["read_file", "grep"]);
            assert_eq!(session.time_limit_secs, 3600);
            assert_eq!(session.call_budget, 100);
            assert_eq!(session.calls_made, 42);
            assert_eq!(session.rate_limit_per_minute, Some(10));
            assert_eq!(session.rate_limit_window_secs, 60);
            assert_eq!(
                session.data_sensitivity_ceiling,
                StoredDataSensitivity::Confidential
            );
            assert_eq!(session.status, StoredSessionStatus::Active);

            // Verify agent listing returns all agents.
            let all_agents = storage.list_agents().await.unwrap();
            assert_eq!(all_agents.len(), 2);

            // Verify delegation listing returns all links.
            let all_delegations = storage.list_delegations().await.unwrap();
            assert_eq!(all_delegations.len(), 1);

            storage.close().await;
        }

        // ── Phase 3: Mutate and re-verify ───────────────────────────────
        {
            let storage = SqliteStorage::new(&db_url).await.unwrap();

            // Deactivate root agent.
            storage.deactivate_agent(root_agent_id).await.unwrap();
            let root = storage.get_agent(root_agent_id).await.unwrap();
            assert!(!root.active);

            // Update child's trust level.
            storage
                .update_trust_level(child_agent_id, StoredTrustLevel::Verified)
                .await
                .unwrap();
            let child = storage.get_agent(child_agent_id).await.unwrap();
            assert_eq!(child.trust_level, StoredTrustLevel::Verified);

            // Update session (increment calls).
            let mut session = storage.get_session(session_id).await.unwrap();
            session.calls_made = 50;
            session.status = StoredSessionStatus::Closed;
            storage.update_session(&session).await.unwrap();

            storage.close().await;
        }

        // ── Phase 4: Verify mutations survived ──────────────────────────
        {
            let storage = SqliteStorage::new(&db_url).await.unwrap();

            let root = storage.get_agent(root_agent_id).await.unwrap();
            assert!(
                !root.active,
                "root should still be deactivated after restart"
            );

            let child = storage.get_agent(child_agent_id).await.unwrap();
            assert_eq!(
                child.trust_level,
                StoredTrustLevel::Verified,
                "trust level update should survive restart"
            );

            let session = storage.get_session(session_id).await.unwrap();
            assert_eq!(
                session.calls_made, 50,
                "calls_made update should survive restart"
            );
            assert_eq!(
                session.status,
                StoredSessionStatus::Closed,
                "status update should survive restart"
            );

            storage.close().await;
        }
    }
}
