use proptest::prelude::*;

use arbiter_session::store::{CreateSessionRequest, SessionStore};
use arbiter_session::{DataSensitivity, SessionError, SessionStatus, TaskSession};
use chrono::Utc;
use uuid::Uuid;

/// Build a CreateSessionRequest with the given parameters.
fn make_request(
    intent: &str,
    tools: Vec<String>,
    budget: u64,
    time_limit: chrono::Duration,
) -> CreateSessionRequest {
    CreateSessionRequest {
        agent_id: Uuid::new_v4(),
        delegation_chain_snapshot: vec![],
        declared_intent: intent.to_string(),
        authorized_tools: tools,
        authorized_credentials: vec![],
        time_limit,
        call_budget: budget,
        rate_limit_per_minute: None,
        rate_limit_window_secs: 60,
        data_sensitivity_ceiling: DataSensitivity::Internal,
    }
}

/// Strategy for generating tool names: ASCII alphanumeric + underscore, 1..32 chars.
fn tool_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,31}"
}

/// Strategy for generating intent strings.
fn intent_strategy() -> impl Strategy<Value = String> {
    "[a-z ]{1,64}"
}

proptest! {
    /// Creating a session and immediately getting it always returns Active status.
    #[test]
    fn create_then_get_is_active(
        intent in intent_strategy(),
        budget in 1u64..100,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = SessionStore::new();
            let req = make_request(&intent, vec![], budget, chrono::Duration::hours(1));
            let session = store.create(req).await;

            prop_assert_eq!(session.status, SessionStatus::Active);
            prop_assert_eq!(session.calls_made, 0);
            prop_assert!(session.is_active());

            let retrieved = store.get(session.session_id).await.unwrap();
            prop_assert_eq!(retrieved.status, SessionStatus::Active);
            prop_assert_eq!(retrieved.session_id, session.session_id);
            Ok(())
        })?;
    }

    /// Budget enforcement: after exactly N use_session calls where N = budget,
    /// the next call must fail with BudgetExceeded.
    #[test]
    fn budget_enforcement(budget in 1u64..20) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = SessionStore::new();
            // Empty authorized_tools means all tools are allowed.
            let req = make_request("test intent", vec![], budget, chrono::Duration::hours(1));
            let session = store.create(req).await;

            // Use up the budget with valid calls.
            for i in 0..budget {
                let result = store.use_session(session.session_id, "any_tool", None).await;
                prop_assert!(
                    result.is_ok(),
                    "call {} of {} should succeed, got: {:?}", i + 1, budget, result
                );
            }

            // The next call must fail with BudgetExceeded.
            let result = store.use_session(session.session_id, "any_tool", None).await;
            prop_assert!(
                matches!(result, Err(SessionError::BudgetExceeded { .. })),
                "call {} should be BudgetExceeded, got: {:?}", budget + 1, result
            );

            Ok(())
        })?;
    }

    /// Tool whitelist: only whitelisted tools are authorized (for any tool name string).
    #[test]
    fn tool_whitelist_enforcement(
        allowed_tool in tool_name_strategy(),
        disallowed_tool in tool_name_strategy(),
    ) {
        // Skip when the two tool names happen to be the same.
        prop_assume!(allowed_tool != disallowed_tool);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = SessionStore::new();
            let req = make_request(
                "test",
                vec![allowed_tool.clone()],
                100,
                chrono::Duration::hours(1),
            );
            let session = store.create(req).await;

            // Allowed tool should succeed.
            let result = store.use_session(session.session_id, &allowed_tool, None).await;
            prop_assert!(result.is_ok(), "allowed tool should succeed: {:?}", result);

            // Disallowed tool should be rejected.
            let result = store.use_session(session.session_id, &disallowed_tool, None).await;
            prop_assert!(
                matches!(result, Err(SessionError::ToolNotAuthorized { .. })),
                "disallowed tool '{}' should be rejected, got: {:?}", disallowed_tool, result
            );

            Ok(())
        })?;
    }

    /// Session with minimum duration expires after 1 second.
    #[test]
    fn short_duration_session_is_expired(intent in intent_strategy()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = SessionStore::new();
            // Minimum duration is clamped to 1s; use that.
            let req = make_request(&intent, vec![], 100, chrono::Duration::seconds(1));
            let session = store.create(req).await;

            // Wait for the session to expire.
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

            let result = store.use_session(session.session_id, "any_tool", None).await;
            prop_assert!(
                matches!(result, Err(SessionError::Expired(_))),
                "expired session should return error, got: {:?}", result
            );

            Ok(())
        })?;
    }

    /// The TaskSession model's is_tool_authorized is consistent with the whitelist:
    /// if a tool is in authorized_tools, it is authorized; if not, it is not
    /// (unless authorized_tools is empty, meaning all tools are allowed).
    #[test]
    fn model_tool_authorization_property(
        tool_a in tool_name_strategy(),
        tool_b in tool_name_strategy(),
    ) {
        let session = TaskSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: "test".into(),
            authorized_tools: vec![tool_a.clone()],
            authorized_credentials: vec![],
            time_limit: chrono::Duration::hours(1),
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: None,
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: DataSensitivity::Internal,
            created_at: Utc::now(),
            status: SessionStatus::Active,
        };

        // tool_a is always authorized because it is in the list.
        prop_assert!(session.is_tool_authorized(&tool_a));

        // tool_b is only authorized if it equals tool_a.
        if tool_a == tool_b {
            prop_assert!(session.is_tool_authorized(&tool_b));
        } else {
            prop_assert!(!session.is_tool_authorized(&tool_b));
        }
    }

    /// Empty authorized_tools means all tools are allowed.
    #[test]
    fn empty_whitelist_allows_any_tool(tool in tool_name_strategy()) {
        let session = TaskSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: "test".into(),
            authorized_tools: vec![],
            authorized_credentials: vec![],
            time_limit: chrono::Duration::hours(1),
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: None,
            rate_window_start: Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: DataSensitivity::Internal,
            created_at: Utc::now(),
            status: SessionStatus::Active,
        };

        prop_assert!(
            session.is_tool_authorized(&tool),
            "empty authorized_tools should allow any tool, but '{}' was rejected", tool
        );
    }
}
