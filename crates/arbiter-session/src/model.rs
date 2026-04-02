use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a task session.
pub type SessionId = Uuid;

/// Maximum data sensitivity level allowed in this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

fn default_rate_limit_window_secs() -> u64 {
    60
}

/// The status of a task session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Closed,
    Expired,
}

/// A task session scoping what an agent is allowed to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSession {
    /// Unique session identifier.
    pub session_id: SessionId,

    /// The agent operating within this session.
    pub agent_id: Uuid,

    /// Snapshot of the delegation chain at session creation time.
    pub delegation_chain_snapshot: Vec<String>,

    /// The declared intent for this session (free-form string).
    pub declared_intent: String,

    /// Tools this session is authorized to call (from policy evaluation).
    pub authorized_tools: Vec<String>,

    /// Maximum duration for this session.
    pub time_limit: chrono::Duration,

    /// Maximum number of tool calls allowed.
    pub call_budget: u64,

    /// Number of tool calls made so far.
    pub calls_made: u64,

    /// Per-minute rate limit. `None` means no rate limit (only lifetime budget applies).
    #[serde(default)]
    pub rate_limit_per_minute: Option<u64>,

    /// Start of the current rate-limit window.
    #[serde(default = "Utc::now")]
    pub rate_window_start: DateTime<Utc>,

    /// Number of calls within the current rate-limit window.
    #[serde(default)]
    pub rate_window_calls: u64,

    /// Duration of the rate-limit window in seconds. Defaults to 60.
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,

    /// Maximum data sensitivity this session may access.
    pub data_sensitivity_ceiling: DataSensitivity,

    /// When this session was created.
    pub created_at: DateTime<Utc>,

    /// Current session status.
    pub status: SessionStatus,
}

impl TaskSession {
    /// Returns true if the session has exceeded its time limit.
    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now() - self.created_at;
        elapsed > self.time_limit || self.status == SessionStatus::Expired
    }

    /// Returns true if the session's call budget is exhausted.
    pub fn is_budget_exceeded(&self) -> bool {
        self.calls_made >= self.call_budget
    }

    /// Returns true if the given tool is authorized in this session.
    pub fn is_tool_authorized(&self, tool_name: &str) -> bool {
        // Empty authorized_tools means "all tools allowed" (wide-open session).
        self.authorized_tools.is_empty() || self.authorized_tools.iter().any(|t| t == tool_name)
    }

    /// Returns true if the session is active and usable.
    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active && !self.is_expired() && !self.is_budget_exceeded()
    }

    /// Check and update the rate-limit window. Returns true if the call
    /// should be rejected due to rate limiting.
    pub fn check_rate_limit(&mut self) -> bool {
        let limit = match self.rate_limit_per_minute {
            Some(l) => l,
            None => return false,
        };
        let now = Utc::now();
        let elapsed = now - self.rate_window_start;
        if elapsed >= chrono::Duration::seconds(self.rate_limit_window_secs as i64) {
            // New window. Reset.
            self.rate_window_start = now;
            self.rate_window_calls = 1;
            false
        } else if self.rate_window_calls >= limit {
            true // rate limited
        } else {
            self.rate_window_calls += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> TaskSession {
        TaskSession {
            session_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_chain_snapshot: vec![],
            declared_intent: "read files".into(),
            authorized_tools: vec!["read_file".into(), "list_dir".into()],
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
        }
    }

    #[test]
    fn active_session_is_usable() {
        let session = test_session();
        assert!(session.is_active());
        assert!(!session.is_expired());
        assert!(!session.is_budget_exceeded());
    }

    #[test]
    fn tool_authorization_check() {
        let session = test_session();
        assert!(session.is_tool_authorized("read_file"));
        assert!(session.is_tool_authorized("list_dir"));
        assert!(!session.is_tool_authorized("delete_file"));
    }

    #[test]
    fn budget_exhaustion() {
        let mut session = test_session();
        session.calls_made = 100;
        assert!(session.is_budget_exceeded());
        assert!(!session.is_active());
    }

    #[test]
    fn expired_session() {
        let mut session = test_session();
        session.created_at = Utc::now() - chrono::Duration::hours(2);
        assert!(session.is_expired());
        assert!(!session.is_active());
    }

    #[test]
    fn rate_limit_none_always_allows() {
        let mut session = test_session();
        assert_eq!(session.rate_limit_per_minute, None);
        for _ in 0..1000 {
            assert!(!session.check_rate_limit(), "None rate limit must never deny");
        }
        // With no rate limit configured, window calls should stay at zero
        // because the method returns early before touching the counter.
        assert_eq!(session.rate_window_calls, 0);
    }

    #[test]
    fn rate_limit_under_threshold_allows() {
        let mut session = test_session();
        session.rate_limit_per_minute = Some(5);
        for i in 0..4 {
            assert!(
                !session.check_rate_limit(),
                "Call {} should be allowed under threshold of 5",
                i + 1
            );
        }
        assert_eq!(session.rate_window_calls, 4);
    }

    #[test]
    fn rate_limit_at_threshold_denies() {
        let mut session = test_session();
        session.rate_limit_per_minute = Some(3);
        // Simulate that the window already has 3 calls recorded.
        session.rate_window_calls = 3;
        assert!(
            session.check_rate_limit(),
            "Must deny when calls already at limit"
        );
    }

    #[test]
    fn rate_limit_window_reset() {
        let mut session = test_session();
        session.rate_limit_per_minute = Some(5);
        // Push the window start 61 seconds into the past so the window is expired.
        session.rate_window_start = Utc::now() - chrono::Duration::seconds(61);
        session.rate_window_calls = 5; // was at limit in the old window

        let denied = session.check_rate_limit();
        assert!(!denied, "New window should allow the call");
        assert_eq!(
            session.rate_window_calls, 1,
            "Window must reset to 1 after a new window starts"
        );
    }

    #[test]
    fn empty_authorized_tools_allows_all() {
        let mut session = test_session();
        session.authorized_tools = vec![];
        assert!(
            session.is_tool_authorized("anything_goes"),
            "Empty authorized_tools must allow any tool"
        );
        assert!(
            session.is_tool_authorized("delete_file"),
            "Empty authorized_tools must allow any tool"
        );
        assert!(
            session.is_tool_authorized(""),
            "Empty authorized_tools must allow even empty-string tool name"
        );
    }

    #[test]
    fn closed_session_not_active() {
        let mut session = test_session();
        session.status = SessionStatus::Closed;
        assert!(
            !session.is_active(),
            "Closed session must not be considered active"
        );
        // Confirm it is NOT because of expiry or budget.
        assert!(!session.is_expired());
        assert!(!session.is_budget_exceeded());
    }

    #[test]
    fn budget_boundary_at_limit_minus_one() {
        let mut session = test_session();
        session.calls_made = session.call_budget - 1;
        assert!(
            !session.is_budget_exceeded(),
            "One call below budget must not be exceeded"
        );
        assert!(
            session.is_active(),
            "Session at budget - 1 should still be active"
        );
    }

    /// A session with call_budget=0 must report budget exceeded immediately.
    #[test]
    fn zero_budget_is_exceeded() {
        let mut session = test_session();
        session.call_budget = 0;
        session.calls_made = 0;
        assert!(
            session.is_budget_exceeded(),
            "0 >= 0 means budget is exceeded"
        );
        assert!(
            !session.is_active(),
            "zero-budget session should not be active"
        );
    }

    /// When elapsed == window duration exactly, the window should reset.
    #[test]
    fn check_rate_limit_at_exact_window_boundary() {
        let mut session = test_session();
        session.rate_limit_per_minute = Some(5);
        // Set the window start exactly `rate_limit_window_secs` ago.
        session.rate_window_start =
            Utc::now() - chrono::Duration::seconds(session.rate_limit_window_secs as i64);
        session.rate_window_calls = 5; // was at limit in old window

        let denied = session.check_rate_limit();
        assert!(!denied, "exact window boundary should reset and allow");
        assert_eq!(
            session.rate_window_calls, 1,
            "window must reset to 1 after boundary reset"
        );
    }
}
