//! Session middleware utilities for proxy integration.
//!
//! Provides session ID parsing from the `X-Arbiter-Session` header and
//! error-to-status-code mapping. Session constraint validation is performed
//! directly by the handler stages in `crates/arbiter/src/stages/`.

use uuid::Uuid;

use crate::error::SessionError;

/// HTTP status code that should be returned for each session error type.
pub fn status_code_for_error(err: &SessionError) -> u16 {
    match err {
        SessionError::NotFound(_) => 404,
        SessionError::Expired(_) => 408,
        SessionError::BudgetExceeded { .. } => 429,
        SessionError::ToolNotAuthorized { .. } => 403,
        SessionError::AlreadyClosed(_) => 410,
        SessionError::RateLimited { .. } => 429,
        SessionError::TooManySessions { .. } => 429,
        SessionError::AgentMismatch { .. } => 403,
        SessionError::StorageWriteThrough { .. } => 503,
    }
}

/// Extract a session ID from the `X-Arbiter-Session` header value.
///
/// Returns `None` if the header is missing or not a valid UUID.
pub fn parse_session_header(header_value: &str) -> Option<Uuid> {
    Uuid::parse_str(header_value.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_session_header_valid() {
        let id = Uuid::new_v4();
        assert_eq!(parse_session_header(&id.to_string()), Some(id));
    }

    #[test]
    fn parse_session_header_invalid() {
        assert_eq!(parse_session_header("not-a-uuid"), None);
        assert_eq!(parse_session_header(""), None);
    }

    /// Test that each SessionError variant maps to the correct HTTP status code.
    #[test]
    fn status_code_for_all_error_variants() {
        let id = Uuid::new_v4();

        assert_eq!(status_code_for_error(&SessionError::NotFound(id)), 404);
        assert_eq!(status_code_for_error(&SessionError::Expired(id)), 408);
        assert_eq!(
            status_code_for_error(&SessionError::BudgetExceeded {
                session_id: id,
                limit: 10,
                used: 10,
            }),
            429
        );
        assert_eq!(
            status_code_for_error(&SessionError::ToolNotAuthorized {
                session_id: id,
                tool: "delete".into(),
            }),
            403
        );
        assert_eq!(status_code_for_error(&SessionError::AlreadyClosed(id)), 410);
        assert_eq!(
            status_code_for_error(&SessionError::RateLimited {
                session_id: id,
                limit_per_minute: 5,
            }),
            429
        );
        assert_eq!(
            status_code_for_error(&SessionError::TooManySessions {
                agent_id: id.to_string(),
                max: 10,
                current: 10,
            }),
            429
        );
    }

    /// Whitespace-padded UUIDs should be accepted (the trim() in parse_session_header).
    #[test]
    fn parse_session_header_with_whitespace() {
        let id = Uuid::new_v4();
        let padded = format!("  {}  ", id);
        assert_eq!(
            parse_session_header(&padded),
            Some(id),
            "whitespace-padded UUID should be parsed correctly"
        );
    }
}
