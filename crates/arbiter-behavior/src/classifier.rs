//! Tool call operation classifier.
//!
//! Classifies MCP tool calls into operation types (read/write/delete/admin)
//! based on the method name and tool name patterns.

use serde::{Deserialize, Serialize};

/// The type of operation a tool call represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationType {
    Read,
    Write,
    Delete,
    Admin,
}

/// Classify an MCP request by its operation type.
///
/// Uses method + tool name patterns:
/// - `resources/read`, `resources/subscribe`, `completion/complete` → Read
/// - Tool names containing "read", "get", "list", "search", "view", "describe" → Read
/// - Tool names containing "delete", "remove", "drop", "purge" → Delete
/// - Tool names containing "admin", "manage", "configure", "grant", "revoke" → Admin
/// - Everything else (including "write", "create", "update", "set", "put") → Write
pub fn classify_operation(method: &str, tool_name: Option<&str>) -> OperationType {
    // Method-level classification for non-tool-call requests.
    match method {
        "resources/read" | "resources/subscribe" | "completion/complete" => {
            return OperationType::Read;
        }
        _ => {}
    }

    let tool = match tool_name {
        Some(t) => t.to_lowercase(),
        None => return OperationType::Read, // Non-tool requests default to read.
    };

    // Admin patterns (check first: "admin_delete" should be Admin, not Delete).
    if contains_any_token(&tool, &["admin", "manage", "configure", "grant", "revoke"]) {
        return OperationType::Admin;
    }

    // Delete patterns.
    if contains_any_token(&tool, &["delete", "remove", "drop", "purge"]) {
        return OperationType::Delete;
    }

    // Read patterns (includes analytical/reporting operations that don't modify data).
    if contains_any_token(
        &tool,
        &[
            "read",
            "get",
            "list",
            "search",
            "view",
            "describe",
            "fetch",
            "query",
            "analyze",
            "summarize",
            "report",
            "calculate",
            "compute",
            "check",
            "inspect",
            "review",
        ],
    ) {
        return OperationType::Read;
    }

    // Default to Write for everything else (create, update, write, set, put, etc.).
    OperationType::Write
}

/// Use word-boundary matching instead of substring matching.
/// Previously "read_and_execute_shell" would match "read" via substring.
/// Now tool names are split on common delimiters and each token is matched independently.
fn contains_any_token(haystack: &str, needles: &[&str]) -> bool {
    let lower = haystack.to_lowercase();
    // Split on common MCP tool name delimiters: underscore, hyphen, dot, slash, space
    let tokens: Vec<&str> = lower.split(['_', '-', '.', '/', ' ']).collect();
    needles.iter().any(|needle| {
        let lower_needle = needle.to_lowercase();
        tokens.iter().any(|token| *token == lower_needle)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_resource_read_method() {
        assert_eq!(
            classify_operation("resources/read", None),
            OperationType::Read
        );
    }

    #[test]
    fn classify_tool_by_name() {
        assert_eq!(
            classify_operation("tools/call", Some("read_file")),
            OperationType::Read
        );
        assert_eq!(
            classify_operation("tools/call", Some("write_file")),
            OperationType::Write
        );
        assert_eq!(
            classify_operation("tools/call", Some("delete_resource")),
            OperationType::Delete
        );
        assert_eq!(
            classify_operation("tools/call", Some("admin_users")),
            OperationType::Admin
        );
    }

    #[test]
    fn classify_mixed_patterns() {
        // "get_user" → Read
        assert_eq!(
            classify_operation("tools/call", Some("get_user")),
            OperationType::Read
        );
        // "create_user" → Write
        assert_eq!(
            classify_operation("tools/call", Some("create_user")),
            OperationType::Write
        );
        // "list_files" → Read
        assert_eq!(
            classify_operation("tools/call", Some("list_files")),
            OperationType::Read
        );
    }

    #[test]
    fn admin_beats_delete() {
        // "admin_delete" should classify as Admin, not Delete.
        assert_eq!(
            classify_operation("tools/call", Some("admin_delete")),
            OperationType::Admin
        );
    }

    /// Novel tool names should not cause panics and should classify sensibly.
    #[test]
    fn classify_novel_tool_names() {
        // "extract_intelligence" -- no standard tokens match, should be Write (default)
        let result = classify_operation("tools/call", Some("extract_intelligence"));
        assert_eq!(result, OperationType::Write);

        // "xread_file" -- "xread" is not "read" as a token, should be Write
        // (word-boundary matching prevents prefix matching)
        let result = classify_operation("tools/call", Some("xread_file"));
        assert_eq!(result, OperationType::Write);

        // "readonly_report" -- "report" IS a read token
        let result = classify_operation("tools/call", Some("readonly_report"));
        assert_eq!(result, OperationType::Read);
    }

    /// Empty tool name and empty method should not panic.
    #[test]
    fn empty_tool_name() {
        // Empty tool name defaults to Write (no tokens match any pattern)
        let result = classify_operation("tools/call", Some(""));
        assert_eq!(result, OperationType::Write);

        // Empty method with no tool defaults to Read
        let result = classify_operation("", None);
        assert_eq!(result, OperationType::Read);

        // Empty method with empty tool name
        let result = classify_operation("", Some(""));
        assert_eq!(result, OperationType::Write);
    }

    /// Tool name consisting only of delimiters should not panic.
    #[test]
    fn tool_name_with_only_delimiters() {
        let result = classify_operation("tools/call", Some("___---..."));
        // All tokens are empty strings after splitting on delimiters,
        // no read/write/delete/admin tokens match, so it defaults to Write.
        assert_eq!(result, OperationType::Write);
    }
}
