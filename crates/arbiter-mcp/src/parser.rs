//! MCP request body parser.
//!
//! Accepts raw bytes from an HTTP request body and determines whether
//! the payload is MCP JSON-RPC traffic. Non-MCP payloads are passed
//! through without modification.

use crate::context::{McpContext, McpRequest};
use crate::jsonrpc::JsonRpcRequest;

use thiserror::Error;

/// Errors from attempting to parse MCP JSON-RPC bodies.
#[derive(Debug, Error)]
pub enum McpParseError {
    /// The body was not valid JSON.
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The JSON was valid but not a valid JSON-RPC 2.0 request.
    #[error("invalid JSON-RPC request: {reason}")]
    InvalidJsonRpc {
        /// What went wrong.
        reason: String,
    },
}

/// Result of attempting to parse an HTTP body as MCP JSON-RPC.
#[derive(Debug)]
pub enum ParseResult {
    /// One or more valid MCP JSON-RPC requests were found.
    Mcp(McpContext),
    /// The body is not MCP JSON-RPC; pass through unmodified.
    NonMcp,
}

/// Parse a request body, returning [`ParseResult::Mcp`] if it contains
/// valid JSON-RPC 2.0 requests, or [`ParseResult::NonMcp`] for anything
/// else (plain text, HTML, non-JSON-RPC JSON, etc.).
///
/// Malformed JSON or invalid JSON-RPC is treated as non-MCP traffic
/// (passthrough) rather than an error, because the proxy forwards all
/// traffic and only *annotates* MCP requests.
pub fn parse_mcp_body(body: &[u8]) -> ParseResult {
    // Empty body is not MCP.
    if body.is_empty() {
        return ParseResult::NonMcp;
    }

    // Try to parse as JSON. If it fails, it's not MCP.
    let json_value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return ParseResult::NonMcp,
    };

    match &json_value {
        // Batch request (JSON array).
        serde_json::Value::Array(arr) => {
            // Cap batch size to prevent a single HTTP request from triggering
            // unbounded policy evaluations and audit entries.
            const MAX_BATCH_SIZE: usize = 100;
            if arr.len() > MAX_BATCH_SIZE {
                tracing::warn!(
                    batch_size = arr.len(),
                    max = MAX_BATCH_SIZE,
                    "batch exceeds maximum size, treating as NonMcp"
                );
                return ParseResult::NonMcp;
            }

            let mut requests = Vec::new();
            let mut _has_jsonrpc_items = false;
            for item in arr {
                // Check if the item looks like a JSON-RPC attempt (has a "jsonrpc" field).
                let looks_like_jsonrpc = item.get("jsonrpc").is_some() || item.get("method").is_some();
                if looks_like_jsonrpc {
                    _has_jsonrpc_items = true;
                }
                if let Some(mcp_req) = try_parse_single(item) {
                    requests.push(mcp_req);
                } else if looks_like_jsonrpc {
                    // An item that looks like JSON-RPC but failed parsing must
                    // cause the entire batch to be rejected. Otherwise the raw
                    // body (containing the unparsed item) would be forwarded to
                    // the upstream while policy only evaluated the parsed subset.
                    tracing::warn!(
                        "batch contains unparseable JSON-RPC item; rejecting entire batch"
                    );
                    return ParseResult::NonMcp;
                }
            }
            if requests.is_empty() {
                ParseResult::NonMcp
            } else {
                ParseResult::Mcp(McpContext { requests })
            }
        }
        // Single request (JSON object).
        serde_json::Value::Object(_) => match try_parse_single(&json_value) {
            Some(mcp_req) => ParseResult::Mcp(McpContext {
                requests: vec![mcp_req],
            }),
            None => {
                // If the body contains a "jsonrpc" or "method" field, it's an
                // attempted JSON-RPC request that failed validation. Treat it
                // as NonMcp so the handler's NonMcp-with-policies check denies
                // it rather than silently passing it through.
                let looks_like_jsonrpc = json_value.get("jsonrpc").is_some()
                    || json_value.get("method").is_some();
                if looks_like_jsonrpc {
                    tracing::warn!("malformed JSON-RPC detected: has jsonrpc/method field but failed validation");
                }
                ParseResult::NonMcp
            }
        },
        // Anything else is not JSON-RPC.
        _ => ParseResult::NonMcp,
    }
}

// Validate tool names to prevent unicode normalization attacks.
// Only ASCII alphanumeric characters plus common delimiters are allowed.
fn is_valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
}

/// Allowed MCP method strings. Requests with methods not in this list
/// are rejected at parse time rather than forwarded opaquely.
const ALLOWED_MCP_METHODS: &[&str] = &[
    "tools/call",
    "tools/list",
    "resources/read",
    "resources/list",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/get",
    "prompts/list",
    "completion/complete",
    "logging/setLevel",
    "initialize",
    "ping",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/roots/list_changed",
    "notifications/resources/updated",
    "notifications/resources/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
];

/// Maximum size for tool arguments in bytes.
const MAX_ARGUMENTS_SIZE: usize = 64 * 1024; // 64 KB

/// Attempt to parse a single JSON value as a JSON-RPC 2.0 request and
/// extract MCP-specific fields.
fn try_parse_single(value: &serde_json::Value) -> Option<McpRequest> {
    let rpc: JsonRpcRequest = serde_json::from_value(value.clone()).ok()?;

    if !rpc.is_valid_version() {
        return None;
    }

    // Validate id field: JSON-RPC 2.0 spec allows string, number, or null only.
    // Reject arrays, objects, and oversized strings.
    if let Some(ref id) = rpc.id {
        match id {
            serde_json::Value::String(s) if s.len() > 256 => {
                tracing::warn!(len = s.len(), "JSON-RPC id string too long, rejecting");
                return None;
            }
            serde_json::Value::String(_) | serde_json::Value::Number(_) | serde_json::Value::Null => {}
            _ => {
                tracing::warn!("JSON-RPC id must be string, number, or null; rejecting");
                return None;
            }
        }
    }

    // Reject methods not in the MCP allowlist.
    if !ALLOWED_MCP_METHODS.contains(&rpc.method.as_str()) {
        tracing::warn!(method = %rpc.method, "rejected unknown MCP method");
        return None;
    }

    let mut tool_name = None;
    let mut arguments = None;
    let mut resource_uri = None;

    if let Some(params) = &rpc.params {
        // tools/call → extract name and arguments
        if rpc.method == "tools/call" {
            tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|name| is_valid_tool_name(name))
                .map(String::from);

            // Bound arguments size to prevent memory exhaustion.
            if let Some(args) = params.get("arguments") {
                let size = args.to_string().len();
                if size > MAX_ARGUMENTS_SIZE {
                    tracing::warn!(size, max = MAX_ARGUMENTS_SIZE, "arguments exceed size limit, dropping");
                } else {
                    arguments = Some(args.clone());
                }
            }
        }

        // resources/read, resources/subscribe → extract uri
        if rpc.method == "resources/read" || rpc.method == "resources/subscribe" {
            if let Some(uri_str) = params.get("uri").and_then(|v| v.as_str()) {
                // Validate URI scheme: only https, http (for localhost), and custom app schemes.
                // Block dangerous schemes (file://, data:, javascript:).
                let is_safe = uri_str.starts_with("https://")
                    || uri_str.starts_with("http://")
                    || !uri_str.contains("://")  // relative URIs are ok
                    || uri_str.starts_with("urn:");
                let is_dangerous = uri_str.starts_with("file://")
                    || uri_str.starts_with("data:")
                    || uri_str.starts_with("javascript:");
                if is_dangerous || (!is_safe && uri_str.len() > 2048) {
                    tracing::warn!(uri = uri_str, "rejected dangerous or oversized resource_uri");
                } else {
                    resource_uri = Some(uri_str.to_string());
                }
            }
        }
    }

    Some(McpRequest {
        id: rpc.id,
        method: rpc.method,
        tool_name,
        arguments,
        resource_uri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_tool_call() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/etc/hosts"
                }
            }
        }))
        .unwrap();

        match parse_mcp_body(&body) {
            ParseResult::Mcp(ctx) => {
                assert_eq!(ctx.requests.len(), 1);
                let req = &ctx.requests[0];
                assert_eq!(req.method, "tools/call");
                assert_eq!(req.tool_name.as_deref(), Some("read_file"));
                assert!(req.arguments.is_some());
                let args = req.arguments.as_ref().unwrap();
                assert_eq!(
                    args.get("path").and_then(|v| v.as_str()),
                    Some("/etc/hosts")
                );
            }
            ParseResult::NonMcp => panic!("expected Mcp result"),
        }
    }

    #[test]
    fn parse_resource_read() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {
                "uri": "https://api.example.com/workspace/README.md"
            }
        }))
        .unwrap();

        match parse_mcp_body(&body) {
            ParseResult::Mcp(ctx) => {
                assert_eq!(ctx.requests.len(), 1);
                let req = &ctx.requests[0];
                assert_eq!(req.method, "resources/read");
                assert_eq!(
                    req.resource_uri.as_deref(),
                    Some("https://api.example.com/workspace/README.md")
                );
                assert!(req.tool_name.is_none());
            }
            ParseResult::NonMcp => panic!("expected Mcp result"),
        }
    }

    #[test]
    fn non_mcp_json_passthrough() {
        // Valid JSON but not JSON-RPC.
        let body = serde_json::to_vec(&json!({"hello": "world"})).unwrap();
        assert!(matches!(parse_mcp_body(&body), ParseResult::NonMcp));
    }

    #[test]
    fn non_json_passthrough() {
        let body = b"this is plain text, not JSON";
        assert!(matches!(parse_mcp_body(body), ParseResult::NonMcp));
    }

    #[test]
    fn empty_body_passthrough() {
        assert!(matches!(parse_mcp_body(b""), ParseResult::NonMcp));
    }

    #[test]
    fn malformed_json_rpc_passthrough() {
        // Valid JSON, has jsonrpc field but wrong version.
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "1.0",
            "method": "tools/call",
            "id": 1
        }))
        .unwrap();
        assert!(matches!(parse_mcp_body(&body), ParseResult::NonMcp));
    }

    #[test]
    fn batch_request_parsed() {
        let body = serde_json::to_vec(&json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "tool_a",
                    "arguments": {}
                }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": {
                    "uri": "https://api.example.com/data.csv"
                }
            }
        ]))
        .unwrap();

        match parse_mcp_body(&body) {
            ParseResult::Mcp(ctx) => {
                assert_eq!(ctx.requests.len(), 2);
                assert_eq!(ctx.requests[0].tool_name.as_deref(), Some("tool_a"));
                assert_eq!(
                    ctx.requests[1].resource_uri.as_deref(),
                    Some("https://api.example.com/data.csv")
                );
                // Test convenience methods.
                assert!(ctx.has_tool_calls());
                let tools: Vec<&str> = ctx.tool_names().collect();
                assert_eq!(tools, vec!["tool_a"]);
                let uris: Vec<&str> = ctx.resource_uris().collect();
                assert_eq!(uris, vec!["https://api.example.com/data.csv"]);
            }
            ParseResult::NonMcp => panic!("expected Mcp result for batch"),
        }
    }

    // -----------------------------------------------------------------------
    // Recursive JSON-RPC in params must not be reinterpreted
    // -----------------------------------------------------------------------

    /// A JSON-RPC request whose `params.arguments` contains another
    /// JSON-RPC-looking structure must NOT produce two parsed requests.
    /// The nested structure is opaque argument data, not a separate call.
    #[test]
    fn nested_jsonrpc_in_params_not_reinterpreted() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "proxy_call",
                "arguments": {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 99,
                    "params": {
                        "name": "read_file",
                        "arguments": {
                            "path": "/etc/shadow"
                        }
                    }
                }
            }
        }))
        .unwrap();

        match parse_mcp_body(&body) {
            ParseResult::Mcp(ctx) => {
                assert_eq!(
                    ctx.requests.len(),
                    1,
                    "nested JSON-RPC in arguments must not be parsed as a separate request, \
                     got {} requests",
                    ctx.requests.len()
                );
                let req = &ctx.requests[0];
                assert_eq!(req.method, "tools/call");
                assert_eq!(req.tool_name.as_deref(), Some("proxy_call"));
                // The nested JSON-RPC structure should be preserved as opaque arguments.
                let args = req.arguments.as_ref().expect("arguments must be present");
                assert_eq!(
                    args.get("method").and_then(|v| v.as_str()),
                    Some("tools/call"),
                    "nested JSON-RPC fields must be preserved as argument data"
                );
            }
            ParseResult::NonMcp => panic!("expected Mcp result"),
        }
    }
}
