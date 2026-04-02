//! Typed MCP context extracted from parsed JSON-RPC requests.

use serde::{Deserialize, Serialize};

/// Aggregated MCP context from one or more JSON-RPC requests in a single
/// HTTP request body. Designed to be inserted into request extensions
/// alongside OAuth claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContext {
    /// Individual MCP requests extracted from the body.
    pub requests: Vec<McpRequest>,
}

/// A single parsed MCP request with extracted fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    /// The JSON-RPC request id, if present.
    #[serde(default)]
    pub id: Option<serde_json::Value>,

    /// The JSON-RPC method (e.g. `"tools/call"`, `"resources/read"`,
    /// `"completion/complete"`).
    pub method: String,

    /// For `tools/call` requests, the tool name from `params.name`.
    #[serde(default)]
    pub tool_name: Option<String>,

    /// For `tools/call` requests, the arguments from `params.arguments`.
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,

    /// For `resources/read` or `resources/subscribe` requests, the
    /// resource URI from `params.uri`.
    #[serde(default)]
    pub resource_uri: Option<String>,
}

impl McpContext {
    /// Returns `true` if any request in this context is a tool call.
    pub fn has_tool_calls(&self) -> bool {
        self.requests.iter().any(|r| r.tool_name.is_some())
    }

    /// Returns an iterator over all tool names in this context.
    pub fn tool_names(&self) -> impl Iterator<Item = &str> {
        self.requests.iter().filter_map(|r| r.tool_name.as_deref())
    }

    /// Returns an iterator over all resource URIs in this context.
    pub fn resource_uris(&self) -> impl Iterator<Item = &str> {
        self.requests
            .iter()
            .filter_map(|r| r.resource_uri.as_deref())
    }
}
