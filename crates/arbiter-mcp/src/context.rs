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

impl McpRequest {
    /// Reconstruct a valid JSON-RPC 2.0 request from the parsed fields.
    pub fn to_jsonrpc(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("jsonrpc".into(), serde_json::Value::String("2.0".into()));
        if let Some(ref id) = self.id {
            obj.insert("id".into(), id.clone());
        }
        obj.insert("method".into(), serde_json::Value::String(self.method.clone()));

        let mut params = serde_json::Map::new();
        if let Some(ref name) = self.tool_name {
            params.insert("name".into(), serde_json::Value::String(name.clone()));
        }
        if let Some(ref args) = self.arguments {
            params.insert("arguments".into(), args.clone());
        }
        if let Some(ref uri) = self.resource_uri {
            params.insert("uri".into(), serde_json::Value::String(uri.clone()));
        }
        if !params.is_empty() {
            obj.insert("params".into(), serde_json::Value::Object(params));
        }
        serde_json::Value::Object(obj)
    }
}

impl McpContext {
    /// Reconstruct a canonical JSON body from the parsed MCP requests.
    /// This eliminates parser differentials (duplicate keys, encoding tricks)
    /// by rebuilding the JSON-RPC envelope from the extracted, validated fields.
    pub fn to_canonical_body(&self) -> Vec<u8> {
        if self.requests.len() == 1 {
            serde_json::to_vec(&self.requests[0].to_jsonrpc())
                .unwrap_or_default()
        } else {
            let batch: Vec<serde_json::Value> = self
                .requests
                .iter()
                .map(|r| r.to_jsonrpc())
                .collect();
            serde_json::to_vec(&batch).unwrap_or_default()
        }
    }

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
