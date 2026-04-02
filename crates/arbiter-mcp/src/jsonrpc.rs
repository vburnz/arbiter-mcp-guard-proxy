//! JSON-RPC 2.0 message types used by MCP.

use serde::{Deserialize, Serialize};

/// A single JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,

    /// Request identifier (number, string, or null for notifications).
    #[serde(default)]
    pub id: Option<serde_json::Value>,

    /// The RPC method name (e.g. `"tools/call"`, `"resources/read"`).
    pub method: String,

    /// Method parameters.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    /// Returns `true` if the `jsonrpc` field is `"2.0"`.
    pub fn is_valid_version(&self) -> bool {
        self.jsonrpc == "2.0"
    }
}

/// Error codes for JSON-RPC 2.0.
#[derive(Debug, Clone, Copy)]
pub enum JsonRpcErrorCode {
    /// Invalid JSON was received.
    ParseError = -32700,
    /// The JSON sent is not a valid Request object.
    InvalidRequest = -32600,
}

impl std::fmt::Display for JsonRpcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError => write!(f, "Parse error"),
            Self::InvalidRequest => write!(f, "Invalid Request"),
        }
    }
}
