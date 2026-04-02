//! MCP JSON-RPC request parser for the Arbiter proxy.
//!
//! Parses MCP (Model Context Protocol) JSON-RPC requests from HTTP
//! request bodies, extracting method names, tool calls, arguments,
//! and resource URIs into a typed [`McpContext`] struct. Non-MCP
//! traffic passes through unmodified.

pub mod context;
pub mod jsonrpc;
pub mod parser;

pub use context::McpContext;
pub use jsonrpc::JsonRpcRequest;
pub use parser::{ParseResult, parse_mcp_body};
