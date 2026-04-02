//! Arbiter Proxy: an async HTTP reverse proxy with a middleware chain architecture.
//!
//! Requests flow through a configurable sequence of middleware before being
//! forwarded to an upstream server. Configuration is loaded from TOML.

pub mod config;
pub mod middleware;
pub mod proxy;
pub mod server;
