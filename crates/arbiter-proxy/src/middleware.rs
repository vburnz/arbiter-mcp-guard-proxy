//! Middleware trait and built-in middleware implementations.
//!
//! Middleware inspects or modifies an incoming request. It can either pass the
//! request forward (returning `Ok(request)`) or reject it (returning
//! `Err(response)`).

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use crate::config::MiddlewareConfig;

/// Outcome of a middleware decision: either the (possibly modified) request
/// continues downstream, or a response is returned immediately.
pub type MiddlewareResult = Result<Request<hyper::body::Incoming>, Box<Response<Full<Bytes>>>>;

/// A single middleware in the proxy pipeline.
pub trait Middleware: Send + Sync {
    /// Process the request. Return `Ok(req)` to forward, `Err(resp)` to reject.
    fn process(&self, req: Request<hyper::body::Incoming>) -> MiddlewareResult;
}

/// Blocks requests whose path matches a configured set of paths.
pub struct PathBlocker {
    blocked: Vec<String>,
}

impl PathBlocker {
    /// Create a new path blocker from a list of blocked paths.
    pub fn new(blocked: Vec<String>) -> Self {
        Self { blocked }
    }
}

impl Middleware for PathBlocker {
    fn process(&self, req: Request<hyper::body::Incoming>) -> MiddlewareResult {
        let path = req.uri().path();
        if self.blocked.iter().any(|b| path == b.as_str()) {
            tracing::warn!(path, "request blocked by path blocker");
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Forbidden")))
                .expect("building static response cannot fail");
            return Err(Box::new(resp));
        }
        Ok(req)
    }
}

/// Rejects requests that are missing required headers.
pub struct RequiredHeaders {
    required: Vec<String>,
}

impl RequiredHeaders {
    /// Create a new required-headers middleware.
    pub fn new(required: Vec<String>) -> Self {
        Self { required }
    }
}

impl Middleware for RequiredHeaders {
    fn process(&self, req: Request<hyper::body::Incoming>) -> MiddlewareResult {
        for header in &self.required {
            if !req.headers().contains_key(header.as_str()) {
                tracing::warn!(header, "request rejected: missing required header");
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(format!(
                        "Missing required header: {header}"
                    ))))
                    .expect("building static response cannot fail");
                return Err(Box::new(resp));
            }
        }
        Ok(req)
    }
}

/// Ordered chain of middleware. Each middleware is executed in sequence.
pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl MiddlewareChain {
    /// Build a middleware chain from the proxy configuration.
    pub fn from_config(config: &MiddlewareConfig) -> Self {
        let mut middlewares: Vec<Box<dyn Middleware>> = Vec::new();

        if !config.blocked_paths.is_empty() {
            middlewares.push(Box::new(PathBlocker::new(config.blocked_paths.clone())));
        }
        if !config.required_headers.is_empty() {
            middlewares.push(Box::new(RequiredHeaders::new(
                config.required_headers.clone(),
            )));
        }

        Self { middlewares }
    }

    /// Create an empty middleware chain (no-op passthrough).
    pub fn empty() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    /// Run the request through all middleware in order.
    /// Returns `Ok(req)` if all middleware pass, or `Err(resp)` on first rejection.
    pub fn execute(&self, mut req: Request<hyper::body::Incoming>) -> MiddlewareResult {
        for mw in &self.middlewares {
            req = mw.process(req)?;
        }
        Ok(req)
    }
}
