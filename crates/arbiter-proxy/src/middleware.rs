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

/// Normalize a URL path by percent-decoding, collapsing dot segments, and
/// rejecting null bytes. This prevents path traversal bypasses via encoded
/// sequences like `%2e%2e` or `%2F`.
fn normalize_path(path: &str) -> Option<String> {
    // Reject null bytes.
    if path.bytes().any(|b| b == 0) {
        return None;
    }
    // Percent-decode the path.
    let decoded = percent_decode(path);
    // Reject null bytes in decoded form.
    if decoded.bytes().any(|b| b == 0) {
        return None;
    }
    // Collapse dot segments (RFC 3986 Section 5.2.4).
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let normalized = format!("/{}", segments.join("/"));
    // Remove double slashes.
    Some(normalized.replace("//", "/"))
}

/// Simple percent-decoding.
fn percent_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl Middleware for PathBlocker {
    fn process(&self, req: Request<hyper::body::Incoming>) -> MiddlewareResult {
        let raw_path = req.uri().path();
        let path = match normalize_path(raw_path) {
            Some(p) => p,
            None => {
                tracing::warn!(path = raw_path, "request blocked: path contains null bytes");
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Bad Request")))
                    .expect("building static response cannot fail");
                return Err(Box::new(resp));
            }
        };
        if self.blocked.iter().any(|b| path == *b || raw_path == b.as_str()) {
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
                // Don't expose the header name in the response body -- it leaks
                // security policy configuration and enables iterative probing.
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Bad Request")))
                    .expect("building static response cannot fail");
                return Err(Box::new(resp));
            }
        }
        Ok(req)
    }
}

/// Rejects requests using HTTP methods not in the allowlist.
/// TRACE and CONNECT are always blocked as they can enable cross-site
/// tracing and proxy tunneling attacks.
pub struct MethodAllowlist {
    allowed: Vec<hyper::Method>,
}

impl MethodAllowlist {
    /// Create with the default safe set: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
    pub fn default_safe() -> Self {
        Self {
            allowed: vec![
                hyper::Method::GET,
                hyper::Method::POST,
                hyper::Method::PUT,
                hyper::Method::DELETE,
                hyper::Method::PATCH,
                hyper::Method::HEAD,
                hyper::Method::OPTIONS,
            ],
        }
    }
}

impl Middleware for MethodAllowlist {
    fn process(&self, req: Request<hyper::body::Incoming>) -> MiddlewareResult {
        if !self.allowed.contains(req.method()) {
            tracing::warn!(method = %req.method(), "request blocked: method not in allowlist");
            let resp = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method Not Allowed")))
                .expect("building static response cannot fail");
            return Err(Box::new(resp));
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

        // Method allowlist first: reject dangerous verbs before any other processing.
        middlewares.push(Box::new(MethodAllowlist::default_safe()));

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
