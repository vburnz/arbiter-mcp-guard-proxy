//! OAuth middleware for the Arbiter proxy middleware chain.
//!
//! Extracts and validates JWT bearer tokens from the `Authorization`
//! header, then injects the validated [`Claims`] into the request's
//! extensions map so downstream handlers can access them.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use arbiter_proxy::middleware::{Middleware, MiddlewareResult};

use crate::claims::Claims;
use crate::validator::OAuthValidator;

/// Middleware that enforces OAuth 2.1 JWT bearer token authentication.
///
/// Tokens are validated locally against cached JWKS keys. On success the
/// decoded [`Claims`] are inserted into the request's extensions. On
/// failure the request is rejected with `401 Unauthorized`.
pub struct OAuthMiddleware {
    validator: Arc<OAuthValidator>,
}

impl OAuthMiddleware {
    /// Create a new OAuth middleware wrapping the given validator.
    pub fn new(validator: Arc<OAuthValidator>) -> Self {
        Self { validator }
    }
}

impl Middleware for OAuthMiddleware {
    fn process(&self, mut req: Request<hyper::body::Incoming>) -> MiddlewareResult {
        // Extract the bearer token from the Authorization header.
        let token = {
            let auth = req
                .headers()
                .get(hyper::header::AUTHORIZATION)
                .ok_or_else(|| {
                    tracing::warn!("request missing Authorization header");
                    Box::new(unauthorized_response())
                })?
                .to_str()
                .map_err(|_| {
                    tracing::warn!("Authorization header contains non-ASCII");
                    Box::new(unauthorized_response())
                })?;

            if !auth.starts_with("Bearer ") {
                tracing::warn!("Authorization header is not Bearer scheme");
                return Err(Box::new(unauthorized_response()));
            }

            auth[7..].to_string()
        };

        // Validate the JWT.
        match self.validator.validate_token(&token) {
            Ok(claims) => {
                tracing::debug!(sub = ?claims.sub, "authenticated request");
                req.extensions_mut().insert(claims);
                Ok(req)
            }
            Err(e) => {
                // Don't log detailed validation errors
                // to prevent information disclosure about token structure.
                tracing::warn!("JWT validation failed");
                tracing::debug!(error = %e, "JWT validation detail (debug level only)");
                Err(Box::new(unauthorized_response()))
            }
        }
    }
}

/// Helper: retrieve validated [`Claims`] from a request's extensions.
///
/// Returns `None` if the OAuth middleware has not run or validation failed.
pub fn get_claims(req: &Request<hyper::body::Incoming>) -> Option<&Claims> {
    req.extensions().get::<Claims>()
}

fn unauthorized_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Bearer")
        .body(Full::new(Bytes::from("Unauthorized")))
        .expect("building static response cannot fail")
}
