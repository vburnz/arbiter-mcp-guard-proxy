//! OAuth 2.1 JWT validation middleware for the Arbiter proxy.
//!
//! Provides JWT validation with JWKS caching, multi-issuer support,
//! and token introspection fallback. Validated claims are attached
//! as request extensions for downstream middleware.

pub mod claims;
pub mod config;
pub mod error;
pub mod introspection;
pub mod jwks;
pub mod middleware;
pub mod validator;

pub use claims::Claims;
pub use config::OAuthConfig;
pub use error::OAuthError;
pub use middleware::OAuthMiddleware;
pub use validator::OAuthValidator;
