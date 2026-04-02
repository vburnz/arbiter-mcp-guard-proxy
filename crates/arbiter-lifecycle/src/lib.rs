//! Agent lifecycle HTTP API for Arbiter.
//!
//! Provides REST endpoints for agent registration, delegation,
//! deactivation, and token issuance.

pub mod api;
pub mod state;
pub mod token;

pub use api::router;
pub use state::AdminRateLimiter;
pub use state::AppState;
pub use token::{JtiBlocklist, TokenConfig};
