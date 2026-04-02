//! Deny-by-default policy engine for Arbiter authorization.
//!
//! Evaluates whether an agent may call specific tools with specific parameters,
//! matching on agent identity, trust level, session context, tool name, and
//! parameter constraints. Policies are loaded from TOML configuration and
//! evaluated with deny-by-default semantics.

pub mod error;
pub mod eval;
pub mod model;
#[cfg(feature = "watch")]
pub mod watcher;

pub use error::PolicyError;
pub use eval::{evaluate, evaluate_explained, Decision, EvalContext, EvalResult, PolicyTrace};
pub use model::{
    Disposition, Effect, Policy, PolicyConfig, PolicyDiagnostic, PolicyId, ValidationResult,
};
#[cfg(feature = "watch")]
pub use watcher::PolicyWatcher;
