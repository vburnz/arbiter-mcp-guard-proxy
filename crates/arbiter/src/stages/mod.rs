//! Enforcement stages for the Arbiter handler pipeline.
//!
//! Each module implements a discrete enforcement check:
//! - [`session_enforcement`]: Session tool validation (whitelist, budgets, TTL)
//! - [`policy_evaluation`]: Authorization policy evaluation (deny-by-default)
//! - [`anomaly_detection`]: Behavioral anomaly detection (intent drift)

pub mod anomaly_detection;
pub mod policy_evaluation;
pub mod session_enforcement;

use hyper::StatusCode;

use crate::handler::ArbiterError;

/// Outcome from a stage function: continue the pipeline, or deny.
pub enum StageVerdict {
    /// Continue to the next stage.
    Continue,
    /// Deny the request with the given status and error.
    Deny {
        status: StatusCode,
        policy_matched: Option<String>,
        error: ArbiterError,
    },
}
