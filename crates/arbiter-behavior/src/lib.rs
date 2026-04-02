//! Operation-type drift detection for Arbiter task sessions.
//!
//! Tracks sequences of tool calls within a session, classifies each call
//! by its operation type (read/write/delete/admin), and flags divergence
//! when operation types fall outside the session's declared scope.

pub mod classifier;
pub mod detector;
pub mod tracker;

pub use classifier::{classify_operation, OperationType};
pub use detector::{AnomalyConfig, AnomalyDetector, AnomalyResponse};
pub use tracker::{BehaviorTracker, CallRecord};
