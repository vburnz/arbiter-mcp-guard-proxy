//! Operation-type drift detection for Arbiter task sessions.
//!
//! Tracks sequences of tool calls within a session, classifies each call
//! by its operation type (read/write/delete/admin), and flags divergence
//! when operation types fall outside the session's declared scope.

pub mod classifier;
pub mod detector;

// BehaviorTracker removed: it accumulated call records per session but was
// disconnected from AnomalyDetector -- it never informed anomaly scoring.
// The detector now handles all per-request analysis directly.
// The tracker module is retained as dead code for historical reference
// but not re-exported.
#[doc(hidden)]
pub mod tracker;

pub use classifier::{OperationType, classify_operation};
pub use detector::{AnomalyConfig, AnomalyDetector, AnomalyResponse};
