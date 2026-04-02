//! Arbiter Audit: structured audit logging with argument redaction.
//!
//! Captures a complete audit trail for every proxied request: timing, identity,
//! authorization decisions, and tool arguments (with configurable redaction of
//! sensitive fields). Outputs structured JSON lines to stdout and/or an
//! append-only file.

pub mod entry;
pub mod middleware;
pub mod redaction;
pub mod sink;
pub mod stats;

pub use entry::AuditEntry;
pub use middleware::AuditCapture;
pub use redaction::{CompiledRedaction, RedactionConfig, redact_arguments};
pub use sink::{AuditSink, AuditSinkConfig};
pub use stats::{AggregateAuditStats, AuditStats, SessionAuditStats};
