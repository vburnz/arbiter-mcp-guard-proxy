//! Agent identity model and registry for Arbiter.
//!
//! Provides the core identity types ([`Agent`], [`DelegationLink`], [`TrustLevel`])
//! and a registry trait ([`AgentRegistry`]) with an in-memory implementation.
//!
//! The [`StorageBackedRegistry`] wraps any `AgentStore + DelegationStore` backend
//! (REQ-007: swappable storage) for persistent identity state (REQ-001).

pub mod any_registry;
pub mod error;
pub mod model;
pub mod registry;
pub mod storage_registry;

pub use any_registry::AnyRegistry;
pub use error::IdentityError;
pub use model::{Agent, AgentId, DelegationLink, TrustLevel};
pub use registry::{AgentRegistry, InMemoryRegistry};
pub use storage_registry::StorageBackedRegistry;
