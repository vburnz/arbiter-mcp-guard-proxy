//! Arbiter Credential: credential resolution and injection for the Arbiter proxy.

pub mod env_provider;
pub mod error;
pub mod file_provider;
pub mod inject;
pub mod provider;
pub mod response_classifier;

pub use env_provider::EnvProvider;
pub use error::CredentialError;
pub use file_provider::FileProvider;
pub use inject::{InjectedRequest, inject_credentials, scrub_response, scrub_response_plain};
pub use provider::{CredentialProvider, CredentialRef};
pub use response_classifier::{
    DataFinding, DetectedSensitivity, scan_response as scan_response_sensitivity,
};
