use thiserror::Error;

/// Errors that can occur during policy operations.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("invalid regex in policy '{policy_id}' (pattern: '{pattern}'): {reason}")]
    InvalidRegex {
        policy_id: String,
        pattern: String,
        reason: String,
    },

    #[error("no policies loaded")]
    NoPolicies,

    #[error("policy '{policy_id}' has priority {priority} exceeding maximum {max}")]
    PriorityTooHigh {
        policy_id: String,
        priority: i32,
        max: i32,
    },

    #[error("policy '{policy_id}' regex pattern length {length} exceeds maximum {max}")]
    RegexTooLong {
        policy_id: String,
        length: usize,
        max: usize,
    },

    #[error("duplicate policy ID '{policy_id}'")]
    DuplicatePolicyId { policy_id: String },

    #[error(
        "policy '{policy_id}' has effect=allow with empty allowed_tools \
         and empty resource_match; this would grant blanket access to every \
         tool and resource. Set allowed_tools or resource_match explicitly, \
         or use effect=deny if a blanket rule is intended."
    )]
    EmptyAllowOnAllEffect { policy_id: String },
}
