//! Stage 9: Behavioral anomaly detection.

use arbiter_behavior::{AnomalyDetector, AnomalyResponse, classify_operation};
use hyper::StatusCode;

use super::StageVerdict;
use crate::handler::ArbiterError;

/// Check MCP requests for behavioral anomalies.
/// Returns verdict + any anomaly flags (even on Continue, for audit).
pub fn detect_behavioral_anomalies(
    detector: &AnomalyDetector,
    declared_intent: &str,
    requests: &[arbiter_mcp::context::McpRequest],
) -> (StageVerdict, Vec<String>) {
    let mut flags = Vec::new();
    for mcp_req in requests {
        let tool = mcp_req.tool_name.as_deref().unwrap_or(&mcp_req.method);
        let op_type = classify_operation(&mcp_req.method, mcp_req.tool_name.as_deref());
        let anomaly = detector.detect(declared_intent, op_type, tool);
        match &anomaly {
            AnomalyResponse::Normal => {}
            AnomalyResponse::Flagged { reason } => {
                tracing::warn!(%reason, "behavioral anomaly flagged");
                flags.push(reason.clone());
            }
            AnomalyResponse::Denied { reason } => {
                tracing::warn!(%reason, "behavioral anomaly denied");
                flags.push(reason.clone());
                return (
                    StageVerdict::Deny {
                        status: StatusCode::FORBIDDEN,
                        policy_matched: None,
                        error: ArbiterError::behavioral_anomaly(reason),
                    },
                    flags,
                );
            }
        }
    }
    (StageVerdict::Continue, flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_behavior::AnomalyConfig;

    fn mcp_tool_call(tool: &str) -> arbiter_mcp::context::McpRequest {
        arbiter_mcp::context::McpRequest {
            id: None,
            method: "tools/call".into(),
            tool_name: Some(tool.into()),
            arguments: None,
            resource_uri: None,
        }
    }

    #[test]
    fn normal_read() {
        let detector = AnomalyDetector::new(AnomalyConfig::default());
        let requests = vec![mcp_tool_call("read_file")];
        let (verdict, flags) =
            detect_behavioral_anomalies(&detector, "read configuration files", &requests);
        assert!(matches!(verdict, StageVerdict::Continue));
        assert!(flags.is_empty());
    }
}
