use proptest::prelude::*;

use arbiter_behavior::{
    AnomalyConfig, AnomalyDetector, AnomalyResponse, OperationType, classify_operation,
};

/// Strategy for MCP method names.
fn method_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("tools/call".to_string()),
        Just("resources/read".to_string()),
        Just("resources/subscribe".to_string()),
        Just("completion/complete".to_string()),
        "[a-z/]{1,32}",
    ]
}

/// Strategy for tool name strings.
fn tool_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,31}"
}

/// Strategy for intent strings that classify as read-only.
fn read_intent_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("read the files".to_string()),
        Just("analyze the logs".to_string()),
        Just("summarize the report".to_string()),
        Just("review the code".to_string()),
        Just("check the status".to_string()),
        Just("inspect the configuration".to_string()),
        Just("search for errors".to_string()),
        Just("view the dashboard".to_string()),
    ]
}

/// Strategy for tool names that will classify as write operations.
/// These contain tokens like "write", "create", "update", "set", "put"
/// but NOT read/delete/admin tokens.
fn write_tool_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("write_file".to_string()),
        Just("create_user".to_string()),
        Just("update_record".to_string()),
        Just("set_config".to_string()),
        Just("put_object".to_string()),
        Just("upload_data".to_string()),
        Just("send_message".to_string()),
        Just("execute_command".to_string()),
    ]
}

/// Strategy for intent strings that classify as unknown tier.
fn unknown_intent_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("do something".to_string()),
        Just("perform task".to_string()),
        Just("handle request".to_string()),
        Just("process data".to_string()),
        Just("run job".to_string()),
    ]
}

proptest! {
    /// classify_operation is deterministic: same (method, tool_name) always
    /// returns the same OperationType.
    #[test]
    fn classify_operation_is_deterministic(
        method in method_strategy(),
        tool_name in prop::option::of(tool_name_strategy()),
    ) {
        let result1 = classify_operation(&method, tool_name.as_deref());
        let result2 = classify_operation(&method, tool_name.as_deref());
        prop_assert_eq!(result1, result2);
    }

    /// classify_operation never panics for arbitrary inputs.
    #[test]
    fn classify_never_panics(
        method in "\\PC{0,64}",
        tool_name in prop::option::of("\\PC{0,64}"),
    ) {
        let _result = classify_operation(&method, tool_name.as_deref());
    }

    /// Read-intent + write-tool always flags as anomaly (never Normal).
    #[test]
    fn read_intent_write_tool_is_anomaly(
        intent in read_intent_strategy(),
        tool in write_tool_strategy(),
    ) {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        let op_type = classify_operation("tools/call", Some(&tool));
        // Verify the tool actually classifies as Write (not Read/Admin/Delete).
        prop_assert_eq!(op_type, OperationType::Write, "tool '{}' should classify as Write", tool);

        let result = detector.detect(&intent, op_type, &tool);

        prop_assert!(
            !matches!(result, AnomalyResponse::Normal),
            "read intent '{}' + write tool '{}' must not be Normal, got: {:?}",
            intent, tool, result
        );
    }

    /// Read-intent + write-tool with escalate_to_deny=true produces Denied.
    #[test]
    fn read_intent_write_tool_denied_when_escalated(
        intent in read_intent_strategy(),
        tool in write_tool_strategy(),
    ) {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        let op_type = classify_operation("tools/call", Some(&tool));
        let result = detector.detect(&intent, op_type, &tool);

        prop_assert!(
            matches!(result, AnomalyResponse::Denied { .. }),
            "escalated read+write anomaly should be Denied, got: {:?}", result
        );
    }

    /// Unknown intent tier flags ALL operations (maximum scrutiny for
    /// unclassified intents). With escalate_to_deny=true, produces Denied.
    #[test]
    fn unknown_intent_always_flagged(
        intent in unknown_intent_strategy(),
        tool in tool_name_strategy(),
        op_type in prop_oneof![
            Just(OperationType::Read),
            Just(OperationType::Write),
            Just(OperationType::Delete),
            Just(OperationType::Admin),
        ],
    ) {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        let result = detector.detect(&intent, op_type, &tool);
        prop_assert!(
            matches!(result, AnomalyResponse::Denied { .. }),
            "unknown intent '{}' + {:?} tool '{}' should be Denied, got {:?}",
            intent, op_type, tool, result
        );
    }

    /// Admin intent allows read/write/admin but flags delete operations.
    #[test]
    fn admin_intent_allows_non_delete(
        tool in tool_name_strategy(),
        op_type in prop_oneof![
            Just(OperationType::Read),
            Just(OperationType::Write),
            Just(OperationType::Admin),
        ],
    ) {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: true,
            ..Default::default()
        });

        let result = detector.detect("manage the infrastructure", op_type, &tool);
        prop_assert_eq!(
            result,
            AnomalyResponse::Normal,
            "admin intent + {:?} should be Normal", op_type
        );
    }

    /// Admin intent flags delete operations for forensic tracing.
    #[test]
    fn admin_intent_flags_delete(
        tool in tool_name_strategy(),
    ) {
        let detector = AnomalyDetector::new(AnomalyConfig {
            escalate_to_deny: false,
            ..Default::default()
        });

        let result = detector.detect("manage the infrastructure", OperationType::Delete, &tool);
        prop_assert!(
            matches!(result, AnomalyResponse::Flagged { .. }),
            "admin intent + Delete should be Flagged, got: {:?}", result
        );
    }

    /// Anomaly detection is deterministic: same inputs always yield the same response.
    #[test]
    fn anomaly_detection_is_deterministic(
        intent in "[a-z ]{1,64}",
        tool in tool_name_strategy(),
        op_type in prop_oneof![
            Just(OperationType::Read),
            Just(OperationType::Write),
            Just(OperationType::Delete),
            Just(OperationType::Admin),
        ],
    ) {
        let detector = AnomalyDetector::new(AnomalyConfig::default());

        let r1 = detector.detect(&intent, op_type, &tool);
        let r2 = detector.detect(&intent, op_type, &tool);

        prop_assert_eq!(r1, r2);
    }
}
