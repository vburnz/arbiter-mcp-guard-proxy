use proptest::prelude::*;

use arbiter_audit::redaction::REDACTED;
use arbiter_audit::{AuditEntry, RedactionConfig, redact_arguments};
use uuid::Uuid;

/// Strategy for generating arbitrary JSON values up to moderate depth.
fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
    // Leaf values.
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        "[a-zA-Z0-9_ ]{0,32}".prop_map(|s| serde_json::Value::String(s)),
    ];

    // Recursive structure (objects and arrays) with limited depth.
    leaf.prop_recursive(
        3,  // max depth
        64, // max nodes
        8,  // items per collection
        |inner| {
            prop_oneof![
                // Array of values.
                prop::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
                // Object with string keys.
                prop::collection::vec(("[a-zA-Z_]{1,16}", inner), 0..4,).prop_map(|pairs| {
                    let map: serde_json::Map<String, serde_json::Value> =
                        pairs.into_iter().collect();
                    serde_json::Value::Object(map)
                }),
            ]
        },
    )
}

/// Strategy for generating audit entries with random field values.
fn arb_audit_entry() -> impl Strategy<Value = AuditEntry> {
    (
        "[a-z0-9-]{1,32}",                        // agent_id
        "[a-z_]{1,32}",                           // tool_called
        prop_oneof!["allow", "deny", "escalate"], // authorization_decision
        0u64..10000,                              // latency_ms
        prop::option::of(200u16..600),            // upstream_status
    )
        .prop_map(|(agent_id, tool_called, auth_dec, latency, status)| {
            let mut entry = AuditEntry::new(Uuid::new_v4());
            entry.agent_id = agent_id;
            entry.tool_called = tool_called;
            entry.authorization_decision = auth_dec;
            entry.latency_ms = latency;
            entry.upstream_status = status;
            entry
        })
}

proptest! {
    /// Entry serialization roundtrip: serialize then deserialize produces an entry
    /// with the same key fields.
    #[test]
    fn entry_serialization_roundtrip(entry in arb_audit_entry()) {
        let json = serde_json::to_string(&entry).expect("serialize must succeed");
        let deserialized: AuditEntry =
            serde_json::from_str(&json).expect("deserialize must succeed");

        prop_assert_eq!(&deserialized.request_id, &entry.request_id);
        prop_assert_eq!(&deserialized.agent_id, &entry.agent_id);
        prop_assert_eq!(&deserialized.tool_called, &entry.tool_called);
        prop_assert_eq!(&deserialized.authorization_decision, &entry.authorization_decision);
        prop_assert_eq!(deserialized.latency_ms, entry.latency_ms);
        prop_assert_eq!(deserialized.upstream_status, entry.upstream_status);
    }

    /// Serialized JSON is always a single line (valid JSONL).
    #[test]
    fn serialized_entry_is_single_line(entry in arb_audit_entry()) {
        let json = serde_json::to_string(&entry).expect("serialize must succeed");
        prop_assert!(
            !json.contains('\n'),
            "serialized JSON must not contain newline"
        );
        prop_assert!(
            !json.contains('\r'),
            "serialized JSON must not contain carriage return"
        );
    }

    /// Redaction is deterministic: same input + same config = same output.
    #[test]
    fn redaction_is_deterministic(value in arb_json_value()) {
        let config = RedactionConfig::default();
        let r1 = redact_arguments(&value, &config);
        let r2 = redact_arguments(&value, &config);
        prop_assert_eq!(r1, r2);
    }

    /// Redacted values are never present in redaction output at the matched keys.
    /// For any JSON structure where a key matches a redaction pattern,
    /// the value at that key must be exactly "[REDACTED]" in the output.
    #[test]
    fn redacted_keys_have_redacted_value(
        secret_value in "[a-zA-Z0-9]{1,32}",
        visible_value in "[a-zA-Z0-9]{1,32}",
    ) {
        let config = RedactionConfig {
            patterns: vec!["secret_field".into()],
        };

        let input = serde_json::json!({
            "secret_field": secret_value.clone(),
            "public_field": visible_value.clone(),
            "nested": {
                "secret_field": secret_value.clone(),
                "public": "also_visible"
            },
            "array": [
                {"secret_field": "array_secret", "id": 1}
            ]
        });

        let redacted = redact_arguments(&input, &config);

        // Every "secret_field" key must have value "[REDACTED]".
        prop_assert_eq!(
            redacted["secret_field"].as_str().unwrap(),
            REDACTED,
            "top-level secret_field must be redacted"
        );
        prop_assert_eq!(
            redacted["nested"]["secret_field"].as_str().unwrap(),
            REDACTED,
            "nested secret_field must be redacted"
        );
        prop_assert_eq!(
            redacted["array"][0]["secret_field"].as_str().unwrap(),
            REDACTED,
            "array-nested secret_field must be redacted"
        );

        // Non-secret fields must be preserved unchanged.
        prop_assert_eq!(
            redacted["public_field"].as_str().unwrap(),
            visible_value.as_str(),
            "public_field must not be redacted"
        );
        prop_assert_eq!(
            redacted["nested"]["public"].as_str().unwrap(),
            "also_visible",
            "nested public field must be preserved"
        );
        prop_assert_eq!(
            &redacted["array"][0]["id"],
            &serde_json::json!(1),
            "array-nested non-secret field must be preserved"
        );
    }

    /// Empty patterns redact nothing: output equals input.
    #[test]
    fn empty_patterns_preserve_input(value in arb_json_value()) {
        let config = RedactionConfig { patterns: vec![] };
        let redacted = redact_arguments(&value, &config);
        prop_assert_eq!(redacted, value);
    }

    /// Scalar values (strings, numbers, booleans, null) pass through unmodified
    /// regardless of redaction config.
    #[test]
    fn scalar_values_pass_through(
        s in "[a-zA-Z0-9]{0,32}",
        n in any::<i64>(),
        b in any::<bool>(),
    ) {
        let config = RedactionConfig::default();

        let string_val = serde_json::Value::String(s.clone());
        prop_assert_eq!(redact_arguments(&string_val, &config), string_val);

        let num_val = serde_json::json!(n);
        prop_assert_eq!(redact_arguments(&num_val, &config), num_val);

        let bool_val = serde_json::Value::Bool(b);
        prop_assert_eq!(redact_arguments(&bool_val, &config), bool_val);

        prop_assert_eq!(
            redact_arguments(&serde_json::Value::Null, &config),
            serde_json::Value::Null
        );
    }
}
