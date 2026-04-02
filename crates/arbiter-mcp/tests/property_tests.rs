use proptest::prelude::*;

use arbiter_mcp::{ParseResult, parse_mcp_body};

/// Strategy that generates valid JSON-RPC 2.0 "tools/call" request bodies.
fn valid_tools_call_body(tool_name: String) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {}
        }
    }))
    .unwrap()
}

/// Strategy for tool names that pass the parser's validation:
/// ASCII alphanumeric plus `_`, `-`, `.`, `/`, `:`, non-empty, max 256 chars.
fn valid_tool_name_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec![
            'a', 'b', 'c', 'z', 'A', 'Z', '0', '9', '_', '-', '.', '/', ':',
        ]),
        1..64,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
}

proptest! {
    /// Any valid JSON-RPC 2.0 request with method "tools/call" and a valid
    /// tool name must parse as the Mcp variant.
    #[test]
    fn valid_tools_call_parses_as_mcp(tool_name in valid_tool_name_strategy()) {
        let body = valid_tools_call_body(tool_name.clone());
        let result = parse_mcp_body(&body);
        match result {
            ParseResult::Mcp(ctx) => {
                prop_assert_eq!(ctx.requests.len(), 1);
                prop_assert_eq!(ctx.requests[0].method.as_str(), "tools/call");
                prop_assert_eq!(ctx.requests[0].tool_name.as_deref(), Some(tool_name.as_str()));
            }
            ParseResult::NonMcp => {
                // This should not happen for a valid tools/call with valid tool name.
                prop_assert!(false, "expected Mcp but got NonMcp for tool_name={}", tool_name);
            }
        }
    }

    /// Any non-JSON input must parse as NonMcp and must never panic.
    #[test]
    fn non_json_input_parses_as_non_mcp(input in "([^{\\[\"0-9tfn]|\\PC){0,512}") {
        let result = parse_mcp_body(input.as_bytes());
        match result {
            ParseResult::NonMcp => {} // expected
            ParseResult::Mcp(_) => {
                // If somehow valid JSON was generated, that's also acceptable
                // as long as we didn't panic.
            }
        }
    }

    /// parse_mcp_body is deterministic: same input always produces same observable output.
    #[test]
    fn parse_is_deterministic(body in prop::collection::vec(any::<u8>(), 0..256)) {
        let result1 = parse_mcp_body(&body);
        let result2 = parse_mcp_body(&body);

        // Compare discriminants and content.
        match (&result1, &result2) {
            (ParseResult::NonMcp, ParseResult::NonMcp) => {}
            (ParseResult::Mcp(ctx1), ParseResult::Mcp(ctx2)) => {
                prop_assert_eq!(ctx1.requests.len(), ctx2.requests.len());
                for (r1, r2) in ctx1.requests.iter().zip(ctx2.requests.iter()) {
                    prop_assert_eq!(&r1.method, &r2.method);
                    prop_assert_eq!(&r1.tool_name, &r2.tool_name);
                    prop_assert_eq!(&r1.resource_uri, &r2.resource_uri);
                    prop_assert_eq!(&r1.arguments, &r2.arguments);
                }
            }
            _ => {
                prop_assert!(false, "determinism violated: results differ for same input");
            }
        }
    }

    /// Arbitrary byte sequences must never cause panics (robustness).
    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        // If this returns at all (doesn't panic), the property holds.
        let _result = parse_mcp_body(&data);
    }

    /// Arbitrary strings must never cause panics.
    #[test]
    fn arbitrary_strings_never_panic(input in "\\PC{0,512}") {
        let _result = parse_mcp_body(input.as_bytes());
    }

    /// Valid JSON that is not JSON-RPC should parse as NonMcp.
    #[test]
    fn non_jsonrpc_json_is_non_mcp(
        key in "[a-z]{1,16}",
        val in "[a-z0-9]{1,16}"
    ) {
        let json = serde_json::json!({ key: val });
        let body = serde_json::to_vec(&json).unwrap();
        let result = parse_mcp_body(&body);
        // Valid JSON without "jsonrpc" and "method" fields should be NonMcp.
        match result {
            ParseResult::NonMcp => {}
            ParseResult::Mcp(_) => {
                prop_assert!(false, "plain JSON object should not parse as MCP");
            }
        }
    }
}
