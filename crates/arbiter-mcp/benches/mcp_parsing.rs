use criterion::{Criterion, black_box, criterion_group, criterion_main};
use serde_json::json;

fn bench_simple_tool_call(c: &mut Criterion) {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/etc/hosts"
            }
        }
    }))
    .unwrap();

    c.bench_function("parse_simple_tool_call", |b| {
        b.iter(|| arbiter_mcp::parse_mcp_body(black_box(&body)))
    });
}

fn bench_batch_request(c: &mut Criterion) {
    let body = serde_json::to_vec(&json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/etc/hosts" }
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_dir",
                "arguments": { "path": "/home" }
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {
                "uri": "file:///workspace/README.md"
            }
        }
    ]))
    .unwrap();

    c.bench_function("parse_batch_3_requests", |b| {
        b.iter(|| arbiter_mcp::parse_mcp_body(black_box(&body)))
    });
}

fn bench_non_mcp_passthrough(c: &mut Criterion) {
    let body = b"This is plain text, not JSON-RPC at all. Just normal HTTP traffic.";

    c.bench_function("parse_non_mcp_passthrough", |b| {
        b.iter(|| arbiter_mcp::parse_mcp_body(black_box(body)))
    });
}

fn bench_large_arguments(c: &mut Criterion) {
    // Build a ~1KB JSON arguments object.
    let large_data: String = "x".repeat(900);
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "process_data",
            "arguments": {
                "data": large_data,
                "format": "text",
                "encoding": "utf-8",
                "options": {
                    "verbose": true,
                    "max_tokens": 4096,
                    "temperature": 0.7
                }
            }
        }
    }))
    .unwrap();

    c.bench_function("parse_large_arguments_1kb", |b| {
        b.iter(|| arbiter_mcp::parse_mcp_body(black_box(&body)))
    });
}

criterion_group!(
    benches,
    bench_simple_tool_call,
    bench_batch_request,
    bench_non_mcp_passthrough,
    bench_large_arguments,
);
criterion_main!(benches);
