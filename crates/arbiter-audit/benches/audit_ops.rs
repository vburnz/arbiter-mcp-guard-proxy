use criterion::{criterion_group, criterion_main, Criterion};

fn bench_audit_entry_serialization(c: &mut Criterion) {
    use arbiter_audit::AuditEntry;
    use uuid::Uuid;

    let mut entry = AuditEntry::new(Uuid::new_v4());
    entry.agent_id = "agent-bench".into();
    entry.tool_called = "read_file".into();
    entry.authorization_decision = "allow".into();
    entry.latency_ms = 5;

    c.bench_function("audit_entry_serialize", |b| {
        b.iter(|| serde_json::to_string(&entry).unwrap());
    });
}

fn bench_redaction(c: &mut Criterion) {
    use arbiter_audit::{redact_arguments, RedactionConfig};

    let config = RedactionConfig::default();
    let value = serde_json::json!({
        "username": "alice",
        "password": "s3cret",
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "data": {
            "nested_token": "tok-123",
            "items": [
                {"secret": "hidden", "public": "visible"},
                {"key": "another-secret", "name": "test"}
            ]
        }
    });

    c.bench_function("redact_nested_json", |b| {
        b.iter(|| redact_arguments(criterion::black_box(&value), &config));
    });
}

criterion_group!(benches, bench_audit_entry_serialization, bench_redaction);
criterion_main!(benches);
