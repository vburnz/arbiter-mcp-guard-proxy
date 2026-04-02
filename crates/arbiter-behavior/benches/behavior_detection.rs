use criterion::{black_box, criterion_group, criterion_main, Criterion};

use arbiter_behavior::{
    classify_operation, AnomalyConfig, AnomalyDetector, OperationType,
};

fn bench_classify_operation(c: &mut Criterion) {
    c.bench_function("classify_operation_read", |b| {
        b.iter(|| {
            classify_operation(black_box("tools/call"), black_box(Some("read_file")))
        })
    });

    c.bench_function("classify_operation_write", |b| {
        b.iter(|| {
            classify_operation(black_box("tools/call"), black_box(Some("write_file")))
        })
    });

    c.bench_function("classify_operation_admin", |b| {
        b.iter(|| {
            classify_operation(black_box("tools/call"), black_box(Some("admin_users")))
        })
    });

    c.bench_function("classify_operation_method_level", |b| {
        b.iter(|| classify_operation(black_box("resources/read"), black_box(None)))
    });
}

fn bench_detect_normal(c: &mut Criterion) {
    let detector = AnomalyDetector::new(AnomalyConfig::default());

    // Read intent + read tool = Normal (no anomaly).
    c.bench_function("detect_read_intent_read_tool", |b| {
        b.iter(|| {
            detector.detect(
                black_box("read and analyze the log files"),
                black_box(OperationType::Read),
                black_box("read_file"),
            )
        })
    });
}

fn bench_detect_flagged(c: &mut Criterion) {
    let detector = AnomalyDetector::new(AnomalyConfig::default());

    // Read intent + write tool = Flagged (anomaly detected).
    c.bench_function("detect_read_intent_write_tool", |b| {
        b.iter(|| {
            detector.detect(
                black_box("read and analyze the log files"),
                black_box(OperationType::Write),
                black_box("write_file"),
            )
        })
    });
}

fn bench_classify_intent(c: &mut Criterion) {
    let detector = AnomalyDetector::new(AnomalyConfig::default());

    c.bench_function("classify_intent_read", |b| {
        b.iter(|| detector.classify_intent(black_box("read and analyze the log files")))
    });

    c.bench_function("classify_intent_write", |b| {
        b.iter(|| detector.classify_intent(black_box("create new deployment artifacts")))
    });

    c.bench_function("classify_intent_admin", |b| {
        b.iter(|| detector.classify_intent(black_box("manage the cluster infrastructure")))
    });

    c.bench_function("classify_intent_unknown", |b| {
        b.iter(|| detector.classify_intent(black_box("do something with the system")))
    });
}

criterion_group!(
    benches,
    bench_classify_operation,
    bench_detect_normal,
    bench_detect_flagged,
    bench_classify_intent,
);
criterion_main!(benches);
