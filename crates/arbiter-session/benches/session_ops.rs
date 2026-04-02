use criterion::{Criterion, black_box, criterion_group, criterion_main};

use arbiter_session::model::DataSensitivity;
use arbiter_session::store::{CreateSessionRequest, SessionStore};

fn make_create_request() -> CreateSessionRequest {
    CreateSessionRequest {
        agent_id: uuid::Uuid::new_v4(),
        delegation_chain_snapshot: vec![],
        declared_intent: "read and analyze files".into(),
        authorized_tools: vec!["read_file".into(), "list_dir".into(), "get_status".into()],
        time_limit: chrono::Duration::hours(1),
        call_budget: 100,
        rate_limit_per_minute: None,
        rate_limit_window_secs: 60,
        data_sensitivity_ceiling: DataSensitivity::Internal,
    }
}

fn bench_session_create(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = SessionStore::new();

    c.bench_function("session_create", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = make_create_request();
                let session = store.create(black_box(req)).await;
                black_box(session);
            })
        })
    });
}

fn bench_session_use(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = SessionStore::new();

    // Pre-create a session with a large budget so we can benchmark repeated use.
    let session = rt.block_on(async {
        let mut req = make_create_request();
        req.call_budget = u64::MAX; // effectively unlimited for benchmarking
        store.create(req).await
    });
    let session_id = session.session_id;

    c.bench_function("session_use_hot_path", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = store
                    .use_session(black_box(session_id), black_box("read_file"))
                    .await;
                black_box(result).unwrap();
            })
        })
    });
}

fn bench_session_cleanup_expired(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("session_cleanup_expired", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let store = SessionStore::new();
                // Create a mix of expired and valid sessions.
                rt.block_on(async {
                    // 5 expired sessions (zero time limit).
                    for _ in 0..5 {
                        let mut req = make_create_request();
                        req.time_limit = chrono::Duration::zero();
                        store.create(req).await;
                    }
                    // 5 valid sessions.
                    for _ in 0..5 {
                        store.create(make_create_request()).await;
                    }
                    // Small delay to ensure expired sessions are past their limit.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                });

                let start = std::time::Instant::now();
                rt.block_on(async {
                    let removed = store.cleanup_expired().await;
                    black_box(removed);
                });
                total += start.elapsed();
            }
            total
        })
    });
}

criterion_group!(
    benches,
    bench_session_create,
    bench_session_use,
    bench_session_cleanup_expired,
);
criterion_main!(benches);
