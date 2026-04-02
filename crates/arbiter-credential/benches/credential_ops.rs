use criterion::{Criterion, black_box, criterion_group, criterion_main};

use arbiter_credential::error::CredentialError;
use arbiter_credential::inject::{find_refs, scrub_response_plain};
use arbiter_credential::inject_credentials;
use arbiter_credential::provider::{CredentialProvider, CredentialRef};
use async_trait::async_trait;
use std::collections::HashMap;

/// A trivial in-memory credential provider for benchmarking.
struct BenchProvider {
    store: HashMap<String, String>,
}

impl BenchProvider {
    fn new(entries: &[(&str, &str)]) -> Self {
        Self {
            store: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}

#[async_trait]
impl CredentialProvider for BenchProvider {
    async fn resolve(&self, reference: &str) -> Result<secrecy::SecretString, CredentialError> {
        self.store
            .get(reference)
            .map(|v| secrecy::SecretString::from(v.clone()))
            .ok_or_else(|| CredentialError::NotFound(reference.to_string()))
    }

    async fn list_refs(&self) -> Result<Vec<CredentialRef>, CredentialError> {
        Ok(self
            .store
            .keys()
            .map(|k| CredentialRef {
                name: k.clone(),
                provider: "bench".into(),
                last_rotated: None,
            })
            .collect())
    }
}

fn bench_inject_credentials(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let provider = BenchProvider::new(&[
        ("api_key", "sk-proj-abcdef1234567890"),
        ("db_password", "super-secret-db-password-42"),
        ("auth_token", "ghp_xxxxxxxxxxxxxxxxxxxx"),
    ]);

    let body = r#"{
        "api_key": "${CRED:api_key}",
        "database": {
            "host": "db.example.com",
            "password": "${CRED:db_password}"
        },
        "auth": "Bearer ${CRED:auth_token}"
    }"#;

    let headers: Vec<(String, String)> = vec![];

    c.bench_function("inject_credentials_3_refs", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result =
                    inject_credentials(black_box(body), black_box(&headers), black_box(&provider))
                        .await
                        .unwrap();
                black_box(result);
            })
        })
    });
}

fn bench_scrub_response(c: &mut Criterion) {
    let known_values = vec![
        "sk-proj-abcdef1234567890".to_string(),
        "super-secret-db-password-42".to_string(),
        "ghp_xxxxxxxxxxxxxxxxxxxx".to_string(),
        "eyJhbGciOiJIUzI1NiJ9.secret".to_string(),
        "p@ssw0rd!special#chars".to_string(),
    ];

    // A response body that contains 3 of the 5 known values.
    let response_body = r#"{
        "status": "ok",
        "debug": {
            "api_key_used": "sk-proj-abcdef1234567890",
            "connection_string": "postgres://user:super-secret-db-password-42@db:5432/app",
            "note": "request processed successfully",
            "token": "ghp_xxxxxxxxxxxxxxxxxxxx",
            "metadata": {
                "region": "us-east-1",
                "latency_ms": 42
            }
        }
    }"#;

    c.bench_function("scrub_response_5_known_values", |b| {
        b.iter(|| scrub_response_plain(black_box(response_body), black_box(&known_values)))
    });
}

fn bench_find_refs(c: &mut Criterion) {
    // A large body (~2KB) with credential references scattered throughout.
    let large_body = format!(
        r#"{{
        "section_1": {{
            "key": "${{CRED:api_key_1}}",
            "data": "{filler_1}"
        }},
        "section_2": {{
            "token": "Bearer ${{CRED:auth_token}}",
            "data": "{filler_2}"
        }},
        "section_3": {{
            "password": "${{CRED:db.password-v2}}",
            "data": "{filler_3}"
        }},
        "section_4": {{
            "config": {{
                "secret": "${{CRED:service_secret}}",
                "webhook": "${{CRED:webhook-key}}",
                "data": "{filler_4}"
            }}
        }},
        "section_5": {{
            "plain_text": "no credentials here just regular data",
            "data": "{filler_5}"
        }}
    }}"#,
        filler_1 = "a".repeat(200),
        filler_2 = "b".repeat(200),
        filler_3 = "c".repeat(200),
        filler_4 = "d".repeat(200),
        filler_5 = "e".repeat(200),
    );

    c.bench_function("find_refs_large_body", |b| {
        b.iter(|| find_refs(black_box(&large_body)))
    });
}

criterion_group!(
    benches,
    bench_inject_credentials,
    bench_scrub_response,
    bench_find_refs,
);
criterion_main!(benches);
