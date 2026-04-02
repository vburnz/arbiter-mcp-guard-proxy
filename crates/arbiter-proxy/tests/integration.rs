//! Integration tests for arbiter-proxy.
//!
//! These tests spin up real TCP listeners for both the proxy and a mock
//! upstream, so they exercise the full request path including audit and metrics.

use std::net::SocketAddr;
use std::sync::Arc;

use arbiter_audit::RedactionConfig;
use arbiter_metrics::ArbiterMetrics;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use arbiter_proxy::config::MiddlewareConfig;
use arbiter_proxy::middleware::MiddlewareChain;
use arbiter_proxy::proxy::{ProxyState, handle_request};

/// Bind to an ephemeral port and return the listener + address.
async fn ephemeral_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Spawn a minimal upstream HTTP server that echoes back a fixed body.
async fn spawn_upstream() -> SocketAddr {
    let (listener, addr) = ephemeral_listener().await;

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req: Request<hyper::body::Incoming>| async move {
                            let path = req.uri().path().to_string();
                            let body = format!("upstream saw {path}");
                            Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(body))))
                        }),
                    )
                    .await;
            });
        }
    });

    addr
}

/// Spawn the proxy on an ephemeral port, returning its address and shared metrics.
async fn spawn_proxy(
    upstream_addr: SocketAddr,
    mw_config: MiddlewareConfig,
) -> (SocketAddr, Arc<ArbiterMetrics>) {
    let (listener, addr) = ephemeral_listener().await;
    let middleware = MiddlewareChain::from_config(&mw_config);
    let metrics = Arc::new(ArbiterMetrics::new().unwrap());
    let metrics_clone = Arc::clone(&metrics);
    let state = Arc::new(ProxyState::new(
        format!("http://{upstream_addr}"),
        middleware,
        None, // no file-based audit sink in tests
        RedactionConfig::default(),
        metrics,
        10 * 1024 * 1024,                   // 10 MB max body
        std::time::Duration::from_secs(30), // 30s upstream timeout
    ));

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    handle_request(state, req)
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, metrics_clone)
}

/// Helper: send a GET request and return (status, body string).
async fn get(url: &str) -> (StatusCode, String) {
    let client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let uri: hyper::Uri = url.parse().unwrap();
    let req = Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn health_check_returns_200() {
    let upstream_addr = spawn_upstream().await;
    let (proxy_addr, _metrics) = spawn_proxy(upstream_addr, MiddlewareConfig::default()).await;

    let (status, body) = get(&format!("http://{proxy_addr}/health")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OK");
}

#[tokio::test]
async fn proxy_forwards_to_upstream() {
    let upstream_addr = spawn_upstream().await;
    let (proxy_addr, _metrics) = spawn_proxy(upstream_addr, MiddlewareConfig::default()).await;

    let (status, body) = get(&format!("http://{proxy_addr}/hello/world")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "upstream saw /hello/world");
}

#[tokio::test]
async fn middleware_rejects_blocked_path() {
    let upstream_addr = spawn_upstream().await;
    let mw = MiddlewareConfig {
        blocked_paths: vec!["/admin".to_string(), "/secret".to_string()],
        required_headers: vec![],
    };
    let (proxy_addr, _metrics) = spawn_proxy(upstream_addr, mw).await;

    // Blocked path should be rejected.
    let (status, body) = get(&format!("http://{proxy_addr}/admin")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Forbidden");

    // Non-blocked path should pass through.
    let (status, body) = get(&format!("http://{proxy_addr}/ok")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "upstream saw /ok");
}

#[tokio::test]
async fn middleware_rejects_missing_required_header() {
    let upstream_addr = spawn_upstream().await;
    let mw = MiddlewareConfig {
        blocked_paths: vec![],
        required_headers: vec!["x-api-key".to_string()],
    };
    let (proxy_addr, _metrics) = spawn_proxy(upstream_addr, mw).await;

    // Missing required header returns generic 400 without exposing the header name.
    let (status, body) = get(&format!("http://{proxy_addr}/api")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !body.contains("x-api-key"),
        "response must NOT leak the required header name; got: {body}"
    );
    assert!(body.contains("Bad Request"));
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_format() {
    let upstream_addr = spawn_upstream().await;
    let (proxy_addr, _metrics) = spawn_proxy(upstream_addr, MiddlewareConfig::default()).await;

    // Make a request to generate metrics.
    let _ = get(&format!("http://{proxy_addr}/hello")).await;

    // Fetch /metrics.
    let (status, body) = get(&format!("http://{proxy_addr}/metrics")).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("requests_total"));
    assert!(body.contains("request_duration_seconds"));
}

#[tokio::test]
async fn metrics_track_requests() {
    let upstream_addr = spawn_upstream().await;
    let (proxy_addr, metrics) = spawn_proxy(upstream_addr, MiddlewareConfig::default()).await;

    // Make two successful requests.
    let _ = get(&format!("http://{proxy_addr}/a")).await;
    let _ = get(&format!("http://{proxy_addr}/b")).await;

    assert_eq!(
        metrics.requests_total.with_label_values(&["allow"]).get(),
        2
    );
    assert_eq!(metrics.tool_calls_total.with_label_values(&["/a"]).get(), 1);
    assert_eq!(metrics.tool_calls_total.with_label_values(&["/b"]).get(), 1);
}

#[tokio::test]
async fn metrics_track_denied_requests() {
    let upstream_addr = spawn_upstream().await;
    let mw = MiddlewareConfig {
        blocked_paths: vec!["/blocked".to_string()],
        required_headers: vec![],
    };
    let (proxy_addr, metrics) = spawn_proxy(upstream_addr, mw).await;

    let _ = get(&format!("http://{proxy_addr}/blocked")).await;

    assert_eq!(metrics.requests_total.with_label_values(&["deny"]).get(), 1);
}
