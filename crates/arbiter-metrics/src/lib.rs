//! Arbiter Metrics: Prometheus-compatible metrics for the Arbiter proxy.
//!
//! Provides counters (requests, tool calls, anomalies), histograms (request and
//! upstream duration), and gauges (active sessions, registered agents). Exposes
//! a `/metrics` handler that returns metrics in the Prometheus text exposition
//! format.

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use std::collections::HashSet;
use std::sync::Mutex;
use thiserror::Error;

/// Limit metric label cardinality to prevent memory exhaustion.
/// If more than this many unique tool names are seen, new ones are bucketed under
/// "__other__" to bound memory usage.
const MAX_TOOL_LABEL_CARDINALITY: usize = 1000;

/// Errors from the metrics subsystem.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
}

/// All Arbiter proxy metrics, registered against a single [`Registry`].
pub struct ArbiterMetrics {
    registry: Registry,

    /// Total requests by authorization decision (allow / deny / escalate).
    pub requests_total: IntCounterVec,

    /// Total tool calls by tool name.
    pub tool_calls_total: IntCounterVec,

    /// Total anomalies detected.
    pub anomalies_total: IntCounter,

    /// End-to-end request duration in seconds.
    pub request_duration_seconds: Histogram,

    /// Duration of the upstream (forwarded) call in seconds.
    pub upstream_duration_seconds: Histogram,

    /// Number of currently active task sessions.
    pub active_sessions: IntGauge,

    /// Number of currently registered agents.
    pub registered_agents: IntGauge,

    /// Tracks unique tool label values to enforce cardinality limits.
    known_tools: Mutex<HashSet<String>>,
}

impl ArbiterMetrics {
    /// Create and register all metrics against a new registry.
    pub fn new() -> Result<Self, MetricsError> {
        let registry = Registry::new();
        Self::with_registry(registry)
    }

    /// Create and register all metrics against the provided registry.
    pub fn with_registry(registry: Registry) -> Result<Self, MetricsError> {
        let requests_total = IntCounterVec::new(
            Opts::new("requests_total", "Total requests by authorization decision"),
            &["decision"],
        )?;
        registry.register(Box::new(requests_total.clone()))?;

        let tool_calls_total = IntCounterVec::new(
            Opts::new("tool_calls_total", "Total tool calls by tool name"),
            &["tool"],
        )?;
        registry.register(Box::new(tool_calls_total.clone()))?;

        let anomalies_total =
            IntCounter::with_opts(Opts::new("anomalies_total", "Total anomalies detected"))?;
        registry.register(Box::new(anomalies_total.clone()))?;

        let request_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "request_duration_seconds",
                "End-to-end request duration in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )?;
        registry.register(Box::new(request_duration_seconds.clone()))?;

        let upstream_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "upstream_duration_seconds",
                "Duration of upstream (forwarded) call in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )?;
        registry.register(Box::new(upstream_duration_seconds.clone()))?;

        let active_sessions = IntGauge::with_opts(Opts::new(
            "active_sessions",
            "Currently active task sessions",
        ))?;
        registry.register(Box::new(active_sessions.clone()))?;

        let registered_agents = IntGauge::with_opts(Opts::new(
            "registered_agents",
            "Currently registered agents",
        ))?;
        registry.register(Box::new(registered_agents.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            tool_calls_total,
            anomalies_total,
            request_duration_seconds,
            upstream_duration_seconds,
            active_sessions,
            registered_agents,
            known_tools: Mutex::new(HashSet::new()),
        })
    }

    /// Record a request with the given authorization decision.
    ///
    /// Decision labels are restricted to a closed allowlist to prevent
    /// unbounded cardinality from arbitrary caller-supplied strings.
    pub fn record_request(&self, decision: &str) {
        let label = match decision {
            "allow" | "deny" | "escalate" | "error" => decision,
            _ => "__unknown__",
        };
        self.requests_total.with_label_values(&[label]).inc();
    }

    /// Record a tool call for the given tool name.
    ///
    /// Tool name labels are sanitized to strict alphanumeric + underscore + '/'
    /// to prevent Prometheus text format injection and PII leakage via metric
    /// label values. The label is also truncated to 64 chars (shorter than
    /// before) to reduce the risk of embedding identifiers.
    pub fn record_tool_call(&self, tool: &str) {
        let sanitized: String = tool
            .chars()
            .take(64)
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '/' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let label = {
            let mut known = self.known_tools.lock().unwrap_or_else(|e| {
                tracing::error!("known_tools mutex poisoned, recovering");
                e.into_inner()
            });
            if known.contains(&sanitized) || known.len() < MAX_TOOL_LABEL_CARDINALITY {
                known.insert(sanitized.clone());
                sanitized
            } else {
                "__other__".to_string()
            }
        };
        self.tool_calls_total.with_label_values(&[&label]).inc();
    }

    /// Record an anomaly.
    pub fn record_anomaly(&self) {
        self.anomalies_total.inc();
    }

    /// Observe a request duration in seconds.
    /// Clamps negative or non-finite values to 0.0 to prevent histogram corruption.
    pub fn observe_request_duration(&self, seconds: f64) {
        let clamped = if seconds.is_finite() && seconds >= 0.0 {
            seconds
        } else {
            tracing::warn!(raw = seconds, "clamping invalid request duration to 0.0");
            0.0
        };
        self.request_duration_seconds.observe(clamped);
    }

    /// Observe an upstream call duration in seconds.
    /// Clamps negative or non-finite values to 0.0 to prevent histogram corruption.
    pub fn observe_upstream_duration(&self, seconds: f64) {
        let clamped = if seconds.is_finite() && seconds >= 0.0 {
            seconds
        } else {
            tracing::warn!(raw = seconds, "clamping invalid upstream duration to 0.0");
            0.0
        };
        self.upstream_duration_seconds.observe(clamped);
    }

    /// Render all metrics in the Prometheus text exposition format.
    pub fn render(&self) -> Result<String, MetricsError> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        String::from_utf8(buffer)
            .map_err(|e| MetricsError::Prometheus(prometheus::Error::Msg(
                format!("metrics encoding produced invalid UTF-8: {e}")
            )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let metrics = ArbiterMetrics::new().unwrap();

        metrics.record_request("allow");
        metrics.record_request("allow");
        metrics.record_request("deny");
        metrics.record_tool_call("read_file");
        metrics.record_tool_call("read_file");
        metrics.record_tool_call("write_file");
        metrics.record_anomaly();

        assert_eq!(
            metrics.requests_total.with_label_values(&["allow"]).get(),
            2
        );
        assert_eq!(metrics.requests_total.with_label_values(&["deny"]).get(), 1);
        assert_eq!(
            metrics
                .tool_calls_total
                .with_label_values(&["read_file"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .tool_calls_total
                .with_label_values(&["write_file"])
                .get(),
            1
        );
        assert_eq!(metrics.anomalies_total.get(), 1);
    }

    #[test]
    fn metrics_endpoint_returns_valid_prometheus_format() {
        let metrics = ArbiterMetrics::new().unwrap();

        metrics.record_request("allow");
        metrics.record_tool_call("list_dir");
        metrics.observe_request_duration(0.042);
        metrics.observe_upstream_duration(0.035);
        metrics.active_sessions.set(3);
        metrics.registered_agents.set(5);

        let output = metrics.render().unwrap();

        // Prometheus format: lines are either comments (# ...) or metric lines.
        assert!(output.contains("requests_total"));
        assert!(output.contains("tool_calls_total"));
        assert!(output.contains("anomalies_total"));
        assert!(output.contains("request_duration_seconds"));
        assert!(output.contains("upstream_duration_seconds"));
        assert!(output.contains("active_sessions 3"));
        assert!(output.contains("registered_agents 5"));

        // Verify HELP and TYPE lines exist (Prometheus convention).
        assert!(output.contains("# HELP requests_total"));
        assert!(output.contains("# TYPE requests_total counter"));
        assert!(output.contains("# HELP request_duration_seconds"));
        assert!(output.contains("# TYPE request_duration_seconds histogram"));
    }

    #[test]
    fn histogram_buckets_are_present() {
        let metrics = ArbiterMetrics::new().unwrap();
        metrics.observe_request_duration(0.05);

        let output = metrics.render().unwrap();

        // Histograms should have _bucket, _sum, and _count lines.
        assert!(output.contains("request_duration_seconds_bucket"));
        assert!(output.contains("request_duration_seconds_sum"));
        assert!(output.contains("request_duration_seconds_count"));
    }

    #[test]
    fn gauges_can_increase_and_decrease() {
        let metrics = ArbiterMetrics::new().unwrap();

        metrics.active_sessions.set(10);
        assert_eq!(metrics.active_sessions.get(), 10);

        metrics.active_sessions.dec();
        assert_eq!(metrics.active_sessions.get(), 9);

        metrics.registered_agents.inc();
        metrics.registered_agents.inc();
        assert_eq!(metrics.registered_agents.get(), 2);
    }

    /// Cardinality limiting must cap unique tool labels at MAX_TOOL_LABEL_CARDINALITY.
    /// The 1001st unique tool name should be bucketed under "__other__".
    #[test]
    fn cardinality_limiting_works() {
        let metrics = ArbiterMetrics::new().unwrap();

        // Record exactly MAX_TOOL_LABEL_CARDINALITY unique tool names
        for i in 0..MAX_TOOL_LABEL_CARDINALITY {
            metrics.record_tool_call(&format!("tool_{i}"));
        }

        // The next unique tool name should be bucketed under "__other__"
        metrics.record_tool_call("tool_overflow_a");
        metrics.record_tool_call("tool_overflow_b");

        // Verify __other__ got the overflow calls
        let other_count = metrics
            .tool_calls_total
            .with_label_values(&["__other__"])
            .get();
        assert_eq!(
            other_count, 2,
            "overflow tool calls should be bucketed under __other__"
        );

        // Verify one of the original tools is still tracked under its own name
        let first_count = metrics
            .tool_calls_total
            .with_label_values(&["tool_0"])
            .get();
        assert_eq!(first_count, 1, "original tool should still have its label");

        // Verify the known_tools set is capped
        let known = metrics.known_tools.lock().unwrap();
        assert_eq!(
            known.len(),
            MAX_TOOL_LABEL_CARDINALITY,
            "known tools should be capped at MAX_TOOL_LABEL_CARDINALITY"
        );

        // Verify that a previously-known tool still gets its own label
        // even after the cap is reached
        drop(known);
        metrics.record_tool_call("tool_0");
        let first_count = metrics
            .tool_calls_total
            .with_label_values(&["tool_0"])
            .get();
        assert_eq!(
            first_count, 2,
            "repeated calls to known tools should still use original label"
        );
    }

    /// Decision labels must be restricted to the closed allowlist.
    /// Arbitrary strings go to __unknown__.
    #[test]
    fn decision_label_allowlist() {
        let metrics = ArbiterMetrics::new().unwrap();
        metrics.record_request("allow");
        metrics.record_request("deny");
        metrics.record_request("escalate");
        metrics.record_request("error");
        metrics.record_request("something_unexpected");
        metrics.record_request("");

        assert_eq!(metrics.requests_total.with_label_values(&["allow"]).get(), 1);
        assert_eq!(metrics.requests_total.with_label_values(&["deny"]).get(), 1);
        assert_eq!(metrics.requests_total.with_label_values(&["escalate"]).get(), 1);
        assert_eq!(metrics.requests_total.with_label_values(&["error"]).get(), 1);
        assert_eq!(
            metrics.requests_total.with_label_values(&["__unknown__"]).get(), 2,
            "unexpected decision values must be bucketed under __unknown__"
        );
    }

    /// Tool labels must sanitize special characters that could break Prometheus format.
    #[test]
    fn tool_label_sanitizes_special_chars() {
        let metrics = ArbiterMetrics::new().unwrap();
        // Prometheus-special chars should be replaced with underscore
        metrics.record_tool_call("tool{job=\"arbiter\"}");
        // The sanitized label should not contain { } " =
        let output = metrics.render().unwrap();
        assert!(
            !output.contains("tool{job"),
            "special chars in tool labels must be sanitized, got: {output}"
        );
    }

    /// Negative or NaN durations should be clamped to 0.0, not corrupt the histogram.
    #[test]
    fn histogram_rejects_invalid_values() {
        let metrics = ArbiterMetrics::new().unwrap();
        metrics.observe_request_duration(-1.0);
        metrics.observe_request_duration(f64::NAN);
        metrics.observe_request_duration(f64::INFINITY);
        metrics.observe_upstream_duration(-0.5);

        let output = metrics.render().unwrap();
        // The histogram should still render without NaN in the sum
        assert!(
            !output.contains("NaN"),
            "NaN should not appear in rendered metrics"
        );
    }
}
