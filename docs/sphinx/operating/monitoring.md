# Monitoring

Arbiter exposes Prometheus metrics and structured JSONL audit logs. This guide covers setting up production monitoring: scraping metrics, building dashboards, and configuring alerts.

## Prometheus Scraping

Add Arbiter to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'arbiter'
    static_configs:
      - targets: ['arbiter:8080']
    metrics_path: /metrics
    scrape_interval: 15s
```

If running in Kubernetes, the equivalent service monitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: arbiter
spec:
  selector:
    matchLabels:
      app: arbiter
  endpoints:
    - port: proxy
      path: /metrics
      interval: 15s
```

## Dashboard Layout

A useful Arbiter dashboard has four panels:

### Request Volume and Decisions

```promql
# Stacked area chart: allow vs deny vs escalate
sum by (decision) (rate(requests_total[5m]))
```

This tells you at a glance whether the system is mostly allowing or mostly denying. A sudden spike in denials warrants investigation.

### Top Tools

```promql
topk(10, sum by (tool) (rate(tool_calls_total[5m])))
```

Shows which tools agents are actually using. Useful for capacity planning and for spotting unexpected tool usage.

### Request Latency

```promql
histogram_quantile(0.50, rate(request_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(request_duration_seconds_bucket[5m]))
```

P50, P95, P99 in a single chart. Arbiter's overhead is typically under 5ms; if latency is high, the upstream MCP server is the bottleneck.

### Active Resources

```promql
active_sessions
registered_agents
```

Gauges that show current utilization.

## Alerts

### High Denial Rate

```yaml
- alert: ArbiterHighDenialRate
  expr: |
    rate(requests_total{decision="deny"}[5m])
    /
    rate(requests_total[5m])
    > 0.5
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "More than 50% of requests are being denied"
```

### Anomaly Detection Firing

```yaml
- alert: ArbiterAnomalySpike
  expr: rate(anomalies_total[5m]) > 0.1
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Behavioral anomalies detected. Agents may be drifting from intent."
```

### Upstream Latency Degradation

```yaml
- alert: ArbiterUpstreamSlow
  expr: histogram_quantile(0.99, rate(upstream_duration_seconds_bucket[5m])) > 5
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Upstream MCP server P99 latency exceeds 5 seconds"
```

## Health Checks

```bash
$ curl http://localhost:8080/health
OK
```

Returns HTTP 200 with body `OK`. Use this for:
- Load balancer health checks
- Kubernetes liveness/readiness probes
- Uptime monitoring

## Structured Logs

Arbiter uses `tracing-subscriber` for structured logging. Log level is configurable at startup:

```bash
$ arbiter --config arbiter.toml --log-level info
```

Levels: `error`, `warn`, `info`, `debug`, `trace`. In production, `info` is a good default: it logs request summaries without the noise of debug-level middleware tracing.

## Next Steps

- {doc}`troubleshooting`: diagnosing common issues
- {doc}`../guides/metrics`: detailed metrics reference
- {doc}`../guides/audit`: structured audit logging
