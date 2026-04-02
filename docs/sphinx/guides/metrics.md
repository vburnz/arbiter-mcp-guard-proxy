# Monitoring & Metrics

Arbiter exposes Prometheus-compatible metrics on the proxy's `/metrics` endpoint. These cover request volume, authorization decisions, tool usage, latency, and resource utilization.

## Accessing Metrics

```bash
$ curl http://localhost:8080/metrics
```

The response is in Prometheus text exposition format, ready to scrape.

## Available Metrics

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `requests_total` | `decision` (allow, deny, escalate) | Total proxied requests by authorization outcome |
| `tool_calls_total` | `tool` | Total calls per tool name |
| `anomalies_total` | (none) | Total behavioral anomalies detected |

### Histograms

| Metric | Buckets | Description |
|--------|---------|-------------|
| `request_duration_seconds` | 5ms to 10s | End-to-end request duration including upstream |
| `upstream_duration_seconds` | 5ms to 10s | Time spent waiting for the upstream MCP server |

### Gauges

| Metric | Description |
|--------|-------------|
| `active_sessions` | Currently active task sessions |
| `registered_agents` | Total registered agents |

## Useful Queries

### Denial Rate

```promql
rate(requests_total{decision="deny"}[5m]) / rate(requests_total[5m])
```

A high denial rate might mean policies are too restrictive, or it might mean an agent is misbehaving. Check the audit log to distinguish.

### Most-Called Tools

```promql
topk(10, rate(tool_calls_total[1h]))
```

### P99 Latency

```promql
histogram_quantile(0.99, rate(request_duration_seconds_bucket[5m]))
```

### Upstream vs. Arbiter Overhead

```promql
histogram_quantile(0.50, rate(request_duration_seconds_bucket[5m]))
-
histogram_quantile(0.50, rate(upstream_duration_seconds_bucket[5m]))
```

The difference is Arbiter's middleware overhead, typically under 5ms for the full chain.

## Health Check

```bash
$ curl http://localhost:8080/health
OK
```

Returns 200 with body `OK` when the proxy is running and can reach the upstream. Use this for load balancer health checks and readiness probes.

## Configuration

```toml
[metrics]
enabled = true
```

Set `enabled = false` to disable the `/metrics` endpoint if you're not using Prometheus.

## Alerting Suggestions

Based on the available metrics, here's a sensible starting set of alerts:

| Alert | Condition | Why |
|-------|-----------|-----|
| High denial rate | `rate(requests_total{decision="deny"}) > 0.5 * rate(requests_total)` | More than half of requests being denied suggests misconfiguration or attack |
| Anomaly spike | `rate(anomalies_total[5m]) > 1` | Sustained anomalies mean agents are drifting from declared intent |
| High latency | `histogram_quantile(0.99, ...) > 2` | P99 above 2 seconds suggests upstream issues |
| Session exhaustion | `active_sessions` near the per-agent cap | Agents may be hitting session limits |

## Next Steps

- {doc}`../operating/monitoring`: Grafana dashboards and production monitoring setup
- {doc}`audit`: structured audit logs complement metrics with per-request detail
- {doc}`../reference/configuration`: full `[metrics]` configuration reference
