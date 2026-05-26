# MCP Gateway Observability Guide

> Looking for the pre-1.25.0 architecture (HTTP POSTs to metrics-service +
> SQLite + port 9465)? See [OBSERVABILITY-LEGACY.md](OBSERVABILITY-LEGACY.md).
> That document is retained for the 1.25.0 transition window and will be
> removed in 1.26.0.

This guide describes the **current** observability architecture (1.25.0+),
the metrics each service emits, and a cookbook of PromQL queries for the
investigations operators most often need to run.

## Table of Contents

- [Architecture in one diagram](#architecture-in-one-diagram)
- [Configuration](#configuration)
- [Metric inventory](#metric-inventory)
- [Query cookbook](#query-cookbook)
- [Verifying the migration is working](#verifying-the-migration-is-working)
- [Troubleshooting](#troubleshooting)

## Architecture in one diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                Registry / Auth-Server / Mcpgw                      │
│                                                                    │
│  In-process OTel SDK with:                                         │
│   • Path-2 events (registry_operation_total, auth_request_total,   │
│     tool_execution_total, tool_discovery_total, protocol_latency)  │
│   • Path-3 in-process counters (nginx_config_writes_total,         │
│     peer_sync_failures_total, m2m_orphan_cleanups_total, ...)      │
│   • HTTP auto-instrumentation (http_server_duration_milliseconds_*)│
│   • Mcpgw per-tool metrics (mcpgw_tool_invocations_total,          │
│     mcpgw_tool_duration)                                           │
└────────────────────────┬───────────────────────────────────────────┘
                         │
   ┌─────────────────────┴─────────────────────┐
   │                                           │
   │ HTTP GET /metrics on :9464                │ OTLP push (when configured)
   │ (always-on Prometheus exporter)           │ to OTEL_EXPORTER_OTLP_ENDPOINT
   │                                           │
   ▼                                           ▼
Prometheus (Compose) /                    Per-task ADOT sidecar (ECS)
in-cluster Prometheus (EKS)                  → Amazon Managed Prometheus
   │
   ▼
Grafana (or any Prometheus-compatible UI)
```

Three differences from the legacy architecture:

1. **No metrics-service container.** Each service emits metrics in-process via
   the OpenTelemetry SDK, not via HTTP POSTs to a separate Python service.
2. **No SQLite store.** Long-term retention is the operator's observability
   backend's job (Prometheus TSDB, AMP, Datadog, Grafana Cloud, etc.).
3. **No API keys.** The legacy `METRICS_API_KEY_*` family is unused; operators
   can remove them from `.env`. They are removed entirely in 1.26.0.

## Configuration

Two new environment variables introduced in 1.25.0, plus reuse of standard
OTel env vars. All four are wired into Docker Compose, Helm, and Terraform/ECS.

| Env var | Default | Purpose |
|---|---|---|
| `OTEL_EXPORTER_PROMETHEUS_HOST` | `0.0.0.0` | Bind address for the in-process Prometheus exporter listener. EKS needs `0.0.0.0` (Prometheus is in a different pod and the chart's NetworkPolicy gates access). Compose can use `127.0.0.1`. |
| `OTEL_EXPORTER_PROMETHEUS_PORT` | `9464` | Port the Prometheus exporter listens on. The Prometheus scrape config in `config/prometheus.yml` targets this port. |
| `OTEL_METRIC_EXPORT_INTERVAL_MS` | `15000` | OTel SDK metric flush interval. Lower for near-real-time dashboards during incident response. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | When set, the OTel SDK ALSO pushes metrics via OTLP. On ECS this points at the per-task ADOT sidecar at `http://localhost:4317`. On EKS, point at your in-cluster collector. Optional in Compose. |
| `METRICS_LEGACY_HTTP_POST` | `false` | When `true`, services ALSO POST JSON events to the legacy `metrics-service:8890`. One-release transition flag; removed in 1.26.0. |

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the docker entrypoint additionally
wraps uvicorn with `opentelemetry-instrument`, which auto-activates the
`opentelemetry-instrumentation-fastapi`, `-httpx`, `-asyncio`, `-pymongo`,
and `-logging` packages. This produces the standard HTTP semantic-convention
metrics (`http_server_duration_*`, `http_server_active_requests`) and per-route
spans without any application code change.

## Metric inventory

The full list of metrics emitted as of 1.25.0. **Names below are the Prometheus
exposition form** (after the OTel exporter appends the unit suffix).

### Counters and gauges (Path-2 + Path-3)

| Metric | Source | Labels | What it counts |
|---|---|---|---|
| `auth_request_total` | auth-server | `success`, `method`, `server` | Authenticated /validate calls |
| `tool_execution_total` | auth-server | `tool_name`, `server_name`, `success`, `method`, `client_name`, `client_version` | MCP tool calls detected at the auth layer |
| `registry_operation_total` | registry middleware | `operation`, `resource_type`, `success` | Registry API operations (list/create/update/delete/search) |
| `tool_discovery_total` | registry middleware | `results_count_bucket` | Semantic search calls |
| `health_check_total` | registry | `endpoint`, `status_code`, `healthy` | Health check probe count |
| `mcpgw_tool_invocations_total` | mcpgw | `tool`, `success` | FastMCP tool invocations |
| `nginx_config_writes_total` | registry | `status` | Nginx config file writes by outcome |
| `registry_nginx_updates_skipped_total` | registry | `operation` | Nginx updates skipped due to mode |
| `registry_mode_blocked_requests_total` | registry | `path_category`, `mode` | Requests blocked by registry mode |
| `peer_sync_failures_total` | registry | `peer_id`, `failure_type` | Federation peer sync failures |
| `app_log_mongodb_flush_failures_total` | registry | `service` | MongoDB log handler failures |
| `telemetry_sends_total` | registry | `event`, `status` | Telemetry events sent |
| `m2m_orphan_cleanups_total` | registry | `idp_had_record` | M2M orphan cleanup deletions |
| `mcp_registry_cloud_detection_total` | registry | `cloud`, `method` | Cloud-detection outcomes |
| `mcp_config_view_requests_total` | registry | `user_type` | Configuration view requests |
| `mcp_config_export_requests_total` | registry | `format`, `includes_sensitive` | Configuration export requests |
| `registry_logout_id_token_hint_present_total` | registry | — | Logouts with id_token hint present |
| `registry_logout_id_token_hint_missing_total` | registry | — | Logouts without id_token hint |
| `registry_logout_jwt_validation_failed_total` | registry | — | Logout JWT validation failures |
| `registry_logout_url_length_warning_total` | registry | — | Logout URLs over recommended length |
| `registry_session_store_resolve_total` | registry | `result` | Session store lookups |
| `m2m_management_requests_total` | registry | `operation`, `outcome` | Direct M2M client API calls |
| `metrics_emission_path_total` | registry, auth-server, mcpgw | `path` (`otel`/`legacy`) | Migration self-observability |
| `registry_deployment_mode_info` (Gauge) | registry | `deployment_mode`, `registry_mode` | Current deployment mode (always 1, observed each cycle) |

### Histograms

| Metric | Source | Labels | What it measures |
|---|---|---|---|
| `auth_request_duration_milliseconds` (`_count`, `_sum`, `_bucket`) | auth-server | `success`, `method`, `server` | Auth /validate latency |
| `tool_execution_duration_milliseconds` | auth-server | same as `tool_execution_total` | Tool call latency at auth layer |
| `protocol_latency_milliseconds` | auth-server | `flow_step`, `server_name` | Time between MCP protocol stages (init → tools/list, etc.) |
| `registry_operation_duration_milliseconds` | registry middleware | same as `registry_operation_total` | Registry API operation latency |
| `tool_discovery_duration_milliseconds` | registry middleware | same as `tool_discovery_total` | Semantic search latency |
| `peer_sync_duration_seconds` | registry | `peer_id`, `success` | Peer sync operation duration |
| `mcpgw_tool_duration_milliseconds` | mcpgw | `tool`, `success` | Per-tool invocation latency |

### HTTP auto-instrumentation (when OTel auto-instrument is active)

| Metric | Source | Labels | What it measures |
|---|---|---|---|
| `http_server_duration_milliseconds` | every service | `http_method`, `http_target`, `http_status_code`, `http_scheme`, `http_host`, `http_server_name`, `net_host_port`, `http_flavor` | Per-route HTTP request latency |
| `http_server_active_requests` | every service | same | In-flight requests right now |

> Note on `http_target`: this is the **raw URL path** (e.g.
> `/api/servers/airegistry-tools/rating`), not the FastAPI route template
> (`/api/servers/{path:path}/rating`). For paths with high-cardinality IDs
> this can produce many time series; in production with large catalogs you
> may want to add a label-relabel rule in Prometheus to collapse them.

## Query cookbook

Open `http://localhost:9090/graph` (Compose) or your AMP/Grafana UI and try
these. Most are useful in **Graph view** with the time window dropped to 5
minutes.

### Semantic search endpoint

| Goal | Query |
|---|---|
| Calls per second | `sum by (http_status_code)(rate(http_server_duration_milliseconds_count{http_target="/api/search/semantic"}[5m]))` |
| p95 latency | `histogram_quantile(0.95, sum by (le)(rate(http_server_duration_milliseconds_bucket{http_target="/api/search/semantic"}[5m])))` |
| Average latency | `rate(http_server_duration_milliseconds_sum{http_target="/api/search/semantic"}[5m]) / rate(http_server_duration_milliseconds_count{http_target="/api/search/semantic"}[5m])` |
| Application-level view (results-bucket dimension) | `sum by (results_count_bucket)(rate(tool_discovery_total[5m]))` |
| Search latency from middleware (alternative source) | `histogram_quantile(0.95, sum by (le)(rate(tool_discovery_duration_milliseconds_bucket[5m])))` |

### Mcpgw — per-tool stats

| Goal | Query |
|---|---|
| Total invocations per tool | `sum by (tool)(mcpgw_tool_invocations_total)` |
| Tool QPS | `sum by (tool)(rate(mcpgw_tool_invocations_total[5m]))` |
| Per-tool error rate | `sum by (tool)(rate(mcpgw_tool_invocations_total{success="False"}[5m])) / sum by (tool)(rate(mcpgw_tool_invocations_total[5m]))` |
| Most-called tool right now | `topk(3, sum by (tool)(rate(mcpgw_tool_invocations_total[5m])))` |
| p95 latency per tool | `histogram_quantile(0.95, sum by (le, tool)(rate(mcpgw_tool_duration_milliseconds_bucket[5m])))` |
| Average duration per tool | `sum by (tool)(rate(mcpgw_tool_duration_milliseconds_sum[5m])) / sum by (tool)(rate(mcpgw_tool_duration_milliseconds_count[5m]))` |
| Slowest tool right now | `topk(1, histogram_quantile(0.95, sum by (le, tool)(rate(mcpgw_tool_duration_milliseconds_bucket[5m]))))` |

### Any API endpoint — invocations + success/failure

Replace `<TARGET>` with the path you care about (e.g. `/api/servers`,
`/api/agents`, `/api/skills`, `/validate`, `/api/auth/login`).

| Goal | Query |
|---|---|
| List all routes that have ever been hit | `group by (http_target, http_method, job)(http_server_duration_milliseconds_count)` |
| Calls per second on `<TARGET>` | `sum by (http_status_code)(rate(http_server_duration_milliseconds_count{http_target="<TARGET>"}[5m]))` |
| Success/failure split | `sum by (http_status_code)(rate(http_server_duration_milliseconds_count{http_target="<TARGET>"}[5m]))` |
| Error rate (4xx/5xx as fraction of total) | `sum(rate(http_server_duration_milliseconds_count{http_target="<TARGET>",http_status_code=~"4..|5.."}[5m])) / sum(rate(http_server_duration_milliseconds_count{http_target="<TARGET>"}[5m]))` |
| p50 / p95 / p99 latency on `<TARGET>` | `histogram_quantile(0.95, sum by (le)(rate(http_server_duration_milliseconds_bucket{http_target="<TARGET>"}[5m])))` |
| Top 5 most-called routes | `topk(5, sum by (http_target, job)(rate(http_server_duration_milliseconds_count[5m])))` |
| Top 5 slowest routes (p95) | `topk(5, histogram_quantile(0.95, sum by (le, http_target)(rate(http_server_duration_milliseconds_bucket[5m]))))` |
| In-flight requests right now | `http_server_active_requests` |
| Request rate per service | `sum by (job)(rate(http_server_duration_milliseconds_count[5m]))` |

### Auth, sessions, federation

| Goal | Query |
|---|---|
| Auth requests per second by outcome | `sum by (success)(rate(auth_request_total[5m]))` |
| Auth p95 latency | `histogram_quantile(0.95, sum by (le)(rate(auth_request_duration_milliseconds_bucket[5m])))` |
| Session-store hit rate | `sum(rate(registry_session_store_resolve_total{result="hit"}[5m])) / sum(rate(registry_session_store_resolve_total[5m]))` |
| Federation peer sync failures by type | `sum by (peer_id, failure_type)(rate(peer_sync_failures_total[5m]))` |
| Logout JWT validation failure rate | `rate(registry_logout_jwt_validation_failed_total[5m])` |

### Registry health and operations

| Goal | Query |
|---|---|
| Registry API operations per second by type | `sum by (operation, resource_type)(rate(registry_operation_total[5m]))` |
| Operations p95 latency | `histogram_quantile(0.95, sum by (le, operation)(rate(registry_operation_duration_milliseconds_bucket[5m])))` |
| Nginx config write outcomes | `sum by (status)(rate(nginx_config_writes_total[5m]))` |
| M2M orphan cleanups | `sum by (idp_had_record)(rate(m2m_orphan_cleanups_total[5m]))` |
| Cloud detection method distribution | `sum by (cloud, method)(mcp_registry_cloud_detection_total)` |
| Telemetry pings success rate | `sum(rate(telemetry_sends_total{status="success"}[5m])) / sum(rate(telemetry_sends_total[5m]))` |

## Verifying the migration is working

Three checks operators can run after upgrading from 1.24.x to 1.25.0:

**1. All Prometheus targets UP**

```
http://localhost:9090/targets
```

You should see `mcp-registry`, `mcp-auth-server`, `mcp-mcpgw`, and (until
1.26.0) `mcp-metrics-service` in the targets list, all with state `UP`.

**2. Migration self-observability**

```
metrics_emission_path_total
```

Should show `path="otel"` rows incrementing on every request.
`path="legacy"` should be empty (or zero) when `METRICS_LEGACY_HTTP_POST=false`.
If both are incrementing, you have the dual-write transition flag enabled.

**3. Previously-invisible counters are now visible**

```
nginx_config_writes_total
peer_sync_failures_total
m2m_orphan_cleanups_total
```

These were `prometheus_client.Counter` instances declared in the registry
process for releases but never exposed anywhere. If they return rows now,
the migration to OTel-native emission worked.

## Troubleshooting

### A Prometheus target shows DOWN with "connection refused"

The OTel SDK Prometheus exporter starts during application startup, after
the SDK initializes. Containers go `Up` before this completes. Wait one or
two scrape intervals (10-20 seconds) and re-check. If still DOWN:

```bash
docker compose exec <service> ss -tlnp | grep 9464
```

If that shows nothing, the Prometheus exporter never bound. Most common
cause: `OTEL_EXPORTER_PROMETHEUS_HOST` is unset, so the bootstrap helper
in the meter module took the no-op path. Set it in `.env` and recreate the
container.

### A query returns "Empty query result"

In order:

1. Wait one minute. Counters appear after first emission. Histograms appear
   after first observation. Rate functions need at least 2 data points in
   the rate window.
2. Try the simpler form: drop labels and aggregations, just type the metric
   name. If that returns rows, your filter is wrong (most often: a label
   typo).
3. Check the raw exposition: `docker compose exec prometheus wget -qO- http://<service>:9464/metrics 2>/dev/null | grep <metric>`.
   If the metric is there, Prometheus's scrape didn't pick it up yet
   (10-second scrape interval). If it's not there, the application code
   didn't emit it.

### `*_milliseconds_*` metric names look weird

That's standard. The OTel-to-Prometheus exporter appends the OTel `unit=`
annotation to histogram metric names. So a Histogram declared with
`unit="ms"` exports as `<name>_milliseconds`, regardless of what we named
the OTel instrument. The naming follows the OTel spec.

### I want to inspect what's actually being scraped without going through Prometheus

```bash
docker compose exec <service> curl -s http://localhost:9464/metrics
```

Or from any other container on the Docker network:

```bash
docker compose exec prometheus wget -qO- http://<service>:9464/metrics
```

### I want metrics flowing to AMP / Datadog / Honeycomb instead of (or in addition to) Prometheus

Set `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_HEADERS` in `.env`.
The OTel SDK will then push every metric over OTLP in addition to serving
the Prometheus exporter on `:9464`. On ECS, the AMP push is wired
automatically via the per-task ADOT sidecar (Phase E of #1122).

### How do I disable OTel emission entirely

Don't set `OTEL_EXPORTER_PROMETHEUS_HOST`, don't set `OTEL_EXPORTER_OTLP_ENDPOINT`.
The bootstrap helpers will detect the unset state and leave the SDK in
NoOp mode. Every `Counter.add()` and `Histogram.record()` call across the
codebase becomes a zero-cost no-op.

## Related docs

- [docs/metrics-architecture.md](metrics-architecture.md) — design-level
  diagrams (component view, sequence diagrams)
- [docs/unified-parameter-reference.md](unified-parameter-reference.md) —
  cross-surface env var mapping
- [docs/OBSERVABILITY-LEGACY.md](OBSERVABILITY-LEGACY.md) — pre-1.25.0
  architecture, retained for the transition window
