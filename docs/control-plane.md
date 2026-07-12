# Control Plane Runtime

v3.2 turns the v3.1 framework core into a persistent single-node control plane.

```text
pqctl / manager-api
        |
        | Service, Policy, release, migration intent
        v
SQLite config-store + audit + runtime metrics
        |
        | signed desired release
        v
gateway-agent -- heartbeat/status --> control plane
        |
        | nginx -t, atomic replace, reload, health check
        v
NGINX/OpenSSL data plane
```

The manager decides and records intent. The Agent verifies and executes released artifacts. NGINX only handles traffic.

## First-class resources

The SQLite control plane persists:

| Resource | Purpose |
|---|---|
| `Service` | Canonical downstream/upstream TLS and protocol configuration. |
| `Policy` | Compiled rollout boundary and fallback intent. |
| `ConfigVersion` | Source, rendered NGINX artifact, checksum and status history. |
| `GatewayAgent` | Current/desired version, health, reload result and heartbeat. |
| `MigrationState` | Audited service migration lifecycle. |
| `AuditEvent` | Operator and system actions. |
| `RuntimeMetric` | Prometheus-compatible counters and gauges. |

Staged configuration artifacts remain immutable. Updating a Service resource does not silently change traffic; the resource set must be published as a new ConfigVersion.

## Release lifecycle

Successful publication follows:

```text
DRAFT -> VALIDATED -> STAGED -> APPLIED -> HEALTHY
```

Failure states are:

```text
VALIDATION_FAILED
NGINX_TEST_FAILED
RELOAD_FAILED
HEALTH_CHECK_FAILED
ROLLED_BACK
```

Every transition is appended to `config_status_events`. A health or reload failure records its precise stage before a successful restore records `ROLLED_BACK`.

The Agent sequence is:

1. Verify the manifest signature when signing is enabled.
2. Verify the rendered SHA-256 checksum.
3. Execute `nginx -t` against a candidate path.
4. Preserve the current active configuration.
5. Atomically replace and reload NGINX.
6. Run the configured health check.
7. Mark the release `HEALTHY`, or restore the prior file and record rollback.

## CLI

Validate and publish a complete document:

```bash
python3 manager/pqctl.py config validate --file config/services.json
python3 manager/pqctl.py --operator alice config apply --file config/services.json
python3 manager/pqctl.py config history
python3 manager/pqctl.py config show 1
python3 manager/pqctl.py --operator alice config rollback 1
```

Manage first-class resources and publish their current set:

```bash
python3 manager/pqctl.py service list
python3 manager/pqctl.py service upsert --file service.json
python3 manager/pqctl.py policy list
python3 manager/pqctl.py config apply-resources
```

Inspect execution and observability:

```bash
python3 manager/pqctl.py agent list
python3 manager/pqctl.py agent get pq-gateway-1
python3 manager/pqctl.py metrics prometheus
python3 manager/pqctl.py migration history compatibility-gateway
```

## REST API

The optional API binds to host loopback in Compose. Generate independent bearer and signing secrets before starting it:

```bash
export MANAGER_API_TOKEN="$(openssl rand -hex 32)"
export PQ_CONFIG_SIGNING_KEY="$(openssl rand -hex 32)"
docker compose --profile control-plane up -d manager-api
```

Main endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Unauthenticated liveness. |
| GET | `/metrics` | Prometheus exposition; public only on the loopback-bound demo API by default. |
| GET/POST | `/v1/services` | List or create/update a Service. |
| GET/PUT/DELETE | `/v1/services/{id}` | Service resource CRUD. |
| GET/POST | `/v1/policies` | List or create/update a Policy. |
| GET/PUT/DELETE | `/v1/policies/{id}` | Policy resource CRUD. |
| GET/POST | `/v1/configs` | Release history or publish a complete document. |
| GET | `/v1/configs/{version}` | Release metadata and full status history. |
| POST | `/v1/configs/validate` | Validate without changing state. |
| POST | `/v1/configs/from-resources` | Publish registered Service resources. |
| POST | `/v1/configs/{version}/rollback` | Create a new rollback release. |
| GET | `/v1/agents` | List agents and computed stale state. |
| POST | `/v1/agents/{id}/heartbeat` | Agent runtime status report. |
| GET | `/v1/migrations` | Current migration states. |
| GET | `/v1/migrations/{id}/history` | Migration transition history. |
| POST | `/v1/services/{id}/transition` | Audited migration transition. |
| GET | `/v1/audit` | Audit trail. |
| GET | `/v1/metrics` | Metrics as JSON. |

All `/v1` endpoints require `Authorization: Bearer ...`. Operators should set `X-PQ-Operator` so audit records identify the caller. Use `--private-metrics` if `/metrics` must also require the bearer token.

## Metrics

The manager endpoint merges Agent/release metrics with the runtime log collector. The core names include:

```text
gateway_config_info
gateway_config_reload_total
gateway_config_rollback_total
gateway_config_apply_failures_total
gateway_agent_heartbeat_timestamp_seconds
gateway_agent_health
gateway_tls_handshakes_total
gateway_tls_group_total
gateway_classical_fallback_total
gateway_tls_handshake_failures_total
gateway_mtls_failures_total
gateway_upstream_tls_failures_total
gateway_connection_duration_seconds_sum
gateway_connection_duration_seconds_count
```

## Scope and security

- The API refuses to start without a bearer token.
- Compose exposes the API only on `127.0.0.1:18080`.
- SHA-256 always protects artifact integrity; HMAC-SHA-256 authenticates releases when `PQ_CONFIG_SIGNING_KEY` is configured on manager and Agent.
- Private keys are references and are not stored in SQLite.
- Business payloads are not stored in control-plane tables or metrics.
- This release remains single-node SQLite. PostgreSQL coordination, rolling multi-instance publication, certificate lifecycle and HSM/KMS providers are deferred.
