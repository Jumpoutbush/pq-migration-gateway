# Scan-to-Migration REST API (v3.4)

v3.4 connects enterprise discovery to the existing release controller. A scan
creates persistent `CryptoAsset` and finding records; assessment produces a
migration decision; a migration request stages compatibility mode; strict mode
is rejected until the compatibility release is healthy and supplied
verification/fallback gates pass.

## Start the API

```bash
export MANAGER_API_TOKEN="$(openssl rand -hex 32)"
export PQ_CONFIG_SIGNING_KEY="$(openssl rand -hex 32)"
docker compose --profile control-plane up -d manager-api
```

Compose mounts the project read-only at `/workspace/project`, which is the
default authorized scan root. Enterprise deployments should replace that mount
and `PQ_SCAN_ALLOWED_ROOTS` with explicit, read-only application paths. API
clients cannot submit roots outside this allowlist.

## Scan and query assets

```bash
curl -X POST \
  -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  -H "X-PQ-Operator: alice" \
  -H 'Content-Type: application/json' \
  -d '{
    "type":"enterprise",
    "roots":["/workspace/project/app"],
    "compile_commands":["/workspace/project/app/build/compile_commands.json"],
    "cpp_semantic":"auto"
  }' \
  http://127.0.0.1:18080/v1/scans
```

The response is `202 Accepted`. Poll the returned scan ID:

```text
GET /v1/scans
GET /v1/scans/{scan_id}
GET /v1/scans/{scan_id}/findings
GET /v1/assets
GET /v1/assets/{asset_id}
```

Jobs use `QUEUED`, `RUNNING`, `SUCCEEDED` and `FAILED`. Scanner output is saved
under the control directory and normalized into SQLite. Source/binary artifacts,
certificates and keys become assets. Interface evidence remains linked to the
owning artifact.

## Assess and stage compatibility mode

```text
POST /v1/assets/{asset_id}/assess
```

Then provide the network boundary that static code scanning cannot safely
invent:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  -H "X-PQ-Operator: alice" \
  -H 'Content-Type: application/json' \
  -d '{
    "action":"create",
    "service":{
      "id":"payment-pqc-gateway",
      "adapter":"http",
      "listen":{"address":"0.0.0.0","port":28443,"server_name":"payment-gateway.local"},
      "upstream":{"address":"http://payment.internal:8080"}
    }
  }' \
  http://127.0.0.1:18080/v1/assets/ASSET_ID/migration
```

The controller forces the first release to:

```json
{
  "downstream_tls":{"mode":"compatibility","groups":["X25519MLKEM768","X25519"]},
  "rollout":{"policy":"fixed","hybrid_percentage":100,"fallback_allowed":true}
}
```

The gateway agent still performs signature/checksum verification, `nginx -t`,
atomic replacement, reload and health check. The API does not claim that a
`STAGED` release is active.

## Verify and promote strict PQC

Strict promotion requires the compatibility version to be `HEALTHY`, an
explicit successful verification result and a fallback rate at or below the
plan threshold (default `0.01`):

```json
{
  "action":"verify",
  "plan_id":"plan-...",
  "passed":true,
  "verification_result":"hybrid clients passed; fallback rate below gate",
  "fallback_rate":0.0
}
```

The new immutable release uses only `X25519MLKEM768` and disables classical
fallback. After that strict release becomes `HEALTHY`, complete the migration:

```json
{
  "action":"complete",
  "plan_id":"plan-...",
  "verification_result":"strict endpoint healthy"
}
```

The migration state sequence is auditable:

```text
DISCOVERED -> ASSESSED -> PLANNED -> COMPATIBILITY -> STRICT -> VERIFIED
```

## Security boundaries

- `/v1` requires a bearer token and records `X-PQ-Operator`.
- Scan roots, compilation databases, imported traces and eBPF libraries must be
  below an administrator configured allowlist.
- Compilation database commands are parsed, hashed and never executed.
- Live process scanning and eBPF are disabled by default.
- eBPF requires explicit server enablement plus a fixed library, PID and bounded
  duration; arbitrary bpftrace programs cannot be supplied through the API.
- The API does not infer business ownership, upstream addresses or listening
  ports from a source file. Those deployment facts must come from CMDB or the
  migration request.

Run the deterministic workflow experiment with:

```bash
make scan-migration-api-test
cat experiment-results/manual-scan-migration-api/scan-migration-api-matrix.json
```
