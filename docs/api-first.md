# API-First Customer Integration (v3.7)

The shell experiment is an acceptance harness. It is not the customer control
interface. After the enterprise containers have started, customer platforms,
CMDB systems and DevSecOps pipelines use Manager API only.

## Boundary

One bootstrap action is unavoidable because the API cannot start its own
container or mount a host directory before it exists:

```bash
make build
make enterprise-init SCAN_ROOT="$PWD" SERVER_NAME=pqc-gateway.local LISTEN_PORT=28443
make enterprise-up
```

After that point, `pqapi` and Make targets are optional REST clients. They do
not access `control-plane.db`. A customer may call the same endpoints from Java,
Go, Python, C++, an API gateway or an existing management platform.

Load the generated bearer token for examples:

```bash
set -a
source .env.enterprise
set +a
```

Discover the machine-readable API contract and deployment capabilities:

```bash
curl http://127.0.0.1:18080/openapi.json

curl -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  http://127.0.0.1:18080/v1/capabilities
```

`/v1/capabilities` returns built-in protocol adapters, allowed scan roots,
release states, migration states and workflow endpoints. Host scan paths cannot
be added through REST: an administrator must pre-mount them read-only during
bootstrap, and API requests are constrained to the returned container roots.
The OpenAPI document includes reusable schemas for concise services, complete
release documents, enterprise scan requests and migration actions.

## One-call service onboarding and publication

A concise request is enough; the control plane expands compatibility TLS,
validates the canonical model, generates a signed immutable release and updates
desired state for the Gateway Agent:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  -H "X-PQ-Operator: enterprise-platform" \
  -H "Content-Type: application/json" \
  -d '{
    "service": {
      "id": "payment-pqc-gateway",
      "adapter": "http",
      "listen": {
        "address": "0.0.0.0",
        "port": 28443,
        "server_name": "payment-gateway.company.local"
      },
      "upstream": {
        "address": "https://payment.internal:9443",
        "tls": {
          "enabled": true,
          "verify": "required",
          "sni": "payment.internal",
          "ca": "/etc/ssl/certs/ca-certificates.crt"
        }
      }
    }
  }' \
  http://127.0.0.1:18080/v1/onboarding
```

The response status is `STAGED`, not `HEALTHY`. The Agent independently verifies
the signature and checksum, executes `nginx -t`, reloads, runs its health check
and reports the resulting release state.

Full canonical service specifications can use:

```text
POST /v1/services/{service_id}/publish
```

Resource CRUD without traffic publication remains available through
`/v1/services` and `/v1/policies`; publish their current set with
`POST /v1/releases/from-resources`.

## Scan-to-migration workflow

```text
POST /v1/scans
GET  /v1/scans/{scan_id}
GET  /v1/scans/{scan_id}/findings
GET  /v1/assets
GET  /v1/assets/{asset_id}
POST /v1/assets/{asset_id}/assess
POST /v1/assets/{asset_id}/migration
```

Create a scan against the pre-authorized container mount:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  -H "X-PQ-Operator: security-platform" \
  -H "Content-Type: application/json" \
  -d '{"type":"enterprise","roots":["/workspace/project"]}' \
  http://127.0.0.1:18080/v1/scans
```

Creating a migration plan stages compatibility mode. Strict promotion remains
gated by a `HEALTHY` compatibility release, explicit application verification
and an acceptable measured fallback rate.

## Release status and rollback

```bash
curl -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  http://127.0.0.1:18080/v1/releases

curl -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  http://127.0.0.1:18080/v1/status

curl -X POST \
  -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  -H "X-PQ-Operator: operations" \
  http://127.0.0.1:18080/v1/releases/1/rollback
```

Rollback creates a new signed release referencing `rollback_from`; historical
records are never modified.

## Python integration

```python
from manager.api_client import ManagerApiClient

api = ManagerApiClient(
    "http://127.0.0.1:18080",
    token="...",
    operator="customer-platform",
)

capabilities = api.capabilities()
release = api.onboard({
    "id": "payment-pqc-gateway",
    "adapter": "http",
    "listen": {"port": 28443, "server_name": "payment.company.local"},
    "upstream": {"address": "http://payment.internal:8080"},
})
scan = api.create_scan(["/workspace/project"])
completed = api.wait_scan(scan["scan_id"])
status = api.status()
```

The optional `manager/pqapi.py` executable exposes the same client for manual
testing. It is a REST wrapper, not an alternative direct-database control path.

## What remains outside the API

For security and causality, REST does not perform these infrastructure actions:

- installing or starting its own containers;
- creating arbitrary host directories or mounting host filesystems;
- changing DNS, load balancers, firewall rules or routes;
- issuing production certificates or retrieving private keys;
- changing host capabilities to enable eBPF.

These are one-time or privileged infrastructure operations and should be
handled by the customer's deployment system. Day-2 Gateway migration control is
available through REST.
