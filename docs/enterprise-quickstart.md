# Enterprise Deployment and API Operations (v3.7)

v3.7 separates the customer runtime from the deterministic demo experiment and makes all post-start control operations available through REST.
`docker-compose.yml` and `run_full_experiment.sh` remain the development and
acceptance environment. `deploy/enterprise/docker-compose.yml` is the customer
runtime and contains no demo bank, MQTT, TCP or secure backend.

## 1. What the enterprise profile starts

```text
Authorized application directory (read-only)
              |
              v
        Manager API :18080  <----- Customer REST clients
              |                    |
              | SQLite + signed releases
              v                    v
Enterprise Gateway listeners ---> Existing business upstreams
              |
              v
       Runtime metrics agent
              |
              v
Prometheus :9090 ---> Grafana :3000
```

The Manager API, Prometheus and Grafana bind to host loopback. Gateway business
listeners bind as declared in `config/enterprise/services.json`. The enterprise
profile uses host networking so a service can add high-numbered listener ports
without editing a Docker port list. Production firewall rules remain an
administrator responsibility.

## 2. Initialize a pilot workspace

Requirements: Linux or WSL2, Docker Compose, Python 3.10+, OpenSSL and Make.

Build the v3.7 data-plane image once:

```bash
make build
```

Authorize one enterprise directory for scanning and generate an isolated
configuration, bearer token, release-signing key and pilot certificate:

```bash
make enterprise-init \
  SCAN_ROOT="$PWD" \
  SERVER_NAME=payment-gateway.company.local \
  LISTEN_PORT=28443
```

`SCAN_ROOT` must be an existing directory on the Docker host. Use the project
directory for a first smoke test, or replace `$PWD` with the absolute path of
the actual application tree. Initialization deliberately does not create an
arbitrary host path on behalf of the API.

Generated state:

```text
.env.enterprise                         mode 0600; API/signing/Grafana secrets
config/enterprise/services.json         enterprise service model
runtime-data/enterprise/certs/          pilot certificate and private key
runtime-data/enterprise/control/        SQLite, releases and audit
runtime-data/enterprise/logs/           NGINX JSON logs
runtime-data/enterprise/metrics/        JSON/JSONL/Prometheus runtime metrics
```

Initialization is idempotent and preserves existing secrets and certificates.
The pilot RSA certificate authenticates the TLS endpoint; the post-quantum
property under test is the TLS 1.3 `X25519MLKEM768` key agreement. Replace the
pilot certificate with certificates from enterprise PKI before production.

## 3. Start the enterprise control and data planes

Start only enterprise runtime components:

```bash
make enterprise-up
make enterprise-status
```

The first start creates a signed immutable pilot release through the Manager
API. Confirm the adapters, authorized scan roots and API workflows:

```bash
make enterprise-capabilities
curl http://127.0.0.1:18080/openapi.json
```

`openapi.json` is the machine-readable integration contract. All authenticated
examples use the token generated in `.env.enterprise`.

## 4. Add and publish the real business boundary through REST

Copy and edit the bundled `config/enterprise/service-onboarding.example.json`,
or create `payment-service.json`:

```json
{
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
```

Submit it with the optional REST wrapper:

```bash
make enterprise-api-onboard SERVICE_FILE=payment-service.json
```

This is equivalent to `POST /v1/onboarding`. The control plane expands the
common compatibility TLS fields, validates the complete model, creates a signed
immutable release and changes desired state. The first real service replaces
the generated `enterprise-pilot`; later requests update or append services.

The Gateway Agent then verifies the signature and checksum, runs `nginx -t`,
atomically replaces the active configuration, reloads NGINX and reports health.
Inspect release history and aggregate state:

```bash
make enterprise-history
make enterprise-status
```

For a complete canonical configuration document, `make enterprise-apply` calls
`POST /v1/releases`. Roll back by creating a new auditable release from an old
version:

```bash
make enterprise-rollback VERSION=1
```

Follow operational logs:

```bash
make enterprise-logs
```

The Make targets above are convenience REST clients. They do not access the
control-plane SQLite database. Customer systems may call the same API directly
from Java, Go, Python, C++ or an API management platform.

## 5. Run an authorized enterprise scan

The host directory supplied as `SCAN_ROOT` is mounted read-only at
`/workspace/project`. API requests cannot escape that allowlist.

Start a full scan through `POST /v1/scans`:

```bash
make enterprise-scan
```

The response contains a `scan_id`. Load the generated token without printing it:

```bash
set -a
source .env.enterprise
set +a
```

Poll and inspect results:

```bash
curl -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  http://127.0.0.1:18080/v1/scans/SCAN_ID

curl -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  http://127.0.0.1:18080/v1/scans/SCAN_ID/findings

make enterprise-assets
```

For C++ compilation metadata, submit an explicit container path:

```bash
curl -X POST \
  -H "Authorization: Bearer $MANAGER_API_TOKEN" \
  -H "X-PQ-Operator: security-team" \
  -H "Content-Type: application/json" \
  -d '{
    "type":"enterprise",
    "roots":["/workspace/project"],
    "compile_commands":["/workspace/project/build/compile_commands.json"],
    "cpp_semantic":"auto"
  }' \
  http://127.0.0.1:18080/v1/scans
```

Process correlation and live eBPF observation remain disabled unless explicitly
enabled in `.env.enterprise`. Enabling eBPF also requires host permissions and a
separate security review; the default hardened Compose drops all capabilities.

## 6. Observe migration continuously

Start the bundled monitoring stack:

```bash
make dashboard-up
```

Open locally:

```text
Grafana:    http://127.0.0.1:3000
Prometheus: http://127.0.0.1:9090
```

Grafana user is `admin`; the generated password is
`GRAFANA_ADMIN_PASSWORD` in `.env.enterprise`. The pre-provisioned dashboard is
under `PQC Migration / PQC Migration Gateway — Enterprise Overview`.

It shows:

- total and quantum-vulnerable cryptographic assets;
- scan job status and migration plan status;
- service migration state;
- negotiated `X25519MLKEM768` and `X25519` groups per service;
- hybrid adoption and classical fallback;
- TLS, downstream mTLS and upstream TLS failures;
- active connections, Agent health and configuration version.

Prometheus also loads alerts for unhealthy Agents, classical fallback above 5%,
TLS handshake spikes and upstream TLS failures. Alertmanager integration is not
bundled and must be connected to the enterprise notification system.

Raw interfaces remain available:

```bash
curl http://127.0.0.1:18080/metrics
cat runtime-data/enterprise/metrics/current.json
tail -f runtime-data/enterprise/metrics/history.jsonl
```

## 7. Observe a running backend

v3.7 can deploy a separate Runtime Agent on a backend host or container node:

```bash
make runtime-agent-build
make runtime-agent-up
make runtime-agent-status
```

Query the ingested processes and evidence:

```bash
make runtime-agents
make runtime-observations
make enterprise-assets
```

The default profile records process-map and container attribution. Actual call
observation is an explicit privileged profile:

```bash
make runtime-agent-down
make runtime-agent-ebpf-up
```

See [`runtime-agent.md`](runtime-agent.md) for the evidence model, separate
Agent token, permissions, HTTPS requirements and WSL/kernel limitations.

## 8. Cut over real traffic

The framework deliberately does not modify DNS, load balancers or firewalls.
Start with a new pilot SNI/port, test PQC-capable and legacy clients, and then
route a controlled client group through the Gateway:

```text
Pilot client group
       |
       v
payment-gateway.company.local:28443
       |
       v
PQC Gateway -- compatibility --> payment.internal:9443
```

Only promote to strict `X25519MLKEM768` after the compatibility release is
healthy, explicit application verification passes, and the measured classical
fallback rate is below the migration plan gate. DNS/LB rollback and Gateway
configuration rollback should both be rehearsed before production traffic.

## 9. Security and production boundary

The enterprise profile runs application containers as the invoking host UID,
uses a read-only root filesystem where supported, drops Linux capabilities and
binds management interfaces to loopback. It is still a single-node framework.
Production deployment additionally needs enterprise PKI, secret management,
backup, SIEM, Alertmanager, high availability, load-balancer health checks and
protocol-specific compatibility/capacity validation. The Manager API binds to
`127.0.0.1` by default. For remote automation, set `PQ_MANAGER_API_BIND=0.0.0.0`
only behind an authenticated TLS or mTLS reverse proxy and set
`PQ_MANAGER_API_URL` to that protected endpoint; do not expose the bearer-token
HTTP listener directly to an untrusted network.
