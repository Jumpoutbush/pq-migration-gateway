# Architecture

PQC Migration Gateway v3.6 separates enterprise crypto discovery, API-first persistent control-plane state and traffic execution, while connecting scan assets to guarded migration releases and a dedicated enterprise operations profile.

```text
Source / binaries / JAR / processes / CMDB / endpoints / CIDR
                |
                v
Discovery + inventory + risk assessment
                |
                v
+-------------------- Control plane --------------------+
| pqctl / manager-api / Prometheus endpoint            |
| Service + Policy + ConfigVersion + MigrationState    |
| config-store -> desired release -> Agent heartbeat   |
+--------------------------+----------------------------+
                           | desired version
                           v
+--------------------- Data plane ----------------------+
| gateway-agent -> validate -> activate -> rollback    |
| NGINX/OpenSSL -> HTTP and registered Stream adapters |
+-------------------------------------------------------+
```

## Control plane

- `manager-api` and `pqctl` accept operator intent.
- `policy-engine` makes TLS rollout boundaries explicit.
- `config-store` keeps resources, immutable staged artifacts, release status history, agents, runtime metrics and audit events.
- the migration state machine rejects invalid lifecycle jumps.
- releases contain canonical source, rendered NGINX configuration and a manifest.

## Discovery plane

- language adapters identify exact cryptographic API/method references;
- artifact inspection reads file magic, symbols, dependencies and bounded strings/class constants without executing targets;
- optional process-map inspection correlates deployed programs with cryptographic libraries;
- CMDB, CIDR and online TLS collectors provide ownership and observed protocol evidence.

## Data plane

- `gateway-agent` watches only the desired release contract.
- the agent verifies checksums and runs `nginx -t` before activation.
- active configuration replacement is atomic.
- reload is followed by a health check; failure restores the previous configuration.
- NGINX/OpenSSL terminates TLS 1.3 and forwards opaque application traffic.

## Adapter layer

HTTP and Stream protocol behavior is no longer embedded in the control plane. The registry supplies built-in adapters for HTTP, MQTT, generic TCP, legacy line protocols, PostgreSQL, MySQL, Redis, Kafka and AMQP. External adapters can be loaded through `PQ_GATEWAY_ADAPTERS`.

## Security boundary

- The manager API requires a bearer token and is published on host loopback by default.
- Private keys stay outside the configuration database; the model stores provider references.
- SHA-256 checksums detect release corruption; optional HMAC-SHA-256 signatures authenticate the publisher when `PQ_CONFIG_SIGNING_KEY` is configured.
- Logs and audit events contain metadata, never business payloads or private-key material.
- The current release is a single-node SQLite control-plane runtime; PostgreSQL coordination, multi-node consensus and rolling cluster release remain future work.
