# Changelog

## 3.6.0

### API-first enterprise control plane

- Added public OpenAPI 3.1 contract and authenticated capability discovery.
- Added aggregated system status and clear `/v1/releases` aliases while preserving `/v1/configs` compatibility.
- Added one-call service validation, registration and signed release staging through `/v1/onboarding` and `/v1/services/{id}/publish`.
- Added a dependency-free Python REST client and `pqapi` automation CLI with no SQLite access.
- Converted enterprise apply, history, rollback, status, scan, asset and audit wrappers to REST calls.
- Added a deterministic 14-case API-first onboarding, scan, migration, status and rollback experiment.
- Fixed the Dockerfile undefined `LD_LIBRARY_PATH` warning and improved invalid scan-root guidance.

## 3.5.0

### Enterprise delivery

- Added an independent, hardened enterprise Compose runtime without demo backends.
- Added idempotent `make enterprise-init` and interactive/automatable `pqctl onboard` flows.
- Added enterprise apply, history, rollback, scan, asset, status and log commands.
- Added a signed initial release and isolated enterprise runtime directories.

### Continuous observability

- Added an optional Prometheus/Grafana deployment profile and provisioned migration dashboard.
- Added control-plane asset, assessment, scan, migration-plan and migration-state gauges.
- Added Agent, fallback, TLS handshake and upstream TLS alert rules.
- Added an end-to-end enterprise onboarding, traffic cutover, observation and rollback guide.

## 3.4.0

### Scan-to-Migration orchestration

- Added authenticated asynchronous scan, finding and asset REST resources.
- Added persistent scan jobs, normalized software assets, assessments and migration plans to the control-plane SQLite schema.
- Connected a discovered C++/RSA/OpenSSL artifact to assessment, compatibility release publication, migration-state transitions and strict PQC promotion.
- Added strict-promotion gates requiring a healthy compatibility release, explicit verification and an acceptable fallback rate.
- Added a deterministic 10-case REST workflow experiment.

### Advanced C++ discovery

- Added safe `compile_commands.json` metadata parsing without executing compilation commands.
- Added bounded macro alias expansion and a confidence-labeled heuristic C++ call graph.
- Added static archive member/symbol inspection with `ar` and `nm`.
- Added C++ symbol demangling with `c++filt` for ELF and static archives.
- Added optional fixed, bounded eBPF/bpftrace uprobe observation plus offline trace import.
- Expanded the enterprise scanner experiment from 15 to 21 cases.

### Reliability

- Fixed persistent TCP protocol benchmark sessions by terminating `s_client` after the expected response.
- Preserved mTLS client certificate/key arguments in protocol performance tests.

## 3.3.1

- Fixed the enterprise experiment assertion to accept Go and Rust interface evidence from either real compiled ELF symbol tables or bounded binary strings.
- No scanner capability or gateway TLS policy changed.

## 3.3.0

### Enterprise Crypto Discovery

- Added language-aware cryptographic interface discovery for C/C++, Java, Rust, Go, Python and Shell.
- Added non-executing ELF, PE, Mach-O, archive and JAR inspection using file magic, dependencies, symbols and bounded strings/class constants.
- Added optional Linux `/proc` correlation for processes that map cryptographic libraries.
- Added schema v3 artifact, interface-method, confidence and runtime-process records while preserving v2 JSON compatibility fields.
- Extended SQLite inventory and risk correlation for source, binary and runtime evidence.
- Added a deterministic 15-case enterprise scanner experiment to the full experiment suite.
- Preserved the v3.2 control-plane service schema and `X25519MLKEM768:X25519` compatibility policy.

## 3.2.0

### Control Plane Runtime

- Promoted Service, Policy, ConfigVersion, GatewayAgent, MigrationState, AuditEvent and RuntimeMetric to persistent control-plane resources.
- Expanded the authenticated REST API with service/policy CRUD, release detail and resource publication, agent heartbeat, migration history and metrics endpoints.
- Added the explicit release lifecycle `DRAFT -> VALIDATED -> STAGED -> APPLIED -> HEALTHY` with stage-specific failure and rollback history.
- Added gateway-agent identity, heartbeat, desired/current version reporting, reload result and stale-agent detection.
- Added Prometheus metrics for release operations, agent health, TLS groups, classical fallback, handshake/mTLS/upstream TLS failures and connection duration.
- Added an idempotent `make init` / `scripts/init_system.sh` bootstrap for secrets, demo PKI, signed initial release, build, startup and health checks.
- Expanded `pqctl` with service, policy, agent, release-detail, migration-history and metrics commands.
- Preserved v3 flat configuration compatibility and the v3.1 canonical service model and adapter contract.
- Added offline v3.2 regression tests for lifecycle history, failed validation retention, resource publication, API authentication, heartbeat and metrics.

## 3.1.0

### Gateway Framework Core

- Split control-plane release decisions from data-plane NGINX execution.
- Added the canonical v4 service model while retaining v3 configuration compatibility.
- Replaced the monolithic renderer with registered HTTP and Stream protocol adapters.
- Added built-in adapters for MQTT, TCP, legacy line, PostgreSQL, MySQL, Redis, Kafka and AMQP.
- Added external adapter loading through `PQ_GATEWAY_ADAPTERS=module:Class`.
- Added immutable SQLite configuration versions, checksums, release manifests and audit events.
- Added `pqctl` validation, apply, history, rollback, audit and migration-state commands.
- Added an authenticated manager REST API bound to localhost by default.
- Added a gateway agent with syntax validation, atomic activation, reload, health check and automatic rollback.
- Added the auditable migration state machine and explicit rollout compilation rules.
- Added offline regression tests for legacy compatibility, release rollback, state guards and agent rollback.

## 3.0.0

### Gateway

- Added NGINX Stream TLS termination for MQTT, generic TCP and non-HTTP legacy protocols.
- Added complete client mTLS matrix with off, optional and required policies.
- Added verified upstream HTTPS, explicit SNI and gateway-to-upstream mTLS.
- Added negative upstream tests for wrong CA and missing client certificate.
- Added upstream certificate rotation test.
- Expanded service configuration schema to version 3.

### Discovery and inventory

- Added batch endpoint JSON/CSV loading.
- Added CMDB CSV/JSON normalization.
- Added concurrent CIDR and port discovery with a host safety limit.
- Added concurrent TLS scanning with endpoint metadata and client certificate support.
- Added scheduled continuous scans, snapshots, retention and diffs.
- Extended SQLite inventory with endpoint metadata and CMDB assets.

### Runtime monitoring

- Persisted HTTP and Stream access logs outside the container.
- Added continuous Hybrid/PQC versus X25519 fallback metrics.
- Added per-service, per-protocol and per-client reports.
- Added Prometheus text output.

### Experiments and performance

- Added complete mTLS, upstream TLS and Stream protocol matrices.
- Added concurrent handshake, HTTP, TCP and legacy tests plus OpenSSL-group-controlled MQTT round-trip benchmarks.
- Added P50/P95/P99, throughput and Docker resource sampling.
- Added explicit `experiment-status.json` and a consolidated summary.
- Changed all project builds to the WSL proxy build path by default.
