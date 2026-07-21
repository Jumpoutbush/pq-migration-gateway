# Runtime Discovery Agent (v3.7)

## Purpose

Static scanning answers which cryptographic interfaces exist in source code and
artifacts. The Runtime Agent adds evidence from a backend while it is running:

```text
backend process/container
        |
        | read-only /proc maps + cgroup identity
        | optional fixed eBPF uprobes
        v
Runtime Agent -- authenticated, spooled batches --> Manager API
        v
runtime agents/processes/observations tables
        v
normalized crypto_assets + scan_findings
```

The Agent never launches the target, never injects code into it, never accepts
an arbitrary eBPF program from an API caller, and never uploads private key
material. Command lines are disabled by default and secret-like arguments are
redacted when explicitly enabled.

## Evidence levels

| Source | Meaning | Confidence |
|---|---|---|
| `/proc/<pid>/maps` | The running process mapped a recognized crypto library | High for library presence; it does not prove a function was called |
| cgroup and namespace metadata | The process belongs to a host, Docker/containerd/CRI-O container or Kubernetes pod | High when identifiers are exposed by the kernel |
| fixed bpftrace uprobes | A selected process actually called an allowlisted crypto symbol | High for the observed interval |
| imported JSONL/TSV trace | An authorized previously collected crypto-call trace | High when provenance is trusted |

The fixed eBPF collector derives libraries from process maps, extracts exact
exported symbols with `nm`, and intersects them with a prioritized allowlist of
high-value TLS, EVP, key-encapsulation, legacy public-key and libsodium entry
points. It loads at most 64 uprobes (plus the timer used to close the sampling
window), even if a library exports thousands of matching names. API clients
cannot submit programs or probe paths.

## Initialize or upgrade the enterprise environment

Initialization generates a separate `RUNTIME_AGENT_TOKEN`. Existing secrets
are preserved. Keep the current scan root when upgrading:

```bash
make enterprise-init \
  SCAN_ROOT=/srv/company/apps \
  SERVER_NAME=payment-gateway.company.local \
  LISTEN_PORT=28443
```

Rebuild and restart the v3.7 Manager API before using Runtime Agents:

```bash
make build
make enterprise-down
make enterprise-up
```

## One-shot host validation

This mode observes processes readable by the current user and uploads one
batch. It is useful before installing a privileged service:

```bash
make runtime-agent-once
make runtime-agents
make runtime-observations
make enterprise-assets
```

Direct collection without uploading:

```bash
python3 manager/runtime_agent.py collect \
  --agent-id backend-host-1 \
  --proc-root /proc \
  --out /tmp/runtime-report.json
```

To validate one known backend process without collecting unrelated workloads,
repeat `--pid` as needed:

```bash
python3 manager/runtime_agent.py once \
  --agent-id payment-host-1 \
  --pid 321 --pid 654 \
  --spool-dir runtime-data/enterprise/runtime-agent/spool
```

## Process/container Agent

Build and start the dedicated Agent image:

```bash
make runtime-agent-build
make runtime-agent-up
make runtime-agent-status
make runtime-agent-logs
```

The default container uses the host PID namespace, mounts `/proc` read-only,
and grants only process-inspection capabilities. It reports loaded crypto
libraries and container attribution. Its delivery spool is persisted at:

```text
runtime-data/enterprise/runtime-agent/spool/
```

The container runs as UID 0 because the optional eBPF profile needs host
process inspection. Compose drops the default capability set and restores
`DAC_OVERRIDE` only so this process can write the bind-mounted spool when that
directory belongs to the invoking host user. The container root filesystem and
all host inspection mounts remain read-only; the spool is its only writable
bind mount.

An acknowledged batch is removed from the spool. Failed uploads remain and are
retried with the same batch ID, so Manager ingestion is idempotent.

On Docker Desktop/WSL, the containerized Agent sees the Docker engine Linux VM
process namespace. Use it for backends running in that Docker engine. For a
backend running directly inside the WSL distribution, run the host command
`make runtime-agent-once` (or install `runtime_agent.py watch` as a service) in
the same distribution so `/proc` refers to the backend's real namespace.

## Optional live eBPF calls

Live call observation requires Linux BPF support, bpftrace, host PID visibility
and additional capabilities. It is explicitly opt-in:

```bash
make runtime-agent-down
make runtime-agent-ebpf-up
```

The Agent resolves every probe target through `/proc/<pid>/root`, so a library
inside a backend container is not confused with an Agent or host library at the
same path. The eBPF override also mounts the host filesystem read-only as a
fallback, keeps `/sys` read-only except for the tracing directory required to
create uprobes, and grants `BPF`, `PERFMON`, `SYS_RESOURCE` and
`SYS_PTRACE`. This profile requires a host security review. On WSL kernels or
locked-down production hosts where BPF is unavailable, the Agent records the
collector error but still uploads process-map evidence.

`PQ_RUNTIME_EBPF_MAX_PROBES` can lower the probe count from its default and hard
maximum of 64. Discovery continues to use the read-only `/host/proc` mount. The
Agent locates each container library through `/proc/<pid>/root/...`, then creates
a private short-lived alias such as `/tmp/pqe-XXXX/p0` for the bpftrace
attachment. This keeps generated tracefs event names within kernel limits; the
alias directory is removed after all bpftrace processes exit. Probe programs
are loaded independently per library target, so one unsupported target is
reported in `failed_targets` without discarding observations from other
containers. On nested WSL/Docker PID namespaces, the Agent reads Linux's
`NSpid` hierarchy, filters bpftrace with the outer kernel PID, and maps each
captured event back to the PID used by the discovery procfs before storage.

The uploaded eBPF metadata records `probes`, `selected_probes`, `failed_probes`,
`eligible_probes`, `probe_limit`, `truncated`, `probe_targets` and
`failed_targets`. Each target also records the real `target` and temporary
`attachment_alias`. A `partial` status means at least one target was sampled
and at least one target was skipped; its observations remain valid.

For a previously captured deterministic event file:

```bash
python3 manager/runtime_agent.py once \
  --agent-id backend-host-1 \
  --event-file authorized-events.jsonl \
  --spool-dir runtime-data/enterprise/runtime-agent/spool
```

Event JSONL format:

```json
{"pid":321,"command":"payment","method":"RSA_sign","library":"/usr/lib/libcrypto.so.3"}
```

## Manager API

Runtime Agent write endpoint (uses `RUNTIME_AGENT_TOKEN`):

```text
POST /v1/runtime/reports
```

Operator read endpoints (use `MANAGER_API_TOKEN`):

```text
GET /v1/runtime/agents
GET /v1/runtime/agents/{agent_id}
GET /v1/runtime/batches
GET /v1/runtime/batches/{batch_id}
GET /v1/runtime/observations
GET /v1/runtime/observations?agent_id=backend-host-1
GET /v1/runtime/observations?asset_id=runtime-asset-...
```

CLI equivalents:

```bash
python3 manager/pqapi.py runtime agents
python3 manager/pqapi.py runtime agent backend-host-1
python3 manager/pqapi.py runtime batches
python3 manager/pqapi.py runtime observations --agent-id backend-host-1
```

Every accepted report also creates a `runtime-agent` scan job. Running workloads
appear in `/v1/assets`; their asset detail contains `proc_maps`, `ebpf_uprobe`
or `imported_trace` evidence. Raw state is stored in:

```text
runtime-data/enterprise/control/control-plane.db
```

## Remote hosts

Run one Agent on each authorized backend host or Kubernetes node. A remote Agent
must use an HTTPS Manager URL. The built-in Manager listener is plain HTTP and
binds to loopback by default, so production remote deployment must place it
behind an enterprise HTTPS/mTLS ingress or service mesh and restrict the report
route. `--allow-insecure-http` exists only for isolated test networks.

## Limits

- Process maps prove library loading, not invocation.
- eBPF observes only calls made during its sampling window and only exported,
  allowlisted symbols; statically linked, inlined, JIT or hidden functions may
  remain invisible.
- Container names are not read from the Docker socket. The Agent records kernel
  cgroup container IDs, runtime type and Kubernetes pod UID without granting
  Docker control privileges.
- Cross-host collection requires an Agent on that host; the Manager container
  cannot inspect an arbitrary remote `/proc` namespace.
