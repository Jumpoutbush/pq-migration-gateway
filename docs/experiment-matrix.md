# Experiment matrix

## Frontend TLS

- compatibility Hybrid success;
- compatibility X25519 success;
- strict Hybrid success;
- strict X25519 rejection.

## Client mTLS

- off/no certificate success;
- optional/no certificate success;
- optional/valid certificate success;
- optional/untrusted certificate rejection;
- required/no certificate rejection;
- required/valid certificate success;
- required/untrusted certificate rejection.

## Upstream HTTPS

- trusted CA success;
- explicit SNI observed by backend;
- gateway client certificate observed by backend;
- wrong CA rejection;
- missing gateway client certificate rejection;
- leaf certificate rotation under the same CA.

## Stream protocols

- MQTT TLS Hybrid handshake and QoS-0 publish/subscribe;
- generic TCP TLS echo;
- non-HTTP legacy line protocol.

## Enterprise crypto discovery

- C/C++, Java, Rust, Go, Python and Shell source interface methods;
- ELF dynamic symbols and bounded marker strings;
- JAR JSSE/JCA/Bouncy Castle class constants;
- extensionless Python and Shell executables;
- Linux process-to-libssl/libcrypto mapping through a deterministic fake `/proc`;
- JSON/CSV inventory and schema v2 compatibility fields;
- target non-execution trap;
- SQLite artifact/process persistence and risk correlation in offline regression tests.

## Running backend discovery

- launch an isolated TLS-capable backend fixture;
- read its live `/proc/<pid>/maps` through the same Runtime Agent collector used in enterprise mode; isolated CI runners whose child PID namespace is not exposed use a deterministic procfs fixture with the running fixture PID;
- link an authorized crypto-call trace to the live PID and process start time;
- reject report submission with the operator token and accept the dedicated Runtime Agent token;
- retain a failed upload in the Agent spool and remove it only after acknowledgement;
- ingest the batch idempotently into Runtime Agent, process and observation tables;
- normalize the running workload into `crypto_assets` and link call evidence through `scan_findings`;
- expose the ingested state through the authenticated runtime and asset REST APIs.

The deterministic matrix uses an imported authorized trace so it does not
require privileged BPF access. The optional eBPF profile must additionally be
validated on the target Linux/WSL kernel.

## Performance

- Hybrid/PQC and X25519 handshake latency, P50/P95/P99 and throughput;
- required-mTLS handshake and HTTP roundtrip;
- verified upstream HTTPS/mTLS roundtrip;
- HTTP, generic TCP and legacy protocol roundtrip;
- MQTT QoS-0 roundtrip under forced `X25519MLKEM768` and `X25519`;
- compatibility MQTT client throughput;
- Docker CPU and memory sampling.
- MQTT message throughput;
- Docker CPU and memory samples.
