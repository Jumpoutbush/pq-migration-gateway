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
