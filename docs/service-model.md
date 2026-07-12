# Unified Service Model

v3.2 keeps the v3.1 unified service document for HTTP, databases, message queues and arbitrary TCP protocols. Protocol differences live in adapters; TLS, identity, timeout, rollout and audit fields are shared. The same canonical service is now also stored as a first-class control-plane resource.

```json
{
  "schema_version": "4.0",
  "defaults": {
    "certificate": "/etc/pq-gateway/certs/server.crt",
    "certificate_key": "/etc/pq-gateway/certs/server.key",
    "client_ca": "/etc/pq-gateway/certs/ca.crt",
    "upstream_ca": "/etc/pq-gateway/certs/upstream/ca.crt",
    "dns_resolver": "127.0.0.11"
  },
  "services": [
    {
      "id": "mqtt-prod",
      "adapter": "mqtt",
      "listen": {
        "address": "0.0.0.0",
        "port": 8883,
        "server_name": "mqtt.gateway.internal"
      },
      "downstream_tls": {
        "mode": "compatibility",
        "groups": ["X25519MLKEM768", "X25519"],
        "client_auth": "required",
        "certificate": "/etc/pq-gateway/certs/server.crt",
        "private_key": {
          "provider": "file",
          "reference": "/etc/pq-gateway/certs/server.key"
        },
        "client_ca": "/etc/pq-gateway/certs/ca.crt"
      },
      "upstream": {
        "address": "mqtt.internal:8883",
        "tls": {
          "enabled": true,
          "verify": "required",
          "sni": "mqtt.internal",
          "ca": "/etc/pq-gateway/certs/upstream/ca.crt",
          "client_identity": {
            "certificate": "/etc/pq-gateway/certs/upstream/client.crt",
            "private_key": {
              "provider": "file",
              "reference": "/etc/pq-gateway/certs/upstream/client.key"
            }
          }
        }
      },
      "timeouts": {"connect": "5s", "send": "60s", "read": "60s"},
      "rollout": {"policy": "percentage", "hybrid_percentage": 80, "fallback_allowed": true},
      "audit": {"enabled": true}
    }
  ]
}
```

## TLS modes

| Mode | Default groups | Meaning |
|---|---|---|
| `compatibility` | `X25519MLKEM768`, `X25519` | Prefer Hybrid/PQC while retaining classical fallback. |
| `strict` | `X25519MLKEM768` | Reject clients without Hybrid/PQC support. |
| `classical` | `X25519` | Classical baseline or rollback entry. |
| `custom` | Explicitly required | Operator-supplied group set. |

`fallback_allowed=false` cannot be combined with `X25519`.

## Rollout boundary

The TLS group is selected during the handshake. An HTTP path cannot decide which key-exchange group was used. Therefore an exact percentage, source-CIDR or client-group rollout must be implemented with separate listeners, SNI names or gateway instances. The policy engine reports `separate-listener-or-instance` when this boundary applies; it never pretends that the group list itself enforces an exact traffic percentage.

## Adapter contract

Every adapter implements:

```python
class ProtocolAdapter:
    def validate(self, service): ...
    def render(self, service): ...
    def probe(self, endpoint): ...
    def health_check(self, service): ...
    def build_tests(self, service): ...
```

Built-ins are `http`, `generic-stream`, `mqtt`, `tcp`, `legacy-line`, `postgres`, `mysql`, `redis`, `kafka` and `amqp`.

An external adapter can be loaded without editing the registry:

```bash
export PQ_GATEWAY_ADAPTERS='my_gateway.kafka:CustomKafkaAdapter'
```

The class must inherit `gateway.adapters.base.ProtocolAdapter` and declare a unique `name`.

## Compatibility

The loader accepts v3 flat documents and converts them in memory. Running `manager/generate_service_config.py` writes the canonical v4 form. This permits staged migration of existing deployments and scripts.
