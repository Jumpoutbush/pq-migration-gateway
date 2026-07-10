# Architecture v2

```text
Static scanner ----+
                   +--> inventory + risk engine + SQLite
Online TLS scanner-+                 |
                                     v
Client --> multi-service PQC gateway --> unchanged HTTP/HTTPS systems
                     |
                     +--> JSON TLS group logs --> fallback report
```

The gateway is application-agnostic. It terminates client-facing TLS 1.3, applies a per-service Hybrid/PQC policy, and forwards opaque HTTP payloads to existing systems. `config/services.json` is the source of truth for multi-service routing.

The migration loop is:

```text
discover -> assess -> configure -> deploy -> validate -> measure fallback
```

Key exchange migration and certificate-authentication migration remain separate. The default demo uses Hybrid ML-KEM key exchange with an RSA certificate so that interoperability can be measured independently.
