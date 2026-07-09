# Architecture

This project implements a migration gateway that can be inserted between a banking client and an existing banking service.

```text
+----------------------+        TLS 1.3 hybrid/PQ KEX        +--------------------------+        existing HTTP/TLS        +-----------------------+
| PQ-ready bank client |  --------------------------------->  | PQC migration gateway    |  --------------------------->  | legacy bank service   |
| curl/OpenSSL 3.5 SDK |                                      | NGINX + OpenSSL 3.5      |                               | no PQC changes needed |
+----------------------+                                      +--------------------------+                               +-----------------------+
                                    protected / upgraded edge            translation / observability
```

## Boundary

The gateway upgrades the client-facing transport layer first. The backend can remain unchanged during the first migration wave. This is the same operational idea as a reverse proxy TLS terminator: the externally exposed security boundary is upgraded before every internal service, SDK, HSM, and application stack is rewritten.

## Cryptographic position

The default frontend TLS group setting is:

```text
X25519MLKEM768:X25519
```

This prefers the OpenSSL 3.5 hybrid group `X25519MLKEM768`, while retaining `X25519` fallback for legacy clients during the migration window. For strict testing set:

```text
X25519MLKEM768
```

Certificate authentication is intentionally separable from key exchange. The default demo uses RSA-3072 certificates for compatibility and hybrid ML-KEM key exchange for forward secrecy migration. Optional ML-DSA certificate generation is included for controlled lab testing where the client and server stack both support PQ certificate chains.

## Asset inventory loop

The included scanner is not a compliance product. It provides a minimal cryptographic inventory loop:

1. scan certificates, private keys, configs, and source references;
2. label RSA/ECC/DH/ECDH/ECDSA as quantum-vulnerable public-key assets;
3. detect PQC or candidate terms such as ML-KEM, ML-DSA, SLH-DSA, Dilithium, Kyber, Falcon;
4. emit JSON/CSV findings for migration planning.

In a real bank environment this should be extended to HSM/KMS inventories, CMDB ownership, network TLS scans, VPN/IKE profiles, Java keystores, container images, SBOM/CBOM, and vendor-managed appliances.
