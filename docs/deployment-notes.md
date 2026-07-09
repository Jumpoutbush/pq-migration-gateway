# Deployment notes for a bank-side pilot

## Recommended pilot sequence

1. Run passive inventory against representative gateway hosts, app hosts, and certificate stores.
2. Deploy the gateway in non-production with `TLS_GROUPS=X25519MLKEM768:X25519`.
3. Test PQ-ready clients with `X25519MLKEM768` forced.
4. Keep backend connectivity unchanged at first.
5. Enable mTLS only after client certificate ownership and renewal paths are clear.
6. Move selected endpoints to `TLS_GROUPS=X25519MLKEM768` only after legacy-client impact is known.
7. Feed inventory results into a migration tracker: owner, system, algorithm, data lifetime, risk, target algorithm, deadline, exception.

## What this gateway does not solve

- It does not rewrite application-layer financial message signatures.
- It does not make a legacy backend internally quantum-safe.
- It does not replace HSM/KMS migration planning.
- It does not remove the need for certificate-chain and client SDK testing.
- It does not claim FIPS validation for this container build.

## Production hardening checklist

- Replace demo certificates with bank PKI-issued certificates.
- Pin container image digests and build OpenSSL/NGINX from verified source artifacts.
- Export NGINX JSON logs to SIEM.
- Add rate limiting and WAF rules if the gateway is internet-facing.
- Use backend TLS with verification enabled for non-local upstreams.
- Document fallback policy: when and why `X25519` remains enabled.
- Add synthetic probes that fail if hybrid negotiation silently regresses to classical-only.
