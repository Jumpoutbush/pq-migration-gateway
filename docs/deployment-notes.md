# Deployment notes

1. Start with compatibility mode: `X25519MLKEM768:X25519`.
2. Use online TLS scans and access-log metrics to identify clients still using X25519.
3. Move selected endpoints to strict `X25519MLKEM768` only after compatibility is proven.
4. Keep application payloads opaque; business-specific signature migration belongs to the application or a separate signing service.
5. Replace demo file keys with enterprise PKI/HSM/KMS integrations before production use.
6. Enable upstream certificate verification for non-demo HTTPS systems.
7. Add every exposed listener to the Compose/Kubernetes service definition and firewall policy.
8. Export JSON logs and inventory results to SIEM/CMDB systems.
9. Run source/rootfs scans with bounded inputs and explicit authorization; enable `/proc` scanning only on approved hosts.
10. Treat string-only binary hits as leads and correlate them with symbols, process maps and online TLS observations.
