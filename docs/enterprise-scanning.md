# Enterprise scanning

Only scan networks and systems for which authorization has been obtained.

## Sources

- `--endpoint`: individual endpoint.
- `--targets-file`: normalized JSON or CSV batch input.
- `--cmdb-file`: CMDB export.
- `--discovery-file`: output from CIDR discovery.

## Workflow

```text
CMDB + batch targets + authorized CIDRs
                 |
                 v
          TCP port discovery
                 |
                 v
        OpenSSL 3.5 TLS probes
                 |
                 v
     snapshot + diff + SQLite import
```

Use `--max-hosts` to prevent accidental expansion of large CIDRs. Use `--allow-unreachable` for inventory jobs where individual endpoint failures should not abort the complete scan.
