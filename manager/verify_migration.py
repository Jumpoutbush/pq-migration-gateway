#!/usr/bin/env python3
"""Verify that online TLS scan results satisfy each configured migration policy."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--services", required=True)
    parser.add_argument("--tls", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    services = json.loads(Path(args.services).read_text(encoding="utf-8")).get("services", [])
    endpoints = json.loads(Path(args.tls).read_text(encoding="utf-8")).get("endpoints", [])
    index = {(e.get("sni"), e.get("port")): e for e in endpoints}
    results = []
    for service in services:
        key = (service["server_name"], service["listen_port"])
        endpoint = index.get(key)
        expected = service.get("tls_groups", "")
        expected_groups = {group for group in expected.split(":") if group}
        failures: list[str] = []
        if endpoint is None:
            failures.append("No matching TLS scan result.")
        else:
            supported = set(endpoint.get("supported_groups", []))
            if "X25519MLKEM768" in expected_groups and "X25519MLKEM768" not in supported:
                failures.append("Hybrid/PQC group was not successfully negotiated.")
            if expected_groups == {"X25519MLKEM768"} and "X25519" in supported:
                failures.append("Strict service unexpectedly accepts X25519 fallback.")
            if "X25519" in expected_groups and "X25519" not in supported:
                failures.append("Configured compatibility fallback was not available.")
        results.append({
            "service": service["name"],
            "server_name": service["server_name"],
            "port": service["listen_port"],
            "configured_groups": expected,
            "status": "PASS" if not failures else "FAIL",
            "failures": failures,
        })

    payload = {
        "schema_version": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {"services": len(results), "passed": sum(x["status"] == "PASS" for x in results), "failed": sum(x["status"] == "FAIL" for x in results)},
        "results": results,
    }
    Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0 if payload["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
