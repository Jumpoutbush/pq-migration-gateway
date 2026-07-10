#!/usr/bin/env python3
"""Add or update a service in config/services.json without editing gateway code."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULTS = {
    "certificate": "/etc/pq-gateway/certs/server.crt",
    "certificate_key": "/etc/pq-gateway/certs/server.key",
    "client_ca": "/etc/pq-gateway/certs/ca.crt",
    "upstream_ca": "/etc/pq-gateway/certs/upstream-ca.crt",
    "dns_resolver": "127.0.0.11",
    "connect_timeout": "5s",
    "send_timeout": "60s",
    "read_timeout": "60s",
}

MODE_GROUPS = {
    "compatibility": "X25519MLKEM768:X25519",
    "strict": "X25519MLKEM768",
    "classical": "X25519",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/services.json")
    parser.add_argument("--name", required=True)
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--mode", choices=sorted(MODE_GROUPS), default="compatibility")
    parser.add_argument("--client-auth", choices=["off", "optional", "required"], default="off")
    parser.add_argument("--upstream-tls-verify", choices=["off", "on"], default="off")
    args = parser.parse_args()

    path = Path(args.config)
    config = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"version": 2, "defaults": dict(DEFAULTS), "services": []}
    service = {
        "name": args.name,
        "listen_port": args.listen,
        "server_name": args.server_name,
        "upstream_url": args.upstream,
        "tls_groups": MODE_GROUPS[args.mode],
        "client_auth": args.client_auth,
        "upstream_tls_verify": args.upstream_tls_verify,
    }
    services = [item for item in config.get("services", []) if item.get("name") != args.name]
    services.append(service)
    config["version"] = 2
    defaults = config.setdefault("defaults", {})
    for key, value in DEFAULTS.items():
        defaults.setdefault(key, value)
    config["services"] = sorted(services, key=lambda x: (x["listen_port"], x["name"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(service, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
