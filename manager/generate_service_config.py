#!/usr/bin/env python3
"""Add or replace one service in the canonical v4 configuration model."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.model import normalize_config  # noqa: E402

DEFAULTS = {
    "certificate": "/etc/pq-gateway/certs/server.crt",
    "certificate_key": "/etc/pq-gateway/certs/server.key",
    "client_ca": "/etc/pq-gateway/certs/ca.crt",
    "upstream_ca": "/etc/pq-gateway/certs/upstream/ca.crt",
    "dns_resolver": "127.0.0.11",
    "connect_timeout": "5s",
    "send_timeout": "60s",
    "read_timeout": "60s",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/services.json")
    parser.add_argument("--id", "--name", dest="service_id", required=True)
    parser.add_argument("--adapter", choices=["http", "mqtt", "tcp", "legacy-line", "generic-stream", "postgres", "mysql", "redis", "kafka", "amqp"], default="http")
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--address", default="0.0.0.0")
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--mode", choices=["compatibility", "strict", "classical", "custom"], default="compatibility")
    parser.add_argument("--groups", default="")
    parser.add_argument("--client-auth", choices=["off", "optional", "required"], default="off")
    parser.add_argument("--upstream-tls", action="store_true")
    parser.add_argument("--upstream-tls-verify", choices=["off", "on", "required"], default="off")
    parser.add_argument("--upstream-sni", default="")
    parser.add_argument("--upstream-ca", default=DEFAULTS["upstream_ca"])
    parser.add_argument("--upstream-client-certificate", default="")
    parser.add_argument("--upstream-client-key", default="")
    args = parser.parse_args()
    path = Path(args.config)
    if path.exists():
        config = normalize_config(json.loads(path.read_text(encoding="utf-8")))
    else:
        config = {"schema_version": "4.0", "defaults": dict(DEFAULTS), "services": []}
    service = {
        "id": args.service_id,
        "adapter": args.adapter,
        "listen": {"address": args.address, "port": args.listen, "server_name": args.server_name},
        "downstream_tls": {
            "mode": args.mode,
            **({"groups": args.groups} if args.groups else {}),
            "client_auth": args.client_auth,
            "certificate": config["defaults"].get("certificate", DEFAULTS["certificate"]),
            "private_key": {"provider": "file", "reference": config["defaults"].get("certificate_key", DEFAULTS["certificate_key"])},
            "client_ca": config["defaults"].get("client_ca", DEFAULTS["client_ca"]),
        },
        "upstream": {
            "address": args.upstream,
            "tls": {
                "enabled": args.upstream_tls or args.upstream.startswith("https://"),
                "verify": args.upstream_tls_verify,
                "sni": args.upstream_sni,
                "ca": args.upstream_ca,
                "client_identity": {"certificate": args.upstream_client_certificate, "private_key": {"provider": "file", "reference": args.upstream_client_key}},
            },
        },
        "timeouts": {"connect": "5s", "send": "60s", "read": "60s"},
        "rollout": {"policy": "fixed", "hybrid_percentage": 0 if args.mode == "classical" else 100, "fallback_allowed": args.mode != "strict"},
        "audit": {"enabled": True},
    }
    config["services"] = sorted([s for s in config["services"] if s["id"] != args.service_id] + [service], key=lambda s: (s["listen"]["port"], s["id"]))
    canonical = normalize_config(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(canonical, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(service, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
