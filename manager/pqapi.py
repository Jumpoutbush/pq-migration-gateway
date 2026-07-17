#!/usr/bin/env python3
"""REST-only CLI and automation client for PQ Gateway Manager API v3.6."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.api_client import ApiError, ManagerApiClient  # noqa: E402


def read_object(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON input must be an object")
    return value


def output(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("PQ_MANAGER_API_URL", "http://127.0.0.1:18080"))
    parser.add_argument("--token", default=os.environ.get("MANAGER_API_TOKEN", ""))
    parser.add_argument("--operator", default=os.environ.get("USER", "pqapi"))
    commands = parser.add_subparsers(dest="area", required=True)
    commands.add_parser("capabilities")
    commands.add_parser("status")
    onboard = commands.add_parser("onboard")
    onboard.add_argument("--file", required=True, help="Concise or canonical service JSON")

    service = commands.add_parser("service")
    service_cmd = service.add_subparsers(dest="command", required=True)
    service_cmd.add_parser("list")
    service_get = service_cmd.add_parser("get");service_get.add_argument("id")
    service_publish = service_cmd.add_parser("publish");service_publish.add_argument("--file", required=True);service_publish.add_argument("--id", default="")
    service_delete = service_cmd.add_parser("delete");service_delete.add_argument("id")

    scan = commands.add_parser("scan")
    scan_cmd = scan.add_subparsers(dest="command", required=True)
    scan_create = scan_cmd.add_parser("create")
    scan_create.add_argument("--root", action="append", default=[])
    scan_create.add_argument("--compile-commands", action="append", default=[])
    scan_create.add_argument("--wait", action="store_true")
    scan_create.add_argument("--timeout", type=float, default=300)
    scan_cmd.add_parser("list")
    scan_get = scan_cmd.add_parser("get");scan_get.add_argument("id")
    scan_findings = scan_cmd.add_parser("findings");scan_findings.add_argument("id")

    asset = commands.add_parser("asset")
    asset_cmd = asset.add_subparsers(dest="command", required=True)
    asset_cmd.add_parser("list")
    asset_get = asset_cmd.add_parser("get");asset_get.add_argument("id")
    asset_assess = asset_cmd.add_parser("assess");asset_assess.add_argument("id")
    asset_migrate = asset_cmd.add_parser("migrate");asset_migrate.add_argument("id");asset_migrate.add_argument("--file", required=True)

    release = commands.add_parser("release")
    release_cmd = release.add_subparsers(dest="command", required=True)
    release_cmd.add_parser("list")
    release_get = release_cmd.add_parser("get");release_get.add_argument("version", type=int)
    release_publish = release_cmd.add_parser("publish");release_publish.add_argument("--file", required=True)
    release_cmd.add_parser("publish-resources")
    release_rollback = release_cmd.add_parser("rollback");release_rollback.add_argument("version", type=int)
    commands.add_parser("audit")

    args = parser.parse_args()
    try:
        client = ManagerApiClient(args.url, args.token, args.operator)
        if args.area == "capabilities":
            result = client.capabilities()
        elif args.area == "status":
            result = client.status()
        elif args.area == "onboard":
            result = client.onboard(read_object(args.file))
        elif args.area == "service":
            if args.command == "list": result = client.request("GET", "/v1/services")
            elif args.command == "get": result = client.request("GET", f"/v1/services/{quote(args.id, safe='')}")
            elif args.command == "delete": result = client.request("DELETE", f"/v1/services/{quote(args.id, safe='')}")
            else:
                spec = read_object(args.file);service_id = args.id or str(spec.get("id", ""))
                if not service_id: raise ValueError("service id is required in the file or through --id")
                result = client.request("POST", f"/v1/services/{quote(service_id, safe='')}/publish", spec)
        elif args.area == "scan":
            if args.command == "list": result = client.request("GET", "/v1/scans")
            elif args.command == "get": result = client.request("GET", f"/v1/scans/{quote(args.id, safe='')}")
            elif args.command == "findings": result = client.request("GET", f"/v1/scans/{quote(args.id, safe='')}/findings")
            else:
                roots = args.root or ["/workspace/project"]
                result = client.create_scan(roots, args.compile_commands)
                if args.wait: result = client.wait_scan(str(result["scan_id"]), args.timeout)
        elif args.area == "asset":
            if args.command == "list": result = client.request("GET", "/v1/assets")
            elif args.command == "get": result = client.request("GET", f"/v1/assets/{quote(args.id, safe='')}")
            elif args.command == "assess": result = client.request("POST", f"/v1/assets/{quote(args.id, safe='')}/assess")
            else: result = client.request("POST", f"/v1/assets/{quote(args.id, safe='')}/migration", read_object(args.file))
        elif args.area == "release":
            if args.command == "list": result = client.request("GET", "/v1/releases")
            elif args.command == "get": result = client.request("GET", f"/v1/releases/{args.version}")
            elif args.command == "publish": result = client.request("POST", "/v1/releases", read_object(args.file))
            elif args.command == "publish-resources": result = client.request("POST", "/v1/releases/from-resources", {})
            else: result = client.request("POST", f"/v1/releases/{args.version}/rollback")
        else:
            result = client.request("GET", "/v1/audit")
        output(result)
        return 0
    except (ApiError, OSError, ValueError, KeyError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"pqapi: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
