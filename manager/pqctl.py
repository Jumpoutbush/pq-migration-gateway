#!/usr/bin/env python3
"""Offline bootstrap CLI for v3.6; use pqapi for day-2 REST operations."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.config_store import ConfigStore, ReleaseTransitionError  # noqa: E402
from manager.control_plane import stage_document, stage_resources, stage_rollback, validate_document  # noqa: E402
from manager.enterprise import DEFAULT_CONFIG, build_service, initialize, redacted_status, upsert_service  # noqa: E402
from manager.state_machine import MigrationStateMachine, TransitionError  # noqa: E402


def output(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def load_object(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON file must contain an object")
    return value


def prompt(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def add_resource_commands(commands: argparse._SubParsersAction, name: str) -> None:
    resource = commands.add_parser(name)
    resource_cmd = resource.add_subparsers(dest="command", required=True)
    listing = resource_cmd.add_parser("list")
    listing.add_argument("--limit", type=int, default=500)
    get = resource_cmd.add_parser("get")
    get.add_argument("id")
    upsert = resource_cmd.add_parser("upsert")
    upsert.add_argument("--file", required=True)
    upsert.add_argument("--id", default="")
    delete = resource_cmd.add_parser("delete")
    delete.add_argument("id")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="runtime-data/control/control-plane.db")
    parser.add_argument("--control-dir", default="runtime-data/control")
    parser.add_argument("--operator", default=os.environ.get("USER", "unknown"))
    commands = parser.add_subparsers(dest="area", required=True)

    onboard = commands.add_parser("onboard", help="Initialize and configure the enterprise deployment")
    onboard_cmd = onboard.add_subparsers(dest="command")
    onboard_init = onboard_cmd.add_parser("init", help="Create secrets, directories and a pilot service")
    onboard_init.add_argument("--scan-root", default=str(ROOT), help="Authorized host directory mounted read-only for scanning")
    onboard_init.add_argument("--server-name", default="pqc-gateway.local")
    onboard_init.add_argument("--listen-port", type=int, default=8443)
    onboard_init.add_argument("--force", action="store_true", help="Replace the generated pilot config; existing secrets are preserved")
    onboard_service = onboard_cmd.add_parser("service", help="Add or update an enterprise gateway service")
    onboard_service.add_argument("--config", default=str(ROOT / DEFAULT_CONFIG))
    onboard_service.add_argument("--id", required=True)
    onboard_service.add_argument("--adapter", choices=["http", "tcp", "mqtt", "legacy-line", "postgres", "mysql", "redis", "kafka", "amqp", "generic-stream"], required=True)
    onboard_service.add_argument("--listen-address", default="0.0.0.0")
    onboard_service.add_argument("--listen-port", type=int, required=True)
    onboard_service.add_argument("--server-name", required=True)
    onboard_service.add_argument("--upstream", required=True)
    onboard_service.add_argument("--client-auth", choices=["off", "optional", "required"], default="off")
    onboard_service.add_argument("--upstream-tls", action=argparse.BooleanOptionalAction, default=None)
    onboard_service.add_argument("--upstream-verify", choices=["off", "on", "required"], default="off")
    onboard_service.add_argument("--upstream-sni", default="")
    onboard_service.add_argument("--upstream-ca", default="/etc/ssl/certs/ca-certificates.crt")
    onboard_service.add_argument("--upstream-client-certificate", default="")
    onboard_service.add_argument("--upstream-client-key", default="")
    onboard_cmd.add_parser("show", help="Show the redacted enterprise deployment configuration")

    config = commands.add_parser("config")
    config_cmd = config.add_subparsers(dest="command", required=True)
    validate = config_cmd.add_parser("validate")
    validate.add_argument("--file", default="config/services.json")
    apply = config_cmd.add_parser("apply")
    apply.add_argument("--file", default="config/services.json")
    config_cmd.add_parser("apply-resources")
    history = config_cmd.add_parser("history")
    history.add_argument("--limit", type=int, default=50)
    show = config_cmd.add_parser("show")
    show.add_argument("version", type=int)
    rollback = config_cmd.add_parser("rollback")
    rollback.add_argument("version", type=int)
    audit = config_cmd.add_parser("audit")
    audit.add_argument("--limit", type=int, default=100)

    add_resource_commands(commands, "service")
    add_resource_commands(commands, "policy")

    migration = commands.add_parser("migration")
    migration_cmd = migration.add_subparsers(dest="command", required=True)
    migration_cmd.add_parser("status")
    migration_history = migration_cmd.add_parser("history")
    migration_history.add_argument("service_id")
    migration_history.add_argument("--limit", type=int, default=100)
    transition = migration_cmd.add_parser("transition")
    transition.add_argument("service_id")
    transition.add_argument("state")
    transition.add_argument("--reason", required=True)
    transition.add_argument("--config-version", type=int)
    transition.add_argument("--verification-result")
    transition.add_argument("--fallback-rate", type=float)

    agent = commands.add_parser("agent")
    agent_cmd = agent.add_subparsers(dest="command", required=True)
    agent_list = agent_cmd.add_parser("list")
    agent_list.add_argument("--stale-after", type=float, default=30)
    agent_get = agent_cmd.add_parser("get")
    agent_get.add_argument("id")

    metrics = commands.add_parser("metrics")
    metrics_cmd = metrics.add_subparsers(dest="command", required=True)
    metrics_cmd.add_parser("show")
    metrics_cmd.add_parser("prometheus")

    args = parser.parse_args()

    try:
        if args.area == "onboard":
            if args.command == "show":
                output(redacted_status(ROOT))
                return 0
            if args.command is None:
                if not sys.stdin.isatty():
                    raise ValueError("interactive onboarding requires a terminal; use 'pqctl onboard init/service' in automation")
                current = redacted_status(ROOT)
                existing_service = current.get("services", [{}])[0] if current.get("services") else {}
                existing_listen = existing_service.get("listen") or {}
                scan_root = prompt("Authorized enterprise scan directory", current.get("scan_root") or str(ROOT))
                service_id = prompt("Service id", existing_service.get("id") or "payment-pqc-gateway")
                adapter = prompt("Adapter (http/tcp/mqtt/postgres/mysql/redis/kafka/amqp)", existing_service.get("adapter") or "http")
                listen_port = int(prompt("Gateway listen port", str(existing_listen.get("port") or 8443)))
                server_name = prompt("Gateway server name (SNI)", existing_listen.get("server_name") or "payment-gateway.local")
                default_upstream = existing_service.get("upstream") or ("http://127.0.0.1:8080" if adapter == "http" else "127.0.0.1:8080")
                upstream = prompt("Existing upstream address", default_upstream)
                client_auth = prompt("Client authentication (off/optional/required)", "off")
                initialized = initialize(ROOT, scan_root, server_name=server_name, port=listen_port)
                configured = upsert_service(ROOT / DEFAULT_CONFIG, build_service(
                    service_id=service_id, adapter=adapter, listen_port=listen_port,
                    server_name=server_name, upstream=upstream, client_auth=client_auth,
                ))
                output({"initialized": initialized, "configured": configured, "next": "make enterprise-up"})
                return 0
            if args.command == "init":
                output(initialize(ROOT, args.scan_root, server_name=args.server_name, port=args.listen_port, force=args.force))
                return 0
            if args.command == "service":
                service = build_service(
                    service_id=args.id, adapter=args.adapter, listen_address=args.listen_address,
                    listen_port=args.listen_port, server_name=args.server_name, upstream=args.upstream,
                    client_auth=args.client_auth, upstream_tls=args.upstream_tls,
                    upstream_verify=args.upstream_verify, upstream_sni=args.upstream_sni,
                    upstream_ca=args.upstream_ca,
                    upstream_client_certificate=args.upstream_client_certificate,
                    upstream_client_key=args.upstream_client_key,
                )
                output(upsert_service(args.config, service))
                return 0
        if args.area == "config" and args.command == "validate":
            result = validate_document(load_object(args.file))
            output({"valid": True, "checksum": result["checksum"], "services": len(result["canonical"]["services"]), "policies": result["policies"]})
            return 0

        store = ConfigStore(args.db)
        if args.area == "config" and args.command == "apply":
            output(stage_document(store, args.control_dir, load_object(args.file), args.operator))
        elif args.area == "config" and args.command == "apply-resources":
            output(stage_resources(store, args.control_dir, args.operator))
        elif args.area == "config" and args.command == "history":
            output(store.list_versions(args.limit))
        elif args.area == "config" and args.command == "show":
            output(store.get_version(args.version, include_rendered=False))
        elif args.area == "config" and args.command == "rollback":
            output(stage_rollback(store, args.control_dir, args.version, args.operator))
        elif args.area == "config" and args.command == "audit":
            output(store.list_audit(args.limit))
        elif args.area in {"service", "policy"}:
            kind = args.area
            if args.command == "list":
                output(store.list_resources(kind, args.limit))
            elif args.command == "get":
                output(store.get_resource(kind, args.id))
            elif args.command == "upsert":
                spec = load_object(args.file)
                resource_id = args.id or str(spec.get("id") or spec.get("service_id") or "")
                if not resource_id:
                    raise ValueError("resource id is required through --id or the JSON object")
                output(store.upsert_resource(kind, resource_id, spec, args.operator))
            elif args.command == "delete":
                store.delete_resource(kind, args.id, args.operator)
                output({"deleted": True, "kind": kind, "id": args.id})
        elif args.area == "migration" and args.command == "status":
            output(MigrationStateMachine(store).list())
        elif args.area == "migration" and args.command == "history":
            output(MigrationStateMachine(store).history(args.service_id, args.limit))
        elif args.area == "migration" and args.command == "transition":
            output(MigrationStateMachine(store).transition(
                args.service_id, args.state, operator=args.operator, reason=args.reason,
                config_version=args.config_version, verification_result=args.verification_result, fallback_rate=args.fallback_rate,
            ))
        elif args.area == "agent" and args.command == "list":
            output(store.list_agents(args.stale_after))
        elif args.area == "agent" and args.command == "get":
            output(store.get_agent(args.id))
        elif args.area == "metrics" and args.command == "show":
            output(store.list_metrics())
        elif args.area == "metrics" and args.command == "prometheus":
            print(store.prometheus_text(), end="")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, TransitionError, ReleaseTransitionError) as exc:
        print(f"pqctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
