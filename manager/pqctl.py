#!/usr/bin/env python3
"""Administrative CLI for v3.3 control-plane resources and releases."""
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
from manager.state_machine import MigrationStateMachine, TransitionError  # noqa: E402


def output(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def load_object(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON file must contain an object")
    return value


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
