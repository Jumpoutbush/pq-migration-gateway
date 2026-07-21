#!/usr/bin/env python3
"""Authenticated v3.7 API-first Gateway control plane."""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.adapters import default_registry  # noqa: E402
from manager.api_workflows import publish_service  # noqa: E402
from manager.config_store import ConfigStore, ReleaseTransitionError  # noqa: E402
from manager.control_plane import stage_document, stage_resources, stage_rollback, validate_document  # noqa: E402
from manager.openapi import document as openapi_document  # noqa: E402
from manager.scan_orchestrator import ScanOrchestrator  # noqa: E402
from manager.state_machine import MigrationStateMachine, TransitionError  # noqa: E402

SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,255}$")


class ApiHandler(BaseHTTPRequestHandler):
    store: ConfigStore
    control_dir: Path
    token: str
    runtime_agent_token: str = ""
    metrics_public = True
    max_body = 2 * 1024 * 1024
    scanner: ScanOrchestrator

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("manager-api: " + fmt % args + "\n")

    def reply(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reply_text(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def route(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlsplit(self.path)
        return parsed.path.rstrip("/") or "/", parse_qs(parsed.query)

    def authenticated(self, path: str) -> bool:
        if path in {"/healthz", "/openapi.json"} or (path == "/metrics" and self.metrics_public):
            return True
        supplied = self.headers.get("Authorization", "")
        token = (self.runtime_agent_token or self.token) if self.command == "POST" and path == "/v1/runtime/reports" else self.token
        expected = "Bearer " + token
        return bool(token) and hmac.compare_digest(supplied, expected)

    def body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > self.max_body:
            raise ValueError("request body is empty or too large")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def actor(self) -> str:
        return self.headers.get("X-PQ-Operator", "api")[:128]

    @staticmethod
    def limit(query: dict[str, list[str]], default: int = 100) -> int:
        try:
            return max(1, min(int(query.get("limit", [str(default)])[0]), 1000))
        except ValueError as exc:
            raise ValueError("limit must be an integer") from exc

    @staticmethod
    def resource_spec(payload: dict, resource_id: str | None = None) -> tuple[str, dict]:
        spec = payload.get("spec", payload)
        if not isinstance(spec, dict):
            raise ValueError("resource spec must be an object")
        candidate = resource_id or str(payload.get("id") or spec.get("id") or spec.get("service_id") or "")
        if not SAFE_ID.fullmatch(candidate):
            raise ValueError("resource id must match [A-Za-z0-9._-]{1,128}")
        return candidate, spec

    def dispatch(self) -> None:
        path, query = self.route()
        if not self.authenticated(path):
            self.reply(401, {"error": "authentication required"})
            return

        if self.command == "GET" and path == "/openapi.json":
            host = self.headers.get("Host", "127.0.0.1:18080")
            if not SAFE_HOST.fullmatch(host):
                host = "127.0.0.1:18080"
            self.reply(200, openapi_document(f"http://{host}"))
        elif self.command == "GET" and path == "/healthz":
            latest = self.store.latest_version()
            self.reply(200, {"status": "ok", "component": "manager-api", "version": "3.7.0", "latest_release": latest["version"] if latest else None})
        elif self.command == "GET" and path == "/metrics":
            self.reply_text(200, self.store.prometheus_text(), "text/plain; version=0.0.4; charset=utf-8")
        elif self.command == "GET" and path == "/v1/metrics":
            self.reply(200, {"items": self.store.list_metrics()})
        elif self.command == "GET" and path == "/v1/capabilities":
            registry = default_registry()
            self.reply(200, {
                "api_version": "3.7.0",
                "adapters": [{"name": name, "plane": registry.get(name).plane} for name in registry.names()],
                "authorized_scan_roots": [str(item) for item in self.scanner.allowed_roots],
                "scanner": {
                    "cpp_semantic": {
                        "engine": "clang-ast-json", "default": "auto",
                        "modes": ["auto", "on", "off"],
                        "compile_command_replayed": False,
                        "detects": [
                            "templates", "nested_macros", "function_pointers",
                            "virtual_dispatch_candidates", "dynamic_symbol_resolution",
                        ],
                    },
                },
                "runtime_discovery": {
                    "report_endpoint": "POST /v1/runtime/reports",
                    "sources": ["proc-maps", "container-cgroup", "fixed-ebpf-uprobes", "trace-import"],
                    "separate_agent_token": bool(self.runtime_agent_token),
                    "target_execution": False,
                },
                "release_lifecycle": [
                    "DRAFT", "VALIDATED", "STAGED", "APPLIED", "HEALTHY",
                    "VALIDATION_FAILED", "NGINX_TEST_FAILED", "RELOAD_FAILED",
                    "HEALTH_CHECK_FAILED", "ROLLED_BACK",
                ],
                "migration_lifecycle": [
                    "DISCOVERED", "ASSESSED", "PLANNED", "COMPATIBILITY",
                    "PQC_PREFERRED", "STRICT", "VERIFIED", "DEGRADED",
                    "ROLLED_BACK", "BLOCKED",
                ],
                "workflows": {
                    "onboard_and_publish": "POST /v1/onboarding",
                    "scan": "POST /v1/scans",
                    "runtime_discovery": "POST /v1/runtime/reports",
                    "asset_migration": "POST /v1/assets/{asset_id}/migration",
                    "rollback": "POST /v1/releases/{version}/rollback",
                },
            })
        elif self.command == "GET" and path == "/v1/status":
            stale_after = float(query.get("stale_after", ["30"])[0])
            self.reply(200, self.store.system_summary(stale_after))
        elif self.command == "POST" and path == "/v1/onboarding":
            self.reply(202, publish_service(self.store, self.control_dir, self.body(), self.actor()))
        elif self.command == "GET" and path in {"/v1/configs", "/v1/releases"}:
            self.reply(200, {"items": self.store.list_versions(self.limit(query, 50))})
        elif self.command == "POST" and path == "/v1/scans":
            self.reply(202, self.scanner.submit(self.body(), self.actor()))
        elif self.command == "GET" and path == "/v1/scans":
            self.reply(200, {"items": self.store.list_scan_jobs(self.limit(query))})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/scans/([A-Za-z0-9._-]+)", path)):
            self.reply(200, self.store.get_scan_job(match.group(1)))
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/scans/([A-Za-z0-9._-]+)/findings", path)):
            self.reply(200, {"items": self.store.list_scan_findings(match.group(1), self.limit(query, 1000))})
        elif self.command == "POST" and path == "/v1/runtime/reports":
            self.reply(202, self.store.ingest_runtime_report(self.body(), self.actor()))
        elif self.command == "GET" and path == "/v1/runtime/agents":
            stale_after = float(query.get("stale_after", ["90"])[0])
            self.reply(200, {"items": self.store.list_runtime_agents(stale_after)})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/runtime/agents/([A-Za-z0-9._-]+)", path)):
            self.reply(200, self.store.get_runtime_agent(match.group(1), self.limit(query)))
        elif self.command == "GET" and path == "/v1/runtime/batches":
            self.reply(200, {"items": self.store.list_runtime_batches(self.limit(query))})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/runtime/batches/([A-Za-z0-9._-]+)", path)):
            self.reply(200, self.store.get_runtime_batch(match.group(1)))
        elif self.command == "GET" and path == "/v1/runtime/observations":
            self.reply(200, {"items": self.store.list_runtime_observations(
                self.limit(query, 500), agent_id=str(query.get("agent_id", [""])[0])[:128],
                asset_id=str(query.get("asset_id", [""])[0])[:128],
            )})
        elif self.command == "GET" and path == "/v1/assets":
            self.reply(200, {"items": self.store.list_crypto_assets(self.limit(query, 500))})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/assets/([A-Za-z0-9._-]+)", path)):
            self.reply(200, self.store.get_crypto_asset(match.group(1), self.limit(query, 1000)))
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/assets/([A-Za-z0-9._-]+)/assess", path)):
            self.reply(201, self.scanner.assess(match.group(1), self.actor()))
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/assets/([A-Za-z0-9._-]+)/migration", path)):
            self.reply(202, self.scanner.migrate(match.group(1), self.body(), self.actor()))
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/(?:configs|releases)/(\d+)", path)):
            self.reply(200, self.store.get_version(int(match.group(1)), include_rendered=False))
        elif self.command == "POST" and path in {"/v1/configs/validate", "/v1/releases/validate"}:
            result = validate_document(self.body())
            self.reply(200, {"valid": True, "checksum": result["checksum"], "services": len(result["canonical"]["services"]), "policies": result["policies"]})
        elif self.command == "POST" and path in {"/v1/configs", "/v1/releases"}:
            self.reply(202, stage_document(self.store, self.control_dir, self.body(), self.actor()))
        elif self.command == "POST" and path in {"/v1/configs/from-resources", "/v1/releases/from-resources"}:
            body = self.body()
            defaults = body.get("defaults")
            if defaults is not None and not isinstance(defaults, dict):
                raise ValueError("defaults must be an object")
            self.reply(202, stage_resources(self.store, self.control_dir, self.actor(), defaults))
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/(?:configs|releases)/(\d+)/rollback", path)):
            self.reply(202, stage_rollback(self.store, self.control_dir, int(match.group(1)), self.actor()))
        elif self.command == "GET" and path in {"/v1/services", "/v1/policies"}:
            kind = "service" if path.endswith("services") else "policy"
            self.reply(200, {"items": self.store.list_resources(kind, self.limit(query, 500))})
        elif self.command == "POST" and path in {"/v1/services", "/v1/policies"}:
            kind = "service" if path.endswith("services") else "policy"
            resource_id, spec = self.resource_spec(self.body())
            self.reply(201, self.store.upsert_resource(kind, resource_id, spec, self.actor()))
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/services/([A-Za-z0-9._-]+)/publish", path)):
            self.reply(202, publish_service(self.store, self.control_dir, self.body(), self.actor(), match.group(1)))
        elif match := re.fullmatch(r"/v1/(services|policies)/([A-Za-z0-9._-]+)", path):
            kind = "service" if match.group(1) == "services" else "policy"
            resource_id = match.group(2)
            if self.command == "GET":
                self.reply(200, self.store.get_resource(kind, resource_id))
            elif self.command == "PUT":
                _, spec = self.resource_spec(self.body(), resource_id)
                if kind == "service" and spec.get("id") not in {None, resource_id}:
                    raise ValueError("service id in the spec must match the request path")
                self.reply(200, self.store.upsert_resource(kind, resource_id, spec, self.actor()))
            elif self.command == "DELETE":
                self.store.delete_resource(kind, resource_id, self.actor())
                self.reply(200, {"deleted": True, "kind": kind, "id": resource_id})
            else:
                self.reply(405, {"error": "method not allowed"})
        elif self.command == "GET" and path == "/v1/agents":
            stale_after = float(query.get("stale_after", ["30"])[0])
            self.reply(200, {"items": self.store.list_agents(stale_after)})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/agents/([A-Za-z0-9._-]+)", path)):
            self.reply(200, self.store.get_agent(match.group(1)))
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/agents/([A-Za-z0-9._-]+)/heartbeat", path)):
            body = self.body()
            self.reply(200, self.store.heartbeat_agent(
                match.group(1), current_version=body.get("current_version"), desired_version=body.get("desired_version"),
                status=str(body.get("status", "UNKNOWN")), health=str(body.get("health", "unknown")),
                reload_result=body.get("reload_result"), active_connections=body.get("active_connections"),
                fallback_rate=body.get("fallback_rate"), error=body.get("error"), metadata=body.get("metadata"),
            ))
        elif self.command == "GET" and path == "/v1/migrations":
            self.reply(200, {"items": MigrationStateMachine(self.store).list()})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/migrations/([A-Za-z0-9._-]+)", path)):
            current = MigrationStateMachine(self.store).get(match.group(1))
            if current is None:
                raise KeyError(f"unknown migration service: {match.group(1)}")
            self.reply(200, current)
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/migrations/([A-Za-z0-9._-]+)/history", path)):
            self.reply(200, {"items": MigrationStateMachine(self.store).history(match.group(1), self.limit(query))})
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/services/([A-Za-z0-9._-]+)/transition", path)):
            body = self.body()
            result = MigrationStateMachine(self.store).transition(
                match.group(1), str(body.get("state", "")), operator=self.actor(), reason=str(body.get("reason", "")),
                config_version=body.get("config_version"), verification_result=body.get("verification_result"), fallback_rate=body.get("fallback_rate"),
            )
            self.reply(200, result)
        elif self.command == "GET" and path == "/v1/audit":
            self.reply(200, {"items": self.store.list_audit(self.limit(query))})
        else:
            self.reply(404, {"error": "not found"})

    def _handle(self) -> None:
        try:
            self.dispatch()
        except KeyError as exc:
            self.reply(404, {"error": str(exc)})
        except (TransitionError, ReleaseTransitionError) as exc:
            self.reply(409, {"error": str(exc)})
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            self.reply(400, {"error": str(exc)})
        except Exception as exc:  # keep the simple server alive and avoid HTML errors
            self.log_message("unhandled error: %s", exc)
            self.reply(500, {"error": "internal control-plane error"})

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--db", default="runtime-data/control/control-plane.db")
    parser.add_argument("--control-dir", default="runtime-data/control")
    parser.add_argument("--token", default=os.environ.get("MANAGER_API_TOKEN", ""))
    parser.add_argument("--runtime-agent-token", default=os.environ.get("RUNTIME_AGENT_TOKEN", ""))
    parser.add_argument("--private-metrics", action="store_true", help="Require the bearer token for /metrics")
    parser.add_argument("--scan-root", action="append", default=[], help="Authorized scan root; may be repeated")
    parser.add_argument("--scan-workers", type=int, default=2)
    parser.add_argument("--enable-process-scan", action="store_true")
    parser.add_argument("--enable-ebpf", action="store_true")
    args = parser.parse_args()
    if not args.token:
        print("manager-api refuses to start without MANAGER_API_TOKEN or --token", file=sys.stderr)
        return 2
    ApiHandler.store = ConfigStore(args.db)
    ApiHandler.control_dir = Path(args.control_dir)
    ApiHandler.token = args.token
    ApiHandler.runtime_agent_token = args.runtime_agent_token
    ApiHandler.metrics_public = not args.private_metrics
    environment_roots = [item for item in os.environ.get("PQ_SCAN_ALLOWED_ROOTS", "").split(os.pathsep) if item]
    allowed_roots = args.scan_root + environment_roots or [str(ROOT)]
    ApiHandler.scanner = ScanOrchestrator(
        ApiHandler.store, args.control_dir, allowed_roots, workers=args.scan_workers,
        process_scan_enabled=args.enable_process_scan or os.environ.get("PQ_PROCESS_SCAN_ENABLED") == "1",
        ebpf_enabled=args.enable_ebpf or os.environ.get("PQ_EBPF_ENABLED") == "1",
    )
    server = ThreadingHTTPServer((args.host, args.port), ApiHandler)
    print(f"manager-api v3.7 listening on {args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        ApiHandler.scanner.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
