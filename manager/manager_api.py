#!/usr/bin/env python3
"""Authenticated v3.3 REST API for Gateway control-plane resources."""
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

from manager.config_store import ConfigStore, ReleaseTransitionError  # noqa: E402
from manager.control_plane import stage_document, stage_resources, stage_rollback, validate_document  # noqa: E402
from manager.state_machine import MigrationStateMachine, TransitionError  # noqa: E402

SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class ApiHandler(BaseHTTPRequestHandler):
    store: ConfigStore
    control_dir: Path
    token: str
    metrics_public = True
    max_body = 2 * 1024 * 1024

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
        if path == "/healthz" or (path == "/metrics" and self.metrics_public):
            return True
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + self.token
        return bool(self.token) and hmac.compare_digest(supplied, expected)

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

        if self.command == "GET" and path == "/healthz":
            latest = self.store.latest_version()
            self.reply(200, {"status": "ok", "component": "manager-api", "version": "3.3.1", "latest_config": latest["version"] if latest else None})
        elif self.command == "GET" and path == "/metrics":
            self.reply_text(200, self.store.prometheus_text(), "text/plain; version=0.0.4; charset=utf-8")
        elif self.command == "GET" and path == "/v1/metrics":
            self.reply(200, {"items": self.store.list_metrics()})
        elif self.command == "GET" and path == "/v1/configs":
            self.reply(200, {"items": self.store.list_versions(self.limit(query, 50))})
        elif self.command == "GET" and (match := re.fullmatch(r"/v1/configs/(\d+)", path)):
            self.reply(200, self.store.get_version(int(match.group(1)), include_rendered=False))
        elif self.command == "POST" and path == "/v1/configs/validate":
            result = validate_document(self.body())
            self.reply(200, {"valid": True, "checksum": result["checksum"], "services": len(result["canonical"]["services"]), "policies": result["policies"]})
        elif self.command == "POST" and path == "/v1/configs":
            self.reply(202, stage_document(self.store, self.control_dir, self.body(), self.actor()))
        elif self.command == "POST" and path == "/v1/configs/from-resources":
            body = self.body()
            defaults = body.get("defaults")
            if defaults is not None and not isinstance(defaults, dict):
                raise ValueError("defaults must be an object")
            self.reply(202, stage_resources(self.store, self.control_dir, self.actor(), defaults))
        elif self.command == "POST" and (match := re.fullmatch(r"/v1/configs/(\d+)/rollback", path)):
            self.reply(202, stage_rollback(self.store, self.control_dir, int(match.group(1)), self.actor()))
        elif self.command == "GET" and path in {"/v1/services", "/v1/policies"}:
            kind = "service" if path.endswith("services") else "policy"
            self.reply(200, {"items": self.store.list_resources(kind, self.limit(query, 500))})
        elif self.command == "POST" and path in {"/v1/services", "/v1/policies"}:
            kind = "service" if path.endswith("services") else "policy"
            resource_id, spec = self.resource_spec(self.body())
            self.reply(201, self.store.upsert_resource(kind, resource_id, spec, self.actor()))
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
    parser.add_argument("--private-metrics", action="store_true", help="Require the bearer token for /metrics")
    args = parser.parse_args()
    if not args.token:
        print("manager-api refuses to start without MANAGER_API_TOKEN or --token", file=sys.stderr)
        return 2
    ApiHandler.store = ConfigStore(args.db)
    ApiHandler.control_dir = Path(args.control_dir)
    ApiHandler.token = args.token
    ApiHandler.metrics_public = not args.private_metrics
    server = ThreadingHTTPServer((args.host, args.port), ApiHandler)
    print(f"manager-api v3.3 listening on {args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
