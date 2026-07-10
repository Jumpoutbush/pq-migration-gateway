#!/usr/bin/env python3
"""Protocol-neutral demo backend used only to validate transparent proxying."""
from __future__ import annotations

import argparse
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class DemoBackendHandler(BaseHTTPRequestHandler):
    server_version = "PQCProxyDemoBackend/0.2"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/health", "/healthz"}:
            self._send_json(200, {"status": "ok", "service": "demo-backend", "ts": int(time.time())})
        elif path == "/service-info":
            self._send_json(200, {
                "service": "protocol-neutral-demo-backend",
                "request_id": self.headers.get("X-Request-ID", ""),
                "forwarded_protocol": self.headers.get("X-PQ-TLS-Protocol", ""),
                "forwarded_group": self.headers.get("X-PQ-TLS-Group", ""),
                "gateway_service": self.headers.get("X-PQ-Service", ""),
            })
        elif path == "/api/balance":  # backward-compatible test endpoint
            self._send_json(200, {"account": "demo-001", "currency": "CNY", "available": "1000000.00"})
        else:
            self._send_json(404, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return
        if path == "/echo":
            self._send_json(200, {"status": "ok", "received": payload, "gateway_service": self.headers.get("X-PQ-Service", "")})
        elif path == "/api/transfer":  # backward-compatible test endpoint
            self._send_json(200, {"status": "accepted", "transaction_id": "txn-" + uuid.uuid4().hex[:20], "received": payload})
        else:
            self._send_json(404, {"error": "not_found", "path": path})

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(json.dumps({"remote": self.client_address[0], "request": fmt % args}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DemoBackendHandler)
    print(json.dumps({"event": "backend_started", "host": args.host, "port": args.port}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
