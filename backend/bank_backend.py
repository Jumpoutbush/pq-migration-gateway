#!/usr/bin/env python3
"""Minimal mock bank backend used to validate the PQC migration gateway.

This service deliberately has no post-quantum dependency. It represents an
existing HTTP banking service that the migration gateway protects without
modifying the backend application.
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class BankBackendHandler(BaseHTTPRequestHandler):
    server_version = "MockBankBackend/0.1"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urlparse(self.path)
        if parsed.path in {"/health", "/healthz"}:
            self._send_json(200, {"status": "ok", "service": "bank-backend", "ts": int(time.time())})
            return
        if parsed.path == "/api/balance":
            self._send_json(200, {"account": "demo-001", "currency": "CNY", "available": "1000000.00"})
            return
        self._send_json(404, {"error": "not_found", "path": parsed.path})

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request_body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return

        if parsed.path == "/api/transfer":
            self._send_json(
                200,
                {
                    "status": "accepted",
                    "transaction_id": "txn-" + uuid.uuid4().hex[:20],
                    "received": request_body,
                    "handled_by": "legacy-bank-service",
                },
            )
            return
        self._send_json(404, {"error": "not_found", "path": parsed.path})

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - stdlib signature
        print(
            json.dumps(
                {
                    "remote": self.client_address[0],
                    "time": self.log_date_time_string(),
                    "request": fmt % args,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock bank backend service")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), BankBackendHandler)
    print(json.dumps({"event": "backend_started", "host": args.host, "port": args.port}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
