#!/usr/bin/env python3
"""HTTPS backend that requires gateway client certificates and records SNI."""
from __future__ import annotations

import argparse
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class Handler(BaseHTTPRequestHandler):
    server_version = "PQCUpstreamTLSBackend/1.0"

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        peer = self.connection.getpeercert() if isinstance(self.connection, ssl.SSLSocket) else {}
        subject = ",".join("=".join(x) for rdn in peer.get("subject", ()) for x in rdn)
        payload = {
            "status": "ok",
            "service": "secure-upstream-backend",
            "path": path,
            "server_name_received": getattr(self.connection, "server_name_received", ""),
            "peer_certificate_subject": subject,
            "tls_version": self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else "",
            "cipher": (self.connection.cipher() or ("",))[0] if isinstance(self.connection, ssl.SSLSocket) else "",
            "ts": int(time.time()),
        }
        if path in {"/healthz", "/tls-info", "/service-info"}:
            self.send_json(200, payload)
        else:
            self.send_json(404, {"error": "not_found", **payload})

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(json.dumps({"remote": self.client_address[0], "request": fmt % args}), flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--client-ca", required=True)
    p.add_argument("--require-client-cert", action="store_true")
    args = p.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED if args.require_client_cert else ssl.CERT_OPTIONAL

    def sni_callback(sock: ssl.SSLSocket, server_name: str | None, _ctx: ssl.SSLContext) -> None:
        sock.server_name_received = server_name or ""  # type: ignore[attr-defined]

    context.set_servername_callback(sni_callback)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"event": "secure_backend_started", "host": args.host, "port": args.port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
