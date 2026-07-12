#!/usr/bin/env python3
"""Threaded plain TCP echo backend for Stream TLS termination tests."""
from __future__ import annotations
import argparse
import socketserver

class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(b"ECHO " + data)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main() -> None:
    p=argparse.ArgumentParser();p.add_argument('--host',default='0.0.0.0');p.add_argument('--port',type=int,default=9000);a=p.parse_args()
    with Server((a.host,a.port),Handler) as s: s.serve_forever()
if __name__=='__main__': main()
