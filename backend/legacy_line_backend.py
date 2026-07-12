#!/usr/bin/env python3
"""Small non-HTTP line protocol backend used to prove legacy protocol transparency."""
from __future__ import annotations
import argparse
import socketserver

class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"LEGACY/1.0 READY\r\n"); self.wfile.flush()
        for raw in self.rfile:
            line=raw.decode('utf-8','replace').strip()
            upper=line.upper()
            if upper=='PING': out='PONG'
            elif upper=='VERSION': out='LEGACY/1.0'
            elif upper.startswith('ECHO '): out=line[5:]
            elif upper=='QUIT': self.wfile.write(b'BYE\r\n'); self.wfile.flush(); return
            else: out='ERR UNKNOWN_COMMAND'
            self.wfile.write((out+'\r\n').encode()); self.wfile.flush()

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True

def main()->None:
    p=argparse.ArgumentParser();p.add_argument('--host',default='0.0.0.0');p.add_argument('--port',type=int,default=9100);a=p.parse_args()
    with Server((a.host,a.port),Handler) as s:s.serve_forever()
if __name__=='__main__':main()
