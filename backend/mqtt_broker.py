#!/usr/bin/env python3
"""Minimal MQTT 3.1.1 QoS-0 broker for protocol-transparent gateway tests."""
from __future__ import annotations
import argparse,socketserver,struct,threading
from collections import defaultdict

subscribers:dict[str,set[socketserver.BaseRequestHandler]]=defaultdict(set)
lock=threading.Lock()

def recv_exact(sock,n):
    data=b''
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk:raise EOFError
        data+=chunk
    return data

def recv_remaining(sock):
    multiplier=1;value=0
    for _ in range(4):
        b=recv_exact(sock,1)[0];value+=(b&127)*multiplier
        if not b&128:return value
        multiplier*=128
    raise ValueError('malformed remaining length')

def encode_remaining(n):
    out=bytearray()
    while True:
        d=n%128;n//=128
        if n:d|=128
        out.append(d)
        if not n:return bytes(out)

def mqtt_string(data,offset):
    n=struct.unpack('!H',data[offset:offset+2])[0];start=offset+2;return data[start:start+n].decode('utf-8','replace'),start+n

class Handler(socketserver.BaseRequestHandler):
    topics:set[str]
    def setup(self):self.topics=set()
    def finish(self):
        with lock:
            for topic in self.topics:subscribers[topic].discard(self)
    def send(self,data):
        try:self.request.sendall(data)
        except OSError:pass
    def handle(self):
        while True:
            try:first=recv_exact(self.request,1)[0];remaining=recv_remaining(self.request);body=recv_exact(self.request,remaining)
            except (EOFError,OSError):return
            packet=first>>4
            if packet==1:  # CONNECT
                self.send(b'\x20\x02\x00\x00')
            elif packet==8:  # SUBSCRIBE
                packet_id=body[:2];offset=2;granted=[]
                while offset<len(body):
                    topic,offset=mqtt_string(body,offset);qos=body[offset] if offset<len(body) else 0;offset+=1
                    with lock:subscribers[topic].add(self)
                    self.topics.add(topic);granted.append(min(qos,1))
                payload=packet_id+bytes(granted);self.send(b'\x90'+encode_remaining(len(payload))+payload)
            elif packet==3:  # PUBLISH QoS0/1
                topic,offset=mqtt_string(body,0);qos=(first>>1)&3
                if qos:offset+=2
                payload=body[offset:];wire=bytes([0x30])+encode_remaining(2+len(topic.encode())+len(payload))+struct.pack('!H',len(topic.encode()))+topic.encode()+payload
                with lock:targets=list(subscribers.get(topic,set()))
                for target in targets:target.send(wire)
                if qos==1:self.send(b'\x40\x02'+body[offset-2:offset])
            elif packet==12:self.send(b'\xd0\x00')
            elif packet==14:return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True

def main():
    p=argparse.ArgumentParser();p.add_argument('--host',default='0.0.0.0');p.add_argument('--port',type=int,default=1883);a=p.parse_args()
    with Server((a.host,a.port),Handler) as s:s.serve_forever()
if __name__=='__main__':main()
