#!/usr/bin/env python3
"""Benchmark MQTT QoS-0 round trips over a selected TLS 1.3/OpenSSL group.

The benchmark uses OpenSSL s_client as a binary TLS tunnel, so it can force
X25519MLKEM768 even when the distribution MQTT client is linked to an older
OpenSSL release.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import statistics
import struct
import subprocess
import time
import uuid
from pathlib import Path


def encode_remaining(value: int) -> bytes:
    if value < 0:
        raise ValueError("remaining length cannot be negative")
    out = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        out.append(digit)
        if not value:
            return bytes(out)


def mqtt_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def connect_packet(client_id: str) -> bytes:
    variable = mqtt_string("MQTT") + b"\x04\x02\x00\x3c"
    payload = mqtt_string(client_id)
    return b"\x10" + encode_remaining(len(variable) + len(payload)) + variable + payload


def subscribe_packet(topic: str, packet_id: int = 1) -> bytes:
    payload = struct.pack("!H", packet_id) + mqtt_string(topic) + b"\x00"
    return b"\x82" + encode_remaining(len(payload)) + payload


def publish_packet(topic: str, payload: bytes) -> bytes:
    body = mqtt_string(topic) + payload
    return b"\x30" + encode_remaining(len(body)) + body


def percentile(values: list[float], ratio: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) - 1) * ratio)))]


class OpenSSLTunnel:
    def __init__(self, args: argparse.Namespace, client_id: str) -> None:
        cmd = [
            args.openssl,
            "s_client",
            "-quiet",
            "-ign_eof",
            "-connect",
            f"{args.host}:{args.port}",
            "-servername",
            args.sni,
            "-tls1_3",
            "-groups",
            args.groups,
            "-CAfile",
            args.cafile,
            "-verify_return_error",
        ]
        self.timeout = args.timeout
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.send(connect_packet(client_id))
        packet_type, body = self.read_packet()
        if packet_type != 2 or body != b"\x00\x00":
            raise RuntimeError(f"MQTT CONNACK failed: type={packet_type}, body={body!r}")

    def send(self, data: bytes) -> None:
        if self.process.stdin is None:
            raise RuntimeError("TLS tunnel stdin is closed")
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def _read_exact(self, size: int) -> bytes:
        if self.process.stdout is None:
            raise RuntimeError("TLS tunnel stdout is closed")
        fd = self.process.stdout.fileno()
        deadline = time.monotonic() + self.timeout
        output = bytearray()
        while len(output) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timed out reading {size} MQTT bytes")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                raise TimeoutError(f"Timed out reading {size} MQTT bytes")
            chunk = os.read(fd, size - len(output))
            if not chunk:
                error = b""
                if self.process.stderr is not None:
                    error = self.process.stderr.read() or b""
                raise EOFError(f"TLS tunnel closed: {error.decode('utf-8', 'replace')[-800:]}")
            output.extend(chunk)
        return bytes(output)

    def read_packet(self) -> tuple[int, bytes]:
        first = self._read_exact(1)[0]
        multiplier = 1
        remaining = 0
        for _ in range(4):
            digit = self._read_exact(1)[0]
            remaining += (digit & 0x7F) * multiplier
            if not digit & 0x80:
                break
            multiplier *= 128
        else:
            raise ValueError("Malformed MQTT remaining length")
        return first >> 4, self._read_exact(remaining)

    def subscribe(self, topic: str) -> None:
        self.send(subscribe_packet(topic))
        packet_type, body = self.read_packet()
        if packet_type != 9 or len(body) < 3:
            raise RuntimeError(f"MQTT SUBACK failed: type={packet_type}, body={body!r}")

    def publish(self, topic: str, payload: bytes) -> None:
        self.send(publish_packet(topic, payload))

    def receive_publish(self) -> tuple[str, bytes]:
        while True:
            packet_type, body = self.read_packet()
            if packet_type != 3:
                continue
            if len(body) < 2:
                raise ValueError("Malformed MQTT PUBLISH")
            topic_length = struct.unpack("!H", body[:2])[0]
            end = 2 + topic_length
            return body[2:end].decode("utf-8", "replace"), body[end:]

    def close(self) -> None:
        try:
            self.send(b"\xe0\x00")
        except Exception:
            pass
        try:
            if self.process.stdin:
                self.process.stdin.close()
        except Exception:
            pass
        self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8883)
    parser.add_argument("--sni", default="mqtt-gateway.local")
    parser.add_argument("--groups", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--cafile", required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--topic", default="pqc/performance/openssl")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:10]
    topic = f"{args.topic}/{suffix}"
    subscriber: OpenSSLTunnel | None = None
    publisher: OpenSSLTunnel | None = None
    latencies: list[float] = []
    failures: list[str] = []
    started = time.perf_counter()
    try:
        subscriber = OpenSSLTunnel(args, f"sub-{suffix}")
        subscriber.subscribe(topic)
        publisher = OpenSSLTunnel(args, f"pub-{suffix}")

        for index in range(args.warmup):
            expected = f"warmup-{index}".encode()
            publisher.publish(topic, expected)
            received_topic, received = subscriber.receive_publish()
            if received_topic != topic or received != expected:
                raise RuntimeError("MQTT warmup payload mismatch")

        benchmark_start = time.perf_counter()
        for index in range(args.count):
            expected = f"message-{index}".encode()
            one_start = time.perf_counter()
            publisher.publish(topic, expected)
            received_topic, received = subscriber.receive_publish()
            elapsed = (time.perf_counter() - one_start) * 1000
            if received_topic != topic or received != expected:
                failures.append(f"payload mismatch at message {index}")
            else:
                latencies.append(elapsed)
        wall = time.perf_counter() - benchmark_start
    except Exception as exc:  # retain a machine-readable report on failure
        wall = time.perf_counter() - started
        failures.append(str(exc))
    finally:
        if publisher:
            publisher.close()
        if subscriber:
            subscriber.close()

    result = {
        "test": "mqtt_qos0_roundtrip_openssl",
        "target": f"{args.host}:{args.port}",
        "sni": args.sni,
        "groups": args.groups,
        "messages": args.count,
        "warmup": args.warmup,
        "received": len(latencies),
        "failures": len(failures),
        "wall_time_s": round(wall, 4),
        "messages_per_s": round(args.count / wall, 3) if wall else None,
        "mean_ms": round(statistics.mean(latencies), 3) if latencies else None,
        "p50_ms": round(percentile(latencies, 0.50), 3) if latencies else None,
        "p95_ms": round(percentile(latencies, 0.95), 3) if latencies else None,
        "p99_ms": round(percentile(latencies, 0.99), 3) if latencies else None,
        "min_ms": round(min(latencies), 3) if latencies else None,
        "max_ms": round(max(latencies), 3) if latencies else None,
        "failure_samples": failures[:3],
    }
    Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not failures and len(latencies) == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
