#!/usr/bin/env python3
"""Small TLS handshake timing harness for migration testing.

This is not a lab-grade benchmark. It is meant to compare gateway deployment
modes on the same host: X25519MLKEM768-only, hybrid-with-fallback, and classical.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


def one_handshake(openssl_bin: str, host: str, port: int, sni: str, groups: str, cafile: str, timeout: int) -> tuple[bool, float, str]:
    cmd = [
        openssl_bin, "s_client",
        "-connect", f"{host}:{port}",
        "-servername", sni,
        "-tls1_3",
        "-groups", groups,
        "-brief",
    ]
    if cafile:
        cmd += ["-CAfile", cafile, "-verify_return_error"]
    started = time.perf_counter()
    proc = subprocess.run(cmd, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    elapsed = (time.perf_counter() - started) * 1000
    text = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    return proc.returncode == 0, elapsed, text


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure repeated TLS handshake wall-clock time via OpenSSL s_client.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", default="")
    parser.add_argument("--groups", default="X25519MLKEM768:X25519")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--cafile", default="")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    sni = args.sni or args.host
    times: list[float] = []
    failures: list[str] = []
    for _ in range(args.count):
        ok, elapsed, text = one_handshake(args.openssl, args.host, args.port, sni, args.groups, args.cafile, args.timeout)
        if ok:
            times.append(elapsed)
        else:
            failures.append("\n".join(text.splitlines()[-6:]))

    result = {
        "target": f"{args.host}:{args.port}",
        "sni": sni,
        "groups": args.groups,
        "attempts": args.count,
        "successes": len(times),
        "failures": len(failures),
        "mean_ms": round(statistics.mean(times), 3) if times else None,
        "median_ms": round(statistics.median(times), 3) if times else None,
        "p95_ms": round(statistics.quantiles(times, n=20)[18], 3) if len(times) >= 20 else None,
        "min_ms": round(min(times), 3) if times else None,
        "max_ms": round(max(times), 3) if times else None,
        "failure_samples": failures[:3],
    }
    data = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(data + "\n", encoding="utf-8")
    print(data)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
