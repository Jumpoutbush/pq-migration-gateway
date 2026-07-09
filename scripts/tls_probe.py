#!/usr/bin/env python3
"""Probe a TLS endpoint and report negotiated TLS/PQC migration details."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(cmd: list[str], timeout: int = 10, input_data: bytes | None = b"") -> tuple[int, str, str, float]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - CLI tool should report any runtime failure
        return 124, "", str(exc), time.perf_counter() - started
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace"), time.perf_counter() - started


def first_match(pattern: str, text: str) -> str:
    m = re.search(pattern, text, re.I | re.M)
    return m.group(1).strip() if m else ""


def extract_first_cert(text: str) -> str:
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    return m.group(0) if m else ""


def parse_cert(openssl_bin: str, pem: str) -> dict:
    if not pem:
        return {}
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        name = fh.name
    try:
        rc, out, err, _ = run([openssl_bin, "x509", "-in", name, "-noout", "-subject", "-issuer", "-dates", "-text"], timeout=5)
    finally:
        Path(name).unlink(missing_ok=True)
    if rc != 0:
        return {"parse_error": err.strip()}
    return {
        "subject": first_match(r"^subject=(.*)$", out),
        "issuer": first_match(r"^issuer=(.*)$", out),
        "not_before": first_match(r"^notBefore=(.*)$", out),
        "not_after": first_match(r"^notAfter=(.*)$", out),
        "public_key_algorithm": first_match(r"Public Key Algorithm:\s*([^\n]+)", out),
        "public_key_bits": first_match(r"Public-Key:\s*\((\d+)\s+bit\)", out),
        "signature_algorithm": first_match(r"Signature Algorithm:\s*([^\n]+)", out),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe TLS 1.3 endpoint and report negotiated PQ/hybrid groups.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", default="")
    parser.add_argument("--groups", default="X25519MLKEM768:X25519")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--cafile", default="")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    sni = args.sni or args.host
    cmd = [
        args.openssl,
        "s_client",
        "-connect", f"{args.host}:{args.port}",
        "-servername", sni,
        "-tls1_3",
        "-groups", args.groups,
        "-brief",
        "-showcerts",
    ]
    if args.cafile:
        cmd += ["-CAfile", args.cafile, "-verify_return_error"]
    elif args.no_verify:
        cmd += ["-verify_quiet"]

    rc, out, err, elapsed = run(cmd, timeout=args.timeout)
    combined = out + "\n" + err
    result = {
        "target": f"{args.host}:{args.port}",
        "sni": sni,
        "requested_groups": args.groups,
        "return_code": rc,
        "elapsed_ms": round(elapsed * 1000, 3),
        "protocol": first_match(r"Protocol version:\s*([^\n]+)", combined) or first_match(r"Protocol\s*:\s*([^\n]+)", combined),
        "cipher_suite": first_match(r"Ciphersuite:\s*([^\n]+)", combined) or first_match(r"Cipher\s*:\s*([^\n]+)", combined),
        "server_temp_key": first_match(r"Server Temp Key:\s*([^\n]+)", combined),
        "verification": first_match(r"Verification:\s*([^\n]+)", combined) or first_match(r"Verify return code:\s*([^\n]+)", combined),
        "peer_certificate": parse_cert(args.openssl, extract_first_cert(combined)),
        "stderr_tail": "\n".join(err.splitlines()[-10:]),
    }

    # Migration-oriented interpretation.
    negotiated = result.get("server_temp_key", "")
    if "MLKEM" in negotiated.upper() or "ML-KEM" in negotiated.upper():
        result["pq_kex_status"] = "hybrid_or_pq_negotiated"
    elif negotiated:
        result["pq_kex_status"] = "classical_kex_negotiated"
    else:
        result["pq_kex_status"] = "unknown_or_failed"

    data = json.dumps(result, ensure_ascii=False, indent=2)
    if args.json:
        Path(args.json).write_text(data + "\n", encoding="utf-8")
    print(data)
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
