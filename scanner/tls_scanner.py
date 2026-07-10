#!/usr/bin/env python3
"""Online TLS endpoint scanner for PQC migration readiness."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_GROUPS = ["X25519MLKEM768", "X25519"]


def run(cmd: list[str], timeout: int, data: bytes = b"") -> tuple[int, str, float]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        text = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", "replace")
        return proc.returncode, text, (time.perf_counter() - started) * 1000
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc), (time.perf_counter() - started) * 1000


def match(pattern: str, text: str) -> str:
    found = re.search(pattern, text, re.I | re.M)
    return found.group(1).strip() if found else ""


def first_certificate(text: str) -> str:
    found = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    return found.group(0) if found else ""


def cert_info(openssl_bin: str, pem: str, timeout: int) -> dict:
    if not pem:
        return {}
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write(pem)
        name = handle.name
    try:
        rc, text, _ = run([openssl_bin, "x509", "-in", name, "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256", "-text"], timeout)
    finally:
        Path(name).unlink(missing_ok=True)
    if rc != 0:
        return {"parse_error": text[-500:]}
    algorithm = match(r"Public Key Algorithm:\s*([^\n]+)", text)
    signature = match(r"Signature Algorithm:\s*([^\n]+)", text)
    bits = match(r"Public-Key:\s*\((\d+)\s+bit", text)
    return {
        "subject": match(r"^subject=(.*)$", text),
        "issuer": match(r"^issuer=(.*)$", text),
        "not_before": match(r"^notBefore=(.*)$", text),
        "not_after": match(r"^notAfter=(.*)$", text),
        "sha256_fingerprint": match(r"SHA256 Fingerprint=(.*)$", text),
        "public_key_algorithm": algorithm,
        "signature_algorithm": signature,
        "public_key_bits": bits,
        "quantum_vulnerable_authentication": bool(re.search(r"RSA|EC|ECDSA|DSA", algorithm + " " + signature, re.I)),
    }


def parse_endpoint(value: str) -> tuple[str, int, str]:
    # HOST:PORT[,SNI]
    endpoint, sep, sni = value.partition(",")
    host, colon, port_text = endpoint.rpartition(":")
    if not colon or not host:
        raise argparse.ArgumentTypeError("endpoint must be HOST:PORT[,SNI]")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid endpoint port") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("endpoint port out of range")
    return host, port, sni or host


@dataclass
class Probe:
    requested_group: str
    success: bool
    return_code: int
    elapsed_ms: float
    protocol: str = ""
    cipher_suite: str = ""
    negotiated_group: str = ""
    verification: str = ""
    error_tail: str = ""


@dataclass
class EndpointResult:
    endpoint_id: str
    host: str
    port: int
    sni: str
    status: str
    pqc_supported: bool
    classical_supported: bool
    fallback_enabled: bool
    supported_groups: list[str] = field(default_factory=list)
    certificate: dict = field(default_factory=dict)
    probes: list[dict] = field(default_factory=list)


def probe(openssl_bin: str, host: str, port: int, sni: str, group: str, cafile: str, no_verify: bool, timeout: int) -> tuple[Probe, str]:
    cmd = [openssl_bin, "s_client", "-connect", f"{host}:{port}", "-servername", sni, "-tls1_3", "-groups", group, "-brief", "-showcerts"]
    if cafile:
        cmd += ["-CAfile", cafile, "-verify_return_error"]
    elif no_verify:
        cmd += ["-verify_quiet"]
    rc, text, elapsed = run(cmd, timeout)
    negotiated = (
        match(r"Negotiated TLS1\.3 group:\s*([^\n]+)", text)
        or match(r"Server Temp Key:\s*([^,\n]+)", text)
        or match(r"Peer Temp Key:\s*([^,\n]+)", text)
    )
    verification = match(r"Verification:\s*([^\n]+)", text) or match(r"Verify return code:\s*([^\n]+)", text)
    success = rc == 0 and bool(match(r"Protocol version:\s*([^\n]+)", text) or match(r"Protocol\s*:\s*([^\n]+)", text))
    return Probe(
        requested_group=group,
        success=success,
        return_code=rc,
        elapsed_ms=round(elapsed, 3),
        protocol=match(r"Protocol version:\s*([^\n]+)", text) or match(r"Protocol\s*:\s*([^\n]+)", text),
        cipher_suite=match(r"Ciphersuite:\s*([^\n]+)", text) or match(r"Cipher\s*:\s*([^\n]+)", text),
        negotiated_group=negotiated,
        verification=verification,
        error_tail="\n".join(text.splitlines()[-8:]) if not success else "",
    ), first_certificate(text)



def fetch_certificate(openssl_bin: str, host: str, port: int, sni: str, group: str, cafile: str, no_verify: bool, timeout: int) -> str:
    cmd = [openssl_bin, "s_client", "-connect", f"{host}:{port}", "-servername", sni, "-tls1_3", "-groups", group, "-showcerts"]
    if cafile:
        cmd += ["-CAfile", cafile, "-verify_return_error"]
    elif no_verify:
        cmd += ["-verify_quiet"]
    _rc, text, _elapsed = run(cmd, timeout)
    return first_certificate(text)

def scan_endpoint(openssl_bin: str, host: str, port: int, sni: str, groups: list[str], cafile: str, no_verify: bool, timeout: int) -> EndpointResult:
    probes: list[Probe] = []
    pem = ""
    for group in groups:
        item, candidate_pem = probe(openssl_bin, host, port, sni, group, cafile, no_verify, timeout)
        probes.append(item)
        pem = pem or candidate_pem
    supported = [p.requested_group for p in probes if p.success]
    if not pem and supported:
        pem = fetch_certificate(openssl_bin, host, port, sni, supported[0], cafile, no_verify, timeout)
    pqc = any("MLKEM" in g.upper() or "ML-KEM" in g.upper() for g in supported)
    classical = "X25519" in supported
    digest = hashlib.sha256(f"{host}:{port}:{sni}".encode()).hexdigest()[:20]
    return EndpointResult(
        endpoint_id="endpoint-" + digest,
        host=host,
        port=port,
        sni=sni,
        status="reachable" if supported else "unreachable_or_incompatible",
        pqc_supported=pqc,
        classical_supported=classical,
        fallback_enabled=pqc and classical,
        supported_groups=supported,
        certificate=cert_info(openssl_bin, pem, timeout),
        probes=[asdict(p) for p in probes],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", action="append", type=parse_endpoint, required=True, help="HOST:PORT[,SNI]; repeatable")
    parser.add_argument("--groups", default=":".join(DEFAULT_GROUPS))
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--cafile", default="")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", default="")
    args = parser.parse_args()

    groups = [item for item in args.groups.split(":") if item]
    endpoints = [scan_endpoint(args.openssl, *ep, groups, args.cafile, args.no_verify, args.timeout) for ep in args.endpoint]
    payload = {
        "schema_version": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "groups_tested": groups,
        "summary": {
            "endpoints": len(endpoints),
            "reachable": sum(e.status == "reachable" for e in endpoints),
            "pqc_supported": sum(e.pqc_supported for e in endpoints),
            "fallback_enabled": sum(e.fallback_enabled for e in endpoints),
        },
        "endpoints": [asdict(e) for e in endpoints],
    }
    Path(args.out_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.out_csv:
        with Path(args.out_csv).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["endpoint_id", "host", "port", "sni", "status", "pqc_supported", "classical_supported", "fallback_enabled", "supported_groups", "certificate_algorithm", "certificate_bits"])
            writer.writeheader()
            for e in endpoints:
                writer.writerow({
                    "endpoint_id": e.endpoint_id, "host": e.host, "port": e.port, "sni": e.sni,
                    "status": e.status, "pqc_supported": e.pqc_supported,
                    "classical_supported": e.classical_supported, "fallback_enabled": e.fallback_enabled,
                    "supported_groups": ":".join(e.supported_groups),
                    "certificate_algorithm": e.certificate.get("public_key_algorithm", ""),
                    "certificate_bits": e.certificate.get("public_key_bits", ""),
                })
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0 if payload["summary"]["reachable"] == len(endpoints) else 1


if __name__ == "__main__":
    raise SystemExit(main())
