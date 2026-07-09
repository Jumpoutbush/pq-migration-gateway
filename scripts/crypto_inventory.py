#!/usr/bin/env python3
"""Cryptographic asset inventory scanner for PQC migration planning.

The scanner is intentionally dependency-light: it uses Python stdlib plus the
OpenSSL CLI available on the host/container. It does not implement cryptography;
it discovers where cryptography is configured or embedded.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

CERT_EXTS = {".crt", ".cer", ".pem"}
KEY_EXTS = {".key", ".pem"}
TEXT_EXTS = {
    ".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".properties",
    ".xml", ".txt", ".md", ".sh", ".py", ".go", ".java", ".js", ".ts", ".rs",
}

CRYPTO_PATTERNS = [
    ("rsa", re.compile(r"\bRSA\b|rsa_keygen_bits|RSAPrivateKey", re.I)),
    ("dsa", re.compile(r"\bDSA\b|DSAPrivateKey", re.I)),
    ("ecdsa_ecdh", re.compile(r"\bECDSA\b|\bECDH\b|\bECC\b|prime256v1|secp(256|384|521)r1|X25519|X448", re.I)),
    ("finite_field_dh", re.compile(r"\bDHE\b|ffdhe|Diffie-Hellman|dhparam", re.I)),
    ("weak_hash", re.compile(r"\bSHA1\b|sha1WithRSA|md5WithRSA|\bMD5\b", re.I)),
    ("tls_config", re.compile(r"ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command\s+Groups|SSLCipherSuite|TLS_GROUPS", re.I)),
    ("pqc", re.compile(r"ML-?KEM|ML-?DSA|SLH-?DSA|Dilithium|Kyber|SPHINCS|Falcon|X25519MLKEM768", re.I)),
]

VULN_PUBLIC_KEY = re.compile(r"RSA|ECDSA|ECDH|DSA|Diffie-Hellman|id-ecPublicKey", re.I)
PQC_PUBLIC_KEY = re.compile(r"ML-?DSA|SLH-?DSA|ML-?KEM|Dilithium|SPHINCS|Falcon", re.I)
WEAK_HASH = re.compile(r"sha1|md5", re.I)


@dataclass
class Finding:
    path: str
    finding_type: str
    algorithm: str = ""
    key_bits: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    line: int | None = None
    evidence: str = ""
    risk: str = "INFO"
    pq_status: str = "unknown"
    recommendation: str = ""
    metadata: dict = field(default_factory=dict)


def run_cmd(cmd: list[str], input_data: bytes | None = None, timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return 124, "", str(exc)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def safe_read_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def parse_date(value: str) -> str:
    # OpenSSL emits e.g. notAfter=Jul  7 12:00:00 2027 GMT.
    return value.strip()


def classify(algorithm: str, evidence: str, key_bits: str = "") -> tuple[str, str, str]:
    blob = f"{algorithm} {evidence}"
    if PQC_PUBLIC_KEY.search(blob):
        return "LOW", "pqc_or_pqc_candidate", "Confirm implementation profile, certificate-chain interoperability, and operational policy."
    if WEAK_HASH.search(blob):
        return "HIGH", "classically_weak", "Remove MD5/SHA-1 and reissue certificates or update signatures."
    if VULN_PUBLIC_KEY.search(blob):
        if key_bits and key_bits.isdigit() and int(key_bits) < 2048 and "RSA" in blob.upper():
            return "CRITICAL", "classically_weak_and_quantum_vulnerable", "Replace weak RSA and plan hybrid/PQC migration immediately."
        return "MEDIUM", "quantum_vulnerable", "Inventory owner, protocol, and data lifetime; migrate to hybrid/PQC where supported."
    return "INFO", "unknown", "Review manually if this component protects long-lived confidential or high-value data."


def parse_cert(path: Path, openssl_bin: str) -> list[Finding]:
    rc, out, err = run_cmd([openssl_bin, "x509", "-in", str(path), "-noout", "-text", "-subject", "-issuer", "-dates"])
    if rc != 0:
        return []

    sig = re.search(r"Signature Algorithm:\s*([^\n]+)", out)
    pub = re.search(r"Public Key Algorithm:\s*([^\n]+)", out)
    bits = re.search(r"Public-Key:\s*\((\d+)\s+bit\)", out)
    subj = re.search(r"subject=([^\n]+)", out)
    issuer = re.search(r"issuer=([^\n]+)", out)
    nb = re.search(r"notBefore=([^\n]+)", out)
    na = re.search(r"notAfter=([^\n]+)", out)

    algorithm = "; ".join(x for x in [(pub.group(1).strip() if pub else ""), (sig.group(1).strip() if sig else "")] if x)
    risk, pq_status, rec = classify(algorithm, out, bits.group(1) if bits else "")
    return [
        Finding(
            path=str(path),
            finding_type="x509_certificate",
            algorithm=algorithm,
            key_bits=bits.group(1) if bits else "",
            subject=subj.group(1).strip() if subj else "",
            issuer=issuer.group(1).strip() if issuer else "",
            not_before=parse_date(nb.group(1)) if nb else "",
            not_after=parse_date(na.group(1)) if na else "",
            risk=risk,
            pq_status=pq_status,
            recommendation=rec,
        )
    ]


def parse_private_key(path: Path, openssl_bin: str) -> list[Finding]:
    rc, out, err = run_cmd([openssl_bin, "pkey", "-in", str(path), "-noout", "-text"], timeout=5)
    if rc != 0:
        return []
    first = "\n".join(out.splitlines()[:8])
    alg = "private_key"
    if re.search(r"RSA", out, re.I):
        alg = "RSA private key"
    elif re.search(r"EC PRIVATE|ASN1 OID|prime256v1|secp|X25519", out, re.I):
        alg = "EC private key"
    elif re.search(r"ML-?DSA|SLH-?DSA", out, re.I):
        alg = "PQC private key"
    bits = re.search(r"Private-Key:\s*\((\d+)\s+bit", out)
    risk, pq_status, rec = classify(alg, out, bits.group(1) if bits else "")
    return [
        Finding(
            path=str(path),
            finding_type="private_key",
            algorithm=alg,
            key_bits=bits.group(1) if bits else "",
            evidence=first,
            risk=risk,
            pq_status=pq_status,
            recommendation=rec,
        )
    ]


def scan_text(path: Path, max_bytes: int) -> list[Finding]:
    text = safe_read_text(path, max_bytes)
    if text is None:
        return []
    findings: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for name, pattern in CRYPTO_PATTERNS:
            if pattern.search(stripped):
                risk, pq_status, rec = classify(name, stripped)
                findings.append(
                    Finding(
                        path=str(path),
                        finding_type="text_crypto_reference",
                        algorithm=name,
                        line=idx,
                        evidence=stripped[:400],
                        risk=risk,
                        pq_status=pq_status,
                        recommendation=rec,
                    )
                )
                break
    return findings


def iter_files(roots: Iterable[Path], exclude_dirs: set[str]) -> Iterable[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".git")]
            for name in filenames:
                yield Path(dirpath) / name


def write_csv(path: Path, findings: list[Finding]) -> None:
    fieldnames = [
        "path", "finding_type", "algorithm", "key_bits", "subject", "issuer", "not_before", "not_after",
        "line", "evidence", "risk", "pq_status", "recommendation",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row.pop("metadata", None)
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a cryptographic asset inventory for PQC migration.")
    parser.add_argument("--root", action="append", required=True, help="File or directory to scan. Can be repeated.")
    parser.add_argument("--openssl", default="openssl", help="OpenSSL CLI path. Use /opt/openssl/bin/openssl in the gateway container.")
    parser.add_argument("--out-json", default="crypto-inventory.json")
    parser.add_argument("--out-csv", default="crypto-inventory.csv")
    parser.add_argument("--max-bytes", type=int, default=2_000_000, help="Max text file size to scan.")
    parser.add_argument("--exclude-dir", action="append", default=["node_modules", "vendor", "target", "build", "dist", "__pycache__"])
    args = parser.parse_args()

    roots = [Path(r).expanduser().resolve() for r in args.root]
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, int | None]] = set()

    for file_path in iter_files(roots, set(args.exclude_dir)):
        suffix = file_path.suffix.lower()
        file_findings: list[Finding] = []
        if suffix in CERT_EXTS:
            file_findings.extend(parse_cert(file_path, args.openssl))
        if suffix in KEY_EXTS:
            file_findings.extend(parse_private_key(file_path, args.openssl))
        if suffix in TEXT_EXTS or suffix in CERT_EXTS or suffix in KEY_EXTS:
            file_findings.extend(scan_text(file_path, args.max_bytes))
        for finding in file_findings:
            key = (finding.path, finding.finding_type, finding.evidence or finding.algorithm, finding.line)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "roots": [str(r) for r in roots],
        "summary": {
            "total_findings": len(findings),
            "by_risk": {risk: sum(1 for f in findings if f.risk == risk) for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "quantum_vulnerable": sum(1 for f in findings if "quantum_vulnerable" in f.pq_status),
            "pqc_or_candidates": sum(1 for f in findings if f.pq_status == "pqc_or_pqc_candidate"),
        },
        "findings": [asdict(f) for f in findings],
    }

    Path(args.out_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_csv(Path(args.out_csv), findings)

    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    print(f"Wrote {args.out_json} and {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
