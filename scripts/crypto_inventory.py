#!/usr/bin/env python3
"""Dependency-light static cryptographic asset inventory scanner.

Version 2 separates concrete assets from source/configuration evidence, assigns
stable IDs, recognises RSA private keys, and never stores private-key material.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

CERT_EXTS = {".crt", ".cer", ".pem"}
KEY_EXTS = {".key", ".pem"}
TEXT_EXTS = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".properties", ".xml", ".txt", ".md", ".sh", ".py", ".go", ".java", ".js", ".ts", ".rs"}

# Order matters: PQC/hybrid must be recognised before generic DSA/ECDH tokens.
PATTERNS = [
    ("hybrid_kex", re.compile(r"X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024", re.I)),
    ("pqc", re.compile(r"ML-?KEM|ML-?DSA|SLH-?DSA|Dilithium|Kyber|SPHINCS|Falcon|HQC|Frodo", re.I)),
    ("rsa", re.compile(r"\bRSA\b|rsa_keygen_bits|RSAPrivateKey", re.I)),
    ("dsa", re.compile(r"(?<!ML-)\bDSA\b|DSAPrivateKey", re.I)),
    ("ecdsa_ecdh", re.compile(r"\bECDSA\b|\bECDH\b|\bECC\b|prime256v1|secp(?:256|384|521)r1|\bX25519\b|\bX448\b", re.I)),
    ("finite_field_dh", re.compile(r"\bDHE\b|ffdhe|Diffie-Hellman|dhparam", re.I)),
    ("weak_hash", re.compile(r"\bSHA1\b|sha1WithRSA|md5WithRSA|\bMD5\b", re.I)),
    ("tls_config", re.compile(r"ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command\s+Groups|SSLCipherSuite|TLS_GROUPS|tls_groups", re.I)),
]

VULNERABLE = re.compile(r"RSA|ECDSA|ECDH|DSA|Diffie-Hellman|id-ecPublicKey", re.I)
PQC = re.compile(r"ML-?DSA|SLH-?DSA|ML-?KEM|Dilithium|SPHINCS|Falcon|HQC|Frodo", re.I)
WEAK_HASH = re.compile(r"sha1|md5", re.I)


@dataclass
class Asset:
    asset_id: str
    asset_type: str
    path: str
    algorithm: str
    key_bits: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    fingerprint: str = ""
    deployment_status: str = "present"
    risk: str = "INFO"
    pq_status: str = "unknown"
    recommendation: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class Evidence:
    evidence_id: str
    path: str
    line: int
    evidence_type: str
    algorithm: str
    excerpt: str
    deployment_status: str = "source_reference"
    risk: str = "INFO"
    pq_status: str = "unknown"
    recommendation: str = ""


def stable_id(prefix: str, *parts: object) -> str:
    blob = "\x1f".join(str(p) for p in parts)
    return f"{prefix}-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def run(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)
    return proc.returncode, (proc.stdout + b"\n" + proc.stderr).decode("utf-8", "replace")


def first(pattern: str, text: str) -> str:
    found = re.search(pattern, text, re.I | re.M)
    return found.group(1).strip() if found else ""


def classify(algorithm: str, evidence: str, key_bits: str = "") -> tuple[str, str, str]:
    blob = f"{algorithm} {evidence}"
    if WEAK_HASH.search(blob):
        return "HIGH", "classically_weak", "Remove MD5/SHA-1 and reissue certificates or update signatures."
    if PQC.search(blob) or "hybrid_kex" in algorithm:
        return "LOW", "pqc_or_pqc_candidate", "Confirm interoperability and the intended migration policy."
    if VULNERABLE.search(blob):
        if algorithm.upper().startswith("RSA") and key_bits.isdigit() and int(key_bits) < 2048:
            return "CRITICAL", "classically_weak_and_quantum_vulnerable", "Replace weak RSA immediately and plan hybrid/PQC migration."
        return "MEDIUM", "quantum_vulnerable", "Associate the asset with its service and migrate to hybrid/PQC where supported."
    return "INFO", "unknown", "Review manually if this component protects long-lived or high-value data."


def parse_certificate(path: Path, openssl: str) -> Asset | None:
    rc, text = run([openssl, "x509", "-in", str(path), "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256", "-text"])
    if rc != 0:
        return None
    pub = first(r"Public Key Algorithm:\s*([^\n]+)", text)
    sig = first(r"Signature Algorithm:\s*([^\n]+)", text)
    bits = first(r"Public-Key:\s*\((\d+)\s+bit", text)
    algorithm = "; ".join(x for x in [pub, sig] if x)
    risk, status, recommendation = classify(algorithm, text, bits)
    fingerprint = first(r"SHA256 Fingerprint=(.*)$", text)
    return Asset(
        asset_id=stable_id("asset", "x509", fingerprint or path.resolve()),
        asset_type="x509_certificate",
        path=str(path.resolve()),
        algorithm=algorithm,
        key_bits=bits,
        subject=first(r"^subject=(.*)$", text),
        issuer=first(r"^issuer=(.*)$", text),
        not_before=first(r"^notBefore=(.*)$", text),
        not_after=first(r"^notAfter=(.*)$", text),
        fingerprint=fingerprint,
        risk=risk,
        pq_status=status,
        recommendation=recommendation,
    )


def identify_private_key(path: Path, openssl: str) -> Asset | None:
    # Validation uses algorithm-specific parsers but never persists key text.
    algorithm = ""
    bits = ""
    if run([openssl, "rsa", "-in", str(path), "-check", "-noout"])[0] == 0:
        algorithm = "RSA"
        rc, text = run([openssl, "pkey", "-in", str(path), "-noout", "-text_pub"])
        bits = first(r"Public-Key:\s*\((\d+)\s+bit", text) if rc == 0 else ""
    elif run([openssl, "ec", "-in", str(path), "-check", "-noout"])[0] == 0:
        algorithm = "EC"
        rc, text = run([openssl, "pkey", "-in", str(path), "-noout", "-text_pub"])
        bits = first(r"Private-Key:\s*\((\d+)\s+bit", text) if rc == 0 else ""
    else:
        rc, text = run([openssl, "pkey", "-in", str(path), "-noout", "-text_pub"])
        if rc != 0:
            return None
        if re.search(r"ML-?DSA", text, re.I):
            algorithm = "ML-DSA"
        elif re.search(r"SLH-?DSA", text, re.I):
            algorithm = "SLH-DSA"
        else:
            algorithm = "private_key_unknown"
        bits = first(r"(?:Public|Private)-Key:\s*\((\d+)\s+bit", text)
    risk, status, recommendation = classify(algorithm, "", bits)
    return Asset(
        asset_id=stable_id("asset", "private-key", path.resolve()),
        asset_type="private_key",
        path=str(path.resolve()),
        algorithm=algorithm,
        key_bits=bits,
        risk=risk,
        pq_status=status,
        recommendation=recommendation,
        metadata={"evidence": f"Private key parsed successfully; algorithm={algorithm}; bits={bits or 'unknown'}"},
    )


def safe_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def scan_text(path: Path, max_bytes: int) -> list[Evidence]:
    text = safe_text(path, max_bytes)
    if text is None:
        return []
    output: list[Evidence] = []
    for number, line in enumerate(text.splitlines(), 1):
        matched_pqc = False
        for algorithm, pattern in PATTERNS:
            if algorithm == "dsa" and matched_pqc:
                continue
            if not pattern.search(line):
                continue
            matched_pqc = matched_pqc or algorithm in {"pqc", "hybrid_kex"}
            excerpt = line.strip()[:500]
            risk, status, recommendation = classify(algorithm, excerpt)
            output.append(Evidence(
                evidence_id=stable_id("evidence", path.resolve(), number, algorithm, excerpt),
                path=str(path.resolve()), line=number, evidence_type="text_crypto_reference",
                algorithm=algorithm, excerpt=excerpt, risk=risk, pq_status=status,
                recommendation=recommendation,
            ))
    return output


def iter_files(roots: list[Path]):
    seen: set[Path] = set()
    for root in roots:
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = (p for p in root.rglob("*") if p.is_file())
        else:
            continue
        for path in candidates:
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved not in seen:
                seen.add(resolved)
                yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--max-text-bytes", type=int, default=2_000_000)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    args = parser.parse_args()

    roots = [Path(x) for x in args.root]
    assets: dict[str, Asset] = {}
    evidence: dict[str, Evidence] = {}
    for path in iter_files(roots):
        suffix = path.suffix.lower()
        if suffix in CERT_EXTS:
            cert = parse_certificate(path, args.openssl)
            if cert:
                assets[cert.asset_id] = cert
        if suffix in KEY_EXTS:
            key = identify_private_key(path, args.openssl)
            if key:
                assets[key.asset_id] = key
        if suffix in TEXT_EXTS or path.name in {"Dockerfile", "Makefile"}:
            for item in scan_text(path, args.max_text_bytes):
                evidence[item.evidence_id] = item

    asset_rows = [asdict(x) for x in sorted(assets.values(), key=lambda x: (x.asset_type, x.path))]
    evidence_rows = [asdict(x) for x in sorted(evidence.values(), key=lambda x: (x.path, x.line, x.algorithm))]
    risks = [x["risk"] for x in asset_rows + evidence_rows]
    payload = {
        "schema_version": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roots": [str(p.resolve()) for p in roots],
        "summary": {
            "concrete_assets": len(asset_rows),
            "source_evidence": len(evidence_rows),
            "by_risk": {name: risks.count(name) for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "quantum_vulnerable_assets": sum(x["pq_status"] == "quantum_vulnerable" for x in asset_rows),
            "pqc_assets_or_references": sum(x["pq_status"] == "pqc_or_pqc_candidate" for x in asset_rows + evidence_rows),
        },
        "assets": asset_rows,
        "evidence": evidence_rows,
        # Compatibility field for tools that consumed v1 findings.
        "findings": asset_rows + evidence_rows,
    }
    Path(args.out_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with Path(args.out_csv).open("w", encoding="utf-8", newline="") as handle:
        fields = ["record_kind", "id", "path", "type", "algorithm", "key_bits", "line", "deployment_status", "risk", "pq_status", "recommendation", "excerpt"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in asset_rows:
            writer.writerow({"record_kind": "asset", "id": item["asset_id"], "path": item["path"], "type": item["asset_type"], "algorithm": item["algorithm"], "key_bits": item["key_bits"], "line": "", "deployment_status": item["deployment_status"], "risk": item["risk"], "pq_status": item["pq_status"], "recommendation": item["recommendation"], "excerpt": item.get("metadata", {}).get("evidence", "")})
        for item in evidence_rows:
            writer.writerow({"record_kind": "evidence", "id": item["evidence_id"], "path": item["path"], "type": item["evidence_type"], "algorithm": item["algorithm"], "key_bits": "", "line": item["line"], "deployment_status": item["deployment_status"], "risk": item["risk"], "pq_status": item["pq_status"], "recommendation": item["recommendation"], "excerpt": item["excerpt"]})
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
