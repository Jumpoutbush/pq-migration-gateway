#!/usr/bin/env python3
"""Enterprise cryptographic asset, source, executable and runtime scanner.

Schema v3 preserves the v2 assets/evidence/findings fields while adding
language-aware API discovery, bounded binary/JAR inspection and optional
runtime process linkage. Targets are never executed and private-key material is
never persisted.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.enterprise_inventory import (  # noqa: E402
    CONFIG_EXTENSIONS,
    DEFAULT_EXCLUDES,
    SOURCE_FILENAMES,
    SOURCE_LANGUAGES,
    artifact_dict,
    inspect_file,
    load_compile_commands,
    process_dict,
    scan_processes,
)
from scanner.ebpf_observer import evidence as ebpf_evidence, observe as observe_ebpf, parse_trace as parse_ebpf_trace  # noqa: E402

CERT_EXTS = {".crt", ".cer", ".pem"}
KEY_EXTS = {".key", ".pem"}
TEXT_EXTS = set(CONFIG_EXTENSIONS) | set(SOURCE_LANGUAGES)

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
    language: str = ""
    method: str = ""
    library: str = ""
    confidence: str = "MEDIUM"
    artifact_type: str = ""
    source: str = "generic_regex"
    artifact_id: str = ""
    metadata: dict = field(default_factory=dict)


def stable_id(prefix: str, *parts: object) -> str:
    blob = "\x1f".join(str(p) for p in parts)
    return f"{prefix}-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def run(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
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
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def scan_text(path: Path, max_bytes: int, artifact_id: str = "", max_evidence: int = 2_000) -> list[Evidence]:
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
                language=SOURCE_LANGUAGES.get(path.suffix.lower(), SOURCE_FILENAMES.get(path.name, "config")),
                confidence="MEDIUM", artifact_type="source_or_configuration",
                source="generic_algorithm_regex", artifact_id=artifact_id,
            ))
            if len(output) >= max_evidence:
                return output
    return output


def iter_files(roots: list[Path], excludes: set[str], max_files: int):
    seen: set[Path] = set()
    emitted = 0
    for root in roots:
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            def walk_files():
                for directory, names, files in os.walk(root, topdown=True, followlinks=False, onerror=lambda _error: None):
                    names[:] = [name for name in names if name not in excludes and not (Path(directory) / name).is_symlink()]
                    for name in files:
                        yield Path(directory) / name
            candidates = walk_files()
        else:
            continue
        for path in candidates:
            if path.is_symlink():
                continue
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved not in seen:
                seen.add(resolved)
                yield path
                emitted += 1
                if emitted >= max_files:
                    return


def discover_compile_databases(roots: list[Path], excludes: set[str], limit: int = 100) -> list[Path]:
    databases: list[Path] = []
    for root in roots:
        if root.is_file() and root.name == "compile_commands.json":
            databases.append(root)
            continue
        if not root.is_dir():
            continue
        for directory, names, files in os.walk(root, topdown=True, followlinks=False, onerror=lambda _error: None):
            names[:] = [name for name in names if name not in excludes and not (Path(directory) / name).is_symlink()]
            if "compile_commands.json" in files:
                databases.append(Path(directory) / "compile_commands.json")
                if len(databases) >= limit:
                    return databases
    return databases


def evidence_from_signal(path: Path, signal: dict, artifact_id: str = "") -> Evidence:
    algorithm = signal.get("algorithm", "unknown")
    excerpt = signal.get("excerpt", "")[:500]
    risk, status, recommendation = classify(algorithm, excerpt)
    source = signal.get("source", "source_parser")
    deployment = "runtime_observed" if source == "proc_maps" else "binary_reference" if signal.get("artifact_type") in {"native_executable", "binary_archive", "java_archive"} else "source_reference"
    evidence_path = Path(signal.get("path", path))
    line = int(signal.get("line", 0))
    return Evidence(
        evidence_id=stable_id("evidence", evidence_path, line, algorithm, signal.get("method", ""), source),
        path=str(evidence_path.resolve()), line=line,
        evidence_type=signal.get("evidence_type", "crypto_interface"), algorithm=algorithm,
        excerpt=excerpt, deployment_status=deployment, risk=risk, pq_status=status,
        recommendation=recommendation, language=signal.get("language", ""),
        method=signal.get("method", ""), library=signal.get("library", ""),
        confidence=signal.get("confidence", "MEDIUM"),
        artifact_type=signal.get("artifact_type", ""), source=source,
        artifact_id=artifact_id, metadata=signal.get("metadata", {}),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--max-text-bytes", type=positive_int, default=2_000_000)
    parser.add_argument("--max-binary-bytes", type=positive_int, default=64_000_000)
    parser.add_argument("--max-files", type=positive_int, default=100_000)
    parser.add_argument("--max-evidence-per-file", type=positive_int, default=2_000)
    parser.add_argument("--exclude", action="append", default=[], help="Directory name to exclude; may be repeated")
    parser.add_argument("--scan-processes", action="store_true", help="Inspect /proc process maps without executing targets")
    parser.add_argument("--proc-root", default="/proc", help="Alternate proc filesystem root for process inspection/tests")
    parser.add_argument("--max-processes", type=positive_int, default=20_000)
    parser.add_argument("--include-command-lines", action="store_true", help="Collect redacted process command lines; disabled by default")
    parser.add_argument("--compile-commands", action="append", default=[], help="Explicit compile_commands.json; may be repeated")
    parser.add_argument("--no-auto-compile-commands", action="store_true", help="Do not discover compile_commands.json below roots")
    parser.add_argument("--cpp-semantic", choices=("auto", "on", "off"), default="auto", help="Run bounded Clang AST analysis: auto requires compile_commands.json")
    parser.add_argument("--clang", default="clang++", help="Clang C++ executable used only with -fsyntax-only")
    parser.add_argument("--clang-timeout", type=positive_int, default=20, help="Maximum Clang analysis seconds per C++ file")
    parser.add_argument("--max-clang-ast-bytes", type=positive_int, default=32_000_000, help="Maximum JSON AST bytes per C++ file")
    parser.add_argument("--ebpf-trace-file", action="append", default=[], help="Import an authorized JSONL/TSV eBPF trace")
    parser.add_argument("--enable-ebpf", action="store_true", help="Run the fixed bpftrace uprobe collector (requires host privileges)")
    parser.add_argument("--ebpf-pid", type=int, default=0)
    parser.add_argument("--ebpf-library", default="")
    parser.add_argument("--ebpf-duration", type=positive_int, default=5)
    parser.add_argument("--bpftrace", default="bpftrace")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    args = parser.parse_args()

    roots = [Path(x) for x in args.root]
    assets: dict[str, Asset] = {}
    evidence: dict[str, Evidence] = {}
    artifacts: dict[str, dict] = {}
    scan_stats = {
        "files_seen": 0, "source_files_inspected": 0, "binary_files_inspected": 0, "files_skipped": 0,
        "cpp_semantic": {name: 0 for name in ("succeeded", "partial", "unavailable", "failed", "timeout", "bounded", "disabled")},
    }
    excludes = set(DEFAULT_EXCLUDES) | set(args.exclude)
    compile_paths = [Path(item) for item in args.compile_commands]
    if not args.no_auto_compile_commands:
        compile_paths.extend(discover_compile_databases(roots, excludes))
    compile_paths = list(dict.fromkeys(path.resolve() for path in compile_paths if path.is_file()))
    compile_contexts, compile_stats = load_compile_commands(compile_paths)
    scanner_implementation_files = {
        Path(__file__).resolve(),
        (PROJECT_ROOT / "scanner/enterprise_inventory.py").resolve(),
        (PROJECT_ROOT / "scripts/build_enterprise_scan_fixtures.py").resolve(),
        (PROJECT_ROOT / "scripts/test_enterprise_scanner.py").resolve(),
    }
    for path in iter_files(roots, excludes, args.max_files):
        scan_stats["files_seen"] += 1
        if path.resolve() in scanner_implementation_files:
            continue
        suffix = path.suffix.lower()
        if suffix in CERT_EXTS:
            cert = parse_certificate(path, args.openssl)
            if cert:
                assets[cert.asset_id] = cert
        if suffix in KEY_EXTS:
            key = identify_private_key(path, args.openssl)
            if key:
                assets[key.asset_id] = key
        artifact, signals, inspected = inspect_file(
            path, args.max_text_bytes, args.max_binary_bytes, args.max_evidence_per_file,
            cpp_compile_context=compile_contexts.get(str(path.resolve())),
            cpp_semantic_mode=args.cpp_semantic, clang_binary=args.clang,
            clang_timeout=args.clang_timeout, max_clang_ast_bytes=args.max_clang_ast_bytes,
        )
        if inspected.get("kind") == "source":
            scan_stats["source_files_inspected"] += 1
        elif inspected.get("kind") == "binary":
            scan_stats["binary_files_inspected"] += 1
        elif inspected.get("skipped"):
            scan_stats["files_skipped"] += 1
        semantic_status = inspected.get("cpp_semantic")
        if semantic_status in scan_stats["cpp_semantic"]:
            scan_stats["cpp_semantic"][semantic_status] += 1
        artifact_id = artifact.artifact_id if artifact else ""
        if artifact:
            artifacts[artifact.artifact_id] = artifact_dict(artifact)
        for signal in signals:
            item = evidence_from_signal(path, signal, artifact_id)
            evidence[item.evidence_id] = item
        if suffix in TEXT_EXTS or path.name in SOURCE_FILENAMES or (inspected.get("kind") == "source"):
            for item in scan_text(path, args.max_text_bytes, artifact_id, args.max_evidence_per_file):
                evidence[item.evidence_id] = item

    runtime_rows: list[dict] = []
    process_stats = {"inspected": 0, "denied": 0, "crypto_processes": 0}
    if args.scan_processes:
        processes, runtime_signals, process_stats = scan_processes(Path(args.proc_root), args.max_processes, args.include_command_lines)
        runtime_rows = [process_dict(item) for item in processes]
        for signal in runtime_signals:
            item = evidence_from_signal(Path(signal["path"]), signal)
            evidence[item.evidence_id] = item

    ebpf_events: list[dict] = []
    ebpf_collectors: list[dict] = []
    for trace_name in args.ebpf_trace_file:
        trace_path = Path(trace_name)
        events = parse_ebpf_trace(trace_path)
        ebpf_events.extend(events)
        ebpf_collectors.append({"mode": "import", "path": str(trace_path.resolve()), "events": len(events)})
        for signal in ebpf_evidence(events, str(trace_path.resolve())):
            item = evidence_from_signal(trace_path, signal)
            evidence[item.evidence_id] = item
    if args.enable_ebpf:
        if not args.ebpf_pid or not args.ebpf_library:
            parser.error("--enable-ebpf requires --ebpf-pid and --ebpf-library")
        events, metadata = observe_ebpf(args.ebpf_pid, Path(args.ebpf_library), args.ebpf_duration, args.bpftrace)
        ebpf_events.extend(events)
        ebpf_collectors.append({"mode": "live", **metadata})
        for signal in ebpf_evidence(events, args.ebpf_library):
            item = evidence_from_signal(Path(args.ebpf_library), signal)
            evidence[item.evidence_id] = item

    asset_rows = [asdict(x) for x in sorted(assets.values(), key=lambda x: (x.asset_type, x.path))]
    evidence_rows = [asdict(x) for x in sorted(evidence.values(), key=lambda x: (x.path, x.line, x.algorithm))]
    artifact_rows = sorted(artifacts.values(), key=lambda x: (x["artifact_type"], x["path"]))
    risks = [x["risk"] for x in asset_rows + evidence_rows]
    languages = [item["language"] for item in evidence_rows if item.get("language") and item["language"] != "config"]
    confidence = [item.get("confidence", "MEDIUM") for item in evidence_rows]
    payload = {
        "schema_version": 4,
        "scanner_version": "3.7.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roots": [str(p.resolve()) for p in roots],
        "summary": {
            "concrete_assets": len(asset_rows),
            "source_evidence": len(evidence_rows),
            "interface_evidence": sum(x["evidence_type"] != "text_crypto_reference" for x in evidence_rows),
            "configuration_references": sum(x["evidence_type"] == "text_crypto_reference" for x in evidence_rows),
            "crypto_relevant_artifacts": len(artifact_rows),
            "native_executables": sum(x["artifact_type"] == "native_executable" for x in artifact_rows),
            "java_archives": sum(x["artifact_type"] == "java_archive" for x in artifact_rows),
            "java_classes": sum(x["artifact_type"] == "java_class" for x in artifact_rows),
            "runtime_crypto_processes": len(runtime_rows),
            "runtime_crypto_api_observations": len(ebpf_events),
            "compile_database_entries": compile_stats["entries"],
            "cpp_semantic_files": scan_stats["cpp_semantic"]["succeeded"] + scan_stats["cpp_semantic"]["partial"],
            "cpp_semantic_failures": sum(scan_stats["cpp_semantic"][name] for name in ("failed", "timeout", "bounded")),
            "files_seen": scan_stats["files_seen"],
            "source_files_inspected": scan_stats["source_files_inspected"],
            "binary_files_inspected": scan_stats["binary_files_inspected"],
            "by_language": {name: languages.count(name) for name in sorted(set(languages))},
            "by_confidence": {name: confidence.count(name) for name in ["HIGH", "MEDIUM", "LOW"]},
            "by_risk": {name: risks.count(name) for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "quantum_vulnerable_assets": sum(x["pq_status"] == "quantum_vulnerable" for x in asset_rows),
            "pqc_assets_or_references": sum(x["pq_status"] == "pqc_or_pqc_candidate" for x in asset_rows + evidence_rows),
        },
        "assets": asset_rows,
        "evidence": evidence_rows,
        "artifacts": artifact_rows,
        "runtime_processes": runtime_rows,
        "scan_statistics": {
            "filesystem": scan_stats, "processes": process_stats,
            "compile_commands": {**compile_stats, "paths": [str(path) for path in compile_paths]},
            "ebpf": {"collectors": ebpf_collectors, "events": len(ebpf_events), "live_collection_enabled": args.enable_ebpf},
            "excluded_directory_names": sorted(excludes),
        },
        # Compatibility field for tools that consumed v1 findings.
        "findings": asset_rows + evidence_rows,
    }
    json_path = Path(args.out_json)
    csv_path = Path(args.out_csv)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        fields = ["record_kind", "id", "path", "type", "algorithm", "key_bits", "line", "deployment_status", "risk", "pq_status", "recommendation", "excerpt", "language", "method", "library", "confidence", "artifact_type", "source", "metadata"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in asset_rows:
            writer.writerow({"record_kind": "asset", "id": item["asset_id"], "path": item["path"], "type": item["asset_type"], "algorithm": item["algorithm"], "key_bits": item["key_bits"], "line": "", "deployment_status": item["deployment_status"], "risk": item["risk"], "pq_status": item["pq_status"], "recommendation": item["recommendation"], "excerpt": item.get("metadata", {}).get("evidence", ""), "metadata": json.dumps(item.get("metadata", {}), ensure_ascii=False)})
        for item in evidence_rows:
            writer.writerow({"record_kind": "evidence", "id": item["evidence_id"], "path": item["path"], "type": item["evidence_type"], "algorithm": item["algorithm"], "key_bits": "", "line": item["line"], "deployment_status": item["deployment_status"], "risk": item["risk"], "pq_status": item["pq_status"], "recommendation": item["recommendation"], "excerpt": item["excerpt"], "language": item["language"], "method": item["method"], "library": item["library"], "confidence": item["confidence"], "artifact_type": item["artifact_type"], "source": item["source"], "metadata": json.dumps(item.get("metadata", {}), ensure_ascii=False)})
        for item in artifact_rows:
            writer.writerow({"record_kind": "artifact", "id": item["artifact_id"], "path": item["path"], "type": item["file_format"], "algorithm": "", "key_bits": "", "line": "", "deployment_status": "present", "risk": "", "pq_status": "", "recommendation": "", "excerpt": ";".join(item.get("dependencies", [])), "language": ";".join(item.get("languages", [])), "method": ";".join(item.get("imported_symbols", []) + item.get("demangled_symbols", [])), "library": "", "confidence": item["confidence"], "artifact_type": item["artifact_type"], "source": "artifact_inspection", "metadata": json.dumps(item.get("metadata", {}), ensure_ascii=False)})
        for item in runtime_rows:
            writer.writerow({"record_kind": "runtime_process", "id": item["process_id"], "path": item["executable"], "type": "process", "algorithm": "runtime-selected", "key_bits": "", "line": "", "deployment_status": "runtime_observed", "risk": "INFO", "pq_status": "unknown", "recommendation": "Correlate the mapped library with application ownership and runtime TLS observations.", "excerpt": item["command"], "language": "runtime", "method": ";".join(item["mapped_crypto_libraries"]), "library": ";".join(item["mapped_crypto_libraries"]), "confidence": item["confidence"], "artifact_type": "runtime_process", "source": "proc_maps", "metadata": json.dumps(item.get("metadata", {}), ensure_ascii=False)})
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
