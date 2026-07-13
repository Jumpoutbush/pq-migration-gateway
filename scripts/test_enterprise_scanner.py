#!/usr/bin/env python3
"""Run the v3.3 enterprise crypto discovery experiment matrix."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from build_enterprise_scan_fixtures import build

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    fixtures = output / "fixtures"
    manifest = build(fixtures)
    inventory_json = output / "enterprise-crypto-inventory.json"
    inventory_csv = output / "enterprise-crypto-inventory.csv"
    subprocess.run([
        sys.executable, str(ROOT / "scripts/crypto_inventory.py"),
        "--root", manifest["source_root"], "--root", manifest["binary_root"],
        "--scan-processes", "--proc-root", manifest["proc_root"],
        "--out-json", str(inventory_json), "--out-csv", str(inventory_csv),
    ], check=True)
    inventory = json.loads(inventory_json.read_text(encoding="utf-8"))
    evidence = inventory["evidence"]

    def has(**expected: str) -> bool:
        return any(all(str(row.get(key, "")) == value for key, value in expected.items()) for row in evidence)

    tests = [
        ("cpp_source_openssl", has(language="cpp", method="SSL_CTX_new", source="source_parser")),
        ("java_source_jca", has(language="java", method="Cipher.getInstance", source="source_parser")),
        ("rust_source_rustls", has(language="rust", method="rustls::ClientConfig::builder", source="source_parser")),
        ("go_source_tls", has(language="go", method="tls.Config", source="source_parser")),
        ("python_source_ssl", has(language="python", method="ssl.SSLContext", source="source_parser")),
        ("shell_source_openssl", has(language="shell", method="openssl s_client", source="source_parser")),
        ("native_elf_openssl", any(row["method"].startswith("SSL_CTX_") and row["artifact_type"] == "native_executable" for row in evidence)),
        ("java_jar_jsse", has(language="java", method="javax/net/ssl/SSLContext", source="class_constants")),
        ("go_binary_interface", any(Path(row["path"]).name == "go-service" and row["language"] == "go" and row["method"].startswith("crypto/tls") for row in evidence)),
        ("rust_binary_interface", any(Path(row["path"]).name == "rust-service" and row["language"] == "rust" and row["method"].startswith(("rustls::", "ring::")) for row in evidence)),
        ("extensionless_python", any(Path(row["path"]).name == "python-service" and row["language"] == "python" for row in evidence)),
        ("extensionless_shell", any(Path(row["path"]).name == "shell-service" and row["language"] == "shell" for row in evidence)),
        ("runtime_proc_maps", any(row["source"] == "proc_maps" and row["method"] == "libssl.so.3" for row in evidence)),
        ("target_never_executed", not Path(manifest["execution_marker"]).exists()),
        ("json_and_csv_outputs", inventory_json.stat().st_size > 0 and inventory_csv.stat().st_size > 0),
    ]
    rows = [{"test": name, "status": "PASS" if passed else "FAIL"} for name, passed in tests]
    summary = {"tests": len(rows), "passed": sum(row["status"] == "PASS" for row in rows), "failed": sum(row["status"] == "FAIL" for row in rows)}
    payload = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "fixture_mode": manifest["native_fixture_mode"],
        "fixture_modes": {
            "cpp": manifest["native_fixture_mode"],
            "go": manifest["go_fixture_mode"],
            "rust": manifest["rust_fixture_mode"],
            "java": manifest["java_fixture_mode"],
        },
        "results": rows,
    }
    (output / "enterprise-scanner-matrix.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
