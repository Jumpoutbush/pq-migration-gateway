from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scanner.enterprise_inventory import inspect_file, scan_processes

ROOT = Path(__file__).resolve().parents[1]


class SourceInterfaceTests(unittest.TestCase):
    CASES = {
        "service.cpp": ("cpp", "SSL_CTX_new", "void f(){SSL_CTX_new(TLS_client_method());}"),
        "Service.java": ("java", "Cipher.getInstance", 'class S{void f()throws Exception{Cipher.getInstance("AES/GCM/NoPadding");}}'),
        "service.rs": ("rust", "rustls::ClientConfig::builder", "fn f(){rustls::ClientConfig::builder();}"),
        "service.go": ("go", "tls.Config", "package main\nfunc f(){ _ = tls.Config{} }"),
        "service.py": ("python", "ssl.SSLContext", "import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)"),
        "service.sh": ("shell", "openssl s_client", "#!/bin/sh\nopenssl s_client -connect host:443"),
    }

    def test_six_languages_report_interface_methods(self):
        with tempfile.TemporaryDirectory() as td:
            for name, (language, method, content) in self.CASES.items():
                path = Path(td) / name
                path.write_text(content, encoding="utf-8")
                artifact, signals, _ = inspect_file(path, 1_000_000, 4_000_000)
                self.assertIsNotNone(artifact, name)
                self.assertIn(language, artifact.languages)
                self.assertTrue(any(item["method"] == method for item in signals), name)
                self.assertTrue(all(item["confidence"] == "HIGH" for item in signals))


class ExecutableAndRuntimeTests(unittest.TestCase):
    def test_standalone_java_class_uses_magic_and_constants(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "CryptoService.class"
            path.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00=javax/net/ssl/SSLContext\x00javax/crypto/Cipher")
            artifact, signals, _ = inspect_file(path, 1_000_000, 4_000_000)
            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.artifact_type, "java_class")
            self.assertEqual(artifact.file_format, "JavaClass")
            self.assertTrue(any(item["method"] == "javax/net/ssl/SSLContext" for item in signals))

    def test_complete_experiment_matrix_and_no_target_execution(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "enterprise"
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/test_enterprise_scanner.py"), str(output)],
                check=True, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            matrix = json.loads((output / "enterprise-scanner-matrix.json").read_text(encoding="utf-8"))
            inventory = json.loads((output / "enterprise-crypto-inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(matrix["summary"], {"tests": 23, "passed": 23, "failed": 0})
            self.assertEqual(inventory["schema_version"], 4)
            self.assertEqual(inventory["scanner_version"], "3.7.0")
            self.assertGreaterEqual(inventory["summary"]["native_executables"], 3)
            self.assertEqual(inventory["summary"]["java_archives"], 1)
            self.assertEqual(inventory["summary"]["runtime_crypto_processes"], 1)
            self.assertIn("cpp_semantic_files", inventory["summary"])
            self.assertIn("cpp_semantic", inventory["scan_statistics"]["filesystem"])
            self.assertFalse((output / "fixtures/TARGET_WAS_EXECUTED").exists())
            self.assertEqual(inventory["findings"], inventory["assets"] + inventory["evidence"])
            risk_path = output / "risk.json"
            subprocess.run([sys.executable, str(ROOT / "manager/risk_engine.py"), "--static", str(output / "enterprise-crypto-inventory.json"), "--out", str(risk_path)], check=True, stdout=subprocess.PIPE)
            risk = json.loads(risk_path.read_text(encoding="utf-8"))
            self.assertTrue(any(row["category"] == "crypto_usage" for row in risk["findings"]))
            db_summary = output / "db-summary.json"
            subprocess.run([sys.executable, str(ROOT / "manager/inventory_db.py"), "--db", str(output / "inventory.db"), "--static", str(output / "enterprise-crypto-inventory.json"), "--summary-json", str(db_summary)], check=True, stdout=subprocess.PIPE)
            stored = json.loads(db_summary.read_text(encoding="utf-8"))
            self.assertGreaterEqual(stored["artifacts"], 1)
            self.assertEqual(stored["runtime_processes"], 1)

    def test_fake_proc_maps_are_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            process = Path(td) / "7"
            process.mkdir()
            (process / "maps").write_text("7f00-7f10 r-xp 0 00:00 1 /usr/lib/libssl.so.3\n", encoding="utf-8")
            (process / "cmdline").write_bytes(b"service\x00--token=secret-value\x00")
            try:
                os.symlink("/opt/service", process / "exe")
            except OSError:
                pass
            processes, evidence, stats = scan_processes(Path(td))
            self.assertEqual(stats["crypto_processes"], 1)
            self.assertEqual(processes[0].mapped_crypto_libraries, ["libssl.so.3"])
            self.assertEqual(processes[0].command, "")
            self.assertEqual(evidence[0]["source"], "proc_maps")
            processes, _, _ = scan_processes(Path(td), include_command_lines=True)
            self.assertIn("--token=<redacted>", processes[0].command)
            self.assertNotIn("secret-value", processes[0].command)


if __name__ == "__main__":
    unittest.main()
