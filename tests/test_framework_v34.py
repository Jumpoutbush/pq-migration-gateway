from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from manager.config_store import ConfigStore
from manager.manager_api import ApiHandler
from manager.scan_orchestrator import ScanOrchestrator
from gateway.adapters.base import upstream_tls_lines
from scanner.ebpf_observer import evidence as ebpf_evidence, parse_trace
from scanner.enterprise_inventory import inspect_file, load_compile_commands


class AdvancedCppScannerTests(unittest.TestCase):
    def test_compile_database_macro_expansion_and_call_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "service.cpp"
            source.write_text(
                "#define MAKE_CTX(method) SSL_CTX_new(method)\n"
                "void *crypto(){ return MAKE_CTX(TLS_client_method()); }\n"
                "void *wrapper(){ return crypto(); }\n",
                encoding="utf-8",
            )
            database = root / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": "service.cpp",
                "arguments": ["g++", "-std=c++20", "-DUSE_OPENSSL=1", "-Iinclude", "-c", "service.cpp"],
            }]), encoding="utf-8")
            contexts, stats = load_compile_commands([database])
            artifact, signals, _ = inspect_file(
                source, 1_000_000, 4_000_000,
                cpp_compile_context=contexts[str(source.resolve())],
            )
            self.assertIsNotNone(artifact)
            self.assertEqual(stats["entries"], 1)
            self.assertEqual(artifact.metadata["compile_commands"]["standard"], "c++20")
            self.assertFalse(artifact.metadata["compile_commands"]["command_executed"])
            self.assertTrue(any(item["source"] == "cpp_macro_expansion" and item["method"] == "SSL_CTX_new" for item in signals))
            self.assertTrue(any(edge["caller"] == "wrapper" and edge["callee"] == "crypto" for edge in artifact.metadata["call_graph"]))
            self.assertTrue(any(item["source"] == "cpp_call_graph" for item in signals))

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("g++", "ar", "nm", "c++filt")), "native toolchain unavailable")
    def test_static_archive_symbols_are_demangled(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "crypto.cpp"
            source.write_text(
                "namespace CryptoPP { struct RSA { void Encrypt(); }; void RSA::Encrypt(){} }\n"
                "extern \"C\" void SSL_CTX_new(); void use_ssl(){ SSL_CTX_new(); }\n",
                encoding="utf-8",
            )
            obj = root / "crypto.o"
            archive = root / "libcrypto_fixture.a"
            subprocess.run(["g++", "-c", str(source), "-o", str(obj)], check=True)
            subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True)
            artifact, signals, _ = inspect_file(archive, 1_000_000, 8_000_000)
            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.file_format, "static_archive")
            self.assertIn("nm-archive", artifact.metadata["inspection"])
            self.assertTrue(any("CryptoPP::RSA::Encrypt" in item for item in artifact.demangled_symbols), artifact.__dict__)
            self.assertTrue(any(item["source"] == "symbol_table" for item in signals))

    def test_imported_ebpf_trace_is_high_confidence_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            trace = Path(td) / "trace.jsonl"
            trace.write_text(json.dumps({
                "pid": 42, "comm": "cpp-service", "method": "EVP_PKEY_encrypt", "library": "/usr/lib/libcrypto.so.3",
            }) + "\n", encoding="utf-8")
            events = parse_trace(trace)
            rows = ebpf_evidence(events, str(trace))
            self.assertEqual(rows[0]["source"], "ebpf_uprobe")
            self.assertEqual(rows[0]["confidence"], "HIGH")
            self.assertTrue(rows[0]["metadata"]["observed_call"])


class UpstreamTlsIsolationTests(unittest.TestCase):
    def test_enabled_upstream_tls_disables_session_reuse(self):
        service = {
            "upstream": {
                "tls": {
                    "enabled": True,
                    "sni": "upstream.internal",
                    "verify": "required",
                    "ca": "/run/ca.pem",
                    "client_identity": {
                        "certificate": "",
                        "private_key": {"reference": ""},
                    },
                },
            },
        }
        self.assertIn("        proxy_ssl_session_reuse off;", upstream_tls_lines(service))


class ScanMigrationApiTests(unittest.TestCase):
    def request(self, method: str, path: str, payload: dict | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Authorization": "Bearer test-token", "X-PQ-Operator": "v34-test", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())

    def test_scan_asset_assess_compatibility_and_strict_api_loop(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_root = root / "authorized"
            source_root.mkdir()
            source = source_root / "payment.cpp"
            source.write_text(
                "#include <openssl/ssl.h>\n"
                "void migrate(){ SSL_CTX_new(TLS_client_method()); RSA_public_encrypt(0,nullptr,nullptr,nullptr,0); }\n",
                encoding="utf-8",
            )
            compile_commands = source_root / "compile_commands.json"
            compile_commands.write_text(json.dumps([{
                "directory": str(source_root), "file": "payment.cpp",
                "arguments": ["g++", "-std=c++20", "-c", "payment.cpp"],
            }]), encoding="utf-8")
            store = ConfigStore(root / "control.db")
            scanner = ScanOrchestrator(store, root / "control", [source_root])
            ApiHandler.store = store
            ApiHandler.control_dir = root / "control"
            ApiHandler.token = "test-token"
            ApiHandler.metrics_public = True
            ApiHandler.scanner = scanner
            server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
            self.base = f"http://127.0.0.1:{server.server_address[1]}"
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                status, job = self.request("POST", "/v1/scans", {
                    "type": "enterprise", "roots": [str(source_root)],
                    "compile_commands": [str(compile_commands)],
                })
                self.assertEqual(status, 202)
                for _ in range(100):
                    _, job = self.request("GET", f"/v1/scans/{job['scan_id']}")
                    if job["status"] in {"SUCCEEDED", "FAILED"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(job["status"], "SUCCEEDED", job.get("error"))
                _, findings = self.request("GET", f"/v1/scans/{job['scan_id']}/findings")
                self.assertTrue(any(item.get("language") == "cpp" and "RSA" in item.get("method", "") for item in findings["items"]))
                _, listing = self.request("GET", "/v1/assets")
                asset = next(item for item in listing["items"] if item["path"].endswith("payment.cpp"))
                _, detail = self.request("GET", f"/v1/assets/{asset['asset_id']}")
                self.assertTrue(detail["evidence"])
                status, assessment = self.request("POST", f"/v1/assets/{asset['asset_id']}/assess", {})
                self.assertEqual(status, 201)
                self.assertEqual(assessment["result"]["decision"], "MIGRATION_REQUIRED")
                status, plan = self.request("POST", f"/v1/assets/{asset['asset_id']}/migration", {
                    "action": "create",
                    "service": {
                        "id": "payment-pqc-gateway", "adapter": "http",
                        "listen": {"address": "0.0.0.0", "port": 28443, "server_name": "payment-gateway.local"},
                        "upstream": {"address": "http://payment.internal:8080"},
                    },
                })
                self.assertEqual(status, 202)
                self.assertEqual(plan["status"], "COMPATIBILITY_STAGED")
                store.set_status(plan["compatibility_version"], "APPLIED", "test-agent")
                store.set_status(plan["compatibility_version"], "HEALTHY", "test-agent")
                _, strict = self.request("POST", f"/v1/assets/{asset['asset_id']}/migration", {
                    "action": "verify", "plan_id": plan["plan_id"], "passed": True,
                    "verification_result": "hybrid clients passed; no classical fallback observed", "fallback_rate": 0.0,
                })
                self.assertEqual(strict["status"], "STRICT_STAGED")
                service = store.get_resource("service", "payment-pqc-gateway")["spec"]
                self.assertEqual(service["downstream_tls"]["groups"], ["X25519MLKEM768"])
                self.assertFalse(service["rollout"]["fallback_allowed"])
                store.set_status(strict["strict_version"], "APPLIED", "test-agent")
                store.set_status(strict["strict_version"], "HEALTHY", "test-agent")
                _, completed = self.request("POST", f"/v1/assets/{asset['asset_id']}/migration", {
                    "action": "complete", "plan_id": plan["plan_id"], "verification_result": "strict endpoint healthy",
                })
                self.assertEqual(completed["status"], "VERIFIED")
                self.assertEqual(store.get_resource("service", "payment-pqc-gateway")["spec"]["downstream_tls"]["mode"], "strict")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                scanner.close()


if __name__ == "__main__":
    unittest.main()
