from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RendererTests(unittest.TestCase):
    def test_default_config_renders_two_services(self):
        renderer = load_module("renderer", ROOT / "scripts" / "render_gateway_config.py")
        config = json.loads((ROOT / "config" / "services.json").read_text())
        text = renderer.render(config)
        self.assertIn("listen 8443 ssl;", text)
        self.assertIn("listen 9443 ssl;", text)
        self.assertIn("X25519MLKEM768:X25519", text)
        self.assertIn("strict-pqc-gateway", text)

    def test_renderer_rejects_injection(self):
        renderer = load_module("renderer_bad", ROOT / "scripts" / "render_gateway_config.py")
        config = json.loads((ROOT / "config" / "services.json").read_text())
        config["services"][0]["server_name"] = "bad; include /tmp/x"
        with self.assertRaises(renderer.ConfigError):
            renderer.render(config)


class ManagerTests(unittest.TestCase):
    def test_fallback_report(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            log = td / "access.log"
            log.write_text(
                '\n'.join([
                    json.dumps({"service": "a", "ssl_curve": "X25519MLKEM768"}),
                    json.dumps({"service": "a", "ssl_curve": "X25519"}),
                ]) + '\n'
            )
            out = td / "report.json"
            subprocess.run([sys.executable, str(ROOT / "manager" / "fallback_report.py"), "--log", str(log), "--out", str(out)], check=True, stdout=subprocess.PIPE)
            report = json.loads(out.read_text())
            self.assertEqual(report["summary"]["hybrid_pqc"], 1)
            self.assertEqual(report["summary"]["classical_fallback"], 1)

    def test_migration_verification(self):
        tls = {
            "endpoints": [
                {"sni": "bank-gateway.local", "port": 8443, "supported_groups": ["X25519MLKEM768", "X25519"]},
                {"sni": "strict-gateway.local", "port": 9443, "supported_groups": ["X25519MLKEM768"]},
            ]
        }
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            tls_path = td / "tls.json"
            out = td / "verify.json"
            tls_path.write_text(json.dumps(tls))
            subprocess.run([
                sys.executable, str(ROOT / "manager" / "verify_migration.py"),
                "--services", str(ROOT / "config" / "services.json"),
                "--tls", str(tls_path), "--out", str(out),
            ], check=True, stdout=subprocess.PIPE)
            report = json.loads(out.read_text())
            self.assertEqual(report["summary"]["failed"], 0)


if __name__ == "__main__":
    unittest.main()
