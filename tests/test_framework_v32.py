from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from gateway.agent import GatewayAgent
from manager.config_store import ConfigStore
from manager.control_plane import stage_document, stage_resources
from manager.manager_api import ApiHandler
from manager.runtime_metrics import prom

ROOT = Path(__file__).resolve().parents[1]


def document() -> dict:
    return json.loads((ROOT / "config/services.json").read_text(encoding="utf-8"))


class ReleaseLifecycleTests(unittest.TestCase):
    def test_release_records_explicit_lifecycle_and_resources(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = ConfigStore(root / "control.db")
            manifest = stage_document(store, root / "control", document(), "tester")
            release = store.get_version(manifest["version"], include_rendered=False)
            self.assertEqual(release["status"], "STAGED")
            self.assertEqual([row["to_status"] for row in release["status_history"]], ["DRAFT", "VALIDATED", "STAGED"])
            self.assertEqual(len(store.list_resources("service")), 10)
            self.assertEqual(len(store.list_resources("policy")), 10)
            store.upsert_resource("policy", "compatibility-gateway", {
                "service_id": "compatibility-gateway",
                "rollout": {"policy": "fixed", "hybrid_percentage": 100, "fallback_allowed": False},
                "downstream_tls": {"mode": "strict", "groups": ["X25519MLKEM768"]},
            }, "tester")
            republished = stage_resources(store, root / "control", "tester")
            self.assertGreater(republished["version"], manifest["version"])
            source = store.get_version(republished["version"], include_rendered=False)["source"]
            changed = next(service for service in source["services"] if service["id"] == "compatibility-gateway")
            self.assertEqual(changed["downstream_tls"]["mode"], "strict")

    def test_invalid_submission_is_retained_as_validation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = ConfigStore(root / "control.db")
            bad = document()
            bad["services"][1]["listen"]["port"] = bad["services"][0]["listen"]["port"]
            with self.assertRaises(ValueError):
                stage_document(store, root / "control", bad, "tester")
            self.assertEqual(store.list_versions()[0]["status"], "VALIDATION_FAILED")


class InitializationTests(unittest.TestCase):
    def test_init_script_is_executable_and_wired_to_make(self):
        script = ROOT / "scripts/init_system.sh"
        root_entry = ROOT / "init_system.sh"
        self.assertTrue(os.access(script, os.X_OK))
        self.assertTrue(os.access(root_entry, os.X_OK))
        subprocess.run(["bash", "-n", str(script)], check=True)
        subprocess.run(["bash", "-n", str(root_entry)], check=True)
        help_result = subprocess.run([str(root_entry), "--help"], check=True, text=True, stdout=subprocess.PIPE)
        self.assertIn("--prepare-only", help_result.stdout)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("init:\n\t./init_system.sh $(INIT_ARGS)", makefile)


class AgentAndMetricTests(unittest.TestCase):
    def test_agent_heartbeat_and_control_plane_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake = root / "nginx"
            fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake, 0o755)
            store = ConfigStore(root / "control.db")
            release = stage_document(store, root / "control", document(), "tester")
            active = root / "active.conf"
            active.write_text("previous", encoding="utf-8")
            result = GatewayAgent(root / "control", active, str(fake), root / "control.db", agent_id="gateway-a").apply(release["version"])
            self.assertEqual(result["status"], "HEALTHY")
            self.assertEqual(store.get_agent("gateway-a")["current_version"], release["version"])
            text = store.prometheus_text()
            self.assertIn("gateway_config_reload_total", text)
            self.assertIn("gateway_agent_heartbeat_timestamp_seconds", text)
            self.assertIn('status="HEALTHY"', text)

    def test_runtime_prometheus_names_are_framework_stable(self):
        payload = {
            "services": {"svc": {"hybrid_pqc": 2, "classical_fallback": 1, "unknown": 0, "hybrid_adoption_rate": 0.6667}},
            "tls_groups": {"svc": {"X25519MLKEM768": 2, "X25519": 1}},
            "durations": {"svc": {"sum": 1.5, "count": 3}},
        }
        text = prom(payload)
        self.assertIn("gateway_tls_handshakes_total", text)
        self.assertIn("gateway_tls_group_total", text)
        self.assertIn("gateway_classical_fallback_total", text)
        self.assertIn("gateway_connection_duration_seconds_sum", text)


class ManagerApiTests(unittest.TestCase):
    def request(self, method: str, path: str, payload: dict | None = None, authenticated: bool = True):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json", "X-PQ-Operator": "api-test"}
        if authenticated:
            headers["Authorization"] = "Bearer test-token"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=3) as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read().decode()
            return response.status, body if path == "/metrics" else json.loads(body), content_type

    def test_resource_crud_agent_heartbeat_and_metrics_endpoint(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ApiHandler.store = ConfigStore(root / "control.db")
            ApiHandler.control_dir = root / "control"
            ApiHandler.token = "test-token"
            ApiHandler.metrics_public = True
            server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
            self.base = f"http://127.0.0.1:{server.server_address[1]}"
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    self.request("GET", "/v1/services", authenticated=False)
                self.assertEqual(denied.exception.code, 401)
                service = document()["services"][0]
                status, created, _ = self.request("POST", "/v1/services", service)
                self.assertEqual(status, 201)
                self.assertEqual(created["id"], service["id"])
                status, listing, _ = self.request("GET", "/v1/services")
                self.assertEqual(len(listing["items"]), 1)
                status, agent, _ = self.request("POST", "/v1/agents/gateway-a/heartbeat", {"status": "HEALTHY", "health": "healthy", "current_version": 1, "desired_version": 1})
                self.assertEqual(agent["agent_id"], "gateway-a")
                status, metrics, content_type = self.request("GET", "/metrics", authenticated=False)
                self.assertEqual(status, 200)
                self.assertIn("gateway_agent_heartbeat_timestamp_seconds", metrics)
                self.assertIn("version=0.0.4", content_type)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
