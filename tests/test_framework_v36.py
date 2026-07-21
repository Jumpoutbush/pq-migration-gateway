from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from manager.api_client import ApiError, ManagerApiClient
from manager.config_store import ConfigStore
from manager.manager_api import ApiHandler
from manager.scan_orchestrator import ScanOrchestrator


ROOT = Path(__file__).resolve().parents[1]


class ApiFirstControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        allowed = root / "authorized"
        allowed.mkdir()
        self.store = ConfigStore(root / "control.db")
        self.scanner = ScanOrchestrator(self.store, root / "control", [allowed])
        ApiHandler.store = self.store
        ApiHandler.control_dir = root / "control"
        ApiHandler.token = "v36-token"
        ApiHandler.runtime_agent_token = ""
        ApiHandler.metrics_public = True
        ApiHandler.scanner = self.scanner
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = ManagerApiClient(self.base, "v36-token", "v36-test")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.scanner.close()
        self.temp.cleanup()

    def test_openapi_capabilities_onboard_release_status_and_rollback(self):
        with urllib.request.urlopen(self.base + "/openapi.json", timeout=3) as response:
            contract = json.loads(response.read())
        self.assertEqual(contract["info"]["version"], "3.7.0")
        self.assertIn("/v1/onboarding", contract["paths"])
        self.assertIn("ScanRequest", contract["components"]["schemas"])
        self.assertIn("RuntimeReport", contract["components"]["schemas"])
        self.assertIn("/v1/runtime/reports", contract["paths"])
        self.assertIn("/v1/policies/{policy_id}", contract["paths"])
        with self.assertRaises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(self.base + "/v1/capabilities", timeout=3)
        self.assertEqual(denied.exception.code, 401)

        capabilities = self.client.capabilities()
        self.assertIn("http", {item["name"] for item in capabilities["adapters"]})
        self.assertIn("PQC_PREFERRED", capabilities["migration_lifecycle"])
        created = self.client.onboard({
            "id": "payment-pqc",
            "adapter": "http",
            "listen": {"port": 28443, "server_name": "payment.company.local"},
            "upstream": {"address": "http://payment.internal:8080"},
        })
        self.assertEqual(created["status"], "STAGED")
        version = created["release"]["version"]
        self.assertEqual(self.store.get_resource("service", "payment-pqc")["spec"]["downstream_tls"]["mode"], "compatibility")
        releases = self.client.request("GET", "/v1/releases")
        self.assertEqual(releases["items"][0]["version"], version)
        status = self.client.status()
        self.assertEqual(status["counts"]["services"], 1)
        self.assertEqual(status["latest_release"]["status"], "STAGED")
        rollback = self.client.request("POST", f"/v1/releases/{version}/rollback")
        self.assertEqual(rollback["rollback_from"], version)
        audit = self.client.request("GET", "/v1/audit")
        self.assertTrue(audit["items"])

    def test_service_publish_rejects_path_identity_mismatch(self):
        with self.assertRaises(ApiError) as failed:
            self.client.request("POST", "/v1/services/expected/publish", {
                "id": "different", "adapter": "tcp",
                "listen": {"port": 29443, "server_name": "tcp.company.local"},
                "upstream": {"address": "127.0.0.1:9000"},
            })
        self.assertEqual(failed.exception.status, 400)


class ApiFirstArtifactTests(unittest.TestCase):
    def test_loopback_api_client_has_proxy_disabled(self):
        client = ManagerApiClient("http://127.0.0.1:18080", "test-token")
        self.assertTrue(client.proxy_disabled)
        remote = ManagerApiClient("https://manager.example.com", "test-token")
        self.assertFalse(remote.proxy_disabled)

    def test_runtime_cli_is_rest_only_and_dockerfile_has_no_undefined_ld_path(self):
        client = (ROOT / "manager/pqapi.py").read_text(encoding="utf-8")
        self.assertNotIn("ConfigStore", client)
        self.assertNotIn("control-plane.db", client)
        dockerfile = (ROOT / "docker/Dockerfile.gateway").read_text(encoding="utf-8")
        self.assertIn('LD_LIBRARY_PATH="/opt/openssl/lib"', dockerfile)
        self.assertNotIn('${LD_LIBRARY_PATH}', dockerfile)


if __name__ == "__main__":
    unittest.main()
