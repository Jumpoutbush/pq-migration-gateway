from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from gateway.model import normalize_config
from manager.config_store import ConfigStore
from manager.enterprise import build_service, initialize, load_env, redacted_status, upsert_service


ROOT = Path(__file__).resolve().parents[1]


class EnterpriseOnboardingTests(unittest.TestCase):
    def test_init_is_secure_idempotent_and_generates_valid_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "company-apps"
            scan.mkdir()
            first = initialize(root, scan, server_name="pilot.company.local", port=28443)
            env_path = Path(first["environment"])
            config_path = Path(first["config"])
            values = load_env(env_path)
            self.assertEqual(values["PQ_SCAN_HOST_ROOT"], str(scan.resolve()))
            self.assertEqual(values["PQ_GATEWAY_IMAGE"], "pq-migration-gateway-pq-gateway:3.7")
            self.assertEqual(values["PQ_MANAGER_API_BIND"], "127.0.0.1")
            self.assertEqual(values["PQ_MANAGER_API_URL"], "http://127.0.0.1:18080")
            self.assertGreaterEqual(len(values["MANAGER_API_TOKEN"]), 64)
            self.assertGreaterEqual(len(values["RUNTIME_AGENT_TOKEN"]), 64)
            self.assertEqual(os.stat(env_path).st_mode & 0o777, 0o600)
            token = values["MANAGER_API_TOKEN"]
            runtime_token = values["RUNTIME_AGENT_TOKEN"]
            initialize(root, scan)
            self.assertEqual(load_env(env_path)["MANAGER_API_TOKEN"], token)
            self.assertEqual(load_env(env_path)["RUNTIME_AGENT_TOKEN"], runtime_token)
            canonical = normalize_config(json.loads(config_path.read_text(encoding="utf-8")))
            self.assertEqual(canonical["services"][0]["listen"]["port"], 28443)

    def test_real_service_replaces_pilot_and_status_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "apps"
            scan.mkdir()
            initialized = initialize(root, scan)
            service = build_service(
                service_id="payment-pqc", adapter="http", listen_port=18443,
                server_name="payment.company.local", upstream="https://payment.internal:9443",
                upstream_sni="payment.internal",
            )
            result = upsert_service(initialized["config"], service)
            self.assertEqual(result["services"], 1)
            document = json.loads(Path(initialized["config"]).read_text(encoding="utf-8"))
            self.assertEqual(document["services"][0]["id"], "payment-pqc")
            self.assertTrue(document["services"][0]["upstream"]["tls"]["enabled"])
            status = redacted_status(root)
            self.assertNotIn("MANAGER_API_TOKEN", json.dumps(status))


class EnterpriseMetricTests(unittest.TestCase):
    def test_metrics_include_scans_assets_and_migration_state(self):
        with tempfile.TemporaryDirectory() as td:
            store = ConfigStore(Path(td) / "control.db")
            store.create_scan_job("scan-1", "enterprise", {"roots": ["/app"]}, "test")
            store.ingest_scan_inventory("scan-1", {
                "assets": [{
                    "asset_id": "asset-1", "asset_type": "private_key", "path": "/app/key.pem",
                    "algorithm": "RSA", "risk": "HIGH", "pq_status": "quantum_vulnerable",
                }],
                "artifacts": [], "findings": [], "summary": {},
            }, "test")
            store.upsert_migration_plan("plan-1", "asset-1", "payment-pqc", "COMPATIBILITY_STAGED", {}, "test")
            with store.connect() as conn:
                conn.execute(
                    "INSERT INTO service_states(service_id,state,config_version,updated_at,operator,reason) VALUES(?,?,?,?,?,?)",
                    ("payment-pqc", "COMPATIBILITY", None, "2026-01-01T00:00:00Z", "test", "pilot"),
                )
            text = store.prometheus_text()
            self.assertIn('gateway_crypto_assets{pq_status="quantum_vulnerable",risk="HIGH"} 1', text)
            self.assertIn('gateway_scan_jobs{status="SUCCEEDED"} 1', text)
            self.assertIn('gateway_migration_plans{status="COMPATIBILITY_STAGED"} 1', text)
            self.assertIn('gateway_migration_services{state="COMPATIBILITY"} 1', text)


class EnterpriseDeploymentArtifactTests(unittest.TestCase):
    def test_enterprise_compose_has_no_demo_backends_and_dashboard_is_valid(self):
        compose = (ROOT / "deploy/enterprise/docker-compose.yml").read_text(encoding="utf-8")
        for demo in ("bank-backend", "secure-backend", "tcp-backend", "mqtt-broker"):
            self.assertNotIn(demo, compose)
        self.assertIn("network_mode: host", compose)
        self.assertIn('profiles: ["observability"]', compose)
        dashboard = json.loads((ROOT / "deploy/enterprise/grafana/dashboards/pq-gateway-overview.json").read_text(encoding="utf-8"))
        self.assertEqual(dashboard["uid"], "pqc-enterprise-overview")
        titles = {panel["title"] for panel in dashboard["panels"]}
        self.assertTrue({"Crypto assets", "Negotiated TLS groups", "Migration plans", "TLS failure counters"} <= titles)

    def test_enterprise_initializer_is_executable_and_make_targets_exist(self):
        script = ROOT / "scripts/init_enterprise.sh"
        self.assertTrue(os.access(script, os.X_OK))
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for target in ("enterprise-init:", "enterprise-up:", "dashboard-up:", "enterprise-logs:"):
            self.assertIn(target, makefile)


if __name__ == "__main__":
    unittest.main()
