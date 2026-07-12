from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from gateway.adapters import default_registry
from gateway.agent import ApplyError, GatewayAgent
from gateway.model import ConfigError, normalize_config
from manager.config_store import ConfigStore
from manager.control_plane import stage_document, stage_rollback, validate_document
from manager.policy_engine import deployment_plan
from manager.state_machine import MigrationStateMachine, TransitionError

ROOT = Path(__file__).resolve().parents[1]


class ModelAndAdapterTests(unittest.TestCase):
    def test_default_config_is_canonical_and_all_adapters_resolve(self):
        config = json.loads((ROOT / "config/services.json").read_text())
        canonical = normalize_config(config)
        registry = default_registry()
        self.assertEqual(canonical["schema_version"], "4.0")
        self.assertEqual(len(canonical["services"]), 10)
        for service in canonical["services"]:
            registry.get(service["adapter"]).validate(service)

    def test_legacy_v3_is_still_supported(self):
        legacy = {
            "version": 3,
            "defaults": {"certificate": "/c", "certificate_key": "/k", "client_ca": "/ca", "upstream_ca": "/uca"},
            "services": [{"name": "old", "protocol": "http", "listen_port": 443, "server_name": "old.local", "upstream_url": "http://backend:80", "tls_groups": "X25519MLKEM768:X25519", "client_auth": "off", "upstream_tls_verify": "off"}],
        }
        service = normalize_config(legacy)["services"][0]
        self.assertEqual(service["id"], "old")
        self.assertEqual(service["adapter"], "http")

    def test_percentage_plan_does_not_claim_http_path_tls_routing(self):
        service = normalize_config(json.loads((ROOT / "config/services.json").read_text()))["services"][0]
        service["rollout"].update({"policy": "percentage", "hybrid_percentage": 80})
        plan = deployment_plan(service)
        self.assertEqual(plan["strategy"], "separate-listener-or-instance")

    def test_fallback_policy_conflict_is_rejected(self):
        config = json.loads((ROOT / "config/services.json").read_text())
        config["services"][0]["rollout"]["fallback_allowed"] = False
        with self.assertRaises(ConfigError):
            normalize_config(config)


class StoreAndStateTests(unittest.TestCase):
    def test_version_history_and_rollback_create_immutable_new_version(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = ConfigStore(root / "control.db")
            document = json.loads((ROOT / "config/services.json").read_text())
            first = stage_document(store, root / "control", document, "tester")
            second = stage_rollback(store, root / "control", first["version"], "tester")
            self.assertNotEqual(first["version"], second["version"])
            self.assertEqual(second["rollback_from"], first["version"])
            self.assertEqual(store.get_version(second["version"])["status"], "STAGED")
            desired = json.loads((root / "control" / "desired.json").read_text())
            self.assertEqual(desired["version"], second["version"])

    def test_state_machine_guards_transitions_and_verification(self):
        with tempfile.TemporaryDirectory() as td:
            machine = MigrationStateMachine(ConfigStore(Path(td) / "control.db"))
            with self.assertRaises(TransitionError):
                machine.transition("svc", "STRICT", operator="tester", reason="skip")
            for state in ("DISCOVERED", "ASSESSED", "PLANNED", "COMPATIBILITY", "PQC_PREFERRED", "STRICT"):
                machine.transition("svc", state, operator="tester", reason="test")
            with self.assertRaises(TransitionError):
                machine.transition("svc", "VERIFIED", operator="tester", reason="missing proof")
            result = machine.transition("svc", "VERIFIED", operator="tester", reason="matrix passed", verification_result="PASS", fallback_rate=0.0)
            self.assertEqual(result["state"], "VERIFIED")
            self.assertEqual(len(machine.history("svc")), 7)


class AgentTests(unittest.TestCase):
    def test_agent_rejects_wrong_release_signature(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake = root / "nginx"
            fake.write_text("#!/bin/sh\nexit 0\n")
            os.chmod(fake, 0o755)
            db = root / "control.db"
            control = root / "control"
            document = json.loads((ROOT / "config/services.json").read_text())
            release = stage_document(ConfigStore(db), control, document, "tester", signing_key="correct")
            with self.assertRaises(ApplyError):
                GatewayAgent(control, root / "active.conf", str(fake), db, signing_key="wrong").apply(release["version"])

    def test_agent_applies_and_rolls_back_after_failed_health(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake = root / "nginx"
            fake.write_text("#!/bin/sh\nexit 0\n")
            os.chmod(fake, 0o755)
            db = root / "control.db"
            control = root / "control"
            active = root / "active.conf"
            active.write_text("previous")
            store = ConfigStore(db)
            document = json.loads((ROOT / "config/services.json").read_text())
            release = stage_document(store, control, document, "tester")
            applied = GatewayAgent(control, active, str(fake), db).apply(release["version"])
            self.assertEqual(applied["status"], "HEALTHY")
            stable = active.read_text()
            second = stage_document(store, control, document, "tester")
            with self.assertRaises(ApplyError):
                GatewayAgent(control, active, str(fake), db, "exit 1").apply(second["version"])
            self.assertEqual(active.read_text(), stable)
            self.assertEqual(store.get_version(second["version"])["status"], "ROLLED_BACK")


if __name__ == "__main__":
    unittest.main()
