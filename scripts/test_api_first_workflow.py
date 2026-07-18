#!/usr/bin/env python3
"""Run the deterministic v3.6 API-first customer workflow matrix."""
from __future__ import annotations

import argparse
import json
import tempfile
import threading
import time
import urllib.request
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.api_client import ManagerApiClient
from manager.config_store import ConfigStore
from manager.manager_api import ApiHandler
from manager.scan_orchestrator import ScanOrchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", nargs="?", default="experiment-results/manual-api-first")
    args = parser.parse_args()
    urllib.request.install_opener(
        urllib.request.build_opener(
            urllib.request.ProxyHandler({})
        )
    )
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    def check(name: str, condition: bool, detail: object = None) -> None:
        rows.append({"test": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    with tempfile.TemporaryDirectory(prefix="pq-api-first-") as td:
        root = Path(td)
        source_root = root / "authorized"
        source_root.mkdir()
        source = source_root / "payment.cpp"
        source.write_text(
            "#include <openssl/ssl.h>\nvoid crypto(){SSL_CTX_new(TLS_client_method());RSA_public_encrypt(0,0,0,0,0);}\n",
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
        ApiHandler.token = "api-first-token"
        ApiHandler.metrics_public = True
        ApiHandler.scanner = scanner
        server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = ManagerApiClient(base, "api-first-token", "api-first-experiment")
        try:
            with urllib.request.urlopen(base + "/openapi.json", timeout=5) as response:
                contract = json.loads(response.read())
            check("openapi_contract", contract["info"]["version"] == "3.6.0")
            capabilities = client.capabilities()
            check("capability_discovery", "http" in {item["name"] for item in capabilities["adapters"]}, capabilities["authorized_scan_roots"])
            initial = client.status()
            check("initial_system_status", initial["counts"]["services"] == 0, initial["counts"])
            onboarded = client.onboard({
                "id": "customer-api-gateway", "adapter": "http",
                "listen": {"port": 30443, "server_name": "customer-api.local"},
                "upstream": {"address": "http://customer.internal:8080"},
            })
            check("one_call_service_publish", onboarded["status"] == "STAGED", onboarded["release"]["version"])
            service = client.request("GET", "/v1/services/customer-api-gateway")
            check("service_resource_query", service["spec"]["downstream_tls"]["mode"] == "compatibility")
            releases = client.request("GET", "/v1/releases")
            check("release_history_api", len(releases["items"]) == 1, releases["items"])
            job = client.create_scan([str(source_root)], [str(compile_commands)])
            completed = client.wait_scan(job["scan_id"], timeout=30, interval=0.05)
            check("asynchronous_scan_api", completed["status"] == "SUCCEEDED", completed.get("summary"))
            findings = client.request("GET", f"/v1/scans/{job['scan_id']}/findings")
            check("finding_evidence_api", any("RSA" in item.get("method", "") for item in findings["items"]), len(findings["items"]))
            assets = client.request("GET", "/v1/assets")
            asset = next(item for item in assets["items"] if item["path"].endswith("payment.cpp"))
            check("asset_inventory_api", bool(asset["asset_id"]), len(assets["items"]))
            assessment = client.request("POST", f"/v1/assets/{asset['asset_id']}/assess")
            check("asset_assessment_api", assessment["result"]["decision"] == "MIGRATION_REQUIRED", assessment["risk"])
            plan = client.request("POST", f"/v1/assets/{asset['asset_id']}/migration", {
                "action": "create",
                "service": {
                    "id": "discovered-payment-gateway", "adapter": "http",
                    "listen": {"address": "0.0.0.0", "port": 31443, "server_name": "discovered-payment.local"},
                    "upstream": {"address": "http://payment.internal:8080"},
                },
            })
            check("scan_to_compatibility_release", plan["status"] == "COMPATIBILITY_STAGED", plan["compatibility_version"])
            rolled_back = client.request("POST", f"/v1/releases/{onboarded['release']['version']}/rollback")
            check("release_rollback_api", rolled_back["rollback_from"] == onboarded["release"]["version"], rolled_back["version"])
            final = client.status()
            check("aggregated_observability_api", final["counts"]["assets"] > 0 and final["counts"]["services"] == 1, final["counts"])
            audit = client.request("GET", "/v1/audit")
            check("audit_api", len(audit["items"]) > 0, len(audit["items"]))
        except Exception as exc:
            rows.append({"test": "workflow_exception", "status": "FAIL", "detail": str(exc)})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            scanner.close()

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "tests": len(rows),
            "passed": sum(row["status"] == "PASS" for row in rows),
            "failed": sum(row["status"] == "FAIL" for row in rows),
        },
        "results": rows,
    }
    (out / "api-first-matrix.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
    return 0 if result["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
