#!/usr/bin/env python3
"""Deterministic REST experiment for scan -> asset -> migration orchestration."""
from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.error
import urllib.request
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.config_store import ConfigStore
from manager.manager_api import ApiHandler
from manager.scan_orchestrator import ScanOrchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    urllib.request.install_opener(
        urllib.request.build_opener(
            urllib.request.ProxyHandler({})
        )
    )
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixtures = output / "fixtures"
    fixtures.mkdir(exist_ok=True)
    source = fixtures / "payment.cpp"
    source.write_text(
        "#define CREATE_CTX(method) SSL_CTX_new(method)\n"
        "void *crypto(){ RSA_public_encrypt(0,nullptr,nullptr,nullptr,0); return CREATE_CTX(TLS_client_method()); }\n"
        "void *payment_tls(){ return crypto(); }\n",
        encoding="utf-8",
    )
    database = fixtures / "compile_commands.json"
    database.write_text(json.dumps([{
        "directory": str(fixtures), "file": "payment.cpp",
        "arguments": ["g++", "-std=c++20", "-DPAYMENT_BUILD=1", "-c", "payment.cpp"],
    }], indent=2) + "\n", encoding="utf-8")

    store = ConfigStore(output / "control-plane.db")
    orchestrator = ScanOrchestrator(store, output / "control", [fixtures])
    ApiHandler.store = store
    ApiHandler.control_dir = output / "control"
    ApiHandler.token = "experiment-token"
    ApiHandler.metrics_public = True
    ApiHandler.scanner = orchestrator
    server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    tests: list[dict] = []

    def request(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            base + path, data=payload, method=method,
            headers={"Authorization": "Bearer experiment-token", "X-PQ-Operator": "experiment", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            text = raw.decode("utf-8", errors="replace")

            print(
                f"{method} {path} -> HTTP {exc.code} {exc.reason}; "
                f"body={text!r}"
            )

            if text.strip():
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = {
                        "error": "non_json_error_response",
                        "body": text,
                    }
            else:
                payload = {
                    "error": "empty_error_response",
                    "reason": str(exc.reason),
                }

            return exc.code, payload

    def record(name: str, passed: bool, details: object = None) -> None:
        tests.append({"test": name, "status": "PASS" if passed else "FAIL", "details": details})

    try:
        status, job = request("POST", "/v1/scans", {
            "type": "enterprise", "roots": [str(fixtures)], "compile_commands": [str(database)],
        })
        record("create_scan_api", status == 202, {"status": status, "scan_id": job.get("scan_id")})
        if status != 202 or not job.get("scan_id"):
            raise RuntimeError(
                f"scan creation failed: HTTP {status}, response={job!r}"
            )
        scan_id = job["scan_id"]
        for _ in range(200):
            _, job = request("GET", f"/v1/scans/{job['scan_id']}")
            if job.get("status") in {"SUCCEEDED", "FAILED"}:
                break
            time.sleep(0.05)
        record("scan_job_succeeded", job.get("status") == "SUCCEEDED", job.get("error"))
        _, findings = request("GET", f"/v1/scans/{job['scan_id']}/findings")
        cpp_rsa = any(item.get("language") == "cpp" and item.get("method", "").startswith("RSA_") for item in findings.get("items", []))
        record("cpp_rsa_openssl_finding", cpp_rsa, {"findings": len(findings.get("items", []))})
        _, assets = request("GET", "/v1/assets")
        asset = next((item for item in assets.get("items", []) if item.get("path", "").endswith("payment.cpp")), {})
        record("control_plane_asset_created", bool(asset), asset.get("asset_id"))
        asset_id = asset["asset_id"]
        status, assessment = request("POST", f"/v1/assets/{asset_id}/assess", {})
        record("asset_assessed", status == 201 and assessment.get("result", {}).get("decision") == "MIGRATION_REQUIRED", assessment.get("risk"))
        status, plan = request("POST", f"/v1/assets/{asset_id}/migration", {
            "action": "create",
            "service": {
                "id": "payment-pqc-gateway", "adapter": "http",
                "listen": {"address": "0.0.0.0", "port": 28443, "server_name": "payment-gateway.local"},
                "upstream": {"address": "http://payment.internal:8080"},
            },
        })
        record("compatibility_release_staged", status == 202 and plan.get("status") == "COMPATIBILITY_STAGED", plan.get("compatibility_version"))
        denied, denial = request("POST", f"/v1/assets/{asset_id}/migration", {
            "action": "verify", "plan_id": plan["plan_id"], "passed": True,
            "verification_result": "premature", "fallback_rate": 0.0,
        })
        record("strict_gate_rejects_unhealthy_release", denied == 400, denial.get("error"))
        store.set_status(plan["compatibility_version"], "APPLIED", "experiment-agent")
        store.set_status(plan["compatibility_version"], "HEALTHY", "experiment-agent")
        status, strict = request("POST", f"/v1/assets/{asset_id}/migration", {
            "action": "verify", "plan_id": plan["plan_id"], "passed": True,
            "verification_result": "hybrid clients passed and fallback rate is zero", "fallback_rate": 0.0,
        })
        record("strict_release_staged_after_verification", status == 202 and strict.get("status") == "STRICT_STAGED", strict.get("strict_version"))
        service = store.get_resource("service", "payment-pqc-gateway")["spec"]
        record("strict_policy_is_hybrid_only", service["downstream_tls"]["groups"] == ["X25519MLKEM768"] and not service["rollout"]["fallback_allowed"], service["downstream_tls"])
        store.set_status(strict["strict_version"], "APPLIED", "experiment-agent")
        store.set_status(strict["strict_version"], "HEALTHY", "experiment-agent")
        status, completed = request("POST", f"/v1/assets/{asset_id}/migration", {
            "action": "complete", "plan_id": plan["plan_id"], "verification_result": "strict endpoint healthy",
        })
        record("migration_verified", status == 202 and completed.get("status") == "VERIFIED", completed.get("status"))
    except Exception as exc:
        import traceback
        traceback.print_exc()
        record("workflow_exception", False, str(exc))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        orchestrator.close()

    summary = {
        "tests": len(tests), "passed": sum(item["status"] == "PASS" for item in tests),
        "failed": sum(item["status"] == "FAIL" for item in tests),
    }
    result = {"schema_version": 1, "summary": summary, "results": tests}
    (output / "scan-migration-api-matrix.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
