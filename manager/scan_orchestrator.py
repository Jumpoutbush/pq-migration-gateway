"""Asynchronous scan jobs and scan-to-migration control-plane orchestration."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from manager.config_store import ConfigStore
from manager.control_plane import stage_resources
from manager.state_machine import MigrationStateMachine


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts/crypto_inventory.py"
RISK_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DEFAULTS = {
    "certificate": "/etc/pq-gateway/certs/server.crt",
    "certificate_key": "/etc/pq-gateway/certs/server.key",
    "client_ca": "/etc/pq-gateway/certs/ca.crt",
    "upstream_ca": "/etc/pq-gateway/certs/upstream/ca.crt",
    "dns_resolver": "127.0.0.11",
    "connect_timeout": "5s", "send_timeout": "60s", "read_timeout": "60s",
}


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class ScanOrchestrator:
    def __init__(self, store: ConfigStore, control_dir: str | Path, allowed_roots: list[str | Path], *,
                 workers: int = 2, process_scan_enabled: bool = False, ebpf_enabled: bool = False,
                 scanner: str | Path = SCANNER):
        self.store = store
        self.control_dir = Path(control_dir)
        self.allowed_roots = [Path(item).resolve() for item in allowed_roots]
        self.process_scan_enabled = process_scan_enabled
        self.ebpf_enabled = ebpf_enabled
        self.scanner = Path(scanner)
        self.executor = ThreadPoolExecutor(max_workers=max(1, min(workers, 8)), thread_name_prefix="pq-scan")

    def close(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=False)

    def _authorized_path(self, value: object, *, must_exist: bool = True) -> Path:
        path = Path(str(value)).resolve()
        if must_exist and not path.exists():
            raise ValueError(f"scan path does not exist: {path}")
        if not self.allowed_roots or not any(_under(path, root) for root in self.allowed_roots):
            raise ValueError(f"scan path is outside PQ_SCAN_ALLOWED_ROOTS: {path}")
        return path

    def validate_request(self, request: dict) -> dict:
        if str(request.get("type", "enterprise")) != "enterprise":
            raise ValueError("only enterprise scan jobs are supported by this endpoint")
        roots = request.get("roots")
        if not isinstance(roots, list) or not roots or len(roots) > 32:
            raise ValueError("roots must contain between 1 and 32 authorized paths")
        normalized = copy.deepcopy(request)
        normalized["type"] = "enterprise"
        normalized["roots"] = [str(self._authorized_path(item)) for item in roots]
        compile_commands = request.get("compile_commands", [])
        if not isinstance(compile_commands, list) or len(compile_commands) > 32:
            raise ValueError("compile_commands must be a list with at most 32 entries")
        normalized["compile_commands"] = [str(self._authorized_path(item)) for item in compile_commands]
        cpp_semantic = str(request.get("cpp_semantic", "auto")).lower()
        if cpp_semantic not in {"auto", "on", "off"}:
            raise ValueError("cpp_semantic must be one of: auto, on, off")
        normalized["cpp_semantic"] = cpp_semantic
        traces = request.get("ebpf_trace_files", [])
        if not isinstance(traces, list) or len(traces) > 32:
            raise ValueError("ebpf_trace_files must be a list with at most 32 entries")
        normalized["ebpf_trace_files"] = [str(self._authorized_path(item)) for item in traces]
        if request.get("scan_processes") and not self.process_scan_enabled:
            raise ValueError("process scanning is disabled on manager-api")
        ebpf = request.get("ebpf", {})
        if ebpf and not isinstance(ebpf, dict):
            raise ValueError("ebpf must be an object")
        if ebpf.get("enabled"):
            if not self.ebpf_enabled:
                raise ValueError("live eBPF observation is disabled on manager-api")
            normalized["ebpf"] = {
                "enabled": True,
                "pid": int(ebpf.get("pid", 0)),
                "library": str(self._authorized_path(ebpf.get("library", ""))),
                "duration": max(1, min(int(ebpf.get("duration", 5)), 60)),
            }
        limits = request.get("limits", {})
        if limits and not isinstance(limits, dict):
            raise ValueError("limits must be an object")
        normalized["limits"] = {
            "max_files": max(1, min(int(limits.get("max_files", 100_000)), 1_000_000)),
            "max_text_bytes": max(1, min(int(limits.get("max_text_bytes", 2_000_000)), 16_000_000)),
            "max_binary_bytes": max(1, min(int(limits.get("max_binary_bytes", 64_000_000)), 512_000_000)),
            "max_evidence_per_file": max(1, min(int(limits.get("max_evidence_per_file", 2_000)), 20_000)),
        }
        return normalized

    def submit(self, request: dict, actor: str) -> dict:
        normalized = self.validate_request(request)
        scan_id = "scan-" + uuid.uuid4().hex[:20]
        job = self.store.create_scan_job(scan_id, "enterprise", normalized, actor)
        self.executor.submit(self._run, scan_id, normalized, actor)
        return job

    def _run(self, scan_id: str, request: dict, actor: str) -> None:
        output_dir = self.control_dir / "scans" / scan_id
        output_dir.mkdir(parents=True, exist_ok=False)
        json_path = output_dir / "inventory.json"
        csv_path = output_dir / "inventory.csv"
        self.store.update_scan_job(scan_id, "RUNNING", output_path=str(json_path))
        command = [sys.executable, str(self.scanner)]
        for root in request["roots"]:
            command += ["--root", root]
        for database in request.get("compile_commands", []):
            command += ["--compile-commands", database]
        command += ["--cpp-semantic", request.get("cpp_semantic", "auto")]
        for trace in request.get("ebpf_trace_files", []):
            command += ["--ebpf-trace-file", trace]
        if request.get("scan_processes"):
            command += ["--scan-processes", "--proc-root", "/proc"]
        ebpf = request.get("ebpf", {})
        if ebpf.get("enabled"):
            command += [
                "--enable-ebpf", "--ebpf-pid", str(ebpf["pid"]), "--ebpf-library", ebpf["library"],
                "--ebpf-duration", str(ebpf["duration"]),
            ]
        limits = request["limits"]
        command += [
            "--max-files", str(limits["max_files"]), "--max-text-bytes", str(limits["max_text_bytes"]),
            "--max-binary-bytes", str(limits["max_binary_bytes"]),
            "--max-evidence-per-file", str(limits["max_evidence_per_file"]),
            "--out-json", str(json_path), "--out-csv", str(csv_path),
        ]
        try:
            process = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=3600, check=False, cwd=ROOT,
            )
            if process.returncode != 0:
                error = (process.stderr or process.stdout).decode("utf-8", "replace")[-4000:]
                raise RuntimeError(f"scanner exited with {process.returncode}: {error}")
            inventory = json.loads(json_path.read_text(encoding="utf-8"))
            self.store.ingest_scan_inventory(scan_id, inventory, actor)
        except Exception as exc:
            self.store.update_scan_job(scan_id, "FAILED", output_path=str(json_path), error=str(exc)[:4000])

    def assess(self, asset_id: str, actor: str) -> dict:
        asset = self.store.get_crypto_asset(asset_id)
        evidence = asset["evidence"]
        risks = [asset.get("risk", "INFO")] + [str(item.get("risk", "INFO")) for item in evidence]
        risk = max(risks, key=lambda item: RISK_RANK.get(item, 0))
        searchable = "\n".join(
            [asset.get("algorithm", ""), json.dumps(asset.get("payload", {}), ensure_ascii=False)]
            + [json.dumps(item, ensure_ascii=False) for item in evidence]
        )
        classical = any(token in searchable.upper() for token in ("RSA", "ECDSA", "ECDH", "DIFFIE-HELLMAN"))
        openssl = "OPENSSL" in searchable.upper() or any(str(item.get("library", "")).lower() == "openssl" for item in evidence)
        pqc = any(token in searchable.upper() for token in ("ML-KEM", "MLKEM", "ML-DSA", "X25519MLKEM", "LIBOQS", "OQS_"))
        reasons: list[str] = []
        if classical:
            reasons.append("Classical public-key cryptography was found and is quantum-vulnerable.")
        if openssl:
            reasons.append("OpenSSL interfaces or dependencies provide a practical TLS migration boundary.")
        if pqc:
            reasons.append("PQC or hybrid interfaces were already observed and must be verified online.")
        if not reasons:
            reasons.append("Cryptographic evidence requires owner and service correlation before migration.")
        result = {
            "asset_id": asset_id, "risk": risk,
            "decision": "MIGRATION_REQUIRED" if classical else "VERIFY_AND_PLAN",
            "recommended_initial_mode": "compatibility",
            "target_mode": "strict",
            "reasons": reasons,
            "guardrails": {
                "required_verification": True,
                "maximum_fallback_rate_for_strict": 0.01,
                "strict_groups": ["X25519MLKEM768"],
            },
        }
        assessment_id = "assessment-" + uuid.uuid4().hex[:20]
        return self.store.create_asset_assessment(assessment_id, asset_id, risk, result, actor)

    @staticmethod
    def _compatibility_service(service: dict) -> dict:
        spec = copy.deepcopy(service)
        service_id = str(spec.get("id", ""))
        if not service_id:
            raise ValueError("migration service.id is required")
        for field in ("adapter", "listen", "upstream"):
            if field not in spec:
                raise ValueError(f"migration service.{field} is required")
        downstream = spec.setdefault("downstream_tls", {})
        downstream.update({"mode": "compatibility", "groups": ["X25519MLKEM768", "X25519"]})
        downstream.setdefault("client_auth", "off")
        downstream.setdefault("certificate", DEFAULTS["certificate"])
        downstream.setdefault("private_key", {"provider": "file", "reference": DEFAULTS["certificate_key"]})
        downstream.setdefault("client_ca", DEFAULTS["client_ca"])
        spec.setdefault("timeouts", {"connect": "5s", "send": "60s", "read": "60s"})
        spec["rollout"] = {"policy": "fixed", "hybrid_percentage": 100, "fallback_allowed": True}
        spec.setdefault("audit", {"enabled": True})
        spec.setdefault("protocol_options", {})
        upstream_tls = spec["upstream"].setdefault("tls", {})
        upstream_tls.setdefault("enabled", False)
        upstream_tls.setdefault("verify", "off" if not upstream_tls["enabled"] else "on")
        upstream_tls.setdefault("sni", "")
        upstream_tls.setdefault("ca", DEFAULTS["upstream_ca"])
        upstream_tls.setdefault("client_identity", {"certificate": "", "private_key": {"provider": "file", "reference": ""}})
        return spec

    @staticmethod
    def _advance(machine: MigrationStateMachine, service_id: str, targets: list[str], actor: str, reason: str,
                 config_version: int | None = None, verification_result: str | None = None,
                 fallback_rate: float | None = None) -> None:
        for target in targets:
            current = machine.get(service_id)
            if current and current["state"] == target:
                continue
            machine.transition(
                service_id, target, operator=actor, reason=reason, config_version=config_version,
                verification_result=verification_result, fallback_rate=fallback_rate,
            )

    def migrate(self, asset_id: str, body: dict, actor: str) -> dict:
        action = str(body.get("action", "create")).lower()
        asset = self.store.get_crypto_asset(asset_id)
        machine = MigrationStateMachine(self.store)
        if action == "create":
            service = self._compatibility_service(body.get("service", {}))
            service_id = service["id"]
            if machine.get(service_id) is not None:
                raise ValueError("migration service already has state; use its existing plan")
            assessment = self.assess(asset_id, actor)
            plan_id = "plan-" + hashlib.sha256(f"{asset_id}\0{service_id}".encode()).hexdigest()[:20]
            self._advance(machine, service_id, ["DISCOVERED", "ASSESSED", "PLANNED"], actor, f"Asset {asset_id} discovered and assessed")
            self.store.upsert_resource("service", service_id, service, actor)
            self.store.upsert_resource("policy", service_id, {
                "service_id": service_id,
                "downstream_tls": {"mode": "compatibility", "groups": ["X25519MLKEM768", "X25519"]},
                "rollout": {"policy": "fixed", "hybrid_percentage": 100, "fallback_allowed": True},
            }, actor)
            if not self.store.get_setting("service_defaults", {}):
                self.store.set_setting("service_defaults", DEFAULTS, actor)
            manifest = stage_resources(self.store, self.control_dir, actor)
            version = int(manifest["version"])
            self._advance(machine, service_id, ["COMPATIBILITY"], actor, "Compatibility release staged from scan finding", version)
            plan = {
                "asset_id": asset_id, "service_id": service_id,
                "source_path": asset["path"], "assessment_id": assessment["assessment_id"],
                "initial_mode": "compatibility", "target_mode": "strict",
                "strict_gate": {"release_status": "HEALTHY", "maximum_fallback_rate": 0.01, "verification_required": True},
            }
            return self.store.upsert_migration_plan(
                plan_id, asset_id, service_id, "COMPATIBILITY_STAGED", plan, actor, compatibility_version=version,
            )
        plans = asset.get("migration_plans", [])
        plan_id = str(body.get("plan_id") or (plans[0]["plan_id"] if plans else ""))
        if not plan_id:
            raise ValueError("asset has no migration plan")
        record = self.store.get_migration_plan(plan_id)
        if record["asset_id"] != asset_id:
            raise ValueError("migration plan does not belong to the asset")
        service_id = record["service_id"]
        if action == "verify":
            current = machine.get(service_id)
            if current is None or current["state"] != "COMPATIBILITY":
                raise ValueError("strict promotion requires the service to be in COMPATIBILITY state")
            compatibility = self.store.get_version(int(record["compatibility_version"]), include_rendered=False)
            if compatibility["status"] != "HEALTHY":
                raise ValueError("compatibility release must be HEALTHY before strict promotion")
            if body.get("passed") is not True:
                raise ValueError("strict promotion requires passed=true")
            verification = str(body.get("verification_result", "")).strip()
            if not verification:
                raise ValueError("strict promotion requires verification_result")
            fallback_rate = float(body.get("fallback_rate", 1.0))
            maximum = float(record["plan"].get("strict_gate", {}).get("maximum_fallback_rate", 0.01))
            if fallback_rate < 0 or fallback_rate > maximum:
                raise ValueError(f"fallback_rate must be between 0 and {maximum} for strict promotion")
            resource = self.store.get_resource("service", service_id)["spec"]
            resource.setdefault("downstream_tls", {}).update({"mode": "strict", "groups": ["X25519MLKEM768"]})
            resource["rollout"] = {"policy": "fixed", "hybrid_percentage": 100, "fallback_allowed": False}
            self.store.upsert_resource("service", service_id, resource, actor)
            self.store.upsert_resource("policy", service_id, {
                "service_id": service_id,
                "downstream_tls": {"mode": "strict", "groups": ["X25519MLKEM768"]},
                "rollout": {"policy": "fixed", "hybrid_percentage": 100, "fallback_allowed": False},
            }, actor)
            manifest = stage_resources(self.store, self.control_dir, actor)
            strict_version = int(manifest["version"])
            self._advance(machine, service_id, ["STRICT"], actor, "Compatibility verification passed; strict PQC staged",
                          strict_version, verification, fallback_rate)
            plan = {**record["plan"], "verification_result": verification, "fallback_rate": fallback_rate}
            return self.store.upsert_migration_plan(
                plan_id, asset_id, service_id, "STRICT_STAGED", plan, actor,
                compatibility_version=record["compatibility_version"], strict_version=strict_version,
            )
        if action == "complete":
            current = machine.get(service_id)
            if current is None or current["state"] != "STRICT":
                raise ValueError("migration completion requires the service to be in STRICT state")
            if not record.get("strict_version"):
                raise ValueError("strict release has not been staged")
            strict = self.store.get_version(int(record["strict_version"]), include_rendered=False)
            if strict["status"] != "HEALTHY":
                raise ValueError("strict release must be HEALTHY before migration completion")
            verification = str(body.get("verification_result", "strict release healthy"))
            self._advance(machine, service_id, ["VERIFIED"], actor, "Strict PQC release verified",
                          int(record["strict_version"]), verification, body.get("fallback_rate"))
            return self.store.upsert_migration_plan(
                plan_id, asset_id, service_id, "VERIFIED", {**record["plan"], "strict_verification": verification}, actor,
                compatibility_version=record["compatibility_version"], strict_version=record["strict_version"],
            )
        raise ValueError("migration action must be create, verify, or complete")
