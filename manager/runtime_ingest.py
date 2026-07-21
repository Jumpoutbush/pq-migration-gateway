"""Validation and normalization for Runtime Agent discovery reports."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone


SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
ALLOWED_EVIDENCE = {"runtime_mapped_library", "runtime_crypto_api"}
ALLOWED_SOURCES = {"proc_maps", "ebpf_uprobe", "imported_trace"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value: object, limit: int) -> str:
    return str(value or "")[:limit]


def _stable_id(prefix: str, *values: object) -> str:
    digest = hashlib.sha256("\0".join(str(value) for value in values).encode()).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _bounded_json(value: object, *, depth: int = 0) -> object:
    """Retain JSON metadata while bounding nesting, keys, lists and strings."""
    if depth > 5:
        return "<depth-limited>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, list):
        return [_bounded_json(item, depth=depth + 1) for item in value[:128]]
    if isinstance(value, dict):
        return {
            str(key)[:128]: _bounded_json(item, depth=depth + 1)
            for key, item in list(value.items())[:128]
        }
    return str(value)[:2000]


def classify_runtime_signal(method: str, library: str, evidence_type: str) -> tuple[str, str, str]:
    """Return server-controlled algorithm, risk and PQ status labels."""
    searchable = f"{method} {library}".upper()
    if any(token in searchable for token in ("OQS_", "LIBOQS", "MLKEM", "ML-KEM", "MLDSA", "ML-DSA", "SLH-DSA")):
        return "PQC/runtime-selected", "INFO", "pqc_or_pqc_candidate"
    if any(token in searchable for token in ("RSA_", "ECDSA_", "ECDH_", "EC_KEY_")):
        risk = "HIGH" if evidence_type == "runtime_crypto_api" else "MEDIUM"
        return "classical-public-key", risk, "quantum_vulnerable"
    if any(token in searchable for token in ("MD5", "SHA1", "SHA-1")):
        return "weak-hash", "HIGH", "classically_weak"
    if method.startswith("SSL_"):
        return "TLS/runtime-selected", "MEDIUM" if evidence_type == "runtime_crypto_api" else "INFO", "unknown"
    return "runtime-selected", "MEDIUM" if evidence_type == "runtime_crypto_api" else "INFO", "unknown"


def normalize_runtime_report(payload: dict) -> dict:
    """Validate a bounded report and recompute identifiers and security labels."""
    if not isinstance(payload, dict):
        raise ValueError("runtime report must be an object")
    if int(payload.get("schema_version", 1)) != 1:
        raise ValueError("unsupported runtime report schema_version")
    raw_agent = payload.get("agent")
    if not isinstance(raw_agent, dict):
        raise ValueError("runtime report agent must be an object")
    agent_id = _text(raw_agent.get("id"), 128)
    if not SAFE_ID.fullmatch(agent_id):
        raise ValueError("runtime agent id must match [A-Za-z0-9._-]{1,128}")
    batch_id = _text(payload.get("batch_id"), 128)
    if not SAFE_ID.fullmatch(batch_id):
        raise ValueError("runtime batch_id must match [A-Za-z0-9._-]{1,128}")
    collected_at = _text(payload.get("collected_at"), 64) or _now()
    agent = {
        "id": agent_id,
        "hostname": _text(raw_agent.get("hostname"), 255),
        "version": _text(raw_agent.get("version"), 64),
        "boot_id": _text(raw_agent.get("boot_id"), 128),
        "mode": _text(raw_agent.get("mode", "host"), 32),
        "capabilities": sorted({_text(item, 64) for item in raw_agent.get("capabilities", [])[:64] if item}),
        "metadata": _bounded_json(raw_agent.get("metadata", {})),
    }

    raw_processes = payload.get("processes", [])
    if not isinstance(raw_processes, list) or len(raw_processes) > 5000:
        raise ValueError("runtime report processes must be an array with at most 5000 entries")
    processes: list[dict] = []
    by_instance: dict[str, dict] = {}
    for raw in raw_processes:
        if not isinstance(raw, dict):
            continue
        pid = int(raw.get("pid", 0))
        start_ticks = int(raw.get("start_time_ticks", 0))
        if pid < 1 or start_ticks < 0:
            continue
        executable = _text(raw.get("executable"), 4096)
        container = raw.get("container", {}) if isinstance(raw.get("container", {}), dict) else {}
        container_id = _text(container.get("id"), 128)
        process_instance_id = _stable_id("proc", agent_id, agent["boot_id"], pid, start_ticks)
        workload_key = container_id or _text(container.get("pod_uid"), 128) or "host"
        workload_asset_id = _stable_id("runtime-asset", agent_id, workload_key, executable)
        libraries = sorted({_text(item, 4096) for item in raw.get("mapped_crypto_libraries", [])[:512] if item})
        item = {
            "process_instance_id": process_instance_id,
            "workload_asset_id": workload_asset_id,
            "pid": pid,
            "start_time_ticks": start_ticks,
            "executable": executable,
            "command": _text(raw.get("command"), 1000),
            "uid": int(raw.get("uid", -1)),
            "mapped_crypto_libraries": libraries,
            "container": {
                "id": container_id,
                "runtime": _text(container.get("runtime"), 64),
                "pod_uid": _text(container.get("pod_uid"), 128),
                "cgroup": _text(container.get("cgroup"), 4096),
            },
            "namespaces": _bounded_json(raw.get("namespaces", {})),
            "metadata": _bounded_json(raw.get("metadata", {})),
        }
        processes.append(item)
        by_instance[process_instance_id] = item

    raw_observations = payload.get("observations", [])
    if not isinstance(raw_observations, list) or len(raw_observations) > 20_000:
        raise ValueError("runtime report observations must be an array with at most 20000 entries")
    observations: list[dict] = []
    seen: set[str] = set()
    for raw in raw_observations:
        if not isinstance(raw, dict):
            continue
        supplied_instance = _text(raw.get("process_instance_id"), 128)
        # Agents may use their locally computed id. Match by pid/start ticks if
        # the server recomputed id differs, but never accept an unlinked event.
        process = by_instance.get(supplied_instance)
        if process is None:
            pid, start_ticks = int(raw.get("pid", 0)), int(raw.get("start_time_ticks", 0))
            process = next((item for item in processes if item["pid"] == pid and item["start_time_ticks"] == start_ticks), None)
        if process is None:
            continue
        evidence_type = _text(raw.get("evidence_type"), 64)
        source = _text(raw.get("source"), 64)
        if evidence_type not in ALLOWED_EVIDENCE or source not in ALLOWED_SOURCES:
            continue
        method = _text(raw.get("method"), 240)
        library = _text(raw.get("library"), 4096)
        if not method and not library:
            continue
        observation_key = _stable_id(
            "runtime-evidence", agent_id, process["process_instance_id"], evidence_type, method, library, source,
        )
        if observation_key in seen:
            continue
        seen.add(observation_key)
        algorithm, risk, pq_status = classify_runtime_signal(method, library, evidence_type)
        observations.append({
            "observation_key": observation_key,
            "process_instance_id": process["process_instance_id"],
            "workload_asset_id": process["workload_asset_id"],
            "pid": process["pid"],
            "start_time_ticks": process["start_time_ticks"],
            "evidence_type": evidence_type,
            "method": method or library,
            "library": library,
            "algorithm": algorithm,
            "risk": risk,
            "pq_status": pq_status,
            "confidence": "HIGH",
            "source": source,
            "observed_at": _text(raw.get("observed_at"), 64) or collected_at,
            "count": max(1, min(int(raw.get("count", 1)), 1_000_000_000)),
            "metadata": _bounded_json(raw.get("metadata", {})),
        })

    normalized = {
        "schema_version": 1,
        "batch_id": batch_id,
        "collected_at": collected_at,
        "agent": agent,
        "processes": processes,
        "observations": observations,
        "summary": {
            "processes": len(processes),
            "containers": len({item["container"]["id"] for item in processes if item["container"]["id"]}),
            "mapped_library_observations": sum(item["evidence_type"] == "runtime_mapped_library" for item in observations),
            "runtime_call_observations": sum(item["evidence_type"] == "runtime_crypto_api" for item in observations),
        },
    }
    # Keep the normalized report comfortably below SQLite/API operational limits.
    if len(json.dumps(normalized, ensure_ascii=False).encode()) > 2 * 1024 * 1024:
        raise ValueError("normalized runtime report exceeds 2 MiB")
    return normalized


def runtime_inventory(report: dict) -> dict:
    """Convert a normalized runtime report to the existing asset inventory schema."""
    artifacts: dict[str, dict] = {}
    for process in report["processes"]:
        asset_id = process["workload_asset_id"]
        item = artifacts.setdefault(asset_id, {
            "artifact_id": asset_id,
            "path": process["executable"],
            "artifact_type": "container_workload" if process["container"]["id"] else "runtime_process",
            "file_format": "running-process",
            "sha256": "",
            "size": 0,
            "executable": True,
            "languages": [],
            "dependencies": [],
            "imported_symbols": [],
            "demangled_symbols": [],
            "confidence": "HIGH",
            "metadata": {
                "agent_id": report["agent"]["id"],
                "hostname": report["agent"]["hostname"],
                "container": process["container"],
                "process_instances": [],
                "runtime_observed": True,
            },
        })
        item["dependencies"] = sorted(set(item["dependencies"]) | set(process["mapped_crypto_libraries"]))[:500]
        item["metadata"]["process_instances"].append({
            "process_instance_id": process["process_instance_id"], "pid": process["pid"],
            "start_time_ticks": process["start_time_ticks"], "uid": process["uid"],
        })

    evidence: list[dict] = []
    for observation in report["observations"]:
        evidence.append({
            "evidence_id": observation["observation_key"],
            "artifact_id": observation["workload_asset_id"],
            "path": observation["library"] or next(
                (item["executable"] for item in report["processes"] if item["process_instance_id"] == observation["process_instance_id"]), ""
            ),
            "line": 0,
            "evidence_type": observation["evidence_type"],
            "algorithm": observation["algorithm"],
            "risk": observation["risk"],
            "pq_status": observation["pq_status"],
            "excerpt": f"pid={observation['pid']} observed {observation['method']}",
            "language": "runtime",
            "method": observation["method"],
            "library": observation["library"],
            "confidence": observation["confidence"],
            "artifact_type": "runtime_process",
            "source": observation["source"],
            "metadata": {
                "agent_id": report["agent"]["id"],
                "batch_id": report["batch_id"],
                "process_instance_id": observation["process_instance_id"],
                "observed_at": observation["observed_at"],
                "count": observation["count"],
                "observed_call": observation["evidence_type"] == "runtime_crypto_api",
                **observation["metadata"],
            },
        })
    summary = {
        **report["summary"],
        "runtime_agent_id": report["agent"]["id"],
        "runtime_batch_id": report["batch_id"],
        "crypto_relevant_artifacts": len(artifacts),
        "runtime_crypto_processes": len(report["processes"]),
        "runtime_crypto_api_observations": report["summary"]["runtime_call_observations"],
    }
    return {
        "schema_version": 4,
        "scanner_version": report["agent"]["version"],
        "generated_at": report["collected_at"],
        "roots": [],
        "summary": summary,
        "assets": [],
        "artifacts": list(artifacts.values()),
        "evidence": evidence,
        "findings": evidence,
        "runtime_processes": report["processes"],
    }
