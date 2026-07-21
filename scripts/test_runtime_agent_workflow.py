#!/usr/bin/env python3
"""Deterministic running backend -> Runtime Agent -> enterprise asset DB matrix."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.api_client import ApiError, ManagerApiClient  # noqa: E402
from manager.config_store import ConfigStore  # noqa: E402
from manager.manager_api import ApiHandler  # noqa: E402
from manager.runtime_agent import RuntimeAgent  # noqa: E402
from manager.scan_orchestrator import ScanOrchestrator  # noqa: E402


BACKEND = """
import ssl
import time

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
print("runtime-backend-ready", flush=True)
time.sleep(30)
"""


def proc_root_for_backend(root: Path, pid: int) -> tuple[Path, str]:
    """Use the live procfs when visible, with a deterministic CI fallback."""
    live_maps = Path("/proc") / str(pid) / "maps"
    try:
        content = live_maps.read_text(encoding="utf-8", errors="replace")
    except OSError:
        content = ""
    if "libssl" in content or "libcrypto" in content:
        return Path("/proc"), "live-procfs"

    proc = root / "proc"
    process = proc / str(pid)
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("runtime-workflow-boot\n", encoding="utf-8")
    (process / "ns").mkdir(parents=True)
    (process / "maps").write_text(
        "7f00-7f10 r-xp 00000000 08:01 1 /usr/lib/libssl.so.3\n"
        "7f20-7f30 r-xp 00000000 08:01 2 /usr/lib/libcrypto.so.3\n",
        encoding="utf-8",
    )
    fields = ["S"] + ["0"] * 18 + ["4242"]
    (process / "stat").write_text(f"{pid} (runtime backend) " + " ".join(fields) + "\n", encoding="utf-8")
    (process / "status").write_text("Name:\truntime-backend\nUid:\t1000\t1000\t1000\t1000\n", encoding="utf-8")
    (process / "cgroup").write_text("0::/runtime-workflow\n", encoding="utf-8")
    (process / "cmdline").write_bytes(b"runtime-backend\x00")
    (process / "exe").symlink_to(sys.executable)
    return proc, "deterministic-procfs-fallback"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="experiment-results/manual-runtime-agent")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    def record(name: str, passed: bool, detail: object = None) -> None:
        rows.append({"test": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    backend: subprocess.Popen[str] | None = None
    server: ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    scanner: ScanOrchestrator | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="pq-runtime-agent-") as temporary:
            root = Path(temporary)
            backend = subprocess.Popen(
                [sys.executable, "-u", "-c", BACKEND], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            ready = backend.stdout.readline().strip() if backend.stdout else ""
            record("running_backend_fixture", ready == "runtime-backend-ready" and backend.poll() is None, {
                "pid": backend.pid, "ready": ready,
            })

            trace = root / "authorized-runtime-trace.jsonl"
            trace.write_text(json.dumps({
                "pid": backend.pid, "command": "runtime-backend",
                "method": "SSL_CTX_new", "library": "libssl.so",
            }) + "\n", encoding="utf-8")
            proc_root, proc_source = proc_root_for_backend(root, backend.pid)

            allowed = root / "authorized-static-root"
            allowed.mkdir()
            store = ConfigStore(output / "control-plane.db")
            scanner = ScanOrchestrator(store, output / "control", [allowed])
            ApiHandler.store = store
            ApiHandler.control_dir = output / "control"
            ApiHandler.token = "runtime-operator-token"
            ApiHandler.runtime_agent_token = "runtime-agent-token"
            ApiHandler.metrics_public = True
            ApiHandler.scanner = scanner
            server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
            base = f"http://127.0.0.1:{server.server_address[1]}"
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            operator = ManagerApiClient(base, "runtime-operator-token", "runtime-workflow")
            agent = RuntimeAgent(
                agent_id="runtime-workflow-agent", manager_url=base, token="runtime-agent-token",
                proc_root=proc_root, host_root=None, spool_dir=output / "spool",
                target_pids={backend.pid}, event_files=[trace],
            )
            report = agent.collect()
            process = next((item for item in report["processes"] if item["pid"] == backend.pid), None)
            record("agent_reads_live_process_maps", process is not None and bool(process["mapped_crypto_libraries"]), {
                "pid": backend.pid,
                "libraries": process["mapped_crypto_libraries"] if process else [],
                "proc_source": proc_source,
            })
            record("authorized_call_trace_linked", any(
                item["source"] == "imported_trace" and item["method"] == "SSL_CTX_new"
                for item in report["observations"]
            ), report["summary"])

            try:
                operator.submit_runtime_report(report)
                record("dedicated_agent_token", False, "operator token unexpectedly accepted")
            except ApiError as exc:
                record("dedicated_agent_token", exc.status == 401, exc.status)

            spool_path = agent.spool(report)
            uploaded = agent.flush()
            record("spooled_authenticated_upload", len(uploaded) == 1 and not spool_path.exists(), uploaded[0] if uploaded else None)

            agents = operator.request("GET", "/v1/runtime/agents")
            observations = operator.request("GET", "/v1/runtime/observations")
            assets = operator.request("GET", "/v1/assets")
            call = next((item for item in observations["items"] if item["method"] == "SSL_CTX_new"), None)
            asset = next((item for item in assets["items"] if call and item["asset_id"] == call["workload_asset_id"]), None)
            detail = operator.request("GET", f"/v1/assets/{asset['asset_id']}") if asset else {}
            record("runtime_agent_registered", agents["items"][0]["agent_id"] == "runtime-workflow-agent", len(agents["items"]))
            record("runtime_call_persisted", call is not None and call["source"] == "imported_trace", call)
            record("enterprise_asset_created", asset is not None and asset["asset_type"] == "runtime_process", asset)
            record("runtime_evidence_linked_to_asset", any(
                item.get("source") == "imported_trace" for item in detail.get("evidence", [])
            ), len(detail.get("evidence", [])))

            duplicate = agent.client.submit_runtime_report(report) if agent.client else {}
            repeated = operator.request("GET", "/v1/runtime/observations")
            repeated_call = next(item for item in repeated["items"] if item["method"] == "SSL_CTX_new")
            record("batch_upload_is_idempotent", duplicate.get("batch_id") == report["batch_id"] and repeated_call["observation_count"] == 1, {
                "batch_id": duplicate.get("batch_id"), "observation_count": repeated_call["observation_count"],
            })

            with store.connect() as connection:
                counts = {
                    "agents": connection.execute("SELECT COUNT(*) FROM runtime_discovery_agents").fetchone()[0],
                    "processes": connection.execute("SELECT COUNT(*) FROM runtime_process_instances").fetchone()[0],
                    "observations": connection.execute("SELECT COUNT(*) FROM runtime_observations").fetchone()[0],
                    "assets": connection.execute("SELECT COUNT(*) FROM crypto_assets WHERE asset_type='runtime_process'").fetchone()[0],
                }
            record("enterprise_database_tables", all(value > 0 for value in counts.values()), counts)
    except Exception as exc:
        traceback.print_exc()
        record("workflow_exception", False, str(exc))
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=3)
        if scanner is not None:
            scanner.close()
        ApiHandler.runtime_agent_token = ""
        if backend is not None and backend.poll() is None:
            backend.terminate()
            try:
                backend.wait(timeout=3)
            except subprocess.TimeoutExpired:
                backend.kill()
                backend.wait(timeout=3)

    result = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "tests": len(rows),
            "passed": sum(item["status"] == "PASS" for item in rows),
            "failed": sum(item["status"] == "FAIL" for item in rows),
        },
        "results": rows,
    }
    (output / "runtime-agent-matrix.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    return 0 if result["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
