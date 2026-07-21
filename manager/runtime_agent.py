#!/usr/bin/env python3
"""Host-side Runtime Agent for process, container and crypto-call evidence."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.api_client import ApiError, ManagerApiClient  # noqa: E402
from scanner.ebpf_observer import MAX_PROBE_SYMBOLS, observe_processes  # noqa: E402
from scanner.runtime_collector import agent_metadata, collect_processes, import_runtime_events, utc_now  # noqa: E402


AGENT_VERSION = "3.7.0"
SAFE_AGENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _loopback_url(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}


def _aggregate_observations(rows: list[dict], maximum: int) -> list[dict]:
    aggregated: dict[tuple, dict] = {}
    for row in rows:
        key = (
            row.get("process_instance_id", ""), row.get("evidence_type", ""),
            row.get("method", ""), row.get("library", ""), row.get("source", ""),
        )
        if key in aggregated:
            aggregated[key]["count"] = min(1_000_000_000, int(aggregated[key].get("count", 1)) + int(row.get("count", 1)))
        elif len(aggregated) < maximum:
            aggregated[key] = dict(row)
    return list(aggregated.values())


class RuntimeAgent:
    def __init__(self, *, agent_id: str, manager_url: str, token: str, proc_root: Path, host_root: Path | None,
                 spool_dir: Path, include_command_lines: bool = False, max_processes: int = 5000,
                 max_events: int = 20_000, event_files: list[Path] | None = None, ebpf: bool = False,
                 ebpf_duration: int = 5, bpftrace: str = "bpftrace", nm: str = "nm",
                 ebpf_max_probes: int = MAX_PROBE_SYMBOLS, allow_insecure_http: bool = False,
                 target_pids: set[int] | None = None, ebpf_proc_root: Path | None = None,
                 cgroup_root: Path = Path("/sys/fs/cgroup")):
        if not SAFE_AGENT_ID.fullmatch(agent_id):
            raise ValueError("runtime agent id must match [A-Za-z0-9._-]{1,128}")
        if not 1 <= max_processes <= 5000:
            raise ValueError("max processes must be between 1 and 5000")
        if not 1 <= max_events <= 20_000:
            raise ValueError("max events must be between 1 and 20000")
        if not 1 <= ebpf_max_probes <= MAX_PROBE_SYMBOLS:
            raise ValueError(f"eBPF max probes must be between 1 and {MAX_PROBE_SYMBOLS}")
        parsed = urlsplit(manager_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("manager URL must use http or https")
        if parsed.scheme != "https" and not _loopback_url(manager_url) and not allow_insecure_http:
            raise ValueError("remote runtime reports require HTTPS; use --allow-insecure-http only in an isolated test network")
        self.agent_id = agent_id
        self.manager_url = manager_url.rstrip("/")
        self.token = token
        self.proc_root = proc_root
        self.host_root = host_root
        self.spool_dir = spool_dir
        self.include_command_lines = include_command_lines
        self.max_processes = max_processes
        self.max_events = max_events
        self.target_pids = target_pids
        self.event_files = event_files or []
        self.ebpf = ebpf
        self.ebpf_duration = ebpf_duration
        self.ebpf_max_probes = ebpf_max_probes
        self.ebpf_proc_root = ebpf_proc_root
        self.cgroup_root = cgroup_root
        self.bpftrace = bpftrace
        self.nm = nm
        self.client = ManagerApiClient(self.manager_url, token, f"runtime-agent:{agent_id}") if token else None

    def collect(self) -> dict:
        processes, observations, stats = collect_processes(
            self.proc_root, agent_id=self.agent_id, max_processes=self.max_processes,
            include_command_lines=self.include_command_lines, target_pids=self.target_pids,
            cgroup_root=self.cgroup_root,
        )
        observations.extend(import_runtime_events(self.event_files, processes, self.max_events))
        ebpf_status: dict = {"enabled": False}
        if self.ebpf and processes:
            try:
                events, ebpf_status = observe_processes(
                    processes, self.ebpf_duration, bpftrace=self.bpftrace, nm=self.nm,
                    host_root=self.host_root, proc_root=self.proc_root,
                    probe_proc_root=self.ebpf_proc_root,
                    max_symbols=self.ebpf_max_probes,
                )
                by_pid = {int(item["pid"]): item for item in processes}
                for event in events:
                    process = by_pid.get(int(event.get("pid", 0)))
                    if process is None:
                        continue
                    observations.append({
                        "process_instance_id": process["process_instance_id"],
                        "pid": process["pid"],
                        "start_time_ticks": process["start_time_ticks"],
                        "evidence_type": "runtime_crypto_api",
                        "method": str(event.get("method", "")),
                        "library": str(event.get("library", "")),
                        "source": "ebpf_uprobe",
                        "observed_at": utc_now(),
                        "count": 1,
                        "metadata": {
                            "observed_call": True,
                            "command": str(event.get("command", ""))[:256],
                            "ebpf_trace_pid": int(event.get("trace_pid", event.get("pid", 0))),
                            "ebpf_cgroup_id": int(event.get("cgroup_id", 0)),
                            "attribution": str(event.get("attribution", "root-pid"))[:32],
                            "candidate_pids": list(event.get("candidate_pids", []))[:128],
                        },
                    })
            except (OSError, RuntimeError, ValueError) as exc:
                # A privilege or kernel limitation must not discard the
                # process-map evidence collected in the same batch.
                ebpf_status = {"enabled": True, "status": "failed", "error": str(exc)[:2000]}
        observations = _aggregate_observations(observations, self.max_events)
        metadata = agent_metadata()
        metadata.update({"collection": stats, "ebpf": ebpf_status})
        capabilities = ["proc-maps", "container-cgroup"]
        if self.event_files:
            capabilities.append("trace-import")
        if self.ebpf:
            capabilities.append("fixed-ebpf-uprobes")
        return {
            "schema_version": 1,
            "batch_id": "batch-" + uuid.uuid4().hex,
            "collected_at": utc_now(),
            "agent": {
                "id": self.agent_id,
                "hostname": socket.gethostname(),
                "version": AGENT_VERSION,
                "boot_id": stats.get("boot_id", ""),
                "mode": "container" if str(self.proc_root) != "/proc" else "host",
                "capabilities": capabilities,
                "metadata": metadata,
            },
            "processes": processes,
            "observations": observations,
            "summary": {
                "processes": len(processes), "observations": len(observations),
                "runtime_calls": sum(row.get("evidence_type") == "runtime_crypto_api" for row in observations),
            },
        }

    def spool(self, report: dict) -> Path:
        path = self.spool_dir / f"{report['batch_id']}.json"
        _atomic_json(path, report)
        return path

    def flush(self) -> list[dict]:
        if self.client is None:
            raise ValueError("RUNTIME_AGENT_TOKEN or --token is required for report submission")
        results: list[dict] = []
        self.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in sorted(self.spool_dir.glob("batch-*.json")):
            report = json.loads(path.read_text(encoding="utf-8"))
            result = self.client.request("POST", "/v1/runtime/reports", report)
            if not isinstance(result, dict) or result.get("batch_id") != report.get("batch_id"):
                raise RuntimeError("Manager API did not acknowledge the runtime batch")
            path.unlink()
            results.append(result)
        return results

    def run_once(self) -> list[dict]:
        self.spool(self.collect())
        return self.flush()

    def watch(self, interval: float) -> None:
        while True:
            try:
                results = self.run_once()
                print(json.dumps({"uploaded": len(results), "results": results}, ensure_ascii=False), flush=True)
            except (ApiError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                print(f"runtime-agent: {exc}", file=sys.stderr, flush=True)
            time.sleep(max(1.0, interval))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["collect", "once", "watch"])
    parser.add_argument("--manager-url", default=os.environ.get("PQ_MANAGER_API_URL", "http://127.0.0.1:18080"))
    parser.add_argument("--token", default=os.environ.get("RUNTIME_AGENT_TOKEN", ""))
    parser.add_argument("--agent-id", default=os.environ.get("PQ_RUNTIME_AGENT_ID", socket.gethostname()))
    parser.add_argument("--proc-root", type=Path, default=Path(os.environ.get("PQ_RUNTIME_PROC_ROOT", "/proc")))
    parser.add_argument(
        "--cgroup-root", type=Path,
        default=Path(os.environ.get("PQ_RUNTIME_CGROUP_ROOT", "/sys/fs/cgroup")),
        help="cgroup v2 filesystem used to resolve stable BPF cgroup identifiers",
    )
    parser.add_argument("--host-root", type=Path, default=Path(os.environ["PQ_RUNTIME_HOST_ROOT"]) if os.environ.get("PQ_RUNTIME_HOST_ROOT") else None)
    parser.add_argument("--spool-dir", type=Path, default=Path(os.environ.get("PQ_RUNTIME_SPOOL_DIR", "/var/lib/pq-runtime-agent/spool")))
    parser.add_argument("--out", type=Path, help="Write a collect-only report to this path")
    parser.add_argument("--interval", type=float, default=30)
    parser.add_argument("--max-processes", type=int, default=5000)
    parser.add_argument("--max-events", type=int, default=20_000)
    parser.add_argument("--include-command-lines", action="store_true")
    parser.add_argument("--pid", action="append", type=int, default=[], help="Inspect only this PID; may be repeated")
    parser.add_argument("--event-file", action="append", type=Path, default=[])
    parser.add_argument("--ebpf", action="store_true", default=os.environ.get("PQ_RUNTIME_EBPF") == "1")
    parser.add_argument("--ebpf-duration", type=int, default=5)
    parser.add_argument(
        "--ebpf-max-probes", type=int,
        default=int(os.environ.get("PQ_RUNTIME_EBPF_MAX_PROBES", str(MAX_PROBE_SYMBOLS))),
        help=f"Maximum high-value eBPF uprobes (1-{MAX_PROBE_SYMBOLS})",
    )
    parser.add_argument(
        "--ebpf-proc-root", type=Path,
        default=Path(os.environ["PQ_RUNTIME_EBPF_PROC_ROOT"])
        if os.environ.get("PQ_RUNTIME_EBPF_PROC_ROOT") else None,
        help="Short host PID namespace path used only for eBPF attachment",
    )
    parser.add_argument("--bpftrace", default="bpftrace")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--allow-insecure-http", action="store_true")
    args = parser.parse_args()
    if args.command == "watch" and args.event_file:
        parser.error("--event-file is collect/once only; watch mode would replay the same trace")
    try:
        agent = RuntimeAgent(
            agent_id=args.agent_id, manager_url=args.manager_url, token=args.token,
            proc_root=args.proc_root, host_root=args.host_root, spool_dir=args.spool_dir,
            include_command_lines=args.include_command_lines, max_processes=args.max_processes,
            max_events=args.max_events, event_files=args.event_file, ebpf=args.ebpf,
            ebpf_duration=args.ebpf_duration, ebpf_max_probes=args.ebpf_max_probes,
            bpftrace=args.bpftrace, nm=args.nm, ebpf_proc_root=args.ebpf_proc_root,
            cgroup_root=args.cgroup_root,
            allow_insecure_http=args.allow_insecure_http,
            target_pids={pid for pid in args.pid if pid > 0} or None,
        )
        if args.command == "collect":
            report = agent.collect()
            if args.out:
                _atomic_json(args.out, report)
                print(json.dumps({"report": str(args.out), "summary": report["summary"]}, indent=2))
            else:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0
        if args.command == "once":
            print(json.dumps({"results": agent.run_once()}, ensure_ascii=False, indent=2))
            return 0
        agent.watch(args.interval)
        return 0
    except (ApiError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"runtime-agent: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
