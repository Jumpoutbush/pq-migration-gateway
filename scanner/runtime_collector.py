"""Read-only Linux process/container discovery for the Runtime Agent."""
from __future__ import annotations

import hashlib
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

from scanner.ebpf_observer import evidence as ebpf_evidence
from scanner.ebpf_observer import parse_trace
from scanner.enterprise_inventory import CRYPTO_LIBRARY


CONTAINER_ID = re.compile(r"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])", re.I)
POD_UID = re.compile(r"pod([0-9a-fA-F_-]{16,})")
SECRET_ARGUMENT = re.compile(
    r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key|credential)(?:=|\s+))\S+"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()[:24]
    return f"{prefix}-{digest}"


def redact_command(command: str) -> str:
    return SECRET_ARGUMENT.sub(r"\1<redacted>", command)[:1000]


def _read_text(path: Path, limit: int = 1_000_000) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _start_time_ticks(stat_text: str) -> int:
    # /proc/PID/stat field 2 is parenthesized and may contain spaces. Fields
    # after the final ')' start at field 3; starttime is field 22.
    end = stat_text.rfind(")")
    if end < 0:
        return 0
    fields = stat_text[end + 1:].strip().split()
    try:
        return int(fields[19])
    except (IndexError, ValueError):
        return 0


def _uid(status_text: str) -> int:
    match = re.search(r"^Uid:\s+(\d+)", status_text, re.M)
    return int(match.group(1)) if match else -1


def _root_pid_from_sched(sched_text: str) -> int:
    """Return the initial PID-namespace number printed by procfs sched.

    A procfs mounted from an intermediate PID namespace may omit ancestor
    numbers from ``NSpid``.  Linux's ``/proc/PID/sched`` header is generated
    with ``task_pid_nr()`` and still exposes the initial-namespace PID, for
    example ``nginx (4467, #threads: 1)``.
    """
    first_line = sched_text.splitlines()[0] if sched_text else ""
    match = re.search(r"\((\d+),\s*#threads:\s*\d+\)\s*$", first_line)
    if not match:
        return 0
    try:
        value = int(match.group(1))
    except ValueError:
        return 0
    return value if value > 0 else 0


def _pid_hierarchy(status_text: str, fallback_pid: int, sched_text: str = "") -> list[int]:
    """Return PIDs from the outermost namespace to the discovery namespace.

    Linux normally exposes this mapping in the ``NSpid`` status field.  A
    procfs bind-mounted from an intermediate Docker/WSL namespace can omit its
    ancestor PID, while eBPF still reports that outermost number.  In that
    case the ``sched`` header supplies the missing initial-namespace PID.
    """
    match = re.search(r"^NSpid:\s+(.+)$", status_text, re.M)
    if match:
        values: list[int] = []
        for token in match.group(1).split()[:16]:
            try:
                value = int(token)
            except ValueError:
                continue
            if value > 0 and value not in values:
                values.append(value)
        if values:
            root_pid = _root_pid_from_sched(sched_text)
            if root_pid and root_pid not in values:
                values.insert(0, root_pid)
            return values
    root_pid = _root_pid_from_sched(sched_text)
    if root_pid and root_pid != fallback_pid:
        return [root_pid, fallback_pid]
    return [fallback_pid]


def _namespaces(process_dir: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("pid", "mnt", "net", "user"):
        try:
            result[name] = os.readlink(process_dir / "ns" / name)[:128]
        except OSError:
            continue
    return result


def container_identity(cgroup_text: str) -> dict:
    paths = [line.split(":", 2)[-1] for line in cgroup_text.splitlines() if ":" in line]
    joined = ";".join(paths)[:4096]
    match = CONTAINER_ID.search(joined)
    container_id = match.group(1).lower() if match else ""
    lowered = joined.lower()
    runtime = ""
    if "docker" in lowered:
        runtime = "docker"
    elif "containerd" in lowered or "cri-containerd" in lowered:
        runtime = "containerd"
    elif "crio" in lowered or "cri-o" in lowered:
        runtime = "cri-o"
    elif container_id:
        runtime = "unknown-oci"
    pod = POD_UID.search(joined)
    return {
        "id": container_id,
        "runtime": runtime,
        "pod_uid": pod.group(1).replace("_", "-")[:128] if pod else "",
        "cgroup": joined,
    }


def _cgroup_v2_id(cgroup_text: str, cgroup_root: Path) -> int:
    """Resolve the numeric cgroup-v2 ID used by bpftrace's ``cgroup`` builtin.

    The BPF helper returns the cgroup's kernfs identifier. On cgroup v2 this is
    exposed as the inode number of the corresponding directory in cgroupfs.
    Kernel-provided paths are still checked for traversal before they are used.
    """
    for line in cgroup_text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3 or parts[0] != "0" or parts[1]:
            continue
        relative = Path(parts[2].lstrip("/"))
        if relative.is_absolute() or ".." in relative.parts:
            return 0
        try:
            value = int((cgroup_root / relative).stat().st_ino)
        except OSError:
            return 0
        return value if value > 0 else 0
    return 0


def _mapped_crypto_libraries(maps_text: str) -> list[str]:
    paths: set[str] = set()
    for line in maps_text.splitlines():
        parts = line.split()
        if not parts:
            continue
        candidate = parts[-1]
        if candidate.startswith("/") and CRYPTO_LIBRARY.search(candidate):
            paths.add(candidate[:4096])
    return sorted(paths)


def collect_processes(proc_root: Path = Path("/proc"), *, agent_id: str, max_processes: int = 20_000,
                      include_command_lines: bool = False,
                      target_pids: set[int] | None = None,
                      cgroup_root: Path = Path("/sys/fs/cgroup")) -> tuple[list[dict], list[dict], dict]:
    """Collect crypto-relevant process mappings without executing a target."""
    boot_id = _read_text(proc_root / "sys/kernel/random/boot_id", 256).strip()[:128]
    processes: list[dict] = []
    observations: list[dict] = []
    denied = 0
    inspected = 0
    try:
        candidates = sorted(
            (
                item for item in proc_root.iterdir()
                if item.name.isdigit() and (target_pids is None or int(item.name) in target_pids)
            ),
            key=lambda item: int(item.name),
        )
    except OSError:
        return [], [], {"boot_id": boot_id, "inspected": 0, "denied": 1, "crypto_processes": 0}
    for process_dir in candidates[:max(1, min(max_processes, 100_000))]:
        inspected += 1
        maps_text = _read_text(process_dir / "maps", 16_000_000)
        if not maps_text:
            denied += 1
            continue
        libraries = _mapped_crypto_libraries(maps_text)
        if not libraries:
            continue
        pid = int(process_dir.name)
        start_ticks = _start_time_ticks(_read_text(process_dir / "stat", 64_000))
        status_text = _read_text(process_dir / "status", 256_000)
        pid_hierarchy = _pid_hierarchy(
            status_text, pid, _read_text(process_dir / "sched", 64_000),
        )
        try:
            executable = os.readlink(process_dir / "exe")[:4096]
        except OSError:
            executable = ""
        command = ""
        if include_command_lines:
            raw = _read_text(process_dir / "cmdline", 64_000).replace("\x00", " ").strip()
            command = redact_command(raw)
        process_instance_id = stable_id("proc", agent_id, boot_id, pid, start_ticks)
        cgroup_text = _read_text(process_dir / "cgroup", 256_000)
        container = container_identity(cgroup_text)
        cgroup_id = _cgroup_v2_id(cgroup_text, cgroup_root)
        process = {
            "process_instance_id": process_instance_id,
            "pid": pid,
            "start_time_ticks": start_ticks,
            "executable": executable,
            "command": command,
            "uid": _uid(status_text),
            "mapped_crypto_libraries": libraries,
            "container": container,
            "namespaces": _namespaces(process_dir),
            "metadata": {
                "proc_root": str(proc_root),
                "command_line_collected": include_command_lines,
                "pid_hierarchy": pid_hierarchy,
                "ebpf_trace_pid": pid_hierarchy[0],
                "cgroup_v2_id": cgroup_id,
            },
        }
        processes.append(process)
        for library in libraries:
            observations.append({
                "process_instance_id": process_instance_id,
                "pid": pid,
                "start_time_ticks": start_ticks,
                "evidence_type": "runtime_mapped_library",
                "method": Path(library).name,
                "library": library,
                "source": "proc_maps",
                "observed_at": utc_now(),
                "count": 1,
                "metadata": {"loaded_not_called": True},
            })
    return processes, observations, {
        "boot_id": boot_id, "inspected": inspected, "denied": denied, "crypto_processes": len(processes),
    }


def import_runtime_events(paths: list[Path], processes: list[dict], max_events: int = 20_000) -> list[dict]:
    """Link authorized imported eBPF traces to currently observed processes."""
    by_pid = {int(item["pid"]): item for item in processes}
    output: list[dict] = []
    remaining = max(0, max_events)
    for path in paths:
        if remaining <= 0:
            break
        for signal in ebpf_evidence(parse_trace(path, remaining), str(path)):
            pid = int(signal.get("metadata", {}).get("pid", 0))
            process = by_pid.get(pid)
            if process is None:
                continue
            output.append({
                "process_instance_id": process["process_instance_id"],
                "pid": pid,
                "start_time_ticks": process["start_time_ticks"],
                "evidence_type": "runtime_crypto_api",
                "method": signal["method"],
                "library": signal.get("library", ""),
                "source": "imported_trace",
                "observed_at": utc_now(),
                "count": 1,
                "metadata": {"trace_path": str(path), "observed_call": True},
            })
            remaining -= 1
            if remaining <= 0:
                break
    return output


def agent_metadata() -> dict:
    return {
        "hostname": socket.gethostname(),
        "kernel": os.uname().release if hasattr(os, "uname") else "",
        "platform": os.uname().sysname if hasattr(os, "uname") else "linux",
    }
