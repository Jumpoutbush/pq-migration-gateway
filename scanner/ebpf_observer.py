#!/usr/bin/env python3
"""Optional, explicitly enabled eBPF uprobe collector for crypto interfaces.

The collector uses a fixed bpftrace program and never executes the target. It
requires host bpftrace plus the privileges needed for uprobes. Deterministic
tests import previously captured TSV/JSONL events instead of requiring eBPF.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


SAFE_LIBRARY = re.compile(r"^[A-Za-z0-9_./+@-]+$")
CRYPTO_METHOD = re.compile(
    r"^(?:SSL_|EVP_|RSA_|EC_KEY_|ECDSA_|ECDH_|OQS_|crypto_(?:box|sign|kx|secretbox|aead|pwhash))"
)
PROBE_PREFIXES = ("SSL_*", "EVP_*", "RSA_*", "EC_KEY_*", "ECDSA_*", "ECDH_*", "OQS_*")


def parse_trace(path: Path, max_events: int = 100_000) -> list[dict]:
    """Parse bounded JSONL or ``pid<TAB>comm<TAB>method`` observations."""
    events: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events
    for line in lines[:max_events]:
        line = line.strip()
        if not line:
            continue
        pid = 0
        command = ""
        method = ""
        library = ""
        if line.startswith("{"):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            pid = int(item.get("pid", 0))
            command = str(item.get("command", item.get("comm", "")))[:256]
            method = str(item.get("method", ""))[:240]
            library = str(item.get("library", ""))[:1000]
        else:
            parts = line.split("\t", 3)
            if len(parts) < 3:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            command, method = parts[1][:256], parts[2][:240]
            library = parts[3][:1000] if len(parts) > 3 else ""
        method = method.rsplit(":", 1)[-1]
        if pid < 1 or not CRYPTO_METHOD.match(method):
            continue
        events.append({"pid": pid, "command": command, "method": method, "library": library})
    return events


def observe(pid: int, library: Path, duration: int, bpftrace: str = "bpftrace") -> tuple[list[dict], dict]:
    """Attach a fixed, bounded uprobe program to one authorized process/library."""
    if pid < 1:
        raise ValueError("eBPF pid must be positive")
    if duration < 1 or duration > 300:
        raise ValueError("eBPF duration must be between 1 and 300 seconds")
    resolved = library.resolve()
    if not resolved.is_file() or not SAFE_LIBRARY.fullmatch(str(resolved)):
        raise ValueError("eBPF library must be an existing absolute path with safe characters")
    probes = ",\n".join(f"uprobe:{resolved}:{prefix}" for prefix in PROBE_PREFIXES)
    program = (
        f"{probes}\n/pid == {pid}/ "
        "{ printf(\"%d\\t%s\\t%s\\n\", pid, comm, probe); }\n"
        f"interval:s:{duration} {{ exit(); }}"
    )
    try:
        process = subprocess.run(
            [bpftrace, "-q", "-e", program], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=duration + 15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"eBPF observer failed: {exc}") from exc
    if process.returncode != 0:
        error = process.stderr.decode("utf-8", "replace")[-2000:]
        raise RuntimeError(f"bpftrace exited with {process.returncode}: {error}")
    temporary = Path("/tmp") / f"pq-ebpf-{pid}.tsv"
    # Parse in memory using the same validation as imported traces.
    events = []
    for line in process.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        method = parts[2].rsplit(":", 1)[-1]
        if CRYPTO_METHOD.match(method):
            events.append({"pid": pid, "command": parts[1][:256], "method": method, "library": str(resolved)})
    return events, {
        "enabled": True, "pid": pid, "library": str(resolved), "duration_seconds": duration,
        "events": len(events), "collector": bpftrace, "temporary_reference": str(temporary),
    }


def evidence(events: list[dict], trace_path: str = "") -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[int, str, str]] = set()
    for item in events:
        key = (int(item["pid"]), str(item["method"]), str(item.get("library", "")))
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "path": trace_path or str(item.get("library", "")), "line": 0,
            "evidence_type": "runtime_crypto_api", "algorithm": "runtime-selected",
            "excerpt": f"pid={item['pid']} observed {item['method']}", "language": "runtime",
            "method": item["method"], "library": item.get("library", ""), "confidence": "HIGH",
            "artifact_type": "runtime_process", "source": "ebpf_uprobe",
            "metadata": {"pid": item["pid"], "command": item.get("command", ""), "observed_call": True},
        })
    return rows
