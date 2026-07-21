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
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable


SAFE_LIBRARY = re.compile(r"^[A-Za-z0-9_./+@-]+$")
CRYPTO_METHOD = re.compile(
    r"^(?:SSL_|EVP_|RSA_|EC_KEY_|ECDSA_|ECDH_|OQS_|crypto_(?:box|sign|kx|secretbox|aead|pwhash))"
)

# Ordered by observation value.  Keep this list exact and deliberately small:
# wildcarding every SSL_/EVP_ export creates hundreds or thousands of BPF
# programs and can prevent bpftrace from loading any probe at all.
HIGH_VALUE_CRYPTO_SYMBOLS = (
    # TLS connection lifecycle and data path.
    "SSL_new",
    "SSL_accept",
    "SSL_connect",
    "SSL_do_handshake",
    "SSL_read_ex",
    "SSL_write_ex",
    "SSL_read",
    "SSL_write",
    "SSL_shutdown",
    "SSL_free",
    "SSL_CTX_new_ex",
    "SSL_CTX_new",
    # Provider/algorithm selection and digest/signature operations.
    "EVP_PKEY_CTX_new_from_name",
    "EVP_MD_fetch",
    "EVP_CIPHER_fetch",
    "EVP_MAC_fetch",
    "EVP_KDF_fetch",
    "EVP_DigestInit_ex",
    "EVP_DigestSignInit_ex",
    "EVP_DigestSignInit",
    "EVP_DigestVerifyInit_ex",
    "EVP_DigestVerifyInit",
    # Symmetric encryption, message authentication and key derivation.
    "EVP_CipherInit_ex",
    "EVP_EncryptInit_ex",
    "EVP_DecryptInit_ex",
    "EVP_MAC_init",
    "EVP_KDF_derive",
    # Public-key generation, signing, agreement and encryption.
    "EVP_PKEY_keygen_init",
    "EVP_PKEY_keygen",
    "EVP_PKEY_sign_init",
    "EVP_PKEY_sign",
    "EVP_PKEY_verify_init",
    "EVP_PKEY_verify",
    "EVP_PKEY_derive_init",
    "EVP_PKEY_derive",
    "EVP_PKEY_encrypt_init",
    "EVP_PKEY_encrypt",
    "EVP_PKEY_decrypt_init",
    "EVP_PKEY_decrypt",
    # OpenSSL 3.2+ key encapsulation, including post-quantum KEM use.
    "EVP_PKEY_encapsulate_init",
    "EVP_PKEY_encapsulate",
    "EVP_PKEY_decapsulate_init",
    "EVP_PKEY_decapsulate",
    # Common legacy direct interfaces still relevant to migration inventory.
    "RSA_sign",
    "RSA_verify",
    "RSA_public_encrypt",
    "RSA_private_decrypt",
    "ECDSA_sign",
    "ECDSA_verify",
    "ECDH_compute_key",
    # Common libsodium entry points.
    "crypto_sign",
    "crypto_sign_open",
    "crypto_box_easy",
    "crypto_box_open_easy",
    "crypto_kx_client_session_keys",
    "crypto_kx_server_session_keys",
    "crypto_secretbox_easy",
    "crypto_secretbox_open_easy",
    "crypto_aead_chacha20poly1305_ietf_encrypt",
    "crypto_aead_chacha20poly1305_ietf_decrypt",
    "crypto_pwhash",
)
MAX_PROBE_SYMBOLS = 64


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
    symbols = exported_crypto_symbols(resolved, max_symbols=MAX_PROBE_SYMBOLS)
    if not symbols:
        return [], {
            "enabled": True, "pid": pid, "library": str(resolved), "duration_seconds": duration,
            "events": 0, "probes": 0, "status": "no-eligible-probes",
            "probe_strategy": "high-value-allowlist-v1",
        }
    probes = ",\n".join(f"uprobe:{resolved}:{symbol}" for symbol in symbols)
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
        "events": len(events), "probes": len(symbols), "collector": bpftrace,
        "status": "completed", "probe_strategy": "high-value-allowlist-v1",
        "temporary_reference": str(temporary),
    }


def exported_crypto_symbols(library: Path, nm: str = "nm", max_symbols: int = MAX_PROBE_SYMBOLS) -> list[str]:
    """Return exported symbols selected by the ordered high-value allowlist."""
    try:
        process = subprocess.run(
            [nm, "-D", "--defined-only", str(library)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if process.returncode != 0:
        return []
    exported: set[str] = set()
    for line in process.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if not parts:
            continue
        symbol = parts[-1].split("@", 1)[0]
        if CRYPTO_METHOD.match(symbol):
            exported.add(symbol)
    limit = max(1, min(max_symbols, MAX_PROBE_SYMBOLS))
    return [symbol for symbol in HIGH_VALUE_CRYPTO_SYMBOLS if symbol in exported][:limit]


def observe_processes(processes: list[dict], duration: int, *, bpftrace: str = "bpftrace", nm: str = "nm",
                      host_root: Path | None = None, proc_root: Path | None = None,
                      probe_proc_root: Path | None = None,
                      max_libraries: int = 16, max_symbols: int = MAX_PROBE_SYMBOLS,
                      runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> tuple[list[dict], dict]:
    """Observe a bounded set of running processes using generated exact probes.

    Probe targets come only from libraries already mapped by the selected
    processes, and symbols must match the fixed crypto allowlist. No arbitrary
    bpftrace program or target command is accepted from the API.
    """
    if duration < 1 or duration > 300:
        raise ValueError("eBPF duration must be between 1 and 300 seconds")
    pids = sorted({int(item.get("pid", 0)) for item in processes if int(item.get("pid", 0)) > 0})
    maximum_libraries = max(1, min(max_libraries, 128))
    # Keep /proc/PID/root in the target path.  Resolving this Linux magic
    # symlink can turn a container path such as
    # /host/proc/PID/root/opt/openssl/lib/libssl.so.3 into
    # /opt/openssl/lib/libssl.so.3 in the Agent's own mount namespace.  The
    # latter may name a different inode, or may not exist at all.
    targets: list[dict] = []
    targets_by_key: dict[tuple[str, str], dict] = {}
    for item in sorted(processes, key=lambda row: int(row.get("pid", 0))):
        pid = int(item.get("pid", 0))
        try:
            cgroup_id = int(item.get("metadata", {}).get("cgroup_v2_id", 0))
        except (TypeError, ValueError):
            cgroup_id = 0
        if cgroup_id < 1:
            cgroup_id = 0
        raw_hierarchy = item.get("metadata", {}).get("pid_hierarchy", [])
        pid_hierarchy = []
        if isinstance(raw_hierarchy, list):
            for value in raw_hierarchy[:16]:
                try:
                    candidate_pid = int(value)
                except (TypeError, ValueError):
                    continue
                if candidate_pid > 0:
                    pid_hierarchy.append(candidate_pid)
        trace_pid = pid_hierarchy[0] if pid_hierarchy else pid
        for value in sorted(item.get("mapped_crypto_libraries", [])):
            logical = str(value)
            logical_path = Path(logical)
            if (
                pid < 1 or not logical_path.is_absolute()
                or ".." in logical_path.parts
                or not SAFE_LIBRARY.fullmatch(logical)
            ):
                continue
            if proc_root is not None:
                # Discovery may use a bind-mounted /host/proc.  When the Agent
                # shares the host PID namespace, /proc is the equivalent path
                # used to locate the target inode.  A separate short alias is
                # created below before this path is passed to bpftrace.
                attach_root = probe_proc_root if probe_proc_root is not None else proc_root
                actual = attach_root / str(pid) / "root" / logical.lstrip("/")
                mount_namespace = str(item.get("namespaces", {}).get("mnt", ""))
                namespace_key = mount_namespace or f"pid:{pid}"
            elif host_root is not None:
                actual = host_root / logical.lstrip("/")
                namespace_key = f"host-root:{host_root}"
            else:
                actual = Path(logical).resolve()
                namespace_key = "agent-root"
            target_key = (namespace_key, logical)
            if target_key in targets_by_key:
                target = targets_by_key[target_key]
                target["pids"].add(pid)
                if cgroup_id:
                    target["cgroup_pid_map"].setdefault(cgroup_id, set()).add(pid)
                else:
                    target["trace_pid_map"][trace_pid] = pid
                container_id = str(item.get("container", {}).get("id", ""))
                if container_id:
                    target["container_ids"].add(container_id)
                continue
            if len(targets) >= maximum_libraries:
                continue
            target = {
                "actual": actual, "logical": logical, "pid": pid,
                "namespace_key": namespace_key, "pids": {pid},
                "trace_pid_map": {} if cgroup_id else {trace_pid: pid},
                "cgroup_pid_map": {cgroup_id: {pid}} if cgroup_id else {},
                "container_ids": {
                    str(item.get("container", {}).get("id", ""))
                } - {""},
            }
            targets_by_key[target_key] = target
            targets.append(target)
    candidates: list[tuple[str, str, str, str, int, str, tuple[tuple[int, int], ...]]] = []
    for target in targets:
        actual = target["actual"]
        logical = target["logical"]
        pid = target["pid"]
        namespace_key = target["namespace_key"]
        if not actual.is_file() or not SAFE_LIBRARY.fullmatch(str(actual)):
            continue
        for symbol in exported_crypto_symbols(actual, nm, MAX_PROBE_SYMBOLS):
            candidates.append((
                f"uprobe:{actual}:{symbol}", symbol, logical,
                str(actual), pid, namespace_key,
                tuple(sorted(target["trace_pid_map"].items())),
            ))
    priority = {symbol: index for index, symbol in enumerate(HIGH_VALUE_CRYPTO_SYMBOLS)}
    candidates.sort(key=lambda row: (priority[row[1]], row[2], row[0]))
    probe_limit = max(1, min(max_symbols, MAX_PROBE_SYMBOLS))
    probe_rows = candidates[:probe_limit]
    if not pids or not probe_rows:
        return [], {
            "enabled": True, "duration_seconds": duration, "events": 0,
            "processes": len(pids), "libraries": len(targets), "probes": 0,
            "eligible_probes": len(candidates), "probe_limit": probe_limit,
            "truncated": False, "status": "no-eligible-probes",
            "probe_strategy": "high-value-allowlist-v6-cgroup-attribution",
        }
    # bpftrace derives the tracefs event name from the attachment path.  Paths
    # such as /proc/PID/root/opt/openssl/lib/libssl.so.3 can exceed the kernel's
    # event-name limit even though they resolve to a valid library.  Attach via
    # private, per-collection aliases (for example /tmp/pqe-XXXX/p0) while
    # retaining the original path for symbol discovery and evidence metadata.
    # The aliases exist until every bpftrace child has exited, then are removed.
    successful_rows: list[tuple] = []
    failed_targets: list[dict] = []
    output_lines: list[str] = []
    attachment_aliases: dict[str, str] = {}
    targets_by_actual = {str(target["actual"]): target for target in targets}
    with tempfile.TemporaryDirectory(prefix="pqe-", dir="/tmp") as alias_directory:
        alias_root = Path(alias_directory)
        for index, actual in enumerate(dict.fromkeys(row[3] for row in probe_rows)):
            alias = alias_root / f"p{index}"
            try:
                alias.symlink_to(actual)
            except OSError as exc:
                rows = [row for row in probe_rows if row[3] == actual]
                failed_targets.append({
                    "pid": rows[0][4], "library": rows[0][2], "target": actual,
                    "mount_namespace": rows[0][5], "probes": len(rows),
                    "error": f"could not create short uprobe alias: {exc}"[:1000],
                })
                continue
            attachment_aliases[actual] = str(alias)

        # Replace only the bpftrace attachment path.  Tuple positions 1 onward
        # continue to describe the real target and its logical container path.
        runnable_rows = [
            (f"uprobe:{attachment_aliases[row[3]]}:{row[1]}", *row[1:])
            for row in probe_rows if row[3] in attachment_aliases
        ]
        # Load each library independently.  One unsupported target must not
        # tear down probes selected for unrelated containers or libraries.
        grouped_rows: dict[str, list[tuple]] = {}
        for row in runnable_rows:
            grouped_rows.setdefault(row[3], []).append(row)

        def run_target(rows: list[tuple]) -> tuple[subprocess.CompletedProcess | None, str]:
            target = targets_by_actual[rows[0][3]]
            cgroup_ids = sorted(target["cgroup_pid_map"])
            trace_pids = sorted({trace_pid for row in rows for trace_pid, _pid in row[6]})
            filters = [f"cgroup == {cgroup_id}" for cgroup_id in cgroup_ids]
            filters.extend(f"pid == {pid}" for pid in trace_pids)
            target_filter = " || ".join(filters)
            probes = ",\n".join(row[0] for row in rows)
            program = (
                f"{probes}\n/{target_filter}/ "
                "{ printf(\"%d\\t%llu\\t%s\\t%s\\n\", pid, cgroup, comm, probe); }\n"
                f"interval:s:{duration} {{ exit(); }}"
            )
            try:
                process = runner(
                    [bpftrace, "-q", "-e", program], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=duration + 20, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return None, str(exc)
            if process.returncode != 0:
                error = process.stderr.decode("utf-8", "replace")[-1000:].strip()
                return process, f"bpftrace exited with {process.returncode}: {error}"
            return process, ""

        results: dict[str, tuple[subprocess.CompletedProcess | None, str]] = {}
        if grouped_rows:
            with ThreadPoolExecutor(max_workers=min(4, len(grouped_rows))) as executor:
                pending = {
                    executor.submit(run_target, rows): actual
                    for actual, rows in grouped_rows.items()
                }
                for future in as_completed(pending):
                    actual = pending[future]
                    try:
                        results[actual] = future.result()
                    except Exception as exc:  # Defensive boundary around injected runners.
                        results[actual] = (None, str(exc))

        for actual, rows in grouped_rows.items():
            process, error = results[actual]
            if error:
                failed_targets.append({
                    "pid": rows[0][4], "library": rows[0][2], "target": actual,
                    "attachment_alias": attachment_aliases[actual],
                    "mount_namespace": rows[0][5], "probes": len(rows),
                    "error": error[:1000],
                })
                continue
            successful_rows.extend(rows)
            if process is not None:
                output_lines.extend(process.stdout.decode("utf-8", "replace").splitlines())

    probe_libraries: dict[str, str] = {}
    symbol_libraries: dict[str, str] = {}
    trace_pid_map: dict[int, int] = {}
    cgroup_pid_candidates: dict[int, set[int]] = {}
    for probe, symbol, logical, _actual, _pid, _namespace_key, pid_pairs in successful_rows:
        probe_libraries[probe] = logical
        symbol_libraries.setdefault(symbol, logical)
        for trace_pid, discovered_pid in pid_pairs:
            trace_pid_map[trace_pid] = discovered_pid
        target = targets_by_actual[_actual]
        for cgroup_id, discovered_pids in target["cgroup_pid_map"].items():
            cgroup_pid_candidates.setdefault(cgroup_id, set()).update(discovered_pids)
    events: list[dict] = []
    allowed_pids = set(pids)
    processes_by_pid = {int(item.get("pid", 0)): item for item in processes}
    for line in output_lines:
        parts = line.split("\t", 3)
        if len(parts) == 4:
            trace_pid_text, cgroup_id_text, command, probe_name = parts
        elif len(parts) == 3:  # Compatibility with imported/fake v5 output.
            trace_pid_text, command, probe_name = parts
            cgroup_id_text = "0"
        else:
            continue
        try:
            trace_pid = int(trace_pid_text)
            cgroup_id = int(cgroup_id_text)
        except ValueError:
            continue
        candidate_pids = sorted(cgroup_pid_candidates.get(cgroup_id, set()))
        if candidate_pids:
            command_matches = [
                candidate_pid for candidate_pid in candidate_pids
                if Path(str(processes_by_pid.get(candidate_pid, {}).get("executable", ""))).name == command
            ]
            pid = min(command_matches or candidate_pids)
            attribution = "cgroup"
        else:
            pid = trace_pid_map.get(trace_pid, trace_pid)
            candidate_pids = [pid]
            attribution = "root-pid"
        method = probe_name.rsplit(":", 1)[-1].split("@", 1)[0]
        if pid not in allowed_pids or not CRYPTO_METHOD.match(method):
            continue
        events.append({
            "pid": pid, "command": command[:256], "method": method,
            "library": probe_libraries.get(probe_name, symbol_libraries.get(method, "")),
            "trace_pid": trace_pid, "cgroup_id": cgroup_id,
            "attribution": attribution, "candidate_pids": candidate_pids[:128],
        })
    selected_targets: list[dict] = []
    seen_selected_targets: set[str] = set()
    for _probe, _symbol, logical, actual, pid, namespace_key, pid_pairs in successful_rows:
        if actual in seen_selected_targets:
            continue
        seen_selected_targets.add(actual)
        target = targets_by_actual[actual]
        selected_targets.append({
            "pid": pid, "library": logical, "target": actual,
            "attachment_alias": attachment_aliases[actual],
            "mount_namespace": namespace_key,
            "pids": sorted(target["pids"]),
            "trace_pids": sorted({trace_pid for trace_pid, _discovered_pid in pid_pairs}),
            "cgroup_ids": sorted(target["cgroup_pid_map"]),
            "container_ids": sorted(target["container_ids"]),
            "attribution_mode": "cgroup" if target["cgroup_pid_map"] else "root-pid",
        })
    if successful_rows and failed_targets:
        status = "partial"
    elif successful_rows:
        status = "completed"
    else:
        status = "failed"
    result_status = {
        "enabled": True, "duration_seconds": duration, "events": len(events),
        "processes": len(pids), "libraries": len(targets), "probes": len(successful_rows),
        "selected_probes": len(probe_rows), "failed_probes": len(probe_rows) - len(successful_rows),
        "eligible_probes": len(candidates), "probe_limit": probe_limit,
        "truncated": len(candidates) > len(probe_rows),
        "collector": bpftrace, "status": status,
        "probe_strategy": "high-value-allowlist-v6-cgroup-attribution",
        "probe_targets": selected_targets,
        "failed_targets": failed_targets,
    }
    if failed_targets:
        result_status["error"] = f"{len(failed_targets)} probe target(s) could not be attached"
    return events, result_status


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
