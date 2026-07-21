from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from manager.api_client import ApiError, ManagerApiClient
from manager.config_store import ConfigStore
from manager.manager_api import ApiHandler
from manager.runtime_ingest import normalize_runtime_report
from manager.scan_orchestrator import ScanOrchestrator
from scanner.ebpf_observer import HIGH_VALUE_CRYPTO_SYMBOLS, MAX_PROBE_SYMBOLS, observe_processes
from scanner.runtime_collector import collect_processes, import_runtime_events


def first_uprobe_target(program: str) -> Path:
    """Return the attachment path from the first generated uprobe clause."""
    first_probe = next(line.rstrip(",") for line in program.splitlines() if line.startswith("uprobe:"))
    return Path(first_probe.split(":", 2)[1])


class RuntimeCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "proc"
        pid = self.root / "321"
        (self.root / "sys/kernel/random").mkdir(parents=True)
        (self.root / "sys/kernel/random/boot_id").write_text("boot-for-test\n", encoding="utf-8")
        (pid / "ns").mkdir(parents=True)
        (pid / "maps").write_text(
            "7f00-7f10 r-xp 00000000 08:01 1 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
            "7f20-7f30 r-xp 00000000 08:01 2 /usr/lib/x86_64-linux-gnu/libcrypto.so.3\n",
            encoding="utf-8",
        )
        after_comm = ["S"] + ["0"] * 18 + ["4242"]
        (pid / "stat").write_text("321 (payment worker) " + " ".join(after_comm) + "\n", encoding="utf-8")
        (pid / "status").write_text(
            "Name:\tpayment\nUid:\t1001\t1001\t1001\t1001\nNSpid:\t77\t321\n",
            encoding="utf-8",
        )
        (pid / "sched").write_text(
            "payment worker (77, #threads: 1)\n",
            encoding="utf-8",
        )
        (pid / "cmdline").write_bytes(b"payment\x00--token\x00secret-value\x00")
        container_id = "a" * 64
        (pid / "cgroup").write_text(f"0::/system.slice/docker-{container_id}.scope\n", encoding="utf-8")
        self.cgroup_root = Path(self.temp.name) / "cgroup"
        (self.cgroup_root / "system.slice" / f"docker-{container_id}.scope").mkdir(parents=True)
        (pid / "exe").symlink_to("/opt/payment/bin/payment")
        for name in ("pid", "mnt", "net", "user"):
            (pid / "ns" / name).symlink_to(f"{name}:[1234]")
        self.trace = Path(self.temp.name) / "trace.jsonl"
        self.trace.write_text(json.dumps({
            "pid": 321, "command": "payment", "method": "RSA_public_encrypt",
            "library": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        }) + "\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_proc_container_and_trace_collection(self):
        processes, observations, stats = collect_processes(
            self.root, agent_id="runtime-test", include_command_lines=True,
            cgroup_root=self.cgroup_root,
        )
        self.assertEqual(stats["crypto_processes"], 1)
        self.assertEqual(len(processes), 1)
        process = processes[0]
        self.assertEqual(process["start_time_ticks"], 4242)
        self.assertEqual(process["container"]["runtime"], "docker")
        self.assertEqual(process["container"]["id"], "a" * 64)
        self.assertEqual(process["metadata"]["pid_hierarchy"], [77, 321])
        self.assertEqual(process["metadata"]["ebpf_trace_pid"], 77)
        self.assertEqual(
            process["metadata"]["cgroup_v2_id"],
            (self.cgroup_root / "system.slice" / f"docker-{'a' * 64}.scope").stat().st_ino,
        )
        self.assertNotIn("secret-value", process["command"])
        self.assertEqual(len(observations), 2)
        calls = import_runtime_events([self.trace], processes)
        self.assertEqual(calls[0]["method"], "RSA_public_encrypt")
        report = normalize_runtime_report({
            "schema_version": 1, "batch_id": "batch-test", "collected_at": "2026-07-20T00:00:00+00:00",
            "agent": {"id": "runtime-test", "hostname": "host", "version": "3.7.0", "boot_id": stats["boot_id"]},
            "processes": processes, "observations": observations + calls,
        })
        self.assertEqual(report["summary"]["runtime_call_observations"], 1)
        self.assertEqual(report["observations"][-1]["pq_status"], "quantum_vulnerable")

    def test_sched_supplies_root_pid_omitted_by_bind_mounted_procfs(self):
        pid = self.root / "321"
        (pid / "status").write_text(
            "Name:\tpayment\nUid:\t1001\t1001\t1001\t1001\nNSpid:\t321\n",
            encoding="utf-8",
        )
        (pid / "sched").write_text(
            "payment worker (77, #threads: 1)\n",
            encoding="utf-8",
        )

        processes, _observations, _stats = collect_processes(
            self.root, agent_id="runtime-test",
        )

        self.assertEqual(processes[0]["metadata"]["pid_hierarchy"], [77, 321])
        self.assertEqual(processes[0]["metadata"]["ebpf_trace_pid"], 77)

    def test_pid_scope_excludes_unselected_processes(self):
        processes, observations, stats = collect_processes(
            self.root, agent_id="runtime-test", target_pids={999},
        )
        self.assertEqual(processes, [])
        self.assertEqual(observations, [])
        self.assertEqual(stats["inspected"], 0)

    def test_fixed_ebpf_probe_generation_is_allowlisted(self):
        library = Path(self.temp.name) / "libcrypto.so.3"
        library.write_bytes(b"ELF")
        fake_nm = Path(self.temp.name) / "nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T RSA_sign\\n0001 T unrelated_symbol\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []

        def runner(args, **kwargs):
            captured.append(args)
            return subprocess.CompletedProcess(args, 0, stdout=f"321\tpayment\tuprobe:{library}:RSA_sign\n".encode(), stderr=b"")

        events, status = observe_processes([
            {"pid": 321, "mapped_crypto_libraries": [str(library)]},
        ], 1, nm=str(fake_nm), runner=runner)
        self.assertEqual(status["probes"], 1)
        self.assertEqual(events[0]["method"], "RSA_sign")
        self.assertIn("RSA_sign", captured[0][-1])
        self.assertNotIn("unrelated_symbol", captured[0][-1])

    def test_ebpf_preserves_target_process_root_path(self):
        proc_root = Path(self.temp.name) / "host-proc"
        container_root = Path(self.temp.name) / "container-root"
        library = container_root / "usr/lib/libcrypto.so.3"
        library.parent.mkdir(parents=True)
        library.write_bytes(b"ELF")
        process_root = proc_root / "321"
        process_root.mkdir(parents=True)
        (process_root / "root").symlink_to(container_root)
        fake_nm = Path(self.temp.name) / "container-nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T RSA_sign\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []
        expected_target = proc_root / "321" / "root" / "usr/lib/libcrypto.so.3"

        def runner(args, **kwargs):
            captured.append(args)
            alias = first_uprobe_target(args[-1])
            self.assertTrue(alias.is_symlink())
            self.assertEqual(alias.readlink(), expected_target)
            return subprocess.CompletedProcess(
                args, 0, stdout=f"321\tpayment\tuprobe:{alias}:RSA_sign\n".encode(), stderr=b"",
            )

        events, status = observe_processes([
            {
                "pid": 321,
                "mapped_crypto_libraries": ["/usr/lib/libcrypto.so.3"],
                "namespaces": {"mnt": "mnt:[1234]"},
            },
        ], 1, nm=str(fake_nm), proc_root=proc_root, runner=runner)
        self.assertEqual(status["probes"], 1)
        self.assertEqual(events[0]["library"], "/usr/lib/libcrypto.so.3")
        self.assertNotIn(str(expected_target), captured[0][-1])
        self.assertNotEqual(str(expected_target), str(expected_target.resolve()))
        self.assertEqual(status["probe_targets"][0]["target"], str(expected_target))
        alias = Path(status["probe_targets"][0]["attachment_alias"])
        self.assertTrue(str(alias).startswith("/tmp/pqe-"))
        self.assertFalse(alias.exists())

    def test_ebpf_deduplicates_processes_in_same_mount_namespace(self):
        proc_root = Path(self.temp.name) / "host-proc"
        container_root = Path(self.temp.name) / "container-root"
        library = container_root / "usr/lib/libssl.so.3"
        library.parent.mkdir(parents=True)
        library.write_bytes(b"ELF")
        for pid in (321, 322):
            process_root = proc_root / str(pid)
            process_root.mkdir(parents=True)
            (process_root / "root").symlink_to(container_root)
        fake_nm = Path(self.temp.name) / "container-nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T SSL_new\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []

        def runner(args, **kwargs):
            captured.append(args)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

        _events, status = observe_processes([
            {
                "pid": 321,
                "mapped_crypto_libraries": ["/usr/lib/libssl.so.3"],
                "namespaces": {"mnt": "mnt:[1234]"},
                "metadata": {"pid_hierarchy": [77, 321]},
            },
            {
                "pid": 322,
                "mapped_crypto_libraries": ["/usr/lib/libssl.so.3"],
                "namespaces": {"mnt": "mnt:[1234]"},
                "metadata": {"pid_hierarchy": [78, 322]},
            },
        ], 1, nm=str(fake_nm), proc_root=proc_root, runner=runner)
        self.assertEqual(status["libraries"], 1)
        self.assertEqual(status["probes"], 1)
        self.assertNotIn(str(proc_root / "321" / "root" / "usr/lib/libssl.so.3"), captured[0][-1])
        self.assertNotIn(str(proc_root / "322" / "root" / "usr/lib/libssl.so.3"), captured[0][-1])
        self.assertIn("pid == 77", captured[0][-1])
        self.assertIn("pid == 78", captured[0][-1])
        self.assertNotIn("pid == 321", captured[0][-1])
        self.assertNotIn("pid == 322", captured[0][-1])
        self.assertEqual(
            status["probe_targets"][0]["target"],
            str(proc_root / "321" / "root" / "usr/lib/libssl.so.3"),
        )
        self.assertEqual(status["probe_targets"][0]["pids"], [321, 322])
        self.assertEqual(status["probe_targets"][0]["trace_pids"], [77, 78])

    def test_ebpf_maps_outer_kernel_pid_back_to_discovered_pid(self):
        library = Path(self.temp.name) / "libssl.so.3"
        library.write_bytes(b"ELF")
        fake_nm = Path(self.temp.name) / "namespace-nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T SSL_new\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []

        def runner(args, **kwargs):
            captured.append(args)
            alias = first_uprobe_target(args[-1])
            return subprocess.CompletedProcess(
                args, 0, stdout=f"77\tnginx\tuprobe:{alias}:SSL_new\n".encode(), stderr=b"",
            )

        events, status = observe_processes([{
            "pid": 321,
            "mapped_crypto_libraries": [str(library)],
            "metadata": {"pid_hierarchy": [77, 321], "ebpf_trace_pid": 77},
        }], 1, nm=str(fake_nm), runner=runner)
        self.assertIn("/pid == 77/", captured[0][-1])
        self.assertNotIn("pid == 321", captured[0][-1])
        self.assertEqual(events[0]["trace_pid"], 77)
        self.assertEqual(events[0]["pid"], 321)
        self.assertEqual(status["probe_targets"][0]["pids"], [321])
        self.assertEqual(status["probe_targets"][0]["trace_pids"], [77])

    def test_ebpf_filters_and_attributes_by_cgroup_across_pid_namespaces(self):
        library = Path(self.temp.name) / "cgroup-libssl.so.3"
        library.write_bytes(b"ELF")
        fake_nm = Path(self.temp.name) / "cgroup-nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T SSL_new\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []

        def runner(args, **kwargs):
            captured.append(args)
            alias = first_uprobe_target(args[-1])
            return subprocess.CompletedProcess(
                args, 0,
                stdout=f"4467\t5351\tnginx\tuprobe:{alias}:SSL_new\n".encode(),
                stderr=b"",
            )

        events, status = observe_processes([{
            "pid": 36223,
            "executable": "/opt/nginx/sbin/nginx",
            "mapped_crypto_libraries": [str(library)],
            "container": {"id": "7" * 64},
            "metadata": {
                "pid_hierarchy": [36223],
                "ebpf_trace_pid": 36223,
                "cgroup_v2_id": 5351,
            },
        }], 1, nm=str(fake_nm), runner=runner)

        self.assertIn("cgroup == 5351", captured[0][-1])
        self.assertNotIn("pid == 36223", captured[0][-1])
        self.assertEqual(events[0]["trace_pid"], 4467)
        self.assertEqual(events[0]["pid"], 36223)
        self.assertEqual(events[0]["cgroup_id"], 5351)
        self.assertEqual(events[0]["attribution"], "cgroup")
        self.assertEqual(status["probe_targets"][0]["cgroup_ids"], [5351])
        self.assertEqual(status["probe_targets"][0]["attribution_mode"], "cgroup")

    def test_ebpf_uses_short_attachment_proc_root(self):
        discovery_root = Path(self.temp.name) / "host-proc"
        attachment_root = Path(self.temp.name) / "short-proc"
        container_root = Path(self.temp.name) / "container-root"
        library = container_root / "opt/openssl/lib/libssl.so.3"
        library.parent.mkdir(parents=True)
        library.write_bytes(b"ELF")
        for root in (discovery_root, attachment_root):
            process_root = root / "321"
            process_root.mkdir(parents=True)
            (process_root / "root").symlink_to(container_root)
        fake_nm = Path(self.temp.name) / "short-root-nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T SSL_new\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []
        expected = attachment_root / "321/root/opt/openssl/lib/libssl.so.3"

        def runner(args, **kwargs):
            captured.append(args)
            alias = first_uprobe_target(args[-1])
            self.assertEqual(alias.readlink(), expected)
            return subprocess.CompletedProcess(
                args, 0, stdout=f"321\tnginx\tuprobe:{alias}:SSL_new\n".encode(), stderr=b"",
            )

        events, status = observe_processes([{
            "pid": 321,
            "mapped_crypto_libraries": ["/opt/openssl/lib/libssl.so.3"],
            "namespaces": {"mnt": "mnt:[1234]"},
        }], 1, nm=str(fake_nm), proc_root=discovery_root,
            probe_proc_root=attachment_root, runner=runner)
        self.assertNotIn(str(expected), captured[0][-1])
        self.assertNotIn(str(discovery_root), captured[0][-1])
        self.assertEqual(status["probe_targets"][0]["target"], str(expected))
        self.assertTrue(status["probe_targets"][0]["attachment_alias"].startswith("/tmp/pqe-"))
        self.assertEqual(events[0]["method"], "SSL_new")

    def test_ebpf_isolates_a_failed_library_target(self):
        good = Path(self.temp.name) / "good-libssl.so.3"
        bad = Path(self.temp.name) / "bad-libcrypto.so.3"
        good.write_bytes(b"ELF")
        bad.write_bytes(b"ELF")
        fake_nm = Path(self.temp.name) / "isolation-nm"
        fake_nm.write_text("#!/bin/sh\nprintf '0000 T SSL_new\\n'\n", encoding="utf-8")
        fake_nm.chmod(0o755)

        def runner(args, **kwargs):
            alias = first_uprobe_target(args[-1])
            if alias.resolve() == bad.resolve():
                return subprocess.CompletedProcess(
                    args, 255, stdout=b"",
                    stderr=b"cannot attach uprobe, Invalid argument",
                )
            return subprocess.CompletedProcess(
                args, 0,
                stdout=f"321\tpayment\tuprobe:{alias}:SSL_new\n".encode(), stderr=b"",
            )

        events, status = observe_processes([
            {"pid": 321, "mapped_crypto_libraries": [str(good)]},
            {"pid": 322, "mapped_crypto_libraries": [str(bad)]},
        ], 1, nm=str(fake_nm), runner=runner)
        self.assertEqual(status["status"], "partial")
        self.assertEqual(status["probes"], 1)
        self.assertEqual(status["selected_probes"], 2)
        self.assertEqual(status["failed_probes"], 1)
        self.assertEqual(len(status["failed_targets"]), 1)
        self.assertEqual(status["failed_targets"][0]["target"], str(bad))
        self.assertEqual(events[0]["method"], "SSL_new")

    def test_ebpf_uses_high_value_allowlist_and_hard_probe_cap(self):
        library = Path(self.temp.name) / "libcrypto.so.3"
        library.write_bytes(b"ELF")
        fake_nm = Path(self.temp.name) / "many-symbols-nm"
        exported = list(HIGH_VALUE_CRYPTO_SYMBOLS) + [f"EVP_low_value_{index}" for index in range(600)]
        fake_nm.write_text(
            "#!/bin/sh\nprintf '%s\\n' "
            + " ".join(repr(f"0000 T {symbol}") for symbol in exported)
            + "\n",
            encoding="utf-8",
        )
        fake_nm.chmod(0o755)
        captured: list[list[str]] = []

        def runner(args, **kwargs):
            captured.append(args)
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

        _events, status = observe_processes(
            [{"pid": 321, "mapped_crypto_libraries": [str(library)]}],
            1, nm=str(fake_nm), max_symbols=2000, runner=runner,
        )
        self.assertLessEqual(status["probes"], MAX_PROBE_SYMBOLS)
        self.assertEqual(status["probe_limit"], MAX_PROBE_SYMBOLS)
        self.assertEqual(status["probe_strategy"], "high-value-allowlist-v6-cgroup-attribution")
        self.assertNotIn("EVP_low_value_0", captured[0][-1])


class RuntimeApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        allowed = root / "authorized"
        allowed.mkdir()
        self.store = ConfigStore(root / "control.db")
        self.scanner = ScanOrchestrator(self.store, root / "control", [allowed])
        ApiHandler.store = self.store
        ApiHandler.control_dir = root / "control"
        ApiHandler.token = "manager-token"
        ApiHandler.runtime_agent_token = "runtime-token"
        ApiHandler.metrics_public = True
        ApiHandler.scanner = self.scanner
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.manager = ManagerApiClient(self.base, "manager-token", "test-manager")
        self.agent = ManagerApiClient(self.base, "runtime-token", "runtime-agent:test")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.scanner.close()
        ApiHandler.runtime_agent_token = ""
        self.temp.cleanup()

    @staticmethod
    def report() -> dict:
        return {
            "schema_version": 1,
            "batch_id": "batch-api-test",
            "collected_at": "2026-07-20T00:00:00+00:00",
            "agent": {
                "id": "runtime-agent-1", "hostname": "backend-1", "version": "3.7.0",
                "boot_id": "boot-1", "mode": "host", "capabilities": ["proc-maps", "fixed-ebpf-uprobes"],
            },
            "processes": [{
                "pid": 77, "start_time_ticks": 12345, "executable": "/opt/payment/payment",
                "command": "", "uid": 1000,
                "mapped_crypto_libraries": ["/usr/lib/libssl.so.3", "/usr/lib/libcrypto.so.3"],
                "container": {"id": "b" * 64, "runtime": "containerd", "pod_uid": "pod-1", "cgroup": "/kubepods/test"},
            }],
            "observations": [
                {"pid": 77, "start_time_ticks": 12345, "evidence_type": "runtime_mapped_library", "method": "libssl.so.3", "library": "/usr/lib/libssl.so.3", "source": "proc_maps"},
                {"pid": 77, "start_time_ticks": 12345, "evidence_type": "runtime_crypto_api", "method": "RSA_sign", "library": "/usr/lib/libcrypto.so.3", "source": "ebpf_uprobe", "count": 3},
            ],
        }

    def test_runtime_report_reaches_normalized_asset_database_idempotently(self):
        with self.assertRaises(ApiError) as denied:
            self.manager.submit_runtime_report(self.report())
        self.assertEqual(denied.exception.status, 401)
        accepted = self.agent.submit_runtime_report(self.report())
        self.assertEqual(accepted["status"], "INGESTED")
        duplicate = self.agent.submit_runtime_report(self.report())
        self.assertEqual(duplicate["batch_id"], accepted["batch_id"])

        agents = self.manager.request("GET", "/v1/runtime/agents")
        self.assertEqual(agents["items"][0]["agent_id"], "runtime-agent-1")
        observations = self.manager.request("GET", "/v1/runtime/observations")
        call = next(item for item in observations["items"] if item["evidence_type"] == "runtime_crypto_api")
        self.assertEqual(call["observation_count"], 3)
        self.assertEqual(call["pq_status"], "quantum_vulnerable")
        assets = self.manager.request("GET", "/v1/assets")
        runtime_asset = next(item for item in assets["items"] if item["asset_type"] == "container_workload")
        detail = self.manager.request("GET", f"/v1/assets/{runtime_asset['asset_id']}")
        self.assertTrue(any(item["source"] == "ebpf_uprobe" for item in detail["evidence"]))
        status = self.manager.status()
        self.assertEqual(status["counts"]["runtime_agents"], 1)
        self.assertEqual(status["counts"]["runtime_observations"], 2)


class RuntimeDeploymentTests(unittest.TestCase):
    def test_compose_can_write_host_owned_spool(self):
        compose = (
            Path(__file__).resolve().parents[1]
            / "deploy/runtime-agent/docker-compose.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('user: "0:0"', compose)
        self.assertIn('"DAC_OVERRIDE"', compose)
        self.assertIn(
            "../../runtime-data/enterprise/runtime-agent:/var/lib/pq-runtime-agent",
            compose,
        )

    def test_ebpf_compose_bounds_probes_and_only_opens_tracing_mount(self):
        compose = (
            Path(__file__).resolve().parents[1]
            / "deploy/runtime-agent/docker-compose.ebpf.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cgroup: host", compose)
        self.assertIn('PQ_RUNTIME_EBPF_MAX_PROBES: "${PQ_RUNTIME_EBPF_MAX_PROBES:-64}"', compose)
        self.assertIn("PQ_RUNTIME_EBPF_PROC_ROOT: /proc", compose)
        self.assertIn("PQ_RUNTIME_CGROUP_ROOT: /sys/fs/cgroup", compose)
        self.assertIn("- --ebpf-proc-root\n      - /proc", compose)
        self.assertIn("/sys:/sys:ro", compose)
        self.assertIn(
            "/sys/kernel/debug/tracing:/sys/kernel/debug/tracing:rw",
            compose,
        )


if __name__ == "__main__":
    unittest.main()
