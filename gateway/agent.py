#!/usr/bin/env python3
"""Data-plane agent for desired-state activation, health and heartbeats."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.config_store import ConfigStore, utc_now  # noqa: E402
from manager.control_plane import atomic_json, manifest_signature  # noqa: E402


class ApplyError(RuntimeError):
    pass


class GatewayAgent:
    def __init__(self, control_dir: str | Path, active_config: str | Path, nginx_bin: str, db: str | Path,
                 health_command: str = "", signing_key: str = "", agent_id: str = "", metadata: dict | None = None,
                 status_url: str = "http://127.0.0.1:18081/nginx_status"):
        self.control_dir = Path(control_dir)
        self.active_config = Path(active_config)
        self.nginx_bin = nginx_bin
        self.store = ConfigStore(db)
        self.health_command = health_command
        self.signing_key = signing_key
        self.agent_id = agent_id or os.environ.get("PQ_AGENT_ID", "") or socket.gethostname()
        self.metadata = {"hostname": socket.gethostname(), "framework_version": "3.7.0", **(metadata or {})}
        self.status_url = status_url

    def _command(self, args: list[str]) -> None:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if result.returncode:
            raise ApplyError(result.stdout.strip() or f"command failed: {args}")

    def _health(self) -> None:
        if not self.health_command:
            return
        result = subprocess.run(self.health_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if result.returncode:
            raise ApplyError("health check failed: " + result.stdout.strip())

    def _observed(self) -> dict:
        path = self.control_dir / "observed.json"
        if not path.exists():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def _active_connections(self) -> int | None:
        if not self.status_url:
            return None
        try:
            with urllib.request.urlopen(self.status_url, timeout=1) as response:
                first = response.read(256).decode(errors="replace").splitlines()[0]
            prefix = "Active connections:"
            return int(first[len(prefix):].strip()) if first.startswith(prefix) else None
        except (OSError, ValueError, IndexError):
            return None

    def _heartbeat(self, *, current_version: int | None, desired_version: int | None, status: str, health: str,
                   reload_result: str | None = None, error: str | None = None) -> dict:
        return self.store.heartbeat_agent(
            self.agent_id, current_version=current_version, desired_version=desired_version,
            status=status, health=health, reload_result=reload_result, active_connections=self._active_connections(), error=error, metadata=self.metadata,
        )

    def _record_failure(self, version: int, state: str, error: Exception) -> None:
        self.store.set_status(version, state, self.agent_id, str(error))
        self.store.increment_metric(
            "gateway_config_apply_failures_total", labels={"agent_id": self.agent_id, "stage": state.lower()},
            help_text="Configuration activation failures by data-plane stage.",
        )

    def _rollback(self, version: int, backup: Path, previous_version: int | None, reason: Exception) -> dict:
        if not backup.exists():
            raise ApplyError(f"activation failed and no previous configuration is available: {reason}") from reason
        rollback_tmp = self.active_config.with_suffix(".rollback")
        shutil.copyfile(backup, rollback_tmp)
        os.replace(rollback_tmp, self.active_config)
        try:
            self._command([self.nginx_bin, "-t", "-c", str(self.active_config)])
            self._command([self.nginx_bin, "-s", "reload", "-c", str(self.active_config)])
        except Exception as rollback_exc:
            raise ApplyError(f"activation failed and rollback failed: {reason}; {rollback_exc}") from rollback_exc
        self.store.increment_metric(
            "gateway_config_rollback_total", labels={"agent_id": self.agent_id},
            help_text="Successful automatic configuration rollbacks.",
        )
        self.store.set_status(version, "ROLLED_BACK", self.agent_id, str(reason))
        observed = {
            "agent_id": self.agent_id, "version": previous_version, "failed_version": version,
            "status": "ROLLED_BACK", "error": str(reason), "observed_at": utc_now(),
        }
        atomic_json(self.control_dir / "observed.json", observed)
        self._heartbeat(current_version=previous_version, desired_version=version, status="ROLLED_BACK", health="healthy", reload_result="rollback-ok", error=str(reason))
        return observed

    def apply(self, version: int) -> dict:
        release = self.control_dir / "releases" / str(version)
        previous = self._observed()
        previous_version = previous.get("version") if isinstance(previous.get("version"), int) else None
        self._heartbeat(current_version=previous_version, desired_version=version, status="APPLYING", health="unknown")
        try:
            manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
            if self.signing_key:
                expected = "hmac-sha256:" + manifest_signature(manifest, self.signing_key)
                if not hmac.compare_digest(str(manifest.get("signature", "")), expected):
                    raise ApplyError("release signature mismatch")
            candidate = release / "nginx.conf"
            actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if actual != manifest["rendered_checksum"]:
                raise ApplyError("release checksum mismatch")
        except Exception as exc:
            self._record_failure(version, "VALIDATION_FAILED", exc)
            self._heartbeat(current_version=previous_version, desired_version=version, status="VALIDATION_FAILED", health="degraded", error=str(exc))
            raise

        backup = self.active_config.with_suffix(".previous")
        temporary = self.active_config.with_suffix(".candidate")
        self.active_config.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(candidate, temporary)
        try:
            self._command([self.nginx_bin, "-t", "-c", str(temporary)])
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            self._record_failure(version, "NGINX_TEST_FAILED", exc)
            self._heartbeat(current_version=previous_version, desired_version=version, status="NGINX_TEST_FAILED", health="degraded", error=str(exc))
            raise

        had_previous = self.active_config.exists()
        if had_previous:
            shutil.copyfile(self.active_config, backup)
        try:
            os.replace(temporary, self.active_config)
            self._command([self.nginx_bin, "-s", "reload", "-c", str(self.active_config)])
            self.store.increment_metric(
                "gateway_config_reload_total", labels={"agent_id": self.agent_id},
                help_text="Successful NGINX configuration reloads.",
            )
            self.store.set_status(version, "APPLIED", self.agent_id)
        except Exception as exc:
            self._record_failure(version, "RELOAD_FAILED", exc)
            if had_previous:
                self._rollback(version, backup, previous_version, exc)
            else:
                self._heartbeat(current_version=None, desired_version=version, status="RELOAD_FAILED", health="degraded", error=str(exc))
            raise

        try:
            self._health()
        except Exception as exc:
            self._record_failure(version, "HEALTH_CHECK_FAILED", exc)
            if had_previous:
                self._rollback(version, backup, previous_version, exc)
            else:
                self._heartbeat(current_version=version, desired_version=version, status="HEALTH_CHECK_FAILED", health="degraded", error=str(exc))
            raise
        finally:
            temporary.unlink(missing_ok=True)

        self.store.set_status(version, "HEALTHY", self.agent_id)
        observed = {
            "agent_id": self.agent_id, "version": version, "status": "HEALTHY",
            "checksum": actual, "observed_at": utc_now(),
        }
        atomic_json(self.control_dir / "observed.json", observed)
        self._heartbeat(current_version=version, desired_version=version, status="HEALTHY", health="healthy", reload_result="reload-ok")
        return observed

    def watch(self, interval: float) -> None:
        observed = self._observed()
        last_version = observed.get("version") if observed.get("status") == "HEALTHY" else None
        current_version = last_version if isinstance(last_version, int) else None
        desired_version: int | None = None
        self._heartbeat(current_version=current_version, desired_version=None, status="WATCHING", health="healthy")
        while True:
            desired_path = self.control_dir / "desired.json"
            if desired_path.exists():
                try:
                    desired_version = int(json.loads(desired_path.read_text(encoding="utf-8"))["version"])
                    if desired_version != last_version:
                        last_version = desired_version
                        result = self.apply(desired_version)
                        current_version = result.get("version") if isinstance(result.get("version"), int) else current_version
                        print(json.dumps(result), flush=True)
                    else:
                        self._heartbeat(current_version=current_version, desired_version=desired_version, status="HEALTHY", health="healthy")
                except Exception as exc:
                    print(f"gateway-agent: {exc}", file=sys.stderr, flush=True)
                    self._heartbeat(current_version=current_version, desired_version=desired_version, status="DEGRADED", health="degraded", error=str(exc))
            else:
                self._heartbeat(current_version=current_version, desired_version=None, status="WAITING", health="healthy")
            time.sleep(max(0.5, interval))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["apply", "watch"])
    parser.add_argument("--version", type=int)
    parser.add_argument("--control-dir", default="/var/lib/pq-control")
    parser.add_argument("--active-config", default="/tmp/pq-gateway/nginx.conf")
    parser.add_argument("--nginx-bin", default="/opt/nginx/sbin/nginx")
    parser.add_argument("--db", default="/var/lib/pq-control/control-plane.db")
    parser.add_argument("--health-command", default="")
    parser.add_argument("--signing-key", default=os.environ.get("PQ_CONFIG_SIGNING_KEY", ""))
    parser.add_argument("--agent-id", default=os.environ.get("PQ_AGENT_ID", ""))
    parser.add_argument("--status-url", default=os.environ.get("PQ_AGENT_STATUS_URL", "http://127.0.0.1:18081/nginx_status"))
    parser.add_argument("--interval", type=float, default=2)
    args = parser.parse_args()
    agent = GatewayAgent(args.control_dir, args.active_config, args.nginx_bin, args.db, args.health_command, args.signing_key, args.agent_id, status_url=args.status_url)
    try:
        if args.command == "apply":
            if args.version is None:
                parser.error("apply requires --version")
            print(json.dumps(agent.apply(args.version), indent=2))
        else:
            agent.watch(args.interval)
        return 0
    except (OSError, ValueError, KeyError, ApplyError, subprocess.SubprocessError) as exc:
        print(f"gateway-agent: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
