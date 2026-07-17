"""Dependency-free Python client for the PQ Gateway Manager REST API."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str, payload: object | None = None):
        super().__init__(f"Manager API returned HTTP {status}: {message}")
        self.status = status
        self.payload = payload


class ManagerApiClient:
    def __init__(self, base_url: str, token: str, operator: str = "pqapi", timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.operator = operator
        self.timeout = timeout
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("Manager API URL must start with http:// or https://")
        if not token:
            raise ValueError("Manager API bearer token is required")

    def request(self, method: str, path: str, payload: dict | None = None) -> object:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "X-PQ-Operator": self.operator,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                content = response.read()
                return json.loads(content) if content else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = {"error": raw}
            raise ApiError(exc.code, str(body.get("error", exc.reason)), body) from exc
        except urllib.error.URLError as exc:
            raise ApiError(0, f"cannot connect to {self.base_url}: {exc.reason}") from exc

    def capabilities(self) -> dict:
        return self.request("GET", "/v1/capabilities")  # type: ignore[return-value]

    def status(self) -> dict:
        return self.request("GET", "/v1/status")  # type: ignore[return-value]

    def onboard(self, service: dict, defaults: dict | None = None) -> dict:
        payload = {"service": service}
        if defaults is not None:
            payload["defaults"] = defaults
        return self.request("POST", "/v1/onboarding", payload)  # type: ignore[return-value]

    def create_scan(self, roots: list[str], compile_commands: list[str] | None = None, **options: object) -> dict:
        payload: dict = {"type": "enterprise", "roots": roots, **options}
        if compile_commands:
            payload["compile_commands"] = compile_commands
        return self.request("POST", "/v1/scans", payload)  # type: ignore[return-value]

    def wait_scan(self, scan_id: str, timeout: float = 300, interval: float = 1) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            job = self.request("GET", f"/v1/scans/{urllib.parse.quote(scan_id, safe='')}")
            if isinstance(job, dict) and job.get("status") in {"SUCCEEDED", "FAILED"}:
                return job
            if time.monotonic() >= deadline:
                raise TimeoutError(f"scan did not finish within {timeout:g}s: {scan_id}")
            time.sleep(max(0.1, interval))
