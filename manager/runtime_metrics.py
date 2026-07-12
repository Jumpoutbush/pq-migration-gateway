#!/usr/bin/env python3
"""Publish runtime JSON, Prometheus text and optional control-plane metrics."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.config_store import ConfigStore  # noqa: E402
from manager.fallback_report import aggregate  # noqa: E402


def error_counts(paths: list[str]) -> dict[str, int]:
    counts = {"handshake": 0, "mtls": 0, "upstream_tls": 0}
    for value in paths:
        path = Path(value)
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            lower = line.lower()
            if "ssl_do_handshake() failed" in lower:
                counts["handshake"] += 1
            if "client ssl certificate verify error" in lower or "client sent no required ssl certificate" in lower:
                counts["mtls"] += 1
            if "upstream ssl" in lower and ("failed" in lower or "verify error" in lower):
                counts["upstream_tls"] += 1
    return counts


def metric_rows(payload: dict, failures: dict[str, int]) -> list[dict]:
    rows: list[dict] = []
    for service, row in payload.get("services", {}).items():
        for category in ("hybrid_pqc", "classical_fallback", "unknown"):
            rows.append({"name": "gateway_tls_handshakes_total", "value": row.get(category, 0), "labels": {"service": service, "category": category}, "type": "counter", "help": "Observed TLS handshakes by service and migration category."})
        rows.append({"name": "gateway_classical_fallback_total", "value": row.get("classical_fallback", 0), "labels": {"service": service}, "type": "counter", "help": "Observed classical X25519 fallbacks by service."})
        rows.append({"name": "gateway_hybrid_adoption_ratio", "value": row.get("hybrid_adoption_rate") or 0, "labels": {"service": service}, "type": "gauge", "help": "Ratio of observed hybrid PQC handshakes."})
    for service, groups in payload.get("tls_groups", {}).items():
        for group, count in groups.items():
            rows.append({"name": "gateway_tls_group_total", "value": count, "labels": {"service": service, "group": group}, "type": "counter", "help": "Negotiated TLS groups by service."})
    for service, duration in payload.get("durations", {}).items():
        rows.append({"name": "gateway_connection_duration_seconds_sum", "value": duration.get("sum", 0), "labels": {"service": service}, "type": "counter", "help": "Sum of observed HTTP request or Stream session duration."})
        rows.append({"name": "gateway_connection_duration_seconds_count", "value": duration.get("count", 0), "labels": {"service": service}, "type": "counter", "help": "Count of observations included in connection duration."})
    rows.extend([
        {"name": "gateway_tls_handshake_failures_total", "value": failures["handshake"], "labels": {}, "type": "counter", "help": "TLS handshake failures found in gateway error logs."},
        {"name": "gateway_mtls_failures_total", "value": failures["mtls"], "labels": {}, "type": "counter", "help": "Downstream mTLS authentication failures."},
        {"name": "gateway_upstream_tls_failures_total", "value": failures["upstream_tls"], "labels": {}, "type": "counter", "help": "Upstream TLS verification or handshake failures."},
    ])
    return rows


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def prom(payload: dict, failures: dict[str, int] | None = None) -> str:
    rows = metric_rows(payload, failures or {"handshake": 0, "mtls": 0, "upstream_tls": 0})
    lines: list[str] = []
    described: set[str] = set()
    for row in rows:
        name = row["name"]
        if name not in described:
            lines.extend([f"# HELP {name} {row['help']}", f"# TYPE {name} {row['type']}"])
            described.add(name)
        labels = row["labels"]
        label_text = "{" + ",".join(f'{key}="{_escape(value)}"' for key, value in sorted(labels.items())) + "}" if labels else ""
        lines.append(f"{name}{label_text} {float(row['value']):g}")
    return "\n".join(lines) + "\n"


def publish(args: argparse.Namespace) -> dict:
    payload = aggregate(args.log)
    failures = error_counts(args.error_log)
    payload["failures"] = failures
    out, prometheus = Path(args.out), Path(args.prometheus)
    out.parent.mkdir(parents=True, exist_ok=True)
    prometheus.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    prometheus.write_text(prom(payload, failures), encoding="utf-8")
    if args.history:
        history = Path(args.history)
        history.parent.mkdir(parents=True, exist_ok=True)
        with history.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"generated_at": payload["generated_at"], **payload["summary"], **failures}, ensure_ascii=False) + "\n")
    if args.db:
        store = ConfigStore(args.db)
        for row in metric_rows(payload, failures):
            store.set_metric(row["name"], row["value"], row["labels"], row["type"], row["help"])
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", action="append", required=True)
    parser.add_argument("--error-log", action="append", default=[])
    parser.add_argument("--out", required=True)
    parser.add_argument("--prometheus", required=True)
    parser.add_argument("--history", default="")
    parser.add_argument("--db", default="")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    while True:
        publish(args)
        if args.once:
            return 0
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
