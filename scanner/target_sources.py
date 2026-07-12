#!/usr/bin/env python3
"""Load and normalize TLS scan targets from endpoint lists, discovery and CMDB files."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Iterable


def stable_asset_id(host: str, port: int, sni: str) -> str:
    return "target-" + hashlib.sha256(f"{host}:{port}:{sni}".encode()).hexdigest()[:20]


def normalize(item: dict, source: str = "input") -> dict:
    host = str(item.get("host") or item.get("hostname") or item.get("ip") or item.get("address") or "").strip()
    port_raw = item.get("port") or item.get("service_port") or item.get("tls_port")
    if not host or port_raw in {None, ""}:
        raise ValueError(f"Target requires host and port: {item!r}")
    port = int(port_raw)
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port: {port}")
    sni = str(item.get("sni") or item.get("server_name") or item.get("dns_name") or host).strip()
    protocol = str(item.get("protocol") or item.get("service") or "tls").strip().lower()
    return {
        "asset_id": str(item.get("asset_id") or item.get("id") or stable_asset_id(host, port, sni)),
        "name": str(item.get("name") or item.get("asset_name") or f"{sni}:{port}"),
        "host": host,
        "port": port,
        "sni": sni,
        "protocol": protocol,
        "owner": str(item.get("owner") or item.get("team") or ""),
        "environment": str(item.get("environment") or item.get("env") or ""),
        "criticality": str(item.get("criticality") or item.get("tier") or ""),
        "client_certificate": str(item.get("client_certificate") or item.get("client_cert") or ""),
        "client_key": str(item.get("client_key") or ""),
        "source": source,
        "metadata": {k: v for k, v in item.items() if k not in {
            "asset_id", "id", "name", "asset_name", "host", "hostname", "ip", "address", "port",
            "service_port", "tls_port", "sni", "server_name", "dns_name", "protocol", "service",
            "owner", "team", "environment", "env", "criticality", "tier", "client_certificate",
            "client_cert", "client_key"
        }},
    }


def load_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("targets") or data.get("assets") or data.get("endpoints") or data.get("open_endpoints") or []
    else:
        raise ValueError(f"Unsupported JSON structure: {path}")
    return [normalize(dict(row), str(path)) for row in rows]


def load_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [normalize(dict(row), str(path)) for row in csv.DictReader(handle)]


def load_file(path_str: str) -> list[dict]:
    path = Path(path_str)
    return load_csv(path) if path.suffix.lower() == ".csv" else load_json(path)


def parse_endpoint(value: str) -> dict:
    # HOST:PORT[,SNI[,PROTOCOL]]
    parts = [x.strip() for x in value.split(",")]
    host_port = parts[0]
    host, port = host_port.rsplit(":", 1)
    return normalize({"host": host, "port": int(port), "sni": parts[1] if len(parts) > 1 else host,
                      "protocol": parts[2] if len(parts) > 2 else "tls"}, "cli")


def deduplicate(targets: Iterable[dict]) -> list[dict]:
    merged: dict[tuple[str, int, str], dict] = {}
    for item in targets:
        key = (item["host"], int(item["port"]), item["sni"])
        if key in merged:
            previous = merged[key]
            for field in ("owner", "environment", "criticality", "client_certificate", "client_key"):
                if not previous.get(field) and item.get(field):
                    previous[field] = item[field]
            previous["source"] = ";".join(dict.fromkeys((previous.get("source", "") + ";" + item.get("source", "")).strip(";").split(";")))
        else:
            merged[key] = dict(item)
    return sorted(merged.values(), key=lambda x: (x["host"], x["port"], x["sni"]))


def expand_cidrs(cidrs: list[str], ports: list[int], max_hosts: int) -> list[dict]:
    output: list[dict] = []
    count = 0
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts() if network.num_addresses > 2 else network:
            count += 1
            if count > max_hosts:
                raise ValueError(f"CIDR expansion exceeds max_hosts={max_hosts}")
            for port in ports:
                output.append(normalize({"host": str(ip), "port": port, "sni": str(ip), "protocol": "tls"}, f"cidr:{cidr}"))
    return output
