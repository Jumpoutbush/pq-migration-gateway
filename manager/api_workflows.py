"""High-level API-first workflows composed from control-plane primitives."""
from __future__ import annotations

import copy
from pathlib import Path

from manager.config_store import ConfigStore
from manager.control_plane import stage_document
from manager.enterprise import ENTERPRISE_DEFAULTS, build_service


def _service_from_request(payload: dict, expected_id: str | None = None) -> dict:
    raw = payload.get("service", payload.get("spec", payload))
    if not isinstance(raw, dict):
        raise ValueError("service must be an object")
    service_id = str(raw.get("id") or expected_id or "")
    if expected_id and service_id not in {"", expected_id}:
        raise ValueError("service id in the request must match the path")
    if not service_id:
        raise ValueError("service.id is required")
    if all(key in raw for key in ("listen", "downstream_tls", "upstream")):
        service = copy.deepcopy(raw)
        service["id"] = service_id
        return service

    listen = raw.get("listen", {})
    upstream = raw.get("upstream", {})
    downstream = raw.get("downstream_tls", {})
    if not isinstance(listen, dict) or not isinstance(upstream, (dict, str)) or not isinstance(downstream, dict):
        raise ValueError("listen, upstream and downstream_tls must use the documented object forms")
    upstream_object = upstream if isinstance(upstream, dict) else {"address": upstream}
    upstream_tls = upstream_object.get("tls", {})
    if not isinstance(upstream_tls, dict):
        raise ValueError("upstream.tls must be an object")
    identity = upstream_tls.get("client_identity", {})
    if not isinstance(identity, dict):
        raise ValueError("upstream.tls.client_identity must be an object")
    private_key = identity.get("private_key", {})
    if not isinstance(private_key, dict):
        raise ValueError("upstream.tls.client_identity.private_key must be an object")
    return build_service(
        service_id=service_id,
        adapter=str(raw.get("adapter", "http")),
        listen_address=str(listen.get("address", "0.0.0.0")),
        listen_port=int(listen.get("port", 0)),
        server_name=str(listen.get("server_name", "")),
        upstream=str(upstream_object.get("address", "")),
        client_auth=str(downstream.get("client_auth", "off")),
        upstream_tls=upstream_tls.get("enabled"),
        upstream_verify=str(upstream_tls.get("verify", "off")),
        upstream_sni=str(upstream_tls.get("sni", "")),
        upstream_ca=str(upstream_tls.get("ca", ENTERPRISE_DEFAULTS["upstream_ca"])),
        upstream_client_certificate=str(identity.get("certificate", "")),
        upstream_client_key=str(private_key.get("reference", "")),
    )


def publish_service(store: ConfigStore, control_dir: str | Path, payload: dict, actor: str,
                    expected_id: str | None = None) -> dict:
    """Validate and stage one service in a single authenticated API request."""
    service = _service_from_request(payload, expected_id)
    defaults = payload.get("defaults")
    if defaults is not None and not isinstance(defaults, dict):
        raise ValueError("defaults must be an object")
    selected_defaults = defaults or store.get_setting("service_defaults", {}) or dict(ENTERPRISE_DEFAULTS)
    services = [item["spec"] for item in store.list_resources("service")]
    if len(services) == 1 and services[0].get("id") == "enterprise-pilot" and service["id"] != "enterprise-pilot":
        services = []
    services = [item for item in services if item.get("id") != service["id"]]
    services.append(service)
    manifest = stage_document(
        store, control_dir,
        {"schema_version": "4.0", "defaults": selected_defaults, "services": services},
        actor,
    )
    return {
        "status": "STAGED",
        "service": store.get_resource("service", service["id"]),
        "release": manifest,
        "execution": "gateway-agent will validate, reload, health-check and report HEALTHY or rollback",
    }
