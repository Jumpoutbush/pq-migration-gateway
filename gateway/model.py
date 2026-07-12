"""Canonical service model with backwards-compatible v3 normalization."""
from __future__ import annotations

import copy
import re
from urllib.parse import urlsplit

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._:/@+\-]+$")
TIMEOUT = re.compile(r"^[1-9][0-9]*(?:ms|s|m)$")
CLIENT_AUTH = {"off", "optional", "required"}
VERIFY = {"off", "on", "required"}
TLS_MODES = {
    "compatibility": ["X25519MLKEM768", "X25519"],
    "strict": ["X25519MLKEM768"],
    "classical": ["X25519"],
    "custom": [],
}


class ConfigError(ValueError):
    pass


def _string(value: object, field: str, pattern: re.Pattern[str] = SAFE_TOKEN) -> str:
    if not isinstance(value, str) or not value or not pattern.fullmatch(value):
        raise ConfigError(f"invalid {field}: {value!r}")
    return value


def _optional(value: object, field: str) -> str:
    if value in {None, ""}:
        return ""
    return _string(value, field)


def _port(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ConfigError(f"invalid {field}: {value!r}")
    return value


def _timeout(value: object, field: str) -> str:
    return _string(value, field, TIMEOUT)


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{field} must be true or false")
    return value


def _groups(tls: dict) -> tuple[str, list[str]]:
    mode = str(tls.get("mode", "compatibility")).lower()
    if mode not in TLS_MODES:
        raise ConfigError(f"invalid downstream_tls.mode: {mode!r}")
    raw = tls.get("groups")
    if raw is None:
        groups = list(TLS_MODES[mode])
    elif isinstance(raw, str):
        groups = [x for x in raw.split(":") if x]
    elif isinstance(raw, list):
        groups = [_string(x, "downstream_tls.groups") for x in raw]
    else:
        raise ConfigError("downstream_tls.groups must be a list or colon-delimited string")
    if not groups:
        raise ConfigError("downstream_tls.groups must not be empty")
    if len(groups) != len(set(groups)):
        raise ConfigError("downstream_tls.groups contains duplicates")
    if mode == "strict" and "X25519" in groups:
        raise ConfigError("strict mode must not include classical X25519 fallback")
    return mode, groups


def _identity(raw: object, field: str) -> dict:
    if raw is None or raw == "":
        return {"certificate": "", "private_key": {"provider": "file", "reference": ""}}
    if not isinstance(raw, dict):
        raise ConfigError(f"{field} must be an object")
    cert = _optional(raw.get("certificate"), f"{field}.certificate")
    key = raw.get("private_key", {})
    if isinstance(key, str):
        key = {"provider": "file", "reference": key}
    if not isinstance(key, dict):
        raise ConfigError(f"{field}.private_key must be an object")
    provider = str(key.get("provider", "file")).lower()
    if provider not in {"file", "pkcs11", "vault", "kms"}:
        raise ConfigError(f"unsupported private-key provider: {provider}")
    reference = _optional(key.get("reference"), f"{field}.private_key.reference")
    if bool(cert) != bool(reference):
        raise ConfigError(f"{field} requires both certificate and private-key reference")
    return {"certificate": cert, "private_key": {"provider": provider, "reference": reference}}


def _legacy_to_v4(config: dict) -> dict:
    defaults = config.get("defaults", {})
    result = {"schema_version": "4.0", "defaults": copy.deepcopy(defaults), "services": []}
    for old in config.get("services", []):
        is_http = old.get("protocol", "http") == "http"
        adapter = "http" if is_http else old.get("application_protocol", "generic-stream")
        upstream_address = old.get("upstream_url") if is_http else old.get("upstream_address")
        upstream_tls = bool(old.get("upstream_tls", False))
        if is_http and isinstance(upstream_address, str):
            upstream_tls = urlsplit(upstream_address).scheme == "https"
        mode = "strict" if old.get("tls_groups") == "X25519MLKEM768" else "compatibility"
        service = {
            "id": old.get("name"),
            "adapter": adapter,
            "listen": {"address": "0.0.0.0", "port": old.get("listen_port"), "server_name": old.get("server_name")},
            "downstream_tls": {
                "mode": mode,
                "groups": old.get("tls_groups", "X25519MLKEM768:X25519"),
                "client_auth": old.get("client_auth", "off"),
                "certificate": old.get("certificate", defaults.get("certificate")),
                "private_key": {"provider": "file", "reference": old.get("certificate_key", defaults.get("certificate_key"))},
                "client_ca": old.get("client_ca", defaults.get("client_ca")),
            },
            "upstream": {
                "address": upstream_address,
                "tls": {
                    "enabled": upstream_tls,
                    "verify": old.get("upstream_tls_verify", "off"),
                    "sni": old.get("upstream_sni", ""),
                    "ca": old.get("upstream_ca", defaults.get("upstream_ca")),
                    "client_identity": {
                        "certificate": old.get("upstream_client_certificate", ""),
                        "private_key": {"provider": "file", "reference": old.get("upstream_client_key", "")},
                    },
                },
            },
            "timeouts": {
                "connect_timeout": old.get("connect_timeout") or defaults.get("connect_timeout") or "5s",
                "send_timeout": old.get("send_timeout") or defaults.get("send_timeout") or "60s",
                "read_timeout": old.get("read_timeout") or defaults.get("read_timeout") or "60s",
            },
            "rollout": {"policy": "fixed", "hybrid_percentage": 0 if mode == "classical" else 100, "fallback_allowed": mode != "strict"},
            "audit": {"enabled": True},
        }
        result["services"].append(service)
    return result


def normalize_config(config: dict) -> dict:
    """Return a validated canonical configuration without mutating input."""
    if not isinstance(config, dict):
        raise ConfigError("configuration root must be an object")
    if config.get("version") == 3:
        config = _legacy_to_v4(config)
    elif str(config.get("schema_version", config.get("version", ""))) not in {"4", "4.0"}:
        raise ConfigError("services config must use version 3 or schema_version 4.0")
    else:
        config = copy.deepcopy(config)

    defaults = config.get("defaults", {})
    services = config.get("services")
    if not isinstance(defaults, dict):
        raise ConfigError("defaults must be an object")
    if not isinstance(services, list) or not services:
        raise ConfigError("services must be a non-empty list")
    resolver = _string(defaults.get("dns_resolver", "127.0.0.11"), "defaults.dns_resolver")
    normalized: list[dict] = []
    names: set[str] = set()
    listeners: set[tuple[str, int]] = set()

    for raw in services:
        if not isinstance(raw, dict):
            raise ConfigError("each service must be an object")
        service_id = _string(raw.get("id"), "service.id", SAFE_NAME)
        if service_id in names:
            raise ConfigError(f"duplicate service id: {service_id}")
        adapter = _string(raw.get("adapter", "http"), f"{service_id}.adapter", SAFE_NAME).lower()
        listen = raw.get("listen", {})
        if not isinstance(listen, dict):
            raise ConfigError(f"{service_id}.listen must be an object")
        address = _string(listen.get("address", "0.0.0.0"), f"{service_id}.listen.address")
        port = _port(listen.get("port"), f"{service_id}.listen.port")
        server_name = _string(listen.get("server_name", f"{service_id}.local"), f"{service_id}.listen.server_name")
        key = (address, port)
        if key in listeners:
            raise ConfigError(f"duplicate listener: {address}:{port}")

        downstream = raw.get("downstream_tls", {})
        if not isinstance(downstream, dict):
            raise ConfigError(f"{service_id}.downstream_tls must be an object")
        mode, groups = _groups(downstream)
        client_auth = str(downstream.get("client_auth", "off")).lower()
        if client_auth not in CLIENT_AUTH:
            raise ConfigError(f"invalid client_auth for {service_id}: {client_auth}")
        certificate = _string(downstream.get("certificate", defaults.get("certificate")), f"{service_id}.certificate")
        private_key = downstream.get("private_key", {"provider": "file", "reference": defaults.get("certificate_key")})
        if isinstance(private_key, str):
            private_key = {"provider": "file", "reference": private_key}
        if not isinstance(private_key, dict):
            raise ConfigError(f"{service_id}.downstream_tls.private_key must be an object")
        if private_key.get("provider", "file") != "file":
            raise ConfigError("NGINX v3.2 data plane currently renders file private-key references only")
        key_ref = _string(private_key.get("reference"), f"{service_id}.downstream_tls.private_key.reference")
        client_ca = _string(downstream.get("client_ca", defaults.get("client_ca")), f"{service_id}.client_ca")

        upstream = raw.get("upstream", {})
        if not isinstance(upstream, dict):
            raise ConfigError(f"{service_id}.upstream must be an object")
        upstream_address = _string(upstream.get("address"), f"{service_id}.upstream.address")
        tls = upstream.get("tls", {})
        if not isinstance(tls, dict):
            raise ConfigError(f"{service_id}.upstream.tls must be an object")
        tls_enabled = _boolean(tls.get("enabled", False), f"{service_id}.upstream.tls.enabled")
        verify = str(tls.get("verify", "off")).lower()
        if verify not in VERIFY:
            raise ConfigError(f"invalid upstream TLS verification for {service_id}: {verify}")
        if not tls_enabled and verify != "off":
            raise ConfigError(f"{service_id}: upstream verification requires TLS")
        upstream_ca = _string(tls.get("ca", defaults.get("upstream_ca")), f"{service_id}.upstream.tls.ca")
        identity = _identity(tls.get("client_identity"), f"{service_id}.upstream.tls.client_identity")
        if identity["private_key"]["provider"] != "file" and identity["certificate"]:
            raise ConfigError("NGINX v3.2 data plane currently renders file upstream identity references only")

        timeouts = raw.get("timeouts", {})
        if not isinstance(timeouts, dict):
            raise ConfigError(f"{service_id}.timeouts must be an object")
        timeout_values = {
            "connect": _timeout(timeouts.get("connect", timeouts.get("connect_timeout", defaults.get("connect_timeout", "5s"))), f"{service_id}.timeouts.connect"),
            "send": _timeout(timeouts.get("send", timeouts.get("send_timeout", defaults.get("send_timeout", "60s"))), f"{service_id}.timeouts.send"),
            "read": _timeout(timeouts.get("read", timeouts.get("read_timeout", defaults.get("read_timeout", "60s"))), f"{service_id}.timeouts.read"),
        }
        rollout = raw.get("rollout", {})
        if not isinstance(rollout, dict):
            raise ConfigError(f"{service_id}.rollout must be an object")
        policy = str(rollout.get("policy", "fixed")).lower()
        if policy not in {"fixed", "percentage", "client-group", "source-cidr", "sni"}:
            raise ConfigError(f"unsupported rollout policy for {service_id}: {policy}")
        percentage = rollout.get("hybrid_percentage", 0 if mode == "classical" else 100)
        if isinstance(percentage, bool) or not isinstance(percentage, int) or not 0 <= percentage <= 100:
            raise ConfigError(f"invalid hybrid_percentage for {service_id}")
        fallback = _boolean(rollout.get("fallback_allowed", mode != "strict"), f"{service_id}.rollout.fallback_allowed")
        if not fallback and "X25519" in groups:
            raise ConfigError(f"{service_id}: fallback_allowed=false conflicts with X25519 group")

        normalized.append({
            "id": service_id,
            "adapter": adapter,
            "listen": {"address": address, "port": port, "server_name": server_name},
            "downstream_tls": {"mode": mode, "groups": groups, "client_auth": client_auth, "certificate": certificate, "private_key": {"provider": "file", "reference": key_ref}, "client_ca": client_ca},
            "upstream": {"address": upstream_address, "tls": {"enabled": tls_enabled, "verify": verify, "sni": _optional(tls.get("sni"), f"{service_id}.upstream.tls.sni"), "ca": upstream_ca, "client_identity": identity}},
            "timeouts": timeout_values,
            "rollout": {"policy": policy, "hybrid_percentage": percentage, "fallback_allowed": fallback},
            "audit": {"enabled": _boolean(raw.get("audit", {}).get("enabled", True), f"{service_id}.audit.enabled") if isinstance(raw.get("audit", {}), dict) else True},
            "protocol_options": copy.deepcopy(raw.get("protocol_options", {})),
        })
        names.add(service_id)
        listeners.add(key)

    return {"schema_version": "4.0", "defaults": {**defaults, "dns_resolver": resolver}, "services": normalized}


def compatibility_view(config: dict) -> list[dict]:
    """Flatten canonical services for v3 scanners and experiment helpers."""
    normalized = normalize_config(config)
    rows = []
    for service in normalized["services"]:
        rows.append({
            "name": service["id"],
            "protocol": "http" if service["adapter"] == "http" else "stream",
            "application_protocol": service["adapter"],
            "listen_port": service["listen"]["port"],
            "server_name": service["listen"]["server_name"],
            "tls_groups": ":".join(service["downstream_tls"]["groups"]),
        })
    return rows
