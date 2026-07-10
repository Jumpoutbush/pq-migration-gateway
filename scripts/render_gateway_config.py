#!/usr/bin/env python3
"""Render a validated multi-service NGINX configuration for the PQC gateway."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._:/@+\-]+$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
TIMEOUT = re.compile(r"^[1-9][0-9]*(?:ms|s|m)$")
VALID_CLIENT_AUTH = {"off", "optional", "required"}
VALID_VERIFY = {"off", "on", "required"}


class ConfigError(ValueError):
    pass


def need_string(value: object, field: str, pattern: re.Pattern[str] = SAFE_TOKEN) -> str:
    if not isinstance(value, str) or not value or not pattern.fullmatch(value):
        raise ConfigError(f"Invalid {field}: {value!r}")
    return value


def need_port(value: object, field: str = "listen_port") -> int:
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise ConfigError(f"Invalid {field}: {value!r}")
    return value


def validate_url(value: object) -> str:
    url = need_string(value, "upstream_url")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"upstream_url must be http:// or https://: {url!r}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError("upstream_url must not contain credentials, query, or fragment")
    return url.rstrip("/")


def get_timeout(service: dict, defaults: dict, key: str, fallback: str) -> str:
    value = service.get(key, defaults.get(key, fallback))
    return need_string(value, key, TIMEOUT)


def quote_json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_server(service: dict, defaults: dict) -> str:
    name = need_string(service.get("name"), "name", SAFE_NAME)
    port = need_port(service.get("listen_port"))
    server_name = need_string(service.get("server_name"), "server_name")
    upstream = validate_url(service.get("upstream_url"))
    groups = need_string(service.get("tls_groups", "X25519MLKEM768:X25519"), "tls_groups")
    cert = need_string(service.get("certificate", defaults.get("certificate")), "certificate")
    key = need_string(service.get("certificate_key", defaults.get("certificate_key")), "certificate_key")
    client_ca = need_string(service.get("client_ca", defaults.get("client_ca")), "client_ca")
    upstream_ca = need_string(service.get("upstream_ca", defaults.get("upstream_ca")), "upstream_ca")
    client_auth = str(service.get("client_auth", "off")).lower()
    verify = str(service.get("upstream_tls_verify", "off")).lower()
    if client_auth not in VALID_CLIENT_AUTH:
        raise ConfigError(f"Invalid client_auth for {name}: {client_auth}")
    if verify not in VALID_VERIFY:
        raise ConfigError(f"Invalid upstream_tls_verify for {name}: {verify}")

    connect_timeout = get_timeout(service, defaults, "connect_timeout", "5s")
    send_timeout = get_timeout(service, defaults, "send_timeout", "60s")
    read_timeout = get_timeout(service, defaults, "read_timeout", "60s")

    mtls = "# mTLS disabled"
    if client_auth == "optional":
        mtls = f"ssl_client_certificate {client_ca};\n        ssl_verify_client optional;\n        ssl_verify_depth 3;"
    elif client_auth == "required":
        mtls = f"ssl_client_certificate {client_ca};\n        ssl_verify_client on;\n        ssl_verify_depth 3;"

    upstream_tls = "proxy_ssl_server_name on;\n        proxy_ssl_verify off;\n        proxy_ssl_protocols TLSv1.2 TLSv1.3;"
    if verify in {"on", "required"}:
        upstream_tls = (
            "proxy_ssl_server_name on;\n"
            "        proxy_ssl_verify on;\n"
            f"        proxy_ssl_trusted_certificate {upstream_ca};\n"
            "        proxy_ssl_verify_depth 3;\n"
            "        proxy_ssl_protocols TLSv1.2 TLSv1.3;"
        )

    return f"""
    server {{
        listen {port} ssl;
        server_name {server_name};

        set $pq_service_name {quote_json_string(name)};
        set $pq_configured_groups {quote_json_string(groups)};

        ssl_protocols TLSv1.3;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        ssl_conf_command Groups {groups};
        ssl_session_timeout 10m;
        ssl_session_cache shared:PQSSL:20m;
        ssl_session_tickets off;

        {mtls}

        {upstream_tls}

        add_header X-PQ-Gateway "pqc-migration-gateway-v2" always;
        add_header X-PQ-Service {quote_json_string(name)} always;
        add_header X-PQ-TLS-Groups {quote_json_string(groups)} always;

        location = /healthz {{
            access_log off;
            default_type application/json;
            return 200 '{{"status":"ok","service":"{name}","tls_groups":"{groups}"}}\\n';
        }}

        location / {{
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Request-ID $request_id;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Client-Verify $ssl_client_verify;
            proxy_set_header X-PQ-TLS-Protocol $ssl_protocol;
            proxy_set_header X-PQ-TLS-Cipher $ssl_cipher;
            proxy_set_header X-PQ-TLS-Group $ssl_curve;
            proxy_set_header X-PQ-Service {quote_json_string(name)};

            proxy_connect_timeout {connect_timeout};
            proxy_send_timeout {send_timeout};
            proxy_read_timeout {read_timeout};
            proxy_pass {upstream};
        }}
    }}
"""


def render(config: dict) -> str:
    if config.get("version") != 2:
        raise ConfigError("services config version must be 2")
    defaults = config.get("defaults", {})
    services = config.get("services")
    if not isinstance(defaults, dict):
        raise ConfigError("defaults must be an object")
    if not isinstance(services, list) or not services:
        raise ConfigError("services must be a non-empty list")

    resolver = need_string(defaults.get("dns_resolver", "127.0.0.11"), "dns_resolver")
    seen_names: set[str] = set()
    seen_listeners: set[tuple[int, str]] = set()
    rendered = []
    for item in services:
        if not isinstance(item, dict):
            raise ConfigError("each service must be an object")
        name = str(item.get("name", ""))
        key = (need_port(item.get("listen_port")), str(item.get("server_name", "")))
        if name in seen_names:
            raise ConfigError(f"duplicate service name: {name}")
        if key in seen_listeners:
            raise ConfigError(f"duplicate listen/server_name pair: {key}")
        seen_names.add(name)
        seen_listeners.add(key)
        rendered.append(render_server(item, defaults))

    header = f"""# Generated by render_gateway_config.py. Do not edit in the container.
worker_processes auto;
pid /tmp/nginx.pid;

events {{
    worker_connections 4096;
}}

http {{
    include /opt/nginx/conf/mime.types;
    default_type application/octet-stream;

    log_format pq_access escape=json
        '{{'
        '"ts":"$time_iso8601",'
        '"service":"$pq_service_name",'
        '"configured_groups":"$pq_configured_groups",'
        '"server_name":"$server_name",'
        '"server_port":$server_port,'
        '"remote_addr":"$remote_addr",'
        '"request_id":"$request_id",'
        '"method":"$request_method",'
        '"uri":"$request_uri",'
        '"status":$status,'
        '"bytes_sent":$bytes_sent,'
        '"request_time":$request_time,'
        '"upstream_addr":"$upstream_addr",'
        '"upstream_status":"$upstream_status",'
        '"upstream_response_time":"$upstream_response_time",'
        '"ssl_protocol":"$ssl_protocol",'
        '"ssl_cipher":"$ssl_cipher",'
        '"ssl_curve":"$ssl_curve",'
        '"ssl_server_name":"$ssl_server_name",'
        '"client_verify":"$ssl_client_verify"'
        '}}';

    access_log /var/log/nginx/access.log pq_access;
    error_log /var/log/nginx/error.log info;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65s;
    server_tokens off;
    resolver {resolver} valid=30s ipv6=off;
"""
    return header + "".join(rendered) + "}\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        output = render(config)
        Path(args.output).write_text(output, encoding="utf-8")
        if args.check:
            print(f"valid: {len(config['services'])} services")
    except (OSError, json.JSONDecodeError, ConfigError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
