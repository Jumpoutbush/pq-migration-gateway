"""HTTP/HTTPS reverse-proxy adapter."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from gateway.model import ConfigError
from .base import ProtocolAdapter, client_auth_lines, upstream_tls_lines


class HttpAdapter(ProtocolAdapter):
    name = "http"
    plane = "http"

    def validate(self, service: dict) -> None:
        parsed = urlsplit(service["upstream"]["address"])
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
            raise ConfigError(f"{service['id']}: HTTP upstream must be an origin URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigError(f"{service['id']}: HTTP upstream must not contain credentials, query or fragment")
        if (parsed.scheme == "https") != service["upstream"]["tls"]["enabled"]:
            raise ConfigError(f"{service['id']}: upstream TLS enabled flag must match URL scheme")

    def render(self, service: dict) -> str:
        sid = service["id"]
        listen = service["listen"]
        tls = service["downstream_tls"]
        upstream = service["upstream"]["address"].rstrip("/")
        groups = ":".join(tls["groups"])
        timeouts = service["timeouts"]
        bind = str(listen["port"]) if listen["address"] == "0.0.0.0" else f"{listen['address']}:{listen['port']}"
        return f'''
    server {{
        listen {bind} ssl;
        server_name {listen['server_name']};

        set $pq_service_name {json.dumps(sid)};
        set $pq_configured_groups {json.dumps(groups)};
        set $pq_application_protocol "http";

        ssl_protocols TLSv1.3;
        ssl_certificate {tls['certificate']};
        ssl_certificate_key {tls['private_key']['reference']};
        ssl_conf_command Groups {groups};
        ssl_session_timeout 10m;
        ssl_session_cache shared:PQHTTP:50m;
        ssl_session_tickets off;

{client_auth_lines(service)}

{chr(10).join(upstream_tls_lines(service))}

        add_header X-PQ-Gateway "pqc-migration-gateway-v3.3" always;
        add_header X-PQ-Service {json.dumps(sid)} always;
        add_header X-PQ-TLS-Groups {json.dumps(groups)} always;

        location = /healthz {{
            access_log off;
            default_type application/json;
            return 200 '{{"status":"ok","service":"{sid}","adapter":"http","tls_groups":"{groups}"}}\\n';
        }}

        location / {{
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Request-ID $request_id;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Client-Verify $ssl_client_verify;
            proxy_set_header X-Forwarded-Client-DN $ssl_client_s_dn;
            proxy_set_header X-PQ-TLS-Protocol $ssl_protocol;
            proxy_set_header X-PQ-TLS-Cipher $ssl_cipher;
            proxy_set_header X-PQ-TLS-Group $ssl_curve;
            proxy_set_header X-PQ-Service {json.dumps(sid)};
            proxy_connect_timeout {timeouts['connect']};
            proxy_send_timeout {timeouts['send']};
            proxy_read_timeout {timeouts['read']};
            proxy_pass {upstream};
        }}
    }}
'''

    def health_check(self, service: dict) -> dict:
        return {"type": "https", "host": "127.0.0.1", "port": service["listen"]["port"], "sni": service["listen"]["server_name"], "path": "/healthz"}
