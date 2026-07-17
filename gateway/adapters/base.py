"""Protocol adapter contract."""
from __future__ import annotations

from abc import ABC, abstractmethod


class ProtocolAdapter(ABC):
    name = "base"
    plane = "stream"

    def validate(self, service: dict) -> None:
        """Perform adapter-specific validation after core model validation."""

    @abstractmethod
    def render(self, service: dict) -> str:
        raise NotImplementedError

    def render_log_format(self, service: dict) -> str:
        return ""

    def probe(self, endpoint: dict) -> dict:
        return {"adapter": self.name, "endpoint": endpoint, "transport": "tcp"}

    def health_check(self, service: dict) -> dict:
        return {"type": "tcp", "host": service["listen"]["address"], "port": service["listen"]["port"]}

    def build_tests(self, service: dict) -> list[dict]:
        return [{"name": "hybrid-handshake", "groups": ["X25519MLKEM768"]}]


def client_auth_lines(service: dict, indent: str = "        ") -> str:
    tls = service["downstream_tls"]
    if tls["client_auth"] == "off":
        return indent + "# client certificate authentication disabled"
    verify = "optional" if tls["client_auth"] == "optional" else "on"
    return (
        f"{indent}ssl_client_certificate {tls['client_ca']};\n"
        f"{indent}ssl_verify_client {verify};\n"
        f"{indent}ssl_verify_depth 3;"
    )


def upstream_tls_lines(service: dict, stream: bool = False) -> list[str]:
    prefix = "proxy_ssl"
    tls = service["upstream"]["tls"]
    lines: list[str] = []
    if stream:
        lines.append(f"        {prefix} {'on' if tls['enabled'] else 'off'};")
        if not tls["enabled"]:
            return lines
    if tls["enabled"]:
        # Do not let a successful upstream mTLS connection authenticate a
        # different service that points at the same address/SNI. Each service
        # must perform its own handshake with its configured CA and identity.
        lines.append("        proxy_ssl_session_reuse off;")
    lines.append("        proxy_ssl_protocols TLSv1.2 TLSv1.3;")
    lines.append(f"        proxy_ssl_server_name {'on' if tls['sni'] else 'off'};")
    if tls["sni"]:
        lines.append(f"        proxy_ssl_name {tls['sni']};")
    lines.append(f"        proxy_ssl_verify {'off' if tls['verify'] == 'off' else 'on'};")
    if tls["verify"] != "off":
        lines.extend([f"        proxy_ssl_trusted_certificate {tls['ca']};", "        proxy_ssl_verify_depth 3;"])
    identity = tls["client_identity"]
    if identity["certificate"]:
        lines.extend([
            f"        proxy_ssl_certificate {identity['certificate']};",
            f"        proxy_ssl_certificate_key {identity['private_key']['reference']};",
        ])
    return lines
