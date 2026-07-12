"""Generic TLS-terminated stream adapters."""
from __future__ import annotations

from gateway.model import ConfigError
from .base import ProtocolAdapter, client_auth_lines, upstream_tls_lines


class StreamAdapter(ProtocolAdapter):
    name = "generic-stream"
    plane = "stream"
    application_protocol = "tcp"

    def validate(self, service: dict) -> None:
        address = service["upstream"]["address"]
        if ":" not in address:
            raise ConfigError(f"{service['id']}: stream upstream must be HOST:PORT")
        host, port = address.rsplit(":", 1)
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ConfigError(f"{service['id']}: invalid stream upstream {address!r}")

    def app_protocol(self, service: dict) -> str:
        return str(service.get("protocol_options", {}).get("application_protocol", self.application_protocol))

    def render_log_format(self, service: dict) -> str:
        sid = service["id"]
        name = sid.replace("-", "_")
        app = self.app_protocol(service)
        listen = service["listen"]
        groups = ":".join(service["downstream_tls"]["groups"])
        return f'''    log_format pq_stream_{name} escape=json
        '{{'
        '"ts":"$time_iso8601",'
        '"protocol_type":"stream",'
        '"application_protocol":"{app}",'
        '"service":"{sid}",'
        '"configured_groups":"{groups}",'
        '"server_name":"{listen['server_name']}",'
        '"server_port":$server_port,'
        '"remote_addr":"$remote_addr",'
        '"status":$status,'
        '"bytes_sent":$bytes_sent,'
        '"bytes_received":$bytes_received,'
        '"session_time":$session_time,'
        '"upstream_addr":"$upstream_addr",'
        '"ssl_protocol":"$ssl_protocol",'
        '"ssl_cipher":"$ssl_cipher",'
        '"ssl_curve":"$ssl_curve",'
        '"ssl_server_name":"$ssl_server_name",'
        '"client_verify":"$ssl_client_verify"'
        '}}';
'''

    def render(self, service: dict) -> str:
        sid = service["id"]
        listen = service["listen"]
        tls = service["downstream_tls"]
        groups = ":".join(tls["groups"])
        timeouts = service["timeouts"]
        bind = str(listen["port"]) if listen["address"] == "0.0.0.0" else f"{listen['address']}:{listen['port']}"
        return f'''
    server {{
        listen {bind} ssl;
        ssl_protocols TLSv1.3;
        ssl_certificate {tls['certificate']};
        ssl_certificate_key {tls['private_key']['reference']};
        ssl_conf_command Groups {groups};
        ssl_session_timeout 10m;
        ssl_session_cache shared:PQSTREAM:50m;
        ssl_session_tickets off;

{client_auth_lines(service)}

        proxy_connect_timeout {timeouts['connect']};
        proxy_timeout {timeouts['read']};
{chr(10).join(upstream_tls_lines(service, stream=True))}
        access_log /var/log/nginx/stream-access.log pq_stream_{sid.replace('-', '_')};
        proxy_pass {service['upstream']['address']};
    }}
'''


class MqttAdapter(StreamAdapter):
    name = "mqtt"
    application_protocol = "mqtt"


class TcpAdapter(StreamAdapter):
    name = "tcp"
    application_protocol = "tcp"


class LegacyLineAdapter(StreamAdapter):
    name = "legacy-line"
    application_protocol = "legacy-line"


class PostgresAdapter(StreamAdapter):
    name = "postgres"
    application_protocol = "postgres"


class MysqlAdapter(StreamAdapter):
    name = "mysql"
    application_protocol = "mysql"


class RedisAdapter(StreamAdapter):
    name = "redis"
    application_protocol = "redis"


class KafkaAdapter(StreamAdapter):
    name = "kafka"
    application_protocol = "kafka"


class AmqpAdapter(StreamAdapter):
    name = "amqp"
    application_protocol = "amqp"
