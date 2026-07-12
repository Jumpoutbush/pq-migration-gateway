"""SQLite persistence for control-plane resources, releases and metrics."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def unix_now() -> float:
    return datetime.now(timezone.utc).timestamp()


RELEASE_STATES = {
    "DRAFT", "VALIDATED", "STAGED", "APPLIED", "HEALTHY",
    "VALIDATION_FAILED", "NGINX_TEST_FAILED", "RELOAD_FAILED",
    "HEALTH_CHECK_FAILED", "ROLLED_BACK",
    # Accepted when opening a database produced by v3.1.
    "CANDIDATE", "READY", "FAILED",
}

RELEASE_TRANSITIONS = {
    "DRAFT": {"VALIDATED", "VALIDATION_FAILED"},
    "VALIDATED": {"STAGED"},
    "STAGED": {"APPLIED", "VALIDATION_FAILED", "NGINX_TEST_FAILED", "RELOAD_FAILED", "ROLLED_BACK"},
    "APPLIED": {"HEALTHY", "HEALTH_CHECK_FAILED", "RELOAD_FAILED", "ROLLED_BACK"},
    "HEALTH_CHECK_FAILED": {"ROLLED_BACK"},
    "RELOAD_FAILED": {"ROLLED_BACK"},
    "HEALTHY": {"ROLLED_BACK"},
    # v3.1 compatibility transitions.
    "CANDIDATE": {"READY", "VALIDATED", "VALIDATION_FAILED"},
    "READY": {"APPLIED", "NGINX_TEST_FAILED", "RELOAD_FAILED", "ROLLED_BACK"},
    "FAILED": {"ROLLED_BACK"},
}


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS config_versions(
  version INTEGER PRIMARY KEY AUTOINCREMENT,
  checksum TEXT NOT NULL,
  created_at TEXT NOT NULL,
  operator TEXT NOT NULL,
  status TEXT NOT NULL,
  rollback_from INTEGER,
  source_json TEXT NOT NULL,
  rendered_config TEXT NOT NULL,
  error TEXT,
  FOREIGN KEY(rollback_from) REFERENCES config_versions(version)
);
CREATE INDEX IF NOT EXISTS idx_config_versions_status ON config_versions(status);
CREATE TABLE IF NOT EXISTS config_status_events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  version INTEGER NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  actor TEXT NOT NULL,
  error TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(version) REFERENCES config_versions(version)
);
CREATE INDEX IF NOT EXISTS idx_config_status_version ON config_status_events(version,event_id);
CREATE TABLE IF NOT EXISTS audit_events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_states(
  service_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  config_version INTEGER,
  updated_at TEXT NOT NULL,
  operator TEXT NOT NULL,
  reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state_transitions(
  transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_id TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  config_version INTEGER,
  verification_result TEXT,
  fallback_rate REAL,
  operator TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_resources(
  service_id TEXT PRIMARY KEY,
  spec_json TEXT NOT NULL,
  revision INTEGER NOT NULL,
  source_config_version INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  actor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_resources(
  policy_id TEXT PRIMARY KEY,
  spec_json TEXT NOT NULL,
  revision INTEGER NOT NULL,
  source_config_version INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  actor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS control_settings(
  setting_key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  actor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_agents(
  agent_id TEXT PRIMARY KEY,
  current_version INTEGER,
  desired_version INTEGER,
  status TEXT NOT NULL,
  health TEXT NOT NULL,
  reload_result TEXT,
  active_connections INTEGER,
  fallback_rate REAL,
  error TEXT,
  metadata_json TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  last_seen_epoch REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gateway_agents_seen ON gateway_agents(last_seen_epoch);
CREATE TABLE IF NOT EXISTS runtime_metrics(
  metric_name TEXT NOT NULL,
  labels_json TEXT NOT NULL,
  metric_type TEXT NOT NULL,
  help_text TEXT NOT NULL,
  metric_value REAL NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(metric_name,labels_json)
);
"""


class ReleaseTransitionError(ValueError):
    pass


class ConfigStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def create_version(self, checksum: str, source: dict, rendered: str, operator: str, status: str = "DRAFT", rollback_from: int | None = None) -> int:
        if status not in RELEASE_STATES:
            raise ReleaseTransitionError(f"unknown release status: {status}")
        now = utc_now()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO config_versions(checksum,created_at,operator,status,rollback_from,source_json,rendered_config) VALUES(?,?,?,?,?,?,?)",
                (checksum, now, operator, status, rollback_from, json.dumps(source, ensure_ascii=False, sort_keys=True), rendered),
            )
            version = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO config_status_events(version,from_status,to_status,actor,error,created_at) VALUES(?,?,?,?,?,?)",
                (version, None, status, operator, None, now),
            )
            self._audit_conn(conn, now, operator, "config.create", "config_version", str(version), {"checksum": checksum, "rollback_from": rollback_from, "status": status})
        return version

    def update_draft_artifacts(self, version: int, checksum: str, source: dict, rendered: str) -> None:
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM config_versions WHERE version=?", (version,)).fetchone()
            if row is None:
                raise KeyError(f"unknown config version: {version}")
            if row["status"] not in {"DRAFT", "CANDIDATE"}:
                raise ReleaseTransitionError("release artifacts are immutable after validation")
            conn.execute(
                "UPDATE config_versions SET checksum=?,source_json=?,rendered_config=? WHERE version=?",
                (checksum, json.dumps(source, ensure_ascii=False, sort_keys=True), rendered, version),
            )

    def set_status(self, version: int, status: str, actor: str, error: str | None = None) -> None:
        if status not in RELEASE_STATES:
            raise ReleaseTransitionError(f"unknown release status: {status}")
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM config_versions WHERE version=?", (version,)).fetchone()
            if row is None:
                raise KeyError(f"unknown config version: {version}")
            current = str(row["status"])
            if current == status:
                return
            if status not in RELEASE_TRANSITIONS.get(current, set()):
                raise ReleaseTransitionError(f"invalid release transition: {current} -> {status}")
            conn.execute("UPDATE config_versions SET status=?,error=? WHERE version=?", (status, error, version))
            conn.execute(
                "INSERT INTO config_status_events(version,from_status,to_status,actor,error,created_at) VALUES(?,?,?,?,?,?)",
                (version, current, status, actor, error, now),
            )
            self._audit_conn(conn, now, actor, "config.status", "config_version", str(version), {"from": current, "status": status, "error": error})

    def get_version(self, version: int, include_rendered: bool = True) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM config_versions WHERE version=?", (version,)).fetchone()
            events = conn.execute("SELECT * FROM config_status_events WHERE version=? ORDER BY event_id", (version,)).fetchall()
        if row is None:
            raise KeyError(f"unknown config version: {version}")
        result = dict(row)
        result["source"] = json.loads(result.pop("source_json"))
        if not include_rendered:
            result.pop("rendered_config", None)
        result["status_history"] = [dict(event) for event in events]
        return result

    def list_versions(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT version,checksum,created_at,operator,status,rollback_from,error FROM config_versions ORDER BY version DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_version(self) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT version FROM config_versions ORDER BY version DESC LIMIT 1").fetchone()
        return self.get_version(int(row["version"]), include_rendered=False) if row else None

    def _audit_conn(self, conn: sqlite3.Connection, now: str, actor: str, action: str, object_type: str, object_id: str, details: dict) -> None:
        conn.execute(
            "INSERT INTO audit_events(created_at,actor,action,object_type,object_id,details_json) VALUES(?,?,?,?,?,?)",
            (now, actor, action, object_type, object_id, json.dumps(details, ensure_ascii=False, sort_keys=True)),
        )

    def audit(self, actor: str, action: str, object_type: str, object_id: str, details: dict | None = None) -> None:
        with self.connect() as conn:
            self._audit_conn(conn, utc_now(), actor, action, object_type, object_id, details or {})

    def list_audit(self, limit: int = 100) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY event_id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    @staticmethod
    def _resource_table(kind: str) -> tuple[str, str]:
        tables = {"service": ("service_resources", "service_id"), "policy": ("policy_resources", "policy_id")}
        if kind not in tables:
            raise ValueError(f"unsupported resource kind: {kind}")
        return tables[kind]

    def upsert_resource(self, kind: str, resource_id: str, spec: dict, actor: str, source_config_version: int | None = None) -> dict:
        table, id_column = self._resource_table(kind)
        now = utc_now()
        with self.connect() as conn:
            existing = conn.execute(f"SELECT revision,created_at FROM {table} WHERE {id_column}=?", (resource_id,)).fetchone()
            revision = int(existing["revision"]) + 1 if existing else 1
            created_at = str(existing["created_at"]) if existing else now
            conn.execute(
                f"INSERT INTO {table}({id_column},spec_json,revision,source_config_version,created_at,updated_at,actor) VALUES(?,?,?,?,?,?,?) "
                f"ON CONFLICT({id_column}) DO UPDATE SET spec_json=excluded.spec_json,revision=excluded.revision,source_config_version=excluded.source_config_version,updated_at=excluded.updated_at,actor=excluded.actor",
                (resource_id, json.dumps(spec, ensure_ascii=False, sort_keys=True), revision, source_config_version, created_at, now, actor),
            )
            self._audit_conn(conn, now, actor, f"{kind}.upsert", kind, resource_id, {"revision": revision, "source_config_version": source_config_version})
        return self.get_resource(kind, resource_id)

    def get_resource(self, kind: str, resource_id: str) -> dict:
        table, id_column = self._resource_table(kind)
        with self.connect() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE {id_column}=?", (resource_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown {kind}: {resource_id}")
        item = dict(row)
        item["id"] = item.pop(id_column)
        item["spec"] = json.loads(item.pop("spec_json"))
        return item

    def list_resources(self, kind: str, limit: int = 500) -> list[dict]:
        table, id_column = self._resource_table(kind)
        with self.connect() as conn:
            rows = conn.execute(f"SELECT {id_column} FROM {table} ORDER BY {id_column} LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [self.get_resource(kind, str(row[id_column])) for row in rows]

    def delete_resource(self, kind: str, resource_id: str, actor: str) -> None:
        table, id_column = self._resource_table(kind)
        now = utc_now()
        with self.connect() as conn:
            cur = conn.execute(f"DELETE FROM {table} WHERE {id_column}=?", (resource_id,))
            if cur.rowcount == 0:
                raise KeyError(f"unknown {kind}: {resource_id}")
            self._audit_conn(conn, now, actor, f"{kind}.delete", kind, resource_id, {})

    def set_setting(self, key: str, value: object, actor: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO control_settings(setting_key,value_json,updated_at,actor) VALUES(?,?,?,?) "
                "ON CONFLICT(setting_key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at,actor=excluded.actor",
                (key, json.dumps(value, ensure_ascii=False, sort_keys=True), utc_now(), actor),
            )

    def get_setting(self, key: str, default: object = None) -> object:
        with self.connect() as conn:
            row = conn.execute("SELECT value_json FROM control_settings WHERE setting_key=?", (key,)).fetchone()
        return json.loads(row["value_json"]) if row else default

    def sync_canonical_resources(self, canonical: dict, policies: list[dict], actor: str, version: int) -> None:
        self.set_setting("service_defaults", canonical.get("defaults", {}), actor)
        service_ids = {service["id"] for service in canonical["services"]}
        policy_ids = {policy["service_id"] for policy in policies}
        for existing in self.list_resources("service"):
            if existing["id"] not in service_ids:
                self.delete_resource("service", existing["id"], actor)
        for existing in self.list_resources("policy"):
            if existing["id"] not in policy_ids:
                self.delete_resource("policy", existing["id"], actor)
        for service in canonical["services"]:
            self.upsert_resource("service", service["id"], service, actor, version)
        for policy in policies:
            self.upsert_resource("policy", policy["service_id"], policy, actor, version)

    def document_from_resources(self, defaults: dict | None = None) -> dict:
        services = [item["spec"] for item in self.list_resources("service")]
        if not services:
            raise ValueError("no service resources are registered")
        policies = {str(item["spec"].get("service_id", item["id"])): item["spec"] for item in self.list_resources("policy")}
        for service in services:
            policy = policies.get(str(service.get("id")))
            if not policy:
                continue
            if isinstance(policy.get("rollout"), dict):
                service.setdefault("rollout", {}).update(policy["rollout"])
            else:
                rollout = service.setdefault("rollout", {})
                if "rollout_policy" in policy:
                    rollout["policy"] = policy["rollout_policy"]
                for key in ("hybrid_percentage", "fallback_allowed"):
                    if key in policy:
                        rollout[key] = policy[key]
            if isinstance(policy.get("downstream_tls"), dict):
                service.setdefault("downstream_tls", {}).update(policy["downstream_tls"])
            else:
                downstream = service.setdefault("downstream_tls", {})
                if "tls_mode" in policy:
                    downstream["mode"] = policy["tls_mode"]
                if "groups" in policy:
                    downstream["groups"] = policy["groups"]
        selected_defaults = defaults if defaults is not None else self.get_setting("service_defaults", {})
        return {"schema_version": "4.0", "defaults": selected_defaults, "services": services}

    def heartbeat_agent(self, agent_id: str, *, current_version: int | None, desired_version: int | None, status: str, health: str,
                        reload_result: str | None = None, active_connections: int | None = None, fallback_rate: float | None = None,
                        error: str | None = None, metadata: dict | None = None) -> dict:
        if fallback_rate is not None and not 0 <= fallback_rate <= 1:
            raise ValueError("fallback_rate must be between 0 and 1")
        now, epoch = utc_now(), unix_now()
        with self.connect() as conn:
            existing = conn.execute("SELECT first_seen FROM gateway_agents WHERE agent_id=?", (agent_id,)).fetchone()
            first_seen = str(existing["first_seen"]) if existing else now
            conn.execute(
                "INSERT INTO gateway_agents(agent_id,current_version,desired_version,status,health,reload_result,active_connections,fallback_rate,error,metadata_json,first_seen,last_seen,last_seen_epoch) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET current_version=excluded.current_version,desired_version=excluded.desired_version,status=excluded.status,health=excluded.health,reload_result=excluded.reload_result,active_connections=excluded.active_connections,fallback_rate=excluded.fallback_rate,error=excluded.error,metadata_json=excluded.metadata_json,last_seen=excluded.last_seen,last_seen_epoch=excluded.last_seen_epoch",
                (agent_id, current_version, desired_version, status, health, reload_result, active_connections, fallback_rate, error,
                 json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True), first_seen, now, epoch),
            )
        self.set_metric("gateway_agent_heartbeat_timestamp_seconds", epoch, {"agent_id": agent_id}, "gauge", "Unix timestamp of the latest gateway-agent heartbeat.")
        self.set_metric("gateway_agent_health", 1 if health == "healthy" else 0, {"agent_id": agent_id}, "gauge", "Whether the gateway agent reports healthy state.")
        self.set_metric("gateway_agent_current_config_version", current_version or 0, {"agent_id": agent_id}, "gauge", "Configuration version currently active on the gateway agent.")
        self.set_metric("gateway_agent_desired_config_version", desired_version or 0, {"agent_id": agent_id}, "gauge", "Configuration version desired by the gateway agent.")
        if active_connections is not None:
            self.set_metric("gateway_active_connections", active_connections, {"agent_id": agent_id}, "gauge", "Active connections reported by the gateway agent.")
        if fallback_rate is not None:
            self.set_metric("gateway_classical_fallback_ratio", fallback_rate, {"agent_id": agent_id}, "gauge", "Classical fallback ratio reported by the gateway agent.")
        return self.get_agent(agent_id)

    def get_agent(self, agent_id: str) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM gateway_agents WHERE agent_id=?", (agent_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown gateway agent: {agent_id}")
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json"))
        return item

    def list_agents(self, stale_after: float = 30.0) -> list[dict]:
        cutoff = unix_now() - max(1.0, stale_after)
        with self.connect() as conn:
            rows = conn.execute("SELECT agent_id FROM gateway_agents ORDER BY agent_id").fetchall()
        result = []
        for row in rows:
            item = self.get_agent(str(row["agent_id"]))
            item["stale"] = float(item["last_seen_epoch"]) < cutoff
            result.append(item)
        return result

    @staticmethod
    def _labels(labels: dict[str, str] | None) -> str:
        return json.dumps(labels or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def set_metric(self, name: str, value: float, labels: dict[str, str] | None = None, metric_type: str = "gauge", help_text: str = "") -> None:
        if metric_type not in {"counter", "gauge"}:
            raise ValueError("metric_type must be counter or gauge")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO runtime_metrics(metric_name,labels_json,metric_type,help_text,metric_value,updated_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(metric_name,labels_json) DO UPDATE SET metric_type=excluded.metric_type,help_text=excluded.help_text,metric_value=excluded.metric_value,updated_at=excluded.updated_at",
                (name, self._labels(labels), metric_type, help_text, float(value), utc_now()),
            )

    def increment_metric(self, name: str, amount: float = 1, labels: dict[str, str] | None = None, help_text: str = "") -> None:
        key = self._labels(labels)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO runtime_metrics(metric_name,labels_json,metric_type,help_text,metric_value,updated_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(metric_name,labels_json) DO UPDATE SET metric_value=runtime_metrics.metric_value+excluded.metric_value,help_text=excluded.help_text,updated_at=excluded.updated_at",
                (name, key, "counter", help_text, float(amount), utc_now()),
            )

    def list_metrics(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM runtime_metrics ORDER BY metric_name,labels_json").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["labels"] = json.loads(item.pop("labels_json"))
            result.append(item)
        return result

    @staticmethod
    def _prom_escape(value: object) -> str:
        return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

    def prometheus_text(self) -> str:
        metrics = self.list_metrics()
        latest = self.latest_version()
        if latest:
            metrics.append({
                "metric_name": "gateway_config_info", "metric_type": "gauge", "help_text": "Latest control-plane configuration version and state.",
                "metric_value": 1.0, "labels": {"version": str(latest["version"]), "status": str(latest["status"])}, "updated_at": latest["created_at"],
            })
        lines: list[str] = []
        described: set[str] = set()
        for metric in sorted(metrics, key=lambda item: (item["metric_name"], json.dumps(item["labels"], sort_keys=True))):
            name = str(metric["metric_name"])
            if name not in described:
                lines.append(f"# HELP {name} {metric['help_text'] or name}")
                lines.append(f"# TYPE {name} {metric['metric_type']}")
                described.add(name)
            labels = metric.get("labels", {})
            label_text = ""
            if labels:
                label_text = "{" + ",".join(f'{key}="{self._prom_escape(value)}"' for key, value in sorted(labels.items())) + "}"
            lines.append(f"{name}{label_text} {float(metric['metric_value']):g}")
        return "\n".join(lines) + ("\n" if lines else "")
