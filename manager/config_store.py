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
CREATE TABLE IF NOT EXISTS scan_jobs(
  scan_id TEXT PRIMARY KEY,
  scan_type TEXT NOT NULL,
  status TEXT NOT NULL,
  request_json TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  output_path TEXT NOT NULL,
  error TEXT,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at);
CREATE TABLE IF NOT EXISTS crypto_assets(
  asset_id TEXT PRIMARY KEY,
  latest_scan_id TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  path TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  risk TEXT NOT NULL,
  pq_status TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(latest_scan_id) REFERENCES scan_jobs(scan_id)
);
CREATE INDEX IF NOT EXISTS idx_crypto_assets_risk ON crypto_assets(risk);
CREATE INDEX IF NOT EXISTS idx_crypto_assets_path ON crypto_assets(path);
CREATE TABLE IF NOT EXISTS scan_findings(
  scan_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  asset_id TEXT,
  finding_type TEXT NOT NULL,
  risk TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY(scan_id,finding_id),
  FOREIGN KEY(scan_id) REFERENCES scan_jobs(scan_id),
  FOREIGN KEY(asset_id) REFERENCES crypto_assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_scan_findings_asset ON scan_findings(asset_id);
CREATE TABLE IF NOT EXISTS asset_assessments(
  assessment_id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  risk TEXT NOT NULL,
  result_json TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(asset_id) REFERENCES crypto_assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_assessments_asset ON asset_assessments(asset_id,created_at);
CREATE TABLE IF NOT EXISTS migration_plans(
  plan_id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  status TEXT NOT NULL,
  compatibility_version INTEGER,
  strict_version INTEGER,
  plan_json TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(asset_id) REFERENCES crypto_assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_migration_plans_asset ON migration_plans(asset_id,updated_at);
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

    def create_scan_job(self, scan_id: str, scan_type: str, request: dict, actor: str) -> dict:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO scan_jobs(scan_id,scan_type,status,request_json,summary_json,output_path,error,actor,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (scan_id, scan_type, "QUEUED", json.dumps(request, ensure_ascii=False, sort_keys=True), "{}", "", None, actor, now),
            )
            self._audit_conn(conn, now, actor, "scan.create", "scan_job", scan_id, {"scan_type": scan_type})
        return self.get_scan_job(scan_id)

    def update_scan_job(self, scan_id: str, status: str, *, summary: dict | None = None,
                        output_path: str = "", error: str | None = None) -> dict:
        allowed = {"QUEUED", "RUNNING", "SUCCEEDED", "FAILED"}
        if status not in allowed:
            raise ValueError(f"unknown scan status: {status}")
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM scan_jobs WHERE scan_id=?", (scan_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown scan: {scan_id}")
            started = now if status == "RUNNING" else None
            completed = now if status in {"SUCCEEDED", "FAILED"} else None
            conn.execute(
                "UPDATE scan_jobs SET status=?,summary_json=COALESCE(?,summary_json),"
                "output_path=CASE WHEN ?='' THEN output_path ELSE ? END,error=?,"
                "started_at=COALESCE(started_at,?),completed_at=COALESCE(?,completed_at) WHERE scan_id=?",
                (status, json.dumps(summary, ensure_ascii=False, sort_keys=True) if summary is not None else None,
                 output_path, output_path, error, started, completed, scan_id),
            )
        return self.get_scan_job(scan_id)

    def get_scan_job(self, scan_id: str) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown scan: {scan_id}")
        item = dict(row)
        item["request"] = json.loads(item.pop("request_json"))
        item["summary"] = json.loads(item.pop("summary_json"))
        return item

    def list_scan_jobs(self, limit: int = 100) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT scan_id FROM scan_jobs ORDER BY created_at DESC,scan_id DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [self.get_scan_job(str(row["scan_id"])) for row in rows]

    @staticmethod
    def _asset_risk(evidence: list[dict]) -> str:
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return max((str(item.get("risk", "INFO")) for item in evidence), key=lambda item: rank.get(item, 0), default="INFO")

    @staticmethod
    def _asset_pq_status(evidence: list[dict]) -> str:
        statuses = {str(item.get("pq_status", "unknown")) for item in evidence}
        if statuses & {"classically_weak", "classically_weak_and_quantum_vulnerable", "quantum_vulnerable"}:
            return "quantum_vulnerable"
        if "pqc_or_pqc_candidate" in statuses:
            return "pqc_or_pqc_candidate"
        return "unknown"

    def ingest_scan_inventory(self, scan_id: str, inventory: dict, actor: str) -> dict:
        """Normalize concrete keys/certificates and code artifacts into control-plane assets."""
        now = utc_now()
        evidence_rows = [item for item in inventory.get("evidence", []) if isinstance(item, dict)]
        by_artifact: dict[str, list[dict]] = {}
        for item in evidence_rows:
            artifact_id = str(item.get("artifact_id", ""))
            if artifact_id:
                by_artifact.setdefault(artifact_id, []).append(item)
        assets: list[tuple[str, str, str, str, str, str, dict]] = []
        for item in inventory.get("assets", []):
            if not isinstance(item, dict) or not item.get("asset_id"):
                continue
            assets.append((
                str(item["asset_id"]), str(item.get("asset_type", "crypto_asset")), str(item.get("path", "")),
                str(item.get("algorithm", "")), str(item.get("risk", "INFO")), str(item.get("pq_status", "unknown")),
                {"record_kind": "concrete_asset", **item},
            ))
        for item in inventory.get("artifacts", []):
            if not isinstance(item, dict) or not item.get("artifact_id"):
                continue
            rows = by_artifact.get(str(item["artifact_id"]), [])
            algorithms = sorted({str(row.get("algorithm", "")) for row in rows if row.get("algorithm")})
            assets.append((
                str(item["artifact_id"]), str(item.get("artifact_type", "software_artifact")), str(item.get("path", "")),
                ";".join(algorithms), self._asset_risk(rows), self._asset_pq_status(rows),
                {"record_kind": "software_artifact", **item, "evidence_count": len(rows), "algorithms": algorithms},
            ))
        asset_ids = {item[0] for item in assets}
        with self.connect() as conn:
            job = conn.execute("SELECT status FROM scan_jobs WHERE scan_id=?", (scan_id,)).fetchone()
            if job is None:
                raise KeyError(f"unknown scan: {scan_id}")
            for asset_id, asset_type, path, algorithm, risk, pq_status, payload in assets:
                existing = conn.execute("SELECT created_at FROM crypto_assets WHERE asset_id=?", (asset_id,)).fetchone()
                created = str(existing["created_at"]) if existing else now
                conn.execute(
                    "INSERT INTO crypto_assets(asset_id,latest_scan_id,asset_type,path,algorithm,risk,pq_status,payload_json,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET latest_scan_id=excluded.latest_scan_id,"
                    "asset_type=excluded.asset_type,path=excluded.path,algorithm=excluded.algorithm,risk=excluded.risk,"
                    "pq_status=excluded.pq_status,payload_json=excluded.payload_json,updated_at=excluded.updated_at",
                    (asset_id, scan_id, asset_type, path, algorithm, risk, pq_status,
                     json.dumps(payload, ensure_ascii=False, sort_keys=True), created, now),
                )
            conn.execute("DELETE FROM scan_findings WHERE scan_id=?", (scan_id,))
            for item in inventory.get("findings", []):
                if not isinstance(item, dict):
                    continue
                finding_id = str(item.get("evidence_id") or item.get("asset_id") or "")
                if not finding_id:
                    continue
                linked_asset = str(item.get("artifact_id") or item.get("asset_id") or "") or None
                if linked_asset not in asset_ids:
                    linked_asset = None
                finding_type = str(item.get("evidence_type") or item.get("asset_type") or "finding")
                conn.execute(
                    "INSERT INTO scan_findings(scan_id,finding_id,asset_id,finding_type,risk,payload_json) VALUES(?,?,?,?,?,?)",
                    (scan_id, finding_id, linked_asset, finding_type, str(item.get("risk", "INFO")),
                     json.dumps(item, ensure_ascii=False, sort_keys=True)),
                )
            summary = dict(inventory.get("summary", {}))
            summary.update({"control_plane_assets": len(assets), "control_plane_findings": len(inventory.get("findings", []))})
            conn.execute(
                "UPDATE scan_jobs SET status='SUCCEEDED',summary_json=?,completed_at=?,error=NULL WHERE scan_id=?",
                (json.dumps(summary, ensure_ascii=False, sort_keys=True), now, scan_id),
            )
            self._audit_conn(conn, now, actor, "scan.ingest", "scan_job", scan_id, summary)
        return self.get_scan_job(scan_id)

    def list_scan_findings(self, scan_id: str, limit: int = 1000) -> list[dict]:
        self.get_scan_job(scan_id)
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM scan_findings WHERE scan_id=? ORDER BY risk DESC,finding_id LIMIT ?",
                (scan_id, max(1, min(limit, 10_000))),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def list_crypto_assets(self, limit: int = 500) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT asset_id,latest_scan_id,asset_type,path,algorithm,risk,pq_status,created_at,updated_at "
                "FROM crypto_assets ORDER BY updated_at DESC,asset_id LIMIT ?",
                (max(1, min(limit, 5000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_crypto_asset(self, asset_id: str, evidence_limit: int = 1000) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM crypto_assets WHERE asset_id=?", (asset_id,)).fetchone()
            evidence = conn.execute(
                "SELECT payload_json FROM scan_findings WHERE asset_id=? ORDER BY scan_id DESC,finding_id LIMIT ?",
                (asset_id, max(1, min(evidence_limit, 5000))),
            ).fetchall()
            assessments = conn.execute(
                "SELECT assessment_id,risk,result_json,actor,created_at FROM asset_assessments WHERE asset_id=? ORDER BY created_at DESC",
                (asset_id,),
            ).fetchall()
            plans = conn.execute(
                "SELECT * FROM migration_plans WHERE asset_id=? ORDER BY updated_at DESC", (asset_id,),
            ).fetchall()
        if row is None:
            raise KeyError(f"unknown asset: {asset_id}")
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        item["evidence"] = [json.loads(record["payload_json"]) for record in evidence]
        item["assessments"] = [
            {**dict(record), "result": json.loads(record["result_json"])} for record in assessments
        ]
        for assessment in item["assessments"]:
            assessment.pop("result_json", None)
        item["migration_plans"] = []
        for record in plans:
            plan = dict(record)
            plan["plan"] = json.loads(plan.pop("plan_json"))
            item["migration_plans"].append(plan)
        return item

    def create_asset_assessment(self, assessment_id: str, asset_id: str, risk: str, result: dict, actor: str) -> dict:
        self.get_crypto_asset(asset_id, 1)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO asset_assessments(assessment_id,asset_id,risk,result_json,actor,created_at) VALUES(?,?,?,?,?,?)",
                (assessment_id, asset_id, risk, json.dumps(result, ensure_ascii=False, sort_keys=True), actor, now),
            )
            self._audit_conn(conn, now, actor, "asset.assess", "crypto_asset", asset_id, {"assessment_id": assessment_id, "risk": risk})
        return {"assessment_id": assessment_id, "asset_id": asset_id, "risk": risk, "result": result, "actor": actor, "created_at": now}

    def upsert_migration_plan(self, plan_id: str, asset_id: str, service_id: str, status: str, plan: dict,
                              actor: str, compatibility_version: int | None = None, strict_version: int | None = None) -> dict:
        self.get_crypto_asset(asset_id, 1)
        now = utc_now()
        with self.connect() as conn:
            existing = conn.execute("SELECT created_at FROM migration_plans WHERE plan_id=?", (plan_id,)).fetchone()
            created = str(existing["created_at"]) if existing else now
            conn.execute(
                "INSERT INTO migration_plans(plan_id,asset_id,service_id,status,compatibility_version,strict_version,plan_json,actor,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(plan_id) DO UPDATE SET status=excluded.status,"
                "compatibility_version=COALESCE(excluded.compatibility_version,migration_plans.compatibility_version),"
                "strict_version=COALESCE(excluded.strict_version,migration_plans.strict_version),plan_json=excluded.plan_json,"
                "actor=excluded.actor,updated_at=excluded.updated_at",
                (plan_id, asset_id, service_id, status, compatibility_version, strict_version,
                 json.dumps(plan, ensure_ascii=False, sort_keys=True), actor, created, now),
            )
            self._audit_conn(conn, now, actor, "migration.plan", "migration_plan", plan_id, {"asset_id": asset_id, "service_id": service_id, "status": status})
            row = conn.execute("SELECT * FROM migration_plans WHERE plan_id=?", (plan_id,)).fetchone()
        result = dict(row)
        result["plan"] = json.loads(result.pop("plan_json"))
        return result

    def get_migration_plan(self, plan_id: str) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM migration_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown migration plan: {plan_id}")
        result = dict(row)
        result["plan"] = json.loads(result.pop("plan_json"))
        return result

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

    def control_plane_summary_metrics(self) -> list[dict]:
        """Return current inventory and migration counts for dashboards.

        These are gauges because rescans and plan transitions can move records
        between labels. Runtime traffic counters remain in runtime_metrics.
        """
        now = utc_now()
        rows: list[dict] = []

        def metric(name: str, value: float, labels: dict[str, str], help_text: str) -> None:
            rows.append({
                "metric_name": name, "metric_type": "gauge", "help_text": help_text,
                "metric_value": float(value), "labels": labels, "updated_at": now,
            })

        with self.connect() as conn:
            assets = conn.execute(
                "SELECT risk,pq_status,COUNT(*) AS count FROM crypto_assets GROUP BY risk,pq_status"
            ).fetchall()
            scans = {str(row["status"]): int(row["count"]) for row in conn.execute(
                "SELECT status,COUNT(*) AS count FROM scan_jobs GROUP BY status"
            ).fetchall()}
            plans = {str(row["status"]): int(row["count"]) for row in conn.execute(
                "SELECT status,COUNT(*) AS count FROM migration_plans GROUP BY status"
            ).fetchall()}
            states = {str(row["state"]): int(row["count"]) for row in conn.execute(
                "SELECT state,COUNT(*) AS count FROM service_states GROUP BY state"
            ).fetchall()}
            service_count = int(conn.execute("SELECT COUNT(*) FROM service_resources").fetchone()[0])
            assessment_count = int(conn.execute("SELECT COUNT(*) FROM asset_assessments").fetchone()[0])

        if assets:
            for row in assets:
                metric("gateway_crypto_assets", int(row["count"]), {"risk": str(row["risk"]), "pq_status": str(row["pq_status"])}, "Current normalized cryptographic assets by risk and PQ status.")
        else:
            metric("gateway_crypto_assets", 0, {"risk": "NONE", "pq_status": "unknown"}, "Current normalized cryptographic assets by risk and PQ status.")
        for status in ("QUEUED", "RUNNING", "SUCCEEDED", "FAILED"):
            metric("gateway_scan_jobs", scans.get(status, 0), {"status": status}, "Current enterprise scan jobs by status.")
        for status in sorted({"COMPATIBILITY_STAGED", "STRICT_STAGED", "VERIFIED", *plans}):
            metric("gateway_migration_plans", plans.get(status, 0), {"status": status}, "Current scan-driven migration plans by status.")
        migration_states = {
            "DISCOVERED", "ASSESSED", "PLANNED", "COMPATIBILITY", "PQC_PREFERRED", "STRICT", "VERIFIED",
            "DEGRADED", "ROLLED_BACK", "BLOCKED", *states,
        }
        for state in sorted(migration_states):
            metric("gateway_migration_services", states.get(state, 0), {"state": state}, "Current services by migration state.")
        metric("gateway_managed_services", service_count, {}, "Current first-class Gateway service resources.")
        metric("gateway_asset_assessments", assessment_count, {}, "Current persisted cryptographic asset assessments.")
        return rows

    def system_summary(self, stale_after: float = 30.0) -> dict:
        """Aggregate API-safe day-2 operational state without exposing secrets."""
        with self.connect() as conn:
            def grouped(table: str, column: str) -> dict[str, int]:
                return {str(row["label"]): int(row["count"]) for row in conn.execute(
                    f"SELECT {column} AS label,COUNT(*) AS count FROM {table} GROUP BY {column}"
                ).fetchall()}

            counts = {
                "services": int(conn.execute("SELECT COUNT(*) FROM service_resources").fetchone()[0]),
                "policies": int(conn.execute("SELECT COUNT(*) FROM policy_resources").fetchone()[0]),
                "assets": int(conn.execute("SELECT COUNT(*) FROM crypto_assets").fetchone()[0]),
                "assessments": int(conn.execute("SELECT COUNT(*) FROM asset_assessments").fetchone()[0]),
            }
            scans = grouped("scan_jobs", "status")
            plans = grouped("migration_plans", "status")
            migrations = grouped("service_states", "state")
        latest = self.latest_version()
        if latest:
            latest = {key: latest.get(key) for key in ("version", "checksum", "created_at", "operator", "status", "rollback_from", "error")}
        return {
            "version": "3.6.0",
            "latest_release": latest,
            "counts": counts,
            "scan_jobs": scans,
            "migration_plans": plans,
            "migration_states": migrations,
            "agents": self.list_agents(stale_after),
        }

    def prometheus_text(self) -> str:
        metrics = self.list_metrics() + self.control_plane_summary_metrics()
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
