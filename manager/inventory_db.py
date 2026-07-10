#!/usr/bin/env python3
"""Import scan and risk results into a deduplicated SQLite inventory database."""
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
  scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
  imported_at TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY,
  asset_type TEXT NOT NULL,
  path TEXT NOT NULL,
  algorithm TEXT,
  key_bits TEXT,
  risk TEXT,
  pq_status TEXT,
  deployment_status TEXT,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  line INTEGER,
  evidence_type TEXT,
  algorithm TEXT,
  risk TEXT,
  pq_status TEXT,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
  endpoint_id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  sni TEXT NOT NULL,
  status TEXT,
  pqc_supported INTEGER,
  classical_supported INTEGER,
  fallback_enabled INTEGER,
  certificate_algorithm TEXT,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_findings (
  finding_id TEXT PRIMARY KEY,
  category TEXT,
  target TEXT,
  risk TEXT,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--static", default="")
    parser.add_argument("--tls", default="")
    parser.add_argument("--risk", default="")
    parser.add_argument("--summary-json", default="")
    args = parser.parse_args()

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    now = stamp()
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        if args.static:
            data = load(args.static)
            conn.execute("INSERT INTO scans(imported_at,source_type,source_path) VALUES(?,?,?)", (now, "static", str(Path(args.static).resolve())))
            for item in data.get("assets", []):
                conn.execute("""INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(asset_id) DO UPDATE SET asset_type=excluded.asset_type,path=excluded.path,algorithm=excluded.algorithm,key_bits=excluded.key_bits,risk=excluded.risk,pq_status=excluded.pq_status,deployment_status=excluded.deployment_status,data_json=excluded.data_json,updated_at=excluded.updated_at""",
                (item["asset_id"], item["asset_type"], item["path"], item.get("algorithm"), item.get("key_bits"), item.get("risk"), item.get("pq_status"), item.get("deployment_status"), json.dumps(item, ensure_ascii=False), now))
            for item in data.get("evidence", []):
                conn.execute("""INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(evidence_id) DO UPDATE SET path=excluded.path,line=excluded.line,evidence_type=excluded.evidence_type,algorithm=excluded.algorithm,risk=excluded.risk,pq_status=excluded.pq_status,data_json=excluded.data_json,updated_at=excluded.updated_at""",
                (item["evidence_id"], item["path"], item.get("line"), item.get("evidence_type"), item.get("algorithm"), item.get("risk"), item.get("pq_status"), json.dumps(item, ensure_ascii=False), now))
        if args.tls:
            data = load(args.tls)
            conn.execute("INSERT INTO scans(imported_at,source_type,source_path) VALUES(?,?,?)", (now, "tls", str(Path(args.tls).resolve())))
            for item in data.get("endpoints", []):
                cert_alg = item.get("certificate", {}).get("public_key_algorithm", "")
                conn.execute("""INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(endpoint_id) DO UPDATE SET host=excluded.host,port=excluded.port,sni=excluded.sni,status=excluded.status,pqc_supported=excluded.pqc_supported,classical_supported=excluded.classical_supported,fallback_enabled=excluded.fallback_enabled,certificate_algorithm=excluded.certificate_algorithm,data_json=excluded.data_json,updated_at=excluded.updated_at""",
                (item["endpoint_id"], item["host"], item["port"], item["sni"], item.get("status"), int(bool(item.get("pqc_supported"))), int(bool(item.get("classical_supported"))), int(bool(item.get("fallback_enabled"))), cert_alg, json.dumps(item, ensure_ascii=False), now))
        if args.risk:
            data = load(args.risk)
            conn.execute("INSERT INTO scans(imported_at,source_type,source_path) VALUES(?,?,?)", (now, "risk", str(Path(args.risk).resolve())))
            for item in data.get("findings", []):
                conn.execute("""INSERT INTO risk_findings VALUES(?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET category=excluded.category,target=excluded.target,risk=excluded.risk,data_json=excluded.data_json,updated_at=excluded.updated_at""",
                (item["finding_id"], item.get("category"), item.get("target"), item.get("risk"), json.dumps(item, ensure_ascii=False), now))
        conn.commit()
        summary = {
            "database": str(db_path.resolve()),
            "assets": conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
            "evidence": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            "endpoints": conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0],
            "risk_findings": conn.execute("SELECT COUNT(*) FROM risk_findings").fetchone()[0],
        }
    if args.summary_json:
        Path(args.summary_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
