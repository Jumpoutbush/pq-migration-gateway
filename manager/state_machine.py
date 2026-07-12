"""Auditable service migration state machine."""
from __future__ import annotations

import json

from manager.config_store import ConfigStore, utc_now

STATES = {
    "DISCOVERED", "ASSESSED", "PLANNED", "COMPATIBILITY", "PQC_PREFERRED", "STRICT", "VERIFIED",
    "DEGRADED", "ROLLED_BACK", "BLOCKED",
}
TRANSITIONS = {
    "DISCOVERED": {"ASSESSED", "BLOCKED"},
    "ASSESSED": {"PLANNED", "BLOCKED"},
    "PLANNED": {"COMPATIBILITY", "PQC_PREFERRED", "STRICT", "BLOCKED"},
    "COMPATIBILITY": {"PQC_PREFERRED", "STRICT", "DEGRADED", "ROLLED_BACK", "BLOCKED"},
    "PQC_PREFERRED": {"STRICT", "VERIFIED", "DEGRADED", "ROLLED_BACK", "BLOCKED"},
    "STRICT": {"VERIFIED", "DEGRADED", "ROLLED_BACK", "BLOCKED"},
    "VERIFIED": {"DEGRADED", "ROLLED_BACK"},
    "DEGRADED": {"COMPATIBILITY", "PQC_PREFERRED", "STRICT", "ROLLED_BACK", "BLOCKED"},
    "ROLLED_BACK": {"PLANNED", "COMPATIBILITY", "BLOCKED"},
    "BLOCKED": {"PLANNED", "ASSESSED"},
}


class TransitionError(ValueError):
    pass


class MigrationStateMachine:
    def __init__(self, store: ConfigStore):
        self.store = store

    def get(self, service_id: str) -> dict | None:
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM service_states WHERE service_id=?", (service_id,)).fetchone()
        return dict(row) if row else None

    def list(self) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute("SELECT * FROM service_states ORDER BY service_id").fetchall()
        return [dict(row) for row in rows]

    def transition(self, service_id: str, target: str, *, operator: str, reason: str, config_version: int | None = None, verification_result: str | None = None, fallback_rate: float | None = None) -> dict:
        if not service_id or len(service_id) > 128:
            raise TransitionError("service_id is required and must not exceed 128 characters")
        if not reason.strip():
            raise TransitionError("migration transition requires a reason")
        target = target.upper()
        if target not in STATES:
            raise TransitionError(f"unknown migration state: {target}")
        current = self.get(service_id)
        source = current["state"] if current else None
        if source is None:
            if target != "DISCOVERED":
                raise TransitionError("a new service must enter DISCOVERED first")
        elif target not in TRANSITIONS[source]:
            raise TransitionError(f"invalid transition: {source} -> {target}")
        if fallback_rate is not None and not 0 <= fallback_rate <= 1:
            raise TransitionError("fallback_rate must be between 0 and 1")
        if target == "VERIFIED" and not verification_result:
            raise TransitionError("VERIFIED requires a verification_result")
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO service_states(service_id,state,config_version,updated_at,operator,reason) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(service_id) DO UPDATE SET state=excluded.state,config_version=excluded.config_version,updated_at=excluded.updated_at,operator=excluded.operator,reason=excluded.reason",
                (service_id, target, config_version, now, operator, reason),
            )
            conn.execute(
                "INSERT INTO state_transitions(service_id,from_state,to_state,config_version,verification_result,fallback_rate,operator,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (service_id, source, target, config_version, verification_result, fallback_rate, operator, reason, now),
            )
            conn.execute(
                "INSERT INTO audit_events(created_at,actor,action,object_type,object_id,details_json) VALUES(?,?,?,?,?,?)",
                (now, operator, "migration.transition", "migration_state", service_id, json.dumps({
                    "from": source, "to": target, "reason": reason, "config_version": config_version,
                    "verification_result": verification_result, "fallback_rate": fallback_rate,
                }, ensure_ascii=False, sort_keys=True)),
            )
        return self.get(service_id) or {}

    def history(self, service_id: str, limit: int = 100) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM state_transitions WHERE service_id=? ORDER BY transition_id DESC LIMIT ?",
                (service_id, max(1, min(limit, 1000))),
            ).fetchall()
        return [dict(row) for row in rows]
