"""Configuration validation, release lifecycle and rollback orchestration."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from gateway.model import normalize_config
from gateway.renderer import render
from manager.config_store import ConfigStore, utc_now
from manager.policy_engine import compile_policies


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def validate_document(document: dict) -> dict:
    canonical = normalize_config(document)
    rendered = render(document)
    canonical_bytes = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return {
        "canonical": canonical,
        "rendered": rendered,
        "checksum": hashlib.sha256(canonical_bytes).hexdigest(),
        "rendered_checksum": hashlib.sha256(rendered.encode()).hexdigest(),
        "policies": compile_policies(canonical),
    }


def document_checksum(document: dict) -> str:
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def manifest_signature(manifest: dict, key: str) -> str:
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    payload = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


def stage_document(store: ConfigStore, control_dir: str | Path, document: dict, operator: str, rollback_from: int | None = None, signing_key: str | None = None) -> dict:
    """Create an audited DRAFT -> VALIDATED -> STAGED release.

    Invalid submissions are retained as VALIDATION_FAILED versions, while only
    validated artifacts become immutable release directories and desired state.
    """
    version = store.create_version(document_checksum(document), document, "", operator, rollback_from=rollback_from)
    try:
        validated = validate_document(document)
    except Exception as exc:
        store.set_status(version, "VALIDATION_FAILED", operator, str(exc))
        raise
    store.update_draft_artifacts(version, validated["checksum"], validated["canonical"], validated["rendered"])
    store.set_status(version, "VALIDATED", operator)
    root = Path(control_dir)
    release = root / "releases" / str(version)
    release.mkdir(parents=True, exist_ok=False)
    (release / "services.json").write_text(json.dumps(validated["canonical"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (release / "nginx.conf").write_text(validated["rendered"], encoding="utf-8")
    manifest = {
        "version": version,
        "config_checksum": validated["checksum"],
        "rendered_checksum": validated["rendered_checksum"],
        "created_at": utc_now(),
        "operator": operator,
        "rollback_from": rollback_from,
        "release_status": "STAGED",
        "policies": validated["policies"],
    }
    signing_key = os.environ.get("PQ_CONFIG_SIGNING_KEY", "") if signing_key is None else signing_key
    if signing_key:
        manifest["signature"] = "hmac-sha256:" + manifest_signature(manifest, signing_key)
    atomic_json(release / "manifest.json", manifest)
    store.sync_canonical_resources(validated["canonical"], validated["policies"], operator, version)
    store.set_status(version, "STAGED", operator)
    atomic_json(root / "desired.json", {"version": version, "rendered_checksum": validated["rendered_checksum"], "requested_at": utc_now(), "operator": operator})
    return manifest


def stage_rollback(store: ConfigStore, control_dir: str | Path, source_version: int, operator: str, signing_key: str | None = None) -> dict:
    source = store.get_version(source_version)
    return stage_document(store, control_dir, source["source"], operator, rollback_from=source_version, signing_key=signing_key)


def stage_resources(store: ConfigStore, control_dir: str | Path, operator: str, defaults: dict | None = None, signing_key: str | None = None) -> dict:
    """Publish the current first-class Service resources as one release."""
    return stage_document(store, control_dir, store.document_from_resources(defaults), operator, signing_key=signing_key)
