#!/usr/bin/env python3
"""Combine static and online scan results into migration-oriented risk findings."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def assess_endpoint(endpoint: dict) -> dict:
    reasons: list[str] = []
    recommendations: list[str] = []
    risk = "LOW"

    if endpoint.get("status") != "reachable":
        risk = "HIGH"
        reasons.append("Endpoint was not reachable with the tested TLS 1.3 groups.")
        recommendations.append("Check connectivity, certificate trust, and supported TLS versions/groups.")
    else:
        if not endpoint.get("pqc_supported"):
            risk = "HIGH"
            reasons.append("No tested Hybrid/PQC key-exchange group succeeded.")
            recommendations.append("Place the service behind the migration gateway or upgrade its TLS stack.")
        elif endpoint.get("fallback_enabled"):
            risk = max((risk, "MEDIUM"), key=RANK.get)
            reasons.append("Hybrid/PQC is available, but classical X25519 fallback remains enabled.")
            recommendations.append("Measure fallback use and move to strict mode after client compatibility is proven.")
        else:
            reasons.append("Hybrid/PQC key exchange is available without tested X25519 fallback.")

        cert = endpoint.get("certificate", {})
        if cert.get("quantum_vulnerable_authentication"):
            risk = max((risk, "MEDIUM"), key=RANK.get)
            reasons.append("The TLS certificate authentication layer still uses a quantum-vulnerable public-key algorithm.")
            recommendations.append("Plan an independent certificate/PKI migration; KEX migration alone is not full-stack PQC.")

    return {
        "finding_id": "risk-" + endpoint.get("endpoint_id", "unknown"),
        "category": "tls_endpoint",
        "target": f"{endpoint.get('sni')}:{endpoint.get('port')}",
        "risk": risk,
        "reasons": reasons,
        "recommendations": recommendations,
        "metadata": {
            "pqc_supported": endpoint.get("pqc_supported", False),
            "fallback_enabled": endpoint.get("fallback_enabled", False),
            "supported_groups": endpoint.get("supported_groups", []),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static", action="append", default=[])
    parser.add_argument("--tls", default="")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    findings: list[dict] = []
    for static_path in args.static:
        static = json.loads(Path(static_path).read_text(encoding="utf-8"))
        for asset in static.get("assets", []):
            findings.append({
                "finding_id": "risk-" + asset["asset_id"],
                "category": "crypto_asset",
                "target": asset["path"],
                "risk": asset["risk"],
                "reasons": [f"{asset['asset_type']} uses {asset['algorithm'] or 'an unidentified algorithm'}."],
                "recommendations": [asset["recommendation"]],
                "metadata": {"pq_status": asset["pq_status"], "deployment_status": asset["deployment_status"]},
            })
        for evidence in static.get("evidence", []):
            if evidence.get("risk") == "INFO" and evidence.get("confidence") != "HIGH":
                continue
            method = evidence.get("method") or evidence.get("algorithm") or "unidentified interface"
            findings.append({
                "finding_id": "risk-" + evidence["evidence_id"],
                "category": "crypto_usage",
                "target": f"{evidence['path']}:{evidence.get('line', 0)}",
                "risk": evidence.get("risk", "INFO"),
                "reasons": [f"{evidence.get('language') or 'configuration'} uses {method} ({evidence.get('library') or 'library unknown'})."],
                "recommendations": [evidence.get("recommendation") or "Associate this cryptographic use with its owning service and migration plan."],
                "metadata": {
                    "pq_status": evidence.get("pq_status"),
                    "method": method,
                    "library": evidence.get("library"),
                    "confidence": evidence.get("confidence", "MEDIUM"),
                    "evidence_source": evidence.get("source"),
                    "artifact_id": evidence.get("artifact_id"),
                },
            })
    if args.tls:
        tls = json.loads(Path(args.tls).read_text(encoding="utf-8"))
        findings.extend(assess_endpoint(item) for item in tls.get("endpoints", []))

    payload = {
        "schema_version": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total": len(findings),
            "by_risk": {name: sum(f["risk"] == name for f in findings) for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        },
        "findings": sorted(findings, key=lambda x: (-RANK[x["risk"]], x["target"])),
    }
    Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
