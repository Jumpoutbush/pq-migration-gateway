"""Compile migration intent into an explicit, auditable deployment plan."""
from __future__ import annotations


def deployment_plan(service: dict) -> dict:
    rollout = service["rollout"]
    tls = service["downstream_tls"]
    exact_split = (
        (rollout["policy"] == "percentage" and rollout["hybrid_percentage"] not in {0, 100})
        or rollout["policy"] in {"client-group", "source-cidr", "sni"}
    )
    return {
        "service_id": service["id"],
        "tls_mode": tls["mode"],
        "groups": tls["groups"],
        "fallback_allowed": rollout["fallback_allowed"],
        "rollout_policy": rollout["policy"],
        "strategy": "separate-listener-or-instance" if exact_split else "single-listener",
        "hybrid_percentage": rollout["hybrid_percentage"],
        "enforcement_note": (
            "Exact percentage routing is compiled outside the TLS handshake and requires distinct listeners, SNI names, or gateway instances."
            if exact_split else "The data-plane listener directly enforces the configured TLS group set."
        ),
    }


def compile_policies(config: dict) -> list[dict]:
    return [deployment_plan(service) for service in config["services"]]
