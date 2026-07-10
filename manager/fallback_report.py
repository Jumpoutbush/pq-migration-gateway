#!/usr/bin/env python3
"""Aggregate NGINX JSON access logs into Hybrid/PQC versus classical fallback metrics."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    total = Counter()
    by_service: dict[str, Counter] = defaultdict(Counter)
    invalid = 0
    for line in Path(args.log).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        group = str(item.get("ssl_curve", ""))
        service = str(item.get("service", "unknown"))
        category = "hybrid_pqc" if "MLKEM" in group.upper() or "ML-KEM" in group.upper() else "classical_fallback" if group else "unknown"
        total[category] += 1
        by_service[service][category] += 1

    connections = sum(total.values())
    payload = {
        "summary": {
            "connections": connections,
            "hybrid_pqc": total["hybrid_pqc"],
            "classical_fallback": total["classical_fallback"],
            "unknown": total["unknown"],
            "hybrid_adoption_rate": round(total["hybrid_pqc"] / connections, 4) if connections else None,
            "invalid_log_lines": invalid,
        },
        "services": {name: dict(counts) for name, counts in sorted(by_service.items())},
    }
    Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
