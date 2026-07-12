#!/usr/bin/env python3
"""Validate a v3/v4 service document and render NGINX configuration."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.adapters import default_registry  # noqa: E402
from gateway.model import ConfigError, normalize_config  # noqa: E402
from gateway.renderer import render  # noqa: E402

__all__ = ["ConfigError", "normalize_config", "render"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        canonical = normalize_config(config)
        output = render(config)
        Path(args.output).write_text(output, encoding="utf-8")
        if args.check:
            adapters = sorted({s["adapter"] for s in canonical["services"]})
            print(f"valid: {len(canonical['services'])} services; adapters={','.join(adapters)}; available={','.join(default_registry().names())}")
    except (OSError, json.JSONDecodeError, ConfigError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
